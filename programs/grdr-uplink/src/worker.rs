// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Inherited-channel daemon worker state machine for `grdr-uplink` (`docs/design/11`, `docs/design/22`).
//! Drives `ScheduleManager`, priority `LaneBatcher`, `ControlChannel`, `Dialer` egress gating,
//! non-empty pinned `ResponseVerifier`, and P8 metadata sanitization.

use std::collections::VecDeque;
use std::path::PathBuf;

use grdr_crypto::sha256_hex;
use grdr_os_clock::Clock;
use grdr_wire::limits::embedded_limits;
use grdr_wire::messages::{UplinkCommandFrame, UplinkEventFrame};

use crate::auth::{FleetTrustAnchor, ResponseVerifier};
use crate::control::{ControlChannel, OpaqueArtifactStager};
use crate::dialer::NetworkMode;
use crate::error::UplinkError;
use crate::lanes::{
    ConnectionMetered, Lane, LaneBatcher, PowerSource, QueuedRecord, WatermarkAdvance,
};
use crate::schedule::ScheduleManager;
use crate::staging_fs::ensure_private_staging_dir;
use crate::watermark::WatermarkTracker;
use crate::worker_verify::{
    CheckInDirective, FlushSpoolDirective, degraded_event, verify_egress_and_directive,
    verify_flush_ack_and_advance,
};

pub use crate::worker_ipc::{run_stdio_daemon_worker, run_stdio_daemon_worker_with_config};
pub use crate::worker_verify::verify_checkin_response_pinned;

const FALLBACK_MAX_PACK_BUNDLE_BYTES: u64 = 32 * 1024 * 1024;

/// Startup configuration provisioned by `grdr-daemon` or CLI for an `UplinkWorkerState`.
#[derive(Clone, Debug)]
pub struct UplinkWorkerConfig {
    pub device_id: String,
    pub network_mode: NetworkMode,
    pub pinned_anchor: Option<FleetTrustAnchor>,
}

/// Stateful worker coordinating fleet schedules, priority lane packing, staging, and verification.
#[derive(Debug)]
pub struct UplinkWorkerState {
    device_id: String,
    schedule: ScheduleManager,
    batcher: LaneBatcher,
    channel: ControlChannel,
    stager: OpaqueArtifactStager,
    network_mode: NetworkMode,
    pinned_anchor: Option<FleetTrustAnchor>,
    verifier: Option<ResponseVerifier>,
    watermarks: WatermarkTracker,
    seen_request_digests: VecDeque<String>,
    next_seq: u64,
    last_hash_hex: String,
}

impl Default for UplinkWorkerConfig {
    fn default() -> Self {
        Self {
            device_id: "dev-unassigned".to_string(),
            network_mode: NetworkMode::Standard,
            pinned_anchor: None,
        }
    }
}

impl UplinkWorkerState {
    /// Open worker with default `Standard` network mode and unpinned anchor (fail-closed check-in).
    pub fn new(staging_root: PathBuf, clock: &dyn Clock) -> Result<Self, UplinkError> {
        Self::with_config(staging_root, UplinkWorkerConfig::default(), clock)
    }

    /// Open worker validating private `staging_root`, device id, egress mode, and pinned anchor.
    pub fn with_config(
        staging_root: PathBuf,
        config: UplinkWorkerConfig,
        clock: &dyn Clock,
    ) -> Result<Self, UplinkError> {
        ensure_private_staging_dir(&staging_root)?;
        if config.device_id.trim().is_empty() {
            return Err(UplinkError::InvalidEndpoint {
                detail: "device_id must not be empty".to_string(),
            });
        }
        let now_mono_ms = boot_mono_ms(clock)?;
        let now_wall_s = wall_unix_s(clock)?;
        let verifier = if let Some(ref anchor) = config.pinned_anchor {
            anchor.validate()?;
            Some(ResponseVerifier::new(
                anchor.clone(),
                now_wall_s,
                now_mono_ms,
            ))
        } else {
            None
        };
        let schedule = ScheduleManager::new(config.device_id.as_bytes(), clock)?;
        let eff = schedule.current_schedule().clone();
        let (max_req_bytes, max_events) = match embedded_limits() {
            Ok(l) => (
                eff.max_request_bytes
                    .min(u32::try_from(l.max_batch_bytes).unwrap_or(u32::MAX)),
                eff.max_events_per_batch
                    .min(u32::try_from(l.max_batch_events).unwrap_or(u32::MAX)),
            ),
            Err(_) => (eff.max_request_bytes, eff.max_events_per_batch),
        };
        let batcher = LaneBatcher::new(
            max_req_bytes,
            max_events,
            eff.evidence_credit_bytes,
            eff.backfill_credit_bytes,
            now_mono_ms,
        );
        Ok(Self {
            device_id: config.device_id,
            schedule,
            batcher,
            channel: ControlChannel::new(),
            stager: OpaqueArtifactStager::new(staging_root),
            network_mode: config.network_mode,
            pinned_anchor: config.pinned_anchor,
            verifier,
            watermarks: WatermarkTracker::new(),
            seen_request_digests: VecDeque::new(),
            next_seq: 1,
            last_hash_hex: String::new(),
        })
    }

    /// Handle one IPC `UplinkCommandFrame` without failing open.
    pub fn handle_command(
        &mut self,
        cmd: &UplinkCommandFrame,
        clock: &dyn Clock,
    ) -> UplinkEventFrame {
        match cmd.action.as_str() {
            "flush_spool" => self.handle_flush_spool(cmd, clock),
            "check_in" => self.handle_check_in(cmd, clock),
            "stage_artifact" | "stage_artifact_chunk" => self.handle_stage_artifact(cmd),
            "query_watermarks" => self.query_event(&cmd.command_id, &cmd.lane),
            other => UplinkEventFrame {
                command_id: cmd.command_id.clone(),
                ack_lane: cmd.lane.clone(),
                durable_through_seq: self.watermarks.durable_through(),
                durable_through_hash: self.last_hash_hex.clone(),
                checkin_blob: Vec::new(),
                staged_manifest_path: String::new(),
                degraded_reason: format!("GRDR-UPLINK-0001: unsupported command `{other}`"),
            },
        }
    }

    #[must_use]
    pub fn queued_total(&self) -> usize {
        self.batcher
            .queued_len(Lane::Decision)
            .saturating_add(self.batcher.queued_len(Lane::Spine))
            .saturating_add(self.batcher.queued_len(Lane::Evidence))
            .saturating_add(self.batcher.queued_len(Lane::Bulk))
    }

    #[must_use]
    pub fn retained_unacked_count(&self) -> usize {
        self.batcher.retained_unacked_count()
    }

    #[must_use]
    pub fn durable_through_for(&self, lane: Lane) -> u64 {
        self.watermarks.durable_through_for(lane)
    }

    fn query_event(&self, command_id: &str, lane_raw: &str) -> UplinkEventFrame {
        let lane = parse_lane(lane_raw).unwrap_or(Lane::Decision);
        let state_label = format!(
            "{:?};phase_ms={}",
            self.channel.state(),
            self.schedule.phase_heartbeat_ms()
        );
        UplinkEventFrame {
            command_id: command_id.to_string(),
            ack_lane: state_label,
            durable_through_seq: self.watermarks.durable_through_for(lane),
            durable_through_hash: self.last_hash_hex.clone(),
            checkin_blob: Vec::new(),
            staged_manifest_path: String::new(),
            degraded_reason: String::new(),
        }
    }

    fn handle_flush_spool(
        &mut self,
        cmd: &UplinkCommandFrame,
        clock: &dyn Clock,
    ) -> UplinkEventFrame {
        let lane = match parse_lane(&cmd.lane) {
            Ok(l) => l,
            Err(err) => return degraded_event(&cmd.command_id, &cmd.lane, 0, &err),
        };
        let now_mono = match boot_mono_ms(clock) {
            Ok(t) => t,
            Err(err) => {
                return degraded_event(
                    &cmd.command_id,
                    &cmd.lane,
                    self.watermarks.durable_through_for(lane),
                    &err,
                );
            }
        };
        let now_wall_s = match wall_unix_s(clock) {
            Ok(t) => t,
            Err(err) => {
                return degraded_event(
                    &cmd.command_id,
                    &cmd.lane,
                    self.watermarks.durable_through_for(lane),
                    &err,
                );
            }
        };

        let parsed_directive = serde_json::from_slice::<FlushSpoolDirective>(&cmd.payload).ok();
        let payloads = match parsed_directive.as_ref() {
            Some(dir) if !dir.records.is_empty() => dir.records.clone(),
            _ => vec![cmd.payload.clone()],
        };
        let mut seq_cursor = cmd.seq_hint.max(self.next_seq);
        for payload in payloads {
            let seq = seq_cursor;
            seq_cursor = seq_cursor.saturating_add(1);
            self.next_seq = seq_cursor;
            if let Err(err) = self.batcher.enqueue(QueuedRecord {
                seq,
                lane,
                enqueued_mono_ms: now_mono,
                payload,
            }) {
                return degraded_event(
                    &cmd.command_id,
                    &cmd.lane,
                    self.watermarks.durable_through_for(lane),
                    &err,
                );
            }
        }
        let _packed = self.batcher.pack_next_batch(
            format!("batch-{}", cmd.command_id),
            PowerSource::Ac,
            ConnectionMetered::Unmetered,
            now_mono,
        );

        let Some(ack) = parsed_directive.and_then(|d| d.verified_ack) else {
            let err = UplinkError::AckUnverified {
                reason: "offline-queued: awaiting signed fleet PushAck".to_string(),
            };
            return degraded_event(
                &cmd.command_id,
                &cmd.lane,
                self.watermarks.durable_through_for(lane),
                &err,
            );
        };
        match verify_flush_ack_and_advance(
            self.verifier.as_mut(),
            &mut self.watermarks,
            &mut self.seen_request_digests,
            &self.device_id,
            lane,
            &ack,
            now_wall_s,
            now_mono,
        ) {
            Ok((advance, hash)) => {
                let durable = self.watermarks.durable_through_for(lane);
                let _pruned = self.batcher.prune_durable_for_lane(lane, durable);
                if let WatermarkAdvance::ServerEpochChanged { backfill_from_seq } = advance {
                    let _requeued = self
                        .batcher
                        .requeue_backfill_for_lane(lane, backfill_from_seq);
                }
                self.last_hash_hex = hash.clone();
                UplinkEventFrame {
                    command_id: cmd.command_id.clone(),
                    ack_lane: cmd.lane.clone(),
                    durable_through_seq: durable,
                    durable_through_hash: hash,
                    checkin_blob: Vec::new(),
                    staged_manifest_path: String::new(),
                    degraded_reason: String::new(),
                }
            }
            Err(err) => degraded_event(
                &cmd.command_id,
                &cmd.lane,
                self.watermarks.durable_through_for(lane),
                &err,
            ),
        }
    }

    fn handle_check_in(&mut self, cmd: &UplinkCommandFrame, clock: &dyn Clock) -> UplinkEventFrame {
        let now_mono = match boot_mono_ms(clock) {
            Ok(t) => t,
            Err(err) => {
                return degraded_event(
                    &cmd.command_id,
                    "checkin",
                    self.watermarks.durable_through(),
                    &err,
                );
            }
        };
        let now_wall_s = match wall_unix_s(clock) {
            Ok(t) => t,
            Err(err) => {
                return degraded_event(
                    &cmd.command_id,
                    "checkin",
                    self.watermarks.durable_through(),
                    &err,
                );
            }
        };

        let Ok(directive) = serde_json::from_slice::<CheckInDirective>(&cmd.payload) else {
            return degraded_event(
                &cmd.command_id,
                "checkin",
                self.watermarks.durable_through(),
                &UplinkError::InvalidEndpoint {
                    detail: "invalid check_in directive payload".to_string(),
                },
            );
        };
        if let Err(err) = verify_egress_and_directive(
            &self.network_mode,
            self.pinned_anchor.as_ref(),
            self.verifier.as_mut(),
            &mut self.seen_request_digests,
            &self.device_id,
            &directive,
            now_wall_s,
            now_mono,
        ) {
            return degraded_event(
                &cmd.command_id,
                "checkin",
                self.watermarks.durable_through(),
                &err,
            );
        }

        self.channel.enter_subscribe("cell-0", now_mono);
        UplinkEventFrame {
            command_id: cmd.command_id.clone(),
            ack_lane: directive.server_url,
            durable_through_seq: self.watermarks.durable_through(),
            durable_through_hash: sha256_hex(&directive.response_payload),
            checkin_blob: directive.response_payload,
            staged_manifest_path: String::new(),
            degraded_reason: String::new(),
        }
    }

    fn handle_stage_artifact(&mut self, cmd: &UplinkCommandFrame) -> UplinkEventFrame {
        let sha = cmd.lane.trim();
        let max_bundle = embedded_limits()
            .ok()
            .and_then(|l| u64::try_from(l.max_pack_bundle_bytes).ok())
            .filter(|&v| v > 0)
            .unwrap_or(FALLBACK_MAX_PACK_BUNDLE_BYTES);
        if cmd.seq_hint == 0 || cmd.seq_hint > max_bundle {
            return degraded_event(
                &cmd.command_id,
                sha,
                self.watermarks.durable_through(),
                &UplinkError::StagingError {
                    detail: format!(
                        "declared artifact size {} out of bounds (1..={max_bundle})",
                        cmd.seq_hint
                    ),
                },
            );
        }
        let offset = match self.stager.resume_offset(sha) {
            Ok(off) => off,
            Err(err) => {
                return degraded_event(
                    &cmd.command_id,
                    sha,
                    self.watermarks.durable_through(),
                    &err,
                );
            }
        };
        let written_len = if !cmd.payload.is_empty() {
            match self
                .stager
                .write_chunk(sha, offset, &cmd.payload, cmd.seq_hint)
            {
                Ok(n) => n,
                Err(err) => {
                    return degraded_event(
                        &cmd.command_id,
                        sha,
                        self.watermarks.durable_through(),
                        &err,
                    );
                }
            }
        } else {
            offset
        };

        if written_len < cmd.seq_hint {
            return UplinkEventFrame {
                command_id: cmd.command_id.clone(),
                ack_lane: "staging-partial".to_string(),
                durable_through_seq: written_len,
                durable_through_hash: sha.to_string(),
                checkin_blob: Vec::new(),
                staged_manifest_path: String::new(),
                degraded_reason: String::new(),
            };
        }

        match self.stager.finalize(sha, cmd.seq_hint) {
            Ok(staged) if staged.byte_len == cmd.seq_hint => UplinkEventFrame {
                command_id: cmd.command_id.clone(),
                ack_lane: "staged".to_string(),
                durable_through_seq: staged.byte_len,
                durable_through_hash: staged.expected_sha256,
                checkin_blob: Vec::new(),
                staged_manifest_path: staged.path.display().to_string(),
                degraded_reason: String::new(),
            },
            Ok(staged) => degraded_event(
                &cmd.command_id,
                sha,
                self.watermarks.durable_through(),
                &UplinkError::StagingError {
                    detail: format!(
                        "final staged size {} != declared {}",
                        staged.byte_len, cmd.seq_hint
                    ),
                },
            ),
            Err(err) => degraded_event(
                &cmd.command_id,
                sha,
                self.watermarks.durable_through(),
                &err,
            ),
        }
    }
}

fn parse_lane(raw: &str) -> Result<Lane, UplinkError> {
    match raw {
        "decision" => Ok(Lane::Decision),
        "spine" => Ok(Lane::Spine),
        "evidence" => Ok(Lane::Evidence),
        "bulk" => Ok(Lane::Bulk),
        other => Err(UplinkError::InvalidEndpoint {
            detail: format!("unknown uplink spool lane '{other}'"),
        }),
    }
}

fn boot_mono_ms(clock: &dyn Clock) -> Result<u64, UplinkError> {
    clock
        .boot_uptime()
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .map_err(|e| UplinkError::ClockFailed {
            detail: e.to_string(),
        })
}

fn wall_unix_s(clock: &dyn Clock) -> Result<i64, UplinkError> {
    clock
        .now_wall()
        .map(|t| t.as_second())
        .map_err(|e| UplinkError::ClockFailed {
            detail: e.to_string(),
        })
}
