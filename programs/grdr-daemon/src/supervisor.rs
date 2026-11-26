// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Child process supervision (`grdr-engine`, `grdr-uplink`, `grdr-updater`) via OS containment
//! and inherited channels with 1s heartbeats, `1.3x`/`1.5x` OS RSS rungs, and request correlation.

use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Stdio};
use std::time::Duration;

use grdr_ipc_os::proto_io::{DuplexPipe, ProtoIpcStream};
use grdr_os_service::ladder::{CrashLoopLadder, HealthTransitionEvent};
use grdr_os_service::rss::child_process_rss_bytes;
use grdr_os_service::supervision::{ChildHeartbeatMonitor, ChildLifecycle};
use grdr_store_local::fs_hardening::redact_path_label;
use grdr_wire::frame::{IPC_WIRE_VERSION, WireFrame, WirePayload, embedded_max_frame_bytes};
use grdr_wire::limits::embedded_limits;
use grdr_wire::messages::{
    BundleLoadFrame, ChannelProfileKind, EndpointServiceKind, EngineForwardFrame,
    EngineResultFrame, HeartbeatFrame, HelloFrame, UpdaterCommandFrame, UplinkCommandFrame,
};
use grdr_wire::peer_auth::{
    AuthenticatedChannel, ClientIdentityPolicy, OsPeerClaims, Profile, open,
};
use jiff::Timestamp;
use thiserror::Error;

use crate::child_loop::build_child_command;
use crate::ladder_codec::{load_ladder_state, persist_ladder_state};

pub const MAX_ENGINE_QUEUE_DEPTH: u32 = 64;
const MAX_CREDIT_SKIP_FRAMES: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SupervisorError {
    #[error("GRDR-DAEM-0005: supervised child lifecycle error: {0}")]
    ChildError(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChildRole {
    Engine,
    Uplink,
    Updater,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryRungs {
    pub soft_mb: u32,
    pub restart_mb: u32,
    pub hard_mb: u32,
}

#[derive(Clone, Debug)]
pub struct RestartSpec {
    pub role: ChildRole,
    pub bin_path: PathBuf,
    pub extra_args: Vec<String>,
    pub work_dir: PathBuf,
    pub ladder_path: PathBuf,
    pub protected_profile: bool,
}

pub struct SupervisedChild {
    pub role: ChildRole,
    pub ladder_path: PathBuf,
    pub child: Child,
    pub channel: AuthenticatedChannel<ProtoIpcStream<DuplexPipe<ChildStdout, ChildStdin>>>,
    pub monitor: ChildHeartbeatMonitor,
    pub ladder: CrashLoopLadder,
    pub memory_rungs: MemoryRungs,
    pub last_rss_bytes: u64,
    pub queue_depth: u32,
    pub unhealthy_reason: Option<String>,
    pub sandbox_partial_reason: Option<String>,
    crash_epochs_s: Vec<i64>,
}

impl ChildRole {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Engine => "grdr-engine",
            Self::Uplink => "grdr-uplink",
            Self::Updater => "grdr-updater",
        }
    }

    #[must_use]
    pub const fn service_kind(self) -> EndpointServiceKind {
        match self {
            Self::Engine => EndpointServiceKind::ProviderEngine,
            Self::Uplink => EndpointServiceKind::ProviderUplink,
            Self::Updater => EndpointServiceKind::ProviderUpdater,
        }
    }
}

impl MemoryRungs {
    #[must_use]
    pub fn for_role(role: ChildRole) -> Self {
        let soft_mb = match embedded_limits() {
            Ok(cfg) => match role {
                ChildRole::Engine => cfg.engine_memory_mb,
                ChildRole::Uplink => cfg.uplink_memory_mb,
                ChildRole::Updater => cfg.updater_memory_mb,
            },
            Err(_) => 32,
        };
        let hard_mb = soft_mb
            .saturating_mul(15)
            .saturating_add(9)
            .saturating_div(10)
            .max(16);
        let restart_mb = if role == ChildRole::Engine {
            soft_mb
                .saturating_mul(13)
                .saturating_add(9)
                .saturating_div(10)
                .max(16)
        } else {
            hard_mb
        };
        Self {
            soft_mb,
            restart_mb,
            hard_mb,
        }
    }

    #[must_use]
    pub const fn soft_bytes(self) -> u64 {
        (self.soft_mb as u64).saturating_mul(1024 * 1024)
    }

    #[must_use]
    pub const fn restart_bytes(self) -> u64 {
        (self.restart_mb as u64).saturating_mul(1024 * 1024)
    }

    #[must_use]
    pub const fn hard_bytes(self) -> u64 {
        (self.hard_mb as u64).saturating_mul(1024 * 1024)
    }
}

impl Drop for SupervisedChild {
    fn drop(&mut self) {
        self.kill_and_wait();
    }
}

impl SupervisedChild {
    pub fn spawn(spec: &RestartSpec, now: Timestamp) -> Result<Self, SupervisorError> {
        let (mut cmd, sandbox_partial_reason) = build_child_command(spec)?;
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|err| {
                SupervisorError::ChildError(format!(
                    "spawn {} ({}): {err}",
                    spec.role.name(),
                    redact_path_label(&spec.bin_path)
                ))
            })?;
        let child_pid = child.id();
        let child_stdin = child
            .stdin
            .take()
            .ok_or_else(|| SupervisorError::ChildError("missing child stdin".to_string()))?;
        let child_stdout = child
            .stdout
            .take()
            .ok_or_else(|| SupervisorError::ChildError("missing child stdout".to_string()))?;

        let stream = ProtoIpcStream::with_timeouts(
            DuplexPipe::new(child_stdout, child_stdin),
            Duration::from_millis(1_500),
            Duration::from_millis(1_500),
        );
        let max_bytes = embedded_max_frame_bytes()
            .map_err(|e| SupervisorError::ChildError(format!("embedded limits failed: {e}")))?;
        let mut nonce = [0u8; 32];
        grdr_wire::fill_random_bytes(&mut nonce)
            .map_err(|err| SupervisorError::ChildError(format!("child nonce RNG: {err}")))?;

        let (channel, _ready) = open(
            stream,
            &OsPeerClaims::Inherited,
            0,
            &ClientIdentityPolicy {
                profile: Profile::Inherited,
                allowed_server_uids: vec![],
                expected_windows_sids: vec![],
                minimum_integrity_rid: 0,
                require_start_time_before_connect: false,
                require_kernel_peer_token: false,
            },
            HelloFrame {
                protocol_version: IPC_WIRE_VERSION,
                service: spec.role.service_kind() as i32,
                profile: ChannelProfileKind::Inherited as i32,
                client_nonce: nonce.to_vec(),
                pid: std::process::id(),
                capabilities: vec![spec.role.name().to_string()],
            },
            max_bytes,
        )
        .map_err(|err| {
            let _ = child.kill();
            let _ = child.wait();
            SupervisorError::ChildError(format!(
                "handshake with {} failed: {err}",
                spec.role.name()
            ))
        })?;

        let mut monitor = ChildHeartbeatMonitor::new(spec.role.name(), now);
        monitor.mark_running(child_pid, now);
        let (ladder, crash_epochs_s) = load_ladder_state(&spec.ladder_path, now);

        Ok(Self {
            role: spec.role,
            ladder_path: spec.ladder_path.clone(),
            child,
            channel,
            monitor,
            ladder,
            memory_rungs: MemoryRungs::for_role(spec.role),
            last_rss_bytes: 0,
            queue_depth: 0,
            unhealthy_reason: None,
            sandbox_partial_reason,
            crash_epochs_s,
        })
    }

    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.unhealthy_reason.is_none()
            && matches!(self.monitor.lifecycle(), ChildLifecycle::Running { .. })
    }

    pub fn heartbeat_tick(
        &mut self,
        seq: u64,
        mono_ms: u64,
        epoch: u64,
        now: Timestamp,
    ) -> Result<bool, SupervisorError> {
        if let Ok(Some(status)) = self.child.try_wait() {
            self.unhealthy_reason = Some(format!("child-exited:{status}"));
            return Ok(false);
        }
        let ping = WireFrame::with_payload(
            1,
            0,
            WirePayload::Heartbeat(HeartbeatFrame {
                seq,
                monotonic_ms: mono_ms,
                rss_bytes: 0,
                queue_depth: self.queue_depth,
                epoch,
            }),
        );
        if self.channel.send_frame(ping).is_err() {
            return Ok(self.record_missed_heartbeat(now));
        }
        match recv_non_credit(&mut self.channel) {
            Ok(WireFrame {
                payload: Some(WirePayload::Heartbeat(hb)),
                ..
            }) if hb.seq == seq => {
                self.monitor.record_heartbeat(now);
                let _ = self.ladder.tick_stability(now);
                let os_rss = child_process_rss_bytes(&self.child);
                self.last_rss_bytes = match os_rss {
                    Some(kernel_bytes) => kernel_bytes.max(hb.rss_bytes),
                    None => hb.rss_bytes,
                };
                self.queue_depth = hb.queue_depth;
                Ok(self.check_rss_rungs_and_enforce())
            }
            Ok(WireFrame {
                payload: Some(WirePayload::Heartbeat(hb)),
                ..
            }) => {
                self.unhealthy_reason = Some(format!("hb-seq-mismatch:{seq}-{}", hb.seq));
                self.kill_and_wait();
                Ok(false)
            }
            _ => Ok(self.record_missed_heartbeat(now)),
        }
    }

    pub fn send_bundle(&mut self, bundle: BundleLoadFrame) -> Result<(), SupervisorError> {
        let frame = WireFrame::with_payload(1, 0, WirePayload::BundleLoad(bundle));
        self.channel
            .send_frame(frame)
            .map_err(|err| SupervisorError::ChildError(err.to_string()))
    }

    pub fn forward_to_engine(
        &mut self,
        fwd: EngineForwardFrame,
    ) -> Result<EngineResultFrame, SupervisorError> {
        if !self.is_healthy() || self.queue_depth >= MAX_ENGINE_QUEUE_DEPTH {
            return Err(SupervisorError::ChildError("overload".to_string()));
        }
        let expected_req_id = fwd.request_id.clone();
        let expected_attempt_id = fwd.attempt_id.clone();
        self.queue_depth = self.queue_depth.saturating_add(1);
        let req_frame = WireFrame::with_payload(1, 0, WirePayload::EngineForward(fwd));
        if let Err(err) = self.channel.send_frame(req_frame) {
            self.queue_depth = self.queue_depth.saturating_sub(1);
            self.unhealthy_reason = Some("engine-pipe-send-failed".to_string());
            self.kill_and_wait();
            return Err(SupervisorError::ChildError(err.to_string()));
        }
        let reply = recv_non_credit(&mut self.channel);
        self.queue_depth = self.queue_depth.saturating_sub(1);
        match reply {
            Ok(WireFrame {
                payload: Some(WirePayload::EngineResult(res)),
                ..
            }) => {
                if res.request_id != expected_req_id || res.attempt_id != expected_attempt_id {
                    self.unhealthy_reason = Some("engine-stream-desync".to_string());
                    self.kill_and_wait();
                    return Err(SupervisorError::ChildError(
                        "engine reply correlation mismatch".to_string(),
                    ));
                }
                Ok(res)
            }
            Ok(other) => {
                self.unhealthy_reason = Some("engine-unexpected-frame".to_string());
                self.kill_and_wait();
                Err(SupervisorError::ChildError(format!(
                    "unexpected reply from engine: {:?}",
                    other.payload.is_some()
                )))
            }
            Err(err) => {
                self.unhealthy_reason = Some("engine-reply-timeout-or-eof".to_string());
                self.kill_and_wait();
                Err(SupervisorError::ChildError(err))
            }
        }
    }

    pub fn send_uplink_command(
        &mut self,
        cmd: UplinkCommandFrame,
    ) -> Result<WireFrame, SupervisorError> {
        let expected_id = cmd.command_id.clone();
        let frame = WireFrame::with_payload(1, 0, WirePayload::UplinkCommand(cmd));
        self.channel
            .send_frame(frame)
            .map_err(|err| SupervisorError::ChildError(err.to_string()))?;
        let reply = recv_non_credit(&mut self.channel).map_err(|err| {
            self.unhealthy_reason = Some("uplink-reply-failed".to_string());
            self.kill_and_wait();
            SupervisorError::ChildError(err)
        })?;
        if let Some(WirePayload::UplinkEvent(ref ev)) = reply.payload
            && !ev.command_id.is_empty()
            && ev.command_id != expected_id
        {
            self.unhealthy_reason = Some("uplink-command-id-mismatch".to_string());
            self.kill_and_wait();
            return Err(SupervisorError::ChildError(
                "uplink response command_id mismatch".to_string(),
            ));
        }
        Ok(reply)
    }

    pub fn send_updater_command(
        &mut self,
        cmd: UpdaterCommandFrame,
    ) -> Result<WireFrame, SupervisorError> {
        let expected_id = cmd.command_id.clone();
        let frame = WireFrame::with_payload(1, 0, WirePayload::UpdaterCommand(cmd));
        self.channel
            .send_frame(frame)
            .map_err(|err| SupervisorError::ChildError(err.to_string()))?;
        let reply = recv_non_credit(&mut self.channel).map_err(|err| {
            self.unhealthy_reason = Some("updater-reply-failed".to_string());
            self.kill_and_wait();
            SupervisorError::ChildError(err)
        })?;
        if let Some(WirePayload::UpdaterEvent(ref ev)) = reply.payload
            && !ev.command_id.is_empty()
            && ev.command_id != expected_id
        {
            self.unhealthy_reason = Some("updater-command-id-mismatch".to_string());
            self.kill_and_wait();
            return Err(SupervisorError::ChildError(
                "updater response command_id mismatch".to_string(),
            ));
        }
        Ok(reply)
    }

    pub fn kill_and_wait(&mut self) {
        if let Err(err) = self.child.kill() {
            let still_running = self.child.try_wait().ok().flatten().is_none();
            if still_running {
                tracing::warn!(role = self.role.name(), error = %err, "failed to kill child");
            }
        }
        if let Err(err) = self.child.wait() {
            tracing::warn!(role = self.role.name(), error = %err, "failed waiting on child exit");
        }
    }

    pub fn record_crash_event(
        &mut self,
        now: Timestamp,
        active_digests: &[String],
    ) -> HealthTransitionEvent {
        self.crash_epochs_s.push(now.as_second());
        if self.crash_epochs_s.len() > 32 {
            let excess = self.crash_epochs_s.len().saturating_sub(32);
            self.crash_epochs_s.drain(..excess);
        }
        let ev = self.ladder.record_engine_crash(now, active_digests);
        if let Err(err) =
            persist_ladder_state(&self.ladder_path, &self.ladder, &self.crash_epochs_s)
        {
            tracing::warn!(error = %err, "failed persisting crash ladder state");
        }
        ev
    }

    fn record_missed_heartbeat(&mut self, now: Timestamp) -> bool {
        let decision = self.monitor.tick_missed_heartbeat(now);
        if decision.should_kill_and_restart {
            self.unhealthy_reason = Some(
                decision
                    .health_condition
                    .unwrap_or("child-unresponsive")
                    .to_string(),
            );
            self.kill_and_wait();
            return false;
        }
        true
    }

    fn check_rss_rungs_and_enforce(&mut self) -> bool {
        let hard_bytes = self.memory_rungs.hard_bytes();
        let restart_bytes = self.memory_rungs.restart_bytes();
        let soft_bytes = self.memory_rungs.soft_bytes();
        if self.last_rss_bytes > hard_bytes {
            self.unhealthy_reason = Some("rss-hard-limit".to_string());
            self.kill_and_wait();
            return false;
        }
        if self.role == ChildRole::Engine && self.last_rss_bytes > restart_bytes {
            self.unhealthy_reason = Some("rss-soft-restart-1.3x".to_string());
            self.kill_and_wait();
            return false;
        }
        if self.last_rss_bytes > soft_bytes {
            tracing::warn!(
                role = self.role.name(),
                rss_bytes = self.last_rss_bytes,
                soft_bytes,
                "child RSS crossed soft memory rung"
            );
        }
        true
    }
}

fn recv_non_credit<S: grdr_wire::peer_auth::FrameStream>(
    chan: &mut AuthenticatedChannel<S>,
) -> Result<WireFrame, String> {
    for _ in 0..MAX_CREDIT_SKIP_FRAMES {
        let frame = chan.recv_frame().map_err(|e| e.to_string())?;
        if matches!(frame.payload, Some(WirePayload::CreditGrant(_))) {
            continue;
        }
        return Ok(frame);
    }
    Err("child credit frame flood".to_string())
}
