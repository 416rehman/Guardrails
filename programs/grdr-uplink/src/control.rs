// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Hybrid `Subscribe` + `Wait` command channel state machine (with monotonic
//! generation replay floors) and streaming opaque artifact staging (`D-22`).

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{Read as _, Write as _};
use std::path::PathBuf;

use grdr_crypto::Sha256Hasher;
use serde::{Deserialize, Serialize};

use crate::error::{OfflineReason, UplinkError};
use crate::staging_fs::{
    ensure_ancestors_safe, ensure_not_symlink_if_exists, open_part_nofollow_append,
    open_regular_nofollow_read,
};

/// Initial `Subscribe` heartbeat interval (25s).
pub const SUBSCRIBE_MIN_HEARTBEAT_MS: u64 = 25_000;
/// Maximum learned `Subscribe` heartbeat interval (55s) matching NAT/proxy timeouts.
pub const SUBSCRIBE_MAX_HEARTBEAT_MS: u64 = 55_000;
/// Step increment when consecutive `Subscribe` beats succeed cleanly (5s).
pub const SUBSCRIBE_STEP_UP_MS: u64 = 5_000;
/// Consecutive missed heartbeats before dropping back to HTTP `Wait` long-poll.
pub const SUBSCRIBE_MISSED_BEAT_FALLBACK: u32 = 2;
/// Standard HTTP long-poll hold duration (`Wait`).
pub const LONG_POLL_WAIT_MS: u64 = 55_000;
/// Maximum deduplication window kept for recently executed command IDs.
pub const COMMAND_DEDUP_CAP: usize = 2_048;
/// Fixed streaming read buffer size (64 KiB) keeping `grdr-uplink` memory well under 20 MiB.
const STREAM_HASH_CHUNK_BYTES: usize = 65_536;

/// Explicit control channel state machine (`Subscribe` fast-path + `Wait` durability guarantee).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControlChannelState {
    Disconnected,
    StreamingSubscribe {
        cell_id: String,
        learned_heartbeat_ms: u64,
        last_beat_mono_ms: u64,
        missed_beats: u32,
    },
    LongPollWait {
        cell_id: String,
        wait_ms: u64,
        started_mono_ms: u64,
    },
    Backoff {
        attempt: u32,
        next_retry_mono_ms: u64,
        reason: OfflineReason,
    },
}

/// Command action dispatched from control plane `PendingCommands` or `Subscribe` nudge.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandAction {
    KillSwitch,
    RevokeGrant,
    QuarantineMode,
    UpdateAvailable,
    FlushSpool,
}

/// Verified server command awaiting dispatch to `grdr-daemon` or `grdr-updater`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingCommand {
    pub command_id: String,
    pub generation: u64,
    pub ttl_expires_unix_s: i64,
    pub action: CommandAction,
    pub payload_json: String,
}

/// Opaque staged artifact metadata handed to `grdr-updater` for TUF/DSSE/slot verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagedArtifact {
    pub path: PathBuf,
    pub expected_sha256: String,
    pub byte_len: u64,
}

/// Tracks active `Subscribe`/`Wait` channel state, TTLs, and monotonic replay floors.
#[derive(Clone, Debug)]
pub struct ControlChannel {
    channel_state: ControlChannelState,
    learned_heartbeat_ms: u64,
    seen_ids_order: VecDeque<String>,
    seen_ids_set: BTreeSet<String>,
    min_generation_floors: BTreeMap<CommandAction, u64>,
}

/// Stages opaque artifact bytes to disk with streaming SHA-256 verification and `Range` resume.
#[derive(Clone, Debug)]
pub struct OpaqueArtifactStager {
    staging_root: PathBuf,
}

impl ControlChannel {
    /// Start disconnected with baseline `25s` `Subscribe` heartbeat probe interval.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            channel_state: ControlChannelState::Disconnected,
            learned_heartbeat_ms: SUBSCRIBE_MIN_HEARTBEAT_MS,
            seen_ids_order: VecDeque::new(),
            seen_ids_set: BTreeSet::new(),
            min_generation_floors: BTreeMap::new(),
        }
    }

    /// Enter `Subscribe` streaming mode for `cell_id`.
    pub fn enter_subscribe(&mut self, cell_id: impl Into<String>, now_mono_ms: u64) {
        self.channel_state = ControlChannelState::StreamingSubscribe {
            cell_id: cell_id.into(),
            learned_heartbeat_ms: self.learned_heartbeat_ms,
            last_beat_mono_ms: now_mono_ms,
            missed_beats: 0,
        };
    }

    /// Enter `Wait` long-poll mode for `cell_id`.
    pub fn enter_long_poll_wait(&mut self, cell_id: impl Into<String>, now_mono_ms: u64) {
        self.channel_state = ControlChannelState::LongPollWait {
            cell_id: cell_id.into(),
            wait_ms: LONG_POLL_WAIT_MS,
            started_mono_ms: now_mono_ms,
        };
    }

    /// Record a successful `Subscribe` heartbeat and gradually learn up to `55s`.
    pub fn record_subscribe_beat(&mut self, now_mono_ms: u64) {
        if let ControlChannelState::StreamingSubscribe {
            learned_heartbeat_ms,
            last_beat_mono_ms,
            missed_beats,
            ..
        } = &mut self.channel_state
        {
            *last_beat_mono_ms = now_mono_ms;
            *missed_beats = 0;
            let next = learned_heartbeat_ms
                .saturating_add(SUBSCRIBE_STEP_UP_MS)
                .min(SUBSCRIBE_MAX_HEARTBEAT_MS);
            *learned_heartbeat_ms = next;
            self.learned_heartbeat_ms = next;
        }
    }

    /// Advance stream timer; drops to `LongPollWait` after 2 missed beats (`Subscribe` fallback).
    pub fn check_subscribe_health(&mut self, now_mono_ms: u64) -> &ControlChannelState {
        let transition_to_wait = match &mut self.channel_state {
            ControlChannelState::StreamingSubscribe {
                cell_id,
                learned_heartbeat_ms,
                last_beat_mono_ms,
                missed_beats,
            } => {
                let elapsed = now_mono_ms.saturating_sub(*last_beat_mono_ms);
                if elapsed >= *learned_heartbeat_ms {
                    *missed_beats = missed_beats.saturating_add(1);
                    *last_beat_mono_ms = now_mono_ms;
                    if *missed_beats >= SUBSCRIBE_MISSED_BEAT_FALLBACK {
                        self.learned_heartbeat_ms = SUBSCRIBE_MIN_HEARTBEAT_MS;
                        Some(cell_id.clone())
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            _ => None,
        };

        if let Some(cell_id) = transition_to_wait {
            self.enter_long_poll_wait(cell_id, now_mono_ms);
        }
        &self.channel_state
    }

    /// Move into exponential backoff on transport failure.
    pub fn enter_backoff(&mut self, attempt: u32, next_retry_mono_ms: u64, reason: OfflineReason) {
        self.channel_state = ControlChannelState::Backoff {
            attempt,
            next_retry_mono_ms,
            reason,
        };
    }

    /// Filter incoming commands by expiry, dedup cache, and per-action monotonic generation floor.
    pub fn accept_commands(
        &mut self,
        incoming: Vec<PendingCommand>,
        trusted_now_unix_s: i64,
    ) -> Vec<PendingCommand> {
        let mut accepted = Vec::new();
        for cmd in incoming {
            if cmd.command_id.trim().is_empty() || trusted_now_unix_s > cmd.ttl_expires_unix_s {
                continue;
            }
            if is_high_impact_monotonic(cmd.action)
                && let Some(&floor) = self.min_generation_floors.get(&cmd.action)
                && cmd.generation <= floor
            {
                continue;
            }
            if !self.seen_ids_set.insert(cmd.command_id.clone()) {
                continue;
            }
            self.seen_ids_order.push_back(cmd.command_id.clone());
            if self.seen_ids_order.len() > COMMAND_DEDUP_CAP
                && let Some(evicted) = self.seen_ids_order.pop_front()
            {
                self.seen_ids_set.remove(&evicted);
            }
            if is_high_impact_monotonic(cmd.action) {
                let entry = self.min_generation_floors.entry(cmd.action).or_insert(0);
                *entry = (*entry).max(cmd.generation);
            }
            accepted.push(cmd);
        }
        accepted.sort_by_key(|c| (c.action, c.generation));
        accepted
    }

    /// Read current explicit control channel state.
    #[must_use]
    pub const fn state(&self) -> &ControlChannelState {
        &self.channel_state
    }
}

impl Default for ControlChannel {
    fn default() -> Self {
        Self::new()
    }
}

impl OpaqueArtifactStager {
    /// Bind stager strictly to `staging_root`.
    pub fn new(staging_root: PathBuf) -> Self {
        Self { staging_root }
    }

    /// Compute deterministic resume offset for an existing non-symlink `.part` file.
    pub fn resume_offset(&self, expected_sha256: &str) -> Result<u64, UplinkError> {
        validate_sha256_hex(expected_sha256)?;
        ensure_ancestors_safe(&self.staging_root)?;
        ensure_not_symlink_if_exists(&self.staging_root)?;
        let part_path = self.part_path(expected_sha256);
        if !part_path.exists() {
            return Ok(0);
        }
        let (_file, fd_meta) = open_regular_nofollow_read(&part_path)?;
        Ok(fd_meta.len())
    }

    /// Append a verified byte range to `<staging_root>/<sha256>.part`, enforcing `declared_max_bytes`.
    pub fn write_chunk(
        &self,
        expected_sha256: &str,
        offset: u64,
        chunk: &[u8],
        declared_max_bytes: u64,
    ) -> Result<u64, UplinkError> {
        validate_sha256_hex(expected_sha256)?;
        ensure_ancestors_safe(&self.staging_root)?;
        std::fs::create_dir_all(&self.staging_root).map_err(|e| UplinkError::Io {
            detail: format!("failed to create staging root: {e}"),
        })?;
        ensure_not_symlink_if_exists(&self.staging_root)?;

        let part_path = self.part_path(expected_sha256);
        let (mut file, fd_meta) = open_part_nofollow_append(&part_path)?;

        let current_len = fd_meta.len();
        if offset != current_len {
            return Err(UplinkError::StagingError {
                detail: format!("resume offset mismatch: expected {current_len}, got {offset}"),
            });
        }
        let chunk_len = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
        let next_len = current_len.saturating_add(chunk_len);
        if next_len > declared_max_bytes {
            return Err(UplinkError::StagingError {
                detail: format!(
                    "staged download {next_len} exceeds TUF declared byte limit {declared_max_bytes}"
                ),
            });
        }

        file.write_all(chunk).map_err(|e| UplinkError::Io {
            detail: format!("failed to write staged chunk: {e}"),
        })?;
        file.sync_all().map_err(|e| UplinkError::Io {
            detail: format!("failed to flush staged chunk: {e}"),
        })?;
        Ok(next_len)
    }

    /// Stream-hash `.part` in bounded 64 KiB chunks (constant memory), verify SHA-256, and promote atomically.
    pub fn finalize(
        &self,
        expected_sha256: &str,
        declared_max_bytes: u64,
    ) -> Result<StagedArtifact, UplinkError> {
        validate_sha256_hex(expected_sha256)?;
        ensure_ancestors_safe(&self.staging_root)?;
        ensure_not_symlink_if_exists(&self.staging_root)?;
        let part_path = self.part_path(expected_sha256);
        let (mut file, _fd_meta) = open_regular_nofollow_read(&part_path)?;

        let mut hasher = Sha256Hasher::new();
        let mut buf = [0u8; STREAM_HASH_CHUNK_BYTES];
        let mut byte_len: u64 = 0;
        loop {
            let n = file.read(&mut buf).map_err(|e| UplinkError::Io {
                detail: format!("failed to read partial staged artifact: {e}"),
            })?;
            if n == 0 {
                break;
            }
            let n_u64 = u64::try_from(n).unwrap_or(u64::MAX);
            byte_len = byte_len.saturating_add(n_u64);
            if byte_len > declared_max_bytes {
                return Err(UplinkError::StagingError {
                    detail: format!(
                        "staged artifact size {byte_len} exceeds TUF declared limit {declared_max_bytes}"
                    ),
                });
            }
            if let Some(chunk) = buf.get(..n) {
                hasher.update(chunk);
            }
        }
        drop(file);

        let actual_hex = hasher.finalize_hex();
        if actual_hex != expected_sha256 {
            return Err(UplinkError::StagingError {
                detail: format!(
                    "staged SHA-256 mismatch (expected {expected_sha256}, got {actual_hex})"
                ),
            });
        }

        let final_path = self.final_path(expected_sha256);
        ensure_not_symlink_if_exists(&final_path)?;
        std::fs::rename(&part_path, &final_path).map_err(|e| UplinkError::Io {
            detail: format!(
                "failed to promote staged artifact {}: {e}",
                final_path.display()
            ),
        })?;
        Ok(StagedArtifact {
            path: final_path,
            expected_sha256: expected_sha256.to_string(),
            byte_len,
        })
    }

    fn part_path(&self, sha256: &str) -> PathBuf {
        self.staging_root.join(format!("{sha256}.part"))
    }

    fn final_path(&self, sha256: &str) -> PathBuf {
        self.staging_root.join(format!("{sha256}.staged"))
    }
}

const fn is_high_impact_monotonic(action: CommandAction) -> bool {
    matches!(
        action,
        CommandAction::KillSwitch | CommandAction::RevokeGrant | CommandAction::QuarantineMode
    )
}

fn validate_sha256_hex(sha256: &str) -> Result<(), UplinkError> {
    if sha256.len() != 64
        || !sha256
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(UplinkError::StagingError {
            detail: format!("expected 64 lowercase hex characters for digest, got '{sha256}'"),
        });
    }
    Ok(())
}
