// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! `<= 2s` (`1,800ms` bounded window) atomic handover marker coordination and
//! `--self-test` verification for `grdr-updater` (`D-11`).

use std::path::{Path, PathBuf};

use grdr_os_clock::Clock;
use grdr_update::{UpdateSlot, canonical_sha256};
use serde::{Deserialize, Serialize};

use crate::error::UpdaterError;
use crate::fs_safe::{
    atomic_write_bytes, confine_path_under_root, ensure_safe_dir, read_bounded_bytes,
};

/// Default handover retry ceiling matching the shim retry window (`1,800ms < 2,000ms` SLA).
pub const DEFAULT_HANDOVER_WINDOW_MS: u64 = 1_800;
/// Hard ceiling beyond which a handover marker violates the `<= 2s` outage budget.
pub const MAX_HANDOVER_WINDOW_MS: u64 = 2_000;
const MAX_HANDOVER_MARKER_BYTES: u64 = 65_536;
const MAX_HANDOVER_BINARY_BYTES: u64 = 134_217_728;

/// Explicit handover lifecycle status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandoverMarkerStatus {
    Active,
    Consumed,
}

/// On-disk `state/handover` marker coordinating binary swap within `<= 2s`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoverMarker {
    pub version: u32,
    pub marker_status: HandoverMarkerStatus,
    pub target_slot: UpdateSlot,
    pub target_binary_path: PathBuf,
    pub target_sha256: String,
    pub created_mono_ms: u64,
    pub expires_mono_ms: u64,
    pub issued_wall_unix_ms: i64,
    pub expires_wall_unix_ms: i64,
}

/// Coordinates atomic `state/handover` marker creation and verification inside `state_root`.
#[derive(Clone, Debug)]
pub struct HandoverCoordinator {
    state_root: PathBuf,
    marker_path: PathBuf,
}

impl HandoverCoordinator {
    /// Bind handover coordinator to `<state_root>/handover`.
    #[must_use]
    pub fn new(state_root: &Path) -> Self {
        Self {
            state_root: state_root.to_path_buf(),
            marker_path: state_root.join("handover"),
        }
    }

    /// Write a bounded `<= 2s` `state/handover` marker confined inside `state_root`.
    pub fn prepare_handover(
        &self,
        target_slot: UpdateSlot,
        target_binary_path: &Path,
        expected_sha256: &str,
        window_ms: u64,
        clock: &dyn Clock,
    ) -> Result<HandoverMarker, UpdaterError> {
        if window_ms == 0 || window_ms > MAX_HANDOVER_WINDOW_MS {
            return Err(UpdaterError::HandoverInvalid {
                detail: format!(
                    "handover window {window_ms}ms violates 1..={MAX_HANDOVER_WINDOW_MS}ms SLA"
                ),
            });
        }
        validate_sha256_hex(expected_sha256)?;
        ensure_safe_dir(&self.state_root)?;
        let canonical_root =
            std::fs::canonicalize(&self.state_root).map_err(|e| UpdaterError::Io {
                detail: format!("failed to canonicalize state root: {e}"),
            })?;
        let confined_bin = confine_path_under_root(&canonical_root, target_binary_path)?;

        let binary_bytes = read_bounded_bytes(&confined_bin, MAX_HANDOVER_BINARY_BYTES)?;
        let actual_sha256 = canonical_sha256(&binary_bytes);
        if actual_sha256 != expected_sha256 {
            return Err(UpdaterError::HandoverInvalid {
                detail: format!(
                    "handover binary digest mismatch (expected {expected_sha256}, got {actual_sha256})"
                ),
            });
        }

        let now_mono_ms = boot_mono_ms(clock)?;
        let issued_wall_unix_ms = clock
            .now_wall()
            .map_err(|e| UpdaterError::ClockFailed {
                detail: e.to_string(),
            })?
            .as_millisecond();
        let window_i64 = i64::try_from(window_ms).unwrap_or(2_000);

        let marker = HandoverMarker {
            version: 1,
            marker_status: HandoverMarkerStatus::Active,
            target_slot,
            target_binary_path: confined_bin,
            target_sha256: actual_sha256,
            created_mono_ms: now_mono_ms,
            expires_mono_ms: now_mono_ms.saturating_add(window_ms),
            issued_wall_unix_ms,
            expires_wall_unix_ms: issued_wall_unix_ms.saturating_add(window_i64),
        };
        let encoded = serde_json::to_vec_pretty(&marker).map_err(|e| UpdaterError::Io {
            detail: format!("failed to serialize handover marker: {e}"),
        })?;
        atomic_write_bytes(&self.marker_path, &encoded)?;
        Ok(marker)
    }

    /// Validate an active `state/handover` marker across reboot-safe monotonic + wall bounds and consume once.
    pub fn validate_and_consume(&self, clock: &dyn Clock) -> Result<HandoverMarker, UpdaterError> {
        ensure_safe_dir(&self.state_root)?;
        let canonical_root =
            std::fs::canonicalize(&self.state_root).map_err(|e| UpdaterError::Io {
                detail: format!("failed to canonicalize state root: {e}"),
            })?;
        let confined_marker = confine_path_under_root(&canonical_root, &self.marker_path)?;
        let raw = read_bounded_bytes(&confined_marker, MAX_HANDOVER_MARKER_BYTES).map_err(|e| {
            UpdaterError::HandoverInvalid {
                detail: format!("missing or unreadable handover marker: {e}"),
            }
        })?;
        let mut marker: HandoverMarker =
            serde_json::from_slice(&raw).map_err(|e| UpdaterError::HandoverInvalid {
                detail: format!("corrupt handover marker: {e}"),
            })?;

        validate_sha256_hex(&marker.target_sha256)?;
        if marker.marker_status != HandoverMarkerStatus::Active {
            return Err(UpdaterError::HandoverInvalid {
                detail: "handover marker already consumed".to_string(),
            });
        }
        let duration = marker
            .expires_mono_ms
            .saturating_sub(marker.created_mono_ms);
        let wall_duration = marker
            .expires_wall_unix_ms
            .saturating_sub(marker.issued_wall_unix_ms);
        if duration == 0
            || duration > MAX_HANDOVER_WINDOW_MS
            || wall_duration <= 0
            || wall_duration > i64::try_from(MAX_HANDOVER_WINDOW_MS).unwrap_or(2_000)
        {
            return Err(UpdaterError::HandoverInvalid {
                detail: format!(
                    "handover marker window {duration}ms violates {MAX_HANDOVER_WINDOW_MS}ms SLA"
                ),
            });
        }

        let now_mono_ms = boot_mono_ms(clock)?;
        if now_mono_ms < marker.created_mono_ms || now_mono_ms > marker.expires_mono_ms {
            return Err(UpdaterError::HandoverInvalid {
                detail: format!(
                    "handover marker outside monotonic window ({}..={}, now {now_mono_ms}ms)",
                    marker.created_mono_ms, marker.expires_mono_ms
                ),
            });
        }
        let now_wall_ms = clock
            .now_wall()
            .map_err(|e| UpdaterError::ClockFailed {
                detail: e.to_string(),
            })?
            .as_millisecond();
        if now_wall_ms < marker.issued_wall_unix_ms || now_wall_ms > marker.expires_wall_unix_ms {
            return Err(UpdaterError::HandoverInvalid {
                detail: format!(
                    "handover marker expired by wall clock ({} > {})",
                    now_wall_ms, marker.expires_wall_unix_ms
                ),
            });
        }

        let confined_bin = confine_path_under_root(&canonical_root, &marker.target_binary_path)?;
        let bin_bytes =
            read_bounded_bytes(&confined_bin, MAX_HANDOVER_BINARY_BYTES).map_err(|e| {
                UpdaterError::HandoverInvalid {
                    detail: format!("target binary unreadable during handover: {e}"),
                }
            })?;
        let actual_sha = canonical_sha256(&bin_bytes);
        if actual_sha != marker.target_sha256 {
            return Err(UpdaterError::HandoverInvalid {
                detail: "target binary digest changed prior to handover completion".to_string(),
            });
        }

        marker.marker_status = HandoverMarkerStatus::Consumed;
        let encoded = serde_json::to_vec_pretty(&marker).map_err(|e| UpdaterError::Io {
            detail: format!("failed to update handover marker: {e}"),
        })?;
        atomic_write_bytes(&self.marker_path, &encoded)?;
        Ok(marker)
    }
}

/// Deterministic fast `--self-test` validating `grdr-compat` + clock health.
pub fn run_updater_self_test(clock: &dyn Clock) -> Result<(), UpdaterError> {
    let _mono = boot_mono_ms(clock)?;
    let _wall = clock.now_wall().map_err(|e| UpdaterError::ClockFailed {
        detail: e.to_string(),
    })?;
    let _matrix = grdr_compat::CompatMatrix::default_v1();
    Ok(())
}

fn boot_mono_ms(clock: &dyn Clock) -> Result<u64, UpdaterError> {
    let uptime = clock.boot_uptime().map_err(|e| UpdaterError::ClockFailed {
        detail: e.to_string(),
    })?;
    Ok(u64::try_from(uptime.as_millis()).unwrap_or(u64::MAX))
}

fn validate_sha256_hex(sha256: &str) -> Result<(), UpdaterError> {
    if sha256.len() != 64
        || !sha256
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(UpdaterError::HandoverInvalid {
            detail: format!("invalid SHA-256 hex digest '{sha256}'"),
        });
    }
    Ok(())
}
