// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Coded error types for `grdr-updater`.

use thiserror::Error;

/// Coded errors produced by `grdr-updater`.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum UpdaterError {
    #[error("[GRDR-UPDATER-0001] TUF or DSSE verification failed: {detail}")]
    TufVerification { detail: String },

    #[error("[GRDR-UPDATER-0002] compatibility gate rejected {component} ({code}): {reason}")]
    CompatibilityRejected {
        component: String,
        code: String,
        reason: String,
    },

    #[error("[GRDR-UPDATER-0003] pack {channel} contains forbidden field {field}")]
    ForbiddenField { channel: String, field: String },

    #[error(
        "[GRDR-UPDATER-0004] pack {channel} exceeds byte budget ({actual_bytes} > {max_bytes})"
    )]
    BudgetExceeded {
        channel: String,
        actual_bytes: u64,
        max_bytes: u64,
    },

    #[error("[GRDR-UPDATER-0005] update authority {authority} disallows {action}")]
    AuthorityDisallowed { authority: String, action: String },

    #[error(
        "[GRDR-UPDATER-0006] candidate generation {candidate_generation} violates security floor {current_floor}"
    )]
    SecurityFloorViolation {
        current_floor: u64,
        candidate_generation: u64,
    },

    #[error("[GRDR-UPDATER-0007] invalid slot transition: {detail}")]
    SlotTransitionInvalid { detail: String },

    #[error("[GRDR-UPDATER-0008] handover validation failed: {detail}")]
    HandoverInvalid { detail: String },

    #[error(
        "[GRDR-UPDATER-0009] delta reconstruction digest mismatch on {target_path} (expected {expected_sha256}, got {actual_sha256}); full download required"
    )]
    DeltaFallbackRequired {
        target_path: String,
        expected_sha256: String,
        actual_sha256: String,
    },

    #[error("[GRDR-UPDATER-0010] stale or rolled-back update metadata: {detail}")]
    StaleOrRollback { detail: String },

    #[error("[GRDR-UPDATER-0011] unsafe update path: {detail}")]
    PathUnsafe { detail: String },

    #[error("[GRDR-UPDATER-0012] clock error: {detail}")]
    ClockFailed { detail: String },

    #[error("[GRDR-UPDATER-0013] local filesystem I/O error: {detail}")]
    Io { detail: String },
}

impl UpdaterError {
    /// Return the stable `GRDR-UPDATER-NNNN` code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::TufVerification { .. } => "GRDR-UPDATER-0001",
            Self::CompatibilityRejected { .. } => "GRDR-UPDATER-0002",
            Self::ForbiddenField { .. } => "GRDR-UPDATER-0003",
            Self::BudgetExceeded { .. } => "GRDR-UPDATER-0004",
            Self::AuthorityDisallowed { .. } => "GRDR-UPDATER-0005",
            Self::SecurityFloorViolation { .. } => "GRDR-UPDATER-0006",
            Self::SlotTransitionInvalid { .. } => "GRDR-UPDATER-0007",
            Self::HandoverInvalid { .. } => "GRDR-UPDATER-0008",
            Self::DeltaFallbackRequired { .. } => "GRDR-UPDATER-0009",
            Self::StaleOrRollback { .. } => "GRDR-UPDATER-0010",
            Self::PathUnsafe { .. } => "GRDR-UPDATER-0011",
            Self::ClockFailed { .. } => "GRDR-UPDATER-0012",
            Self::Io { .. } => "GRDR-UPDATER-0013",
        }
    }
}
