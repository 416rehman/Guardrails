// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Error types and health conditions for `grdr-uplink`.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Offline diagnosis reason surfaced through endpoint health status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfflineReason {
    DnsFailure,
    TlsHandshakeFailed,
    ProxyAuthRequired,
    ProxyAuthUserOnly,
    EgressUnlisted,
    Revoked,
    ClockSkew,
    RateLimited,
}

/// Non-fatal or degraded uplink condition surfaced to `grdr-daemon`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UplinkHealthCondition {
    Healthy,
    AckUnverified,
    UplinkDowngraded,
    UplinkOffline(OfflineReason),
    ScheduleClamped,
    ClockSkew,
    EvidenceBudgetExhausted,
    SpoolWatermarkExceeded,
}

/// Coded errors produced by `grdr-uplink`.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum UplinkError {
    #[error("[GRDR-CFG-0020] isolated mode refused unlisted egress to {host}: {reason}")]
    EgressUnlisted { host: String, reason: String },

    #[error("[GRDR-UPLINK-0001] invalid endpoint target: {detail}")]
    InvalidEndpoint { detail: String },

    #[error("[GRDR-UPLINK-0002] schedule validation failed: {detail}")]
    ScheduleRejected { detail: String },

    #[error("[GRDR-UPLINK-0003] retry budget exhausted for origin {origin}")]
    RetryBudgetExhausted { origin: String },

    #[error("[GRDR-UPLINK-0004] circuit breaker open for origin {origin} until {retry_at_ms}ms")]
    CircuitOpen { origin: String, retry_at_ms: u64 },

    #[error("[GRDR-UPLINK-0005] failed to create request signature: {detail}")]
    SignatureCreationFailed { detail: String },

    #[error("[GRDR-UPLINK-0006] server ack failed cryptographic verification: {reason}")]
    AckUnverified { reason: String },

    #[error("[GRDR-UPLINK-0007] transport or response key certificate invalid: {reason}")]
    CertificateInvalid { reason: String },

    #[error("[GRDR-UPLINK-0008] clock reading failed: {detail}")]
    ClockFailed { detail: String },

    #[error("[GRDR-UPLINK-0009] lane batch overflow on {lane} ({size} > {max})")]
    BatchOverflow {
        lane: String,
        size: usize,
        max: usize,
    },

    #[error("[GRDR-UPLINK-0010] opaque artifact staging rejected: {detail}")]
    StagingError { detail: String },

    #[error("[GRDR-UPLINK-0011] proxy requires interactive user credentials: {detail}")]
    ProxyAuthUserOnly { detail: String },

    #[error("[GRDR-UPLINK-0012] local I/O failure: {detail}")]
    Io { detail: String },

    #[error("[GRDR-UPLINK-0013] transport execution failed: {detail}")]
    Transport { detail: String },

    #[error("[GRDR-UPLINK-0014] herd simulator invariant failed: {detail}")]
    HerdSimAssertion { detail: String },
}

impl UplinkError {
    /// Return the stable `GRDR-<AREA>-<NNNN>` error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::EgressUnlisted { .. } => "GRDR-CFG-0020",
            Self::InvalidEndpoint { .. } => "GRDR-UPLINK-0001",
            Self::ScheduleRejected { .. } => "GRDR-UPLINK-0002",
            Self::RetryBudgetExhausted { .. } => "GRDR-UPLINK-0003",
            Self::CircuitOpen { .. } => "GRDR-UPLINK-0004",
            Self::SignatureCreationFailed { .. } => "GRDR-UPLINK-0005",
            Self::AckUnverified { .. } => "GRDR-UPLINK-0006",
            Self::CertificateInvalid { .. } => "GRDR-UPLINK-0007",
            Self::ClockFailed { .. } => "GRDR-UPLINK-0008",
            Self::BatchOverflow { .. } => "GRDR-UPLINK-0009",
            Self::StagingError { .. } => "GRDR-UPLINK-0010",
            Self::ProxyAuthUserOnly { .. } => "GRDR-UPLINK-0011",
            Self::Io { .. } => "GRDR-UPLINK-0012",
            Self::Transport { .. } => "GRDR-UPLINK-0013",
            Self::HerdSimAssertion { .. } => "GRDR-UPLINK-0014",
        }
    }

    /// Map an uplink failure into an endpoint health condition when applicable.
    #[must_use]
    pub const fn health_condition(&self) -> Option<UplinkHealthCondition> {
        match self {
            Self::EgressUnlisted { .. } => Some(UplinkHealthCondition::UplinkOffline(
                OfflineReason::EgressUnlisted,
            )),
            Self::AckUnverified { .. } => Some(UplinkHealthCondition::AckUnverified),
            Self::ProxyAuthUserOnly { .. } => Some(UplinkHealthCondition::UplinkOffline(
                OfflineReason::ProxyAuthUserOnly,
            )),
            Self::RetryBudgetExhausted { .. } | Self::CircuitOpen { .. } => Some(
                UplinkHealthCondition::UplinkOffline(OfflineReason::RateLimited),
            ),
            Self::InvalidEndpoint { .. }
            | Self::ScheduleRejected { .. }
            | Self::SignatureCreationFailed { .. }
            | Self::CertificateInvalid { .. }
            | Self::ClockFailed { .. }
            | Self::BatchOverflow { .. }
            | Self::StagingError { .. }
            | Self::Io { .. }
            | Self::Transport { .. }
            | Self::HerdSimAssertion { .. } => None,
        }
    }
}
