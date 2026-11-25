// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

pub mod ladder;
pub mod lifecycle;
pub mod pipe_dacl;
pub mod supervision;

use grdr_model::CodedError;

pub use ladder::{
    BootLoopGuard, CrashLoopLadder, FloorRuleUnion, HealthTransitionEvent, LadderAction, LadderRung,
};
pub use lifecycle::{
    AdoptedListener, ListenerTransportKind, ServiceActivationConfig, ServiceAdapter,
    ServiceManagerBackend, ServiceManagerState, SystemServiceAdapter, WindowsScmServiceState,
    format_sd_notify_payload, parse_systemd_listen_fds,
};
pub use pipe_dacl::{
    NamedPipeAccessRight, NamedPipeDaclSpec, PipeSecurityProfile, build_named_pipe_dacl,
    validate_windows_sid,
};
pub use supervision::{ChildHeartbeatMonitor, ChildLifecycle, SupervisionDecision};

pub const CODE_SVC_INVALID_TRANSITION: &str = "GRDR-SVC-0001";
pub const CODE_SVC_ACTIVATION_INVALID: &str = "GRDR-SVC-0002";
pub const CODE_SVC_DACL_VIOLATION: &str = "GRDR-SVC-0003";
pub const CODE_SVC_NOTIFY_FAILED: &str = "GRDR-SVC-0004";
pub const CODE_SVC_SUPERVISION_FAULT: &str = "GRDR-SVC-0005";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ServiceError {
    #[error("GRDR-SVC-0001: invalid service lifecycle transition from {from} to {to}")]
    InvalidTransition { from: String, to: String },
    #[error("GRDR-SVC-0002: invalid socket activation metadata: {0}")]
    InvalidActivation(String),
    #[error("GRDR-SVC-0003: named pipe DACL policy violation: {0}")]
    DaclViolation(String),
    #[error("GRDR-SVC-0004: service manager notification failed: {0}")]
    NotifyFailed(String),
    #[error("GRDR-SVC-0005: child supervision error: {0}")]
    Supervision(String),
}

impl From<ServiceError> for CodedError {
    fn from(err: ServiceError) -> Self {
        let code = match &err {
            ServiceError::InvalidTransition { .. } => CODE_SVC_INVALID_TRANSITION,
            ServiceError::InvalidActivation(_) => CODE_SVC_ACTIVATION_INVALID,
            ServiceError::DaclViolation(_) => CODE_SVC_DACL_VIOLATION,
            ServiceError::NotifyFailed(_) => CODE_SVC_NOTIFY_FAILED,
            ServiceError::Supervision(_) => CODE_SVC_SUPERVISION_FAULT,
        };
        CodedError::new(
            code,
            err.to_string(),
            "Inspect service manager and pipe ACL state.",
        )
    }
}
