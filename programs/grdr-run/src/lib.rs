// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

//! Dedicated D-21 containment launcher (`Delegate`, `WrapTools`, `WrapAgent`).

pub mod executor;
pub mod floor_fallback;
pub mod gate;
pub mod ipc_transport;
pub mod planner;
pub mod planner_macos;

use grdr_model::CodedError;

pub const CODE_RUN_INVALID_PLAN: &str = "GRDR-RUN-0001";
pub const CODE_RUN_POLICY_DENIED: &str = "GRDR-RUN-0002";
pub const CODE_RUN_GATE_UNAVAILABLE: &str = "GRDR-RUN-0003";
pub const CODE_RUN_FLOOR_UNTRUSTED: &str = "GRDR-RUN-0004";
pub const CODE_RUN_SPAWN_FAILED: &str = "GRDR-RUN-0005";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RunError {
    #[error("GRDR-RUN-0001: invalid launch or containment plan: {0}")]
    InvalidPlan(String),
    #[error("GRDR-RUN-0002: launch blocked by policy: {0}")]
    PolicyDenied(String),
    #[error("GRDR-RUN-0003: daemon unavailable and no verified compiled floor available: {0}")]
    GateUnavailable(String),
    #[error("GRDR-RUN-0004: compiled floor signature check failed")]
    FloorUntrusted,
    #[error("GRDR-RUN-0005: failed to prepare or spawn contained process: {0}")]
    SpawnFailed(String),
}

impl From<RunError> for CodedError {
    fn from(err: RunError) -> Self {
        let code = match &err {
            RunError::InvalidPlan(_) => CODE_RUN_INVALID_PLAN,
            RunError::PolicyDenied(_) => CODE_RUN_POLICY_DENIED,
            RunError::GateUnavailable(_) => CODE_RUN_GATE_UNAVAILABLE,
            RunError::FloorUntrusted => CODE_RUN_FLOOR_UNTRUSTED,
            RunError::SpawnFailed(_) => CODE_RUN_SPAWN_FAILED,
        };
        CodedError::new(
            code,
            err.to_string(),
            "Verify workspace containment paths, daemon availability, and signed floor keys.",
        )
    }
}
