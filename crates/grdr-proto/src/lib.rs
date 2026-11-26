// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use serde::{Deserialize, Serialize};

pub mod api;
pub mod canonical;
pub mod common;
pub mod descriptor;
mod descriptor_wire;
pub mod serde_proto;
pub mod unknown_fields;
mod unknown_fields_nested;
mod unknown_fields_nested_walk;

pub const PROTO_VERSION: u16 = 1;
pub const DEFAULT_MAX_IPC_BYTES: usize = 1_048_576;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProtoError {
    #[error("GRDR-PROTO-0001: unsupported protocol version {0} (expected {PROTO_VERSION})")]
    UnsupportedVersion(u16),
    #[error("GRDR-PROTO-0002: empty correlation id on IPC frame")]
    EmptyCorrelationId,
    #[error("GRDR-PROTO-0003: IPC payload invalid: {0}")]
    InvalidPayload(String),
    #[error("GRDR-PROTO-0004: constraint violation: {0}")]
    ConstraintViolation(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpcMessage<T> {
    pub protocol_version: u16,
    pub correlation_id: String,
    pub body: T,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluateAttemptPayload {
    pub attempt_id: String,
    pub session_id: String,
    pub device_id: String,
    pub device_name: String,
    pub agent_name: String,
    pub action_class: String,
    pub control_point: String,
    pub target: String,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EngineCommand {
    Ping,
    Status,
    EvaluateAttempt(Box<EvaluateAttemptPayload>),
    Shutdown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerdictReply {
    pub receipt_id: String,
    pub attempt_id: String,
    pub verdict: String,
    pub rule_id: Option<String>,
    pub reason: String,
    pub next_step: String,
    pub receipt_digest: String,
    pub key_id: Option<String>,
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EngineReply {
    Pong {
        version: String,
        protocol_version: u16,
    },
    Status {
        loaded_packs: usize,
        active_grants: usize,
        signed_receipts: u64,
    },
    Verdict(Box<VerdictReply>),
    Ack,
    Error {
        code: String,
        message: String,
    },
}

impl<T> IpcMessage<T> {
    pub fn new(correlation_id: impl Into<String>, body: T) -> Self {
        Self {
            protocol_version: PROTO_VERSION,
            correlation_id: correlation_id.into(),
            body,
        }
    }

    pub fn validate(&self) -> Result<(), ProtoError> {
        validate_protocol_version(self.protocol_version)?;
        if self.correlation_id.trim().is_empty() {
            return Err(ProtoError::EmptyCorrelationId);
        }
        Ok(())
    }
}

pub fn validate_protocol_version(version: u16) -> Result<(), ProtoError> {
    if version == PROTO_VERSION {
        Ok(())
    } else {
        Err(ProtoError::UnsupportedVersion(version))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_and_roundtrips_ipc_engine_commands_and_replies() {
        let msg = IpcMessage::new(
            "corr-1",
            EngineCommand::EvaluateAttempt(Box::new(EvaluateAttemptPayload {
                attempt_id: "att-1".into(),
                session_id: "sess-1".into(),
                device_id: "dev-1".into(),
                device_name: "host-1".into(),
                agent_name: "claude-code".into(),
                action_class: "file.write".into(),
                control_point: "hook".into(),
                target: ".claude/settings.json".into(),
                summary: "Write protected settings".into(),
            })),
        );
        assert!(msg.validate().is_ok());

        let json = serde_json::to_string(&msg).unwrap();
        let decoded: IpcMessage<EngineCommand> = serde_json::from_str(&json).unwrap();
        assert_eq!(msg, decoded);

        let mut bad = decoded;
        bad.protocol_version = 99;
        assert_eq!(bad.validate(), Err(ProtoError::UnsupportedVersion(99)));
    }
}
