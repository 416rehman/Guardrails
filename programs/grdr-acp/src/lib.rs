// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

//! Fail-closed OWASP Agent Control Standard, Microsoft agent-hooks, and ACP conductor adapter.

pub mod acs_hmac;
pub mod adapters;
pub mod conductor;
pub mod conductor_fs;
pub mod envelope;
pub mod floor_fallback;
pub mod ipc_client;
mod ipc_transport;

use std::future::Future;
use std::pin::Pin;

use jiff::Timestamp;
use uuid::Uuid;

use grdr_core::policy::ReceiptDigestInput;
use grdr_core::policy::compute_receipt_digest;
use grdr_model::{
    ActionAttempt, ActionClass, CodedError, ControlPoint, DecisionReceipt, ProvenanceSource,
    Verdict,
};
use grdr_strings::sanitize_untrusted_text;

pub use ipc_client::PeerDaemonClient;

pub const CODE_ACP_INVALID_PAYLOAD: &str = "GRDR-ACP-0001";
pub const CODE_ACP_UNSUPPORTED_VERSION: &str = "GRDR-ACP-0002";
pub const CODE_ACP_SIGNATURE: &str = "GRDR-ACP-0003";
pub const CODE_ACP_REPLAY_OR_SKEW: &str = "GRDR-ACP-0004";
pub const CODE_ACP_DAEMON_UNAVAILABLE: &str = "GRDR-ACP-0005";
pub const CODE_ACP_TRANSPORT: &str = "GRDR-ACP-0006";

pub const DEFAULT_DECIDE_TIMEOUT_MS: u64 = 2_000;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AcpError {
    #[error("GRDR-ACP-0001: malformed adapter payload: {0}")]
    InvalidPayload(String),
    #[error("GRDR-ACP-0002: unsupported protocol version `{0}`")]
    UnsupportedVersion(String),
    #[error("GRDR-ACP-0003: envelope signature verification failed: {0}")]
    SignatureInvalid(String),
    #[error("GRDR-ACP-0004: nonce replay or timestamp skew rejected: {0}")]
    ReplayOrSkew(String),
    #[error("GRDR-ACP-0005: daemon policy decision unavailable: {0}")]
    DaemonUnavailable(String),
    #[error("GRDR-ACP-0006: wire framing or stream error: {0}")]
    Transport(String),
}

pub type EvalFuture<'a> =
    Pin<Box<dyn Future<Output = Result<DecisionReceipt, AcpError>> + Send + 'a>>;

/// Asynchronous boundary delegating authorization decisions to `grdr-daemon`.
pub trait DecisionClient: Send + Sync {
    fn decide<'a>(&'a self, attempt: &'a ActionAttempt) -> EvalFuture<'a>;
}

/// Normalized adapter inputs built from any supported protocol dialect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedControlCall {
    pub request_id: String,
    pub spec_version: String,
    pub session_id: String,
    pub agent_name: String,
    pub action_class: ActionClass,
    pub target: String,
    pub summary: String,
}

impl From<AcpError> for CodedError {
    fn from(err: AcpError) -> Self {
        let code = match &err {
            AcpError::InvalidPayload(_) => CODE_ACP_INVALID_PAYLOAD,
            AcpError::UnsupportedVersion(_) => CODE_ACP_UNSUPPORTED_VERSION,
            AcpError::SignatureInvalid(_) => CODE_ACP_SIGNATURE,
            AcpError::ReplayOrSkew(_) => CODE_ACP_REPLAY_OR_SKEW,
            AcpError::DaemonUnavailable(_) => CODE_ACP_DAEMON_UNAVAILABLE,
            AcpError::Transport(_) => CODE_ACP_TRANSPORT,
        };
        CodedError::new(
            code,
            err.to_string(),
            "Verify wire envelope signature, clock sync, and daemon reachability.",
        )
    }
}

#[must_use]
pub fn classify_action_kind(raw_kind: &str, tool_or_stage: &str) -> ActionClass {
    let normalized = raw_kind.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "exec" | "execute" | "shell" | "bash" | "command" | "process" => ActionClass::Exec,
        "file_read" | "read" | "fs_read" => ActionClass::FileRead,
        "file_write" | "write" | "edit" | "fs_write" => ActionClass::FileWrite,
        "file_delete" | "delete" | "unlink" => ActionClass::FileDelete,
        "net_connect" | "connect" | "socket" => ActionClass::NetConnect,
        "net_request" | "http" | "fetch" | "network" => ActionClass::NetRequest,
        "llm_request" | "llm" | "model" => ActionClass::LlmRequest,
        "mcp_connect" => ActionClass::McpConnect,
        "mcp_call" | "mcp" => ActionClass::McpCall,
        "cred_use" | "credential" => ActionClass::CredUse,
        "agent_spawn" | "spawn" => ActionClass::AgentSpawn,
        "config_change" | "config" => ActionClass::ConfigChange,
        "elevate" | "sudo" => ActionClass::Elevate,
        "ui_act" | "browser" => ActionClass::UiAct,
        "data_flow" => ActionClass::DataFlow,
        _ => infer_from_tool_name(tool_or_stage),
    }
}

fn infer_from_tool_name(tool: &str) -> ActionClass {
    let lower = tool.trim().to_ascii_lowercase();
    if lower.contains("exec")
        || lower.contains("bash")
        || lower.contains("shell")
        || lower.contains("cmd")
        || lower.contains("eval")
        || lower.contains("spawn")
        || lower.contains("sudo")
    {
        ActionClass::Exec
    } else if lower.contains("write") || lower.contains("edit") {
        ActionClass::FileWrite
    } else if lower.contains("delete") || lower.contains("remove") || lower.contains("unlink") {
        ActionClass::FileDelete
    } else if lower.contains("http") || lower.contains("fetch") || lower.contains("web") {
        ActionClass::NetRequest
    } else if lower.contains("mcp") {
        ActionClass::McpCall
    } else if lower == "read" || lower == "read_file" || lower == "fs_read" {
        ActionClass::FileRead
    } else {
        ActionClass::Exec
    }
}

#[must_use]
pub fn build_attempt(call: &NormalizedControlCall, now: Timestamp) -> ActionAttempt {
    let session = sanitize_non_empty(&call.session_id, "sess-acp");
    let agent = sanitize_non_empty(&call.agent_name, "acp-client");
    let target = sanitize_non_empty(&call.target, "unspecified");
    ActionAttempt {
        id: format!("att_{}", Uuid::now_v7().simple()),
        session_id: session,
        device_id: "dev-local".into(),
        device_name: "local-host".into(),
        agent_name: agent,
        action_class: call.action_class,
        control_point: ControlPoint::Hook,
        target,
        summary: sanitize_untrusted_text(&call.summary),
        timestamp: now,
        provenance: ProvenanceSource::Mediated,
        ..Default::default()
    }
}

/// Construct an ACP receipt whose digest commits to the final verdict, rule id, and reason.
#[must_use]
pub fn build_acp_receipt(
    attempt: &ActionAttempt,
    verdict: Verdict,
    rule_id: Option<&str>,
    reason: &str,
    next_step: &str,
    receipt_id_override: Option<&str>,
    now: Timestamp,
) -> DecisionReceipt {
    let attempt_id = attempt.id.clone();
    let receipt_id = receipt_id_override
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map_or_else(
            || format!("rcp_{}", Uuid::now_v7().simple()),
            str::to_string,
        );
    let clean_reason = sanitize_untrusted_text(reason);
    let digest = compute_receipt_digest(&ReceiptDigestInput {
        attempt_id: &attempt_id,
        session_id: &attempt.session_id,
        agent_name: &attempt.agent_name,
        action_class: attempt.action_class,
        target: &attempt.target,
        verdict,
        rule_id,
        decided_at: now,
    });
    DecisionReceipt {
        receipt_id,
        attempt_id,
        session_id: attempt.session_id.clone(),
        device_id: attempt.device_id.clone(),
        agent_name: attempt.agent_name.clone(),
        action_class: attempt.action_class,
        control_point: attempt.control_point,
        target: attempt.target.clone(),
        verdict,
        would_be: None,
        rule_id: rule_id.map(str::to_string),
        pack_id: Some("grdr-acp".into()),
        mode_applied: None,
        grant_id: None,
        reason: clean_reason,
        next_step: sanitize_untrusted_text(next_step),
        receipt_digest: digest,
        decided_at: now,
        key_id: None,
        signature: None,
        signature_verified: None,
    }
}

/// Fail-closed synthetic receipt emitted when verification or daemon evaluation fails.
#[must_use]
pub fn fail_closed_receipt(
    attempt: &ActionAttempt,
    reason: &str,
    now: Timestamp,
) -> DecisionReceipt {
    build_acp_receipt(
        attempt,
        Verdict::Deny,
        Some("acp.fail-closed"),
        reason,
        "Check daemon connection and wire credentials; failing closed.",
        None,
        now,
    )
}

fn sanitize_non_empty(raw: &str, fallback: &str) -> String {
    let cleaned = sanitize_untrusted_text(raw);
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        fallback.to_owned()
    } else {
        trimmed.to_owned()
    }
}
