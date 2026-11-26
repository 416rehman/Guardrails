// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Daemon + D-14 signed CompiledFloorTable decision resolution driving `grdr-broker::McpBroker`.

use std::future::Future;
use std::pin::Pin;

use jiff::Timestamp;
use uuid::Uuid;

use grdr_broker::{BrokerOutcome, McpBroker};
use grdr_core::compile::evaluate_compiled_floor;
use grdr_core::policy::{ReceiptDigestInput, compute_receipt_digest};
use grdr_mcp_proto::{
    McpAttemptContext, McpMethod, McpRequest, ToolDescriptor, mcp_call_to_attempt,
};
use grdr_model::{
    ActionAttempt, CodedError, CompiledFloorTable, DecisionReceipt, Grant, Mode, PolicyPack,
    SignatureStatus, TrustedKeyInfo, Verdict, verify_floor_table,
};
use grdr_os_clock::{Clock, SystemClock};
use grdr_ports::DecisionEnginePort;

use crate::McpBrokerError;
pub use crate::ipc_client::IpcDaemonDecisionSource;
use crate::pinning::{PinApprovalState, PinRegistry};

pub const DEFAULT_DECIDE_TIMEOUT_MS: u64 = 1_500;

pub type DecideFuture<'a> =
    Pin<Box<dyn Future<Output = Result<DecisionReceipt, McpBrokerError>> + Send + 'a>>;

pub trait AsyncDecisionSource: Send + Sync {
    fn evaluate_attempt<'a>(&'a self, attempt: &'a ActionAttempt) -> DecideFuture<'a>;
}

#[derive(Debug, Clone)]
pub struct MediationResult {
    pub outcome: BrokerOutcome,
    pub pin_state: PinApprovalState,
    pub manifest_pinned: bool,
    pub degraded: bool,
}

struct PreResolvedEngine {
    receipt: DecisionReceipt,
}

impl DecisionEnginePort for PreResolvedEngine {
    fn load_packs(&mut self, _packs: Vec<PolicyPack>) -> Result<(), CodedError> {
        Ok(())
    }

    fn add_grant(&mut self, _grant: Grant) -> Result<(), CodedError> {
        Ok(())
    }

    fn evaluate(&mut self, _attempt: &ActionAttempt) -> Result<DecisionReceipt, CodedError> {
        Ok(self.receipt.clone())
    }
}

/// Evaluates an MCP request through pin verification, shadowing check, poisoning check,
/// async daemon decision (or verified D-14 signed floor fallback), and `grdr_broker::McpBroker`.
pub async fn mediate_mcp_request<S: AsyncDecisionSource>(
    source: &S,
    pins: &PinRegistry,
    req: &McpRequest,
    desc: Option<&ToolDescriptor>,
    ctx: &McpAttemptContext,
    floor: Option<(&CompiledFloorTable, &[TrustedKeyInfo])>,
) -> Result<MediationResult, McpBrokerError> {
    let manifest_pinned = pins.is_manifest_pinned(&ctx.server_name);
    let pin_state = if req.method == McpMethod::ToolsCall {
        let tool = req.tool_name.as_deref().unwrap_or("");
        pins.verify_tool_call(&ctx.server_name, tool, desc)?
    } else {
        PinApprovalState::UnpinnedFirstSight
    };

    let attempt =
        mcp_call_to_attempt(req, ctx).map_err(|e| McpBrokerError::Transport(e.to_string()))?;
    let (receipt, degraded) = resolve_with_floor_fallback(source, &attempt, floor).await?;

    let mut broker = McpBroker::new(PreResolvedEngine { receipt });
    let outcome = broker
        .mediate_call(req, desc, ctx)
        .map_err(|e| McpBrokerError::Transport(e.to_string()))?;

    Ok(MediationResult {
        outcome,
        pin_state,
        manifest_pinned,
        degraded,
    })
}

async fn resolve_with_floor_fallback<S: AsyncDecisionSource>(
    source: &S,
    attempt: &ActionAttempt,
    floor: Option<(&CompiledFloorTable, &[TrustedKeyInfo])>,
) -> Result<(DecisionReceipt, bool), McpBrokerError> {
    match source.evaluate_attempt(attempt).await {
        Ok(receipt) => return Ok((receipt, false)),
        Err(err @ McpBrokerError::FailClosed(_)) => return Err(err),
        Err(McpBrokerError::FloorUntrusted) => return Err(McpBrokerError::FloorUntrusted),
        Err(_) => {}
    }

    tracing::warn!(
        sr = "SR-15",
        degraded = true,
        session_id = %attempt.session_id,
        action_class = attempt.action_class.as_str(),
        "grdr-daemon unavailable; evaluating MCP request under D-14 degraded floor mode"
    );

    let Some((table, trusted_keys)) = floor else {
        return Ok((
            synthetic_floor_receipt(
                attempt,
                Verdict::Deny,
                Some("mcp.daemon-unavailable"),
                "daemon unreachable and no signed floor table provided; failing closed",
            ),
            true,
        ));
    };

    if verify_floor_table(table, trusted_keys) != SignatureStatus::Verified {
        return Err(McpBrokerError::FloorUntrusted);
    }

    if let Some(matched) = evaluate_compiled_floor(
        table,
        attempt.action_class,
        &attempt.agent_name,
        &attempt.target,
    ) {
        return Ok((
            synthetic_floor_receipt(
                attempt,
                matched.verdict,
                Some(&matched.rule_id),
                "evaluated against signed offline compiled floor",
            ),
            true,
        ));
    }

    Ok((
        synthetic_floor_receipt(
            attempt,
            Verdict::Deny,
            Some("mcp.degraded-fail-closed"),
            "D-14 degraded offline floor denies unmatched MCP request while daemon is unreachable",
        ),
        true,
    ))
}

#[must_use]
pub fn build_mcp_receipt(
    attempt: &ActionAttempt,
    verdict: Verdict,
    rule_id: Option<&str>,
    reason: &str,
    next_step: &str,
    receipt_id_override: Option<&str>,
    now: Timestamp,
) -> DecisionReceipt {
    let receipt_id = receipt_id_override
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map_or_else(|| format!("rcp_{}", Uuid::now_v7().simple()), str::to_owned);
    let digest = compute_receipt_digest(&ReceiptDigestInput {
        attempt_id: &attempt.id,
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
        attempt_id: attempt.id.clone(),
        session_id: attempt.session_id.clone(),
        device_id: attempt.device_id.clone(),
        agent_name: attempt.agent_name.clone(),
        action_class: attempt.action_class,
        control_point: attempt.control_point,
        target: attempt.target.clone(),
        verdict,
        would_be: None,
        rule_id: rule_id.map(str::to_owned),
        pack_id: Some("grdr-mcp".into()),
        mode_applied: Some(Mode::Block),
        grant_id: None,
        reason: reason.to_owned(),
        next_step: next_step.to_owned(),
        receipt_digest: digest,
        decided_at: now,
        key_id: None,
        signature: None,
        signature_verified: None,
    }
}

#[must_use]
pub fn synthetic_floor_receipt(
    attempt: &ActionAttempt,
    verdict: Verdict,
    rule_id: Option<&str>,
    reason: &str,
) -> DecisionReceipt {
    let now = SystemClock::new().now_wall().unwrap_or(attempt.timestamp);
    build_mcp_receipt(
        attempt,
        verdict,
        rule_id,
        reason,
        "inspect MCP policy decision receipt",
        None,
        now,
    )
}
