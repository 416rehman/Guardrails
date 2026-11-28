// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Protocol translation for OWASP ACS (v0.1.0 / v0.1.4), Microsoft agent-hooks
//! (v0.1.0-beta.3), and ACP conductor (1.30.0 / v2) through one shared decision path.

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use grdr_model::{ActionClass, DecisionReceipt, Verdict};
use grdr_strings::sanitize_untrusted_text;

use crate::conductor_fs::{default_workspace_root, evaluate_modify_decision};
use crate::{
    AcpError, DecisionClient, NormalizedControlCall, build_attempt, classify_action_kind,
    extract_daemon_retry_token, fail_closed_receipt,
};

const OWASP_VERSIONS: &[&str] = &["0.1.0", "0.1.4"];
const MS_HOOK_VERSIONS: &[&str] = &["0.1.0-beta.3", "v0.1.0-beta.3"];
const ACP_CONDUCTOR_VERSIONS: &[&str] = &["1.30.0", "v2", "2.0"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcpProtocolDialect {
    OwaspAcs,
    MicrosoftAgentHooks,
    AcpConductor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwaspAcsStage {
    PreTool,
    PostTool,
    PreModel,
    PostModel,
    SessionStart,
    NetworkRequest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwaspAcsVerdict {
    Allow,
    Modify,
    RequireApproval,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MsHookDecision {
    Approve,
    Modify,
    StepUp,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcpConductorOutcome {
    Allow,
    Modify,
    StepUp,
    Defer,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwaspAcsRequest {
    pub spec_version: String,
    pub request_id: String,
    pub session_id: String,
    pub agent_name: String,
    pub hook_point: OwaspAcsStage,
    pub action_kind: Option<String>,
    pub target: String,
    #[serde(default)]
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwaspAcsResponse {
    pub spec_version: String,
    pub request_id: String,
    pub verdict: OwaspAcsVerdict,
    pub reason: String,
    pub rule_id: Option<String>,
    pub receipt_id: String,
    pub receipt_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified_target: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MsAgentHookRequest {
    pub protocol: String,
    pub hook_id: String,
    pub session_id: String,
    pub agent_name: String,
    pub event: String,
    pub tool_name: String,
    pub action_kind: Option<String>,
    pub target: String,
    #[serde(default)]
    pub arguments: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MsAgentHookResponse {
    pub protocol: String,
    pub hook_id: String,
    pub decision: MsHookDecision,
    pub message: String,
    pub receipt_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified_target: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcpConductorRequest {
    pub acp_version: String,
    pub call_id: String,
    pub session_id: String,
    pub conductor_id: String,
    pub capability: String,
    pub action_kind: Option<String>,
    pub target: String,
    #[serde(default)]
    pub context: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcpConductorResponse {
    pub acp_version: String,
    pub call_id: String,
    pub verdict: AcpConductorOutcome,
    pub reason: String,
    pub receipt_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified_target: Option<String>,
}

impl AcpProtocolDialect {
    #[must_use]
    pub const fn default_version(self) -> &'static str {
        match self {
            Self::OwaspAcs => "0.1.4",
            Self::MicrosoftAgentHooks => "0.1.0-beta.3",
            Self::AcpConductor => "1.30.0",
        }
    }
}

impl OwaspAcsStage {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PreTool => "pre_tool",
            Self::PostTool => "post_tool",
            Self::PreModel => "pre_model",
            Self::PostModel => "post_model",
            Self::SessionStart => "session_start",
            Self::NetworkRequest => "network_request",
        }
    }
}

pub fn parse_dialect_payload(
    dialect: AcpProtocolDialect,
    raw: &Value,
) -> Result<NormalizedControlCall, AcpError> {
    match dialect {
        AcpProtocolDialect::OwaspAcs => parse_owasp(raw),
        AcpProtocolDialect::MicrosoftAgentHooks => parse_ms_hooks(raw),
        AcpProtocolDialect::AcpConductor => parse_conductor(raw),
    }
}

pub async fn evaluate_dialect_request<C: DecisionClient>(
    dialect: AcpProtocolDialect,
    raw: &Value,
    client: &C,
    now: Timestamp,
) -> Value {
    match evaluate_dialect_inner(dialect, raw, client, now).await {
        Ok(resp) => resp,
        Err(err) => {
            let synthetic_call = NormalizedControlCall {
                request_id: extract_str(raw, &["request_id", "hook_id", "call_id"])
                    .unwrap_or_else(|| "unknown-id".into()),
                spec_version: extract_str(raw, &["spec_version", "protocol", "acp_version"])
                    .unwrap_or_else(|| dialect.default_version().into()),
                session_id: extract_str(raw, &["session_id"])
                    .unwrap_or_else(|| "sess-fail-closed".into()),
                agent_name: extract_str(raw, &["agent_name", "conductor_id"])
                    .unwrap_or_else(|| "unknown-agent".into()),
                action_class: ActionClass::Exec,
                target: extract_str(raw, &["target"]).unwrap_or_else(|| "fail-closed".into()),
                summary: err.to_string(),
            };
            let attempt = build_attempt(&synthetic_call, now);
            let receipt = fail_closed_receipt(&attempt, &err.to_string(), now);
            format_dialect_response(dialect, &synthetic_call, &receipt)
        }
    }
}

async fn evaluate_dialect_inner<C: DecisionClient>(
    dialect: AcpProtocolDialect,
    raw: &Value,
    client: &C,
    now: Timestamp,
) -> Result<Value, AcpError> {
    let call = parse_dialect_payload(dialect, raw)?;
    let attempt = build_attempt(&call, now);
    let receipt = match client.decide(&attempt).await {
        Ok(r) if r.verdict == Verdict::Modify => {
            let root = default_workspace_root();
            match evaluate_modify_decision(client, &root, &call, &attempt, &r).await {
                Ok((mut final_receipt, rewritten)) => {
                    final_receipt.verdict = Verdict::Modify;
                    final_receipt.target = rewritten;
                    final_receipt.key_id = None;
                    final_receipt.signature = None;
                    final_receipt.signature_verified = None;
                    final_receipt.receipt_digest = grdr_core::policy::compute_receipt_digest(
                        &grdr_core::policy::ReceiptDigestInput {
                            attempt_id: &final_receipt.attempt_id,
                            session_id: &final_receipt.session_id,
                            agent_name: &final_receipt.agent_name,
                            action_class: final_receipt.action_class,
                            target: &final_receipt.target,
                            verdict: final_receipt.verdict,
                            rule_id: final_receipt.rule_id.as_deref(),
                            decided_at: final_receipt.decided_at,
                        },
                    );
                    final_receipt
                }
                Err(reason) => fail_closed_receipt(&attempt, &reason, now),
            }
        }
        Ok(r) => r,
        Err(err) => fail_closed_receipt(&attempt, &err.to_string(), now),
    };
    Ok(format_dialect_response(dialect, &call, &receipt))
}

fn parse_owasp(raw: &Value) -> Result<NormalizedControlCall, AcpError> {
    let req: OwaspAcsRequest =
        serde_json::from_value(raw.clone()).map_err(|e| AcpError::InvalidPayload(e.to_string()))?;
    ensure_version(req.spec_version.trim(), OWASP_VERSIONS)?;
    require_non_empty(&req.request_id, "request_id")?;
    require_non_empty(&req.session_id, "session_id")?;
    require_non_empty(&req.agent_name, "agent_name")?;
    require_non_empty(&req.target, "target")?;
    let action_class = classify_action_kind(
        req.action_kind.as_deref().unwrap_or(""),
        req.hook_point.as_str(),
    );
    Ok(NormalizedControlCall {
        request_id: req.request_id,
        spec_version: req.spec_version,
        session_id: req.session_id,
        agent_name: req.agent_name,
        action_class,
        target: req.target,
        summary: format!(
            "owasp-acs hook_point={} has_meta={}",
            req.hook_point.as_str(),
            req.metadata.is_some()
        ),
    })
}

fn parse_ms_hooks(raw: &Value) -> Result<NormalizedControlCall, AcpError> {
    let req: MsAgentHookRequest =
        serde_json::from_value(raw.clone()).map_err(|e| AcpError::InvalidPayload(e.to_string()))?;
    ensure_version(req.protocol.trim(), MS_HOOK_VERSIONS)?;
    require_non_empty(&req.hook_id, "hook_id")?;
    require_non_empty(&req.session_id, "session_id")?;
    require_non_empty(&req.agent_name, "agent_name")?;
    require_non_empty(&req.target, "target")?;
    let action_class =
        classify_action_kind(req.action_kind.as_deref().unwrap_or(""), &req.tool_name);
    Ok(NormalizedControlCall {
        request_id: req.hook_id,
        spec_version: req.protocol,
        session_id: req.session_id,
        agent_name: req.agent_name,
        action_class,
        target: req.target,
        summary: format!(
            "ms-agent-hooks event={} tool={} has_args={}",
            req.event,
            req.tool_name,
            req.arguments.is_some()
        ),
    })
}

fn parse_conductor(raw: &Value) -> Result<NormalizedControlCall, AcpError> {
    let req: AcpConductorRequest =
        serde_json::from_value(raw.clone()).map_err(|e| AcpError::InvalidPayload(e.to_string()))?;
    ensure_version(req.acp_version.trim(), ACP_CONDUCTOR_VERSIONS)?;
    require_non_empty(&req.call_id, "call_id")?;
    require_non_empty(&req.session_id, "session_id")?;
    require_non_empty(&req.conductor_id, "conductor_id")?;
    require_non_empty(&req.target, "target")?;
    let action_class =
        classify_action_kind(req.action_kind.as_deref().unwrap_or(""), &req.capability);
    Ok(NormalizedControlCall {
        request_id: req.call_id,
        spec_version: req.acp_version,
        session_id: req.session_id,
        agent_name: req.conductor_id,
        action_class,
        target: req.target,
        summary: format!(
            "acp-conductor capability={} has_ctx={}",
            req.capability,
            req.context.is_some()
        ),
    })
}

#[must_use]
pub fn format_dialect_response(
    dialect: AcpProtocolDialect,
    call: &NormalizedControlCall,
    receipt: &DecisionReceipt,
) -> Value {
    let reason = sanitize_untrusted_text(&receipt.reason);
    let retry_token = extract_daemon_retry_token(receipt);
    let modified_target = if receipt.verdict == Verdict::Modify
        && !receipt.target.trim().is_empty()
        && receipt.target != call.target
    {
        Some(sanitize_untrusted_text(&receipt.target))
    } else {
        None
    };
    match dialect {
        AcpProtocolDialect::OwaspAcs => {
            let verdict = match receipt.verdict {
                Verdict::Allow => OwaspAcsVerdict::Allow,
                Verdict::Modify => OwaspAcsVerdict::Modify,
                Verdict::StepUp => OwaspAcsVerdict::RequireApproval,
                Verdict::Defer | Verdict::Deny => OwaspAcsVerdict::Deny,
            };
            serde_json::json!(OwaspAcsResponse {
                spec_version: call.spec_version.clone(),
                request_id: call.request_id.clone(),
                verdict,
                reason,
                rule_id: receipt.rule_id.clone(),
                receipt_id: receipt.receipt_id.clone(),
                receipt_digest: receipt.receipt_digest.clone(),
                retry_token,
                modified_target,
            })
        }
        AcpProtocolDialect::MicrosoftAgentHooks => {
            let decision = match receipt.verdict {
                Verdict::Allow => MsHookDecision::Approve,
                Verdict::Modify => MsHookDecision::Modify,
                Verdict::StepUp => MsHookDecision::StepUp,
                Verdict::Defer | Verdict::Deny => MsHookDecision::Block,
            };
            serde_json::json!(MsAgentHookResponse {
                protocol: call.spec_version.clone(),
                hook_id: call.request_id.clone(),
                decision,
                message: reason,
                receipt_digest: receipt.receipt_digest.clone(),
                retry_token,
                modified_target,
            })
        }
        AcpProtocolDialect::AcpConductor => {
            let verdict = match receipt.verdict {
                Verdict::Allow => AcpConductorOutcome::Allow,
                Verdict::Modify => AcpConductorOutcome::Modify,
                Verdict::StepUp => AcpConductorOutcome::StepUp,
                Verdict::Defer => AcpConductorOutcome::Defer,
                Verdict::Deny => AcpConductorOutcome::Deny,
            };
            serde_json::json!(AcpConductorResponse {
                acp_version: call.spec_version.clone(),
                call_id: call.request_id.clone(),
                verdict,
                reason,
                receipt_id: receipt.receipt_id.clone(),
                retry_token,
                modified_target,
            })
        }
    }
}

fn ensure_version(version: &str, allowed: &[&str]) -> Result<(), AcpError> {
    if allowed.contains(&version) {
        Ok(())
    } else {
        Err(AcpError::UnsupportedVersion(version.to_owned()))
    }
}

fn require_non_empty(value: &str, field: &str) -> Result<(), AcpError> {
    if value.trim().is_empty() {
        Err(AcpError::InvalidPayload(format!("{field} cannot be empty")))
    } else {
        Ok(())
    }
}

fn extract_str(raw: &Value, keys: &[&str]) -> Option<String> {
    let obj = raw.as_object()?;
    for key in keys {
        if let Some(val) = obj.get(*key).and_then(Value::as_str) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return Some(sanitize_untrusted_text(trimmed));
            }
        }
    }
    None
}
