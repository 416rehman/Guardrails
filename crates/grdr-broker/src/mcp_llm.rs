// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! MCP and LLM control-point mediation brokers with configurable white-label branding (`docs/design/07`, `docs/design/26`).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use grdr_core::policy::{ReceiptDigestInput, compute_receipt_digest};
use grdr_llm_proto::LlmRequestMeta;
use grdr_mcp_proto::{
    McpAttemptContext, McpMethod, McpProtoError, McpRequest, PinVerification, ToolDescriptor,
    ToolPin, detect_tool_poisoning, mcp_call_to_attempt, verify_tool_pin,
};
use grdr_messages::{AgentNoticeInput, AgentVerb, NextStepKind, format_agent_message};
use grdr_model::{ActionAttempt, ActionClass, CodedError, ControlPoint, DecisionReceipt, Verdict};
use grdr_ports::DecisionEnginePort;
use grdr_strings::sanitize_untrusted_text;

use crate::brand::BrokerBrand;
use crate::secret_rules::contains_secret_indicator;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BrokerError {
    #[error("GRDR-BRK-0001: decision engine error: {0}")]
    EngineFailure(String),
    #[error("GRDR-BRK-0002: malformed broker request frame: {0}")]
    InvalidFrame(String),
    #[error("GRDR-BRK-0003: tool descriptor rejected due to poisoning signal on {tool_name}")]
    PoisonedTool { tool_name: String },
    #[error("GRDR-BRK-0004: session is frozen after repeated refusals")]
    SessionFrozen,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerState {
    Active,
    DegradedOffline,
    Frozen,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum BrokerOutcome {
    Forward,
    Ask {
        message: String,
        receipt: DecisionReceipt,
    },
    Block {
        message: String,
        receipt: DecisionReceipt,
    },
}

#[derive(Debug)]
pub struct McpBroker<E: DecisionEnginePort> {
    engine: E,
    pins: BTreeMap<String, ToolPin>,
    state: BrokerState,
    brand: BrokerBrand,
}

#[derive(Debug)]
pub struct LlmBroker<E: DecisionEnginePort> {
    engine: E,
    state: BrokerState,
    brand: BrokerBrand,
}

impl From<McpProtoError> for BrokerError {
    fn from(value: McpProtoError) -> Self {
        Self::InvalidFrame(value.to_string())
    }
}

impl From<CodedError> for BrokerError {
    fn from(value: CodedError) -> Self {
        Self::EngineFailure(value.display_line())
    }
}

impl<E: DecisionEnginePort> McpBroker<E> {
    #[must_use]
    pub fn new(engine: E) -> Self {
        Self::with_brand(engine, BrokerBrand::workspace_default())
    }

    #[must_use]
    pub fn with_brand(engine: E, brand: BrokerBrand) -> Self {
        Self {
            engine,
            pins: BTreeMap::new(),
            state: BrokerState::Active,
            brand,
        }
    }

    #[must_use]
    pub fn brand(&self) -> &BrokerBrand {
        &self.brand
    }

    #[must_use]
    pub fn state(&self) -> BrokerState {
        self.state
    }

    pub fn set_state(&mut self, state: BrokerState) {
        self.state = state;
    }

    #[must_use]
    pub fn pinned_tools(&self) -> &BTreeMap<String, ToolPin> {
        &self.pins
    }

    pub fn register_or_verify_tools(
        &mut self,
        server_name: &str,
        tools: &[ToolDescriptor],
    ) -> Result<Vec<(String, PinVerification)>, BrokerError> {
        let mut results = Vec::with_capacity(tools.len());
        for desc in tools {
            let findings = detect_tool_poisoning(desc);
            if !findings.is_empty() {
                return Err(BrokerError::PoisonedTool {
                    tool_name: sanitize_untrusted_text(&desc.name),
                });
            }
            let key = pin_key(server_name, &desc.name);
            match self.pins.get(&key) {
                Some(existing) => {
                    let verification = verify_tool_pin(desc, Some(existing));
                    results.push((desc.name.clone(), verification));
                }
                None => {
                    let pin = ToolPin::from_descriptor(server_name, desc);
                    self.pins.insert(key, pin);
                    results.push((desc.name.clone(), PinVerification::Matched));
                }
            }
        }
        Ok(results)
    }

    pub fn mediate_call(
        &mut self,
        req: &McpRequest,
        desc: Option<&ToolDescriptor>,
        ctx: &McpAttemptContext,
    ) -> Result<BrokerOutcome, BrokerError> {
        if self.state == BrokerState::Frozen {
            return Err(BrokerError::SessionFrozen);
        }

        if let (McpMethod::ToolsCall, Some(tool_desc)) = (&req.method, desc) {
            if req.tool_name.as_deref() != Some(tool_desc.name.as_str()) {
                return Err(BrokerError::InvalidFrame(
                    "tool descriptor name does not match request tool_name".into(),
                ));
            }
            let safe_name = sanitize_untrusted_text(&tool_desc.name);
            if !detect_tool_poisoning(tool_desc).is_empty() {
                return Err(BrokerError::PoisonedTool {
                    tool_name: safe_name,
                });
            }
            let key = pin_key(&ctx.server_name, &tool_desc.name);
            let status = verify_tool_pin(tool_desc, self.pins.get(&key));
            if let PinVerification::Drifted { expected, actual } = status {
                let attempt = mcp_call_to_attempt(req, ctx)?;
                let mut receipt = self.engine.evaluate(&attempt)?;
                receipt.verdict = Verdict::Deny;
                receipt.rule_id = Some("essentials.mcp-pin-drift".into());
                receipt.reason = format!(
                    "MCP tool schema pin drifted for {safe_name}: expected {expected}, saw {actual}"
                );
                receipt.receipt_digest = compute_receipt_digest(&ReceiptDigestInput {
                    attempt_id: &receipt.attempt_id,
                    session_id: &receipt.session_id,
                    agent_name: &receipt.agent_name,
                    action_class: receipt.action_class,
                    target: &receipt.target,
                    verdict: receipt.verdict,
                    rule_id: receipt.rule_id.as_deref(),
                    decided_at: receipt.decided_at,
                });
                let message = format_agent_message(&AgentNoticeInput {
                    brand: self.brand.product_name.clone(),
                    verb: AgentVerb::Blocked,
                    action_class: "mcp.call".into(),
                    status_code: "GRDR-MCP-0004".into(),
                    rule_id: "essentials.mcp-pin-drift".into(),
                    reference: receipt.receipt_id.clone(),
                    reason: receipt.reason.clone(),
                    next_step: NextStepKind::Blocked,
                });
                return Ok(BrokerOutcome::Block { message, receipt });
            }
        }

        let attempt = mcp_call_to_attempt(req, ctx)?;
        let mut receipt = self.engine.evaluate(&attempt)?;
        if self.state == BrokerState::DegradedOffline && receipt.verdict == Verdict::Allow {
            escalate_degraded_receipt(&mut receipt);
        }
        Ok(outcome_from_receipt(&self.brand.product_name, receipt))
    }
}

impl<E: DecisionEnginePort> LlmBroker<E> {
    #[must_use]
    pub fn new(engine: E) -> Self {
        Self::with_brand(engine, BrokerBrand::workspace_default())
    }

    #[must_use]
    pub fn with_brand(engine: E, brand: BrokerBrand) -> Self {
        Self {
            engine,
            state: BrokerState::Active,
            brand,
        }
    }

    #[must_use]
    pub fn brand(&self) -> &BrokerBrand {
        &self.brand
    }

    #[must_use]
    pub fn state(&self) -> BrokerState {
        self.state
    }

    pub fn set_state(&mut self, state: BrokerState) {
        self.state = state;
    }

    pub fn mediate_request(
        &mut self,
        meta: &LlmRequestMeta,
        prompt_preview: &str,
        ctx: &McpAttemptContext,
    ) -> Result<BrokerOutcome, BrokerError> {
        if self.state == BrokerState::Frozen {
            return Err(BrokerError::SessionFrozen);
        }

        let safe_provider = sanitize_uri_segment(&meta.provider);
        let safe_model = sanitize_uri_segment(meta.model.as_deref().unwrap_or("default"));
        let secret_hit = contains_secret_indicator(prompt_preview);
        let target = if secret_hit {
            format!("llm://{safe_provider}/secret-egress-detected")
        } else {
            format!("llm://{safe_provider}/{safe_model}")
        };

        let attempt = ActionAttempt {
            id: ctx.attempt_id.clone(),
            session_id: ctx.session_id.clone(),
            device_id: ctx.device_id.clone(),
            device_name: ctx.device_name.clone(),
            agent_name: ctx.agent_name.clone(),
            action_class: ActionClass::LlmRequest,
            control_point: ControlPoint::Proxy,
            target,
            summary: format!(
                "LLM request to {} ({} messages, {} tools)",
                safe_provider,
                meta.message_count,
                meta.tool_names.len()
            ),
            timestamp: ctx.timestamp,
            ..Default::default()
        };

        let mut receipt = self.engine.evaluate(&attempt)?;
        if self.state == BrokerState::DegradedOffline && receipt.verdict == Verdict::Allow {
            escalate_degraded_receipt(&mut receipt);
        }
        Ok(outcome_from_receipt(&self.brand.product_name, receipt))
    }
}

fn escalate_degraded_receipt(receipt: &mut DecisionReceipt) {
    receipt.verdict = Verdict::StepUp;
    receipt.rule_id = Some("broker.degraded_offline".into());
    receipt.reason =
        "broker operating in degraded offline mode; owner step-up confirmation required".into();
    receipt.next_step = "Approve or retry after daemon connection is restored.".into();
    receipt.receipt_digest = compute_receipt_digest(&ReceiptDigestInput {
        attempt_id: &receipt.attempt_id,
        session_id: &receipt.session_id,
        agent_name: &receipt.agent_name,
        action_class: receipt.action_class,
        target: &receipt.target,
        verdict: receipt.verdict,
        rule_id: receipt.rule_id.as_deref(),
        decided_at: receipt.decided_at,
    });
}

fn sanitize_uri_segment(raw: &str) -> String {
    let cleaned: String = sanitize_untrusted_text(raw)
        .chars()
        .map(|c| {
            if matches!(c, '/' | '?' | '#' | '@' | '\\' | ' ') {
                '_'
            } else {
                c
            }
        })
        .collect();
    if cleaned.is_empty() {
        "unknown".into()
    } else {
        cleaned
    }
}

fn pin_key(server: &str, tool: &str) -> String {
    format!("{server}::{tool}")
}

fn outcome_from_receipt(brand: &str, receipt: DecisionReceipt) -> BrokerOutcome {
    let action_class = format!("{:?}", receipt.action_class).to_ascii_lowercase();
    let rule_id = receipt
        .rule_id
        .clone()
        .unwrap_or_else(|| "policy.default".to_owned());

    match receipt.verdict {
        Verdict::Allow => BrokerOutcome::Forward,
        Verdict::Modify | Verdict::StepUp | Verdict::Defer => {
            let message = format_agent_message(&AgentNoticeInput {
                brand: brand.to_owned(),
                verb: AgentVerb::Held,
                action_class,
                status_code: "GRDR-DEC-0001".into(),
                rule_id,
                reference: receipt.receipt_id.clone(),
                reason: receipt.reason.clone(),
                next_step: NextStepKind::RetryAfterApproval {
                    approver: "the device owner".into(),
                },
            });
            BrokerOutcome::Ask { message, receipt }
        }
        Verdict::Deny => {
            let message = format_agent_message(&AgentNoticeInput {
                brand: brand.to_owned(),
                verb: AgentVerb::Blocked,
                action_class,
                status_code: "GRDR-DEC-0002".into(),
                rule_id,
                reference: receipt.receipt_id.clone(),
                reason: receipt.reason.clone(),
                next_step: NextStepKind::Blocked,
            });
            BrokerOutcome::Block { message, receipt }
        }
    }
}
