// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Hook-broker deny-wins merge and D-14 / D-15 250ms ack / 2s exit fail-safe bounds.

use grdr_broker::{BrokerOutcome, McpBroker};
use grdr_core::compile::{compile_floor_table, evaluate_compiled_floor};
use grdr_core::policy::{essentials_pack, evaluate_mut};
use grdr_crypto::{SigningKeypair, verify_bytes};
use grdr_mcp_proto::{McpAttemptContext, ToolDescriptor, parse_mcp_request};
use grdr_model::{
    ActionAttempt, ActionClass, CodedError, DecisionReceipt, KillSwitchState, PolicyPack,
    SigningKeypairExt as _, TrustedKeyInfo, Verdict,
};
use grdr_ports::DecisionEnginePort;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{ConformanceError, ScenarioCategory, ScenarioOutcome, ScenarioResult};

pub const HOOK_ACK_BUDGET_MS: u64 = 250;
pub const SHIM_MAX_EXIT_MS: u64 = 2_000;
const HANDOVER_DOMAIN: &str = "shim_handover_ack";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderResponse {
    pub provider_id: String,
    pub verdict: Verdict,
    pub modifies_payload: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoverAck {
    pub daemon_elapsed_ms: u64,
    pub handover_deadline_ms: u64,
    pub verdict: Verdict,
    pub action_class: ActionClass,
    pub target: String,
    pub signer_key_id: String,
    pub signature_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailSafeEvalResult {
    pub verdict: Verdict,
    pub effective_deadline_ms: u64,
    pub used_fail_safe_table: bool,
    pub rule_id: Option<String>,
}

#[derive(Serialize)]
struct CanonicalHandoverPayload<'a> {
    daemon_elapsed_ms: u64,
    handover_deadline_ms: u64,
    verdict: Verdict,
    action_class: ActionClass,
    target: &'a str,
}

struct LiveBrokerEngine {
    packs: Vec<PolicyPack>,
}

impl DecisionEnginePort for LiveBrokerEngine {
    fn load_packs(&mut self, packs: Vec<PolicyPack>) -> Result<(), CodedError> {
        self.packs = packs;
        Ok(())
    }

    fn add_grant(&mut self, _grant: grdr_model::Grant) -> Result<(), CodedError> {
        Ok(())
    }

    fn evaluate(&mut self, attempt: &ActionAttempt) -> Result<DecisionReceipt, CodedError> {
        Ok(evaluate_mut(
            attempt,
            &self.packs,
            &mut [],
            &KillSwitchState::Inactive,
            attempt.timestamp,
        ))
    }
}

pub fn sign_handover_ack(
    keypair: &SigningKeypair,
    daemon_elapsed_ms: u64,
    handover_deadline_ms: u64,
    verdict: Verdict,
    action_class: ActionClass,
    target: &str,
) -> Result<HandoverAck, ConformanceError> {
    let payload = serde_json::to_vec(&CanonicalHandoverPayload {
        daemon_elapsed_ms,
        handover_deadline_ms,
        verdict,
        action_class,
        target,
    })
    .map_err(|e| ConformanceError::ScenarioFailed {
        scenario_id: "D14-HANDOVER-SIGN".into(),
        detail: e.to_string(),
    })?;
    Ok(HandoverAck {
        daemon_elapsed_ms,
        handover_deadline_ms,
        verdict,
        action_class,
        target: target.to_owned(),
        signer_key_id: keypair.key_id().to_owned(),
        signature_b64: keypair.sign_bytes(HANDOVER_DOMAIN, &payload),
    })
}

pub fn merge_provider_verdicts(
    responses: &[ProviderResponse],
) -> Result<Verdict, ConformanceError> {
    let modify_count = responses.iter().filter(|r| r.modifies_payload).count();
    if modify_count > 1 {
        return Err(ConformanceError::MultipleModifyProviders);
    }

    let mut merged = Verdict::Allow;
    for resp in responses {
        merged = stricter_verdict(merged, resp.verdict);
    }
    Ok(merged)
}

pub fn simulate_shim_fail_safe_eval(
    ack: Option<&HandoverAck>,
    trusted_key: Option<&TrustedKeyInfo>,
    handover_deadline_ms: Option<u64>,
    action_class: ActionClass,
    agent: &str,
    target: &str,
    now: Timestamp,
) -> Result<FailSafeEvalResult, ConformanceError> {
    if let Some(handover) = handover_deadline_ms
        && handover > SHIM_MAX_EXIT_MS
    {
        return Err(ConformanceError::HandoverCeilingExceeded {
            requested_ms: handover,
        });
    }

    let ack_limit = handover_deadline_ms.unwrap_or(HOOK_ACK_BUDGET_MS);
    if let (Some(h), Some(key)) = (ack, trusted_key)
        && h.daemon_elapsed_ms <= ack_limit
        && h.handover_deadline_ms <= ack_limit
        && h.signer_key_id == key.key_id
        && h.action_class == action_class
        && h.target == target
        && let Ok(payload) = serde_json::to_vec(&CanonicalHandoverPayload {
            daemon_elapsed_ms: h.daemon_elapsed_ms,
            handover_deadline_ms: h.handover_deadline_ms,
            verdict: h.verdict,
            action_class: h.action_class,
            target: &h.target,
        })
        && verify_bytes(
            &key.public_key_b64,
            HANDOVER_DOMAIN,
            &payload,
            &h.signature_b64,
        )
        .is_ok()
    {
        return Ok(FailSafeEvalResult {
            verdict: h.verdict,
            effective_deadline_ms: ack_limit,
            used_fail_safe_table: false,
            rule_id: None,
        });
    }

    let floor = compile_floor_table(&[essentials_pack()], now);
    if let Some(hit) = evaluate_compiled_floor(&floor, action_class, agent, target) {
        return Ok(FailSafeEvalResult {
            verdict: hit.verdict,
            effective_deadline_ms: ack_limit.min(SHIM_MAX_EXIT_MS),
            used_fail_safe_table: true,
            rule_id: Some(hit.rule_id),
        });
    }

    Ok(FailSafeEvalResult {
        verdict: Verdict::Allow,
        effective_deadline_ms: ack_limit.min(SHIM_MAX_EXIT_MS),
        used_fail_safe_table: true,
        rule_id: None,
    })
}

pub fn run_broker_and_bounds_checks() -> Result<Vec<ScenarioResult>, ConformanceError> {
    let now = Timestamp::from_second(1_700_000_000).unwrap_or(Timestamp::UNIX_EPOCH);

    let merged = merge_provider_verdicts(&[
        ProviderResponse {
            provider_id: "p1".into(),
            verdict: Verdict::Allow,
            modifies_payload: false,
        },
        ProviderResponse {
            provider_id: "p2".into(),
            verdict: Verdict::StepUp,
            modifies_payload: false,
        },
        ProviderResponse {
            provider_id: "p3".into(),
            verdict: Verdict::Deny,
            modifies_payload: false,
        },
    ])?;
    if merged != Verdict::Deny {
        return Err(ConformanceError::ScenarioFailed {
            scenario_id: "BRK-DENY-WINS".into(),
            detail: "provider fan-out failed deny-wins merge".into(),
        });
    }

    let multi_mod = merge_provider_verdicts(&[
        ProviderResponse {
            provider_id: "p1".into(),
            verdict: Verdict::Modify,
            modifies_payload: true,
        },
        ProviderResponse {
            provider_id: "p2".into(),
            verdict: Verdict::Modify,
            modifies_payload: true,
        },
    ]);
    if !matches!(multi_mod, Err(ConformanceError::MultipleModifyProviders)) {
        return Err(ConformanceError::ScenarioFailed {
            scenario_id: "BRK-SINGLE-MODIFY".into(),
            detail: "expected MultipleModifyProviders error".into(),
        });
    }

    verify_live_mcp_broker_block(now)?;

    let kp = SigningKeypair::generate().map_err(|e| ConformanceError::ScenarioFailed {
        scenario_id: "D14-ACK-SIGN".into(),
        detail: e.to_string(),
    })?;
    let mut forged_ack = sign_handover_ack(
        &kp,
        50,
        HOOK_ACK_BUDGET_MS,
        Verdict::Allow,
        ActionClass::FileWrite,
        ".claude/settings.json",
    )?;
    forged_ack.signature_b64 = "forged_invalid_signature".into();
    let forged_fallback = simulate_shim_fail_safe_eval(
        Some(&forged_ack),
        Some(&kp.public_info()),
        None,
        ActionClass::FileWrite,
        "claude-code",
        "repo/sub/../../.claude/settings.json",
        now,
    )?;
    if !forged_fallback.used_fail_safe_table || forged_fallback.verdict != Verdict::Deny {
        return Err(ConformanceError::ScenarioFailed {
            scenario_id: "D14-ACK-250MS".into(),
            detail: "unverified handover or ack miss did not fall back fail-closed to floor".into(),
        });
    }

    let bad_handover = simulate_shim_fail_safe_eval(
        None,
        None,
        Some(2_500),
        ActionClass::Exec,
        "claude-code",
        "git status",
        now,
    );
    if !matches!(
        bad_handover,
        Err(ConformanceError::HandoverCeilingExceeded { .. })
    ) {
        return Err(ConformanceError::ScenarioFailed {
            scenario_id: "D14-EXIT-2S".into(),
            detail: "handover marker above 2000ms was not rejected".into(),
        });
    }

    Ok(vec![
        ScenarioResult {
            id: "BRK-DENY-WINS".into(),
            category: ScenarioCategory::BrokerBounds,
            title: "Hook and live MCP broker deny-wins and single-MODIFY cap".into(),
            outcome: ScenarioOutcome::Pass,
            detail: "verified".into(),
        },
        ScenarioResult {
            id: "D14-FAILSAFE-BOUNDS".into(),
            category: ScenarioCategory::BrokerBounds,
            title: "Signed handover check, 250ms ack fallback, and 2s ceiling bounds".into(),
            outcome: ScenarioOutcome::Pass,
            detail: "verified".into(),
        },
    ])
}

fn verify_live_mcp_broker_block(now: Timestamp) -> Result<(), ConformanceError> {
    let mut pack = essentials_pack();
    for rule in &mut pack.rules {
        if rule.id == "essentials.mcp-unpinned-write" {
            rule.mode = grdr_model::Mode::Block;
        }
    }
    let mut broker = McpBroker::new(LiveBrokerEngine { packs: vec![pack] });
    let read_tool = ToolDescriptor {
        name: "read_file".into(),
        description: "Read file in workspace".into(),
        input_schema: json!({"type": "object"}),
    };
    let write_tool = ToolDescriptor {
        name: "write_file".into(),
        description: "Write file to workspace".into(),
        input_schema: json!({"type": "object"}),
    };
    let _ = broker
        .register_or_verify_tools("fs", &[read_tool.clone(), write_tool.clone()])
        .map_err(|e| ConformanceError::ScenarioFailed {
            scenario_id: "BRK-LIVE-DENY".into(),
            detail: e.to_string(),
        })?;
    let ctx = McpAttemptContext {
        attempt_id: "brk-live-1".into(),
        session_id: "ses_brk_1".into(),
        device_id: "dev_brk_1".into(),
        device_name: "conformance-host".into(),
        agent_name: "claude-code".into(),
        server_name: "fs".into(),
        timestamp: now,
    };
    let read_req = parse_mcp_request(
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"README.md"}}}"#,
    )
    .map_err(|e| ConformanceError::ScenarioFailed {
        scenario_id: "BRK-LIVE-DENY".into(),
        detail: e.to_string(),
    })?;
    let read_outcome = broker
        .mediate_call(&read_req, Some(&read_tool), &ctx)
        .map_err(|e| ConformanceError::ScenarioFailed {
            scenario_id: "BRK-LIVE-DENY".into(),
            detail: e.to_string(),
        })?;
    if read_outcome != BrokerOutcome::Forward {
        return Err(ConformanceError::ScenarioFailed {
            scenario_id: "BRK-LIVE-DENY".into(),
            detail: "clean MCP read_file should Forward".into(),
        });
    }
    let write_req = parse_mcp_request(
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_file","arguments":{"path":".claude/settings.json"}}}"#,
    )
    .map_err(|e| ConformanceError::ScenarioFailed {
        scenario_id: "BRK-LIVE-DENY".into(),
        detail: e.to_string(),
    })?;
    let outcome = broker
        .mediate_call(&write_req, Some(&write_tool), &ctx)
        .map_err(|e| ConformanceError::ScenarioFailed {
            scenario_id: "BRK-LIVE-DENY".into(),
            detail: e.to_string(),
        })?;
    if !matches!(outcome, BrokerOutcome::Block { .. }) {
        return Err(ConformanceError::ScenarioFailed {
            scenario_id: "BRK-LIVE-DENY".into(),
            detail: "live McpBroker failed to Block write_file when essentials.mcp-writes is Block"
                .into(),
        });
    }
    Ok(())
}

fn stricter_verdict(a: Verdict, b: Verdict) -> Verdict {
    if verdict_rank(b) > verdict_rank(a) {
        b
    } else {
        a
    }
}

fn verdict_rank(v: Verdict) -> u8 {
    match v {
        Verdict::Allow => 0,
        Verdict::Modify => 1,
        Verdict::Defer => 2,
        Verdict::StepUp => 3,
        Verdict::Deny => 4,
    }
}
