// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Hook-broker deny-wins merge and D-14 / D-15 250ms ack / 2s exit fail-safe bounds.

use grdr_core::compile::{compile_floor_table, evaluate_compiled_floor};
use grdr_core::policy::essentials_pack;
use grdr_model::{ActionClass, Verdict};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::{ConformanceError, ScenarioCategory, ScenarioOutcome, ScenarioResult};

pub const HOOK_ACK_BUDGET_MS: u64 = 250;
pub const SHIM_MAX_EXIT_MS: u64 = 2_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderResponse {
    pub provider_id: String,
    pub verdict: Verdict,
    pub modifies_payload: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailSafeEvalResult {
    pub verdict: Verdict,
    pub effective_deadline_ms: u64,
    pub used_fail_safe_table: bool,
    pub rule_id: Option<String>,
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
    daemon_ack_ms: Option<u64>,
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
    let ack_missed = match daemon_ack_ms {
        Some(elapsed) => elapsed > ack_limit,
        None => true,
    };

    if !ack_missed {
        return Ok(FailSafeEvalResult {
            verdict: Verdict::Allow,
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

    let fs_ctrl = simulate_shim_fail_safe_eval(
        Some(300),
        None,
        ActionClass::FileWrite,
        "claude-code",
        "repo/sub/../../.claude/settings.json",
        now,
    )?;
    if !fs_ctrl.used_fail_safe_table
        || fs_ctrl.verdict != Verdict::Deny
        || fs_ctrl.effective_deadline_ms != HOOK_ACK_BUDGET_MS
    {
        return Err(ConformanceError::ScenarioFailed {
            scenario_id: "D14-ACK-250MS".into(),
            detail: "250ms ack miss did not trigger fail-safe floor denial".into(),
        });
    }

    let bad_handover = simulate_shim_fail_safe_eval(
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
            title: "Hook broker provider deny-wins and single-MODIFY cap".into(),
            outcome: ScenarioOutcome::Pass,
            detail: "verified".into(),
        },
        ScenarioResult {
            id: "D14-FAILSAFE-BOUNDS".into(),
            category: ScenarioCategory::BrokerBounds,
            title: "250ms ack fallback and 2s handover ceiling bounds".into(),
            outcome: ScenarioOutcome::Pass,
            detail: "verified".into(),
        },
    ])
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
