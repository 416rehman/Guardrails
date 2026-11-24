// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Bundle compilation to the floor and fail-safe tables and interest sets.

use jiff::Timestamp;

use grdr_fastpath::{
    FLOOR_FORMAT_VERSION, FastActionClass, FastVerdict, FloorRuleRef, evaluate_floor_entries,
};
use grdr_model::{ActionClass, CompiledFloorRule, CompiledFloorTable, Mode, PolicyPack, Verdict};

use crate::analyze::normalize_attempt_target;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FloorMatch {
    pub rule_id: String,
    pub verdict: Verdict,
    pub reason: String,
}

pub fn compile_floor_table(packs: &[PolicyPack], now: Timestamp) -> CompiledFloorTable {
    let mut rules = Vec::new();
    for pack in packs {
        for rule in &pack.rules {
            if !rule.enabled || rule.mode != Mode::Block {
                continue;
            }
            rules.push(CompiledFloorRule {
                rule_id: rule.id.clone(),
                action_classes: rule.matcher.action_classes.clone(),
                target_prefixes: rule.matcher.target_prefixes.clone(),
                target_contains: rule.matcher.target_contains.clone(),
                agents: rule.matcher.agents.clone(),
                verdict: Verdict::Deny,
                reason: rule.reason_template.clone(),
            });
        }
    }

    CompiledFloorTable {
        version: FLOOR_FORMAT_VERSION,
        compiled_at: now,
        rules,
        key_id: None,
        signature: None,
    }
}

pub fn evaluate_compiled_floor(
    table: &CompiledFloorTable,
    action_class: ActionClass,
    agent: &str,
    target: &str,
) -> Option<FloorMatch> {
    let fast_action = to_fast_action(action_class);
    let (normalized_target, _) = normalize_attempt_target(action_class, target);

    let prefix_slices: Vec<Vec<&str>> = table
        .rules
        .iter()
        .map(|r| r.target_prefixes.iter().map(String::as_str).collect())
        .collect();
    let contains_slices: Vec<Vec<&str>> = table
        .rules
        .iter()
        .map(|r| r.target_contains.iter().map(String::as_str).collect())
        .collect();
    let agent_slices: Vec<Vec<&str>> = table
        .rules
        .iter()
        .map(|r| r.agents.iter().map(String::as_str).collect())
        .collect();

    let mut entries = Vec::with_capacity(table.rules.len());
    for (idx, rule) in table.rules.iter().enumerate() {
        let action_mask = rule
            .action_classes
            .iter()
            .fold(0u32, |mask, c| mask | to_fast_action(*c).bit());
        entries.push(FloorRuleRef {
            rule_id: &rule.rule_id,
            action_mask,
            prefixes: prefix_slices.get(idx).map(Vec::as_slice).unwrap_or(&[]),
            contains: contains_slices.get(idx).map(Vec::as_slice).unwrap_or(&[]),
            agents: agent_slices.get(idx).map(Vec::as_slice).unwrap_or(&[]),
            verdict: to_fast_verdict(rule.verdict),
        });
    }

    let hit = evaluate_floor_entries(&entries, fast_action, agent, target).or_else(|| {
        if normalized_target != target {
            evaluate_floor_entries(&entries, fast_action, agent, &normalized_target)
        } else {
            None
        }
    })?;

    let reason = table
        .rules
        .iter()
        .find(|r| r.rule_id == hit.rule_id)
        .map(|r| r.reason.clone())
        .unwrap_or_else(|| "Blocked by compiled Guardrails ADR floor rule.".into());

    Some(FloorMatch {
        rule_id: hit.rule_id.into(),
        verdict: from_fast_verdict(hit.verdict),
        reason,
    })
}

fn to_fast_action(action: ActionClass) -> FastActionClass {
    match action {
        ActionClass::Exec => FastActionClass::Exec,
        ActionClass::FileRead => FastActionClass::FileRead,
        ActionClass::FileWrite => FastActionClass::FileWrite,
        ActionClass::FileDelete => FastActionClass::FileDelete,
        ActionClass::NetConnect => FastActionClass::NetConnect,
        ActionClass::NetRequest => FastActionClass::NetRequest,
        ActionClass::LlmRequest => FastActionClass::LlmRequest,
        ActionClass::McpConnect => FastActionClass::McpConnect,
        ActionClass::McpCall => FastActionClass::McpCall,
        ActionClass::CredUse => FastActionClass::CredUse,
        ActionClass::AgentSpawn => FastActionClass::AgentSpawn,
        ActionClass::ConfigChange => FastActionClass::ConfigChange,
        ActionClass::Elevate => FastActionClass::Elevate,
        ActionClass::UiAct => FastActionClass::UiAct,
        ActionClass::DataFlow => FastActionClass::DataFlow,
    }
}

fn to_fast_verdict(verdict: Verdict) -> FastVerdict {
    match verdict {
        Verdict::Allow | Verdict::Modify => FastVerdict::Allow,
        Verdict::StepUp | Verdict::Defer => FastVerdict::StepUp,
        Verdict::Deny => FastVerdict::Deny,
    }
}

fn from_fast_verdict(verdict: FastVerdict) -> Verdict {
    match verdict {
        FastVerdict::Allow => Verdict::Allow,
        FastVerdict::StepUp => Verdict::StepUp,
        FastVerdict::Deny => Verdict::Deny,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{essentials_pack, evaluate};
    use grdr_model::{ActionAttempt, ControlPoint, KillSwitchState};

    #[test]
    fn compiled_floor_matches_core_evaluator_on_block_rules() {
        let now = Timestamp::from_second(1_700_000_000).unwrap();
        let packs = vec![essentials_pack()];
        let floor = compile_floor_table(&packs, now);
        assert_eq!(floor.rules.len(), 2);

        let cases = [
            (ActionClass::FileWrite, ".claude/settings.json", true),
            (
                ActionClass::FileWrite,
                "repo/src/../../.claude/settings.json",
                true,
            ),
            (
                ActionClass::Exec,
                "claude --dangerously-skip-permissions",
                true,
            ),
            (ActionClass::Exec, "git status", false),
        ];

        for (class, target, expect_deny) in cases {
            let floor_hit = evaluate_compiled_floor(&floor, class, "claude-code", target);
            assert_eq!(floor_hit.is_some(), expect_deny);

            if expect_deny && !target.contains("..") {
                let attempt = ActionAttempt {
                    id: "att".into(),
                    session_id: "s1".into(),
                    device_id: "d1".into(),
                    device_name: "h1".into(),
                    agent_name: "claude-code".into(),
                    action_class: class,
                    control_point: ControlPoint::Hook,
                    target: target.into(),
                    summary: target.into(),
                    timestamp: now,
                };
                let full = evaluate(&attempt, &packs, &[], &KillSwitchState::Inactive, now);
                assert_eq!(full.verdict, Verdict::Deny);
                assert_eq!(floor_hit.unwrap().rule_id, full.rule_id.unwrap());
            }
        }
    }
}
