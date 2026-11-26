// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Bundle compilation to the floor and fail-safe tables and interest sets.

use std::str::FromStr;

use cedar_policy::{Effect, PolicySet};
use jiff::Timestamp;

use grdr_fastpath::{
    BinaryFloorTable, BinaryRuleInput, FLOOR_FORMAT_VERSION, FastActionClass, FastVerdict,
    FastpathError, FloorRuleRef, LABEL_CREDENTIAL_ACCESSED, LABEL_REPEATED_DENIALS,
    LABEL_TAINTED_EXFIL, LABEL_UNTRUSTED_WEB, PRINCIPAL_PROCESS, PRINCIPAL_SESSION,
    encode_binary_floor, encoded_binary_floor_size, evaluate_floor_entries,
};
use grdr_model::{
    ActionClass, CompiledFloorRule, CompiledFloorTable, Mode, PolicyPack, SessionLabel, Verdict,
};

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
            if !is_floor_eligible_rule(rule) {
                continue;
            }
            let action_classes = match rule.cedar.as_deref().filter(|s| !s.trim().is_empty()) {
                Some(cedar) => crate::policy::extract_policy_actions_for_compile(cedar),
                None => rule.matcher.action_classes.clone(),
            };
            rules.push(CompiledFloorRule {
                rule_id: rule.id.clone(),
                action_classes,
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

fn has_non_bypass_facts(body: &str) -> bool {
    let body_ns: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    if !body_ns.contains("context.facts") {
        return false;
    }
    const BYPASS_FLAGS: &[&str] = &[
        "flag.bypass-permissions",
        "flag.hooks-disabled",
        "flag.no-sandbox",
        "grdr.disable",
    ];
    let mut rest = body;
    while let Some((_, after_q)) = rest.split_once('"') {
        let Some((lit, tail)) = after_q.split_once('"') else {
            return true;
        };
        if !BYPASS_FLAGS.contains(&lit) {
            return true;
        }
        rest = tail;
    }
    false
}

fn is_floor_eligible_rule(rule: &grdr_model::PolicyRule) -> bool {
    if !rule.enabled || rule.mode != Mode::Block || !rule.locked {
        return false;
    }
    let has_matchers =
        !rule.matcher.target_prefixes.is_empty() || !rule.matcher.target_contains.is_empty();
    let Some(cedar) = rule.cedar.as_deref().filter(|s| !s.trim().is_empty()) else {
        return !rule.matcher.action_classes.is_empty() && has_matchers;
    };
    let Ok(parsed_set) = PolicySet::from_str(cedar) else {
        return false;
    };
    let mut policies = parsed_set.policies();
    let (Some(policy), None) = (policies.next(), policies.next()) else {
        return false;
    };
    if policy.effect() != Effect::Forbid
        || policy.annotation("final") != Some("true")
        || policy.annotation("remedy").is_some()
        || policy.annotation("obligation") == Some("snapshot")
        || crate::policy::body_has_unless_clause_for_compile(cedar)
    {
        return false;
    }
    let canon = policy.to_string();
    let raw_body = crate::policy::cedar_body_slice_for_compile(&canon);
    let body = crate::policy::strip_comments_for_compile(raw_body, false);
    let body_with_strings = crate::policy::strip_comments_for_compile(raw_body, true);
    let header_len = crate::policy::scope_header_slice_for_compile(&body_with_strings).len();
    let cond_with_strings = body_with_strings.get(header_len..).unwrap_or("");
    let dynamic_tokens = [
        "context.session",
        "context.source_labels",
        "context.assurance",
        "context.attribution",
        "context.control_point",
        "context.cloud",
        "context.tenant",
        "context.http",
        "context.args",
        "context.child",
        "context.change_classes",
        "context.recursive",
        "resource.in_workspace",
        "resource.port",
        "resource.identity_pinned",
        "resource.manifest_pinned",
        "resource.write_capable",
        "resource.provider",
        "resource.transport",
        "resource.kind",
        "resource.digest_pinned",
        "resource.has_scripts",
        "resource.requests_broad_tools",
        "resource.bidi_obfuscation",
        "principal in",
        "principal.",
        " like ",
    ];
    if dynamic_tokens.iter().any(|t| body.contains(t)) || has_non_bypass_facts(cond_with_strings) {
        return false;
    }
    has_matchers
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

    let raw_hit = evaluate_floor_entries(&entries, fast_action, agent, target);
    let norm_hit = if normalized_target != target {
        evaluate_floor_entries(&entries, fast_action, agent, &normalized_target)
    } else {
        None
    };
    let hit = match (raw_hit, norm_hit) {
        (Some(a), Some(b)) => Some(if (b.verdict as u8) > (a.verdict as u8) {
            b
        } else {
            a
        }),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }?;

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

pub fn compile_binary_floor_table(packs: &[PolicyPack]) -> Result<Vec<u8>, FastpathError> {
    let floor = compile_floor_table(packs, Timestamp::UNIX_EPOCH);
    let prefix_slices: Vec<Vec<&str>> = floor
        .rules
        .iter()
        .map(|r| r.target_prefixes.iter().map(String::as_str).collect())
        .collect();
    let contains_slices: Vec<Vec<&str>> = floor
        .rules
        .iter()
        .map(|r| r.target_contains.iter().map(String::as_str).collect())
        .collect();
    let agent_slices: Vec<Vec<&str>> = floor
        .rules
        .iter()
        .map(|r| r.agents.iter().map(String::as_str).collect())
        .collect();

    let mut principal_masks = Vec::with_capacity(floor.rules.len());
    for rule in &floor.rules {
        let cedar_opt = packs
            .iter()
            .flat_map(|p| &p.rules)
            .find(|r| r.id == rule.rule_id)
            .and_then(|r| r.cedar.as_deref());
        let mask = match cedar_opt {
            None => PRINCIPAL_SESSION,
            Some(cedar) => {
                let body = crate::policy::strip_comments_for_compile(
                    crate::policy::cedar_body_slice_for_compile(cedar),
                    true,
                );
                let header = crate::policy::scope_header_slice_for_compile(&body);
                if header.contains("principal is Grdr::Session") {
                    PRINCIPAL_SESSION
                } else if header.contains("principal is Grdr::Process") {
                    PRINCIPAL_PROCESS
                } else {
                    PRINCIPAL_SESSION | PRINCIPAL_PROCESS
                }
            }
        };
        principal_masks.push(mask);
    }

    let mut inputs = Vec::with_capacity(floor.rules.len());
    for (idx, rule) in floor.rules.iter().enumerate() {
        let action_mask = rule
            .action_classes
            .iter()
            .fold(0u32, |mask, c| mask | to_fast_action(*c).bit());
        inputs.push(BinaryRuleInput {
            rule_id: &rule.rule_id,
            reason: &rule.reason,
            action_mask,
            principal_mask: principal_masks
                .get(idx)
                .copied()
                .unwrap_or(PRINCIPAL_SESSION | PRINCIPAL_PROCESS),
            label_mask: 0,
            verdict: to_fast_verdict(rule.verdict),
            agents: agent_slices.get(idx).map(Vec::as_slice).unwrap_or(&[]),
            prefixes: prefix_slices.get(idx).map(Vec::as_slice).unwrap_or(&[]),
            contains: contains_slices.get(idx).map(Vec::as_slice).unwrap_or(&[]),
        });
    }

    let (needed, _) = encoded_binary_floor_size(&inputs)?;
    let mut buf = vec![0u8; needed];
    let len = encode_binary_floor(&inputs, &mut buf)?;
    buf.truncate(len);
    Ok(buf)
}

pub fn evaluate_binary_floor(
    bytes: &[u8],
    action_class: ActionClass,
    principal_is_session: bool,
    labels: &[SessionLabel],
    agent: &str,
    target: &str,
) -> Result<Option<FloorMatch>, FastpathError> {
    let table = BinaryFloorTable::parse(bytes)?;
    let fast_action = to_fast_action(action_class);
    let principal_mask = if principal_is_session {
        PRINCIPAL_SESSION
    } else {
        PRINCIPAL_PROCESS
    };
    let label_mask = labels.iter().fold(0u16, |acc, lbl| {
        acc | match lbl {
            SessionLabel::CredentialAccessed => LABEL_CREDENTIAL_ACCESSED,
            SessionLabel::UntrustedWebFetched => LABEL_UNTRUSTED_WEB,
            SessionLabel::RepeatedDenials => LABEL_REPEATED_DENIALS,
            SessionLabel::TaintedExfilRisk => LABEL_TAINTED_EXFIL,
        }
    });
    let (normalized, _) = normalize_attempt_target(action_class, target);
    let raw_hit = table.evaluate(fast_action, principal_mask, label_mask, agent, target);
    let norm_hit = if normalized != target {
        table.evaluate(fast_action, principal_mask, label_mask, agent, &normalized)
    } else {
        None
    };
    let hit = match (raw_hit, norm_hit) {
        (Some(a), Some(b)) => Some(if (b.verdict as u8) > (a.verdict as u8) {
            b
        } else {
            a
        }),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    };
    Ok(hit.map(|h| FloorMatch {
        rule_id: h.rule_id.into(),
        verdict: from_fast_verdict(h.verdict),
        reason: h.reason.into(),
    }))
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
                    ..Default::default()
                };
                let full = evaluate(&attempt, &packs, &[], &KillSwitchState::Inactive, now);
                assert_eq!(full.verdict, Verdict::Deny);
                assert_eq!(floor_hit.unwrap().rule_id, full.rule_id.unwrap());
            }
        }

        let bin = compile_binary_floor_table(&packs).unwrap();
        let bin_hit = evaluate_binary_floor(
            &bin,
            ActionClass::FileWrite,
            true,
            &[],
            "claude-code",
            ".claude/settings.json",
        )
        .unwrap()
        .unwrap();
        assert_eq!(bin_hit.rule_id, "essentials.agent-control-files");
        assert_eq!(bin_hit.verdict, Verdict::Deny);
    }
}
