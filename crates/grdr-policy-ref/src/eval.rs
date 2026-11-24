// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Table-free reference evaluator over PolicyPack, Grant, KillSwitchState, and ActionAttempt.

use std::cmp::Reverse;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use grdr_model::{
    ActionAttempt, ActionClass, Grant, KillSwitchState, Mode, PolicyPack, PolicyRule, Verdict,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceDecision {
    pub verdict: Verdict,
    pub would_be: Option<Verdict>,
    pub rule_id: Option<String>,
    pub pack_id: Option<String>,
    pub mode_applied: Option<Mode>,
    pub grant_id: Option<String>,
    pub reason: String,
}

struct RuleMatchCandidate<'a> {
    pack_id: &'a str,
    rule: &'a PolicyRule,
}

pub fn evaluate_ref(
    attempt: &ActionAttempt,
    packs: &[PolicyPack],
    grants: &[Grant],
    kill_switch: &KillSwitchState,
    now: Timestamp,
) -> ReferenceDecision {
    if kill_switch.is_active_for(&attempt.session_id, &attempt.device_id, now) {
        return ReferenceDecision {
            verdict: Verdict::Deny,
            would_be: None,
            rule_id: Some("system.kill-switch".into()),
            pack_id: Some("system".into()),
            mode_applied: Some(Mode::Block),
            grant_id: None,
            reason: "Kill switch or freeze active for session/device.".into(),
        };
    }

    let mut enforced_hits: Vec<RuleMatchCandidate<'_>> = Vec::new();
    let mut watch_hits: Vec<RuleMatchCandidate<'_>> = Vec::new();

    for pack in packs {
        for rule in &pack.rules {
            if !rule.enabled || rule.mode == Mode::Off {
                continue;
            }
            if !rule_matches_attempt(rule, attempt) {
                continue;
            }
            match rule.mode {
                Mode::Watch => watch_hits.push(RuleMatchCandidate {
                    pack_id: &pack.id,
                    rule,
                }),
                Mode::Ask | Mode::Block => enforced_hits.push(RuleMatchCandidate {
                    pack_id: &pack.id,
                    rule,
                }),
                Mode::Off => {}
            }
        }
    }

    let mut blocking_hits: Vec<RuleMatchCandidate<'_>> = Vec::new();
    let mut lifted_hits: Vec<(RuleMatchCandidate<'_>, &Grant)> = Vec::new();

    for cand in enforced_hits {
        let liftable =
            cand.rule.mode == Mode::Ask || (cand.rule.mode == Mode::Block && !cand.rule.locked);
        let matching_grant = if liftable {
            grants.iter().find(|g| {
                g.rule_id == cand.rule.id
                    && g.grade >= cand.rule.min_grade
                    && g.matches(attempt, now)
            })
        } else {
            None
        };
        if let Some(grant) = matching_grant {
            lifted_hits.push((cand, grant));
        } else {
            blocking_hits.push(cand);
        }
    }

    blocking_hits.sort_by_key(|c| Reverse(c.rule.mode));
    if let Some(top) = blocking_hits.first() {
        let verdict = if top.rule.mode == Mode::Block {
            Verdict::Deny
        } else {
            Verdict::StepUp
        };
        return ReferenceDecision {
            verdict,
            would_be: None,
            rule_id: Some(top.rule.id.clone()),
            pack_id: Some(top.pack_id.to_owned()),
            mode_applied: Some(top.rule.mode),
            grant_id: None,
            reason: top.rule.reason_template.clone(),
        };
    }

    lifted_hits.sort_by_key(|(c, _)| Reverse(c.rule.mode));
    if let Some((top, grant)) = lifted_hits.first() {
        return ReferenceDecision {
            verdict: Verdict::Allow,
            would_be: Some(Verdict::StepUp),
            rule_id: Some(top.rule.id.clone()),
            pack_id: Some(top.pack_id.to_owned()),
            mode_applied: Some(top.rule.mode),
            grant_id: Some(grant.grant_id.clone()),
            reason: format!("Allowed by active approval grant {}.", grant.grant_id),
        };
    }

    if let Some(watch) = watch_hits.first() {
        return ReferenceDecision {
            verdict: Verdict::Allow,
            would_be: Some(Verdict::StepUp),
            rule_id: Some(watch.rule.id.clone()),
            pack_id: Some(watch.pack_id.to_owned()),
            mode_applied: Some(Mode::Watch),
            grant_id: None,
            reason: watch.rule.reason_template.clone(),
        };
    }

    ReferenceDecision {
        verdict: Verdict::Allow,
        would_be: None,
        rule_id: None,
        pack_id: None,
        mode_applied: None,
        grant_id: None,
        reason: "No policy rule restricted this action.".into(),
    }
}

pub fn evaluate_ref_mut(
    attempt: &ActionAttempt,
    packs: &[PolicyPack],
    grants: &mut [Grant],
    kill_switch: &KillSwitchState,
    now: Timestamp,
) -> ReferenceDecision {
    let decision = evaluate_ref(attempt, packs, grants, kill_switch, now);
    if let Some(grant_id) = decision.grant_id.as_deref()
        && let Some(grant) = grants.iter_mut().find(|g| g.grant_id == grant_id)
    {
        grant.consume_use();
    }
    decision
}

fn rule_matches_attempt(rule: &PolicyRule, attempt: &ActionAttempt) -> bool {
    if !rule.matcher.action_classes.is_empty()
        && !rule.matcher.action_classes.contains(&attempt.action_class)
    {
        return false;
    }
    if !rule.matcher.agents.is_empty() {
        let agent_norm = attempt.agent_name.trim().to_ascii_lowercase();
        let agent_hit = rule
            .matcher
            .agents
            .iter()
            .any(|a| a.trim().to_ascii_lowercase() == agent_norm);
        if !agent_hit {
            return false;
        }
    }

    let raw_lower = attempt.target.replace('\\', "/").to_ascii_lowercase();
    let norm_lower = normalize_target_for_match(attempt.action_class, &attempt.target);

    if rule.id == "essentials.privilege-elevation" && attempt.action_class == ActionClass::Elevate {
        return true;
    }

    if rule.matcher.target_prefixes.is_empty() && rule.matcher.target_contains.is_empty() {
        return true;
    }

    let prefix_hit = rule.matcher.target_prefixes.iter().any(|prefix| {
        let p = prefix.replace('\\', "/").to_ascii_lowercase();
        !p.is_empty() && (raw_lower.starts_with(&p) || norm_lower.starts_with(&p))
    });
    let contains_hit = rule.matcher.target_contains.iter().any(|needle| {
        let n = needle.replace('\\', "/").to_ascii_lowercase();
        !n.is_empty() && (raw_lower.contains(&n) || norm_lower.contains(&n))
    });
    prefix_hit || contains_hit
}

fn normalize_target_for_match(action_class: ActionClass, target: &str) -> String {
    match action_class {
        ActionClass::FileRead
        | ActionClass::FileWrite
        | ActionClass::FileDelete
        | ActionClass::ConfigChange => canonicalize_path_ref(target).to_ascii_lowercase(),
        ActionClass::Exec | ActionClass::Elevate => {
            strip_quotes_and_collapse(target).to_ascii_lowercase()
        }
        _ => target.trim().replace('\\', "/").to_ascii_lowercase(),
    }
}

fn canonicalize_path_ref(raw: &str) -> String {
    let trimmed = raw.trim();
    let without_scheme = trimmed
        .strip_prefix("file:///")
        .map(|rest| format!("/{rest}"))
        .or_else(|| trimmed.strip_prefix("file://").map(str::to_string))
        .unwrap_or_else(|| trimmed.to_string());
    let slashed = without_scheme.replace('\\', "/");
    let (prefix, rest) = if let Some(r) = slashed.strip_prefix("~/") {
        ("~/", r)
    } else if let Some(r) = slashed.strip_prefix('/') {
        ("/", r)
    } else {
        ("", slashed.as_str())
    };
    let mut stack: Vec<&str> = Vec::new();
    for seg in rest.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                let _ = stack.pop();
            }
            other => stack.push(other),
        }
    }
    if prefix.is_empty() && stack.is_empty() {
        return ".".into();
    }
    let joined = stack.join("/");
    if prefix.is_empty() {
        joined
    } else if joined.is_empty() {
        prefix.into()
    } else {
        format!("{prefix}{joined}")
    }
}

fn strip_quotes_and_collapse(raw: &str) -> String {
    let mut out = String::new();
    let mut prev_ws = false;
    for ch in raw.trim().chars() {
        if ch == '\'' || ch == '"' {
            continue;
        }
        if ch.is_ascii_whitespace() {
            if !prev_ws {
                out.push(' ');
                prev_ws = true;
            }
        } else {
            out.push(ch);
            prev_ws = false;
        }
    }
    out
}
