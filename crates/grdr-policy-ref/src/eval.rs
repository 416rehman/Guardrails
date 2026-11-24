// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Table-free reference evaluator over PolicyPack, Grant, KillSwitchState, and ActionAttempt.

use std::cmp::Reverse;
use std::collections::BTreeSet;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use grdr_model::{
    ActionAttempt, ActionClass, ApprovalGrade, CommandParseStatus, Grant, KillSwitchState, Mode,
    PolicyPack, PolicyRule, SessionLabel, Verdict,
};

use crate::normalize::{
    TargetSignals, analyze_attempt_signals, normalize_target_for_match, rule_is_final,
    validate_inline_cedar_stub,
};

const REPEATED_DENIALS_THRESHOLD: u32 = 2;

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

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RefSessionState {
    pub session_id: String,
    pub labels: BTreeSet<SessionLabel>,
    pub denial_count: u32,
    pub step_up_count: u32,
    pub event_seq: u64,
}

struct RuleMatchCandidate<'a> {
    pack_id: &'a str,
    rule: &'a PolicyRule,
}

impl RefSessionState {
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            labels: BTreeSet::new(),
            denial_count: 0,
            step_up_count: 0,
            event_seq: 0,
        }
    }

    fn pre_evaluate_escalation(
        &self,
        attempt: &ActionAttempt,
        signals: &TargetSignals,
    ) -> Option<(&'static str, &'static str)> {
        let is_outbound = matches!(
            attempt.action_class,
            ActionClass::NetRequest | ActionClass::NetConnect | ActionClass::DataFlow
        ) || signals.external_network;

        if self.labels.contains(&SessionLabel::CredentialAccessed) && is_outbound {
            return Some((
                "session.tainted-exfil-escalation",
                "Outbound network or data flow attempted after sensitive credential access in this session.",
            ));
        }
        if self.labels.contains(&SessionLabel::UntrustedWebFetched)
            && matches!(
                attempt.action_class,
                ActionClass::Exec | ActionClass::Elevate
            )
            && signals.risk_score >= 45
        {
            return Some((
                "session.untrusted-web-exec",
                "High-risk command execution attempted after external web content was fetched in this session.",
            ));
        }
        if self.labels.contains(&SessionLabel::RepeatedDenials)
            && matches!(
                attempt.action_class,
                ActionClass::Exec | ActionClass::Elevate | ActionClass::FileDelete
            )
        {
            return Some((
                "session.repeated-denials-escalation",
                "Session crossed the repeated-denials threshold and requires step-up approval for privileged actions.",
            ));
        }
        None
    }

    fn record_outcome(
        &mut self,
        attempt: &ActionAttempt,
        signals: &TargetSignals,
        verdict: Verdict,
    ) {
        self.event_seq = self.event_seq.saturating_add(1);

        if attempt.action_class == ActionClass::CredUse || signals.sensitive_credential {
            self.labels.insert(SessionLabel::CredentialAccessed);
        }

        let is_outbound = matches!(
            attempt.action_class,
            ActionClass::NetRequest | ActionClass::NetConnect | ActionClass::DataFlow
        ) || signals.external_network;

        if is_outbound {
            if self.labels.contains(&SessionLabel::CredentialAccessed) {
                self.labels.insert(SessionLabel::TaintedExfilRisk);
            }
            if matches!(
                attempt.action_class,
                ActionClass::NetRequest | ActionClass::NetConnect
            ) {
                self.labels.insert(SessionLabel::UntrustedWebFetched);
            }
        }

        if verdict == Verdict::Deny {
            self.denial_count = self.denial_count.saturating_add(1);
            if self.denial_count >= REPEATED_DENIALS_THRESHOLD {
                self.labels.insert(SessionLabel::RepeatedDenials);
            }
        } else if verdict == Verdict::StepUp {
            self.step_up_count = self.step_up_count.saturating_add(1);
        }
    }
}

pub fn evaluate_ref(
    attempt: &ActionAttempt,
    packs: &[PolicyPack],
    grants: &[Grant],
    kill_switch: &KillSwitchState,
    now: Timestamp,
) -> ReferenceDecision {
    for pack in packs {
        for rule in &pack.rules {
            if rule.enabled
                && rule.mode != Mode::Off
                && let Some(cedar) = rule.cedar.as_deref()
                && !cedar.trim().is_empty()
                && !validate_inline_cedar_stub(cedar)
            {
                return ReferenceDecision {
                    verdict: Verdict::Deny,
                    would_be: None,
                    rule_id: Some("policy.compile-error".into()),
                    pack_id: Some("system".into()),
                    mode_applied: Some(Mode::Block),
                    grant_id: None,
                    reason: format!(
                        "Policy rule `{}` failed inline Cedar syntax validation.",
                        rule.id
                    ),
                };
            }
        }
    }

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
            if !rule.enabled || rule.mode == Mode::Off || !rule_matches_attempt(rule, attempt) {
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
        let is_final = rule_is_final(cand.rule);
        let liftable = cand.rule.mode == Mode::Ask || (cand.rule.mode == Mode::Block && !is_final);
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
    consume_matching_grant(&decision, grants);
    decision
}

pub fn evaluate_ref_with_session(
    attempt: &ActionAttempt,
    packs: &[PolicyPack],
    grants: &mut [Grant],
    kill_switch: &KillSwitchState,
    session_state: &mut RefSessionState,
    now: Timestamp,
) -> ReferenceDecision {
    let signals = analyze_attempt_signals(attempt);
    if signals.command_status == CommandParseStatus::Malformed {
        let decision = ReferenceDecision {
            verdict: Verdict::Deny,
            would_be: None,
            rule_id: Some("session.malformed-command".into()),
            pack_id: Some("session".into()),
            mode_applied: Some(Mode::Block),
            grant_id: None,
            reason:
                "Malformed command syntax (unclosed quote or trailing escape) blocked by normalizer."
                    .into(),
        };
        session_state.record_outcome(attempt, &signals, decision.verdict);
        return decision;
    }

    let mut match_attempt = attempt.clone();
    if !signals.normalized_target.is_empty() {
        match_attempt.target = signals.normalized_target.clone();
    }

    let mut decision = evaluate_ref(&match_attempt, packs, grants, kill_switch, now);
    consume_matching_grant(&decision, grants);

    if decision.verdict == Verdict::Allow {
        if signals.command_status == CommandParseStatus::Unresolved {
            decision = evaluate_synthetic_step_up_ref(
                attempt,
                grants,
                "session.opaque-command",
                "Opaque shell construct (subshell, backtick, or encoded command) requires approval.",
                now,
            );
        } else if let Some((rule_id, reason)) =
            session_state.pre_evaluate_escalation(attempt, &signals)
        {
            decision = evaluate_synthetic_step_up_ref(attempt, grants, rule_id, reason, now);
        }
    }

    session_state.record_outcome(attempt, &signals, decision.verdict);
    decision
}

fn consume_matching_grant(decision: &ReferenceDecision, grants: &mut [Grant]) {
    if let Some(grant_id) = decision.grant_id.as_deref()
        && let Some(grant) = grants.iter_mut().find(|g| g.grant_id == grant_id)
    {
        grant.consume_use();
    }
}

fn evaluate_synthetic_step_up_ref(
    attempt: &ActionAttempt,
    grants: &mut [Grant],
    rule_id: &str,
    reason: &str,
    now: Timestamp,
) -> ReferenceDecision {
    if let Some(grant) = grants
        .iter_mut()
        .find(|g| g.rule_id == rule_id && g.grade >= ApprovalGrade::G1 && g.matches(attempt, now))
    {
        let grant_id = grant.grant_id.clone();
        grant.consume_use();
        return ReferenceDecision {
            verdict: Verdict::Allow,
            would_be: Some(Verdict::StepUp),
            rule_id: Some(rule_id.into()),
            pack_id: Some("session".into()),
            mode_applied: Some(Mode::Ask),
            grant_id: Some(grant_id.clone()),
            reason: format!("Allowed by active approval grant {grant_id}."),
        };
    }

    ReferenceDecision {
        verdict: Verdict::StepUp,
        would_be: None,
        rule_id: Some(rule_id.into()),
        pack_id: Some("session".into()),
        mode_applied: Some(Mode::Ask),
        grant_id: None,
        reason: reason.into(),
    }
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
    let (norm_target, _) = normalize_target_for_match(attempt.action_class, &attempt.target);
    let norm_lower = norm_target.to_ascii_lowercase();

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
