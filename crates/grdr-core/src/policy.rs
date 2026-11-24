// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

pub use grdr_model::eval::{
    essentials_pack, evaluate_attempt as evaluate, evaluate_attempt_mut as evaluate_mut,
    rule_matches, sha256_hex,
};
use grdr_model::{
    ActionAttempt, CommandParseStatus, DecisionReceipt, Grant, KillSwitchState, Mode, PolicyPack,
    PolicyRule, ReplaySample, ReplaySummary, Verdict,
};
use jiff::Timestamp;
use uuid::Uuid;

use crate::analyze::{classify_target, normalize_attempt_target};
use crate::session::SessionRuleState;

const MAX_REPLAY_SAMPLES: usize = 25;

pub fn evaluate_with_session(
    attempt: &ActionAttempt,
    packs: &[PolicyPack],
    grants: &mut [Grant],
    kill_switch: &KillSwitchState,
    session_state: &mut SessionRuleState,
    now: Timestamp,
) -> DecisionReceipt {
    let (normalized_target, command_status) =
        normalize_attempt_target(attempt.action_class, &attempt.target);
    let analysis = classify_target(attempt.action_class, &attempt.target);

    if command_status == CommandParseStatus::Malformed {
        let receipt = build_synthetic_receipt(
            attempt,
            Verdict::Deny,
            "session.malformed-command",
            Mode::Block,
            "Malformed command syntax (unclosed quote or trailing escape) blocked by normalizer.",
            "Fix quoting or inspect the command before retrying.",
            now,
        );
        session_state.record_outcome(attempt, &analysis, receipt.verdict);
        return receipt;
    }

    let mut match_attempt = attempt.clone();
    if !normalized_target.is_empty() {
        match_attempt.target = normalized_target;
    }

    let mut receipt = evaluate_mut(&match_attempt, packs, grants, kill_switch, now);
    receipt.target = attempt.target.clone();

    if receipt.verdict == Verdict::Allow {
        if command_status == CommandParseStatus::Unresolved {
            receipt = evaluate_synthetic_step_up(
                attempt,
                grants,
                "session.opaque-command",
                "Opaque shell construct (subshell, backtick, or encoded command) requires approval.",
                "Review the expanded command and approve in Respond before retrying.",
                now,
            );
        } else if let Some(escalation) = session_state.pre_evaluate_escalation(attempt, &analysis) {
            receipt = evaluate_synthetic_step_up(
                attempt,
                grants,
                escalation.rule_id,
                escalation.reason,
                escalation.next_step,
                now,
            );
        }
    }

    session_state.record_outcome(attempt, &analysis, receipt.verdict);
    receipt
}

pub fn replay_rule(
    attempts: &[ActionAttempt],
    rule: &PolicyRule,
    candidate_mode: Mode,
) -> ReplaySummary {
    let mut candidate_rule = rule.clone();
    candidate_rule.mode = candidate_mode;
    candidate_rule.enabled = candidate_mode != Mode::Off;

    let mut total_scanned: u64 = 0;
    let mut matched: u64 = 0;
    let mut would_ask: u64 = 0;
    let mut would_block: u64 = 0;
    let mut not_matched: u64 = 0;
    let mut samples = Vec::new();

    for attempt in attempts {
        total_scanned = total_scanned.saturating_add(1);
        let (normalized_target, _) =
            normalize_attempt_target(attempt.action_class, &attempt.target);
        let mut match_attempt = attempt.clone();
        if !normalized_target.is_empty() {
            match_attempt.target = normalized_target;
        }

        let current_verdict = if rule_matches(rule, attempt) || rule_matches(rule, &match_attempt) {
            verdict_for_mode(rule.mode)
        } else {
            Verdict::Allow
        };

        let is_hit = if candidate_mode == Mode::Off {
            false
        } else {
            rule_matches(&candidate_rule, attempt) || rule_matches(&candidate_rule, &match_attempt)
        };

        if !is_hit {
            not_matched = not_matched.saturating_add(1);
            continue;
        }

        matched = matched.saturating_add(1);
        let candidate_verdict = verdict_for_mode(candidate_mode);
        match candidate_mode {
            Mode::Ask => {
                would_ask = would_ask.saturating_add(1);
            }
            Mode::Block => {
                would_block = would_block.saturating_add(1);
            }
            Mode::Watch | Mode::Off => {}
        }

        if samples.len() < MAX_REPLAY_SAMPLES {
            samples.push(ReplaySample {
                attempt_id: attempt.id.clone(),
                session_id: attempt.session_id.clone(),
                agent_name: attempt.agent_name.clone(),
                action_class: attempt.action_class,
                target: attempt.target.clone(),
                current_verdict,
                candidate_verdict,
                timestamp: attempt.timestamp,
            });
        }
    }

    ReplaySummary {
        rule_id: rule.id.clone(),
        candidate_mode,
        window_label: "Last 7 days".into(),
        total_scanned,
        matched,
        would_ask,
        would_block,
        not_matched,
        samples,
    }
}

fn evaluate_synthetic_step_up(
    attempt: &ActionAttempt,
    grants: &mut [Grant],
    rule_id: &str,
    reason: &str,
    next_step: &str,
    now: Timestamp,
) -> DecisionReceipt {
    if let Some(grant) = grants
        .iter_mut()
        .find(|g| g.rule_id == rule_id && g.matches(attempt, now))
    {
        let grant_id = grant.grant_id.clone();
        grant.consume_use();
        let digest = synthetic_digest(attempt, Verdict::Allow, rule_id, now);
        return DecisionReceipt {
            receipt_id: format!("rcp_{}", Uuid::now_v7().simple()),
            attempt_id: attempt.id.clone(),
            session_id: attempt.session_id.clone(),
            device_id: attempt.device_id.clone(),
            agent_name: attempt.agent_name.clone(),
            action_class: attempt.action_class,
            control_point: attempt.control_point,
            target: attempt.target.clone(),
            verdict: Verdict::Allow,
            would_be: Some(Verdict::StepUp),
            rule_id: Some(rule_id.into()),
            pack_id: Some("session".into()),
            mode_applied: Some(Mode::Ask),
            grant_id: Some(grant_id.clone()),
            reason: format!("Allowed by active approval grant {grant_id}."),
            next_step: "Action permitted within grant expiry window.".into(),
            receipt_digest: digest,
            decided_at: now,
            key_id: None,
            signature: None,
            signature_verified: None,
        };
    }

    build_synthetic_receipt(
        attempt,
        Verdict::StepUp,
        rule_id,
        Mode::Ask,
        reason,
        next_step,
        now,
    )
}

fn build_synthetic_receipt(
    attempt: &ActionAttempt,
    verdict: Verdict,
    rule_id: &str,
    mode: Mode,
    reason: &str,
    next_step: &str,
    now: Timestamp,
) -> DecisionReceipt {
    DecisionReceipt {
        receipt_id: format!("rcp_{}", Uuid::now_v7().simple()),
        attempt_id: attempt.id.clone(),
        session_id: attempt.session_id.clone(),
        device_id: attempt.device_id.clone(),
        agent_name: attempt.agent_name.clone(),
        action_class: attempt.action_class,
        control_point: attempt.control_point,
        target: attempt.target.clone(),
        verdict,
        would_be: None,
        rule_id: Some(rule_id.into()),
        pack_id: Some("session".into()),
        mode_applied: Some(mode),
        grant_id: None,
        reason: reason.into(),
        next_step: next_step.into(),
        receipt_digest: synthetic_digest(attempt, verdict, rule_id, now),
        decided_at: now,
        key_id: None,
        signature: None,
        signature_verified: None,
    }
}

fn synthetic_digest(
    attempt: &ActionAttempt,
    verdict: Verdict,
    rule_id: &str,
    now: Timestamp,
) -> String {
    let payload = format!(
        "{}:{}:{}:{}:{:?}:{}:{}",
        attempt.session_id,
        attempt.agent_name,
        attempt.action_class.as_str(),
        attempt.target,
        verdict,
        rule_id,
        now.as_second()
    );
    sha256_hex(payload.as_bytes())
}

fn verdict_for_mode(mode: Mode) -> Verdict {
    match mode {
        Mode::Off | Mode::Watch => Verdict::Allow,
        Mode::Ask => Verdict::StepUp,
        Mode::Block => Verdict::Deny,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use grdr_model::{ActionClass, ApprovalGrade, ControlPoint, RuleMatch};
    use jiff::Timestamp;

    fn sample_attempt(id: &str, class: ActionClass, target: &str) -> ActionAttempt {
        ActionAttempt {
            id: id.into(),
            session_id: "s1".into(),
            device_id: "d1".into(),
            device_name: "host".into(),
            agent_name: "claude-code".into(),
            action_class: class,
            control_point: ControlPoint::Hook,
            target: target.into(),
            summary: target.into(),
            timestamp: Timestamp::from_second(1_700_000_000).unwrap(),
        }
    }

    #[test]
    fn replay_counts_matches_accurately_before_promotion() {
        let rule = PolicyRule {
            id: "test.egress".into(),
            title: "Outbound curl".into(),
            description: "Track curl transfers".into(),
            mode: Mode::Watch,
            min_grade: ApprovalGrade::G1,
            enabled: true,
            locked: false,
            matcher: RuleMatch {
                action_classes: vec![ActionClass::Exec],
                target_prefixes: vec![],
                target_contains: vec!["curl ".into()],
                agents: vec![],
            },
            hits: 0,
            would_ask_hits: 0,
            would_block_hits: 0,
            reason_template: "Outbound transfer".into(),
        };

        let attempts = vec![
            sample_attempt("1", ActionClass::Exec, "curl https://webhook.site/abc"),
            sample_attempt("2", ActionClass::Exec, "git status"),
        ];

        let summary = replay_rule(&attempts, &rule, Mode::Block);
        assert_eq!(summary.total_scanned, 2);
        assert_eq!(summary.matched, 1);
        assert_eq!(summary.would_block, 1);
        assert_eq!(summary.not_matched, 1);
        assert_eq!(summary.samples.len(), 1);
    }

    #[test]
    fn evaluate_with_session_blocks_traversal_and_malformed_and_escalates_taint() {
        let now = Timestamp::from_second(1_700_000_000).unwrap();
        let packs = vec![essentials_pack()];
        let mut grants = Vec::new();
        let mut session_state = SessionRuleState::new("s1");

        let traversal = sample_attempt(
            "a1",
            ActionClass::FileWrite,
            "workspace/../../.claude/settings.json",
        );
        let r1 = evaluate_with_session(
            &traversal,
            &packs,
            &mut grants,
            &KillSwitchState::Inactive,
            &mut session_state,
            now,
        );
        assert_eq!(r1.verdict, Verdict::Deny);
        assert_eq!(r1.target, "workspace/../../.claude/settings.json");

        let malformed = sample_attempt("a2", ActionClass::Exec, r#"bash -c "unclosed"#);
        let r2 = evaluate_with_session(
            &malformed,
            &packs,
            &mut grants,
            &KillSwitchState::Inactive,
            &mut session_state,
            now,
        );
        assert_eq!(r2.verdict, Verdict::Deny);
        assert_eq!(r2.rule_id.as_deref(), Some("session.malformed-command"));

        let opaque = sample_attempt("a3", ActionClass::Exec, "echo $(id)");
        let r3 = evaluate_with_session(
            &opaque,
            &packs,
            &mut grants,
            &KillSwitchState::Inactive,
            &mut session_state,
            now,
        );
        assert_eq!(r3.verdict, Verdict::StepUp);
        assert_eq!(r3.rule_id.as_deref(), Some("session.opaque-command"));

        let cred = sample_attempt("a4", ActionClass::FileRead, "~/.ssh/id_rsa");
        let _ = evaluate_with_session(
            &cred,
            &packs,
            &mut grants,
            &KillSwitchState::Inactive,
            &mut session_state,
            now,
        );
        let exfil = sample_attempt(
            "a5",
            ActionClass::NetRequest,
            "https://example.test/collect",
        );
        let r5 = evaluate_with_session(
            &exfil,
            &packs,
            &mut grants,
            &KillSwitchState::Inactive,
            &mut session_state,
            now,
        );
        assert_eq!(r5.verdict, Verdict::StepUp);
        assert_eq!(
            r5.rule_id.as_deref(),
            Some("session.tainted-exfil-escalation")
        );
    }
}
