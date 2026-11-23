// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use grdr_model::eval::rule_matches;
pub use grdr_model::eval::{essentials_pack, evaluate_attempt as evaluate};
use grdr_model::{ActionAttempt, Mode, PolicyRule, ReplaySample, ReplaySummary, Verdict};

const MAX_REPLAY_SAMPLES: usize = 25;

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
        let current_verdict = if rule_matches(rule, attempt) {
            verdict_for_mode(rule.mode)
        } else {
            Verdict::Allow
        };

        let is_hit = if candidate_mode == Mode::Off {
            false
        } else {
            rule_matches(&candidate_rule, attempt)
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

    #[test]
    fn replay_counts_matches_accurately_before_promotion() {
        let now = Timestamp::from_second(1_700_000_000).unwrap();
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
            ActionAttempt {
                id: "1".into(),
                session_id: "s1".into(),
                device_id: "d1".into(),
                device_name: "host".into(),
                agent_name: "claude-code".into(),
                action_class: ActionClass::Exec,
                control_point: ControlPoint::Hook,
                target: "curl https://webhook.site/abc".into(),
                summary: "curl upload".into(),
                timestamp: now,
            },
            ActionAttempt {
                id: "2".into(),
                session_id: "s1".into(),
                device_id: "d1".into(),
                device_name: "host".into(),
                agent_name: "claude-code".into(),
                action_class: ActionClass::Exec,
                control_point: ControlPoint::Hook,
                target: "git status".into(),
                summary: "git status".into(),
                timestamp: now,
            },
        ];

        let summary = replay_rule(&attempts, &rule, Mode::Block);
        assert_eq!(summary.total_scanned, 2);
        assert_eq!(summary.matched, 1);
        assert_eq!(summary.would_block, 1);
        assert_eq!(summary.not_matched, 1);
        assert_eq!(summary.samples.len(), 1);
    }
}
