// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Deterministic session rules state machine writing enforcing labels.

use std::collections::{BTreeMap, BTreeSet};

use grdr_model::{
    ActionAttempt, ActionClass, DecisionReceipt, SessionLabel, SessionSummary, Verdict,
};

use crate::analyze::{TargetAnalysis, classify_target};

const REPEATED_DENIALS_THRESHOLD: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SessionRuleState {
    pub session_id: String,
    pub labels: BTreeSet<SessionLabel>,
    pub denial_count: u32,
    pub step_up_count: u32,
    pub event_seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionEscalation {
    pub rule_id: &'static str,
    pub reason: &'static str,
    pub next_step: &'static str,
}

impl SessionRuleState {
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            labels: BTreeSet::new(),
            denial_count: 0,
            step_up_count: 0,
            event_seq: 0,
        }
    }

    pub fn labels_vec(&self) -> Vec<SessionLabel> {
        self.labels.iter().copied().collect()
    }

    pub fn pre_evaluate_escalation(
        &self,
        attempt: &ActionAttempt,
        analysis: &TargetAnalysis,
    ) -> Option<SessionEscalation> {
        let is_outbound = matches!(
            attempt.action_class,
            ActionClass::NetRequest | ActionClass::NetConnect | ActionClass::DataFlow
        ) || analysis.risk_tags.iter().any(|t| t == "external-network");

        if self.labels.contains(&SessionLabel::CredentialAccessed) && is_outbound {
            return Some(SessionEscalation {
                rule_id: "session.tainted-exfil-escalation",
                reason: "Outbound network or data flow attempted after sensitive credential access in this session.",
                next_step: "Review destination and grant a scoped approval in Respond before retrying.",
            });
        }

        if self.labels.contains(&SessionLabel::UntrustedWebFetched)
            && matches!(
                attempt.action_class,
                ActionClass::Exec | ActionClass::Elevate
            )
            && analysis.risk_score >= 45
        {
            return Some(SessionEscalation {
                rule_id: "session.untrusted-web-exec",
                reason: "High-risk command execution attempted after external web content was fetched in this session.",
                next_step: "Verify the command was not driven by untrusted fetched content and approve in Respond.",
            });
        }

        if self.labels.contains(&SessionLabel::RepeatedDenials)
            && matches!(
                attempt.action_class,
                ActionClass::Exec | ActionClass::Elevate | ActionClass::FileDelete
            )
        {
            return Some(SessionEscalation {
                rule_id: "session.repeated-denials-escalation",
                reason: "Session crossed the repeated-denials threshold and requires step-up approval for privileged actions.",
                next_step: "Inspect prior blocked attempts in Sessions and approve or freeze the session in Respond.",
            });
        }

        None
    }

    pub fn record_outcome(
        &mut self,
        attempt: &ActionAttempt,
        analysis: &TargetAnalysis,
        verdict: Verdict,
    ) {
        self.event_seq = self.event_seq.saturating_add(1);

        if attempt.action_class == ActionClass::CredUse
            || analysis
                .risk_tags
                .iter()
                .any(|t| t == "sensitive-credential")
        {
            self.labels.insert(SessionLabel::CredentialAccessed);
        }

        let is_outbound = matches!(
            attempt.action_class,
            ActionClass::NetRequest | ActionClass::NetConnect | ActionClass::DataFlow
        ) || analysis.risk_tags.iter().any(|t| t == "external-network");

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

pub fn replay_session_states(
    attempts: &[ActionAttempt],
    receipts: &[DecisionReceipt],
) -> BTreeMap<String, SessionRuleState> {
    let mut receipt_by_attempt: BTreeMap<&str, Verdict> = BTreeMap::new();
    for receipt in receipts {
        receipt_by_attempt.insert(receipt.attempt_id.as_str(), receipt.verdict);
    }

    let mut ordered_attempts: Vec<&ActionAttempt> = attempts.iter().collect();
    ordered_attempts.sort_by_key(|a| a.timestamp);

    let mut states: BTreeMap<String, SessionRuleState> = BTreeMap::new();
    for attempt in ordered_attempts {
        let verdict = receipt_by_attempt
            .get(attempt.id.as_str())
            .copied()
            .unwrap_or(Verdict::Allow);
        let analysis = classify_target(attempt.action_class, &attempt.target);
        let state = states
            .entry(attempt.session_id.clone())
            .or_insert_with(|| SessionRuleState::new(attempt.session_id.clone()));
        state.record_outcome(attempt, &analysis, verdict);
    }
    states
}

pub fn attach_session_labels(
    summaries: &mut [SessionSummary],
    states: &BTreeMap<String, SessionRuleState>,
) {
    for summary in summaries {
        if let Some(state) = states.get(&summary.id) {
            summary.labels = state.labels_vec();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use grdr_model::{ControlPoint, summarize_sessions};
    use jiff::Timestamp;

    fn sample_attempt(
        id: &str,
        session_id: &str,
        class: ActionClass,
        target: &str,
    ) -> ActionAttempt {
        ActionAttempt {
            id: id.into(),
            session_id: session_id.into(),
            device_id: "dev-1".into(),
            device_name: "host".into(),
            agent_name: "claude-code".into(),
            action_class: class,
            control_point: ControlPoint::Hook,
            target: target.into(),
            summary: target.into(),
            timestamp: Timestamp::from_second(1_700_000_000).unwrap(),
            ..Default::default()
        }
    }

    #[test]
    fn credential_access_plus_outbound_network_sets_taint_and_escalates() {
        let mut state = SessionRuleState::new("sess-1");

        let cred_read = sample_attempt("a1", "sess-1", ActionClass::FileRead, "~/.ssh/id_rsa");
        let cred_analysis = classify_target(cred_read.action_class, &cred_read.target);
        assert!(
            state
                .pre_evaluate_escalation(&cred_read, &cred_analysis)
                .is_none()
        );
        state.record_outcome(&cred_read, &cred_analysis, Verdict::StepUp);
        assert!(state.labels.contains(&SessionLabel::CredentialAccessed));

        let egress = sample_attempt(
            "a2",
            "sess-1",
            ActionClass::NetRequest,
            "https://example.test/upload",
        );
        let egress_analysis = classify_target(egress.action_class, &egress.target);
        let esc = state
            .pre_evaluate_escalation(&egress, &egress_analysis)
            .expect("tainted egress should escalate");
        assert_eq!(esc.rule_id, "session.tainted-exfil-escalation");
        state.record_outcome(&egress, &egress_analysis, Verdict::StepUp);
        assert!(state.labels.contains(&SessionLabel::TaintedExfilRisk));
    }

    #[test]
    fn two_denials_trigger_repeated_denials_label_and_escalation() {
        let mut state = SessionRuleState::new("sess-2");
        let bad = sample_attempt(
            "a1",
            "sess-2",
            ActionClass::FileWrite,
            ".claude/settings.json",
        );
        let bad_analysis = classify_target(bad.action_class, &bad.target);

        state.record_outcome(&bad, &bad_analysis, Verdict::Deny);
        assert!(!state.labels.contains(&SessionLabel::RepeatedDenials));

        state.record_outcome(&bad, &bad_analysis, Verdict::Deny);
        assert!(state.labels.contains(&SessionLabel::RepeatedDenials));

        let exec = sample_attempt("a3", "sess-2", ActionClass::Exec, "cargo test");
        let exec_analysis = classify_target(exec.action_class, &exec.target);
        let esc = state
            .pre_evaluate_escalation(&exec, &exec_analysis)
            .expect("repeated denials should escalate exec");
        assert_eq!(esc.rule_id, "session.repeated-denials-escalation");
    }

    #[test]
    fn replay_attaches_labels_to_session_summaries() {
        let a1 = sample_attempt("a1", "sess-r", ActionClass::FileRead, "~/.aws/credentials");
        let a2 = sample_attempt(
            "a2",
            "sess-r",
            ActionClass::NetConnect,
            "https://webhook.site/exfil",
        );
        let attempts = vec![a1, a2];
        let states = replay_session_states(&attempts, &[]);
        let mut summaries = summarize_sessions(&attempts, &[]);
        attach_session_labels(&mut summaries, &states);
        let labels = &summaries.first().unwrap().labels;
        assert!(labels.contains(&SessionLabel::CredentialAccessed));
        assert!(labels.contains(&SessionLabel::TaintedExfilRisk));
    }
}
