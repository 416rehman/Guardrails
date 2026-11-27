// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Deterministic session rules state machine writing enforcing labels (`D-54`, `D-28`).

pub mod baseline;
mod baseline_guard;
pub mod graph;
pub mod join;
pub mod lifecycle;
pub mod reconcile;
pub mod replay;
pub mod rules;
pub mod taint;
mod taint_validate;

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use grdr_model::{ActionAttempt, ActionClass, ApprovalGrade, SessionLabel, Verdict};

pub use graph::{
    ChildSessionSpawnPlan, ChildSpawnRequest, EdgeKind, GraphNodeKind, LineageBreakKind,
    LineageEdge, LineageGraph, format_outward_identity,
};
pub use join::{
    AttributionRecord, CorrelationKeyKind, EvidenceGrade, HostSharingMode, JoinCandidate,
    JoinConsumptionState, JoinContext, JoinResult, K4MatchStrength, ProcessRoleHint,
    ProvenanceKind, SessionActorKind, grade_for_evidence, resolve_correlation_join,
    satisfies_unless_floor, supersede_attribution,
};
pub use lifecycle::{
    ClaimClosureState, GrantInheritancePolicy, SessionCloseTrigger, SessionConstraints,
    SessionLifecyclePhase, SessionRecord, SessionRegistry, StartBasis, stricter_mode,
};
pub use reconcile::{
    DivergenceKind, HookObservation, ReconciliationFinding, ReconciliationInput, SensorObservation,
    reconcile_session_evidence,
};
pub use replay::{attach_session_labels, replay_session_states, replay_session_states_checked};

use crate::analyze::TargetAnalysis;
use crate::session::baseline::{
    MASS_CHANGE_THRESHOLD_DEFAULT, MassChangeBreakerState, WorkspaceBaselineTracker,
};
use crate::session::rules::{DynamicSessionEscalation, SessionRuleSet};
use crate::session::taint::{ConfidentialityAxis, IntegrityTaintAxis, TwoAxisTaintState};

const REPEATED_DENIALS_THRESHOLD: u32 = 2;
const MAX_ACTION_HISTORY_PER_CLASS: usize = 2_048;
const MAX_ACTION_HISTORY_SECS: i64 = 3_600;
const MASS_CHANGE_WINDOW_SECS: i64 = 60;
const MAX_OVERWRITES_IN_WINDOW: usize = 2_000;

#[derive(Clone, PartialEq, Eq, Default)]
pub struct SessionRuleState {
    pub session_id: String,
    pub labels: BTreeSet<SessionLabel>,
    pub extra_labels: BTreeSet<String>,
    pub taint: TwoAxisTaintState,
    pub action_history: BTreeMap<String, VecDeque<i64>>,
    pub bulk_mutations: VecDeque<(i64, String)>,
    pub latest_ts_sec: i64,
    pub pending_future_ts: Option<i64>,
    pub baseline: Option<WorkspaceBaselineTracker>,
    pub breaker_state: MassChangeBreakerState,
    pub replay_coverage_gaps: Vec<String>,
    pub denial_count: u32,
    pub step_up_count: u32,
    pub event_seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionEscalation {
    pub rule_id: &'static str,
    pub verdict: Verdict,
    pub min_grade: ApprovalGrade,
    pub reason: &'static str,
    pub next_step: &'static str,
}

impl core::fmt::Debug for SessionRuleState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SessionRuleState")
            .field("session_id", &self.session_id)
            .field("labels", &self.labels)
            .field("extra_labels_count", &self.extra_labels.len())
            .field("taint", &self.taint)
            .field("bulk_mutations_count", &self.bulk_mutations.len())
            .field("latest_ts_sec", &self.latest_ts_sec)
            .field("breaker_state", &self.breaker_state)
            .field("denial_count", &self.denial_count)
            .field("step_up_count", &self.step_up_count)
            .field("event_seq", &self.event_seq)
            .finish()
    }
}

impl SessionRuleState {
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            ..Self::default()
        }
    }

    pub fn labels_vec(&self) -> Vec<SessionLabel> {
        self.labels.iter().copied().collect()
    }

    pub fn bind_workspace_baseline(&mut self, tracker: WorkspaceBaselineTracker) {
        if tracker.breaker_state == MassChangeBreakerState::TrippedPausedForRestore {
            self.breaker_state = MassChangeBreakerState::TrippedPausedForRestore;
            self.extra_labels.insert("mass-change".into());
        }
        self.baseline = Some(tracker);
    }

    /// Evaluates dynamic rules loaded from `packs/essentials/session-rules.yaml` + extended rules.
    pub fn evaluate_dynamic(
        &self,
        rules: &SessionRuleSet,
        attempt: &ActionAttempt,
        analysis: &TargetAnalysis,
    ) -> Option<DynamicSessionEscalation> {
        rules.evaluate_with_history(
            &self.labels,
            &self.extra_labels,
            attempt,
            analysis,
            &self.action_history,
        )
    }

    /// Full dynamic session verdict + grade escalation check (`Verdict::Deny` / `G3` supported natively).
    #[must_use]
    pub fn pre_evaluate_verdict_escalation(
        &self,
        attempt: &ActionAttempt,
        analysis: &TargetAnalysis,
    ) -> Option<DynamicSessionEscalation> {
        if self.breaker_state == MassChangeBreakerState::TrippedPausedForRestore
            || self
                .baseline
                .as_ref()
                .is_some_and(|b| b.breaker_state == MassChangeBreakerState::TrippedPausedForRestore)
        {
            return Some(DynamicSessionEscalation {
                rule_id: "grdr.destructive.mass-change".into(),
                verdict: Verdict::Deny,
                min_grade: ApprovalGrade::G3,
                reason: "Workspace bulk mutation circuit breaker tripped; restore baseline first."
                    .into(),
                next_step: "Freeze session and restore workspace baseline before further writes."
                    .into(),
            });
        }
        if let Some(child) = self
            .taint
            .quarantined_children
            .get(attempt.session_id.trim())
            && !child.permits_action(attempt.action_class)
        {
            return Some(DynamicSessionEscalation {
                rule_id: "session.quarantined-child-sink".into(),
                verdict: Verdict::Deny,
                min_grade: ApprovalGrade::G3,
                reason: "Quarantined child sub-session attempted disallowed side-effecting action."
                    .into(),
                next_step: "Return typed schema output to parent session instead.".into(),
            });
        }
        let default_rules = SessionRuleSet::load_default_dynamic();
        self.evaluate_dynamic(&default_rules, attempt, analysis)
    }

    pub fn pre_evaluate_escalation(
        &self,
        attempt: &ActionAttempt,
        analysis: &TargetAnalysis,
    ) -> Option<SessionEscalation> {
        let dyn_esc = self.pre_evaluate_verdict_escalation(attempt, analysis)?;
        let (rule_id, reason, next_step): (&'static str, &'static str, &'static str) = match dyn_esc
            .rule_id
            .as_str()
        {
            "session.tainted-exfil-escalation" | "session.ext.cred-net-escalation" => (
                "session.tainted-exfil-escalation",
                "Outbound network or data flow attempted after sensitive credential access in this session.",
                "Review destination and grant a scoped approval in Respond before retrying.",
            ),
            "session.untrusted-web-exec" => (
                "session.untrusted-web-exec",
                "High-risk command execution attempted after external web content was fetched in this session.",
                "Verify the command was not driven by untrusted fetched content and approve in Respond.",
            ),
            "session.repeated-denials-escalation" => (
                "session.repeated-denials-escalation",
                "Session crossed the repeated-denials threshold and requires step-up approval for privileged actions.",
                "Inspect prior blocked attempts in Sessions and approve or freeze the session in Respond.",
            ),
            "session.secret-to-sink" | "session.ext.secret-to-sink" => (
                "session.secret-to-sink",
                "Outbound data flow attempted after reading credential material.",
                "Verify destination or issue a digest-bound declassification grant.",
            ),
            "session.ext.honeytoken-block" => (
                "session.ext.honeytoken-block",
                "Honeytoken credential touched; session egress and execution blocked.",
                "Contain session immediately and rotate any exposed credentials.",
            ),
            "session.ext.taint-pause-restore" | "grdr.destructive.mass-change" => (
                "grdr.destructive.mass-change",
                "Workspace bulk mutation rate crossed mass-change circuit breaker.",
                "Freeze session and restore workspace baseline.",
            ),
            "grdr.approval-streak" => (
                "grdr.approval-streak",
                "Approval fatigue streak exceeded threshold within rolling window.",
                "Require elevated out-of-band confirmation.",
            ),
            "session.quarantined-child-sink" => (
                "session.quarantined-child-sink",
                "Quarantined sub-session attempted restricted side-effect.",
                "Return typed schema output to parent session instead.",
            ),
            _ => (
                "session.dynamic-rule",
                "Dynamic session policy escalation triggered.",
                "Inspect Findings and Respond for the dynamic session escalation verdict.",
            ),
        };
        Some(SessionEscalation {
            rule_id,
            verdict: dyn_esc.verdict,
            min_grade: dyn_esc.min_grade,
            reason,
            next_step,
        })
    }

    pub fn record_outcome(
        &mut self,
        attempt: &ActionAttempt,
        analysis: &TargetAnalysis,
        verdict: Verdict,
    ) {
        let had_prior_events = self.event_seq > 0;
        self.event_seq = self.event_seq.saturating_add(1);
        let raw_sec = attempt.timestamp.as_second();
        let prev_latest = self.latest_ts_sec;
        // Guard active rolling windows against backward clock regression, single spikes, and alternating jumps.
        let mut is_future_outlier =
            had_prior_events && raw_sec.saturating_sub(prev_latest) > MAX_ACTION_HISTORY_SECS;
        if is_future_outlier {
            if let Some(pending) = self.pending_future_ts
                && raw_sec >= pending.saturating_sub(MASS_CHANGE_WINDOW_SECS)
                && raw_sec.saturating_sub(pending) <= MAX_ACTION_HISTORY_SECS
            {
                self.latest_ts_sec = prev_latest.max(pending.max(raw_sec));
                self.pending_future_ts = None;
                is_future_outlier = false;
            } else {
                self.pending_future_ts = Some(raw_sec);
            }
        } else {
            self.latest_ts_sec = if had_prior_events {
                prev_latest.max(raw_sec)
            } else {
                raw_sec
            };
            self.pending_future_ts = None;
        }
        let anchor_sec = if is_future_outlier {
            prev_latest
        } else {
            self.latest_ts_sec
        };

        let recorded_ts = if !had_prior_events {
            raw_sec
        } else if is_future_outlier {
            prev_latest
        } else {
            raw_sec.max(prev_latest)
        };
        let hist = self
            .action_history
            .entry(attempt.action_class.as_str().to_owned())
            .or_default();
        hist.push_back(recorded_ts);
        if !is_future_outlier {
            let cutoff = anchor_sec.saturating_sub(MAX_ACTION_HISTORY_SECS);
            hist.retain(|&ts| ts >= cutoff);
        }
        while hist.len() > MAX_ACTION_HISTORY_PER_CLASS {
            hist.pop_front();
        }

        if attempt.action_class == ActionClass::CredUse
            || analysis.risk_tags.iter().any(|t| {
                matches!(
                    t.as_str(),
                    "sensitive-credential" | "content.secret" | "secret.present" | "dlp.secret"
                )
            })
        {
            self.labels.insert(SessionLabel::CredentialAccessed);
            self.extra_labels.insert("secret-read".into());
            self.taint
                .record_confidentiality(ConfidentialityAxis::SecretRead);
        }

        for tag in &analysis.risk_tags {
            match tag.as_str() {
                "sensitive:confidential" | "sensitive-confidential" => {
                    self.extra_labels.insert("sensitive-confidential".into());
                    self.taint
                        .record_confidentiality(ConfidentialityAxis::SensitiveConfidential);
                }
                "sensitive:secret" | "sensitive-secret" | "content.secret" | "secret.present"
                | "dlp.secret" => {
                    self.extra_labels.insert("sensitive-secret".into());
                    self.taint
                        .record_confidentiality(ConfidentialityAxis::SensitiveSecret);
                }
                "sensitive:regulated" | "sensitive-regulated" => {
                    self.extra_labels.insert("sensitive-regulated".into());
                    self.taint
                        .record_confidentiality(ConfidentialityAxis::SensitiveRegulated);
                }
                "honeytoken-touched" | "honeytoken" => {
                    self.extra_labels.insert("honeytoken-touched".into());
                    self.taint
                        .record_confidentiality(ConfidentialityAxis::HoneytokenTouched);
                }
                "untrusted-mcp" => {
                    self.extra_labels.insert("untrusted-mcp".into());
                    self.extra_labels.insert("untrusted-input".into());
                    self.taint
                        .record_integrity_taint(IntegrityTaintAxis::UntrustedMcp);
                }
                "untrusted-repo" => {
                    self.extra_labels.insert("untrusted-repo".into());
                    self.extra_labels.insert("untrusted-input".into());
                    self.taint
                        .record_integrity_taint(IntegrityTaintAxis::UntrustedRepo);
                }
                "untrusted-paste" => {
                    self.extra_labels.insert("untrusted-paste".into());
                    self.extra_labels.insert("untrusted-input".into());
                    self.taint
                        .record_integrity_taint(IntegrityTaintAxis::UntrustedPaste);
                }
                _ => {}
            }
        }

        let is_outbound = matches!(
            attempt.action_class,
            ActionClass::NetRequest
                | ActionClass::NetConnect
                | ActionClass::DataFlow
                | ActionClass::LlmRequest
                | ActionClass::McpCall
        ) || analysis.risk_tags.iter().any(|t| t == "external-network");

        if is_outbound {
            if self.labels.contains(&SessionLabel::CredentialAccessed)
                || !self.taint.confidentiality.is_empty()
            {
                self.labels.insert(SessionLabel::TaintedExfilRisk);
            }
            if matches!(
                attempt.action_class,
                ActionClass::NetRequest | ActionClass::NetConnect
            ) {
                self.labels.insert(SessionLabel::UntrustedWebFetched);
                self.extra_labels.insert("untrusted-input".into());
                self.taint
                    .record_integrity_taint(IntegrityTaintAxis::UntrustedWeb);
            } else if attempt.action_class == ActionClass::McpCall {
                self.extra_labels.insert("untrusted-mcp".into());
                self.extra_labels.insert("untrusted-input".into());
                self.taint
                    .record_integrity_taint(IntegrityTaintAxis::UntrustedMcp);
            }
        }

        if matches!(
            attempt.action_class,
            ActionClass::FileWrite | ActionClass::FileDelete
        ) {
            let norm_target = if let Some(tracker) = &self.baseline {
                baseline_guard::canonicalize_within_workspace(
                    &tracker.workspace_root,
                    tracker.os,
                    tracker.volume_case,
                    &attempt.target,
                    false,
                )
                .unwrap_or_else(|_| {
                    let norm = analysis.normalized_target.as_str();
                    if tracker.os == crate::analyze::path::OsKind::Windows {
                        crate::analyze::path::split_ntfs_ads(norm).0.to_owned()
                    } else {
                        norm.to_owned()
                    }
                })
            } else {
                let raw_or_norm = if analysis.normalized_target.is_empty() {
                    attempt.target.as_str()
                } else {
                    analysis.normalized_target.as_str()
                };
                let trimmed = raw_or_norm.trim();
                let b = trimmed.as_bytes();
                let windows_like = attempt.target.contains('\\')
                    || trimmed.starts_with("//?/")
                    || trimmed.starts_with("//./")
                    || (b.len() >= 3
                        && b.first().is_some_and(u8::is_ascii_alphabetic)
                        && b.get(1) == Some(&b':')
                        && matches!(b.get(2), Some(b'/' | b'\\')));
                if windows_like {
                    crate::analyze::path::split_ntfs_ads(trimmed).0.to_owned()
                } else {
                    trimmed.to_owned()
                }
            };
            self.bulk_mutations.push_back((recorded_ts, norm_target));
            if !is_future_outlier {
                let mut_cutoff = anchor_sec.saturating_sub(MASS_CHANGE_WINDOW_SECS);
                self.bulk_mutations.retain(|(ts, _)| *ts >= mut_cutoff);
            }
            while self.bulk_mutations.len() > MAX_ACTION_HISTORY_PER_CLASS {
                self.bulk_mutations.pop_front();
            }
            let eval_end = anchor_sec;
            let eval_start = eval_end.saturating_sub(MASS_CHANGE_WINDOW_SECS);
            let mut distinct_targets = BTreeSet::new();
            let mut total_in_win: usize = 0;
            for (ts, tgt) in &self.bulk_mutations {
                if *ts >= eval_start && *ts <= eval_end {
                    distinct_targets.insert(tgt.as_str());
                    total_in_win = total_in_win.saturating_add(1);
                }
            }
            if distinct_targets.len() >= MASS_CHANGE_THRESHOLD_DEFAULT
                || total_in_win >= MAX_OVERWRITES_IN_WINDOW
            {
                self.breaker_state = MassChangeBreakerState::TrippedPausedForRestore;
                self.extra_labels.insert("mass-change".into());
            }
            if let Some(tracker) = self.baseline.as_mut() {
                let ts_ms = attempt.timestamp.as_millisecond();
                let bstate = tracker.record_mutation(&attempt.target, None, ts_ms);
                if bstate == MassChangeBreakerState::TrippedPausedForRestore {
                    self.breaker_state = MassChangeBreakerState::TrippedPausedForRestore;
                    self.extra_labels.insert("mass-change".into());
                }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::classify_target;
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
        let (states, gaps) = replay_session_states_checked(&attempts, &[]);
        assert_eq!(gaps.len(), 2);
        let mut summaries = summarize_sessions(&attempts, &[]);
        attach_session_labels(&mut summaries, &states);
        let labels = &summaries.first().unwrap().labels;
        assert!(labels.contains(&SessionLabel::CredentialAccessed));
        assert!(labels.contains(&SessionLabel::TaintedExfilRisk));
    }
}
