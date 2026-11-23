// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::domain::{
    ActionClass, ApprovalGrade, ApprovalState, ControlPoint, FindingClass, FindingLifecycle,
    FindingSeverity, GrantScope, Mode, Verdict,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleMatch {
    pub action_classes: Vec<ActionClass>,
    pub target_prefixes: Vec<String>,
    pub target_contains: Vec<String>,
    pub agents: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    pub title: String,
    pub description: String,
    pub mode: Mode,
    pub min_grade: ApprovalGrade,
    pub enabled: bool,
    pub locked: bool,
    pub matcher: RuleMatch,
    pub hits: u64,
    pub would_ask_hits: u64,
    pub would_block_hits: u64,
    pub reason_template: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyPack {
    pub id: String,
    pub name: String,
    pub description: String,
    pub version: String,
    pub channel: String,
    pub rules: Vec<PolicyRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionAttempt {
    pub id: String,
    pub session_id: String,
    pub device_id: String,
    pub device_name: String,
    pub agent_name: String,
    pub action_class: ActionClass,
    pub control_point: ControlPoint,
    pub target: String,
    pub summary: String,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReceipt {
    pub receipt_id: String,
    pub attempt_id: String,
    pub session_id: String,
    pub device_id: String,
    pub agent_name: String,
    pub action_class: ActionClass,
    pub control_point: ControlPoint,
    pub target: String,
    pub verdict: Verdict,
    pub would_be: Option<Verdict>,
    pub rule_id: Option<String>,
    pub pack_id: Option<String>,
    pub mode_applied: Option<Mode>,
    pub grant_id: Option<String>,
    pub reason: String,
    pub next_step: String,
    pub receipt_digest: String,
    pub decided_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub grant_id: String,
    pub rule_id: String,
    pub session_id: String,
    pub device_id: String,
    pub action_class: ActionClass,
    pub target_pattern: String,
    pub scope: GrantScope,
    pub grade: ApprovalGrade,
    pub granted_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub remaining_uses: Option<u32>,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub id: String,
    pub receipt_id: String,
    pub session_id: String,
    pub device_id: String,
    pub device_name: String,
    pub agent_name: String,
    pub action_class: ActionClass,
    pub target: String,
    pub rule_id: String,
    pub rule_title: String,
    pub required_grade: ApprovalGrade,
    pub reason: String,
    pub requested_at: Timestamp,
    pub state: ApprovalState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub session_id: String,
    pub device_id: String,
    pub device_name: String,
    pub agent_name: String,
    pub class: FindingClass,
    pub severity: FindingSeverity,
    pub lifecycle: FindingLifecycle,
    pub rule_id: Option<String>,
    pub title: String,
    pub summary: String,
    pub target: String,
    pub detected_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplaySample {
    pub attempt_id: String,
    pub session_id: String,
    pub agent_name: String,
    pub action_class: ActionClass,
    pub target: String,
    pub current_verdict: Verdict,
    pub candidate_verdict: Verdict,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplaySummary {
    pub rule_id: String,
    pub candidate_mode: Mode,
    pub window_label: String,
    pub total_scanned: u64,
    pub matched: u64,
    pub would_ask: u64,
    pub would_block: u64,
    pub not_matched: u64,
    pub samples: Vec<ReplaySample>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: String,
    pub timestamp: Timestamp,
    pub kind: String,
    pub actor: String,
    pub summary: String,
    pub target: String,
}

impl Grant {
    pub fn is_active(&self, now: Timestamp) -> bool {
        if self.expires_at.is_some_and(|exp| exp <= now) {
            return false;
        }
        if self.remaining_uses.is_some_and(|uses| uses == 0) {
            return false;
        }
        true
    }

    pub fn consume_use(&mut self) {
        if let Some(uses) = self.remaining_uses.as_mut() {
            *uses = uses.saturating_sub(1);
        }
    }

    pub fn matches(&self, attempt: &ActionAttempt, now: Timestamp) -> bool {
        if !self.is_active(now) {
            return false;
        }
        if self.action_class != attempt.action_class {
            return false;
        }
        if self.device_id != "*" && self.device_id != attempt.device_id {
            return false;
        }
        if matches!(self.scope, GrantScope::Once | GrantScope::Session)
            && self.session_id != attempt.session_id
        {
            return false;
        }
        target_pattern_matches(&self.target_pattern, &attempt.target)
    }
}

fn target_pattern_matches(pattern: &str, target: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let norm_pattern = pattern.replace('\\', "/");
    let norm_target = target.replace('\\', "/");
    if norm_target == norm_pattern {
        return true;
    }
    let trimmed = norm_pattern.trim_end_matches('/');
    if trimmed.is_empty() {
        return false;
    }
    norm_target
        .strip_prefix(trimmed)
        .is_some_and(|rest| rest.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::ControlPoint;

    fn sample_attempt(session_id: &str, device_id: &str, target: &str) -> ActionAttempt {
        ActionAttempt {
            id: "att-1".into(),
            session_id: session_id.into(),
            device_id: device_id.into(),
            device_name: "workstation".into(),
            agent_name: "claude-code".into(),
            action_class: ActionClass::FileRead,
            control_point: ControlPoint::Hook,
            target: target.into(),
            summary: target.into(),
            timestamp: Timestamp::from_second(1_700_000_000).unwrap(),
        }
    }

    fn sample_grant(
        scope: GrantScope,
        target_pattern: &str,
        remaining_uses: Option<u32>,
        expires_at: Option<Timestamp>,
    ) -> Grant {
        Grant {
            grant_id: "grn_test".into(),
            rule_id: "essentials.credential-stores".into(),
            session_id: "sess-1".into(),
            device_id: "dev-1".into(),
            action_class: ActionClass::FileRead,
            target_pattern: target_pattern.into(),
            scope,
            grade: ApprovalGrade::G1,
            granted_at: Timestamp::from_second(1_700_000_000).unwrap(),
            expires_at,
            remaining_uses,
            note: "test".into(),
        }
    }

    #[test]
    fn once_grant_binds_device_and_session_and_consumes_use() {
        let now = Timestamp::from_second(1_700_000_000).unwrap();
        let mut grant = sample_grant(GrantScope::Once, "/home/dev/.ssh/id_rsa", Some(1), None);

        let same = sample_attempt("sess-1", "dev-1", "/home/dev/.ssh/id_rsa");
        let wrong_session = sample_attempt("sess-2", "dev-1", "/home/dev/.ssh/id_rsa");
        let wrong_device = sample_attempt("sess-1", "dev-2", "/home/dev/.ssh/id_rsa");

        assert!(grant.matches(&same, now));
        assert!(!grant.matches(&wrong_session, now));
        assert!(!grant.matches(&wrong_device, now));

        grant.consume_use();
        assert!(!grant.is_active(now));
        assert!(!grant.matches(&same, now));
    }

    #[test]
    fn one_hour_grant_crosses_sessions_on_same_device_until_expiry() {
        let now = Timestamp::from_second(1_700_000_000).unwrap();
        let exp = Timestamp::from_second(1_700_003_600).unwrap();
        let grant = sample_grant(
            GrantScope::OneHour,
            "/home/dev/.ssh/id_rsa",
            None,
            Some(exp),
        );

        let other_sess = sample_attempt("sess-2", "dev-1", "/home/dev/.ssh/id_rsa");
        let other_dev = sample_attempt("sess-2", "dev-2", "/home/dev/.ssh/id_rsa");

        assert!(grant.matches(&other_sess, now));
        assert!(!grant.matches(&other_dev, now));
        assert!(!grant.matches(&other_sess, exp));
    }

    #[test]
    fn target_pattern_enforces_path_boundaries() {
        assert!(target_pattern_matches("*", "/anything"));
        assert!(target_pattern_matches(
            "/home/dev/.ssh",
            "/home/dev/.ssh/id_rsa"
        ));
        assert!(target_pattern_matches(
            "/home/dev/.ssh",
            r"\home\dev\.ssh\id_rsa"
        ));
        assert!(!target_pattern_matches(
            "/home/dev/.ssh",
            "/home/dev/.ssh-other/id_rsa"
        ));
    }
}
