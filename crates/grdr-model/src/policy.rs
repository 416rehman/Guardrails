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
    pub fn matches(&self, attempt: &ActionAttempt, now: Timestamp) -> bool {
        if let Some(exp) = self.expires_at
            && exp <= now
        {
            return false;
        }
        if let Some(uses) = self.remaining_uses
            && uses == 0
        {
            return false;
        }
        if self.action_class != attempt.action_class {
            return false;
        }
        if self.scope == GrantScope::Session && self.session_id != attempt.session_id {
            return false;
        }
        self.target_pattern == "*"
            || self.target_pattern == attempt.target
            || attempt.target.starts_with(&self.target_pattern)
    }
}
