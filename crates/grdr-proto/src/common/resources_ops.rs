// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use serde::{Deserialize, Serialize};

use super::enums::{
    action_class_serde, approval_grade_serde, approval_status_serde, grant_scope_serde,
    kill_scope_serde, kill_state_serde, mode_serde,
};
use super::enums_ext::{
    finding_class_serde, finding_lifecycle_serde, finding_severity_serde, identity_mode_serde,
    risk_tier_serde, session_label_serde,
};

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Grant {
    #[prost(string, tag = "1")]
    #[serde(alias = "grant_id")]
    pub grant_id: String,
    #[prost(string, tag = "2")]
    #[serde(alias = "rule_id")]
    pub rule_id: String,
    #[prost(string, tag = "3")]
    #[serde(alias = "session_id")]
    pub session_id: String,
    #[prost(string, tag = "4")]
    #[serde(alias = "device_id")]
    pub device_id: String,
    #[prost(enumeration = "super::enums::ActionClass", tag = "5")]
    #[serde(with = "action_class_serde", alias = "action_class")]
    pub action_class: i32,
    #[prost(string, tag = "6")]
    #[serde(alias = "target_pattern")]
    pub target_pattern: String,
    #[prost(enumeration = "super::enums::GrantScope", tag = "7")]
    #[serde(with = "grant_scope_serde")]
    pub scope: i32,
    #[prost(enumeration = "super::enums::ApprovalGrade", tag = "8")]
    #[serde(with = "approval_grade_serde")]
    pub grade: i32,
    #[prost(string, tag = "9")]
    #[serde(alias = "granted_at")]
    pub granted_at: String,
    #[prost(string, optional, tag = "10")]
    #[serde(alias = "expires_at")]
    pub expires_at: Option<String>,
    #[prost(uint32, optional, tag = "11")]
    #[serde(alias = "remaining_uses")]
    pub remaining_uses: Option<u32>,
    #[prost(string, tag = "12")]
    pub note: String,
    #[prost(string, optional, tag = "13")]
    #[serde(alias = "key_id")]
    pub key_id: Option<String>,
    #[prost(string, optional, tag = "14")]
    pub signature: Option<String>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RuleMatch {
    #[prost(enumeration = "super::enums::ActionClass", repeated, tag = "1")]
    #[serde(with = "action_class_serde::vec", alias = "action_classes")]
    pub action_classes: Vec<i32>,
    #[prost(string, repeated, tag = "2")]
    #[serde(alias = "target_prefixes")]
    pub target_prefixes: Vec<String>,
    #[prost(string, repeated, tag = "3")]
    #[serde(alias = "target_contains")]
    pub target_contains: Vec<String>,
    #[prost(string, repeated, tag = "4")]
    pub agents: Vec<String>,
}

// grdr:allow-s4 prost enumeration wire representation uses i32 backed by Mode enum codec
#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PolicyRule {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub title: String,
    #[prost(string, tag = "3")]
    pub description: String,
    #[prost(enumeration = "super::enums::Mode", tag = "4")]
    #[serde(with = "mode_serde")]
    pub mode: i32,
    #[prost(enumeration = "super::enums::ApprovalGrade", tag = "5")]
    #[serde(with = "approval_grade_serde", alias = "min_grade")]
    pub min_grade: i32,
    #[prost(bool, tag = "6")]
    pub enabled: bool,
    #[prost(bool, tag = "7")]
    pub locked: bool,
    #[prost(message, optional, tag = "8")]
    pub matcher: Option<RuleMatch>,
    #[prost(uint64, tag = "9")]
    pub hits: u64,
    #[prost(uint64, tag = "10")]
    #[serde(alias = "would_ask_hits")]
    pub would_ask_hits: u64,
    #[prost(uint64, tag = "11")]
    #[serde(alias = "would_block_hits")]
    pub would_block_hits: u64,
    #[prost(string, tag = "12")]
    #[serde(alias = "reason_template")]
    pub reason_template: String,
    #[prost(string, optional, tag = "13")]
    pub cedar: Option<String>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PolicyPack {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub name: String,
    #[prost(string, tag = "3")]
    pub description: String,
    #[prost(string, tag = "4")]
    pub version: String,
    #[prost(string, tag = "5")]
    pub channel: String,
    #[prost(message, repeated, tag = "6")]
    pub rules: Vec<PolicyRule>,
    #[prost(string, optional, tag = "7")]
    #[serde(alias = "key_id")]
    pub key_id: Option<String>,
    #[prost(string, optional, tag = "8")]
    pub signature: Option<String>,
}

// grdr:allow-s4 prost enumeration wire representation uses i32 backed by ApprovalStatus enum codec
#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ApprovalRequest {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    #[serde(alias = "receipt_id")]
    pub receipt_id: String,
    #[prost(string, tag = "3")]
    #[serde(alias = "session_id")]
    pub session_id: String,
    #[prost(string, tag = "4")]
    #[serde(alias = "device_id")]
    pub device_id: String,
    #[prost(string, tag = "5")]
    #[serde(alias = "device_name")]
    pub device_name: String,
    #[prost(string, tag = "6")]
    #[serde(alias = "agent_name")]
    pub agent_name: String,
    #[prost(enumeration = "super::enums::ActionClass", tag = "7")]
    #[serde(with = "action_class_serde", alias = "action_class")]
    pub action_class: i32,
    #[prost(string, tag = "8")]
    pub target: String,
    #[prost(string, tag = "9")]
    #[serde(alias = "rule_id")]
    pub rule_id: String,
    #[prost(string, tag = "10")]
    #[serde(alias = "rule_title")]
    pub rule_title: String,
    #[prost(enumeration = "super::enums::ApprovalGrade", tag = "11")]
    #[serde(with = "approval_grade_serde", alias = "required_grade")]
    pub required_grade: i32,
    #[prost(string, tag = "12")]
    pub reason: String,
    #[prost(string, tag = "13")]
    #[serde(alias = "requested_at")]
    pub requested_at: String,
    #[prost(enumeration = "super::enums::ApprovalStatus", tag = "14")]
    #[serde(with = "approval_status_serde")]
    pub status: i32,
    #[prost(string, optional, tag = "15")]
    #[serde(alias = "expires_at")]
    pub expires_at: Option<String>,
    #[prost(string, optional, tag = "16")]
    #[serde(alias = "grant_id")]
    pub grant_id: Option<String>,
    #[prost(enumeration = "super::enums::GrantScope", optional, tag = "17")]
    #[serde(with = "grant_scope_serde::opt")]
    pub scope: Option<i32>,
    #[prost(string, optional, tag = "18")]
    #[serde(alias = "decided_at")]
    pub decided_at: Option<String>,
    #[prost(string, optional, tag = "19")]
    pub note: Option<String>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Finding {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    #[serde(alias = "session_id")]
    pub session_id: String,
    #[prost(string, tag = "3")]
    #[serde(alias = "device_id")]
    pub device_id: String,
    #[prost(string, tag = "4")]
    #[serde(alias = "device_name")]
    pub device_name: String,
    #[prost(string, tag = "5")]
    #[serde(alias = "agent_name")]
    pub agent_name: String,
    #[prost(enumeration = "super::enums_ext::FindingClass", tag = "6")]
    #[serde(with = "finding_class_serde", alias = "finding_class", alias = "class")]
    pub finding_class: i32,
    #[prost(enumeration = "super::enums_ext::FindingSeverity", tag = "7")]
    #[serde(with = "finding_severity_serde")]
    pub severity: i32,
    #[prost(enumeration = "super::enums_ext::FindingLifecycle", tag = "8")]
    #[serde(with = "finding_lifecycle_serde")]
    pub lifecycle: i32,
    #[prost(string, optional, tag = "9")]
    #[serde(alias = "rule_id")]
    pub rule_id: Option<String>,
    #[prost(string, tag = "10")]
    pub title: String,
    #[prost(string, tag = "11")]
    pub summary: String,
    #[prost(string, tag = "12")]
    pub target: String,
    #[prost(string, tag = "13")]
    #[serde(alias = "detected_at")]
    pub detected_at: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Incident {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    #[serde(alias = "session_id")]
    pub session_id: String,
    #[prost(string, tag = "3")]
    #[serde(alias = "device_id")]
    pub device_id: String,
    #[prost(string, tag = "4")]
    #[serde(alias = "device_name")]
    pub device_name: String,
    #[prost(string, tag = "5")]
    #[serde(alias = "agent_name")]
    pub agent_name: String,
    #[prost(string, tag = "6")]
    pub title: String,
    #[prost(string, tag = "7")]
    pub summary: String,
    #[prost(enumeration = "super::enums_ext::FindingSeverity", tag = "8")]
    #[serde(with = "finding_severity_serde")]
    pub severity: i32,
    #[prost(enumeration = "super::enums_ext::FindingLifecycle", tag = "9")]
    #[serde(with = "finding_lifecycle_serde")]
    pub lifecycle: i32,
    #[prost(string, repeated, tag = "10")]
    #[serde(alias = "finding_ids")]
    pub finding_ids: Vec<String>,
    #[prost(uint64, tag = "11")]
    #[serde(alias = "finding_count")]
    pub finding_count: u64,
    #[prost(enumeration = "super::enums_ext::SessionLabel", repeated, tag = "12")]
    #[serde(with = "session_label_serde::vec")]
    pub labels: Vec<i32>,
    #[prost(string, tag = "13")]
    #[serde(alias = "first_seen")]
    pub first_seen: String,
    #[prost(string, tag = "14")]
    #[serde(alias = "last_seen")]
    pub last_seen: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AuditEntry {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub timestamp: String,
    #[prost(string, tag = "3")]
    pub kind: String,
    #[prost(string, tag = "4")]
    pub actor: String,
    #[prost(string, tag = "5")]
    pub summary: String,
    #[prost(string, tag = "6")]
    pub target: String,
}

// grdr:allow-s4 prost enumeration wire representation uses i32 backed by KillState enum codec
#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct KillSwitchState {
    #[prost(enumeration = "super::enums::KillState", tag = "1")]
    #[serde(with = "kill_state_serde")]
    pub state: i32,
    #[prost(enumeration = "super::enums::KillScope", optional, tag = "2")]
    #[serde(with = "kill_scope_serde::opt")]
    pub scope: Option<i32>,
    #[prost(string, optional, tag = "3")]
    #[serde(alias = "target_id")]
    pub target_id: Option<String>,
    #[prost(string, optional, tag = "4")]
    pub reason: Option<String>,
    #[prost(string, optional, tag = "5")]
    #[serde(alias = "issued_at")]
    pub issued_at: Option<String>,
    #[prost(string, optional, tag = "6")]
    #[serde(alias = "expires_at")]
    pub expires_at: Option<String>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct UserRiskFactor {
    #[prost(string, tag = "1")]
    pub code: String,
    #[prost(string, tag = "2")]
    pub label: String,
    #[prost(uint32, tag = "3")]
    pub points: u32,
    #[prost(uint32, tag = "4")]
    pub count: u32,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct UserProfile {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    #[serde(alias = "display_name")]
    pub display_name: String,
    #[prost(string, tag = "3")]
    pub email: String,
    #[prost(string, tag = "4")]
    pub department: String,
    #[prost(string, tag = "5")]
    #[serde(alias = "idp_source")]
    pub idp_source: String,
    #[prost(string, tag = "6")]
    #[serde(alias = "pseudonym_id")]
    pub pseudonym_id: String,
    #[prost(string, repeated, tag = "7")]
    #[serde(alias = "device_ids")]
    pub device_ids: Vec<String>,
    #[prost(string, repeated, tag = "8")]
    #[serde(alias = "agent_names")]
    pub agent_names: Vec<String>,
    #[prost(uint64, tag = "9")]
    #[serde(alias = "artifact_count")]
    pub artifact_count: u64,
    #[prost(uint64, tag = "10")]
    #[serde(alias = "session_count")]
    pub session_count: u64,
    #[prost(uint64, tag = "11")]
    #[serde(alias = "blocked_count")]
    pub blocked_count: u64,
    #[prost(uint64, tag = "12")]
    #[serde(alias = "asked_count")]
    pub asked_count: u64,
    #[prost(uint64, tag = "13")]
    #[serde(alias = "watch_count")]
    pub watch_count: u64,
    #[prost(uint64, tag = "14")]
    #[serde(alias = "finding_count")]
    pub finding_count: u64,
    #[prost(uint32, tag = "15")]
    #[serde(alias = "risk_score")]
    pub risk_score: u32,
    #[prost(enumeration = "super::enums_ext::RiskTier", tag = "16")]
    #[serde(with = "risk_tier_serde", alias = "risk_tier")]
    pub risk_tier: i32,
    #[prost(message, repeated, tag = "17")]
    #[serde(alias = "risk_factors")]
    pub risk_factors: Vec<UserRiskFactor>,
    #[prost(string, tag = "18")]
    #[serde(alias = "last_active")]
    pub last_active: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct OrgPrivacyConfig {
    #[prost(enumeration = "super::enums_ext::IdentityMode", tag = "1")]
    #[serde(with = "identity_mode_serde", alias = "identity_mode")]
    pub identity_mode: i32,
    #[prost(bool, tag = "2")]
    #[serde(alias = "user_risk_scoring")]
    pub user_risk_scoring: bool,
}
