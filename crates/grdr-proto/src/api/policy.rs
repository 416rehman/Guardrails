// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use serde::{Deserialize, Serialize};

use crate::common::{
    PolicyPack, PolicyRule, RevisionMeta, RuleMatch, action_class_serde, approval_grade_serde,
    mode_serde, verdict_serde,
};

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ReplaySample {
    #[prost(string, tag = "1")]
    #[serde(alias = "attempt_id")]
    pub attempt_id: String,
    #[prost(string, tag = "2")]
    #[serde(alias = "session_id")]
    pub session_id: String,
    #[prost(string, tag = "3")]
    #[serde(alias = "agent_name")]
    pub agent_name: String,
    #[prost(enumeration = "crate::common::ActionClass", tag = "4")]
    #[serde(with = "action_class_serde", alias = "action_class")]
    pub action_class: i32,
    #[prost(string, tag = "5")]
    pub target: String,
    #[prost(enumeration = "crate::common::Verdict", tag = "6")]
    #[serde(with = "verdict_serde", alias = "current_verdict")]
    pub current_verdict: i32,
    #[prost(enumeration = "crate::common::Verdict", tag = "7")]
    #[serde(with = "verdict_serde", alias = "candidate_verdict")]
    pub candidate_verdict: i32,
    #[prost(string, tag = "8")]
    pub timestamp: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ReplaySummary {
    #[prost(string, tag = "1")]
    #[serde(alias = "rule_id")]
    pub rule_id: String,
    #[prost(enumeration = "crate::common::Mode", tag = "2")]
    #[serde(with = "mode_serde", alias = "candidate_mode")]
    pub candidate_mode: i32,
    #[prost(string, tag = "3")]
    #[serde(alias = "window_label")]
    pub window_label: String,
    #[prost(uint64, tag = "4")]
    #[serde(alias = "total_scanned")]
    pub total_scanned: u64,
    #[prost(uint64, tag = "5")]
    pub matched: u64,
    #[prost(uint64, tag = "6")]
    #[serde(alias = "would_ask")]
    pub would_ask: u64,
    #[prost(uint64, tag = "7")]
    #[serde(alias = "would_block")]
    pub would_block: u64,
    #[prost(uint64, tag = "8")]
    #[serde(alias = "not_matched")]
    pub not_matched: u64,
    #[prost(message, repeated, tag = "9")]
    pub samples: Vec<ReplaySample>,
}

// grdr:allow-s4 orthogonal browser DLP guard flags and Mode wire enum field
#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct BrowserAppPolicy {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub name: String,
    #[prost(string, repeated, tag = "3")]
    pub domains: Vec<String>,
    #[prost(enumeration = "crate::common::Mode", tag = "4")]
    #[serde(with = "mode_serde")]
    pub mode: i32,
    #[prost(bool, tag = "5")]
    #[serde(alias = "block_file_uploads")]
    pub block_file_uploads: bool,
    #[prost(bool, tag = "6")]
    #[serde(alias = "block_secret_paste")]
    pub block_secret_paste: bool,
    #[prost(bool, tag = "7")]
    #[serde(alias = "managed_extension_only")]
    pub managed_extension_only: bool,
    #[prost(uint32, tag = "8")]
    #[serde(alias = "events_24h")]
    pub events_24h: u32,
    #[prost(uint32, tag = "9")]
    #[serde(alias = "blocked_24h")]
    pub blocked_24h: u32,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListPacksRequest {}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListPacksResponse {
    #[prost(message, repeated, tag = "1")]
    pub packs: Vec<PolicyPack>,
    #[prost(message, optional, tag = "2")]
    pub revision: Option<RevisionMeta>,
}

// grdr:allow-s4 prost enumeration wire representation uses i32 backed by Mode codec
#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CreateRuleRequest {
    #[prost(string, optional, tag = "1")]
    #[serde(alias = "pack_id")]
    pub pack_id: Option<String>,
    #[prost(string, tag = "2")]
    pub title: String,
    #[prost(string, tag = "3")]
    pub description: String,
    #[prost(enumeration = "crate::common::Mode", tag = "4")]
    #[serde(with = "mode_serde")]
    pub mode: i32,
    #[prost(enumeration = "crate::common::ApprovalGrade", optional, tag = "5")]
    #[serde(with = "approval_grade_serde::opt", alias = "min_grade")]
    pub min_grade: Option<i32>,
    #[prost(message, optional, tag = "6")]
    pub matcher: Option<RuleMatch>,
    #[prost(string, tag = "7")]
    #[serde(alias = "reason_template")]
    pub reason_template: String,
    #[prost(string, optional, tag = "8")]
    pub cedar: Option<String>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CreateRuleResponse {
    #[prost(message, optional, tag = "1")]
    pub rule: Option<PolicyRule>,
}

// grdr:allow-s4 partial update DTO mirrors optional protobuf patch fields
#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct UpdateRuleRequest {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, optional, tag = "2")]
    pub title: Option<String>,
    #[prost(string, optional, tag = "3")]
    pub description: Option<String>,
    #[prost(enumeration = "crate::common::Mode", optional, tag = "4")]
    #[serde(with = "mode_serde::opt")]
    pub mode: Option<i32>,
    #[prost(enumeration = "crate::common::ApprovalGrade", optional, tag = "5")]
    #[serde(with = "approval_grade_serde::opt", alias = "min_grade")]
    pub min_grade: Option<i32>,
    #[prost(message, optional, tag = "6")]
    pub matcher: Option<RuleMatch>,
    #[prost(string, optional, tag = "7")]
    #[serde(alias = "reason_template")]
    pub reason_template: Option<String>,
    #[prost(string, optional, tag = "8")]
    pub cedar: Option<String>,
    #[prost(string, optional, tag = "9")]
    pub actor: Option<String>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct UpdateRuleResponse {
    #[prost(message, optional, tag = "1")]
    pub rule: Option<PolicyRule>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DeleteRuleRequest {
    #[prost(string, tag = "1")]
    pub id: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DeleteRuleResponse {}

// grdr:allow-s4 prost enumeration wire representation uses i32 backed by Mode codec
#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct UpdateRuleModeRequest {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(enumeration = "crate::common::Mode", tag = "2")]
    #[serde(with = "mode_serde")]
    pub mode: i32,
    #[prost(string, optional, tag = "3")]
    pub actor: Option<String>,
    #[prost(bool, optional, tag = "4")]
    #[serde(alias = "replay_confirmed")]
    pub replay_confirmed: Option<bool>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct UpdateRuleModeResponse {
    #[prost(message, optional, tag = "1")]
    pub rule: Option<PolicyRule>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ReplayRuleRequest {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(enumeration = "crate::common::Mode", tag = "2")]
    #[serde(with = "mode_serde", alias = "candidate_mode")]
    pub candidate_mode: i32,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ReplayRuleResponse {
    #[prost(message, optional, tag = "1")]
    pub summary: Option<ReplaySummary>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListBrowserPoliciesRequest {}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListBrowserPoliciesResponse {
    #[prost(message, repeated, tag = "1")]
    pub policies: Vec<BrowserAppPolicy>,
    #[prost(message, optional, tag = "2")]
    pub revision: Option<RevisionMeta>,
}

// grdr:allow-s4 partial update DTO mirrors optional protobuf patch fields
#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct UpdateBrowserPolicyRequest {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(enumeration = "crate::common::Mode", optional, tag = "2")]
    #[serde(with = "mode_serde::opt")]
    pub mode: Option<i32>,
    #[prost(bool, optional, tag = "3")]
    #[serde(alias = "block_file_uploads")]
    pub block_file_uploads: Option<bool>,
    #[prost(bool, optional, tag = "4")]
    #[serde(alias = "block_secret_paste")]
    pub block_secret_paste: Option<bool>,
    #[prost(bool, optional, tag = "5")]
    #[serde(alias = "managed_extension_only")]
    pub managed_extension_only: Option<bool>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct UpdateBrowserPolicyResponse {
    #[prost(message, optional, tag = "1")]
    pub policy: Option<BrowserAppPolicy>,
}
