// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use serde::{Deserialize, Serialize};

use crate::common::{RevisionMeta, provider_org_status_serde, review_cluster_status_serde};

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ExplainReceiptRequest {
    #[prost(string, tag = "1")]
    pub reference: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct WhyExplanation {
    #[prost(string, tag = "1")]
    pub reference: String,
    #[prost(string, tag = "2")]
    #[serde(alias = "receipt_id")]
    pub receipt_id: String,
    #[prost(string, tag = "3")]
    #[serde(alias = "attempt_id")]
    pub attempt_id: String,
    #[prost(string, tag = "4")]
    pub heading: String,
    #[prost(string, tag = "5")]
    pub verdict: String,
    #[prost(string, tag = "6")]
    #[serde(alias = "status_code")]
    pub status_code: String,
    #[prost(string, tag = "7")]
    pub component: String,
    #[prost(string, tag = "8")]
    #[serde(alias = "action_class")]
    pub action_class: String,
    #[prost(string, tag = "9")]
    #[serde(alias = "rule_id")]
    pub rule_id: String,
    #[prost(string, tag = "10")]
    #[serde(alias = "rule_title")]
    pub rule_title: String,
    #[prost(string, tag = "11")]
    #[serde(alias = "pack_id")]
    pub pack_id: String,
    #[prost(string, tag = "12")]
    #[serde(alias = "agent_name")]
    pub agent_name: String,
    #[prost(string, tag = "13")]
    #[serde(alias = "device_id")]
    pub device_id: String,
    #[prost(string, tag = "14")]
    #[serde(alias = "device_name")]
    pub device_name: String,
    #[prost(string, tag = "15")]
    #[serde(alias = "session_id")]
    pub session_id: String,
    #[prost(string, tag = "16")]
    #[serde(alias = "target_quoted")]
    pub target_quoted: String,
    #[prost(string, tag = "17")]
    pub reason: String,
    #[prost(string, tag = "18")]
    #[serde(alias = "agent_told")]
    pub agent_told: String,
    #[prost(string, tag = "19")]
    pub timestamp: String,
    #[prost(string, optional, tag = "20")]
    #[serde(alias = "key_id")]
    pub key_id: Option<String>,
    #[prost(string, tag = "21")]
    #[serde(alias = "signature_status")]
    pub signature_status: String,
    #[prost(string, tag = "22")]
    #[serde(alias = "primary_action_label")]
    pub primary_action_label: String,
    #[prost(string, tag = "23")]
    #[serde(alias = "primary_action_route")]
    pub primary_action_route: String,
    #[prost(string, optional, tag = "24")]
    #[serde(alias = "approval_id")]
    pub approval_id: Option<String>,
    #[prost(string, optional, tag = "25")]
    #[serde(alias = "approver_label")]
    pub approver_label: Option<String>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ExplainReceiptResponse {
    #[prost(message, optional, tag = "1")]
    pub explanation: Option<WhyExplanation>,
}

// grdr:allow-s4 prost enumeration wire representation uses i32 backed by ReviewClusterStatus codec
#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ReviewCluster {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub bucket: String,
    #[prost(uint32, tag = "3")]
    pub score: u32,
    #[prost(string, tag = "4")]
    #[serde(alias = "rule_id")]
    pub rule_id: String,
    #[prost(string, tag = "5")]
    #[serde(alias = "rule_title")]
    pub rule_title: String,
    #[prost(string, tag = "6")]
    #[serde(alias = "observable_digest")]
    pub observable_digest: String,
    #[prost(string, tag = "7")]
    #[serde(alias = "agent_name")]
    pub agent_name: String,
    #[prost(string, tag = "8")]
    #[serde(alias = "device_id")]
    pub device_id: String,
    #[prost(string, tag = "9")]
    #[serde(alias = "device_name")]
    pub device_name: String,
    #[prost(string, tag = "10")]
    #[serde(alias = "session_id")]
    pub session_id: String,
    #[prost(string, tag = "11")]
    #[serde(alias = "receipt_ref")]
    pub receipt_ref: String,
    #[prost(uint32, tag = "12")]
    #[serde(alias = "occurrence_count")]
    pub occurrence_count: u32,
    #[prost(string, tag = "13")]
    #[serde(alias = "latest_timestamp")]
    pub latest_timestamp: String,
    #[prost(string, tag = "14")]
    #[serde(alias = "target_preview")]
    pub target_preview: String,
    #[prost(string, tag = "15")]
    #[serde(alias = "current_mode")]
    pub current_mode: String,
    #[prost(string, tag = "16")]
    #[serde(alias = "suggested_mode")]
    pub suggested_mode: String,
    #[prost(string, tag = "17")]
    #[serde(alias = "risk_label")]
    pub risk_label: String,
    #[prost(enumeration = "crate::common::ReviewClusterStatus", tag = "18")]
    #[serde(with = "review_cluster_status_serde")]
    pub status: i32,
    #[prost(string, tag = "19")]
    pub reason: String,
    #[prost(string, tag = "20")]
    pub note: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListReviewQueueRequest {
    #[prost(string, tag = "1")]
    pub bucket: String,
    #[prost(string, tag = "2")]
    pub search: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListReviewQueueResponse {
    #[prost(message, repeated, tag = "1")]
    pub clusters: Vec<ReviewCluster>,
    #[prost(uint32, tag = "2")]
    #[serde(alias = "worth_a_look_count")]
    pub worth_a_look_count: u32,
    #[prost(uint32, tag = "3")]
    #[serde(alias = "routine_count")]
    pub routine_count: u32,
    #[prost(uint32, tag = "4")]
    #[serde(alias = "noise_count")]
    pub noise_count: u32,
    #[prost(message, optional, tag = "5")]
    pub revision: Option<RevisionMeta>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DecideReviewClusterRequest {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub decision: String,
    #[prost(string, optional, tag = "3")]
    #[serde(alias = "target_mode")]
    pub target_mode: Option<String>,
    #[prost(string, optional, tag = "4")]
    pub note: Option<String>,
    #[prost(string, optional, tag = "5")]
    pub actor: Option<String>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DecideReviewClusterResponse {
    #[prost(message, optional, tag = "1")]
    pub cluster: Option<ReviewCluster>,
}

// grdr:allow-s4 prost enumeration wire representation uses i32 backed by ProviderOrgStatus codec
#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ProviderOrgEntry {
    #[prost(string, tag = "1")]
    #[serde(alias = "org_id")]
    pub org_id: String,
    #[prost(string, tag = "2")]
    pub name: String,
    #[prost(string, tag = "3")]
    #[serde(alias = "org_set")]
    pub org_set: String,
    #[prost(string, tag = "4")]
    pub ring: String,
    #[prost(uint32, tag = "5")]
    #[serde(alias = "devices_count")]
    pub devices_count: u32,
    #[prost(uint32, tag = "6")]
    #[serde(alias = "open_findings")]
    pub open_findings: u32,
    #[prost(uint32, tag = "7")]
    #[serde(alias = "pending_approvals")]
    pub pending_approvals: u32,
    #[prost(uint32, tag = "8")]
    #[serde(alias = "coverage_pct")]
    pub coverage_pct: u32,
    #[prost(string, tag = "9")]
    #[serde(alias = "floor_version")]
    pub floor_version: String,
    #[prost(uint32, tag = "10")]
    #[serde(alias = "delegated_overrides")]
    pub delegated_overrides: u32,
    #[prost(enumeration = "crate::common::ProviderOrgStatus", tag = "11")]
    #[serde(with = "provider_org_status_serde")]
    pub status: i32,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ProviderRingSummary {
    #[prost(string, tag = "1")]
    pub ring: String,
    #[prost(uint32, tag = "2")]
    #[serde(alias = "org_count")]
    pub org_count: u32,
    #[prost(string, tag = "3")]
    #[serde(alias = "target_version")]
    pub target_version: String,
    #[prost(string, tag = "4")]
    #[serde(alias = "health_state")]
    pub health_state: String,
    #[prost(uint32, tag = "5")]
    #[serde(alias = "soak_hours")]
    pub soak_hours: u32,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GetProviderWorkspaceRequest {
    #[prost(string, optional, tag = "1")]
    #[serde(alias = "org_set")]
    pub org_set: Option<String>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GetProviderWorkspaceResponse {
    #[prost(string, optional, tag = "1")]
    #[serde(alias = "acting_as_org_id")]
    pub acting_as_org_id: Option<String>,
    #[prost(string, optional, tag = "2")]
    #[serde(alias = "acting_as_org_name")]
    pub acting_as_org_name: Option<String>,
    #[prost(string, optional, tag = "3")]
    #[serde(alias = "acting_as_reason")]
    pub acting_as_reason: Option<String>,
    #[prost(message, repeated, tag = "4")]
    pub orgs: Vec<ProviderOrgEntry>,
    #[prost(message, repeated, tag = "5")]
    pub rings: Vec<ProviderRingSummary>,
    #[prost(message, optional, tag = "6")]
    pub revision: Option<RevisionMeta>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SwitchProviderOrgRequest {
    #[prost(string, optional, tag = "1")]
    #[serde(alias = "org_id")]
    pub org_id: Option<String>,
    #[prost(string, optional, tag = "2")]
    pub reason: Option<String>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SwitchProviderOrgResponse {
    #[prost(string, optional, tag = "1")]
    #[serde(alias = "acting_as_org_id")]
    pub acting_as_org_id: Option<String>,
    #[prost(string, optional, tag = "2")]
    #[serde(alias = "acting_as_org_name")]
    pub acting_as_org_name: Option<String>,
    #[prost(string, optional, tag = "3")]
    #[serde(alias = "acting_as_reason")]
    pub acting_as_reason: Option<String>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AdvanceProviderRingRequest {
    #[prost(string, tag = "1")]
    pub ring: String,
    #[prost(string, tag = "2")]
    #[serde(alias = "target_version")]
    pub target_version: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AdvanceProviderRingResponse {
    #[prost(message, optional, tag = "1")]
    pub ring: Option<ProviderRingSummary>,
}

pub use super::surfaces_comply::*;
