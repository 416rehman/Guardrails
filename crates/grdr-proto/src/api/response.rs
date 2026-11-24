// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use serde::{Deserialize, Serialize};

use crate::common::{
    ApprovalRequest, AuditEntry, Finding, Incident, KillSwitchState, PageInfo, RevisionMeta,
    finding_lifecycle_serde, grant_scope_serde, kill_action_serde, kill_scope_serde,
};

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListApprovalsRequest {
    #[prost(uint32, tag = "1")]
    #[serde(alias = "page_size")]
    pub page_size: u32,
    #[prost(string, tag = "2")]
    #[serde(alias = "page_token")]
    pub page_token: String,
    #[prost(string, tag = "3")]
    pub filter: String,
    #[prost(string, tag = "4")]
    #[serde(alias = "order_by")]
    pub order_by: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListApprovalsResponse {
    #[prost(message, repeated, tag = "1")]
    pub approvals: Vec<ApprovalRequest>,
    #[prost(message, optional, tag = "2")]
    #[serde(alias = "page_info")]
    pub page_info: Option<PageInfo>,
    #[prost(message, optional, tag = "3")]
    pub revision: Option<RevisionMeta>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DecideApprovalRequest {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(bool, tag = "2")]
    pub approve: bool,
    #[prost(enumeration = "crate::common::GrantScope", optional, tag = "3")]
    #[serde(with = "grant_scope_serde::opt")]
    pub scope: Option<i32>,
    #[prost(string, optional, tag = "4")]
    pub note: Option<String>,
    #[prost(string, optional, tag = "5")]
    pub actor: Option<String>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DecideApprovalResponse {
    #[prost(message, optional, tag = "1")]
    pub approval: Option<ApprovalRequest>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListFindingsRequest {
    #[prost(uint32, tag = "1")]
    #[serde(alias = "page_size")]
    pub page_size: u32,
    #[prost(string, tag = "2")]
    #[serde(alias = "page_token")]
    pub page_token: String,
    #[prost(string, tag = "3")]
    pub filter: String,
    #[prost(string, tag = "4")]
    #[serde(alias = "order_by")]
    pub order_by: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListFindingsResponse {
    #[prost(message, repeated, tag = "1")]
    pub findings: Vec<Finding>,
    #[prost(message, optional, tag = "2")]
    #[serde(alias = "page_info")]
    pub page_info: Option<PageInfo>,
    #[prost(message, optional, tag = "3")]
    pub revision: Option<RevisionMeta>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct UpdateFindingRequest {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(enumeration = "crate::common::FindingLifecycle", tag = "2")]
    #[serde(with = "finding_lifecycle_serde")]
    pub lifecycle: i32,
    #[prost(string, optional, tag = "3")]
    pub note: Option<String>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct UpdateFindingResponse {
    #[prost(message, optional, tag = "1")]
    pub finding: Option<Finding>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListIncidentsRequest {
    #[prost(uint32, tag = "1")]
    #[serde(alias = "page_size")]
    pub page_size: u32,
    #[prost(string, tag = "2")]
    #[serde(alias = "page_token")]
    pub page_token: String,
    #[prost(string, tag = "3")]
    pub filter: String,
    #[prost(string, tag = "4")]
    #[serde(alias = "order_by")]
    pub order_by: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListIncidentsResponse {
    #[prost(message, repeated, tag = "1")]
    pub incidents: Vec<Incident>,
    #[prost(message, optional, tag = "2")]
    #[serde(alias = "page_info")]
    pub page_info: Option<PageInfo>,
    #[prost(message, optional, tag = "3")]
    pub revision: Option<RevisionMeta>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GetKillSwitchRequest {}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GetKillSwitchResponse {
    #[prost(message, optional, tag = "1")]
    #[serde(alias = "kill_switch")]
    pub kill_switch: Option<KillSwitchState>,
    #[prost(message, optional, tag = "2")]
    pub revision: Option<RevisionMeta>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SetKillSwitchRequest {
    #[prost(enumeration = "crate::common::KillAction", tag = "1")]
    #[serde(with = "kill_action_serde")]
    pub action: i32,
    #[prost(enumeration = "crate::common::KillScope", tag = "2")]
    #[serde(with = "kill_scope_serde")]
    pub scope: i32,
    #[prost(string, tag = "3")]
    #[serde(alias = "target_id")]
    pub target_id: String,
    #[prost(string, tag = "4")]
    pub reason: String,
    #[prost(int64, optional, tag = "5")]
    #[serde(alias = "duration_minutes")]
    pub duration_minutes: Option<i64>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SetKillSwitchResponse {
    #[prost(message, optional, tag = "1")]
    #[serde(alias = "kill_switch")]
    pub kill_switch: Option<KillSwitchState>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListAuditEventsRequest {
    #[prost(uint32, tag = "1")]
    #[serde(alias = "page_size")]
    pub page_size: u32,
    #[prost(string, tag = "2")]
    #[serde(alias = "page_token")]
    pub page_token: String,
    #[prost(string, tag = "3")]
    pub filter: String,
    #[prost(string, tag = "4")]
    #[serde(alias = "order_by")]
    pub order_by: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListAuditEventsResponse {
    #[prost(message, repeated, tag = "1")]
    pub entries: Vec<AuditEntry>,
    #[prost(message, optional, tag = "2")]
    #[serde(alias = "page_info")]
    pub page_info: Option<PageInfo>,
    #[prost(message, optional, tag = "3")]
    pub revision: Option<RevisionMeta>,
}
