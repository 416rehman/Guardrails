// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use serde::{Deserialize, Serialize};

use crate::common::{
    ActionAttempt, ArtifactEntry, DecisionReceipt, Device, Finding, OrgPrivacyConfig, PageInfo,
    RevisionMeta, SessionSummary, UserProfile, identity_mode_serde,
};

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListUsersRequest {
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
pub struct ListUsersResponse {
    #[prost(message, repeated, tag = "1")]
    pub users: Vec<UserProfile>,
    #[prost(message, optional, tag = "2")]
    #[serde(alias = "page_info")]
    pub page_info: Option<PageInfo>,
    #[prost(message, optional, tag = "3")]
    pub revision: Option<RevisionMeta>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GetUserRequest {
    #[prost(string, tag = "1")]
    pub id: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GetUserResponse {
    #[prost(message, optional, tag = "1")]
    pub user: Option<UserProfile>,
    #[prost(message, repeated, tag = "2")]
    pub devices: Vec<Device>,
    #[prost(message, repeated, tag = "3")]
    pub sessions: Vec<SessionSummary>,
    #[prost(message, repeated, tag = "4")]
    #[serde(alias = "recent_attempts")]
    pub recent_attempts: Vec<ActionAttempt>,
    #[prost(message, repeated, tag = "5")]
    pub receipts: Vec<DecisionReceipt>,
    #[prost(message, repeated, tag = "6")]
    pub findings: Vec<Finding>,
    #[prost(message, repeated, tag = "7")]
    pub artifacts: Vec<ArtifactEntry>,
    #[prost(enumeration = "crate::common::IdentityMode", tag = "8")]
    #[serde(with = "identity_mode_serde", alias = "identity_mode")]
    pub identity_mode: i32,
    #[prost(message, optional, tag = "9")]
    pub revision: Option<RevisionMeta>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GetPrivacyConfigRequest {}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GetPrivacyConfigResponse {
    #[prost(message, optional, tag = "1")]
    pub config: Option<OrgPrivacyConfig>,
    #[prost(message, optional, tag = "2")]
    pub revision: Option<RevisionMeta>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct UpdatePrivacyConfigRequest {
    #[prost(enumeration = "crate::common::IdentityMode", optional, tag = "1")]
    #[serde(with = "identity_mode_serde::opt", alias = "identity_mode")]
    pub identity_mode: Option<i32>,
    #[prost(bool, optional, tag = "2")]
    #[serde(alias = "user_risk_scoring")]
    pub user_risk_scoring: Option<bool>,
    #[prost(string, optional, tag = "3")]
    pub actor: Option<String>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct UpdatePrivacyConfigResponse {
    #[prost(message, optional, tag = "1")]
    pub config: Option<OrgPrivacyConfig>,
}
