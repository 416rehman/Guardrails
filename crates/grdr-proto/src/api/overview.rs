// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use serde::{Deserialize, Serialize};

use crate::common::{
    KillSwitchState, RevisionMeta, TrustedKeyInfo, server_health_serde, storage_kind_serde,
    verdict_serde,
};

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct StorageMode {
    #[prost(enumeration = "crate::common::StorageKind", tag = "1")]
    #[serde(with = "storage_kind_serde")]
    pub kind: i32,
    #[prost(string, optional, tag = "2")]
    pub path: Option<String>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct InsightTile {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub headline: String,
    #[prost(string, tag = "3")]
    pub metric: String,
    #[prost(string, tag = "4")]
    pub comparison: String,
    #[prost(string, tag = "5")]
    #[serde(alias = "action_label")]
    pub action_label: String,
    #[prost(string, tag = "6")]
    pub route: String,
    #[prost(string, tag = "7")]
    pub tone: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SetupStep {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub label: String,
    #[prost(bool, tag = "3")]
    pub done: bool,
    #[prost(string, tag = "4")]
    pub detail: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GetHealthRequest {}

// grdr:allow-s4 prost enumeration wire representation uses i32 backed by ServerHealth codec
#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GetHealthResponse {
    #[prost(enumeration = "crate::common::ServerHealth", tag = "1")]
    #[serde(with = "server_health_serde")]
    pub status: i32,
    #[prost(string, tag = "2")]
    pub version: String,
    #[prost(message, optional, tag = "3")]
    #[serde(alias = "storage_mode")]
    pub storage_mode: Option<StorageMode>,
    #[prost(string, tag = "4")]
    pub timestamp: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GetOverviewRequest {}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GetOverviewResponse {
    #[prost(enumeration = "crate::common::ServerHealth", tag = "1")]
    #[serde(with = "server_health_serde", alias = "server_status")]
    pub server_status: i32,
    #[prost(uint64, tag = "2")]
    #[serde(alias = "total_devices")]
    pub total_devices: u64,
    #[prost(uint64, tag = "3")]
    #[serde(alias = "online_devices")]
    pub online_devices: u64,
    #[prost(uint64, tag = "4")]
    #[serde(alias = "total_agents")]
    pub total_agents: u64,
    #[prost(uint64, tag = "5")]
    #[serde(alias = "total_mcp_servers")]
    pub total_mcp_servers: u64,
    #[prost(uint64, tag = "6")]
    #[serde(alias = "active_sessions")]
    pub active_sessions: u64,
    #[prost(uint64, tag = "7")]
    #[serde(alias = "pending_approvals")]
    pub pending_approvals: u64,
    #[prost(uint64, tag = "8")]
    #[serde(alias = "open_findings")]
    pub open_findings: u64,
    #[prost(uint64, tag = "9")]
    #[serde(alias = "open_incidents")]
    pub open_incidents: u64,
    #[prost(message, optional, tag = "10")]
    #[serde(alias = "kill_switch")]
    pub kill_switch: Option<KillSwitchState>,
    #[prost(message, repeated, tag = "11")]
    pub tiles: Vec<InsightTile>,
    #[prost(message, repeated, tag = "12")]
    #[serde(alias = "setup_steps")]
    pub setup_steps: Vec<SetupStep>,
    #[prost(message, optional, tag = "13")]
    pub revision: Option<RevisionMeta>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListKeysRequest {}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListKeysResponse {
    #[prost(message, repeated, tag = "1")]
    pub keys: Vec<TrustedKeyInfo>,
    #[prost(message, optional, tag = "2")]
    pub revision: Option<RevisionMeta>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ExportOcsfRequest {}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ExportOcsfResponse {
    #[prost(string, tag = "1")]
    pub filename: String,
    #[prost(string, tag = "2")]
    #[serde(alias = "content_type")]
    pub content_type: String,
    #[prost(string, tag = "3")]
    pub payload: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ExportAuditJsonlRequest {}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ExportAuditJsonlResponse {
    #[prost(string, tag = "1")]
    pub filename: String,
    #[prost(string, tag = "2")]
    #[serde(alias = "content_type")]
    pub content_type: String,
    #[prost(string, tag = "3")]
    pub payload: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct IssueLiveTicketRequest {}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct IssueLiveTicketResponse {
    #[prost(string, tag = "1")]
    pub ticket: String,
    #[prost(uint32, tag = "2")]
    #[serde(alias = "expires_in_seconds")]
    pub expires_in_seconds: u32,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct LiveEvent {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub topic: String,
    #[prost(string, tag = "3")]
    pub summary: String,
    #[prost(enumeration = "crate::common::Verdict", optional, tag = "4")]
    #[serde(with = "verdict_serde::opt")]
    pub verdict: Option<i32>,
    #[prost(string, tag = "5")]
    pub timestamp: String,
}
