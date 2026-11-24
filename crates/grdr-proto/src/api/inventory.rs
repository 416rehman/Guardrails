// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use serde::{Deserialize, Serialize};

use crate::common::{
    ArtifactEntry, Device, DiscoveredAgent, Grant, KillSwitchState, McpServerEntry, PageInfo,
    PolicyPack, RevisionMeta, TrustedKeyInfo, deployment_key_status_serde, install_profile_serde,
    integration_category_serde, integration_health_state_serde, mdm_format_serde,
};

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct InstallerSpec {
    #[prost(string, tag = "1")]
    pub platform: String,
    #[prost(string, tag = "2")]
    pub label: String,
    #[prost(string, tag = "3")]
    pub version: String,
    #[prost(string, tag = "4")]
    pub command: String,
    #[prost(string, tag = "5")]
    pub sha256: String,
    #[prost(string, tag = "6")]
    #[serde(alias = "doctor_command")]
    pub doctor_command: String,
    #[prost(string, tag = "7")]
    pub notes: String,
}

// grdr:allow-s4 prost enumeration wire representation uses i32 backed by DeploymentKeyStatus codec
#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DeploymentKey {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub label: String,
    #[prost(string, tag = "3")]
    #[serde(alias = "token_preview")]
    pub token_preview: String,
    #[prost(string, tag = "4")]
    #[serde(alias = "install_profile")]
    pub install_profile: String,
    #[prost(string, tag = "5")]
    pub wave: String,
    #[prost(uint32, tag = "6")]
    #[serde(alias = "max_uses")]
    pub max_uses: u32,
    #[prost(uint32, tag = "7")]
    #[serde(alias = "used_count")]
    pub used_count: u32,
    #[prost(enumeration = "crate::common::DeploymentKeyStatus", tag = "8")]
    #[serde(with = "deployment_key_status_serde")]
    pub status: i32,
    #[prost(string, tag = "9")]
    #[serde(alias = "created_at")]
    pub created_at: String,
    #[prost(string, tag = "10")]
    #[serde(alias = "expires_at")]
    pub expires_at: String,
    #[prost(string, tag = "11")]
    #[serde(alias = "created_by")]
    pub created_by: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct OtlpFanoutConfig {
    #[prost(bool, tag = "1")]
    pub enabled: bool,
    #[prost(uint32, tag = "2")]
    #[serde(alias = "grpc_port")]
    pub grpc_port: u32,
    #[prost(uint32, tag = "3")]
    #[serde(alias = "http_port")]
    pub http_port: u32,
    #[prost(string, tag = "4")]
    #[serde(alias = "bind_address")]
    pub bind_address: String,
    #[prost(string, repeated, tag = "5")]
    #[serde(alias = "downstream_targets")]
    pub downstream_targets: Vec<String>,
    #[prost(bool, tag = "6")]
    #[serde(alias = "loopback_only")]
    pub loopback_only: bool,
    #[prost(uint64, tag = "7")]
    #[serde(alias = "accepted_spans_24h")]
    pub accepted_spans_24h: u64,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ReadinessCheck {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(bool, tag = "2")]
    pub passed: bool,
    #[prost(string, tag = "3")]
    pub detail: String,
}

// grdr:allow-s4 prost enumeration wire representation uses i32 backed by IntegrationHealthState codec
#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct IntegrationEntry {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub name: String,
    #[prost(string, tag = "3")]
    pub provider: String,
    #[prost(enumeration = "crate::common::IntegrationCategory", tag = "4")]
    #[serde(with = "integration_category_serde")]
    pub category: i32,
    #[prost(enumeration = "crate::common::IntegrationHealthState", tag = "5")]
    #[serde(with = "integration_health_state_serde")]
    pub state: i32,
    #[prost(uint32, tag = "6")]
    #[serde(alias = "synced_users")]
    pub synced_users: u32,
    #[prost(string, optional, tag = "7")]
    #[serde(alias = "last_sync_at")]
    pub last_sync_at: Option<String>,
    #[prost(uint32, optional, tag = "8")]
    #[serde(alias = "credential_expires_in_days")]
    pub credential_expires_in_days: Option<u32>,
    #[prost(string, tag = "9")]
    pub detail: String,
    #[prost(message, repeated, tag = "10")]
    #[serde(alias = "readiness_checks")]
    pub readiness_checks: Vec<ReadinessCheck>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListDevicesRequest {
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
pub struct ListDevicesResponse {
    #[prost(message, repeated, tag = "1")]
    pub devices: Vec<Device>,
    #[prost(message, optional, tag = "2")]
    #[serde(alias = "page_info")]
    pub page_info: Option<PageInfo>,
    #[prost(message, optional, tag = "3")]
    pub revision: Option<RevisionMeta>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DeviceCheckinRequest {
    #[prost(string, optional, tag = "1")]
    #[serde(alias = "device_id")]
    pub device_id: Option<String>,
    #[prost(string, tag = "2")]
    pub hostname: String,
    #[prost(string, tag = "3")]
    pub os: String,
    #[prost(string, tag = "4")]
    pub arch: String,
    #[prost(enumeration = "crate::common::InstallProfile", tag = "5")]
    #[serde(with = "install_profile_serde", alias = "install_profile")]
    pub install_profile: i32,
    #[prost(string, tag = "6")]
    #[serde(alias = "daemon_version")]
    pub daemon_version: String,
    #[prost(bool, tag = "7")]
    #[serde(alias = "hook_effective")]
    pub hook_effective: bool,
    #[prost(message, repeated, tag = "8")]
    pub agents: Vec<DiscoveredAgent>,
    #[prost(message, repeated, tag = "9")]
    #[serde(alias = "mcp_servers")]
    pub mcp_servers: Vec<McpServerEntry>,
    #[prost(message, repeated, tag = "10")]
    pub artifacts: Vec<ArtifactEntry>,
    #[prost(string, optional, tag = "11")]
    #[serde(alias = "user_id")]
    pub user_id: Option<String>,
    #[prost(string, optional, tag = "12")]
    #[serde(alias = "user_display")]
    pub user_display: Option<String>,
    #[prost(message, optional, tag = "13")]
    #[serde(alias = "device_public_key")]
    pub device_public_key: Option<TrustedKeyInfo>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DeviceCheckinResponse {
    #[prost(message, optional, tag = "1")]
    pub device: Option<Device>,
    #[prost(message, repeated, tag = "2")]
    pub packs: Vec<PolicyPack>,
    #[prost(message, repeated, tag = "3")]
    pub grants: Vec<Grant>,
    #[prost(message, optional, tag = "4")]
    #[serde(alias = "kill_switch")]
    pub kill_switch: Option<KillSwitchState>,
    #[prost(string, tag = "5")]
    #[serde(alias = "server_time")]
    pub server_time: String,
    #[prost(message, repeated, tag = "6")]
    #[serde(alias = "trusted_keys")]
    pub trusted_keys: Vec<TrustedKeyInfo>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AgentInventoryItem {
    #[prost(string, tag = "1")]
    #[serde(alias = "device_id")]
    pub device_id: String,
    #[prost(string, tag = "2")]
    #[serde(alias = "device_name")]
    pub device_name: String,
    #[prost(message, optional, tag = "3")]
    pub agent: Option<DiscoveredAgent>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListAgentsRequest {
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
pub struct ListAgentsResponse {
    #[prost(message, repeated, tag = "1")]
    pub items: Vec<AgentInventoryItem>,
    #[prost(message, optional, tag = "2")]
    #[serde(alias = "page_info")]
    pub page_info: Option<PageInfo>,
    #[prost(message, optional, tag = "3")]
    pub revision: Option<RevisionMeta>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct McpInventoryItem {
    #[prost(string, tag = "1")]
    #[serde(alias = "device_id")]
    pub device_id: String,
    #[prost(string, tag = "2")]
    #[serde(alias = "device_name")]
    pub device_name: String,
    #[prost(message, optional, tag = "3")]
    pub server: Option<McpServerEntry>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListMcpServersRequest {
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
pub struct ListMcpServersResponse {
    #[prost(message, repeated, tag = "1")]
    pub items: Vec<McpInventoryItem>,
    #[prost(message, optional, tag = "2")]
    #[serde(alias = "page_info")]
    pub page_info: Option<PageInfo>,
    #[prost(message, optional, tag = "3")]
    pub revision: Option<RevisionMeta>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListArtifactsRequest {
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
pub struct ListArtifactsResponse {
    #[prost(message, repeated, tag = "1")]
    pub artifacts: Vec<ArtifactEntry>,
    #[prost(message, optional, tag = "2")]
    #[serde(alias = "page_info")]
    pub page_info: Option<PageInfo>,
    #[prost(message, optional, tag = "3")]
    pub revision: Option<RevisionMeta>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GetConnectConfigRequest {}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GetConnectConfigResponse {
    #[prost(string, tag = "1")]
    #[serde(alias = "server_origin")]
    pub server_origin: String,
    #[prost(message, repeated, tag = "2")]
    pub installers: Vec<InstallerSpec>,
    #[prost(message, repeated, tag = "3")]
    #[serde(alias = "deployment_keys")]
    pub deployment_keys: Vec<DeploymentKey>,
    #[prost(message, optional, tag = "4")]
    pub otlp: Option<OtlpFanoutConfig>,
    #[prost(message, repeated, tag = "5")]
    pub integrations: Vec<IntegrationEntry>,
    #[prost(message, optional, tag = "6")]
    pub revision: Option<RevisionMeta>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CreateDeploymentKeyRequest {
    #[prost(string, tag = "1")]
    pub label: String,
    #[prost(string, tag = "2")]
    pub wave: String,
    #[prost(string, tag = "3")]
    #[serde(alias = "install_profile")]
    pub install_profile: String,
    #[prost(uint32, tag = "4")]
    #[serde(alias = "max_uses")]
    pub max_uses: u32,
    #[prost(uint32, tag = "5")]
    #[serde(alias = "ttl_days")]
    pub ttl_days: u32,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CreateDeploymentKeyResponse {
    #[prost(message, optional, tag = "1")]
    pub key: Option<DeploymentKey>,
    #[prost(string, tag = "2")]
    #[serde(alias = "plaintext_token")]
    pub plaintext_token: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RevokeDeploymentKeyRequest {
    #[prost(string, tag = "1")]
    pub id: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RevokeDeploymentKeyResponse {
    #[prost(message, optional, tag = "1")]
    pub key: Option<DeploymentKey>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RenderMdmConfigRequest {
    #[prost(enumeration = "crate::common::MdmFormat", tag = "1")]
    #[serde(with = "mdm_format_serde")]
    pub format: i32,
    #[prost(string, optional, tag = "2")]
    #[serde(alias = "deployment_key_id")]
    pub deployment_key_id: Option<String>,
    #[prost(bool, tag = "3")]
    #[serde(alias = "include_browser_extension")]
    pub include_browser_extension: bool,
    #[prost(string, tag = "4")]
    #[serde(alias = "update_authority")]
    pub update_authority: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RenderMdmConfigResponse {
    #[prost(enumeration = "crate::common::MdmFormat", tag = "1")]
    #[serde(with = "mdm_format_serde")]
    pub format: i32,
    #[prost(string, tag = "2")]
    pub filename: String,
    #[prost(string, tag = "3")]
    #[serde(alias = "content_type")]
    pub content_type: String,
    #[prost(string, tag = "4")]
    pub payload: String,
    #[prost(string, repeated, tag = "5")]
    #[serde(alias = "deployment_notes")]
    pub deployment_notes: Vec<String>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListIntegrationsRequest {}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListIntegrationsResponse {
    #[prost(message, repeated, tag = "1")]
    pub integrations: Vec<IntegrationEntry>,
    #[prost(message, optional, tag = "2")]
    pub revision: Option<RevisionMeta>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CheckIntegrationReadinessRequest {
    #[prost(string, tag = "1")]
    pub id: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CheckIntegrationReadinessResponse {
    #[prost(message, optional, tag = "1")]
    pub integration: Option<IntegrationEntry>,
}
