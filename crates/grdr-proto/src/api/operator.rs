// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use serde::{Deserialize, Serialize};

use crate::common::{
    RevisionMeta, backup_drill_status_serde, compat_outcome_kind_serde,
    config_revision_lifecycle_serde, target_health_status_serde,
};

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct OperatorRuntimeConfig {
    #[prost(string, tag = "1")]
    #[serde(alias = "revision_id")]
    pub revision_id: String,
    #[prost(uint64, tag = "2")]
    pub version: u64,
    #[prost(string, tag = "3")]
    #[serde(alias = "capture_level")]
    pub capture_level: String,
    #[prost(string, tag = "4")]
    #[serde(alias = "privacy_profile")]
    pub privacy_profile: String,
    #[prost(string, tag = "5")]
    #[serde(alias = "retention_preset")]
    pub retention_preset: String,
    #[prost(uint32, tag = "6")]
    #[serde(alias = "hot_days")]
    pub hot_days: u32,
    #[prost(uint32, tag = "7")]
    #[serde(alias = "activity_days")]
    pub activity_days: u32,
    #[prost(uint32, tag = "8")]
    #[serde(alias = "decision_days")]
    pub decision_days: u32,
    #[prost(uint32, tag = "9")]
    #[serde(alias = "audit_days")]
    pub audit_days: u32,
    #[prost(bool, tag = "10")]
    #[serde(alias = "otlp_enabled")]
    pub otlp_enabled: bool,
    #[prost(string, tag = "11")]
    #[serde(alias = "release_channel")]
    pub release_channel: String,
    #[prost(string, tag = "12")]
    pub summary: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ConfigDiffEntry {
    #[prost(string, tag = "1")]
    pub field: String,
    #[prost(string, tag = "2")]
    pub previous: String,
    #[prost(string, tag = "3")]
    pub next: String,
}

// grdr:allow-s4 prost enumeration wire representation uses i32 backed by ConfigRevisionLifecycle codec
#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ConfigRevisionEntry {
    #[prost(string, tag = "1")]
    #[serde(alias = "revision_id")]
    pub revision_id: String,
    #[prost(uint64, tag = "2")]
    pub version: u64,
    #[prost(enumeration = "crate::common::ConfigRevisionLifecycle", tag = "3")]
    #[serde(with = "config_revision_lifecycle_serde")]
    pub state: i32,
    #[prost(string, tag = "4")]
    pub author: String,
    #[prost(string, tag = "5")]
    pub summary: String,
    #[prost(string, tag = "6")]
    #[serde(alias = "created_at")]
    pub created_at: String,
    #[prost(string, optional, tag = "7")]
    #[serde(alias = "applied_at")]
    pub applied_at: Option<String>,
    #[prost(message, repeated, tag = "8")]
    #[serde(alias = "diff_lines")]
    pub diff_lines: Vec<ConfigDiffEntry>,
    #[prost(message, optional, tag = "9")]
    pub config: Option<OperatorRuntimeConfig>,
}

// grdr:allow-s4 prost enumeration wire representation uses i32 backed by CompatOutcomeKind codec
#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CompatCheckEntry {
    #[prost(string, tag = "1")]
    pub component: String,
    #[prost(string, tag = "2")]
    #[serde(alias = "current_version")]
    pub current_version: String,
    #[prost(string, tag = "3")]
    #[serde(alias = "target_version")]
    pub target_version: String,
    #[prost(string, tag = "4")]
    #[serde(alias = "supported_range")]
    pub supported_range: String,
    #[prost(enumeration = "crate::common::CompatOutcomeKind", tag = "5")]
    #[serde(with = "compat_outcome_kind_serde")]
    pub status: i32,
    #[prost(string, repeated, tag = "6")]
    #[serde(alias = "agreed_capabilities")]
    pub agreed_capabilities: Vec<String>,
    #[prost(string, repeated, tag = "7")]
    pub warnings: Vec<String>,
    #[prost(string, tag = "8")]
    pub remediation: String,
}

// grdr:allow-s4 prost enumeration wire representation uses i32 backed by TargetHealthStatus codec
#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TargetHealthEntry {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub name: String,
    #[prost(uint32, tag = "3")]
    pub tier: u32,
    #[prost(string, tag = "4")]
    pub kind: String,
    #[prost(enumeration = "crate::common::TargetHealthStatus", tag = "5")]
    #[serde(with = "target_health_status_serde")]
    pub status: i32,
    #[prost(string, tag = "6")]
    #[serde(alias = "circuit_state")]
    pub circuit_state: String,
    #[prost(uint32, tag = "7")]
    #[serde(alias = "failure_count")]
    pub failure_count: u32,
    #[prost(uint32, tag = "8")]
    #[serde(alias = "latency_ms")]
    pub latency_ms: u32,
    #[prost(string, tag = "9")]
    pub detail: String,
    #[prost(string, tag = "10")]
    #[serde(alias = "last_checked_at")]
    pub last_checked_at: String,
}

// grdr:allow-s4 prost enumeration wire representation uses i32 backed by BackupDrillStatus codec
#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct BackupDrillRecord {
    #[prost(string, tag = "1")]
    #[serde(alias = "drill_id")]
    pub drill_id: String,
    #[prost(string, tag = "2")]
    pub kind: String,
    #[prost(enumeration = "crate::common::BackupDrillStatus", tag = "3")]
    #[serde(with = "backup_drill_status_serde")]
    pub status: i32,
    #[prost(string, tag = "4")]
    #[serde(alias = "snapshot_digest")]
    pub snapshot_digest: String,
    #[prost(uint32, tag = "5")]
    #[serde(alias = "record_count")]
    pub record_count: u32,
    #[prost(uint32, tag = "6")]
    #[serde(alias = "verified_tables")]
    pub verified_tables: u32,
    #[prost(uint32, tag = "7")]
    #[serde(alias = "duration_ms")]
    pub duration_ms: u32,
    #[prost(string, tag = "8")]
    #[serde(alias = "executed_at")]
    pub executed_at: String,
    #[prost(string, tag = "9")]
    pub actor: String,
    #[prost(string, tag = "10")]
    pub note: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GetOperatorStateRequest {}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GetOperatorStateResponse {
    #[prost(message, optional, tag = "1")]
    #[serde(alias = "runtime_config")]
    pub runtime_config: Option<OperatorRuntimeConfig>,
    #[prost(message, repeated, tag = "2")]
    pub revisions: Vec<ConfigRevisionEntry>,
    #[prost(message, repeated, tag = "3")]
    #[serde(alias = "preflight_matrix")]
    pub preflight_matrix: Vec<CompatCheckEntry>,
    #[prost(string, tag = "4")]
    #[serde(alias = "target_version")]
    pub target_version: String,
    #[prost(bool, tag = "5")]
    #[serde(alias = "overall_compatible")]
    pub overall_compatible: bool,
    #[prost(message, repeated, tag = "6")]
    pub targets: Vec<TargetHealthEntry>,
    #[prost(message, repeated, tag = "7")]
    pub drills: Vec<BackupDrillRecord>,
    #[prost(message, optional, tag = "8")]
    pub revision: Option<RevisionMeta>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct StageConfigRevisionRequest {
    #[prost(string, tag = "1")]
    #[serde(alias = "capture_level")]
    pub capture_level: String,
    #[prost(string, tag = "2")]
    #[serde(alias = "privacy_profile")]
    pub privacy_profile: String,
    #[prost(string, tag = "3")]
    #[serde(alias = "retention_preset")]
    pub retention_preset: String,
    #[prost(bool, tag = "4")]
    #[serde(alias = "otlp_enabled")]
    pub otlp_enabled: bool,
    #[prost(string, tag = "5")]
    #[serde(alias = "release_channel")]
    pub release_channel: String,
    #[prost(string, tag = "6")]
    pub summary: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct StageConfigRevisionResponse {
    #[prost(message, optional, tag = "1")]
    pub revision: Option<ConfigRevisionEntry>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ApplyConfigRevisionRequest {
    #[prost(string, tag = "1")]
    #[serde(alias = "revision_id")]
    pub revision_id: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ApplyConfigRevisionResponse {
    #[prost(message, optional, tag = "1")]
    #[serde(alias = "runtime_config")]
    pub runtime_config: Option<OperatorRuntimeConfig>,
    #[prost(message, optional, tag = "2")]
    #[serde(alias = "applied_revision")]
    pub applied_revision: Option<ConfigRevisionEntry>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RollbackConfigRevisionRequest {
    #[prost(string, optional, tag = "1")]
    #[serde(alias = "target_revision_id")]
    pub target_revision_id: Option<String>,
    #[prost(string, tag = "2")]
    pub reason: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RollbackConfigRevisionResponse {
    #[prost(message, optional, tag = "1")]
    #[serde(alias = "runtime_config")]
    pub runtime_config: Option<OperatorRuntimeConfig>,
    #[prost(message, optional, tag = "2")]
    #[serde(alias = "rolled_back_revision")]
    pub rolled_back_revision: Option<ConfigRevisionEntry>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RunUpgradePreflightRequest {
    #[prost(string, tag = "1")]
    #[serde(alias = "target_version")]
    pub target_version: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RunUpgradePreflightResponse {
    #[prost(string, tag = "1")]
    #[serde(alias = "target_version")]
    pub target_version: String,
    #[prost(bool, tag = "2")]
    #[serde(alias = "overall_compatible")]
    pub overall_compatible: bool,
    #[prost(message, repeated, tag = "3")]
    #[serde(alias = "preflight_matrix")]
    pub preflight_matrix: Vec<CompatCheckEntry>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ResetTargetBreakerRequest {
    #[prost(string, tag = "1")]
    #[serde(alias = "target_id")]
    pub target_id: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ResetTargetBreakerResponse {
    #[prost(message, optional, tag = "1")]
    pub target: Option<TargetHealthEntry>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RunBackupDrillRequest {
    #[prost(string, tag = "1")]
    pub kind: String,
    #[prost(string, optional, tag = "2")]
    pub note: Option<String>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RunBackupDrillResponse {
    #[prost(message, optional, tag = "1")]
    pub drill: Option<BackupDrillRecord>,
}
