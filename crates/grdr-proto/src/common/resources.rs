// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use serde::{Deserialize, Serialize};

use super::enums::{
    action_class_serde, assurance_level_serde, control_point_serde, control_strength_serde,
    install_profile_serde, mode_serde, on_failure_serde, tamper_grade_serde, verdict_serde,
    visibility_serde,
};
use super::enums_ext::{
    artifact_kind_serde, artifact_risk_flag_serde, artifact_scope_serde, provenance_source_serde,
    session_label_serde, span_kind_serde,
};

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TrustedKeyInfo {
    #[prost(string, tag = "1")]
    #[serde(alias = "key_id")]
    pub key_id: String,
    #[prost(string, tag = "2")]
    #[serde(alias = "public_key_b64")]
    pub public_key_b64: String,
}

#[derive(Clone, Copy, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AssuranceRecord {
    #[prost(enumeration = "super::enums::Visibility", tag = "1")]
    #[serde(with = "visibility_serde")]
    pub visibility: i32,
    #[prost(enumeration = "super::enums::ControlStrength", tag = "2")]
    #[serde(with = "control_strength_serde")]
    pub control: i32,
    #[prost(enumeration = "super::enums::OnFailure", tag = "3")]
    #[serde(with = "on_failure_serde", alias = "on_failure")]
    pub on_failure: i32,
    #[prost(enumeration = "super::enums::TamperGrade", tag = "4")]
    #[serde(with = "tamper_grade_serde")]
    pub tamper: i32,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct McpServerEntry {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(string, tag = "2")]
    pub transport: String,
    #[prost(string, tag = "3")]
    pub command: String,
    #[prost(string, tag = "4")]
    #[serde(alias = "source_agent")]
    pub source_agent: String,
    #[prost(string, tag = "5")]
    #[serde(alias = "config_path")]
    pub config_path: String,
    #[prost(bool, tag = "6")]
    pub pinned: bool,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DiscoveredAgent {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub name: String,
    #[prost(string, tag = "3")]
    pub kind: String,
    #[prost(string, tag = "4")]
    #[serde(alias = "config_path")]
    pub config_path: String,
    #[prost(bool, tag = "5")]
    #[serde(alias = "hook_installed")]
    pub hook_installed: bool,
    #[prost(uint64, tag = "6")]
    #[serde(alias = "mcp_count")]
    pub mcp_count: u64,
    #[prost(message, optional, tag = "7")]
    pub assurance: Option<AssuranceRecord>,
    #[prost(enumeration = "super::enums::AssuranceLevel", tag = "8")]
    #[serde(with = "assurance_level_serde", alias = "assurance_level")]
    pub assurance_level: i32,
    #[prost(string, optional, tag = "9")]
    pub sponsor: Option<String>,
    #[prost(string, tag = "10")]
    #[serde(alias = "detected_at")]
    pub detected_at: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ArtifactEntry {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub name: String,
    #[prost(enumeration = "super::enums_ext::ArtifactKind", tag = "3")]
    #[serde(with = "artifact_kind_serde")]
    pub kind: i32,
    #[prost(enumeration = "super::enums_ext::ArtifactScope", tag = "4")]
    #[serde(with = "artifact_scope_serde")]
    pub scope: i32,
    #[prost(string, tag = "5")]
    #[serde(alias = "source_agent")]
    pub source_agent: String,
    #[prost(string, tag = "6")]
    pub path: String,
    #[prost(string, tag = "7")]
    #[serde(alias = "content_digest")]
    pub content_digest: String,
    #[prost(uint64, tag = "8")]
    #[serde(alias = "file_count")]
    pub file_count: u64,
    #[prost(uint64, tag = "9")]
    #[serde(alias = "total_bytes")]
    pub total_bytes: u64,
    #[prost(uint32, tag = "10")]
    #[serde(alias = "usage_count")]
    pub usage_count: u32,
    #[prost(bool, tag = "11")]
    pub pinned: bool,
    #[prost(
        enumeration = "super::enums_ext::ArtifactRiskFlag",
        repeated,
        tag = "12"
    )]
    #[serde(with = "artifact_risk_flag_serde::vec", alias = "risk_flags")]
    pub risk_flags: Vec<i32>,
    #[prost(string, tag = "13")]
    #[serde(alias = "device_id")]
    pub device_id: String,
    #[prost(string, tag = "14")]
    #[serde(alias = "device_name")]
    pub device_name: String,
    #[prost(string, optional, tag = "15")]
    #[serde(alias = "user_id")]
    pub user_id: Option<String>,
    #[prost(string, tag = "16")]
    #[serde(alias = "detected_at")]
    pub detected_at: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Device {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub hostname: String,
    #[prost(string, tag = "3")]
    pub os: String,
    #[prost(string, tag = "4")]
    pub arch: String,
    #[prost(enumeration = "super::enums::InstallProfile", tag = "5")]
    #[serde(with = "install_profile_serde", alias = "install_profile")]
    pub install_profile: i32,
    #[prost(string, tag = "6")]
    #[serde(alias = "daemon_version")]
    pub daemon_version: String,
    #[prost(bool, tag = "7")]
    pub online: bool,
    #[prost(bool, tag = "8")]
    #[serde(alias = "hook_effective")]
    pub hook_effective: bool,
    #[prost(message, repeated, tag = "9")]
    pub agents: Vec<DiscoveredAgent>,
    #[prost(message, repeated, tag = "10")]
    #[serde(alias = "mcp_servers")]
    pub mcp_servers: Vec<McpServerEntry>,
    #[prost(message, repeated, tag = "11")]
    pub artifacts: Vec<ArtifactEntry>,
    #[prost(string, optional, tag = "12")]
    #[serde(alias = "user_id")]
    pub user_id: Option<String>,
    #[prost(string, optional, tag = "13")]
    #[serde(alias = "user_display")]
    pub user_display: Option<String>,
    #[prost(string, tag = "14")]
    #[serde(alias = "last_seen")]
    pub last_seen: String,
    #[prost(message, optional, tag = "15")]
    #[serde(alias = "public_key")]
    pub public_key: Option<TrustedKeyInfo>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SecondaryAction {
    #[prost(string, tag = "1")]
    pub command: String,
    #[prost(enumeration = "super::enums::ActionClass", tag = "2")]
    #[serde(with = "action_class_serde", alias = "action_class")]
    pub action_class: i32,
    #[prost(string, tag = "3")]
    pub target: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ActionAttempt {
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
    #[prost(enumeration = "super::enums::ActionClass", tag = "6")]
    #[serde(with = "action_class_serde", alias = "action_class")]
    pub action_class: i32,
    #[prost(enumeration = "super::enums::ControlPoint", tag = "7")]
    #[serde(with = "control_point_serde", alias = "control_point")]
    pub control_point: i32,
    #[prost(string, tag = "8")]
    pub target: String,
    #[prost(string, tag = "9")]
    pub summary: String,
    #[prost(string, tag = "10")]
    pub timestamp: String,
    #[prost(string, optional, tag = "11")]
    #[serde(alias = "user_id")]
    pub user_id: Option<String>,
    #[prost(string, optional, tag = "12")]
    #[serde(alias = "user_display")]
    pub user_display: Option<String>,
    #[prost(uint32, tag = "13")]
    #[serde(alias = "turn_index")]
    pub turn_index: u32,
    #[prost(string, optional, tag = "14")]
    #[serde(alias = "span_id")]
    pub span_id: Option<String>,
    #[prost(string, optional, tag = "15")]
    #[serde(alias = "parent_span_id")]
    pub parent_span_id: Option<String>,
    #[prost(enumeration = "super::enums_ext::SpanKind", tag = "16")]
    #[serde(with = "span_kind_serde", alias = "span_kind")]
    pub span_kind: i32,
    #[prost(uint64, tag = "17")]
    #[serde(alias = "duration_ms")]
    pub duration_ms: u64,
    #[prost(enumeration = "super::enums_ext::ProvenanceSource", tag = "18")]
    #[serde(with = "provenance_source_serde")]
    pub provenance: i32,
    #[prost(message, repeated, tag = "19")]
    #[serde(alias = "secondary_actions")]
    pub secondary_actions: Vec<SecondaryAction>,
    #[prost(string, optional, tag = "20")]
    #[serde(alias = "skill_used")]
    pub skill_used: Option<String>,
    #[prost(bool, tag = "21")]
    pub compaction: bool,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DecisionReceipt {
    #[prost(string, tag = "1")]
    #[serde(alias = "receipt_id")]
    pub receipt_id: String,
    #[prost(string, tag = "2")]
    #[serde(alias = "attempt_id")]
    pub attempt_id: String,
    #[prost(string, tag = "3")]
    #[serde(alias = "session_id")]
    pub session_id: String,
    #[prost(string, tag = "4")]
    #[serde(alias = "device_id")]
    pub device_id: String,
    #[prost(string, tag = "5")]
    #[serde(alias = "agent_name")]
    pub agent_name: String,
    #[prost(enumeration = "super::enums::ActionClass", tag = "6")]
    #[serde(with = "action_class_serde", alias = "action_class")]
    pub action_class: i32,
    #[prost(enumeration = "super::enums::ControlPoint", tag = "7")]
    #[serde(with = "control_point_serde", alias = "control_point")]
    pub control_point: i32,
    #[prost(string, tag = "8")]
    pub target: String,
    #[prost(enumeration = "super::enums::Verdict", tag = "9")]
    #[serde(with = "verdict_serde")]
    pub verdict: i32,
    #[prost(enumeration = "super::enums::Verdict", optional, tag = "10")]
    #[serde(with = "verdict_serde::opt", alias = "would_be")]
    pub would_be: Option<i32>,
    #[prost(string, optional, tag = "11")]
    #[serde(alias = "rule_id")]
    pub rule_id: Option<String>,
    #[prost(string, optional, tag = "12")]
    #[serde(alias = "pack_id")]
    pub pack_id: Option<String>,
    #[prost(enumeration = "super::enums::Mode", optional, tag = "13")]
    #[serde(with = "mode_serde::opt", alias = "mode_applied")]
    pub mode_applied: Option<i32>,
    #[prost(string, optional, tag = "14")]
    #[serde(alias = "grant_id")]
    pub grant_id: Option<String>,
    #[prost(string, tag = "15")]
    pub reason: String,
    #[prost(string, tag = "16")]
    #[serde(alias = "next_step")]
    pub next_step: String,
    #[prost(string, tag = "17")]
    #[serde(alias = "receipt_digest")]
    pub receipt_digest: String,
    #[prost(string, optional, tag = "18")]
    #[serde(alias = "key_id")]
    pub key_id: Option<String>,
    #[prost(string, optional, tag = "19")]
    pub signature: Option<String>,
    #[prost(bool, optional, tag = "20")]
    #[serde(alias = "signature_verified")]
    pub signature_verified: Option<bool>,
    #[prost(string, tag = "21")]
    #[serde(alias = "decided_at")]
    pub decided_at: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TurnSummary {
    #[prost(uint32, tag = "1")]
    #[serde(alias = "turn_index")]
    pub turn_index: u32,
    #[prost(string, tag = "2")]
    #[serde(alias = "trace_id")]
    pub trace_id: String,
    #[prost(uint64, tag = "3")]
    #[serde(alias = "span_count")]
    pub span_count: u64,
    #[prost(uint64, tag = "4")]
    #[serde(alias = "duration_ms")]
    pub duration_ms: u64,
    #[prost(uint64, tag = "5")]
    #[serde(alias = "blocked_count")]
    pub blocked_count: u64,
    #[prost(uint64, tag = "6")]
    #[serde(alias = "asked_count")]
    pub asked_count: u64,
    #[prost(bool, tag = "7")]
    #[serde(alias = "has_compaction")]
    pub has_compaction: bool,
    #[prost(bool, tag = "8")]
    #[serde(alias = "has_subagent_handoff")]
    pub has_subagent_handoff: bool,
    #[prost(string, tag = "9")]
    #[serde(alias = "started_at")]
    pub started_at: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SessionSummary {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    #[serde(alias = "device_id")]
    pub device_id: String,
    #[prost(string, tag = "3")]
    #[serde(alias = "device_name")]
    pub device_name: String,
    #[prost(string, tag = "4")]
    #[serde(alias = "agent_name")]
    pub agent_name: String,
    #[prost(string, optional, tag = "5")]
    #[serde(alias = "user_id")]
    pub user_id: Option<String>,
    #[prost(string, optional, tag = "6")]
    #[serde(alias = "user_display")]
    pub user_display: Option<String>,
    #[prost(uint64, tag = "7")]
    #[serde(alias = "turn_count")]
    pub turn_count: u64,
    #[prost(string, optional, tag = "8")]
    #[serde(alias = "parent_session_id")]
    pub parent_session_id: Option<String>,
    #[prost(string, tag = "9")]
    #[serde(alias = "started_at")]
    pub started_at: String,
    #[prost(string, tag = "10")]
    #[serde(alias = "last_activity")]
    pub last_activity: String,
    #[prost(uint64, tag = "11")]
    #[serde(alias = "total_actions")]
    pub total_actions: u64,
    #[prost(uint64, tag = "12")]
    #[serde(alias = "blocked_count")]
    pub blocked_count: u64,
    #[prost(uint64, tag = "13")]
    #[serde(alias = "step_up_count")]
    pub step_up_count: u64,
    #[prost(uint64, tag = "14")]
    #[serde(alias = "watch_hits")]
    pub watch_hits: u64,
    #[prost(enumeration = "super::enums::AssuranceLevel", tag = "15")]
    #[serde(with = "assurance_level_serde", alias = "assurance_level")]
    pub assurance_level: i32,
    #[prost(enumeration = "super::enums_ext::SessionLabel", repeated, tag = "16")]
    #[serde(with = "session_label_serde::vec")]
    pub labels: Vec<i32>,
}
