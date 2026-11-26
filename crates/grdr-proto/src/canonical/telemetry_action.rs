// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Canonical action payload codecs (`exec`, `file`, `net`, `mcp`, `llm`, `cred`, `elevate`) for `grdr.event.v1alpha1`.

use serde::{Deserialize, Serialize};

use crate::canonical::common_types::{ExecutableRef, PathRef, TargetRef};

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DeterministicFact {
    #[prost(string, tag = "1")]
    pub key: String,
    #[prost(int32, tag = "2")]
    #[serde(with = "crate::canonical::common_types::fact_origin_serde")]
    pub origin: i32,
    #[prost(string, tag = "3")]
    pub analyser: String,
    #[prost(oneof = "deterministic_fact::Value", tags = "4, 5, 6")]
    #[serde(flatten)]
    pub value: Option<deterministic_fact::Value>,
}

pub mod deterministic_fact {
    use super::*;

    #[derive(Clone, PartialEq, Eq, prost::Oneof, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub enum Value {
        #[prost(bool, tag = "4")]
        Flag(bool),
        #[prost(int64, tag = "5")]
        Count(i64),
        #[prost(string, tag = "6")]
        Tag(String),
    }
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SecondaryActionRef {
    #[prost(string, tag = "1")]
    pub action_id: String,
    #[prost(int32, tag = "2")]
    #[serde(with = "crate::common::enums::action_class_serde")]
    pub action_class: i32,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ExecAction {
    #[prost(message, optional, tag = "1")]
    pub executable: Option<ExecutableRef>,
    #[prost(string, repeated, tag = "2")]
    pub command_classes: Vec<String>,
    #[prost(uint32, tag = "3")]
    pub argv_count: u32,
    #[prost(string, tag = "4")]
    pub argv_digest: String,
    #[prost(message, optional, tag = "5")]
    pub cwd: Option<PathRef>,
    #[prost(int32, optional, tag = "6")]
    pub exit_code: Option<i32>,
    #[prost(string, repeated, tag = "7")]
    pub argv_redacted: Vec<String>,
    #[prost(string, optional, tag = "8")]
    pub command_line: Option<String>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FileAction {
    #[prost(message, optional, tag = "1")]
    pub path: Option<PathRef>,
    #[prost(uint64, optional, tag = "2")]
    pub byte_count: Option<u64>,
    #[prost(string, optional, tag = "3")]
    pub content_digest: Option<String>,
    #[prost(string, optional, tag = "4")]
    pub protected_category: Option<String>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct NetAction {
    #[prost(string, tag = "1")]
    pub host: String,
    #[prost(uint32, tag = "2")]
    pub port: u32,
    #[prost(string, tag = "3")]
    pub protocol: String,
    #[prost(string, optional, tag = "4")]
    pub method: Option<String>,
    #[prost(string, optional, tag = "5")]
    pub destination_class: Option<String>,
    #[prost(string, optional, tag = "6")]
    pub request_target: Option<String>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct McpAction {
    #[prost(string, tag = "1")]
    pub mcp_id: String,
    #[prost(string, tag = "2")]
    pub tool_name: String,
    #[prost(string, tag = "3")]
    pub manifest_digest: String,
    #[prost(bool, tag = "4")]
    pub write_capable: bool,
    #[prost(string, optional, tag = "5")]
    pub arguments_preview: Option<String>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct LlmAction {
    #[prost(string, tag = "1")]
    pub provider_host: String,
    #[prost(string, tag = "2")]
    pub model: String,
    #[prost(bool, tag = "3")]
    pub tenant_endpoint: bool,
    #[prost(uint64, tag = "4")]
    pub input_tokens: u64,
    #[prost(string, optional, tag = "5")]
    pub prompt_excerpt: Option<String>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CredAction {
    #[prost(string, tag = "1")]
    pub credential_ref: String,
    #[prost(string, tag = "2")]
    pub credential_class: String,
    #[prost(string, tag = "3")]
    pub lease_id: String,
    #[prost(bool, tag = "4")]
    pub peer_verified: bool,
    #[prost(string, repeated, tag = "5")]
    pub scope_classes: Vec<String>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ElevateAction {
    #[prost(string, tag = "1")]
    pub mechanism: String,
    #[prost(string, tag = "2")]
    pub requested_privilege: String,
    #[prost(message, optional, tag = "3")]
    pub target: Option<TargetRef>,
}

// grdr:allow-s4 prost enum wire tags require i32 fields for ActionClass/ActionPhase/ActionOutcome/ResolutionKind
#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Action {
    #[prost(string, tag = "1")]
    pub action_id: String,
    #[prost(int32, tag = "2")]
    #[serde(with = "crate::common::enums::action_class_serde")]
    pub action_class: i32,
    #[prost(int32, tag = "3")]
    #[serde(with = "crate::canonical::common_types::action_phase_serde")]
    pub phase: i32,
    #[prost(int32, tag = "4")]
    #[serde(with = "crate::canonical::common_types::action_outcome_serde")]
    pub outcome: i32,
    #[prost(string, optional, tag = "5")]
    pub native_tool: Option<String>,
    #[prost(int32, tag = "6")]
    #[serde(with = "crate::canonical::common_types::resolution_kind_serde")]
    pub resolution: i32,
    #[prost(message, optional, tag = "7")]
    pub target: Option<TargetRef>,
    #[prost(message, repeated, tag = "8")]
    pub facts: Vec<DeterministicFact>,
    #[prost(string, tag = "9")]
    pub action_digest: String,
    #[prost(string, optional, tag = "10")]
    pub decision_id: Option<String>,
    #[prost(message, repeated, tag = "11")]
    pub secondary_actions: Vec<SecondaryActionRef>,
    #[prost(oneof = "action::Detail", tags = "12, 13, 14, 15, 16, 17, 18")]
    #[serde(flatten)]
    pub detail: Option<action::Detail>,
}

pub mod action {
    use super::*;

    #[derive(Clone, PartialEq, Eq, prost::Oneof, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub enum Detail {
        #[prost(message, tag = "12")]
        Exec(ExecAction),
        #[prost(message, tag = "13")]
        File(FileAction),
        #[prost(message, tag = "14")]
        Net(NetAction),
        #[prost(message, tag = "15")]
        Mcp(McpAction),
        #[prost(message, tag = "16")]
        Llm(LlmAction),
        #[prost(message, tag = "17")]
        Cred(CredAction),
        #[prost(message, tag = "18")]
        Elevate(ElevateAction),
    }
}
