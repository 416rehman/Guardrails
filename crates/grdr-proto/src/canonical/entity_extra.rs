// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Extended canonical message definitions re-exported into `entity`, `decision`, and `inventory`.

pub mod entity_defs {
    use serde::{Deserialize, Serialize};

    use crate::canonical::common_types::{PathRef, ProtoTimestamp};

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct Organisation {
        #[prost(string, tag = "1")]
        pub org_id: String,
        #[prost(int32, tag = "2")]
        #[serde(with = "crate::common::enums_ext::identity_mode_serde")]
        pub identity_mode: i32,
        #[prost(int32, tag = "3")]
        #[serde(with = "crate::canonical::common_types::capture_level_serde")]
        pub capture_level: i32,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct Device {
        #[prost(string, tag = "1")]
        pub device_id: String,
        #[prost(string, tag = "2")]
        pub org_id: String,
        #[prost(string, tag = "3")]
        pub hostname: String,
        #[prost(string, tag = "4")]
        pub os: String,
        #[prost(string, tag = "5")]
        pub arch: String,
        #[prost(int32, tag = "6")]
        #[serde(with = "crate::common::enums::install_profile_serde")]
        pub install_profile: i32,
        #[prost(int32, tag = "7")]
        #[serde(with = "crate::common::enums::tamper_grade_serde")]
        pub tamper: i32,
        #[prost(int32, tag = "8")]
        #[serde(with = "crate::common::enums::assurance_level_serde")]
        pub assurance_level: i32,
        #[prost(string, tag = "9")]
        pub sensor_version: String,
        #[prost(message, optional, tag = "10")]
        pub last_seen_at: Option<ProtoTimestamp>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct AgentType {
        #[prost(string, tag = "1")]
        pub agent_type_id: String,
        #[prost(string, tag = "2")]
        pub slug: String,
        #[prost(string, tag = "3")]
        pub catalogue_tier: String,
        #[prost(bool, tag = "4")]
        pub session_exclusive: bool,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct ToolCall {
        #[prost(string, tag = "1")]
        pub tool_call_id: String,
        #[prost(string, tag = "2")]
        pub session_id: String,
        #[prost(string, tag = "3")]
        pub native_tool: String,
        #[prost(message, optional, tag = "4")]
        pub started_at: Option<ProtoTimestamp>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct McpServer {
        #[prost(string, tag = "1")]
        pub mcp_id: String,
        #[prost(string, tag = "2")]
        pub name: String,
        #[prost(string, tag = "3")]
        pub transport: String,
        #[prost(bool, tag = "4")]
        pub identity_pinned: bool,
        #[prost(string, tag = "5")]
        pub manifest_digest: String,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct Artifact {
        #[prost(string, tag = "1")]
        pub artifact_id: String,
        #[prost(int32, tag = "2")]
        #[serde(with = "crate::common::enums_ext::artifact_kind_serde")]
        pub kind: i32,
        #[prost(string, optional, tag = "3")]
        pub kind_other: Option<String>,
        #[prost(int32, tag = "4")]
        #[serde(with = "crate::common::enums_ext::artifact_scope_serde")]
        pub scope: i32,
        #[prost(string, tag = "5")]
        pub content_digest: String,
        #[prost(message, optional, tag = "6")]
        pub location: Option<PathRef>,
    }
}

pub mod decision_defs {
    use serde::{Deserialize, Serialize};

    use crate::canonical::common_types::ProtoTimestamp;

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct Grant {
        #[prost(string, tag = "1")]
        pub grant_id: String,
        #[prost(string, tag = "2")]
        pub rule_id: String,
        #[prost(string, tag = "3")]
        pub session_id: String,
        #[prost(string, tag = "4")]
        pub device_id: String,
        #[prost(int32, tag = "5")]
        #[serde(with = "crate::common::enums::action_class_serde")]
        pub action_class: i32,
        #[prost(string, tag = "6")]
        pub target_digest: String,
        #[prost(int32, tag = "7")]
        #[serde(with = "crate::common::enums::grant_scope_serde")]
        pub scope: i32,
        #[prost(int32, tag = "8")]
        #[serde(with = "crate::common::enums::approval_grade_serde")]
        pub grade: i32,
        #[prost(message, optional, tag = "9")]
        pub issued_at: Option<ProtoTimestamp>,
        #[prost(message, optional, tag = "10")]
        pub expires_at: Option<ProtoTimestamp>,
        #[prost(uint32, optional, tag = "11")]
        pub remaining_uses: Option<u32>,
        #[prost(string, tag = "12")]
        pub signature: String,
    }
}

pub mod inventory_defs {
    use serde::{Deserialize, Serialize};

    use crate::canonical::common_types::ProtoTimestamp;
    use crate::canonical::governance::inventory::{
        DiffState, PinState, diff_state_serde, pin_state_serde,
    };

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct DeclaredToolSpec {
        #[prost(string, tag = "1")]
        pub name: String,
        #[prost(int32, tag = "2")]
        #[serde(with = "crate::common::enums::action_class_serde")]
        pub action_class: i32,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct AgentDeclaration {
        #[prost(string, tag = "1")]
        pub schema: String,
        #[prost(string, tag = "2")]
        pub slug: String,
        #[prost(string, tag = "3")]
        pub sponsor_team: String,
        #[prost(string, tag = "4")]
        pub program_identity: String,
        #[prost(bool, tag = "5")]
        pub session_exclusive: bool,
        #[prost(message, repeated, tag = "6")]
        pub tools: Vec<DeclaredToolSpec>,
        #[prost(string, repeated, tag = "7")]
        pub mcp_servers: Vec<String>,
        #[prost(string, repeated, tag = "8")]
        pub model_endpoints: Vec<String>,
        #[prost(int32, tag = "9")]
        #[serde(with = "crate::canonical::common_types::credential_mode_serde")]
        pub credential_mode: i32,
        #[prost(int32, tag = "10")]
        #[serde(with = "crate::canonical::common_types::identity_proof_serde")]
        pub identity_proof: i32,
    }

    // grdr:allow-s4 prost enum wire tags require i32 fields for DiffState and PinState
    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct DeclaredSourceRow {
        #[prost(string, tag = "1")]
        pub source_name: String,
        #[prost(string, tag = "2")]
        pub identity: String,
        #[prost(enumeration = "DiffState", tag = "3")]
        #[serde(with = "diff_state_serde")]
        pub diff_state: i32,
        #[prost(enumeration = "PinState", optional, tag = "4")]
        #[serde(with = "pin_state_serde::opt")]
        pub pin_state: Option<i32>,
        #[prost(message, optional, tag = "5")]
        pub observed_at: Option<ProtoTimestamp>,
    }
}
