// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Extended canonical message definitions re-exported into `fleet`, `identity`, and `operator`.

pub mod fleet_defs {
    use serde::{Deserialize, Serialize};

    use crate::canonical::common_types::ProtoTimestamp;
    use crate::canonical::fleet_ops::fleet::{CompatRange, ResponseKeyCertificate, Schedule};

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct Handshake {
        #[prost(string, tag = "1")]
        pub sensor_version: String,
        #[prost(message, repeated, tag = "2")]
        pub contracts: Vec<CompatRange>,
        #[prost(int32, tag = "3")]
        #[serde(with = "crate::common::enums::install_profile_serde")]
        pub install_profile: i32,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct CommandEnvelope {
        #[prost(string, tag = "1")]
        pub command_id: String,
        #[prost(int32, tag = "2")]
        #[serde(with = "crate::common::enums::kill_action_serde")]
        pub action: i32,
        #[prost(int32, tag = "3")]
        #[serde(with = "crate::common::enums::kill_scope_serde")]
        pub scope: i32,
        #[prost(message, optional, tag = "4")]
        pub not_after: Option<ProtoTimestamp>,
        #[prost(bytes = "vec", tag = "5")]
        #[serde(with = "crate::serde_proto::bytes_b64_serde")]
        pub payload: Vec<u8>,
        #[prost(bytes = "vec", repeated, tag = "6")]
        #[serde(with = "crate::serde_proto::bytes_b64_serde::vec")]
        pub signatures: Vec<Vec<u8>>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct EnrolRequest {
        #[prost(bytes = "vec", tag = "1")]
        #[serde(with = "crate::serde_proto::bytes_b64_serde")]
        pub enrolment_token: Vec<u8>,
        #[prost(bytes = "vec", tag = "2")]
        #[serde(with = "crate::serde_proto::bytes_b64_serde")]
        pub device_public_key: Vec<u8>,
        #[prost(string, tag = "3")]
        pub key_protection: String,
        #[prost(message, optional, tag = "4")]
        pub handshake: Option<Handshake>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct EnrolResponse {
        #[prost(string, tag = "1")]
        pub device_id: String,
        #[prost(string, tag = "2")]
        pub org_id: String,
        #[prost(string, tag = "3")]
        pub deployment_root_digest: String,
        #[prost(message, optional, tag = "4")]
        pub schedule: Option<Schedule>,
        #[prost(message, optional, tag = "5")]
        pub response_cert: Option<ResponseKeyCertificate>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct CheckInRequest {
        #[prost(string, tag = "1")]
        pub device_id: String,
        #[prost(message, optional, tag = "2")]
        pub handshake: Option<Handshake>,
        #[prost(string, repeated, tag = "3")]
        pub active_bundle_digests: Vec<String>,
        #[prost(string, tag = "4")]
        pub health_summary: String,
        #[prost(message, optional, tag = "5")]
        pub health_at: Option<ProtoTimestamp>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct CheckInResponse {
        #[prost(message, optional, tag = "1")]
        pub schedule: Option<Schedule>,
        #[prost(string, repeated, tag = "2")]
        pub desired_bundle_digests: Vec<String>,
        #[prost(message, repeated, tag = "3")]
        pub pending_commands: Vec<CommandEnvelope>,
        #[prost(message, optional, tag = "4")]
        pub response_cert: Option<ResponseKeyCertificate>,
        #[prost(message, optional, tag = "5")]
        pub server_time: Option<ProtoTimestamp>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct WaitRequest {
        #[prost(string, tag = "1")]
        pub device_id: String,
        #[prost(uint64, tag = "2")]
        pub known_schedule_revision: u64,
    }

    #[derive(Clone, Copy, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct WaitResponse {
        #[prost(bool, tag = "1")]
        pub commands_available: bool,
        #[prost(bool, tag = "2")]
        pub schedule_changed: bool,
        #[prost(message, optional, tag = "3")]
        pub server_time: Option<ProtoTimestamp>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct PendingCommandsRequest {
        #[prost(string, tag = "1")]
        pub device_id: String,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct PendingCommandsResponse {
        #[prost(message, repeated, tag = "1")]
        pub commands: Vec<CommandEnvelope>,
    }
}

pub mod identity_defs {
    use serde::{Deserialize, Serialize};

    use crate::canonical::common_types::ProtoTimestamp;

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct LocalAttestation {
        #[prost(string, tag = "1")]
        pub device_id: String,
        #[prost(string, tag = "2")]
        pub agent_instance_id: String,
        #[prost(int32, repeated, tag = "3")]
        #[serde(with = "crate::common::enums_open::attribution_evidence_kind_serde::vec")]
        pub evidence: Vec<i32>,
        #[prost(int32, tag = "4")]
        #[serde(with = "crate::canonical::common_types::identity_proof_serde")]
        pub proof: i32,
        #[prost(string, tag = "5")]
        pub boot_key_id: String,
        #[prost(string, tag = "6")]
        pub signature: String,
        #[prost(message, optional, tag = "7")]
        pub attested_at: Option<ProtoTimestamp>,
        #[prost(string, optional, tag = "8")]
        pub evidence_other: Option<String>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct Ceiling {
        #[prost(string, tag = "1")]
        pub ceiling_id: String,
        #[prost(string, repeated, tag = "2")]
        pub allowed_credential_classes: Vec<String>,
        #[prost(uint32, tag = "3")]
        pub max_ttl_seconds: u32,
        #[prost(bool, tag = "4")]
        pub requires_containment: bool,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct Correlation {
        #[prost(string, tag = "1")]
        pub session_id: String,
        #[prost(string, tag = "2")]
        pub grade: String,
        #[prost(string, tag = "3")]
        pub external_object_id: String,
        #[prost(string, tag = "4")]
        pub delegator_pseudonym: String,
    }
}

pub mod operator_defs {
    use serde::{Deserialize, Serialize};

    use crate::canonical::common_types::ProtoTimestamp;
    use crate::canonical::fleet_ops::operator::{RuntimeConfigRevision, RuntimeSettingEntry};
    use crate::common::PageInfo;

    // grdr:allow-s4 proto wire contract operator.proto encodes status as string
    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct OperatorTargetHealth {
        #[prost(string, tag = "1")]
        pub target_id: String,
        #[prost(string, tag = "2")]
        pub status: String,
        #[prost(uint32, tag = "3")]
        pub open_breakers: u32,
        #[prost(message, optional, tag = "4")]
        pub checked_at: Option<ProtoTimestamp>,
    }

    // grdr:allow-s4 proto wire contract operator.proto encodes status as string
    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct OrganisationSummary {
        #[prost(string, tag = "1")]
        pub org_id: String,
        #[prost(string, tag = "2")]
        pub status: String,
        #[prost(string, tag = "3")]
        pub home_cell: String,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct OperatorAuditEntry {
        #[prost(string, tag = "1")]
        pub entry_id: String,
        #[prost(string, tag = "2")]
        pub operator_id: String,
        #[prost(string, tag = "3")]
        pub action: String,
        #[prost(string, tag = "4")]
        pub target: String,
        #[prost(string, tag = "5")]
        pub chain_digest: String,
        #[prost(message, optional, tag = "6")]
        pub recorded_at: Option<ProtoTimestamp>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct ListRuntimeRevisionsRequest {
        #[prost(uint32, tag = "1")]
        pub page_size: u32,
        #[prost(string, tag = "2")]
        pub page_token: String,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct ListRuntimeRevisionsResponse {
        #[prost(message, repeated, tag = "1")]
        pub revisions: Vec<RuntimeConfigRevision>,
        #[prost(message, optional, tag = "2")]
        pub page_info: Option<PageInfo>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct StageRuntimeRevisionRequest {
        #[prost(message, repeated, tag = "1")]
        pub settings: Vec<RuntimeSettingEntry>,
        #[prost(bool, tag = "2")]
        pub validate_only: bool,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct StageRuntimeRevisionResponse {
        #[prost(message, optional, tag = "1")]
        pub revision: Option<RuntimeConfigRevision>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct ApplyRuntimeRevisionRequest {
        #[prost(string, tag = "1")]
        pub revision_id: String,
        #[prost(string, tag = "2")]
        pub etag: String,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct ApplyRuntimeRevisionResponse {
        #[prost(message, optional, tag = "1")]
        pub revision: Option<RuntimeConfigRevision>,
    }

    #[derive(Clone, Copy, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct ListTargetHealthRequest {}

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct ListTargetHealthResponse {
        #[prost(message, repeated, tag = "1")]
        pub targets: Vec<OperatorTargetHealth>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct ListOperatorAuditRequest {
        #[prost(uint32, tag = "1")]
        pub page_size: u32,
        #[prost(string, tag = "2")]
        pub page_token: String,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct ListOperatorAuditResponse {
        #[prost(message, repeated, tag = "1")]
        pub entries: Vec<OperatorAuditEntry>,
        #[prost(message, optional, tag = "2")]
        pub page_info: Option<PageInfo>,
    }
}
