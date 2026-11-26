// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Canonical wire codecs for `local`, `identity`, `ingest`, `fleet`, `bootstrap`, `embed`, and `operator`.

pub mod local {
    use serde::{Deserialize, Serialize};

    use crate::canonical::common_types::{MessageRef, ProtoTimestamp};
    use crate::canonical::governance::assurance::AssuranceRecord;
    use crate::proto_enum_codec;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
    #[repr(i32)]
    pub enum RelayDisposition {
        Unspecified = 0,
        Forward = 1,
        Replace = 2,
        Reply = 3,
        Drop = 4,
    }
    proto_enum_codec!(RelayDisposition, relay_disposition_serde, [
        RelayDisposition::Unspecified => "RELAY_DISPOSITION_UNSPECIFIED",
        RelayDisposition::Forward => "RELAY_DISPOSITION_FORWARD" | "forward",
        RelayDisposition::Replace => "RELAY_DISPOSITION_REPLACE" | "replace",
        RelayDisposition::Reply => "RELAY_DISPOSITION_REPLY" | "reply",
        RelayDisposition::Drop => "RELAY_DISPOSITION_DROP" | "drop",
    ]);

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct HealthCondition {
        #[prost(string, tag = "1")]
        pub code: String,
        #[prost(int32, tag = "2")]
        #[serde(with = "crate::common::enums_ext::finding_severity_serde")]
        pub severity: i32,
        #[prost(message, optional, tag = "3")]
        pub summary: Option<MessageRef>,
        #[prost(message, optional, tag = "4")]
        pub first_seen_at: Option<ProtoTimestamp>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct GetStatusResponse {
        #[prost(string, tag = "1")]
        pub summary_state: String,
        #[prost(bool, tag = "2")]
        pub stale: bool,
        #[prost(int32, tag = "3")]
        #[serde(with = "crate::common::enums::install_profile_serde")]
        pub install_profile: i32,
        #[prost(string, tag = "4")]
        pub daemon_version: String,
        #[prost(message, repeated, tag = "5")]
        pub conditions: Vec<HealthCondition>,
        #[prost(message, repeated, tag = "6")]
        pub assurance_records: Vec<AssuranceRecord>,
    }

    pub use crate::canonical::embed_local::local_defs::*;
}

pub mod identity {
    use serde::{Deserialize, Serialize};

    use crate::canonical::common_types::ProtoTimestamp;
    pub use crate::canonical::fleet_extra::identity_defs::*;

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct ExternalId {
        #[prost(string, tag = "1")]
        pub system: String,
        #[prost(string, tag = "2")]
        pub external_id: String,
        #[prost(string, tag = "3")]
        pub join_method: String,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct AgentIdentity {
        #[prost(string, tag = "1")]
        pub spiffe_id: String,
        #[prost(string, tag = "2")]
        pub agent_instance_id: String,
        #[prost(int32, tag = "3")]
        #[serde(with = "crate::canonical::common_types::identity_proof_serde")]
        pub identity_proof: i32,
        #[prost(message, repeated, tag = "4")]
        pub external_ids: Vec<ExternalId>,
        #[prost(string, optional, tag = "5")]
        pub sponsor: Option<String>,
        #[prost(int32, tag = "6")]
        #[serde(with = "crate::canonical::common_types::agent_lifecycle_serde")]
        pub lifecycle: i32,
        #[prost(int32, tag = "7")]
        #[serde(with = "crate::canonical::common_types::containment_mode_serde")]
        pub containment_mode: i32,
        #[prost(int32, tag = "8")]
        #[serde(with = "crate::canonical::common_types::credential_mode_serde")]
        pub credential_mode: i32,
        #[prost(string, optional, tag = "9")]
        pub ceiling_ref: Option<String>,
    }

    // grdr:allow-s4 prost enum wire tags require i32 fields for CredentialMode
    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct Lease {
        #[prost(string, tag = "1")]
        pub lease_id: String,
        #[prost(string, tag = "2")]
        pub agent_instance_id: String,
        #[prost(string, repeated, tag = "3")]
        pub scope_classes: Vec<String>,
        #[prost(int32, tag = "4")]
        #[serde(with = "crate::canonical::common_types::credential_mode_serde")]
        pub mode: i32,
        #[prost(bool, tag = "5")]
        pub peer_verified: bool,
        #[prost(message, optional, tag = "6")]
        pub issued_at: Option<ProtoTimestamp>,
        #[prost(message, optional, tag = "7")]
        pub expires_at: Option<ProtoTimestamp>,
    }
}

pub mod fleet {
    use serde::{Deserialize, Serialize};

    use crate::canonical::common_types::ProtoTimestamp;

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct CompatRange {
        #[prost(string, tag = "1")]
        pub contract: String,
        #[prost(string, tag = "2")]
        pub min_version: String,
        #[prost(string, tag = "3")]
        pub max_version: String,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct Schedule {
        #[prost(uint64, tag = "1")]
        pub revision: u64,
        #[prost(uint32, tag = "2")]
        pub batch_interval_ms: u32,
        #[prost(uint32, tag = "3")]
        pub checkin_phase_ms: u32,
        #[prost(uint32, tag = "4")]
        pub heartbeat_interval_ms: u32,
        #[prost(uint32, tag = "5")]
        pub poll_interval_ms: u32,
        #[prost(uint32, tag = "6")]
        pub retry_after_ms: u32,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct ResponseKeyCertificate {
        #[prost(string, tag = "1")]
        pub key_id: String,
        #[prost(bytes = "vec", tag = "2")]
        #[serde(with = "crate::serde_proto::bytes_b64_serde")]
        pub public_key: Vec<u8>,
        #[prost(message, optional, tag = "3")]
        pub not_before: Option<ProtoTimestamp>,
        #[prost(message, optional, tag = "4")]
        pub not_after: Option<ProtoTimestamp>,
        #[prost(bytes = "vec", tag = "5")]
        #[serde(with = "crate::serde_proto::bytes_b64_serde")]
        pub fleet_signature: Vec<u8>,
    }

    pub use crate::canonical::fleet_extra::fleet_defs::*;
}

pub mod ingest {
    use serde::{Deserialize, Serialize};

    use crate::canonical::common_types::ProtoTimestamp;
    use crate::canonical::fleet_ops::fleet::Schedule;
    use crate::canonical::telemetry::{event::Event, feed::GapRecord};
    use crate::proto_enum_codec;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
    #[repr(i32)]
    pub enum LaneAckStatus {
        Unspecified = 0,
        Durable = 1,
        Duplicate = 2,
        OutOfOrder = 3,
        Shed = 4,
    }
    proto_enum_codec!(LaneAckStatus, lane_ack_status_serde, [
        LaneAckStatus::Unspecified => "LANE_ACK_STATUS_UNSPECIFIED",
        LaneAckStatus::Durable => "LANE_ACK_STATUS_DURABLE" | "durable",
        LaneAckStatus::Duplicate => "LANE_ACK_STATUS_DUPLICATE" | "duplicate",
        LaneAckStatus::OutOfOrder => "LANE_ACK_STATUS_OUT_OF_ORDER" | "out_of_order",
        LaneAckStatus::Shed => "LANE_ACK_STATUS_SHED" | "shed",
    ]);

    // grdr:allow-s4 prost enum wire tags require i32 fields for LaneAckStatus
    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct LaneAck {
        #[prost(int32, tag = "1")]
        #[serde(with = "crate::canonical::common_types::lane_serde")]
        pub lane: i32,
        #[prost(uint64, tag = "2")]
        pub acked_through: u64,
        #[prost(uint64, tag = "3")]
        pub durable_through: u64,
        #[prost(enumeration = "LaneAckStatus", tag = "4")]
        #[serde(with = "lane_ack_status_serde")]
        pub status: i32,
        #[prost(uint64, tag = "5")]
        pub expected_seq: u64,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct FlowControl {
        #[prost(uint32, tag = "1")]
        pub retry_after_ms: u32,
        #[prost(uint64, tag = "2")]
        pub backfill_credit_bytes: u64,
        #[prost(uint32, tag = "3")]
        pub bulk_sample_permille: u32,
        #[prost(message, optional, tag = "4")]
        pub schedule: Option<Schedule>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct PushBatchRequest {
        #[prost(string, tag = "1")]
        pub device_id: String,
        #[prost(uint64, tag = "2")]
        pub epoch: u64,
        #[prost(int32, tag = "3")]
        #[serde(with = "crate::canonical::common_types::lane_serde")]
        pub lane: i32,
        #[prost(uint64, tag = "4")]
        pub first_seq: u64,
        #[prost(uint64, tag = "5")]
        pub last_seq: u64,
        #[prost(message, repeated, tag = "6")]
        pub events: Vec<Event>,
        #[prost(message, repeated, tag = "7")]
        pub gaps: Vec<GapRecord>,
        #[prost(string, tag = "8")]
        pub head_signature: String,
        #[prost(string, tag = "9")]
        pub signer_key_id: String,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct PushBatchResponse {
        #[prost(message, repeated, tag = "1")]
        pub acks: Vec<LaneAck>,
        #[prost(message, optional, tag = "2")]
        pub flow_control: Option<FlowControl>,
        #[prost(uint64, tag = "3")]
        pub server_epoch: u64,
        #[prost(message, optional, tag = "4")]
        pub server_time: Option<ProtoTimestamp>,
        #[prost(string, tag = "5")]
        pub response_key_id: String,
        #[prost(bytes = "vec", tag = "6")]
        #[serde(with = "crate::serde_proto::bytes_b64_serde")]
        pub response_signature: Vec<u8>,
    }
}

pub mod bootstrap {
    use serde::{Deserialize, Serialize};

    use crate::canonical::common_types::ProtoTimestamp;
    use crate::proto_enum_codec;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
    #[repr(i32)]
    pub enum BootstrapDisposition {
        Unspecified = 0,
        Current = 1,
        UpgradeRequired = 2,
        Decommissioned = 3,
    }
    proto_enum_codec!(BootstrapDisposition, bootstrap_disposition_serde, [
        BootstrapDisposition::Unspecified => "BOOTSTRAP_DISPOSITION_UNSPECIFIED",
        BootstrapDisposition::Current => "BOOTSTRAP_DISPOSITION_CURRENT" | "current",
        BootstrapDisposition::UpgradeRequired => "BOOTSTRAP_DISPOSITION_UPGRADE_REQUIRED" | "upgrade_required",
        BootstrapDisposition::Decommissioned => "BOOTSTRAP_DISPOSITION_DECOMMISSIONED" | "decommissioned",
    ]);

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct HelloRequest {
        #[prost(string, tag = "1")]
        pub client_version: String,
        #[prost(string, tag = "2")]
        pub platform: String,
        #[prost(string, tag = "3")]
        pub arch: String,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct HelloResponse {
        #[prost(enumeration = "BootstrapDisposition", tag = "1")]
        #[serde(with = "bootstrap_disposition_serde")]
        pub disposition: i32,
        #[prost(string, tag = "2")]
        pub target_path: String,
        #[prost(message, optional, tag = "3")]
        pub not_before: Option<ProtoTimestamp>,
        #[prost(uint32, tag = "4")]
        pub retry_after_ms: u32,
        #[prost(string, tag = "5")]
        pub min_version: String,
    }
}

pub mod embed {
    use serde::{Deserialize, Serialize};

    use crate::canonical::common_types::ProtoTimestamp;
    use crate::canonical::telemetry::event::Event;
    use crate::proto_enum_codec;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
    #[repr(i32)]
    pub enum DiagnosticSeverity {
        Unspecified = 0,
        Info = 1,
        Warn = 2,
        Error = 3,
    }
    proto_enum_codec!(DiagnosticSeverity, diagnostic_severity_serde, [
        DiagnosticSeverity::Unspecified => "SEVERITY_UNSPECIFIED",
        DiagnosticSeverity::Info => "SEVERITY_INFO" | "info",
        DiagnosticSeverity::Warn => "SEVERITY_WARN" | "warn",
        DiagnosticSeverity::Error => "SEVERITY_ERROR" | "error",
    ]);

    #[derive(Clone, Copy, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct Tick {
        #[prost(message, optional, tag = "1")]
        pub now: Option<ProtoTimestamp>,
    }

    // grdr:allow-s4 prost enum wire tags require i32 fields for DiagnosticSeverity
    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct Diagnostic {
        #[prost(string, tag = "1")]
        pub code: String,
        #[prost(enumeration = "DiagnosticSeverity", tag = "2")]
        #[serde(with = "diagnostic_severity_serde")]
        pub severity: i32,
        #[prost(string, optional, tag = "3")]
        pub rule_id: Option<String>,
        #[prost(string, tag = "4")]
        pub message: String,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct Effect {
        #[prost(string, tag = "1")]
        pub effect_kind: String,
        #[prost(string, tag = "2")]
        pub target_ref: String,
        #[prost(string, tag = "3")]
        pub rule_id: String,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct HostProfile {
        #[prost(string, tag = "1")]
        pub host_id: String,
        #[prost(string, tag = "2")]
        pub host_version: String,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct Output {
        #[prost(uint64, tag = "1")]
        pub step_seq: u64,
        #[prost(string, tag = "2")]
        pub step_id: String,
        #[prost(message, repeated, tag = "3")]
        pub events: Vec<Event>,
        #[prost(message, repeated, tag = "4")]
        pub effects: Vec<Effect>,
        #[prost(message, repeated, tag = "5")]
        pub diagnostics: Vec<Diagnostic>,
    }

    pub use crate::canonical::embed_local::embed_defs::*;
}

pub mod operator {
    use serde::{Deserialize, Serialize};

    use crate::canonical::common_types::ProtoTimestamp;
    use crate::proto_enum_codec;

    pub use crate::canonical::fleet_extra::operator_defs::*;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
    #[repr(i32)]
    pub enum RuntimeConfigState {
        Unspecified = 0,
        Draft = 1,
        Validated = 2,
        Applying = 3,
        Applied = 4,
        RolledBack = 5,
        Superseded = 6,
        Discarded = 7,
    }
    proto_enum_codec!(RuntimeConfigState, runtime_config_state_serde, [
        RuntimeConfigState::Unspecified => "RUNTIME_CONFIG_STATE_UNSPECIFIED",
        RuntimeConfigState::Draft => "RUNTIME_CONFIG_STATE_DRAFT" | "draft",
        RuntimeConfigState::Validated => "RUNTIME_CONFIG_STATE_VALIDATED" | "validated",
        RuntimeConfigState::Applying => "RUNTIME_CONFIG_STATE_APPLYING" | "applying",
        RuntimeConfigState::Applied => "RUNTIME_CONFIG_STATE_APPLIED" | "applied",
        RuntimeConfigState::RolledBack => "RUNTIME_CONFIG_STATE_ROLLED_BACK" | "rolled_back",
        RuntimeConfigState::Superseded => "RUNTIME_CONFIG_STATE_SUPERSEDED" | "superseded",
        RuntimeConfigState::Discarded => "RUNTIME_CONFIG_STATE_DISCARDED" | "discarded",
    ]);

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct RuntimeSettingEntry {
        #[prost(string, tag = "1")]
        pub key: String,
        #[prost(string, tag = "2")]
        pub value: String,
        #[prost(bool, tag = "3")]
        pub source_locked: bool,
        #[prost(bool, tag = "4")]
        pub security_sensitive: bool,
    }

    // grdr:allow-s4 prost enum wire tags require i32 fields for RuntimeConfigState
    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct RuntimeConfigRevision {
        #[prost(string, tag = "1")]
        pub revision_id: String,
        #[prost(uint64, tag = "2")]
        pub version: u64,
        #[prost(enumeration = "RuntimeConfigState", tag = "3")]
        #[serde(with = "runtime_config_state_serde")]
        pub state: i32,
        #[prost(message, repeated, tag = "4")]
        pub settings: Vec<RuntimeSettingEntry>,
        #[prost(string, tag = "5")]
        pub author: String,
        #[prost(message, optional, tag = "6")]
        pub created_at: Option<ProtoTimestamp>,
    }
}

#[cfg(test)]
mod tests {
    use super::embed::Diagnostic;

    #[test]
    fn diagnostic_severity_serde_matches_proto() {
        let diag: Diagnostic = serde_json::from_str(
            r#"{"code":"E01","message":"bad","severity":"SEVERITY_ERROR","ruleId":"r1"}"#,
        )
        .unwrap();
        assert_eq!(diag.severity, 3);
        let j = serde_json::to_string(&diag).unwrap();
        assert!(j.contains("SEVERITY_ERROR"));
        let alias: Diagnostic =
            serde_json::from_str(r#"{"code":"E01","message":"bad","severity":"warn"}"#).unwrap();
        assert_eq!(alias.severity, 2);
        assert!(serde_json::from_str::<Diagnostic>(r#"{"severity":"BOGUS"}"#).is_err());
    }
}
