// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Canonical `grdr.common.v1alpha1` shared wire enums, timestamp/duration twins, and common messages.

use serde::{Deserialize, Serialize};

use crate::proto_enum_codec;

#[derive(Clone, Copy, PartialEq, Eq, prost::Message)]
pub struct ProtoTimestamp {
    #[prost(int64, tag = "1")]
    pub seconds: i64,
    #[prost(int32, tag = "2")]
    pub nanos: i32,
}

#[derive(Clone, Copy, PartialEq, Eq, prost::Message)]
pub struct ProtoDuration {
    #[prost(int64, tag = "1")]
    pub seconds: i64,
    #[prost(int32, tag = "2")]
    pub nanos: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum Lane {
    Unspecified = 0,
    Decision = 1,
    Spine = 2,
    Bulk = 3,
    Evidence = 4,
    Local = 5,
}
proto_enum_codec!(Lane, lane_serde, [
    Lane::Unspecified => "LANE_UNSPECIFIED",
    Lane::Decision => "LANE_DECISION" | "decision",
    Lane::Spine => "LANE_SPINE" | "spine",
    Lane::Bulk => "LANE_BULK" | "bulk",
    Lane::Evidence => "LANE_EVIDENCE" | "evidence",
    Lane::Local => "LANE_LOCAL" | "local",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum CaptureLevel {
    Unspecified = 0,
    Metadata = 1,
    RedactedArguments = 2,
    RedactedContent = 3,
    FullContent = 4,
}
proto_enum_codec!(CaptureLevel, capture_level_serde, [
    CaptureLevel::Unspecified => "CAPTURE_LEVEL_UNSPECIFIED",
    CaptureLevel::Metadata => "CAPTURE_LEVEL_METADATA" | "metadata",
    CaptureLevel::RedactedArguments => "CAPTURE_LEVEL_REDACTED_ARGUMENTS" | "redacted_arguments",
    CaptureLevel::RedactedContent => "CAPTURE_LEVEL_REDACTED_CONTENT" | "redacted_content",
    CaptureLevel::FullContent => "CAPTURE_LEVEL_FULL_CONTENT" | "full_content",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum ActorKind {
    Unspecified = 0,
    Human = 1,
    Agent = 2,
    System = 3,
    External = 4,
    Undetermined = 5,
}
proto_enum_codec!(ActorKind, actor_kind_serde, [
    ActorKind::Unspecified => "ACTOR_KIND_UNSPECIFIED",
    ActorKind::Human => "ACTOR_KIND_HUMAN" | "human",
    ActorKind::Agent => "ACTOR_KIND_AGENT" | "agent",
    ActorKind::System => "ACTOR_KIND_SYSTEM" | "system",
    ActorKind::External => "ACTOR_KIND_EXTERNAL" | "external",
    ActorKind::Undetermined => "ACTOR_KIND_UNDETERMINED" | "undetermined",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum ActionPhase {
    Unspecified = 0,
    Intent = 1,
    Outcome = 2,
}
proto_enum_codec!(ActionPhase, action_phase_serde, [
    ActionPhase::Unspecified => "ACTION_PHASE_UNSPECIFIED",
    ActionPhase::Intent => "ACTION_PHASE_INTENT" | "intent",
    ActionPhase::Outcome => "ACTION_PHASE_OUTCOME" | "outcome",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum ActionOutcome {
    Unspecified = 0,
    Attempted = 1,
    Completed = 2,
    Denied = 3,
    Failed = 4,
    Unknown = 5,
}
proto_enum_codec!(ActionOutcome, action_outcome_serde, [
    ActionOutcome::Unspecified => "ACTION_OUTCOME_UNSPECIFIED",
    ActionOutcome::Attempted => "ACTION_OUTCOME_ATTEMPTED" | "attempted",
    ActionOutcome::Completed => "ACTION_OUTCOME_COMPLETED" | "completed",
    ActionOutcome::Denied => "ACTION_OUTCOME_DENIED" | "denied",
    ActionOutcome::Failed => "ACTION_OUTCOME_FAILED" | "failed",
    ActionOutcome::Unknown => "ACTION_OUTCOME_UNKNOWN" | "unknown",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum ResolutionKind {
    Unspecified = 0,
    Resolved = 1,
    Undetermined = 2,
    Unresolved = 3,
}
proto_enum_codec!(ResolutionKind, resolution_kind_serde, [
    ResolutionKind::Unspecified => "RESOLUTION_KIND_UNSPECIFIED",
    ResolutionKind::Resolved => "RESOLUTION_KIND_RESOLVED" | "resolved",
    ResolutionKind::Undetermined => "RESOLUTION_KIND_UNDETERMINED" | "undetermined",
    ResolutionKind::Unresolved => "RESOLUTION_KIND_UNRESOLVED" | "unresolved",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum IdentityProof {
    Unspecified = 0,
    Observed = 1,
    SelfAsserted = 2,
    IdpIssued = 3,
    Attested = 4,
}
proto_enum_codec!(IdentityProof, identity_proof_serde, [
    IdentityProof::Unspecified => "IDENTITY_PROOF_UNSPECIFIED",
    IdentityProof::Observed => "IDENTITY_PROOF_OBSERVED" | "observed",
    IdentityProof::SelfAsserted => "IDENTITY_PROOF_SELF_ASSERTED" | "self_asserted",
    IdentityProof::IdpIssued => "IDENTITY_PROOF_IDP_ISSUED" | "idp_issued",
    IdentityProof::Attested => "IDENTITY_PROOF_ATTESTED" | "attested",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum ProvenanceKind {
    Unspecified = 0,
    Observed = 1,
    Claimed = 2,
    Inferred = 3,
    Derived = 4,
}
proto_enum_codec!(ProvenanceKind, provenance_kind_serde, [
    ProvenanceKind::Unspecified => "PROVENANCE_KIND_UNSPECIFIED",
    ProvenanceKind::Observed => "PROVENANCE_KIND_OBSERVED" | "observed",
    ProvenanceKind::Claimed => "PROVENANCE_KIND_CLAIMED" | "claimed",
    ProvenanceKind::Inferred => "PROVENANCE_KIND_INFERRED" | "inferred",
    ProvenanceKind::Derived => "PROVENANCE_KIND_DERIVED" | "derived",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum PathClass {
    Unspecified = 0,
    Workspace = 1,
    Home = 2,
    System = 3,
    Temp = 4,
    Sensitive = 5,
    External = 6,
}
proto_enum_codec!(PathClass, path_class_serde, [
    PathClass::Unspecified => "PATH_CLASS_UNSPECIFIED",
    PathClass::Workspace => "PATH_CLASS_WORKSPACE" | "workspace",
    PathClass::Home => "PATH_CLASS_HOME" | "home",
    PathClass::System => "PATH_CLASS_SYSTEM" | "system",
    PathClass::Temp => "PATH_CLASS_TEMP" | "temp",
    PathClass::Sensitive => "PATH_CLASS_SENSITIVE" | "sensitive",
    PathClass::External => "PATH_CLASS_EXTERNAL" | "external",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum FactOrigin {
    Unspecified = 0,
    Deterministic = 1,
    Heuristic = 2,
    Model = 3,
}
proto_enum_codec!(FactOrigin, fact_origin_serde, [
    FactOrigin::Unspecified => "FACT_ORIGIN_UNSPECIFIED",
    FactOrigin::Deterministic => "FACT_ORIGIN_DETERMINISTIC" | "deterministic",
    FactOrigin::Heuristic => "FACT_ORIGIN_HEURISTIC" | "heuristic",
    FactOrigin::Model => "FACT_ORIGIN_MODEL" | "model",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum AgentLifecycle {
    Unspecified = 0,
    Discovered = 1,
    Active = 2,
    Suspended = 3,
    Retired = 4,
}
proto_enum_codec!(AgentLifecycle, agent_lifecycle_serde, [
    AgentLifecycle::Unspecified => "AGENT_LIFECYCLE_UNSPECIFIED",
    AgentLifecycle::Discovered => "AGENT_LIFECYCLE_DISCOVERED" | "discovered",
    AgentLifecycle::Active => "AGENT_LIFECYCLE_ACTIVE" | "active",
    AgentLifecycle::Suspended => "AGENT_LIFECYCLE_SUSPENDED" | "suspended",
    AgentLifecycle::Retired => "AGENT_LIFECYCLE_RETIRED" | "retired",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum ContainmentMode {
    Unspecified = 0,
    None = 1,
    Delegate = 2,
    WrapTools = 3,
    WrapAgent = 4,
}
proto_enum_codec!(ContainmentMode, containment_mode_serde, [
    ContainmentMode::Unspecified => "CONTAINMENT_MODE_UNSPECIFIED",
    ContainmentMode::None => "CONTAINMENT_MODE_NONE" | "none",
    ContainmentMode::Delegate => "CONTAINMENT_MODE_DELEGATE" | "delegate",
    ContainmentMode::WrapTools => "CONTAINMENT_MODE_WRAP_TOOLS" | "wrap_tools",
    ContainmentMode::WrapAgent => "CONTAINMENT_MODE_WRAP_AGENT" | "wrap_agent",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum CredentialMode {
    Unspecified = 0,
    VendorLogin = 1,
    Gateway = 2,
    KeyHelper = 3,
    Federated = 4,
}
proto_enum_codec!(CredentialMode, credential_mode_serde, [
    CredentialMode::Unspecified => "CREDENTIAL_MODE_UNSPECIFIED",
    CredentialMode::VendorLogin => "CREDENTIAL_MODE_VENDOR_LOGIN" | "vendor_login",
    CredentialMode::Gateway => "CREDENTIAL_MODE_GATEWAY" | "gateway",
    CredentialMode::KeyHelper => "CREDENTIAL_MODE_KEY_HELPER" | "key_helper",
    CredentialMode::Federated => "CREDENTIAL_MODE_FEDERATED" | "federated",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum GapReason {
    Unspecified = 0,
    SpoolShedding = 1,
    RecorderExpired = 2,
    CollectorLoss = 3,
    ClockJump = 4,
    Other = 99,
}
proto_enum_codec!(GapReason, gap_reason_serde, [
    GapReason::Unspecified => "GAP_REASON_UNSPECIFIED",
    GapReason::SpoolShedding => "GAP_REASON_SPOOL_SHEDDING" | "spool_shedding",
    GapReason::RecorderExpired => "GAP_REASON_RECORDER_EXPIRED" | "recorder_expired",
    GapReason::CollectorLoss => "GAP_REASON_COLLECTOR_LOSS" | "collector_loss",
    GapReason::ClockJump => "GAP_REASON_CLOCK_JUMP" | "clock_jump",
    GapReason::Other => "GAP_REASON_OTHER" | "other",
]);

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Digest {
    #[prost(int32, tag = "1")]
    #[serde(with = "crate::common::enums_open::hash_algorithm_serde")]
    pub algorithm: i32,
    #[prost(string, optional, tag = "2")]
    pub algorithm_other: Option<String>,
    #[prost(bytes = "vec", tag = "3")]
    #[serde(with = "crate::serde_proto::bytes_b64_serde")]
    pub value: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TraceContext {
    #[prost(string, tag = "1")]
    pub trace_id: String,
    #[prost(string, tag = "2")]
    pub span_id: String,
    #[prost(string, optional, tag = "3")]
    pub parent_span_id: Option<String>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PathRef {
    #[prost(enumeration = "PathClass", tag = "1")]
    #[serde(with = "path_class_serde")]
    pub path_class: i32,
    #[prost(string, tag = "2")]
    pub prefix_template: String,
    #[prost(string, tag = "3")]
    pub path_digest: String,
    #[prost(string, optional, tag = "4")]
    pub display_path: Option<String>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ExecutableRef {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(string, tag = "2")]
    pub identity: String,
    #[prost(string, optional, tag = "3")]
    pub signer: Option<String>,
    #[prost(string, optional, tag = "4")]
    pub executable_path: Option<String>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TargetRef {
    #[prost(string, tag = "1")]
    pub target_digest: String,
    #[prost(string, tag = "2")]
    pub classification: String,
    #[prost(string, optional, tag = "3")]
    pub value: Option<String>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Redaction {
    #[prost(string, repeated, tag = "1")]
    pub withheld_classes: Vec<String>,
    #[prost(string, repeated, tag = "2")]
    pub withheld_fields: Vec<String>,
    #[prost(string, tag = "3")]
    pub reason: String,
    #[prost(string, tag = "4")]
    pub capture_level: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Sealed {
    #[prost(string, tag = "1")]
    pub recipient_key_id: String,
    #[prost(string, tag = "2")]
    pub enc: String,
    #[prost(bytes = "vec", tag = "3")]
    #[serde(with = "crate::serde_proto::bytes_b64_serde")]
    pub ciphertext: Vec<u8>,
    #[prost(enumeration = "crate::common::DataClass", tag = "4")]
    #[serde(with = "crate::common::types::data_class_serde")]
    pub inner_class: i32,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DecimalInput {
    #[prost(string, tag = "1")]
    pub raw: String,
    #[prost(uint32, tag = "2")]
    pub scale: u32,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct MessageArg {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(enumeration = "crate::common::DataClass", tag = "2")]
    #[serde(with = "crate::common::types::data_class_serde")]
    pub value_class: i32,
    #[prost(oneof = "message_arg::Value", tags = "3, 4, 5, 6, 7, 8, 9")]
    #[serde(flatten)]
    pub value: Option<message_arg::Value>,
}

pub mod message_arg {
    use super::*;

    #[derive(Clone, PartialEq, Eq, prost::Oneof, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub enum Value {
        #[prost(string, tag = "3")]
        TextStructural(String),
        #[prost(string, tag = "4")]
        TextIdentifier(String),
        #[prost(string, tag = "5")]
        TextContent(String),
        #[prost(int64, tag = "6")]
        Integer(i64),
        #[prost(message, tag = "7")]
        Decimal(DecimalInput),
        #[prost(message, tag = "8")]
        Timestamp(ProtoTimestamp),
        #[prost(message, tag = "9")]
        Duration(ProtoDuration),
    }
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct MessageRef {
    #[prost(string, tag = "1")]
    pub token_id: String,
    #[prost(message, repeated, tag = "2")]
    pub args: Vec<MessageArg>,
    #[prost(string, tag = "3")]
    pub source_hash: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ClockReading {
    #[prost(message, optional, tag = "1")]
    pub observed_at: Option<ProtoTimestamp>,
    #[prost(uint64, tag = "2")]
    pub monotonic_ns: u64,
    #[prost(uint64, tag = "3")]
    pub epoch: u64,
}
