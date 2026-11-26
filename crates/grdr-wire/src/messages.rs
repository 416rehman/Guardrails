// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Protobuf message structs for endpoint IPC planes (`grdr.decide.v1alpha1`,
//! `grdr.local.v1alpha1`, `grdr.provider.v1alpha1`).
//!
//! Data-class annotations per `docs/design/02` / `ADR-0007`:
//! - Control headers (`stream_id`, `seq`, `credit_delta`, `epoch`, `pid`): `Operational` / `LogSafe`
//! - Policy outcomes (`verdict`, `rule_id`, `degraded_reason`, `labels`): `Operational` / `LogSafe`
//! - Hook attempt details (`target`, `command_line`, `cwd`, `raw_payload`, `summary`): `Restricted` (never log raw)
//! - Receipt/audit payloads (`authored_records`, `payload`): `Confidential` / `Restricted`

use grdr_fastpath::FastActionClass;
use grdr_model::{ActionClass, ControlPoint};

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum WireControlPoint {
    Unspecified = 0,
    Hook = 1,
    PostHook = 2,
    McpBroker = 3,
    Proxy = 4,
    Sandbox = 5,
    Sensor = 6,
    Browser = 7,
    Gateway = 8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum WireActionClass {
    Unspecified = 0,
    Exec = 1,
    FileRead = 2,
    FileWrite = 3,
    FileDelete = 4,
    NetConnect = 5,
    NetRequest = 6,
    LlmRequest = 7,
    McpConnect = 8,
    McpCall = 9,
    CredUse = 10,
    AgentSpawn = 11,
    ConfigChange = 12,
    Elevate = 13,
    UiAct = 14,
    DataFlow = 15,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum ChannelProfileKind {
    Unspecified = 0,
    Protected = 1,
    User = 2,
    Inherited = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum EndpointServiceKind {
    Unspecified = 0,
    Decide = 1,
    Local = 2,
    ProviderEngine = 3,
    ProviderUplink = 4,
    ProviderUpdater = 5,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum WireVerdict {
    Unspecified = 0,
    Allow = 1,
    Ask = 2,
    Block = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum WireEnforcementMode {
    Unspecified = 0,
    Off = 1,
    Watch = 2,
    Ask = 3,
    Block = 4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum HandoverStage {
    Unspecified = 0,
    Normal = 1,
    Preparing = 2,
    Active = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum LocalCommandKind {
    Unspecified = 0,
    Ping = 1,
    Status = 2,
    Evaluate = 3,
    ListReceipts = 4,
    IssueGrant = 5,
    RevokeGrant = 6,
    SetKillSwitch = 7,
    Reload = 8,
    QueryHistory = 9,
    QuerySpool = 10,
}

#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct HelloFrame {
    #[prost(uint32, tag = "1")]
    pub protocol_version: u32,
    // grdr:allow-s4 prost enum wire representation backed by EndpointServiceKind
    #[prost(enumeration = "EndpointServiceKind", tag = "2")]
    pub service: i32,
    // grdr:allow-s4 prost enum wire representation backed by ChannelProfileKind
    #[prost(enumeration = "ChannelProfileKind", tag = "3")]
    pub profile: i32,
    #[prost(bytes = "vec", tag = "4")]
    pub client_nonce: Vec<u8>,
    #[prost(uint32, tag = "5")]
    pub pid: u32,
    #[prost(string, repeated, tag = "6")]
    pub capabilities: Vec<String>,
}

#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct ReadyFrame {
    #[prost(uint32, tag = "1")]
    pub protocol_version: u32,
    #[prost(uint32, tag = "2")]
    pub initial_credit: u32,
    #[prost(uint32, tag = "3")]
    pub max_frame_bytes: u32,
    #[prost(bytes = "vec", tag = "4")]
    pub server_nonce: Vec<u8>,
    #[prost(string, tag = "5")]
    pub floor_digest: String,
    #[prost(uint64, tag = "6")]
    pub epoch: u64,
    // grdr:allow-s4 prost enum wire representation backed by HandoverStage
    #[prost(enumeration = "HandoverStage", tag = "7")]
    pub handover_stage: i32,
}

#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct HeartbeatFrame {
    #[prost(uint64, tag = "1")]
    pub seq: u64,
    #[prost(uint64, tag = "2")]
    pub monotonic_ms: u64,
    #[prost(uint64, tag = "3")]
    pub rss_bytes: u64,
    #[prost(uint32, tag = "4")]
    pub queue_depth: u32,
    #[prost(uint64, tag = "5")]
    pub epoch: u64,
}

#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct CreditGrantFrame {
    #[prost(uint32, tag = "1")]
    pub delta: u32,
}

#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct DecideRequestFrame {
    #[prost(string, tag = "1")]
    pub request_id: String,
    #[prost(uint64, tag = "2")]
    pub hook_seq: u64,
    #[prost(string, tag = "3")]
    pub agent: String,
    // grdr:allow-s4 prost enum wire representation backed by WireControlPoint
    #[prost(enumeration = "WireControlPoint", tag = "4")]
    pub control_point: i32,
    // grdr:allow-s4 prost enum wire representation backed by WireActionClass
    #[prost(enumeration = "WireActionClass", tag = "5")]
    pub action_class: i32,
    #[prost(string, tag = "6")]
    pub session_id: String,
    /// `Restricted`: untrusted action target (must be redacted before logging/persistence).
    #[prost(string, tag = "7")]
    pub target: String,
    #[prost(string, tag = "8")]
    pub summary: String,
    /// `Restricted`: untrusted shell command line.
    #[prost(string, tag = "9")]
    pub command_line: String,
    /// `Restricted`: caller working directory.
    #[prost(string, tag = "10")]
    pub cwd: String,
    #[prost(string, tag = "11")]
    pub sha256: String,
    #[prost(uint64, tag = "12")]
    pub emitted_mono_ms: u64,
    #[prost(string, tag = "13")]
    pub tool_name: String,
    /// `Restricted`: bounded raw hook stdin payload for daemon-side inspection.
    #[prost(bytes = "vec", tag = "14")]
    pub raw_payload: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct DecideAckFrame {
    #[prost(string, tag = "1")]
    pub request_id: String,
    #[prost(uint64, tag = "2")]
    pub epoch: u64,
    #[prost(uint64, tag = "3")]
    pub accepted_at_mono_ms: u64,
    // grdr:allow-s4 prost enum wire representation backed by HandoverStage
    #[prost(enumeration = "HandoverStage", tag = "4")]
    pub handover_stage: i32,
}

#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct DecideVerdictFrame {
    #[prost(string, tag = "1")]
    pub request_id: String,
    // grdr:allow-s4 prost enum wire representation backed by WireVerdict
    #[prost(enumeration = "WireVerdict", tag = "2")]
    pub verdict: i32,
    #[prost(string, tag = "3")]
    pub receipt_id: String,
    #[prost(string, tag = "4")]
    pub rule_id: String,
    #[prost(string, tag = "5")]
    pub reason: String,
    #[prost(string, tag = "6")]
    pub degraded_reason: String,
    #[prost(bool, tag = "7")]
    pub floor_fallback: bool,
    #[prost(bool, tag = "8")]
    pub audit_fsynced: bool,
    #[prost(string, repeated, tag = "9")]
    pub labels: Vec<String>,
}

#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct LocalRequestFrame {
    #[prost(string, tag = "1")]
    pub request_id: String,
    // grdr:allow-s4 prost enum wire representation backed by LocalCommandKind
    #[prost(enumeration = "LocalCommandKind", tag = "2")]
    pub kind: i32,
    #[prost(string, tag = "3")]
    pub argument: String,
    #[prost(bytes = "vec", tag = "4")]
    pub payload: Vec<u8>,
    #[prost(uint32, tag = "5")]
    pub limit: u32,
}

#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct DaemonHealthSummary {
    #[prost(uint32, tag = "1")]
    pub pid: u32,
    // grdr:allow-s4 prost enum wire representation backed by WireEnforcementMode
    #[prost(enumeration = "WireEnforcementMode", tag = "2")]
    pub enforcement_mode: i32,
    #[prost(string, tag = "3")]
    pub degraded_reason: String,
    #[prost(string, tag = "4")]
    pub floor_digest: String,
    #[prost(bool, tag = "5")]
    pub engine_alive: bool,
    #[prost(bool, tag = "6")]
    pub uplink_alive: bool,
    #[prost(bool, tag = "7")]
    pub updater_alive: bool,
    #[prost(uint64, tag = "8")]
    pub spool_bytes: u64,
    #[prost(uint64, tag = "9")]
    pub gap_count: u64,
    #[prost(uint64, tag = "10")]
    pub rss_bytes: u64,
    #[prost(uint64, tag = "11")]
    pub receipts_total: u64,
}

#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct LocalResponseFrame {
    #[prost(string, tag = "1")]
    pub request_id: String,
    #[prost(bool, tag = "2")]
    pub ok: bool,
    #[prost(string, tag = "3")]
    pub error_code: String,
    #[prost(string, tag = "4")]
    pub message: String,
    #[prost(bytes = "vec", tag = "5")]
    pub payload: Vec<u8>,
    #[prost(message, optional, tag = "6")]
    pub health: Option<DaemonHealthSummary>,
}

#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct EngineForwardFrame {
    #[prost(string, tag = "1")]
    pub request_id: String,
    #[prost(string, tag = "2")]
    pub attempt_id: String,
    #[prost(string, tag = "3")]
    pub agent: String,
    // grdr:allow-s4 prost enum wire representation backed by WireControlPoint
    #[prost(enumeration = "WireControlPoint", tag = "4")]
    pub control_point: i32,
    // grdr:allow-s4 prost enum wire representation backed by WireActionClass
    #[prost(enumeration = "WireActionClass", tag = "5")]
    pub action_class: i32,
    #[prost(string, tag = "6")]
    pub session_id: String,
    /// `Restricted`: untrusted target string.
    #[prost(string, tag = "7")]
    pub target: String,
    #[prost(string, tag = "8")]
    pub summary: String,
    /// `Restricted`: untrusted command line.
    #[prost(string, tag = "9")]
    pub command_line: String,
    #[prost(uint64, tag = "10")]
    pub received_mono_ms: u64,
    #[prost(uint64, tag = "11")]
    pub epoch: u64,
    #[prost(string, tag = "12")]
    pub tool_name: String,
    #[prost(string, tag = "13")]
    pub device_id: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct EngineAuthoredRecord {
    #[prost(string, tag = "1")]
    pub lane: String,
    #[prost(string, tag = "2")]
    pub record_type: String,
    #[prost(string, tag = "3")]
    pub session_id: String,
    /// `Confidential` / `Restricted`: serialized telemetry event.
    #[prost(bytes = "vec", tag = "4")]
    pub payload: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct EngineResultFrame {
    #[prost(string, tag = "1")]
    pub request_id: String,
    #[prost(string, tag = "2")]
    pub attempt_id: String,
    // grdr:allow-s4 prost enum wire representation backed by WireVerdict
    #[prost(enumeration = "WireVerdict", tag = "3")]
    pub verdict: i32,
    #[prost(string, tag = "4")]
    pub rule_id: String,
    #[prost(string, tag = "5")]
    pub reason: String,
    #[prost(string, repeated, tag = "6")]
    pub labels: Vec<String>,
    #[prost(string, repeated, tag = "7")]
    pub obligations: Vec<String>,
    #[prost(message, repeated, tag = "8")]
    pub authored_records: Vec<EngineAuthoredRecord>,
    #[prost(uint64, tag = "9")]
    pub session_step: u64,
    #[prost(string, tag = "10")]
    pub consumed_grant_id: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct BundleLoadFrame {
    #[prost(uint64, tag = "1")]
    pub epoch: u64,
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub pack_blobs: Vec<Vec<u8>>,
    #[prost(bytes = "vec", repeated, tag = "3")]
    pub grant_blobs: Vec<Vec<u8>>,
    #[prost(bool, tag = "4")]
    pub kill_switch_active: bool,
    #[prost(string, tag = "5")]
    pub kill_switch_reason: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct UplinkCommandFrame {
    #[prost(string, tag = "1")]
    pub command_id: String,
    #[prost(string, tag = "2")]
    pub action: String,
    #[prost(string, tag = "3")]
    pub lane: String,
    #[prost(uint64, tag = "4")]
    pub seq_hint: u64,
    #[prost(bytes = "vec", tag = "5")]
    pub payload: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct UplinkEventFrame {
    #[prost(string, tag = "1")]
    pub command_id: String,
    #[prost(string, tag = "2")]
    pub ack_lane: String,
    #[prost(uint64, tag = "3")]
    pub durable_through_seq: u64,
    #[prost(string, tag = "4")]
    pub durable_through_hash: String,
    #[prost(bytes = "vec", tag = "5")]
    pub checkin_blob: Vec<u8>,
    #[prost(string, tag = "6")]
    pub staged_manifest_path: String,
    #[prost(string, tag = "7")]
    pub degraded_reason: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct UpdaterCommandFrame {
    #[prost(string, tag = "1")]
    pub command_id: String,
    #[prost(string, tag = "2")]
    pub action: String,
    #[prost(uint64, tag = "3")]
    pub security_floor: u64,
    #[prost(bytes = "vec", tag = "4")]
    pub payload: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct UpdaterEventFrame {
    #[prost(string, tag = "1")]
    pub command_id: String,
    #[prost(string, tag = "2")]
    pub active_slot: String,
    #[prost(string, tag = "3")]
    pub active_version: String,
    #[prost(uint64, tag = "4")]
    pub security_floor: u64,
    #[prost(bool, tag = "5")]
    pub handover_active: bool,
    #[prost(bool, tag = "6")]
    pub ok: bool,
    #[prost(string, tag = "7")]
    pub error_code: String,
    #[prost(string, tag = "8")]
    pub detail: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct ErrorFrame {
    #[prost(string, tag = "1")]
    pub code: String,
    #[prost(string, tag = "2")]
    pub message: String,
    #[prost(bool, tag = "3")]
    pub retryable: bool,
}

impl WireControlPoint {
    #[must_use]
    pub fn from_wire_i32(raw: i32) -> Option<Self> {
        Self::try_from(raw).ok().filter(|v| *v != Self::Unspecified)
    }

    #[must_use]
    pub const fn to_model(self) -> Option<ControlPoint> {
        match self {
            Self::Unspecified => None,
            Self::Hook | Self::PostHook => Some(ControlPoint::Hook),
            Self::McpBroker => Some(ControlPoint::McpBroker),
            Self::Proxy => Some(ControlPoint::Proxy),
            Self::Sandbox => Some(ControlPoint::Sandbox),
            Self::Sensor => Some(ControlPoint::Sensor),
            Self::Browser => Some(ControlPoint::Browser),
            Self::Gateway => Some(ControlPoint::Gateway),
        }
    }
}

impl WireActionClass {
    #[must_use]
    pub const fn from_fast(cls: FastActionClass) -> Self {
        match cls {
            FastActionClass::Exec => Self::Exec,
            FastActionClass::FileRead => Self::FileRead,
            FastActionClass::FileWrite => Self::FileWrite,
            FastActionClass::FileDelete => Self::FileDelete,
            FastActionClass::NetConnect => Self::NetConnect,
            FastActionClass::NetRequest => Self::NetRequest,
            FastActionClass::LlmRequest => Self::LlmRequest,
            FastActionClass::McpConnect => Self::McpConnect,
            FastActionClass::McpCall => Self::McpCall,
            FastActionClass::CredUse => Self::CredUse,
            FastActionClass::AgentSpawn => Self::AgentSpawn,
            FastActionClass::ConfigChange => Self::ConfigChange,
            FastActionClass::Elevate => Self::Elevate,
            FastActionClass::UiAct => Self::UiAct,
            FastActionClass::DataFlow => Self::DataFlow,
        }
    }

    #[must_use]
    pub const fn to_fast(self) -> Option<FastActionClass> {
        match self {
            Self::Unspecified => None,
            Self::Exec => Some(FastActionClass::Exec),
            Self::FileRead => Some(FastActionClass::FileRead),
            Self::FileWrite => Some(FastActionClass::FileWrite),
            Self::FileDelete => Some(FastActionClass::FileDelete),
            Self::NetConnect => Some(FastActionClass::NetConnect),
            Self::NetRequest => Some(FastActionClass::NetRequest),
            Self::LlmRequest => Some(FastActionClass::LlmRequest),
            Self::McpConnect => Some(FastActionClass::McpConnect),
            Self::McpCall => Some(FastActionClass::McpCall),
            Self::CredUse => Some(FastActionClass::CredUse),
            Self::AgentSpawn => Some(FastActionClass::AgentSpawn),
            Self::ConfigChange => Some(FastActionClass::ConfigChange),
            Self::Elevate => Some(FastActionClass::Elevate),
            Self::UiAct => Some(FastActionClass::UiAct),
            Self::DataFlow => Some(FastActionClass::DataFlow),
        }
    }

    #[must_use]
    pub const fn to_model(self) -> Option<ActionClass> {
        match self {
            Self::Unspecified => None,
            Self::Exec => Some(ActionClass::Exec),
            Self::FileRead => Some(ActionClass::FileRead),
            Self::FileWrite => Some(ActionClass::FileWrite),
            Self::FileDelete => Some(ActionClass::FileDelete),
            Self::NetConnect => Some(ActionClass::NetConnect),
            Self::NetRequest => Some(ActionClass::NetRequest),
            Self::LlmRequest => Some(ActionClass::LlmRequest),
            Self::McpConnect => Some(ActionClass::McpConnect),
            Self::McpCall => Some(ActionClass::McpCall),
            Self::CredUse => Some(ActionClass::CredUse),
            Self::AgentSpawn => Some(ActionClass::AgentSpawn),
            Self::ConfigChange => Some(ActionClass::ConfigChange),
            Self::Elevate => Some(ActionClass::Elevate),
            Self::UiAct => Some(ActionClass::UiAct),
            Self::DataFlow => Some(ActionClass::DataFlow),
        }
    }

    #[must_use]
    pub fn from_wire_i32(raw: i32) -> Option<Self> {
        Self::try_from(raw).ok().filter(|v| *v != Self::Unspecified)
    }
}
