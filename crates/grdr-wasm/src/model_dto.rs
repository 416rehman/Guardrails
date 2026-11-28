// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use grdr_fastpath::{FastActionClass, FastVerdict};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

pub const CODE_INVALID_INPUT: &str = "GRDR-MODEL-0001";
pub const EMBEDDED_ESSENTIALS_JSON: &str = include_str!("../manifests/essentials-pack.json");

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WasmMode {
    Off,
    Watch,
    Ask,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WasmVerdict {
    Allow,
    Modify,
    StepUp,
    Defer,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum WasmApprovalGrade {
    G0,
    G1,
    G2,
    G3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WasmGrantScope {
    Once,
    Session,
    OneHour,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WasmKillScope {
    Session,
    Device,
    Organisation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum WasmKillSwitchState {
    Inactive,
    Frozen {
        scope: WasmKillScope,
        target_id: String,
        reason: String,
        issued_at: Timestamp,
        expires_at: Timestamp,
    },
    Killed {
        scope: WasmKillScope,
        target_id: String,
        reason: String,
        issued_at: Timestamp,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WasmActionClass {
    Exec,
    #[serde(rename = "file.read")]
    FileRead,
    #[serde(rename = "file.write")]
    FileWrite,
    #[serde(rename = "file.delete")]
    FileDelete,
    #[serde(rename = "net.connect")]
    NetConnect,
    #[serde(rename = "net.request")]
    NetRequest,
    #[serde(rename = "llm.request")]
    LlmRequest,
    #[serde(rename = "mcp.connect")]
    McpConnect,
    #[serde(rename = "mcp.call")]
    McpCall,
    #[serde(rename = "cred.use")]
    CredUse,
    #[serde(rename = "agent.spawn")]
    AgentSpawn,
    #[serde(rename = "config.change")]
    ConfigChange,
    Elevate,
    #[serde(rename = "ui.act")]
    UiAct,
    #[serde(rename = "data.flow")]
    DataFlow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WasmControlPoint {
    #[default]
    Hook,
    McpBroker,
    Proxy,
    Sandbox,
    Sensor,
    Browser,
    Gateway,
    Connector,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WasmSpanKind {
    InvokeAgent,
    Chat,
    #[default]
    ExecuteTool,
    McpCall,
    OsEffect,
    SubagentSpawn,
    Compaction,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WasmProvenanceSource {
    Claimed,
    #[default]
    Observed,
    Mediated,
    Reconciled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmSecondaryAction {
    pub command: String,
    pub action_class: WasmActionClass,
    pub target: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmRuleMatch {
    pub action_classes: Vec<WasmActionClass>,
    pub target_prefixes: Vec<String>,
    pub target_contains: Vec<String>,
    pub agents: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmPolicyRule {
    pub id: String,
    pub title: String,
    pub description: String,
    pub mode: WasmMode,
    pub min_grade: WasmApprovalGrade,
    pub enabled: bool,
    pub locked: bool,
    pub matcher: WasmRuleMatch,
    pub hits: u64,
    pub would_ask_hits: u64,
    pub would_block_hits: u64,
    pub reason_template: String,
    #[serde(default)]
    pub cedar: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmPolicyPack {
    pub id: String,
    pub name: String,
    pub description: String,
    pub version: String,
    pub channel: String,
    pub rules: Vec<WasmPolicyRule>,
    #[serde(default)]
    pub key_id: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmActionAttempt {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub device_id: String,
    #[serde(default)]
    pub device_name: String,
    pub agent_name: String,
    pub action_class: WasmActionClass,
    #[serde(default)]
    pub control_point: WasmControlPoint,
    pub target: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default = "default_timestamp")]
    pub timestamp: Timestamp,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub user_display: Option<String>,
    #[serde(default = "default_turn_index")]
    pub turn_index: u32,
    #[serde(default)]
    pub span_id: Option<String>,
    #[serde(default)]
    pub parent_span_id: Option<String>,
    #[serde(default)]
    pub span_kind: WasmSpanKind,
    #[serde(default)]
    pub duration_ms: u64,
    #[serde(default)]
    pub provenance: WasmProvenanceSource,
    #[serde(default)]
    pub secondary_actions: Vec<WasmSecondaryAction>,
    #[serde(default)]
    pub skill_used: Option<String>,
    #[serde(default)]
    pub compaction: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmDecisionReceipt {
    pub receipt_id: String,
    pub attempt_id: String,
    pub session_id: String,
    pub device_id: String,
    pub agent_name: String,
    pub action_class: WasmActionClass,
    pub control_point: WasmControlPoint,
    pub target: String,
    pub verdict: WasmVerdict,
    pub would_be: Option<WasmVerdict>,
    pub rule_id: Option<String>,
    pub pack_id: Option<String>,
    pub mode_applied: Option<WasmMode>,
    pub grant_id: Option<String>,
    pub reason: String,
    pub next_step: String,
    pub receipt_digest: String,
    pub decided_at: Timestamp,
    #[serde(default)]
    pub key_id: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub signature_verified: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmGrant {
    pub grant_id: String,
    pub rule_id: String,
    pub session_id: String,
    pub device_id: String,
    pub action_class: WasmActionClass,
    pub target_pattern: String,
    pub scope: WasmGrantScope,
    pub grade: WasmApprovalGrade,
    pub granted_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub remaining_uses: Option<u32>,
    pub note: String,
    #[serde(default)]
    pub key_id: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmCompiledFloorRule {
    pub rule_id: String,
    pub action_classes: Vec<WasmActionClass>,
    pub target_prefixes: Vec<String>,
    pub target_contains: Vec<String>,
    pub agents: Vec<String>,
    pub verdict: WasmVerdict,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmCompiledFloorTable {
    pub version: u32,
    pub compiled_at: Timestamp,
    pub rules: Vec<WasmCompiledFloorRule>,
    #[serde(default)]
    pub key_id: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmReplaySample {
    pub attempt_id: String,
    pub session_id: String,
    pub agent_name: String,
    pub action_class: WasmActionClass,
    pub target: String,
    pub current_verdict: WasmVerdict,
    pub candidate_verdict: WasmVerdict,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmReplaySummary {
    pub rule_id: String,
    pub candidate_mode: WasmMode,
    pub window_label: String,
    pub total_scanned: u64,
    pub matched: u64,
    pub would_ask: u64,
    pub would_block: u64,
    pub not_matched: u64,
    pub samples: Vec<WasmReplaySample>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmCodedError {
    pub code: String,
    pub message: String,
    pub next_step: String,
}

impl WasmActionClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exec => "exec",
            Self::FileRead => "file.read",
            Self::FileWrite => "file.write",
            Self::FileDelete => "file.delete",
            Self::NetConnect => "net.connect",
            Self::NetRequest => "net.request",
            Self::LlmRequest => "llm.request",
            Self::McpConnect => "mcp.connect",
            Self::McpCall => "mcp.call",
            Self::CredUse => "cred.use",
            Self::AgentSpawn => "agent.spawn",
            Self::ConfigChange => "config.change",
            Self::Elevate => "elevate",
            Self::UiAct => "ui.act",
            Self::DataFlow => "data.flow",
        }
    }

    pub const fn to_fast(self) -> FastActionClass {
        match self {
            Self::Exec => FastActionClass::Exec,
            Self::FileRead => FastActionClass::FileRead,
            Self::FileWrite => FastActionClass::FileWrite,
            Self::FileDelete => FastActionClass::FileDelete,
            Self::NetConnect => FastActionClass::NetConnect,
            Self::NetRequest => FastActionClass::NetRequest,
            Self::LlmRequest => FastActionClass::LlmRequest,
            Self::McpConnect => FastActionClass::McpConnect,
            Self::McpCall => FastActionClass::McpCall,
            Self::CredUse => FastActionClass::CredUse,
            Self::AgentSpawn => FastActionClass::AgentSpawn,
            Self::ConfigChange => FastActionClass::ConfigChange,
            Self::Elevate => FastActionClass::Elevate,
            Self::UiAct => FastActionClass::UiAct,
            Self::DataFlow => FastActionClass::DataFlow,
        }
    }
}

impl WasmVerdict {
    pub const fn to_fast(self) -> FastVerdict {
        match self {
            Self::Allow | Self::Modify => FastVerdict::Allow,
            Self::StepUp | Self::Defer => FastVerdict::StepUp,
            Self::Deny => FastVerdict::Deny,
        }
    }

    pub const fn from_fast(v: FastVerdict) -> Self {
        match v {
            FastVerdict::Allow => Self::Allow,
            FastVerdict::StepUp => Self::StepUp,
            FastVerdict::Deny => Self::Deny,
        }
    }
}

impl WasmCodedError {
    pub fn new(
        code: impl Into<String>,
        message: impl Into<String>,
        next_step: impl Into<String>,
    ) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            next_step: next_step.into(),
        }
    }

    pub fn invalid_input(message: impl Into<String>, next_step: impl Into<String>) -> Self {
        Self::new(CODE_INVALID_INPUT, message, next_step)
    }
}

impl Default for WasmActionAttempt {
    fn default() -> Self {
        Self {
            id: String::new(),
            session_id: String::new(),
            device_id: String::new(),
            device_name: String::new(),
            agent_name: String::new(),
            action_class: WasmActionClass::Exec,
            control_point: WasmControlPoint::Hook,
            target: String::new(),
            summary: String::new(),
            timestamp: Timestamp::UNIX_EPOCH,
            user_id: None,
            user_display: None,
            turn_index: default_turn_index(),
            span_id: None,
            parent_span_id: None,
            span_kind: WasmSpanKind::default(),
            duration_ms: 0,
            provenance: WasmProvenanceSource::default(),
            secondary_actions: Vec::new(),
            skill_used: None,
            compaction: false,
        }
    }
}

fn default_turn_index() -> u32 {
    1
}

fn default_timestamp() -> Timestamp {
    Timestamp::UNIX_EPOCH
}
