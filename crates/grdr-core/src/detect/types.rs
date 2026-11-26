// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Core types, bounds, AST condition nodes, and trait contracts for the Sigma detection engine (`D-09`, `D-54`).

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use grdr_model::{ActionClass, CodedError, Finding, FindingClass, FindingSeverity, Mode};

pub const CODE_DETECT_INVALID_RULE: &str = "GRDR-DETECT-0001";
pub const CODE_DETECT_DUPLICATE_RULE: &str = "GRDR-DETECT-0002";
pub const CODE_DETECT_STATE_RESTORE: &str = "GRDR-DETECT-0003";
pub const CODE_DETECT_CONFIG_TAMPER: &str = "GRDR-DETECT-0004";
pub const CODE_DETECT_RESPONSE_BREAKER: &str = "GRDR-DETECT-0005";
pub const CODE_DETECT_L0_UNSUPPORTED: &str = "GRDR-DETECT-0006";

pub const MAX_CORRELATION_ENTRIES_PER_LINEAGE: usize = 4_096;
pub const MAX_GROUP_KEYS_PER_RULE: usize = 256;
pub const MAX_GROUP_KEYS_PER_LINEAGE: usize = 256;
pub const MAX_CONDITION_DEPTH: usize = 32;
pub const MAX_ENGINE_LINEAGES: usize = 4_096;
pub const MAX_ENGINE_DEDUP_KEYS: usize = 16_384;
pub const MAX_PROBE_BUCKETS: usize = 4_096;
pub const DEFAULT_DETECT_LAG_BACKLOG_EVENTS: usize = 10_000;
pub const DEFAULT_DETECT_LAG_MS: i64 = 2_000;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DetectError {
    #[error("GRDR-DETECT-0001: invalid Sigma/YAML detection rule: {0}")]
    InvalidRule(String),
    #[error("GRDR-DETECT-0002: duplicate rule id `{0}`")]
    DuplicateRule(String),
    #[error("GRDR-DETECT-0003: corrupt detection engine snapshot: {0}")]
    StateRestore(String),
    #[error("GRDR-DETECT-0004: configuration integrity baseline failure: {0}")]
    ConfigTamper(String),
    #[error("GRDR-DETECT-0005: response action circuit breaker or validation error: {0}")]
    ResponseBreaker(String),
    #[error("GRDR-DETECT-0006: L0 compilation unsupported for target: {0}")]
    L0Unsupported(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigmaStatus {
    Experimental,
    Test,
    Stable,
    Deprecated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleOrigin {
    Official,
    Community,
    Organisation,
    Project,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingCeiling {
    Record,
    Notify,
    Contain,
    Remediate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseExecutionMode {
    Simulate,
    Live,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationKind {
    EventCount,
    ValueCount,
    Temporal,
    TemporalOrdered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigmaModifier {
    Exact,
    Contains,
    StartsWith,
    EndsWith,
    Re,
    Cidr,
    Exists,
    Expand,
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentScope {
    Device,
    Server,
    Any,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConditionExpr {
    Sel(String),
    Not(Box<ConditionExpr>),
    And(Box<ConditionExpr>, Box<ConditionExpr>),
    Or(Box<ConditionExpr>, Box<ConditionExpr>),
    Of { all: bool, pattern: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogSourceSpec {
    pub product: String,
    pub category: Option<String>,
    pub service: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseBinding {
    pub mode: ResponseExecutionMode,
    pub verbs: Vec<String>,
    pub max_scope: String,
    pub max_share_bp: u16,
    pub opted_in_remediate: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrelationSpec {
    pub kind: CorrelationKind,
    pub group_by: Vec<String>,
    pub timespan_secs: u64,
    pub threshold: u32,
    pub count_field: Option<String>,
    #[serde(default)]
    pub distinct_field: Option<String>,
    #[serde(default)]
    pub distinct_threshold: u32,
    pub rules: Vec<String>,
    pub scope: Option<DeploymentScope>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldPredicate {
    pub field: String,
    pub modifiers: Vec<SigmaModifier>,
    pub values: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectionBlock {
    pub name: String,
    pub predicates: Vec<FieldPredicate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigmaRule {
    pub title: String,
    pub uuid: String,
    pub author: String,
    pub status: SigmaStatus,
    pub origin: RuleOrigin,
    pub origin_declared: bool,
    pub row: u32,
    pub rule_id: String,
    pub version: String,
    pub finding_class: FindingClass,
    #[serde(default)]
    pub finding_class_other: Option<String>,
    pub severity: FindingSeverity,
    pub ceiling: FindingCeiling,
    pub scope: DeploymentScope,
    pub min_provenance: u8,
    pub stage: Option<String>,
    pub atlas: Vec<String>,
    pub owasp_asi: Vec<String>,
    pub logsource: LogSourceSpec,
    pub selections: BTreeMap<String, SelectionBlock>,
    pub condition: String,
    pub condition_ast: ConditionExpr,
    pub correlation: Option<CorrelationSpec>,
    pub response: Option<ResponseBinding>,
    pub derived_from: Option<String>,
    pub has_tests: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedRule {
    pub rule_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct LoadReport {
    pub loaded_rules: Vec<String>,
    pub skipped_rules: Vec<SkippedRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedDetectionContent {
    pub pack_id: String,
    pub version: String,
    pub raw_rules_yaml: Vec<String>,
    pub pack_mode: Mode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostProfile {
    pub device_id: String,
    pub device_name: String,
    pub organisation_id: String,
    pub scope: DeploymentScope,
    pub provenance_grade: u8,
    pub expand_vars: BTreeMap<String, Vec<String>>,
    pub model_audit_passed: bool,
    pub remediate_approvers: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct EventView<'a> {
    pub event_id: &'a str,
    pub session_id: &'a str,
    pub root_session_id: &'a str,
    pub organisation_id: &'a str,
    pub device_id: &'a str,
    pub device_name: &'a str,
    pub agent_name: &'a str,
    pub observed_at: Timestamp,
    pub action_class: ActionClass,
    pub category: &'a str,
    pub service: &'a str,
    pub target: &'a str,
    pub provenance_grade: u8,
    pub fields: BTreeMap<&'a str, &'a str>,
    pub list_fields: BTreeMap<&'a str, Vec<&'a str>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriggeredResponseIntent {
    pub rule_id: String,
    pub dedup_key: String,
    pub mode_applied: Mode,
    pub verbs: Vec<String>,
    pub simulated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DetectOutput {
    pub findings: Vec<Finding>,
    pub dedup_keys: Vec<String>,
    pub response_intents: Vec<TriggeredResponseIntent>,
    pub coverage_gaps: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrelationHitRecord {
    pub rule_id: String,
    #[serde(default)]
    pub parent_rule_id: Option<String>,
    pub group_key: String,
    pub observed_sec: i64,
    pub distinct_value: Option<String>,
    #[serde(default)]
    pub secondary_distinct_value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LineageCorrelationState {
    pub entries: VecDeque<CorrelationHitRecord>,
    pub group_keys_by_rule: BTreeMap<String, VecDeque<String>>,
    pub overflow_emitted_rules: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DetectState {
    pub by_lineage: BTreeMap<String, LineageCorrelationState>,
    pub hook_last_seen_sec: BTreeMap<String, i64>,
    pub sensor_exec_without_hook: BTreeMap<String, u32>,
    #[serde(default)]
    pub sensor_exec_last_seen_sec: BTreeMap<String, i64>,
    pub emitted_dedup_keys: BTreeSet<String>,
    pub emitted_dedup_order: VecDeque<String>,
    pub breaker_hourly_devices: BTreeMap<String, BTreeMap<String, i64>>,
    pub judge_probe_history: BTreeMap<String, VecDeque<(i64, String, String)>>,
    #[serde(default)]
    pub judge_probe_pending_future_sec: BTreeMap<String, i64>,
}

pub trait DetectionEngine {
    fn load(
        c: &VerifiedDetectionContent,
        host: &HostProfile,
    ) -> Result<(Self, LoadReport), DetectError>
    where
        Self: Sized;

    fn on_event(&mut self, ev: &EventView<'_>, out: &mut DetectOutput);

    fn on_tick(&mut self, now: Timestamp, out: &mut DetectOutput);

    fn snapshot(&self) -> DetectState;

    fn restore(&mut self, s: &DetectState) -> Result<(), DetectError>;
}

impl From<DetectError> for CodedError {
    fn from(err: DetectError) -> Self {
        let code = match &err {
            DetectError::InvalidRule(_) => CODE_DETECT_INVALID_RULE,
            DetectError::DuplicateRule(_) => CODE_DETECT_DUPLICATE_RULE,
            DetectError::StateRestore(_) => CODE_DETECT_STATE_RESTORE,
            DetectError::ConfigTamper(_) => CODE_DETECT_CONFIG_TAMPER,
            DetectError::ResponseBreaker(_) => CODE_DETECT_RESPONSE_BREAKER,
            DetectError::L0Unsupported(_) => CODE_DETECT_L0_UNSUPPORTED,
        };
        CodedError::new(
            code,
            err.to_string(),
            "Inspect detection pack rule schema and engine constraints.",
        )
    }
}

impl FindingCeiling {
    /// Clamps ceiling strictly by status maturity and rule provenance (`docs/design/13` s.5 & s.12).
    #[must_use]
    pub const fn clamp_by_origin(self, status: SigmaStatus, origin: RuleOrigin) -> Self {
        if matches!(status, SigmaStatus::Experimental | SigmaStatus::Deprecated) {
            return Self::Record;
        }
        if matches!(status, SigmaStatus::Test) && matches!(self, Self::Contain | Self::Remediate) {
            return Self::Notify;
        }
        if matches!(origin, RuleOrigin::Community) && matches!(self, Self::Remediate) {
            return Self::Contain;
        }
        self
    }
}
