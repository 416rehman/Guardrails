// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeSet;

use grdr_core::session::SessionRuleState;
use grdr_fastpath::{HostCapabilityState, HostProfile};
use grdr_model::{ActionClass, CodedError, DecisionReceipt, Grant, KillSwitchState, PolicyPack};
use serde::{Deserialize, Serialize};

pub const DEFAULT_STEP_BUDGET: u64 = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityPresence {
    Present,
    Absent,
    Pending,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssuranceKind {
    Enforced,
    WatchOnly,
    NotEvaluable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequiredHostSignal {
    UserIdentity,
    FileSensor,
    NetEgressSensor,
    CommandParser,
    SessionStore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostProfileDto {
    pub principal_attestation: CapabilityPresence,
    pub user_identity: CapabilityPresence,
    pub os_file_sensor: CapabilityPresence,
    pub net_egress_sensor: CapabilityPresence,
    pub command_parser: CapabilityPresence,
    pub session_store: CapabilityPresence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackAssuranceDto {
    pub pack_id: String,
    pub assurance: AssuranceKind,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterestSummary {
    pub action_classes: Vec<ActionClass>,
    pub target_prefixes: Vec<String>,
    pub target_contains: Vec<String>,
    pub agents: Vec<String>,
    pub required_signals: BTreeSet<RequiredHostSignal>,
    pub bundle_tag: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrandManifestDto {
    pub schema: String,
    pub namespace: String,
    pub product_name: String,
    pub short_name: String,
    pub publisher: String,
    pub domain: String,
    pub copyright_holder: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotSummary {
    pub snapshot_id: String,
    pub epoch: u64,
    pub steps_executed: u64,
    pub denial_count: u32,
    pub step_up_count: u32,
    pub labels: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct EngineCheckpoint {
    pub packs: Vec<PolicyPack>,
    pub grants: Vec<Grant>,
    pub kill_switch: KillSwitchState,
    pub host_profile: HostProfileDto,
    pub session: SessionRuleState,
    pub epoch: u64,
    pub steps_executed: u64,
    pub step_budget: u64,
    pub bundle_tag: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FfiStepOutput {
    pub receipt: DecisionReceipt,
    pub assurance: AssuranceKind,
    pub steps_executed: u64,
    pub fastpath_version: u32,
}

impl AssuranceKind {
    pub const fn severity_rank(self) -> u8 {
        match self {
            Self::NotEvaluable => 0,
            Self::WatchOnly => 1,
            Self::Enforced => 2,
        }
    }
}

impl HostProfileDto {
    pub const fn minimal_sandbox() -> Self {
        Self {
            principal_attestation: CapabilityPresence::Present,
            user_identity: CapabilityPresence::Absent,
            os_file_sensor: CapabilityPresence::Present,
            net_egress_sensor: CapabilityPresence::Absent,
            command_parser: CapabilityPresence::Present,
            session_store: CapabilityPresence::Absent,
        }
    }

    pub const fn full_endpoint() -> Self {
        Self {
            principal_attestation: CapabilityPresence::Present,
            user_identity: CapabilityPresence::Present,
            os_file_sensor: CapabilityPresence::Present,
            net_egress_sensor: CapabilityPresence::Present,
            command_parser: CapabilityPresence::Present,
            session_store: CapabilityPresence::Present,
        }
    }
}

impl Default for HostProfileDto {
    fn default() -> Self {
        Self::minimal_sandbox()
    }
}

impl From<HostProfileDto> for HostProfile {
    fn from(dto: HostProfileDto) -> Self {
        Self {
            principal_attestation: to_fast_cap(dto.principal_attestation),
            user_identity: to_fast_cap(dto.user_identity),
            os_file_sensor: to_fast_cap(dto.os_file_sensor),
            net_egress_sensor: to_fast_cap(dto.net_egress_sensor),
            command_parser: to_fast_cap(dto.command_parser),
            session_store: to_fast_cap(dto.session_store),
        }
    }
}

pub fn to_fast_cap(c: CapabilityPresence) -> HostCapabilityState {
    match c {
        CapabilityPresence::Present => HostCapabilityState::Present,
        CapabilityPresence::Absent => HostCapabilityState::Absent,
        CapabilityPresence::Pending => HostCapabilityState::Pending,
    }
}

pub fn invalid_input(msg: impl Into<String>, hint: impl Into<String>) -> CodedError {
    CodedError::new(grdr_model::error::CODE_INVALID_INPUT, msg, hint)
}
