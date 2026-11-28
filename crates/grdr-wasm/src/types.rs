// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeSet;

use grdr_fastpath::{HostCapabilityState, HostProfile};
use serde::{Deserialize, Serialize};

use crate::model_dto::{
    WasmActionClass, WasmDecisionReceipt, WasmGrant, WasmKillSwitchState, WasmPolicyPack,
};

pub const DEFAULT_WASM_STEP_BUDGET: u64 = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WasmCapPresence {
    Present,
    Absent,
    Pending,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WasmAssuranceKind {
    Enforced,
    WatchOnly,
    NotEvaluable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WasmRequiredSignal {
    UserIdentity,
    FileSensor,
    NetEgressSensor,
    CommandParser,
    SessionStore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmHostProfile {
    pub principal_attestation: WasmCapPresence,
    pub user_identity: WasmCapPresence,
    pub os_file_sensor: WasmCapPresence,
    pub net_egress_sensor: WasmCapPresence,
    pub command_parser: WasmCapPresence,
    pub session_store: WasmCapPresence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmPackAssurance {
    pub pack_id: String,
    pub assurance: WasmAssuranceKind,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmInterestSummary {
    pub action_classes: Vec<WasmActionClass>,
    pub target_prefixes: Vec<String>,
    pub target_contains: Vec<String>,
    pub agents: Vec<String>,
    pub required_signals: BTreeSet<WasmRequiredSignal>,
    pub bundle_tag: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmBrandManifest {
    pub schema: String,
    pub namespace: String,
    pub product_name: String,
    pub short_name: String,
    pub publisher: String,
    pub domain: String,
    pub copyright_holder: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmSnapshotSummary {
    pub snapshot_id: String,
    pub epoch: u64,
    pub steps_executed: u64,
    pub denial_count: u32,
    pub step_up_count: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WasmSessionState {
    pub denial_count: u32,
    pub step_up_count: u32,
    pub label_flags: u8,
    pub extra_labels: BTreeSet<String>,
}

#[derive(Debug, Clone)]
pub struct WasmCheckpoint {
    pub packs: Vec<WasmPolicyPack>,
    pub grants: Vec<WasmGrant>,
    pub kill_switch: WasmKillSwitchState,
    pub host_profile: WasmHostProfile,
    pub session: WasmSessionState,
    pub epoch: u64,
    pub steps_executed: u64,
    pub step_budget: u64,
    pub bundle_tag: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmStepOutput {
    pub receipt: WasmDecisionReceipt,
    pub assurance: WasmAssuranceKind,
    pub steps_executed: u64,
    pub fastpath_version: u32,
}

impl WasmAssuranceKind {
    pub const fn severity_rank(self) -> u8 {
        match self {
            Self::NotEvaluable => 0,
            Self::WatchOnly => 1,
            Self::Enforced => 2,
        }
    }
}

impl WasmHostProfile {
    pub const fn minimal_sandbox() -> Self {
        Self {
            principal_attestation: WasmCapPresence::Present,
            user_identity: WasmCapPresence::Absent,
            os_file_sensor: WasmCapPresence::Present,
            net_egress_sensor: WasmCapPresence::Absent,
            command_parser: WasmCapPresence::Present,
            session_store: WasmCapPresence::Absent,
        }
    }

    pub const fn full_endpoint() -> Self {
        Self {
            principal_attestation: WasmCapPresence::Present,
            user_identity: WasmCapPresence::Present,
            os_file_sensor: WasmCapPresence::Present,
            net_egress_sensor: WasmCapPresence::Present,
            command_parser: WasmCapPresence::Present,
            session_store: WasmCapPresence::Present,
        }
    }
}

impl Default for WasmHostProfile {
    fn default() -> Self {
        Self::minimal_sandbox()
    }
}

impl From<WasmHostProfile> for HostProfile {
    fn from(dto: WasmHostProfile) -> Self {
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

pub fn to_fast_cap(c: WasmCapPresence) -> HostCapabilityState {
    match c {
        WasmCapPresence::Present => HostCapabilityState::Present,
        WasmCapPresence::Absent => HostCapabilityState::Absent,
        WasmCapPresence::Pending => HostCapabilityState::Pending,
    }
}
