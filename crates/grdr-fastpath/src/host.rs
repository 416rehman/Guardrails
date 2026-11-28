// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! `#![no_std]` OEM host capability profile, label bundle gating, and brand manifest parser.

use crate::binary::{BinaryFloorHit, BinaryFloorTable, FastpathError};
use crate::{FastActionClass, FastVerdict};

pub const EMBEDDED_BRAND_TOML: &str = include_str!("../../../contracts/interface/brand/brand.toml");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostCapabilityState {
    Present,
    Absent,
    Pending,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssuranceVerdict {
    Evaluable,
    NotEvaluable(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelBundleState {
    Ready {
        active_labels_mask: u16,
        bundle_tag: [u8; 32],
    },
    MissingOrLate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostEvalOutcome<'a> {
    Matched(BinaryFloorHit<'a>),
    NoMatch,
    StateError(FastpathHostStatus),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FastpathHostStatus {
    InvalidTable(FastpathError),
    LabelStateMismatch,
    HostProfileNotEvaluable,
}

pub const REQ_USER_IDENTITY: u8 = 1 << 0;
pub const REQ_OS_FILE_SENSOR: u8 = 1 << 1;
pub const REQ_NET_EGRESS_SENSOR: u8 = 1 << 2;
pub const REQ_COMMAND_PARSER: u8 = 1 << 3;
pub const REQ_SESSION_STORE: u8 = 1 << 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HostRuleRequirements(pub u8);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostProfile {
    pub principal_attestation: HostCapabilityState,
    pub user_identity: HostCapabilityState,
    pub os_file_sensor: HostCapabilityState,
    pub net_egress_sensor: HostCapabilityState,
    pub command_parser: HostCapabilityState,
    pub session_store: HostCapabilityState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FastpathInterestView<'a> {
    pub action_mask: u32,
    pub path_prefixes: &'a [&'a str],
    pub net_domains: &'a [&'a str],
    pub label_mask: u16,
    pub expected_bundle_tag: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FastpathBrandManifest<'a> {
    pub schema: &'a str,
    pub namespace: &'a str,
    pub product_name: &'a str,
    pub short_name: &'a str,
    pub publisher: &'a str,
    pub domain: &'a str,
    pub copyright_holder: &'a str,
}

impl HostRuleRequirements {
    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn with(self, flag: u8) -> Self {
        Self(self.0 | flag)
    }

    pub const fn contains(self, flag: u8) -> bool {
        (self.0 & flag) != 0
    }
}

impl Default for HostProfile {
    fn default() -> Self {
        Self::minimal_sandbox()
    }
}

impl HostProfile {
    pub const fn minimal_sandbox() -> Self {
        Self {
            principal_attestation: HostCapabilityState::Present,
            user_identity: HostCapabilityState::Absent,
            os_file_sensor: HostCapabilityState::Present,
            net_egress_sensor: HostCapabilityState::Absent,
            command_parser: HostCapabilityState::Present,
            session_store: HostCapabilityState::Absent,
        }
    }

    pub const fn full_endpoint() -> Self {
        Self {
            principal_attestation: HostCapabilityState::Present,
            user_identity: HostCapabilityState::Present,
            os_file_sensor: HostCapabilityState::Present,
            net_egress_sensor: HostCapabilityState::Present,
            command_parser: HostCapabilityState::Present,
            session_store: HostCapabilityState::Present,
        }
    }

    pub fn assess_rule_requirements(
        &self,
        requires_user: bool,
        requires_net_sensor: bool,
        requires_session: bool,
    ) -> AssuranceVerdict {
        let mut req = HostRuleRequirements::empty();
        if requires_user {
            req = req.with(REQ_USER_IDENTITY);
        }
        if requires_net_sensor {
            req = req.with(REQ_NET_EGRESS_SENSOR);
        }
        if requires_session {
            req = req.with(REQ_SESSION_STORE);
        }
        self.assess_full_requirements(req)
    }

    pub fn assess_full_requirements(&self, req: HostRuleRequirements) -> AssuranceVerdict {
        if self.principal_attestation != HostCapabilityState::Present {
            return AssuranceVerdict::NotEvaluable("principal attestation absent or pending");
        }
        if req.contains(REQ_USER_IDENTITY) && self.user_identity != HostCapabilityState::Present {
            return AssuranceVerdict::NotEvaluable("host profile omits user identity");
        }
        if req.contains(REQ_OS_FILE_SENSOR) && self.os_file_sensor != HostCapabilityState::Present {
            return AssuranceVerdict::NotEvaluable("host profile omits OS file sensor");
        }
        if req.contains(REQ_NET_EGRESS_SENSOR)
            && self.net_egress_sensor != HostCapabilityState::Present
        {
            return AssuranceVerdict::NotEvaluable("host profile omits net egress sensor");
        }
        if req.contains(REQ_COMMAND_PARSER) && self.command_parser != HostCapabilityState::Present {
            return AssuranceVerdict::NotEvaluable("host profile omits command parser");
        }
        if req.contains(REQ_SESSION_STORE) && self.session_store != HostCapabilityState::Present {
            return AssuranceVerdict::NotEvaluable("host profile omits session state store");
        }
        AssuranceVerdict::Evaluable
    }
}

impl FastpathBrandManifest<'static> {
    pub fn embedded() -> Self {
        Self::from_toml(EMBEDDED_BRAND_TOML)
    }
}

impl<'a> FastpathBrandManifest<'a> {
    pub fn from_toml(toml_raw: &'a str) -> Self {
        Self {
            schema: find_toml_str(toml_raw, "schema").unwrap_or(""),
            namespace: find_toml_str(toml_raw, "namespace").unwrap_or(""),
            product_name: find_toml_str(toml_raw, "product_name").unwrap_or(""),
            short_name: find_toml_str(toml_raw, "short_name").unwrap_or(""),
            publisher: find_toml_str(toml_raw, "publisher").unwrap_or(""),
            domain: find_toml_str(toml_raw, "domain").unwrap_or(""),
            copyright_holder: find_toml_str(toml_raw, "copyright_holder").unwrap_or(""),
        }
    }
}

pub fn evaluate_floor_with_host<'a>(
    table_bytes: &'a [u8],
    interest: &FastpathInterestView<'_>,
    label_state: LabelBundleState,
    action: FastActionClass,
    principal_mask: u16,
    agent: &str,
    target: &str,
) -> HostEvalOutcome<'a> {
    let table = match BinaryFloorTable::parse(table_bytes) {
        Ok(t) => t,
        Err(err) => return HostEvalOutcome::StateError(FastpathHostStatus::InvalidTable(err)),
    };

    let needs_labels = interest.label_mask != 0 || table.uses_labels();
    let active_labels = match (needs_labels, label_state) {
        (false, LabelBundleState::MissingOrLate) => 0,
        (
            false,
            LabelBundleState::Ready {
                active_labels_mask,
                bundle_tag,
            },
        ) => {
            if interest.expected_bundle_tag != [0u8; 32]
                && bundle_tag != interest.expected_bundle_tag
            {
                return HostEvalOutcome::StateError(FastpathHostStatus::LabelStateMismatch);
            }
            active_labels_mask
        }
        (true, LabelBundleState::MissingOrLate) => {
            return HostEvalOutcome::StateError(FastpathHostStatus::LabelStateMismatch);
        }
        (
            true,
            LabelBundleState::Ready {
                active_labels_mask,
                bundle_tag,
            },
        ) => {
            if bundle_tag == [0u8; 32] || bundle_tag != interest.expected_bundle_tag {
                return HostEvalOutcome::StateError(FastpathHostStatus::LabelStateMismatch);
            }
            active_labels_mask
        }
    };

    match table.evaluate(action, principal_mask, active_labels, agent, target) {
        Some(hit) => HostEvalOutcome::Matched(hit),
        None => HostEvalOutcome::NoMatch,
    }
}

pub fn is_protected_verdict(verdict: FastVerdict) -> bool {
    matches!(verdict, FastVerdict::StepUp | FastVerdict::Deny)
}

fn find_toml_str<'a>(raw: &'a str, key: &str) -> Option<&'a str> {
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }
        if let Some((lhs, rhs)) = trimmed.split_once('=')
            && lhs.trim() == key
        {
            let val = rhs.trim();
            if let Some(inner) = val.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
                return Some(inner);
            }
        }
    }
    None
}
