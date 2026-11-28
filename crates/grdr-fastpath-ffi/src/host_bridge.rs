// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use grdr_fastpath::{
    AssuranceVerdict, BinaryFloorHit, FastActionClass, FastVerdict, FastpathBrandManifest,
    FastpathInterestView, HostCapabilityState, HostEvalOutcome, HostProfile, HostRuleRequirements,
    LabelBundleState, evaluate_failsafe, evaluate_floor_with_host,
};

use crate::{GrdrFastStatus, GrdrFastVerdict};

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrdrFpHostProfileC {
    pub struct_size: usize,
    pub principal_attestation: u8,
    pub user_identity: u8,
    pub os_file_sensor: u8,
    pub net_egress_sensor: u8,
    pub command_parser: u8,
    pub session_store: u8,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrdrFpInterestC {
    pub action_mask: u32,
    pub label_mask: u16,
    pub expected_bundle_tag: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostLabelStateC {
    MissingOrLate,
    Ready {
        active_labels_mask: u16,
        bundle_tag: [u8; 32],
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostEvalRequest<'a> {
    pub interest: GrdrFpInterestC,
    pub label_state: HostLabelStateC,
    pub action: FastActionClass,
    pub principal_mask: u16,
    pub agent: &'a str,
    pub target: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostEvalSummary<'a> {
    pub status: GrdrFastStatus,
    pub verdict: GrdrFastVerdict,
    pub hit: Option<BinaryFloorHit<'a>>,
}

impl From<GrdrFpHostProfileC> for HostProfile {
    fn from(raw: GrdrFpHostProfileC) -> Self {
        Self {
            principal_attestation: decode_cap_state(raw.principal_attestation),
            user_identity: decode_cap_state(raw.user_identity),
            os_file_sensor: decode_cap_state(raw.os_file_sensor),
            net_egress_sensor: decode_cap_state(raw.net_egress_sensor),
            command_parser: decode_cap_state(raw.command_parser),
            session_store: decode_cap_state(raw.session_store),
        }
    }
}

pub fn eval_binary_table_with_interest<'a>(
    table_bytes: &'a [u8],
    request: &HostEvalRequest<'_>,
) -> HostEvalSummary<'a> {
    let view = FastpathInterestView {
        action_mask: request.interest.action_mask,
        path_prefixes: &[],
        net_domains: &[],
        label_mask: request.interest.label_mask,
        expected_bundle_tag: request.interest.expected_bundle_tag,
    };
    let label_state = match request.label_state {
        HostLabelStateC::MissingOrLate => LabelBundleState::MissingOrLate,
        HostLabelStateC::Ready {
            active_labels_mask,
            bundle_tag,
        } => LabelBundleState::Ready {
            active_labels_mask,
            bundle_tag,
        },
    };
    match evaluate_floor_with_host(
        table_bytes,
        &view,
        label_state,
        request.action,
        request.principal_mask,
        request.agent,
        request.target,
    ) {
        HostEvalOutcome::Matched(hit) => HostEvalSummary {
            status: GrdrFastStatus::Ok,
            verdict: match hit.verdict {
                FastVerdict::Allow => GrdrFastVerdict::Allow,
                FastVerdict::StepUp => GrdrFastVerdict::StepUp,
                FastVerdict::Deny => GrdrFastVerdict::Deny,
            },
            hit: Some(hit),
        },
        HostEvalOutcome::NoMatch => HostEvalSummary {
            status: GrdrFastStatus::Ok,
            verdict: GrdrFastVerdict::Allow,
            hit: None,
        },
        HostEvalOutcome::StateError(_) => HostEvalSummary {
            status: GrdrFastStatus::ErrState,
            verdict: GrdrFastVerdict::Deny,
            hit: None,
        },
    }
}

pub fn eval_manifest_failsafe(action: FastActionClass, target: &str) -> GrdrFastVerdict {
    match evaluate_failsafe(action, target) {
        Some(hit) => match hit.verdict {
            FastVerdict::Allow => GrdrFastVerdict::Allow,
            FastVerdict::StepUp => GrdrFastVerdict::StepUp,
            FastVerdict::Deny => GrdrFastVerdict::Deny,
        },
        None => GrdrFastVerdict::Allow,
    }
}

pub fn assess_host_profile_c(
    profile: GrdrFpHostProfileC,
    requires_user: bool,
    requires_net_sensor: bool,
    requires_session: bool,
) -> GrdrFastStatus {
    let hp = HostProfile::from(profile);
    match hp.assess_rule_requirements(requires_user, requires_net_sensor, requires_session) {
        AssuranceVerdict::Evaluable => GrdrFastStatus::Ok,
        AssuranceVerdict::NotEvaluable(_) => GrdrFastStatus::ErrNotEvaluable,
    }
}

pub fn assess_host_profile_mask_c(profile: GrdrFpHostProfileC, req_mask: u8) -> GrdrFastStatus {
    let hp = HostProfile::from(profile);
    match hp.assess_full_requirements(HostRuleRequirements(req_mask)) {
        AssuranceVerdict::Evaluable => GrdrFastStatus::Ok,
        AssuranceVerdict::NotEvaluable(_) => GrdrFastStatus::ErrNotEvaluable,
    }
}

pub fn embedded_brand_manifest() -> FastpathBrandManifest<'static> {
    FastpathBrandManifest::embedded()
}

fn decode_cap_state(raw: u8) -> HostCapabilityState {
    match raw {
        1 => HostCapabilityState::Present,
        2 => HostCapabilityState::Pending,
        _ => HostCapabilityState::Absent,
    }
}
