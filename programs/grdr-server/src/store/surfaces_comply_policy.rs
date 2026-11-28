// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use jiff::Timestamp;
use uuid::Uuid;

use grdr_comply::{
    CaptureLevel, CoApproverQuorumPolicy, NoticeChangeState, PrivacyCeilingProfile,
    RetentionPreset, format_utc_quarter, schedule_capture_change, validate_works_council_quorum,
};
use grdr_model::error::CODE_INVALID_INPUT;
use grdr_model::{AuditEntry, CodedError};
use grdr_proto::api::surfaces::RetentionStateSummary;

use crate::store::StoreData;
use crate::store::surfaces_comply::ops::{
    capture_level_str, extend_pending_capture_for_works_council, parse_capture_level,
};
use crate::store::surfaces_comply_helpers::{build_retention_summary, comply_to_coded};
use crate::store::surfaces_types::{
    ComplianceGovernanceState, DisclosureRecord, PendingCaptureChange, PendingProfileDowngrade,
};

pub(crate) struct DowngradeProposal<'a> {
    pub(crate) tenant_id: &'a str,
    pub(crate) actor: &'a str,
    pub(crate) presets: &'a [RetentionPreset],
    pub(crate) caller_basis: &'a Option<String>,
    pub(crate) requested_capture_str: &'a Option<String>,
    pub(crate) now: Timestamp,
}

pub(crate) fn stage_or_complete_downgrade(
    guard: &mut StoreData,
    input: DowngradeProposal<'_>,
) -> Result<Option<RetentionStateSummary>, CodedError> {
    let mut staged_summary: Option<RetentionStateSummary> = None;
    if let Some(ref mut comp) = guard.surfaces.compliance {
        match comp.pending_profile_downgrade.clone() {
            None => {
                comp.pending_profile_downgrade = Some(PendingProfileDowngrade {
                    target_profile: PrivacyCeilingProfile::Standard,
                    first_approver: input.actor.to_owned(),
                    presets: input.presets.to_vec(),
                    override_legal_basis: input.caller_basis.clone(),
                    requested_capture_level: input.requested_capture_str.clone(),
                    requested_at: input.now.to_string(),
                });
                comp.disclosures.insert(
                    0,
                    DisclosureRecord {
                        id: format!("disc_{}", Uuid::now_v7().simple()),
                        organisation: input.tenant_id.to_owned(),
                        kind: "retention_policy_downgrade_proposed".to_owned(),
                        actor: input.actor.to_owned(),
                        target_ref: "WorksCouncil->Standard (pending quorum)".to_owned(),
                        legal_basis: input.caller_basis.clone().unwrap_or_default(),
                        timestamp: input.now.to_string(),
                        quarter: format_utc_quarter(input.now),
                        summary: "Staged works-council downgrade pending second co-approver"
                            .to_owned(),
                    },
                );
                staged_summary = Some(build_retention_summary(comp, input.tenant_id));
            }
            Some(pending) => {
                if pending.presets.as_slice() != input.presets
                    || pending.override_legal_basis != *input.caller_basis
                    || pending.requested_capture_level != *input.requested_capture_str
                {
                    return Err(CodedError::new(
                        CODE_INVALID_INPUT,
                        "Co-approver downgrade confirmation parameters must match the staged downgrade request.",
                        "Submit the exact presets, override_legal_basis, and capture_level staged by the first approver.",
                    ));
                }
                let policy = CoApproverQuorumPolicy {
                    profile: PrivacyCeilingProfile::WorksCouncil,
                    co_approver_group: comp.co_approver_group.iter().cloned().collect(),
                };
                let approvers = vec![pending.first_approver, input.actor.to_owned()];
                validate_works_council_quorum("profile-downgrade", &approvers, &policy)
                    .map_err(comply_to_coded)?;
                comp.pending_profile_downgrade = None;
            }
        }
    }
    if staged_summary.is_some() {
        guard.audit.insert(
            0,
            AuditEntry {
                id: format!("aud_{}", Uuid::now_v7().simple()),
                timestamp: input.now,
                kind: "compliance.retention.downgrade_proposed".to_owned(),
                actor: input.actor.to_owned(),
                summary: "Proposed works-council privacy downgrade (1/2 co-approver quorum)"
                    .to_owned(),
                target: "compliance-retention".to_owned(),
            },
        );
    }
    Ok(staged_summary)
}

pub(crate) fn apply_capture_schedule_update(
    comp: &mut ComplianceGovernanceState,
    profile: PrivacyCeilingProfile,
    requested_capture: Option<CaptureLevel>,
    actor: &str,
    now: Timestamp,
) -> Result<String, CodedError> {
    let prev_capture =
        parse_capture_level(&comp.capture_level).unwrap_or(CaptureLevel::MetadataOnly);
    if let Some(next_cap) = requested_capture {
        let sched = schedule_capture_change(profile, prev_capture, next_cap, now)
            .map_err(comply_to_coded)?;
        return match sched.schedule {
            NoticeChangeState::Immediate => {
                comp.capture_level = capture_level_str(next_cap).to_owned();
                comp.pending_capture_change = None;
                Ok(String::new())
            }
            NoticeChangeState::Scheduled {
                notice_days,
                announced_at,
                effective_at,
            } => {
                comp.pending_capture_change = Some(PendingCaptureChange {
                    target_capture_level: capture_level_str(next_cap).to_owned(),
                    requested_at: now.to_string(),
                    effective_at: effective_at.to_string(),
                    notice_rule: format!(
                        "{notice_days}d advance notice (announced {announced_at})"
                    ),
                    actor: actor.to_owned(),
                });
                Ok(format!(
                    "; {notice_days}d advance notice until {effective_at}"
                ))
            }
        };
    }
    if profile == PrivacyCeilingProfile::WorksCouncil
        && let Some(ext_note) = extend_pending_capture_for_works_council(comp, now)?
    {
        return Ok(ext_note);
    }
    Ok(String::new())
}
