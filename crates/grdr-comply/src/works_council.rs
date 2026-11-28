// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Works-council co-approver quorum and purpose-bound drill-down controls (`D-51`, `D-57`).

use std::collections::BTreeSet;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::ComplyError;
use crate::holds::validate_dual_approvers;
use crate::retention::PrivacyCeilingProfile;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoApproverQuorumPolicy {
    pub profile: PrivacyCeilingProfile,
    pub co_approver_group: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrillDownAuditRecord {
    pub audit_kind: String,
    pub actor: String,
    pub target_ref: String,
    pub incident_ref: Option<String>,
    pub assigned_finding_id: Option<String>,
    pub purpose: String,
    pub recorded_at: Timestamp,
}

pub fn validate_works_council_quorum(
    operation_id: &str,
    approvers: &[String],
    policy: &CoApproverQuorumPolicy,
) -> Result<Vec<String>, ComplyError> {
    if policy.co_approver_group.iter().any(|m| m.trim().is_empty()) {
        return Err(ComplyError::InvalidHold {
            hold_id: operation_id.to_owned(),
            detail: "co_approver_group cannot contain empty or whitespace entries".into(),
        });
    }
    let distinct = validate_dual_approvers(operation_id, approvers)?;
    if policy.profile == PrivacyCeilingProfile::WorksCouncil {
        let norm_group: BTreeSet<String> = policy
            .co_approver_group
            .iter()
            .map(|m| m.trim().to_ascii_lowercase())
            .filter(|m| !m.is_empty())
            .collect();
        if norm_group.is_empty() {
            return Err(ComplyError::InvalidHold {
                hold_id: operation_id.to_owned(),
                detail: "works-council mode requires a configured non-empty co_approver_group"
                    .into(),
            });
        }
        let has_co_approver = distinct
            .iter()
            .any(|a| norm_group.contains(&a.trim().to_ascii_lowercase()));
        if !has_co_approver {
            return Err(ComplyError::InvalidHold {
                hold_id: operation_id.to_owned(),
                detail: "works-council quorum requires at least one co_approver_group member"
                    .into(),
            });
        }
    }
    Ok(distinct)
}

pub fn validate_purpose_bound_drill_down(
    profile: PrivacyCeilingProfile,
    actor: &str,
    target_ref: &str,
    incident_ref: Option<&str>,
    assigned_finding_id: Option<&str>,
    purpose: &str,
    recorded_at: Timestamp,
) -> Result<DrillDownAuditRecord, ComplyError> {
    if actor.trim().is_empty() || target_ref.trim().is_empty() {
        return Err(ComplyError::InvalidEvidenceInput {
            detail: "drill-down requires non-empty actor and target_ref".into(),
        });
    }
    let clean_incident = incident_ref
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    let clean_finding = assigned_finding_id
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    let clean_purpose = purpose.trim();
    if profile == PrivacyCeilingProfile::WorksCouncil
        && ((clean_incident.is_none() && clean_finding.is_none()) || clean_purpose.is_empty())
    {
        return Err(ComplyError::InvalidEvidenceInput {
            detail: "works-council drill-down requires a non-empty purpose and an open incident_ref or assigned_finding_id".into(),
        });
    }
    Ok(DrillDownAuditRecord {
        audit_kind: "audit.access".to_owned(),
        actor: actor.trim().to_owned(),
        target_ref: target_ref.trim().to_owned(),
        incident_ref: clean_incident,
        assigned_finding_id: clean_finding,
        purpose: clean_purpose.to_owned(),
        recorded_at,
    })
}
