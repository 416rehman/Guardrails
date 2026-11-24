// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::fmt;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApproverRole {
    PrivacyOfficer,
    OrgOwner,
    WorksCouncilDelegate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultPolicy {
    pub quorum_ttl_secs: i64,
    pub max_legal_hold_deferral_days: i64,
    pub require_works_council_coapproval: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApproverRecord {
    pub account_id: String,
    pub role: ApproverRole,
    pub approved_at: Timestamp,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultSubjectRecord {
    pub raw_subject: String,
    pub display_hint: String,
    pub device_pseudonym: String,
    pub org_pseudonym: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "disclosure", rename_all = "snake_case")]
pub enum SubjectDisclosureState {
    PendingDisclosure,
    Disclosed { disclosed_at: Timestamp },
    LegalHoldDeferred { deferred_until: Timestamp },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ReidentQuorumState {
    Pending {
        request_id: String,
        org_id: String,
        requester_id: String,
        target_org_pseudonym: String,
        purpose: String,
        incident_ref: String,
        requested_at: Timestamp,
        expires_at: Timestamp,
    },
    PartialApproval {
        request_id: String,
        org_id: String,
        requester_id: String,
        target_org_pseudonym: String,
        purpose: String,
        incident_ref: String,
        first_approver: ApproverRecord,
        requested_at: Timestamp,
        expires_at: Timestamp,
    },
    Approved {
        request_id: String,
        org_id: String,
        requester_id: String,
        target_org_pseudonym: String,
        purpose: String,
        incident_ref: String,
        approvers: [ApproverRecord; 2],
        approved_at: Timestamp,
        disclosure: SubjectDisclosureState,
    },
    Rejected {
        request_id: String,
        org_id: String,
        rejected_by: String,
        reason: String,
        rejected_at: Timestamp,
    },
    Expired {
        request_id: String,
        org_id: String,
        expired_at: Timestamp,
    },
}

impl Default for VaultPolicy {
    fn default() -> Self {
        Self {
            quorum_ttl_secs: 86_400,
            max_legal_hold_deferral_days: 90,
            require_works_council_coapproval: false,
        }
    }
}

impl fmt::Debug for VaultSubjectRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultSubjectRecord")
            .field("raw_subject", &"[REDACTED]")
            .field("display_hint", &"[REDACTED]")
            .field("device_pseudonym", &self.device_pseudonym)
            .field("org_pseudonym", &self.org_pseudonym)
            .finish()
    }
}

pub(crate) fn roles_satisfy_quorum(
    first: ApproverRole,
    second: ApproverRole,
    require_works_council: bool,
) -> bool {
    if require_works_council {
        return matches!(
            (first, second),
            (
                ApproverRole::PrivacyOfficer,
                ApproverRole::WorksCouncilDelegate
            ) | (
                ApproverRole::WorksCouncilDelegate,
                ApproverRole::PrivacyOfficer
            )
        );
    }
    matches!(
        (first, second),
        (
            ApproverRole::PrivacyOfficer,
            ApproverRole::PrivacyOfficer | ApproverRole::OrgOwner
        ) | (ApproverRole::OrgOwner, ApproverRole::PrivacyOfficer)
    )
}
