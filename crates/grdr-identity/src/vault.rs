// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;
use std::fmt;

use grdr_crypto::{AeadKey, open_token, seal_token};
use jiff::Timestamp;

use crate::IdentityError;
use crate::pseudonym::{
    QuarterKey, QuarterlyDisclosureEntry, derive_device_pseudonym, re_pseudonymize_for_org,
};
use crate::vault_types::{
    ApproverRecord, ApproverRole, ReidentQuorumState, SubjectDisclosureState, VaultPolicy,
    VaultSubjectRecord, roles_satisfy_quorum,
};

const VAULT_DOMAIN: &str = "grdr.identity.vault.v1";
const SECONDS_PER_DAY: i64 = 86_400;

#[derive(Clone)]
pub struct IdentityVault {
    org_id: String,
    org_pseudonym_key: [u8; 32],
    vault_aead_key: AeadKey,
    pseudonym_epoch: u32,
    policy: VaultPolicy,
    sealed_subjects: BTreeMap<String, String>,
    quorums: BTreeMap<String, ReidentQuorumState>,
    disclosure_ledger: BTreeMap<QuarterKey, QuarterlyDisclosureEntry>,
}

impl fmt::Debug for IdentityVault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityVault")
            .field("org_id", &self.org_id)
            .field("org_pseudonym_key", &"[REDACTED]")
            .field("vault_aead_key", &self.vault_aead_key)
            .field("pseudonym_epoch", &self.pseudonym_epoch)
            .field("policy", &self.policy)
            .field("subject_count", &self.sealed_subjects.len())
            .field("quorum_count", &self.quorums.len())
            .finish()
    }
}

impl IdentityVault {
    #[must_use]
    pub fn new(
        org_id: impl Into<String>,
        org_pseudonym_key: [u8; 32],
        vault_aead_key: AeadKey,
        pseudonym_epoch: u32,
        policy: VaultPolicy,
    ) -> Self {
        Self {
            org_id: org_id.into(),
            org_pseudonym_key,
            vault_aead_key,
            pseudonym_epoch,
            policy,
            sealed_subjects: BTreeMap::new(),
            quorums: BTreeMap::new(),
            disclosure_ledger: BTreeMap::new(),
        }
    }

    pub fn register_subject(
        &mut self,
        device_pseudonym_key: &[u8; 32],
        raw_subject: &str,
        display_hint: &str,
    ) -> Result<(String, String), IdentityError> {
        let device_pseudonym = derive_device_pseudonym(device_pseudonym_key, raw_subject);
        let org_pseudonym = re_pseudonymize_for_org(
            &self.org_pseudonym_key,
            self.pseudonym_epoch,
            &device_pseudonym,
        );
        let record = VaultSubjectRecord {
            raw_subject: raw_subject.to_owned(),
            display_hint: display_hint.to_owned(),
            device_pseudonym: device_pseudonym.clone(),
            org_pseudonym: org_pseudonym.clone(),
        };
        let bytes = serde_json::to_vec(&record)
            .map_err(|e| IdentityError::VaultState(format!("vault serialize failed: {e}")))?;
        let aad = self.vault_aad(&org_pseudonym);
        let sealed = seal_token(&self.vault_aead_key, VAULT_DOMAIN, &aad, &bytes)
            .map_err(|e| IdentityError::VaultState(format!("vault seal failed: {e}")))?;
        self.sealed_subjects.insert(org_pseudonym.clone(), sealed);
        Ok((device_pseudonym, org_pseudonym))
    }

    pub fn request_reidentification(
        &mut self,
        request_id: impl Into<String>,
        requester_id: impl Into<String>,
        target_org_pseudonym: impl Into<String>,
        purpose: impl Into<String>,
        incident_ref: impl Into<String>,
        now: Timestamp,
    ) -> Result<&ReidentQuorumState, IdentityError> {
        let request_id = request_id.into();
        let target_org_pseudonym = target_org_pseudonym.into();
        if !self.sealed_subjects.contains_key(&target_org_pseudonym) {
            return Err(IdentityError::VaultState(format!(
                "unknown target pseudonym {target_org_pseudonym}"
            )));
        }
        if self.quorums.contains_key(&request_id) {
            return Err(IdentityError::VaultState(format!(
                "re-identification request {request_id} already exists"
            )));
        }

        let expires_at =
            Timestamp::from_second(now.as_second().saturating_add(self.policy.quorum_ttl_secs))
                .map_err(|e| IdentityError::VaultState(format!("invalid quorum expiry: {e}")))?;

        let state = ReidentQuorumState::Pending {
            request_id: request_id.clone(),
            org_id: self.org_id.clone(),
            requester_id: requester_id.into(),
            target_org_pseudonym,
            purpose: purpose.into(),
            incident_ref: incident_ref.into(),
            requested_at: now,
            expires_at,
        };
        self.quorums.insert(request_id.clone(), state);
        let ledger = self.quarter_entry_mut(QuarterKey::from_timestamp(now));
        ledger.requested_count = ledger.requested_count.saturating_add(1);

        self.quorums
            .get(&request_id)
            .ok_or_else(|| IdentityError::VaultState("missing inserted quorum".into()))
    }

    pub fn approve_reidentification(
        &mut self,
        request_id: &str,
        approver_id: impl Into<String>,
        role: ApproverRole,
        now: Timestamp,
    ) -> Result<&ReidentQuorumState, IdentityError> {
        let approver_id = approver_id.into();
        let current =
            self.quorums.get(request_id).cloned().ok_or_else(|| {
                IdentityError::VaultState(format!("unknown request {request_id}"))
            })?;

        let next = self.step_approval(current, request_id, approver_id, role, now)?;
        self.quorums.insert(request_id.to_owned(), next);
        self.quorums
            .get(request_id)
            .ok_or_else(|| IdentityError::VaultState("missing updated quorum".into()))
    }

    pub fn reject_reidentification(
        &mut self,
        request_id: &str,
        rejected_by: impl Into<String>,
        reason: impl Into<String>,
        now: Timestamp,
    ) -> Result<&ReidentQuorumState, IdentityError> {
        let current =
            self.quorums.get(request_id).cloned().ok_or_else(|| {
                IdentityError::VaultState(format!("unknown request {request_id}"))
            })?;
        match current {
            ReidentQuorumState::Pending { org_id, .. }
            | ReidentQuorumState::PartialApproval { org_id, .. } => {
                let rejected = ReidentQuorumState::Rejected {
                    request_id: request_id.to_owned(),
                    org_id,
                    rejected_by: rejected_by.into(),
                    reason: reason.into(),
                    rejected_at: now,
                };
                self.quorums.insert(request_id.to_owned(), rejected);
                self.quorums
                    .get(request_id)
                    .ok_or_else(|| IdentityError::VaultState("missing rejected quorum".into()))
            }
            _ => Err(IdentityError::VaultState(
                "only Pending or PartialApproval quorums can be rejected".into(),
            )),
        }
    }

    pub fn record_subject_disclosure(
        &mut self,
        request_id: &str,
        now: Timestamp,
    ) -> Result<(), IdentityError> {
        let current =
            self.quorums.get(request_id).cloned().ok_or_else(|| {
                IdentityError::VaultState(format!("unknown request {request_id}"))
            })?;
        let ReidentQuorumState::Approved {
            request_id: id,
            org_id,
            requester_id,
            target_org_pseudonym,
            purpose,
            incident_ref,
            approvers,
            approved_at,
            disclosure,
        } = current
        else {
            return Err(IdentityError::VaultState(
                "subject disclosure requires Approved quorum".into(),
            ));
        };

        if matches!(disclosure, SubjectDisclosureState::Disclosed { .. }) {
            return Err(IdentityError::VaultState(
                "subject disclosure already recorded".into(),
            ));
        }

        self.quorums.insert(
            request_id.to_owned(),
            ReidentQuorumState::Approved {
                request_id: id,
                org_id,
                requester_id,
                target_org_pseudonym,
                purpose,
                incident_ref,
                approvers,
                approved_at,
                disclosure: SubjectDisclosureState::Disclosed { disclosed_at: now },
            },
        );
        let ledger = self.quarter_entry_mut(QuarterKey::from_timestamp(now));
        ledger.subject_disclosed_count = ledger.subject_disclosed_count.saturating_add(1);
        Ok(())
    }

    pub fn defer_subject_notification(
        &mut self,
        request_id: &str,
        defer_until: Timestamp,
        now: Timestamp,
    ) -> Result<Timestamp, IdentityError> {
        let current =
            self.quorums.get(request_id).cloned().ok_or_else(|| {
                IdentityError::VaultState(format!("unknown request {request_id}"))
            })?;
        let max_secs = self
            .policy
            .max_legal_hold_deferral_days
            .saturating_mul(SECONDS_PER_DAY);

        let ReidentQuorumState::Approved {
            request_id: id,
            org_id,
            requester_id,
            target_org_pseudonym,
            purpose,
            incident_ref,
            approvers,
            approved_at,
            disclosure,
        } = current
        else {
            return Err(IdentityError::VaultState(
                "legal-hold deferral requires Approved quorum".into(),
            ));
        };

        if disclosure != SubjectDisclosureState::PendingDisclosure {
            return Err(IdentityError::VaultState(
                "legal-hold deferral is only allowed once while PendingDisclosure".into(),
            ));
        }
        if defer_until <= approved_at || defer_until <= now {
            return Err(IdentityError::VaultState(
                "defer_until must be strictly in the future relative to approval and current time"
                    .into(),
            ));
        }

        let max_until = Timestamp::from_second(approved_at.as_second().saturating_add(max_secs))
            .map_err(|e| IdentityError::VaultState(format!("invalid deferral cap: {e}")))?;
        if defer_until > max_until {
            return Err(IdentityError::DeferralCapExceeded {
                max_until: max_until.to_string(),
            });
        }
        let updated = ReidentQuorumState::Approved {
            request_id: id,
            org_id,
            requester_id,
            target_org_pseudonym,
            purpose,
            incident_ref,
            approvers,
            approved_at,
            disclosure: SubjectDisclosureState::LegalHoldDeferred {
                deferred_until: defer_until,
            },
        };
        self.quorums.insert(request_id.to_owned(), updated);
        let ledger = self.quarter_entry_mut(QuarterKey::from_timestamp(now));
        ledger.legal_hold_deferred_count = ledger.legal_hold_deferred_count.saturating_add(1);
        Ok(defer_until)
    }

    pub fn resolve_reidentified_subject(
        &self,
        request_id: &str,
    ) -> Result<VaultSubjectRecord, IdentityError> {
        let Some(ReidentQuorumState::Approved {
            target_org_pseudonym,
            ..
        }) = self.quorums.get(request_id)
        else {
            return Err(IdentityError::VaultState(
                "re-identification requires an Approved two-approver quorum".into(),
            ));
        };
        let Some(sealed) = self.sealed_subjects.get(target_org_pseudonym) else {
            return Err(IdentityError::VaultState(
                "target pseudonym missing from vault".into(),
            ));
        };
        let aad = self.vault_aad(target_org_pseudonym);
        let bytes = open_token(&self.vault_aead_key, VAULT_DOMAIN, &aad, sealed)
            .map_err(|e| IdentityError::VaultState(format!("vault unseal failed: {e}")))?;
        serde_json::from_slice(&bytes)
            .map_err(|e| IdentityError::VaultState(format!("vault deserialize failed: {e}")))
    }

    #[must_use]
    pub fn quarterly_disclosure_report(&self, quarter: QuarterKey) -> QuarterlyDisclosureEntry {
        self.disclosure_ledger
            .get(&quarter)
            .cloned()
            .unwrap_or(QuarterlyDisclosureEntry {
                org_id: self.org_id.clone(),
                quarter,
                requested_count: 0,
                approved_count: 0,
                legal_hold_deferred_count: 0,
                subject_disclosed_count: 0,
            })
    }

    fn step_approval(
        &mut self,
        current: ReidentQuorumState,
        request_id: &str,
        approver_id: String,
        role: ApproverRole,
        now: Timestamp,
    ) -> Result<ReidentQuorumState, IdentityError> {
        match current {
            ReidentQuorumState::Pending {
                request_id: id,
                org_id,
                requester_id,
                target_org_pseudonym,
                purpose,
                incident_ref,
                requested_at,
                expires_at,
            } => {
                if expires_at <= now {
                    self.mark_expired(request_id, id, org_id, now);
                    return Err(IdentityError::VaultState(
                        "re-identification request expired".into(),
                    ));
                }
                if approver_id == requester_id {
                    return Err(IdentityError::SelfApprovalForbidden);
                }
                Ok(ReidentQuorumState::PartialApproval {
                    request_id: id,
                    org_id,
                    requester_id,
                    target_org_pseudonym,
                    purpose,
                    incident_ref,
                    first_approver: ApproverRecord {
                        account_id: approver_id,
                        role,
                        approved_at: now,
                    },
                    requested_at,
                    expires_at,
                })
            }
            ReidentQuorumState::PartialApproval {
                request_id: id,
                org_id,
                requester_id,
                target_org_pseudonym,
                purpose,
                incident_ref,
                first_approver,
                expires_at,
                ..
            } => {
                if expires_at <= now {
                    self.mark_expired(request_id, id, org_id, now);
                    return Err(IdentityError::VaultState(
                        "re-identification request expired".into(),
                    ));
                }
                if approver_id == requester_id {
                    return Err(IdentityError::SelfApprovalForbidden);
                }
                if approver_id == first_approver.account_id {
                    return Err(IdentityError::DuplicateApprover(approver_id));
                }
                if !roles_satisfy_quorum(
                    first_approver.role,
                    role,
                    self.policy.require_works_council_coapproval,
                ) {
                    return Err(IdentityError::InsufficientApproverRole);
                }
                let second = ApproverRecord {
                    account_id: approver_id,
                    role,
                    approved_at: now,
                };
                let ledger = self.quarter_entry_mut(QuarterKey::from_timestamp(now));
                ledger.approved_count = ledger.approved_count.saturating_add(1);
                Ok(ReidentQuorumState::Approved {
                    request_id: id,
                    org_id,
                    requester_id,
                    target_org_pseudonym,
                    purpose,
                    incident_ref,
                    approvers: [first_approver, second],
                    approved_at: now,
                    disclosure: SubjectDisclosureState::PendingDisclosure,
                })
            }
            other => Err(IdentityError::VaultState(format!(
                "cannot approve quorum in state {other:?}"
            ))),
        }
    }

    fn mark_expired(&mut self, key: &str, id: String, org_id: String, now: Timestamp) {
        self.quorums.insert(
            key.to_owned(),
            ReidentQuorumState::Expired {
                request_id: id,
                org_id,
                expired_at: now,
            },
        );
    }

    fn vault_aad(&self, org_pseudonym: &str) -> Vec<u8> {
        format!("{}|{}|{org_pseudonym}", self.org_id, self.pseudonym_epoch).into_bytes()
    }

    fn quarter_entry_mut(&mut self, quarter: QuarterKey) -> &mut QuarterlyDisclosureEntry {
        let org_id = self.org_id.clone();
        self.disclosure_ledger
            .entry(quarter)
            .or_insert_with(|| QuarterlyDisclosureEntry {
                org_id,
                quarter,
                requested_count: 0,
                approved_count: 0,
                legal_hold_deferred_count: 0,
                subject_disclosed_count: 0,
            })
    }
}
