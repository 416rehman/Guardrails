// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use jiff::Timestamp;
use uuid::Uuid;

use grdr_comply::{HoldNotice, HoldScope, HoldsLedger, PlaceHoldInput};
use grdr_model::error::{CODE_INVALID_INPUT, CODE_NOT_FOUND};
use grdr_model::{AuditEntry, CodedError};
use grdr_proto::api::surfaces::{
    ApproveLegalHoldRequest, ApproveReidentificationRequest, CreateLegalHoldRequest,
    LegalHoldEntry, ReidentificationRequestEntry, RequestReidentificationRequest,
};
use grdr_strings::sanitize_untrusted_text as sanitize_inert_text;

use crate::auth::AuthContext;

use super::AppState;
use super::surfaces_comply_helpers::{comply_to_coded, reid_to_proto};
use super::surfaces_comply_seed::ensure_compliance_seeded;
use super::surfaces_types::{
    DisclosureRecord, PendingLegalHoldRecord, ReidLifecycle, ReidentificationRecord,
};

const SECONDS_PER_DAY: i64 = 86_400;

pub(crate) fn push_compliance_audit(
    guard: &mut super::StoreData,
    now: Timestamp,
    kind: &str,
    actor: String,
    summary: String,
    target: String,
) {
    guard.audit.insert(
        0,
        AuditEntry {
            id: format!("aud_{}", Uuid::now_v7().simple()),
            timestamp: now,
            kind: kind.to_owned(),
            actor,
            summary,
            target,
        },
    );
}

impl AppState {
    pub async fn create_legal_hold(
        &self,
        req: CreateLegalHoldRequest,
        auth: &AuthContext,
    ) -> Result<LegalHoldEntry, CodedError> {
        let now = Timestamp::now();
        let target_ref = sanitize_inert_text(req.pseudonym_or_session.trim());
        let matter_ref = sanitize_inert_text(req.matter_ref.trim());
        let reason = sanitize_inert_text(req.reason.trim());
        if target_ref.is_empty() || matter_ref.is_empty() || reason.is_empty() {
            return Err(CodedError::new(
                CODE_INVALID_INPUT,
                "Matter reference, target reference, and rationale are required for legal holds.",
                "Provide matter reference, scope target, and reason before submitting.",
            ));
        }

        let actor = auth.principal_id.clone();
        let review_by =
            Timestamp::from_second(now.as_second().saturating_add(90 * SECONDS_PER_DAY))
                .unwrap_or(now);
        let hold_id = format!("hold_{}", Uuid::now_v7().simple());

        let mut guard = self.inner.write().await;
        ensure_compliance_seeded(&mut guard, now);

        let rec = PendingLegalHoldRecord {
            hold_id: hold_id.clone(),
            organisation: auth.tenant_id.clone(),
            matter_ref: matter_ref.clone(),
            reason: reason.clone(),
            target_ref: target_ref.clone(),
            created_by: actor.clone(),
            approvers: vec![actor.clone()],
            created_at: now.to_string(),
            review_by: review_by.to_string(),
        };

        if let Some(ref mut comp) = guard.surfaces.compliance {
            comp.pending_holds.insert(0, rec.clone());
        }
        push_compliance_audit(
            &mut guard,
            now,
            "compliance.hold.proposed",
            actor,
            format!("Proposed legal hold {hold_id} for {target_ref} (1/2 quorum)"),
            hold_id.clone(),
        );
        self.persist_store(&guard)?;

        Ok(LegalHoldEntry {
            hold_id,
            matter_ref,
            reason,
            lifecycle: "pending_quorum".to_owned(),
            created_by: rec.created_by,
            approvers: rec.approvers,
            created_at: rec.created_at,
            review_by: rec.review_by,
            notice_mode: "immediate".to_owned(),
            scope_summary: target_ref,
        })
    }

    pub async fn approve_legal_hold(
        &self,
        req: ApproveLegalHoldRequest,
        auth: &AuthContext,
    ) -> Result<LegalHoldEntry, CodedError> {
        let now = Timestamp::now();
        let hold_id = req.hold_id.trim();
        if hold_id.is_empty() {
            return Err(CodedError::new(
                CODE_INVALID_INPUT,
                "Hold identifier is required.",
                "Select a pending legal hold to co-sign.",
            ));
        }

        let mut guard = self.inner.write().await;
        ensure_compliance_seeded(&mut guard, now);
        let comp = guard.surfaces.compliance.as_ref().ok_or_else(|| {
            CodedError::new(CODE_NOT_FOUND, "Compliance state uninitialized.", "Reload.")
        })?;
        let idx = comp
            .pending_holds
            .iter()
            .position(|h| h.hold_id == hold_id && h.organisation == auth.tenant_id)
            .ok_or_else(|| {
                CodedError::new(
                    CODE_NOT_FOUND,
                    format!("Pending legal hold `{hold_id}` was not found."),
                    "Verify the hold identifier or refresh Compliance.",
                )
            })?;
        let pending =
            comp.pending_holds.get(idx).cloned().ok_or_else(|| {
                CodedError::new(CODE_NOT_FOUND, "Pending hold missing.", "Reload.")
            })?;

        if pending.created_by.eq_ignore_ascii_case(&auth.principal_id)
            || pending
                .approvers
                .iter()
                .any(|a| a.eq_ignore_ascii_case(&auth.principal_id))
        {
            return Err(CodedError::new(
                CODE_INVALID_INPUT,
                "Initiator cannot co-sign their own legal hold; two distinct authenticated principals are required.",
                "Have a second distinct approver co-sign this legal hold.",
            ));
        }

        let mut ledger = HoldsLedger {
            holds: comp.legal_holds.clone(),
        };
        let review_ts = pending.review_by.parse::<Timestamp>().unwrap_or_else(|_| {
            Timestamp::from_second(now.as_second().saturating_add(90 * SECONDS_PER_DAY))
                .unwrap_or(now)
        });
        let created_ts = pending.created_at.parse::<Timestamp>().unwrap_or(now);
        let mut approvers = pending.approvers.clone();
        approvers.push(auth.principal_id.clone());

        let hold = ledger
            .place_hold(PlaceHoldInput {
                organisation: pending.organisation.clone(),
                scope: HoldScope {
                    pseudonyms: vec![pending.target_ref.clone()],
                    session_ids: Vec::new(),
                    incident_id: None,
                    classes: vec!["decision".to_owned(), "audit".to_owned()],
                    from: None,
                    to: None,
                },
                matter_ref: pending.matter_ref.clone(),
                reason: pending.reason.clone(),
                created_by: pending.created_by.clone(),
                approvers,
                created_at: created_ts,
                review_by: review_ts,
                notice: HoldNotice::Immediate,
            })
            .map_err(comply_to_coded)?;

        if let Some(ref mut comp_mut) = guard.surfaces.compliance {
            comp_mut.pending_holds.remove(idx);
            comp_mut.legal_holds = ledger.holds;
            comp_mut.disclosures.insert(
                0,
                DisclosureRecord {
                    id: format!("disc_{}", Uuid::now_v7().simple()),
                    organisation: pending.organisation.clone(),
                    kind: "legal_hold".to_owned(),
                    actor: format!("{} + {}", pending.created_by, auth.principal_id),
                    target_ref: pending.target_ref.clone(),
                    legal_basis: hold.matter_ref.clone(),
                    timestamp: now.to_string(),
                    quarter: "2026-Q4".to_owned(),
                    summary: format!(
                        "Legal hold {} activated by dual approvers {} & {}",
                        hold.hold_id, pending.created_by, auth.principal_id
                    ),
                },
            );
        }

        push_compliance_audit(
            &mut guard,
            now,
            "compliance.hold.created",
            auth.principal_id.clone(),
            format!(
                "Co-signed and activated legal hold {} on {}",
                hold.hold_id, pending.target_ref
            ),
            hold.hold_id.clone(),
        );
        self.persist_store(&guard)?;

        Ok(LegalHoldEntry {
            hold_id: hold.hold_id,
            matter_ref: hold.matter_ref,
            reason: hold.reason,
            lifecycle: "active".to_owned(),
            created_by: hold.created_by,
            approvers: hold.approvers,
            created_at: hold.created_at.to_string(),
            review_by: hold.review_by.to_string(),
            notice_mode: "immediate".to_owned(),
            scope_summary: pending.target_ref,
        })
    }

    pub async fn request_reidentification(
        &self,
        req: RequestReidentificationRequest,
        auth: &AuthContext,
    ) -> Result<ReidentificationRequestEntry, CodedError> {
        let now = Timestamp::now();
        let pseudonym = sanitize_inert_text(req.pseudonym_id.trim());
        let requester = auth.principal_id.clone();
        let reason = sanitize_inert_text(req.reason.trim());
        let legal_basis = sanitize_inert_text(req.legal_basis.trim());
        if pseudonym.is_empty() || reason.is_empty() || legal_basis.is_empty() {
            return Err(CodedError::new(
                CODE_INVALID_INPUT,
                "Pseudonym, reason, and legal basis are required for re-identification.",
                "Complete all quorum justification fields.",
            ));
        }

        let mut guard = self.inner.write().await;
        ensure_compliance_seeded(&mut guard, now);

        let rec = ReidentificationRecord {
            request_id: format!("reid_{}", Uuid::now_v7().simple()),
            organisation: auth.tenant_id.clone(),
            pseudonym_id: pseudonym.clone(),
            requester: requester.clone(),
            reason,
            legal_basis,
            status: ReidLifecycle::PendingQuorum,
            approvers: Vec::new(),
            resolved_identity: None,
            created_at: now.to_string(),
            resolved_at: None,
        };

        if let Some(ref mut comp) = guard.surfaces.compliance {
            comp.reid_requests.insert(0, rec.clone());
        }
        push_compliance_audit(
            &mut guard,
            now,
            "privacy.reidentification.requested",
            requester,
            format!("Requested two-approver re-identification for {pseudonym}"),
            rec.request_id.clone(),
        );
        self.persist_store(&guard)?;
        Ok(reid_to_proto(&rec))
    }

    pub async fn approve_reidentification(
        &self,
        req: ApproveReidentificationRequest,
        auth: &AuthContext,
    ) -> Result<ReidentificationRequestEntry, CodedError> {
        let now = Timestamp::now();
        let req_id = req.request_id.trim();
        let approver = auth.principal_id.clone();
        if req_id.is_empty() {
            return Err(CodedError::new(
                CODE_INVALID_INPUT,
                "Request identifier is required.",
                "Supply a valid request ID.",
            ));
        }

        let mut guard = self.inner.write().await;
        ensure_compliance_seeded(&mut guard, now);

        let directory_clone = guard.user_directory.clone();
        let comp = guard.surfaces.compliance.as_mut().ok_or_else(|| {
            CodedError::new(
                CODE_NOT_FOUND,
                "Compliance workspace not initialized.",
                "Reload settings.",
            )
        })?;
        let idx = comp
            .reid_requests
            .iter()
            .position(|r| r.request_id == req_id && r.organisation == auth.tenant_id)
            .ok_or_else(|| {
                CodedError::new(
                    CODE_NOT_FOUND,
                    format!("Re-identification request `{req_id}` was not found."),
                    "Refresh Settings and retry.",
                )
            })?;

        let existing = comp.reid_requests.get(idx).ok_or_else(|| {
            CodedError::new(CODE_NOT_FOUND, "Missing request record.", "Refresh.")
        })?;
        if approver.eq_ignore_ascii_case(&existing.requester) {
            return Err(CodedError::new(
                CODE_INVALID_INPUT,
                "Requester cannot approve their own re-identification request.",
                "Select a separate Security or Legal approver.",
            ));
        }
        if existing
            .approvers
            .iter()
            .any(|a| a.eq_ignore_ascii_case(&approver))
        {
            return Err(CodedError::new(
                CODE_INVALID_INPUT,
                "Duplicate approver: two distinct approvers are required.",
                "Ask a second distinct approver to sign off.",
            ));
        }

        let mut updated_rec = existing.clone();
        updated_rec.approvers.push(approver.clone());
        let mut newly_resolved = false;
        if updated_rec.approvers.len() >= 2 && updated_rec.status != ReidLifecycle::Approved {
            updated_rec.status = ReidLifecycle::Approved;
            updated_rec.resolved_at = Some(now.to_string());
            let matched = directory_clone
                .iter()
                .find(|u| {
                    u.pseudonym_id == updated_rec.pseudonym_id || u.id == updated_rec.pseudonym_id
                })
                .map(|u| format!("{} <{}>", u.display_name, u.email))
                .unwrap_or_else(|| format!("Resolved Principal ({})", updated_rec.pseudonym_id));
            updated_rec.resolved_identity = Some(matched);
            newly_resolved = true;
        }

        if let Some(slot) = comp.reid_requests.get_mut(idx) {
            *slot = updated_rec.clone();
        }
        if newly_resolved {
            comp.disclosures.insert(
                0,
                DisclosureRecord {
                    id: format!("disc_{}", Uuid::now_v7().simple()),
                    organisation: auth.tenant_id.clone(),
                    kind: "reidentification".to_owned(),
                    actor: updated_rec.approvers.join(" + "),
                    target_ref: updated_rec.pseudonym_id.clone(),
                    legal_basis: updated_rec.legal_basis.clone(),
                    timestamp: now.to_string(),
                    quarter: "2026-Q4".to_owned(),
                    summary: format!(
                        "Two-approver quorum completed for {}",
                        updated_rec.pseudonym_id
                    ),
                },
            );
        }

        push_compliance_audit(
            &mut guard,
            now,
            "privacy.reidentification.approved",
            approver,
            format!(
                "Approval {}/2 recorded for {}",
                updated_rec.approvers.len(),
                updated_rec.pseudonym_id
            ),
            updated_rec.request_id.clone(),
        );
        self.persist_store(&guard)?;
        Ok(reid_to_proto(&updated_rec))
    }
}
