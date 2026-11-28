// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use jiff::Timestamp;
use uuid::Uuid;

use grdr_comply::{CoApproverQuorumPolicy, format_utc_quarter, validate_works_council_quorum};
use grdr_model::CodedError;
use grdr_model::error::{CODE_INVALID_INPUT, CODE_NOT_FOUND};
use grdr_proto::api::surfaces::{
    ApproveReidentificationRequest, ReidentificationRequestEntry, RequestReidentificationRequest,
};
use grdr_strings::sanitize_untrusted_text as sanitize_inert_text;

use crate::auth::AuthContext;

use super::super::AppState;
use super::super::surfaces_comply_helpers::{comply_to_coded, reid_to_proto};
use super::super::surfaces_comply_seed::ensure_compliance_seeded;
use super::super::surfaces_types::{DisclosureRecord, ReidLifecycle, ReidentificationRecord};
use super::push_compliance_audit;

impl AppState {
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
            let quorum_policy = CoApproverQuorumPolicy {
                profile: comp.privacy_profile,
                co_approver_group: comp.co_approver_group.iter().cloned().collect(),
            };
            validate_works_council_quorum(req_id, &updated_rec.approvers, &quorum_policy)
                .map_err(comply_to_coded)?;
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
                    quarter: format_utc_quarter(now),
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
