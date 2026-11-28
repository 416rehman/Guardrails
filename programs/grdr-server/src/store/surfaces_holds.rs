// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeSet;

use jiff::Timestamp;
use uuid::Uuid;

use grdr_comply::{
    CoApproverQuorumPolicy, HoldNotice, HoldScope, HoldsLedger, PlaceHoldInput, format_utc_quarter,
    validate_works_council_quorum,
};
use grdr_model::error::{CODE_INVALID_INPUT, CODE_NOT_FOUND};
use grdr_model::{AuditEntry, CodedError};
use grdr_proto::api::surfaces::{ApproveLegalHoldRequest, CreateLegalHoldRequest, LegalHoldEntry};
use grdr_strings::sanitize_untrusted_text as sanitize_inert_text;

use crate::auth::AuthContext;

use super::surfaces_comply_helpers::comply_to_coded;
use super::surfaces_comply_seed::ensure_compliance_seeded;
use super::surfaces_types::{DisclosureRecord, PendingLegalHoldRecord};
use super::{AppState, StoreData};

#[path = "surfaces_reid.rs"]
mod reid;

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
        let (pseudonyms, session_ids) = resolve_hold_targets(&guard, &target_ref);

        let rec = PendingLegalHoldRecord {
            hold_id: hold_id.clone(),
            organisation: auth.tenant_id.clone(),
            matter_ref: matter_ref.clone(),
            reason: reason.clone(),
            target_ref: target_ref.clone(),
            pseudonyms,
            session_ids,
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
        let quorum_policy = CoApproverQuorumPolicy {
            profile: comp.privacy_profile,
            co_approver_group: comp.co_approver_group.iter().cloned().collect(),
        };
        let distinct_approvers = validate_works_council_quorum(hold_id, &approvers, &quorum_policy)
            .map_err(comply_to_coded)?;

        let (live_pseudonyms, live_sessions) = resolve_hold_targets(&guard, &pending.target_ref);
        let mut pseudonyms = pending.pseudonyms.clone();
        for ps in live_pseudonyms {
            if !pseudonyms.contains(&ps) {
                pseudonyms.push(ps);
            }
        }
        let mut session_ids = pending.session_ids.clone();
        for sid in live_sessions {
            if !session_ids.contains(&sid) {
                session_ids.push(sid);
            }
        }
        if pseudonyms.is_empty() && session_ids.is_empty() {
            pseudonyms.push(pending.target_ref.clone());
            session_ids.push(pending.target_ref.clone());
        }

        let hold = ledger
            .place_hold(PlaceHoldInput {
                organisation: pending.organisation.clone(),
                scope: HoldScope {
                    pseudonyms,
                    session_ids,
                    incident_id: None,
                    classes: vec!["decision".to_owned(), "audit".to_owned()],
                    from: None,
                    to: None,
                },
                matter_ref: pending.matter_ref.clone(),
                reason: pending.reason.clone(),
                created_by: pending.created_by.clone(),
                approvers: distinct_approvers,
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
                    quarter: format_utc_quarter(now),
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

    // Awaits W5 proto/RPC surface exposure outside surfaces_holds ownership.
    #[allow(dead_code)]
    pub async fn release_legal_hold(
        &self,
        hold_id: &str,
        approvers: &[String],
        reason: &str,
        auth: &AuthContext,
    ) -> Result<(LegalHoldEntry, usize), CodedError> {
        let now = Timestamp::now();
        let trimmed_id = hold_id.trim();
        let clean_reason = sanitize_inert_text(reason.trim());
        if trimmed_id.is_empty() || clean_reason.is_empty() {
            return Err(CodedError::new(
                CODE_INVALID_INPUT,
                "Hold identifier and release rationale are required.",
                "Provide hold_id and non-empty release reason.",
            ));
        }
        if !approvers
            .iter()
            .any(|a| a.trim().eq_ignore_ascii_case(&auth.principal_id))
        {
            return Err(CodedError::new(
                CODE_INVALID_INPUT,
                "Authenticated principal must participate in dual-approver hold release.",
                "Include the active principal and a second distinct co-approver.",
            ));
        }

        let mut guard = self.inner.write().await;
        ensure_compliance_seeded(&mut guard, now);

        let (profile, co_approver_group, existing_holds) = {
            let comp = guard.surfaces.compliance.as_ref().ok_or_else(|| {
                CodedError::new(CODE_NOT_FOUND, "Compliance state uninitialized.", "Reload.")
            })?;
            (
                comp.privacy_profile,
                comp.co_approver_group.iter().cloned().collect(),
                comp.legal_holds.clone(),
            )
        };
        let quorum_policy = CoApproverQuorumPolicy {
            profile,
            co_approver_group,
        };
        let distinct_approvers =
            validate_works_council_quorum(trimmed_id, approvers, &quorum_policy)
                .map_err(comply_to_coded)?;

        let mut ledger = HoldsLedger {
            holds: existing_holds,
        };
        let released = ledger
            .release_hold(
                &auth.tenant_id,
                trimmed_id,
                &distinct_approvers,
                &clean_reason,
                now,
            )
            .map_err(comply_to_coded)?
            .clone();

        // Execute post-hold DSAR cascade atomically before persisting hold release.
        let reprocessed = self
            .reprocess_held_erasures_with_holds(&mut guard, &ledger, auth, now)
            .await?;

        let scope_summary = if released.scope.pseudonyms.is_empty() {
            released.scope.session_ids.join(", ")
        } else {
            released.scope.pseudonyms.join(", ")
        };
        if let Some(ref mut comp) = guard.surfaces.compliance {
            comp.legal_holds = ledger.holds;
            comp.disclosures.insert(
                0,
                DisclosureRecord {
                    id: format!("disc_{}", Uuid::now_v7().simple()),
                    organisation: auth.tenant_id.clone(),
                    kind: "legal_hold_release".to_owned(),
                    actor: distinct_approvers.join(" + "),
                    target_ref: scope_summary.clone(),
                    legal_basis: released.matter_ref.clone(),
                    timestamp: now.to_string(),
                    quarter: format_utc_quarter(now),
                    summary: format!(
                        "Legal hold {} released; reprocessed {reprocessed} held DSAR(s)",
                        released.hold_id
                    ),
                },
            );
        }
        push_compliance_audit(
            &mut guard,
            now,
            "compliance.hold.released",
            auth.principal_id.clone(),
            format!(
                "Released legal hold {} ({reprocessed} held erasure(s) reprocessed)",
                released.hold_id
            ),
            released.hold_id.clone(),
        );
        self.persist_store(&guard)?;

        let entry = LegalHoldEntry {
            hold_id: released.hold_id,
            matter_ref: released.matter_ref,
            reason: released.reason,
            lifecycle: "released".to_owned(),
            created_by: released.created_by,
            approvers: released.approvers,
            created_at: released.created_at.to_string(),
            review_by: released.review_by.to_string(),
            notice_mode: "immediate".to_owned(),
            scope_summary,
        };
        Ok((entry, reprocessed))
    }
}

fn resolve_hold_targets(data: &StoreData, target_ref: &str) -> (Vec<String>, Vec<String>) {
    let target = target_ref.trim();
    let mut known_sessions = BTreeSet::new();
    for att in &data.attempts {
        known_sessions.insert(att.session_id.as_str());
    }
    for rcp in &data.receipts {
        known_sessions.insert(rcp.session_id.as_str());
    }
    for apr in &data.approvals {
        known_sessions.insert(apr.session_id.as_str());
    }
    for gr in &data.grants {
        known_sessions.insert(gr.session_id.as_str());
    }
    for f in &data.findings {
        known_sessions.insert(f.session_id.as_str());
    }

    let mut pseudonyms = BTreeSet::new();
    let mut session_ids = BTreeSet::new();
    if known_sessions.contains(target) || target.starts_with("sess") || target.starts_with("ses_") {
        session_ids.insert(target.to_owned());
    }
    for u in &data.user_directory {
        if (u.id == target || u.email == target || u.pseudonym_id == target)
            && !u.pseudonym_id.is_empty()
        {
            pseudonyms.insert(u.pseudonym_id.clone());
        }
    }
    if target.starts_with("prn_") {
        pseudonyms.insert(target.to_owned());
    }
    if pseudonyms.is_empty() && session_ids.is_empty() && !target.is_empty() {
        pseudonyms.insert(target.to_owned());
        session_ids.insert(target.to_owned());
    }
    (
        pseudonyms.into_iter().collect(),
        session_ids.into_iter().collect(),
    )
}
