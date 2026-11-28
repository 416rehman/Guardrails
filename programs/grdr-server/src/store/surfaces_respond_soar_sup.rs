// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Server-side time-bounded finding suppressions and crash-safe SOAR orchestration (`docs/design/18`).

use grdr_core::detect::kill_switch::server_operational_limits;
use grdr_core::detect::response::KillSwitchScope;
use grdr_model::error::{CODE_CONFLICT, CODE_INVALID_INPUT, CODE_NOT_FOUND, CODE_POLICY_STEP_UP};
use grdr_model::{CodedError, Device};

use crate::store::AppState;
use crate::store::surfaces_respond_hunts::record_belongs_to_org;
use crate::store::surfaces_respond_playbooks::{
    ExecutionPrincipal, PlaybookAdvanceCtx, PlaybookMode, PlaybookPromotionProof,
    PlaybookRunJournal, PlaybookRunState, SoarPlaybookSpec, StepAdvanceOutcome,
    advance_next_pending_step, apply_blast_radius_drop, compute_soar_fleet_share_bp,
    initialize_or_validate_journal, verify_and_build_promotion_proof,
};
use crate::store::surfaces_respond_triage::{FindingSuppression, SuppressionStatus};

const DAY_SECS: i64 = 86_400;
const MAX_SUPPRESSION_WINDOW_DAYS: i64 = 30;

pub struct ApproveSuppressionRequest<'a> {
    pub org_id: &'a str,
    pub suppression_id: &'a str,
    pub finding_id: &'a str,
    pub author_id: &'a str,
    pub approver_id: &'a str,
    pub expires_at_sec: i64,
    pub now_sec: i64,
}

pub struct PromotePlaybookRequest<'a> {
    pub org_id: &'a str,
    pub spec: &'a SoarPlaybookSpec,
    pub author_id: &'a str,
    pub approver_id: &'a str,
    pub now_sec: i64,
}

pub struct RunPlaybookRequest {
    pub org_id: String,
    pub spec: SoarPlaybookSpec,
    pub principal: ExecutionPrincipal,
    pub scope: KillSwitchScope,
    pub pause_after_step_idx: Option<usize>,
    pub approve_manual_step_idx: Option<usize>,
    pub resume_run_id: Option<String>,
    pub now_sec: i64,
}

impl AppState {
    pub async fn respond_approve_suppression(
        &self,
        req: ApproveSuppressionRequest<'_>,
    ) -> Result<FindingSuppression, CodedError> {
        if req.org_id.trim().is_empty()
            || req.suppression_id.trim().is_empty()
            || req.finding_id.trim().is_empty()
        {
            return Err(CodedError::new(
                CODE_INVALID_INPUT,
                "suppression requires org_id, suppression_id, and finding_id",
                "Provide non-empty identifiers.",
            ));
        }
        if req.author_id.trim().is_empty()
            || req.approver_id.trim().is_empty()
            || req
                .author_id
                .trim()
                .eq_ignore_ascii_case(req.approver_id.trim())
        {
            return Err(CodedError::new(
                CODE_POLICY_STEP_UP,
                "suppression requires distinct second-person approver (cannot self-approve)",
                "Route suppression to a second operator.",
            ));
        }
        let cfg = server_operational_limits().map_err(|err| {
            CodedError::new(
                CODE_CONFLICT,
                format!("operational limits unavailable: {err}"),
                "Restore contracts/limits.toml.",
            )
        })?;
        let max_suppressions = usize::try_from(cfg.max_devices_default).unwrap_or(10_000);
        let max_secs = MAX_SUPPRESSION_WINDOW_DAYS.saturating_mul(DAY_SECS);
        if req.expires_at_sec <= req.now_sec
            || req.expires_at_sec.saturating_sub(req.now_sec) > max_secs
        {
            return Err(CodedError::new(
                CODE_INVALID_INPUT,
                "suppression expiry must be positive and <= 30 days",
                "Specify bounded expiry <= 30 days.",
            ));
        }
        let mut guard = self.inner.write().await;
        guard
            .respond
            .suppressions
            .retain(|s| s.status == SuppressionStatus::Active && s.expires_at_sec > req.now_sec);
        if guard.respond.suppressions.len() >= max_suppressions {
            return Err(CodedError::new(
                CODE_CONFLICT,
                "active suppression capacity reached",
                "Expire older suppressions before adding more.",
            ));
        }
        if guard
            .respond
            .suppressions
            .iter()
            .any(|s| s.suppression_id == req.suppression_id)
        {
            return Err(CodedError::new(
                CODE_CONFLICT,
                "duplicate suppression_id",
                "Use unique suppression_id.",
            ));
        }
        if guard.respond.suppressions.iter().any(|s| {
            s.org_id == req.org_id
                && s.finding_id == req.finding_id
                && s.status == SuppressionStatus::Active
                && s.expires_at_sec > req.now_sec
        }) {
            return Err(CodedError::new(
                CODE_CONFLICT,
                "overlapping active suppression already exists for finding",
                "Wait for active suppression expiry or expire it before adding another.",
            ));
        }
        let target = guard
            .findings
            .iter()
            .find(|f| f.id == req.finding_id)
            .ok_or_else(|| {
                CodedError::new(CODE_NOT_FOUND, "finding not found", "Check finding_id.")
            })?;
        if !record_belongs_to_org(
            req.org_id,
            &target.session_id,
            &target.device_id,
            &guard.respond.session_orgs,
            &guard.respond.device_orgs,
        ) {
            return Err(CodedError::new(
                CODE_NOT_FOUND,
                "finding not accessible inside tenant org_id",
                "Verify finding belongs to active org_id.",
            ));
        }
        let sup = FindingSuppression {
            suppression_id: req.suppression_id.to_owned(),
            org_id: req.org_id.to_owned(),
            finding_id: req.finding_id.to_owned(),
            author_id: req.author_id.trim().to_owned(),
            approver_id: Some(req.approver_id.trim().to_owned()),
            prior_lifecycle: target.lifecycle,
            expires_at_sec: req.expires_at_sec,
            status: SuppressionStatus::Active,
        };
        guard.respond.suppressions.push(sup.clone());
        self.persist_store(&guard)?;
        Ok(sup)
    }

    pub async fn respond_expire_suppressions(
        &self,
        org_id: &str,
        now_sec: i64,
    ) -> Result<usize, CodedError> {
        let mut guard = self.inner.write().await;
        let mut expired: usize = 0;
        for sup in &mut guard.respond.suppressions {
            if sup.org_id == org_id
                && sup.status == SuppressionStatus::Active
                && sup.expires_at_sec <= now_sec
            {
                sup.status = SuppressionStatus::Expired;
                expired = expired.saturating_add(1);
            }
        }
        self.persist_store(&guard)?;
        Ok(expired)
    }

    pub async fn respond_promote_playbook_to_live(
        &self,
        req: PromotePlaybookRequest<'_>,
    ) -> Result<PlaybookPromotionProof, CodedError> {
        let mut guard = self.inner.write().await;
        let digest = req.spec.digest_sha256()?;
        let key = format!("{digest}:{}", req.org_id);
        let sim_started = guard
            .respond
            .playbook_simulate_started
            .get(&key)
            .copied()
            .ok_or_else(|| {
                CodedError::new(
                    CODE_POLICY_STEP_UP,
                    "SOAR playbook must first run in Simulate mode before Live promotion",
                    "Execute playbook in Simulate mode and wait 7 days.",
                )
            })?;
        let proof = verify_and_build_promotion_proof(
            req.org_id,
            req.spec,
            req.author_id,
            req.approver_id,
            sim_started,
            req.now_sec,
        )?;
        guard.respond.playbook_promotions.insert(key, proof.clone());
        self.persist_store(&guard)?;
        Ok(proof)
    }

    pub async fn respond_run_playbook(
        &self,
        req: RunPlaybookRequest,
    ) -> Result<PlaybookRunJournal, CodedError> {
        let mut guard = self.inner.write().await;
        let spec_digest = req.spec.digest_sha256()?;
        let promo_key = format!("{spec_digest}:{}", req.org_id);
        let promotion_proof = guard.respond.playbook_promotions.get(&promo_key).cloned();
        let org_devices: Vec<Device> = guard
            .devices
            .iter()
            .filter(|d| {
                guard
                    .respond
                    .device_orgs
                    .get(&d.id)
                    .is_some_and(|o| o == &req.org_id)
            })
            .cloned()
            .collect();
        let fleet_share_bp = compute_soar_fleet_share_bp(&org_devices, &req.scope);
        let existing = match req.resume_run_id.as_deref() {
            Some(rid) => Some(
                guard
                    .respond
                    .playbook_runs
                    .iter()
                    .find(|r| r.run_id == rid)
                    .cloned()
                    .ok_or_else(|| {
                        CodedError::new(
                            CODE_CONFLICT,
                            "playbook run_id missing",
                            "Start run first.",
                        )
                    })?,
            ),
            None => None,
        };
        let ctx = PlaybookAdvanceCtx {
            org_id: &req.org_id,
            spec: &req.spec,
            principal: req.principal,
            scope: &req.scope,
            fleet_share_bp,
            approve_manual_step_idx: req.approve_manual_step_idx,
            promotion_proof: promotion_proof.as_ref(),
        };
        let mut journal = initialize_or_validate_journal(&ctx, existing.as_ref())?;
        if req.spec.mode == PlaybookMode::Simulate {
            if !guard
                .respond
                .playbook_simulate_started
                .contains_key(&promo_key)
                && guard.respond.playbook_simulate_started.len() >= 1_000
                && let Some(old_k) = guard
                    .respond
                    .playbook_simulate_started
                    .iter()
                    .min_by_key(|(_, ts)| **ts)
                    .map(|(k, _)| k.clone())
            {
                guard.respond.playbook_simulate_started.remove(&old_k);
            }
            guard
                .respond
                .playbook_simulate_started
                .entry(promo_key)
                .or_insert(req.now_sec);
        }
        upsert_playbook_run(&mut guard.respond.playbook_runs, &journal)?;
        self.persist_store(&guard)?;

        if apply_blast_radius_drop(&mut journal, &ctx, &mut guard.findings) {
            upsert_playbook_run(&mut guard.respond.playbook_runs, &journal)?;
            self.persist_store(&guard)?;
            return Ok(journal);
        }

        loop {
            match advance_next_pending_step(&mut journal, &ctx)? {
                StepAdvanceOutcome::Executed(step_idx) => {
                    upsert_playbook_run(&mut guard.respond.playbook_runs, &journal)?;
                    self.persist_store(&guard)?;
                    if req.pause_after_step_idx == Some(step_idx) {
                        return Ok(journal);
                    }
                }
                StepAdvanceOutcome::PausedForManual | StepAdvanceOutcome::Finished => {
                    upsert_playbook_run(&mut guard.respond.playbook_runs, &journal)?;
                    self.persist_store(&guard)?;
                    return Ok(journal);
                }
            }
        }
    }
}

fn upsert_playbook_run(
    runs: &mut Vec<PlaybookRunJournal>,
    journal: &PlaybookRunJournal,
) -> Result<(), CodedError> {
    if let Some(slot) = runs.iter_mut().find(|r| r.run_id == journal.run_id) {
        *slot = journal.clone();
        return Ok(());
    }
    if runs.len() >= 1_000 {
        if let Some(pos) = runs.iter().position(|r| {
            matches!(
                r.state,
                PlaybookRunState::Completed
                    | PlaybookRunState::Simulated
                    | PlaybookRunState::DroppedToSimulateAndCompensated
            )
        }) {
            runs.remove(pos);
        } else {
            return Err(CodedError::new(
                CODE_CONFLICT,
                "active playbook run capacity reached",
                "Finish or cancel paused/running playbooks before starting more.",
            ));
        }
    }
    runs.push(journal.clone());
    Ok(())
}
