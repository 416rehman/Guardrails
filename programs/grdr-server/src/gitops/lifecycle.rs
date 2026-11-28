// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use grdr_model::error::CODE_POLICY_DENIED;
use grdr_proto::common::ErrorClass;
use jiff::Timestamp;

use crate::auth::AuthContext;
use crate::connect_error::{ApiError, ApiErrorInner, ConnectCode};
use crate::store::AppState;

use super::binding::{apply_packs_to_store, failed_precondition, not_found_change};
use super::operations::agent_propose_only_err;
use super::store::GitopsStore;
use super::types::{
    ApproveChangeRequest, DenyChangeRequest, PolicyChangeRecord, PolicyChangeState, ProposerKind,
};

impl GitopsStore {
    pub async fn approve_change(
        &self,
        app_state: &AppState,
        auth: &AuthContext,
        change_id: &str,
        req: ApproveChangeRequest,
    ) -> Result<PolicyChangeRecord, ApiError> {
        if Self::is_agent_lineage(auth) {
            return Err(agent_propose_only_err(
                "AgentSession identities cannot approve PolicyChanges.",
                "Require a human operator approval via Console or CLI.",
            ));
        }
        if !auth.allows_scope("policy:approve") {
            return Err(ApiError::new(ApiErrorInner {
                code: ConnectCode::PermissionDenied,
                grdr_code: CODE_POLICY_DENIED.into(),
                reason: "MISSING_APPROVE_SCOPE".into(),
                class: ErrorClass::Permission,
                message: "Approving a PolicyChange requires `policy:approve` scope.".into(),
                fix: "Authenticate with a principal carrying `policy:approve`.".into(),
                metadata: BTreeMap::new(),
            }));
        }
        self.ensure_unlocked_tenant(&auth.tenant_id).await?;
        let rec = self.get_change(auth, change_id).await?;
        if rec.proposer_id == auth.principal_id {
            return Err(ApiError::new(ApiErrorInner {
                code: ConnectCode::PermissionDenied,
                grdr_code: CODE_POLICY_DENIED.into(),
                reason: "PROPOSER_SELF_APPROVAL_FORBIDDEN".into(),
                class: ErrorClass::Permission,
                message: "PolicyChange proposer cannot self-approve their own change.".into(),
                fix: "Request approval from a distinct second reviewer.".into(),
                metadata: BTreeMap::new(),
            }));
        }
        if rec.state != PolicyChangeState::AwaitingApproval
            && rec.state != PolicyChangeState::Checked
        {
            return Err(failed_precondition(
                "INVALID_CHANGE_STATE",
                "Only checked or awaiting-approval PolicyChanges can be approved.",
            ));
        }
        let needs_step_up = rec.proposer_kind == ProposerKind::AgentSession
            || rec
                .diff
                .as_ref()
                .is_some_and(|d| d.is_widening || d.promotes_enforcement);
        if needs_step_up && !auth.confirmation.is_step_up() {
            return Err(ApiError::new(ApiErrorInner {
                code: ConnectCode::PermissionDenied,
                grdr_code: CODE_POLICY_DENIED.into(),
                reason: "STEP_UP_REQUIRED".into(),
                class: ErrorClass::Permission,
                message: "Widening, enforcing, or AgentSession PolicyChange approval requires step-up authentication.".into(),
                fix: "Authenticate with step-up confirmation and retry.".into(),
                metadata: BTreeMap::new(),
            }));
        }
        let note = (!req.note.trim().is_empty()).then_some(req.note.trim());
        self.commit_rollout(app_state, auth, change_id, note).await
    }

    pub async fn deny_change(
        &self,
        auth: &AuthContext,
        change_id: &str,
        req: DenyChangeRequest,
    ) -> Result<PolicyChangeRecord, ApiError> {
        if Self::is_agent_lineage(auth) {
            return Err(failed_precondition(
                "AGENT_SESSION_PROPOSE_ONLY",
                "AgentSession cannot deny PolicyChanges.",
            ));
        }
        let mut guard = self.inner.write().await;
        let slot = guard
            .changes
            .get_mut(change_id)
            .filter(|c| c.tenant_id == auth.tenant_id)
            .ok_or_else(|| not_found_change(change_id))?;
        if matches!(
            slot.state,
            PolicyChangeState::Applied | PolicyChangeState::Denied | PolicyChangeState::Superseded
        ) {
            return Err(failed_precondition(
                "INVALID_CHANGE_STATE",
                "Terminal PolicyChange cannot be denied.",
            ));
        }
        slot.state = PolicyChangeState::Denied;
        slot.denied_by = Some(auth.principal_id.clone());
        slot.denied_reason = Some(req.reason);
        slot.updated_at = Timestamp::now().to_string();
        Ok(slot.clone())
    }

    pub async fn cancel_change(
        &self,
        auth: &AuthContext,
        change_id: &str,
    ) -> Result<PolicyChangeRecord, ApiError> {
        if Self::is_agent_lineage(auth) {
            return Err(failed_precondition(
                "AGENT_SESSION_PROPOSE_ONLY",
                "AgentSession cannot cancel PolicyChanges.",
            ));
        }
        let mut guard = self.inner.write().await;
        let slot = guard
            .changes
            .get_mut(change_id)
            .filter(|c| c.tenant_id == auth.tenant_id)
            .ok_or_else(|| not_found_change(change_id))?;
        if matches!(
            slot.state,
            PolicyChangeState::Applied
                | PolicyChangeState::Denied
                | PolicyChangeState::Superseded
                | PolicyChangeState::Failed
        ) {
            return Err(failed_precondition(
                "INVALID_CHANGE_STATE",
                "Terminal or failed PolicyChange cannot be cancelled.",
            ));
        }
        slot.state = match slot.state {
            PolicyChangeState::RollingOut => PolicyChangeState::Halted,
            _ => PolicyChangeState::Superseded,
        };
        slot.updated_at = Timestamp::now().to_string();
        Ok(slot.clone())
    }

    pub async fn resume_change(
        &self,
        app_state: &AppState,
        auth: &AuthContext,
        change_id: &str,
    ) -> Result<PolicyChangeRecord, ApiError> {
        if Self::is_agent_lineage(auth) {
            return Err(agent_propose_only_err(
                "AgentSession cannot resume PolicyChanges.",
                "Require a human operator.",
            ));
        }
        self.ensure_unlocked_tenant(&auth.tenant_id).await?;
        let rec = self.get_change(auth, change_id).await?;
        if rec.state != PolicyChangeState::Halted {
            return Err(failed_precondition(
                "CHANGE_NOT_HALTED",
                "Only halted PolicyChanges can be resumed.",
            ));
        }
        let needs_step_up = rec.proposer_kind == ProposerKind::AgentSession
            || rec
                .diff
                .as_ref()
                .is_some_and(|d| d.is_widening || d.promotes_enforcement);
        if needs_step_up && !auth.confirmation.is_step_up() {
            return Err(ApiError::new(ApiErrorInner {
                code: ConnectCode::PermissionDenied,
                grdr_code: CODE_POLICY_DENIED.into(),
                reason: "STEP_UP_REQUIRED".into(),
                class: ErrorClass::Permission,
                message: "Resuming widening or enforcing PolicyChanges requires step-up auth."
                    .into(),
                fix: "Authenticate with step-up confirmation and retry.".into(),
                metadata: BTreeMap::new(),
            }));
        }
        self.commit_rollout(app_state, auth, change_id, None).await
    }

    pub(crate) async fn commit_rollout(
        &self,
        app_state: &AppState,
        auth: &AuthContext,
        change_id: &str,
        note: Option<&str>,
    ) -> Result<PolicyChangeRecord, ApiError> {
        let (candidate_packs, is_narrowing) = {
            let guard = self.inner.read().await;
            let rec = guard
                .changes
                .get(change_id)
                .filter(|c| c.tenant_id == auth.tenant_id)
                .ok_or_else(|| not_found_change(change_id))?;
            let packs = guard
                .candidate_packs
                .get(change_id)
                .cloned()
                .ok_or_else(|| {
                    failed_precondition(
                        "CHECK_REQUIRED",
                        "PolicyChange must be checked before applying.",
                    )
                })?;
            let narrowing = rec
                .diff
                .as_ref()
                .is_some_and(|d| !d.is_widening && !d.promotes_enforcement);
            (packs, narrowing)
        };
        let audit_summary = match note {
            Some(text) => format!("Applied PolicyChange {change_id}: {text}"),
            None => format!("Applied PolicyChange {change_id}"),
        };
        apply_packs_to_store(
            app_state,
            candidate_packs,
            &auth.principal_id,
            &audit_summary,
            None,
        )
        .await;

        let now = Timestamp::now().to_string();
        let mut guard = self.inner.write().await;
        let slot = guard
            .changes
            .get_mut(change_id)
            .filter(|c| c.tenant_id == auth.tenant_id)
            .ok_or_else(|| not_found_change(change_id))?;
        slot.rollout_ring = Some(1);
        slot.approved_by = Some(auth.principal_id.clone());
        slot.state = if is_narrowing {
            PolicyChangeState::RollingOut
        } else {
            PolicyChangeState::Applied
        };
        slot.updated_at = now;
        Ok(slot.clone())
    }
}
