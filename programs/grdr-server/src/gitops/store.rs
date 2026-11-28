// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;
use std::sync::Arc;

use grdr_jobs::SqliteJobJournal;
use grdr_model::PolicyPack;
use jiff::Timestamp;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::auth::AuthContext;
use crate::connect_error::ApiError;
use crate::routes::rest::limits::rest_limits;
use crate::store::AppState;

use super::binding::{failed_precondition, invalid_arg, not_found_change};
use super::diff::compute_policy_diff;
use super::operations::{agent_propose_only_err, gitops_locked_err};
use super::simulate::run_four_bucket_simulation;
use super::types::{
    CreatePolicyChangeRequest, GitopsBinding, GitopsSourceKind, PolicyChangeRecord,
    PolicyChangeState, ProposerKind,
};

#[derive(Debug, Default)]
pub(crate) struct GitopsStoreInner {
    pub(crate) changes: BTreeMap<String, PolicyChangeRecord>,
    pub(crate) candidate_packs: BTreeMap<String, Vec<PolicyPack>>,
    pub(crate) bindings: BTreeMap<String, GitopsBinding>,
    pub(crate) cancelled_operations: BTreeMap<(String, String), i64>,
}

#[derive(Clone)]
pub struct GitopsStore {
    pub(crate) inner: Arc<RwLock<GitopsStoreInner>>,
    jobs: Option<Arc<SqliteJobJournal>>,
}

impl Default for GitopsStore {
    fn default() -> Self {
        Self::new(SqliteJobJournal::open_in_memory().ok().map(Arc::new))
    }
}

impl GitopsStore {
    pub fn new(jobs: Option<Arc<SqliteJobJournal>>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(GitopsStoreInner::default())),
            jobs,
        }
    }

    pub fn jobs(&self) -> Option<&Arc<SqliteJobJournal>> {
        self.jobs.as_ref()
    }

    pub fn is_agent_lineage(auth: &AuthContext) -> bool {
        auth.principal_id.starts_with("agent:")
            || auth.principal_id.starts_with("session:")
            || auth
                .scopes
                .iter()
                .any(|s| s.starts_with("mcp:") || s == "agent:session")
    }

    pub async fn require_unlocked_for_direct_write(
        &self,
        auth: &AuthContext,
    ) -> Result<(), ApiError> {
        if Self::is_agent_lineage(auth) {
            return Err(agent_propose_only_err(
                "AgentSession identities may only propose changes; direct writes are blocked.",
                "Use propose_policy_change / POST /v1/policy-changes and await human approval.",
            ));
        }
        let guard = self.inner.read().await;
        if let Some(binding) = guard.bindings.get(&auth.tenant_id)
            && binding.source != GitopsSourceKind::None
        {
            return Err(gitops_locked_err(binding));
        }
        Ok(())
    }

    pub(crate) async fn ensure_unlocked_tenant(&self, tenant_id: &str) -> Result<(), ApiError> {
        let guard = self.inner.read().await;
        if let Some(binding) = guard.bindings.get(tenant_id)
            && binding.source != GitopsSourceKind::None
        {
            return Err(gitops_locked_err(binding));
        }
        Ok(())
    }

    pub async fn list_changes(&self, auth: &AuthContext) -> Vec<PolicyChangeRecord> {
        self.inner
            .read()
            .await
            .changes
            .values()
            .filter(|c| c.tenant_id == auth.tenant_id)
            .cloned()
            .collect()
    }

    pub async fn get_change(
        &self,
        auth: &AuthContext,
        change_id: &str,
    ) -> Result<PolicyChangeRecord, ApiError> {
        self.inner
            .read()
            .await
            .changes
            .get(change_id)
            .filter(|c| c.tenant_id == auth.tenant_id)
            .cloned()
            .ok_or_else(|| not_found_change(change_id))
    }

    pub async fn create_change(
        &self,
        auth: &AuthContext,
        req: CreatePolicyChangeRequest,
        force_agent_lineage: bool,
    ) -> Result<PolicyChangeRecord, ApiError> {
        if req.title.trim().is_empty() {
            return Err(invalid_arg(
                "MISSING_TITLE",
                "PolicyChange title is required.",
            ));
        }
        if req.operations.is_empty() {
            return Err(invalid_arg(
                "EMPTY_POLICY_CHANGE",
                "PolicyChange requires at least one operation.",
            ));
        }
        let proposer_kind = if force_agent_lineage || Self::is_agent_lineage(auth) {
            ProposerKind::AgentSession
        } else {
            req.proposer_kind.unwrap_or(ProposerKind::Human)
        };
        let now = Timestamp::now().to_string();
        let id = format!("chg_{}", Uuid::now_v7().simple());
        let record = PolicyChangeRecord {
            id: id.clone(),
            tenant_id: auth.tenant_id.clone(),
            title: req.title,
            description: req.description,
            state: PolicyChangeState::Draft,
            proposer_id: auth.principal_id.clone(),
            proposer_kind,
            source_ref: req.source_ref,
            operations: req.operations,
            diff: None,
            check_errors: Vec::new(),
            replay_summary: None,
            simulation_job_id: None,
            rollout_ring: None,
            requires_human_approval: proposer_kind == ProposerKind::AgentSession,
            approved_by: None,
            denied_by: None,
            denied_reason: None,
            created_at: now.clone(),
            updated_at: now,
        };
        let max_items = rest_limits().max_store_items.max(1);
        let mut guard = self.inner.write().await;
        if guard.changes.len() >= max_items {
            let terminal_id = guard
                .changes
                .iter()
                .find(|(_, c)| {
                    matches!(
                        c.state,
                        PolicyChangeState::Applied
                            | PolicyChangeState::Denied
                            | PolicyChangeState::Superseded
                    )
                })
                .map(|(k, _)| k.clone());
            if let Some(evict) = terminal_id {
                guard.changes.remove(&evict);
                guard.candidate_packs.remove(&evict);
            } else {
                return Err(failed_precondition(
                    "POLICY_CHANGE_LIMIT_EXCEEDED",
                    "PolicyChange store capacity reached.",
                ));
            }
        }
        guard.changes.insert(id, record.clone());
        Ok(record)
    }

    pub async fn check_change(
        &self,
        app_state: &AppState,
        auth: &AuthContext,
        change_id: &str,
    ) -> Result<PolicyChangeRecord, ApiError> {
        let current_packs = app_state.inner.read().await.packs.clone();
        let (ops, state) = {
            let guard = self.inner.read().await;
            let rec = guard
                .changes
                .get(change_id)
                .filter(|c| c.tenant_id == auth.tenant_id)
                .ok_or_else(|| not_found_change(change_id))?;
            (rec.operations.clone(), rec.state)
        };
        if matches!(
            state,
            PolicyChangeState::Applied | PolicyChangeState::Denied | PolicyChangeState::Superseded
        ) {
            return Err(failed_precondition(
                "INVALID_CHANGE_STATE",
                "Terminal PolicyChange cannot be re-checked.",
            ));
        }

        let (diff, candidate_packs, check_errors) = compute_policy_diff(&current_packs, &ops)?;
        let now = Timestamp::now().to_string();
        let mut guard = self.inner.write().await;
        let rec = guard
            .changes
            .get_mut(change_id)
            .filter(|c| c.tenant_id == auth.tenant_id)
            .ok_or_else(|| not_found_change(change_id))?;
        rec.requires_human_approval = rec.proposer_kind == ProposerKind::AgentSession
            || diff.is_widening
            || diff.promotes_enforcement;
        rec.diff = Some(diff);
        rec.check_errors = check_errors.clone();
        rec.state = if check_errors.is_empty() {
            PolicyChangeState::Checked
        } else {
            PolicyChangeState::Failed
        };
        rec.updated_at = now;
        let out = rec.clone();
        if check_errors.is_empty() {
            guard
                .candidate_packs
                .insert(change_id.to_owned(), candidate_packs);
        } else {
            guard.candidate_packs.remove(change_id);
        }
        Ok(out)
    }

    pub async fn simulate_change(
        &self,
        app_state: &AppState,
        auth: &AuthContext,
        change_id: &str,
    ) -> Result<PolicyChangeRecord, ApiError> {
        let checked = self.check_change(app_state, auth, change_id).await?;
        if checked.state == PolicyChangeState::Failed {
            return Ok(checked);
        }
        let diff = checked.diff.clone().ok_or_else(|| {
            invalid_arg(
                "CHECK_MISSING_DIFF",
                "PolicyChange diff missing after check.",
            )
        })?;
        let candidate_packs = {
            let guard = self.inner.read().await;
            guard
                .candidate_packs
                .get(change_id)
                .cloned()
                .unwrap_or_default()
        };
        let attempts = app_state.inner.read().await.attempts.clone();
        let summary = run_four_bucket_simulation(&attempts, &candidate_packs, &diff);
        let job_id = self.record_simulation_job(&checked.tenant_id, change_id, &summary)?;

        let mut guard = self.inner.write().await;
        let rec = guard
            .changes
            .get_mut(change_id)
            .filter(|c| c.tenant_id == auth.tenant_id)
            .ok_or_else(|| not_found_change(change_id))?;
        rec.replay_summary = Some(summary);
        rec.simulation_job_id = job_id;
        rec.updated_at = Timestamp::now().to_string();
        Ok(rec.clone())
    }

    pub async fn apply_change(
        &self,
        app_state: &AppState,
        auth: &AuthContext,
        change_id: &str,
    ) -> Result<PolicyChangeRecord, ApiError> {
        let rec = self.get_change(auth, change_id).await?;
        if rec.state == PolicyChangeState::Applied {
            return Ok(rec);
        }
        if matches!(
            rec.state,
            PolicyChangeState::Denied | PolicyChangeState::Superseded | PolicyChangeState::Failed
        ) {
            return Err(failed_precondition(
                "CHANGE_NOT_APPLICABLE",
                "Failed, denied, or superseded PolicyChanges cannot be applied.",
            ));
        }
        self.ensure_unlocked_tenant(&auth.tenant_id).await?;
        if rec.diff.is_none() {
            self.check_change(app_state, auth, change_id).await?;
        }
        let current = self.get_change(auth, change_id).await?;
        if current.state == PolicyChangeState::Failed {
            return Err(failed_precondition(
                "CHANGE_CHECK_FAILED",
                "PolicyChange validation errors must be resolved before apply.",
            ));
        }

        let is_agent =
            current.proposer_kind == ProposerKind::AgentSession || Self::is_agent_lineage(auth);
        if current.requires_human_approval || is_agent {
            let mut guard = self.inner.write().await;
            let slot = guard
                .changes
                .get_mut(change_id)
                .filter(|c| c.tenant_id == auth.tenant_id)
                .ok_or_else(|| not_found_change(change_id))?;
            slot.requires_human_approval = true;
            slot.state = PolicyChangeState::AwaitingApproval;
            slot.updated_at = Timestamp::now().to_string();
            return Ok(slot.clone());
        }

        self.commit_rollout(app_state, auth, change_id, None).await
    }
}
