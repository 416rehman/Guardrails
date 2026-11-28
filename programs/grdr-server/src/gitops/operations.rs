// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use grdr_model::error::{CODE_CONFLICT, CODE_NOT_FOUND, CODE_POLICY_DENIED};
use grdr_model::eval::FourBucketSummary;
use grdr_ports::{
    JobEnqueueOutcome, JobEnqueueRequest, JobPort, JobState, OrgId, SingleCtx, TenantCtx,
};
use grdr_proto::common::ErrorClass;
use jiff::Timestamp;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::auth::AuthContext;
use crate::connect_error::{ApiError, ApiErrorInner, ConnectCode};
use crate::routes::rest::limits::rest_limits;

use super::binding::failed_precondition;
use super::store::GitopsStore;
use super::types::GitopsBinding;

impl GitopsStore {
    pub async fn get_operation(
        &self,
        auth: &AuthContext,
        job_id: &str,
    ) -> Result<Option<Value>, ApiError> {
        let Some(jobs) = self.jobs() else {
            return Ok(None);
        };
        let org = OrgId::new(safe_org(&auth.tenant_id)).map_err(ApiError::from_coded)?;
        let ctx = TenantCtx::Single(SingleCtx::new(org));
        let Some(mut job) = jobs.get_job(&ctx, job_id).map_err(ApiError::from_coded)? else {
            return Ok(None);
        };
        let cancelled_at = self
            .inner
            .read()
            .await
            .cancelled_operations
            .get(&(auth.tenant_id.clone(), job_id.to_owned()))
            .copied();
        if let Some(finished_at_ms) = cancelled_at
            && matches!(job.state, JobState::Queued | JobState::Running { .. })
        {
            job.state = JobState::Cancelled { finished_at_ms };
        }
        Ok(Some(
            serde_json::to_value(job).unwrap_or_else(|_| json!({})),
        ))
    }

    pub async fn cancel_operation(
        &self,
        auth: &AuthContext,
        job_id: &str,
    ) -> Result<Value, ApiError> {
        if Self::is_agent_lineage(auth) {
            return Err(agent_propose_only_err(
                "AgentSession cannot cancel async operations.",
                "Require a human operator.",
            ));
        }
        let Some(jobs) = self.jobs() else {
            return Err(operation_not_found(job_id));
        };
        let org = OrgId::new(safe_org(&auth.tenant_id)).map_err(ApiError::from_coded)?;
        let single_ctx = SingleCtx::new(org);
        let tenant_ctx = TenantCtx::Single(single_ctx.clone());
        let mut job = jobs
            .get_job(&tenant_ctx, job_id)
            .map_err(ApiError::from_coded)?
            .ok_or_else(|| operation_not_found(job_id))?;
        if matches!(
            job.state,
            JobState::Completed { .. } | JobState::Failed { .. } | JobState::Cancelled { .. }
        ) || self
            .inner
            .read()
            .await
            .cancelled_operations
            .contains_key(&(auth.tenant_id.clone(), job_id.to_owned()))
        {
            return Err(failed_precondition(
                "INVALID_OPERATION_STATE",
                "Completed or terminal operations cannot be cancelled.",
            ));
        }
        let now_ms = Timestamp::now().as_millisecond();
        if let JobState::Running { fence, .. } = job.state {
            let _ = jobs.fail(
                &single_ctx,
                job_id,
                fence,
                "CANCELLED",
                "Cancelled by operator",
                now_ms,
            );
        }
        job.state = JobState::Cancelled {
            finished_at_ms: now_ms,
        };
        let mut guard = self.inner.write().await;
        if guard.cancelled_operations.len() >= rest_limits().max_store_items.max(1)
            && let Some(oldest) = guard.cancelled_operations.keys().next().cloned()
        {
            guard.cancelled_operations.remove(&oldest);
        }
        guard
            .cancelled_operations
            .insert((auth.tenant_id.clone(), job_id.to_owned()), now_ms);
        Ok(serde_json::to_value(job).unwrap_or_else(|_| json!({})))
    }

    pub(crate) fn record_simulation_job(
        &self,
        tenant_id: &str,
        change_id: &str,
        summary: &FourBucketSummary,
    ) -> Result<Option<String>, ApiError> {
        let Some(journal) = self.jobs() else {
            return Ok(None);
        };
        let org = OrgId::new(safe_org(tenant_id)).map_err(ApiError::from_coded)?;
        let ctx = SingleCtx::new(org);
        let now_ms = Timestamp::now().as_millisecond();
        let req = JobEnqueueRequest {
            kind: "policy_change.simulate".into(),
            idempotency_key: format!("sim:{change_id}:{}", Uuid::now_v7().simple()),
            payload_json: serde_json::to_string(summary).unwrap_or_else(|_| "{}".into()),
            not_before_ms: now_ms,
        };
        let job_id = match journal.enqueue(&ctx, &req).map_err(ApiError::from_coded)? {
            JobEnqueueOutcome::Enqueued(job) | JobEnqueueOutcome::AlreadyExists(job) => job.id,
        };
        if let Ok(Some(claimed)) = journal.claim(
            &ctx,
            &["policy_change.simulate"],
            "grdr-server",
            now_ms,
            60_000,
        ) && let JobState::Running { fence, .. } = claimed.state
        {
            let _ = journal.record_step(
                &ctx,
                &claimed.id,
                0,
                "replay_4bucket",
                fence,
                &req.payload_json,
                now_ms,
            );
            let _ = journal.complete(&ctx, &claimed.id, fence, now_ms);
        }
        Ok(Some(job_id))
    }
}

fn safe_org(tenant_id: &str) -> &str {
    if tenant_id.trim().is_empty() {
        "org-default"
    } else {
        tenant_id
    }
}

fn operation_not_found(job_id: &str) -> ApiError {
    ApiError::new(ApiErrorInner {
        code: ConnectCode::NotFound,
        grdr_code: CODE_NOT_FOUND.into(),
        reason: "OPERATION_NOT_FOUND".into(),
        class: ErrorClass::NotFound,
        message: format!("Operation `{job_id}` was not found."),
        fix: "Verify the operation ID.".into(),
        metadata: BTreeMap::new(),
    })
}

pub(crate) fn agent_propose_only_err(message: &str, fix: &str) -> ApiError {
    ApiError::new(ApiErrorInner {
        code: ConnectCode::PermissionDenied,
        grdr_code: CODE_POLICY_DENIED.into(),
        reason: "AGENT_SESSION_PROPOSE_ONLY".into(),
        class: ErrorClass::Permission,
        message: message.into(),
        fix: fix.into(),
        metadata: BTreeMap::new(),
    })
}

pub(crate) fn gitops_locked_err(binding: &GitopsBinding) -> ApiError {
    ApiError::new(ApiErrorInner {
        code: ConnectCode::FailedPrecondition,
        grdr_code: CODE_CONFLICT.into(),
        reason: "GITOPS_LOCKED".into(),
        class: ErrorClass::Conflict,
        message: format!(
            "Policy store is locked to {:?} GitOps source ({}).",
            binding.source, binding.repo_url
        ),
        fix: "Submit a pull request to the GitOps repository or use dual-approver edit-anyway."
            .into(),
        metadata: BTreeMap::new(),
    })
}
