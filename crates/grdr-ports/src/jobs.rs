// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use serde::{Deserialize, Serialize};

use grdr_model::CodedError;

use crate::tenant::{FencingToken, OrgId, SingleCtx, TenantCtx};

pub const CODE_JOBS_IO: &str = "GRDR-JOBS-0001";
pub const CODE_JOBS_STALE_FENCE: &str = "GRDR-JOBS-0002";
pub const CODE_JOBS_NOT_FOUND: &str = "GRDR-JOBS-0003";
pub const CODE_JOBS_INVALID_STATE: &str = "GRDR-JOBS-0004";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum JobState {
    Queued,
    Running {
        holder: String,
        fence: FencingToken,
        lease_expires_at_ms: i64,
    },
    Completed {
        finished_at_ms: i64,
    },
    Failed {
        error_code: String,
        message: String,
        finished_at_ms: i64,
    },
    Cancelled {
        finished_at_ms: i64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum JobStepState {
    Started {
        started_at_ms: i64,
    },
    Succeeded {
        output_digest: String,
        output_json: String,
        finished_at_ms: i64,
    },
    Failed {
        error_code: String,
        message: String,
        finished_at_ms: i64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum LeaseState {
    Vacant,
    Held {
        holder: String,
        fence: FencingToken,
        expiry_ms: i64,
    },
    Expired {
        last_holder: String,
        last_fence: FencingToken,
        expired_at_ms: i64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobEnqueueRequest {
    pub kind: String,
    pub idempotency_key: String,
    pub payload_json: String,
    pub not_before_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobEnqueueOutcome {
    Enqueued(JobRecord),
    AlreadyExists(JobRecord),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobRecord {
    pub organisation_id: OrgId,
    pub id: String,
    pub kind: String,
    pub idempotency_key: String,
    pub delegation_id: Option<String>,
    pub delegation_epoch: Option<u64>,
    pub state: JobState,
    pub payload_json: String,
    pub not_before_ms: i64,
    pub attempts: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobStepRecord {
    pub organisation_id: OrgId,
    pub job_id: String,
    pub step_index: u32,
    pub name: String,
    pub state: JobStepState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseRecord {
    pub name: String,
    pub state: LeaseState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeaseAcquireOutcome {
    Acquired(LeaseRecord),
    Contended {
        current_holder: String,
        fence: FencingToken,
        expiry_ms: i64,
    },
}

pub trait JobPort {
    fn enqueue(
        &self,
        ctx: &SingleCtx,
        req: &JobEnqueueRequest,
    ) -> Result<JobEnqueueOutcome, CodedError>;

    fn claim(
        &self,
        ctx: &SingleCtx,
        kinds: &[&str],
        holder: &str,
        now_ms: i64,
        lease_ttl_ms: i64,
    ) -> Result<Option<JobRecord>, CodedError>;

    #[allow(clippy::too_many_arguments)]
    fn record_step(
        &self,
        ctx: &SingleCtx,
        job_id: &str,
        step_index: u32,
        name: &str,
        fence: FencingToken,
        output_json: &str,
        now_ms: i64,
    ) -> Result<JobStepRecord, CodedError>;

    fn get_step(
        &self,
        ctx: &TenantCtx,
        job_id: &str,
        step_index: u32,
    ) -> Result<Option<JobStepRecord>, CodedError>;

    fn complete(
        &self,
        ctx: &SingleCtx,
        job_id: &str,
        fence: FencingToken,
        now_ms: i64,
    ) -> Result<JobRecord, CodedError>;

    fn fail(
        &self,
        ctx: &SingleCtx,
        job_id: &str,
        fence: FencingToken,
        error_code: &str,
        message: &str,
        now_ms: i64,
    ) -> Result<JobRecord, CodedError>;

    fn get_job(&self, ctx: &TenantCtx, job_id: &str) -> Result<Option<JobRecord>, CodedError>;

    fn acquire_lease(
        &self,
        name: &str,
        holder: &str,
        now_ms: i64,
        ttl_ms: i64,
    ) -> Result<LeaseAcquireOutcome, CodedError>;

    fn inspect_lease(&self, name: &str, now_ms: i64) -> Result<LeaseRecord, CodedError>;

    fn release_lease(
        &self,
        name: &str,
        holder: &str,
        fence: FencingToken,
    ) -> Result<LeaseRecord, CodedError>;
}
