// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, MutexGuard};

use uuid::Uuid;

use grdr_model::CodedError;
use grdr_model::error::CODE_STORE_IO;
use grdr_ports::{
    CODE_JOBS_INVALID_STATE, CODE_JOBS_NOT_FOUND, CODE_JOBS_STALE_FENCE, FencingToken,
    JobEnqueueOutcome, JobEnqueueRequest, JobPort, JobRecord, JobState, JobStepRecord,
    JobStepState, LeaseAcquireOutcome, LeaseRecord, LeaseState, SingleCtx, TenantCtx,
};

use crate::mem_blob::sha256_hex;

#[derive(Debug, Default)]
struct MemJobsInner {
    jobs: BTreeMap<(String, String), JobRecord>,
    idempotency: HashMap<(String, String), String>,
    steps: BTreeMap<(String, String, u32), JobStepRecord>,
    leases: BTreeMap<String, LeaseState>,
    next_fence: u64,
}

#[derive(Debug, Default)]
pub struct MemoryJobJournal {
    inner: Mutex<MemJobsInner>,
}

impl JobPort for MemoryJobJournal {
    fn enqueue(
        &self,
        ctx: &SingleCtx,
        req: &JobEnqueueRequest,
    ) -> Result<JobEnqueueOutcome, CodedError> {
        let mut g = lock_jobs(&self.inner)?;
        let org = ctx.organisation_id().as_str().to_string();
        if let Some(existing_id) = g
            .idempotency
            .get(&(org.clone(), req.idempotency_key.clone()))
            .cloned()
            && let Some(job) = g.jobs.get(&(org.clone(), existing_id))
        {
            return Ok(JobEnqueueOutcome::AlreadyExists(job.clone()));
        }
        let id = format!("job_{}", Uuid::now_v7().simple());
        let record = JobRecord {
            organisation_id: ctx.organisation_id().clone(),
            id: id.clone(),
            kind: req.kind.clone(),
            idempotency_key: req.idempotency_key.clone(),
            delegation_id: ctx.delegation_id().map(str::to_string),
            delegation_epoch: ctx.delegation_epoch(),
            state: JobState::Queued,
            payload_json: req.payload_json.clone(),
            not_before_ms: req.not_before_ms,
            attempts: 0,
        };
        g.idempotency
            .insert((org.clone(), req.idempotency_key.clone()), id.clone());
        g.jobs.insert((org, id), record.clone());
        Ok(JobEnqueueOutcome::Enqueued(record))
    }

    fn claim(
        &self,
        ctx: &SingleCtx,
        kinds: &[&str],
        holder: &str,
        now_ms: i64,
        lease_ttl_ms: i64,
    ) -> Result<Option<JobRecord>, CodedError> {
        let mut g = lock_jobs(&self.inner)?;
        let org = ctx.organisation_id().as_str().to_string();
        let mut candidate_key = None;
        for (key, job) in &g.jobs {
            if key.0 != org {
                continue;
            }
            if !kinds.is_empty() && !kinds.contains(&job.kind.as_str()) {
                continue;
            }
            if job.not_before_ms > now_ms {
                continue;
            }
            let claimable = match &job.state {
                JobState::Queued => true,
                JobState::Running {
                    lease_expires_at_ms,
                    ..
                } => *lease_expires_at_ms <= now_ms,
                _ => false,
            };
            if claimable {
                candidate_key = Some(key.clone());
                break;
            }
        }
        let Some(key) = candidate_key else {
            return Ok(None);
        };
        g.next_fence = g.next_fence.saturating_add(1);
        let fence = FencingToken::new(g.next_fence);
        let Some(job) = g.jobs.get_mut(&key) else {
            return Ok(None);
        };
        job.attempts = job.attempts.saturating_add(1);
        job.state = JobState::Running {
            holder: holder.into(),
            fence,
            lease_expires_at_ms: now_ms.saturating_add(lease_ttl_ms.max(1)),
        };
        Ok(Some(job.clone()))
    }

    fn record_step(
        &self,
        ctx: &SingleCtx,
        job_id: &str,
        step_index: u32,
        name: &str,
        fence: FencingToken,
        output_json: &str,
        now_ms: i64,
    ) -> Result<JobStepRecord, CodedError> {
        let mut g = lock_jobs(&self.inner)?;
        let org = ctx.organisation_id().as_str().to_string();
        let job = g.jobs.get(&(org.clone(), job_id.into())).ok_or_else(|| {
            CodedError::new(
                CODE_JOBS_NOT_FOUND,
                format!("Job `{job_id}` was not found."),
                "Verify job_id and organisation context.",
            )
        })?;
        match &job.state {
            JobState::Running {
                fence: current_fence,
                ..
            } if *current_fence == fence => {}
            JobState::Running { .. } => {
                return Err(CodedError::new(
                    CODE_JOBS_STALE_FENCE,
                    "Job step fence token is stale.",
                    "Re-claim the job before recording steps.",
                ));
            }
            _ => {
                return Err(CodedError::new(
                    CODE_JOBS_INVALID_STATE,
                    "Job is not in Running state.",
                    "Only running jobs can record steps.",
                ));
            }
        }

        let step_key = (org, job_id.into(), step_index);
        if let Some(existing) = g.steps.get(&step_key) {
            return Ok(existing.clone());
        }
        let rec = JobStepRecord {
            organisation_id: ctx.organisation_id().clone(),
            job_id: job_id.into(),
            step_index,
            name: name.into(),
            state: JobStepState::Succeeded {
                output_digest: sha256_hex(output_json.as_bytes()),
                output_json: output_json.into(),
                finished_at_ms: now_ms,
            },
        };
        g.steps.insert(step_key, rec.clone());
        Ok(rec)
    }

    fn get_step(
        &self,
        ctx: &TenantCtx,
        job_id: &str,
        step_index: u32,
    ) -> Result<Option<JobStepRecord>, CodedError> {
        let g = lock_jobs(&self.inner)?;
        for org in ctx.organisation_ids() {
            if let Some(s) = g
                .steps
                .get(&(org.as_str().into(), job_id.into(), step_index))
            {
                return Ok(Some(s.clone()));
            }
        }
        Ok(None)
    }

    fn complete(
        &self,
        ctx: &SingleCtx,
        job_id: &str,
        fence: FencingToken,
        now_ms: i64,
    ) -> Result<JobRecord, CodedError> {
        let mut g = lock_jobs(&self.inner)?;
        let job = g
            .jobs
            .get_mut(&(ctx.organisation_id().as_str().into(), job_id.into()))
            .ok_or_else(|| {
                CodedError::new(
                    CODE_JOBS_NOT_FOUND,
                    format!("Job `{job_id}` was not found."),
                    "Verify job_id and organisation context.",
                )
            })?;
        match &job.state {
            JobState::Running {
                fence: current_fence,
                ..
            } if *current_fence == fence => {
                job.state = JobState::Completed {
                    finished_at_ms: now_ms,
                };
                Ok(job.clone())
            }
            JobState::Running { .. } => Err(CodedError::new(
                CODE_JOBS_STALE_FENCE,
                "Job completion fence token is stale.",
                "Stop work and re-claim job.",
            )),
            _ => Err(CodedError::new(
                CODE_JOBS_INVALID_STATE,
                "Cannot complete a job that is not Running.",
                "Check current job state.",
            )),
        }
    }

    fn fail(
        &self,
        ctx: &SingleCtx,
        job_id: &str,
        fence: FencingToken,
        error_code: &str,
        message: &str,
        now_ms: i64,
    ) -> Result<JobRecord, CodedError> {
        let mut g = lock_jobs(&self.inner)?;
        let job = g
            .jobs
            .get_mut(&(ctx.organisation_id().as_str().into(), job_id.into()))
            .ok_or_else(|| {
                CodedError::new(
                    CODE_JOBS_NOT_FOUND,
                    format!("Job `{job_id}` was not found."),
                    "Verify job_id and organisation context.",
                )
            })?;
        match &job.state {
            JobState::Running {
                fence: current_fence,
                ..
            } if *current_fence == fence => {
                job.state = JobState::Failed {
                    error_code: error_code.into(),
                    message: message.into(),
                    finished_at_ms: now_ms,
                };
                Ok(job.clone())
            }
            JobState::Running { .. } => Err(CodedError::new(
                CODE_JOBS_STALE_FENCE,
                "Job failure fence token is stale.",
                "Stop work and re-claim job.",
            )),
            _ => Err(CodedError::new(
                CODE_JOBS_INVALID_STATE,
                "Cannot fail a job that is not Running.",
                "Check current job state.",
            )),
        }
    }

    fn get_job(&self, ctx: &TenantCtx, job_id: &str) -> Result<Option<JobRecord>, CodedError> {
        let g = lock_jobs(&self.inner)?;
        for org in ctx.organisation_ids() {
            if let Some(job) = g.jobs.get(&(org.as_str().into(), job_id.into())) {
                return Ok(Some(job.clone()));
            }
        }
        Ok(None)
    }

    fn acquire_lease(
        &self,
        name: &str,
        holder: &str,
        now_ms: i64,
        ttl_ms: i64,
    ) -> Result<LeaseAcquireOutcome, CodedError> {
        let mut g = lock_jobs(&self.inner)?;
        if let Some(LeaseState::Held {
            holder: current_holder,
            fence,
            expiry_ms,
        }) = g.leases.get(name)
            && *expiry_ms > now_ms
            && current_holder != holder
        {
            return Ok(LeaseAcquireOutcome::Contended {
                current_holder: current_holder.clone(),
                fence: *fence,
                expiry_ms: *expiry_ms,
            });
        }
        g.next_fence = g.next_fence.saturating_add(1);
        let new_fence = FencingToken::new(g.next_fence);
        let state = LeaseState::Held {
            holder: holder.into(),
            fence: new_fence,
            expiry_ms: now_ms.saturating_add(ttl_ms.max(1)),
        };
        g.leases.insert(name.into(), state.clone());
        Ok(LeaseAcquireOutcome::Acquired(LeaseRecord {
            name: name.into(),
            state,
        }))
    }

    fn inspect_lease(&self, name: &str, now_ms: i64) -> Result<LeaseRecord, CodedError> {
        let g = lock_jobs(&self.inner)?;
        let state = match g.leases.get(name) {
            Some(LeaseState::Held {
                holder,
                fence,
                expiry_ms,
            }) if *expiry_ms <= now_ms => LeaseState::Expired {
                last_holder: holder.clone(),
                last_fence: *fence,
                expired_at_ms: *expiry_ms,
            },
            Some(other) => other.clone(),
            None => LeaseState::Vacant,
        };
        Ok(LeaseRecord {
            name: name.into(),
            state,
        })
    }

    fn release_lease(
        &self,
        name: &str,
        holder: &str,
        fence: FencingToken,
    ) -> Result<LeaseRecord, CodedError> {
        let mut g = lock_jobs(&self.inner)?;
        match g.leases.get(name) {
            Some(LeaseState::Held {
                holder: current_holder,
                fence: current_fence,
                ..
            }) if current_holder == holder && *current_fence == fence => {
                g.leases.insert(name.into(), LeaseState::Vacant);
                Ok(LeaseRecord {
                    name: name.into(),
                    state: LeaseState::Vacant,
                })
            }
            Some(LeaseState::Held { .. }) => Err(CodedError::new(
                CODE_JOBS_STALE_FENCE,
                "Lease holder or fence does not match.",
                "Only the active lease holder with matching fence may release.",
            )),
            _ => Ok(LeaseRecord {
                name: name.into(),
                state: LeaseState::Vacant,
            }),
        }
    }
}

fn lock_jobs<T>(mutex: &Mutex<T>) -> Result<MutexGuard<'_, T>, CodedError> {
    mutex.lock().map_err(|_| {
        CodedError::new(
            CODE_STORE_IO,
            "In-memory jobs testkit mutex poisoned.",
            "Recreate MemoryJobJournal.",
        )
    })
}
