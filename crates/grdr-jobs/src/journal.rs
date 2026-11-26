// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::fs;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use grdr_crypto::sha256_hex;
use rusqlite::types::Value;
use rusqlite::{Connection, OptionalExtension};
use uuid::Uuid;

use grdr_model::CodedError;
use grdr_ports::{
    CODE_JOBS_INVALID_STATE, CODE_JOBS_IO, CODE_JOBS_NOT_FOUND, CODE_JOBS_STALE_FENCE,
    FencingToken, JobEnqueueOutcome, JobEnqueueRequest, JobRecord, JobState, JobStepRecord,
    JobStepState, OrgId, SingleCtx, TenantCtx,
};

use crate::row_codec::{decode_json, encode_json, fetch_job_by_id, fetch_job_by_key, jobs_sql_err};
use crate::schema::configure_and_init_jobs;

#[derive(Debug)]
pub struct SqliteJobJournal {
    conn: Mutex<Connection>,
}

impl SqliteJobJournal {
    pub fn open(path: &Path) -> Result<Self, CodedError> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|e| {
                CodedError::new(
                    CODE_JOBS_IO,
                    format!("Failed creating jobs directory {}: {e}", parent.display()),
                    "Verify write permissions in --data-dir.",
                )
            })?;
        }
        let mut conn = Connection::open(path).map_err(|e| {
            CodedError::new(
                CODE_JOBS_IO,
                format!("Failed opening SQLite jobs DB {}: {e}", path.display()),
                "Verify SQLite jobs file path and permissions.",
            )
        })?;
        configure_and_init_jobs(&mut conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn open_in_memory() -> Result<Self, CodedError> {
        let mut conn = Connection::open_in_memory().map_err(|e| {
            CodedError::new(
                CODE_JOBS_IO,
                format!("Failed opening in-memory SQLite jobs DB: {e}"),
                "Check SQLite runtime availability.",
            )
        })?;
        configure_and_init_jobs(&mut conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub(crate) fn lock_conn(&self) -> Result<MutexGuard<'_, Connection>, CodedError> {
        self.conn.lock().map_err(|_| {
            CodedError::new(
                CODE_JOBS_IO,
                "SQLite jobs journal mutex poisoned.",
                "Restart the jobs journal adapter.",
            )
        })
    }

    pub(crate) fn enqueue_impl(
        &self,
        ctx: &SingleCtx,
        req: &JobEnqueueRequest,
    ) -> Result<JobEnqueueOutcome, CodedError> {
        let org = ctx.organisation_id().as_str();
        let mut conn = self.lock_conn()?;
        let tx = conn.transaction().map_err(jobs_sql_err)?;

        if let Some(existing) = fetch_job_by_key(&tx, org, &req.idempotency_key)? {
            return Ok(JobEnqueueOutcome::AlreadyExists(existing));
        }

        let job = JobRecord {
            organisation_id: ctx.organisation_id().clone(),
            id: format!("job_{}", Uuid::now_v7().simple()),
            kind: req.kind.clone(),
            idempotency_key: req.idempotency_key.clone(),
            delegation_id: ctx.delegation_id().map(str::to_string),
            delegation_epoch: ctx.delegation_epoch(),
            state: JobState::Queued,
            payload_json: req.payload_json.clone(),
            not_before_ms: req.not_before_ms,
            attempts: 0,
        };
        let state_json = encode_json(&job.state)?;
        let del_epoch = job.delegation_epoch.and_then(|v| i64::try_from(v).ok());

        tx.execute(
            "INSERT INTO job (
                organisation_id, id, kind, idempotency_key, delegation_id, delegation_epoch,
                status_tag, state_json, payload_json, not_before_ms, attempts, lease_expires_at_ms, fence
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'queued', ?7, ?8, ?9, 0, NULL, 0)",
            rusqlite::params![
                org,
                job.id,
                job.kind,
                job.idempotency_key,
                job.delegation_id,
                del_epoch,
                state_json,
                job.payload_json,
                job.not_before_ms
            ],
        )
        .map_err(jobs_sql_err)?;
        tx.commit().map_err(jobs_sql_err)?;
        Ok(JobEnqueueOutcome::Enqueued(job))
    }

    pub(crate) fn claim_impl(
        &self,
        ctx: &SingleCtx,
        kinds: &[&str],
        holder: &str,
        now_ms: i64,
        lease_ttl_ms: i64,
    ) -> Result<Option<JobRecord>, CodedError> {
        let org = ctx.organisation_id().as_str();
        let mut conn = self.lock_conn()?;
        let tx = conn.transaction().map_err(jobs_sql_err)?;

        let mut params = vec![Value::from(org.to_string()), Value::from(now_ms)];
        let kind_filter = if kinds.is_empty() {
            String::new()
        } else {
            let placeholders = (0..kinds.len())
                .map(|idx| format!("?{}", idx.saturating_add(3)))
                .collect::<Vec<_>>()
                .join(", ");
            for k in kinds {
                params.push(Value::from((*k).to_string()));
            }
            format!("AND kind IN ({placeholders})")
        };

        let sql = format!(
            "SELECT id, attempts FROM job
             WHERE organisation_id = ?1
               AND not_before_ms <= ?2
               AND (status_tag = 'queued' OR (status_tag = 'running' AND lease_expires_at_ms <= ?2))
               {kind_filter}
             ORDER BY not_before_ms ASC, id ASC
             LIMIT 1"
        );

        let candidate: Option<(String, i64)> = tx
            .query_row(&sql, rusqlite::params_from_iter(params), |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .optional()
            .map_err(jobs_sql_err)?;

        let Some((job_id, attempts_i64)) = candidate else {
            return Ok(None);
        };

        let fence = allocate_fence(&tx)?;
        let fence_i64 = i64::try_from(fence.value()).unwrap_or(i64::MAX);
        let new_attempts = u32::try_from(attempts_i64).unwrap_or(0).saturating_add(1);
        let lease_exp = now_ms.saturating_add(lease_ttl_ms.max(1));
        let next_state = JobState::Running {
            holder: holder.into(),
            fence,
            lease_expires_at_ms: lease_exp,
        };
        let state_json = encode_json(&next_state)?;

        tx.execute(
            "UPDATE job
             SET status_tag = 'running',
                 state_json = ?1,
                 attempts = ?2,
                 lease_expires_at_ms = ?3,
                 fence = ?4
             WHERE organisation_id = ?5 AND id = ?6",
            rusqlite::params![
                state_json,
                i64::from(new_attempts),
                lease_exp,
                fence_i64,
                org,
                job_id
            ],
        )
        .map_err(jobs_sql_err)?;

        let updated = fetch_job_by_id(&tx, org, &job_id)?;
        tx.commit().map_err(jobs_sql_err)?;
        Ok(updated)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn record_step_impl(
        &self,
        ctx: &SingleCtx,
        job_id: &str,
        step_index: u32,
        name: &str,
        fence: FencingToken,
        output_json: &str,
        now_ms: i64,
    ) -> Result<JobStepRecord, CodedError> {
        let org = ctx.organisation_id().as_str();
        let mut conn = self.lock_conn()?;
        let tx = conn.transaction().map_err(jobs_sql_err)?;

        let job = fetch_job_by_id(&tx, org, job_id)?.ok_or_else(|| {
            CodedError::new(
                CODE_JOBS_NOT_FOUND,
                format!("Job `{job_id}` was not found."),
                "Verify job_id and organisation context.",
            )
        })?;
        check_running_fence(&job.state, fence)?;

        let existing: Option<String> = tx
            .query_row(
                "SELECT state_json FROM job_step WHERE organisation_id = ?1 AND job_id = ?2 AND step_index = ?3",
                rusqlite::params![org, job_id, i64::from(step_index)],
                |row| row.get(0),
            )
            .optional()
            .map_err(jobs_sql_err)?;

        if let Some(raw_state) = existing {
            let state: JobStepState = decode_json(&raw_state)?;
            return Ok(JobStepRecord {
                organisation_id: ctx.organisation_id().clone(),
                job_id: job_id.into(),
                step_index,
                name: name.into(),
                state,
            });
        }

        let state = JobStepState::Succeeded {
            output_digest: sha256_hex(output_json.as_bytes()),
            output_json: output_json.into(),
            finished_at_ms: now_ms,
        };
        let state_json = encode_json(&state)?;
        tx.execute(
            "INSERT INTO job_step (organisation_id, job_id, step_index, name, state_json)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![org, job_id, i64::from(step_index), name, state_json],
        )
        .map_err(jobs_sql_err)?;
        tx.commit().map_err(jobs_sql_err)?;

        Ok(JobStepRecord {
            organisation_id: ctx.organisation_id().clone(),
            job_id: job_id.into(),
            step_index,
            name: name.into(),
            state,
        })
    }

    pub(crate) fn get_step_impl(
        &self,
        ctx: &TenantCtx,
        job_id: &str,
        step_index: u32,
    ) -> Result<Option<JobStepRecord>, CodedError> {
        let conn = self.lock_conn()?;
        let org_count = ctx.organisation_ids().len();
        let placeholders = (0..org_count)
            .map(|idx| format!("?{}", idx.saturating_add(3)))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "SELECT organisation_id, name, state_json
             FROM job_step
             WHERE job_id = ?1 AND step_index = ?2 AND organisation_id IN ({placeholders})
             LIMIT 1"
        );
        let mut params = vec![
            Value::from(job_id.to_string()),
            Value::from(i64::from(step_index)),
        ];
        for org in ctx.organisation_ids() {
            params.push(Value::from(org.as_str().to_string()));
        }
        let row: Option<(String, String, String)> = conn
            .query_row(&sql, rusqlite::params_from_iter(params), |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .optional()
            .map_err(jobs_sql_err)?;
        let Some((org_str, name, state_json)) = row else {
            return Ok(None);
        };
        Ok(Some(JobStepRecord {
            organisation_id: OrgId::new(org_str)?,
            job_id: job_id.into(),
            step_index,
            name,
            state: decode_json(&state_json)?,
        }))
    }

    pub(crate) fn get_job_impl(
        &self,
        ctx: &TenantCtx,
        job_id: &str,
    ) -> Result<Option<JobRecord>, CodedError> {
        let conn = self.lock_conn()?;
        for org in ctx.organisation_ids() {
            if let Some(job) = fetch_job_by_id(&conn, org.as_str(), job_id)? {
                return Ok(Some(job));
            }
        }
        Ok(None)
    }
}

pub(crate) fn finish_job(
    journal: &SqliteJobJournal,
    ctx: &SingleCtx,
    job_id: &str,
    fence: FencingToken,
    status_tag: &str,
    next_state: JobState,
) -> Result<JobRecord, CodedError> {
    let org = ctx.organisation_id().as_str();
    let mut conn = journal.lock_conn()?;
    let tx = conn.transaction().map_err(jobs_sql_err)?;

    let job = fetch_job_by_id(&tx, org, job_id)?.ok_or_else(|| {
        CodedError::new(
            CODE_JOBS_NOT_FOUND,
            format!("Job `{job_id}` was not found."),
            "Verify job_id and organisation context.",
        )
    })?;
    check_running_fence(&job.state, fence)?;

    let state_json = encode_json(&next_state)?;
    tx.execute(
        "UPDATE job
         SET status_tag = ?1, state_json = ?2, lease_expires_at_ms = NULL
         WHERE organisation_id = ?3 AND id = ?4",
        rusqlite::params![status_tag, state_json, org, job_id],
    )
    .map_err(jobs_sql_err)?;
    let updated = fetch_job_by_id(&tx, org, job_id)?.ok_or_else(|| {
        CodedError::new(
            CODE_JOBS_NOT_FOUND,
            format!("Job `{job_id}` disappeared during update."),
            "Retry job state update.",
        )
    })?;
    tx.commit().map_err(jobs_sql_err)?;
    Ok(updated)
}

pub(crate) fn allocate_fence(tx: &rusqlite::Transaction<'_>) -> Result<FencingToken, CodedError> {
    let val: i64 = tx
        .query_row(
            "UPDATE fence_seq SET next_val = next_val + 1 WHERE seq_name = 'global' RETURNING next_val",
            [],
            |row| row.get(0),
        )
        .map_err(jobs_sql_err)?;
    Ok(FencingToken::new(u64::try_from(val).unwrap_or(1)))
}

fn check_running_fence(state: &JobState, fence: FencingToken) -> Result<(), CodedError> {
    match state {
        JobState::Running {
            fence: current_fence,
            ..
        } if *current_fence == fence => Ok(()),
        JobState::Running { .. } => Err(CodedError::new(
            CODE_JOBS_STALE_FENCE,
            "Job fence token is stale.",
            "Stop work and re-claim job.",
        )),
        _ => Err(CodedError::new(
            CODE_JOBS_INVALID_STATE,
            "Job is not in Running state.",
            "Only Running jobs accept step or terminal updates.",
        )),
    }
}
