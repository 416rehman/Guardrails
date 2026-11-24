// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use rusqlite::OptionalExtension;

use grdr_model::CodedError;
use grdr_ports::{
    CODE_JOBS_STALE_FENCE, FencingToken, JobEnqueueOutcome, JobEnqueueRequest, JobPort, JobRecord,
    JobState, JobStepRecord, LeaseAcquireOutcome, LeaseRecord, LeaseState, SingleCtx, TenantCtx,
};

use crate::journal::{SqliteJobJournal, allocate_fence, finish_job};
use crate::row_codec::{decode_json, encode_json, jobs_sql_err};

impl JobPort for SqliteJobJournal {
    fn enqueue(
        &self,
        ctx: &SingleCtx,
        req: &JobEnqueueRequest,
    ) -> Result<JobEnqueueOutcome, CodedError> {
        self.enqueue_impl(ctx, req)
    }

    fn claim(
        &self,
        ctx: &SingleCtx,
        kinds: &[&str],
        holder: &str,
        now_ms: i64,
        lease_ttl_ms: i64,
    ) -> Result<Option<JobRecord>, CodedError> {
        self.claim_impl(ctx, kinds, holder, now_ms, lease_ttl_ms)
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
        self.record_step_impl(ctx, job_id, step_index, name, fence, output_json, now_ms)
    }

    fn get_step(
        &self,
        ctx: &TenantCtx,
        job_id: &str,
        step_index: u32,
    ) -> Result<Option<JobStepRecord>, CodedError> {
        self.get_step_impl(ctx, job_id, step_index)
    }

    fn complete(
        &self,
        ctx: &SingleCtx,
        job_id: &str,
        fence: FencingToken,
        now_ms: i64,
    ) -> Result<JobRecord, CodedError> {
        finish_job(
            self,
            ctx,
            job_id,
            fence,
            "completed",
            JobState::Completed {
                finished_at_ms: now_ms,
            },
        )
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
        finish_job(
            self,
            ctx,
            job_id,
            fence,
            "failed",
            JobState::Failed {
                error_code: error_code.into(),
                message: message.into(),
                finished_at_ms: now_ms,
            },
        )
    }

    fn get_job(&self, ctx: &TenantCtx, job_id: &str) -> Result<Option<JobRecord>, CodedError> {
        self.get_job_impl(ctx, job_id)
    }

    fn acquire_lease(
        &self,
        name: &str,
        holder: &str,
        now_ms: i64,
        ttl_ms: i64,
    ) -> Result<LeaseAcquireOutcome, CodedError> {
        let mut conn = self.lock_conn()?;
        let tx = conn.transaction().map_err(jobs_sql_err)?;

        let existing: Option<(Option<String>, i64, i64)> = tx
            .query_row(
                "SELECT holder, fence, expiry_ms FROM lease WHERE name = ?1",
                rusqlite::params![name],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(jobs_sql_err)?;

        if let Some((Some(curr_holder), curr_fence_i64, expiry_ms)) = existing
            && expiry_ms > now_ms
            && curr_holder != holder
        {
            return Ok(LeaseAcquireOutcome::Contended {
                current_holder: curr_holder,
                fence: FencingToken::new(u64::try_from(curr_fence_i64).unwrap_or(0)),
                expiry_ms,
            });
        }

        let new_fence = allocate_fence(&tx)?;
        let new_fence_i64 = i64::try_from(new_fence.value()).unwrap_or(i64::MAX);
        let expiry_ms = now_ms.saturating_add(ttl_ms.max(1));
        let state = LeaseState::Held {
            holder: holder.into(),
            fence: new_fence,
            expiry_ms,
        };
        let state_json = encode_json(&state)?;

        tx.execute(
            "INSERT INTO lease (name, holder, fence, expiry_ms, state_json)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(name) DO UPDATE SET
               holder = excluded.holder,
               fence = excluded.fence,
               expiry_ms = excluded.expiry_ms,
               state_json = excluded.state_json",
            rusqlite::params![name, holder, new_fence_i64, expiry_ms, state_json],
        )
        .map_err(jobs_sql_err)?;
        tx.commit().map_err(jobs_sql_err)?;

        Ok(LeaseAcquireOutcome::Acquired(LeaseRecord {
            name: name.into(),
            state,
        }))
    }

    fn inspect_lease(&self, name: &str, now_ms: i64) -> Result<LeaseRecord, CodedError> {
        let conn = self.lock_conn()?;
        let raw: Option<String> = conn
            .query_row(
                "SELECT state_json FROM lease WHERE name = ?1",
                rusqlite::params![name],
                |row| row.get(0),
            )
            .optional()
            .map_err(jobs_sql_err)?;
        let state = match raw {
            None => LeaseState::Vacant,
            Some(json) => match decode_json::<LeaseState>(&json)? {
                LeaseState::Held {
                    holder,
                    fence,
                    expiry_ms,
                } if expiry_ms <= now_ms => LeaseState::Expired {
                    last_holder: holder,
                    last_fence: fence,
                    expired_at_ms: expiry_ms,
                },
                other => other,
            },
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
        let mut conn = self.lock_conn()?;
        let tx = conn.transaction().map_err(jobs_sql_err)?;
        let raw: Option<String> = tx
            .query_row(
                "SELECT state_json FROM lease WHERE name = ?1",
                rusqlite::params![name],
                |row| row.get(0),
            )
            .optional()
            .map_err(jobs_sql_err)?;
        let Some(json) = raw else {
            return Ok(LeaseRecord {
                name: name.into(),
                state: LeaseState::Vacant,
            });
        };
        let state: LeaseState = decode_json(&json)?;
        match state {
            LeaseState::Held {
                holder: curr_holder,
                fence: curr_fence,
                ..
            } if curr_holder == holder && curr_fence == fence => {
                let vacant_json = encode_json(&LeaseState::Vacant)?;
                tx.execute(
                    "UPDATE lease SET holder = NULL, expiry_ms = 0, state_json = ?1 WHERE name = ?2",
                    rusqlite::params![vacant_json, name],
                )
                .map_err(jobs_sql_err)?;
                tx.commit().map_err(jobs_sql_err)?;
                Ok(LeaseRecord {
                    name: name.into(),
                    state: LeaseState::Vacant,
                })
            }
            LeaseState::Held { .. } => Err(CodedError::new(
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
