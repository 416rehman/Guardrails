// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

mod journal;
mod leases;
mod row_codec;
mod schema;

pub use journal::SqliteJobJournal;

#[cfg(test)]
mod tests {
    use super::*;
    use grdr_ports::{
        JobEnqueueOutcome, JobEnqueueRequest, JobPort, JobState, OrgId, SingleCtx, TenantCtx,
    };

    #[test]
    fn sqlite_jobs_passes_port_contract() {
        let jobs = SqliteJobJournal::open_in_memory().unwrap();
        grdr_ports_testkit::assert_job_port_contract(&jobs).unwrap();
    }

    #[test]
    fn sqlite_jobs_persists_steps_across_reopen() {
        let dir = std::env::temp_dir().join(format!("grdr-jobs-persist-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let db_path = dir.join("jobs.sqlite3");

        let org = OrgId::new("org-job-persist").unwrap();
        let ctx = SingleCtx::new(org);
        let read_ctx = TenantCtx::Single(ctx.clone());

        let job_id = {
            let jobs = SqliteJobJournal::open(&db_path).unwrap();
            let JobEnqueueOutcome::Enqueued(job) = jobs
                .enqueue(
                    &ctx,
                    &JobEnqueueRequest {
                        kind: "backup".into(),
                        idempotency_key: "backup-1".into(),
                        payload_json: "{}".into(),
                        not_before_ms: 100,
                    },
                )
                .unwrap()
            else {
                panic!("expected fresh job");
            };
            let claimed = jobs
                .claim(&ctx, &["backup"], "node-1", 200, 10_000)
                .unwrap()
                .unwrap();
            let fence = match claimed.state {
                JobState::Running { fence, .. } => fence,
                _ => panic!("expected running"),
            };
            jobs.record_step(&ctx, &job.id, 0, "snapshot", fence, "{\"ok\":true}", 250)
                .unwrap();
            jobs.complete(&ctx, &job.id, fence, 300).unwrap();
            job.id
        };

        let reopened = SqliteJobJournal::open(&db_path).unwrap();
        let loaded = reopened.get_job(&read_ctx, &job_id).unwrap().unwrap();
        assert!(matches!(loaded.state, JobState::Completed { .. }));
        assert!(reopened.get_step(&read_ctx, &job_id, 0).unwrap().is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
