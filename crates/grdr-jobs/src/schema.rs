// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use rusqlite::Connection;

use grdr_model::CodedError;
use grdr_ports::CODE_JOBS_IO;

const JOBS_SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS fence_seq (
    seq_name TEXT PRIMARY KEY,
    next_val INTEGER NOT NULL
);

INSERT OR IGNORE INTO fence_seq (seq_name, next_val) VALUES ('global', 0);

CREATE TABLE IF NOT EXISTS job (
    organisation_id TEXT NOT NULL,
    id TEXT NOT NULL,
    kind TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    delegation_id TEXT,
    delegation_epoch INTEGER,
    status_tag TEXT NOT NULL,
    state_json TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    not_before_ms INTEGER NOT NULL,
    attempts INTEGER NOT NULL,
    lease_expires_at_ms INTEGER,
    fence INTEGER NOT NULL,
    PRIMARY KEY (organisation_id, id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_job_org_idempotency
    ON job (organisation_id, idempotency_key);

CREATE TABLE IF NOT EXISTS job_step (
    organisation_id TEXT NOT NULL,
    job_id TEXT NOT NULL,
    step_index INTEGER NOT NULL,
    name TEXT NOT NULL,
    state_json TEXT NOT NULL,
    PRIMARY KEY (organisation_id, job_id, step_index),
    FOREIGN KEY (organisation_id, job_id) REFERENCES job (organisation_id, id)
);

CREATE TABLE IF NOT EXISTS lease (
    name TEXT PRIMARY KEY,
    holder TEXT,
    fence INTEGER NOT NULL,
    expiry_ms INTEGER NOT NULL,
    state_json TEXT NOT NULL
);
"#;

pub(crate) fn configure_and_init_jobs(conn: &mut Connection) -> Result<(), CodedError> {
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA foreign_keys = ON;
         PRAGMA busy_timeout = 5000;",
    )
    .map_err(|e| {
        CodedError::new(
            CODE_JOBS_IO,
            format!("Failed applying SQLite WAL pragmas for jobs: {e}"),
            "Check SQLite jobs database permissions.",
        )
    })?;

    conn.execute_batch(JOBS_SCHEMA_SQL).map_err(|e| {
        CodedError::new(
            CODE_JOBS_IO,
            format!("Failed initializing SQLite jobs tables: {e}"),
            "Verify jobs SQLite database is writable.",
        )
    })?;

    Ok(())
}
