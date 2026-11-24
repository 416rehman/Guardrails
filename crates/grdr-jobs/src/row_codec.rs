// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use rusqlite::{Connection, OptionalExtension};
use serde::Serialize;
use serde::de::DeserializeOwned;

use grdr_model::CodedError;
use grdr_ports::{CODE_JOBS_IO, JobRecord, OrgId};

pub(crate) type JobTuple = (
    String,
    String,
    String,
    String,
    Option<String>,
    Option<i64>,
    String,
    String,
    i64,
    i64,
);

pub(crate) fn fetch_job_by_key(
    conn: &Connection,
    org: &str,
    idempotency_key: &str,
) -> Result<Option<JobRecord>, CodedError> {
    let row = conn
        .query_row(
            "SELECT organisation_id, id, kind, idempotency_key, delegation_id, delegation_epoch, state_json, payload_json, not_before_ms, attempts
             FROM job WHERE organisation_id = ?1 AND idempotency_key = ?2",
            rusqlite::params![org, idempotency_key],
            map_job_row,
        )
        .optional()
        .map_err(jobs_sql_err)?;
    row.map(decode_job_tuple).transpose()
}

pub(crate) fn fetch_job_by_id(
    conn: &Connection,
    org: &str,
    job_id: &str,
) -> Result<Option<JobRecord>, CodedError> {
    let row = conn
        .query_row(
            "SELECT organisation_id, id, kind, idempotency_key, delegation_id, delegation_epoch, state_json, payload_json, not_before_ms, attempts
             FROM job WHERE organisation_id = ?1 AND id = ?2",
            rusqlite::params![org, job_id],
            map_job_row,
        )
        .optional()
        .map_err(jobs_sql_err)?;
    row.map(decode_job_tuple).transpose()
}

pub(crate) fn jobs_sql_err(err: rusqlite::Error) -> CodedError {
    CodedError::new(
        CODE_JOBS_IO,
        format!("SQLite jobs query failed: {err}"),
        "Inspect SQLite jobs database state.",
    )
}

pub(crate) fn encode_json<T: Serialize>(value: &T) -> Result<String, CodedError> {
    serde_json::to_string(value).map_err(|e| {
        CodedError::new(
            CODE_JOBS_IO,
            format!("Failed serializing job state: {e}"),
            "Check job payload.",
        )
    })
}

pub(crate) fn decode_json<T: DeserializeOwned>(raw: &str) -> Result<T, CodedError> {
    serde_json::from_str(raw).map_err(|e| {
        CodedError::new(
            CODE_JOBS_IO,
            format!("Failed deserializing job state: {e}"),
            "Inspect stored job JSON.",
        )
    })
}

fn map_job_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<JobTuple> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
    ))
}

fn decode_job_tuple(tuple: JobTuple) -> Result<JobRecord, CodedError> {
    let (
        org_str,
        id,
        kind,
        idempotency_key,
        delegation_id,
        delegation_epoch,
        state_json,
        payload_json,
        not_before_ms,
        attempts_i64,
    ) = tuple;
    Ok(JobRecord {
        organisation_id: OrgId::new(org_str)?,
        id,
        kind,
        idempotency_key,
        delegation_id,
        delegation_epoch: delegation_epoch.and_then(|v| u64::try_from(v).ok()),
        state: decode_json(&state_json)?,
        payload_json,
        not_before_ms,
        attempts: u32::try_from(attempts_i64).unwrap_or(0),
    })
}
