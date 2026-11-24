// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use rusqlite::Connection;

use grdr_model::CodedError;
use grdr_ports::CODE_LAKE_IO;

const LAKE_SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS lake_fencing (
    organisation_id TEXT PRIMARY KEY,
    current_fence INTEGER NOT NULL,
    snapshot_seq INTEGER NOT NULL,
    manifest_seq INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS lake_segments (
    organisation_id TEXT NOT NULL,
    segment_id TEXT NOT NULL,
    retention_class TEXT NOT NULL,
    day TEXT NOT NULL,
    object_key TEXT NOT NULL,
    row_count INTEGER NOT NULL,
    size_bytes INTEGER NOT NULL,
    digest_sha256 TEXT NOT NULL,
    schema_rev INTEGER NOT NULL,
    data_key_id TEXT NOT NULL,
    device_ids_json TEXT NOT NULL,
    root_session_ids_json TEXT NOT NULL,
    min_observed_ms INTEGER NOT NULL,
    max_observed_ms INTEGER NOT NULL,
    fence INTEGER NOT NULL,
    logical_deleted_at_ms INTEGER,
    physical_deleted_at_ms INTEGER,
    PRIMARY KEY (organisation_id, segment_id)
);

CREATE INDEX IF NOT EXISTS idx_lake_segments_class_day
    ON lake_segments (organisation_id, retention_class, day);

CREATE TABLE IF NOT EXISTS lake_archive_segments (
    organisation_id TEXT NOT NULL,
    object_key TEXT NOT NULL,
    lane TEXT NOT NULL,
    day TEXT NOT NULL,
    root_session_ids_json TEXT NOT NULL,
    digest_sha256 TEXT NOT NULL,
    reduced_at_ms INTEGER,
    logical_deleted_at_ms INTEGER,
    physical_deleted_at_ms INTEGER,
    PRIMARY KEY (organisation_id, object_key)
);

CREATE TABLE IF NOT EXISTS lake_holds (
    organisation_id TEXT NOT NULL,
    hold_id TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    reason TEXT NOT NULL,
    incident_ref TEXT,
    created_by TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER,
    state_json TEXT NOT NULL,
    PRIMARY KEY (organisation_id, hold_id)
);

CREATE TABLE IF NOT EXISTS lake_content_keys (
    organisation_id TEXT NOT NULL,
    root_session_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    wrapped_key TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    destroy_after_ms INTEGER NOT NULL,
    state TEXT NOT NULL,
    destroyed_at_ms INTEGER,
    destruction_record_id TEXT,
    PRIMARY KEY (organisation_id, root_session_id)
);

CREATE TABLE IF NOT EXISTS lake_manifests (
    organisation_id TEXT NOT NULL,
    manifest_seq INTEGER NOT NULL,
    prev_manifest_digest TEXT,
    manifest_digest TEXT NOT NULL,
    object_key TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    entries_json TEXT NOT NULL,
    PRIMARY KEY (organisation_id, manifest_seq)
);

CREATE TABLE IF NOT EXISTS lake_observables (
    organisation_id TEXT NOT NULL,
    observable_type TEXT NOT NULL,
    value TEXT NOT NULL,
    segment_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    PRIMARY KEY (organisation_id, observable_type, value, segment_id, event_id)
);
"#;

pub(crate) fn configure_and_migrate_catalogue(conn: &mut Connection) -> Result<(), CodedError> {
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA foreign_keys = ON;
         PRAGMA busy_timeout = 5000;",
    )
    .map_err(lake_sql_err)?;
    conn.execute_batch(LAKE_SCHEMA_SQL).map_err(lake_sql_err)?;
    Ok(())
}

pub(crate) fn lake_sql_err(err: rusqlite::Error) -> CodedError {
    CodedError::new(
        CODE_LAKE_IO,
        format!("Lake catalogue SQLite operation failed: {err}"),
        "Check lake catalogue SQLite database path and permissions.",
    )
}
