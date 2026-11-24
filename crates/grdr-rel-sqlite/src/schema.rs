// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use jiff::Timestamp;
use rusqlite::Connection;

use grdr_model::CodedError;

pub const CODE_REL_IO: &str = "GRDR-REL-0001";
pub const CODE_REL_MIGRATION: &str = "GRDR-REL-0002";
pub const CODE_REL_CODEC: &str = "GRDR-REL-0003";

const MIGRATION_V1_NAME: &str = "0001_initial_embedded_schema";

const MIGRATION_V1_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS device (
    organisation_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    hostname TEXT NOT NULL,
    os TEXT NOT NULL,
    arch TEXT NOT NULL,
    online INTEGER NOT NULL,
    last_seen TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    PRIMARY KEY (organisation_id, device_id)
);

CREATE TABLE IF NOT EXISTS session_summary (
    organisation_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    agent_name TEXT NOT NULL,
    user_id TEXT,
    started_at TEXT NOT NULL,
    last_activity TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    PRIMARY KEY (organisation_id, session_id)
);

CREATE TABLE IF NOT EXISTS finding (
    organisation_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    lifecycle TEXT NOT NULL,
    detected_at TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    PRIMARY KEY (organisation_id, finding_id)
);

CREATE TABLE IF NOT EXISTS policy_pack (
    organisation_id TEXT NOT NULL,
    pack_id TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    channel TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    PRIMARY KEY (organisation_id, pack_id)
);

CREATE TABLE IF NOT EXISTS user_profile (
    organisation_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    email TEXT NOT NULL,
    department TEXT NOT NULL,
    pseudonym_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    PRIMARY KEY (organisation_id, user_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_user_profile_pseudonym
    ON user_profile (organisation_id, pseudonym_id);

CREATE TABLE IF NOT EXISTS tenant_kv (
    organisation_id TEXT NOT NULL,
    namespace TEXT NOT NULL,
    entry_key TEXT NOT NULL,
    value_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (organisation_id, namespace, entry_key)
);

CREATE VIRTUAL TABLE IF NOT EXISTS entity_fts USING fts5(
    organisation_id UNINDEXED,
    entity_kind UNINDEXED,
    entity_id UNINDEXED,
    parent_key UNINDEXED,
    title,
    subtitle
);
"#;

pub(crate) fn configure_and_migrate(conn: &mut Connection) -> Result<(), CodedError> {
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA foreign_keys = ON;
         PRAGMA busy_timeout = 5000;",
    )
    .map_err(|e| {
        CodedError::new(
            CODE_REL_IO,
            format!("Failed applying SQLite WAL pragmas: {e}"),
            "Check SQLite database file permissions.",
        )
    })?;

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at TEXT NOT NULL
        );",
    )
    .map_err(|e| {
        CodedError::new(
            CODE_REL_MIGRATION,
            format!("Failed initializing schema_migrations table: {e}"),
            "Verify relational SQLite file is writable.",
        )
    })?;

    let applied_v1: Option<i64> = conn
        .query_row(
            "SELECT version FROM schema_migrations WHERE version = 1",
            [],
            |row| row.get(0),
        )
        .ok();

    if applied_v1.is_none() {
        let tx = conn.transaction().map_err(|e| {
            CodedError::new(
                CODE_REL_MIGRATION,
                format!("Failed starting migration v1 transaction: {e}"),
                "Verify database is not locked.",
            )
        })?;
        tx.execute_batch(MIGRATION_V1_SQL).map_err(|e| {
            CodedError::new(
                CODE_REL_MIGRATION,
                format!("Failed applying migration v1: {e}"),
                "Check SQLite FTS5 availability and database permissions.",
            )
        })?;
        let now_str = Timestamp::now().to_string();
        tx.execute(
            "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?1, ?2, ?3)",
            rusqlite::params![1i64, MIGRATION_V1_NAME, now_str],
        )
        .map_err(|e| {
            CodedError::new(
                CODE_REL_MIGRATION,
                format!("Failed recording migration v1: {e}"),
                "Retry opening relational store.",
            )
        })?;
        tx.commit().map_err(|e| {
            CodedError::new(
                CODE_REL_MIGRATION,
                format!("Failed committing migration v1: {e}"),
                "Check disk space and permissions.",
            )
        })?;
    }

    Ok(())
}
