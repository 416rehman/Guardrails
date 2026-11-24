// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use rusqlite::Connection;

use grdr_model::CodedError;
use grdr_ports::CODE_BUS_IO;

const BUS_SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS bus_partition (
    stream TEXT NOT NULL,
    partition INTEGER NOT NULL,
    next_offset INTEGER NOT NULL,
    PRIMARY KEY (stream, partition)
);

CREATE TABLE IF NOT EXISTS bus_message (
    stream TEXT NOT NULL,
    partition INTEGER NOT NULL,
    offset INTEGER NOT NULL,
    organisation_id TEXT NOT NULL,
    delegation_id TEXT,
    delegation_epoch INTEGER,
    msg_key TEXT NOT NULL,
    headers_json TEXT NOT NULL,
    payload BLOB NOT NULL,
    appended_at_ms INTEGER NOT NULL,
    PRIMARY KEY (stream, partition, offset)
);

CREATE INDEX IF NOT EXISTS idx_bus_message_org
    ON bus_message (organisation_id, stream, partition, offset);

CREATE TABLE IF NOT EXISTS bus_consumer (
    consumer_group TEXT NOT NULL,
    stream TEXT NOT NULL,
    partition INTEGER NOT NULL,
    committed_offset INTEGER,
    checkpoint TEXT,
    holder TEXT NOT NULL,
    fence INTEGER NOT NULL,
    expiry_ms INTEGER NOT NULL,
    PRIMARY KEY (consumer_group, stream, partition)
);
"#;

pub(crate) fn configure_and_init_bus(conn: &mut Connection) -> Result<(), CodedError> {
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA foreign_keys = ON;
         PRAGMA busy_timeout = 5000;",
    )
    .map_err(|e| {
        CodedError::new(
            CODE_BUS_IO,
            format!("Failed applying SQLite WAL pragmas for bus: {e}"),
            "Check SQLite bus database permissions.",
        )
    })?;

    conn.execute_batch(BUS_SCHEMA_SQL).map_err(|e| {
        CodedError::new(
            CODE_BUS_IO,
            format!("Failed initializing SQLite bus tables: {e}"),
            "Verify bus SQLite database is writable.",
        )
    })?;

    Ok(())
}
