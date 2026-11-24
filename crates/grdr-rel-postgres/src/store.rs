// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::sync::{Mutex, MutexGuard};

use jiff::Timestamp;
use rusqlite::Connection;
use rusqlite::types::Value;
use serde::Serialize;
use serde::de::DeserializeOwned;

use grdr_model::CodedError;
use grdr_ports::{EntityKind, SingleCtx, TenantCtx};

use crate::config::{
    CODE_PG_CODEC, CODE_PG_IO, CODE_PG_MIGRATION, PostgresConfig, PostgresTransport,
};
use crate::dialect::{rls_session_statements, rls_write_statements};
use crate::migrations::{MigrationPhase, OFFLINE_SCHEMA_SQL, POSTGRES_MIGRATIONS};
use crate::wire::{
    WireConnParams, WireStatement, execute_extended_tx_wire, execute_simple_query_wire,
};

#[derive(Debug)]
pub(crate) enum StoreBackend {
    OfflineSqlite(Mutex<Connection>),
    WireTcp,
}

#[derive(Debug)]
pub struct PostgresRelationalStore {
    pub(crate) config: PostgresConfig,
    pub(crate) backend: StoreBackend,
}

impl PostgresRelationalStore {
    pub fn open_offline() -> Result<Self, CodedError> {
        let mut conn = Connection::open_in_memory().map_err(pg_sql_err)?;
        init_offline_postgres(&mut conn)?;
        Ok(Self {
            config: PostgresConfig::offline(),
            backend: StoreBackend::OfflineSqlite(Mutex::new(conn)),
        })
    }

    pub fn connect(config: PostgresConfig) -> Result<Self, CodedError> {
        config.validate()?;
        match &config.transport {
            PostgresTransport::OfflineEmbedded => Self::open_offline(),
            PostgresTransport::TcpWire {
                endpoint,
                database,
                user,
                password,
            } => {
                let conn = WireConnParams {
                    endpoint,
                    user,
                    database,
                    app_name: &config.application_name,
                    timeout_ms: config.connect_timeout_ms,
                    ssl_mode: config.ssl_mode,
                };
                let _ = execute_simple_query_wire(&conn, password.as_deref(), "SELECT 1")?;
                Ok(Self {
                    config,
                    backend: StoreBackend::WireTcp,
                })
            }
        }
    }

    pub fn run_migrations(&self) -> Result<(), CodedError> {
        let PostgresTransport::TcpWire {
            endpoint,
            database,
            user,
            password,
        } = &self.config.transport
        else {
            return Ok(());
        };
        let conn = WireConnParams {
            endpoint,
            user,
            database,
            app_name: &self.config.application_name,
            timeout_ms: self.config.connect_timeout_ms,
            ssl_mode: self.config.ssl_mode,
        };
        let _ = execute_simple_query_wire(
            &conn,
            password.as_deref(),
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                phase TEXT NOT NULL,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );",
        )?;
        let applied_rows = execute_simple_query_wire(
            &conn,
            password.as_deref(),
            "SELECT version::text FROM schema_migrations ORDER BY version ASC;",
        )?;
        let mut applied_versions = std::collections::BTreeSet::new();
        for row in applied_rows {
            if let Some(Some(v_str)) = row.first()
                && let Ok(ver) = v_str.trim().parse::<u32>()
            {
                applied_versions.insert(ver);
            }
        }
        for mig in POSTGRES_MIGRATIONS {
            if applied_versions.contains(&mig.version) {
                continue;
            }
            let record_sql = format!(
                "{}\nINSERT INTO schema_migrations (version, name, phase) VALUES ({}, '{}', '{}') ON CONFLICT (version) DO NOTHING;",
                mig.sql,
                mig.version,
                mig.name,
                phase_label(mig.phase),
            );
            let _ = execute_simple_query_wire(&conn, password.as_deref(), &record_sql)?;
        }
        Ok(())
    }

    pub fn config(&self) -> &PostgresConfig {
        &self.config
    }

    pub fn rls_guard_sql_for_read(&self, ctx: &TenantCtx) -> Result<Vec<String>, CodedError> {
        rls_session_statements(ctx)
    }

    pub fn rls_guard_sql_for_write(&self, ctx: &SingleCtx) -> Result<Vec<String>, CodedError> {
        rls_write_statements(ctx)
    }

    pub(crate) fn lock_offline(&self) -> Result<MutexGuard<'_, Connection>, CodedError> {
        match &self.backend {
            StoreBackend::OfflineSqlite(m) => m.lock().map_err(|_| {
                CodedError::new(
                    CODE_PG_IO,
                    "PostgreSQL offline store mutex poisoned.",
                    "Recreate PostgresRelationalStore.",
                )
            }),
            StoreBackend::WireTcp => Err(CodedError::new(
                CODE_PG_IO,
                "Offline SQLite connection requested on TcpWire store.",
                "Use wire execution helper for TcpWire mode.",
            )),
        }
    }

    pub(crate) fn execute_wire_statements(
        &self,
        rls_stmts: &[String],
        statements: &[WireStatement<'_>],
    ) -> Result<Vec<Vec<Vec<Option<String>>>>, CodedError> {
        let PostgresTransport::TcpWire {
            endpoint,
            database,
            user,
            password,
        } = &self.config.transport
        else {
            return Err(CodedError::new(
                CODE_PG_IO,
                "Wire execution requested on OfflineEmbedded store.",
                "Connect with a postgres:// DSN.",
            ));
        };
        let conn = WireConnParams {
            endpoint,
            user,
            database,
            app_name: &self.config.application_name,
            timeout_ms: self.config.statement_timeout_ms,
            ssl_mode: self.config.ssl_mode,
        };
        execute_extended_tx_wire(&conn, password.as_deref(), rls_stmts, statements)
    }
}

fn init_offline_postgres(conn: &mut Connection) -> Result<(), CodedError> {
    conn.execute_batch(OFFLINE_SCHEMA_SQL).map_err(|e| {
        CodedError::new(
            CODE_PG_MIGRATION,
            format!("Failed initializing offline PostgreSQL schema: {e}"),
            "Check SQLite runtime availability.",
        )
    })?;
    let now_str = Timestamp::now().to_string();
    for mig in POSTGRES_MIGRATIONS {
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations (version, name, phase, applied_at)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                i64::from(mig.version),
                mig.name,
                phase_label(mig.phase),
                now_str
            ],
        )
        .map_err(pg_sql_err)?;
    }
    Ok(())
}

fn phase_label(phase: MigrationPhase) -> &'static str {
    match phase {
        MigrationPhase::Expand => "expand",
        MigrationPhase::Backfill => "backfill",
        MigrationPhase::Contract => "contract",
    }
}

pub(crate) fn pg_sql_err(err: rusqlite::Error) -> CodedError {
    CodedError::new(
        CODE_PG_IO,
        format!("PostgreSQL adapter query failed: {err}"),
        "Inspect relational store state.",
    )
}

pub(crate) fn encode_json<T: Serialize>(value: &T) -> Result<String, CodedError> {
    serde_json::to_string(value).map_err(|e| {
        CodedError::new(
            CODE_PG_CODEC,
            format!("Failed encoding PostgreSQL JSON entity: {e}"),
            "Check entity payload fields.",
        )
    })
}

pub(crate) fn decode_json<T: DeserializeOwned>(raw: &str) -> Result<T, CodedError> {
    serde_json::from_str(raw).map_err(|e| {
        CodedError::new(
            CODE_PG_CODEC,
            format!("Failed decoding PostgreSQL JSON entity: {e}"),
            "Inspect stored JSON payload integrity.",
        )
    })
}

pub(crate) fn in_placeholders(count: usize, start_idx: usize) -> String {
    (0..count)
        .map(|offset| format!("?{}", start_idx.saturating_add(offset)))
        .collect::<Vec<_>>()
        .join(", ")
}

pub(crate) fn append_org_params(ctx: &TenantCtx, params: &mut Vec<Value>) {
    for org in ctx.organisation_ids() {
        params.push(Value::from(org.as_str().to_string()));
    }
}

pub(crate) fn query_json_rows<T: DeserializeOwned>(
    conn: &Connection,
    sql: &str,
    params: Vec<Value>,
) -> Result<Vec<T>, CodedError> {
    let mut stmt = conn.prepare(sql).map_err(pg_sql_err)?;
    let rows = stmt
        .query_map(rusqlite::params_from_iter(params), |row| {
            row.get::<_, String>(0)
        })
        .map_err(pg_sql_err)?;
    let mut out = Vec::new();
    for item in rows {
        let raw = item.map_err(pg_sql_err)?;
        out.push(decode_json(&raw)?);
    }
    Ok(out)
}

pub(crate) fn delete_search_parent(
    tx: &rusqlite::Transaction<'_>,
    org: &str,
    parent_key: &str,
) -> Result<(), CodedError> {
    tx.execute(
        "DELETE FROM entity_search_index WHERE organisation_id = ?1 AND parent_key = ?2",
        rusqlite::params![org, parent_key],
    )
    .map_err(pg_sql_err)?;
    Ok(())
}

pub(crate) fn insert_search_row(
    tx: &rusqlite::Transaction<'_>,
    org: &str,
    kind: EntityKind,
    entity_id: &str,
    parent_key: &str,
    title: &str,
    subtitle: &str,
) -> Result<(), CodedError> {
    tx.execute(
        "INSERT OR REPLACE INTO entity_search_index (
            organisation_id, entity_kind, entity_id, parent_key, title, subtitle
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![org, kind.as_str(), entity_id, parent_key, title, subtitle],
    )
    .map_err(pg_sql_err)?;
    Ok(())
}
