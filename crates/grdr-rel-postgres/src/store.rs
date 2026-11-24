// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::sync::{Mutex, MutexGuard};

use jiff::Timestamp;
use rusqlite::types::Value;
use rusqlite::{Connection, OptionalExtension};
use serde::Serialize;
use serde::de::DeserializeOwned;

use grdr_model::{CodedError, Device, SessionSummary};
use grdr_ports::{DeviceRepo, EntityKind, SessionSummaryRepo, SingleCtx, TenantCtx};

use crate::config::{
    CODE_PG_CODEC, CODE_PG_IO, CODE_PG_MIGRATION, PostgresConfig, PostgresTransport,
};
use crate::dialect::{
    PostgresSqlRegistry, PostgresStatementId, rls_session_statements, rls_write_statements,
};
use crate::migrations::{MigrationPhase, OFFLINE_SCHEMA_SQL, POSTGRES_MIGRATIONS};
use crate::wire::execute_simple_query_wire;

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
                for mig in POSTGRES_MIGRATIONS {
                    let record_sql = format!(
                        "{}\nINSERT INTO schema_migrations (version, name, phase) VALUES ({}, '{}', '{}') ON CONFLICT (version) DO NOTHING;",
                        mig.sql,
                        mig.version,
                        mig.name,
                        phase_label(mig.phase),
                    );
                    execute_simple_query_wire(
                        endpoint,
                        user,
                        database,
                        password.as_deref(),
                        &config.application_name,
                        config.connect_timeout_ms,
                        &record_sql,
                    )?;
                }
                Ok(Self {
                    config,
                    backend: StoreBackend::WireTcp,
                })
            }
        }
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

    pub(crate) fn execute_wire_with_rls(
        &self,
        rls_stmts: &[String],
        statement_sql: &str,
    ) -> Result<Vec<Vec<Option<String>>>, CodedError> {
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
        let batch = format!(
            "BEGIN; {}; {}; COMMIT;",
            rls_stmts.join("; "),
            statement_sql.trim_end_matches(';')
        );
        execute_simple_query_wire(
            endpoint,
            user,
            database,
            password.as_deref(),
            &self.config.application_name,
            self.config.statement_timeout_ms,
            &batch,
        )
    }
}

impl DeviceRepo for PostgresRelationalStore {
    fn upsert_device(&self, ctx: &SingleCtx, device: &Device) -> Result<(), CodedError> {
        let rls = self.rls_guard_sql_for_write(ctx)?;
        let payload = encode_json(device)?;
        let org = ctx.organisation_id().as_str();
        let last_seen = device.last_seen.to_string();

        if matches!(self.backend, StoreBackend::WireTcp) {
            let sql = format!(
                "{} -- {}",
                PostgresSqlRegistry::sql_for(PostgresStatementId::UpsertDevice),
                sql_literal(org)
            );
            let _ = self.execute_wire_with_rls(&rls, &sql)?;
            return Ok(());
        }

        let mut conn = self.lock_offline()?;
        let tx = conn.transaction().map_err(pg_sql_err)?;
        tx.execute(
            "INSERT INTO device (organisation_id, device_id, hostname, os, arch, online, last_seen, payload_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(organisation_id, device_id) DO UPDATE SET
               hostname = excluded.hostname,
               os = excluded.os,
               arch = excluded.arch,
               online = excluded.online,
               last_seen = excluded.last_seen,
               payload_json = excluded.payload_json",
            rusqlite::params![
                org,
                device.id,
                device.hostname,
                device.os,
                device.arch,
                i64::from(device.online),
                last_seen,
                payload
            ],
        )
        .map_err(pg_sql_err)?;
        let parent_key = format!("device:{}", device.id);
        delete_search_parent(&tx, org, &parent_key)?;
        insert_search_row(
            &tx,
            org,
            EntityKind::Device,
            &device.id,
            &parent_key,
            &device.hostname,
            &format!("{} {}", device.os, device.arch),
        )?;
        for agent in &device.agents {
            insert_search_row(
                &tx,
                org,
                EntityKind::Agent,
                &agent.id,
                &parent_key,
                &agent.name,
                &agent.kind,
            )?;
        }
        for mcp in &device.mcp_servers {
            insert_search_row(
                &tx,
                org,
                EntityKind::McpServer,
                &mcp.name,
                &parent_key,
                &mcp.name,
                &mcp.transport,
            )?;
        }
        tx.commit().map_err(pg_sql_err)?;
        Ok(())
    }

    fn get_device(&self, ctx: &TenantCtx, device_id: &str) -> Result<Option<Device>, CodedError> {
        let rls = self.rls_guard_sql_for_read(ctx)?;
        if matches!(self.backend, StoreBackend::WireTcp) {
            let sql = PostgresSqlRegistry::sql_for(PostgresStatementId::GetDevice);
            let rows = self.execute_wire_with_rls(&rls, sql)?;
            return rows
                .first()
                .and_then(|r| r.first())
                .and_then(|v| v.as_deref())
                .map(decode_json)
                .transpose();
        }

        let conn = self.lock_offline()?;
        let placeholders = in_placeholders(ctx.organisation_ids().len(), 2);
        let sql = format!(
            "SELECT payload_json FROM device WHERE device_id = ?1 AND organisation_id IN ({placeholders}) LIMIT 1"
        );
        let mut params = vec![Value::from(device_id.to_string())];
        append_org_params(ctx, &mut params);
        let raw: Option<String> = conn
            .query_row(&sql, rusqlite::params_from_iter(params), |r| r.get(0))
            .optional()
            .map_err(pg_sql_err)?;
        raw.map(|s| decode_json(&s)).transpose()
    }

    fn list_devices(&self, ctx: &TenantCtx) -> Result<Vec<Device>, CodedError> {
        let _ = self.rls_guard_sql_for_read(ctx)?;
        let conn = self.lock_offline()?;
        let placeholders = in_placeholders(ctx.organisation_ids().len(), 1);
        let sql = format!(
            "SELECT payload_json FROM device WHERE organisation_id IN ({placeholders}) ORDER BY last_seen DESC, device_id ASC"
        );
        let mut params = Vec::new();
        append_org_params(ctx, &mut params);
        query_json_rows(&conn, &sql, params)
    }
}

impl SessionSummaryRepo for PostgresRelationalStore {
    fn upsert_session_summary(
        &self,
        ctx: &SingleCtx,
        summary: &SessionSummary,
    ) -> Result<(), CodedError> {
        let _ = self.rls_guard_sql_for_write(ctx)?;
        let payload = encode_json(summary)?;
        let org = ctx.organisation_id().as_str();
        let mut conn = self.lock_offline()?;
        let tx = conn.transaction().map_err(pg_sql_err)?;
        tx.execute(
            "INSERT INTO session_summary (organisation_id, session_id, device_id, agent_name, user_id, started_at, last_activity, payload_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(organisation_id, session_id) DO UPDATE SET
               device_id = excluded.device_id,
               agent_name = excluded.agent_name,
               user_id = excluded.user_id,
               started_at = excluded.started_at,
               last_activity = excluded.last_activity,
               payload_json = excluded.payload_json",
            rusqlite::params![
                org,
                summary.id,
                summary.device_id,
                summary.agent_name,
                summary.user_id,
                summary.started_at.to_string(),
                summary.last_activity.to_string(),
                payload
            ],
        )
        .map_err(pg_sql_err)?;
        let parent_key = format!("session:{}", summary.id);
        delete_search_parent(&tx, org, &parent_key)?;
        insert_search_row(
            &tx,
            org,
            EntityKind::Session,
            &summary.id,
            &parent_key,
            &summary.agent_name,
            &summary.device_name,
        )?;
        tx.commit().map_err(pg_sql_err)?;
        Ok(())
    }

    fn get_session_summary(
        &self,
        ctx: &TenantCtx,
        session_id: &str,
    ) -> Result<Option<SessionSummary>, CodedError> {
        let _ = self.rls_guard_sql_for_read(ctx)?;
        let conn = self.lock_offline()?;
        let placeholders = in_placeholders(ctx.organisation_ids().len(), 2);
        let sql = format!(
            "SELECT payload_json FROM session_summary WHERE session_id = ?1 AND organisation_id IN ({placeholders}) LIMIT 1"
        );
        let mut params = vec![Value::from(session_id.to_string())];
        append_org_params(ctx, &mut params);
        let raw: Option<String> = conn
            .query_row(&sql, rusqlite::params_from_iter(params), |r| r.get(0))
            .optional()
            .map_err(pg_sql_err)?;
        raw.map(|s| decode_json(&s)).transpose()
    }

    fn list_session_summaries(&self, ctx: &TenantCtx) -> Result<Vec<SessionSummary>, CodedError> {
        let _ = self.rls_guard_sql_for_read(ctx)?;
        let conn = self.lock_offline()?;
        let placeholders = in_placeholders(ctx.organisation_ids().len(), 1);
        let sql = format!(
            "SELECT payload_json FROM session_summary WHERE organisation_id IN ({placeholders}) ORDER BY last_activity DESC, session_id ASC"
        );
        let mut params = Vec::new();
        append_org_params(ctx, &mut params);
        query_json_rows(&conn, &sql, params)
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

fn sql_literal(raw: &str) -> String {
    raw.replace('\'', "''")
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
