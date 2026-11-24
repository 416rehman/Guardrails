// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::fs;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rusqlite::types::Value;
use rusqlite::{Connection, OptionalExtension};
use serde::Serialize;
use serde::de::DeserializeOwned;

use grdr_model::{CodedError, Device, Finding, SessionSummary};
use grdr_ports::{DeviceRepo, EntityKind, FindingRepo, SessionSummaryRepo, SingleCtx, TenantCtx};

use crate::schema::{CODE_REL_CODEC, CODE_REL_IO, configure_and_migrate};

#[derive(Debug)]
pub struct SqliteRelationalStore {
    pub(crate) conn: Mutex<Connection>,
}

impl SqliteRelationalStore {
    pub fn open(path: &Path) -> Result<Self, CodedError> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|e| {
                CodedError::new(
                    CODE_REL_IO,
                    format!("Failed creating directory {}: {e}", parent.display()),
                    "Verify write permissions in --data-dir.",
                )
            })?;
        }
        let mut conn = Connection::open(path).map_err(|e| {
            CodedError::new(
                CODE_REL_IO,
                format!(
                    "Failed opening SQLite relational DB {}: {e}",
                    path.display()
                ),
                "Verify SQLite file path and permissions.",
            )
        })?;
        configure_and_migrate(&mut conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn open_in_memory() -> Result<Self, CodedError> {
        let mut conn = Connection::open_in_memory().map_err(|e| {
            CodedError::new(
                CODE_REL_IO,
                format!("Failed opening in-memory SQLite relational DB: {e}"),
                "Check SQLite runtime availability.",
            )
        })?;
        configure_and_migrate(&mut conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub(crate) fn lock_conn(&self) -> Result<MutexGuard<'_, Connection>, CodedError> {
        self.conn.lock().map_err(|_| {
            CodedError::new(
                CODE_REL_IO,
                "SQLite relational store mutex poisoned.",
                "Restart the storage adapter.",
            )
        })
    }
}

impl DeviceRepo for SqliteRelationalStore {
    fn upsert_device(&self, ctx: &SingleCtx, device: &Device) -> Result<(), CodedError> {
        let payload = encode_json(device)?;
        let org = ctx.organisation_id().as_str();
        let online = i64::from(device.online);
        let last_seen = device.last_seen.to_string();

        let mut conn = self.lock_conn()?;
        let tx = conn.transaction().map_err(sql_io_err)?;
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
                online,
                last_seen,
                payload
            ],
        )
        .map_err(sql_io_err)?;

        let parent_key = format!("device:{}", device.id);
        delete_fts_parent(&tx, org, &parent_key)?;
        insert_fts_row(
            &tx,
            org,
            EntityKind::Device,
            &device.id,
            &parent_key,
            &device.hostname,
            &format!("{} {}", device.os, device.arch),
        )?;
        for agent in &device.agents {
            insert_fts_row(
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
            insert_fts_row(
                &tx,
                org,
                EntityKind::McpServer,
                &mcp.name,
                &parent_key,
                &mcp.name,
                &mcp.transport,
            )?;
        }
        tx.commit().map_err(sql_io_err)?;
        Ok(())
    }

    fn get_device(&self, ctx: &TenantCtx, device_id: &str) -> Result<Option<Device>, CodedError> {
        let conn = self.lock_conn()?;
        let placeholders = in_placeholders(ctx.organisation_ids().len(), 2);
        let sql = format!(
            "SELECT payload_json FROM device WHERE device_id = ?1 AND organisation_id IN ({placeholders}) LIMIT 1"
        );
        let mut params = vec![Value::from(device_id.to_string())];
        append_org_params(ctx, &mut params);
        let raw: Option<String> = conn
            .query_row(&sql, rusqlite::params_from_iter(params), |r| r.get(0))
            .optional()
            .map_err(sql_io_err)?;
        raw.map(|s| decode_json(&s)).transpose()
    }

    fn list_devices(&self, ctx: &TenantCtx) -> Result<Vec<Device>, CodedError> {
        let conn = self.lock_conn()?;
        let placeholders = in_placeholders(ctx.organisation_ids().len(), 1);
        let sql = format!(
            "SELECT payload_json FROM device WHERE organisation_id IN ({placeholders}) ORDER BY last_seen DESC, device_id ASC"
        );
        let mut params = Vec::new();
        append_org_params(ctx, &mut params);
        query_json_rows(&conn, &sql, params)
    }
}

impl SessionSummaryRepo for SqliteRelationalStore {
    fn upsert_session_summary(
        &self,
        ctx: &SingleCtx,
        summary: &SessionSummary,
    ) -> Result<(), CodedError> {
        let payload = encode_json(summary)?;
        let org = ctx.organisation_id().as_str();
        let started_at = summary.started_at.to_string();
        let last_activity = summary.last_activity.to_string();

        let mut conn = self.lock_conn()?;
        let tx = conn.transaction().map_err(sql_io_err)?;
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
                started_at,
                last_activity,
                payload
            ],
        )
        .map_err(sql_io_err)?;

        let parent_key = format!("session:{}", summary.id);
        delete_fts_parent(&tx, org, &parent_key)?;
        insert_fts_row(
            &tx,
            org,
            EntityKind::Session,
            &summary.id,
            &parent_key,
            &summary.agent_name,
            &summary.device_name,
        )?;
        tx.commit().map_err(sql_io_err)?;
        Ok(())
    }

    fn get_session_summary(
        &self,
        ctx: &TenantCtx,
        session_id: &str,
    ) -> Result<Option<SessionSummary>, CodedError> {
        let conn = self.lock_conn()?;
        let placeholders = in_placeholders(ctx.organisation_ids().len(), 2);
        let sql = format!(
            "SELECT payload_json FROM session_summary WHERE session_id = ?1 AND organisation_id IN ({placeholders}) LIMIT 1"
        );
        let mut params = vec![Value::from(session_id.to_string())];
        append_org_params(ctx, &mut params);
        let raw: Option<String> = conn
            .query_row(&sql, rusqlite::params_from_iter(params), |r| r.get(0))
            .optional()
            .map_err(sql_io_err)?;
        raw.map(|s| decode_json(&s)).transpose()
    }

    fn list_session_summaries(&self, ctx: &TenantCtx) -> Result<Vec<SessionSummary>, CodedError> {
        let conn = self.lock_conn()?;
        let placeholders = in_placeholders(ctx.organisation_ids().len(), 1);
        let sql = format!(
            "SELECT payload_json FROM session_summary WHERE organisation_id IN ({placeholders}) ORDER BY last_activity DESC, session_id ASC"
        );
        let mut params = Vec::new();
        append_org_params(ctx, &mut params);
        query_json_rows(&conn, &sql, params)
    }
}

impl FindingRepo for SqliteRelationalStore {
    fn upsert_finding(&self, ctx: &SingleCtx, finding: &Finding) -> Result<(), CodedError> {
        let payload = encode_json(finding)?;
        let org = ctx.organisation_id().as_str();
        let severity = encode_json(&finding.severity)?;
        let lifecycle = encode_json(&finding.lifecycle)?;
        let detected_at = finding.detected_at.to_string();

        let mut conn = self.lock_conn()?;
        let tx = conn.transaction().map_err(sql_io_err)?;
        tx.execute(
            "INSERT INTO finding (organisation_id, finding_id, session_id, device_id, severity, lifecycle, detected_at, payload_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(organisation_id, finding_id) DO UPDATE SET
               session_id = excluded.session_id,
               device_id = excluded.device_id,
               severity = excluded.severity,
               lifecycle = excluded.lifecycle,
               detected_at = excluded.detected_at,
               payload_json = excluded.payload_json",
            rusqlite::params![
                org,
                finding.id,
                finding.session_id,
                finding.device_id,
                severity,
                lifecycle,
                detected_at,
                payload
            ],
        )
        .map_err(sql_io_err)?;

        let parent_key = format!("finding:{}", finding.id);
        delete_fts_parent(&tx, org, &parent_key)?;
        insert_fts_row(
            &tx,
            org,
            EntityKind::Finding,
            &finding.id,
            &parent_key,
            &finding.title,
            &finding.target,
        )?;
        tx.commit().map_err(sql_io_err)?;
        Ok(())
    }

    fn get_finding(
        &self,
        ctx: &TenantCtx,
        finding_id: &str,
    ) -> Result<Option<Finding>, CodedError> {
        let conn = self.lock_conn()?;
        let placeholders = in_placeholders(ctx.organisation_ids().len(), 2);
        let sql = format!(
            "SELECT payload_json FROM finding WHERE finding_id = ?1 AND organisation_id IN ({placeholders}) LIMIT 1"
        );
        let mut params = vec![Value::from(finding_id.to_string())];
        append_org_params(ctx, &mut params);
        let raw: Option<String> = conn
            .query_row(&sql, rusqlite::params_from_iter(params), |r| r.get(0))
            .optional()
            .map_err(sql_io_err)?;
        raw.map(|s| decode_json(&s)).transpose()
    }

    fn list_findings(&self, ctx: &TenantCtx) -> Result<Vec<Finding>, CodedError> {
        let conn = self.lock_conn()?;
        let placeholders = in_placeholders(ctx.organisation_ids().len(), 1);
        let sql = format!(
            "SELECT payload_json FROM finding WHERE organisation_id IN ({placeholders}) ORDER BY detected_at DESC, finding_id ASC"
        );
        let mut params = Vec::new();
        append_org_params(ctx, &mut params);
        query_json_rows(&conn, &sql, params)
    }
}

pub(crate) fn sql_io_err(err: rusqlite::Error) -> CodedError {
    CodedError::new(
        CODE_REL_IO,
        format!("SQLite relational query failed: {err}"),
        "Inspect relational SQLite store state.",
    )
}

pub(crate) fn encode_json<T: Serialize>(value: &T) -> Result<String, CodedError> {
    serde_json::to_string(value).map_err(|e| {
        CodedError::new(
            CODE_REL_CODEC,
            format!("Failed serializing relational entity: {e}"),
            "Check entity payload fields.",
        )
    })
}

pub(crate) fn decode_json<T: DeserializeOwned>(raw: &str) -> Result<T, CodedError> {
    serde_json::from_str(raw).map_err(|e| {
        CodedError::new(
            CODE_REL_CODEC,
            format!("Failed deserializing relational entity: {e}"),
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
    let mut stmt = conn.prepare(sql).map_err(sql_io_err)?;
    let rows = stmt
        .query_map(rusqlite::params_from_iter(params), |row| {
            row.get::<_, String>(0)
        })
        .map_err(sql_io_err)?;
    let mut out = Vec::new();
    for item in rows {
        let raw = item.map_err(sql_io_err)?;
        out.push(decode_json(&raw)?);
    }
    Ok(out)
}

pub(crate) fn delete_fts_parent(
    tx: &rusqlite::Transaction<'_>,
    org: &str,
    parent_key: &str,
) -> Result<(), CodedError> {
    tx.execute(
        "DELETE FROM entity_fts WHERE organisation_id = ?1 AND parent_key = ?2",
        rusqlite::params![org, parent_key],
    )
    .map_err(sql_io_err)?;
    Ok(())
}

pub(crate) fn insert_fts_row(
    tx: &rusqlite::Transaction<'_>,
    org: &str,
    kind: EntityKind,
    entity_id: &str,
    parent_key: &str,
    title: &str,
    subtitle: &str,
) -> Result<(), CodedError> {
    tx.execute(
        "INSERT INTO entity_fts (organisation_id, entity_kind, entity_id, parent_key, title, subtitle)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![org, kind.as_str(), entity_id, parent_key, title, subtitle],
    )
    .map_err(sql_io_err)?;
    Ok(())
}
