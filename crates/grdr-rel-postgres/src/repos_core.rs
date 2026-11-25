// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use rusqlite::OptionalExtension;
use rusqlite::types::Value;

use grdr_model::{CodedError, Device, Finding, SessionSummary};
use grdr_ports::{DeviceRepo, EntityKind, FindingRepo, SessionSummaryRepo, SingleCtx, TenantCtx};

use crate::dialect::{PostgresSqlRegistry, PostgresStatementId};
use crate::store::{
    PostgresRelationalStore, StoreBackend, append_org_params, decode_json, delete_search_parent,
    encode_json, in_placeholders, insert_search_row, pg_sql_err, query_json_rows,
};
use crate::wire::WireStatement;
use crate::wire_repos::{org_array_param, search_sync_statements, wire_get_json, wire_list_json};

impl DeviceRepo for PostgresRelationalStore {
    fn upsert_device(&self, ctx: &SingleCtx, device: &Device) -> Result<(), CodedError> {
        let rls = self.rls_guard_sql_for_write(ctx)?;
        let payload = encode_json(device)?;
        let org = ctx.organisation_id().as_str();
        let last_seen = device.last_seen.to_string();
        let parent_key = format!("device:{}", device.id);

        if matches!(self.backend, StoreBackend::WireTcp) {
            let dev_subtitle = format!("{} {}", device.os, device.arch);
            let mut search_rows = vec![(
                EntityKind::Device,
                device.id.as_str(),
                device.hostname.as_str(),
                dev_subtitle.as_str(),
            )];
            for agent in &device.agents {
                search_rows.push((
                    EntityKind::Agent,
                    agent.id.as_str(),
                    agent.name.as_str(),
                    agent.kind.as_str(),
                ));
            }
            for mcp in &device.mcp_servers {
                search_rows.push((
                    EntityKind::McpServer,
                    mcp.name.as_str(),
                    mcp.name.as_str(),
                    mcp.transport.as_str(),
                ));
            }
            let mut stmts = vec![WireStatement {
                sql: PostgresSqlRegistry::sql_for(PostgresStatementId::UpsertDevice),
                params: vec![
                    Some(org.to_string()),
                    Some(device.id.clone()),
                    Some(device.hostname.clone()),
                    Some(device.os.clone()),
                    Some(device.arch.clone()),
                    Some(device.online.to_string()),
                    Some(last_seen),
                    Some(payload),
                ],
            }];
            stmts.extend(search_sync_statements(org, &parent_key, &search_rows));
            let _ = self.execute_wire_statements(&rls, &stmts)?;
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
            return wire_get_json(
                self,
                &rls,
                PostgresStatementId::GetDevice,
                vec![Some(device_id.to_string()), Some(org_array_param(ctx))],
            );
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
        let rls = self.rls_guard_sql_for_read(ctx)?;
        if matches!(self.backend, StoreBackend::WireTcp) {
            return wire_list_json(
                self,
                &rls,
                PostgresStatementId::ListDevices,
                vec![Some(org_array_param(ctx))],
            );
        }

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
        let rls = self.rls_guard_sql_for_write(ctx)?;
        let payload = encode_json(summary)?;
        let org = ctx.organisation_id().as_str();
        let parent_key = format!("session:{}", summary.id);

        if matches!(self.backend, StoreBackend::WireTcp) {
            let search_rows = vec![(
                EntityKind::Session,
                summary.id.as_str(),
                summary.agent_name.as_str(),
                summary.device_name.as_str(),
            )];
            let mut stmts = vec![WireStatement {
                sql: PostgresSqlRegistry::sql_for(PostgresStatementId::UpsertSessionSummary),
                params: vec![
                    Some(org.to_string()),
                    Some(summary.id.clone()),
                    Some(summary.device_id.clone()),
                    Some(summary.agent_name.clone()),
                    summary.user_id.clone(),
                    Some(summary.started_at.to_string()),
                    Some(summary.last_activity.to_string()),
                    Some(payload),
                ],
            }];
            stmts.extend(search_sync_statements(org, &parent_key, &search_rows));
            let _ = self.execute_wire_statements(&rls, &stmts)?;
            return Ok(());
        }

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
        let rls = self.rls_guard_sql_for_read(ctx)?;
        if matches!(self.backend, StoreBackend::WireTcp) {
            return wire_get_json(
                self,
                &rls,
                PostgresStatementId::GetSessionSummary,
                vec![Some(session_id.to_string()), Some(org_array_param(ctx))],
            );
        }

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
        let rls = self.rls_guard_sql_for_read(ctx)?;
        if matches!(self.backend, StoreBackend::WireTcp) {
            return wire_list_json(
                self,
                &rls,
                PostgresStatementId::ListSessionSummaries,
                vec![Some(org_array_param(ctx))],
            );
        }

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

impl FindingRepo for PostgresRelationalStore {
    fn upsert_finding(&self, ctx: &SingleCtx, finding: &Finding) -> Result<(), CodedError> {
        let rls = self.rls_guard_sql_for_write(ctx)?;
        let payload = encode_json(finding)?;
        let org = ctx.organisation_id().as_str();
        let parent_key = format!("finding:{}", finding.id);
        let sev_json = encode_json(&finding.severity)?;
        let life_json = encode_json(&finding.lifecycle)?;

        if matches!(self.backend, StoreBackend::WireTcp) {
            let search_rows = vec![(
                EntityKind::Finding,
                finding.id.as_str(),
                finding.title.as_str(),
                finding.target.as_str(),
            )];
            let mut stmts = vec![WireStatement {
                sql: PostgresSqlRegistry::sql_for(PostgresStatementId::UpsertFinding),
                params: vec![
                    Some(org.to_string()),
                    Some(finding.id.clone()),
                    Some(finding.session_id.clone()),
                    Some(finding.device_id.clone()),
                    Some(sev_json),
                    Some(life_json),
                    Some(finding.detected_at.to_string()),
                    Some(payload),
                ],
            }];
            stmts.extend(search_sync_statements(org, &parent_key, &search_rows));
            let _ = self.execute_wire_statements(&rls, &stmts)?;
            return Ok(());
        }

        let mut conn = self.lock_offline()?;
        let tx = conn.transaction().map_err(pg_sql_err)?;
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
                sev_json,
                life_json,
                finding.detected_at.to_string(),
                payload
            ],
        )
        .map_err(pg_sql_err)?;
        delete_search_parent(&tx, org, &parent_key)?;
        insert_search_row(
            &tx,
            org,
            EntityKind::Finding,
            &finding.id,
            &parent_key,
            &finding.title,
            &finding.target,
        )?;
        tx.commit().map_err(pg_sql_err)?;
        Ok(())
    }

    fn get_finding(
        &self,
        ctx: &TenantCtx,
        finding_id: &str,
    ) -> Result<Option<Finding>, CodedError> {
        let rls = self.rls_guard_sql_for_read(ctx)?;
        if matches!(self.backend, StoreBackend::WireTcp) {
            return wire_get_json(
                self,
                &rls,
                PostgresStatementId::GetFinding,
                vec![Some(finding_id.to_string()), Some(org_array_param(ctx))],
            );
        }

        let conn = self.lock_offline()?;
        let placeholders = in_placeholders(ctx.organisation_ids().len(), 2);
        let sql = format!(
            "SELECT payload_json FROM finding WHERE finding_id = ?1 AND organisation_id IN ({placeholders}) LIMIT 1"
        );
        let mut params = vec![Value::from(finding_id.to_string())];
        append_org_params(ctx, &mut params);
        let raw: Option<String> = conn
            .query_row(&sql, rusqlite::params_from_iter(params), |r| r.get(0))
            .optional()
            .map_err(pg_sql_err)?;
        raw.map(|s| decode_json(&s)).transpose()
    }

    fn list_findings(&self, ctx: &TenantCtx) -> Result<Vec<Finding>, CodedError> {
        let rls = self.rls_guard_sql_for_read(ctx)?;
        if matches!(self.backend, StoreBackend::WireTcp) {
            return wire_list_json(
                self,
                &rls,
                PostgresStatementId::ListFindings,
                vec![Some(org_array_param(ctx))],
            );
        }

        let conn = self.lock_offline()?;
        let placeholders = in_placeholders(ctx.organisation_ids().len(), 1);
        let sql = format!(
            "SELECT payload_json FROM finding WHERE organisation_id IN ({placeholders}) ORDER BY detected_at DESC, finding_id ASC"
        );
        let mut params = Vec::new();
        append_org_params(ctx, &mut params);
        query_json_rows(&conn, &sql, params)
    }
}
