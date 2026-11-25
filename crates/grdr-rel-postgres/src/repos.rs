// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use jiff::Timestamp;
use rusqlite::OptionalExtension;
use rusqlite::types::Value;

use grdr_model::{CodedError, PolicyPack};
use grdr_ports::{
    EntityKind, EntitySearchHit, KvSnapshotRepo, MigrationRecord, PolicyRepo, ProfileKind,
    RelationalStorePort, SingleCtx, TenantCtx, TenantUserRecord, UserRepo,
};

use crate::dialect::{PostgresSqlRegistry, PostgresStatementId};
use crate::store::{
    PostgresRelationalStore, StoreBackend, append_org_params, decode_json, delete_search_parent,
    encode_json, in_placeholders, insert_search_row, pg_sql_err, query_json_rows,
};
use crate::wire::WireStatement;
use crate::wire_repos::{
    org_array_param, search_sync_statements, wire_applied_migrations, wire_get_json,
    wire_list_json, wire_list_kv, wire_search_entities,
};

impl PolicyRepo for PostgresRelationalStore {
    fn upsert_pack(&self, ctx: &SingleCtx, pack: &PolicyPack) -> Result<(), CodedError> {
        let rls = self.rls_guard_sql_for_write(ctx)?;
        let payload = encode_json(pack)?;
        let org = ctx.organisation_id().as_str();
        let parent_key = format!("pack:{}", pack.id);

        if matches!(self.backend, StoreBackend::WireTcp) {
            let subtitles: Vec<String> = pack
                .rules
                .iter()
                .map(|r| format!("{} {}", r.id, pack.name))
                .collect();
            let search_rows: Vec<_> = pack
                .rules
                .iter()
                .zip(subtitles.iter())
                .map(|(r, sub)| {
                    (
                        EntityKind::Rule,
                        r.id.as_str(),
                        r.title.as_str(),
                        sub.as_str(),
                    )
                })
                .collect();
            let mut stmts = vec![WireStatement {
                sql: PostgresSqlRegistry::sql_for(PostgresStatementId::UpsertPolicyPack),
                params: vec![
                    Some(org.to_string()),
                    Some(pack.id.clone()),
                    Some(pack.name.clone()),
                    Some(pack.version.clone()),
                    Some(pack.channel.clone()),
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
            "INSERT INTO policy_pack (organisation_id, pack_id, name, version, channel, payload_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(organisation_id, pack_id) DO UPDATE SET
               name = excluded.name,
               version = excluded.version,
               channel = excluded.channel,
               payload_json = excluded.payload_json",
            rusqlite::params![org, pack.id, pack.name, pack.version, pack.channel, payload],
        )
        .map_err(pg_sql_err)?;

        delete_search_parent(&tx, org, &parent_key)?;
        for rule in &pack.rules {
            insert_search_row(
                &tx,
                org,
                EntityKind::Rule,
                &rule.id,
                &parent_key,
                &rule.title,
                &format!("{} {}", rule.id, pack.name),
            )?;
        }
        tx.commit().map_err(pg_sql_err)?;
        Ok(())
    }

    fn get_pack(&self, ctx: &TenantCtx, pack_id: &str) -> Result<Option<PolicyPack>, CodedError> {
        let rls = self.rls_guard_sql_for_read(ctx)?;
        if matches!(self.backend, StoreBackend::WireTcp) {
            return wire_get_json(
                self,
                &rls,
                PostgresStatementId::GetPolicyPack,
                vec![Some(pack_id.to_string()), Some(org_array_param(ctx))],
            );
        }

        let conn = self.lock_offline()?;
        let placeholders = in_placeholders(ctx.organisation_ids().len(), 2);
        let sql = format!(
            "SELECT payload_json FROM policy_pack WHERE pack_id = ?1 AND organisation_id IN ({placeholders}) LIMIT 1"
        );
        let mut params = vec![Value::from(pack_id.to_string())];
        append_org_params(ctx, &mut params);
        let raw: Option<String> = conn
            .query_row(&sql, rusqlite::params_from_iter(params), |r| r.get(0))
            .optional()
            .map_err(pg_sql_err)?;
        raw.map(|s| decode_json(&s)).transpose()
    }

    fn list_packs(&self, ctx: &TenantCtx) -> Result<Vec<PolicyPack>, CodedError> {
        let rls = self.rls_guard_sql_for_read(ctx)?;
        if matches!(self.backend, StoreBackend::WireTcp) {
            return wire_list_json(
                self,
                &rls,
                PostgresStatementId::ListPolicyPacks,
                vec![Some(org_array_param(ctx))],
            );
        }

        let conn = self.lock_offline()?;
        let placeholders = in_placeholders(ctx.organisation_ids().len(), 1);
        let sql = format!(
            "SELECT payload_json FROM policy_pack WHERE organisation_id IN ({placeholders}) ORDER BY pack_id ASC"
        );
        let mut params = Vec::new();
        append_org_params(ctx, &mut params);
        query_json_rows(&conn, &sql, params)
    }
}

impl UserRepo for PostgresRelationalStore {
    fn upsert_user(&self, ctx: &SingleCtx, user: &TenantUserRecord) -> Result<(), CodedError> {
        let rls = self.rls_guard_sql_for_write(ctx)?;
        let payload = encode_json(user)?;
        let org = ctx.organisation_id().as_str();
        let parent_key = format!("user:{}", user.id);

        if matches!(self.backend, StoreBackend::WireTcp) {
            let subtitle = format!("{} {}", user.email, user.department);
            let search_rows = vec![(
                EntityKind::User,
                user.id.as_str(),
                user.display_name.as_str(),
                subtitle.as_str(),
            )];
            let mut stmts = vec![WireStatement {
                sql: PostgresSqlRegistry::sql_for(PostgresStatementId::UpsertUser),
                params: vec![
                    Some(org.to_string()),
                    Some(user.id.clone()),
                    Some(user.display_name.clone()),
                    Some(user.email.clone()),
                    Some(user.department.clone()),
                    Some(user.pseudonym_id.clone()),
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
            "INSERT INTO user_profile (organisation_id, user_id, display_name, email, department, pseudonym_id, payload_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(organisation_id, user_id) DO UPDATE SET
               display_name = excluded.display_name,
               email = excluded.email,
               department = excluded.department,
               pseudonym_id = excluded.pseudonym_id,
               payload_json = excluded.payload_json",
            rusqlite::params![
                org,
                user.id,
                user.display_name,
                user.email,
                user.department,
                user.pseudonym_id,
                payload
            ],
        )
        .map_err(pg_sql_err)?;

        delete_search_parent(&tx, org, &parent_key)?;
        insert_search_row(
            &tx,
            org,
            EntityKind::User,
            &user.id,
            &parent_key,
            &user.display_name,
            &format!("{} {}", user.email, user.department),
        )?;
        tx.commit().map_err(pg_sql_err)?;
        Ok(())
    }

    fn get_user(
        &self,
        ctx: &TenantCtx,
        user_id: &str,
    ) -> Result<Option<TenantUserRecord>, CodedError> {
        let rls = self.rls_guard_sql_for_read(ctx)?;
        if matches!(self.backend, StoreBackend::WireTcp) {
            return wire_get_json(
                self,
                &rls,
                PostgresStatementId::GetUser,
                vec![Some(user_id.to_string()), Some(org_array_param(ctx))],
            );
        }

        let conn = self.lock_offline()?;
        let placeholders = in_placeholders(ctx.organisation_ids().len(), 2);
        let sql = format!(
            "SELECT payload_json FROM user_profile WHERE user_id = ?1 AND organisation_id IN ({placeholders}) LIMIT 1"
        );
        let mut params = vec![Value::from(user_id.to_string())];
        append_org_params(ctx, &mut params);
        let raw: Option<String> = conn
            .query_row(&sql, rusqlite::params_from_iter(params), |r| r.get(0))
            .optional()
            .map_err(pg_sql_err)?;
        raw.map(|s| decode_json(&s)).transpose()
    }

    fn list_users(&self, ctx: &TenantCtx) -> Result<Vec<TenantUserRecord>, CodedError> {
        let rls = self.rls_guard_sql_for_read(ctx)?;
        if matches!(self.backend, StoreBackend::WireTcp) {
            return wire_list_json(
                self,
                &rls,
                PostgresStatementId::ListUsers,
                vec![Some(org_array_param(ctx))],
            );
        }

        let conn = self.lock_offline()?;
        let placeholders = in_placeholders(ctx.organisation_ids().len(), 1);
        let sql = format!(
            "SELECT payload_json FROM user_profile WHERE organisation_id IN ({placeholders}) ORDER BY user_id ASC"
        );
        let mut params = Vec::new();
        append_org_params(ctx, &mut params);
        query_json_rows(&conn, &sql, params)
    }
}

impl KvSnapshotRepo for PostgresRelationalStore {
    fn put_kv(
        &self,
        ctx: &SingleCtx,
        namespace: &str,
        key: &str,
        value_json: &str,
    ) -> Result<(), CodedError> {
        let rls = self.rls_guard_sql_for_write(ctx)?;
        if matches!(self.backend, StoreBackend::WireTcp) {
            let stmts = [WireStatement {
                sql: PostgresSqlRegistry::sql_for(PostgresStatementId::PutKv),
                params: vec![
                    Some(ctx.organisation_id().as_str().to_string()),
                    Some(namespace.to_string()),
                    Some(key.to_string()),
                    Some(value_json.to_string()),
                ],
            }];
            let _ = self.execute_wire_statements(&rls, &stmts)?;
            return Ok(());
        }

        let conn = self.lock_offline()?;
        let now_str = Timestamp::now().to_string();
        conn.execute(
            "INSERT INTO tenant_kv (organisation_id, namespace, entry_key, value_json, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(organisation_id, namespace, entry_key) DO UPDATE SET
               value_json = excluded.value_json,
               updated_at = excluded.updated_at",
            rusqlite::params![
                ctx.organisation_id().as_str(),
                namespace,
                key,
                value_json,
                now_str
            ],
        )
        .map_err(pg_sql_err)?;
        Ok(())
    }

    fn get_kv(
        &self,
        ctx: &TenantCtx,
        namespace: &str,
        key: &str,
    ) -> Result<Option<String>, CodedError> {
        let rls = self.rls_guard_sql_for_read(ctx)?;
        if matches!(self.backend, StoreBackend::WireTcp) {
            let stmts = [WireStatement {
                sql: PostgresSqlRegistry::sql_for(PostgresStatementId::GetKv),
                params: vec![
                    Some(namespace.to_string()),
                    Some(key.to_string()),
                    Some(org_array_param(ctx)),
                ],
            }];
            let res = self.execute_wire_statements(&rls, &stmts)?;
            return Ok(res
                .first()
                .and_then(|rows| rows.first())
                .and_then(|cols| cols.first())
                .and_then(|val| val.clone()));
        }

        let conn = self.lock_offline()?;
        let placeholders = in_placeholders(ctx.organisation_ids().len(), 3);
        let sql = format!(
            "SELECT value_json FROM tenant_kv WHERE namespace = ?1 AND entry_key = ?2 AND organisation_id IN ({placeholders}) LIMIT 1"
        );
        let mut params = vec![
            Value::from(namespace.to_string()),
            Value::from(key.to_string()),
        ];
        append_org_params(ctx, &mut params);
        conn.query_row(&sql, rusqlite::params_from_iter(params), |r| r.get(0))
            .optional()
            .map_err(pg_sql_err)
    }

    fn list_kv(
        &self,
        ctx: &TenantCtx,
        namespace: &str,
    ) -> Result<Vec<(String, String)>, CodedError> {
        let rls = self.rls_guard_sql_for_read(ctx)?;
        if matches!(self.backend, StoreBackend::WireTcp) {
            return wire_list_kv(self, &rls, ctx, namespace);
        }

        let conn = self.lock_offline()?;
        let placeholders = in_placeholders(ctx.organisation_ids().len(), 2);
        let sql = format!(
            "SELECT entry_key, value_json FROM tenant_kv WHERE namespace = ?1 AND organisation_id IN ({placeholders}) ORDER BY entry_key ASC"
        );
        let mut params = vec![Value::from(namespace.to_string())];
        append_org_params(ctx, &mut params);
        let mut stmt = conn.prepare(&sql).map_err(pg_sql_err)?;
        let rows = stmt
            .query_map(rusqlite::params_from_iter(params), |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(pg_sql_err)?;
        let mut out = Vec::new();
        for item in rows {
            out.push(item.map_err(pg_sql_err)?);
        }
        Ok(out)
    }

    fn delete_kv(&self, ctx: &SingleCtx, namespace: &str, key: &str) -> Result<(), CodedError> {
        let rls = self.rls_guard_sql_for_write(ctx)?;
        if matches!(self.backend, StoreBackend::WireTcp) {
            let stmts = [WireStatement {
                sql: PostgresSqlRegistry::sql_for(PostgresStatementId::DeleteKv),
                params: vec![
                    Some(ctx.organisation_id().as_str().to_string()),
                    Some(namespace.to_string()),
                    Some(key.to_string()),
                ],
            }];
            let _ = self.execute_wire_statements(&rls, &stmts)?;
            return Ok(());
        }

        let conn = self.lock_offline()?;
        conn.execute(
            "DELETE FROM tenant_kv WHERE organisation_id = ?1 AND namespace = ?2 AND entry_key = ?3",
            rusqlite::params![ctx.organisation_id().as_str(), namespace, key],
        )
        .map_err(pg_sql_err)?;
        Ok(())
    }
}

impl RelationalStorePort for PostgresRelationalStore {
    fn profile(&self) -> ProfileKind {
        ProfileKind::Ha
    }

    fn search_entities(
        &self,
        ctx: &TenantCtx,
        query: &str,
        limit: usize,
    ) -> Result<Vec<EntitySearchHit>, CodedError> {
        let rls = self.rls_guard_sql_for_read(ctx)?;
        let needle = query.trim().to_ascii_lowercase();
        if needle.is_empty() || limit == 0 {
            return Ok(Vec::new());
        }
        if matches!(self.backend, StoreBackend::WireTcp) {
            return wire_search_entities(self, &rls, ctx, &needle, limit);
        }

        let pattern = format!("%{needle}%");
        let conn = self.lock_offline()?;
        let org_count = ctx.organisation_ids().len();
        let placeholders = in_placeholders(org_count, 2);
        let limit_idx = org_count.saturating_add(2);
        let sql = format!(
            "SELECT entity_kind, entity_id, title, subtitle
             FROM entity_search_index
             WHERE organisation_id IN ({placeholders}) AND (LOWER(title) LIKE ?1 OR LOWER(subtitle) LIKE ?1)
             ORDER BY entity_id ASC
             LIMIT ?{limit_idx}"
        );
        let mut params = vec![Value::from(pattern)];
        append_org_params(ctx, &mut params);
        params.push(Value::from(i64::try_from(limit).unwrap_or(i64::MAX)));

        let mut stmt = conn.prepare(&sql).map_err(pg_sql_err)?;
        let rows = stmt
            .query_map(rusqlite::params_from_iter(params), |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .map_err(pg_sql_err)?;
        let mut out = Vec::new();
        for item in rows {
            let (kind_str, entity_id, title, subtitle) = item.map_err(pg_sql_err)?;
            let Some(entity_kind) = EntityKind::parse(&kind_str) else {
                continue;
            };
            out.push(EntitySearchHit {
                entity_kind,
                entity_id,
                title,
                subtitle,
                rank_score: 100,
            });
        }
        Ok(out)
    }

    fn applied_migrations(&self) -> Result<Vec<MigrationRecord>, CodedError> {
        if matches!(self.backend, StoreBackend::WireTcp) {
            return wire_applied_migrations(self);
        }

        let conn = self.lock_offline()?;
        let mut stmt = conn
            .prepare("SELECT version, name, applied_at FROM schema_migrations ORDER BY version ASC")
            .map_err(pg_sql_err)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(pg_sql_err)?;
        let mut out = Vec::new();
        for item in rows {
            let (ver, name, applied_at) = item.map_err(pg_sql_err)?;
            out.push(MigrationRecord {
                version: u32::try_from(ver).unwrap_or(0),
                name,
                applied_at,
            });
        }
        Ok(out)
    }
}
