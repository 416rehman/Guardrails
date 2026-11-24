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

use crate::store::{
    SqliteRelationalStore, append_org_params, decode_json, delete_fts_parent, encode_json,
    in_placeholders, insert_fts_row, query_json_rows, sql_io_err,
};

impl PolicyRepo for SqliteRelationalStore {
    fn upsert_pack(&self, ctx: &SingleCtx, pack: &PolicyPack) -> Result<(), CodedError> {
        let payload = encode_json(pack)?;
        let org = ctx.organisation_id().as_str();

        let mut conn = self.lock_conn()?;
        let tx = conn.transaction().map_err(sql_io_err)?;
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
        .map_err(sql_io_err)?;

        let parent_key = format!("pack:{}", pack.id);
        delete_fts_parent(&tx, org, &parent_key)?;
        for rule in &pack.rules {
            insert_fts_row(
                &tx,
                org,
                EntityKind::Rule,
                &rule.id,
                &parent_key,
                &rule.title,
                &format!("{} {}", rule.id, pack.name),
            )?;
        }
        tx.commit().map_err(sql_io_err)?;
        Ok(())
    }

    fn get_pack(&self, ctx: &TenantCtx, pack_id: &str) -> Result<Option<PolicyPack>, CodedError> {
        let conn = self.lock_conn()?;
        let placeholders = in_placeholders(ctx.organisation_ids().len(), 2);
        let sql = format!(
            "SELECT payload_json FROM policy_pack WHERE pack_id = ?1 AND organisation_id IN ({placeholders}) LIMIT 1"
        );
        let mut params = vec![Value::from(pack_id.to_string())];
        append_org_params(ctx, &mut params);
        let raw: Option<String> = conn
            .query_row(&sql, rusqlite::params_from_iter(params), |r| r.get(0))
            .optional()
            .map_err(sql_io_err)?;
        raw.map(|s| decode_json(&s)).transpose()
    }

    fn list_packs(&self, ctx: &TenantCtx) -> Result<Vec<PolicyPack>, CodedError> {
        let conn = self.lock_conn()?;
        let placeholders = in_placeholders(ctx.organisation_ids().len(), 1);
        let sql = format!(
            "SELECT payload_json FROM policy_pack WHERE organisation_id IN ({placeholders}) ORDER BY pack_id ASC"
        );
        let mut params = Vec::new();
        append_org_params(ctx, &mut params);
        query_json_rows(&conn, &sql, params)
    }
}

impl UserRepo for SqliteRelationalStore {
    fn upsert_user(&self, ctx: &SingleCtx, user: &TenantUserRecord) -> Result<(), CodedError> {
        let payload = encode_json(user)?;
        let org = ctx.organisation_id().as_str();

        let mut conn = self.lock_conn()?;
        let tx = conn.transaction().map_err(sql_io_err)?;
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
        .map_err(sql_io_err)?;

        let parent_key = format!("user:{}", user.id);
        delete_fts_parent(&tx, org, &parent_key)?;
        insert_fts_row(
            &tx,
            org,
            EntityKind::User,
            &user.id,
            &parent_key,
            &user.display_name,
            &format!("{} {}", user.email, user.department),
        )?;
        tx.commit().map_err(sql_io_err)?;
        Ok(())
    }

    fn get_user(
        &self,
        ctx: &TenantCtx,
        user_id: &str,
    ) -> Result<Option<TenantUserRecord>, CodedError> {
        let conn = self.lock_conn()?;
        let placeholders = in_placeholders(ctx.organisation_ids().len(), 2);
        let sql = format!(
            "SELECT payload_json FROM user_profile WHERE user_id = ?1 AND organisation_id IN ({placeholders}) LIMIT 1"
        );
        let mut params = vec![Value::from(user_id.to_string())];
        append_org_params(ctx, &mut params);
        let raw: Option<String> = conn
            .query_row(&sql, rusqlite::params_from_iter(params), |r| r.get(0))
            .optional()
            .map_err(sql_io_err)?;
        raw.map(|s| decode_json(&s)).transpose()
    }

    fn list_users(&self, ctx: &TenantCtx) -> Result<Vec<TenantUserRecord>, CodedError> {
        let conn = self.lock_conn()?;
        let placeholders = in_placeholders(ctx.organisation_ids().len(), 1);
        let sql = format!(
            "SELECT payload_json FROM user_profile WHERE organisation_id IN ({placeholders}) ORDER BY user_id ASC"
        );
        let mut params = Vec::new();
        append_org_params(ctx, &mut params);
        query_json_rows(&conn, &sql, params)
    }
}

impl KvSnapshotRepo for SqliteRelationalStore {
    fn put_kv(
        &self,
        ctx: &SingleCtx,
        namespace: &str,
        key: &str,
        value_json: &str,
    ) -> Result<(), CodedError> {
        let conn = self.lock_conn()?;
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
        .map_err(sql_io_err)?;
        Ok(())
    }

    fn get_kv(
        &self,
        ctx: &TenantCtx,
        namespace: &str,
        key: &str,
    ) -> Result<Option<String>, CodedError> {
        let conn = self.lock_conn()?;
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
            .map_err(sql_io_err)
    }

    fn list_kv(
        &self,
        ctx: &TenantCtx,
        namespace: &str,
    ) -> Result<Vec<(String, String)>, CodedError> {
        let conn = self.lock_conn()?;
        let placeholders = in_placeholders(ctx.organisation_ids().len(), 2);
        let sql = format!(
            "SELECT entry_key, value_json FROM tenant_kv WHERE namespace = ?1 AND organisation_id IN ({placeholders}) ORDER BY entry_key ASC"
        );
        let mut params = vec![Value::from(namespace.to_string())];
        append_org_params(ctx, &mut params);
        let mut stmt = conn.prepare(&sql).map_err(sql_io_err)?;
        let rows = stmt
            .query_map(rusqlite::params_from_iter(params), |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(sql_io_err)?;
        let mut out = Vec::new();
        for item in rows {
            out.push(item.map_err(sql_io_err)?);
        }
        Ok(out)
    }

    fn delete_kv(&self, ctx: &SingleCtx, namespace: &str, key: &str) -> Result<(), CodedError> {
        let conn = self.lock_conn()?;
        conn.execute(
            "DELETE FROM tenant_kv WHERE organisation_id = ?1 AND namespace = ?2 AND entry_key = ?3",
            rusqlite::params![ctx.organisation_id().as_str(), namespace, key],
        )
        .map_err(sql_io_err)?;
        Ok(())
    }
}

impl RelationalStorePort for SqliteRelationalStore {
    fn profile(&self) -> ProfileKind {
        ProfileKind::Embedded
    }

    fn search_entities(
        &self,
        ctx: &TenantCtx,
        query: &str,
        limit: usize,
    ) -> Result<Vec<EntitySearchHit>, CodedError> {
        let Some(fts_query) = sanitize_fts_query(query) else {
            return Ok(Vec::new());
        };
        if limit == 0 {
            return Ok(Vec::new());
        }
        let conn = self.lock_conn()?;
        let org_count = ctx.organisation_ids().len();
        let placeholders = in_placeholders(org_count, 2);
        let limit_idx = org_count.saturating_add(2);
        let sql = format!(
            "SELECT entity_kind, entity_id, title, subtitle, CAST(bm25(entity_fts) * 1000 AS INTEGER)
             FROM entity_fts
             WHERE entity_fts MATCH ?1 AND organisation_id IN ({placeholders})
             ORDER BY bm25(entity_fts) ASC
             LIMIT ?{limit_idx}"
        );
        let mut params = vec![Value::from(fts_query)];
        append_org_params(ctx, &mut params);
        params.push(Value::from(i64::try_from(limit).unwrap_or(i64::MAX)));

        let mut stmt = conn.prepare(&sql).map_err(sql_io_err)?;
        let rows = stmt
            .query_map(rusqlite::params_from_iter(params), |row| {
                let kind_str: String = row.get(0)?;
                let entity_id: String = row.get(1)?;
                let title: String = row.get(2)?;
                let subtitle: String = row.get(3)?;
                let rank_score: i64 = row.get(4)?;
                Ok((kind_str, entity_id, title, subtitle, rank_score))
            })
            .map_err(sql_io_err)?;

        let mut out = Vec::new();
        for row_res in rows {
            let (kind_str, entity_id, title, subtitle, rank_score) = row_res.map_err(sql_io_err)?;
            let Some(entity_kind) = EntityKind::parse(&kind_str) else {
                continue;
            };
            out.push(EntitySearchHit {
                entity_kind,
                entity_id,
                title,
                subtitle,
                rank_score,
            });
        }
        Ok(out)
    }

    fn applied_migrations(&self) -> Result<Vec<MigrationRecord>, CodedError> {
        let conn = self.lock_conn()?;
        let mut stmt = conn
            .prepare("SELECT version, name, applied_at FROM schema_migrations ORDER BY version ASC")
            .map_err(sql_io_err)?;
        let rows = stmt
            .query_map([], |row| {
                let ver_i64: i64 = row.get(0)?;
                let name: String = row.get(1)?;
                let applied_at: String = row.get(2)?;
                Ok((ver_i64, name, applied_at))
            })
            .map_err(sql_io_err)?;

        let mut out = Vec::new();
        for item in rows {
            let (ver_i64, name, applied_at) = item.map_err(sql_io_err)?;
            out.push(MigrationRecord {
                version: u32::try_from(ver_i64).unwrap_or(0),
                name,
                applied_at,
            });
        }
        Ok(out)
    }
}

fn sanitize_fts_query(raw: &str) -> Option<String> {
    let tokens: Vec<String> = raw
        .split_whitespace()
        .map(|part| {
            part.chars()
                .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
                .collect::<String>()
        })
        .filter(|tok| !tok.is_empty())
        .map(|tok| format!("\"{tok}\"*"))
        .collect();
    if tokens.is_empty() {
        None
    } else {
        Some(tokens.join(" "))
    }
}
