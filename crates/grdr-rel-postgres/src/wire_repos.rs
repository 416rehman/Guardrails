// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use serde::de::DeserializeOwned;

use grdr_model::CodedError;
use grdr_ports::{EntityKind, EntitySearchHit, MigrationRecord, TenantCtx};

use crate::dialect::{PostgresSqlRegistry, PostgresStatementId};
use crate::store::{PostgresRelationalStore, decode_json};
use crate::wire::WireStatement;
use crate::wire_codec::format_pg_text_array;

pub(crate) fn org_array_param(ctx: &TenantCtx) -> String {
    let orgs: Vec<String> = ctx
        .organisation_ids()
        .iter()
        .map(|o| o.as_str().to_string())
        .collect();
    format_pg_text_array(&orgs)
}

pub(crate) fn search_sync_statements<'a>(
    org: &str,
    parent_key: &str,
    rows: &[(EntityKind, &str, &str, &str)],
) -> Vec<WireStatement<'a>> {
    let mut stmts = Vec::with_capacity(1usize.saturating_add(rows.len()));
    stmts.push(WireStatement {
        sql: PostgresSqlRegistry::sql_for(PostgresStatementId::DeleteSearchParent),
        params: vec![Some(org.to_string()), Some(parent_key.to_string())],
    });
    for (kind, entity_id, title, subtitle) in rows {
        stmts.push(WireStatement {
            sql: PostgresSqlRegistry::sql_for(PostgresStatementId::InsertSearchRow),
            params: vec![
                Some(org.to_string()),
                Some(kind.as_str().to_string()),
                Some((*entity_id).to_string()),
                Some(parent_key.to_string()),
                Some((*title).to_string()),
                Some((*subtitle).to_string()),
            ],
        });
    }
    stmts
}

pub(crate) fn wire_get_json<T: DeserializeOwned>(
    store: &PostgresRelationalStore,
    rls: &[String],
    stmt_id: PostgresStatementId,
    params: Vec<Option<String>>,
) -> Result<Option<T>, CodedError> {
    let stmts = [WireStatement {
        sql: PostgresSqlRegistry::sql_for(stmt_id),
        params,
    }];
    let res = store.execute_wire_statements(rls, &stmts)?;
    res.first()
        .and_then(|rows| rows.first())
        .and_then(|cols| cols.first())
        .and_then(|val| val.as_deref())
        .map(decode_json)
        .transpose()
}

pub(crate) fn wire_list_json<T: DeserializeOwned>(
    store: &PostgresRelationalStore,
    rls: &[String],
    stmt_id: PostgresStatementId,
    params: Vec<Option<String>>,
) -> Result<Vec<T>, CodedError> {
    let stmts = [WireStatement {
        sql: PostgresSqlRegistry::sql_for(stmt_id),
        params,
    }];
    let res = store.execute_wire_statements(rls, &stmts)?;
    let mut out = Vec::new();
    if let Some(rows) = res.first() {
        for cols in rows {
            if let Some(raw) = cols.first().and_then(|v| v.as_deref()) {
                out.push(decode_json(raw)?);
            }
        }
    }
    Ok(out)
}

pub(crate) fn wire_list_kv(
    store: &PostgresRelationalStore,
    rls: &[String],
    ctx: &TenantCtx,
    namespace: &str,
) -> Result<Vec<(String, String)>, CodedError> {
    let stmts = [WireStatement {
        sql: PostgresSqlRegistry::sql_for(PostgresStatementId::ListKv),
        params: vec![Some(namespace.to_string()), Some(org_array_param(ctx))],
    }];
    let res = store.execute_wire_statements(rls, &stmts)?;
    let mut out = Vec::new();
    if let Some(rows) = res.first() {
        for cols in rows {
            if let (Some(Some(k)), Some(Some(v))) = (cols.first(), cols.get(1)) {
                out.push((k.clone(), v.clone()));
            }
        }
    }
    Ok(out)
}

pub(crate) fn wire_search_entities(
    store: &PostgresRelationalStore,
    rls: &[String],
    ctx: &TenantCtx,
    needle: &str,
    limit: usize,
) -> Result<Vec<EntitySearchHit>, CodedError> {
    let pattern = format!("%{needle}%");
    let stmts = [WireStatement {
        sql: PostgresSqlRegistry::sql_for(PostgresStatementId::SearchEntities),
        params: vec![
            Some(org_array_param(ctx)),
            Some(pattern),
            Some(limit.to_string()),
        ],
    }];
    let res = store.execute_wire_statements(rls, &stmts)?;
    let mut out = Vec::new();
    if let Some(rows) = res.first() {
        for cols in rows {
            let Some(kind_str) = cols.first().and_then(|v| v.as_deref()) else {
                continue;
            };
            let Some(entity_kind) = EntityKind::parse(kind_str) else {
                continue;
            };
            let entity_id = cols.get(1).and_then(|v| v.clone()).unwrap_or_default();
            let title = cols.get(2).and_then(|v| v.clone()).unwrap_or_default();
            let subtitle = cols.get(3).and_then(|v| v.clone()).unwrap_or_default();
            let rank_score = cols
                .get(4)
                .and_then(|v| v.as_deref())
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(100);
            out.push(EntitySearchHit {
                entity_kind,
                entity_id,
                title,
                subtitle,
                rank_score,
            });
        }
    }
    Ok(out)
}

pub(crate) fn wire_applied_migrations(
    store: &PostgresRelationalStore,
) -> Result<Vec<MigrationRecord>, CodedError> {
    let stmts = [WireStatement {
        sql: PostgresSqlRegistry::sql_for(PostgresStatementId::AppliedMigrations),
        params: Vec::new(),
    }];
    let res = store.execute_wire_statements(&[], &stmts)?;
    let mut out = Vec::new();
    if let Some(rows) = res.first() {
        for cols in rows {
            let ver = cols
                .first()
                .and_then(|v| v.as_deref())
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(0);
            let name = cols.get(1).and_then(|v| v.clone()).unwrap_or_default();
            let applied_at = cols.get(2).and_then(|v| v.clone()).unwrap_or_default();
            out.push(MigrationRecord {
                version: ver,
                name,
                applied_at,
            });
        }
    }
    Ok(out)
}
