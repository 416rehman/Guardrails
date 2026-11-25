// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use grdr_model::CodedError;
use grdr_ports::{SingleCtx, TenantCtx};

use crate::config::CODE_PG_RLS;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PostgresStatementId {
    UpsertDevice,
    GetDevice,
    ListDevices,
    UpsertSessionSummary,
    GetSessionSummary,
    ListSessionSummaries,
    UpsertFinding,
    GetFinding,
    ListFindings,
    UpsertPolicyPack,
    GetPolicyPack,
    ListPolicyPacks,
    UpsertUser,
    GetUser,
    ListUsers,
    PutKv,
    GetKv,
    ListKv,
    DeleteKv,
    DeleteSearchParent,
    InsertSearchRow,
    SearchEntities,
    AppliedMigrations,
}

pub struct PostgresSqlRegistry;

impl PostgresSqlRegistry {
    pub const ALL_STATEMENTS: &'static [PostgresStatementId] = &[
        PostgresStatementId::UpsertDevice,
        PostgresStatementId::GetDevice,
        PostgresStatementId::ListDevices,
        PostgresStatementId::UpsertSessionSummary,
        PostgresStatementId::GetSessionSummary,
        PostgresStatementId::ListSessionSummaries,
        PostgresStatementId::UpsertFinding,
        PostgresStatementId::GetFinding,
        PostgresStatementId::ListFindings,
        PostgresStatementId::UpsertPolicyPack,
        PostgresStatementId::GetPolicyPack,
        PostgresStatementId::ListPolicyPacks,
        PostgresStatementId::UpsertUser,
        PostgresStatementId::GetUser,
        PostgresStatementId::ListUsers,
        PostgresStatementId::PutKv,
        PostgresStatementId::GetKv,
        PostgresStatementId::ListKv,
        PostgresStatementId::DeleteKv,
        PostgresStatementId::DeleteSearchParent,
        PostgresStatementId::InsertSearchRow,
        PostgresStatementId::SearchEntities,
        PostgresStatementId::AppliedMigrations,
    ];

    pub fn sql_for(id: PostgresStatementId) -> &'static str {
        match id {
            PostgresStatementId::UpsertDevice => {
                "INSERT INTO device (organisation_id, device_id, hostname, os, arch, online, last_seen, payload_json)
                 VALUES ($1, $2, $3, $4, $5, $6::boolean, $7::timestamptz, $8::jsonb)
                 ON CONFLICT (organisation_id, device_id) DO UPDATE SET
                   hostname = EXCLUDED.hostname,
                   os = EXCLUDED.os,
                   arch = EXCLUDED.arch,
                   online = EXCLUDED.online,
                   last_seen = EXCLUDED.last_seen,
                   payload_json = EXCLUDED.payload_json"
            }
            PostgresStatementId::GetDevice => {
                "SELECT payload_json::text FROM device WHERE device_id = $1 AND organisation_id = ANY($2::text[]) LIMIT 1"
            }
            PostgresStatementId::ListDevices => {
                "SELECT payload_json::text FROM device WHERE organisation_id = ANY($1::text[]) ORDER BY last_seen DESC, device_id ASC"
            }
            PostgresStatementId::UpsertSessionSummary => {
                "INSERT INTO session_summary (organisation_id, session_id, device_id, agent_name, user_id, started_at, last_activity, payload_json)
                 VALUES ($1, $2, $3, $4, $5, $6::timestamptz, $7::timestamptz, $8::jsonb)
                 ON CONFLICT (organisation_id, session_id) DO UPDATE SET
                   device_id = EXCLUDED.device_id,
                   agent_name = EXCLUDED.agent_name,
                   user_id = EXCLUDED.user_id,
                   started_at = EXCLUDED.started_at,
                   last_activity = EXCLUDED.last_activity,
                   payload_json = EXCLUDED.payload_json"
            }
            PostgresStatementId::GetSessionSummary => {
                "SELECT payload_json::text FROM session_summary WHERE session_id = $1 AND organisation_id = ANY($2::text[]) LIMIT 1"
            }
            PostgresStatementId::ListSessionSummaries => {
                "SELECT payload_json::text FROM session_summary WHERE organisation_id = ANY($1::text[]) ORDER BY last_activity DESC, session_id ASC"
            }
            PostgresStatementId::UpsertFinding => {
                "INSERT INTO finding (organisation_id, finding_id, session_id, device_id, severity, lifecycle, detected_at, payload_json)
                 VALUES ($1, $2, $3, $4, $5, $6, $7::timestamptz, $8::jsonb)
                 ON CONFLICT (organisation_id, finding_id) DO UPDATE SET
                   session_id = EXCLUDED.session_id,
                   device_id = EXCLUDED.device_id,
                   severity = EXCLUDED.severity,
                   lifecycle = EXCLUDED.lifecycle,
                   detected_at = EXCLUDED.detected_at,
                   payload_json = EXCLUDED.payload_json"
            }
            PostgresStatementId::GetFinding => {
                "SELECT payload_json::text FROM finding WHERE finding_id = $1 AND organisation_id = ANY($2::text[]) LIMIT 1"
            }
            PostgresStatementId::ListFindings => {
                "SELECT payload_json::text FROM finding WHERE organisation_id = ANY($1::text[]) ORDER BY detected_at DESC, finding_id ASC"
            }
            PostgresStatementId::UpsertPolicyPack => {
                "INSERT INTO policy_pack (organisation_id, pack_id, name, version, channel, payload_json)
                 VALUES ($1, $2, $3, $4, $5, $6::jsonb)
                 ON CONFLICT (organisation_id, pack_id) DO UPDATE SET
                   name = EXCLUDED.name,
                   version = EXCLUDED.version,
                   channel = EXCLUDED.channel,
                   payload_json = EXCLUDED.payload_json"
            }
            PostgresStatementId::GetPolicyPack => {
                "SELECT payload_json::text FROM policy_pack WHERE pack_id = $1 AND organisation_id = ANY($2::text[]) LIMIT 1"
            }
            PostgresStatementId::ListPolicyPacks => {
                "SELECT payload_json::text FROM policy_pack WHERE organisation_id = ANY($1::text[]) ORDER BY pack_id ASC"
            }
            PostgresStatementId::UpsertUser => {
                "INSERT INTO user_profile (organisation_id, user_id, display_name, email, department, pseudonym_id, payload_json)
                 VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
                 ON CONFLICT (organisation_id, user_id) DO UPDATE SET
                   display_name = EXCLUDED.display_name,
                   email = EXCLUDED.email,
                   department = EXCLUDED.department,
                   pseudonym_id = EXCLUDED.pseudonym_id,
                   payload_json = EXCLUDED.payload_json"
            }
            PostgresStatementId::GetUser => {
                "SELECT payload_json::text FROM user_profile WHERE user_id = $1 AND organisation_id = ANY($2::text[]) LIMIT 1"
            }
            PostgresStatementId::ListUsers => {
                "SELECT payload_json::text FROM user_profile WHERE organisation_id = ANY($1::text[]) ORDER BY user_id ASC"
            }
            PostgresStatementId::PutKv => {
                "INSERT INTO tenant_kv (organisation_id, namespace, entry_key, value_json, updated_at)
                 VALUES ($1, $2, $3, $4::jsonb, NOW())
                 ON CONFLICT (organisation_id, namespace, entry_key) DO UPDATE SET
                   value_json = EXCLUDED.value_json,
                   updated_at = EXCLUDED.updated_at"
            }
            PostgresStatementId::GetKv => {
                "SELECT value_json::text FROM tenant_kv WHERE namespace = $1 AND entry_key = $2 AND organisation_id = ANY($3::text[]) LIMIT 1"
            }
            PostgresStatementId::ListKv => {
                "SELECT entry_key, value_json::text FROM tenant_kv WHERE namespace = $1 AND organisation_id = ANY($2::text[]) ORDER BY entry_key ASC"
            }
            PostgresStatementId::DeleteKv => {
                "DELETE FROM tenant_kv WHERE organisation_id = $1 AND namespace = $2 AND entry_key = $3"
            }
            PostgresStatementId::DeleteSearchParent => {
                "DELETE FROM entity_search_index WHERE organisation_id = $1 AND parent_key = $2"
            }
            PostgresStatementId::InsertSearchRow => {
                "INSERT INTO entity_search_index (organisation_id, entity_kind, entity_id, parent_key, title, subtitle)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (organisation_id, entity_kind, entity_id) DO UPDATE SET
                   parent_key = EXCLUDED.parent_key,
                   title = EXCLUDED.title,
                   subtitle = EXCLUDED.subtitle"
            }
            PostgresStatementId::SearchEntities => {
                "SELECT entity_kind, entity_id, title, subtitle, 100::bigint AS rank_score
                 FROM entity_search_index
                 WHERE organisation_id = ANY($1::text[]) AND (title ILIKE $2 OR subtitle ILIKE $2)
                 ORDER BY entity_id ASC
                 LIMIT $3"
            }
            PostgresStatementId::AppliedMigrations => {
                "SELECT version::text, name, applied_at::text FROM schema_migrations ORDER BY version ASC"
            }
        }
    }
}

pub fn rls_write_statements(ctx: &SingleCtx) -> Result<Vec<String>, CodedError> {
    let org = sanitize_rls_token(ctx.organisation_id().as_str())?;
    Ok(vec![
        format!("SET LOCAL app.org_id = '{org}'"),
        format!("SET LOCAL grdr.orgs = '{org}'"),
    ])
}

pub fn rls_session_statements(ctx: &TenantCtx) -> Result<Vec<String>, CodedError> {
    match ctx {
        TenantCtx::Single(single) => rls_write_statements(single),
        TenantCtx::Set(set) => {
            let snap = sanitize_rls_token(set.snapshot_id())?;
            let mut orgs = Vec::with_capacity(set.organisation_ids().len());
            for org in set.organisation_ids() {
                orgs.push(sanitize_rls_token(org.as_str())?);
            }
            Ok(vec![
                format!("SET LOCAL grdr.orgset = '{snap}'"),
                format!("SET LOCAL grdr.orgs = '{}'", orgs.join(",")),
            ])
        }
    }
}

fn sanitize_rls_token(raw: &str) -> Result<String, CodedError> {
    let trimmed = raw.trim();
    let valid = !trimmed.is_empty()
        && trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if !valid {
        return Err(CodedError::new(
            CODE_PG_RLS,
            format!("Invalid tenant RLS context token `{trimmed}`."),
            "Mint TenantCtx from validated OrgId/SetCtx identifiers only.",
        ));
    }
    Ok(trimmed.to_string())
}
