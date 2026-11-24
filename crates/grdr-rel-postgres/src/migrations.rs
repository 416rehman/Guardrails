// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationPhase {
    Expand,
    Backfill,
    Contract,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostgresMigration {
    pub version: u32,
    pub name: &'static str,
    pub phase: MigrationPhase,
    pub sql: &'static str,
}

pub const POSTGRES_MIGRATIONS: &[PostgresMigration] = &[
    PostgresMigration {
        version: 1,
        name: "0001_expand_core_tables_and_rls",
        phase: MigrationPhase::Expand,
        sql: r#"
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    phase TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS delegation_snapshot (
    snapshot_id TEXT NOT NULL,
    organisation_id TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, organisation_id)
);

CREATE TABLE IF NOT EXISTS device (
    organisation_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    hostname TEXT NOT NULL,
    os TEXT NOT NULL,
    arch TEXT NOT NULL,
    online BOOLEAN NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    payload_json JSONB NOT NULL,
    PRIMARY KEY (organisation_id, device_id)
);

CREATE TABLE IF NOT EXISTS session_summary (
    organisation_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    agent_name TEXT NOT NULL,
    user_id TEXT,
    started_at TIMESTAMPTZ NOT NULL,
    last_activity TIMESTAMPTZ NOT NULL,
    payload_json JSONB NOT NULL,
    PRIMARY KEY (organisation_id, session_id)
);

CREATE TABLE IF NOT EXISTS finding (
    organisation_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    lifecycle TEXT NOT NULL,
    detected_at TIMESTAMPTZ NOT NULL,
    payload_json JSONB NOT NULL,
    PRIMARY KEY (organisation_id, finding_id)
);

CREATE TABLE IF NOT EXISTS policy_pack (
    organisation_id TEXT NOT NULL,
    pack_id TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    channel TEXT NOT NULL,
    payload_json JSONB NOT NULL,
    PRIMARY KEY (organisation_id, pack_id)
);

CREATE TABLE IF NOT EXISTS user_profile (
    organisation_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    email TEXT NOT NULL,
    department TEXT NOT NULL,
    pseudonym_id TEXT NOT NULL,
    payload_json JSONB NOT NULL,
    PRIMARY KEY (organisation_id, user_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_user_profile_pseudonym
    ON user_profile (organisation_id, pseudonym_id);

CREATE TABLE IF NOT EXISTS tenant_kv (
    organisation_id TEXT NOT NULL,
    namespace TEXT NOT NULL,
    entry_key TEXT NOT NULL,
    value_json JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (organisation_id, namespace, entry_key)
);

ALTER TABLE device ENABLE ROW LEVEL SECURITY;
ALTER TABLE device FORCE ROW LEVEL SECURITY;
CREATE POLICY device_tenant_rls ON device USING (
    organisation_id = NULLIF(current_setting('app.org_id', true), '')
    OR organisation_id = ANY(string_to_array(COALESCE(current_setting('grdr.orgs', true), ''), ','))
    OR organisation_id IN (
        SELECT organisation_id FROM delegation_snapshot
        WHERE snapshot_id = NULLIF(current_setting('grdr.orgset', true), '')
    )
);

ALTER TABLE session_summary ENABLE ROW LEVEL SECURITY;
ALTER TABLE session_summary FORCE ROW LEVEL SECURITY;
CREATE POLICY session_summary_tenant_rls ON session_summary USING (
    organisation_id = NULLIF(current_setting('app.org_id', true), '')
    OR organisation_id = ANY(string_to_array(COALESCE(current_setting('grdr.orgs', true), ''), ','))
);

ALTER TABLE finding ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding FORCE ROW LEVEL SECURITY;
CREATE POLICY finding_tenant_rls ON finding USING (
    organisation_id = NULLIF(current_setting('app.org_id', true), '')
    OR organisation_id = ANY(string_to_array(COALESCE(current_setting('grdr.orgs', true), ''), ','))
);

ALTER TABLE policy_pack ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_pack FORCE ROW LEVEL SECURITY;
CREATE POLICY policy_pack_tenant_rls ON policy_pack USING (
    organisation_id = NULLIF(current_setting('app.org_id', true), '')
    OR organisation_id = ANY(string_to_array(COALESCE(current_setting('grdr.orgs', true), ''), ','))
);

ALTER TABLE user_profile ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_profile FORCE ROW LEVEL SECURITY;
CREATE POLICY user_profile_tenant_rls ON user_profile USING (
    organisation_id = NULLIF(current_setting('app.org_id', true), '')
    OR organisation_id = ANY(string_to_array(COALESCE(current_setting('grdr.orgs', true), ''), ','))
);

ALTER TABLE tenant_kv ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_kv FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_kv_tenant_rls ON tenant_kv USING (
    organisation_id = NULLIF(current_setting('app.org_id', true), '')
    OR organisation_id = ANY(string_to_array(COALESCE(current_setting('grdr.orgs', true), ''), ','))
);
"#,
    },
    PostgresMigration {
        version: 2,
        name: "0002_expand_entity_search_index",
        phase: MigrationPhase::Expand,
        sql: r#"
CREATE TABLE IF NOT EXISTS entity_search_index (
    organisation_id TEXT NOT NULL,
    entity_kind TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    parent_key TEXT NOT NULL,
    title TEXT NOT NULL,
    subtitle TEXT NOT NULL,
    PRIMARY KEY (organisation_id, entity_kind, entity_id)
);

CREATE INDEX IF NOT EXISTS idx_entity_search_title
    ON entity_search_index (organisation_id, title);

ALTER TABLE entity_search_index ENABLE ROW LEVEL SECURITY;
ALTER TABLE entity_search_index FORCE ROW LEVEL SECURITY;
CREATE POLICY entity_search_tenant_rls ON entity_search_index USING (
    organisation_id = NULLIF(current_setting('app.org_id', true), '')
    OR organisation_id = ANY(string_to_array(COALESCE(current_setting('grdr.orgs', true), ''), ','))
);
"#,
    },
    PostgresMigration {
        version: 3,
        name: "0003_contract_active_device_index",
        phase: MigrationPhase::Contract,
        sql: r#"
CREATE INDEX IF NOT EXISTS idx_device_last_seen
    ON device (organisation_id, last_seen DESC, device_id ASC);
"#,
    },
];

pub(crate) const OFFLINE_SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    phase TEXT NOT NULL,
    applied_at TEXT NOT NULL
);

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

CREATE UNIQUE INDEX IF NOT EXISTS idx_pg_offline_user_pseudonym
    ON user_profile (organisation_id, pseudonym_id);

CREATE TABLE IF NOT EXISTS tenant_kv (
    organisation_id TEXT NOT NULL,
    namespace TEXT NOT NULL,
    entry_key TEXT NOT NULL,
    value_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (organisation_id, namespace, entry_key)
);

CREATE TABLE IF NOT EXISTS entity_search_index (
    organisation_id TEXT NOT NULL,
    entity_kind TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    parent_key TEXT NOT NULL,
    title TEXT NOT NULL,
    subtitle TEXT NOT NULL,
    PRIMARY KEY (organisation_id, entity_kind, entity_id)
);
"#;
