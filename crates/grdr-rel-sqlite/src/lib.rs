// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

mod repos_policy_user;
mod schema;
mod store;

pub use schema::{CODE_REL_CODEC, CODE_REL_IO, CODE_REL_MIGRATION};
pub use store::SqliteRelationalStore;

#[cfg(test)]
mod tests {
    use super::*;
    use grdr_model::{Device, InstallProfile};
    use grdr_ports::{DeviceRepo, OrgId, RelationalStorePort, SingleCtx, TenantCtx};
    use jiff::Timestamp;

    #[test]
    fn sqlite_relational_passes_port_contract() {
        let store = SqliteRelationalStore::open_in_memory().unwrap();
        grdr_ports_testkit::assert_relational_store_contract(&store).unwrap();
    }

    #[test]
    fn sqlite_relational_persists_wal_across_reopen_and_fts_searches() {
        let dir = std::env::temp_dir().join(format!("grdr-rel-sqlite-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let db_path = dir.join("relational.sqlite3");

        let org = OrgId::new("org-persist").unwrap();
        let ctx = SingleCtx::new(org);
        let read_ctx = TenantCtx::Single(ctx.clone());
        let dev = Device {
            id: "dev-wal-1".into(),
            hostname: "workstation-omega".into(),
            os: "windows".into(),
            arch: "x86_64".into(),
            install_profile: InstallProfile::Protected,
            daemon_version: "0.1.0".into(),
            online: true,
            hook_effective: true,
            agents: Vec::new(),
            mcp_servers: Vec::new(),
            artifacts: Vec::new(),
            user_id: None,
            user_display: None,
            last_seen: Timestamp::from_second(1_700_000_000).unwrap(),
            public_key: None,
        };

        {
            let store = SqliteRelationalStore::open(&db_path).unwrap();
            store.upsert_device(&ctx, &dev).unwrap();
        }

        let reopened = SqliteRelationalStore::open(&db_path).unwrap();
        let loaded = reopened
            .get_device(&read_ctx, "dev-wal-1")
            .unwrap()
            .unwrap();
        assert_eq!(loaded.hostname, "workstation-omega");

        let hits = reopened.search_entities(&read_ctx, "omega", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].entity_id, "dev-wal-1");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
