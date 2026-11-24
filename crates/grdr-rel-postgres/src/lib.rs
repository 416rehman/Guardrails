// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

pub mod config;
pub mod dialect;
pub mod migrations;
mod repos;
mod store;
pub mod wire;

pub use config::{
    CODE_PG_CODEC, CODE_PG_CONFIG, CODE_PG_IO, CODE_PG_MIGRATION, CODE_PG_RLS, CODE_PG_WIRE,
    PostgresConfig, PostgresSslMode, PostgresTransport,
};
pub use dialect::{
    PostgresSqlRegistry, PostgresStatementId, rls_session_statements, rls_write_statements,
};
pub use migrations::{MigrationPhase, POSTGRES_MIGRATIONS, PostgresMigration};
pub use store::PostgresRelationalStore;
pub use wire::PostgresWireState;

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    use grdr_ports::{OrgId, RelationalStorePort, SingleCtx, TenantCtx};

    use super::*;

    #[test]
    fn postgres_offline_passes_relational_port_contract() {
        let store = PostgresRelationalStore::open_offline().unwrap();
        grdr_ports_testkit::assert_relational_store_contract(&store).unwrap();
        assert_eq!(store.applied_migrations().unwrap().len(), 3);
    }

    #[test]
    fn postgres_dsn_and_rls_session_guards_validate() {
        let cfg = PostgresConfig::parse_dsn(
            "postgres://grdr:pw@pg.internal.test:5432/guardrails?sslmode=verify-full",
        )
        .unwrap();
        assert_eq!(cfg.ssl_mode, PostgresSslMode::VerifyFull);
        assert!(cfg.validate().is_ok());
        assert!(PostgresConfig::parse_dsn("mysql://bad/db").is_err());

        let org_a = OrgId::new("org-pg-a").unwrap();
        let org_b = OrgId::new("org-pg-b").unwrap();
        let single = SingleCtx::new(org_a.clone());
        let write_sql = rls_write_statements(&single).unwrap();
        assert_eq!(
            write_sql,
            vec![
                "SET LOCAL app.org_id = 'org-pg-a'",
                "SET LOCAL grdr.orgs = 'org-pg-a'"
            ]
        );

        let set = TenantCtx::set("snap-pg-1", vec![org_a, org_b]).unwrap();
        let read_sql = rls_session_statements(&set).unwrap();
        assert_eq!(
            read_sql,
            vec![
                "SET LOCAL grdr.orgset = 'snap-pg-1'",
                "SET LOCAL grdr.orgs = 'org-pg-a,org-pg-b'"
            ]
        );
    }

    #[test]
    fn postgres_dialect_registry_and_migrations_cover_all_repos() {
        for stmt_id in PostgresSqlRegistry::ALL_STATEMENTS {
            let sql = PostgresSqlRegistry::sql_for(*stmt_id);
            assert!(!sql.trim().is_empty());
        }
        assert!(
            POSTGRES_MIGRATIONS
                .iter()
                .any(|m| m.sql.contains("ENABLE ROW LEVEL SECURITY"))
        );
        assert!(
            POSTGRES_MIGRATIONS
                .iter()
                .any(|m| m.phase == MigrationPhase::Expand)
        );
        assert!(
            POSTGRES_MIGRATIONS
                .iter()
                .any(|m| m.phase == MigrationPhase::Contract)
        );
    }

    #[test]
    fn postgres_wire_v3_roundtrip_against_mock_tcp_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut len_buf = [0u8; 4];
            sock.read_exact(&mut len_buf).unwrap();
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut rest = vec![0u8; len - 4];
            sock.read_exact(&mut rest).unwrap();
            // Send AuthenticationOk ('R', len=8, code=0) + ReadyForQuery ('Z', len=5, 'I')
            sock.write_all(&[b'R', 0, 0, 0, 8, 0, 0, 0, 0]).unwrap();
            sock.write_all(&[b'Z', 0, 0, 0, 5, b'I']).unwrap();

            // Read Query message
            let mut q_hdr = [0u8; 5];
            sock.read_exact(&mut q_hdr).unwrap();
            assert_eq!(q_hdr[0], b'Q');
            let q_len = u32::from_be_bytes([q_hdr[1], q_hdr[2], q_hdr[3], q_hdr[4]]) as usize;
            let mut q_body = vec![0u8; q_len - 4];
            sock.read_exact(&mut q_body).unwrap();
            assert!(String::from_utf8_lossy(&q_body).contains("SELECT 1"));

            // Send CommandComplete + ReadyForQuery
            let tag = b"SELECT 1\0";
            let clen = (4 + tag.len()) as u32;
            sock.write_all(b"C").unwrap();
            sock.write_all(&clen.to_be_bytes()).unwrap();
            sock.write_all(tag).unwrap();
            sock.write_all(&[b'Z', 0, 0, 0, 5, b'I']).unwrap();
        });

        let rows = wire::execute_simple_query_wire(
            &addr.to_string(),
            "grdr",
            "guardrails",
            None,
            "grdr-test",
            2_000,
            "SELECT 1",
        )
        .unwrap();
        assert!(rows.is_empty());
        server.join().unwrap();
    }
}
