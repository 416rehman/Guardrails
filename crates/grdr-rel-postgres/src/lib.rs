// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

mod bus_pg;
mod bus_pg_offline;
mod bus_pg_wire;
pub mod config;
pub mod dialect;
pub mod migrations;
pub mod pool;
mod repos;
mod repos_core;
mod scram;
mod store;
mod tls;
mod tls_hash;
pub mod wire;
pub mod wire_codec;
mod wire_repos;

pub use bus_pg::PostgresLogBus;
pub use config::{
    CODE_PG_CODEC, CODE_PG_CONFIG, CODE_PG_IO, CODE_PG_MIGRATION, CODE_PG_RLS, CODE_PG_WIRE,
    PostgresConfig, PostgresSslMode, PostgresTransport,
};
pub use dialect::{
    PostgresSqlRegistry, PostgresStatementId, rls_session_statements, rls_write_statements,
};
pub use migrations::{MigrationPhase, POSTGRES_MIGRATIONS, PostgresMigration};
pub use pool::{PgConnectionPool, PgPoolStats};
pub use store::PostgresRelationalStore;
pub use wire::{PostgresWireState, TransactionStatus, WireConnParams};

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    use grdr_ports::{KvSnapshotRepo, OrgId, RelationalStorePort, SingleCtx, TenantCtx};

    use super::*;

    fn read_pg_frame(sock: &mut TcpStream) -> (u8, Vec<u8>) {
        let mut hdr = [0u8; 5];
        sock.read_exact(&mut hdr).unwrap();
        let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
        let mut body = vec![0u8; len.saturating_sub(4)];
        sock.read_exact(&mut body).unwrap();
        (hdr[0], body)
    }

    fn send_auth_ok(sock: &mut TcpStream) {
        sock.write_all(&[b'R', 0, 0, 0, 8, 0, 0, 0, 0]).unwrap();
        sock.write_all(&[b'Z', 0, 0, 0, 5, b'I']).unwrap();
    }

    fn send_cmd_complete(sock: &mut TcpStream, tag: &[u8]) {
        let clen = 4usize.saturating_add(tag.len()) as u32;
        sock.write_all(b"C").unwrap();
        sock.write_all(&clen.to_be_bytes()).unwrap();
        sock.write_all(tag).unwrap();
        sock.write_all(&[b'Z', 0, 0, 0, 5, b'I']).unwrap();
    }

    fn send_single_row(sock: &mut TcpStream, val: &str) {
        let vbytes = val.as_bytes();
        let body_len = 6usize.saturating_add(vbytes.len());
        let frame_len = 4usize.saturating_add(body_len) as u32;
        sock.write_all(b"D").unwrap();
        sock.write_all(&frame_len.to_be_bytes()).unwrap();
        sock.write_all(&1u16.to_be_bytes()).unwrap();
        sock.write_all(&(vbytes.len() as i32).to_be_bytes())
            .unwrap();
        sock.write_all(vbytes).unwrap();
    }

    #[test]
    fn postgres_offline_passes_relational_port_contract() {
        let store = PostgresRelationalStore::open_offline().unwrap();
        grdr_ports_testkit::assert_relational_store_contract(&store).unwrap();
        assert_eq!(store.applied_migrations().unwrap().len(), 3);
    }

    #[test]
    fn postgres_dsn_and_rls_session_guards_validate() {
        let mut random_pw_bytes = [0u8; 12];
        grdr_crypto::fill_random(&mut random_pw_bytes).unwrap();
        let random_pw = grdr_crypto::sha256_hex(&random_pw_bytes);
        let dsn = format!(
            "postgres://grdr:{random_pw}@pg.internal.test:5432/guardrails?sslmode=verify-full"
        );
        let cfg = PostgresConfig::parse_dsn(&dsn).unwrap();
        assert_eq!(cfg.ssl_mode, PostgresSslMode::VerifyFull);
        assert!(cfg.validate().is_ok());

        let ipv6_cfg = PostgresConfig::parse_dsn("postgres://grdr@[::1]:5433/guardrails").unwrap();
        assert_eq!(ipv6_cfg.ssl_mode, PostgresSslMode::VerifyFull);
        assert!(matches!(
            ipv6_cfg.transport,
            PostgresTransport::TcpWire { ref endpoint, .. } if endpoint == "[::1]:5433"
        ));

        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains(&random_pw));
        assert!(dbg.contains("[REDACTED]"));

        for bad_dsn in [
            "mysql://bad/db",
            "postgres://grdr@host:0/db",
            "postgres://grdr@host\0:5432/db",
            "postgres://grdr@host:5432/db\nextra",
            "postgres://grdr@host:5432/db#fragment",
            "postgres://grdr@host:5432/db/sub",
        ] {
            assert!(PostgresConfig::parse_dsn(bad_dsn).is_err());
        }

        let mut bad_cfg = ipv6_cfg.clone();
        if let PostgresTransport::TcpWire {
            ref mut endpoint, ..
        } = bad_cfg.transport
        {
            *endpoint = "missing_port_host".into();
        }
        assert!(bad_cfg.validate().is_err());

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

        let set = TenantCtx::set("snap-pg-1", vec![org_a.clone(), org_b]).unwrap();
        let read_sql = rls_session_statements(&set).unwrap();
        assert_eq!(
            read_sql,
            vec![
                "SET LOCAL grdr.orgset = 'snap-pg-1'",
                "SET LOCAL grdr.orgs = 'org-pg-a,org-pg-b'"
            ]
        );

        let sqli_set = TenantCtx::set("snap'; DROP TABLE device;--", vec![org_a]).unwrap();
        assert_eq!(
            rls_session_statements(&sqli_set).unwrap_err().code,
            CODE_PG_RLS
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
                .any(|m| m.sql.contains("WITH CHECK"))
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
    fn postgres_wire_v3_roundtrip_and_extended_repo_wire_tcp() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut len_buf = [0u8; 4];
            sock.read_exact(&mut len_buf).unwrap();
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut rest = vec![0u8; len.saturating_sub(4)];
            sock.read_exact(&mut rest).unwrap();
            send_auth_ok(&mut sock);

            let mut saw_put = false;
            let mut saw_get = false;
            loop {
                let (tag, body) = read_pg_frame(&mut sock);
                match tag {
                    b'Q' => {
                        let sql = String::from_utf8_lossy(&body);
                        if sql.contains("SET LOCAL app.org_id = 'org-wire-kv'") {
                            send_cmd_complete(&mut sock, b"BEGIN\0");
                        } else if sql.contains("SELECT 1") {
                            send_cmd_complete(&mut sock, b"SELECT 1\0");
                        } else if sql.contains("COMMIT") {
                            send_cmd_complete(&mut sock, b"COMMIT\0");
                        } else {
                            send_cmd_complete(&mut sock, b"OK\0");
                        }
                    }
                    b'P' => {
                        let sql = String::from_utf8_lossy(&body);
                        let (b_tag, b_body) = read_pg_frame(&mut sock);
                        assert_eq!(b_tag, b'B');
                        let (e_tag, _) = read_pg_frame(&mut sock);
                        assert_eq!(e_tag, b'E');
                        let (s_tag, _) = read_pg_frame(&mut sock);
                        assert_eq!(s_tag, b'S');
                        sock.write_all(&[b'1', 0, 0, 0, 4]).unwrap();
                        sock.write_all(&[b'2', 0, 0, 0, 4]).unwrap();
                        if sql.contains("INSERT INTO tenant_kv") {
                            assert!(String::from_utf8_lossy(&b_body).contains("{\"ok\":true}"));
                            saw_put = true;
                            send_cmd_complete(&mut sock, b"INSERT 0 1\0");
                        } else {
                            saw_get = true;
                            send_single_row(&mut sock, "{\"ok\":true}");
                            send_cmd_complete(&mut sock, b"SELECT 1\0");
                        }
                    }
                    b'X' => break,
                    other => panic!("unexpected frame tag {other}"),
                }
            }
            assert!(saw_put && saw_get);
        });

        let cfg = PostgresConfig::parse_dsn(&format!(
            "postgres://grdr@{addr}/guardrails?sslmode=disable"
        ))
        .unwrap();
        let store = PostgresRelationalStore::connect(cfg).unwrap();
        let ctx = SingleCtx::new(OrgId::new("org-wire-kv").unwrap());
        store.put_kv(&ctx, "ns", "k1", "{\"ok\":true}").unwrap();
        let val = store.get_kv(&TenantCtx::Single(ctx), "ns", "k1").unwrap();
        assert_eq!(val.as_deref(), Some("{\"ok\":true}"));
        let stats = store.pool_stats().unwrap().unwrap();
        assert_eq!(stats.total_connects, 1);
        assert!(stats.reused_checkouts >= 2);
        drop(store);
        server.join().unwrap();
    }

    #[test]
    fn postgres_wire_adversarial_tls_cleartext_auth_and_nul_smuggling() {
        // sslmode=require/verify-ca/verify-full must fail closed before TCP connect.
        for mode in [
            PostgresSslMode::Require,
            PostgresSslMode::VerifyCa,
            PostgresSslMode::VerifyFull,
        ] {
            let conn = WireConnParams {
                endpoint: "127.0.0.1:1",
                user: "grdr",
                database: "guardrails",
                app_name: "grdr-test",
                timeout_ms: 1_000,
                ssl_mode: mode,
                ca_cert_pem: None,
            };
            let err = wire::execute_simple_query_wire(&conn, None, "SELECT 1").unwrap_err();
            assert_eq!(err.code, CODE_PG_WIRE);
        }

        // NUL-byte smuggling must be rejected in encoders.
        assert_eq!(
            wire_codec::encode_startup_packet("grdr\0admin", "db", "app")
                .unwrap_err()
                .code,
            CODE_PG_WIRE
        );
        assert_eq!(
            wire_codec::encode_query_message("SELECT 1\0DROP TABLE device")
                .unwrap_err()
                .code,
            CODE_PG_WIRE
        );

        // Oversized wire frame rejected.
        let bad_frame = [b'D', 0x7f, 0xff, 0xff, 0xff];
        assert_eq!(
            wire_codec::decode_backend_message(&mut bad_frame.as_slice())
                .unwrap_err()
                .code,
            CODE_PG_WIRE
        );

        // Cleartext auth over non-TLS TCP refused both without AND with dynamic password.
        let mut pw_bytes = [0u8; 16];
        grdr_crypto::fill_random(&mut pw_bytes).unwrap();
        let dyn_pw = grdr_crypto::sha256_hex(&pw_bytes);
        for maybe_pw in [None, Some(dyn_pw.as_str())] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let srv = thread::spawn(move || {
                let (mut sock, _) = listener.accept().unwrap();
                let mut len_buf = [0u8; 4];
                sock.read_exact(&mut len_buf).unwrap();
                let len = u32::from_be_bytes(len_buf) as usize;
                let mut rest = vec![0u8; len - 4];
                sock.read_exact(&mut rest).unwrap();
                sock.write_all(&[b'R', 0, 0, 0, 8, 0, 0, 0, 3]).unwrap();
            });
            let addr_str = addr.to_string();
            let conn = WireConnParams {
                endpoint: &addr_str,
                user: "grdr",
                database: "guardrails",
                app_name: "grdr-test",
                timeout_ms: 2_000,
                ssl_mode: PostgresSslMode::Disable,
                ca_cert_pem: None,
            };
            let err = wire::execute_simple_query_wire(&conn, maybe_pw, "SELECT 1").unwrap_err();
            assert_eq!(err.code, CODE_PG_WIRE);
            srv.join().unwrap();
        }

        // Server skipping SCRAM with AuthenticationOk when password is configured must fail.
        {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let srv = thread::spawn(move || {
                let (mut sock, _) = listener.accept().unwrap();
                let mut len_buf = [0u8; 4];
                sock.read_exact(&mut len_buf).unwrap();
                let len = u32::from_be_bytes(len_buf) as usize;
                let mut rest = vec![0u8; len - 4];
                sock.read_exact(&mut rest).unwrap();
                send_auth_ok(&mut sock);
            });
            let addr_str = addr.to_string();
            let conn = WireConnParams {
                endpoint: &addr_str,
                user: "grdr",
                database: "guardrails",
                app_name: "grdr-test",
                timeout_ms: 2_000,
                ssl_mode: PostgresSslMode::Disable,
                ca_cert_pem: None,
            };
            let err =
                wire::execute_simple_query_wire(&conn, Some(&dyn_pw), "SELECT 1").unwrap_err();
            assert_eq!(err.code, CODE_PG_WIRE);
            srv.join().unwrap();
        }

        // Truncated or non-UTF-8 DataRow / RowDescription must fail closed.
        let truncated_datarow = [b'D', 0, 0, 0, 10, 0, 1, 0, 0, 0, 16];
        assert_eq!(
            wire_codec::decode_backend_message(&mut truncated_datarow.as_slice())
                .unwrap_err()
                .code,
            CODE_PG_WIRE
        );
        let invalid_utf8_datarow = [b'D', 0, 0, 0, 12, 0, 1, 0, 0, 0, 2, 0xff, 0xfe];
        assert_eq!(
            wire_codec::decode_backend_message(&mut invalid_utf8_datarow.as_slice())
                .unwrap_err()
                .code,
            CODE_PG_WIRE
        );

        // ReadyForQuery before AuthenticationOk must be rejected.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut len_buf = [0u8; 4];
            sock.read_exact(&mut len_buf).unwrap();
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut rest = vec![0u8; len - 4];
            sock.read_exact(&mut rest).unwrap();
            sock.write_all(&[b'Z', 0, 0, 0, 5, b'I']).unwrap();
        });
        let addr_str = addr.to_string();
        let conn = WireConnParams {
            endpoint: &addr_str,
            user: "grdr",
            database: "guardrails",
            app_name: "grdr-test",
            timeout_ms: 2_000,
            ssl_mode: PostgresSslMode::Disable,
            ca_cert_pem: None,
        };
        let err = wire::execute_simple_query_wire(&conn, None, "SELECT 1").unwrap_err();
        assert_eq!(err.code, CODE_PG_WIRE);
        srv.join().unwrap();

        // Notice/ParameterStatus flood must abort at MAX_WIRE_CONTROL_FRAMES.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut len_buf = [0u8; 4];
            sock.read_exact(&mut len_buf).unwrap();
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut rest = vec![0u8; len.saturating_sub(4)];
            sock.read_exact(&mut rest).unwrap();
            for _ in 0..4_200 {
                if sock.write_all(&[b'N', 0, 0, 0, 5, 0]).is_err() {
                    break;
                }
            }
        });
        let addr_str = addr.to_string();
        let conn = WireConnParams {
            endpoint: &addr_str,
            user: "grdr",
            database: "guardrails",
            app_name: "grdr-test",
            timeout_ms: 2_000,
            ssl_mode: PostgresSslMode::Disable,
            ca_cert_pem: None,
        };
        let err = wire::execute_simple_query_wire(&conn, None, "SELECT 1").unwrap_err();
        assert_eq!(err.code, CODE_PG_WIRE);
        let _ = srv.join();
    }

    #[test]
    fn postgres_run_migrations_skips_already_applied_versions() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut len_buf = [0u8; 4];
            sock.read_exact(&mut len_buf).unwrap();
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut rest = vec![0u8; len.saturating_sub(4)];
            sock.read_exact(&mut rest).unwrap();
            send_auth_ok(&mut sock);

            loop {
                let (tag, body) = read_pg_frame(&mut sock);
                match tag {
                    b'Q' => {
                        let sql = String::from_utf8_lossy(&body);
                        if sql.contains("SELECT version::text FROM schema_migrations") {
                            send_single_row(&mut sock, "1");
                            send_single_row(&mut sock, "2");
                            send_single_row(&mut sock, "3");
                            send_cmd_complete(&mut sock, b"SELECT 3\0");
                        } else if sql.contains("CREATE TABLE") {
                            send_cmd_complete(&mut sock, b"CREATE TABLE\0");
                        } else {
                            send_cmd_complete(&mut sock, b"SELECT 1\0");
                        }
                    }
                    b'X' => break,
                    other => panic!("unexpected frame tag {other}"),
                }
            }
        });
        let cfg = PostgresConfig::parse_dsn(&format!(
            "postgres://grdr@{addr}/guardrails?sslmode=disable"
        ))
        .unwrap();
        let store = PostgresRelationalStore::connect(cfg).unwrap();
        store.run_migrations().unwrap();
        drop(store);
        srv.join().unwrap();
    }
}
