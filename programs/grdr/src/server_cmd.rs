// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Subcommand;

use crate::egress::{EgressComponent, EgressEvalOptions, NetworkMode, run_egress_command};
use crate::server_migrate::{MigrateHaOptions, run_migrate_command};
use crate::server_preflight::{
    DiskHeadroomProbe, PgClockProbe, PreflightOptions, S3AddressingStyle, run_preflight,
};

#[derive(Debug, Subcommand)]
pub enum ServerCommand {
    /// Inspect effective outbound server egress destinations (empty in isolated mode unless allow-listed).
    Egress {
        #[arg(long, value_enum, default_value_t = NetworkMode::Standard)]
        network_mode: NetworkMode,
        #[arg(long, default_value_t = false)]
        isolated: bool,
        #[arg(long = "allow")]
        allow: Vec<String>,
        #[arg(long = "mirror")]
        mirrors: Vec<String>,
        #[arg(long = "sink")]
        sinks: Vec<String>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Run storage, database, bus, and object-store preflight checks.
    Preflight {
        #[arg(long, default_value = "embedded")]
        profile: String,

        #[arg(long)]
        data_dir: Option<PathBuf>,

        #[arg(long)]
        backup_dir: Option<PathBuf>,

        #[arg(long, env = "GRDR_POSTGRES_DSN")]
        postgres_dsn: Option<String>,

        #[arg(long, env = "GRDR_NATS_URL")]
        nats_url: Option<String>,

        #[arg(long)]
        object_store_dir: Option<PathBuf>,

        #[arg(long, env = "GRDR_OBJECT_STORE_ENDPOINT")]
        object_store_endpoint: Option<String>,

        #[arg(long, env = "GRDR_OBJECT_STORE_BUCKET")]
        object_store_bucket: Option<String>,

        #[arg(long, env = "GRDR_BACKUP_BUCKET")]
        backup_bucket: Option<String>,

        #[arg(long, env = "GRDR_OBJECT_STORE_PATH_STYLE", default_value_t = false)]
        object_store_path_style: bool,

        #[arg(long = "cert-file", alias = "cert")]
        cert_files: Vec<PathBuf>,

        #[arg(long, default_value_t = false)]
        check_pg_clock: bool,

        #[arg(long, default_value_t = false)]
        check_disk: bool,

        #[arg(long)]
        restore_drill_marker: Option<PathBuf>,

        #[arg(long, default_value_t = false)]
        json: bool,

        #[arg(long, default_value_t = false)]
        strict: bool,
    },
    /// Migrate an embedded installation to HA (PostgreSQL + object storage).
    Migrate {
        #[arg(long, default_value = "ha")]
        to: String,

        #[arg(long)]
        from_data_dir: PathBuf,

        #[arg(long)]
        target_bucket_dir: PathBuf,

        #[arg(long, env = "GRDR_POSTGRES_DSN")]
        postgres_dsn: Option<String>,

        #[arg(long, default_value_t = false)]
        dry_run: bool,

        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

pub fn handle_server_command(cmd: ServerCommand) -> ExitCode {
    match cmd {
        ServerCommand::Egress {
            network_mode,
            isolated,
            allow,
            mirrors,
            sinks,
            json,
        } => {
            let mode = if isolated {
                NetworkMode::Isolated
            } else {
                network_mode
            };
            run_egress_command(
                &EgressEvalOptions {
                    component: EgressComponent::Server,
                    network_mode: mode,
                    state_dir: None,
                    allow_patterns: allow,
                    mirrors,
                    update_sources: Vec::new(),
                    server_origin: None,
                    export_sinks: sinks,
                    updates_enabled: false,
                },
                json,
            )
        }
        ServerCommand::Preflight {
            profile,
            data_dir,
            backup_dir,
            postgres_dsn,
            nats_url,
            object_store_dir,
            object_store_endpoint,
            object_store_bucket,
            backup_bucket,
            object_store_path_style,
            cert_files,
            check_pg_clock,
            check_disk,
            restore_drill_marker,
            json,
            strict,
        } => {
            let mut opts = PreflightOptions::for_profile(&profile);
            opts.data_dir = data_dir.as_deref();
            opts.backup_dir = backup_dir.as_deref();
            opts.postgres_dsn = postgres_dsn.as_deref();
            opts.nats_url = nats_url.as_deref();
            opts.object_store_dir = object_store_dir.as_deref();
            opts.object_store_endpoint = object_store_endpoint.as_deref();
            opts.object_store_bucket = object_store_bucket.as_deref();
            opts.backup_bucket = backup_bucket.as_deref();
            opts.object_store_addressing = if object_store_path_style {
                S3AddressingStyle::PathStyle
            } else {
                S3AddressingStyle::VirtualHosted
            };
            opts.cert_files = &cert_files;
            opts.pg_clock_probe = if check_pg_clock {
                PgClockProbe::Enforce
            } else {
                PgClockProbe::Skip
            };
            opts.disk_headroom_probe = if check_disk {
                DiskHeadroomProbe::Enforce
            } else {
                DiskHeadroomProbe::Skip
            };
            opts.restore_drill_marker = restore_drill_marker.as_deref();
            run_preflight(&opts, json, strict)
        }
        ServerCommand::Migrate {
            to,
            from_data_dir,
            target_bucket_dir,
            postgres_dsn,
            dry_run,
            json,
        } => {
            let opts = MigrateHaOptions {
                to_profile: &to,
                from_data_dir: &from_data_dir,
                target_bucket_dir: &target_bucket_dir,
                postgres_dsn: postgres_dsn.as_deref(),
                dry_run,
            };
            run_migrate_command(&opts, json)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use grdr_blob::FilesystemBlobStore;
    use grdr_bus_log::SqliteLogBus;
    use grdr_model::{Device, InstallProfile};
    use grdr_ports::{
        BlobPort, BusAppendMessage, BusPort, DeviceRepo, OrgId, SingleCtx, TenantPath,
    };
    use grdr_rel_sqlite::SqliteRelationalStore;
    use jiff::Timestamp;

    use super::*;
    use crate::server_migrate::{
        CODE_MIGRATE_BUCKET_NOT_EMPTY, CODE_MIGRATE_INVALID_TARGET, migrate_embedded_to_ha,
    };
    use crate::server_preflight::{
        CheckOutcome, DiskHeadroomProbe, PgClockProbe, S3AddressingStyle, build_preflight_report,
        build_preflight_report_with_probes, check_loopback_test, evaluate_disk_headroom_sample,
        parse_limits_thresholds_test, sign_s3_test_headers,
    };

    fn ed25519_pkcs8(seed: [u8; 32]) -> Vec<u8> {
        let mut out = vec![
            0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        out.extend_from_slice(&seed);
        out
    }

    fn der_tlv(tag: u8, val: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if val.len() < 128 {
            out.push(val.len() as u8);
        } else {
            let len_bytes = val.len().to_be_bytes();
            let trimmed: Vec<u8> = len_bytes.into_iter().skip_while(|b| *b == 0).collect();
            out.push(0x80 | (trimmed.len() as u8));
            out.extend_from_slice(&trimmed);
        }
        out.extend_from_slice(val);
        out
    }

    fn der_cn(name: &str) -> Vec<u8> {
        let attr = der_tlv(
            0x30,
            &[
                der_tlv(0x06, &[0x55, 0x04, 0x03]),
                der_tlv(0x0C, name.as_bytes()),
            ]
            .concat(),
        );
        der_tlv(0x30, &der_tlv(0x31, &attr))
    }

    fn der_asn1_time(epoch_s: i64) -> Vec<u8> {
        let ts = Timestamp::from_second(epoch_s).unwrap();
        let dt = jiff::tz::TimeZone::UTC.to_datetime(ts);
        if dt.year() < 2050 {
            let s = format!(
                "{:02}{:02}{:02}{:02}{:02}{:02}Z",
                dt.year() % 100,
                dt.month(),
                dt.day(),
                dt.hour(),
                dt.minute(),
                dt.second()
            );
            der_tlv(0x17, s.as_bytes())
        } else {
            let s = format!(
                "{:04}{:02}{:02}{:02}{:02}{:02}Z",
                dt.year(),
                dt.month(),
                dt.day(),
                dt.hour(),
                dt.minute(),
                dt.second()
            );
            der_tlv(0x18, s.as_bytes())
        }
    }

    fn encode_b64_pem(der: &[u8]) -> String {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        format!("-----BEGIN CERTIFICATE-----\n{b64}\n-----END CERTIFICATE-----\n")
    }

    struct TestPki {
        ca_der: Vec<u8>,
        leaf_der: Vec<u8>,
        leaf_pkcs8: Vec<u8>,
        ca_pem: String,
        chain_pem: String,
    }

    fn make_test_pki(
        now_s: i64,
        leaf_days_valid: i64,
        san_ip: [u8; 4],
        san_dns: &str,
        server_eku: bool,
    ) -> TestPki {
        use rustls::SignatureScheme;
        use rustls::crypto::aws_lc_rs::sign::any_eddsa_type;
        use rustls::pki_types::PrivatePkcs8KeyDer;

        let ca_pkcs8 = ed25519_pkcs8([0x11u8; 32]);
        let leaf_pkcs8 = ed25519_pkcs8([0x22u8; 32]);
        let ca_key = any_eddsa_type(&PrivatePkcs8KeyDer::from(ca_pkcs8)).unwrap();
        let leaf_key = any_eddsa_type(&PrivatePkcs8KeyDer::from(leaf_pkcs8.clone())).unwrap();
        let ca_spki = ca_key.public_key().unwrap().to_vec();
        let leaf_spki = leaf_key.public_key().unwrap().to_vec();
        let ed_alg = der_tlv(0x30, &der_tlv(0x06, &[0x2B, 0x65, 0x70]));
        let ca_dn = der_cn("Guardrails Test CA");
        let leaf_dn = der_cn("Guardrails Test Server");

        let ca_bc = der_tlv(
            0x30,
            &[
                der_tlv(0x06, &[0x55, 0x1D, 0x13]),
                der_tlv(0x01, &[0xFF]),
                der_tlv(0x04, &der_tlv(0x30, &der_tlv(0x01, &[0xFF]))),
            ]
            .concat(),
        );
        let ca_ku = der_tlv(
            0x30,
            &[
                der_tlv(0x06, &[0x55, 0x1D, 0x0F]),
                der_tlv(0x01, &[0xFF]),
                der_tlv(0x04, &der_tlv(0x03, &[0x01, 0x06])),
            ]
            .concat(),
        );
        let ca_validity = der_tlv(
            0x30,
            &[
                der_asn1_time(now_s - 86_400),
                der_asn1_time(now_s + 365 * 86_400),
            ]
            .concat(),
        );
        let ca_tbs = der_tlv(
            0x30,
            &[
                der_tlv(0xA0, &der_tlv(0x02, &[2])),
                der_tlv(0x02, &[1]),
                ed_alg.clone(),
                ca_dn.clone(),
                ca_validity,
                ca_dn.clone(),
                ca_spki,
                der_tlv(0xA3, &der_tlv(0x30, &[ca_bc, ca_ku].concat())),
            ]
            .concat(),
        );
        let ca_sig = ca_key
            .choose_scheme(&[SignatureScheme::ED25519])
            .unwrap()
            .sign(&ca_tbs)
            .unwrap();
        let mut ca_bit = vec![0x00];
        ca_bit.extend_from_slice(&ca_sig);
        let ca_der = der_tlv(
            0x30,
            &[ca_tbs, ed_alg.clone(), der_tlv(0x03, &ca_bit)].concat(),
        );

        let leaf_bc = der_tlv(
            0x30,
            &[
                der_tlv(0x06, &[0x55, 0x1D, 0x13]),
                der_tlv(0x01, &[0xFF]),
                der_tlv(0x04, &der_tlv(0x30, &[])),
            ]
            .concat(),
        );
        let eku_oid: &[u8] = if server_eku {
            &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01]
        } else {
            &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02]
        };
        let leaf_eku = der_tlv(
            0x30,
            &[
                der_tlv(0x06, &[0x55, 0x1D, 0x25]),
                der_tlv(0x04, &der_tlv(0x30, &der_tlv(0x06, eku_oid))),
            ]
            .concat(),
        );
        let leaf_san = der_tlv(
            0x30,
            &[
                der_tlv(0x06, &[0x55, 0x1D, 0x11]),
                der_tlv(
                    0x04,
                    &der_tlv(
                        0x30,
                        &[der_tlv(0x82, san_dns.as_bytes()), der_tlv(0x87, &san_ip)].concat(),
                    ),
                ),
            ]
            .concat(),
        );
        let leaf_ku = der_tlv(
            0x30,
            &[
                der_tlv(0x06, &[0x55, 0x1D, 0x0F]),
                der_tlv(0x01, &[0xFF]),
                der_tlv(0x04, &der_tlv(0x03, &[0x07, 0x80])),
            ]
            .concat(),
        );
        let leaf_validity = der_tlv(
            0x30,
            &[
                der_asn1_time(now_s - 86_400),
                der_asn1_time(now_s + leaf_days_valid * 86_400),
            ]
            .concat(),
        );
        let leaf_tbs = der_tlv(
            0x30,
            &[
                der_tlv(0xA0, &der_tlv(0x02, &[2])),
                der_tlv(0x02, &[2]),
                ed_alg.clone(),
                ca_dn,
                leaf_validity,
                leaf_dn,
                leaf_spki,
                der_tlv(
                    0xA3,
                    &der_tlv(0x30, &[leaf_bc, leaf_ku, leaf_eku, leaf_san].concat()),
                ),
            ]
            .concat(),
        );
        let leaf_sig = ca_key
            .choose_scheme(&[SignatureScheme::ED25519])
            .unwrap()
            .sign(&leaf_tbs)
            .unwrap();
        let mut leaf_bit = vec![0x00];
        leaf_bit.extend_from_slice(&leaf_sig);
        let leaf_der = der_tlv(0x30, &[leaf_tbs, ed_alg, der_tlv(0x03, &leaf_bit)].concat());

        let ca_pem = encode_b64_pem(&ca_der);
        let leaf_pem = encode_b64_pem(&leaf_der);
        TestPki {
            ca_der,
            leaf_der,
            leaf_pkcs8,
            chain_pem: format!("{leaf_pem}{ca_pem}"),
            ca_pem,
        }
    }

    fn make_three_cert_chain_parts(now_s: i64, tamper_intermediate: bool) -> (String, Vec<u8>) {
        use rustls::SignatureScheme;
        use rustls::crypto::aws_lc_rs::sign::any_eddsa_type;
        use rustls::pki_types::PrivatePkcs8KeyDer;

        let root_key =
            any_eddsa_type(&PrivatePkcs8KeyDer::from(ed25519_pkcs8([0x31u8; 32]))).unwrap();
        let int_key =
            any_eddsa_type(&PrivatePkcs8KeyDer::from(ed25519_pkcs8([0x42u8; 32]))).unwrap();
        let leaf_key =
            any_eddsa_type(&PrivatePkcs8KeyDer::from(ed25519_pkcs8([0x53u8; 32]))).unwrap();
        let ed_alg = der_tlv(0x30, &der_tlv(0x06, &[0x2B, 0x65, 0x70]));
        let root_dn = der_cn("Guardrails Root CA");
        let int_dn = der_cn("Guardrails Intermediate CA");
        let leaf_dn = der_cn("Guardrails Chain Leaf");
        let ca_bc = der_tlv(
            0x30,
            &[
                der_tlv(0x06, &[0x55, 0x1D, 0x13]),
                der_tlv(0x01, &[0xFF]),
                der_tlv(0x04, &der_tlv(0x30, &der_tlv(0x01, &[0xFF]))),
            ]
            .concat(),
        );
        let ca_ku = der_tlv(
            0x30,
            &[
                der_tlv(0x06, &[0x55, 0x1D, 0x0F]),
                der_tlv(0x01, &[0xFF]),
                der_tlv(0x04, &der_tlv(0x03, &[0x01, 0x06])),
            ]
            .concat(),
        );
        let validity = der_tlv(
            0x30,
            &[
                der_asn1_time(now_s - 86_400),
                der_asn1_time(now_s + 90 * 86_400),
            ]
            .concat(),
        );
        let root_tbs = der_tlv(
            0x30,
            &[
                der_tlv(0xA0, &der_tlv(0x02, &[2])),
                der_tlv(0x02, &[1]),
                ed_alg.clone(),
                root_dn.clone(),
                validity.clone(),
                root_dn.clone(),
                root_key.public_key().unwrap().to_vec(),
                der_tlv(
                    0xA3,
                    &der_tlv(0x30, &[ca_bc.clone(), ca_ku.clone()].concat()),
                ),
            ]
            .concat(),
        );
        let root_sig = root_key
            .choose_scheme(&[SignatureScheme::ED25519])
            .unwrap()
            .sign(&root_tbs)
            .unwrap();
        let mut root_bit = vec![0x00];
        root_bit.extend_from_slice(&root_sig);
        let root_der = der_tlv(
            0x30,
            &[root_tbs, ed_alg.clone(), der_tlv(0x03, &root_bit)].concat(),
        );

        let int_tbs = der_tlv(
            0x30,
            &[
                der_tlv(0xA0, &der_tlv(0x02, &[2])),
                der_tlv(0x02, &[2]),
                ed_alg.clone(),
                root_dn,
                validity.clone(),
                int_dn.clone(),
                int_key.public_key().unwrap().to_vec(),
                der_tlv(0xA3, &der_tlv(0x30, &[ca_bc, ca_ku].concat())),
            ]
            .concat(),
        );
        let mut int_sig = root_key
            .choose_scheme(&[SignatureScheme::ED25519])
            .unwrap()
            .sign(&int_tbs)
            .unwrap();
        if tamper_intermediate {
            int_sig[0] ^= 0xFF;
        }
        let mut int_bit = vec![0x00];
        int_bit.extend_from_slice(&int_sig);
        let int_der = der_tlv(
            0x30,
            &[int_tbs, ed_alg.clone(), der_tlv(0x03, &int_bit)].concat(),
        );

        let leaf_bc = der_tlv(
            0x30,
            &[
                der_tlv(0x06, &[0x55, 0x1D, 0x13]),
                der_tlv(0x01, &[0xFF]),
                der_tlv(0x04, &der_tlv(0x30, &[])),
            ]
            .concat(),
        );
        let leaf_eku = der_tlv(
            0x30,
            &[
                der_tlv(0x06, &[0x55, 0x1D, 0x25]),
                der_tlv(
                    0x04,
                    &der_tlv(
                        0x30,
                        &der_tlv(0x06, &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01]),
                    ),
                ),
            ]
            .concat(),
        );
        let leaf_san = der_tlv(
            0x30,
            &[
                der_tlv(0x06, &[0x55, 0x1D, 0x11]),
                der_tlv(0x04, &der_tlv(0x30, &der_tlv(0x82, b"localhost"))),
            ]
            .concat(),
        );
        let leaf_tbs = der_tlv(
            0x30,
            &[
                der_tlv(0xA0, &der_tlv(0x02, &[2])),
                der_tlv(0x02, &[3]),
                ed_alg.clone(),
                int_dn,
                validity,
                leaf_dn,
                leaf_key.public_key().unwrap().to_vec(),
                der_tlv(
                    0xA3,
                    &der_tlv(0x30, &[leaf_bc, leaf_eku, leaf_san].concat()),
                ),
            ]
            .concat(),
        );
        let leaf_sig = int_key
            .choose_scheme(&[SignatureScheme::ED25519])
            .unwrap()
            .sign(&leaf_tbs)
            .unwrap();
        let mut leaf_bit = vec![0x00];
        leaf_bit.extend_from_slice(&leaf_sig);
        let leaf_der = der_tlv(0x30, &[leaf_tbs, ed_alg, der_tlv(0x03, &leaf_bit)].concat());

        let fullchain = format!("{}{}", encode_b64_pem(&leaf_der), encode_b64_pem(&int_der));
        (fullchain, root_der)
    }

    fn make_three_cert_chain_pem(now_s: i64, tamper_intermediate: bool) -> String {
        let (fullchain, root_der) = make_three_cert_chain_parts(now_s, tamper_intermediate);
        format!("{fullchain}{}", encode_b64_pem(&root_der))
    }

    fn tls_server_cfg(pki: &TestPki) -> std::sync::Arc<rustls::ServerConfig> {
        use rustls::crypto::aws_lc_rs::default_provider;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        let provider = std::sync::Arc::new(default_provider());
        let cfg = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![
                    CertificateDer::from(pki.leaf_der.clone()),
                    CertificateDer::from(pki.ca_der.clone()),
                ],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pki.leaf_pkcs8.clone())),
            )
            .unwrap();
        std::sync::Arc::new(cfg)
    }

    fn accept_pg_ssl_connection(
        listener: &std::net::TcpListener,
        srv_cfg: std::sync::Arc<rustls::ServerConfig>,
    ) -> Option<(std::net::TcpStream, rustls::ServerConnection)> {
        use std::io::{Read, Write};
        for _ in 0..4 {
            let Ok((mut tcp, _)) = listener.accept() else {
                return None;
            };
            let mut hdr = [0u8; 8];
            if tcp.read_exact(&mut hdr).is_err() {
                continue;
            }
            if hdr.get(4..8) != Some(&[0x04, 0xD2, 0x16, 0x2F]) {
                continue;
            }
            tcp.write_all(b"S").ok()?;
            let mut tls_srv = rustls::ServerConnection::new(srv_cfg).ok()?;
            while tls_srv.is_handshaking() {
                tls_srv.complete_io(&mut tcp).ok()?;
            }
            return Some((tcp, tls_srv));
        }
        None
    }

    #[test]
    fn server_preflight_validates_all_profiles() {
        let now_s = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let base =
            std::env::temp_dir().join(format!("grdr-pf-prof-{}", uuid::Uuid::now_v7().simple()));
        let _ = std::fs::remove_dir_all(&base);
        let obj_dir = base.join("objects");
        std::fs::create_dir_all(&obj_dir).unwrap();

        let pki = make_test_pki(now_s, 60, [127, 0, 0, 1], "localhost", true);
        let ca_path = base.join("ca.pem");
        std::fs::write(&ca_path, &pki.ca_pem).unwrap();

        let embedded = build_preflight_report(&PreflightOptions::for_profile("embedded"));
        assert_eq!(embedded.overall, CheckOutcome::Warn);

        let strict_code = run_preflight(&PreflightOptions::for_profile("embedded"), true, true);
        assert_eq!(strict_code, ExitCode::FAILURE);

        let ha_bad = build_preflight_report(&PreflightOptions::for_profile("ha"));
        assert_eq!(ha_bad.overall, CheckOutcome::Fail);

        let mut dist_opts = PreflightOptions::for_profile("distributed");
        dist_opts.postgres_dsn =
            Some("postgres://grdr@pg.example.test:5432/guardrails?sslmode=verify-full");
        dist_opts.nats_url = Some("tls://nats.example.test:4222");
        dist_opts.object_store_dir = Some(&obj_dir);
        let dist_ok = build_preflight_report(&dist_opts);
        assert_eq!(dist_ok.overall, CheckOutcome::Pass, "{:?}", dist_ok.checks);

        // Plain nats:// and non-verify-full sslmodes (require/verify-ca/prefer) must Fail.
        for bad_ssl in ["disable", "prefer", "require", "verify-ca"] {
            let dsn = format!("postgres://grdr@pg.example.test:5432/guardrails?sslmode={bad_ssl}");
            let mut opts = PreflightOptions::for_profile("ha");
            opts.postgres_dsn = Some(&dsn);
            opts.object_store_dir = Some(&obj_dir);
            let rep = build_preflight_report(&opts);
            assert_eq!(
                rep.overall,
                CheckOutcome::Fail,
                "expected Fail for {bad_ssl}"
            );
        }
        let mut plain_nats = PreflightOptions::for_profile("distributed");
        plain_nats.postgres_dsn =
            Some("postgres://grdr@pg.example.test:5432/guardrails?sslmode=verify-full");
        plain_nats.nats_url = Some("nats://127.0.0.1:4222");
        plain_nats.object_store_dir = Some(&obj_dir);
        assert_eq!(
            build_preflight_report(&plain_nats).overall,
            CheckOutcome::Fail
        );

        // Real rustls TLS handshake tests on both PG SSLRequest and NATS tls://.
        let srv_cfg = tls_server_cfg(&pki);
        let pg_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let pg_addr = pg_listener.local_addr().unwrap();
        let srv_cfg_pg = srv_cfg.clone();
        let pg_thread = std::thread::spawn(move || {
            let _ = accept_pg_ssl_connection(&pg_listener, srv_cfg_pg);
        });

        let nats_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let nats_addr = nats_listener.local_addr().unwrap();
        let nats_thread = std::thread::spawn(move || {
            use std::io::Write;
            let (mut tcp, _) = nats_listener.accept().unwrap();
            let mut tls_srv = rustls::ServerConnection::new(srv_cfg).unwrap();
            while tls_srv.is_handshaking() {
                tls_srv.complete_io(&mut tcp).unwrap();
            }
            let mut stream = rustls::Stream::new(&mut tls_srv, &mut tcp);
            let _ = stream.write_all(b"INFO {\"server_id\":\"test\"}\r\n");
        });

        let live_pg = format!("postgres://grdr@{pg_addr}/guardrails?sslmode=verify-full");
        let live_nats = format!("tls://{nats_addr}");
        let certs = vec![ca_path];
        let mut live_opts = PreflightOptions::for_profile("distributed");
        live_opts.postgres_dsn = Some(&live_pg);
        live_opts.nats_url = Some(&live_nats);
        live_opts.object_store_dir = Some(&obj_dir);
        live_opts.cert_files = &certs;
        let live_ok = build_preflight_report_with_probes(&live_opts, true);
        let _ = pg_thread.join();
        let _ = nats_thread.join();
        assert_eq!(live_ok.overall, CheckOutcome::Pass, "{:?}", live_ok.checks);

        let _ = std::fs::remove_dir_all(&base);
    }

    fn spawn_s3_mock(
        requests: usize,
        date_hdr: Option<String>,
        versioning_status: u16,
        versioning_body: &'static str,
        lifecycle_status: u16,
        lifecycle_body: &'static str,
        object_lock_body: &'static str,
    ) -> (std::net::SocketAddr, std::thread::JoinHandle<Vec<String>>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let mut seen_headers = Vec::new();
            for _ in 0..requests {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                seen_headers.push(req.clone());
                let first_line = req.lines().next().unwrap_or("");
                let (status, body) = if first_line.starts_with("HEAD ") {
                    ("200 OK", "")
                } else if first_line.contains("?versioning") {
                    let st = if versioning_status == 200 {
                        "200 OK"
                    } else if versioning_status == 403 {
                        "403 Forbidden"
                    } else {
                        "404 Not Found"
                    };
                    (st, versioning_body)
                } else if first_line.contains("?lifecycle") {
                    let st = if lifecycle_status == 200 {
                        "200 OK"
                    } else {
                        "404 Not Found"
                    };
                    (st, lifecycle_body)
                } else if first_line.contains("?object-lock") {
                    ("200 OK", object_lock_body)
                } else {
                    ("200 OK", "<ListAllMyBucketsResult/>")
                };
                let date_line = date_hdr
                    .as_ref()
                    .map(|d| format!("Date: {d}\r\n"))
                    .unwrap_or_default();
                let resp = format!(
                    "HTTP/1.1 {status}\r\n{date_line}Content-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
            }
            seen_headers
        });
        (addr, handle)
    }

    fn fmt_http_date_utc(epoch_s: i64) -> String {
        const WDAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
        const MONTHS: [&str; 12] = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ];
        let ts = Timestamp::from_second(epoch_s).unwrap();
        let dt = jiff::tz::TimeZone::UTC.to_datetime(ts);
        let wd = WDAYS[dt.weekday().to_monday_zero_offset() as usize];
        let mo = MONTHS[(dt.month() as usize) - 1];
        format!(
            "{wd}, {:02} {mo} {:04} {:02}:{:02}:{:02} +0000",
            dt.day(),
            dt.year(),
            dt.hour(),
            dt.minute(),
            dt.second()
        )
    }

    #[test]
    fn server_preflight_s3_object_lock_lifecycle_and_http_skew() {
        let now_s = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let ok_date = fmt_http_date_utc(now_s);

        // AWS SigV4 header calculation produces valid AWS4-HMAC-SHA256 Authorization.
        let sig_hdrs = sign_s3_test_headers(
            "GET",
            "https://s3.us-east-1.amazonaws.com/grdr-backup?object-lock",
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            1_700_000_000,
        )
        .unwrap();
        assert!(
            sig_hdrs
                .iter()
                .any(|(k, v)| k == "Authorization" && v.starts_with("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20231114/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature="))
        );

        // Reject userinfo, non-loopback http://, and [::1]@attacker.example bypasses.
        assert!(!check_loopback_test("[::1]@attacker.example"));
        assert!(check_loopback_test("[::1]:8333"));
        assert!(check_loopback_test("127.0.0.1:8333"));
        for bad_s3_url in [
            "http://s3.example.com",
            "https://user:pass@s3.example.com",
            "http://[::1]@attacker.example:8333",
            "https://s3.example.com?foo=bar",
        ] {
            let mut uopts = PreflightOptions::for_profile("ha");
            uopts.postgres_dsn =
                Some("postgres://grdr@pg.example.test:5432/guardrails?sslmode=verify-full");
            uopts.object_store_endpoint = Some(bad_s3_url);
            uopts.object_store_bucket = Some("grdr-lake");
            uopts.backup_bucket = Some("grdr-backup");
            let urep = build_preflight_report(&uopts);
            assert_eq!(urep.overall, CheckOutcome::Fail, "must reject {bad_s3_url}");
        }

        let base =
            std::env::temp_dir().join(format!("grdr-pf-s3-{}", uuid::Uuid::now_v7().simple()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let pki = make_test_pki(now_s, 60, [127, 0, 0, 1], "localhost", true);
        let ca_path = base.join("ca.pem");
        std::fs::write(&ca_path, &pki.ca_pem).unwrap();

        let srv_cfg = tls_server_cfg(&pki);
        let pg_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let pg_addr = pg_listener.local_addr().unwrap();
        let pg_thread = std::thread::spawn(move || {
            let _ = accept_pg_ssl_connection(&pg_listener, srv_cfg);
        });
        let pg_dsn = format!("postgres://grdr@{pg_addr}/guardrails?sslmode=verify-full");

        let (s3_addr, s3_ok_thread) = spawn_s3_mock(
            5,
            Some(ok_date.clone()),
            200,
            "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
            200,
            "<LifecycleConfiguration><Rule><ID>r1</ID><Status>Enabled</Status><NoncurrentVersionExpiration><NoncurrentDays>35</NoncurrentDays></NoncurrentVersionExpiration></Rule></LifecycleConfiguration>",
            "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Days>35</Days></DefaultRetention></Rule></ObjectLockConfiguration>",
        );
        let endpoint = format!("http://{s3_addr}");
        let certs = vec![ca_path];
        let mut ok_opts = PreflightOptions::for_profile("ha");
        ok_opts.postgres_dsn = Some(&pg_dsn);
        ok_opts.object_store_endpoint = Some(&endpoint);
        ok_opts.object_store_bucket = Some("grdr-lake");
        ok_opts.backup_bucket = Some("grdr-backup");
        ok_opts.object_store_addressing = S3AddressingStyle::PathStyle;
        ok_opts.cert_files = &certs;
        let ok_rep = build_preflight_report_with_probes(&ok_opts, true);
        let _ = s3_ok_thread.join();
        let _ = pg_thread.join();
        assert_eq!(ok_rep.overall, CheckOutcome::Pass, "{:?}", ok_rep.checks);

        // Fail on missing Date, 403, missing Expiration rule, GOVERNANCE lock, DTD injection.
        let pg_dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let pg_dead_dsn = format!(
            "postgres://grdr@{}/guardrails?sslmode=verify-full",
            pg_dead.local_addr().unwrap()
        );
        let (bad_s3, s3_bad_thread) = spawn_s3_mock(
            5,
            None,
            403,
            "AccessDenied",
            200,
            "<LifecycleConfiguration><Rule><Status>Enabled</Status></Rule></LifecycleConfiguration>",
            "<!DOCTYPE x [<!ENTITY a 'b'>]><ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>7</Days></DefaultRetention></Rule></ObjectLockConfiguration>",
        );
        let bad_endpoint = format!("http://{bad_s3}");
        let mut bad_opts = PreflightOptions::for_profile("ha");
        bad_opts.postgres_dsn = Some(&pg_dead_dsn);
        bad_opts.object_store_endpoint = Some(&bad_endpoint);
        bad_opts.object_store_bucket = Some("grdr-lake");
        bad_opts.backup_bucket = Some("grdr-backup");
        bad_opts.object_store_addressing = S3AddressingStyle::PathStyle;
        let bad_rep = build_preflight_report_with_probes(&bad_opts, true);
        let _ = s3_bad_thread.join();
        drop(pg_dead);
        assert_eq!(bad_rep.overall, CheckOutcome::Fail);
        assert!(
            bad_rep
                .checks
                .iter()
                .any(|c| c.name == "http_clock_skew" && c.outcome == CheckOutcome::Fail)
        );
        assert!(
            bad_rep
                .checks
                .iter()
                .any(|c| c.name == "object_store_bucket_versioning"
                    && c.outcome == CheckOutcome::Fail
                    && c.code.as_deref() == Some("GRDR-PREFLIGHT-0003"))
        );
        assert!(
            bad_rep
                .checks
                .iter()
                .any(|c| c.name == "object_store_bucket_lifecycle"
                    && c.outcome == CheckOutcome::Fail)
        );
        assert!(
            bad_rep
                .checks
                .iter()
                .any(|c| c.name == "backup_bucket_object_lock"
                    && c.outcome == CheckOutcome::Fail
                    && c.code.as_deref() == Some("GRDR-PREFLIGHT-0003"))
        );

        // VirtualHosted on IP literal must instruct passing --object-store-path-style.
        let (vh_s3, vh_thread) = spawn_s3_mock(1, Some(ok_date), 200, "", 200, "", "");
        let vh_endpoint = format!("http://{vh_s3}");
        let mut vh_opts = PreflightOptions::for_profile("ha");
        vh_opts.postgres_dsn =
            Some("postgres://grdr@pg.example.test:5432/guardrails?sslmode=verify-full");
        vh_opts.object_store_endpoint = Some(&vh_endpoint);
        vh_opts.object_store_bucket = Some("grdr-lake");
        vh_opts.backup_bucket = Some("grdr-backup");
        vh_opts.object_store_addressing = S3AddressingStyle::VirtualHosted;
        let vh_rep = build_preflight_report_with_probes(&vh_opts, true);
        let _ = vh_thread.join();
        assert!(vh_rep.checks.iter().any(|c| {
            c.outcome == CheckOutcome::Fail
                && c.detail
                    .contains("pass --object-store-path-style for IP endpoints")
        }));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn server_preflight_pg_wire_clock_skew_and_ssl_request() {
        use std::io::{Read, Write};
        let now_s = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let base =
            std::env::temp_dir().join(format!("grdr-pf-pgtls-{}", uuid::Uuid::now_v7().simple()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let obj_dir = base.join("objects");
        std::fs::create_dir_all(&obj_dir).unwrap();

        let pki = make_test_pki(now_s, 60, [127, 0, 0, 1], "localhost", true);
        let ca_path = base.join("ca.pem");
        std::fs::write(&ca_path, &pki.ca_pem).unwrap();

        let epoch_str = (now_s - 30).to_string();
        let srv_cfg = tls_server_cfg(&pki);
        let pg_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let pg_addr = pg_listener.local_addr().unwrap();
        let pg_thread = std::thread::spawn(move || {
            let (mut stream, mut tls_srv) =
                accept_pg_ssl_connection(&pg_listener, srv_cfg).unwrap();
            let mut io = rustls::Stream::new(&mut tls_srv, &mut stream);
            let mut buf = [0u8; 512];
            let _ = io.read(&mut buf);
            let _ = io.write_all(&[b'R', 0, 0, 0, 8, 0, 0, 0, 0, b'Z', 0, 0, 0, 5, b'I']);
            let _ = io.flush();
            let _ = io.read(&mut buf);
            let val_bytes = epoch_str.as_bytes();
            let row_len = (4 + 2 + 4 + val_bytes.len()) as u32;
            let mut row = vec![b'D'];
            row.extend_from_slice(&row_len.to_be_bytes());
            row.extend_from_slice(&1i16.to_be_bytes());
            row.extend_from_slice(&(val_bytes.len() as i32).to_be_bytes());
            row.extend_from_slice(val_bytes);
            row.extend_from_slice(&[b'Z', 0, 0, 0, 5, b'I']);
            let _ = io.write_all(&row);
            let _ = io.flush();
        });

        let certs = vec![ca_path];
        let dsn = format!("postgres://grdr@{pg_addr}/guardrails?sslmode=verify-full");
        let mut opts = PreflightOptions::for_profile("ha");
        opts.postgres_dsn = Some(&dsn);
        opts.object_store_dir = Some(&obj_dir);
        opts.cert_files = &certs;
        opts.pg_clock_probe = PgClockProbe::Enforce;
        let rep = build_preflight_report_with_probes(&opts, true);
        let _ = pg_thread.join();
        assert_eq!(rep.overall, CheckOutcome::Fail);
        assert!(
            rep.checks
                .iter()
                .any(|c| c.name == "postgres_tls_negotiation" && c.outcome == CheckOutcome::Pass)
        );
        assert!(rep.checks.iter().any(|c| c.name == "postgres_clock_skew"
            && c.outcome == CheckOutcome::Fail
            && c.code.as_deref() == Some("GRDR-PREFLIGHT-0001")));

        let ssl_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let ssl_addr = ssl_listener.local_addr().unwrap();
        let ssl_thread = std::thread::spawn(move || {
            for _ in 0..2 {
                if let Ok((mut s, _)) = ssl_listener.accept() {
                    let mut b = [0u8; 64];
                    if s.read(&mut b).unwrap_or(0) == 8 && b[4..8] == [0x04, 0xD2, 0x16, 0x2F] {
                        let _ = s.write_all(b"N");
                    }
                }
            }
        });
        let ssl_dsn = format!("postgres://grdr@{ssl_addr}/guardrails?sslmode=verify-full");
        let mut ssl_opts = PreflightOptions::for_profile("ha");
        ssl_opts.postgres_dsn = Some(&ssl_dsn);
        ssl_opts.object_store_dir = Some(&obj_dir);
        ssl_opts.pg_clock_probe = PgClockProbe::Enforce;
        let ssl_rep = build_preflight_report_with_probes(&ssl_opts, true);
        let _ = ssl_thread.join();
        assert_eq!(ssl_rep.overall, CheckOutcome::Fail);
        assert!(
            ssl_rep
                .checks
                .iter()
                .any(|c| c.name == "postgres_tls_negotiation"
                    && c.outcome == CheckOutcome::Fail
                    && c.code.as_deref() == Some("GRDR-PREFLIGHT-0005"))
        );

        // Reject sslmode=require/disable on PF-06 without opening any TCP/TLS connection.
        let untouched_pg = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let untouched_addr = untouched_pg.local_addr().unwrap();
        untouched_pg.set_nonblocking(true).unwrap();
        for bad_ssl in ["require", "disable"] {
            let bad_dsn = format!("postgres://grdr@{untouched_addr}/guardrails?sslmode={bad_ssl}");
            let mut bopts = PreflightOptions::for_profile("ha");
            bopts.postgres_dsn = Some(&bad_dsn);
            bopts.object_store_dir = Some(&obj_dir);
            bopts.pg_clock_probe = PgClockProbe::Enforce;
            let brep = build_preflight_report_with_probes(&bopts, true);
            assert_eq!(brep.overall, CheckOutcome::Fail);
            assert!(
                brep.checks
                    .iter()
                    .any(|c| c.name == "postgres_18_dsn" && c.outcome == CheckOutcome::Fail)
            );
            assert!(
                !brep.checks.iter().any(
                    |c| c.name == "postgres_tls_negotiation" || c.name == "postgres_clock_skew"
                ),
                "must fail early before any TCP/TLS connection on {bad_ssl}"
            );
            assert!(
                untouched_pg.accept().is_err(),
                "no TCP connection may be dialed on {bad_ssl}"
            );
        }

        // Reject ReadyForQuery before SCRAM ServerFinal (auth code 12) completes.
        let scram_cfg = tls_server_cfg(&pki);
        let scram_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let scram_addr = scram_listener.local_addr().unwrap();
        let scram_thread = std::thread::spawn(move || {
            let (mut stream, mut tls_srv) =
                accept_pg_ssl_connection(&scram_listener, scram_cfg).unwrap();
            let mut io = rustls::Stream::new(&mut tls_srv, &mut stream);
            let mut hdr = [0u8; 4];
            if io.read_exact(&mut hdr).is_ok() {
                let total = u32::from_be_bytes(hdr) as usize;
                let rem = total.saturating_sub(4).min(4096);
                let mut sbody = vec![0u8; rem];
                let _ = io.read_exact(&mut sbody);
            }
            let mut msg = vec![b'R', 0, 0, 0, 23, 0, 0, 0, 10];
            msg.extend_from_slice(b"SCRAM-SHA-256\0\0");
            let _ = io.write_all(&msg);
            let _ = io.flush();
            let mut tag_len = [0u8; 5];
            if io.read_exact(&mut tag_len).is_ok() {
                let p_len =
                    u32::from_be_bytes([tag_len[1], tag_len[2], tag_len[3], tag_len[4]]) as usize;
                let rem = p_len.saturating_sub(4).min(4096);
                let mut pbody = vec![0u8; rem];
                let _ = io.read_exact(&mut pbody);
            }
            let _ = io.write_all(&[b'Z', 0, 0, 0, 5, b'I']);
            let _ = io.flush();
            let mut drain = [0u8; 32];
            let _ = io.read(&mut drain);
        });
        let scram_dsn = format!("postgres://grdr@{scram_addr}/guardrails?sslmode=verify-full");
        let mut scram_opts = PreflightOptions::for_profile("ha");
        scram_opts.postgres_dsn = Some(&scram_dsn);
        scram_opts.object_store_dir = Some(&obj_dir);
        scram_opts.cert_files = &certs;
        scram_opts.pg_clock_probe = PgClockProbe::Enforce;
        let scram_rep = build_preflight_report_with_probes(&scram_opts, true);
        let _ = scram_thread.join();
        assert!(scram_rep.checks.iter().any(|c| {
            c.name == "postgres_clock_skew"
                && c.outcome == CheckOutcome::Fail
                && c.detail.contains("before completing authentication")
        }));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn server_preflight_certs_backups_drills_and_headroom() {
        let base =
            std::env::temp_dir().join(format!("grdr-pf-host-{}", uuid::Uuid::now_v7().simple()));
        let _ = std::fs::remove_dir_all(&base);
        let data_dir = base.join("data");
        let backup_dir = base.join("backups");
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::create_dir_all(&backup_dir).unwrap();

        let now_s = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let ok_pki = make_test_pki(now_s, 60, [127, 0, 0, 1], "localhost", true);
        let soon_pki = make_test_pki(now_s, 5, [127, 0, 0, 1], "localhost", true);
        let bad_eku_pki = make_test_pki(now_s, 60, [127, 0, 0, 1], "localhost", false);

        let ok_cert = base.join("ok.pem");
        std::fs::write(&ok_cert, &ok_pki.chain_pem).unwrap();
        let soon_cert = base.join("soon.pem");
        std::fs::write(&soon_cert, &soon_pki.chain_pem).unwrap();
        let bad_eku_cert = base.join("bad-eku.pem");
        std::fs::write(&bad_eku_cert, &bad_eku_pki.chain_pem).unwrap();
        let bad_b64_cert = base.join("bad-b64.pem");
        std::fs::write(
            &bad_b64_cert,
            "-----BEGIN CERTIFICATE-----\nAA=A\n-----END CERTIFICATE-----\n",
        )
        .unwrap();

        std::fs::write(backup_dir.join("snap-latest.sqlite3"), b"snap").unwrap();
        let fresh_drill = format!(
            "{{\"completed_at\":\"{}\"}}",
            Timestamp::from_second(now_s - 86_400).unwrap()
        );
        std::fs::write(backup_dir.join("restore-drill.json"), fresh_drill).unwrap();

        let certs_ok = vec![ok_cert];
        let mut ok_opts = PreflightOptions::for_profile("embedded");
        ok_opts.data_dir = Some(&data_dir);
        ok_opts.backup_dir = Some(&backup_dir);
        ok_opts.cert_files = &certs_ok;
        let ok_rep = build_preflight_report(&ok_opts);
        assert_eq!(ok_rep.overall, CheckOutcome::Pass, "{:?}", ok_rep.checks);

        // Expiring cert, bad EKU cert, corrupt Base64 PEM, tampered intermediate CA chain, and corrupt drill.
        let chain_ok = base.join("chain-ok.pem");
        std::fs::write(&chain_ok, make_three_cert_chain_pem(now_s, false)).unwrap();
        let chain_tampered = base.join("chain-tampered.pem");
        std::fs::write(&chain_tampered, make_three_cert_chain_pem(now_s, true)).unwrap();

        let chain_ok_certs = vec![chain_ok];
        let mut chain_ok_opts = PreflightOptions::for_profile("embedded");
        chain_ok_opts.data_dir = Some(&data_dir);
        chain_ok_opts.cert_files = &chain_ok_certs;
        assert_eq!(
            build_preflight_report(&chain_ok_opts).overall,
            CheckOutcome::Pass
        );

        // [leaf, intermediate] fullchain.pem without inline root passes when signed by built-in roots,
        // while unanchored or tampered [leaf, intermediate] still fails PF-09.
        let (fullchain_pem, root_der) = make_three_cert_chain_parts(now_s, false);
        let fullchain_path = base.join("fullchain.pem");
        std::fs::write(&fullchain_path, fullchain_pem).unwrap();
        let builtin_roots = vec![rustls::pki_types::CertificateDer::from(root_der)];
        let fc_paths = vec![fullchain_path.clone()];
        let fc_builtin_checks = crate::server_preflight::probe_certs_with_builtin_roots_test(
            &fc_paths,
            &builtin_roots,
            now_s,
        );
        assert_eq!(fc_builtin_checks.len(), 2, "{fc_builtin_checks:?}");
        assert!(
            fc_builtin_checks
                .iter()
                .all(|c| c.outcome == CheckOutcome::Pass),
            "{fc_builtin_checks:?}"
        );
        let mut unanchored_opts = PreflightOptions::for_profile("embedded");
        unanchored_opts.data_dir = Some(&data_dir);
        unanchored_opts.cert_files = &fc_paths;
        assert_eq!(
            build_preflight_report(&unanchored_opts).overall,
            CheckOutcome::Fail
        );
        let (bad_fullchain_pem, _) = make_three_cert_chain_parts(now_s, true);
        let bad_fullchain_path = base.join("fullchain-tampered.pem");
        std::fs::write(&bad_fullchain_path, bad_fullchain_pem).unwrap();
        let bad_fc_checks = crate::server_preflight::probe_certs_with_builtin_roots_test(
            &[bad_fullchain_path],
            &builtin_roots,
            now_s,
        );
        assert!(
            bad_fc_checks
                .iter()
                .any(|c| c.outcome == CheckOutcome::Fail),
            "{bad_fc_checks:?}"
        );

        for bad_cert_path in [soon_cert, bad_eku_cert, bad_b64_cert, chain_tampered] {
            let bad_certs = vec![bad_cert_path];
            let mut bopts = PreflightOptions::for_profile("embedded");
            bopts.data_dir = Some(&data_dir);
            bopts.cert_files = &bad_certs;
            assert_eq!(build_preflight_report(&bopts).overall, CheckOutcome::Fail);
        }

        // --check-disk with --object-store-dir and without --data-dir still probes object_store_dir.
        let obj_only_dir = base.join("obj-only");
        std::fs::create_dir_all(&obj_only_dir).unwrap();
        let mut obj_disk_opts = PreflightOptions::for_profile("ha");
        obj_disk_opts.postgres_dsn =
            Some("postgres://grdr@pg.example.test:5432/guardrails?sslmode=verify-full");
        obj_disk_opts.object_store_dir = Some(&obj_only_dir);
        obj_disk_opts.disk_headroom_probe = DiskHeadroomProbe::Enforce;
        let obj_disk_rep = build_preflight_report(&obj_disk_opts);
        let obj_disk_chk = obj_disk_rep
            .checks
            .iter()
            .find(|c| c.name == "disk_headroom")
            .expect("disk_headroom probe must run when only --object-store-dir is passed");
        assert!(
            obj_disk_chk.detail.starts_with("Disk free space on ")
                && obj_disk_chk.detail.contains("obj-only"),
            "unexpected object-store disk_headroom check: {obj_disk_chk:?}"
        );
        if obj_disk_chk.detail.contains("(>= 30%)") {
            assert_eq!(obj_disk_chk.outcome, CheckOutcome::Pass);
        } else {
            assert!(obj_disk_chk.detail.contains("(< 30% required)"));
            assert_eq!(obj_disk_chk.outcome, CheckOutcome::Fail);
        }
        let obj_missing = base.join("obj-missing");
        let mut obj_missing_opts = PreflightOptions::for_profile("ha");
        obj_missing_opts.postgres_dsn = obj_disk_opts.postgres_dsn;
        obj_missing_opts.object_store_dir = Some(&obj_missing);
        obj_missing_opts.disk_headroom_probe = DiskHeadroomProbe::Enforce;
        let obj_missing_rep = build_preflight_report(&obj_missing_opts);
        assert!(obj_missing_rep.checks.iter().any(|c| {
            c.name == "disk_headroom"
                && c.outcome == CheckOutcome::Fail
                && c.detail.contains("obj-missing")
        }));

        let corrupt_drill_path = base.join("corrupt-drill.json");
        std::fs::write(&corrupt_drill_path, "{corrupt json").unwrap();
        let mut drill_opts = PreflightOptions::for_profile("embedded");
        drill_opts.data_dir = Some(&data_dir);
        drill_opts.backup_dir = Some(&backup_dir);
        drill_opts.restore_drill_marker = Some(&corrupt_drill_path);
        let drill_rep = build_preflight_report(&drill_opts);
        assert_eq!(drill_rep.overall, CheckOutcome::Fail);
        assert!(
            drill_rep
                .checks
                .iter()
                .any(|c| c.name == "restore_drill_age" && c.outcome == CheckOutcome::Fail)
        );

        // --check-disk on missing path must Fail (not silently omitted).
        let missing_dir = base.join("does-not-exist");
        let mut disk_opts = PreflightOptions::for_profile("embedded");
        disk_opts.data_dir = Some(&missing_dir);
        disk_opts.disk_headroom_probe = DiskHeadroomProbe::Enforce;
        let disk_rep = build_preflight_report(&disk_opts);
        assert_eq!(disk_rep.overall, CheckOutcome::Fail);
        assert!(
            disk_rep
                .checks
                .iter()
                .any(|c| c.name == "disk_headroom" && c.outcome == CheckOutcome::Fail)
        );

        // Malformed limits.toml must fail closed.
        assert!(
            parse_limits_thresholds_test("[server.preflight]\nbackup_max_age_hours = not_a_num\n")
                .is_err()
        );

        let low_disk = evaluate_disk_headroom_sample("/var/lib/grdr", 1_000, 200, 30);
        assert_eq!(low_disk.outcome, CheckOutcome::Fail);
        let ok_disk = evaluate_disk_headroom_sample("/var/lib/grdr", 1_000, 500, 30);
        assert_eq!(ok_disk.outcome, CheckOutcome::Pass);

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn server_migrate_to_ha_copies_embedded_state_and_refuses_nonempty_bucket() {
        let base = std::env::temp_dir().join(format!(
            "grdr-cli-migrate-{}",
            uuid::Uuid::now_v7().simple()
        ));
        let src_dir = base.join("embedded");
        let dst_bucket = base.join("ha-bucket");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&src_dir).unwrap();

        let org = OrgId::new("org-embedded").unwrap();
        let ctx = SingleCtx::new(org);
        let rel = SqliteRelationalStore::open(&src_dir.join("relational.sqlite3")).unwrap();
        rel.upsert_device(
            &ctx,
            &Device {
                id: "dev-mig-1".into(),
                hostname: "mig-host".into(),
                os: "linux".into(),
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
            },
        )
        .unwrap();
        let bus = SqliteLogBus::open(&src_dir.join("bus.sqlite3")).unwrap();
        bus.append(
            &ctx,
            "events",
            0,
            &[BusAppendMessage {
                key: "dev-mig-1".into(),
                headers: BTreeMap::new(),
                payload: b"tail-msg".to_vec(),
            }],
            1_000,
        )
        .unwrap();
        let blobs = FilesystemBlobStore::open(&src_dir.join("blobs")).unwrap();
        blobs
            .put(
                &ctx,
                &TenantPath::parse(&ctx, "class=decision/day=2026-11-24/seg-1.json").unwrap(),
                b"{\"ok\":true}",
            )
            .unwrap();

        let dry = migrate_embedded_to_ha(&MigrateHaOptions {
            to_profile: "ha",
            from_data_dir: &src_dir,
            target_bucket_dir: &dst_bucket,
            postgres_dsn: None,
            dry_run: true,
        })
        .unwrap();
        assert_eq!(dry.devices_copied, 1);
        assert_eq!(dry.blobs_copied, 1);
        assert_eq!(dry.bus_messages_replayed, 1);
        assert!(!dst_bucket.exists());

        let bad_target = migrate_embedded_to_ha(&MigrateHaOptions {
            to_profile: "distributed",
            from_data_dir: &src_dir,
            target_bucket_dir: &dst_bucket,
            postgres_dsn: None,
            dry_run: false,
        })
        .unwrap_err();
        assert_eq!(bad_target.code, CODE_MIGRATE_INVALID_TARGET);

        let report = migrate_embedded_to_ha(&MigrateHaOptions {
            to_profile: "ha",
            from_data_dir: &src_dir,
            target_bucket_dir: &dst_bucket,
            postgres_dsn: None,
            dry_run: false,
        })
        .unwrap();
        assert_eq!(report.devices_copied, 1);
        assert_eq!(report.blobs_copied, 1);
        assert_eq!(report.bus_messages_replayed, 1);

        let err = migrate_embedded_to_ha(&MigrateHaOptions {
            to_profile: "ha",
            from_data_dir: &src_dir,
            target_bucket_dir: &dst_bucket,
            postgres_dsn: None,
            dry_run: false,
        })
        .unwrap_err();
        assert_eq!(err.code, CODE_MIGRATE_BUCKET_NOT_EMPTY);

        let _ = std::fs::remove_dir_all(&base);
    }
}
