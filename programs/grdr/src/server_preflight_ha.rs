// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use grdr_bus_nats::{NatsConfig, NatsTransportMode};
use grdr_rel_postgres::{POSTGRES_MIGRATIONS, PostgresConfig, PostgresSslMode, PostgresTransport};

use crate::server_preflight::pg_tls_probes;
use crate::server_preflight::probe_types::{
    CODE_NATS_URL, CODE_OBJECT_STORE, CODE_PG_DSN, CODE_STORAGE, CheckOutcome, ErrCodeSlot,
    PgClockProbe, PreflightCheck, PreflightOptions, PreflightThresholds, mk_check,
    normalize_path_for_overlap, probe_tcp_reachability, push_raw, raw_to_check,
};
use crate::server_preflight::s3_auth;
use crate::server_preflight::s3_probes;
use crate::server_preflight::storage_probes;
use crate::server_preflight::tls_probes;

pub(super) fn check_embedded(opts: &PreflightOptions<'_>, checks: &mut Vec<PreflightCheck>) {
    match opts.data_dir {
        Some(dir) => {
            checks.push(raw_to_check(storage_probes::check_directory_writable(
                "embedded_data_dir",
                dir,
                false,
            )));
            if let Some(backup) = opts.backup_dir {
                let norm_dir = normalize_path_for_overlap(dir);
                let norm_backup = normalize_path_for_overlap(backup);
                let same_root =
                    norm_backup.starts_with(&norm_dir) || norm_dir.starts_with(&norm_backup);
                let (outcome, detail, remedy) = if same_root {
                    (
                        CheckOutcome::Warn,
                        "backup/ shares a normalized root with data_dir; place backups on a separate volume.".to_string(),
                        Some("Mount backups on a separate volume."),
                    )
                } else {
                    (
                        CheckOutcome::Pass,
                        "Backup directory is isolated from data_dir.".to_string(),
                        None,
                    )
                };
                checks.push(mk_check(
                    "PF-02",
                    "backup_volume_isolation",
                    outcome,
                    detail,
                    None,
                    remedy,
                ));
            }
        }
        None => checks.push(mk_check(
            "PF-02",
            "embedded_data_dir",
            CheckOutcome::Warn,
            "No --data-dir provided; ephemeral memory mode will not persist lake segments.".into(),
            None,
            None,
        )),
    }
}

pub(super) fn check_postgres(
    postgres_dsn: Option<&str>,
    cert_files: &[std::path::PathBuf],
    probe_network: bool,
    pg_clock_probe: PgClockProbe,
    thresholds: &PreflightThresholds,
    now_s: i64,
    checks: &mut Vec<PreflightCheck>,
) {
    let Some(dsn) = postgres_dsn else {
        checks.push(mk_check(
            "PF-06",
            "postgres_18_dsn",
            CheckOutcome::Fail,
            "Missing --postgres-dsn for HA/Distributed profile.".into(),
            Some(CODE_PG_DSN.into()),
            Some("Provide GRDR_POSTGRES_DSN."),
        ));
        return;
    };
    match PostgresConfig::parse_dsn(dsn).and_then(|cfg| cfg.validate().map(|()| cfg)) {
        Ok(cfg) => {
            if cfg.ssl_mode != PostgresSslMode::VerifyFull {
                checks.push(mk_check(
                    "PF-06",
                    "postgres_18_dsn",
                    CheckOutcome::Fail,
                    format!(
                        "PostgreSQL sslmode={} is non-compliant; docs/design/24 section 6 mandates sslmode=verify-full.",
                        cfg.ssl_mode.as_str()
                    ),
                    Some(CODE_PG_DSN.into()),
                    Some(
                        "Set sslmode=verify-full on GRDR_POSTGRES_DSN and configure --cert / SSL_CERT_FILE.",
                    ),
                ));
                return;
            }
            checks.push(mk_check(
                "PF-06",
                "postgres_18_dsn",
                CheckOutcome::Pass,
                format!(
                    "Parsed PostgreSQL 18 DSN (sslmode=verify-full, migrations={}).",
                    POSTGRES_MIGRATIONS.len()
                ),
                None,
                None,
            ));
            if probe_network && let PostgresTransport::TcpWire { endpoint, .. } = &cfg.transport {
                checks.push(raw_to_check(probe_tcp_reachability(
                    "postgres_tcp_reachability",
                    endpoint,
                    ErrCodeSlot::PgTcp,
                )));
                push_raw(
                    pg_tls_probes::probe_postgres_wire_and_clock(
                        &cfg,
                        cert_files,
                        pg_clock_probe,
                        thresholds,
                        now_s,
                    ),
                    checks,
                );
            }
        }
        Err(err) => checks.push(mk_check(
            "PF-06",
            "postgres_18_dsn",
            CheckOutcome::Fail,
            err.message,
            Some(err.code),
            None,
        )),
    }
}

pub(super) fn check_nats(
    nats_url: Option<&str>,
    cert_files: &[std::path::PathBuf],
    probe_network: bool,
    checks: &mut Vec<PreflightCheck>,
) {
    let Some(url) = nats_url else {
        checks.push(mk_check(
            "PF-03",
            "nats_jetstream_url",
            CheckOutcome::Fail,
            "Missing --nats-url for Distributed profile.".into(),
            Some(CODE_NATS_URL.into()),
            Some("Provide GRDR_NATS_URL."),
        ));
        return;
    };
    match NatsConfig::parse_url(url).and_then(|cfg| cfg.validate().map(|()| cfg)) {
        Ok(cfg) => {
            if let NatsTransportMode::JetStreamTcp { ref server_url } = cfg.transport {
                if !server_url.starts_with("tls://") {
                    checks.push(mk_check(
                        "PF-03",
                        "nats_jetstream_url",
                        CheckOutcome::Fail,
                        "NATS URL uses plaintext nats://; tls:// is required.".into(),
                        Some(CODE_NATS_URL.into()),
                        Some("Use tls://host:port for GRDR_NATS_URL."),
                    ));
                    return;
                }
                if probe_network {
                    checks.push(raw_to_check(tls_probes::probe_nats_tls(
                        server_url, cert_files,
                    )));
                }
            }
            checks.push(mk_check(
                "PF-03",
                "nats_jetstream_url",
                CheckOutcome::Pass,
                format!(
                    "Validated NATS JetStream TLS URL (replicas={}).",
                    cfg.replicas
                ),
                None,
                None,
            ));
        }
        Err(err) => checks.push(mk_check(
            "PF-03",
            "nats_jetstream_url",
            CheckOutcome::Fail,
            err.message,
            Some(err.code),
            None,
        )),
    }
}

pub(super) fn check_object_store(
    opts: &PreflightOptions<'_>,
    probe_network: bool,
    thresholds: &PreflightThresholds,
    now_s: i64,
    checks: &mut Vec<PreflightCheck>,
) {
    let has_dir = opts
        .object_store_dir
        .is_some_and(|d| !d.as_os_str().is_empty());
    let has_s3_endpoint = opts
        .object_store_endpoint
        .is_some_and(|e| !e.trim().is_empty());

    if let Some(dir) = opts.object_store_dir.filter(|d| !d.as_os_str().is_empty()) {
        checks.push(raw_to_check(storage_probes::check_directory_writable(
            "object_store_conformance",
            dir,
            true,
        )));
        if let Some(state) = opts.data_dir {
            let norm_state = normalize_path_for_overlap(state);
            let norm_dir = normalize_path_for_overlap(dir);
            if norm_state == norm_dir
                || norm_state.starts_with(&norm_dir)
                || norm_dir.starts_with(&norm_state)
            {
                checks.push(mk_check(
                    "PF-04",
                    "state_key_isolation",
                    CheckOutcome::Fail,
                    "State directory (--data-dir) must not overlap --object-store-dir.".into(),
                    Some(CODE_STORAGE.into()),
                    None,
                ));
            }
        }
    }

    if let Some(endpoint) = opts
        .object_store_endpoint
        .map(str::trim)
        .filter(|e| !e.is_empty())
    {
        if probe_network {
            push_raw(
                s3_probes::probe_s3_object_store(
                    endpoint,
                    opts.object_store_bucket,
                    opts.backup_bucket,
                    opts.object_store_addressing,
                    opts.cert_files,
                    thresholds,
                    now_s,
                ),
                checks,
            );
        } else if let Err(msg) = s3_auth::validate_s3_endpoint_url(endpoint) {
            checks.push(mk_check(
                "PF-04",
                "object_store_endpoint_reachability",
                CheckOutcome::Fail,
                msg.into(),
                Some(CODE_OBJECT_STORE.into()),
                None,
            ));
        }
    }

    if !has_dir && !has_s3_endpoint {
        checks.push(mk_check(
            "PF-04",
            "object_store_conformance",
            CheckOutcome::Fail,
            "Missing --object-store-dir or --object-store-endpoint for HA/Distributed lake storage.".into(),
            Some(CODE_OBJECT_STORE.into()),
            None,
        ));
    }
}
