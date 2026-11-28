// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#[path = "server_preflight_cert.rs"]
mod cert_probes;
#[path = "server_preflight_der.rs"]
mod der_parse;
#[path = "server_preflight_ha.rs"]
mod ha_probes;
#[path = "server_preflight_pg_tls.rs"]
mod pg_tls_probes;
#[path = "server_preflight_types.rs"]
mod probe_types;
#[path = "server_preflight_s3_auth.rs"]
mod s3_auth;
#[path = "server_preflight_s3_http.rs"]
mod s3_http;
#[path = "server_preflight_s3.rs"]
mod s3_probes;
#[path = "server_preflight_storage.rs"]
mod storage_probes;
#[path = "server_preflight_tls.rs"]
mod tls_probes;

use std::process::ExitCode;

use grdr_ports::ProfileKind;

#[cfg(test)]
use probe_types::PreflightCheck;
use probe_types::{
    CODE_STORAGE, PreflightThresholds, current_unix_s, load_preflight_thresholds, mk_check,
    normalize_path_for_overlap, push_raw, raw_to_check,
};
pub use probe_types::{
    CheckOutcome, DiskHeadroomProbe, PgClockProbe, PreflightOptions, PreflightReport,
    S3AddressingStyle,
};

#[cfg(test)]
pub fn evaluate_disk_headroom_sample(
    label: &str,
    total_bytes: u64,
    avail_bytes: u64,
    min_pct: u64,
) -> PreflightCheck {
    raw_to_check(storage_probes::evaluate_disk_headroom_bytes(
        label,
        total_bytes,
        avail_bytes,
        min_pct,
    ))
}

#[cfg(test)]
pub fn build_preflight_report(opts: &PreflightOptions<'_>) -> PreflightReport {
    build_preflight_report_with_probes(opts, false)
}

#[cfg(test)]
pub fn sign_s3_test_headers(
    method: &str,
    url: &str,
    access_key: &str,
    secret_key: &str,
    region: &str,
    now_unix_s: i64,
) -> Result<Vec<(String, String)>, String> {
    let creds = s3_auth::S3Credentials {
        access_key: access_key.to_string(),
        secret_key: secret_key.to_string(),
        session_token: None,
        region: region.to_string(),
    };
    s3_auth::sign_aws_sigv4_headers(method, url, &creds, now_unix_s)
}

#[cfg(test)]
pub fn parse_limits_thresholds_test(toml_text: &str) -> Result<(), String> {
    probe_types::parse_preflight_thresholds_from(toml_text).map(|_| ())
}

#[cfg(test)]
pub fn check_loopback_test(hostport: &str) -> bool {
    probe_types::is_loopback_hostport(hostport)
}

#[cfg(test)]
pub fn probe_certs_with_builtin_roots_test(
    cert_files: &[std::path::PathBuf],
    builtin_roots: &[rustls_pki_types::CertificateDer<'static>],
    now_unix_s: i64,
) -> Vec<PreflightCheck> {
    let thresholds = load_preflight_thresholds().unwrap_or_else(|_| PreflightThresholds::default());
    cert_probes::probe_pem_certificates_with_roots(
        cert_files,
        builtin_roots,
        &thresholds,
        now_unix_s,
    )
    .into_iter()
    .map(raw_to_check)
    .collect()
}

pub fn run_preflight(opts: &PreflightOptions<'_>, json: bool, strict: bool) -> ExitCode {
    let report = build_preflight_report_with_probes(opts, true);
    if json {
        match serde_json::to_string_pretty(&report) {
            Ok(out) => println!("{out}"),
            Err(err) => {
                eprintln!("GRDR-CLI-0005: failed serializing preflight report: {err}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        println!(
            "Guardrails server preflight (profile: {}, overall: {:?})",
            report.profile, report.overall
        );
        for chk in &report.checks {
            let id_prefix = chk
                .id
                .as_deref()
                .map(|id| format!("{id} "))
                .unwrap_or_default();
            let code_suffix = chk
                .code
                .as_deref()
                .map(|c| format!(" [{c}]"))
                .unwrap_or_default();
            println!(
                "  - {:?} {}{}{}: {}",
                chk.outcome, id_prefix, chk.name, code_suffix, chk.detail
            );
        }
    }

    match report.overall {
        CheckOutcome::Fail => ExitCode::FAILURE,
        CheckOutcome::Warn if strict => ExitCode::FAILURE,
        CheckOutcome::Pass | CheckOutcome::Warn => ExitCode::SUCCESS,
    }
}

pub fn build_preflight_report_with_probes(
    opts: &PreflightOptions<'_>,
    probe_network: bool,
) -> PreflightReport {
    let mut checks = Vec::new();
    let thresholds = match load_preflight_thresholds() {
        Ok(cfg) => cfg,
        Err(detail) => {
            checks.push(mk_check(
                "PF-01",
                "preflight_limits_contract",
                CheckOutcome::Fail,
                detail,
                Some(CODE_STORAGE.into()),
                Some("Restore valid [server.tenancy] and [server.preflight] entries in contracts/limits.toml."),
            ));
            PreflightThresholds::default()
        }
    };
    let now_s = match current_unix_s() {
        Ok(s) => s,
        Err(detail) => {
            checks.push(mk_check(
                "PF-08",
                "host_system_clock",
                CheckOutcome::Fail,
                detail,
                Some(CODE_STORAGE.into()),
                Some("Synchronize host clock before starting server."),
            ));
            return PreflightReport {
                profile: opts.profile.to_string(),
                overall: CheckOutcome::Fail,
                checks,
            };
        }
    };

    let parsed_profile = match ProfileKind::parse(opts.profile) {
        Ok(p) => {
            checks.push(mk_check(
                "PF-01",
                "profile_selection",
                CheckOutcome::Pass,
                format!("Validated profile `{}` (P6/D-33).", p.as_str()),
                None,
                None,
            ));
            Some(p)
        }
        Err(err) => {
            checks.push(mk_check(
                "PF-01",
                "profile_selection",
                CheckOutcome::Fail,
                err.message,
                Some(err.code),
                Some("Specify embedded, ha, or distributed."),
            ));
            None
        }
    };

    if let Some(profile) = parsed_profile {
        match profile {
            ProfileKind::Embedded => ha_probes::check_embedded(opts, &mut checks),
            ProfileKind::Ha => {
                ha_probes::check_postgres(
                    opts.postgres_dsn,
                    opts.cert_files,
                    probe_network,
                    opts.pg_clock_probe,
                    &thresholds,
                    now_s,
                    &mut checks,
                );
                ha_probes::check_object_store(opts, probe_network, &thresholds, now_s, &mut checks);
            }
            ProfileKind::Distributed => {
                ha_probes::check_postgres(
                    opts.postgres_dsn,
                    opts.cert_files,
                    probe_network,
                    opts.pg_clock_probe,
                    &thresholds,
                    now_s,
                    &mut checks,
                );
                ha_probes::check_nats(opts.nats_url, opts.cert_files, probe_network, &mut checks);
                ha_probes::check_object_store(opts, probe_network, &thresholds, now_s, &mut checks);
            }
        }
        if opts.backup_dir.is_some() || opts.restore_drill_marker.is_some() {
            push_raw(
                storage_probes::probe_backup_and_drill(
                    profile,
                    opts.backup_dir,
                    opts.data_dir,
                    opts.restore_drill_marker,
                    &thresholds,
                    now_s,
                ),
                &mut checks,
            );
        }
        if !opts.cert_files.is_empty() {
            push_raw(
                cert_probes::probe_pem_certificates(opts.cert_files, &thresholds, now_s),
                &mut checks,
            );
        }
        if opts.disk_headroom_probe == DiskHeadroomProbe::Enforce {
            let clean_obj_dir = opts.object_store_dir.filter(|d| !d.as_os_str().is_empty());
            if let Some(dir) = opts.data_dir {
                checks.push(raw_to_check(storage_probes::probe_disk_headroom(
                    dir,
                    &thresholds,
                )));
            } else if clean_obj_dir.is_none() {
                checks.push(mk_check(
                    "PF-12",
                    "disk_headroom",
                    CheckOutcome::Fail,
                    "Disk headroom probe enabled without --data-dir or --object-store-dir.".into(),
                    Some(CODE_STORAGE.into()),
                    Some("Supply --data-dir or --object-store-dir when using --check-disk."),
                ));
            }
            if let Some(dir) = clean_obj_dir
                && opts.data_dir.is_none_or(|d| {
                    normalize_path_for_overlap(d) != normalize_path_for_overlap(dir)
                })
            {
                checks.push(raw_to_check(storage_probes::probe_disk_headroom(
                    dir,
                    &thresholds,
                )));
            }
        }
    }

    let overall = if checks.iter().any(|c| c.outcome == CheckOutcome::Fail) {
        CheckOutcome::Fail
    } else if checks.iter().any(|c| c.outcome == CheckOutcome::Warn) {
        CheckOutcome::Warn
    } else {
        CheckOutcome::Pass
    };
    PreflightReport {
        profile: opts.profile.to_string(),
        overall,
        checks,
    }
}
