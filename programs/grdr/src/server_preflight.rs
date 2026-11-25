// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::fs;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use serde::Serialize;
use uuid::Uuid;

use grdr_bus_nats::{NatsConfig, NatsTransportMode};
use grdr_ports::ProfileKind;
use grdr_rel_postgres::{POSTGRES_MIGRATIONS, PostgresConfig, PostgresSslMode, PostgresTransport};

const TCP_PROBE_TIMEOUT_MS: u64 = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckOutcome {
    Pass,
    Warn,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PreflightCheck {
    pub name: String,
    pub outcome: CheckOutcome,
    pub detail: String,
    pub code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PreflightReport {
    pub profile: String,
    pub overall: CheckOutcome,
    pub checks: Vec<PreflightCheck>,
}

pub struct PreflightOptions<'a> {
    pub profile: &'a str,
    pub data_dir: Option<&'a Path>,
    pub backup_dir: Option<&'a Path>,
    pub postgres_dsn: Option<&'a str>,
    pub nats_url: Option<&'a str>,
    pub object_store_dir: Option<&'a Path>,
}

pub fn run_preflight(opts: &PreflightOptions<'_>, json: bool, strict: bool) -> ExitCode {
    let report = build_preflight_report_with_probes(opts, true);
    if json {
        match serde_json::to_string_pretty(&report) {
            Ok(out) => println!("{out}"),
            Err(err) => {
                eprintln!("GRDR-CLI-0001: failed serializing preflight report: {err}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        println!(
            "Guardrails server preflight (profile: {}, overall: {:?})",
            report.profile, report.overall
        );
        for chk in &report.checks {
            let code_suffix = chk
                .code
                .as_deref()
                .map(|c| format!(" [{c}]"))
                .unwrap_or_default();
            println!(
                "  - {:?} {}{}: {}",
                chk.outcome, chk.name, code_suffix, chk.detail
            );
        }
    }

    match report.overall {
        CheckOutcome::Fail => ExitCode::FAILURE,
        CheckOutcome::Warn if strict => ExitCode::FAILURE,
        CheckOutcome::Pass | CheckOutcome::Warn => ExitCode::SUCCESS,
    }
}

#[cfg(test)]
pub fn build_preflight_report(opts: &PreflightOptions<'_>) -> PreflightReport {
    build_preflight_report_with_probes(opts, false)
}

pub fn build_preflight_report_with_probes(
    opts: &PreflightOptions<'_>,
    probe_network: bool,
) -> PreflightReport {
    let mut checks = Vec::new();
    let parsed_profile = match ProfileKind::parse(opts.profile) {
        Ok(p) => {
            checks.push(PreflightCheck {
                name: "profile_selection".into(),
                outcome: CheckOutcome::Pass,
                detail: format!("Validated profile `{}` (P6/D-33).", p.as_str()),
                code: None,
            });
            Some(p)
        }
        Err(err) => {
            checks.push(PreflightCheck {
                name: "profile_selection".into(),
                outcome: CheckOutcome::Fail,
                detail: err.message,
                code: Some(err.code),
            });
            None
        }
    };

    if let Some(profile) = parsed_profile {
        match profile {
            ProfileKind::Embedded => check_embedded(opts, &mut checks),
            ProfileKind::Ha => {
                check_postgres(opts.postgres_dsn, probe_network, &mut checks);
                check_object_store(opts.object_store_dir, opts.data_dir, &mut checks);
            }
            ProfileKind::Distributed => {
                check_postgres(opts.postgres_dsn, probe_network, &mut checks);
                check_nats(opts.nats_url, probe_network, &mut checks);
                check_object_store(opts.object_store_dir, opts.data_dir, &mut checks);
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

fn check_embedded(opts: &PreflightOptions<'_>, checks: &mut Vec<PreflightCheck>) {
    match opts.data_dir {
        Some(dir) => {
            check_directory_writable("embedded_data_dir", dir, false, checks);
            if let Some(backup) = opts.backup_dir {
                let same_root = backup.starts_with(dir) || dir.starts_with(backup);
                checks.push(PreflightCheck {
                    name: "backup_volume_isolation".into(),
                    outcome: if same_root {
                        CheckOutcome::Warn
                    } else {
                        CheckOutcome::Pass
                    },
                    detail: if same_root {
                        "backup/ shares a prefix with data_dir; place backups on a separate volume."
                            .into()
                    } else {
                        "Backup directory is separated from data_dir.".into()
                    },
                    code: None,
                });
            }
        }
        None => checks.push(PreflightCheck {
            name: "embedded_data_dir".into(),
            outcome: CheckOutcome::Warn,
            detail: "No --data-dir provided; ephemeral memory mode will not persist lake segments."
                .into(),
            code: None,
        }),
    }
}

fn check_postgres(
    postgres_dsn: Option<&str>,
    probe_network: bool,
    checks: &mut Vec<PreflightCheck>,
) {
    let Some(dsn) = postgres_dsn else {
        checks.push(PreflightCheck {
            name: "postgres_18_dsn".into(),
            outcome: CheckOutcome::Fail,
            detail: "Missing --postgres-dsn for HA/Distributed profile.".into(),
            code: Some("GRDR-PREFLIGHT-0001".into()),
        });
        return;
    };
    match PostgresConfig::parse_dsn(dsn).and_then(|cfg| cfg.validate().map(|()| cfg)) {
        Ok(cfg) => {
            let (ssl_outcome, ssl_detail) = match cfg.ssl_mode {
                PostgresSslMode::Disable | PostgresSslMode::Prefer => (
                    CheckOutcome::Warn,
                    format!(
                        "PostgreSQL sslmode={} permits unencrypted connections; prefer require or verify-full.",
                        cfg.ssl_mode.as_str()
                    ),
                ),
                _ => (
                    CheckOutcome::Pass,
                    format!(
                        "Parsed PostgreSQL 18 DSN (sslmode={}, migrations={}).",
                        cfg.ssl_mode.as_str(),
                        POSTGRES_MIGRATIONS.len()
                    ),
                ),
            };
            checks.push(PreflightCheck {
                name: "postgres_18_dsn".into(),
                outcome: ssl_outcome,
                detail: ssl_detail,
                code: None,
            });
            if probe_network && let PostgresTransport::TcpWire { endpoint, .. } = &cfg.transport {
                probe_tcp(
                    "postgres_tcp_reachability",
                    endpoint,
                    "GRDR-PREFLIGHT-0005",
                    checks,
                );
            }
        }
        Err(err) => checks.push(PreflightCheck {
            name: "postgres_18_dsn".into(),
            outcome: CheckOutcome::Fail,
            detail: err.message,
            code: Some(err.code),
        }),
    }
}

fn check_nats(nats_url: Option<&str>, probe_network: bool, checks: &mut Vec<PreflightCheck>) {
    let Some(url) = nats_url else {
        checks.push(PreflightCheck {
            name: "nats_jetstream_url".into(),
            outcome: CheckOutcome::Fail,
            detail: "Missing --nats-url for Distributed profile.".into(),
            code: Some("GRDR-PREFLIGHT-0002".into()),
        });
        return;
    };
    match NatsConfig::parse_url(url).and_then(|cfg| cfg.validate().map(|()| cfg)) {
        Ok(cfg) => {
            let mut outcome = CheckOutcome::Pass;
            let mut detail = format!(
                "Validated NATS JetStream URL with unused listeners disabled (replicas={}).",
                cfg.replicas
            );
            if let NatsTransportMode::JetStreamTcp { ref server_url } = cfg.transport {
                if let Some(hp) = server_url.strip_prefix("nats://")
                    && !is_loopback_endpoint(hp)
                {
                    outcome = CheckOutcome::Warn;
                    detail = format!(
                        "NATS URL `{server_url}` uses plaintext nats:// on a non-loopback host; prefer tls://."
                    );
                }
                if probe_network {
                    let endpoint = server_url
                        .strip_prefix("nats://")
                        .or_else(|| server_url.strip_prefix("tls://"))
                        .unwrap_or(server_url);
                    probe_tcp(
                        "nats_tcp_reachability",
                        endpoint,
                        "GRDR-PREFLIGHT-0006",
                        checks,
                    );
                }
            }
            checks.push(PreflightCheck {
                name: "nats_jetstream_url".into(),
                outcome,
                detail,
                code: None,
            });
        }
        Err(err) => checks.push(PreflightCheck {
            name: "nats_jetstream_url".into(),
            outcome: CheckOutcome::Fail,
            detail: err.message,
            code: Some(err.code),
        }),
    }
}

fn check_object_store(
    object_store_dir: Option<&Path>,
    data_dir: Option<&Path>,
    checks: &mut Vec<PreflightCheck>,
) {
    match object_store_dir {
        Some(dir) if !dir.as_os_str().is_empty() => {
            check_directory_writable("object_store_conformance", dir, true, checks);
            if let Some(state) = data_dir {
                let norm_state = normalize_path_for_overlap(state);
                let norm_dir = normalize_path_for_overlap(dir);
                if norm_state == norm_dir
                    || norm_state.starts_with(&norm_dir)
                    || norm_dir.starts_with(&norm_state)
                {
                    checks.push(PreflightCheck {
                        name: "state_key_isolation".into(),
                        outcome: CheckOutcome::Fail,
                        detail: "State directory (--data-dir) must not overlap --object-store-dir."
                            .into(),
                        code: Some("GRDR-PREFLIGHT-0004".into()),
                    });
                }
            }
        }
        _ => checks.push(PreflightCheck {
            name: "object_store_conformance".into(),
            outcome: CheckOutcome::Fail,
            detail: "Missing --object-store-dir for HA/Distributed lake and archive storage."
                .into(),
            code: Some("GRDR-PREFLIGHT-0003".into()),
        }),
    }
}

fn check_directory_writable(
    name: &str,
    dir: &Path,
    warn_if_missing: bool,
    checks: &mut Vec<PreflightCheck>,
) {
    if dir.exists() {
        if !dir.is_dir() {
            checks.push(PreflightCheck {
                name: name.into(),
                outcome: CheckOutcome::Fail,
                detail: format!("Path `{}` exists and is not a directory.", dir.display()),
                code: Some("GRDR-PREFLIGHT-0004".into()),
            });
            return;
        }
        let probe = dir.join(format!(".grdr-preflight-{}", Uuid::now_v7().simple()));
        match fs::write(&probe, b"probe") {
            Ok(()) => {
                let _ = fs::remove_file(&probe);
                checks.push(PreflightCheck {
                    name: name.into(),
                    outcome: CheckOutcome::Pass,
                    detail: format!("Directory `{}` exists and is writable.", dir.display()),
                    code: None,
                });
            }
            Err(err) => checks.push(PreflightCheck {
                name: name.into(),
                outcome: CheckOutcome::Fail,
                detail: format!("Directory `{}` is not writable: {err}", dir.display()),
                code: Some("GRDR-PREFLIGHT-0004".into()),
            }),
        }
    } else {
        checks.push(PreflightCheck {
            name: name.into(),
            outcome: if warn_if_missing {
                CheckOutcome::Pass
            } else {
                CheckOutcome::Warn
            },
            detail: format!(
                "Directory `{}` does not exist yet and will be initialized on start.",
                dir.display()
            ),
            code: None,
        });
    }
}

fn probe_tcp(name: &str, endpoint: &str, err_code: &str, checks: &mut Vec<PreflightCheck>) {
    let timeout = Duration::from_millis(TCP_PROBE_TIMEOUT_MS);
    let resolved: Vec<SocketAddr> = match endpoint.to_socket_addrs() {
        Ok(addrs) => addrs.collect(),
        Err(err) => {
            checks.push(PreflightCheck {
                name: name.into(),
                outcome: CheckOutcome::Fail,
                detail: format!("Failed resolving endpoint `{endpoint}`: {err}"),
                code: Some(err_code.into()),
            });
            return;
        }
    };
    let connected = resolved
        .into_iter()
        .any(|addr| TcpStream::connect_timeout(&addr, timeout).is_ok());
    if connected {
        checks.push(PreflightCheck {
            name: name.into(),
            outcome: CheckOutcome::Pass,
            detail: format!("TCP endpoint `{endpoint}` is reachable."),
            code: None,
        });
    } else {
        checks.push(PreflightCheck {
            name: name.into(),
            outcome: CheckOutcome::Fail,
            detail: format!("TCP endpoint `{endpoint}` is unreachable."),
            code: Some(err_code.into()),
        });
    }
}

fn normalize_path_for_overlap(path: &Path) -> PathBuf {
    let abs = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let mut stack: Vec<Component<'_>> = Vec::new();
    for comp in abs.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(stack.last(), Some(Component::Normal(_))) {
                    stack.pop();
                } else {
                    stack.push(comp);
                }
            }
            other => stack.push(other),
        }
    }
    let clean: PathBuf = stack.into_iter().collect();
    let mut probe = clean.as_path();
    let mut tail = Vec::new();
    loop {
        if probe.exists()
            && let Ok(canon) = fs::canonicalize(probe)
        {
            let mut out = canon;
            for seg in tail.into_iter().rev() {
                out.push(seg);
            }
            return out;
        }
        let Some(name) = probe.file_name() else {
            return clean;
        };
        tail.push(name.to_os_string());
        let Some(parent) = probe.parent() else {
            return clean;
        };
        probe = parent;
    }
}

fn is_loopback_endpoint(hostport: &str) -> bool {
    let host = if let Some(inner) = hostport.strip_prefix('[') {
        inner.split_once(']').map(|(h, _)| h).unwrap_or(hostport)
    } else {
        hostport.split_once(':').map(|(h, _)| h).unwrap_or(hostport)
    };
    host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1"
}
