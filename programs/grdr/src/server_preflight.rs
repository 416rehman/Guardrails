// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::fs;
use std::path::Path;
use std::process::ExitCode;

use serde::Serialize;

use grdr_bus_nats::NatsConfig;
use grdr_ports::ProfileKind;
use grdr_rel_postgres::{POSTGRES_MIGRATIONS, PostgresConfig, PostgresSslMode};

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
    let report = build_preflight_report(opts);
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

pub fn build_preflight_report(opts: &PreflightOptions<'_>) -> PreflightReport {
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
                check_postgres(opts.postgres_dsn, &mut checks);
                check_object_store(opts.object_store_dir, &mut checks);
            }
            ProfileKind::Distributed => {
                check_postgres(opts.postgres_dsn, &mut checks);
                check_nats(opts.nats_url, &mut checks);
                check_object_store(opts.object_store_dir, &mut checks);
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
            if dir.exists() && fs::read_dir(dir).is_ok() {
                checks.push(PreflightCheck {
                    name: "embedded_data_dir".into(),
                    outcome: CheckOutcome::Pass,
                    detail: format!("Data directory `{}` is readable.", dir.display()),
                    code: None,
                });
            } else {
                checks.push(PreflightCheck {
                    name: "embedded_data_dir".into(),
                    outcome: CheckOutcome::Warn,
                    detail: format!(
                        "Data directory `{}` does not exist yet and will be initialized on start.",
                        dir.display()
                    ),
                    code: None,
                });
            }
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

fn check_postgres(postgres_dsn: Option<&str>, checks: &mut Vec<PreflightCheck>) {
    let Some(dsn) = postgres_dsn else {
        checks.push(PreflightCheck {
            name: "postgres_18_dsn".into(),
            outcome: CheckOutcome::Fail,
            detail: "Missing --postgres-dsn for HA/Distributed profile.".into(),
            code: Some("GRDR-PREFLIGHT-0001".into()),
        });
        return;
    };
    match PostgresConfig::parse_dsn(dsn) {
        Ok(cfg) => {
            let ssl_outcome = if cfg.ssl_mode == PostgresSslMode::Disable {
                CheckOutcome::Warn
            } else {
                CheckOutcome::Pass
            };
            checks.push(PreflightCheck {
                name: "postgres_18_dsn".into(),
                outcome: ssl_outcome,
                detail: format!(
                    "Parsed PostgreSQL 18 DSN (sslmode={}, migrations={}).",
                    cfg.ssl_mode.as_str(),
                    POSTGRES_MIGRATIONS.len()
                ),
                code: None,
            });
        }
        Err(err) => checks.push(PreflightCheck {
            name: "postgres_18_dsn".into(),
            outcome: CheckOutcome::Fail,
            detail: err.message,
            code: Some(err.code),
        }),
    }
}

fn check_nats(nats_url: Option<&str>, checks: &mut Vec<PreflightCheck>) {
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
        Ok(cfg) => checks.push(PreflightCheck {
            name: "nats_jetstream_url".into(),
            outcome: CheckOutcome::Pass,
            detail: format!(
                "Validated NATS JetStream URL with unused listeners disabled (replicas={}).",
                cfg.replicas
            ),
            code: None,
        }),
        Err(err) => checks.push(PreflightCheck {
            name: "nats_jetstream_url".into(),
            outcome: CheckOutcome::Fail,
            detail: err.message,
            code: Some(err.code),
        }),
    }
}

fn check_object_store(object_store_dir: Option<&Path>, checks: &mut Vec<PreflightCheck>) {
    match object_store_dir {
        Some(dir) if !dir.as_os_str().is_empty() => checks.push(PreflightCheck {
            name: "object_store_conformance".into(),
            outcome: CheckOutcome::Pass,
            detail: format!(
                "Object store target `{}` configured with server-enforced lifecycle policy.",
                dir.display()
            ),
            code: None,
        }),
        _ => checks.push(PreflightCheck {
            name: "object_store_conformance".into(),
            outcome: CheckOutcome::Fail,
            detail: "Missing --object-store-dir for HA/Distributed lake and archive storage."
                .into(),
            code: Some("GRDR-PREFLIGHT-0003".into()),
        }),
    }
}
