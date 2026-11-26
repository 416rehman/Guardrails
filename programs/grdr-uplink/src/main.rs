// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

//! Unprivileged Guardrails fleet uplink binary (`grdr-uplink`).

use std::collections::BTreeMap;
use std::net::{IpAddr, ToSocketAddrs as _};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use grdr_os_clock::{Clock, SystemClock};
use tracing_subscriber::EnvFilter;

use grdr_uplink::allowlist::{AllowEntry, parse_https_target};
use grdr_uplink::auth::FleetTrustAnchor;
use grdr_uplink::dialer::{DialPurpose, DialTarget, Dialer, NetworkMode, ProxySelection};
use grdr_uplink::herd_sim::{HerdSimConfig, run_s23_suite};
use grdr_uplink::worker::{UplinkWorkerConfig, run_stdio_daemon_worker_with_config};

#[derive(Debug, Parser)]
#[command(
    name = "grdr-uplink",
    version,
    about = "Guardrails ADR low-privilege fleet transport"
)]
struct Cli {
    #[command(subcommand)]
    command: UplinkCommand,
}

#[derive(Debug, Subcommand)]
enum UplinkCommand {
    /// Validate a target URL (plus resolved DNS/explicit IPs) against the Dialer egress policy.
    CheckEgress {
        #[arg(long)]
        uri: String,
        #[arg(long, default_value_t = false)]
        isolated: bool,
        #[arg(long = "allow")]
        allow_list: Vec<String>,
        #[arg(long = "resolved-ip")]
        resolved_ips: Vec<IpAddr>,
    },
    /// Execute the S-23 Fleet Herd Simulator across 1,000,000+ logical devices.
    HerdSim {
        #[arg(long, default_value_t = 1_000_000)]
        devices: usize,
        #[arg(long, default_value_t = 100)]
        cells: usize,
        #[arg(long, default_value_t = 1_200)]
        duration_secs: usize,
    },
    /// Verify clock, schedule defaults, and HTTP client assembly locally.
    SelfTest,
    /// Run supervised inherited-IPC worker loop attached to `grdr-daemon`.
    DaemonWorker {
        #[arg(long)]
        staging_root: PathBuf,
        #[arg(long)]
        device_id: Option<String>,
        #[arg(long, default_value_t = false)]
        isolated: bool,
        #[arg(long = "allow")]
        allow_list: Vec<String>,
        #[arg(long)]
        deployment_id: Option<String>,
        #[arg(long = "pinned-key")]
        pinned_keys: Vec<String>,
    },
}

fn main() -> ExitCode {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    if tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(filter)
        .try_init()
        .is_err()
    {
        tracing::debug!("tracing subscriber already initialized");
    }

    let cli = Cli::parse();
    match run_cli(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            tracing::error!("{msg}");
            ExitCode::FAILURE
        }
    }
}

fn run_cli(cli: Cli) -> Result<(), String> {
    let clock = SystemClock::new();
    let now_mono_ms = clock
        .boot_uptime()
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .map_err(|e| format!("clock failed: {e}"))?;

    match cli.command {
        UplinkCommand::CheckEgress {
            uri,
            isolated,
            allow_list,
            resolved_ips,
        } => {
            let parsed = parse_https_target(&uri).map_err(|e| e.to_string())?;
            let mode = if isolated {
                let mut entries = Vec::with_capacity(allow_list.len());
                for item in allow_list {
                    entries.push(AllowEntry::parse(&item).map_err(|e| e.to_string())?);
                }
                NetworkMode::Isolated {
                    allow_list: entries,
                }
            } else {
                NetworkMode::Standard
            };
            let dialer = Dialer::new(mode, ProxySelection::Direct);
            // Enforce Isolated allowlist BEFORE any DNS query leaks unlisted hostnames (P16).
            dialer
                .check_host_allowed(
                    &parsed.host,
                    "target destination not in isolated allow_list",
                )
                .map_err(|e| e.to_string())?;

            let resolved = if !resolved_ips.is_empty() || parsed.host_ip.is_some() {
                resolved_ips
            } else {
                let addr_str = format!("{}:{}", parsed.host, parsed.port);
                let addrs: Vec<IpAddr> = addr_str
                    .to_socket_addrs()
                    .map_err(|e| format!("DNS resolution failed for {addr_str}: {e}"))?
                    .map(|sock| sock.ip())
                    .collect();
                if addrs.is_empty() {
                    return Err(format!(
                        "DNS resolution returned zero addresses for {addr_str}"
                    ));
                }
                addrs
            };

            let target = DialTarget {
                uri,
                purpose: DialPurpose::FleetControl,
                resolved_ips: resolved,
            };
            let plan = dialer
                .authorize_dial(&target, None, now_mono_ms)
                .map_err(|e| e.to_string())?;
            let _client = dialer
                .build_http_client_for_plan(Some(&plan))
                .map_err(|e| e.to_string())?;
            tracing::info!(
                host = %plan.host,
                port = plan.port,
                rung = ?plan.rung,
                "egress target authorized"
            );
            Ok(())
        }
        UplinkCommand::HerdSim {
            devices,
            cells,
            duration_secs,
        } => {
            let cfg = HerdSimConfig {
                device_count: devices,
                cell_count: cells,
                duration_secs,
                ..HerdSimConfig::default()
            };
            let reports = run_s23_suite(&cfg).map_err(|e| e.to_string())?;
            for r in reports {
                tracing::info!(
                    scenario = ?r.scenario,
                    devices = r.device_count,
                    peak_tls_per_cell = r.peak_new_tls_per_sec_per_cell,
                    hb_ratio = r.peak_hb_ratio,
                    kill_10s = r.kill_reach_10s_ratio,
                    "s23 scenario passed"
                );
            }
            Ok(())
        }
        UplinkCommand::SelfTest => {
            let dialer = Dialer::new(NetworkMode::Standard, ProxySelection::Direct);
            let _client = dialer
                .build_http_client_for_plan(None)
                .map_err(|e| e.to_string())?;
            tracing::info!(uptime_ms = now_mono_ms, "grdr-uplink self-test passed");
            Ok(())
        }
        UplinkCommand::DaemonWorker {
            staging_root,
            device_id,
            isolated,
            allow_list,
            deployment_id,
            pinned_keys,
        } => {
            let network_mode = if isolated {
                let parsed = allow_list
                    .iter()
                    .map(|raw| AllowEntry::parse(raw))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| e.to_string())?;
                NetworkMode::Isolated { allow_list: parsed }
            } else {
                NetworkMode::Standard
            };
            let pinned_anchor = match deployment_id {
                Some(dep_id) => {
                    let mut keys = BTreeMap::new();
                    for item in pinned_keys {
                        let (kid, pk) = item.split_once('=').ok_or_else(|| {
                            "invalid --pinned-key format (expected id=b64)".to_string()
                        })?;
                        keys.insert(kid.to_string(), pk.to_string());
                    }
                    let anchor = FleetTrustAnchor {
                        deployment_id: dep_id,
                        fleet_public_keys: keys,
                    };
                    anchor.validate().map_err(|e| e.to_string())?;
                    Some(anchor)
                }
                None if !pinned_keys.is_empty() => {
                    return Err("--pinned-key requires --deployment-id".to_string());
                }
                None => None,
            };
            let resolved_device_id = match device_id {
                Some(id) if !id.trim().is_empty() => id,
                _ => format!("uplink-{}", uuid::Uuid::now_v7().simple()),
            };
            let config = UplinkWorkerConfig {
                device_id: resolved_device_id,
                network_mode,
                pinned_anchor,
            };
            run_stdio_daemon_worker_with_config(staging_root, config)
        }
    }
}
