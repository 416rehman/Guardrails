// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

//! Unprivileged Guardrails fleet uplink binary (`grdr-uplink`).

use std::net::{IpAddr, ToSocketAddrs as _};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use grdr_os_clock::{Clock, SystemClock};
use tracing_subscriber::EnvFilter;

use grdr_uplink::allowlist::{AllowEntry, parse_https_target};
use grdr_uplink::dialer::{DialPurpose, DialTarget, Dialer, NetworkMode, ProxySelection};
use grdr_uplink::herd_sim::{HerdSimConfig, run_s23_suite};

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
}

fn main() -> ExitCode {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    if tracing_subscriber::fmt()
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
    }
}
