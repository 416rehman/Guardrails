// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Configuration-driven egress allow-list inspection (`grdr egress` and `grdr server egress`, `D-48`, `P16`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, ValueEnum};
use serde::{Deserialize, Serialize};

use crate::enrol::load_enrolment_summary;

pub const CODE_CFG_ISOLATED_EGRESS_REJECTED: &str = "GRDR-CFG-0020";

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    Standard,
    Isolated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressComponent {
    Endpoint,
    Server,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressPurpose {
    Uplink,
    Update,
    MirrorUpstream,
    ExportSink,
    Idp,
    Notify,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressDestination {
    pub destination: String,
    pub port: u16,
    pub purpose: EgressPurpose,
    pub config_key: String,
    pub component: EgressComponent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressReport {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub component: EgressComponent,
    pub network_mode: NetworkMode,
    pub isolated: bool,
    pub allow_patterns: Vec<String>,
    pub destinations: Vec<EgressDestination>,
}

#[derive(Debug, Clone)]
pub struct EgressEvalOptions {
    pub component: EgressComponent,
    pub network_mode: NetworkMode,
    pub state_dir: Option<PathBuf>,
    pub allow_patterns: Vec<String>,
    pub mirrors: Vec<String>,
    pub update_sources: Vec<String>,
    pub server_origin: Option<String>,
    pub export_sinks: Vec<String>,
    pub updates_enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum UpdatesPolicyArg {
    Enabled,
    Disabled,
}

#[derive(Debug, Clone, Args)]
pub struct EgressCliArgs {
    #[arg(long, value_enum, default_value_t = NetworkMode::Standard)]
    pub network_mode: NetworkMode,
    #[arg(long, default_value_t = false)]
    pub isolated: bool,
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    #[arg(long = "allow")]
    pub allow: Vec<String>,
    #[arg(long = "mirror")]
    pub mirrors: Vec<String>,
    #[arg(long = "update-source")]
    pub update_sources: Vec<String>,
    #[arg(long)]
    pub server: Option<String>,
    #[arg(long = "sink")]
    pub sinks: Vec<String>,
    #[arg(long, value_enum, default_value_t = UpdatesPolicyArg::Enabled)]
    pub updates: UpdatesPolicyArg,
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EgressError {
    #[error(
        "{CODE_CFG_ISOLATED_EGRESS_REJECTED}: configured destination `{destination}` ({config_key}) is outside isolated network.allow"
    )]
    OutsideIsolatedAllowList {
        destination: String,
        config_key: String,
    },
    #[error("GRDR-CFG-0021: malformed destination `{0}`")]
    MalformedDestination(String),
}

pub fn handle_egress_args(args: EgressCliArgs) -> ExitCode {
    let network_mode = if args.isolated {
        NetworkMode::Isolated
    } else {
        args.network_mode
    };
    run_egress_command(
        &EgressEvalOptions {
            component: EgressComponent::Endpoint,
            network_mode,
            state_dir: args.state_dir,
            allow_patterns: args.allow,
            mirrors: args.mirrors,
            update_sources: args.update_sources,
            server_origin: args.server,
            export_sinks: args.sinks,
            updates_enabled: args.updates == UpdatesPolicyArg::Enabled,
        },
        args.json,
    )
}

pub fn run_egress_command(opts: &EgressEvalOptions, json: bool) -> ExitCode {
    match evaluate_egress(opts) {
        Ok(report) => {
            if json {
                match serde_json::to_string_pretty(&report) {
                    Ok(rendered) => println!("{rendered}"),
                    Err(err) => {
                        eprintln!("Failed serializing egress allow-list: {err}");
                        return ExitCode::FAILURE;
                    }
                }
            } else {
                println!(
                    "Guardrails ADR {:?} egress (mode={:?}, allow_patterns={}, destinations={})",
                    report.component,
                    report.network_mode,
                    report.allow_patterns.len(),
                    report.destinations.len()
                );
                if report.destinations.is_empty() {
                    println!("  (no outbound destinations configured)");
                } else {
                    for entry in &report.destinations {
                        println!(
                            "  - {}:{} purpose={:?} key={} component={:?}",
                            entry.destination,
                            entry.port,
                            entry.purpose,
                            entry.config_key,
                            entry.component
                        );
                    }
                }
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            if json {
                let err_doc = serde_json::json!({
                    "apiVersion": "grdr.cli.v1alpha1",
                    "type": "egress.error",
                    "error_code": CODE_CFG_ISOLATED_EGRESS_REJECTED,
                    "message": err.to_string(),
                });
                println!("{err_doc}");
            } else {
                eprintln!("{err}");
            }
            ExitCode::FAILURE
        }
    }
}

pub fn evaluate_egress(opts: &EgressEvalOptions) -> Result<EgressReport, EgressError> {
    let mut allow_patterns: Vec<String> = opts
        .allow_patterns
        .iter()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect();
    allow_patterns.sort();
    allow_patterns.dedup();

    let mut destinations = Vec::new();
    let enrolled_server = opts
        .server_origin
        .clone()
        .or_else(|| load_enrolment_summary(opts.state_dir.as_deref()));

    if let Some(origin) = enrolled_server {
        let (host, port) = parse_endpoint_host_port(&origin)?;
        check_destination_allowed(
            opts.network_mode,
            &allow_patterns,
            &host,
            "enrolment.server_url",
        )?;
        destinations.push(EgressDestination {
            destination: host,
            port,
            purpose: EgressPurpose::Uplink,
            config_key: "enrolment.server_url".into(),
            component: opts.component,
        });
    }

    if opts.network_mode != NetworkMode::Isolated && opts.updates_enabled {
        for source in &opts.update_sources {
            let (host, port) = parse_endpoint_host_port(source)?;
            destinations.push(EgressDestination {
                destination: host,
                port,
                purpose: EgressPurpose::Update,
                config_key: "updates.sources".into(),
                component: opts.component,
            });
        }
    } else if opts.network_mode == NetworkMode::Isolated && !opts.update_sources.is_empty() {
        for source in &opts.update_sources {
            let (host, port) = parse_endpoint_host_port(source)?;
            check_destination_allowed(
                opts.network_mode,
                &allow_patterns,
                &host,
                "updates.sources",
            )?;
            destinations.push(EgressDestination {
                destination: host,
                port,
                purpose: EgressPurpose::Update,
                config_key: "updates.sources".into(),
                component: opts.component,
            });
        }
    }

    for mirror in &opts.mirrors {
        let (host, port) = parse_endpoint_host_port(mirror)?;
        check_destination_allowed(opts.network_mode, &allow_patterns, &host, "updates.mirrors")?;
        destinations.push(EgressDestination {
            destination: host,
            port,
            purpose: EgressPurpose::MirrorUpstream,
            config_key: "updates.mirrors".into(),
            component: opts.component,
        });
    }

    for sink in &opts.export_sinks {
        let (host, port) = parse_endpoint_host_port(sink)?;
        check_destination_allowed(opts.network_mode, &allow_patterns, &host, "export.sinks")?;
        destinations.push(EgressDestination {
            destination: host,
            port,
            purpose: EgressPurpose::ExportSink,
            config_key: "export.sinks".into(),
            component: opts.component,
        });
    }

    let kind = match opts.component {
        EgressComponent::Endpoint => "egress.allowlist".to_owned(),
        EgressComponent::Server => "server.egress.allowlist".to_owned(),
    };

    Ok(EgressReport {
        api_version: "grdr.cli.v1alpha1".into(),
        kind,
        component: opts.component,
        network_mode: opts.network_mode,
        isolated: opts.network_mode == NetworkMode::Isolated,
        allow_patterns,
        destinations,
    })
}

pub fn check_destination_allowed(
    mode: NetworkMode,
    allow_patterns: &[String],
    host: &str,
    config_key: &str,
) -> Result<(), EgressError> {
    if mode != NetworkMode::Isolated {
        return Ok(());
    }
    if host_matches_allow_patterns(host, allow_patterns) {
        return Ok(());
    }
    Err(EgressError::OutsideIsolatedAllowList {
        destination: host.to_owned(),
        config_key: config_key.to_owned(),
    })
}

pub fn parse_endpoint_host_port(raw: &str) -> Result<(String, u16), EgressError> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed
            .chars()
            .any(|c| c.is_ascii_control() || c.is_ascii_whitespace())
        || trimmed.contains('\\')
    {
        return Err(EgressError::MalformedDestination(raw.to_owned()));
    }

    let (default_port, after_scheme) = if let Some(rest) = trimmed.strip_prefix("https://") {
        (443_u16, rest)
    } else if let Some(rest) = trimmed.strip_prefix("http://") {
        (80_u16, rest)
    } else if trimmed.contains("://") {
        return Err(EgressError::MalformedDestination(raw.to_owned()));
    } else {
        (443_u16, trimmed)
    };

    let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') || authority.contains('%') {
        return Err(EgressError::MalformedDestination(raw.to_owned()));
    }

    if let Some(after_open) = authority.strip_prefix('[') {
        let Some((ip_part, rest)) = after_open.split_once(']') else {
            return Err(EgressError::MalformedDestination(raw.to_owned()));
        };
        let ip: Ipv6Addr = ip_part
            .parse()
            .map_err(|_| EgressError::MalformedDestination(raw.to_owned()))?;
        let port = parse_optional_port(rest, default_port)?;
        return Ok((ip.to_string(), port));
    }

    let (host, port) = if let Some((h, p_str)) = authority.rsplit_once(':') {
        let p = p_str
            .parse::<u16>()
            .map_err(|_| EgressError::MalformedDestination(raw.to_owned()))?;
        (h, p)
    } else {
        (authority, default_port)
    };

    let normalized = normalize_and_validate_host(host)
        .ok_or_else(|| EgressError::MalformedDestination(raw.to_owned()))?;
    Ok((normalized, port))
}

pub fn unwrap_embedded_ipv4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(v4) = v6.to_ipv4_mapped().or_else(|| v6.to_ipv4()) {
        return Some(v4);
    }
    let [s0, s1, s2, s3, s4, s5, s6, s7] = v6.segments();
    // NAT64 well-known prefix 64:ff9b::/96 -> embedded IPv4 in low 32 bits.
    if s0 == 0x0064 && s1 == 0xff9b && [s2, s3, s4, s5] == [0, 0, 0, 0] {
        let [a, b] = s6.to_be_bytes();
        let [c, d] = s7.to_be_bytes();
        return Some(Ipv4Addr::new(a, b, c, d));
    }
    // 6to4 2002::/16 -> embedded IPv4 in segments 1..=2.
    if s0 == 0x2002 {
        let [a, b] = s1.to_be_bytes();
        let [c, d] = s2.to_be_bytes();
        return Some(Ipv4Addr::new(a, b, c, d));
    }
    None
}

fn normalize_and_validate_host(raw_host: &str) -> Option<String> {
    let trimmed = raw_host.trim().trim_end_matches('.').to_ascii_lowercase();
    if trimmed.is_empty() || trimmed.contains(':') || trimmed.len() > 253 {
        return None;
    }
    if let Ok(ip) = trimmed.parse::<Ipv4Addr>() {
        return Some(ip.to_string());
    }
    if looks_like_non_canonical_ip_literal(&trimmed) {
        return None;
    }
    for label in trimmed.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return None;
        }
    }
    Some(trimmed)
}

fn looks_like_non_canonical_ip_literal(host: &str) -> bool {
    let labels: Vec<&str> = host.split('.').collect();
    if labels.is_empty() || labels.len() > 4 {
        return false;
    }
    let all_numeric_forms = labels.iter().all(|seg| {
        if let Some(hex) = seg.strip_prefix("0x") {
            !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit())
        } else {
            !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_digit())
        }
    });
    if all_numeric_forms {
        return true;
    }
    labels
        .last()
        .is_some_and(|tld| !tld.is_empty() && tld.bytes().all(|b| b.is_ascii_digit()))
}

fn parse_optional_port(rest: &str, default_port: u16) -> Result<u16, EgressError> {
    if rest.is_empty() {
        return Ok(default_port);
    }
    let Some(p_str) = rest.strip_prefix(':') else {
        return Err(EgressError::MalformedDestination(rest.to_owned()));
    };
    p_str
        .parse::<u16>()
        .map_err(|_| EgressError::MalformedDestination(rest.to_owned()))
}

fn host_matches_allow_patterns(host: &str, patterns: &[String]) -> bool {
    let norm_host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let is_valid_ip = norm_host.parse::<IpAddr>().is_ok();
    if !is_valid_ip && normalize_and_validate_host(&norm_host).is_none() {
        return false;
    }

    for raw_pat in patterns {
        let pat = raw_pat.trim().trim_end_matches('.').to_ascii_lowercase();
        if pat.is_empty() {
            continue;
        }
        if let Some((net_ip, prefix)) = parse_cidr(&pat)
            && let Ok(host_ip) = norm_host.parse::<IpAddr>()
            && ip_in_cidr(host_ip, net_ip, prefix)
        {
            return true;
        }
        if pat == norm_host {
            return true;
        }
        if let Some(suffix_body) = pat.strip_prefix("*.") {
            let dotted = format!(".{suffix_body}");
            if norm_host.ends_with(&dotted) {
                return true;
            }
        } else if pat.starts_with('.') && norm_host.ends_with(&pat) {
            return true;
        }
    }
    false
}

fn parse_cidr(raw: &str) -> Option<(IpAddr, u8)> {
    let (ip_str, mask_str) = raw.split_once('/')?;
    let ip: IpAddr = ip_str.parse().ok()?;
    let prefix: u8 = mask_str.parse().ok()?;
    let max_bits = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > max_bits {
        return None;
    }
    Some((ip, prefix))
}

fn ip_in_cidr(host: IpAddr, network: IpAddr, prefix: u8) -> bool {
    match (host, network) {
        (IpAddr::V4(h), IpAddr::V4(n)) => v4_in_cidr(h, n, prefix),
        (IpAddr::V6(h), IpAddr::V4(n)) => {
            unwrap_embedded_ipv4(h).is_some_and(|v4| v4_in_cidr(v4, n, prefix))
        }
        (IpAddr::V6(h), IpAddr::V6(n)) => {
            if prefix == 0 {
                return true;
            }
            let mask = u128::MAX
                .checked_shl(u32::from(128_u8.saturating_sub(prefix)))
                .unwrap_or(0);
            (ipv6_to_u128(h) & mask) == (ipv6_to_u128(n) & mask)
        }
        _ => false,
    }
}

fn v4_in_cidr(h: Ipv4Addr, n: Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let mask = u32::MAX
        .checked_shl(u32::from(32_u8.saturating_sub(prefix)))
        .unwrap_or(0);
    (ipv4_to_u32(h) & mask) == (ipv4_to_u32(n) & mask)
}

fn ipv4_to_u32(ip: Ipv4Addr) -> u32 {
    u32::from_be_bytes(ip.octets())
}

fn ipv6_to_u128(ip: Ipv6Addr) -> u128 {
    u128::from_be_bytes(ip.octets())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isolated_mode_drops_defaults_and_enforces_allow_list() {
        let missing_base = std::env::temp_dir().join(format!(
            "grdr-egress-test-{}-nonexistent",
            std::process::id()
        ));
        let isolated_empty = evaluate_egress(&EgressEvalOptions {
            component: EgressComponent::Endpoint,
            network_mode: NetworkMode::Isolated,
            state_dir: Some(missing_base.join("case-empty")),
            allow_patterns: vec![],
            mirrors: vec![],
            update_sources: vec![],
            server_origin: None,
            export_sinks: vec![],
            updates_enabled: true,
        })
        .unwrap();
        assert!(isolated_empty.destinations.is_empty());

        let rejected = evaluate_egress(&EgressEvalOptions {
            component: EgressComponent::Server,
            network_mode: NetworkMode::Isolated,
            state_dir: Some(missing_base.join("case-rejected")),
            allow_patterns: vec![".airgap.test".into()],
            mirrors: vec![],
            update_sources: vec![],
            server_origin: None,
            export_sinks: vec!["https://siem.outside.example/ingest".into()],
            updates_enabled: false,
        });
        assert!(matches!(
            rejected,
            Err(EgressError::OutsideIsolatedAllowList { .. })
        ));

        let allowed = evaluate_egress(&EgressEvalOptions {
            component: EgressComponent::Server,
            network_mode: NetworkMode::Isolated,
            state_dir: Some(missing_base.join("case-allowed")),
            allow_patterns: vec![".airgap.test".into(), "10.77.0.0/16".into()],
            mirrors: vec!["https://mirror.airgap.test:8443".into()],
            update_sources: vec![],
            server_origin: None,
            export_sinks: vec!["https://10.77.2.15:9000".into()],
            updates_enabled: false,
        })
        .unwrap();
        assert_eq!(allowed.destinations.len(), 2);
    }
}
