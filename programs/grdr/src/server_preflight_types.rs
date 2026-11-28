// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;

const LIMITS_TOML: &str = include_str!("../../../contracts/limits.toml");
const TCP_PROBE_TIMEOUT_MS: u64 = 1_500;
pub const CODE_PG_DSN: &str = "GRDR-PREFLIGHT-0001";
pub const CODE_NATS_URL: &str = "GRDR-PREFLIGHT-0002";
pub const CODE_OBJECT_STORE: &str = "GRDR-PREFLIGHT-0003";
pub const CODE_STORAGE: &str = "GRDR-PREFLIGHT-0004";
pub const CODE_PG_TCP: &str = "GRDR-PREFLIGHT-0005";
pub const CODE_NATS_TCP: &str = "GRDR-PREFLIGHT-0006";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S3AddressingStyle {
    VirtualHosted,
    PathStyle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcomeKind {
    Pass,
    Warn,
    Fail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrCodeSlot {
    None,
    PgConfig,
    ObjectStore,
    Storage,
    PgTcp,
    NatsTcp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PgClockProbe {
    Skip,
    Enforce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskHeadroomProbe {
    Skip,
    Enforce,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightThresholds {
    pub pitr_window_days: u64,
    pub backup_max_age_hours: u64,
    pub sqlite_backup_max_age_minutes: u64,
    pub restore_drill_warn_days: u64,
    pub restore_drill_fail_days: u64,
    pub cert_min_validity_days: u64,
    pub clock_skew_pg_fail_s: u64,
    pub clock_skew_http_warn_s: u64,
    pub clock_skew_http_fail_s: u64,
    pub disk_headroom_min_pct: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawProbeResult {
    pub id: &'static str,
    pub name: &'static str,
    pub kind: ProbeOutcomeKind,
    pub err_slot: ErrCodeSlot,
    pub detail: String,
    pub remedy: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckOutcome {
    Pass,
    Warn,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PreflightCheck {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub name: String,
    pub outcome: CheckOutcome,
    pub detail: String,
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remedy: Option<String>,
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
    pub object_store_endpoint: Option<&'a str>,
    pub object_store_bucket: Option<&'a str>,
    pub backup_bucket: Option<&'a str>,
    pub object_store_addressing: S3AddressingStyle,
    pub cert_files: &'a [PathBuf],
    pub pg_clock_probe: PgClockProbe,
    pub disk_headroom_probe: DiskHeadroomProbe,
    pub restore_drill_marker: Option<&'a Path>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LimitsSection {
    Other,
    ServerTenancy,
    ServerPreflight,
}

impl Default for PreflightThresholds {
    fn default() -> Self {
        Self {
            pitr_window_days: 35,
            backup_max_age_hours: 24,
            sqlite_backup_max_age_minutes: 10,
            restore_drill_warn_days: 35,
            restore_drill_fail_days: 90,
            cert_min_validity_days: 14,
            clock_skew_pg_fail_s: 1,
            clock_skew_http_warn_s: 2,
            clock_skew_http_fail_s: 60,
            disk_headroom_min_pct: 30,
        }
    }
}

impl<'a> PreflightOptions<'a> {
    pub fn for_profile(profile: &'a str) -> Self {
        Self {
            profile,
            data_dir: None,
            backup_dir: None,
            postgres_dsn: None,
            nats_url: None,
            object_store_dir: None,
            object_store_endpoint: None,
            object_store_bucket: None,
            backup_bucket: None,
            object_store_addressing: S3AddressingStyle::VirtualHosted,
            cert_files: &[],
            pg_clock_probe: PgClockProbe::Skip,
            disk_headroom_probe: DiskHeadroomProbe::Skip,
            restore_drill_marker: None,
        }
    }
}

pub fn load_preflight_thresholds() -> Result<PreflightThresholds, String> {
    parse_preflight_thresholds_from(LIMITS_TOML)
}

pub fn parse_preflight_thresholds_from(toml_text: &str) -> Result<PreflightThresholds, String> {
    let mut cfg = PreflightThresholds::default();
    let mut section = LimitsSection::Other;
    let mut seen_pitr = false;
    let mut seen_bits = 0u16;

    for (line_idx, raw_line) in toml_text.lines().enumerate() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = match line {
                "[server.tenancy]" => LimitsSection::ServerTenancy,
                "[server.preflight]" => LimitsSection::ServerPreflight,
                _ => LimitsSection::Other,
            };
            continue;
        }
        if section == LimitsSection::Other {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            return Err(format!(
                "Malformed entry on limits.toml line {}.",
                line_idx.saturating_add(1)
            ));
        };
        let key = k.trim();
        let val_str = v.trim();
        let num = val_str.parse::<u64>().map_err(|e| {
            format!("Invalid integer for `{key}` in limits.toml (`{val_str}`): {e}")
        })?;
        match (section, key) {
            (LimitsSection::ServerTenancy, "pitr_window_days") => {
                cfg.pitr_window_days = num;
                seen_pitr = true;
            }
            (LimitsSection::ServerPreflight, "backup_max_age_hours") => {
                cfg.backup_max_age_hours = num;
                seen_bits |= 1 << 0;
            }
            (LimitsSection::ServerPreflight, "sqlite_backup_max_age_minutes") => {
                cfg.sqlite_backup_max_age_minutes = num;
                seen_bits |= 1 << 1;
            }
            (LimitsSection::ServerPreflight, "restore_drill_warn_days") => {
                cfg.restore_drill_warn_days = num;
                seen_bits |= 1 << 2;
            }
            (LimitsSection::ServerPreflight, "restore_drill_fail_days") => {
                cfg.restore_drill_fail_days = num;
                seen_bits |= 1 << 3;
            }
            (LimitsSection::ServerPreflight, "cert_min_validity_days") => {
                cfg.cert_min_validity_days = num;
                seen_bits |= 1 << 4;
            }
            (LimitsSection::ServerPreflight, "clock_skew_pg_fail_s") => {
                cfg.clock_skew_pg_fail_s = num;
                seen_bits |= 1 << 5;
            }
            (LimitsSection::ServerPreflight, "clock_skew_http_warn_s") => {
                cfg.clock_skew_http_warn_s = num;
                seen_bits |= 1 << 6;
            }
            (LimitsSection::ServerPreflight, "clock_skew_http_fail_s") => {
                cfg.clock_skew_http_fail_s = num;
                seen_bits |= 1 << 7;
            }
            (LimitsSection::ServerPreflight, "disk_headroom_min_pct") => {
                cfg.disk_headroom_min_pct = num;
                seen_bits |= 1 << 8;
            }
            _ => {}
        }
    }

    if !seen_pitr || seen_bits != ((1 << 9) - 1) {
        return Err("Missing required [server.tenancy]/[server.preflight] thresholds in contracts/limits.toml.".into());
    }
    if cfg.pitr_window_days == 0
        || cfg.backup_max_age_hours == 0
        || cfg.sqlite_backup_max_age_minutes == 0
        || cfg.cert_min_validity_days == 0
        || cfg.clock_skew_pg_fail_s == 0
        || cfg.clock_skew_http_warn_s == 0
        || cfg.disk_headroom_min_pct == 0
        || cfg.disk_headroom_min_pct > 100
        || cfg.restore_drill_warn_days > cfg.restore_drill_fail_days
        || cfg.clock_skew_http_warn_s > cfg.clock_skew_http_fail_s
    {
        return Err("Invalid threshold ordering or range in contracts/limits.toml.".into());
    }
    Ok(cfg)
}

pub fn current_unix_s() -> Result<i64, String> {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("Host clock precedes Unix epoch: {e}"))?;
    i64::try_from(dur.as_secs()).map_err(|_| "Host clock seconds exceed i64 range.".into())
}

pub fn parse_host_and_optional_port(
    raw: &str,
    require_port: bool,
) -> Result<(String, Option<u16>), String> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.chars().any(char::is_whitespace)
        || trimmed.contains('@')
        || trimmed.contains('?')
        || trimmed.contains('#')
        || trimmed.contains('/')
        || trimmed.contains('\\')
    {
        return Err("Endpoint authority contains forbidden characters or userinfo.".into());
    }
    if let Some(after_open) = trimmed.strip_prefix('[') {
        let Some((ip_str, rest)) = after_open.split_once(']') else {
            return Err("Unclosed bracketed IPv6 literal.".into());
        };
        let ip: IpAddr = ip_str
            .parse()
            .map_err(|_| "Invalid IPv6 address literal.".to_string())?;
        if !matches!(ip, IpAddr::V6(_)) {
            return Err("Bracketed literal must be an IPv6 address.".into());
        }
        if rest.is_empty() {
            if require_port {
                return Err("Missing TCP port after bracketed IPv6 host.".into());
            }
            return Ok((ip_str.to_string(), None));
        }
        let Some(port_str) = rest.strip_prefix(':') else {
            return Err("Unexpected trailing characters after bracketed IPv6 host.".into());
        };
        let port = port_str
            .parse::<u16>()
            .ok()
            .filter(|&p| p > 0)
            .ok_or_else(|| "Invalid TCP port.".to_string())?;
        return Ok((ip_str.to_string(), Some(port)));
    }

    if let Some((host, port_str)) = trimmed.split_once(':') {
        if host.is_empty() || port_str.contains(':') {
            return Err("Invalid host:port authority.".into());
        }
        let port = port_str
            .parse::<u16>()
            .ok()
            .filter(|&p| p > 0)
            .ok_or_else(|| "Invalid TCP port.".to_string())?;
        Ok((host.to_string(), Some(port)))
    } else {
        if require_port {
            return Err("Missing TCP port in endpoint.".into());
        }
        Ok((trimmed.to_string(), None))
    }
}

pub fn is_loopback_hostport(hostport: &str) -> bool {
    let Ok((host, _)) = parse_host_and_optional_port(hostport, false) else {
        return false;
    };
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

pub fn push_raw(raw: Vec<RawProbeResult>, checks: &mut Vec<PreflightCheck>) {
    for item in raw {
        checks.push(raw_to_check(item));
    }
}

pub fn mk_check(
    id: &str,
    name: &str,
    outcome: CheckOutcome,
    detail: String,
    code: Option<String>,
    remedy: Option<&str>,
) -> PreflightCheck {
    PreflightCheck {
        id: Some(id.to_string()),
        name: name.to_string(),
        outcome,
        detail,
        code,
        remedy: remedy.map(str::to_string),
    }
}

pub fn raw_to_check(item: RawProbeResult) -> PreflightCheck {
    let outcome = match item.kind {
        ProbeOutcomeKind::Pass => CheckOutcome::Pass,
        ProbeOutcomeKind::Warn => CheckOutcome::Warn,
        ProbeOutcomeKind::Fail => CheckOutcome::Fail,
    };
    let code = if matches!(outcome, CheckOutcome::Pass) {
        None
    } else {
        slot_to_code(item.err_slot).map(str::to_string)
    };
    PreflightCheck {
        id: Some(item.id.to_string()),
        name: item.name.to_string(),
        outcome,
        detail: item.detail,
        code,
        remedy: item.remedy.map(str::to_string),
    }
}

fn slot_to_code(slot: ErrCodeSlot) -> Option<&'static str> {
    match slot {
        ErrCodeSlot::None => None,
        ErrCodeSlot::PgConfig => Some(CODE_PG_DSN),
        ErrCodeSlot::ObjectStore => Some(CODE_OBJECT_STORE),
        ErrCodeSlot::Storage => Some(CODE_STORAGE),
        ErrCodeSlot::PgTcp => Some(CODE_PG_TCP),
        ErrCodeSlot::NatsTcp => Some(CODE_NATS_TCP),
    }
}

pub fn probe_tcp_reachability(
    name: &'static str,
    endpoint: &str,
    err_slot: ErrCodeSlot,
) -> RawProbeResult {
    let timeout = Duration::from_millis(TCP_PROBE_TIMEOUT_MS);
    let resolved: Vec<SocketAddr> = match endpoint.to_socket_addrs() {
        Ok(addrs) => addrs.collect(),
        Err(err) => {
            return RawProbeResult {
                id: "PF-03",
                name,
                kind: ProbeOutcomeKind::Fail,
                err_slot,
                detail: format!("Failed resolving endpoint `{endpoint}`: {err}"),
                remedy: None,
            };
        }
    };
    if resolved
        .into_iter()
        .any(|addr| TcpStream::connect_timeout(&addr, timeout).is_ok())
    {
        RawProbeResult {
            id: "PF-03",
            name,
            kind: ProbeOutcomeKind::Pass,
            err_slot: ErrCodeSlot::None,
            detail: format!("TCP endpoint `{endpoint}` is reachable."),
            remedy: None,
        }
    } else {
        RawProbeResult {
            id: "PF-03",
            name,
            kind: ProbeOutcomeKind::Fail,
            err_slot,
            detail: format!("TCP endpoint `{endpoint}` is unreachable."),
            remedy: None,
        }
    }
}

pub fn normalize_path_for_overlap(path: &Path) -> PathBuf {
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
            && let Ok(canon) = std::fs::canonicalize(probe)
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
