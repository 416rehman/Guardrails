// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::sync::OnceLock;

const LIMITS_TOML: &str = include_str!("../../../../contracts/limits.toml");

#[derive(Debug, Clone, Copy)]
pub struct RestLimits {
    pub max_idempotent_body_bytes: usize,
    pub idempotency_ttl_secs: i64,
    pub rate_limit_window_secs: i64,
    pub rate_limit_default_per_min: u32,
    pub max_cache_entries: usize,
    pub webhook_timeout_ms: u64,
    pub mcp_read_limit_per_min: u32,
    pub mcp_propose_limit_per_hour: u32,
    pub mcp_propose_window_secs: i64,
    pub max_store_items: usize,
}

static LIMITS_CACHE: OnceLock<RestLimits> = OnceLock::new();

pub fn rest_limits() -> &'static RestLimits {
    LIMITS_CACHE.get_or_init(|| parse_rest_limits(LIMITS_TOML))
}

fn parse_rest_limits(raw: &str) -> RestLimits {
    let max_frame_bytes = toml_u64(raw, "endpoint.ipc", "max_frame_bytes")
        .and_then(|v| usize::try_from(v).ok())
        .unwrap_or(1_048_576);
    let fleet_key_hours = toml_u64(raw, "uplink.schedule", "fleet_response_key_hours")
        .and_then(|v| i64::try_from(v).ok())
        .unwrap_or(24);
    let freshness_secs = toml_u64(raw, "server.ingest", "freshness_p99_s")
        .and_then(|v| i64::try_from(v).ok())
        .unwrap_or(60);
    let max_outcomes = toml_u64(raw, "broker.circuit_breaker", "max_outcomes")
        .and_then(|v| usize::try_from(v).ok())
        .unwrap_or(4096);
    let webhook_timeout_ms = toml_u64(raw, "server.ingest", "detection_lag_p99_ms").unwrap_or(5000);
    let max_store_items = toml_u64(raw, "server.enrolment", "max_devices_default")
        .and_then(|v| usize::try_from(v).ok())
        .unwrap_or(10_000);
    let rate_limit_default_per_min = toml_u64(raw, "server.rest", "rate_limit_default_per_min")
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(120);
    let mcp_read_limit_per_min = toml_u64(raw, "server.mcp", "read_limit_per_min")
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(60);
    let mcp_propose_limit_per_hour = toml_u64(raw, "server.mcp", "propose_limit_per_hour")
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(10);
    let mcp_propose_window_secs = toml_u64(raw, "server.mcp", "propose_window_secs")
        .and_then(|v| i64::try_from(v).ok())
        .unwrap_or(3600);

    RestLimits {
        max_idempotent_body_bytes: max_frame_bytes,
        idempotency_ttl_secs: fleet_key_hours.saturating_mul(3600),
        rate_limit_window_secs: freshness_secs,
        rate_limit_default_per_min,
        max_cache_entries: max_outcomes,
        webhook_timeout_ms,
        mcp_read_limit_per_min,
        mcp_propose_limit_per_hour,
        mcp_propose_window_secs,
        max_store_items,
    }
}

fn toml_u64(raw: &str, section: &str, key: &str) -> Option<u64> {
    let mut current_section = String::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(inner) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            current_section = inner.trim().to_owned();
            continue;
        }
        if current_section == section
            && let Some((lhs, rhs)) = trimmed.split_once('=')
            && lhs.trim() == key
        {
            let clean = rhs.split('#').next().unwrap_or("").trim();
            return clean.parse::<u64>().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rest_limits_load_server_rest_and_mcp_from_contracts_toml() {
        let lim = rest_limits();
        assert_eq!(lim.rate_limit_default_per_min, 120);
        assert_eq!(lim.mcp_read_limit_per_min, 60);
        assert_eq!(lim.mcp_propose_limit_per_hour, 10);
        assert_eq!(lim.mcp_propose_window_secs, 3600);
    }
}
