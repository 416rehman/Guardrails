// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use crate::limits_types::{LIMITS_SCHEMA_V1ALPHA1, LimitsError};

pub(crate) type SectionMap<'a> = BTreeMap<String, BTreeMap<String, (&'a str, usize)>>;

const ALLOWED_SECTIONS: &[(&str, &[&str])] = &[
    ("", &["schema"]),
    (
        "endpoint.memory_mb",
        &[
            "daemon",
            "engine",
            "uplink",
            "proxy",
            "tray",
            "console",
            "updater",
            "approve",
            "total_resident_target",
        ],
    ),
    ("endpoint.cpu_pct", &["idle_max"]),
    (
        "endpoint.disk_mb",
        &["total_cap", "spool_cap", "decision_reserve", "cache_cap"],
    ),
    (
        "endpoint.latency_ms",
        &[
            "hook_linux_p50",
            "hook_linux_p99",
            "hook_macos_p50",
            "hook_macos_p99",
            "hook_windows_p50",
            "hook_windows_p99",
            "shim_hang_max",
            "policy_1000_p99",
            "fastpath_cached_us",
            "fastpath_uncached_us",
            "proxy_added_p99",
            "proxy_first_byte_p99",
        ],
    ),
    (
        "endpoint.ipc",
        &[
            "max_frame_bytes",
            "connect_timeout_ms",
            "read_timeout_ms",
            "command_hold_max_ms",
        ],
    ),
    (
        "endpoint.prompts",
        &["median_per_dev_day", "p95_per_dev_day", "max_opaque_pct"],
    ),
    (
        "packs",
        &[
            "essentials_max_kb",
            "detections_max_mb",
            "intel_base_max_mb",
            "intel_daily_segment_max_kb",
            "max_pack_bundle_mb",
        ],
    ),
    (
        "uplink.schedule",
        &[
            "spine_interval_s",
            "spine_max_interval_s",
            "heartbeat_interval_s",
            "reconnect_spread_ms",
            "backfill_target_hours_low",
            "backfill_target_hours_high",
            "max_batch_bytes",
            "max_batch_events",
            "tuf_timestamp_stale_s",
            "stale_after_days",
            "kill_delivery_target_s",
            "kill_delivery_max_s",
            "policy_rollout_p99_s",
            "destructive_cmds_per_10m_max",
            "offline_renewal_days",
            "fleet_response_key_hours",
        ],
    ),
    (
        "retry.uplink_reconnect",
        &[
            "max_attempts",
            "initial_backoff_ms",
            "max_backoff_ms",
            "multiplier",
            "jitter",
        ],
    ),
    (
        "retry.ingest_flush",
        &[
            "max_attempts",
            "initial_backoff_ms",
            "max_backoff_ms",
            "multiplier",
            "jitter",
        ],
    ),
    (
        "retry.kms_unwrap",
        &[
            "max_attempts",
            "initial_backoff_ms",
            "max_backoff_ms",
            "multiplier",
            "jitter",
        ],
    ),
    (
        "retry.webhook_deliver",
        &[
            "max_attempts",
            "initial_backoff_ms",
            "max_backoff_ms",
            "multiplier",
            "jitter",
        ],
    ),
    (
        "server.ingest",
        &[
            "max_body_bytes",
            "max_skew_seconds",
            "ack_p99_ms",
            "detection_lag_p99_ms",
            "freshness_p99_s",
            "ha_endpoint_ceiling_5k",
            "ha_endpoint_ceiling_100k",
            "distributed_tls_conn_per_sec_per_cell",
        ],
    ),
    (
        "server.lake",
        &[
            "small_org_day_max_objects",
            "small_org_day_max_puts",
            "catalogue_commit_p99_ms",
            "catalogue_max_rows_per_file",
            "late_file_write_amp_max",
            "timeline_p95_s",
            "agg_30d_low_s",
            "agg_30d_high_s",
            "hunt_bg_threshold_gb",
            "wal_bytes_per_event_max",
            "archive_lag_p99_s",
        ],
    ),
    (
        "server.relational",
        &["transaction_life_ms", "set_transaction_life_ms"],
    ),
    (
        "server.tenancy",
        &[
            "confirm_interval_s",
            "copy_life_days",
            "pitr_window_days",
            "erasure_cancel_window_days",
            "payment_retry_days",
            "suspended_grace_days",
            "free_inactive_days",
            "structural_default_retention_days",
        ],
    ),
    (
        "server.preflight",
        &[
            "backup_max_age_hours",
            "wal_lag_max_minutes",
            "sqlite_backup_max_age_minutes",
            "restore_drill_warn_days",
            "restore_drill_fail_days",
            "cert_min_validity_days",
            "clock_skew_pg_fail_s",
            "clock_skew_http_warn_s",
            "clock_skew_http_fail_s",
            "disk_headroom_min_pct",
            "synthetic_alarm_max_age_days",
        ],
    ),
    (
        "server.enrolment",
        &[
            "default_rate_per_hour",
            "vdi_pool_rate_per_hour",
            "max_devices_default",
            "token_ttl_hours",
        ],
    ),
    (
        "server.operator",
        &[
            "settings_apply_timeout_s",
            "rto_relational_minutes",
            "rto_events_hours",
            "rollback_circuit_breaker_pct",
        ],
    ),
];

pub(crate) fn parse_sections(src: &str) -> Result<SectionMap<'_>, LimitsError> {
    let clean = src.strip_prefix('\u{feff}').unwrap_or(src);
    let mut map: SectionMap<'_> = BTreeMap::new();
    let mut current_section = String::new();
    for (idx, raw_line) in clean.lines().enumerate() {
        let line_no = idx.saturating_add(1);
        let stripped = strip_toml_comment(raw_line).trim();
        if stripped.is_empty() {
            continue;
        }
        if stripped.starts_with('[') {
            let inner = stripped
                .strip_prefix('[')
                .and_then(|s| s.strip_suffix(']'))
                .map(str::trim)
                .ok_or_else(|| LimitsError::Parse {
                    line: line_no,
                    message: "unclosed TOML section header".into(),
                })?;
            if inner.is_empty() || inner.contains('[') || inner.contains(']') {
                return Err(LimitsError::Parse {
                    line: line_no,
                    message: "invalid TOML section header".into(),
                });
            }
            if allowed_keys_for_section(inner).is_none() {
                return Err(LimitsError::Parse {
                    line: line_no,
                    message: format!("unknown limits section `[{inner}]`"),
                });
            }
            current_section = inner.to_string();
            map.entry(current_section.clone()).or_default();
            continue;
        }
        let Some((raw_k, raw_v)) = stripped.split_once('=') else {
            return Err(LimitsError::Parse {
                line: line_no,
                message: "expected `key = value`".into(),
            });
        };
        let key = raw_k.trim();
        let val = raw_v.trim();
        if key.is_empty() || val.is_empty() {
            return Err(LimitsError::Parse {
                line: line_no,
                message: "empty key or value".into(),
            });
        }
        let Some(allowed_keys) = allowed_keys_for_section(&current_section) else {
            return Err(LimitsError::Parse {
                line: line_no,
                message: format!("unknown limits section `[{current_section}]`"),
            });
        };
        if !allowed_keys.contains(&key) {
            return Err(LimitsError::Parse {
                line: line_no,
                message: format!("unknown key `{}`", full_key(&current_section, key)),
            });
        }
        let sec = map.entry(current_section.clone()).or_default();
        if sec.contains_key(key) {
            return Err(LimitsError::Parse {
                line: line_no,
                message: format!("duplicate key `{key}` in [{current_section}]"),
            });
        }
        sec.insert(key.to_string(), (val, line_no));
    }
    Ok(map)
}

fn allowed_keys_for_section(section: &str) -> Option<&'static [&'static str]> {
    ALLOWED_SECTIONS
        .iter()
        .find(|(sec, _)| *sec == section)
        .map(|(_, keys)| *keys)
}

pub(crate) fn strip_toml_comment(line: &str) -> &str {
    let mut in_double = false;
    let mut in_single = false;
    let mut escaped = false;
    for (idx, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_double => escaped = true,
            '"' if !in_single => in_double = !in_double,
            '\'' if !in_double => in_single = !in_single,
            '#' if !in_double && !in_single => return line.get(..idx).unwrap_or(line),
            _ => {}
        }
    }
    line
}

pub(crate) fn parse_schema_version(sections: &SectionMap<'_>) -> Result<String, LimitsError> {
    let schema = req_str(sections, "", "schema")?.to_string();
    if schema != LIMITS_SCHEMA_V1ALPHA1 {
        return Err(LimitsError::UnsupportedSchema { found: schema });
    }
    Ok(schema)
}

fn lookup<'a>(
    sections: &'a SectionMap<'a>,
    section: &str,
    key: &str,
) -> Result<(&'a str, usize), LimitsError> {
    let full = full_key(section, key);
    sections
        .get(section)
        .and_then(|s| s.get(key))
        .copied()
        .ok_or(LimitsError::MissingKey { key: full })
}

pub(crate) fn req_str<'a>(
    sections: &'a SectionMap<'a>,
    section: &str,
    key: &str,
) -> Result<&'a str, LimitsError> {
    let (raw, line_no) = lookup(sections, section, key)?;
    raw.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .or_else(|| raw.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
        .ok_or_else(|| LimitsError::Parse {
            line: line_no,
            message: format!("expected quoted string for `{}`", full_key(section, key)),
        })
}

pub(crate) fn req_u32(
    sections: &SectionMap<'_>,
    section: &str,
    key: &str,
) -> Result<u32, LimitsError> {
    let (raw, line_no) = lookup(sections, section, key)?;
    raw.replace('_', "")
        .parse::<u32>()
        .map_err(|_| LimitsError::Parse {
            line: line_no,
            message: format!("expected u32 for `{}`", full_key(section, key)),
        })
}

pub(crate) fn req_u64(
    sections: &SectionMap<'_>,
    section: &str,
    key: &str,
) -> Result<u64, LimitsError> {
    let (raw, line_no) = lookup(sections, section, key)?;
    raw.replace('_', "")
        .parse::<u64>()
        .map_err(|_| LimitsError::Parse {
            line: line_no,
            message: format!("expected u64 for `{}`", full_key(section, key)),
        })
}

pub(crate) fn req_usize(
    sections: &SectionMap<'_>,
    section: &str,
    key: &str,
) -> Result<usize, LimitsError> {
    let (raw, line_no) = lookup(sections, section, key)?;
    raw.replace('_', "")
        .parse::<usize>()
        .map_err(|_| LimitsError::Parse {
            line: line_no,
            message: format!("expected usize for `{}`", full_key(section, key)),
        })
}

pub(crate) fn req_f64(
    sections: &SectionMap<'_>,
    section: &str,
    key: &str,
) -> Result<f64, LimitsError> {
    let (raw, line_no) = lookup(sections, section, key)?;
    raw.replace('_', "")
        .parse::<f64>()
        .ok()
        .filter(|v| v.is_finite())
        .ok_or_else(|| LimitsError::Parse {
            line: line_no,
            message: format!("expected finite f64 for `{}`", full_key(section, key)),
        })
}

fn full_key(section: &str, key: &str) -> String {
    if section.is_empty() {
        key.to_string()
    } else {
        format!("{section}.{key}")
    }
}
