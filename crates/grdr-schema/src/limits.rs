// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use crate::limits_parse::{
    SectionMap, parse_schema_version, parse_sections, req_f64, req_u16, req_u32, req_u64, req_usize,
};
pub use crate::limits_types::*;
pub use crate::limits_validate::validate_limits;

pub const EMBEDDED_LIMITS_TOML: &str = include_str!("../../../contracts/limits.toml");

pub fn load_embedded_limits() -> Result<LimitsConfig, LimitsError> {
    parse_limits_toml(EMBEDDED_LIMITS_TOML)
}

pub fn parse_limits_toml(src: &str) -> Result<LimitsConfig, LimitsError> {
    let sections = parse_sections(src)?;
    let schema = parse_schema_version(&sections)?;
    let cfg = LimitsConfig {
        schema,
        endpoint: parse_endpoint(&sections)?,
        packs: parse_packs(&sections)?,
        uplink: parse_uplink(&sections)?,
        retry: parse_retry(&sections)?,
        server: parse_server(&sections)?,
    };
    validate_limits(&cfg)?;
    Ok(cfg)
}

fn parse_endpoint(sections: &SectionMap<'_>) -> Result<EndpointLimits, LimitsError> {
    let (m, d, l, i, p, ls, sb) = (
        "endpoint.memory_mb",
        "endpoint.disk_mb",
        "endpoint.latency_ms",
        "endpoint.ipc",
        "endpoint.prompts",
        "endpoint.linux_sensor",
        "endpoint.sandbox",
    );
    Ok(EndpointLimits {
        memory_mb: EndpointMemoryMb {
            daemon: req_u32(sections, m, "daemon")?,
            engine: req_u32(sections, m, "engine")?,
            uplink: req_u32(sections, m, "uplink")?,
            proxy: req_u32(sections, m, "proxy")?,
            tray: req_u32(sections, m, "tray")?,
            console: req_u32(sections, m, "console")?,
            updater: req_u32(sections, m, "updater")?,
            approve: req_u32(sections, m, "approve")?,
            total_resident_target: req_u32(sections, m, "total_resident_target")?,
        },
        cpu_pct: EndpointCpuPct {
            idle_max: req_f64(sections, "endpoint.cpu_pct", "idle_max")?,
        },
        disk_mb: EndpointDiskMb {
            total_cap: req_u32(sections, d, "total_cap")?,
            spool_cap: req_u32(sections, d, "spool_cap")?,
            decision_reserve: req_u32(sections, d, "decision_reserve")?,
            cache_cap: req_u32(sections, d, "cache_cap")?,
        },
        latency_ms: EndpointLatencyMs {
            hook_linux_p50: req_u32(sections, l, "hook_linux_p50")?,
            hook_linux_p99: req_u32(sections, l, "hook_linux_p99")?,
            hook_macos_p50: req_u32(sections, l, "hook_macos_p50")?,
            hook_macos_p99: req_u32(sections, l, "hook_macos_p99")?,
            hook_windows_p50: req_u32(sections, l, "hook_windows_p50")?,
            hook_windows_p99: req_u32(sections, l, "hook_windows_p99")?,
            shim_hang_max: req_u32(sections, l, "shim_hang_max")?,
            policy_1000_p99: req_u32(sections, l, "policy_1000_p99")?,
            fastpath_cached_us: req_u32(sections, l, "fastpath_cached_us")?,
            fastpath_uncached_us: req_u32(sections, l, "fastpath_uncached_us")?,
            proxy_added_p99: req_u32(sections, l, "proxy_added_p99")?,
            proxy_first_byte_p99: req_u32(sections, l, "proxy_first_byte_p99")?,
        },
        ipc: EndpointIpcLimits {
            max_frame_bytes: req_usize(sections, i, "max_frame_bytes")?,
            connect_timeout_ms: req_u64(sections, i, "connect_timeout_ms")?,
            read_timeout_ms: req_u64(sections, i, "read_timeout_ms")?,
            command_hold_max_ms: req_u64(sections, i, "command_hold_max_ms")?,
        },
        prompts: EndpointPromptLimits {
            median_per_dev_day: req_u32(sections, p, "median_per_dev_day")?,
            p95_per_dev_day: req_u32(sections, p, "p95_per_dev_day")?,
            max_opaque_pct: req_f64(sections, p, "max_opaque_pct")?,
        },
        linux_sensor: EndpointLinuxSensorLimits {
            catalogue_file_max_bytes: req_u64(sections, ls, "catalogue_file_max_bytes")?,
            seccheck_line_max_bytes: req_usize(sections, ls, "seccheck_line_max_bytes")?,
            cri_field_max_bytes: req_usize(sections, ls, "cri_field_max_bytes")?,
            cri_annotations_max: req_usize(sections, ls, "cri_annotations_max")?,
            trampoline_cap: req_u16(sections, ls, "trampoline_cap")?,
            trampoline_slots_enforce: req_u16(sections, ls, "trampoline_slots_enforce")?,
        },
        sandbox: EndpointSandboxLimits {
            floor_pubkey_max_bytes: req_usize(sections, sb, "floor_pubkey_max_bytes")?,
            seccomp_denied_rules_max: req_usize(sections, sb, "seccomp_denied_rules_max")?,
            default_memory_limit_bytes: req_u64(sections, sb, "default_memory_limit_bytes")?,
            default_cgroup_pids_max: req_u32(sections, sb, "default_cgroup_pids_max")?,
        },
    })
}

fn parse_packs(sections: &SectionMap<'_>) -> Result<PackLimits, LimitsError> {
    let s = "packs";
    Ok(PackLimits {
        essentials_max_kb: req_u32(sections, s, "essentials_max_kb")?,
        detections_max_mb: req_u32(sections, s, "detections_max_mb")?,
        intel_base_max_mb: req_u32(sections, s, "intel_base_max_mb")?,
        intel_daily_segment_max_kb: req_u32(sections, s, "intel_daily_segment_max_kb")?,
        max_pack_bundle_mb: req_u32(sections, s, "max_pack_bundle_mb")?,
    })
}

fn parse_uplink(sections: &SectionMap<'_>) -> Result<UplinkLimits, LimitsError> {
    let s = "uplink.schedule";
    Ok(UplinkLimits {
        schedule: UplinkScheduleLimits {
            spine_interval_s: req_u64(sections, s, "spine_interval_s")?,
            spine_max_interval_s: req_u64(sections, s, "spine_max_interval_s")?,
            heartbeat_interval_s: req_u64(sections, s, "heartbeat_interval_s")?,
            reconnect_spread_ms: req_u64(sections, s, "reconnect_spread_ms")?,
            backfill_target_hours_low: req_u32(sections, s, "backfill_target_hours_low")?,
            backfill_target_hours_high: req_u32(sections, s, "backfill_target_hours_high")?,
            max_batch_bytes: req_usize(sections, s, "max_batch_bytes")?,
            max_batch_events: req_usize(sections, s, "max_batch_events")?,
            tuf_timestamp_stale_s: req_u64(sections, s, "tuf_timestamp_stale_s")?,
            stale_after_days: req_u32(sections, s, "stale_after_days")?,
            kill_delivery_target_s: req_u64(sections, s, "kill_delivery_target_s")?,
            kill_delivery_max_s: req_u64(sections, s, "kill_delivery_max_s")?,
            policy_rollout_p99_s: req_u64(sections, s, "policy_rollout_p99_s")?,
            destructive_cmds_per_10m_max: req_u32(sections, s, "destructive_cmds_per_10m_max")?,
            offline_renewal_days: req_u32(sections, s, "offline_renewal_days")?,
            fleet_response_key_hours: req_u32(sections, s, "fleet_response_key_hours")?,
        },
    })
}

fn parse_retry_policy(sections: &SectionMap<'_>, sec: &str) -> Result<RetryPolicy, LimitsError> {
    Ok(RetryPolicy {
        max_attempts: req_u32(sections, sec, "max_attempts")?,
        initial_backoff_ms: req_u64(sections, sec, "initial_backoff_ms")?,
        max_backoff_ms: req_u64(sections, sec, "max_backoff_ms")?,
        multiplier: req_f64(sections, sec, "multiplier")?,
        jitter: req_f64(sections, sec, "jitter")?,
    })
}

fn parse_retry(sections: &SectionMap<'_>) -> Result<RetryLimits, LimitsError> {
    Ok(RetryLimits {
        uplink_reconnect: parse_retry_policy(sections, "retry.uplink_reconnect")?,
        ingest_flush: parse_retry_policy(sections, "retry.ingest_flush")?,
        kms_unwrap: parse_retry_policy(sections, "retry.kms_unwrap")?,
        webhook_deliver: parse_retry_policy(sections, "retry.webhook_deliver")?,
    })
}

fn parse_server(sections: &SectionMap<'_>) -> Result<ServerLimits, LimitsError> {
    let (i, l, r, t, p, e, o) = (
        "server.ingest",
        "server.lake",
        "server.relational",
        "server.tenancy",
        "server.preflight",
        "server.enrolment",
        "server.operator",
    );
    Ok(ServerLimits {
        ingest: ServerIngestLimits {
            max_body_bytes: req_usize(sections, i, "max_body_bytes")?,
            max_skew_seconds: req_u64(sections, i, "max_skew_seconds")?,
            ack_p99_ms: req_u32(sections, i, "ack_p99_ms")?,
            detection_lag_p99_ms: req_u32(sections, i, "detection_lag_p99_ms")?,
            freshness_p99_s: req_u32(sections, i, "freshness_p99_s")?,
            ha_endpoint_ceiling_5k: req_u32(sections, i, "ha_endpoint_ceiling_5k")?,
            ha_endpoint_ceiling_100k: req_u32(sections, i, "ha_endpoint_ceiling_100k")?,
            distributed_tls_conn_per_sec_per_cell: req_u32(
                sections,
                i,
                "distributed_tls_conn_per_sec_per_cell",
            )?,
        },
        lake: ServerLakeLimits {
            small_org_day_max_objects: req_u32(sections, l, "small_org_day_max_objects")?,
            small_org_day_max_puts: req_u32(sections, l, "small_org_day_max_puts")?,
            catalogue_commit_p99_ms: req_u32(sections, l, "catalogue_commit_p99_ms")?,
            catalogue_max_rows_per_file: req_u32(sections, l, "catalogue_max_rows_per_file")?,
            late_file_write_amp_max: req_f64(sections, l, "late_file_write_amp_max")?,
            timeline_p95_s: req_u32(sections, l, "timeline_p95_s")?,
            agg_30d_low_s: req_u32(sections, l, "agg_30d_low_s")?,
            agg_30d_high_s: req_u32(sections, l, "agg_30d_high_s")?,
            hunt_bg_threshold_gb: req_u32(sections, l, "hunt_bg_threshold_gb")?,
            wal_bytes_per_event_max: req_u32(sections, l, "wal_bytes_per_event_max")?,
            archive_lag_p99_s: req_u32(sections, l, "archive_lag_p99_s")?,
        },
        relational: ServerRelationalLimits {
            transaction_life_ms: req_u64(sections, r, "transaction_life_ms")?,
            set_transaction_life_ms: req_u64(sections, r, "set_transaction_life_ms")?,
        },
        tenancy: ServerTenancyLimits {
            confirm_interval_s: req_u64(sections, t, "confirm_interval_s")?,
            copy_life_days: req_u32(sections, t, "copy_life_days")?,
            pitr_window_days: req_u32(sections, t, "pitr_window_days")?,
            erasure_cancel_window_days: req_u32(sections, t, "erasure_cancel_window_days")?,
            payment_retry_days: req_u32(sections, t, "payment_retry_days")?,
            suspended_grace_days: req_u32(sections, t, "suspended_grace_days")?,
            free_inactive_days: req_u32(sections, t, "free_inactive_days")?,
            structural_default_retention_days: req_u32(
                sections,
                t,
                "structural_default_retention_days",
            )?,
        },
        preflight: ServerPreflightLimits {
            backup_max_age_hours: req_u32(sections, p, "backup_max_age_hours")?,
            wal_lag_max_minutes: req_u32(sections, p, "wal_lag_max_minutes")?,
            sqlite_backup_max_age_minutes: req_u32(sections, p, "sqlite_backup_max_age_minutes")?,
            restore_drill_warn_days: req_u32(sections, p, "restore_drill_warn_days")?,
            restore_drill_fail_days: req_u32(sections, p, "restore_drill_fail_days")?,
            cert_min_validity_days: req_u32(sections, p, "cert_min_validity_days")?,
            clock_skew_pg_fail_s: req_u64(sections, p, "clock_skew_pg_fail_s")?,
            clock_skew_http_warn_s: req_u64(sections, p, "clock_skew_http_warn_s")?,
            clock_skew_http_fail_s: req_u64(sections, p, "clock_skew_http_fail_s")?,
            disk_headroom_min_pct: req_u32(sections, p, "disk_headroom_min_pct")?,
            synthetic_alarm_max_age_days: req_u32(sections, p, "synthetic_alarm_max_age_days")?,
        },
        enrolment: ServerEnrolmentLimits {
            default_rate_per_hour: req_u32(sections, e, "default_rate_per_hour")?,
            vdi_pool_rate_per_hour: req_u32(sections, e, "vdi_pool_rate_per_hour")?,
            max_devices_default: req_u32(sections, e, "max_devices_default")?,
            token_ttl_hours: req_u32(sections, e, "token_ttl_hours")?,
        },
        operator: ServerOperatorLimits {
            settings_apply_timeout_s: req_u64(sections, o, "settings_apply_timeout_s")?,
            rto_relational_minutes: req_u32(sections, o, "rto_relational_minutes")?,
            rto_events_hours: req_u32(sections, o, "rto_events_hours")?,
            rollback_circuit_breaker_pct: req_u32(sections, o, "rollback_circuit_breaker_pct")?,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_limits_toml_parses_and_validates() {
        let cfg = load_embedded_limits().expect("contracts/limits.toml must parse cleanly");
        assert_eq!(cfg.schema, LIMITS_SCHEMA_V1ALPHA1);
        assert_eq!(cfg.endpoint.memory_mb.daemon, 40);
        assert_eq!(cfg.endpoint.ipc.max_frame_bytes, 1_048_576);
        assert_eq!(cfg.packs.max_pack_bundle_mb, 32);
        assert_eq!(cfg.uplink.schedule.max_batch_bytes, 262_144);
        assert_eq!(cfg.retry.uplink_reconnect.max_attempts, 16);
        assert_eq!(cfg.server.ingest.max_body_bytes, 10_485_760);
        assert_eq!(cfg.server.operator.rollback_circuit_breaker_pct, 15);
        assert_eq!(
            cfg.endpoint.linux_sensor.catalogue_file_max_bytes,
            1_048_576
        );
        assert_eq!(cfg.endpoint.linux_sensor.trampoline_cap, 36);
        assert_eq!(cfg.endpoint.sandbox.floor_pubkey_max_bytes, 512);
        assert_eq!(cfg.endpoint.sandbox.default_cgroup_pids_max, 256);
    }

    #[test]
    fn rejects_wrong_schema_and_inverted_bounds() {
        let wrong_schema = EMBEDDED_LIMITS_TOML.replace(LIMITS_SCHEMA_V1ALPHA1, "grdr.limits.v99");
        assert!(matches!(
            parse_limits_toml(&wrong_schema),
            Err(LimitsError::UnsupportedSchema { .. })
        ));

        let inverted = EMBEDDED_LIMITS_TOML.replace("agg_30d_low_s = 10", "agg_30d_low_s = 999");
        assert!(matches!(
            parse_limits_toml(&inverted),
            Err(LimitsError::InvalidBound { .. })
        ));
    }

    #[test]
    fn rejects_missing_required_key_unknown_section_and_unknown_key() {
        let missing = EMBEDDED_LIMITS_TOML.replace("token_ttl_hours = 24", "");
        assert!(matches!(
            parse_limits_toml(&missing),
            Err(LimitsError::MissingKey { .. })
        ));

        let unknown_sec = format!("{EMBEDDED_LIMITS_TOML}\n[evil.section]\nx = 1\n");
        assert!(matches!(
            parse_limits_toml(&unknown_sec),
            Err(LimitsError::Parse { .. })
        ));

        let unknown_key = format!("{EMBEDDED_LIMITS_TOML}\nsneaky = 1\n");
        assert!(matches!(
            parse_limits_toml(&unknown_key),
            Err(LimitsError::Parse { .. })
        ));
    }

    #[test]
    fn single_quoted_schema_with_hash_parses_and_zero_bounds_fail() {
        let single_q = EMBEDDED_LIMITS_TOML.replace(
            "schema = \"grdr.limits.v1alpha1\"",
            "schema = 'grdr.limits.v1alpha1'",
        );
        assert!(parse_limits_toml(&single_q).is_ok());

        let hash_in_sq = EMBEDDED_LIMITS_TOML
            .replace("schema = \"grdr.limits.v1alpha1\"", "schema = 'v1#alpha'");
        assert!(matches!(
            parse_limits_toml(&hash_in_sq),
            Err(LimitsError::UnsupportedSchema { .. })
        ));

        for (needle, zeroed) in [
            ("policy_1000_p99 = 1", "policy_1000_p99 = 0"),
            ("stale_after_days = 14", "stale_after_days = 0"),
            (
                "destructive_cmds_per_10m_max = 3",
                "destructive_cmds_per_10m_max = 0",
            ),
            (
                "fleet_response_key_hours = 24",
                "fleet_response_key_hours = 0",
            ),
            ("max_devices_default = 10000", "max_devices_default = 0"),
        ] {
            let bad = EMBEDDED_LIMITS_TOML.replace(needle, zeroed);
            assert!(
                matches!(
                    parse_limits_toml(&bad),
                    Err(LimitsError::InvalidBound { .. })
                ),
                "expected InvalidBound for {zeroed}"
            );
        }
    }
}
