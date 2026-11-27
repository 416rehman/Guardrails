// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use crate::limits_parse::validate_broker;
use crate::limits_types::{
    EndpointLimits, LIMITS_SCHEMA_V1ALPHA1, LimitsConfig, LimitsError, PackLimits, RetryLimits,
    ServerLimits, UplinkLimits,
};

pub fn validate_limits(cfg: &LimitsConfig) -> Result<(), LimitsError> {
    if cfg.schema != LIMITS_SCHEMA_V1ALPHA1 {
        return Err(LimitsError::UnsupportedSchema {
            found: cfg.schema.clone(),
        });
    }
    validate_endpoint(&cfg.endpoint)?;
    validate_packs(&cfg.packs)?;
    validate_uplink(&cfg.uplink)?;
    validate_retry(&cfg.retry)?;
    validate_server(&cfg.server)?;
    validate_broker(&cfg.broker)?;
    Ok(())
}

fn validate_endpoint(ep: &EndpointLimits) -> Result<(), LimitsError> {
    let mem = &ep.memory_mb;
    for (k, v) in [
        ("endpoint.memory_mb.daemon", mem.daemon),
        ("endpoint.memory_mb.engine", mem.engine),
        ("endpoint.memory_mb.uplink", mem.uplink),
        ("endpoint.memory_mb.proxy", mem.proxy),
        ("endpoint.memory_mb.tray", mem.tray),
        ("endpoint.memory_mb.console", mem.console),
        ("endpoint.memory_mb.updater", mem.updater),
        ("endpoint.memory_mb.approve", mem.approve),
        (
            "endpoint.memory_mb.total_resident_target",
            mem.total_resident_target,
        ),
        (
            "endpoint.latency_ms.shim_hang_max",
            ep.latency_ms.shim_hang_max,
        ),
        (
            "endpoint.latency_ms.policy_1000_p99",
            ep.latency_ms.policy_1000_p99,
        ),
        (
            "endpoint.latency_ms.proxy_added_p99",
            ep.latency_ms.proxy_added_p99,
        ),
        (
            "endpoint.latency_ms.proxy_first_byte_p99",
            ep.latency_ms.proxy_first_byte_p99,
        ),
    ] {
        ensure_positive_u64(k, u64::from(v))?;
    }
    if !(ep.cpu_pct.idle_max.is_finite()
        && ep.cpu_pct.idle_max > 0.0
        && ep.cpu_pct.idle_max <= 100.0)
    {
        return Err(bound_err(
            "endpoint.cpu_pct.idle_max",
            "must be in (0.0, 100.0]",
        ));
    }
    ensure_positive_u64(
        "endpoint.disk_mb.total_cap",
        u64::from(ep.disk_mb.total_cap),
    )?;
    for (k, v) in [
        ("endpoint.disk_mb.spool_cap", ep.disk_mb.spool_cap),
        (
            "endpoint.disk_mb.decision_reserve",
            ep.disk_mb.decision_reserve,
        ),
        ("endpoint.disk_mb.cache_cap", ep.disk_mb.cache_cap),
    ] {
        ensure_le(k, u64::from(v), u64::from(ep.disk_mb.total_cap))?;
    }
    for (k, low, high) in [
        (
            "endpoint.latency_ms.hook_linux_p50",
            ep.latency_ms.hook_linux_p50,
            ep.latency_ms.hook_linux_p99,
        ),
        (
            "endpoint.latency_ms.hook_macos_p50",
            ep.latency_ms.hook_macos_p50,
            ep.latency_ms.hook_macos_p99,
        ),
        (
            "endpoint.latency_ms.hook_windows_p50",
            ep.latency_ms.hook_windows_p50,
            ep.latency_ms.hook_windows_p99,
        ),
        (
            "endpoint.latency_ms.fastpath_cached_us",
            ep.latency_ms.fastpath_cached_us,
            ep.latency_ms.fastpath_uncached_us,
        ),
        (
            "endpoint.prompts.median_per_dev_day",
            ep.prompts.median_per_dev_day,
            ep.prompts.p95_per_dev_day,
        ),
    ] {
        ensure_le(k, u64::from(low), u64::from(high))?;
    }
    if ep.ipc.max_frame_bytes < 1024 || ep.ipc.max_frame_bytes > 64 * 1024 * 1024 {
        return Err(bound_err(
            "endpoint.ipc.max_frame_bytes",
            "must be in [1024, 67108864]",
        ));
    }
    ensure_positive_u64("endpoint.ipc.connect_timeout_ms", ep.ipc.connect_timeout_ms)?;
    ensure_positive_u64("endpoint.ipc.read_timeout_ms", ep.ipc.read_timeout_ms)?;
    ensure_positive_u64(
        "endpoint.ipc.command_hold_max_ms",
        ep.ipc.command_hold_max_ms,
    )?;
    for (k, v) in [
        (
            "endpoint.linux_sensor.catalogue_file_max_bytes",
            ep.linux_sensor.catalogue_file_max_bytes,
        ),
        (
            "endpoint.linux_sensor.seccheck_line_max_bytes",
            ep.linux_sensor.seccheck_line_max_bytes as u64,
        ),
        (
            "endpoint.linux_sensor.cri_field_max_bytes",
            ep.linux_sensor.cri_field_max_bytes as u64,
        ),
        (
            "endpoint.linux_sensor.cri_annotations_max",
            ep.linux_sensor.cri_annotations_max as u64,
        ),
        (
            "endpoint.linux_sensor.trampoline_cap",
            u64::from(ep.linux_sensor.trampoline_cap),
        ),
        (
            "endpoint.linux_sensor.trampoline_slots_enforce",
            u64::from(ep.linux_sensor.trampoline_slots_enforce),
        ),
        (
            "endpoint.sandbox.floor_pubkey_max_bytes",
            ep.sandbox.floor_pubkey_max_bytes as u64,
        ),
        (
            "endpoint.sandbox.seccomp_denied_rules_max",
            ep.sandbox.seccomp_denied_rules_max as u64,
        ),
        (
            "endpoint.sandbox.default_memory_limit_bytes",
            ep.sandbox.default_memory_limit_bytes,
        ),
        (
            "endpoint.sandbox.default_cgroup_pids_max",
            u64::from(ep.sandbox.default_cgroup_pids_max),
        ),
    ] {
        ensure_positive_u64(k, v)?;
    }
    ensure_le(
        "endpoint.linux_sensor.trampoline_slots_enforce",
        u64::from(ep.linux_sensor.trampoline_slots_enforce),
        u64::from(ep.linux_sensor.trampoline_cap),
    )?;
    if !(ep.prompts.max_opaque_pct.is_finite()
        && ep.prompts.max_opaque_pct >= 0.0
        && ep.prompts.max_opaque_pct <= 100.0)
    {
        return Err(bound_err(
            "endpoint.prompts.max_opaque_pct",
            "must be in [0.0, 100.0]",
        ));
    }
    Ok(())
}

fn validate_packs(p: &PackLimits) -> Result<(), LimitsError> {
    for (k, v) in [
        ("packs.essentials_max_kb", p.essentials_max_kb),
        ("packs.detections_max_mb", p.detections_max_mb),
        ("packs.intel_base_max_mb", p.intel_base_max_mb),
        (
            "packs.intel_daily_segment_max_kb",
            p.intel_daily_segment_max_kb,
        ),
        ("packs.max_pack_bundle_mb", p.max_pack_bundle_mb),
    ] {
        ensure_positive_u64(k, u64::from(v))?;
    }
    Ok(())
}

fn validate_uplink(u: &UplinkLimits) -> Result<(), LimitsError> {
    let s = &u.schedule;
    for (k, v) in [
        ("uplink.schedule.spine_interval_s", s.spine_interval_s),
        (
            "uplink.schedule.heartbeat_interval_s",
            s.heartbeat_interval_s,
        ),
        (
            "uplink.schedule.stale_after_days",
            u64::from(s.stale_after_days),
        ),
        (
            "uplink.schedule.destructive_cmds_per_10m_max",
            u64::from(s.destructive_cmds_per_10m_max),
        ),
        (
            "uplink.schedule.offline_renewal_days",
            u64::from(s.offline_renewal_days),
        ),
        (
            "uplink.schedule.fleet_response_key_hours",
            u64::from(s.fleet_response_key_hours),
        ),
    ] {
        ensure_positive_u64(k, v)?;
    }
    ensure_le(
        "uplink.schedule.spine_interval_s",
        s.spine_interval_s,
        s.spine_max_interval_s,
    )?;
    ensure_le(
        "uplink.schedule.backfill_target_hours_low",
        u64::from(s.backfill_target_hours_low),
        u64::from(s.backfill_target_hours_high),
    )?;
    ensure_le(
        "uplink.schedule.kill_delivery_target_s",
        s.kill_delivery_target_s,
        s.kill_delivery_max_s,
    )?;
    if s.max_batch_bytes == 0 || s.max_batch_events == 0 {
        return Err(bound_err(
            "uplink.schedule",
            "max_batch_bytes and max_batch_events must be > 0",
        ));
    }
    Ok(())
}

fn validate_retry(r: &RetryLimits) -> Result<(), LimitsError> {
    for (name, pol) in [
        ("retry.uplink_reconnect", &r.uplink_reconnect),
        ("retry.ingest_flush", &r.ingest_flush),
        ("retry.kms_unwrap", &r.kms_unwrap),
        ("retry.webhook_deliver", &r.webhook_deliver),
    ] {
        ensure_positive_u64(name, u64::from(pol.max_attempts))?;
        ensure_positive_u64(name, pol.initial_backoff_ms)?;
        ensure_le(name, pol.initial_backoff_ms, pol.max_backoff_ms)?;
        if !(pol.multiplier.is_finite() && pol.multiplier >= 1.0) {
            return Err(bound_err(name, "multiplier must be >= 1.0"));
        }
        if !(pol.jitter.is_finite() && pol.jitter >= 0.0 && pol.jitter <= 1.0) {
            return Err(bound_err(name, "jitter must be in [0.0, 1.0]"));
        }
    }
    Ok(())
}

fn validate_server(s: &ServerLimits) -> Result<(), LimitsError> {
    if s.ingest.max_body_bytes == 0 {
        return Err(bound_err("server.ingest.max_body_bytes", "must be > 0"));
    }
    for (k, v) in [
        ("server.ingest.max_skew_seconds", s.ingest.max_skew_seconds),
        (
            "server.relational.transaction_life_ms",
            s.relational.transaction_life_ms,
        ),
        (
            "server.relational.set_transaction_life_ms",
            s.relational.set_transaction_life_ms,
        ),
        (
            "server.tenancy.structural_default_retention_days",
            u64::from(s.tenancy.structural_default_retention_days),
        ),
        (
            "server.enrolment.max_devices_default",
            u64::from(s.enrolment.max_devices_default),
        ),
        (
            "server.enrolment.token_ttl_hours",
            u64::from(s.enrolment.token_ttl_hours),
        ),
    ] {
        ensure_positive_u64(k, v)?;
    }
    ensure_le(
        "server.lake.agg_30d_low_s",
        u64::from(s.lake.agg_30d_low_s),
        u64::from(s.lake.agg_30d_high_s),
    )?;
    if !(s.lake.late_file_write_amp_max.is_finite() && s.lake.late_file_write_amp_max >= 1.0) {
        return Err(bound_err(
            "server.lake.late_file_write_amp_max",
            "must be >= 1.0",
        ));
    }
    ensure_le(
        "server.preflight.restore_drill_warn_days",
        u64::from(s.preflight.restore_drill_warn_days),
        u64::from(s.preflight.restore_drill_fail_days),
    )?;
    ensure_le(
        "server.preflight.clock_skew_http_warn_s",
        s.preflight.clock_skew_http_warn_s,
        s.preflight.clock_skew_http_fail_s,
    )?;
    ensure_le(
        "server.preflight.disk_headroom_min_pct",
        u64::from(s.preflight.disk_headroom_min_pct),
        100,
    )?;
    ensure_le(
        "server.operator.rollback_circuit_breaker_pct",
        u64::from(s.operator.rollback_circuit_breaker_pct),
        100,
    )?;
    Ok(())
}

fn bound_err(key: &str, reason: &str) -> LimitsError {
    LimitsError::InvalidBound {
        key: key.to_string(),
        reason: reason.to_string(),
    }
}

fn ensure_positive_u64(key: &str, value: u64) -> Result<(), LimitsError> {
    if value == 0 {
        return Err(bound_err(key, "must be > 0"));
    }
    Ok(())
}

fn ensure_le(key: &str, low: u64, high: u64) -> Result<(), LimitsError> {
    if low > high {
        return Err(bound_err(key, &format!("{low} exceeds upper bound {high}")));
    }
    Ok(())
}
