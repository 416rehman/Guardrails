// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use serde::{Deserialize, Serialize};

pub const LIMITS_SCHEMA_V1ALPHA1: &str = "grdr.limits.v1alpha1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LimitsConfig {
    pub schema: String,
    pub endpoint: EndpointLimits,
    pub packs: PackLimits,
    pub uplink: UplinkLimits,
    pub retry: RetryLimits,
    pub server: ServerLimits,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EndpointLimits {
    pub memory_mb: EndpointMemoryMb,
    pub cpu_pct: EndpointCpuPct,
    pub disk_mb: EndpointDiskMb,
    pub latency_ms: EndpointLatencyMs,
    pub ipc: EndpointIpcLimits,
    pub prompts: EndpointPromptLimits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointMemoryMb {
    pub daemon: u32,
    pub engine: u32,
    pub uplink: u32,
    pub proxy: u32,
    pub tray: u32,
    pub console: u32,
    pub updater: u32,
    pub approve: u32,
    pub total_resident_target: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EndpointCpuPct {
    pub idle_max: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointDiskMb {
    pub total_cap: u32,
    pub spool_cap: u32,
    pub decision_reserve: u32,
    pub cache_cap: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointLatencyMs {
    pub hook_linux_p50: u32,
    pub hook_linux_p99: u32,
    pub hook_macos_p50: u32,
    pub hook_macos_p99: u32,
    pub hook_windows_p50: u32,
    pub hook_windows_p99: u32,
    pub shim_hang_max: u32,
    pub policy_1000_p99: u32,
    pub fastpath_cached_us: u32,
    pub fastpath_uncached_us: u32,
    pub proxy_added_p99: u32,
    pub proxy_first_byte_p99: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointIpcLimits {
    pub max_frame_bytes: usize,
    pub connect_timeout_ms: u64,
    pub read_timeout_ms: u64,
    pub command_hold_max_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EndpointPromptLimits {
    pub median_per_dev_day: u32,
    pub p95_per_dev_day: u32,
    pub max_opaque_pct: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackLimits {
    pub essentials_max_kb: u32,
    pub detections_max_mb: u32,
    pub intel_base_max_mb: u32,
    pub intel_daily_segment_max_kb: u32,
    pub max_pack_bundle_mb: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UplinkLimits {
    pub schedule: UplinkScheduleLimits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UplinkScheduleLimits {
    pub spine_interval_s: u64,
    pub spine_max_interval_s: u64,
    pub heartbeat_interval_s: u64,
    pub reconnect_spread_ms: u64,
    pub backfill_target_hours_low: u32,
    pub backfill_target_hours_high: u32,
    pub max_batch_bytes: usize,
    pub max_batch_events: usize,
    pub tuf_timestamp_stale_s: u64,
    pub stale_after_days: u32,
    pub kill_delivery_target_s: u64,
    pub kill_delivery_max_s: u64,
    pub policy_rollout_p99_s: u64,
    pub destructive_cmds_per_10m_max: u32,
    pub offline_renewal_days: u32,
    pub fleet_response_key_hours: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetryLimits {
    pub uplink_reconnect: RetryPolicy,
    pub ingest_flush: RetryPolicy,
    pub kms_unwrap: RetryPolicy,
    pub webhook_deliver: RetryPolicy,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub initial_backoff_ms: u64,
    pub max_backoff_ms: u64,
    pub multiplier: f64,
    pub jitter: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerLimits {
    pub ingest: ServerIngestLimits,
    pub lake: ServerLakeLimits,
    pub relational: ServerRelationalLimits,
    pub tenancy: ServerTenancyLimits,
    pub preflight: ServerPreflightLimits,
    pub enrolment: ServerEnrolmentLimits,
    pub operator: ServerOperatorLimits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerIngestLimits {
    pub max_body_bytes: usize,
    pub max_skew_seconds: u64,
    pub ack_p99_ms: u32,
    pub detection_lag_p99_ms: u32,
    pub freshness_p99_s: u32,
    pub ha_endpoint_ceiling_5k: u32,
    pub ha_endpoint_ceiling_100k: u32,
    pub distributed_tls_conn_per_sec_per_cell: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerLakeLimits {
    pub small_org_day_max_objects: u32,
    pub small_org_day_max_puts: u32,
    pub catalogue_commit_p99_ms: u32,
    pub catalogue_max_rows_per_file: u32,
    pub late_file_write_amp_max: f64,
    pub timeline_p95_s: u32,
    pub agg_30d_low_s: u32,
    pub agg_30d_high_s: u32,
    pub hunt_bg_threshold_gb: u32,
    pub wal_bytes_per_event_max: u32,
    pub archive_lag_p99_s: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerRelationalLimits {
    pub transaction_life_ms: u64,
    pub set_transaction_life_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerTenancyLimits {
    pub confirm_interval_s: u64,
    pub copy_life_days: u32,
    pub pitr_window_days: u32,
    pub erasure_cancel_window_days: u32,
    pub payment_retry_days: u32,
    pub suspended_grace_days: u32,
    pub free_inactive_days: u32,
    pub structural_default_retention_days: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerPreflightLimits {
    pub backup_max_age_hours: u32,
    pub wal_lag_max_minutes: u32,
    pub sqlite_backup_max_age_minutes: u32,
    pub restore_drill_warn_days: u32,
    pub restore_drill_fail_days: u32,
    pub cert_min_validity_days: u32,
    pub clock_skew_pg_fail_s: u64,
    pub clock_skew_http_warn_s: u64,
    pub clock_skew_http_fail_s: u64,
    pub disk_headroom_min_pct: u32,
    pub synthetic_alarm_max_age_days: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerEnrolmentLimits {
    pub default_rate_per_hour: u32,
    pub vdi_pool_rate_per_hour: u32,
    pub max_devices_default: u32,
    pub token_ttl_hours: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerOperatorLimits {
    pub settings_apply_timeout_s: u64,
    pub rto_relational_minutes: u32,
    pub rto_events_hours: u32,
    pub rollback_circuit_breaker_pct: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LimitsError {
    #[error("GRDR-LIMITS-0001: limits parse error at line {line}: {message}")]
    Parse { line: usize, message: String },
    #[error("GRDR-LIMITS-0002: missing required limits key `{key}`")]
    MissingKey { key: String },
    #[error(
        "GRDR-LIMITS-0003: invalid limits schema `{found}`; expected `{LIMITS_SCHEMA_V1ALPHA1}`"
    )]
    UnsupportedSchema { found: String },
    #[error("GRDR-LIMITS-0004: invalid limit bound for `{key}`: {reason}")]
    InvalidBound { key: String, reason: String },
}
