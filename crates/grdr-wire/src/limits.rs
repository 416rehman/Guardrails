// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Embedded operational limits loaded from `contracts/limits.toml` (`ADR-0022`, `P14`).

use std::sync::OnceLock;

use crate::frame::IpcFrameError;

const MIB_U64: u64 = 1024 * 1024;
const MIB_USIZE: usize = 1024 * 1024;
const KIB_USIZE: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EmbeddedLimits {
    pub max_frame_bytes: usize,
    pub connect_timeout_ms: u64,
    pub read_timeout_ms: u64,
    pub command_hold_max_ms: u64,
    pub shim_hang_max_ms: u64,
    pub spool_cap_bytes: u64,
    pub decision_reserve_bytes: u64,
    pub cache_cap_bytes: u64,
    pub daemon_memory_mb: u32,
    pub engine_memory_mb: u32,
    pub uplink_memory_mb: u32,
    pub updater_memory_mb: u32,
    pub essentials_max_bytes: usize,
    pub detections_max_bytes: usize,
    pub max_pack_bundle_bytes: usize,
    pub max_batch_bytes: usize,
    pub max_batch_events: usize,
    pub tuf_timestamp_stale_s: u64,
    pub stale_after_days: u32,
    pub fleet_response_key_hours: u32,
    pub spine_interval_s: u64,
    pub heartbeat_interval_s: u64,
    pub reconnect_spread_ms: u64,
}

static CACHED_LIMITS: OnceLock<Result<EmbeddedLimits, String>> = OnceLock::new();

pub fn embedded_limits() -> Result<EmbeddedLimits, IpcFrameError> {
    let cached = CACHED_LIMITS.get_or_init(load_from_schema);
    match cached {
        Ok(limits) => Ok(*limits),
        Err(detail) => Err(IpcFrameError::LimitsUnavailable {
            detail: detail.clone(),
        }),
    }
}

fn load_from_schema() -> Result<EmbeddedLimits, String> {
    let cfg = grdr_schema::limits::load_embedded_limits().map_err(|err| err.to_string())?;
    let max_frame_bytes = cfg.endpoint.ipc.max_frame_bytes;
    if max_frame_bytes == 0 {
        return Err("endpoint.ipc.max_frame_bytes must be > 0".to_string());
    }
    let essentials_max_bytes = usize::try_from(cfg.packs.essentials_max_kb)
        .ok()
        .and_then(|v| v.checked_mul(KIB_USIZE))
        .ok_or_else(|| "packs.essentials_max_kb overflow".to_string())?;
    let detections_max_bytes = usize::try_from(cfg.packs.detections_max_mb)
        .ok()
        .and_then(|v| v.checked_mul(MIB_USIZE))
        .ok_or_else(|| "packs.detections_max_mb overflow".to_string())?;
    let max_pack_bundle_bytes = usize::try_from(cfg.packs.max_pack_bundle_mb)
        .ok()
        .and_then(|v| v.checked_mul(MIB_USIZE))
        .ok_or_else(|| "packs.max_pack_bundle_mb overflow".to_string())?;
    let max_batch_bytes = cfg.uplink.schedule.max_batch_bytes;
    let max_batch_events = cfg.uplink.schedule.max_batch_events;

    Ok(EmbeddedLimits {
        max_frame_bytes,
        connect_timeout_ms: cfg.endpoint.ipc.connect_timeout_ms,
        read_timeout_ms: cfg.endpoint.ipc.read_timeout_ms,
        command_hold_max_ms: cfg.endpoint.ipc.command_hold_max_ms,
        shim_hang_max_ms: u64::from(cfg.endpoint.latency_ms.shim_hang_max),
        spool_cap_bytes: u64::from(cfg.endpoint.disk_mb.spool_cap).saturating_mul(MIB_U64),
        decision_reserve_bytes: u64::from(cfg.endpoint.disk_mb.decision_reserve)
            .saturating_mul(MIB_U64),
        cache_cap_bytes: u64::from(cfg.endpoint.disk_mb.cache_cap).saturating_mul(MIB_U64),
        daemon_memory_mb: cfg.endpoint.memory_mb.daemon,
        engine_memory_mb: cfg.endpoint.memory_mb.engine,
        uplink_memory_mb: cfg.endpoint.memory_mb.uplink,
        updater_memory_mb: cfg.endpoint.memory_mb.updater,
        essentials_max_bytes,
        detections_max_bytes,
        max_pack_bundle_bytes,
        max_batch_bytes,
        max_batch_events,
        tuf_timestamp_stale_s: cfg.uplink.schedule.tuf_timestamp_stale_s,
        stale_after_days: cfg.uplink.schedule.stale_after_days,
        fleet_response_key_hours: cfg.uplink.schedule.fleet_response_key_hours,
        spine_interval_s: cfg.uplink.schedule.spine_interval_s,
        heartbeat_interval_s: cfg.uplink.schedule.heartbeat_interval_s,
        reconnect_spread_ms: cfg.uplink.schedule.reconnect_spread_ms,
    })
}
