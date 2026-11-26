// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Server-directed fleet schedule, clamping bounds, expiry fallback, and
//! deterministic `SHA-256(device_id || phase_salt) mod interval` phase placement (`D-22`).

use std::collections::BTreeMap;

use grdr_crypto::Sha256Hasher;
use grdr_os_clock::Clock;
use serde::{Deserialize, Serialize};

use crate::backoff::{BackoffClass, OriginFailureController, full_jitter_backoff_ms};
use crate::error::{UplinkError, UplinkHealthCondition};

/// Default schedule and fleet pacing constants matching design doc 22.
pub const DEFAULT_HEARTBEAT_INTERVAL_MS: u64 = 300_000;
pub const DEFAULT_EVIDENCE_INTERVAL_MS: u64 = 900_000;
pub const DEFAULT_BULK_INTERVAL_MS: u64 = 3_600_000;
pub const DEFAULT_JITTER_FRACTION: f64 = 0.15;
pub const DEFAULT_MAX_REQUEST_BYTES: u32 = 262_144;
pub const DEFAULT_MAX_EVENTS_PER_BATCH: u32 = 1_000;
pub const DEFAULT_EVIDENCE_CREDIT_BYTES: u64 = 2_097_152;
pub const DEFAULT_BACKFILL_CREDIT_BYTES: u64 = 1_048_576;
pub const DEFAULT_CONTROL_BACKOFF_CAP_MS: u64 = 120_000;
pub const DEFAULT_DATA_BACKOFF_CAP_MS: u64 = 900_000;
pub const DEFAULT_BACKOFF_BASE_MS: u64 = 1_000;
pub const DEFAULT_RECONNECT_SPREAD_MS: u64 = 60_000;
pub const DEFAULT_SCHEDULE_TTL_MS: i64 = 86_400_000;
pub const MIN_CREDIT_BYTES: u64 = 65_536;
pub const MAX_CREDIT_BYTES: u64 = 16_777_216;
pub const MIN_SCHEDULE_TTL_MS: i64 = 60_000;

/// Hard clamping bounds applied when receiving server `Schedule` directives.
#[derive(Clone, Debug, PartialEq)]
pub struct ScheduleLimits {
    pub heartbeat_min_ms: u64,
    pub heartbeat_max_ms: u64,
    pub evidence_min_ms: u64,
    pub evidence_max_ms: u64,
    pub bulk_min_ms: u64,
    pub bulk_max_ms: u64,
    pub jitter_fraction_max: f64,
    pub max_request_bytes_min: u32,
    pub max_request_bytes_max: u32,
    pub max_events_per_batch_min: u32,
    pub max_events_per_batch_max: u32,
    pub reconnect_spread_min_ms: u64,
    pub reconnect_spread_max_ms: u64,
    pub backoff_cap_min_ms: u64,
    pub backoff_cap_max_ms: u64,
    pub max_retry_after_ms: u64,
}

/// Fleet schedule directive matching the `Schedule` proto contract.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FleetSchedule {
    pub fleet_profile_id: String,
    pub heartbeat_interval_ms: u64,
    pub evidence_interval_ms: u64,
    pub bulk_interval_ms: u64,
    pub jitter_fraction: f64,
    pub phase_salt: String,
    pub max_request_bytes: u32,
    pub max_events_per_batch: u32,
    pub evidence_credit_bytes: u64,
    pub backfill_credit_bytes: u64,
    pub control_backoff_cap_ms: u64,
    pub data_backoff_cap_ms: u64,
    pub reconnect_spread_ms: u64,
    pub issued_at_unix_ms: i64,
    pub valid_until_unix_ms: i64,
}

/// Whether clamping altered any incoming server schedule field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClampOutcome {
    Unchanged,
    Clamped,
}

/// Validated and clamped schedule paired with any clamped field names.
#[derive(Clone, Debug, PartialEq)]
pub struct ClampedSchedule {
    pub effective: FleetSchedule,
    pub outcome: ClampOutcome,
    pub clamped_fields: Vec<&'static str>,
}

/// Stateful per-device schedule engine managing expiry fallback, phase, and backoff state.
#[derive(Clone, Debug)]
pub struct ScheduleManager {
    device_id: Vec<u8>,
    limits: ScheduleLimits,
    current: FleetSchedule,
    phase_heartbeat_ms: u64,
    phase_evidence_ms: u64,
    phase_bulk_ms: u64,
    control_attempt: u32,
    data_attempt: u32,
    origins: BTreeMap<String, OriginFailureController>,
}

impl Default for ScheduleLimits {
    fn default() -> Self {
        Self {
            heartbeat_min_ms: 5_000,
            heartbeat_max_ms: 3_600_000,
            evidence_min_ms: 60_000,
            evidence_max_ms: 86_400_000,
            bulk_min_ms: 300_000,
            bulk_max_ms: 604_800_000,
            jitter_fraction_max: 0.50,
            max_request_bytes_min: 65_536,
            max_request_bytes_max: 16_777_216,
            max_events_per_batch_min: 10,
            max_events_per_batch_max: 10_000,
            reconnect_spread_min_ms: 1_000,
            reconnect_spread_max_ms: 300_000,
            backoff_cap_min_ms: 10_000,
            backoff_cap_max_ms: 3_600_000,
            max_retry_after_ms: 604_800_000,
        }
    }
}

impl FleetSchedule {
    /// Compiled conservative defaults used at bootstrap or when a server schedule expires.
    #[must_use]
    pub fn compiled_defaults(issued_at_unix_ms: i64) -> Self {
        let limits = grdr_wire::limits::embedded_limits().ok();
        let max_request_bytes = limits
            .as_ref()
            .and_then(|l| u32::try_from(l.max_batch_bytes).ok())
            .filter(|&v| v > 0)
            .unwrap_or(DEFAULT_MAX_REQUEST_BYTES);
        let max_events_per_batch = limits
            .as_ref()
            .and_then(|l| u32::try_from(l.max_batch_events).ok())
            .filter(|&v| v > 0)
            .unwrap_or(DEFAULT_MAX_EVENTS_PER_BATCH);
        let reconnect_spread_ms = limits
            .as_ref()
            .map(|l| l.reconnect_spread_ms)
            .filter(|&v| v > 0)
            .unwrap_or(DEFAULT_RECONNECT_SPREAD_MS);
        Self {
            fleet_profile_id: "compiled-default".to_string(),
            heartbeat_interval_ms: DEFAULT_HEARTBEAT_INTERVAL_MS,
            evidence_interval_ms: DEFAULT_EVIDENCE_INTERVAL_MS,
            bulk_interval_ms: DEFAULT_BULK_INTERVAL_MS,
            jitter_fraction: DEFAULT_JITTER_FRACTION,
            phase_salt: format!("epoch-{issued_at_unix_ms}"),
            max_request_bytes,
            max_events_per_batch,
            evidence_credit_bytes: DEFAULT_EVIDENCE_CREDIT_BYTES,
            backfill_credit_bytes: DEFAULT_BACKFILL_CREDIT_BYTES,
            control_backoff_cap_ms: DEFAULT_CONTROL_BACKOFF_CAP_MS,
            data_backoff_cap_ms: DEFAULT_DATA_BACKOFF_CAP_MS,
            reconnect_spread_ms,
            issued_at_unix_ms,
            valid_until_unix_ms: issued_at_unix_ms.saturating_add(DEFAULT_SCHEDULE_TTL_MS),
        }
    }
}

impl ScheduleManager {
    /// Initialize with compiled defaults for `device_id` using `clock` for expiry baseline.
    pub fn new(device_id: impl Into<Vec<u8>>, clock: &dyn Clock) -> Result<Self, UplinkError> {
        let wall = clock
            .now_wall()
            .map_err(|e| UplinkError::ClockFailed {
                detail: e.to_string(),
            })?
            .as_millisecond();
        Ok(Self::with_unix_ms(device_id, wall))
    }

    /// Initialize deterministically from an explicit UNIX timestamp in milliseconds.
    #[must_use]
    pub fn with_unix_ms(device_id: impl Into<Vec<u8>>, now_unix_ms: i64) -> Self {
        let device_id = device_id.into();
        let current = FleetSchedule::compiled_defaults(now_unix_ms);
        let limits = ScheduleLimits::default();
        let phase_heartbeat_ms = deterministic_phase_ms(
            &device_id,
            &current.phase_salt,
            current.heartbeat_interval_ms,
        );
        let phase_evidence_ms = deterministic_phase_ms(
            &device_id,
            &current.phase_salt,
            current.evidence_interval_ms,
        );
        let phase_bulk_ms =
            deterministic_phase_ms(&device_id, &current.phase_salt, current.bulk_interval_ms);

        Self {
            device_id,
            limits,
            current,
            phase_heartbeat_ms,
            phase_evidence_ms,
            phase_bulk_ms,
            control_attempt: 0,
            data_attempt: 0,
            origins: BTreeMap::new(),
        }
    }

    /// Validate, clamp, and apply a server-sent `Schedule` directive.
    pub fn apply_server_schedule(
        &mut self,
        incoming: FleetSchedule,
    ) -> Result<(ClampedSchedule, Option<UplinkHealthCondition>), UplinkError> {
        if incoming.phase_salt.trim().is_empty() {
            return Err(UplinkError::ScheduleRejected {
                detail: "schedule phase_salt must not be empty".to_string(),
            });
        }
        let clamped = clamp_schedule(incoming, &self.limits);
        self.recompute_phases(&clamped.effective);
        self.current = clamped.effective.clone();

        let condition = match clamped.outcome {
            ClampOutcome::Unchanged => None,
            ClampOutcome::Clamped => Some(UplinkHealthCondition::ScheduleClamped),
        };
        Ok((clamped, condition))
    }

    /// Revert cleanly to compiled defaults if `valid_until_unix_ms` has passed.
    pub fn refresh_expiry(&mut self, now_unix_ms: i64) -> bool {
        if now_unix_ms > self.current.valid_until_unix_ms {
            let defaults = FleetSchedule::compiled_defaults(now_unix_ms);
            self.recompute_phases(&defaults);
            self.current = defaults;
            return true;
        }
        false
    }

    /// Compute the next phase-aligned heartbeat deadline in monotonic milliseconds.
    #[must_use]
    pub fn next_heartbeat_mono_ms(&self, now_mono_ms: u64, prng_unit: f64) -> u64 {
        next_tick_ms(
            now_mono_ms,
            self.phase_heartbeat_ms,
            self.current.heartbeat_interval_ms,
            self.current.jitter_fraction,
            prng_unit,
        )
    }

    /// Compute the next phase-aligned evidence deadline in monotonic milliseconds.
    #[must_use]
    pub fn next_evidence_mono_ms(&self, now_mono_ms: u64, prng_unit: f64) -> u64 {
        next_tick_ms(
            now_mono_ms,
            self.phase_evidence_ms,
            self.current.evidence_interval_ms,
            self.current.jitter_fraction,
            prng_unit,
        )
    }

    /// Compute next full-jitter backoff delay for `class` and increment the attempt counter.
    pub fn next_backoff_delay_ms(
        &mut self,
        class: BackoffClass,
        retry_after_ms: Option<u64>,
        prng_unit: f64,
    ) -> u64 {
        let (attempt, cap_ms) = match class {
            BackoffClass::Control => {
                let current_attempt = self.control_attempt;
                self.control_attempt = self.control_attempt.saturating_add(1);
                (current_attempt, self.current.control_backoff_cap_ms)
            }
            BackoffClass::Data => {
                let current_attempt = self.data_attempt;
                self.data_attempt = self.data_attempt.saturating_add(1);
                (current_attempt, self.current.data_backoff_cap_ms)
            }
        };
        let bounded_retry_after = retry_after_ms.map(|ms| ms.min(self.limits.max_retry_after_ms));
        full_jitter_backoff_ms(
            attempt,
            DEFAULT_BACKOFF_BASE_MS,
            cap_ms,
            bounded_retry_after,
            prng_unit,
        )
    }

    /// Reset backoff attempt counter for `class` once a request succeeds.
    pub fn reset_backoff(&mut self, class: BackoffClass) {
        match class {
            BackoffClass::Control => self.control_attempt = 0,
            BackoffClass::Data => self.data_attempt = 0,
        }
    }

    /// Access or create the per-origin failure controller.
    pub fn origin_controller(
        &mut self,
        origin: &str,
        now_mono_ms: u64,
    ) -> &mut OriginFailureController {
        self.origins
            .entry(origin.to_string())
            .or_insert_with(|| OriginFailureController::new(now_mono_ms))
    }

    /// Inspect current clamped schedule.
    #[must_use]
    pub const fn current_schedule(&self) -> &FleetSchedule {
        &self.current
    }

    /// Deterministic per-device heartbeat phase offset in milliseconds.
    #[must_use]
    pub const fn phase_heartbeat_ms(&self) -> u64 {
        self.phase_heartbeat_ms
    }

    /// Deterministic per-device evidence phase offset in milliseconds.
    #[must_use]
    pub const fn phase_evidence_ms(&self) -> u64 {
        self.phase_evidence_ms
    }

    /// Deterministic per-device bulk phase offset in milliseconds.
    #[must_use]
    pub const fn phase_bulk_ms(&self) -> u64 {
        self.phase_bulk_ms
    }

    fn recompute_phases(&mut self, schedule: &FleetSchedule) {
        self.phase_heartbeat_ms = deterministic_phase_ms(
            &self.device_id,
            &schedule.phase_salt,
            schedule.heartbeat_interval_ms,
        );
        self.phase_evidence_ms = deterministic_phase_ms(
            &self.device_id,
            &schedule.phase_salt,
            schedule.evidence_interval_ms,
        );
        self.phase_bulk_ms = deterministic_phase_ms(
            &self.device_id,
            &schedule.phase_salt,
            schedule.bulk_interval_ms,
        );
    }
}

/// Deterministic `SHA-256(device_id || 0x00 || phase_tag) mod interval_ms`.
#[must_use]
pub fn deterministic_phase_ms(device_id: &[u8], phase_tag: &str, interval_ms: u64) -> u64 {
    if interval_ms <= 1 {
        return 0;
    }
    let mut hasher = Sha256Hasher::new();
    hasher.update(device_id);
    hasher.update(&[0x00]);
    hasher.update(phase_tag.as_bytes());
    let digest = hasher.finalize_digest();
    let head: [u8; 8] = digest
        .get(..8)
        .and_then(|s| s.try_into().ok())
        .unwrap_or([0u8; 8]);
    let raw = u64::from_be_bytes(head);
    raw.checked_rem(interval_ms).unwrap_or(0)
}

/// Compute next phase-aligned tick with bounded positive jitter (never skips an epoch).
#[must_use]
pub fn next_tick_ms(
    now_mono_ms: u64,
    phase_ms: u64,
    interval_ms: u64,
    jitter_fraction: f64,
    prng_unit: f64,
) -> u64 {
    let safe_interval = interval_ms.max(1);
    let phase = phase_ms.checked_rem(safe_interval).unwrap_or(0);
    let epoch = now_mono_ms.checked_div(safe_interval).unwrap_or(0);
    let current_epoch_tick = epoch.saturating_mul(safe_interval).saturating_add(phase);
    let base_tick = if current_epoch_tick > now_mono_ms {
        current_epoch_tick
    } else {
        current_epoch_tick.saturating_add(safe_interval)
    };
    let clamped_jitter = if jitter_fraction.is_finite() {
        jitter_fraction.clamp(0.0, 0.50)
    } else {
        DEFAULT_JITTER_FRACTION
    };
    let unit = if prng_unit.is_finite() {
        prng_unit.clamp(0.0, 1.0)
    } else {
        0.0
    };
    let max_jitter_ms = (safe_interval as f64) * clamped_jitter;
    let delta_ms = (max_jitter_ms * unit).floor().max(0.0) as u64;
    base_tick.saturating_add(delta_ms)
}

/// Clamp a `FleetSchedule` to client safety bounds and report which fields changed.
#[must_use]
pub fn clamp_schedule(mut schedule: FleetSchedule, limits: &ScheduleLimits) -> ClampedSchedule {
    let mut clamped_fields = Vec::new();

    if clamp_u64_field(
        &mut schedule.heartbeat_interval_ms,
        limits.heartbeat_min_ms,
        limits.heartbeat_max_ms,
    ) {
        clamped_fields.push("heartbeat_interval_ms");
    }
    if clamp_u64_field(
        &mut schedule.evidence_interval_ms,
        limits.evidence_min_ms,
        limits.evidence_max_ms,
    ) {
        clamped_fields.push("evidence_interval_ms");
    }
    if clamp_u64_field(
        &mut schedule.bulk_interval_ms,
        limits.bulk_min_ms,
        limits.bulk_max_ms,
    ) {
        clamped_fields.push("bulk_interval_ms");
    }
    if !schedule.jitter_fraction.is_finite()
        || schedule.jitter_fraction < 0.0
        || schedule.jitter_fraction > limits.jitter_fraction_max
    {
        let sanitized = if schedule.jitter_fraction.is_finite() {
            schedule.jitter_fraction
        } else {
            DEFAULT_JITTER_FRACTION
        };
        schedule.jitter_fraction = sanitized.clamp(0.0, limits.jitter_fraction_max);
        clamped_fields.push("jitter_fraction");
    }
    if clamp_u32_field(
        &mut schedule.max_request_bytes,
        limits.max_request_bytes_min,
        limits.max_request_bytes_max,
    ) {
        clamped_fields.push("max_request_bytes");
    }
    if clamp_u32_field(
        &mut schedule.max_events_per_batch,
        limits.max_events_per_batch_min,
        limits.max_events_per_batch_max,
    ) {
        clamped_fields.push("max_events_per_batch");
    }
    if clamp_u64_field(
        &mut schedule.control_backoff_cap_ms,
        limits.backoff_cap_min_ms,
        limits.backoff_cap_max_ms,
    ) {
        clamped_fields.push("control_backoff_cap_ms");
    }
    if clamp_u64_field(
        &mut schedule.data_backoff_cap_ms,
        limits.backoff_cap_min_ms,
        limits.backoff_cap_max_ms,
    ) {
        clamped_fields.push("data_backoff_cap_ms");
    }
    if clamp_u64_field(
        &mut schedule.reconnect_spread_ms,
        limits.reconnect_spread_min_ms,
        limits.reconnect_spread_max_ms,
    ) {
        clamped_fields.push("reconnect_spread_ms");
    }
    if clamp_u64_field(
        &mut schedule.evidence_credit_bytes,
        MIN_CREDIT_BYTES,
        MAX_CREDIT_BYTES,
    ) {
        clamped_fields.push("evidence_credit_bytes");
    }
    if clamp_u64_field(
        &mut schedule.backfill_credit_bytes,
        MIN_CREDIT_BYTES,
        MAX_CREDIT_BYTES,
    ) {
        clamped_fields.push("backfill_credit_bytes");
    }
    let ttl_ms = schedule
        .valid_until_unix_ms
        .saturating_sub(schedule.issued_at_unix_ms);
    let clamped_ttl = ttl_ms.clamp(MIN_SCHEDULE_TTL_MS, DEFAULT_SCHEDULE_TTL_MS);
    if clamped_ttl != ttl_ms {
        schedule.valid_until_unix_ms = schedule.issued_at_unix_ms.saturating_add(clamped_ttl);
        clamped_fields.push("valid_until_unix_ms");
    }

    let outcome = if clamped_fields.is_empty() {
        ClampOutcome::Unchanged
    } else {
        ClampOutcome::Clamped
    };
    ClampedSchedule {
        effective: schedule,
        outcome,
        clamped_fields,
    }
}

fn clamp_u64_field(value: &mut u64, min: u64, max: u64) -> bool {
    let clamped = (*value).clamp(min, max);
    if clamped != *value {
        *value = clamped;
        true
    } else {
        false
    }
}

fn clamp_u32_field(value: &mut u32, min: u32, max: u32) -> bool {
    let clamped = (*value).clamp(min, max);
    if clamped != *value {
        *value = clamped;
        true
    } else {
        false
    }
}
