// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use grdr_model::CodedError;

pub const CODE_CLOCK_MONOTONIC_UNAVAILABLE: &str = "GRDR-CLOCK-0001";
pub const CODE_CLOCK_WALL_INVALID: &str = "GRDR-CLOCK-0002";
pub const CODE_CLOCK_JUMP: &str = "GRDR-CLOCK-0003";
pub const DEFAULT_JUMP_THRESHOLD_MS: i64 = 5_000;
const NANOS_PER_SEC: u128 = 1_000_000_000;
const NANOS_PER_MS: i128 = 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClockError {
    #[error("GRDR-CLOCK-0001: monotonic or boot clock unavailable: {0}")]
    MonotonicUnavailable(String),
    #[error("GRDR-CLOCK-0002: system wall clock invalid: {0}")]
    WallClockInvalid(String),
    #[error("GRDR-CLOCK-0003: clock state lock poisoned")]
    StatePoisoned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct MonotonicInstant {
    pub nanos: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClockSourceKind {
    SystemMonotonicAndWall,
    ManualDeterministic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootClockReading {
    pub wall_time: Timestamp,
    pub monotonic: MonotonicInstant,
    pub boot_uptime_ns: u64,
    pub source: ClockSourceKind,
    pub os_target: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ClockJumpAssessment {
    Continuous {
        delta_wall_ms: i64,
        delta_mono_ms: i64,
    },
    ForwardJump {
        skew_ms: i64,
    },
    BackwardJump {
        skew_ms: i64,
    },
}

pub trait Clock: Send + Sync {
    fn now_wall(&self) -> Result<Timestamp, ClockError>;
    fn now_monotonic(&self) -> Result<MonotonicInstant, ClockError>;
    fn boot_uptime(&self) -> Result<Duration, ClockError>;
    fn reading(&self) -> Result<BootClockReading, ClockError>;
}

#[derive(Debug, Clone)]
pub struct SystemClock {
    origin: Instant,
    boot_offset_ns: u64,
}

#[derive(Debug, Clone)]
struct ManualClockState {
    wall_ns: i128,
    mono_ns: u64,
    boot_ns: u64,
}

#[derive(Debug, Clone)]
pub struct ManualClock {
    inner: Arc<Mutex<ManualClockState>>,
}

impl From<ClockError> for CodedError {
    fn from(err: ClockError) -> Self {
        let code = match &err {
            ClockError::MonotonicUnavailable(_) | ClockError::StatePoisoned => {
                CODE_CLOCK_MONOTONIC_UNAVAILABLE
            }
            ClockError::WallClockInvalid(_) => CODE_CLOCK_WALL_INVALID,
        };
        CodedError::new(
            code,
            err.to_string(),
            "Verify host clock and monotonic source.",
        )
    }
}

impl MonotonicInstant {
    pub const fn from_nanos(nanos: u64) -> Self {
        Self { nanos }
    }

    pub fn elapsed_since(self, earlier: Self) -> Option<Duration> {
        self.nanos
            .checked_sub(earlier.nanos)
            .map(Duration::from_nanos)
    }

    pub fn saturating_add_duration(self, delta: Duration) -> Self {
        let delta_ns = u64::try_from(delta.as_nanos()).unwrap_or(u64::MAX);
        Self {
            nanos: self.nanos.saturating_add(delta_ns),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemClock {
    pub fn new() -> Self {
        let boot_offset_ns = probe_os_boot_uptime_ns().unwrap_or(0);
        Self {
            origin: Instant::now(),
            boot_offset_ns,
        }
    }

    fn elapsed_origin_ns(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }
}

impl Clock for SystemClock {
    fn now_wall(&self) -> Result<Timestamp, ClockError> {
        let dur = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| ClockError::WallClockInvalid(e.to_string()))?;
        let nanos = i128::try_from(dur.as_nanos())
            .map_err(|e| ClockError::WallClockInvalid(e.to_string()))?;
        Timestamp::from_nanosecond(nanos).map_err(|e| ClockError::WallClockInvalid(e.to_string()))
    }

    fn now_monotonic(&self) -> Result<MonotonicInstant, ClockError> {
        Ok(MonotonicInstant::from_nanos(self.elapsed_origin_ns()))
    }

    fn boot_uptime(&self) -> Result<Duration, ClockError> {
        if let Some(os_boot_ns) = probe_os_boot_uptime_ns() {
            return Ok(Duration::from_nanos(os_boot_ns));
        }
        Ok(Duration::from_nanos(
            self.boot_offset_ns.saturating_add(self.elapsed_origin_ns()),
        ))
    }

    fn reading(&self) -> Result<BootClockReading, ClockError> {
        let wall_time = self.now_wall()?;
        let monotonic = self.now_monotonic()?;
        let uptime = self.boot_uptime()?;
        let boot_uptime_ns = u64::try_from(uptime.as_nanos()).unwrap_or(u64::MAX);
        Ok(BootClockReading {
            wall_time,
            monotonic,
            boot_uptime_ns,
            source: ClockSourceKind::SystemMonotonicAndWall,
            os_target: std::env::consts::OS.into(),
        })
    }
}

impl ManualClock {
    pub fn new(initial_wall: Timestamp, initial_boot: Duration) -> Self {
        let boot_ns = u64::try_from(initial_boot.as_nanos()).unwrap_or(u64::MAX);
        Self {
            inner: Arc::new(Mutex::new(ManualClockState {
                wall_ns: initial_wall.as_nanosecond(),
                mono_ns: 0,
                boot_ns,
            })),
        }
    }

    pub fn advance(&self, delta: Duration) -> Result<(), ClockError> {
        let delta_u64 = u64::try_from(delta.as_nanos()).unwrap_or(u64::MAX);
        let delta_i128 = i128::try_from(delta.as_nanos()).unwrap_or(i128::MAX);
        let mut guard = self.inner.lock().map_err(|_| ClockError::StatePoisoned)?;
        guard.mono_ns = guard.mono_ns.saturating_add(delta_u64);
        guard.boot_ns = guard.boot_ns.saturating_add(delta_u64);
        guard.wall_ns = guard.wall_ns.saturating_add(delta_i128);
        Ok(())
    }

    pub fn jump_wall_seconds(&self, delta_seconds: i64) -> Result<(), ClockError> {
        let delta_ns = i128::from(delta_seconds).saturating_mul(1_000_000_000);
        let mut guard = self.inner.lock().map_err(|_| ClockError::StatePoisoned)?;
        guard.wall_ns = guard.wall_ns.saturating_add(delta_ns);
        Ok(())
    }
}

impl Clock for ManualClock {
    fn now_wall(&self) -> Result<Timestamp, ClockError> {
        let guard = self.inner.lock().map_err(|_| ClockError::StatePoisoned)?;
        Timestamp::from_nanosecond(guard.wall_ns)
            .map_err(|e| ClockError::WallClockInvalid(e.to_string()))
    }

    fn now_monotonic(&self) -> Result<MonotonicInstant, ClockError> {
        let guard = self.inner.lock().map_err(|_| ClockError::StatePoisoned)?;
        Ok(MonotonicInstant::from_nanos(guard.mono_ns))
    }

    fn boot_uptime(&self) -> Result<Duration, ClockError> {
        let guard = self.inner.lock().map_err(|_| ClockError::StatePoisoned)?;
        Ok(Duration::from_nanos(guard.boot_ns))
    }

    fn reading(&self) -> Result<BootClockReading, ClockError> {
        let guard = self.inner.lock().map_err(|_| ClockError::StatePoisoned)?;
        let wall_time = Timestamp::from_nanosecond(guard.wall_ns)
            .map_err(|e| ClockError::WallClockInvalid(e.to_string()))?;
        Ok(BootClockReading {
            wall_time,
            monotonic: MonotonicInstant::from_nanos(guard.mono_ns),
            boot_uptime_ns: guard.boot_ns,
            source: ClockSourceKind::ManualDeterministic,
            os_target: std::env::consts::OS.into(),
        })
    }
}

pub fn assess_clock_jump(
    previous: &BootClockReading,
    current: &BootClockReading,
    threshold_ms: i64,
) -> ClockJumpAssessment {
    let wall_diff_ns = current
        .wall_time
        .as_nanosecond()
        .saturating_sub(previous.wall_time.as_nanosecond());
    let mono_diff_ns =
        i128::from(current.monotonic.nanos).saturating_sub(i128::from(previous.monotonic.nanos));

    let delta_wall_ms = i64::try_from(wall_diff_ns / NANOS_PER_MS).unwrap_or(i64::MAX);
    let delta_mono_ms = i64::try_from(mono_diff_ns / NANOS_PER_MS).unwrap_or(i64::MAX);
    let skew_ms = delta_wall_ms.saturating_sub(delta_mono_ms);
    let limit = threshold_ms.max(0);

    if skew_ms > limit {
        ClockJumpAssessment::ForwardJump { skew_ms }
    } else if skew_ms < limit.saturating_neg() {
        ClockJumpAssessment::BackwardJump { skew_ms }
    } else {
        ClockJumpAssessment::Continuous {
            delta_wall_ms,
            delta_mono_ms,
        }
    }
}

#[cfg(target_os = "linux")]
fn probe_os_boot_uptime_ns() -> Option<u64> {
    let raw = std::fs::read_to_string("/proc/uptime").ok()?;
    parse_proc_uptime_ns(&raw)
}

#[cfg(not(target_os = "linux"))]
fn probe_os_boot_uptime_ns() -> Option<u64> {
    None
}

pub fn parse_proc_uptime_ns(raw: &str) -> Option<u64> {
    let first = raw.split_whitespace().next()?;
    let (secs_str, frac_str) = match first.split_once('.') {
        Some((s, f)) => (s, f),
        None => (first, ""),
    };
    let secs = secs_str.parse::<u128>().ok()?;
    let mut frac_ns: u128 = 0;
    let mut scale: u128 = NANOS_PER_SEC / 10;
    for byte in frac_str.bytes().take(9) {
        if !byte.is_ascii_digit() {
            return None;
        }
        let digit = u128::from(byte.saturating_sub(b'0'));
        frac_ns = frac_ns.saturating_add(digit.saturating_mul(scale));
        scale /= 10;
    }
    let total = secs.saturating_mul(NANOS_PER_SEC).saturating_add(frac_ns);
    u64::try_from(total).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_clock_reads_wall_monotonic_and_boot_uptime() {
        let clock = SystemClock::new();
        let r1 = clock.reading().unwrap();
        let r2 = clock.reading().unwrap();
        assert!(r2.monotonic >= r1.monotonic);
        assert!(r2.wall_time.as_second() > 1_600_000_000);
        assert_eq!(r1.source, ClockSourceKind::SystemMonotonicAndWall);
    }

    #[test]
    fn manual_clock_advances_and_detects_forward_and_backward_jumps() {
        let start = Timestamp::from_second(1_700_000_000).unwrap();
        let clock = ManualClock::new(start, Duration::from_secs(120));
        let r0 = clock.reading().unwrap();

        clock.advance(Duration::from_secs(10)).unwrap();
        let r1 = clock.reading().unwrap();
        assert_eq!(
            assess_clock_jump(&r0, &r1, DEFAULT_JUMP_THRESHOLD_MS),
            ClockJumpAssessment::Continuous {
                delta_wall_ms: 10_000,
                delta_mono_ms: 10_000,
            }
        );

        clock.jump_wall_seconds(60).unwrap();
        let r2 = clock.reading().unwrap();
        assert!(matches!(
            assess_clock_jump(&r1, &r2, DEFAULT_JUMP_THRESHOLD_MS),
            ClockJumpAssessment::ForwardJump { skew_ms: 60_000 }
        ));

        clock.jump_wall_seconds(-120).unwrap();
        let r3 = clock.reading().unwrap();
        assert!(matches!(
            assess_clock_jump(&r2, &r3, DEFAULT_JUMP_THRESHOLD_MS),
            ClockJumpAssessment::BackwardJump { skew_ms: -120_000 }
        ));
    }

    #[test]
    fn parses_linux_proc_uptime_precisely() {
        assert_eq!(
            parse_proc_uptime_ns("1234.56 4567.89\n"),
            Some(1_234_560_000_000)
        );
        assert_eq!(parse_proc_uptime_ns("42"), Some(42_000_000_000));
        assert_eq!(parse_proc_uptime_ns("not-a-number"), None);
    }
}
