// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Full-jitter exponential backoff, `Retry-After` floor spreading, retry budgets,
//! per-origin circuit breakers, and PRNG helpers (`D-22`).

use crate::error::UplinkError;

/// Denominator `2^53` converting top 53 random bits into a uniform `f64` in `[0, 1)`.
const F64_UNIT_DENOM: f64 = 9_007_199_254_740_992.0;

/// Traffic category used to select backoff cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BackoffClass {
    Control,
    Data,
}

/// Explicit state enum for per-origin circuit breakers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CircuitState {
    Closed {
        consecutive_failures: u32,
    },
    Open {
        opened_at_mono_ms: u64,
        until_mono_ms: u64,
    },
    HalfOpen {
        probe_in_flight: bool,
    },
}

/// Per-origin rolling 60-second retry budget (`10%` of baseline traffic, floor `1 per 10s`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetryBudget {
    window_start_mono_ms: u64,
    baseline_requests_in_window: u64,
    retries_in_window: u64,
}

/// Combined per-origin failure protection (circuit breaker + retry budget).
#[derive(Clone, Debug)]
pub struct OriginFailureController {
    circuit: CircuitState,
    budget: RetryBudget,
    open_threshold: u32,
    cooldown_ms: u64,
}

/// Fast PRNG (`SplitMix64`) seeded from OS entropy or per-device simulation seed.
#[derive(Clone, Debug)]
pub struct SplitMix64 {
    word: u64,
}

impl SplitMix64 {
    /// Create a PRNG seeded from OS cryptographic entropy.
    pub fn from_os_entropy() -> Result<Self, UplinkError> {
        let mut bytes = [0u8; 8];
        grdr_crypto::fill_random(&mut bytes).map_err(|e| UplinkError::ClockFailed {
            detail: format!("entropy failure: {e}"),
        })?;
        Ok(Self {
            word: u64::from_le_bytes(bytes),
        })
    }

    /// Create a PRNG from an explicit 64-bit seed derived externally.
    #[must_use]
    pub const fn from_seed(seed: u64) -> Self {
        Self { word: seed }
    }

    /// Next raw 64-bit pseudorandom word.
    pub fn next_u64(&mut self) -> u64 {
        self.word = self.word.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.word;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Next uniform `f64` in `[0.0, 1.0)`.
    pub fn next_unit_f64(&mut self) -> f64 {
        let top_bits = self.next_u64() >> 11;
        (top_bits as f64) / F64_UNIT_DENOM
    }
}

impl RetryBudget {
    /// Construct an empty rolling 60-second retry budget.
    #[must_use]
    pub const fn new(now_mono_ms: u64) -> Self {
        Self {
            window_start_mono_ms: now_mono_ms,
            baseline_requests_in_window: 0,
            retries_in_window: 0,
        }
    }

    /// Record a primary non-retry request toward the 10% window quota.
    pub fn record_primary_request(&mut self, now_mono_ms: u64) {
        self.roll_if_needed(now_mono_ms);
        self.baseline_requests_in_window = self.baseline_requests_in_window.saturating_add(1);
    }

    /// Attempt to consume one retry token (`max(baseline / 10, 6)` per 60s window).
    pub fn try_consume_retry(&mut self, now_mono_ms: u64) -> bool {
        self.roll_if_needed(now_mono_ms);
        let ten_percent = self
            .baseline_requests_in_window
            .checked_div(10)
            .unwrap_or(0);
        let cap = ten_percent.max(6);
        if self.retries_in_window >= cap {
            return false;
        }
        self.retries_in_window = self.retries_in_window.saturating_add(1);
        true
    }

    fn roll_if_needed(&mut self, now_mono_ms: u64) {
        if now_mono_ms.saturating_sub(self.window_start_mono_ms) >= 60_000 {
            self.window_start_mono_ms = now_mono_ms;
            self.baseline_requests_in_window = 0;
            self.retries_in_window = 0;
        }
    }
}

impl OriginFailureController {
    /// Construct a circuit breaker + retry budget controller for one fleet origin.
    #[must_use]
    pub const fn new(now_mono_ms: u64) -> Self {
        Self {
            circuit: CircuitState::Closed {
                consecutive_failures: 0,
            },
            budget: RetryBudget::new(now_mono_ms),
            open_threshold: 5,
            cooldown_ms: 30_000,
        }
    }

    /// Check whether a non-retry or retry attempt is currently allowed for this origin.
    pub fn allow_attempt(
        &mut self,
        origin: &str,
        is_retry: bool,
        now_mono_ms: u64,
    ) -> Result<(), UplinkError> {
        match self.circuit {
            CircuitState::Open { until_mono_ms, .. } => {
                if now_mono_ms < until_mono_ms {
                    return Err(UplinkError::CircuitOpen {
                        origin: origin.to_string(),
                        retry_at_ms: until_mono_ms,
                    });
                }
                self.circuit = CircuitState::HalfOpen {
                    probe_in_flight: true,
                };
            }
            CircuitState::HalfOpen { probe_in_flight } => {
                if probe_in_flight {
                    return Err(UplinkError::CircuitOpen {
                        origin: origin.to_string(),
                        retry_at_ms: now_mono_ms.saturating_add(1_000),
                    });
                }
                self.circuit = CircuitState::HalfOpen {
                    probe_in_flight: true,
                };
            }
            CircuitState::Closed { .. } => {}
        }

        if is_retry {
            if !self.budget.try_consume_retry(now_mono_ms) {
                return Err(UplinkError::RetryBudgetExhausted {
                    origin: origin.to_string(),
                });
            }
        } else {
            self.budget.record_primary_request(now_mono_ms);
        }

        Ok(())
    }

    /// Record a successful response, closing any half-open probe.
    pub fn record_success(&mut self) {
        self.circuit = CircuitState::Closed {
            consecutive_failures: 0,
        };
    }

    /// Record a transient origin failure and open the circuit when threshold is reached.
    pub fn record_failure(&mut self, now_mono_ms: u64) {
        match self.circuit {
            CircuitState::Closed {
                consecutive_failures,
            } => {
                let next = consecutive_failures.saturating_add(1);
                if next >= self.open_threshold {
                    self.circuit = CircuitState::Open {
                        opened_at_mono_ms: now_mono_ms,
                        until_mono_ms: now_mono_ms.saturating_add(self.cooldown_ms),
                    };
                } else {
                    self.circuit = CircuitState::Closed {
                        consecutive_failures: next,
                    };
                }
            }
            CircuitState::HalfOpen { .. } => {
                self.circuit = CircuitState::Open {
                    opened_at_mono_ms: now_mono_ms,
                    until_mono_ms: now_mono_ms.saturating_add(self.cooldown_ms),
                };
            }
            CircuitState::Open { .. } => {}
        }
    }

    /// Current circuit breaker state for diagnostics and tests.
    #[must_use]
    pub const fn state(&self) -> CircuitState {
        self.circuit
    }
}

/// Full-jitter backoff with `retry_after_ms * (1 + U(0, 1))` floor (`D-22`).
#[must_use]
pub fn full_jitter_backoff_ms(
    attempt: u32,
    base_ms: u64,
    cap_ms: u64,
    retry_after_ms: Option<u64>,
    prng_unit: f64,
) -> u64 {
    let safe_cap = cap_ms.max(base_ms);
    let shift = attempt.min(20);
    let factor = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
    let exp_window = base_ms.saturating_mul(factor).min(safe_cap);
    let unit = prng_unit.clamp(0.0, 1.0);
    let jitter_delay = ((exp_window as f64) * unit).floor().max(0.0) as u64;

    if let Some(floor_ms) = retry_after_ms {
        let spread_floor = ((floor_ms as f64) * (1.0 + unit)).floor().max(0.0) as u64;
        jitter_delay.max(spread_floor)
    } else {
        jitter_delay
    }
}

/// Unplanned stream reconnect delay drawn uniformly from `[0, spread_ms]`.
#[must_use]
pub fn reconnect_spread_delay_ms(spread_ms: u64, prng_unit: f64) -> u64 {
    let unit = prng_unit.clamp(0.0, 1.0);
    ((spread_ms as f64) * unit).floor().max(0.0) as u64
}
