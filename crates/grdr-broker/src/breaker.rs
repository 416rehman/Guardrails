// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Per-provider circuit breaker state machine backed by `contracts/limits.toml` (`docs/design/07`).

use std::collections::VecDeque;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use grdr_schema::limits::{BrokerCircuitBreakerLimits, load_embedded_limits};

const BASIS_SCALE: u64 = 10_000;
static BREAKER_LIMITS: OnceLock<BrokerCircuitBreakerLimits> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CircuitBreakerState {
    Closed,
    HalfOpen,
    Suspended { until_ms: u64 },
}

#[derive(Debug, Clone, Default)]
pub(crate) struct BreakerTracker {
    consecutive_failures: u32,
    suspended_until_ms: Option<u64>,
    half_open: bool,
    last_seen_ms: u64,
    recent_outcomes_ms: VecDeque<(u64, bool)>,
}

fn breaker_limits() -> &'static BrokerCircuitBreakerLimits {
    BREAKER_LIMITS.get_or_init(|| match load_embedded_limits() {
        Ok(cfg) => cfg.broker.circuit_breaker,
        Err(_) => BrokerCircuitBreakerLimits {
            consecutive_failures: 5,
            window_ms: 300_000,
            min_calls: 20,
            error_rate_bp: 500,
            cooldown_ms: 60_000,
            max_outcomes: 4_096,
        },
    })
}

impl BreakerTracker {
    pub(crate) fn current_state(&mut self, now_ms: u64) -> CircuitBreakerState {
        if let Some(until) = self.suspended_until_ms {
            if now_ms < self.last_seen_ms || now_ms < until {
                return CircuitBreakerState::Suspended { until_ms: until };
            }
            self.suspended_until_ms = None;
            self.half_open = true;
            return CircuitBreakerState::HalfOpen;
        }
        if self.half_open {
            return CircuitBreakerState::HalfOpen;
        }
        CircuitBreakerState::Closed
    }

    pub(crate) fn record(&mut self, now_ms: u64, success: bool) -> Option<String> {
        let lim = breaker_limits();
        let effective_now = now_ms.max(self.last_seen_ms);
        self.last_seen_ms = effective_now;

        let cutoff = effective_now.saturating_sub(lim.window_ms);
        while self
            .recent_outcomes_ms
            .front()
            .is_some_and(|(ts, _)| *ts < cutoff)
        {
            self.recent_outcomes_ms.pop_front();
        }
        while self.recent_outcomes_ms.len() >= lim.max_outcomes {
            self.recent_outcomes_ms.pop_front();
        }
        self.recent_outcomes_ms.push_back((effective_now, success));

        if success {
            self.consecutive_failures = 0;
            self.half_open = false;
            return None;
        }

        if self.half_open {
            self.half_open = false;
            self.consecutive_failures = self.consecutive_failures.saturating_add(1);
            self.suspended_until_ms = Some(effective_now.saturating_add(lim.cooldown_ms));
            return Some("provider-reopened-failed:half-open-trip".into());
        }

        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        let total = self.recent_outcomes_ms.len();
        let failed = self
            .recent_outcomes_ms
            .iter()
            .filter(|(_, ok)| !*ok)
            .count();
        let rate_bp = u64::try_from(failed)
            .unwrap_or(u64::MAX)
            .saturating_mul(BASIS_SCALE)
            .checked_div(u64::try_from(total).unwrap_or(1).max(1))
            .unwrap_or(0);

        if self.consecutive_failures >= lim.consecutive_failures
            || (total >= lim.min_calls && rate_bp > lim.error_rate_bp)
        {
            self.suspended_until_ms = Some(effective_now.saturating_add(lim.cooldown_ms));
            return Some(format!(
                "provider-suspend:consecutive={},rate_bp={rate_bp}",
                self.consecutive_failures
            ));
        }
        None
    }
}
