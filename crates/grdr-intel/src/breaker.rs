// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Per-device hourly new-artefact Block circuit breaker (`docs/design/14`).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::IntelError;

pub const MAX_HOURLY_INTEL_BLOCKS: usize = 3;
pub const ONE_HOUR_MS: i64 = 3_600_000;
const MAX_BREAKER_DEVICES: usize = 1_024;
const MAX_BREAKER_ENTRIES_PER_DEVICE: usize = 64;
const MAX_DEVICE_ID_BYTES: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BreakerState {
    Closed,
    Tripped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BreakerHit {
    activation_epoch: u64,
    canonical_value: String,
    seen_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct DeviceBreakerState {
    hits: Vec<BreakerHit>,
    last_seen_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IntelCircuitBreaker {
    per_device: BTreeMap<String, DeviceBreakerState>,
}

impl IntelCircuitBreaker {
    /// Tracks distinct `(activation_epoch, canonical_value)` `Block` activations per device
    /// within one hour, returning `Err(IntelError::BreakerOpen)` once > 3 distinct artefacts fire.
    pub fn record_new_block(
        &mut self,
        device_id: &str,
        activation_epoch: u64,
        canonical_value: &str,
        now_ms: i64,
    ) -> Result<BreakerState, IntelError> {
        if now_ms < 0 {
            return Err(IntelError::BreakerOpen(
                "negative timestamp rejected by circuit breaker".into(),
            ));
        }
        if device_id.trim().is_empty()
            || device_id.len() > MAX_DEVICE_ID_BYTES
            || device_id.chars().any(char::is_control)
        {
            return Err(IntelError::BreakerOpen("invalid device_id".into()));
        }
        if !self.per_device.contains_key(device_id) && self.per_device.len() >= MAX_BREAKER_DEVICES
        {
            self.evict_oldest_device();
        }
        let state = self.per_device.entry(device_id.to_owned()).or_default();
        state.last_seen_ms = state.last_seen_ms.max(now_ms);
        let cutoff = state.last_seen_ms.saturating_sub(ONE_HOUR_MS);
        state.hits.retain(|hit| hit.seen_at_ms >= cutoff);

        if let Some(existing) = state.hits.iter_mut().find(|hit| {
            hit.activation_epoch == activation_epoch && hit.canonical_value == canonical_value
        }) {
            existing.seen_at_ms = existing.seen_at_ms.max(state.last_seen_ms);
            return Ok(if state.hits.len() > MAX_HOURLY_INTEL_BLOCKS {
                BreakerState::Tripped
            } else {
                BreakerState::Closed
            });
        }

        let will_trip = state.hits.len() >= MAX_HOURLY_INTEL_BLOCKS;
        if state.hits.len() < MAX_BREAKER_ENTRIES_PER_DEVICE {
            state.hits.push(BreakerHit {
                activation_epoch,
                canonical_value: canonical_value.to_owned(),
                seen_at_ms: state.last_seen_ms,
            });
        }
        if will_trip {
            return Err(IntelError::BreakerOpen(
                "hourly Block activation cap exceeded for device".into(),
            ));
        }
        Ok(BreakerState::Closed)
    }

    #[must_use]
    pub fn state(&self, device_id: &str, now_ms: i64) -> BreakerState {
        let count = self.per_device.get(device_id).map_or(0, |s| {
            let monotonic_now = s.last_seen_ms.max(now_ms);
            let cutoff = monotonic_now.saturating_sub(ONE_HOUR_MS);
            s.hits.iter().filter(|hit| hit.seen_at_ms >= cutoff).count()
        });
        if count > MAX_HOURLY_INTEL_BLOCKS {
            BreakerState::Tripped
        } else {
            BreakerState::Closed
        }
    }

    #[must_use]
    pub fn tracked_devices(&self) -> usize {
        self.per_device.len()
    }

    fn evict_oldest_device(&mut self) {
        let oldest = self
            .per_device
            .iter()
            .min_by_key(|(_, st)| st.last_seen_ms)
            .map(|(k, _)| k.clone());
        if let Some(key) = oldest {
            self.per_device.remove(&key);
        }
    }
}
