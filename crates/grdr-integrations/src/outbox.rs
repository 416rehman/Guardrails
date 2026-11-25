// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::IntegrationError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutboxLimits {
    pub max_items: usize,
    pub max_cursors: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportStream {
    Finding,
    Incident,
    Decision,
    Response,
    Approval,
    Inventory,
    Health,
    Audit,
    Events,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum CircuitState {
    Closed {
        consecutive_failures: u32,
    },
    Open {
        opened_at: Timestamp,
        retry_after_at: Timestamp,
        consecutive_failures: u32,
    },
    HalfOpen {
        probes_in_flight: u32,
        probes_succeeded: u32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    pub failure_threshold: u32,
    pub open_cooldown_secs: i64,
    pub half_open_success_threshold: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryPolicy {
    pub name: String,
    pub base_delay_ms: u64,
    pub max_delay_ms: u64,
    pub max_attempts: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportEnvelope {
    pub grdr_export: String,
    pub stream: ExportStream,
    pub record_id: String,
    pub revision: u64,
    pub dedup_key: String,
    pub emitted_at: Timestamp,
    pub organisation: String,
    pub replay: bool,
    pub record: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum OutboxItemState {
    Queued {
        attempt: u32,
        next_attempt_at: Timestamp,
    },
    Delivered {
        delivered_at: Timestamp,
    },
    DeadLettered {
        reason: String,
        dead_lettered_at: Timestamp,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboxItem {
    pub item_id: String,
    pub destination_id: String,
    pub envelope: ExportEnvelope,
    pub state: OutboxItemState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportCursor {
    pub destination_id: String,
    pub stream: ExportStream,
    pub last_acked_revision: u64,
    pub last_dedup_key: String,
    pub updated_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryOutcome {
    Success,
    RetryableFailure {
        retry_after_secs: Option<i64>,
        reason: String,
    },
    NonRetryableFailure {
        status_code: u16,
        reason: String,
    },
}

#[derive(Debug, Clone)]
pub struct OutboxQueue {
    destination_id: String,
    retry_policy: RetryPolicy,
    circuit_config: CircuitBreakerConfig,
    limits: OutboxLimits,
    circuit: CircuitState,
    items: BTreeMap<String, OutboxItem>,
    cursors: BTreeMap<ExportStream, ExportCursor>,
    record_cursors: BTreeMap<(ExportStream, String), ExportCursor>,
}

impl Default for OutboxLimits {
    fn default() -> Self {
        Self {
            max_items: 10_000,
            max_cursors: 10_000,
        }
    }
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 3,
            open_cooldown_secs: 60,
            half_open_success_threshold: 2,
        }
    }
}

impl RetryPolicy {
    #[must_use]
    pub fn export_delivery_default() -> Self {
        Self {
            name: "export-delivery".into(),
            base_delay_ms: 1_000,
            max_delay_ms: 300_000,
            max_attempts: 5,
        }
    }

    #[must_use]
    pub fn backoff_secs_for_attempt(&self, attempt: u32) -> i64 {
        let shift = attempt.min(16);
        let factor = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
        let delay_ms = self
            .base_delay_ms
            .saturating_mul(factor)
            .min(self.max_delay_ms);
        let secs = delay_ms.div_ceil(1_000);
        i64::try_from(secs).unwrap_or(i64::MAX)
    }
}

impl OutboxQueue {
    #[must_use]
    pub fn new(
        destination_id: impl Into<String>,
        retry_policy: RetryPolicy,
        circuit_config: CircuitBreakerConfig,
    ) -> Self {
        Self {
            destination_id: destination_id.into(),
            retry_policy,
            circuit_config,
            limits: OutboxLimits::default(),
            circuit: CircuitState::Closed {
                consecutive_failures: 0,
            },
            items: BTreeMap::new(),
            cursors: BTreeMap::new(),
            record_cursors: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_limits(mut self, limits: OutboxLimits) -> Self {
        self.limits = limits;
        self
    }

    #[must_use]
    pub fn circuit_state(&self) -> &CircuitState {
        &self.circuit
    }

    #[must_use]
    pub fn retry_policy(&self) -> &RetryPolicy {
        &self.retry_policy
    }

    #[must_use]
    pub fn cursor(&self, stream: ExportStream) -> Option<&ExportCursor> {
        self.cursors.get(&stream)
    }

    #[must_use]
    pub fn record_cursor(&self, stream: ExportStream, record_id: &str) -> Option<&ExportCursor> {
        self.record_cursors.get(&(stream, record_id.to_owned()))
    }

    #[must_use]
    pub fn item(&self, item_id: &str) -> Option<&OutboxItem> {
        self.items.get(item_id)
    }

    pub fn enqueue(
        &mut self,
        envelope: ExportEnvelope,
        now: Timestamp,
    ) -> Result<String, IntegrationError> {
        if envelope.dedup_key.trim().is_empty() || envelope.record_id.trim().is_empty() {
            return Err(IntegrationError::OutboxState(
                "dedup_key and record_id must be non-empty".into(),
            ));
        }
        let item_id = envelope.dedup_key.clone();
        if self.items.contains_key(&item_id) {
            return Ok(item_id);
        }
        if self.items.len() >= self.limits.max_items {
            return Err(IntegrationError::OutboxState(format!(
                "outbox item capacity {} reached",
                self.limits.max_items
            )));
        }
        let item = OutboxItem {
            item_id: item_id.clone(),
            destination_id: self.destination_id.clone(),
            envelope,
            state: OutboxItemState::Queued {
                attempt: 0,
                next_attempt_at: now,
            },
        };
        self.items.insert(item_id.clone(), item);
        Ok(item_id)
    }

    pub fn poll_dispatchable(&mut self, now: Timestamp) -> Result<Vec<String>, IntegrationError> {
        match &self.circuit {
            CircuitState::Closed { .. } => Ok(self.ready_item_ids(now)),
            CircuitState::Open { retry_after_at, .. } => {
                if now < *retry_after_at {
                    return Err(IntegrationError::CircuitOpen {
                        retry_after_at: retry_after_at.to_string(),
                    });
                }
                let ready: Vec<String> = self.ready_item_ids(now).into_iter().take(1).collect();
                if ready.is_empty() {
                    return Ok(ready);
                }
                self.circuit = CircuitState::HalfOpen {
                    probes_in_flight: 1,
                    probes_succeeded: 0,
                };
                Ok(ready)
            }
            CircuitState::HalfOpen {
                probes_in_flight,
                probes_succeeded,
            } => {
                if *probes_in_flight > 0 {
                    return Ok(Vec::new());
                }
                let ready: Vec<String> = self.ready_item_ids(now).into_iter().take(1).collect();
                if !ready.is_empty() {
                    self.circuit = CircuitState::HalfOpen {
                        probes_in_flight: 1,
                        probes_succeeded: *probes_succeeded,
                    };
                }
                Ok(ready)
            }
        }
    }

    pub fn record_delivery(
        &mut self,
        item_id: &str,
        outcome: DeliveryOutcome,
        now: Timestamp,
    ) -> Result<(), IntegrationError> {
        let current = self
            .items
            .get(item_id)
            .cloned()
            .ok_or_else(|| IntegrationError::OutboxState(format!("unknown item {item_id}")))?;

        let OutboxItemState::Queued { attempt, .. } = current.state else {
            return Err(IntegrationError::OutboxState(format!(
                "item {item_id} is not Queued"
            )));
        };

        match outcome {
            DeliveryOutcome::Success => {
                self.advance_circuit_on_success();
                self.advance_cursor(&current.envelope, now);
                self.items.insert(
                    item_id.to_owned(),
                    OutboxItem {
                        state: OutboxItemState::Delivered { delivered_at: now },
                        ..current
                    },
                );
            }
            DeliveryOutcome::RetryableFailure {
                retry_after_secs,
                reason,
            } => {
                self.trip_circuit_on_failure(now);
                let next_attempt = attempt.saturating_add(1);
                let next_state = if next_attempt >= self.retry_policy.max_attempts {
                    OutboxItemState::DeadLettered {
                        reason: format!("max retries exceeded: {reason}"),
                        dead_lettered_at: now,
                    }
                } else {
                    let backoff = self.retry_policy.backoff_secs_for_attempt(attempt);
                    let delay = retry_after_secs.unwrap_or(0).max(backoff);
                    let next_at = Timestamp::from_second(now.as_second().saturating_add(delay))
                        .map_err(|e| {
                            IntegrationError::OutboxState(format!("invalid retry timestamp: {e}"))
                        })?;
                    OutboxItemState::Queued {
                        attempt: next_attempt,
                        next_attempt_at: next_at,
                    }
                };
                self.items.insert(
                    item_id.to_owned(),
                    OutboxItem {
                        state: next_state,
                        ..current
                    },
                );
            }
            DeliveryOutcome::NonRetryableFailure {
                status_code,
                reason,
            } => {
                self.release_half_open_probe();
                self.items.insert(
                    item_id.to_owned(),
                    OutboxItem {
                        state: OutboxItemState::DeadLettered {
                            reason: format!("HTTP {status_code}: {reason}"),
                            dead_lettered_at: now,
                        },
                        ..current
                    },
                );
            }
        }
        Ok(())
    }

    fn ready_item_ids(&self, now: Timestamp) -> Vec<String> {
        self.items
            .values()
            .filter_map(|item| match item.state {
                OutboxItemState::Queued {
                    next_attempt_at, ..
                } if next_attempt_at <= now => Some(item.item_id.clone()),
                _ => None,
            })
            .collect()
    }

    fn advance_cursor(&mut self, env: &ExportEnvelope, now: Timestamp) {
        let cursor = ExportCursor {
            destination_id: self.destination_id.clone(),
            stream: env.stream,
            last_acked_revision: env.revision,
            last_dedup_key: env.dedup_key.clone(),
            updated_at: now,
        };
        if self
            .cursors
            .get(&env.stream)
            .is_none_or(|c| env.revision >= c.last_acked_revision)
        {
            self.cursors.insert(env.stream, cursor.clone());
        }
        let rec_key = (env.stream, env.record_id.clone());
        let should_update_record = self
            .record_cursors
            .get(&rec_key)
            .is_none_or(|c| env.revision >= c.last_acked_revision);
        if should_update_record
            && (self.record_cursors.contains_key(&rec_key)
                || self.record_cursors.len() < self.limits.max_cursors)
        {
            self.record_cursors.insert(rec_key, cursor);
        }
    }

    fn advance_circuit_on_success(&mut self) {
        self.circuit = match self.circuit {
            CircuitState::Closed { .. } => CircuitState::Closed {
                consecutive_failures: 0,
            },
            CircuitState::HalfOpen {
                probes_succeeded, ..
            } => {
                let total = probes_succeeded.saturating_add(1);
                if total >= self.circuit_config.half_open_success_threshold {
                    CircuitState::Closed {
                        consecutive_failures: 0,
                    }
                } else {
                    CircuitState::HalfOpen {
                        probes_in_flight: 0,
                        probes_succeeded: total,
                    }
                }
            }
            CircuitState::Open { .. } => CircuitState::Closed {
                consecutive_failures: 0,
            },
        };
    }

    fn release_half_open_probe(&mut self) {
        if let CircuitState::HalfOpen {
            probes_in_flight,
            probes_succeeded,
        } = self.circuit
        {
            self.circuit = CircuitState::HalfOpen {
                probes_in_flight: probes_in_flight.saturating_sub(1),
                probes_succeeded,
            };
        }
    }

    fn trip_circuit_on_failure(&mut self, now: Timestamp) {
        let cooldown = self.circuit_config.open_cooldown_secs;
        let retry_after =
            Timestamp::from_second(now.as_second().saturating_add(cooldown)).unwrap_or(now);

        self.circuit = match self.circuit {
            CircuitState::Closed {
                consecutive_failures,
            } => {
                let next_failures = consecutive_failures.saturating_add(1);
                if next_failures >= self.circuit_config.failure_threshold {
                    CircuitState::Open {
                        opened_at: now,
                        retry_after_at: retry_after,
                        consecutive_failures: next_failures,
                    }
                } else {
                    CircuitState::Closed {
                        consecutive_failures: next_failures,
                    }
                }
            }
            CircuitState::HalfOpen { .. } => CircuitState::Open {
                opened_at: now,
                retry_after_at: retry_after,
                consecutive_failures: self.circuit_config.failure_threshold,
            },
            CircuitState::Open {
                consecutive_failures,
                ..
            } => CircuitState::Open {
                opened_at: now,
                retry_after_at: retry_after,
                consecutive_failures: consecutive_failures.saturating_add(1),
            },
        };
    }
}
