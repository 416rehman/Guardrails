// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Priority push lanes (`decision > spine > evidence > bulk`), battery/metered
//! deferrals, priority preemption, and dual watermarks (`acked_through` vs `durable_through`).

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

use crate::error::{UplinkError, UplinkHealthCondition};

/// Default daily evidence upload cap on battery power (5 MiB).
pub const BATTERY_EVIDENCE_DAILY_CAP_BYTES: u64 = 5 * 1_048_576;
/// Maximum deferral window for `bulk` lane on battery/metered connections (6 hours).
pub const BULK_MAX_DEFER_MS: u64 = 21_600_000;
/// Fast flush latency for urgent `decision` lane records (250ms).
pub const DECISION_FLUSH_LATENCY_MS: u64 = 250;
/// Spine urgent flush size threshold (256 KiB).
pub const SPINE_URGENT_FLUSH_BYTES: usize = 262_144;
/// Hard per-batcher queue record ceiling bounding unprivileged uplink memory during outages.
pub const MAX_QUEUED_RECORDS: usize = 16_384;
/// Hard per-batcher byte ceiling (8 MiB) bounding queued spool buffers in memory.
pub const MAX_QUEUED_BYTES: usize = 8_388_608;
/// Hard unacknowledged retention cap before refusing further queue pressure.
pub const MAX_RETAINED_UNACKED_RECORDS: usize = 4_096;

/// Strictly ordered push priority lanes (`Decision` is highest priority).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lane {
    Decision = 0,
    Spine = 1,
    Evidence = 2,
    Bulk = 3,
}

/// Device power source state governing background bandwidth caps.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PowerSource {
    Ac,
    Battery,
    BatterySaver,
}

/// Network metering state governing `bulk` deferral.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionMetered {
    Unmetered,
    Metered,
}

/// Whether `decision` preempted lower-priority queued items in a packed batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreemptionOutcome {
    StandardPack,
    DecisionPreemptedLowerLanes,
}

/// Action returned when reconciling verified server watermarks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatermarkAdvance {
    Advanced {
        acked_through: u64,
        durable_through: u64,
    },
    ServerEpochChanged {
        backfill_from_seq: u64,
    },
    RejectedUnverified,
}

/// Single queued spool record eligible for priority packing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueuedRecord {
    pub seq: u64,
    pub lane: Lane,
    pub enqueued_mono_ms: u64,
    pub payload: Vec<u8>,
}

/// Per-lane counts included in a built push batch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneCounts {
    pub decision: u32,
    pub spine: u32,
    pub evidence: u32,
    pub bulk: u32,
}

/// Framed batch ready for `PushBatch` submission over `grdr-uplink`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackedPushBatch {
    pub batch_id: String,
    pub max_seq: u64,
    pub total_bytes: usize,
    pub lane_counts: LaneCounts,
    pub records: Vec<QueuedRecord>,
    pub preemption: PreemptionOutcome,
    pub health_warnings: Vec<UplinkHealthCondition>,
}

/// Dual watermark tracker separating de-duplication (`acked`) from spool deletion (`durable`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatermarkTracker {
    acked_through: u64,
    durable_through: u64,
    server_epoch: Option<String>,
    pending_backfill_from_seq: Option<u64>,
}

/// Priority queue packer with credits, preemption, and battery/metered policies.
#[derive(Clone, Debug)]
pub struct LaneBatcher {
    max_request_bytes: usize,
    max_events_per_batch: usize,
    evidence_credit_bytes: u64,
    backfill_credit_bytes: u64,
    battery_evidence_used_today: u64,
    battery_window_start_mono_ms: u64,
    decision: VecDeque<QueuedRecord>,
    spine: VecDeque<QueuedRecord>,
    evidence: VecDeque<QueuedRecord>,
    bulk: VecDeque<QueuedRecord>,
    sent_unacked: BTreeMapReplayBuffer,
}

/// Track sent-but-not-yet-durable records so epoch changes or unverified acks retain spool safety.
#[derive(Clone, Debug, Default)]
struct BTreeMapReplayBuffer {
    records: std::collections::BTreeMap<u64, QueuedRecord>,
}

impl WatermarkTracker {
    /// Create a fresh dual-watermark tracker at sequence `0`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            acked_through: 0,
            durable_through: 0,
            server_epoch: None,
            pending_backfill_from_seq: None,
        }
    }

    /// Reconcile a cryptographically verified `PushAck` into `acked_through` / `durable_through`.
    pub fn apply_verified_ack(
        &mut self,
        acked_through: u64,
        durable_through: u64,
        epoch: &str,
    ) -> WatermarkAdvance {
        let clamped_durable = durable_through.min(acked_through);
        if let Some(prev_epoch) = &self.server_epoch
            && prev_epoch != epoch
        {
            self.server_epoch = Some(epoch.to_string());
            let backfill_start = self.durable_through.saturating_add(1);
            self.acked_through = self.durable_through.max(clamped_durable);
            self.durable_through = self.durable_through.max(clamped_durable);
            self.pending_backfill_from_seq = Some(backfill_start);
            return WatermarkAdvance::ServerEpochChanged {
                backfill_from_seq: backfill_start,
            };
        }

        if self.server_epoch.is_none() {
            self.server_epoch = Some(epoch.to_string());
        }
        self.acked_through = self.acked_through.max(acked_through);
        self.durable_through = self.durable_through.max(clamped_durable);
        WatermarkAdvance::Advanced {
            acked_through: self.acked_through,
            durable_through: self.durable_through,
        }
    }

    /// Reject an unverified ack without advancing either watermark (preserves spool durability).
    pub fn reject_unverified_ack(&mut self) -> WatermarkAdvance {
        WatermarkAdvance::RejectedUnverified
    }

    /// Sequence number below which records need not be resent under current `server_epoch`.
    #[must_use]
    pub const fn acked_through(&self) -> u64 {
        self.acked_through
    }

    /// Sequence number below which local spool segments are eligible for deletion.
    #[must_use]
    pub const fn durable_through(&self) -> u64 {
        self.durable_through
    }

    /// Consume any pending backfill cursor triggered by a `server_epoch` change.
    pub fn take_backfill_cursor(&mut self) -> Option<u64> {
        self.pending_backfill_from_seq.take()
    }
}

impl LaneBatcher {
    /// Construct a lane batcher matching the active `Schedule` limits.
    #[must_use]
    pub fn new(
        max_request_bytes: u32,
        max_events_per_batch: u32,
        evidence_credit_bytes: u64,
        backfill_credit_bytes: u64,
        now_mono_ms: u64,
    ) -> Self {
        Self {
            max_request_bytes: usize::try_from(max_request_bytes).unwrap_or(524_288),
            max_events_per_batch: usize::try_from(max_events_per_batch).unwrap_or(1_000),
            evidence_credit_bytes,
            backfill_credit_bytes,
            battery_evidence_used_today: 0,
            battery_window_start_mono_ms: now_mono_ms,
            decision: VecDeque::new(),
            spine: VecDeque::new(),
            evidence: VecDeque::new(),
            bulk: VecDeque::new(),
            sent_unacked: BTreeMapReplayBuffer::default(),
        }
    }

    /// Update dynamic schedule bounds (credits, request cap, batch count).
    pub fn update_bounds(
        &mut self,
        max_request_bytes: u32,
        max_events_per_batch: u32,
        evidence_credit_bytes: u64,
        backfill_credit_bytes: u64,
    ) {
        self.max_request_bytes =
            usize::try_from(max_request_bytes).unwrap_or(self.max_request_bytes);
        self.max_events_per_batch =
            usize::try_from(max_events_per_batch).unwrap_or(self.max_events_per_batch);
        self.evidence_credit_bytes = evidence_credit_bytes;
        self.backfill_credit_bytes = backfill_credit_bytes;
    }

    /// Enqueue a record into its priority lane, checking `max_request_bytes` and memory ceilings.
    pub fn enqueue(&mut self, record: QueuedRecord) -> Result<(), UplinkError> {
        if record.payload.len() > self.max_request_bytes {
            return Err(UplinkError::BatchOverflow {
                lane: format!("{:?}", record.lane),
                size: record.payload.len(),
                max: self.max_request_bytes,
            });
        }
        let total_records = self
            .decision
            .len()
            .saturating_add(self.spine.len())
            .saturating_add(self.evidence.len())
            .saturating_add(self.bulk.len());
        if total_records >= MAX_QUEUED_RECORDS {
            return Err(UplinkError::BatchOverflow {
                lane: format!("{:?}", record.lane),
                size: total_records.saturating_add(1),
                max: MAX_QUEUED_RECORDS,
            });
        }
        let next_bytes = self
            .total_queued_bytes()
            .saturating_add(record.payload.len());
        if next_bytes > MAX_QUEUED_BYTES {
            return Err(UplinkError::BatchOverflow {
                lane: format!("{:?}", record.lane),
                size: next_bytes,
                max: MAX_QUEUED_BYTES,
            });
        }
        match record.lane {
            Lane::Decision => self.decision.push_back(record),
            Lane::Spine => self.spine.push_back(record),
            Lane::Evidence => self.evidence.push_back(record),
            Lane::Bulk => self.bulk.push_back(record),
        }
        Ok(())
    }

    fn total_queued_bytes(&self) -> usize {
        self.decision
            .iter()
            .chain(self.spine.iter())
            .chain(self.evidence.iter())
            .chain(self.bulk.iter())
            .fold(0usize, |acc, rec| acc.saturating_add(rec.payload.len()))
    }

    /// Re-queue records strictly above `durable_through` after a `server_epoch` change.
    ///
    /// Decision lane items are re-queued ahead of lower lanes; lower lanes obey `backfill_credit_bytes`.
    pub fn requeue_backfill(&mut self, durable_through: u64) -> usize {
        let mut candidates: Vec<QueuedRecord> = self
            .sent_unacked
            .records
            .range(durable_through.saturating_add(1)..)
            .map(|(_, r)| r.clone())
            .collect();
        candidates.sort_by_key(|r| (r.lane, r.seq));

        let mut remaining_non_decision_credit = self.backfill_credit_bytes;
        let mut requeued = 0usize;
        for record in candidates {
            if record.lane != Lane::Decision {
                let len = u64::try_from(record.payload.len()).unwrap_or(u64::MAX);
                if len > remaining_non_decision_credit {
                    continue;
                }
                remaining_non_decision_credit = remaining_non_decision_credit.saturating_sub(len);
            }
            if self.enqueue(record).is_ok() {
                requeued = requeued.saturating_add(1);
            }
        }
        requeued
    }

    /// Purge records up to verified `durable_through` once the server proves durable persistence.
    pub fn prune_durable(&mut self, durable_through: u64) -> usize {
        let keys: Vec<u64> = self
            .sent_unacked
            .records
            .range(..=durable_through)
            .map(|(k, _)| *k)
            .collect();
        let count = keys.len();
        for key in keys {
            self.sent_unacked.records.remove(&key);
        }
        count
    }

    /// Determine whether an urgent flush should happen before the heartbeat tick.
    #[must_use]
    pub fn has_urgent_work(&self, now_mono_ms: u64) -> bool {
        if let Some(head) = self.decision.front()
            && now_mono_ms.saturating_sub(head.enqueued_mono_ms) >= DECISION_FLUSH_LATENCY_MS
        {
            return true;
        }
        let spine_bytes: usize = self
            .spine
            .iter()
            .fold(0usize, |acc, r| acc.saturating_add(r.payload.len()));
        spine_bytes >= SPINE_URGENT_FLUSH_BYTES
    }

    /// Pack up to `max_request_bytes` strictly in priority order (`Decision > Spine > Evidence > Bulk`).
    pub fn pack_next_batch(
        &mut self,
        batch_id: impl Into<String>,
        power: PowerSource,
        metered: ConnectionMetered,
        now_mono_ms: u64,
    ) -> Option<PackedPushBatch> {
        self.roll_battery_window(now_mono_ms);

        let mut records = Vec::new();
        let mut total_bytes = 0usize;
        let mut max_seq = 0u64;
        let mut counts = LaneCounts::default();
        let mut health_warnings = Vec::new();
        let mut remaining_evidence_credit = self.evidence_credit_bytes;

        let had_lower_queued =
            !self.spine.is_empty() || !self.evidence.is_empty() || !self.bulk.is_empty();
        let had_decision = !self.decision.is_empty();

        self.drain_lane_into(
            Lane::Decision,
            &mut records,
            &mut total_bytes,
            &mut max_seq,
            &mut counts.decision,
        );
        self.drain_lane_into(
            Lane::Spine,
            &mut records,
            &mut total_bytes,
            &mut max_seq,
            &mut counts.spine,
        );

        let evidence_warning = self.drain_evidence(
            power,
            &mut remaining_evidence_credit,
            &mut records,
            &mut total_bytes,
            &mut max_seq,
            &mut counts.evidence,
        );
        if let Some(warning) = evidence_warning {
            health_warnings.push(warning);
        }

        let bulk_allowed_now = power == PowerSource::Ac && metered == ConnectionMetered::Unmetered;
        let bulk_deadline_due = self.bulk.front().is_some_and(|head| {
            now_mono_ms.saturating_sub(head.enqueued_mono_ms) >= BULK_MAX_DEFER_MS
        });
        if bulk_allowed_now || bulk_deadline_due {
            self.drain_lane_into(
                Lane::Bulk,
                &mut records,
                &mut total_bytes,
                &mut max_seq,
                &mut counts.bulk,
            );
        }

        if records.is_empty() {
            return None;
        }

        for r in &records {
            if self.sent_unacked.records.len() >= MAX_RETAINED_UNACKED_RECORDS
                && let Some(oldest_seq) = self.sent_unacked.records.keys().next().copied()
            {
                self.sent_unacked.records.remove(&oldest_seq);
            }
            self.sent_unacked.records.insert(r.seq, r.clone());
        }

        let preemption = if had_decision && had_lower_queued {
            PreemptionOutcome::DecisionPreemptedLowerLanes
        } else {
            PreemptionOutcome::StandardPack
        };

        Some(PackedPushBatch {
            batch_id: batch_id.into(),
            max_seq,
            total_bytes,
            lane_counts: counts,
            records,
            preemption,
            health_warnings,
        })
    }

    /// Number of unacknowledged in-flight records retained until `durable_through` advances.
    #[must_use]
    pub fn retained_unacked_count(&self) -> usize {
        self.sent_unacked.records.len()
    }

    /// Queued count for a specific lane.
    #[must_use]
    pub fn queued_len(&self, lane: Lane) -> usize {
        match lane {
            Lane::Decision => self.decision.len(),
            Lane::Spine => self.spine.len(),
            Lane::Evidence => self.evidence.len(),
            Lane::Bulk => self.bulk.len(),
        }
    }

    fn drain_lane_into(
        &mut self,
        lane: Lane,
        out: &mut Vec<QueuedRecord>,
        total_bytes: &mut usize,
        max_seq: &mut u64,
        lane_count: &mut u32,
    ) {
        let queue = match lane {
            Lane::Decision => &mut self.decision,
            Lane::Spine => &mut self.spine,
            Lane::Evidence => &mut self.evidence,
            Lane::Bulk => &mut self.bulk,
        };
        while let Some(front) = queue.front() {
            if out.len() >= self.max_events_per_batch {
                break;
            }
            let next_bytes = total_bytes.saturating_add(front.payload.len());
            if next_bytes > self.max_request_bytes {
                break;
            }
            if let Some(item) = queue.pop_front() {
                *total_bytes = next_bytes;
                *max_seq = (*max_seq).max(item.seq);
                *lane_count = lane_count.saturating_add(1);
                out.push(item);
            }
        }
    }

    fn drain_evidence(
        &mut self,
        power: PowerSource,
        remaining_credit: &mut u64,
        out: &mut Vec<QueuedRecord>,
        total_bytes: &mut usize,
        max_seq: &mut u64,
        lane_count: &mut u32,
    ) -> Option<UplinkHealthCondition> {
        let mut exhausted = false;
        while let Some(front) = self.evidence.front() {
            if out.len() >= self.max_events_per_batch {
                break;
            }
            let payload_bytes = front.payload.len();
            let payload_u64 = u64::try_from(payload_bytes).unwrap_or(u64::MAX);
            if payload_u64 > *remaining_credit {
                exhausted = true;
                break;
            }
            if power != PowerSource::Ac
                && self.battery_evidence_used_today.saturating_add(payload_u64)
                    > BATTERY_EVIDENCE_DAILY_CAP_BYTES
            {
                exhausted = true;
                break;
            }
            let next_bytes = total_bytes.saturating_add(payload_bytes);
            if next_bytes > self.max_request_bytes {
                break;
            }
            if let Some(item) = self.evidence.pop_front() {
                *remaining_credit = remaining_credit.saturating_sub(payload_u64);
                if power != PowerSource::Ac {
                    self.battery_evidence_used_today =
                        self.battery_evidence_used_today.saturating_add(payload_u64);
                }
                *total_bytes = next_bytes;
                *max_seq = (*max_seq).max(item.seq);
                *lane_count = lane_count.saturating_add(1);
                out.push(item);
            }
        }

        if exhausted {
            Some(UplinkHealthCondition::EvidenceBudgetExhausted)
        } else {
            None
        }
    }

    fn roll_battery_window(&mut self, now_mono_ms: u64) {
        if now_mono_ms.saturating_sub(self.battery_window_start_mono_ms) >= 86_400_000 {
            self.battery_window_start_mono_ms = now_mono_ms;
            self.battery_evidence_used_today = 0;
        }
    }
}
