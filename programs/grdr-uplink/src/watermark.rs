// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Per-lane dual watermark tracking separating server de-duplication (`acked`)
//! from durable persistence proof (`durable`) before local spool pruning (`D-22`).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::lanes::{Lane, WatermarkAdvance};

/// Per-lane dual watermark state separating de-duplication from spool durability.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneWatermarks {
    pub acked_through: u64,
    pub durable_through: u64,
    pub server_epoch: Option<String>,
    pub pending_backfill_from_seq: Option<u64>,
}

/// Dual watermark tracker separating de-duplication (`acked`) from spool deletion (`durable`) per lane.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatermarkTracker {
    per_lane: BTreeMap<Lane, LaneWatermarks>,
}

impl WatermarkTracker {
    /// Create a fresh dual-watermark tracker at sequence `0` for all lanes.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            per_lane: BTreeMap::new(),
        }
    }

    /// Reconcile a cryptographically verified `PushAck` for `lane` into `acked_through` / `durable_through`.
    pub fn apply_verified_ack_for_lane(
        &mut self,
        lane: Lane,
        acked_through: u64,
        durable_through: u64,
        epoch: &str,
    ) -> WatermarkAdvance {
        let entry = self.per_lane.entry(lane).or_default();
        let clamped_durable = durable_through.min(acked_through);
        if let Some(prev_epoch) = &entry.server_epoch
            && prev_epoch != epoch
        {
            entry.server_epoch = Some(epoch.to_string());
            let backfill_start = entry.durable_through.saturating_add(1);
            entry.acked_through = entry.durable_through.max(clamped_durable);
            entry.durable_through = entry.durable_through.max(clamped_durable);
            entry.pending_backfill_from_seq = Some(backfill_start);
            return WatermarkAdvance::ServerEpochChanged {
                backfill_from_seq: backfill_start,
            };
        }

        if entry.server_epoch.is_none() {
            entry.server_epoch = Some(epoch.to_string());
        }
        entry.acked_through = entry.acked_through.max(acked_through);
        entry.durable_through = entry.durable_through.max(clamped_durable);
        WatermarkAdvance::Advanced {
            acked_through: entry.acked_through,
            durable_through: entry.durable_through,
        }
    }

    /// Reconcile a cryptographically verified `PushAck` on `Lane::Decision`.
    pub fn apply_verified_ack(
        &mut self,
        acked_through: u64,
        durable_through: u64,
        epoch: &str,
    ) -> WatermarkAdvance {
        self.apply_verified_ack_for_lane(Lane::Decision, acked_through, durable_through, epoch)
    }

    /// Reject an unverified ack without advancing either watermark (preserves spool durability).
    pub fn reject_unverified_ack(&mut self) -> WatermarkAdvance {
        WatermarkAdvance::RejectedUnverified
    }

    /// Watermark record for a specific lane, if initialized.
    #[must_use]
    pub fn lane_watermarks(&self, lane: Lane) -> Option<&LaneWatermarks> {
        self.per_lane.get(&lane)
    }

    /// Sequence number below which records need not be resent for `lane`.
    #[must_use]
    pub fn acked_through_for(&self, lane: Lane) -> u64 {
        self.per_lane.get(&lane).map_or(0, |w| w.acked_through)
    }

    /// Sequence number below which local spool segments are eligible for deletion for `lane`.
    #[must_use]
    pub fn durable_through_for(&self, lane: Lane) -> u64 {
        self.per_lane.get(&lane).map_or(0, |w| w.durable_through)
    }

    /// Consume any pending backfill cursor for `lane` triggered by a `server_epoch` change.
    pub fn take_backfill_cursor_for(&mut self, lane: Lane) -> Option<u64> {
        self.per_lane
            .get_mut(&lane)
            .and_then(|w| w.pending_backfill_from_seq.take())
    }

    /// Sequence number below which `Decision` records need not be resent under current `server_epoch`.
    #[must_use]
    pub fn acked_through(&self) -> u64 {
        self.acked_through_for(Lane::Decision)
    }

    /// Sequence number below which `Decision` spool records are eligible for deletion.
    #[must_use]
    pub fn durable_through(&self) -> u64 {
        self.durable_through_for(Lane::Decision)
    }

    /// Consume any pending `Decision` backfill cursor triggered by a `server_epoch` change.
    pub fn take_backfill_cursor(&mut self) -> Option<u64> {
        self.take_backfill_cursor_for(Lane::Decision)
    }
}
