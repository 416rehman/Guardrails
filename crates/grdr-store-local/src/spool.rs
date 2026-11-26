// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! 4 MiB hash-chained segmented endpoint spool with 512 MiB cap, 64 MiB `decision` reserve,
//! priority shedding (`bulk -> evidence -> spine -> decision` when reserve full),
//! gap records (`spool-full`), and exact `(seq, hash)` `durable_through` pruning.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use grdr_crypto::encode_lower_hex;

use crate::fs_hardening::{ensure_private_dir_all, redact_path_label, sync_parent_dir};
use crate::spool_io::{
    FLAG_DECISION_FSYNC, FLAG_GAP, FLAG_NORMAL, LaneState, MAX_SPOOL_RECORD_BYTES,
    RECORD_HEADER_LEN, SpoolError, SpoolLane, SpoolRecord, append_bytes, compute_entry_hash,
    encode_record, ensure_active_segment, read_segment_records_for_lane, recover_lane_with_gaps,
};
use crate::spool_recover::{decode_hex_32, verify_exact_seq_hash};

pub use crate::spool_io::SpoolGapRecord;

pub const DEFAULT_SEGMENT_BYTES: u64 = 4 * 1024 * 1024;
pub const DEFAULT_SPOOL_CAP_BYTES: u64 = 512 * 1024 * 1024;
pub const DEFAULT_DECISION_RESERVE_BYTES: u64 = 64 * 1024 * 1024;
const GAP_MARKER_HEADROOM_BYTES: u64 = 512;
const MAX_IN_MEMORY_GAPS: usize = 1024;
const MAX_UNPAGINATED_READ_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpoolPolicy {
    pub segment_bytes: u64,
    pub total_cap_bytes: u64,
    pub decision_reserve_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppendOutcome {
    pub seq: u64,
    pub entry_hash: [u8; 32],
    pub fsynced: bool,
    pub emitted_gaps: Vec<SpoolGapRecord>,
}

#[derive(Debug)]
pub struct SegmentedSpool {
    root: PathBuf,
    policy: SpoolPolicy,
    lanes: BTreeMap<SpoolLane, LaneState>,
    gaps: Vec<SpoolGapRecord>,
}

struct DropSummary {
    lane: SpoolLane,
    first_seq: u64,
    last_seq: u64,
    bytes: u64,
    hash_before_gap: String,
    dropped_count: usize,
}

impl SpoolPolicy {
    #[must_use]
    pub fn from_embedded_limits() -> Self {
        match grdr_schema::limits::load_embedded_limits() {
            Ok(limits) => Self {
                segment_bytes: DEFAULT_SEGMENT_BYTES,
                total_cap_bytes: u64::from(limits.endpoint.disk_mb.spool_cap)
                    .saturating_mul(1024 * 1024),
                decision_reserve_bytes: u64::from(limits.endpoint.disk_mb.decision_reserve)
                    .saturating_mul(1024 * 1024),
            },
            Err(_) => Self {
                segment_bytes: DEFAULT_SEGMENT_BYTES,
                total_cap_bytes: DEFAULT_SPOOL_CAP_BYTES,
                decision_reserve_bytes: DEFAULT_DECISION_RESERVE_BYTES,
            },
        }
    }

    pub fn validate(&self) -> Result<(), SpoolError> {
        let min_seg = u64::try_from(RECORD_HEADER_LEN)
            .unwrap_or(86)
            .saturating_add(64);
        if self.segment_bytes < min_seg
            || self.total_cap_bytes < self.segment_bytes
            || self.decision_reserve_bytes > self.total_cap_bytes
        {
            return Err(SpoolError::Io {
                detail: "invalid spool policy bounds".to_string(),
            });
        }
        Ok(())
    }
}

impl SegmentedSpool {
    pub fn open(root: impl AsRef<Path>, policy: SpoolPolicy) -> Result<Self, SpoolError> {
        policy.validate()?;
        let root_path = root.as_ref().to_path_buf();
        ensure_private_dir_all(&root_path).map_err(|detail| SpoolError::Io { detail })?;

        let mut lanes = BTreeMap::new();
        let mut gaps = Vec::new();
        for lane in SpoolLane::all() {
            let (state, lane_gaps) =
                recover_lane_with_gaps(&root_path.join(lane.dir_name()), lane)?;
            lanes.insert(lane, state);
            gaps.extend(lane_gaps);
        }
        trim_gaps_vec(&mut gaps);
        Ok(Self {
            root: root_path,
            policy,
            lanes,
            gaps,
        })
    }

    pub fn append(
        &mut self,
        lane: SpoolLane,
        payload: &[u8],
        fsync: bool,
    ) -> Result<AppendOutcome, SpoolError> {
        if payload.len() > MAX_SPOOL_RECORD_BYTES {
            return Err(SpoolError::RecordTooLarge {
                len: payload.len(),
                max: MAX_SPOOL_RECORD_BYTES,
            });
        }
        let encoded_len =
            u64::try_from(RECORD_HEADER_LEN.saturating_add(payload.len())).map_err(|_| {
                SpoolError::RecordTooLarge {
                    len: payload.len(),
                    max: MAX_SPOOL_RECORD_BYTES,
                }
            })?;

        let emitted_gaps = self.enforce_capacity(lane, encoded_len)?;

        let state = self
            .lanes
            .get_mut(&lane)
            .ok_or(SpoolError::SpoolFull { lane })?;
        let seq = state.next_seq;
        let next_seq = seq.checked_add(1).ok_or_else(|| SpoolError::Io {
            detail: "spool sequence counter overflow".to_string(),
        })?;
        let flags = if lane == SpoolLane::Decision && fsync {
            FLAG_DECISION_FSYNC
        } else {
            FLAG_NORMAL
        };
        let prev_hash = state.tail_hash;
        let entry_hash = compute_entry_hash(seq, lane, flags, &prev_hash, payload);
        let encoded = encode_record(seq, lane, flags, &prev_hash, &entry_hash, payload)?;
        let active_path = ensure_active_segment(
            &self.root,
            lane,
            state,
            self.policy.segment_bytes,
            encoded_len,
        )?;
        append_bytes(&active_path, &encoded, lane == SpoolLane::Decision && fsync)?;

        if let Some(last) = state.segments.back_mut() {
            last.bytes = last.bytes.saturating_add(encoded_len);
            if last.first_seq == 0 {
                last.first_seq = seq;
                last.first_prev_hash = prev_hash;
            }
            last.last_seq = seq;
            last.last_hash = entry_hash;
        }
        state.next_seq = next_seq;
        state.tail_hash = entry_hash;
        state.total_bytes = state.total_bytes.saturating_add(encoded_len);

        Ok(AppendOutcome {
            seq,
            entry_hash,
            fsynced: lane == SpoolLane::Decision && fsync,
            emitted_gaps,
        })
    }

    pub fn read_lane_records(&self, lane: SpoolLane) -> Result<Vec<SpoolRecord>, SpoolError> {
        self.read_lane_records_paginated(lane, 0, usize::MAX, MAX_UNPAGINATED_READ_BYTES)
    }

    pub fn read_lane_records_paginated(
        &self,
        lane: SpoolLane,
        after_seq: u64,
        max_records: usize,
        max_bytes: usize,
    ) -> Result<Vec<SpoolRecord>, SpoolError> {
        let Some(state) = self.lanes.get(&lane) else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        let mut acc_bytes: usize = 0;
        for seg in &state.segments {
            if seg.last_seq <= after_seq {
                continue;
            }
            for rec in read_segment_records_for_lane(&seg.path, lane)? {
                if rec.seq <= after_seq {
                    continue;
                }
                let next_bytes = acc_bytes.saturating_add(rec.payload.len());
                if out.len() >= max_records || (!out.is_empty() && next_bytes > max_bytes) {
                    return Ok(out);
                }
                acc_bytes = next_bytes;
                out.push(rec);
            }
        }
        Ok(out)
    }

    pub fn acknowledge_durable_through(
        &mut self,
        lane: SpoolLane,
        durable_seq: u64,
        verified_tail_hash_hex: &str,
    ) -> Result<u64, SpoolError> {
        if durable_seq == 0 {
            return Ok(0);
        }
        let expected_hash = decode_hex_32(verified_tail_hash_hex)?;
        let Some(state) = self.lanes.get_mut(&lane) else {
            return Ok(0);
        };
        if !verify_exact_seq_hash(state, lane, durable_seq, &expected_hash)? {
            return Err(SpoolError::ChainCorrupt {
                path: lane.dir_name().to_string(),
                detail: format!("durable_through seq {durable_seq} or hash mismatch"),
            });
        }

        state.durable_through_seq = state.durable_through_seq.max(durable_seq);
        let mut pruned: u64 = 0;
        while let Some(front) = state.segments.front() {
            if !front.sealed || front.last_seq == 0 || front.last_seq > state.durable_through_seq {
                break;
            }
            let victim_path = front.path.clone();
            let victim_bytes = front.bytes;
            fs::remove_file(&victim_path).map_err(|err| SpoolError::Io {
                detail: format!(
                    "prune durable segment {}: {err}",
                    redact_path_label(&victim_path)
                ),
            })?;
            sync_parent_dir(&victim_path).map_err(|detail| SpoolError::Io { detail })?;
            state.segments.pop_front();
            state.total_bytes = state.total_bytes.saturating_sub(victim_bytes);
            pruned = pruned.saturating_add(1);
        }
        Ok(pruned)
    }

    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.lanes
            .values()
            .fold(0u64, |acc, s| acc.saturating_add(s.total_bytes))
    }

    #[must_use]
    pub fn lane_bytes(&self, lane: SpoolLane) -> u64 {
        self.lanes.get(&lane).map_or(0, |s| s.total_bytes)
    }

    #[must_use]
    pub fn gap_records(&self) -> &[SpoolGapRecord] {
        &self.gaps
    }

    #[must_use]
    pub fn head_state(&self, lane: SpoolLane) -> Option<(u64, [u8; 32], u64)> {
        self.lanes.get(&lane).map(|s| {
            (
                s.next_seq.saturating_sub(1),
                s.tail_hash,
                s.durable_through_seq,
            )
        })
    }

    fn non_decision_bytes(&self) -> u64 {
        self.lanes
            .iter()
            .filter(|(l, _)| **l != SpoolLane::Decision)
            .fold(0u64, |acc, (_, s)| acc.saturating_add(s.total_bytes))
    }

    fn enforce_capacity(
        &mut self,
        incoming_lane: SpoolLane,
        incoming_bytes: u64,
    ) -> Result<Vec<SpoolGapRecord>, SpoolError> {
        let non_dec_cap = self
            .policy
            .total_cap_bytes
            .saturating_sub(self.policy.decision_reserve_bytes);
        let mut sim_total = self.total_bytes();
        let mut sim_non_dec = self.non_decision_bytes();
        if fits_after_sim(
            incoming_lane,
            incoming_bytes,
            sim_total,
            sim_non_dec,
            self.policy.total_cap_bytes,
            non_dec_cap,
        ) {
            return Ok(Vec::new());
        }

        let order: &[SpoolLane] = if incoming_lane == SpoolLane::Decision {
            &[
                SpoolLane::Bulk,
                SpoolLane::Evidence,
                SpoolLane::Spine,
                SpoolLane::Decision,
            ]
        } else {
            &[SpoolLane::Bulk, SpoolLane::Evidence, SpoolLane::Spine]
        };

        let mut planned: BTreeMap<SpoolLane, DropSummary> = BTreeMap::new();
        for &victim_lane in order {
            if fits_after_sim(
                incoming_lane,
                incoming_bytes,
                sim_total,
                sim_non_dec,
                self.policy.total_cap_bytes,
                non_dec_cap,
            ) {
                break;
            }
            let Some(state) = self.lanes.get(&victim_lane) else {
                continue;
            };
            let min_keep = usize::from(victim_lane == incoming_lane);
            let mut rem = state.segments.len();
            for seg in &state.segments {
                if rem <= min_keep
                    || fits_after_sim(
                        incoming_lane,
                        incoming_bytes,
                        sim_total,
                        sim_non_dec,
                        self.policy.total_cap_bytes,
                        non_dec_cap,
                    )
                {
                    break;
                }
                sim_total = sim_total.saturating_sub(seg.bytes);
                if victim_lane != SpoolLane::Decision {
                    sim_non_dec = sim_non_dec.saturating_sub(seg.bytes);
                }
                rem = rem.saturating_sub(1);

                let entry = planned.entry(victim_lane).or_insert_with(|| {
                    sim_total = sim_total.saturating_add(GAP_MARKER_HEADROOM_BYTES);
                    if victim_lane != SpoolLane::Decision {
                        sim_non_dec = sim_non_dec.saturating_add(GAP_MARKER_HEADROOM_BYTES);
                    }
                    DropSummary {
                        lane: victim_lane,
                        first_seq: seg.first_seq,
                        last_seq: seg.last_seq,
                        bytes: 0,
                        hash_before_gap: encode_lower_hex(&seg.first_prev_hash),
                        dropped_count: 0,
                    }
                });
                entry.last_seq = seg.last_seq;
                entry.bytes = entry.bytes.saturating_add(seg.bytes);
                entry.dropped_count = entry.dropped_count.saturating_add(1);
            }
        }

        if !fits_after_sim(
            incoming_lane,
            incoming_bytes,
            sim_total,
            sim_non_dec,
            self.policy.total_cap_bytes,
            non_dec_cap,
        ) {
            return Err(SpoolError::SpoolFull {
                lane: incoming_lane,
            });
        }

        let mut emitted = Vec::new();
        for (victim_lane, drop_info) in planned {
            self.remove_planned_segments(victim_lane, drop_info.dropped_count)?;
            let tail_hash = self.lanes.get(&drop_info.lane).map_or_else(
                || encode_lower_hex(&[0u8; 32]),
                |s| encode_lower_hex(&s.tail_hash),
            );
            let gap = SpoolGapRecord {
                lane: drop_info.lane,
                first_dropped_seq: drop_info.first_seq,
                last_dropped_seq: drop_info.last_seq,
                dropped_bytes: drop_info.bytes,
                hash_before_gap: drop_info.hash_before_gap,
                hash_after_gap: tail_hash,
                reason: "spool-full".to_string(),
            };
            self.append_gap_marker(drop_info.lane, &gap)?;
            self.gaps.push(gap.clone());
            trim_gaps_vec(&mut self.gaps);
            emitted.push(gap);
        }
        Ok(emitted)
    }

    fn remove_planned_segments(&mut self, lane: SpoolLane, count: usize) -> Result<(), SpoolError> {
        let Some(state) = self.lanes.get_mut(&lane) else {
            return Ok(());
        };
        for _ in 0..count {
            let Some(front) = state.segments.front() else {
                break;
            };
            let path = front.path.clone();
            let bytes = front.bytes;
            fs::remove_file(&path).map_err(|err| SpoolError::Io {
                detail: format!("shed segment {}: {err}", redact_path_label(&path)),
            })?;
            sync_parent_dir(&path).map_err(|detail| SpoolError::Io { detail })?;
            state.segments.pop_front();
            state.total_bytes = state.total_bytes.saturating_sub(bytes);
        }
        Ok(())
    }

    fn append_gap_marker(
        &mut self,
        lane: SpoolLane,
        gap: &SpoolGapRecord,
    ) -> Result<(), SpoolError> {
        let payload = serde_json::to_vec(gap).map_err(|err| SpoolError::Io {
            detail: format!("serialize gap record: {err}"),
        })?;
        let state = self
            .lanes
            .get_mut(&lane)
            .ok_or(SpoolError::SpoolFull { lane })?;
        let seq = state.next_seq;
        let next_seq = seq.checked_add(1).ok_or_else(|| SpoolError::Io {
            detail: "spool sequence counter overflow".to_string(),
        })?;
        let prev_hash = state.tail_hash;
        let entry_hash = compute_entry_hash(seq, lane, FLAG_GAP, &prev_hash, &payload);
        let encoded = encode_record(seq, lane, FLAG_GAP, &prev_hash, &entry_hash, &payload)?;
        let needed = u64::try_from(encoded.len()).unwrap_or(0);
        let active =
            ensure_active_segment(&self.root, lane, state, self.policy.segment_bytes, needed)?;
        append_bytes(&active, &encoded, false)?;
        if let Some(last) = state.segments.back_mut() {
            last.bytes = last.bytes.saturating_add(needed);
            if last.first_seq == 0 {
                last.first_seq = seq;
                last.first_prev_hash = prev_hash;
            }
            last.last_seq = seq;
            last.last_hash = entry_hash;
        }
        state.next_seq = next_seq;
        state.tail_hash = entry_hash;
        state.total_bytes = state.total_bytes.saturating_add(needed);
        Ok(())
    }
}

fn fits_after_sim(
    lane: SpoolLane,
    needed: u64,
    total_bytes: u64,
    non_decision_bytes: u64,
    total_cap: u64,
    non_decision_cap: u64,
) -> bool {
    total_bytes.saturating_add(needed) <= total_cap
        && (lane == SpoolLane::Decision
            || non_decision_bytes.saturating_add(needed) <= non_decision_cap)
}

fn trim_gaps_vec(gaps: &mut Vec<SpoolGapRecord>) {
    if gaps.len() > MAX_IN_MEMORY_GAPS {
        let excess = gaps.len().saturating_sub(MAX_IN_MEMORY_GAPS);
        gaps.drain(..excess);
    }
}
