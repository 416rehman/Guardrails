// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Low-level hash-chained 4 MiB spool segment framing, CRC-32C computation, and segment creation.

use std::collections::VecDeque;
use std::io::Write;
use std::path::{Path, PathBuf};

use grdr_crypto::Sha256Hasher;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::crc32c::crc32c_append;
use crate::fs_hardening::{open_nofollow_append_create, redact_path_label, sync_parent_dir};

pub const MAX_SPOOL_RECORD_BYTES: usize = 2 * 1024 * 1024;
pub(crate) const RECORD_MAGIC: [u8; 4] = *b"GRSP";
pub const RECORD_HEADER_LEN: usize = 4 + 8 + 1 + 1 + 32 + 32 + 4 + 4;
const HASH_DOMAIN: &[u8] = b"grdr.spool.v1\0";
pub const FLAG_NORMAL: u8 = 0;
pub const FLAG_GAP: u8 = 1;
pub const FLAG_DECISION_FSYNC: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SpoolError {
    #[error("GRDR-LSTORE-0007: spool I/O failure: {detail}")]
    Io { detail: String },
    #[error("GRDR-LSTORE-0008: spool chain integrity violation in {path}: {detail}")]
    ChainCorrupt { path: String, detail: String },
    #[error("GRDR-LSTORE-0009: spool record payload {len} exceeds maximum {max} bytes")]
    RecordTooLarge { len: usize, max: usize },
    #[error("GRDR-LSTORE-0010: decision reserve exhausted and no older segments can be shed")]
    SpoolFull { lane: SpoolLane },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpoolLane {
    Decision = 0,
    Spine = 1,
    Evidence = 2,
    Bulk = 3,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpoolGapRecord {
    pub lane: SpoolLane,
    pub first_dropped_seq: u64,
    pub last_dropped_seq: u64,
    pub dropped_bytes: u64,
    pub hash_before_gap: String,
    pub hash_after_gap: String,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpoolRecord {
    pub seq: u64,
    pub lane: SpoolLane,
    pub is_gap: bool,
    pub fsynced: bool,
    pub prev_hash: [u8; 32],
    pub entry_hash: [u8; 32],
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegmentMeta {
    pub segment_id: u64,
    pub lane: SpoolLane,
    pub path: PathBuf,
    pub bytes: u64,
    pub first_seq: u64,
    pub last_seq: u64,
    pub first_prev_hash: [u8; 32],
    pub last_hash: [u8; 32],
    pub sealed: bool,
}

#[derive(Clone, Debug)]
pub struct LaneState {
    pub next_seq: u64,
    pub tail_hash: [u8; 32],
    pub next_segment_id: u64,
    pub durable_through_seq: u64,
    pub segments: VecDeque<SegmentMeta>,
    pub total_bytes: u64,
}

impl SpoolLane {
    #[must_use]
    pub const fn dir_name(self) -> &'static str {
        match self {
            Self::Decision => "decision",
            Self::Spine => "spine",
            Self::Evidence => "evidence",
            Self::Bulk => "bulk",
        }
    }

    #[must_use]
    pub const fn all() -> [Self; 4] {
        [Self::Decision, Self::Spine, Self::Evidence, Self::Bulk]
    }

    pub fn from_byte(raw: u8) -> Result<Self, SpoolError> {
        match raw {
            0 => Ok(Self::Decision),
            1 => Ok(Self::Spine),
            2 => Ok(Self::Evidence),
            3 => Ok(Self::Bulk),
            other => Err(SpoolError::ChainCorrupt {
                path: String::new(),
                detail: format!("invalid lane byte {other}"),
            }),
        }
    }
}

pub use crate::spool_recover::{
    read_segment_records, read_segment_records_for_lane, recover_lane, recover_lane_with_gaps,
};

pub fn ensure_active_segment(
    root: &Path,
    lane: SpoolLane,
    state: &mut LaneState,
    segment_bytes: u64,
    incoming_len: u64,
) -> Result<PathBuf, SpoolError> {
    let rotate = match state.segments.back() {
        None => true,
        Some(active) => {
            active.sealed
                || (active.bytes > 0 && active.bytes.saturating_add(incoming_len) > segment_bytes)
        }
    };
    if !rotate && let Some(active) = state.segments.back() {
        return Ok(active.path.clone());
    }
    if let Some(prev) = state.segments.back_mut() {
        prev.sealed = true;
    }
    let seg_id = state.next_segment_id;
    state.next_segment_id = seg_id.checked_add(1).ok_or_else(|| SpoolError::Io {
        detail: "spool segment ID counter overflow".to_string(),
    })?;
    let seg_path = root
        .join(lane.dir_name())
        .join(format!("seg-{seg_id:08}.seg"));
    let _file = open_nofollow_append_create(&seg_path).map_err(|err| SpoolError::Io {
        detail: format!("create segment {}: {err}", redact_path_label(&seg_path)),
    })?;
    sync_parent_dir(&seg_path).map_err(|detail| SpoolError::Io { detail })?;
    state.segments.push_back(SegmentMeta {
        segment_id: seg_id,
        lane,
        path: seg_path.clone(),
        bytes: 0,
        first_seq: 0,
        last_seq: 0,
        first_prev_hash: state.tail_hash,
        last_hash: state.tail_hash,
        sealed: false,
    });
    Ok(seg_path)
}

pub fn append_bytes(path: &Path, bytes: &[u8], fsync: bool) -> Result<(), SpoolError> {
    let mut file = open_nofollow_append_create(path).map_err(|err| SpoolError::Io {
        detail: format!("open segment {}: {err}", redact_path_label(path)),
    })?;
    let prior_len = file
        .metadata()
        .map_err(|err| SpoolError::Io {
            detail: format!("stat segment {}: {err}", redact_path_label(path)),
        })?
        .len();
    if let Err(err) = file.write_all(bytes) {
        let _ = file.set_len(prior_len);
        let _ = file.sync_all();
        return Err(SpoolError::Io {
            detail: format!("write segment {}: {err}", redact_path_label(path)),
        });
    }
    if fsync && let Err(err) = file.sync_all() {
        let _ = file.set_len(prior_len);
        let _ = file.sync_all();
        return Err(SpoolError::Io {
            detail: format!("fsync segment {}: {err}", redact_path_label(path)),
        });
    }
    Ok(())
}

pub fn compute_entry_hash(
    seq: u64,
    lane: SpoolLane,
    flags: u8,
    prev_hash: &[u8; 32],
    payload: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256Hasher::new();
    hasher.update(HASH_DOMAIN);
    hasher.update(&seq.to_le_bytes());
    hasher.update(&[lane as u8, flags]);
    hasher.update(prev_hash);
    hasher.update(payload);
    hasher.finalize_digest()
}

pub fn encode_record(
    seq: u64,
    lane: SpoolLane,
    flags: u8,
    prev_hash: &[u8; 32],
    entry_hash: &[u8; 32],
    payload: &[u8],
) -> Result<Vec<u8>, SpoolError> {
    if payload.len() > MAX_SPOOL_RECORD_BYTES {
        return Err(SpoolError::RecordTooLarge {
            len: payload.len(),
            max: MAX_SPOOL_RECORD_BYTES,
        });
    }
    let payload_len = u32::try_from(payload.len()).map_err(|_| SpoolError::RecordTooLarge {
        len: payload.len(),
        max: MAX_SPOOL_RECORD_BYTES,
    })?;
    let crc = compute_record_crc(seq, lane, flags, prev_hash, entry_hash, payload)?;
    let mut out = Vec::with_capacity(RECORD_HEADER_LEN.saturating_add(payload.len()));
    out.extend_from_slice(&RECORD_MAGIC);
    out.extend_from_slice(&seq.to_le_bytes());
    out.push(lane as u8);
    out.push(flags);
    out.extend_from_slice(prev_hash);
    out.extend_from_slice(entry_hash);
    out.extend_from_slice(&payload_len.to_le_bytes());
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

pub(crate) fn compute_record_crc(
    seq: u64,
    lane: SpoolLane,
    flags: u8,
    prev_hash: &[u8; 32],
    entry_hash: &[u8; 32],
    payload: &[u8],
) -> Result<u32, SpoolError> {
    if payload.len() > MAX_SPOOL_RECORD_BYTES {
        return Err(SpoolError::RecordTooLarge {
            len: payload.len(),
            max: MAX_SPOOL_RECORD_BYTES,
        });
    }
    let payload_len = u32::try_from(payload.len()).map_err(|_| SpoolError::RecordTooLarge {
        len: payload.len(),
        max: MAX_SPOOL_RECORD_BYTES,
    })?;
    let mut hdr = [0u8; 82];
    if let Some(slot) = hdr.get_mut(..4) {
        slot.copy_from_slice(&RECORD_MAGIC);
    }
    if let Some(slot) = hdr.get_mut(4..12) {
        slot.copy_from_slice(&seq.to_le_bytes());
    }
    if let Some(b) = hdr.get_mut(12) {
        *b = lane as u8;
    }
    if let Some(b) = hdr.get_mut(13) {
        *b = flags;
    }
    if let Some(slot) = hdr.get_mut(14..46) {
        slot.copy_from_slice(prev_hash);
    }
    if let Some(slot) = hdr.get_mut(46..78) {
        slot.copy_from_slice(entry_hash);
    }
    if let Some(slot) = hdr.get_mut(78..82) {
        slot.copy_from_slice(&payload_len.to_le_bytes());
    }
    let crc = crc32c_append(0, &hdr);
    Ok(crc32c_append(crc, payload))
}
