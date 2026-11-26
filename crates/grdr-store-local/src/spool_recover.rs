// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Segment recovery, cross-segment chain checks, and torn crash-tail truncation.

use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};

use crate::fs_hardening::{
    ensure_private_dir_all, is_symlink_or_reparse, read_bounded_nofollow, redact_path_label,
    set_private_file_perms, sync_parent_dir,
};
use crate::spool_io::{
    FLAG_DECISION_FSYNC, FLAG_GAP, FLAG_NORMAL, LaneState, MAX_SPOOL_RECORD_BYTES,
    RECORD_HEADER_LEN, RECORD_MAGIC, SegmentMeta, SpoolError, SpoolGapRecord, SpoolLane,
    SpoolRecord, compute_entry_hash, compute_record_crc,
};

const MAX_SEGMENT_READ_BYTES: usize = 16 * 1024 * 1024;

pub fn recover_lane(lane_dir: &Path, lane: SpoolLane) -> Result<LaneState, SpoolError> {
    let (state, _gaps) = recover_lane_with_gaps(lane_dir, lane)?;
    Ok(state)
}

pub fn recover_lane_with_gaps(
    lane_dir: &Path,
    lane: SpoolLane,
) -> Result<(LaneState, Vec<SpoolGapRecord>), SpoolError> {
    ensure_private_dir_all(lane_dir).map_err(|detail| SpoolError::Io { detail })?;
    let mut files = collect_sorted_segments(lane_dir)?;
    while let Some((_, tail_path)) = files.last() {
        let meta = fs::symlink_metadata(tail_path).map_err(|err| SpoolError::Io {
            detail: format!("stat segment {}: {err}", redact_path_label(tail_path)),
        })?;
        if meta.len() == 0 {
            let orphan = tail_path.clone();
            fs::remove_file(&orphan).map_err(|err| SpoolError::Io {
                detail: format!(
                    "remove empty tail segment {}: {err}",
                    redact_path_label(&orphan)
                ),
            })?;
            sync_parent_dir(&orphan).map_err(|detail| SpoolError::Io { detail })?;
            files.pop();
        } else {
            break;
        }
    }

    let mut segments = VecDeque::new();
    let mut recovered_gaps = Vec::new();
    let mut prior_chain: Option<(u64, [u8; 32])> = None;
    let mut next_seq: u64 = 1;
    let mut tail_hash = [0u8; 32];
    let mut total_bytes: u64 = 0;
    let mut max_seg_id: u64 = 0;
    let total_files = files.len();

    for (idx, (seg_id, path)) in files.into_iter().enumerate() {
        max_seg_id = max_seg_id.max(seg_id);
        let is_last = idx.saturating_add(1) == total_files;
        let (recs, actual_len) = read_segment_records_internal(&path, Some(lane), is_last)?;
        if recs.is_empty() {
            if is_last {
                fs::remove_file(&path).map_err(|err| SpoolError::Io {
                    detail: format!("remove empty segment {}: {err}", redact_path_label(&path)),
                })?;
                sync_parent_dir(&path).map_err(|detail| SpoolError::Io { detail })?;
                continue;
            }
            return Err(SpoolError::ChainCorrupt {
                path: redact_path_label(&path),
                detail: "unexpected empty sealed segment".to_string(),
            });
        }
        let (Some(first), Some(last)) = (recs.first(), recs.last()) else {
            continue;
        };

        if let Some((prev_last_seq, prev_last_hash)) = prior_chain {
            let expected_seq =
                prev_last_seq
                    .checked_add(1)
                    .ok_or_else(|| SpoolError::ChainCorrupt {
                        path: redact_path_label(&path),
                        detail: "spool sequence overflow".to_string(),
                    })?;
            if first.seq != expected_seq || first.prev_hash != prev_last_hash {
                return Err(SpoolError::ChainCorrupt {
                    path: redact_path_label(&path),
                    detail: "cross-segment seq or prev_hash discontinuity".to_string(),
                });
            }
        }

        for rec in &recs {
            if rec.is_gap
                && let Ok(parsed_gap) = serde_json::from_slice::<SpoolGapRecord>(&rec.payload)
            {
                recovered_gaps.push(parsed_gap);
            }
        }

        let seg_bytes = u64::try_from(actual_len).unwrap_or(0);
        total_bytes = total_bytes.saturating_add(seg_bytes);
        next_seq = last
            .seq
            .checked_add(1)
            .ok_or_else(|| SpoolError::ChainCorrupt {
                path: redact_path_label(&path),
                detail: "spool sequence counter overflow".to_string(),
            })?;
        tail_hash = last.entry_hash;
        prior_chain = Some((last.seq, last.entry_hash));

        segments.push_back(SegmentMeta {
            segment_id: seg_id,
            lane,
            path,
            bytes: seg_bytes,
            first_seq: first.seq,
            last_seq: last.seq,
            first_prev_hash: first.prev_hash,
            last_hash: last.entry_hash,
            sealed: !is_last,
        });
    }

    let next_segment_id = max_seg_id.checked_add(1).ok_or_else(|| SpoolError::Io {
        detail: "segment id overflow on recover".to_string(),
    })?;

    Ok((
        LaneState {
            next_seq,
            tail_hash,
            next_segment_id,
            durable_through_seq: 0,
            segments,
            total_bytes,
        },
        recovered_gaps,
    ))
}

pub fn read_segment_records(path: &Path) -> Result<Vec<SpoolRecord>, SpoolError> {
    let (recs, _len) = read_segment_records_internal(path, None, false)?;
    Ok(recs)
}

pub fn read_segment_records_for_lane(
    path: &Path,
    expected_lane: SpoolLane,
) -> Result<Vec<SpoolRecord>, SpoolError> {
    let (recs, _len) = read_segment_records_internal(path, Some(expected_lane), false)?;
    Ok(recs)
}

fn collect_sorted_segments(lane_dir: &Path) -> Result<Vec<(u64, PathBuf)>, SpoolError> {
    let entries = fs::read_dir(lane_dir).map_err(|err| SpoolError::Io {
        detail: format!("read lane dir {}: {err}", redact_path_label(lane_dir)),
    })?;
    let mut files = Vec::new();
    for entry_res in entries {
        let entry = entry_res.map_err(|err| SpoolError::Io {
            detail: format!("iterate lane dir {}: {err}", redact_path_label(lane_dir)),
        })?;
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).map_err(|err| SpoolError::Io {
            detail: format!("stat segment {}: {err}", redact_path_label(&path)),
        })?;
        if is_symlink_or_reparse(&meta) {
            return Err(SpoolError::ChainCorrupt {
                path: redact_path_label(&path),
                detail: "refusing symlink inside spool lane".to_string(),
            });
        }
        if let Some(seg_id) = parse_segment_id(&path) {
            set_private_file_perms(&path).map_err(|detail| SpoolError::Io { detail })?;
            files.push((seg_id, path));
        }
    }
    files.sort_by_key(|(id, _)| *id);
    Ok(files)
}

fn read_segment_records_internal(
    path: &Path,
    expected_lane: Option<SpoolLane>,
    recover_torn_tail: bool,
) -> Result<(Vec<SpoolRecord>, usize), SpoolError> {
    let raw =
        read_bounded_nofollow(path, MAX_SEGMENT_READ_BYTES).map_err(|err| SpoolError::Io {
            detail: format!("read segment {}: {err}", redact_path_label(path)),
        })?;
    let label = redact_path_label(path);
    let mut pos: usize = 0;
    let mut records: Vec<SpoolRecord> = Vec::new();
    let mut prev_seq_hash: Option<(u64, [u8; 32])> = None;

    while pos < raw.len() {
        let remaining = raw.len().saturating_sub(pos);
        if remaining < RECORD_HEADER_LEN {
            if recover_torn_tail {
                truncate_torn_tail(path, pos)?;
                return Ok((records, pos));
            }
            return Err(SpoolError::ChainCorrupt {
                path: label,
                detail: "truncated record header in segment".to_string(),
            });
        }
        let header = raw
            .get(pos..pos.saturating_add(RECORD_HEADER_LEN))
            .ok_or_else(|| SpoolError::ChainCorrupt {
                path: label.clone(),
                detail: "missing record header slice".to_string(),
            })?;
        if header.get(..4) != Some(&RECORD_MAGIC[..]) {
            return Err(SpoolError::ChainCorrupt {
                path: label,
                detail: "invalid GRSP magic".to_string(),
            });
        }
        let seq = read_u64_slice(header, 4)?;
        if seq == 0 {
            return Err(SpoolError::ChainCorrupt {
                path: label,
                detail: "record sequence number 0 is invalid".to_string(),
            });
        }
        let lane = SpoolLane::from_byte(header.get(12).copied().unwrap_or(u8::MAX))?;
        if let Some(exp_lane) = expected_lane
            && lane != exp_lane
        {
            return Err(SpoolError::ChainCorrupt {
                path: label,
                detail: format!(
                    "record lane {} != expected {}",
                    lane.dir_name(),
                    exp_lane.dir_name()
                ),
            });
        }
        let flags = header.get(13).copied().unwrap_or(u8::MAX);
        if flags != FLAG_NORMAL && flags != FLAG_GAP && flags != FLAG_DECISION_FSYNC {
            return Err(SpoolError::ChainCorrupt {
                path: label,
                detail: format!("unknown record flag byte {flags}"),
            });
        }
        let prev_hash = read_32_slice(header, 14)?;
        let entry_hash = read_32_slice(header, 46)?;
        let payload_len = usize::try_from(read_u32_slice(header, 78)?).unwrap_or(usize::MAX);
        let expected_crc = read_u32_slice(header, 82)?;
        if payload_len > MAX_SPOOL_RECORD_BYTES {
            return Err(SpoolError::RecordTooLarge {
                len: payload_len,
                max: MAX_SPOOL_RECORD_BYTES,
            });
        }

        let payload_start = pos.saturating_add(RECORD_HEADER_LEN);
        let payload_end =
            payload_start
                .checked_add(payload_len)
                .ok_or_else(|| SpoolError::ChainCorrupt {
                    path: label.clone(),
                    detail: "record length overflow".to_string(),
                })?;
        if payload_end > raw.len() {
            if recover_torn_tail {
                truncate_torn_tail(path, pos)?;
                return Ok((records, pos));
            }
            return Err(SpoolError::ChainCorrupt {
                path: label,
                detail: "truncated record payload".to_string(),
            });
        }
        let payload = raw.get(payload_start..payload_end).unwrap_or(&[]);

        if compute_record_crc(seq, lane, flags, &prev_hash, &entry_hash, payload)? != expected_crc {
            return Err(SpoolError::ChainCorrupt {
                path: label,
                detail: format!("CRC-32C mismatch at seq {seq}"),
            });
        }
        if compute_entry_hash(seq, lane, flags, &prev_hash, payload) != entry_hash {
            return Err(SpoolError::ChainCorrupt {
                path: label,
                detail: format!("SHA-256 entry_hash mismatch at seq {seq}"),
            });
        }
        if let Some((prev_seq, prev_entry_hash)) = prev_seq_hash {
            let expected_seq = prev_seq
                .checked_add(1)
                .ok_or_else(|| SpoolError::ChainCorrupt {
                    path: label.clone(),
                    detail: "sequence overflow in segment".to_string(),
                })?;
            if seq != expected_seq || prev_hash != prev_entry_hash {
                return Err(SpoolError::ChainCorrupt {
                    path: label,
                    detail: format!("seq or prev_hash discontinuity at seq {seq}"),
                });
            }
        }

        prev_seq_hash = Some((seq, entry_hash));
        records.push(SpoolRecord {
            seq,
            lane,
            is_gap: flags == FLAG_GAP,
            fsynced: flags == FLAG_DECISION_FSYNC,
            prev_hash,
            entry_hash,
            payload: payload.to_vec(),
        });
        pos = payload_end;
    }

    Ok((records, raw.len()))
}

fn truncate_torn_tail(path: &Path, valid_len: usize) -> Result<(), SpoolError> {
    let valid_u64 = u64::try_from(valid_len).unwrap_or(0);
    let mut opts = OpenOptions::new();
    opts.write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let file = opts.open(path).map_err(|err| SpoolError::Io {
        detail: format!("open segment tail {}: {err}", redact_path_label(path)),
    })?;
    file.set_len(valid_u64).map_err(|err| SpoolError::Io {
        detail: format!("truncate torn tail {}: {err}", redact_path_label(path)),
    })?;
    file.sync_all().map_err(|err| SpoolError::Io {
        detail: format!("sync truncated segment {}: {err}", redact_path_label(path)),
    })?;
    Ok(())
}

fn parse_segment_id(path: &Path) -> Option<u64> {
    let name = path.file_name()?.to_str()?;
    name.strip_prefix("seg-")?
        .strip_suffix(".seg")?
        .parse::<u64>()
        .ok()
}

fn read_u64_slice(src: &[u8], offset: usize) -> Result<u64, SpoolError> {
    let raw =
        src.get(offset..offset.saturating_add(8))
            .ok_or_else(|| SpoolError::ChainCorrupt {
                path: String::new(),
                detail: "truncated u64 field".to_string(),
            })?;
    let mut arr = [0u8; 8];
    arr.copy_from_slice(raw);
    Ok(u64::from_le_bytes(arr))
}

fn read_u32_slice(src: &[u8], offset: usize) -> Result<u32, SpoolError> {
    let raw =
        src.get(offset..offset.saturating_add(4))
            .ok_or_else(|| SpoolError::ChainCorrupt {
                path: String::new(),
                detail: "truncated u32 field".to_string(),
            })?;
    let mut arr = [0u8; 4];
    arr.copy_from_slice(raw);
    Ok(u32::from_le_bytes(arr))
}

fn read_32_slice(src: &[u8], offset: usize) -> Result<[u8; 32], SpoolError> {
    let raw =
        src.get(offset..offset.saturating_add(32))
            .ok_or_else(|| SpoolError::ChainCorrupt {
                path: String::new(),
                detail: "truncated 32-byte hash".to_string(),
            })?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(raw);
    Ok(arr)
}

pub(crate) fn verify_exact_seq_hash(
    state: &LaneState,
    lane: SpoolLane,
    target_seq: u64,
    expected_hash: &[u8; 32],
) -> Result<bool, SpoolError> {
    if state.next_seq > 1 && target_seq == state.next_seq.saturating_sub(1) {
        return Ok(ct_eq_32(&state.tail_hash, expected_hash));
    }
    for seg in &state.segments {
        if seg.last_seq == target_seq {
            return Ok(ct_eq_32(&seg.last_hash, expected_hash));
        }
        if seg.first_seq > 0 && target_seq >= seg.first_seq && target_seq < seg.last_seq {
            for rec in read_segment_records_for_lane(&seg.path, lane)? {
                if rec.seq == target_seq {
                    return Ok(ct_eq_32(&rec.entry_hash, expected_hash));
                }
            }
            return Ok(false);
        }
    }
    Ok(false)
}

fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter()
        .zip(b.iter())
        .fold(0u8, |diff, (x, y)| diff | (x ^ y))
        == 0
}

pub(crate) fn decode_hex_32(hex: &str) -> Result<[u8; 32], SpoolError> {
    let trimmed = hex.trim();
    if trimmed.len() != 64
        || !trimmed
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(SpoolError::ChainCorrupt {
            path: String::new(),
            detail: "durable_through hash must be 64 lowercase hex characters".to_string(),
        });
    }
    let mut out = [0u8; 32];
    for (idx, chunk) in trimmed.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let [b0, b1] = *chunk;
        let hi = hex_nibble(b0)?;
        let lo = hex_nibble(b1)?;
        if let Some(slot) = out.get_mut(idx) {
            *slot = (hi << 4) | lo;
        }
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, SpoolError> {
    match b {
        b'0'..=b'9' => Ok(b.saturating_sub(b'0')),
        b'a'..=b'f' => Ok(b.saturating_sub(b'a').saturating_add(10)),
        _ => Err(SpoolError::ChainCorrupt {
            path: String::new(),
            detail: "invalid hex digit in durable_through hash".to_string(),
        }),
    }
}
