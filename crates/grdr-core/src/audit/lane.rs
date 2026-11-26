// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use grdr_crypto::constant_time_eq;
use grdr_schema::{AuditLane, CommitmentClass, FiveWayCommitments};

use super::commitments::verify_five_way_commitments_with_withheld;
use super::merkle::verify_lane_merkle_checkpoint;
use super::{
    AuditLogFormat, AuditVerifyError, AuditVerifySummary, GENESIS_PREV_HASH,
    normalize_prefixed_digest, sha256_framed,
};

const GENESIS_LANE_DOMAIN: &[u8] = b"grdr.audit.lane_genesis.v1\0";
const LANE_ENTRY_DOMAIN: &[u8] = b"grdr.audit.lane_entry.v1\0";
const COMPOSITE_HEAD_DOMAIN: &[u8] = b"grdr.audit.composite_head.v1\0";
const MAX_DEVICE_ID_BYTES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleInclusionInput<'a> {
    pub leaf: &'a [u8],
    pub leaf_index: u64,
    pub tree_size: u64,
    pub audit_path: &'a [String],
    pub expected_root: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleConsistencyInput<'a> {
    pub first_size: u64,
    pub second_size: u64,
    pub first_root: &'a str,
    pub second_root: &'a str,
    pub proof: &'a [String],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaneChainAnchor {
    pub device_id: String,
    pub epoch: u64,
    pub prev_epoch_final_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExpectedAnchor {
    pub device_id: Option<String>,
    pub epoch: Option<u64>,
    pub head_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaneEntryKind<'a> {
    Event {
        commitments: &'a FiveWayCommitments,
        commitment_root_digest: &'a str,
        payloads: [Option<&'a [u8]>; 5],
        withheld_classes: Option<&'a [CommitmentClass]>,
        merkle: Option<Box<MerkleInclusionInput<'a>>>,
        merkle_consistency: Option<Box<MerkleConsistencyInput<'a>>>,
    },
    Gap {
        start_seq: u64,
        end_seq: u64,
        dropped_count: u64,
        reason: &'a str,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaneAuditRecord<'a> {
    pub line: usize,
    pub epoch: u64,
    pub lane: AuditLane,
    pub seq: u64,
    pub prev_hash: &'a str,
    pub entry_hash: &'a str,
    pub kind: LaneEntryKind<'a>,
}

struct LaneCursor {
    last_seq: u64,
    expected_prev: String,
    last_merkle: Option<(u64, String)>,
}

fn lane_err(line: usize, detail: impl Into<String>) -> AuditVerifyError {
    AuditVerifyError::InvalidLaneRecord {
        line,
        detail: detail.into(),
    }
}

pub fn lane_genesis_hash(
    device_id: &str,
    epoch: u64,
    lane: AuditLane,
    prev_epoch_final_hash: Option<&str>,
) -> Result<String, AuditVerifyError> {
    if device_id.trim().is_empty()
        || device_id.contains('\0')
        || device_id.len() > MAX_DEVICE_ID_BYTES
    {
        return Err(lane_err(0, "invalid anchor device_id"));
    }
    let prev = match prev_epoch_final_hash {
        Some(raw) => normalize_prefixed_digest(raw)
            .ok_or_else(|| lane_err(0, "invalid anchor prev_epoch_final_hash"))?,
        None if epoch > 1 => return Err(lane_err(0, "epoch > 1 requires prev_epoch_final_hash")),
        None => GENESIS_PREV_HASH.to_string(),
    };
    let ep = epoch.to_be_bytes();
    Ok(sha256_framed(
        GENESIS_LANE_DOMAIN,
        &[
            device_id.as_bytes(),
            &ep,
            lane.as_str().as_bytes(),
            prev.as_bytes(),
        ],
    ))
}

pub fn compute_lane_entry_hash(
    prev_hash: &str,
    epoch: u64,
    lane: AuditLane,
    seq: u64,
    kind: &LaneEntryKind<'_>,
) -> Result<String, AuditVerifyError> {
    let norm_prev =
        normalize_prefixed_digest(prev_hash).ok_or_else(|| AuditVerifyError::MalformedEntry {
            line: 0,
            detail: "invalid prev_hash digest".into(),
        })?;
    let ep = epoch.to_be_bytes();
    let seq_b = seq.to_be_bytes();
    match kind {
        LaneEntryKind::Event {
            commitment_root_digest,
            ..
        } => {
            let norm_root = normalize_prefixed_digest(commitment_root_digest).ok_or_else(|| {
                AuditVerifyError::CommitmentMismatch {
                    line: 0,
                    class_label: "root",
                    detail: "malformed commitment_root_digest".into(),
                }
            })?;
            Ok(sha256_framed(
                LANE_ENTRY_DOMAIN,
                &[
                    norm_prev.as_bytes(),
                    &ep,
                    lane.as_str().as_bytes(),
                    &seq_b,
                    b"event",
                    norm_root.as_bytes(),
                ],
            ))
        }
        LaneEntryKind::Gap {
            start_seq,
            end_seq,
            dropped_count,
            reason,
        } => Ok(sha256_framed(
            LANE_ENTRY_DOMAIN,
            &[
                norm_prev.as_bytes(),
                &ep,
                lane.as_str().as_bytes(),
                &seq_b,
                b"gap",
                &start_seq.to_be_bytes(),
                &end_seq.to_be_bytes(),
                &dropped_count.to_be_bytes(),
                reason.as_bytes(),
            ],
        )),
    }
}

pub fn verify_lane_audit_chain(
    entries: &[LaneAuditRecord<'_>],
    anchor: &LaneChainAnchor,
) -> Result<AuditVerifySummary, AuditVerifyError> {
    verify_lane_audit_chain_with_expected(entries, anchor, None)
}

pub fn verify_lane_audit_chain_with_expected(
    entries: &[LaneAuditRecord<'_>],
    anchor: &LaneChainAnchor,
    expected: Option<&ExpectedAnchor>,
) -> Result<AuditVerifySummary, AuditVerifyError> {
    if entries.is_empty() {
        return Err(AuditVerifyError::EmptyLog);
    }
    validate_expected_anchor(anchor, expected)?;
    let mut cursors: BTreeMap<(AuditLane, u64), LaneCursor> = BTreeMap::new();
    let mut active_epoch: Option<u64> = None;

    for entry in entries {
        if let Some(prev_ep) = active_epoch
            && entry.epoch != prev_ep
        {
            let msg = if entry.epoch < prev_ep {
                "epoch regression rejected"
            } else {
                "unlinked epoch transition rejected"
            };
            return Err(lane_err(entry.line, msg));
        }
        active_epoch = Some(entry.epoch);
        let key = (entry.lane, entry.epoch);
        let expected_prev = match cursors.get(&key) {
            Some(c) => c.expected_prev.clone(),
            None => {
                if anchor.epoch != entry.epoch {
                    return Err(lane_err(entry.line, "epoch mismatch against anchor"));
                }
                lane_genesis_hash(
                    &anchor.device_id,
                    entry.epoch,
                    entry.lane,
                    anchor.prev_epoch_final_hash.as_deref(),
                )?
            }
        };
        let norm_prev = normalize_prefixed_digest(entry.prev_hash).ok_or_else(|| {
            AuditVerifyError::MalformedEntry {
                line: entry.line,
                detail: "invalid prev_hash digest".into(),
            }
        })?;
        if !constant_time_eq(norm_prev.as_bytes(), expected_prev.as_bytes()) {
            return Err(AuditVerifyError::BrokenChainLink {
                line: entry.line,
                expected_prev,
                actual_prev: norm_prev,
            });
        }
        let norm_entry_hash = normalize_prefixed_digest(entry.entry_hash).ok_or_else(|| {
            AuditVerifyError::MalformedEntry {
                line: entry.line,
                detail: "invalid entry_hash digest".into(),
            }
        })?;
        let computed =
            compute_lane_entry_hash(&norm_prev, entry.epoch, entry.lane, entry.seq, &entry.kind)
                .map_err(|mut err| {
                    match &mut err {
                        AuditVerifyError::MalformedEntry { line, .. }
                        | AuditVerifyError::CommitmentMismatch { line, .. } => *line = entry.line,
                        _ => {}
                    }
                    err
                })?;
        if !constant_time_eq(norm_entry_hash.as_bytes(), computed.as_bytes()) {
            return Err(AuditVerifyError::HashMismatch {
                line: entry.line,
                expected: computed,
                actual: norm_entry_hash,
            });
        }
        let prev_seq = cursors.get(&key).map(|c| c.last_seq);
        let prev_merkle = cursors.get(&key).and_then(|c| c.last_merkle.as_ref());
        let (next_last_seq, next_merkle) =
            verify_entry_kind(entry, &norm_entry_hash, prev_seq, prev_merkle)?;
        cursors.insert(
            key,
            LaneCursor {
                last_seq: next_last_seq,
                expected_prev: norm_entry_hash,
                last_merkle: next_merkle,
            },
        );
    }

    let head_hash = compute_composite_head(&cursors);
    if let Some(exp_head_raw) = expected.and_then(|e| e.head_hash.as_deref()) {
        let exp_head = normalize_prefixed_digest(exp_head_raw).ok_or_else(|| {
            AuditVerifyError::MalformedEntry {
                line: 0,
                detail: "invalid expected head_hash".into(),
            }
        })?;
        if !constant_time_eq(head_hash.as_bytes(), exp_head.as_bytes()) {
            return Err(AuditVerifyError::HashMismatch {
                line: entries.last().map_or(0, |e| e.line),
                expected: exp_head,
                actual: head_hash,
            });
        }
    }
    Ok(AuditVerifySummary {
        verified: true,
        entries: entries.len(),
        format: AuditLogFormat::LaneChain,
        head_hash,
    })
}

fn validate_expected_anchor(
    anchor: &LaneChainAnchor,
    expected: Option<&ExpectedAnchor>,
) -> Result<(), AuditVerifyError> {
    let _ = lane_genesis_hash(
        &anchor.device_id,
        anchor.epoch,
        AuditLane::Event,
        anchor.prev_epoch_final_hash.as_deref(),
    )?;
    let Some(exp) = expected else {
        return Ok(());
    };
    if let Some(ref exp_dev) = exp.device_id
        && &anchor.device_id != exp_dev
    {
        return Err(lane_err(0, "anchor device_id mismatch"));
    }
    if let Some(exp_ep) = exp.epoch
        && anchor.epoch != exp_ep
    {
        return Err(lane_err(0, "anchor epoch mismatch"));
    }
    Ok(())
}

fn verify_entry_kind(
    entry: &LaneAuditRecord<'_>,
    norm_entry_hash: &str,
    prev_seq: Option<u64>,
    prev_merkle: Option<&(u64, String)>,
) -> Result<(u64, Option<(u64, String)>), AuditVerifyError> {
    match &entry.kind {
        LaneEntryKind::Event {
            commitments,
            commitment_root_digest,
            payloads,
            withheld_classes,
            merkle,
            merkle_consistency,
        } => {
            verify_seq_progression(entry.line, prev_seq, entry.seq, false)?;
            let verified_root = verify_five_way_commitments_with_withheld(
                entry.line,
                commitments,
                *payloads,
                *withheld_classes,
                Some(commitment_root_digest),
            )?;
            let next_merkle = verify_lane_merkle_checkpoint(
                entry.line,
                norm_entry_hash,
                &verified_root,
                prev_merkle,
                merkle.as_deref(),
                merkle_consistency.as_deref(),
            )?;
            Ok((entry.seq, next_merkle))
        }
        LaneEntryKind::Gap {
            start_seq,
            end_seq,
            dropped_count,
            reason,
        } => {
            let span = end_seq
                .checked_sub(*start_seq)
                .and_then(|d| d.checked_add(1));
            if reason.trim().is_empty() || span != Some(*dropped_count) || entry.seq != *start_seq {
                return Err(AuditVerifyError::InvalidGapRecord {
                    line: entry.line,
                    detail: "invalid gap bounds, count, or reason".into(),
                });
            }
            verify_seq_progression(entry.line, prev_seq, *start_seq, true)?;
            Ok((*end_seq, prev_merkle.cloned()))
        }
    }
}

fn verify_seq_progression(
    line: usize,
    prev_seq: Option<u64>,
    actual: u64,
    is_gap: bool,
) -> Result<(), AuditVerifyError> {
    match prev_seq {
        Some(prev) => {
            let next = prev.checked_add(1).ok_or_else(|| {
                if is_gap {
                    AuditVerifyError::InvalidGapRecord {
                        line,
                        detail: "seq overflow".into(),
                    }
                } else {
                    lane_err(line, "seq overflow")
                }
            })?;
            if actual != next {
                if is_gap {
                    return Err(AuditVerifyError::InvalidGapRecord {
                        line,
                        detail: format!("expected gap start {next}, got {actual}"),
                    });
                }
                return Err(AuditVerifyError::SequenceGap {
                    line,
                    expected: next,
                    actual,
                });
            }
            Ok(())
        }
        None if actual > 1 => Err(AuditVerifyError::SequenceGap {
            line,
            expected: 0,
            actual,
        }),
        None => Ok(()),
    }
}

fn compute_composite_head(cursors: &BTreeMap<(AuditLane, u64), LaneCursor>) -> String {
    if cursors.len() == 1
        && let Some(only) = cursors.values().next()
    {
        return only.expected_prev.clone();
    }
    let mut items: Vec<Vec<u8>> = Vec::with_capacity(cursors.len().saturating_mul(4));
    for ((lane, epoch), cursor) in cursors {
        items.push(lane.as_str().as_bytes().to_vec());
        items.push(epoch.to_be_bytes().to_vec());
        items.push(cursor.last_seq.to_be_bytes().to_vec());
        items.push(cursor.expected_prev.as_bytes().to_vec());
    }
    let refs: Vec<&[u8]> = items.iter().map(Vec::as_slice).collect();
    sha256_framed(COMPOSITE_HEAD_DOMAIN, &refs)
}
