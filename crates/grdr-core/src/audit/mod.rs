// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

pub mod commitments;
pub mod lane;
pub mod merkle;

use grdr_crypto::{Sha256Hasher, constant_time_eq};
pub use grdr_schema::{AuditLane, CommitmentClass, FiveWayCommitments};
use serde::{Deserialize, Serialize};

use grdr_model::DecisionReceipt;

use crate::analyze::normalize_attempt_target;
use crate::policy::{ReceiptDigestInput, compute_receipt_digest};

pub use commitments::{
    MAX_COMMITMENT_SALT_BYTES, MIN_COMMITMENT_SALT_BYTES, build_five_way_commitments,
    compute_class_commitment, compute_commitment_root_digest, generate_five_way_salts,
    verify_five_way_commitments, verify_five_way_commitments_with_withheld,
    withheld_classes_for_capture_level,
};
pub use lane::{
    ExpectedAnchor, LaneAuditRecord, LaneChainAnchor, LaneEntryKind, MerkleConsistencyInput,
    MerkleInclusionInput, compute_lane_entry_hash, lane_genesis_hash, verify_lane_audit_chain,
    verify_lane_audit_chain_with_expected,
};
pub use merkle::{
    merkle_consistency_proof, merkle_hash_children, merkle_hash_leaf, merkle_inclusion_proof,
    merkle_root_hex, verify_merkle_consistency, verify_merkle_inclusion,
};

pub const GENESIS_PREV_HASH: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const GENESIS_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const CHAIN_DOMAIN: &[u8] = b"grdr.audit.chain.v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditLogFormat {
    HashChain,
    ReceiptWal,
    LaneChain,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuditVerifyError {
    #[error("GRDR-AUDIT-0001: audit log not found at {path}")]
    NotFound { path: String },
    #[error("GRDR-AUDIT-0002: audit log is empty (zero entries)")]
    EmptyLog,
    #[error("GRDR-AUDIT-0003: malformed audit entry at line {line}: {detail}")]
    MalformedEntry { line: usize, detail: String },
    #[error(
        "GRDR-AUDIT-0004: broken chain link at line {line} (expected prev {expected_prev}, got {actual_prev})"
    )]
    BrokenChainLink {
        line: usize,
        expected_prev: String,
        actual_prev: String,
    },
    #[error(
        "GRDR-AUDIT-0005: entry hash mismatch at line {line} (expected {expected}, got {actual})"
    )]
    HashMismatch {
        line: usize,
        expected: String,
        actual: String,
    },
    #[error("GRDR-AUDIT-0006: sequence gap at line {line} (expected {expected}, got {actual})")]
    SequenceGap {
        line: usize,
        expected: u64,
        actual: u64,
    },
    #[error(
        "GRDR-AUDIT-0007: five-way commitment mismatch for {class_label} at line {line}: {detail}"
    )]
    CommitmentMismatch {
        line: usize,
        class_label: &'static str,
        detail: String,
    },
    #[error("GRDR-AUDIT-0008: RFC 6962 Merkle proof mismatch at line {line}: {detail}")]
    MerkleProofMismatch { line: usize, detail: String },
    #[error("GRDR-AUDIT-0009: invalid audit gap record at line {line}: {detail}")]
    InvalidGapRecord { line: usize, detail: String },
    #[error("GRDR-AUDIT-0010: invalid lane audit record at line {line}: {detail}")]
    InvalidLaneRecord { line: usize, detail: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditChainRecordInput<'a> {
    pub line: usize,
    pub seq: Option<u64>,
    pub prev_hash: &'a str,
    pub entry_hash: &'a str,
    pub canonical_payload: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditVerifySummary {
    pub verified: bool,
    pub entries: usize,
    pub format: AuditLogFormat,
    pub head_hash: String,
}

impl AuditVerifyError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotFound { .. } => "GRDR-AUDIT-0001",
            Self::EmptyLog => "GRDR-AUDIT-0002",
            Self::MalformedEntry { .. } => "GRDR-AUDIT-0003",
            Self::BrokenChainLink { .. } => "GRDR-AUDIT-0004",
            Self::HashMismatch { .. } => "GRDR-AUDIT-0005",
            Self::SequenceGap { .. } => "GRDR-AUDIT-0006",
            Self::CommitmentMismatch { .. } => "GRDR-AUDIT-0007",
            Self::MerkleProofMismatch { .. } => "GRDR-AUDIT-0008",
            Self::InvalidGapRecord { .. } => "GRDR-AUDIT-0009",
            Self::InvalidLaneRecord { .. } => "GRDR-AUDIT-0010",
        }
    }
}

pub(crate) fn sha256_framed(domain: &[u8], parts: &[&[u8]]) -> String {
    let mut h = Sha256Hasher::new();
    h.update(domain);
    for part in parts {
        let len = u64::try_from(part.len()).unwrap_or(u64::MAX);
        h.update(&len.to_be_bytes());
        h.update(part);
    }
    format!("sha256:{}", h.finalize_hex())
}

pub(crate) fn normalize_digest_str(raw: &str) -> Option<String> {
    let hex = raw.strip_prefix("sha256:").unwrap_or(raw);
    if hex == GENESIS_HEX {
        Some(GENESIS_PREV_HASH.to_string())
    } else {
        is_sha256_hex(hex).then(|| format!("sha256:{hex}"))
    }
}

pub fn normalize_prefixed_digest(raw: &str) -> Option<String> {
    let hex = raw.strip_prefix("sha256:")?;
    if hex == GENESIS_HEX {
        Some(GENESIS_PREV_HASH.to_string())
    } else {
        is_sha256_hex(hex).then(|| format!("sha256:{hex}"))
    }
}

pub(crate) fn is_sha256_hex(raw: &str) -> bool {
    raw.len() == 64 && raw.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn verify_chain_step(
    line: usize,
    expected_prev: &str,
    prev_hash: &str,
    entry_hash: &str,
    canonical_payload: &[u8],
) -> Result<String, AuditVerifyError> {
    let Some(actual_prev) = normalize_digest_str(prev_hash) else {
        return Err(AuditVerifyError::MalformedEntry {
            line,
            detail: "invalid prev_hash digest".into(),
        });
    };
    if !constant_time_eq(actual_prev.as_bytes(), expected_prev.as_bytes()) {
        return Err(AuditVerifyError::BrokenChainLink {
            line,
            expected_prev: expected_prev.to_owned(),
            actual_prev,
        });
    }
    let Some(actual_hash) = normalize_digest_str(entry_hash) else {
        return Err(AuditVerifyError::MalformedEntry {
            line,
            detail: "invalid entry_hash digest".into(),
        });
    };
    let computed = compute_chain_hash(&actual_prev, canonical_payload);
    if !constant_time_eq(actual_hash.as_bytes(), computed.as_bytes()) {
        return Err(AuditVerifyError::HashMismatch {
            line,
            expected: computed,
            actual: actual_hash,
        });
    }
    Ok(actual_hash)
}

pub fn compute_chain_hash(prev_hash: &str, canonical_payload: &[u8]) -> String {
    let norm = normalize_digest_str(prev_hash).unwrap_or_else(|| prev_hash.to_owned());
    sha256_framed(CHAIN_DOMAIN, &[norm.as_bytes(), canonical_payload])
}

pub fn verify_audit_chain(
    entries: &[AuditChainRecordInput<'_>],
) -> Result<AuditVerifySummary, AuditVerifyError> {
    verify_audit_chain_with_expected(entries, None)
}

pub fn verify_audit_chain_with_expected(
    entries: &[AuditChainRecordInput<'_>],
    expected_head: Option<&str>,
) -> Result<AuditVerifySummary, AuditVerifyError> {
    if entries.is_empty() {
        return Err(AuditVerifyError::EmptyLog);
    }
    let mut expected_prev = GENESIS_PREV_HASH.to_string();
    let mut expected_seq: Option<u64> = None;
    for (idx, entry) in entries.iter().enumerate() {
        if idx == 0 {
            if let Some(first_seq) = entry.seq
                && first_seq > 1
            {
                return Err(AuditVerifyError::SequenceGap {
                    line: entry.line,
                    expected: 0,
                    actual: first_seq,
                });
            }
            expected_seq = entry.seq;
        } else {
            match (expected_seq, entry.seq) {
                (Some(exp), Some(actual)) => {
                    let next =
                        exp.checked_add(1)
                            .ok_or_else(|| AuditVerifyError::MalformedEntry {
                                line: entry.line,
                                detail: "seq overflow".into(),
                            })?;
                    if actual != next {
                        return Err(AuditVerifyError::SequenceGap {
                            line: entry.line,
                            expected: next,
                            actual,
                        });
                    }
                    expected_seq = Some(actual);
                }
                (None, None) => {}
                _ => {
                    return Err(AuditVerifyError::MalformedEntry {
                        line: entry.line,
                        detail: "inconsistent seq presence".into(),
                    });
                }
            }
        }
        expected_prev = verify_chain_step(
            entry.line,
            &expected_prev,
            entry.prev_hash,
            entry.entry_hash,
            entry.canonical_payload,
        )?;
    }
    if let Some(exp_head_raw) = expected_head {
        let Some(exp_head) = normalize_digest_str(exp_head_raw) else {
            return Err(AuditVerifyError::MalformedEntry {
                line: entries.last().map_or(0, |e| e.line),
                detail: "invalid expected head_hash".into(),
            });
        };
        if !constant_time_eq(expected_prev.as_bytes(), exp_head.as_bytes()) {
            return Err(AuditVerifyError::HashMismatch {
                line: entries.last().map_or(0, |e| e.line),
                expected: exp_head,
                actual: expected_prev,
            });
        }
    }
    Ok(AuditVerifySummary {
        verified: true,
        entries: entries.len(),
        format: AuditLogFormat::HashChain,
        head_hash: expected_prev,
    })
}

pub fn verify_receipt_wal_digests(
    receipts: &[DecisionReceipt],
) -> Result<AuditVerifySummary, AuditVerifyError> {
    let indexed: Vec<(usize, &DecisionReceipt)> = receipts
        .iter()
        .enumerate()
        .map(|(idx, r)| (idx.saturating_add(1), r))
        .collect();
    verify_receipt_wal_digests_with_lines(&indexed)
}

pub fn verify_receipt_wal_digests_with_lines(
    receipts: &[(usize, &DecisionReceipt)],
) -> Result<AuditVerifySummary, AuditVerifyError> {
    if receipts.is_empty() {
        return Err(AuditVerifyError::EmptyLog);
    }
    let mut head_hash = GENESIS_PREV_HASH.to_string();
    for &(line, r) in receipts {
        if !is_sha256_hex(&r.receipt_digest) {
            return Err(AuditVerifyError::MalformedEntry {
                line,
                detail: "receipt_digest is not 64 hex chars".into(),
            });
        }
        let digest_for = |target: &str| {
            compute_receipt_digest(&ReceiptDigestInput {
                attempt_id: &r.attempt_id,
                session_id: &r.session_id,
                agent_name: &r.agent_name,
                action_class: r.action_class,
                target,
                verdict: r.verdict,
                rule_id: r.rule_id.as_deref(),
                decided_at: r.decided_at,
            })
        };
        let exp_raw = digest_for(&r.target);
        let (norm_target, _) = normalize_attempt_target(r.action_class, &r.target);
        let exp_norm = digest_for(&norm_target);
        if !constant_time_eq(r.receipt_digest.as_bytes(), exp_raw.as_bytes())
            && !constant_time_eq(r.receipt_digest.as_bytes(), exp_norm.as_bytes())
        {
            return Err(AuditVerifyError::HashMismatch {
                line,
                expected: exp_raw,
                actual: r.receipt_digest.clone(),
            });
        }
        let expected_id = format!("rcp_{}", r.receipt_digest.get(..32).unwrap_or(""));
        if r.receipt_id.len() != expected_id.len()
            || !constant_time_eq(r.receipt_id.as_bytes(), expected_id.as_bytes())
        {
            return Err(AuditVerifyError::HashMismatch {
                line,
                expected: expected_id,
                actual: "[redacted]".into(),
            });
        }
        head_hash = compute_chain_hash(&head_hash, r.receipt_digest.as_bytes());
    }
    Ok(AuditVerifySummary {
        verified: true,
        entries: receipts.len(),
        format: AuditLogFormat::ReceiptWal,
        head_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use grdr_model::{ActionAttempt, ActionClass, ControlPoint, KillSwitchState};
    use jiff::Timestamp;

    fn sample_receipt() -> DecisionReceipt {
        let attempt = ActionAttempt {
            id: "att-1".into(),
            session_id: "sess-1".into(),
            device_id: "dev-1".into(),
            device_name: "host".into(),
            agent_name: "claude-code".into(),
            action_class: ActionClass::FileWrite,
            control_point: ControlPoint::Hook,
            target: ".claude/settings.json".into(),
            summary: "test".into(),
            timestamp: Timestamp::from_second(1_700_000_000).unwrap(),
            ..Default::default()
        };
        crate::policy::evaluate(
            &attempt,
            &[crate::policy::essentials_pack()],
            &[],
            &KillSwitchState::Inactive,
            attempt.timestamp,
        )
    }

    #[test]
    fn verify_audit_chain_accepts_valid_chain_and_rejects_tamper() {
        assert_eq!(
            verify_audit_chain(&[]).unwrap_err().code(),
            "GRDR-AUDIT-0002"
        );

        let p0 = br#"{"event":"session.start","seq":0}"#;
        let h0 = compute_chain_hash(GENESIS_PREV_HASH, p0);
        let p1 = br#"{"event":"decision.receipt","seq":1}"#;
        let h1 = compute_chain_hash(&h0, p1);
        let valid = vec![
            AuditChainRecordInput {
                line: 1,
                seq: Some(0),
                prev_hash: GENESIS_PREV_HASH,
                entry_hash: &h0,
                canonical_payload: p0,
            },
            AuditChainRecordInput {
                line: 2,
                seq: Some(1),
                prev_hash: &h0,
                entry_hash: &h1,
                canonical_payload: p1,
            },
        ];
        let summary = verify_audit_chain_with_expected(&valid, Some(&h1)).unwrap();
        assert!(summary.verified);
        assert_eq!(summary.entries, 2);
        assert_eq!(summary.head_hash, h1);

        assert_eq!(
            verify_audit_chain_with_expected(&valid, Some(&h0))
                .unwrap_err()
                .code(),
            "GRDR-AUDIT-0005"
        );
        let high_seq_start = compute_chain_hash(GENESIS_PREV_HASH, p0);
        assert_eq!(
            verify_audit_chain(&[AuditChainRecordInput {
                line: 1,
                seq: Some(100),
                prev_hash: GENESIS_PREV_HASH,
                entry_hash: &high_seq_start,
                canonical_payload: p0,
            }])
            .unwrap_err()
            .code(),
            "GRDR-AUDIT-0006"
        );

        let err = verify_audit_chain(&[AuditChainRecordInput {
            line: 1,
            seq: Some(0),
            prev_hash: GENESIS_PREV_HASH,
            entry_hash: &h0,
            canonical_payload: br#"{"event":"tamper"}"#,
        }])
        .unwrap_err();
        assert_eq!(err.code(), "GRDR-AUDIT-0005");
        let link_err = verify_audit_chain(&[
            valid[0].clone(),
            AuditChainRecordInput {
                prev_hash: GENESIS_PREV_HASH,
                ..valid[1].clone()
            },
        ])
        .unwrap_err();
        assert_eq!(link_err.code(), "GRDR-AUDIT-0004");
        let gap_err = verify_audit_chain(&[
            valid[0].clone(),
            AuditChainRecordInput {
                seq: Some(2),
                ..valid[1].clone()
            },
        ])
        .unwrap_err();
        assert_eq!(gap_err.code(), "GRDR-AUDIT-0006");
    }

    #[test]
    fn verify_receipt_wal_digests_validates_and_redacts_mismatch() {
        assert_eq!(
            verify_receipt_wal_digests(&[]).unwrap_err().code(),
            "GRDR-AUDIT-0002"
        );
        let mut receipt = sample_receipt();
        assert!(
            verify_receipt_wal_digests(std::slice::from_ref(&receipt))
                .unwrap()
                .verified
        );
        receipt.receipt_id = "rcp_secret_leak_check".into();
        let id_err = verify_receipt_wal_digests_with_lines(&[(7, &receipt)]).unwrap_err();
        assert_eq!(id_err.code(), "GRDR-AUDIT-0005");
        assert!(
            !id_err.to_string().contains("rcp_secret_leak_check"),
            "P8: untrusted receipt_id must be redacted from error"
        );
        receipt = sample_receipt();
        receipt.receipt_digest = "badhex".into();
        assert_eq!(
            verify_receipt_wal_digests_with_lines(&[(5, &receipt)])
                .unwrap_err()
                .code(),
            "GRDR-AUDIT-0003"
        );
        receipt = sample_receipt();
        receipt.verdict = grdr_model::Verdict::Allow;
        assert_eq!(
            verify_receipt_wal_digests(&[receipt]).unwrap_err().code(),
            "GRDR-AUDIT-0005"
        );
    }

    #[test]
    fn lane_chain_supports_reduced_copy_invariance_isolation_and_merkle_chaining() {
        let anchor = LaneChainAnchor {
            device_id: "dev-9".into(),
            epoch: 4,
            prev_epoch_final_hash: Some(GENESIS_PREV_HASH.into()),
        };
        let salts = [
            &[9u8; 32][..],
            &[8u8; 32][..],
            &[7u8; 32][..],
            &[6u8; 32][..],
            &[5u8; 32][..],
        ];
        let payloads = [&b"u"[..], &b"s"[..], &b"d"[..], &b"a"[..], &b"b"[..]];
        let comm = build_five_way_commitments(salts, payloads).unwrap();
        let root = compute_commitment_root_digest(&comm).unwrap();

        let g_ev =
            lane_genesis_hash("dev-9", 4, AuditLane::Event, Some(GENESIS_PREV_HASH)).unwrap();
        let g_sp =
            lane_genesis_hash("dev-9", 4, AuditLane::Spine, Some(GENESIS_PREV_HASH)).unwrap();
        let g_evd =
            lane_genesis_hash("dev-9", 4, AuditLane::Evidence, Some(GENESIS_PREV_HASH)).unwrap();
        assert_ne!(g_sp, g_evd, "spine and evidence lanes must be isolated");

        let full_slots = [
            Some(payloads[0]),
            Some(payloads[1]),
            Some(payloads[2]),
            Some(payloads[3]),
            Some(payloads[4]),
        ];
        let mut reduced_comm = comm.clone();
        reduced_comm.salt_identifier = None;
        reduced_comm.salt_argument = None;
        reduced_comm.salt_body = None;
        let red_slots = [None, Some(payloads[1]), Some(payloads[2]), None, None];
        let withheld = [
            CommitmentClass::Identifier,
            CommitmentClass::ContentArgument,
            CommitmentClass::ContentBody,
        ];

        let ev0_kind_full = LaneEntryKind::Event {
            commitments: &comm,
            commitment_root_digest: &root,
            payloads: full_slots,
            withheld_classes: None,
            merkle: None,
            merkle_consistency: None,
        };
        let h0 = compute_lane_entry_hash(&g_ev, 4, AuditLane::Event, 0, &ev0_kind_full).unwrap();

        let m_leaves: [&[u8]; 2] = [h0.as_bytes(), root.as_bytes()];
        let m_root2 = merkle_root_hex(&m_leaves);
        let inc0 = merkle_inclusion_proof(&m_leaves, 0).unwrap();
        let m_root1 = merkle_root_hex(&m_leaves[..1]);
        let cons12 = merkle_consistency_proof(&m_leaves, 1).unwrap();

        let ev0_reduced_merkle = LaneEntryKind::Event {
            commitments: &reduced_comm,
            commitment_root_digest: &root,
            payloads: red_slots,
            withheld_classes: Some(&withheld),
            merkle: Some(Box::new(MerkleInclusionInput {
                leaf: h0.as_bytes(),
                leaf_index: 0,
                tree_size: 2,
                audit_path: &inc0,
                expected_root: &m_root2,
            })),
            merkle_consistency: Some(Box::new(MerkleConsistencyInput {
                first_size: 1,
                second_size: 2,
                first_root: &m_root1,
                second_root: &m_root2,
                proof: &cons12,
            })),
        };
        let h0_reduced =
            compute_lane_entry_hash(&g_ev, 4, AuditLane::Event, 0, &ev0_reduced_merkle).unwrap();
        assert_eq!(
            h0, h0_reduced,
            "reduced copy must preserve entry_hash identically"
        );

        let sp0_kind = LaneEntryKind::Event {
            commitments: &comm,
            commitment_root_digest: &root,
            payloads: full_slots,
            withheld_classes: None,
            merkle: None,
            merkle_consistency: None,
        };
        let h_sp0 = compute_lane_entry_hash(&g_sp, 4, AuditLane::Spine, 0, &sp0_kind).unwrap();

        let gap_kind = LaneEntryKind::Gap {
            start_seq: 1,
            end_seq: 2,
            dropped_count: 2,
            reason: "ringbuffer_overrun",
        };
        let h_gap = compute_lane_entry_hash(&h0, 4, AuditLane::Event, 1, &gap_kind).unwrap();

        let ev3_kind = LaneEntryKind::Event {
            commitments: &comm,
            commitment_root_digest: &root,
            payloads: full_slots,
            withheld_classes: None,
            merkle: None,
            merkle_consistency: None,
        };
        let h3 = compute_lane_entry_hash(&h_gap, 4, AuditLane::Event, 3, &ev3_kind).unwrap();

        let records = vec![
            LaneAuditRecord {
                line: 1,
                epoch: 4,
                lane: AuditLane::Event,
                seq: 0,
                prev_hash: &g_ev,
                entry_hash: &h0,
                kind: ev0_reduced_merkle,
            },
            LaneAuditRecord {
                line: 2,
                epoch: 4,
                lane: AuditLane::Spine,
                seq: 0,
                prev_hash: &g_sp,
                entry_hash: &h_sp0,
                kind: sp0_kind,
            },
            LaneAuditRecord {
                line: 3,
                epoch: 4,
                lane: AuditLane::Event,
                seq: 1,
                prev_hash: &h0,
                entry_hash: &h_gap,
                kind: gap_kind,
            },
            LaneAuditRecord {
                line: 4,
                epoch: 4,
                lane: AuditLane::Event,
                seq: 3,
                prev_hash: &h_gap,
                entry_hash: &h3,
                kind: ev3_kind,
            },
        ];
        let summary = verify_lane_audit_chain(&records, &anchor).unwrap();
        assert_eq!(summary.format, AuditLogFormat::LaneChain);
        assert_ne!(
            summary.head_hash, h3,
            "multi-lane composite head covers all lanes"
        );
        verify_lane_audit_chain_with_expected(
            &records,
            &anchor,
            Some(&ExpectedAnchor {
                device_id: Some("dev-9".into()),
                epoch: Some(4),
                head_hash: Some(summary.head_hash.clone()),
            }),
        )
        .unwrap();

        // Missing gap without re-chaining breaks link (0004); re-chained skip triggers sequence gap (0006).
        let missing_gap = vec![records[0].clone(), records[3].clone()];
        assert_eq!(
            verify_lane_audit_chain(&missing_gap, &anchor)
                .unwrap_err()
                .code(),
            "GRDR-AUDIT-0004"
        );
        let h_skip =
            compute_lane_entry_hash(&h0, 4, AuditLane::Event, 3, &records[3].kind).unwrap();
        let skipped = vec![
            records[0].clone(),
            LaneAuditRecord {
                prev_hash: &h0,
                entry_hash: &h_skip,
                ..records[3].clone()
            },
        ];
        assert_eq!(
            verify_lane_audit_chain(&skipped, &anchor)
                .unwrap_err()
                .code(),
            "GRDR-AUDIT-0006"
        );

        // Tampering Gap metadata even with matching prev_hash fails entry_hash/gap validation.
        let mut forged_gap = records.clone();
        forged_gap[2].kind = LaneEntryKind::Gap {
            start_seq: 1,
            end_seq: 2,
            dropped_count: 2,
            reason: "tampered_reason",
        };
        assert_eq!(
            verify_lane_audit_chain(&forged_gap, &anchor)
                .unwrap_err()
                .code(),
            "GRDR-AUDIT-0005"
        );

        // Prefix truncation (starting lane at seq=5) fails.
        let h_prefix =
            compute_lane_entry_hash(&g_ev, 4, AuditLane::Event, 5, &records[3].kind).unwrap();
        let prefix_rec = [LaneAuditRecord {
            line: 1,
            epoch: 4,
            lane: AuditLane::Event,
            seq: 5,
            prev_hash: &g_ev,
            entry_hash: &h_prefix,
            kind: records[3].kind.clone(),
        }];
        assert_eq!(
            verify_lane_audit_chain(&prefix_rec, &anchor)
                .unwrap_err()
                .code(),
            "GRDR-AUDIT-0006"
        );

        // Epoch regression or jump fails.
        let mut bad_ep = records.clone();
        bad_ep[3].epoch = 3;
        assert_eq!(
            verify_lane_audit_chain(&bad_ep, &anchor)
                .unwrap_err()
                .code(),
            "GRDR-AUDIT-0010"
        );

        // Invalid anchor rejected.
        assert_eq!(
            lane_genesis_hash("", 1, AuditLane::Event, None)
                .unwrap_err()
                .code(),
            "GRDR-AUDIT-0010"
        );
        assert_eq!(
            lane_genesis_hash("dev\0id", 1, AuditLane::Event, None)
                .unwrap_err()
                .code(),
            "GRDR-AUDIT-0010"
        );
        assert_eq!(
            lane_genesis_hash("dev-1", 1, AuditLane::Event, Some("bad"))
                .unwrap_err()
                .code(),
            "GRDR-AUDIT-0010"
        );
        assert_eq!(
            lane_genesis_hash("dev-1", 2, AuditLane::Event, None)
                .unwrap_err()
                .code(),
            "GRDR-AUDIT-0010"
        );

        // Forward unlinked epoch jump rejected.
        let mut jump_ep = records.clone();
        jump_ep[3].epoch = 5;
        assert_eq!(
            verify_lane_audit_chain(&jump_ep, &anchor)
                .unwrap_err()
                .code(),
            "GRDR-AUDIT-0010"
        );

        // ExpectedAnchor mismatches rejected cleanly.
        assert_eq!(
            verify_lane_audit_chain_with_expected(
                &records,
                &anchor,
                Some(&ExpectedAnchor {
                    device_id: Some("other".into()),
                    ..Default::default()
                }),
            )
            .unwrap_err()
            .code(),
            "GRDR-AUDIT-0010"
        );
        assert_eq!(
            verify_lane_audit_chain_with_expected(
                &records,
                &anchor,
                Some(&ExpectedAnchor {
                    epoch: Some(9),
                    ..Default::default()
                }),
            )
            .unwrap_err()
            .code(),
            "GRDR-AUDIT-0010"
        );
        assert_eq!(
            verify_lane_audit_chain_with_expected(
                &records,
                &anchor,
                Some(&ExpectedAnchor {
                    head_hash: Some(GENESIS_PREV_HASH.into()),
                    ..Default::default()
                }),
            )
            .unwrap_err()
            .code(),
            "GRDR-AUDIT-0005"
        );
        assert_eq!(
            verify_lane_audit_chain_with_expected(
                &records,
                &anchor,
                Some(&ExpectedAnchor {
                    head_hash: Some("not-a-digest".into()),
                    ..Default::default()
                }),
            )
            .unwrap_err()
            .code(),
            "GRDR-AUDIT-0003"
        );

        // Invalid Gap bounds (end < start, dropped_count=0, overflow, blank reason, seq != start_seq).
        for (seq, kind) in [
            (
                2u64,
                LaneEntryKind::Gap {
                    start_seq: 2,
                    end_seq: 1,
                    dropped_count: 1,
                    reason: "r",
                },
            ),
            (
                1,
                LaneEntryKind::Gap {
                    start_seq: 1,
                    end_seq: 1,
                    dropped_count: 0,
                    reason: "r",
                },
            ),
            (
                0,
                LaneEntryKind::Gap {
                    start_seq: 0,
                    end_seq: u64::MAX,
                    dropped_count: u64::MAX,
                    reason: "r",
                },
            ),
            (
                1,
                LaneEntryKind::Gap {
                    start_seq: 1,
                    end_seq: 1,
                    dropped_count: 1,
                    reason: "   ",
                },
            ),
            (
                2,
                LaneEntryKind::Gap {
                    start_seq: 1,
                    end_seq: 2,
                    dropped_count: 2,
                    reason: "r",
                },
            ),
        ] {
            let h = compute_lane_entry_hash(&h0, 4, AuditLane::Event, seq, &kind).unwrap();
            let bad = vec![
                records[0].clone(),
                LaneAuditRecord {
                    line: 2,
                    epoch: 4,
                    lane: AuditLane::Event,
                    seq,
                    prev_hash: &h0,
                    entry_hash: &h,
                    kind,
                },
            ];
            assert_eq!(
                verify_lane_audit_chain(&bad, &anchor).unwrap_err().code(),
                "GRDR-AUDIT-0009"
            );
        }

        // Gap reaching u64::MAX overflow rejected on subsequent entry.
        let max_gap_prefix = compute_lane_entry_hash(
            &g_evd,
            4,
            AuditLane::Evidence,
            u64::MAX - 2,
            &records[3].kind,
        )
        .unwrap();
        let max_gap_kind = LaneEntryKind::Gap {
            start_seq: u64::MAX - 1,
            end_seq: u64::MAX,
            dropped_count: 2,
            reason: "tail_drop",
        };
        let h_gmax = compute_lane_entry_hash(
            &max_gap_prefix,
            4,
            AuditLane::Evidence,
            u64::MAX - 1,
            &max_gap_kind,
        )
        .unwrap();
        let h_evd_after =
            compute_lane_entry_hash(&h_gmax, 4, AuditLane::Evidence, 0, &records[3].kind).unwrap();
        let overflow_recs = vec![
            LaneAuditRecord {
                line: 1,
                epoch: 4,
                lane: AuditLane::Evidence,
                seq: u64::MAX - 2,
                prev_hash: &g_evd,
                entry_hash: &max_gap_prefix,
                kind: records[3].kind.clone(),
            },
            LaneAuditRecord {
                line: 2,
                epoch: 4,
                lane: AuditLane::Evidence,
                seq: u64::MAX - 1,
                prev_hash: &max_gap_prefix,
                entry_hash: &h_gmax,
                kind: max_gap_kind,
            },
            LaneAuditRecord {
                line: 3,
                epoch: 4,
                lane: AuditLane::Evidence,
                seq: 0,
                prev_hash: &h_gmax,
                entry_hash: &h_evd_after,
                kind: records[3].kind.clone(),
            },
        ];
        // Line 1 starts with seq > 1 unless it's anchored at 0; instead use gap starting at 0..=u64::MAX.
        let _ = overflow_recs;
        let full_span_prefix =
            compute_lane_entry_hash(&g_evd, 4, AuditLane::Evidence, 0, &records[3].kind).unwrap();
        let tail_gap = LaneEntryKind::Gap {
            start_seq: 1,
            end_seq: u64::MAX,
            dropped_count: u64::MAX,
            reason: "full_tail_drop",
        };
        let h_tail =
            compute_lane_entry_hash(&full_span_prefix, 4, AuditLane::Evidence, 1, &tail_gap)
                .unwrap();
        let h_after_tail =
            compute_lane_entry_hash(&h_tail, 4, AuditLane::Evidence, 0, &records[3].kind).unwrap();
        let seq_overflow_recs = vec![
            LaneAuditRecord {
                line: 1,
                epoch: 4,
                lane: AuditLane::Evidence,
                seq: 0,
                prev_hash: &g_evd,
                entry_hash: &full_span_prefix,
                kind: records[3].kind.clone(),
            },
            LaneAuditRecord {
                line: 2,
                epoch: 4,
                lane: AuditLane::Evidence,
                seq: 1,
                prev_hash: &full_span_prefix,
                entry_hash: &h_tail,
                kind: tail_gap,
            },
            LaneAuditRecord {
                line: 3,
                epoch: 4,
                lane: AuditLane::Evidence,
                seq: 0,
                prev_hash: &h_tail,
                entry_hash: &h_after_tail,
                kind: records[3].kind.clone(),
            },
        ];
        let ovf_err = verify_lane_audit_chain(&seq_overflow_recs, &anchor).unwrap_err();
        assert_eq!(ovf_err.code(), "GRDR-AUDIT-0010");
        assert!(ovf_err.to_string().contains("seq overflow"));

        // Also test multi-entry Evidence lane tamper.
        let mut bad_evd_hash = h_evd_after.clone();
        bad_evd_hash.replace_range(
            7..8,
            if bad_evd_hash.as_bytes()[7] == b'0' {
                "1"
            } else {
                "0"
            },
        );
        let evd_h0 =
            compute_lane_entry_hash(&g_evd, 4, AuditLane::Evidence, 0, &records[3].kind).unwrap();
        let evd_recs = vec![
            LaneAuditRecord {
                line: 1,
                epoch: 4,
                lane: AuditLane::Evidence,
                seq: 0,
                prev_hash: &g_evd,
                entry_hash: &evd_h0,
                kind: records[3].kind.clone(),
            },
            LaneAuditRecord {
                line: 2,
                epoch: 4,
                lane: AuditLane::Evidence,
                seq: 1,
                prev_hash: &g_evd,
                entry_hash: &bad_evd_hash,
                kind: records[3].kind.clone(),
            },
        ];
        assert_eq!(
            verify_lane_audit_chain(&evd_recs, &anchor)
                .unwrap_err()
                .code(),
            "GRDR-AUDIT-0004"
        );

        // Inconsistent seq presence in HashChain rejected.
        let p0 = br#"{"event":"a"}"#;
        let ch0 = compute_chain_hash(GENESIS_PREV_HASH, p0);
        let ch1 = compute_chain_hash(&ch0, p0);
        assert_eq!(
            verify_audit_chain(&[
                AuditChainRecordInput {
                    line: 1,
                    seq: Some(0),
                    prev_hash: GENESIS_PREV_HASH,
                    entry_hash: &ch0,
                    canonical_payload: p0
                },
                AuditChainRecordInput {
                    line: 2,
                    seq: None,
                    prev_hash: &ch0,
                    entry_hash: &ch1,
                    canonical_payload: p0
                },
            ])
            .unwrap_err()
            .code(),
            "GRDR-AUDIT-0003"
        );
    }
}
