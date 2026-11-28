// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Independent audit verification domain types, error codes, and digest validators (`04-15`).

use std::fmt;

use grdr_model::{AuditLane, CommitmentClass, FiveWayCommitments};
use serde::{Deserialize, Serialize};

pub const CODE_AUDIT_NOT_FOUND: &str = "GRDR-AUDIT-0001";
pub const CODE_AUDIT_EMPTY_LOG: &str = "GRDR-AUDIT-0002";
pub const CODE_AUDIT_MALFORMED_ENTRY: &str = "GRDR-AUDIT-0003";
pub const CODE_AUDIT_BROKEN_CHAIN_LINK: &str = "GRDR-AUDIT-0004";
pub const CODE_AUDIT_HASH_MISMATCH: &str = "GRDR-AUDIT-0005";
pub const CODE_AUDIT_SEQUENCE_GAP: &str = "GRDR-AUDIT-0006";
pub const CODE_AUDIT_COMMITMENT_MISMATCH: &str = "GRDR-AUDIT-0007";
pub const CODE_AUDIT_MERKLE_MISMATCH: &str = "GRDR-AUDIT-0008";
pub const CODE_AUDIT_INVALID_GAP: &str = "GRDR-AUDIT-0009";
pub const CODE_AUDIT_INVALID_LANE: &str = "GRDR-AUDIT-0010";

pub const GENESIS_PREV_HASH: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const GENESIS_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditLogFormat {
    HashChain,
    ReceiptWal,
    LaneChain,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditVerifyError {
    NotFound {
        path: String,
    },
    EmptyLog,
    MalformedEntry {
        line: usize,
        detail: String,
    },
    BrokenChainLink {
        line: usize,
        expected_prev: String,
        actual_prev: String,
    },
    HashMismatch {
        line: usize,
        expected: String,
        actual: String,
    },
    SequenceGap {
        line: usize,
        expected: u64,
        actual: u64,
    },
    CommitmentMismatch {
        line: usize,
        class_label: &'static str,
        detail: String,
    },
    MerkleProofMismatch {
        line: usize,
        detail: String,
    },
    InvalidGapRecord {
        line: usize,
        detail: String,
    },
    InvalidLaneRecord {
        line: usize,
        detail: String,
    },
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

impl AuditVerifyError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NotFound { .. } => CODE_AUDIT_NOT_FOUND,
            Self::EmptyLog => CODE_AUDIT_EMPTY_LOG,
            Self::MalformedEntry { .. } => CODE_AUDIT_MALFORMED_ENTRY,
            Self::BrokenChainLink { .. } => CODE_AUDIT_BROKEN_CHAIN_LINK,
            Self::HashMismatch { .. } => CODE_AUDIT_HASH_MISMATCH,
            Self::SequenceGap { .. } => CODE_AUDIT_SEQUENCE_GAP,
            Self::CommitmentMismatch { .. } => CODE_AUDIT_COMMITMENT_MISMATCH,
            Self::MerkleProofMismatch { .. } => CODE_AUDIT_MERKLE_MISMATCH,
            Self::InvalidGapRecord { .. } => CODE_AUDIT_INVALID_GAP,
            Self::InvalidLaneRecord { .. } => CODE_AUDIT_INVALID_LANE,
        }
    }
}

impl fmt::Display for AuditVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound { path } => {
                write!(f, "{CODE_AUDIT_NOT_FOUND}: audit log not found at {path}")
            }
            Self::EmptyLog => write!(
                f,
                "{CODE_AUDIT_EMPTY_LOG}: audit log is empty (zero entries)"
            ),
            Self::MalformedEntry { line, detail } => {
                write!(
                    f,
                    "{CODE_AUDIT_MALFORMED_ENTRY}: malformed audit entry at line {line}: {detail}"
                )
            }
            Self::BrokenChainLink {
                line,
                expected_prev,
                actual_prev,
            } => write!(
                f,
                "{CODE_AUDIT_BROKEN_CHAIN_LINK}: broken chain link at line {line} (expected prev {expected_prev}, got {actual_prev})"
            ),
            Self::HashMismatch {
                line,
                expected,
                actual,
            } => write!(
                f,
                "{CODE_AUDIT_HASH_MISMATCH}: entry hash mismatch at line {line} (expected {expected}, got {actual})"
            ),
            Self::SequenceGap {
                line,
                expected,
                actual,
            } => write!(
                f,
                "{CODE_AUDIT_SEQUENCE_GAP}: sequence gap at line {line} (expected {expected}, got {actual})"
            ),
            Self::CommitmentMismatch {
                line,
                class_label,
                detail,
            } => write!(
                f,
                "{CODE_AUDIT_COMMITMENT_MISMATCH}: five-way commitment mismatch for {class_label} at line {line}: {detail}"
            ),
            Self::MerkleProofMismatch { line, detail } => write!(
                f,
                "{CODE_AUDIT_MERKLE_MISMATCH}: RFC 6962 Merkle proof mismatch at line {line}: {detail}"
            ),
            Self::InvalidGapRecord { line, detail } => write!(
                f,
                "{CODE_AUDIT_INVALID_GAP}: invalid audit gap record at line {line}: {detail}"
            ),
            Self::InvalidLaneRecord { line, detail } => write!(
                f,
                "{CODE_AUDIT_INVALID_LANE}: invalid lane audit record at line {line}: {detail}"
            ),
        }
    }
}

impl std::error::Error for AuditVerifyError {}

#[must_use]
pub fn is_sha256_hex(raw: &str) -> bool {
    raw.len() == 64 && raw.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[must_use]
pub fn normalize_digest_str(raw: &str) -> Option<String> {
    let hex = raw.strip_prefix("sha256:").unwrap_or(raw);
    if hex == GENESIS_HEX {
        Some(GENESIS_PREV_HASH.to_string())
    } else {
        is_sha256_hex(hex).then(|| format!("sha256:{hex}"))
    }
}

#[must_use]
pub fn normalize_prefixed_digest(raw: &str) -> Option<String> {
    let hex = raw.strip_prefix("sha256:")?;
    if hex == GENESIS_HEX {
        Some(GENESIS_PREV_HASH.to_string())
    } else {
        is_sha256_hex(hex).then(|| format!("sha256:{hex}"))
    }
}
