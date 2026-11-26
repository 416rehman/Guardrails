// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use grdr_crypto::Sha256Hasher;
use serde::{Deserialize, Serialize};

use grdr_model::DecisionReceipt;

use crate::analyze::normalize_attempt_target;
use crate::policy::{ReceiptDigestInput, compute_receipt_digest};

pub const GENESIS_PREV_HASH: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const GENESIS_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const CHAIN_DOMAIN: &[u8] = b"grdr.audit.chain.v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditLogFormat {
    HashChain,
    ReceiptWal,
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
        }
    }
}

pub fn compute_chain_hash(prev_hash: &str, canonical_payload: &[u8]) -> String {
    let normalized_prev = normalize_digest_str(prev_hash).unwrap_or_else(|| prev_hash.to_owned());
    let mut hasher = Sha256Hasher::new();
    hasher.update(CHAIN_DOMAIN);
    hasher.update(normalized_prev.as_bytes());
    hasher.update(b"\0");
    hasher.update(canonical_payload);
    let hex = hasher.finalize_hex();
    format!("sha256:{hex}")
}

pub fn verify_audit_chain(
    entries: &[AuditChainRecordInput<'_>],
) -> Result<AuditVerifySummary, AuditVerifyError> {
    if entries.is_empty() {
        return Err(AuditVerifyError::EmptyLog);
    }

    let mut expected_prev = GENESIS_PREV_HASH.to_string();
    let mut expected_seq: Option<u64> = None;

    for (idx, entry) in entries.iter().enumerate() {
        let Some(actual_prev) = normalize_digest_str(entry.prev_hash) else {
            return Err(AuditVerifyError::MalformedEntry {
                line: entry.line,
                detail: "invalid prev_hash digest format".into(),
            });
        };
        if actual_prev != expected_prev {
            return Err(AuditVerifyError::BrokenChainLink {
                line: entry.line,
                expected_prev,
                actual_prev,
            });
        }

        if idx == 0 {
            expected_seq = entry.seq;
        } else {
            match (expected_seq, entry.seq) {
                (Some(exp), Some(actual)) => {
                    let next =
                        exp.checked_add(1)
                            .ok_or_else(|| AuditVerifyError::MalformedEntry {
                                line: entry.line,
                                detail: "sequence overflow".into(),
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
                        detail: "inconsistent seq presence across entries".into(),
                    });
                }
            }
        }

        let Some(actual_hash) = normalize_digest_str(entry.entry_hash) else {
            return Err(AuditVerifyError::MalformedEntry {
                line: entry.line,
                detail: "invalid entry_hash digest format".into(),
            });
        };
        let computed = compute_chain_hash(&actual_prev, entry.canonical_payload);
        if actual_hash != computed {
            return Err(AuditVerifyError::HashMismatch {
                line: entry.line,
                expected: computed,
                actual: actual_hash,
            });
        }
        expected_prev = actual_hash;
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
    if receipts.is_empty() {
        return Err(AuditVerifyError::EmptyLog);
    }

    let mut head_hash = GENESIS_PREV_HASH.to_string();
    for (idx, receipt) in receipts.iter().enumerate() {
        let line = idx.saturating_add(1);
        if !is_sha256_hex(&receipt.receipt_digest) {
            return Err(AuditVerifyError::MalformedEntry {
                line,
                detail: "receipt_digest is not 64 lowercase hex chars".into(),
            });
        }

        let expected_raw = compute_receipt_digest(&ReceiptDigestInput {
            attempt_id: &receipt.attempt_id,
            session_id: &receipt.session_id,
            agent_name: &receipt.agent_name,
            action_class: receipt.action_class,
            target: &receipt.target,
            verdict: receipt.verdict,
            rule_id: receipt.rule_id.as_deref(),
            decided_at: receipt.decided_at,
        });
        let (norm_target, _) = normalize_attempt_target(receipt.action_class, &receipt.target);
        let expected_norm = compute_receipt_digest(&ReceiptDigestInput {
            attempt_id: &receipt.attempt_id,
            session_id: &receipt.session_id,
            agent_name: &receipt.agent_name,
            action_class: receipt.action_class,
            target: &norm_target,
            verdict: receipt.verdict,
            rule_id: receipt.rule_id.as_deref(),
            decided_at: receipt.decided_at,
        });

        if receipt.receipt_digest != expected_raw && receipt.receipt_digest != expected_norm {
            return Err(AuditVerifyError::HashMismatch {
                line,
                expected: expected_raw,
                actual: receipt.receipt_digest.clone(),
            });
        }

        let digest_prefix = receipt.receipt_digest.get(..32).unwrap_or("");
        let expected_id = format!("rcp_{digest_prefix}");
        if receipt.receipt_id != expected_id {
            return Err(AuditVerifyError::HashMismatch {
                line,
                expected: expected_id,
                actual: receipt.receipt_id.clone(),
            });
        }

        head_hash = compute_chain_hash(&head_hash, receipt.receipt_digest.as_bytes());
    }

    Ok(AuditVerifySummary {
        verified: true,
        entries: receipts.len(),
        format: AuditLogFormat::ReceiptWal,
        head_hash,
    })
}

fn normalize_digest_str(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let hex = trimmed.strip_prefix("sha256:").unwrap_or(trimmed);
    if hex == GENESIS_HEX {
        return Some(GENESIS_PREV_HASH.to_string());
    }
    if is_sha256_hex(hex) {
        return Some(format!("sha256:{hex}"));
    }
    None
}

fn is_sha256_hex(raw: &str) -> bool {
    raw.len() == 64 && raw.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use grdr_model::{ActionAttempt, ActionClass, ControlPoint, KillSwitchState};
    use jiff::Timestamp;

    #[test]
    fn verify_audit_chain_accepts_valid_chain_and_rejects_tamper() {
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
        let summary = verify_audit_chain(&valid).unwrap();
        assert!(summary.verified);
        assert_eq!(summary.entries, 2);
        assert_eq!(summary.head_hash, h1);

        let tampered_payload = br#"{"event":"session.start","seq":9}"#;
        let bad_hash = vec![AuditChainRecordInput {
            line: 1,
            seq: Some(0),
            prev_hash: GENESIS_PREV_HASH,
            entry_hash: &h0,
            canonical_payload: tampered_payload,
        }];
        let err = verify_audit_chain(&bad_hash).unwrap_err();
        assert_eq!(err.code(), "GRDR-AUDIT-0005");

        let broken_link = vec![
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
                prev_hash: GENESIS_PREV_HASH,
                entry_hash: &h1,
                canonical_payload: p1,
            },
        ];
        let link_err = verify_audit_chain(&broken_link).unwrap_err();
        assert_eq!(link_err.code(), "GRDR-AUDIT-0004");

        let seq_gap = vec![
            AuditChainRecordInput {
                line: 1,
                seq: Some(0),
                prev_hash: GENESIS_PREV_HASH,
                entry_hash: &h0,
                canonical_payload: p0,
            },
            AuditChainRecordInput {
                line: 2,
                seq: Some(2),
                prev_hash: &h0,
                entry_hash: &h1,
                canonical_payload: p1,
            },
        ];
        let gap_err = verify_audit_chain(&seq_gap).unwrap_err();
        assert_eq!(gap_err.code(), "GRDR-AUDIT-0006");
    }

    #[test]
    fn verify_receipt_wal_digests_validates_and_detects_tamper() {
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
        let mut receipt = crate::policy::evaluate(
            &attempt,
            &[crate::policy::essentials_pack()],
            &[],
            &KillSwitchState::Inactive,
            attempt.timestamp,
        );
        let ok = verify_receipt_wal_digests(std::slice::from_ref(&receipt)).unwrap();
        assert!(ok.verified);
        assert_eq!(ok.entries, 1);

        receipt.verdict = grdr_model::Verdict::Allow;
        let err = verify_receipt_wal_digests(&[receipt]).unwrap_err();
        assert_eq!(err.code(), "GRDR-AUDIT-0005");
    }
}
