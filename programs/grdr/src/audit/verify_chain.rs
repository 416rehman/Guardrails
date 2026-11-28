// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Independent hash-chain and DecisionReceipt WAL digest verification (`04-15`).

use grdr_model::DecisionReceipt;

use super::sha256::{constant_time_eq, sha256_framed, sha256_hex};
use super::types::{
    AuditChainRecordInput, AuditLogFormat, AuditVerifyError, AuditVerifySummary, GENESIS_PREV_HASH,
    is_sha256_hex, normalize_digest_str,
};

const CHAIN_DOMAIN: &[u8] = b"grdr.audit.chain.v1\0";

#[must_use]
pub fn compute_chain_hash(prev_hash: &str, canonical_payload: &[u8]) -> String {
    let norm = normalize_digest_str(prev_hash).unwrap_or_else(|| prev_hash.to_owned());
    sha256_framed(CHAIN_DOMAIN, &[norm.as_bytes(), canonical_payload])
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

fn push_len(buf: &mut String, val: &str) {
    buf.push_str(&val.len().to_string());
    buf.push(':');
    buf.push_str(val);
    buf.push(';');
}

/// Recomputes a WAL receipt digest over verbatim `receipt.target` (parity with
/// the live policy receipt builder, without target-normalization slack).
#[must_use]
pub fn compute_receipt_digest(receipt: &DecisionReceipt) -> String {
    let mut payload = String::new();
    for field in [
        receipt.attempt_id.as_str(),
        receipt.session_id.as_str(),
        receipt.agent_name.as_str(),
        receipt.action_class.as_str(),
        receipt.target.as_str(),
        receipt.rule_id.as_deref().unwrap_or("none"),
    ] {
        push_len(&mut payload, field);
    }
    payload.push_str(&format!(
        "{:?}:{}",
        receipt.verdict,
        receipt.decided_at.as_second()
    ));
    sha256_hex(payload.as_bytes())
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
        let exp = compute_receipt_digest(r);
        if !constant_time_eq(r.receipt_digest.as_bytes(), exp.as_bytes()) {
            return Err(AuditVerifyError::HashMismatch {
                line,
                expected: exp,
                actual: r.receipt_digest.clone(),
            });
        }
        let prefix = r.receipt_digest.get(..32).unwrap_or("");
        let expected_id = format!("rcp_{prefix}");
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
