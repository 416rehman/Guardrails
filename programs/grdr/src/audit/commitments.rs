// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Independent 5-way privacy class commitment verification (`04-15`).

use grdr_model::{CommitmentClass, FiveWayCommitments, capture_schema};

use super::sha256::{constant_time_eq, sha256_framed};
use super::types::{AuditVerifyError, normalize_prefixed_digest};

const COMMITMENT_DOMAIN: &[u8] = b"grdr.audit.commit.v1\0";
const COMMITMENT_ROOT_DOMAIN: &[u8] = b"grdr.audit.commitments.v1\0";
pub const MIN_COMMITMENT_SALT_BYTES: usize = 16;
pub const MAX_COMMITMENT_SALT_BYTES: usize = 64;

#[must_use]
pub fn withheld_classes_for_capture_level(level: &str) -> Option<Vec<CommitmentClass>> {
    let spec = capture_schema::find_capture_level(level)?;
    let list = CommitmentClass::ALL
        .into_iter()
        .filter(|&cls| spec.for_class(cls) == capture_schema::CaptureDisposition::Withheld)
        .collect();
    Some(list)
}

fn commit_err(
    line: usize,
    class_label: &'static str,
    detail: impl Into<String>,
) -> AuditVerifyError {
    AuditVerifyError::CommitmentMismatch {
        line,
        class_label,
        detail: detail.into(),
    }
}

fn validate_salt(
    line: usize,
    class_label: &'static str,
    salt: &[u8],
) -> Result<(), AuditVerifyError> {
    if salt.len() < MIN_COMMITMENT_SALT_BYTES || salt.len() > MAX_COMMITMENT_SALT_BYTES {
        return Err(commit_err(
            line,
            class_label,
            format!(
                "salt length {} out of bounds ({MIN_COMMITMENT_SALT_BYTES}..={MAX_COMMITMENT_SALT_BYTES})",
                salt.len()
            ),
        ));
    }
    if salt.iter().all(|&b| b == 0) {
        return Err(commit_err(line, class_label, "salt must not be all zeros"));
    }
    Ok(())
}

fn ensure_distinct_salts(
    line: usize,
    salts: &[(&'static str, &[u8])],
) -> Result<(), AuditVerifyError> {
    for (idx, &(cls_a, salt_a)) in salts.iter().enumerate() {
        for &(cls_b, salt_b) in salts.iter().skip(idx.saturating_add(1)) {
            if salt_a.len() == salt_b.len() && constant_time_eq(salt_a, salt_b) {
                return Err(commit_err(
                    line,
                    cls_b,
                    format!("reused salt shared with {cls_a}"),
                ));
            }
        }
    }
    Ok(())
}

#[must_use]
pub fn compute_class_commitment(class: CommitmentClass, salt: &[u8], payload: &[u8]) -> String {
    sha256_framed(
        COMMITMENT_DOMAIN,
        &[class.wire_name().as_bytes(), salt, payload],
    )
}

#[cfg(test)]
pub(crate) fn build_five_way_commitments(
    salts: [&[u8]; 5],
    payloads: [&[u8]; 5],
) -> Result<FiveWayCommitments, AuditVerifyError> {
    let mut checks = Vec::with_capacity(5);
    for (cls, salt) in CommitmentClass::ALL.into_iter().zip(salts) {
        validate_salt(0, cls.wire_name(), salt)?;
        checks.push((cls.wire_name(), salt));
    }
    ensure_distinct_salts(0, &checks)?;

    let [s_id, s_st, s_dr, s_ar, s_bd] = salts;
    let [p_id, p_st, p_dr, p_ar, p_bd] = payloads;
    Ok(FiveWayCommitments {
        d_identifier: compute_class_commitment(CommitmentClass::Identifier, s_id, p_id),
        d_structural: compute_class_commitment(CommitmentClass::Structural, s_st, p_st),
        d_derived: compute_class_commitment(CommitmentClass::Derived, s_dr, p_dr),
        d_argument: compute_class_commitment(CommitmentClass::ContentArgument, s_ar, p_ar),
        d_body: compute_class_commitment(CommitmentClass::ContentBody, s_bd, p_bd),
        salt_identifier: Some(s_id.to_vec()),
        salt_structural: Some(s_st.to_vec()),
        salt_derived: Some(s_dr.to_vec()),
        salt_argument: Some(s_ar.to_vec()),
        salt_body: Some(s_bd.to_vec()),
    })
}

pub fn compute_commitment_root_digest(
    commitments: &FiveWayCommitments,
) -> Result<String, AuditVerifyError> {
    let mut parts: Vec<String> = Vec::with_capacity(5);
    for cls in CommitmentClass::ALL {
        let (raw, _) = commitments.slot(cls);
        let norm = normalize_prefixed_digest(raw).ok_or_else(|| {
            commit_err(
                0,
                cls.wire_name(),
                "malformed commitment digest (requires sha256:<64 hex>)",
            )
        })?;
        parts.push(norm);
    }
    match parts.as_slice() {
        [a, b, c, d, e] => Ok(sha256_framed(
            COMMITMENT_ROOT_DOMAIN,
            &[
                a.as_bytes(),
                b.as_bytes(),
                c.as_bytes(),
                d.as_bytes(),
                e.as_bytes(),
            ],
        )),
        _ => Err(commit_err(0, "root", "incomplete 5-way commitment slots")),
    }
}

pub fn verify_five_way_commitments_with_withheld(
    line: usize,
    commitments: &FiveWayCommitments,
    payloads: [Option<&[u8]>; 5],
    withheld_classes: Option<&[CommitmentClass]>,
    expected_root: Option<&str>,
) -> Result<String, AuditVerifyError> {
    if let Some(withheld) = withheld_classes {
        for cls in withheld {
            if matches!(cls, CommitmentClass::Structural | CommitmentClass::Derived) {
                return Err(commit_err(
                    line,
                    cls.wire_name(),
                    "mandatory structural/derived class cannot be withheld",
                ));
            }
        }
    }

    let mut present_salts: Vec<(&'static str, &[u8])> = Vec::with_capacity(5);
    let mut verified_count = 0usize;

    for (cls, payload_opt) in CommitmentClass::ALL.into_iter().zip(payloads) {
        let (raw, salt_opt) = commitments.slot(cls);
        let exp = normalize_prefixed_digest(raw)
            .ok_or_else(|| commit_err(line, cls.wire_name(), "malformed commitment digest"))?;

        let is_mandatory = matches!(cls, CommitmentClass::Structural | CommitmentClass::Derived);
        let marked_withheld = withheld_classes.is_some_and(|list| list.contains(&cls));

        if marked_withheld && (salt_opt.is_some() || payload_opt.is_some()) {
            return Err(commit_err(
                line,
                cls.wire_name(),
                "withheld class must omit both salt and payload",
            ));
        }

        match (salt_opt, payload_opt) {
            (Some(salt), Some(payload)) => {
                validate_salt(line, cls.wire_name(), salt)?;
                present_salts.push((cls.wire_name(), salt));
                let actual = compute_class_commitment(cls, salt, payload);
                if !constant_time_eq(actual.as_bytes(), exp.as_bytes()) {
                    return Err(commit_err(
                        line,
                        cls.wire_name(),
                        format!("expected {exp}, got {actual}"),
                    ));
                }
                verified_count = verified_count.saturating_add(1);
            }
            (None, None) => {
                if is_mandatory {
                    return Err(commit_err(
                        line,
                        cls.wire_name(),
                        "mandatory non-withholdable class must include salt and payload",
                    ));
                }
                if !marked_withheld {
                    return Err(commit_err(
                        line,
                        cls.wire_name(),
                        "non-withheld class omitted salt and payload",
                    ));
                }
            }
            _ => {
                return Err(commit_err(
                    line,
                    cls.wire_name(),
                    "salt and payload must both exist or both be omitted",
                ));
            }
        }
    }

    if verified_count == 0 {
        return Err(commit_err(
            line,
            "root",
            "at least one commitment class must be verified",
        ));
    }
    ensure_distinct_salts(line, &present_salts)?;

    let root = compute_commitment_root_digest(commitments).map_err(|mut e| {
        if let AuditVerifyError::CommitmentMismatch {
            line: ref mut l, ..
        } = e
        {
            *l = line;
        }
        e
    })?;
    if let Some(exp_root) = expected_root {
        let norm_exp = normalize_prefixed_digest(exp_root)
            .ok_or_else(|| commit_err(line, "root", "malformed root digest"))?;
        if !constant_time_eq(root.as_bytes(), norm_exp.as_bytes()) {
            return Err(commit_err(
                line,
                "root",
                format!("root mismatch (expected {norm_exp}, got {root})"),
            ));
        }
    }
    Ok(root)
}
