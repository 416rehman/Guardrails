// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use grdr_crypto::{constant_time_eq, fill_random};
pub use grdr_schema::{CommitmentClass, FiveWayCommitments};

use super::{AuditVerifyError, normalize_prefixed_digest, sha256_framed};

const COMMITMENT_DOMAIN: &[u8] = b"grdr.audit.commit.v1\0";
const COMMITMENT_ROOT_DOMAIN: &[u8] = b"grdr.audit.commitments.v1\0";
pub const MIN_COMMITMENT_SALT_BYTES: usize = 16;
pub const MAX_COMMITMENT_SALT_BYTES: usize = 64;

pub fn withheld_classes_for_capture_level(level: &str) -> Option<Vec<CommitmentClass>> {
    let spec = grdr_schema::capture::find_capture_level(level)?;
    let list = CommitmentClass::ALL
        .into_iter()
        .filter(|&cls| spec.for_class(cls) == grdr_schema::capture::CaptureDisposition::Withheld)
        .collect();
    Some(list)
}

pub fn generate_five_way_salts() -> Result<[[u8; 32]; 5], AuditVerifyError> {
    let mut salts = [[0u8; 32]; 5];
    for slot in &mut salts {
        fill_random(slot).map_err(|_| {
            commit_err(
                0,
                "salt",
                "OS entropy source unavailable for salt generation",
            )
        })?;
        if slot.iter().all(|&b| b == 0) {
            return Err(commit_err(
                0,
                "salt",
                "OS entropy source produced all-zero salt",
            ));
        }
    }
    Ok(salts)
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

pub fn compute_class_commitment(class: CommitmentClass, salt: &[u8], payload: &[u8]) -> String {
    sha256_framed(
        COMMITMENT_DOMAIN,
        &[class.wire_name().as_bytes(), salt, payload],
    )
}

pub fn build_five_way_commitments(
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

pub fn verify_five_way_commitments(
    line: usize,
    commitments: &FiveWayCommitments,
    payloads: [Option<&[u8]>; 5],
    expected_root: Option<&str>,
) -> Result<String, AuditVerifyError> {
    verify_five_way_commitments_with_withheld(line, commitments, payloads, None, expected_root)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_salts() -> [&'static [u8]; 5] {
        [
            &[1u8; 32][..],
            &[2u8; 32][..],
            &[3u8; 32][..],
            &[4u8; 32][..],
            &[5u8; 32][..],
        ]
    }

    #[test]
    fn five_way_commitments_verify_full_reduced_copy_and_reject_tamper() {
        let salts = test_salts();
        let payloads = [
            &b"alice@org"[..],
            &b"exec"[..],
            &b"risk=high"[..],
            &b"cat /etc/shadow"[..],
            &b"body-text"[..],
        ];
        let full = build_five_way_commitments(salts, payloads).unwrap();
        let root = compute_commitment_root_digest(&full).unwrap();

        let verified_root = verify_five_way_commitments(
            1,
            &full,
            [
                Some(payloads[0]),
                Some(payloads[1]),
                Some(payloads[2]),
                Some(payloads[3]),
                Some(payloads[4]),
            ],
            Some(&root),
        )
        .unwrap();
        assert_eq!(verified_root, root);

        let mut reduced = full.clone();
        reduced.salt_identifier = None;
        reduced.salt_argument = None;
        reduced.salt_body = None;
        let withheld = [
            CommitmentClass::Identifier,
            CommitmentClass::ContentArgument,
            CommitmentClass::ContentBody,
        ];
        assert_eq!(
            verify_five_way_commitments_with_withheld(
                1,
                &reduced,
                [None, Some(payloads[1]), Some(payloads[2]), None, None],
                Some(&withheld),
                Some(&root),
            )
            .unwrap(),
            root
        );

        assert_eq!(
            verify_five_way_commitments(
                1,
                &full,
                [
                    Some(b"eve@org"),
                    Some(payloads[1]),
                    Some(payloads[2]),
                    Some(payloads[3]),
                    Some(payloads[4]),
                ],
                Some(&root),
            )
            .unwrap_err()
            .code(),
            "GRDR-AUDIT-0007"
        );
        assert_eq!(
            verify_five_way_commitments(
                1,
                &full,
                [
                    None,
                    Some(payloads[1]),
                    Some(payloads[2]),
                    Some(payloads[3]),
                    Some(payloads[4]),
                ],
                Some(&root),
            )
            .unwrap_err()
            .code(),
            "GRDR-AUDIT-0007"
        );
    }

    #[test]
    fn commitment_framing_and_salt_policy_reject_adversarial_inputs() {
        let mut s0 = [0x11u8; 16];
        s0[15] = 0x00;
        let p0 = b"payload";
        let s1 = [0x11u8; 15];
        let p1 = b"\0payload";
        assert_ne!(
            compute_class_commitment(CommitmentClass::Structural, &s0, p0),
            compute_class_commitment(CommitmentClass::Structural, &s1, p1),
            "length-prefixed framing must prevent NUL-boundary shifts"
        );

        let mut bad_short = test_salts();
        bad_short[0] = &[7u8; 15];
        assert_eq!(
            build_five_way_commitments(bad_short, [b"a"; 5])
                .unwrap_err()
                .code(),
            "GRDR-AUDIT-0007"
        );
        let mut bad_long = test_salts();
        bad_long[1] = &[8u8; 65];
        assert_eq!(
            build_five_way_commitments(bad_long, [b"a"; 5])
                .unwrap_err()
                .code(),
            "GRDR-AUDIT-0007"
        );
        let mut bad_reuse = test_salts();
        bad_reuse[1] = bad_reuse[0];
        assert_eq!(
            build_five_way_commitments(bad_reuse, [b"a"; 5])
                .unwrap_err()
                .code(),
            "GRDR-AUDIT-0007"
        );

        let full = build_five_way_commitments(test_salts(), [b"a"; 5]).unwrap();
        let root = compute_commitment_root_digest(&full).unwrap();

        let all_none = FiveWayCommitments {
            salt_identifier: None,
            salt_structural: None,
            salt_derived: None,
            salt_argument: None,
            salt_body: None,
            ..full.clone()
        };
        assert_eq!(
            verify_five_way_commitments(1, &all_none, [None; 5], Some(&root))
                .unwrap_err()
                .code(),
            "GRDR-AUDIT-0007"
        );

        let mut no_structural = all_none.clone();
        no_structural.salt_identifier = Some(test_salts()[0].to_vec());
        no_structural.salt_derived = Some(test_salts()[2].to_vec());
        assert_eq!(
            verify_five_way_commitments(
                1,
                &no_structural,
                [Some(b"a"), None, Some(b"a"), None, None],
                Some(&root),
            )
            .unwrap_err()
            .code(),
            "GRDR-AUDIT-0007"
        );

        let unprefixed_root = root.strip_prefix("sha256:").unwrap().to_owned();
        assert_eq!(
            verify_five_way_commitments(1, &full, [Some(b"a"); 5], Some(&unprefixed_root))
                .unwrap_err()
                .code(),
            "GRDR-AUDIT-0007"
        );

        let gen_salts = generate_five_way_salts().unwrap();
        let gen_refs: [&[u8]; 5] = [
            &gen_salts[0],
            &gen_salts[1],
            &gen_salts[2],
            &gen_salts[3],
            &gen_salts[4],
        ];
        assert!(build_five_way_commitments(gen_refs, [b"x"; 5]).is_ok());

        let mut all_zero = test_salts();
        all_zero[2] = &[0u8; 32];
        assert_eq!(
            build_five_way_commitments(all_zero, [b"a"; 5])
                .unwrap_err()
                .code(),
            "GRDR-AUDIT-0007"
        );

        let mut bad_verify_short = full.clone();
        bad_verify_short.salt_identifier = Some(vec![7u8; 15]);
        assert_eq!(
            verify_five_way_commitments(1, &bad_verify_short, [Some(b"a"); 5], Some(&root))
                .unwrap_err()
                .code(),
            "GRDR-AUDIT-0007"
        );
        let mut bad_verify_reuse = full.clone();
        bad_verify_reuse.salt_body = bad_verify_reuse.salt_identifier.clone();
        bad_verify_reuse.d_body = compute_class_commitment(
            CommitmentClass::ContentBody,
            bad_verify_reuse.salt_body.as_deref().unwrap_or(&[]),
            b"a",
        );
        let reuse_root = compute_commitment_root_digest(&bad_verify_reuse).unwrap();
        let reuse_err =
            verify_five_way_commitments(1, &bad_verify_reuse, [Some(b"a"); 5], Some(&reuse_root))
                .unwrap_err();
        assert_eq!(reuse_err.code(), "GRDR-AUDIT-0007");
        assert!(reuse_err.to_string().contains("reused salt"));
        let mut missing_derived = full.clone();
        missing_derived.salt_derived = None;
        assert_eq!(
            verify_five_way_commitments_with_withheld(
                1,
                &missing_derived,
                [Some(b"a"), Some(b"a"), None, Some(b"a"), Some(b"a")],
                Some(&[]),
                Some(&root),
            )
            .unwrap_err()
            .code(),
            "GRDR-AUDIT-0007"
        );
        assert_eq!(
            verify_five_way_commitments_with_withheld(
                1,
                &full,
                [Some(b"a"); 5],
                Some(&[CommitmentClass::Derived]),
                Some(&root),
            )
            .unwrap_err()
            .code(),
            "GRDR-AUDIT-0007"
        );
        let mut reduced_id = full.clone();
        reduced_id.salt_identifier = None;
        assert_eq!(
            verify_five_way_commitments(
                1,
                &reduced_id,
                [None, Some(b"a"), Some(b"a"), Some(b"a"), Some(b"a")],
                Some(&root),
            )
            .unwrap_err()
            .code(),
            "GRDR-AUDIT-0007"
        );
        assert_eq!(
            verify_five_way_commitments_with_withheld(
                1,
                &reduced_id,
                [None, Some(b"a"), Some(b"a"), Some(b"a"), Some(b"a")],
                Some(&[]),
                Some(&root),
            )
            .unwrap_err()
            .code(),
            "GRDR-AUDIT-0007"
        );
        assert_eq!(
            verify_five_way_commitments_with_withheld(
                1,
                &full,
                [Some(b"a"); 5],
                Some(&[CommitmentClass::Identifier]),
                Some(&root),
            )
            .unwrap_err()
            .code(),
            "GRDR-AUDIT-0007"
        );
    }
}
