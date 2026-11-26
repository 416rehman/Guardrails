// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use grdr_crypto::{Sha256Hasher, constant_time_eq, encode_lower_hex, sha256_digest};

use super::lane::{MerkleConsistencyInput, MerkleInclusionInput};
use super::{AuditVerifyError, is_sha256_hex, normalize_prefixed_digest};

const MAX_INCLUSION_PROOF_LEN: usize = 64;
const MAX_CONSISTENCY_PROOF_LEN: usize = 65;

fn merkle_err(line: usize, detail: impl Into<String>) -> AuditVerifyError {
    AuditVerifyError::MerkleProofMismatch {
        line,
        detail: detail.into(),
    }
}

fn merkle_hash_tag(prefix: u8, left: &[u8], right: &[u8]) -> [u8; 32] {
    let mut h = Sha256Hasher::new();
    h.update(&[prefix]);
    h.update(left);
    h.update(right);
    h.finalize_digest()
}

pub fn merkle_hash_leaf(leaf: &[u8]) -> [u8; 32] {
    merkle_hash_tag(0x00, leaf, &[])
}

pub fn merkle_hash_children(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    merkle_hash_tag(0x01, left, right)
}

fn largest_pow2_lt(n: u64) -> u64 {
    if n <= 1 {
        0
    } else {
        1u64.checked_shl(n.saturating_sub(1).ilog2()).unwrap_or(0)
    }
}

fn mth_bytes(leaves: &[&[u8]]) -> [u8; 32] {
    match leaves {
        [] => sha256_digest(&[]),
        [single] => merkle_hash_leaf(single),
        many => {
            let n = u64::try_from(many.len()).unwrap_or(u64::MAX);
            let k = usize::try_from(largest_pow2_lt(n)).unwrap_or(1);
            let Some((left, right)) = many.split_at_checked(k) else {
                return sha256_digest(&[]);
            };
            merkle_hash_children(&mth_bytes(left), &mth_bytes(right))
        }
    }
}

pub fn merkle_root_hex(leaves: &[&[u8]]) -> String {
    format!("sha256:{}", encode_lower_hex(&mth_bytes(leaves)))
}

fn build_merkle_proof(
    leaves: &[&[u8]],
    target: usize,
    is_consistency: bool,
    complete: bool,
    out: &mut Vec<String>,
) {
    let n = leaves.len();
    if is_consistency && target == n {
        if !complete {
            out.push(format!("sha256:{}", encode_lower_hex(&mth_bytes(leaves))));
        }
        return;
    }
    if n <= 1 {
        return;
    }
    let n_u64 = u64::try_from(n).unwrap_or(u64::MAX);
    let k = usize::try_from(largest_pow2_lt(n_u64)).unwrap_or(1);
    let Some((left, right)) = leaves.split_at_checked(k) else {
        return;
    };
    let go_left = if is_consistency {
        target <= k
    } else {
        target < k
    };
    if go_left {
        build_merkle_proof(left, target, is_consistency, complete, out);
        out.push(format!("sha256:{}", encode_lower_hex(&mth_bytes(right))));
    } else {
        build_merkle_proof(right, target.saturating_sub(k), is_consistency, false, out);
        out.push(format!("sha256:{}", encode_lower_hex(&mth_bytes(left))));
    }
}

pub fn merkle_inclusion_proof(
    leaves: &[&[u8]],
    leaf_index: usize,
) -> Result<Vec<String>, AuditVerifyError> {
    if leaf_index >= leaves.len() {
        return Err(merkle_err(0, "leaf_index out of range"));
    }
    let mut out = Vec::new();
    build_merkle_proof(leaves, leaf_index, false, true, &mut out);
    Ok(out)
}

pub fn merkle_consistency_proof(
    leaves: &[&[u8]],
    first_size: usize,
) -> Result<Vec<String>, AuditVerifyError> {
    if first_size == 0 || first_size > leaves.len() {
        return Err(merkle_err(0, "invalid consistency first_size"));
    }
    let mut out = Vec::new();
    build_merkle_proof(leaves, first_size, true, true, &mut out);
    Ok(out)
}

fn eval_inclusion(
    line: usize,
    leaf_h: [u8; 32],
    idx: u64,
    size: u64,
    path: &[[u8; 32]],
) -> Result<[u8; 32], AuditVerifyError> {
    if size == 1 {
        return if path.is_empty() && idx == 0 {
            Ok(leaf_h)
        } else {
            Err(merkle_err(line, "trailing inclusion nodes"))
        };
    }
    let (sibling, rest) = path
        .split_last()
        .ok_or_else(|| merkle_err(line, "truncated audit_path"))?;
    let k = largest_pow2_lt(size);
    if idx < k {
        Ok(merkle_hash_children(
            &eval_inclusion(line, leaf_h, idx, k, rest)?,
            sibling,
        ))
    } else {
        Ok(merkle_hash_children(
            sibling,
            &eval_inclusion(
                line,
                leaf_h,
                idx.saturating_sub(k),
                size.saturating_sub(k),
                rest,
            )?,
        ))
    }
}

pub fn verify_merkle_inclusion(
    line: usize,
    leaf: &[u8],
    leaf_index: u64,
    tree_size: u64,
    audit_path: &[String],
    expected_root: &str,
) -> Result<(), AuditVerifyError> {
    if tree_size == 0 || leaf_index >= tree_size || audit_path.len() > MAX_INCLUSION_PROOF_LEN {
        return Err(merkle_err(line, "invalid inclusion bounds"));
    }
    let expected = parse_digest_32(line, expected_root)?;
    let decoded = audit_path
        .iter()
        .map(|s| parse_digest_32(line, s))
        .collect::<Result<Vec<_>, _>>()?;
    let computed = eval_inclusion(
        line,
        merkle_hash_leaf(leaf),
        leaf_index,
        tree_size,
        &decoded,
    )?;
    if !constant_time_eq(&computed, &expected) {
        return Err(merkle_err(line, "inclusion root mismatch"));
    }
    Ok(())
}

fn eval_consistency(
    line: usize,
    m: u64,
    n: u64,
    complete: bool,
    known_first: [u8; 32],
    proof: &[[u8; 32]],
) -> Result<([u8; 32], [u8; 32]), AuditVerifyError> {
    if m == n {
        return match (complete, proof) {
            (true, []) => Ok((known_first, known_first)),
            (false, [single]) => Ok((*single, *single)),
            _ => Err(merkle_err(line, "malformed consistency proof length")),
        };
    }
    let (sibling, rest) = path_split(line, proof)?;
    let k = largest_pow2_lt(n);
    if m <= k {
        let (fl, sl) = eval_consistency(line, m, k, complete, known_first, rest)?;
        Ok((fl, merkle_hash_children(&sl, sibling)))
    } else {
        let (fr, sr) = eval_consistency(
            line,
            m.saturating_sub(k),
            n.saturating_sub(k),
            false,
            known_first,
            rest,
        )?;
        Ok((
            merkle_hash_children(sibling, &fr),
            merkle_hash_children(sibling, &sr),
        ))
    }
}

fn path_split(
    line: usize,
    proof: &[[u8; 32]],
) -> Result<(&[u8; 32], &[[u8; 32]]), AuditVerifyError> {
    proof
        .split_last()
        .ok_or_else(|| merkle_err(line, "truncated consistency proof"))
}

pub fn verify_merkle_consistency(
    line: usize,
    first_size: u64,
    second_size: u64,
    first_root: &str,
    second_root: &str,
    proof: &[String],
) -> Result<(), AuditVerifyError> {
    if first_size == 0 || first_size > second_size || proof.len() > MAX_CONSISTENCY_PROOF_LEN {
        return Err(merkle_err(line, "invalid consistency tree sizes"));
    }
    let first = parse_digest_32(line, first_root)?;
    let second = parse_digest_32(line, second_root)?;
    let decoded = proof
        .iter()
        .map(|s| parse_digest_32(line, s))
        .collect::<Result<Vec<_>, _>>()?;
    let (c_first, c_second) =
        eval_consistency(line, first_size, second_size, true, first, &decoded)?;
    if !constant_time_eq(&c_first, &first) || !constant_time_eq(&c_second, &second) {
        return Err(merkle_err(line, "consistency root mismatch"));
    }
    Ok(())
}

fn parse_digest_32(line: usize, raw: &str) -> Result<[u8; 32], AuditVerifyError> {
    let Some(hex) = raw.strip_prefix("sha256:") else {
        return Err(merkle_err(line, "digest must begin with sha256:"));
    };
    if !is_sha256_hex(hex) {
        return Err(merkle_err(line, "digest is not 64 lowercase hex chars"));
    }
    let mut out = [0u8; 32];
    let (pairs, _) = hex.as_bytes().as_chunks::<2>();
    for (idx, &[hi_b, lo_b]) in pairs.iter().enumerate() {
        if let Some(slot) = out.get_mut(idx) {
            *slot = (hex_val(hi_b) << 4) | hex_val(lo_b);
        }
    }
    Ok(out)
}

fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b.saturating_sub(b'0'),
        _ => b.saturating_sub(b'a').saturating_add(10),
    }
}

pub(crate) fn verify_lane_merkle_checkpoint(
    line: usize,
    entry_hash: &str,
    commitment_root: &str,
    prev_merkle: Option<&(u64, String)>,
    merkle: Option<&MerkleInclusionInput<'_>>,
    consistency: Option<&MerkleConsistencyInput<'_>>,
) -> Result<Option<(u64, String)>, AuditVerifyError> {
    if let Some(m) = merkle {
        let leaf_matches = constant_time_eq(m.leaf, entry_hash.as_bytes())
            || constant_time_eq(m.leaf, commitment_root.as_bytes());
        if !leaf_matches {
            return Err(merkle_err(
                line,
                "merkle leaf must match entry_hash or commitment_root_digest",
            ));
        }
        verify_merkle_inclusion(
            line,
            m.leaf,
            m.leaf_index,
            m.tree_size,
            m.audit_path,
            m.expected_root,
        )?;
    }
    if let Some(c) = consistency {
        verify_merkle_consistency(
            line,
            c.first_size,
            c.second_size,
            c.first_root,
            c.second_root,
            c.proof,
        )?;
    }
    let c_first = consistency.and_then(|c| normalize_prefixed_digest(c.first_root));
    let c_second = consistency.and_then(|c| normalize_prefixed_digest(c.second_root));
    let m_root = merkle.and_then(|m| normalize_prefixed_digest(m.expected_root));

    if let (Some(m), Some(c), Some(mr), Some(cs)) = (merkle, consistency, &m_root, &c_second)
        && (m.tree_size != c.second_size || !constant_time_eq(mr.as_bytes(), cs.as_bytes()))
    {
        return Err(merkle_err(
            line,
            "merkle inclusion root/size disagrees with consistency proof",
        ));
    }
    if let (Some((prev_sz, prev_root)), Some(c), Some(cf)) = (prev_merkle, consistency, &c_first)
        && (c.first_size != *prev_sz || !constant_time_eq(cf.as_bytes(), prev_root.as_bytes()))
    {
        return Err(merkle_err(
            line,
            "merkle consistency proof does not extend prior checkpoint",
        ));
    }
    if let (Some((prev_sz, prev_root)), Some(m), None, Some(mr)) =
        (prev_merkle, merkle, consistency, &m_root)
    {
        if m.tree_size < *prev_sz {
            return Err(merkle_err(line, "merkle tree_size regression"));
        }
        if m.tree_size == *prev_sz && !constant_time_eq(mr.as_bytes(), prev_root.as_bytes()) {
            return Err(merkle_err(line, "merkle root fork at equal tree_size"));
        }
        if m.tree_size > *prev_sz {
            return Err(merkle_err(
                line,
                "merkle tree grew without consistency proof",
            ));
        }
    }
    match (consistency, c_second, merkle, m_root) {
        (Some(c), Some(cs), _, _) => Ok(Some((c.second_size, cs))),
        (_, _, Some(m), Some(mr)) => Ok(Some((m.tree_size, mr))),
        _ => Ok(prev_merkle.cloned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::GENESIS_PREV_HASH;

    #[test]
    fn rfc6962_merkle_inclusion_and_consistency_proofs_verify_and_reject_tamper() {
        assert_eq!(
            merkle_root_hex(&[]),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let single_root = merkle_root_hex(&[b"only"]);
        verify_merkle_inclusion(1, b"only", 0, 1, &[], &single_root).unwrap();
        assert_eq!(
            verify_merkle_inclusion(
                1,
                b"only",
                0,
                1,
                std::slice::from_ref(&single_root),
                &single_root
            )
            .unwrap_err()
            .code(),
            "GRDR-AUDIT-0008"
        );

        let pow2: [&[u8]; 4] = [b"a", b"b", b"c", b"d"];
        let pow2_root = merkle_root_hex(&pow2);
        for (i, item) in pow2.iter().enumerate() {
            let path = merkle_inclusion_proof(&pow2, i).unwrap();
            verify_merkle_inclusion(1, item, i as u64, 4, &path, &pow2_root).unwrap();
        }
        verify_merkle_consistency(1, 4, 4, &pow2_root, &pow2_root, &[]).unwrap();
        assert_eq!(
            verify_merkle_consistency(
                1,
                4,
                4,
                &pow2_root,
                &pow2_root,
                std::slice::from_ref(&pow2_root)
            )
            .unwrap_err()
            .code(),
            "GRDR-AUDIT-0008"
        );

        let leaves: [&[u8]; 7] = [b"l0", b"l1", b"l2", b"l3", b"l4", b"l5", b"l6"];
        let root7 = merkle_root_hex(&leaves);
        for (i, item) in leaves.iter().enumerate() {
            let path = merkle_inclusion_proof(&leaves, i).unwrap();
            verify_merkle_inclusion(1, item, i as u64, 7, &path, &root7).unwrap();
        }
        let path2 = merkle_inclusion_proof(&leaves, 2).unwrap();
        assert_eq!(
            verify_merkle_inclusion(1, b"tampered", 2, 7, &path2, &root7)
                .unwrap_err()
                .code(),
            "GRDR-AUDIT-0008"
        );
        let mut extra_path = path2.clone();
        extra_path.push(GENESIS_PREV_HASH.into());
        assert_eq!(
            verify_merkle_inclusion(1, b"l2", 2, 7, &extra_path, &root7)
                .unwrap_err()
                .code(),
            "GRDR-AUDIT-0008"
        );
        let short_path = &path2[..path2.len().saturating_sub(1)];
        assert_eq!(
            verify_merkle_inclusion(1, b"l2", 2, 7, short_path, &root7)
                .unwrap_err()
                .code(),
            "GRDR-AUDIT-0008"
        );

        for m in [1usize, 3, 4, 5, 7] {
            let root_m = merkle_root_hex(&leaves[..m]);
            let cons = merkle_consistency_proof(&leaves, m).unwrap();
            verify_merkle_consistency(1, m as u64, 7, &root_m, &root7, &cons).unwrap();
            if !cons.is_empty() {
                assert_eq!(
                    verify_merkle_consistency(
                        1,
                        m as u64,
                        7,
                        &root_m,
                        &root7,
                        &cons[..cons.len() - 1]
                    )
                    .unwrap_err()
                    .code(),
                    "GRDR-AUDIT-0008"
                );
            }
        }
        assert_eq!(
            verify_merkle_consistency(1, 4, 7, &pow2_root, GENESIS_PREV_HASH, &[])
                .unwrap_err()
                .code(),
            "GRDR-AUDIT-0008"
        );
    }

    #[test]
    fn merkle_rejects_second_preimage_oob_whitespace_and_max_depth() {
        let two_leaves: [&[u8]; 2] = [b"left", b"right"];
        let h_l = merkle_hash_leaf(two_leaves[0]);
        let h_r = merkle_hash_leaf(two_leaves[1]);
        let mut interior_preimage = Vec::with_capacity(64);
        interior_preimage.extend_from_slice(&h_l);
        interior_preimage.extend_from_slice(&h_r);
        assert_ne!(
            merkle_root_hex(&two_leaves),
            merkle_root_hex(&[&interior_preimage]),
            "0x00 leaf vs 0x01 node domain separation must prevent second-preimage forgery"
        );

        let r1 = merkle_root_hex(&[b"x"]);
        assert_eq!(
            verify_merkle_inclusion(1, b"x", 0, 0, &[], &r1)
                .unwrap_err()
                .code(),
            "GRDR-AUDIT-0008"
        );
        assert_eq!(
            verify_merkle_inclusion(1, b"x", 1, 1, &[], &r1)
                .unwrap_err()
                .code(),
            "GRDR-AUDIT-0008"
        );
        assert_eq!(
            verify_merkle_inclusion(1, b"x", 0, 1, &[], &format!(" {r1}"))
                .unwrap_err()
                .code(),
            "GRDR-AUDIT-0008"
        );
        let bare = r1.strip_prefix("sha256:").unwrap();
        assert_eq!(
            verify_merkle_inclusion(1, b"x", 0, 1, &[], bare)
                .unwrap_err()
                .code(),
            "GRDR-AUDIT-0008"
        );

        let oversized_inc = vec![GENESIS_PREV_HASH.to_owned(); 65];
        assert_eq!(
            verify_merkle_inclusion(1, b"x", 0, 2, &oversized_inc, &r1)
                .unwrap_err()
                .code(),
            "GRDR-AUDIT-0008"
        );

        assert_eq!(
            verify_merkle_consistency(1, 0, 1, &r1, &r1, &[])
                .unwrap_err()
                .code(),
            "GRDR-AUDIT-0008"
        );
        assert_eq!(
            verify_merkle_consistency(1, 2, 1, &r1, &r1, &[])
                .unwrap_err()
                .code(),
            "GRDR-AUDIT-0008"
        );
        let depth65 = vec![GENESIS_PREV_HASH.to_owned(); 65];
        let depth65_err =
            verify_merkle_consistency(1, (1u64 << 63) + 1, u64::MAX, &r1, &r1, &depth65)
                .unwrap_err();
        assert_ne!(
            depth65_err.to_string(),
            "GRDR-AUDIT-0008: RFC 6962 Merkle proof mismatch at line 1: invalid consistency tree sizes",
            "65-node consistency proof must pass length gate and reach eval_consistency"
        );
        let depth66 = vec![GENESIS_PREV_HASH.to_owned(); 66];
        assert_eq!(
            verify_merkle_consistency(1, 1, u64::MAX, &r1, &r1, &depth66)
                .unwrap_err()
                .to_string(),
            "GRDR-AUDIT-0008: RFC 6962 Merkle proof mismatch at line 1: invalid consistency tree sizes"
        );

        assert_eq!(
            verify_merkle_consistency(1, 1, 1, &r1, GENESIS_PREV_HASH, &[])
                .unwrap_err()
                .code(),
            "GRDR-AUDIT-0008"
        );

        let cp_leaves: [&[u8]; 3] = [b"eh0", b"eh1", b"eh2"];
        let cp_r1 = merkle_root_hex(&cp_leaves[..1]);
        let cp_r2 = merkle_root_hex(&cp_leaves[..2]);
        let cp_r3 = merkle_root_hex(&cp_leaves);
        let inc1 = merkle_inclusion_proof(&cp_leaves[..2], 1).unwrap();
        let cons12 = merkle_consistency_proof(&cp_leaves[..2], 1).unwrap();
        let inc2 = merkle_inclusion_proof(&cp_leaves, 2).unwrap();

        assert_eq!(
            verify_lane_merkle_checkpoint(
                1,
                "eh1",
                "cr1",
                None,
                Some(&MerkleInclusionInput {
                    leaf: b"unrelated",
                    leaf_index: 1,
                    tree_size: 2,
                    audit_path: &inc1,
                    expected_root: &cp_r2,
                }),
                None,
            )
            .unwrap_err()
            .code(),
            "GRDR-AUDIT-0008"
        );
        assert_eq!(
            verify_lane_merkle_checkpoint(
                2,
                "eh1",
                "cr1",
                Some(&(1, cp_r1.clone())),
                Some(&MerkleInclusionInput {
                    leaf: b"eh1",
                    leaf_index: 1,
                    tree_size: 2,
                    audit_path: &inc1,
                    expected_root: &cp_r2,
                }),
                Some(&MerkleConsistencyInput {
                    first_size: 1,
                    second_size: 3,
                    first_root: &cp_r1,
                    second_root: &cp_r3,
                    proof: &merkle_consistency_proof(&cp_leaves, 1).unwrap(),
                }),
            )
            .unwrap_err()
            .code(),
            "GRDR-AUDIT-0008"
        );
        assert_eq!(
            verify_lane_merkle_checkpoint(
                2,
                "eh1",
                "cr1",
                Some(&(2, GENESIS_PREV_HASH.into())),
                None,
                Some(&MerkleConsistencyInput {
                    first_size: 1,
                    second_size: 2,
                    first_root: &cp_r1,
                    second_root: &cp_r2,
                    proof: &cons12,
                }),
            )
            .unwrap_err()
            .code(),
            "GRDR-AUDIT-0008"
        );
        assert_eq!(
            verify_lane_merkle_checkpoint(
                2,
                "eh1",
                "cr1",
                Some(&(3, cp_r3.clone())),
                Some(&MerkleInclusionInput {
                    leaf: b"eh1",
                    leaf_index: 1,
                    tree_size: 2,
                    audit_path: &inc1,
                    expected_root: &cp_r2,
                }),
                None,
            )
            .unwrap_err()
            .code(),
            "GRDR-AUDIT-0008"
        );
        assert_eq!(
            verify_lane_merkle_checkpoint(
                2,
                "eh1",
                "cr1",
                Some(&(2, GENESIS_PREV_HASH.into())),
                Some(&MerkleInclusionInput {
                    leaf: b"eh1",
                    leaf_index: 1,
                    tree_size: 2,
                    audit_path: &inc1,
                    expected_root: &cp_r2,
                }),
                None,
            )
            .unwrap_err()
            .code(),
            "GRDR-AUDIT-0008"
        );
        assert_eq!(
            verify_lane_merkle_checkpoint(
                3,
                "eh2",
                "cr2",
                Some(&(2, cp_r2.clone())),
                Some(&MerkleInclusionInput {
                    leaf: b"eh2",
                    leaf_index: 2,
                    tree_size: 3,
                    audit_path: &inc2,
                    expected_root: &cp_r3,
                }),
                None,
            )
            .unwrap_err()
            .code(),
            "GRDR-AUDIT-0008"
        );
    }
}
