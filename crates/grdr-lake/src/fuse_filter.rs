// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeSet;

use grdr_crypto::domain_sha256_digest;
use grdr_ports::LakeObservable;

const HASH_DOMAIN: &str = "grdr.lake.fuse16.v1";
const SEGMENT_MULTIPLIER_NUM: usize = 123;
const SEGMENT_MULTIPLIER_DEN: usize = 100;
const EXTRA_SLOTS: usize = 33;
const MAX_CONSTRUCTION_SEEDS: u64 = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ObservableFuseFilter {
    pub(crate) seed: u64,
    pub(crate) segment_len: usize,
    pub(crate) fingerprints: Vec<u16>,
}

impl ObservableFuseFilter {
    pub(crate) fn build(observables: &[LakeObservable]) -> Self {
        let mut keys = BTreeSet::new();
        for obs in observables {
            keys.insert(typed_key(&obs.observable_type, &obs.value));
            keys.insert(untyped_key(&obs.value));
        }
        let key_list: Vec<String> = keys.into_iter().collect();
        if key_list.is_empty() {
            return Self {
                seed: 0,
                segment_len: 0,
                fingerprints: Vec::new(),
            };
        }

        let raw_cap = key_list
            .len()
            .saturating_mul(SEGMENT_MULTIPLIER_NUM)
            .div_ceil(SEGMENT_MULTIPLIER_DEN)
            .saturating_add(EXTRA_SLOTS);
        let segment_len = raw_cap.div_ceil(3).max(2);
        let total_slots = segment_len.saturating_mul(3);

        for seed in 0..MAX_CONSTRUCTION_SEEDS {
            if let Some(fps) = try_build_with_seed(&key_list, seed, segment_len, total_slots) {
                return Self {
                    seed,
                    segment_len,
                    fingerprints: fps,
                };
            }
        }

        // Conservative pass-all fallback if 3-wise peeling ever hits cycles across 64 seeds.
        let wide_seg = segment_len.saturating_mul(2).max(16);
        let wide_slots = wide_seg.saturating_mul(3);
        if let Some(fps) = try_build_with_seed(&key_list, 0x9e37_79b9, wide_seg, wide_slots) {
            Self {
                seed: 0x9e37_79b9,
                segment_len: wide_seg,
                fingerprints: fps,
            }
        } else {
            Self {
                seed: u64::MAX,
                segment_len: 1,
                fingerprints: Vec::new(),
            }
        }
    }

    pub(crate) fn may_contain(&self, observable_type: Option<&str>, value: &str) -> bool {
        if self.segment_len == 0 {
            return false;
        }
        if self.fingerprints.len() < 3 {
            return true;
        }
        let key = match observable_type {
            Some(kind) => typed_key(kind, value),
            None => untyped_key(value),
        };
        let (h0, h1, h2, fp) = key_hashes(&key, self.seed, self.segment_len);
        let v0 = self.fingerprints.get(h0).copied().unwrap_or(0);
        let v1 = self.fingerprints.get(h1).copied().unwrap_or(0);
        let v2 = self.fingerprints.get(h2).copied().unwrap_or(0);
        (v0 ^ v1 ^ v2) == fp
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(16usize.saturating_add(self.fingerprints.len().saturating_mul(2)));
        out.extend_from_slice(&self.seed.to_le_bytes());
        out.extend_from_slice(&u64::try_from(self.segment_len).unwrap_or(0).to_le_bytes());
        for &fp in &self.fingerprints {
            out.extend_from_slice(&fp.to_le_bytes());
        }
        out
    }

    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 16 {
            return None;
        }
        let seed_arr: [u8; 8] = bytes.get(..8)?.try_into().ok()?;
        let seg_arr: [u8; 8] = bytes.get(8..16)?.try_into().ok()?;
        let seed = u64::from_le_bytes(seed_arr);
        let segment_len = usize::try_from(u64::from_le_bytes(seg_arr)).ok()?;
        const MAX_FUSE_SEGMENT_LEN: usize = 16_000_000;
        let payload = bytes.get(16..)?;
        if payload.len() % 2 != 0 {
            return None;
        }
        let fp_count = payload.len() / 2;
        let is_empty = segment_len == 0 && fp_count == 0;
        let is_pass_all_fallback = seed == u64::MAX && segment_len == 1 && fp_count == 0;
        let is_valid_normal = (2..=MAX_FUSE_SEGMENT_LEN).contains(&segment_len)
            && segment_len.checked_mul(3) == Some(fp_count);
        if !is_empty && !is_pass_all_fallback && !is_valid_normal {
            return None;
        }
        let mut fingerprints = Vec::with_capacity(fp_count);
        let (chunks, _) = payload.as_chunks::<2>();
        for &[lo, hi] in chunks {
            fingerprints.push(u16::from_le_bytes([lo, hi]));
        }
        Some(Self {
            seed,
            segment_len,
            fingerprints,
        })
    }
}

fn try_build_with_seed(
    keys: &[String],
    seed: u64,
    segment_len: usize,
    total_slots: usize,
) -> Option<Vec<u16>> {
    let mut xor_key_idx = vec![0usize; total_slots];
    let mut counts = vec![0usize; total_slots];

    for (idx, key) in keys.iter().enumerate() {
        let (h0, h1, h2, _) = key_hashes(key, seed, segment_len);
        for slot in [h0, h1, h2] {
            if let Some(c) = counts.get_mut(slot) {
                *c = c.saturating_add(1);
            }
            if let Some(x) = xor_key_idx.get_mut(slot) {
                *x ^= idx;
            }
        }
    }

    let mut queue = Vec::with_capacity(total_slots);
    for (slot, &count) in counts.iter().enumerate() {
        if count == 1 {
            queue.push(slot);
        }
    }

    let mut stack: Vec<(usize, usize)> = Vec::with_capacity(keys.len());
    let mut head = 0usize;
    while let Some(&slot) = queue.get(head) {
        head = head.saturating_add(1);
        if counts.get(slot).copied().unwrap_or(0) != 1 {
            continue;
        }
        let key_idx = xor_key_idx.get(slot).copied().unwrap_or(0);
        let Some(key) = keys.get(key_idx) else {
            continue;
        };
        stack.push((key_idx, slot));
        let (h0, h1, h2, _) = key_hashes(key, seed, segment_len);
        for h in [h0, h1, h2] {
            if let Some(x) = xor_key_idx.get_mut(h) {
                *x ^= key_idx;
            }
            if let Some(c) = counts.get_mut(h) {
                *c = c.saturating_sub(1);
                if *c == 1 {
                    queue.push(h);
                }
            }
        }
    }

    if stack.len() != keys.len() {
        return None;
    }

    let mut fingerprints = vec![0u16; total_slots];
    for &(key_idx, slot) in stack.iter().rev() {
        let key = keys.get(key_idx)?;
        let (h0, h1, h2, fp) = key_hashes(key, seed, segment_len);
        let v0 = fingerprints.get(h0).copied().unwrap_or(0);
        let v1 = fingerprints.get(h1).copied().unwrap_or(0);
        let v2 = fingerprints.get(h2).copied().unwrap_or(0);
        if let Some(cell) = fingerprints.get_mut(slot) {
            *cell = fp ^ v0 ^ v1 ^ v2;
        }
    }
    Some(fingerprints)
}

fn typed_key(observable_type: &str, value: &str) -> String {
    format!(
        "{}\0{}",
        observable_type.trim().to_ascii_lowercase(),
        value.trim()
    )
}

fn untyped_key(value: &str) -> String {
    format!("\0{}", value.trim())
}

fn key_hashes(key: &str, seed: u64, segment_len: usize) -> (usize, usize, usize, u16) {
    let mut payload = Vec::with_capacity(8usize.saturating_add(key.len()));
    payload.extend_from_slice(&seed.to_le_bytes());
    payload.extend_from_slice(key.as_bytes());
    let digest = domain_sha256_digest(HASH_DOMAIN, &payload);
    let r0 = u64_from_slice(&digest, 0);
    let r1 = u64_from_slice(&digest, 8);
    let r2 = u64_from_slice(&digest, 16);
    let r3 = u64_from_slice(&digest, 24);

    let seg = u128::try_from(segment_len).unwrap_or(1);
    let h0 = usize::try_from((u128::from(r0).saturating_mul(seg)) >> 64).unwrap_or(0);
    let h1 = segment_len
        .saturating_add(usize::try_from((u128::from(r1).saturating_mul(seg)) >> 64).unwrap_or(0));
    let h2 = segment_len
        .saturating_mul(2)
        .saturating_add(usize::try_from((u128::from(r2).saturating_mul(seg)) >> 64).unwrap_or(0));
    let fp = u16::try_from(r3 & 0xFFFF).unwrap_or(0);
    (h0, h1, h2, fp)
}

fn u64_from_slice(digest: &[u8; 32], start: usize) -> u64 {
    let end = start.saturating_add(8);
    let arr: [u8; 8] = digest
        .get(start..end)
        .and_then(|s| s.try_into().ok())
        .unwrap_or([0; 8]);
    u64::from_le_bytes(arr)
}
