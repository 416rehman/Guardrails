// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Validated 24-bit Binary Fuse filter (`docs/design/14`).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use grdr_crypto::sha256_digest;

use crate::IntelError;

const MAX_SEED_ATTEMPTS: u64 = 32;
const MAX_SEGMENT_LENGTH: u32 = 65_536;
const MAX_ARRAY_BYTES: usize = 32 * 1024 * 1024;
const MAX_INITIAL_FINGERPRINT_ALLOC: usize = 4_096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "BinaryFuse24Wire")]
pub struct BinaryFuse24 {
    seed: u64,
    segment_length: u32,
    segment_length_mask: u32,
    segment_count_length: u32,
    fingerprints_3byte: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BinaryFuse24Wire {
    seed: u64,
    segment_length: u32,
    segment_length_mask: u32,
    segment_count_length: u32,
    fingerprints_3byte: BoundedFingerprints,
}

struct BoundedFingerprints(Vec<u8>);

impl<'de> serde::Deserialize<'de> for BoundedFingerprints {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct FingerprintsVisitor;

        impl<'de> serde::de::Visitor<'de> for FingerprintsVisitor {
            type Value = BoundedFingerprints;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "byte sequence of at most {MAX_ARRAY_BYTES} bytes")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let cap = seq
                    .size_hint()
                    .unwrap_or(0)
                    .min(MAX_INITIAL_FINGERPRINT_ALLOC);
                let mut out = Vec::with_capacity(cap);
                while let Some(byte) = seq.next_element::<u8>()? {
                    if out.len() >= MAX_ARRAY_BYTES {
                        return Err(serde::de::Error::custom(
                            "fingerprints_3byte exceeds MAX_ARRAY_BYTES",
                        ));
                    }
                    out.push(byte);
                }
                Ok(BoundedFingerprints(out))
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.len() > MAX_ARRAY_BYTES {
                    return Err(E::custom("fingerprints_3byte exceeds MAX_ARRAY_BYTES"));
                }
                Ok(BoundedFingerprints(v.to_vec()))
            }

            fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.len() > MAX_ARRAY_BYTES {
                    return Err(E::custom("fingerprints_3byte exceeds MAX_ARRAY_BYTES"));
                }
                Ok(BoundedFingerprints(v))
            }
        }

        deserializer.deserialize_seq(FingerprintsVisitor)
    }
}

impl TryFrom<BinaryFuse24Wire> for BinaryFuse24 {
    type Error = IntelError;

    fn try_from(wire: BinaryFuse24Wire) -> Result<Self, Self::Error> {
        Self::from_parts(
            wire.seed,
            wire.segment_length,
            wire.segment_length_mask,
            wire.segment_count_length,
            wire.fingerprints_3byte.0,
        )
    }
}

impl BinaryFuse24 {
    /// Constructs a validated `BinaryFuse24` from serialized parts, rejecting tampered
    /// segment lengths, masks, or buffer sizes with `IntelError::CorruptFilter`.
    pub fn from_parts(
        seed: u64,
        segment_length: u32,
        segment_length_mask: u32,
        segment_count_length: u32,
        fingerprints_3byte: Vec<u8>,
    ) -> Result<Self, IntelError> {
        let candidate = Self {
            seed,
            segment_length,
            segment_length_mask,
            segment_count_length,
            fingerprints_3byte,
        };
        candidate.validate()?;
        Ok(candidate)
    }

    pub fn build(keys: &[String]) -> Result<Self, IntelError> {
        let mut unique: Vec<u64> = keys
            .iter()
            .map(|k| hash_observable_u64(k))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        if unique.is_empty() {
            return Ok(Self {
                seed: 0,
                segment_length: 1,
                segment_length_mask: 0,
                segment_count_length: 0,
                fingerprints_3byte: vec![0_u8; 9],
            });
        }

        let size = unique.len();
        let seg_len = calculate_segment_length(size);
        let seg_len_u32 = u32::try_from(seg_len)
            .map_err(|_| IntelError::CorruptFilter("segment length overflow".into()))?;
        let seg_mask = seg_len_u32.saturating_sub(1);
        let min_cap = size
            .saturating_mul(135)
            .saturating_div(100)
            .saturating_add(seg_len.saturating_mul(3));
        let num_segs_total = (min_cap
            .saturating_add(seg_len.saturating_sub(1))
            .checked_div(seg_len)
            .unwrap_or(0))
        .max(4);
        let array_len = num_segs_total.saturating_mul(seg_len);
        let array_bytes = array_len
            .checked_mul(3)
            .ok_or_else(|| IntelError::CorruptFilter("binary fuse byte size overflow".into()))?;
        if array_bytes > MAX_ARRAY_BYTES {
            return Err(IntelError::CorruptFilter(
                "binary fuse filter exceeds MAX_ARRAY_BYTES".into(),
            ));
        }
        let seg_count_len = u32::try_from(num_segs_total.saturating_sub(2))
            .map_err(|_| IntelError::CorruptFilter("segment count overflow".into()))?;

        let mut base_seed = mix64(u64::try_from(size).unwrap_or(0) ^ 0x9E37_79B9_7F4A_7C15);
        for _ in 0..MAX_SEED_ATTEMPTS {
            if let Some(table) = try_construct_fuse(
                &mut unique,
                base_seed,
                seg_len_u32,
                seg_mask,
                seg_count_len,
                array_len,
            ) {
                let mut bytes = Vec::with_capacity(table.len().saturating_mul(3));
                for fp in table {
                    let le = fp.to_le_bytes();
                    bytes.push(*le.first().unwrap_or(&0));
                    bytes.push(*le.get(1).unwrap_or(&0));
                    bytes.push(*le.get(2).unwrap_or(&0));
                }
                return Self::from_parts(base_seed, seg_len_u32, seg_mask, seg_count_len, bytes);
            }
            base_seed = mix64(base_seed.wrapping_add(1));
        }

        Err(IntelError::CorruptFilter(
            "failed to construct binary fuse filter within seed attempts".into(),
        ))
    }

    pub fn validate(&self) -> Result<(), IntelError> {
        if self.fingerprints_3byte.len() > MAX_ARRAY_BYTES
            || !self.fingerprints_3byte.len().is_multiple_of(3)
        {
            return Err(IntelError::CorruptFilter(
                "invalid binary fuse fingerprint buffer length".into(),
            ));
        }
        if self.segment_count_length == 0 {
            if self.segment_length == 1
                && self.segment_length_mask == 0
                && self.fingerprints_3byte.len() == 9
            {
                return Ok(());
            }
            return Err(IntelError::CorruptFilter(
                "corrupt empty binary fuse filter header".into(),
            ));
        }
        if self.segment_length == 0
            || !self.segment_length.is_power_of_two()
            || self.segment_length > MAX_SEGMENT_LENGTH
        {
            return Err(IntelError::CorruptFilter(format!(
                "invalid binary fuse segment_length {}",
                self.segment_length
            )));
        }
        if self.segment_length_mask != self.segment_length.saturating_sub(1) {
            return Err(IntelError::CorruptFilter(
                "segment_length_mask mismatch".into(),
            ));
        }
        if self.segment_count_length < 2 {
            return Err(IntelError::CorruptFilter(
                "segment_count_length must be >= 2 for non-empty filter".into(),
            ));
        }
        let seg_count_total = usize::try_from(self.segment_count_length)
            .ok()
            .and_then(|c| c.checked_add(2))
            .ok_or_else(|| IntelError::CorruptFilter("segment count overflow".into()))?;
        let seg_len = usize::try_from(self.segment_length)
            .map_err(|_| IntelError::CorruptFilter("segment length overflow".into()))?;
        let expected_bytes = seg_count_total
            .checked_mul(seg_len)
            .and_then(|slots| slots.checked_mul(3))
            .ok_or_else(|| IntelError::CorruptFilter("binary fuse byte size overflow".into()))?;
        if self.fingerprints_3byte.len() != expected_bytes {
            return Err(IntelError::CorruptFilter(format!(
                "binary fuse buffer len {} does not match expected {expected_bytes}",
                self.fingerprints_3byte.len()
            )));
        }
        Ok(())
    }

    pub fn might_contain(&self, key: &str) -> Result<bool, IntelError> {
        self.validate()?;
        if self.segment_count_length == 0 {
            return Ok(false);
        }
        let h = hash_observable_u64(key);
        let key_hash = mix64(h ^ self.seed);
        let expected_fp = fingerprint24(key_hash);
        let (h0, h1, h2) = fuse_positions(
            key_hash,
            self.segment_length,
            self.segment_length_mask,
            self.segment_count_length,
        );
        let x0 = read_fp24(&self.fingerprints_3byte, h0)?;
        let x1 = read_fp24(&self.fingerprints_3byte, h1)?;
        let x2 = read_fp24(&self.fingerprints_3byte, h2)?;
        Ok((x0 ^ x1 ^ x2) == expected_fp)
    }

    #[must_use]
    pub const fn segment_length(&self) -> u32 {
        self.segment_length
    }
}

fn hash_observable_u64(key: &str) -> u64 {
    let digest = sha256_digest(key.as_bytes());
    let b = [
        *digest.first().unwrap_or(&0),
        *digest.get(1).unwrap_or(&0),
        *digest.get(2).unwrap_or(&0),
        *digest.get(3).unwrap_or(&0),
        *digest.get(4).unwrap_or(&0),
        *digest.get(5).unwrap_or(&0),
        *digest.get(6).unwrap_or(&0),
        *digest.get(7).unwrap_or(&0),
    ];
    u64::from_le_bytes(b)
}

const fn mix64(mut k: u64) -> u64 {
    k = (k ^ (k >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    k = (k ^ (k >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    k ^ (k >> 31)
}

const fn fingerprint24(hash: u64) -> u32 {
    ((hash ^ (hash >> 32)) as u32) & 0x00FF_FFFF
}

fn calculate_segment_length(size: usize) -> usize {
    let mut len: usize = 8;
    let target = (size / 6).clamp(8, 65_536);
    while len < target {
        len = len.saturating_mul(2);
    }
    len
}

fn fuse_positions(
    hash: u64,
    seg_len: u32,
    seg_mask: u32,
    seg_count_len: u32,
) -> (usize, usize, usize) {
    let r0 = u128::from(hash);
    let sc = u128::from(seg_count_len);
    let seg = u32::try_from((r0.wrapping_mul(sc)) >> 64).unwrap_or(0);
    let h0_base = seg.wrapping_mul(seg_len);

    let seg_bits = seg_len.trailing_zeros();
    let h0 = h0_base.saturating_add((hash as u32) & seg_mask);
    let h1_shift = hash.checked_shr(seg_bits).unwrap_or(0);
    let h2_shift = hash.checked_shr(seg_bits.saturating_mul(2)).unwrap_or(0);
    let h1_off = (h1_shift as u32) & seg_mask;
    let h2_off = (h2_shift as u32) & seg_mask;
    let h1 = h0_base.saturating_add(seg_len).saturating_add(h1_off);
    let h2 = h0_base
        .saturating_add(seg_len.saturating_mul(2))
        .saturating_add(h2_off);
    (h0 as usize, h1 as usize, h2 as usize)
}

fn try_construct_fuse(
    keys: &mut [u64],
    seed: u64,
    seg_len: u32,
    seg_mask: u32,
    seg_count_len: u32,
    array_len: usize,
) -> Option<Vec<u32>> {
    let mut t2count = vec![0_u8; array_len];
    let mut t2hash = vec![0_u64; array_len];

    for &k in keys.iter() {
        let h = mix64(k ^ seed);
        let (h0, h1, h2) = fuse_positions(h, seg_len, seg_mask, seg_count_len);
        for idx in [h0, h1, h2] {
            let cnt = t2count.get_mut(idx)?;
            if *cnt == u8::MAX {
                return None;
            }
            *cnt = cnt.saturating_add(1);
            let slot = t2hash.get_mut(idx)?;
            *slot ^= h;
        }
    }

    let mut alone: Vec<usize> = Vec::new();
    for (idx, &cnt) in t2count.iter().enumerate() {
        if cnt == 1 {
            alone.push(idx);
        }
    }

    let mut reverse_order: Vec<(u64, u8)> = Vec::with_capacity(keys.len());
    while let Some(idx) = alone.pop() {
        if t2count.get(idx).copied().unwrap_or(0) == 0 {
            continue;
        }
        let h = *t2hash.get(idx)?;
        let (h0, h1, h2) = fuse_positions(h, seg_len, seg_mask, seg_count_len);
        let found = if h0 == idx {
            0_u8
        } else if h1 == idx {
            1_u8
        } else {
            2_u8
        };
        reverse_order.push((h, found));
        for p in [h0, h1, h2] {
            let cnt = t2count.get_mut(p)?;
            *cnt = cnt.saturating_sub(1);
            *t2hash.get_mut(p)? ^= h;
            if *cnt == 1 {
                alone.push(p);
            }
        }
    }

    if reverse_order.len() != keys.len() {
        return None;
    }

    let mut fingerprints = vec![0_u32; array_len];
    for &(h, found) in reverse_order.iter().rev() {
        let (h0, h1, h2) = fuse_positions(h, seg_len, seg_mask, seg_count_len);
        let mut xor_val = fingerprint24(h);
        match found {
            0 => {
                xor_val ^= fingerprints.get(h1).copied().unwrap_or(0);
                xor_val ^= fingerprints.get(h2).copied().unwrap_or(0);
                if let Some(slot) = fingerprints.get_mut(h0) {
                    *slot = xor_val;
                }
            }
            1 => {
                xor_val ^= fingerprints.get(h0).copied().unwrap_or(0);
                xor_val ^= fingerprints.get(h2).copied().unwrap_or(0);
                if let Some(slot) = fingerprints.get_mut(h1) {
                    *slot = xor_val;
                }
            }
            _ => {
                xor_val ^= fingerprints.get(h0).copied().unwrap_or(0);
                xor_val ^= fingerprints.get(h1).copied().unwrap_or(0);
                if let Some(slot) = fingerprints.get_mut(h2) {
                    *slot = xor_val;
                }
            }
        }
    }
    Some(fingerprints)
}

fn read_fp24(buf: &[u8], slot: usize) -> Result<u32, IntelError> {
    let off = slot
        .checked_mul(3)
        .ok_or_else(|| IntelError::CorruptFilter("fuse slot offset overflow".into()))?;
    let b0 = buf
        .get(off)
        .copied()
        .ok_or_else(|| IntelError::CorruptFilter("fuse slot out of bounds".into()))?;
    let b1 = buf
        .get(off.saturating_add(1))
        .copied()
        .ok_or_else(|| IntelError::CorruptFilter("fuse slot out of bounds".into()))?;
    let b2 = buf
        .get(off.saturating_add(2))
        .copied()
        .ok_or_else(|| IntelError::CorruptFilter("fuse slot out of bounds".into()))?;
    Ok(u32::from(b0) | (u32::from(b1) << 8) | (u32::from(b2) << 16))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::de::{SeqAccess, Visitor};

    struct FloodSeqDeserializer {
        len: usize,
        pos: usize,
    }

    impl<'de> serde::Deserializer<'de> for FloodSeqDeserializer {
        type Error = serde::de::value::Error;

        fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            visitor.visit_seq(self)
        }

        serde::forward_to_deserialize_any! {
            bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
            bytes byte_buf option unit unit_struct newtype_struct seq tuple
            tuple_struct map struct enum identifier ignored_any
        }
    }

    impl<'de> SeqAccess<'de> for FloodSeqDeserializer {
        type Error = serde::de::value::Error;

        fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Self::Error>
        where
            T: serde::de::DeserializeSeed<'de>,
        {
            if self.pos >= self.len {
                return Ok(None);
            }
            self.pos = self.pos.saturating_add(1);
            seed.deserialize(serde::de::value::U8Deserializer::new(0))
                .map(Some)
        }

        fn size_hint(&self) -> Option<usize> {
            Some(usize::MAX)
        }
    }

    #[test]
    fn round4_bounded_fingerprints_caps_with_capacity_and_rejects_exceeding_max_array_bytes() {
        let ok = BoundedFingerprints::deserialize(FloodSeqDeserializer { len: 16, pos: 0 });
        assert!(ok.is_ok());

        let over = BoundedFingerprints::deserialize(FloodSeqDeserializer {
            len: MAX_ARRAY_BYTES + 1,
            pos: 0,
        });
        assert!(over.is_err());
    }
}
