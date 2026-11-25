// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use jiff::{Timestamp, tz::TimeZone};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct QuarterKey {
    pub year: i16,
    pub quarter: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarterlyDisclosureEntry {
    pub org_id: String,
    pub quarter: QuarterKey,
    pub requested_count: u64,
    pub approved_count: u64,
    pub legal_hold_deferred_count: u64,
    pub subject_disclosed_count: u64,
}

impl QuarterKey {
    #[must_use]
    pub fn from_timestamp(ts: Timestamp) -> Self {
        let dt = TimeZone::UTC.to_datetime(ts);
        let quarter = match dt.month() {
            1..=3 => 1,
            4..=6 => 2,
            7..=9 => 3,
            _ => 4,
        };
        Self {
            year: dt.year(),
            quarter,
        }
    }
}

#[must_use]
pub fn derive_device_pseudonym(device_key: &[u8; 32], raw_subject: &str) -> String {
    let mac = hmac_sha256(device_key, format!("dev:{raw_subject}").as_bytes());
    format!("prn_dev_{}", encode_hex_prefix(&mac, 16))
}

#[must_use]
pub fn re_pseudonymize_for_org(
    org_key: &[u8; 32],
    pseudonym_epoch: u32,
    device_pseudonym: &str,
) -> String {
    let mac = hmac_sha256(
        org_key,
        format!("org:{pseudonym_epoch}:{device_pseudonym}").as_bytes(),
    );
    format!("prn_org_{pseudonym_epoch}_{}", encode_hex_prefix(&mac, 16))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    let mut padded_key = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let hashed: [u8; 32] = Sha256::digest(key).into();
        for (dst, src) in padded_key.iter_mut().zip(hashed.iter()) {
            *dst = *src;
        }
    } else {
        for (dst, src) in padded_key.iter_mut().zip(key.iter()) {
            *dst = *src;
        }
    }

    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];
    for (dst, k) in ipad.iter_mut().zip(padded_key.iter()) {
        *dst ^= *k;
    }
    for (dst, k) in opad.iter_mut().zip(padded_key.iter()) {
        *dst ^= *k;
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(data);
    let inner_hash: [u8; 32] = inner.finalize().into();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    outer.finalize().into()
}

fn encode_hex_prefix(bytes: &[u8], byte_count: usize) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(byte_count.saturating_mul(2));
    for byte in bytes.iter().take(byte_count) {
        let hi = usize::from(byte >> 4);
        let lo = usize::from(byte & 0x0f);
        if let (Some(&c1), Some(&c2)) = (HEX.get(hi), HEX.get(lo)) {
            out.push(char::from(c1));
            out.push(char::from(c2));
        }
    }
    out
}
