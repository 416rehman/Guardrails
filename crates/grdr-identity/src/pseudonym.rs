// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use grdr_crypto::hmac_sha256;
use jiff::{Timestamp, tz::TimeZone};
use serde::{Deserialize, Serialize};

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
