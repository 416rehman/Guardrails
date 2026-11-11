//! Identifiers without a random-number crate: session ids for `claude --session-id` (UUID v4) and
//! audit run ids (UUID v7, time-ordered, as `audits/schema` requires). The random bits are SHA-256
//! over the clock, the process id and a counter, which is unique enough for ids and never a secret.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

static COUNTER: AtomicU64 = AtomicU64::new(0);

const VERSION_4: u8 = 0x40;
const VERSION_7: u8 = 0x70;
const VERSION_MASK: u8 = 0x0f;
const VARIANT: u8 = 0x80;
const VARIANT_MASK: u8 = 0x3f;
const VERSION_BYTE: usize = 6;
const VARIANT_BYTE: usize = 8;
const TIMESTAMP_BYTES: usize = 6;

pub fn session_id() -> String {
    let mut bytes = entropy();
    set_version(&mut bytes, VERSION_4);
    format_uuid(&bytes)
}

pub fn run_id() -> String {
    let mut bytes = entropy();
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis())
        .unwrap_or(0)
        .to_be_bytes();
    let start = millis.len().saturating_sub(TIMESTAMP_BYTES);
    copy_prefix(&mut bytes, millis.get(start..).unwrap_or_default());
    set_version(&mut bytes, VERSION_7);
    format_uuid(&bytes)
}

/// A small pseudo-random number below `bound`, for jitter.
pub fn below(bound: u64) -> u64 {
    if bound == 0 {
        return 0;
    }
    let mut word = [0u8; 8];
    copy_prefix(&mut word, &entropy());
    u64::from_le_bytes(word) % bound
}

fn entropy() -> [u8; 16] {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    let mut hasher = Sha256::new();
    hasher.update(nanos.to_le_bytes());
    hasher.update(std::process::id().to_le_bytes());
    hasher.update(COUNTER.fetch_add(1, Ordering::Relaxed).to_le_bytes());
    let mut bytes = [0u8; 16];
    copy_prefix(&mut bytes, &hasher.finalize());
    bytes
}

fn copy_prefix(target: &mut [u8], source: &[u8]) {
    for (to, from) in target.iter_mut().zip(source) {
        *to = *from;
    }
}

fn set_version(bytes: &mut [u8; 16], version: u8) {
    if let Some(byte) = bytes.get_mut(VERSION_BYTE) {
        *byte = (*byte & VERSION_MASK) | version;
    }
    if let Some(byte) = bytes.get_mut(VARIANT_BYTE) {
        *byte = (*byte & VARIANT_MASK) | VARIANT;
    }
}

fn format_uuid(bytes: &[u8; 16]) -> String {
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    let part = |from: usize, to: usize| hex.get(from..to).unwrap_or_default();
    format!(
        "{}-{}-{}-{}-{}",
        part(0, 8),
        part(8, 12),
        part(12, 16),
        part(16, 20),
        part(20, 32)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;

    #[test]
    fn ids_have_the_uuid_shape_and_differ() {
        let v4 =
            Regex::new("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
                .unwrap();
        let v7 =
            Regex::new("^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
                .unwrap();
        let (a, b) = (session_id(), session_id());
        assert!(v4.is_match(&a), "{a}");
        assert_ne!(a, b);
        let run = run_id();
        assert!(v7.is_match(&run), "{run}");
        assert!(below(10) < 10);
        assert_eq!(below(0), 0);
    }
}
