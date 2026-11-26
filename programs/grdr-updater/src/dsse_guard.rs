// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Strict DSSE payload-type allowlist (`PackKind`-bound), signature bounds, strict base64
//! `[u8; 32]` public key deduplication, and `grdr-update` PAE threshold verification.

use std::collections::{BTreeMap, BTreeSet};

use grdr_model::api::TrustedKeyInfo;
use grdr_update::{DsseEnvelope, DsseLimits, PackKind, verify_dsse_envelope_with_limits};

use crate::error::UpdaterError;

pub(crate) const MAX_DSSE_SIGNATURES: usize = 32;

const PAYLOAD_TYPE_PACK: &str = "application/vnd.grdr.pack-manifest+json";
const PAYLOAD_TYPE_BINARY: &str = "application/vnd.grdr.binary-manifest+json";
const PAYLOAD_TYPE_AIRGAP: &str = "application/vnd.grdr.airgap-manifest+json";
const PAYLOAD_TYPE_TUF_TARGET: &str = "application/vnd.guardrails.tuf-target+json";

/// Decode a canonical unpadded/single-`=` 32-byte Ed25519 SPKI/raw public key strictly (no whitespace).
pub(crate) fn decode_ed25519_pubkey_b64_strict(b64: &str) -> Result<[u8; 32], UpdaterError> {
    if b64.len() != 44 || b64.bytes().any(|b| b.is_ascii_whitespace()) {
        return Err(UpdaterError::TufVerification {
            detail: "Ed25519 public_key_b64 must be exact 44-char base64 without whitespace"
                .to_string(),
        });
    }
    let bytes = b64.as_bytes();
    if bytes.get(43) != Some(&b'=') {
        return Err(UpdaterError::TufVerification {
            detail: "32-byte base64 public key must end with single '=' padding".to_string(),
        });
    }
    let mut out = [0u8; 32];
    let mut out_idx = 0usize;
    for chunk_idx in 0..11usize {
        let off = chunk_idx.saturating_mul(4);
        let c0 = b64_val(*bytes.get(off).unwrap_or(&b'!'))?;
        let c1 = b64_val(*bytes.get(off.saturating_add(1)).unwrap_or(&b'!'))?;
        let b2 = *bytes.get(off.saturating_add(2)).unwrap_or(&b'!');
        let b3 = *bytes.get(off.saturating_add(3)).unwrap_or(&b'!');
        if chunk_idx < 10 {
            let c2 = b64_val(b2)?;
            let c3 = b64_val(b3)?;
            let triple = (u32::from(c0) << 18)
                | (u32::from(c1) << 12)
                | (u32::from(c2) << 6)
                | u32::from(c3);
            if let Some(dst) = out.get_mut(out_idx) {
                *dst = ((triple >> 16) & 0xff) as u8;
            }
            if let Some(dst) = out.get_mut(out_idx.saturating_add(1)) {
                *dst = ((triple >> 8) & 0xff) as u8;
            }
            if let Some(dst) = out.get_mut(out_idx.saturating_add(2)) {
                *dst = (triple & 0xff) as u8;
            }
            out_idx = out_idx.saturating_add(3);
        } else {
            let c2 = b64_val(b2)?;
            if b3 != b'=' || (c2 & 0x03) != 0 {
                return Err(UpdaterError::TufVerification {
                    detail: "non-canonical trailing base64 bits in public_key_b64".to_string(),
                });
            }
            let pair = (u32::from(c0) << 12) | (u32::from(c1) << 6) | u32::from(c2);
            if let Some(dst) = out.get_mut(out_idx) {
                *dst = ((pair >> 10) & 0xff) as u8;
            }
            if let Some(dst) = out.get_mut(out_idx.saturating_add(1)) {
                *dst = ((pair >> 2) & 0xff) as u8;
            }
            out_idx = out_idx.saturating_add(2);
        }
    }
    if out_idx != 32 {
        return Err(UpdaterError::TufVerification {
            detail: "decoded Ed25519 key length mismatch".to_string(),
        });
    }
    Ok(out)
}

fn b64_val(byte: u8) -> Result<u8, UpdaterError> {
    match byte {
        b'A'..=b'Z' => Ok(byte.saturating_sub(b'A')),
        b'a'..=b'z' => Ok(byte.saturating_sub(b'a').saturating_add(26)),
        b'0'..=b'9' => Ok(byte.saturating_sub(b'0').saturating_add(52)),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(UpdaterError::TufVerification {
            detail: "invalid base64 character in public_key_b64".to_string(),
        }),
    }
}

const fn is_payload_type_allowed_for_pack(payload_type: &str, pack_kind: PackKind) -> bool {
    match pack_kind {
        PackKind::Binary => matches!(
            payload_type.as_bytes(),
            b"application/vnd.grdr.binary-manifest+json"
                | b"application/vnd.grdr.airgap-manifest+json"
                | b"application/vnd.guardrails.tuf-target+json"
        ),
        _ => matches!(
            payload_type.as_bytes(),
            b"application/vnd.grdr.pack-manifest+json"
                | b"application/vnd.grdr.airgap-manifest+json"
                | b"application/vnd.guardrails.tuf-target+json"
        ),
    }
}

/// Verify DSSE envelope enforcing `PackKind`-bound `payload_type`, duplicate `key_id` rejection,
/// canonical `[u8; 32]` public key deduplication, and `grdr-update` PAE threshold checks.
pub(crate) fn verify_dsse_envelope_strict(
    envelope: &DsseEnvelope,
    pack_kind: PackKind,
    trusted_keys: &[TrustedKeyInfo],
    threshold: u32,
    limits: &DsseLimits,
) -> Result<(), UpdaterError> {
    if !is_payload_type_allowed_for_pack(&envelope.payload_type, pack_kind) {
        return Err(UpdaterError::TufVerification {
            detail: format!(
                "disallowed DSSE payload_type '{}' for pack kind {:?}",
                envelope.payload_type, pack_kind
            ),
        });
    }
    if threshold == 0 || envelope.signatures.is_empty() {
        return Err(UpdaterError::TufVerification {
            detail: "DSSE threshold and signatures must be non-empty".to_string(),
        });
    }
    if envelope.signatures.len() > MAX_DSSE_SIGNATURES {
        return Err(UpdaterError::TufVerification {
            detail: format!(
                "DSSE signature count {} exceeds cap {MAX_DSSE_SIGNATURES}",
                envelope.signatures.len()
            ),
        });
    }

    let mut key_map: BTreeMap<&str, (&TrustedKeyInfo, [u8; 32])> = BTreeMap::new();
    for key in trusted_keys {
        let raw_pk = decode_ed25519_pubkey_b64_strict(&key.public_key_b64)?;
        if key_map.insert(key.key_id.as_str(), (key, raw_pk)).is_some() {
            return Err(UpdaterError::TufVerification {
                detail: format!("duplicate key_id '{}' in trusted role keys", key.key_id),
            });
        }
    }

    let _decoded =
        envelope
            .decode_payload_with_limits(limits)
            .map_err(|e| UpdaterError::TufVerification {
                detail: format!("DSSE payload decode failed: {e}"),
            })?;

    let mut seen_keyids = BTreeSet::new();
    let mut seen_pubkeys: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut valid_unique_count: u32 = 0;
    for sig in &envelope.signatures {
        if !seen_keyids.insert(sig.keyid.as_str()) {
            return Err(UpdaterError::TufVerification {
                detail: format!("duplicate DSSE keyid '{}'", sig.keyid),
            });
        }
        if let Some(&(key_info, raw_pk)) = key_map.get(sig.keyid.as_str()) {
            if !seen_pubkeys.insert(raw_pk) {
                return Err(UpdaterError::TufVerification {
                    detail: "duplicate Ed25519 public key across DSSE signatures".to_string(),
                });
            }
            let single = DsseEnvelope {
                payload_type: envelope.payload_type.clone(),
                payload: envelope.payload.clone(),
                signatures: vec![sig.clone()],
            };
            if verify_dsse_envelope_with_limits(&single, std::slice::from_ref(key_info), 1, limits)
                .is_ok()
            {
                valid_unique_count = valid_unique_count.saturating_add(1);
            }
        }
    }
    if valid_unique_count < threshold {
        return Err(UpdaterError::TufVerification {
            detail: format!(
                "DSSE verified unique signers {valid_unique_count} < threshold {threshold}"
            ),
        });
    }
    let _payload_types = (
        PAYLOAD_TYPE_PACK,
        PAYLOAD_TYPE_BINARY,
        PAYLOAD_TYPE_AIRGAP,
        PAYLOAD_TYPE_TUF_TARGET,
    );

    verify_dsse_envelope_with_limits(envelope, trusted_keys, threshold, limits)
        .map(|_| ())
        .map_err(|e| UpdaterError::TufVerification {
            detail: format!("DSSE limit verification failed: {e}"),
        })
}
