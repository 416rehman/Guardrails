// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeSet;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use grdr_crypto::{SigningKeypair, verify_bytes};
use grdr_model::TrustedKeyInfo;
use serde::{Deserialize, Serialize};

use crate::UpdateError;

const DSSE_SIG_DOMAIN: &str = "dsse.v1";
const DEFAULT_MAX_DSSE_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DsseLimits {
    pub max_payload_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DsseSignature {
    pub keyid: String,
    pub sig: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DsseEnvelope {
    pub payload_type: String,
    pub payload: String,
    pub signatures: Vec<DsseSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DsseTargetStatement {
    pub target_path: String,
    pub sha256: String,
    pub length: u64,
}

impl Default for DsseLimits {
    fn default() -> Self {
        Self {
            max_payload_bytes: DEFAULT_MAX_DSSE_PAYLOAD_BYTES,
        }
    }
}

impl DsseEnvelope {
    pub fn decode_payload(&self) -> Result<Vec<u8>, UpdateError> {
        self.decode_payload_with_limits(&DsseLimits::default())
    }

    pub fn decode_payload_with_limits(&self, limits: &DsseLimits) -> Result<Vec<u8>, UpdateError> {
        let trimmed = self.payload.trim();
        // Base64 expands 3 bytes into 4 chars; enforce pre-decode bound before allocating.
        let max_encoded = limits.max_payload_bytes.div_ceil(3).saturating_mul(4);
        if trimmed.len() > max_encoded {
            return Err(UpdateError::MalformedMetadata(format!(
                "DSSE encoded payload length {} exceeds limit {}",
                trimmed.len(),
                max_encoded
            )));
        }
        let decoded = B64.decode(trimmed).map_err(|e| {
            UpdateError::MalformedMetadata(format!("invalid base64 DSSE payload: {e}"))
        })?;
        if decoded.len() > limits.max_payload_bytes {
            return Err(UpdateError::MalformedMetadata(format!(
                "DSSE payload length {} exceeds limit {}",
                decoded.len(),
                limits.max_payload_bytes
            )));
        }
        Ok(decoded)
    }
}

#[must_use]
pub fn dsse_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let header = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload.len()
    );
    let mut out = Vec::with_capacity(header.len().saturating_add(payload.len()));
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(payload);
    out
}

pub fn sign_dsse_envelope(
    payload_type: &str,
    payload: &[u8],
    signers: &[&SigningKeypair],
) -> Result<DsseEnvelope, UpdateError> {
    if payload_type.trim().is_empty() {
        return Err(UpdateError::MalformedMetadata(
            "DSSE payloadType cannot be empty".into(),
        ));
    }
    if signers.is_empty() {
        return Err(UpdateError::InvalidSignature(
            "at least one signer is required for DSSE envelope".into(),
        ));
    }
    let pae = dsse_pae(payload_type, payload);
    let mut signatures = Vec::with_capacity(signers.len());
    for signer in signers {
        let sig = signer.sign_bytes(DSSE_SIG_DOMAIN, &pae);
        signatures.push(DsseSignature {
            keyid: signer.key_id().to_owned(),
            sig,
        });
    }
    Ok(DsseEnvelope {
        payload_type: payload_type.to_owned(),
        payload: B64.encode(payload),
        signatures,
    })
}

pub fn verify_dsse_envelope(
    envelope: &DsseEnvelope,
    trusted_keys: &[TrustedKeyInfo],
    threshold: u32,
) -> Result<Vec<u8>, UpdateError> {
    verify_dsse_envelope_with_limits(envelope, trusted_keys, threshold, &DsseLimits::default())
}

pub fn verify_dsse_envelope_with_limits(
    envelope: &DsseEnvelope,
    trusted_keys: &[TrustedKeyInfo],
    threshold: u32,
    limits: &DsseLimits,
) -> Result<Vec<u8>, UpdateError> {
    if threshold == 0 {
        return Err(UpdateError::InvalidSignature(
            "DSSE threshold must be at least 1".into(),
        ));
    }
    if envelope.payload_type.trim().is_empty() {
        return Err(UpdateError::MalformedMetadata(
            "DSSE payloadType cannot be empty".into(),
        ));
    }
    let payload_bytes = envelope.decode_payload_with_limits(limits)?;
    let pae = dsse_pae(&envelope.payload_type, &payload_bytes);

    let mut verified_key_ids = BTreeSet::new();
    for entry in &envelope.signatures {
        if verified_key_ids.contains(&entry.keyid) {
            continue;
        }
        let Some(key) = trusted_keys.iter().find(|k| k.key_id == entry.keyid) else {
            continue;
        };
        if verify_bytes(&key.public_key_b64, DSSE_SIG_DOMAIN, &pae, &entry.sig).is_ok() {
            verified_key_ids.insert(entry.keyid.clone());
        }
    }

    let verified_count = u32::try_from(verified_key_ids.len()).unwrap_or(u32::MAX);
    if verified_count < threshold {
        return Err(UpdateError::InvalidSignature(format!(
            "DSSE verified {verified_count} unique signatures, required threshold {threshold}"
        )));
    }
    Ok(payload_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dsse_pae_matches_specification_format() {
        let pae = dsse_pae("application/vnd.grdr.pack-manifest+json", b"hello");
        assert_eq!(
            pae,
            b"DSSEv1 39 application/vnd.grdr.pack-manifest+json 5 hello"
        );
    }

    #[test]
    fn dsse_enforces_threshold_limits_and_rejects_tampered_payload() {
        let k1 = SigningKeypair::generate().expect("k1");
        let k2 = SigningKeypair::generate().expect("k2");
        let trusted = vec![k1.public_info(), k2.public_info()];

        let env = sign_dsse_envelope(
            "application/vnd.grdr.pack-manifest+json",
            br#"{"id":"pack-1"}"#,
            &[&k1, &k2],
        )
        .expect("sign");

        let verified = verify_dsse_envelope(&env, &trusted, 2).expect("verify 2-of-2");
        assert_eq!(verified, br#"{"id":"pack-1"}"#);

        let tiny_limits = DsseLimits {
            max_payload_bytes: 4,
        };
        assert!(matches!(
            verify_dsse_envelope_with_limits(&env, &trusted, 2, &tiny_limits),
            Err(UpdateError::MalformedMetadata(_))
        ));

        let dup_env = DsseEnvelope {
            payload_type: env.payload_type.clone(),
            payload: env.payload.clone(),
            signatures: vec![env.signatures[0].clone(), env.signatures[0].clone()],
        };
        assert!(matches!(
            verify_dsse_envelope(&dup_env, &trusted, 2),
            Err(UpdateError::InvalidSignature(_))
        ));

        let mut tampered = env.clone();
        tampered.payload = B64.encode(br#"{"id":"evil"}"#);
        assert!(matches!(
            verify_dsse_envelope(&tampered, &trusted, 1),
            Err(UpdateError::InvalidSignature(_))
        ));
    }
}
