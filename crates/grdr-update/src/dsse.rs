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

impl DsseEnvelope {
    pub fn decode_payload(&self) -> Result<Vec<u8>, UpdateError> {
        B64.decode(self.payload.trim()).map_err(|e| {
            UpdateError::MalformedMetadata(format!("invalid base64 DSSE payload: {e}"))
        })
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
    let payload_bytes = envelope.decode_payload()?;
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
    fn dsse_enforces_threshold_and_rejects_duplicate_and_tampered_payload() {
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

        // Duplicate signature from same key cannot satisfy threshold 2.
        let dup_env = DsseEnvelope {
            payload_type: env.payload_type.clone(),
            payload: env.payload.clone(),
            signatures: vec![env.signatures[0].clone(), env.signatures[0].clone()],
        };
        assert!(matches!(
            verify_dsse_envelope(&dup_env, &trusted, 2),
            Err(UpdateError::InvalidSignature(_))
        ));

        // Tampering payload breaks verification.
        let mut tampered = env.clone();
        tampered.payload = B64.encode(br#"{"id":"evil"}"#);
        assert!(matches!(
            verify_dsse_envelope(&tampered, &trusted, 1),
            Err(UpdateError::InvalidSignature(_))
        ));
    }
}
