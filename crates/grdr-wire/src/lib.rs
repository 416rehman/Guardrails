// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::collections::{HashSet, VecDeque};

use jiff::Timestamp;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use grdr_crypto::{SigningKeypair, verify_bytes};
use grdr_model::TrustedKeyInfo;

pub const WIRE_PROTOCOL_VERSION: u16 = 1;
pub const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;
const FRAME_MAGIC: [u8; 4] = *b"GRDR";
const HEADER_LEN: usize = 10;
const DOMAIN_WIRE_ENVELOPE: &str = "wire_envelope_v1";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    #[error("GRDR-WIRE-0001: wire frame size {size} exceeds maximum {max}")]
    FrameTooLarge { size: usize, max: usize },
    #[error("GRDR-WIRE-0002: wire frame truncated (needed {needed} bytes, got {available})")]
    TruncatedFrame { needed: usize, available: usize },
    #[error("GRDR-WIRE-0003: invalid wire frame magic header")]
    InvalidMagic,
    #[error("GRDR-WIRE-0004: unsupported wire protocol version {0}")]
    UnsupportedVersion(u16),
    #[error("GRDR-WIRE-0005: wire JSON codec error: {0}")]
    Codec(String),
    #[error("GRDR-WIRE-0006: wire signature verification error: {0}")]
    Crypto(String),
    #[error("GRDR-WIRE-0007: duplicate nonce `{nonce}` replayed for key `{key_id}`")]
    ReplayDetected { key_id: String, nonce: String },
    #[error("GRDR-WIRE-0008: wire envelope timestamp outside allowed skew window")]
    ExpiredTimestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireEnvelope<T> {
    pub version: u16,
    pub nonce: String,
    pub sent_at: Timestamp,
    pub sender_key_id: String,
    pub payload: T,
    pub signature: String,
}

#[derive(Serialize)]
struct CanonicalEnvelope<'a, T> {
    version: u16,
    nonce: &'a str,
    sent_at: Timestamp,
    sender_key_id: &'a str,
    payload: &'a T,
}

#[derive(Debug)]
pub struct ReplayWindow {
    max_entries: usize,
    max_skew_seconds: i64,
    order: VecDeque<(String, String)>,
    seen: HashSet<(String, String)>,
}

impl ReplayWindow {
    pub fn new(max_entries: usize, max_skew_seconds: i64) -> Self {
        Self {
            max_entries: max_entries.max(1),
            max_skew_seconds: max_skew_seconds.max(1),
            order: VecDeque::new(),
            seen: HashSet::new(),
        }
    }

    pub fn verify_and_record<T: Serialize>(
        &mut self,
        envelope: &WireEnvelope<T>,
        trusted_keys: &[TrustedKeyInfo],
        now: Timestamp,
    ) -> Result<(), WireError> {
        let delta = envelope.sent_at.as_second().saturating_sub(now.as_second());
        if delta.saturating_abs() > self.max_skew_seconds {
            return Err(WireError::ExpiredTimestamp);
        }
        verify_envelope(envelope, trusted_keys)?;

        let key = (envelope.sender_key_id.clone(), envelope.nonce.clone());
        if self.seen.contains(&key) {
            return Err(WireError::ReplayDetected {
                key_id: key.0,
                nonce: key.1,
            });
        }

        if self.order.len() >= self.max_entries
            && let Some(evicted) = self.order.pop_front()
        {
            self.seen.remove(&evicted);
        }
        self.order.push_back(key.clone());
        self.seen.insert(key);
        Ok(())
    }
}

pub fn sign_envelope<T: Serialize>(
    keypair: &SigningKeypair,
    nonce: impl Into<String>,
    sent_at: Timestamp,
    payload: T,
) -> Result<WireEnvelope<T>, WireError> {
    let nonce_str = nonce.into();
    let canonical = CanonicalEnvelope {
        version: WIRE_PROTOCOL_VERSION,
        nonce: &nonce_str,
        sent_at,
        sender_key_id: keypair.key_id(),
        payload: &payload,
    };
    let bytes = serde_json::to_vec(&canonical).map_err(|e| WireError::Codec(e.to_string()))?;
    let signature = keypair.sign_bytes(DOMAIN_WIRE_ENVELOPE, &bytes);
    Ok(WireEnvelope {
        version: WIRE_PROTOCOL_VERSION,
        nonce: nonce_str,
        sent_at,
        sender_key_id: keypair.key_id().to_string(),
        payload,
        signature,
    })
}

pub fn verify_envelope<T: Serialize>(
    envelope: &WireEnvelope<T>,
    trusted_keys: &[TrustedKeyInfo],
) -> Result<(), WireError> {
    if envelope.version != WIRE_PROTOCOL_VERSION {
        return Err(WireError::UnsupportedVersion(envelope.version));
    }
    if envelope.nonce.trim().is_empty() {
        return Err(WireError::Crypto("envelope nonce cannot be empty".into()));
    }
    let Some(trusted) = trusted_keys
        .iter()
        .find(|k| k.key_id == envelope.sender_key_id)
    else {
        return Err(WireError::Crypto(format!(
            "untrusted sender key_id `{}`",
            envelope.sender_key_id
        )));
    };
    let canonical = CanonicalEnvelope {
        version: envelope.version,
        nonce: &envelope.nonce,
        sent_at: envelope.sent_at,
        sender_key_id: &envelope.sender_key_id,
        payload: &envelope.payload,
    };
    let bytes = serde_json::to_vec(&canonical).map_err(|e| WireError::Codec(e.to_string()))?;
    verify_bytes(
        &trusted.public_key_b64,
        DOMAIN_WIRE_ENVELOPE,
        &bytes,
        &envelope.signature,
    )
    .map_err(|e| WireError::Crypto(e.to_string()))
}

pub fn encode_frame<T: Serialize>(envelope: &WireEnvelope<T>) -> Result<Vec<u8>, WireError> {
    if envelope.version != WIRE_PROTOCOL_VERSION {
        return Err(WireError::UnsupportedVersion(envelope.version));
    }
    let body = serde_json::to_vec(envelope).map_err(|e| WireError::Codec(e.to_string()))?;
    if body.len() > MAX_FRAME_BYTES {
        return Err(WireError::FrameTooLarge {
            size: body.len(),
            max: MAX_FRAME_BYTES,
        });
    }
    let len_u32 = u32::try_from(body.len()).map_err(|_| WireError::FrameTooLarge {
        size: body.len(),
        max: MAX_FRAME_BYTES,
    })?;

    let total = HEADER_LEN
        .checked_add(body.len())
        .ok_or(WireError::FrameTooLarge {
            size: body.len(),
            max: MAX_FRAME_BYTES,
        })?;
    let mut frame = Vec::with_capacity(total);
    frame.extend_from_slice(&FRAME_MAGIC);
    frame.extend_from_slice(&envelope.version.to_be_bytes());
    frame.extend_from_slice(&len_u32.to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

pub fn decode_frame<T: DeserializeOwned>(
    bytes: &[u8],
) -> Result<(WireEnvelope<T>, usize), WireError> {
    let Some(header) = bytes.get(..HEADER_LEN) else {
        return Err(WireError::TruncatedFrame {
            needed: HEADER_LEN,
            available: bytes.len(),
        });
    };
    let Some(magic) = header.get(..4) else {
        return Err(WireError::InvalidMagic);
    };
    if magic != FRAME_MAGIC {
        return Err(WireError::InvalidMagic);
    }
    let Some(ver_slice) = header.get(4..6) else {
        return Err(WireError::InvalidMagic);
    };
    let ver_bytes: [u8; 2] = ver_slice.try_into().map_err(|_| WireError::InvalidMagic)?;
    let version = u16::from_be_bytes(ver_bytes);
    if version != WIRE_PROTOCOL_VERSION {
        return Err(WireError::UnsupportedVersion(version));
    }

    let Some(len_slice) = header.get(6..10) else {
        return Err(WireError::InvalidMagic);
    };
    let len_bytes: [u8; 4] = len_slice.try_into().map_err(|_| WireError::InvalidMagic)?;
    let payload_len =
        usize::try_from(u32::from_be_bytes(len_bytes)).map_err(|_| WireError::FrameTooLarge {
            size: MAX_FRAME_BYTES,
            max: MAX_FRAME_BYTES,
        })?;
    if payload_len > MAX_FRAME_BYTES {
        return Err(WireError::FrameTooLarge {
            size: payload_len,
            max: MAX_FRAME_BYTES,
        });
    }

    let total_needed = HEADER_LEN
        .checked_add(payload_len)
        .ok_or(WireError::FrameTooLarge {
            size: payload_len,
            max: MAX_FRAME_BYTES,
        })?;
    let Some(payload) = bytes.get(HEADER_LEN..total_needed) else {
        return Err(WireError::TruncatedFrame {
            needed: total_needed,
            available: bytes.len(),
        });
    };
    let envelope: WireEnvelope<T> =
        serde_json::from_slice(payload).map_err(|e| WireError::Codec(e.to_string()))?;
    Ok((envelope, total_needed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use grdr_model::{ActionClass, DecideInput};

    #[test]
    fn signs_frames_verifies_and_rejects_replay_or_tampering() {
        let kp = SigningKeypair::generate().unwrap();
        let trusted = vec![kp.public_info()];
        let now = Timestamp::from_second(1_700_000_000).unwrap();

        let input = DecideInput {
            session_id: Some("sess-wire-1".into()),
            device_id: Some("dev-wire-1".into()),
            device_name: Some("wire-host".into()),
            agent_name: "claude-code".into(),
            action_class: ActionClass::Exec,
            control_point: None,
            target: "git status".into(),
            summary: None,
        };

        let env = sign_envelope(&kp, "nonce-001", now, input).unwrap();
        let frame = encode_frame(&env).unwrap();
        let (mut decoded, consumed): (WireEnvelope<DecideInput>, usize) =
            decode_frame(&frame).unwrap();
        assert_eq!(consumed, frame.len());

        let mut window = ReplayWindow::new(2, 60);
        window.verify_and_record(&decoded, &trusted, now).unwrap();

        // Replaying the same nonce fails cleanly.
        let replay_err = window
            .verify_and_record(&decoded, &trusted, now)
            .unwrap_err();
        assert!(matches!(replay_err, WireError::ReplayDetected { .. }));

        // Tampered payload fails Ed25519 verification.
        decoded.nonce = "nonce-002".into();
        let tamper_err = window
            .verify_and_record(&decoded, &trusted, now)
            .unwrap_err();
        assert!(matches!(tamper_err, WireError::Crypto(_)));

        // Out-of-window timestamp fails skew check.
        let stale = Timestamp::from_second(1_700_000_200).unwrap();
        let env_stale = sign_envelope(&kp, "nonce-003", now, decoded.payload.clone()).unwrap();
        assert_eq!(
            window.verify_and_record(&env_stale, &trusted, stale),
            Err(WireError::ExpiredTimestamp)
        );
    }
}
