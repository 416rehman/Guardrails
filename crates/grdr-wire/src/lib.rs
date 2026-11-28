// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

pub mod codes;
pub mod dialer;
mod dialer_net;
pub mod endpoint;
pub use codes::{
    CODE_WIRE_CODEC, CODE_WIRE_CRYPTO, CODE_WIRE_EGRESS_BLOCKED, CODE_WIRE_EXPIRED_TIMESTAMP,
    CODE_WIRE_FLOOR_EMPTY_KEYS, CODE_WIRE_FLOOR_EXPIRED, CODE_WIRE_FLOOR_INVALID_HEADER,
    CODE_WIRE_FLOOR_MALFORMED_FIELD, CODE_WIRE_FLOOR_TOO_LARGE, CODE_WIRE_FLOOR_TOO_MANY_RULES,
    CODE_WIRE_FLOOR_TRUNCATED, CODE_WIRE_FLOOR_UNTRUSTED_SIGNATURE, CODE_WIRE_FRAME_TOO_LARGE,
    CODE_WIRE_INVALID_MAGIC, CODE_WIRE_IPC_CREDIT_EXHAUSTED, CODE_WIRE_IPC_CREDIT_OVERFLOW,
    CODE_WIRE_IPC_EMPTY_PAYLOAD, CODE_WIRE_IPC_END_OF_STREAM, CODE_WIRE_IPC_FRAME_TOO_LARGE,
    CODE_WIRE_IPC_INVALID_PROTOBUF, CODE_WIRE_IPC_IO, CODE_WIRE_IPC_LIMITS_UNAVAILABLE,
    CODE_WIRE_IPC_PROTOCOL_VERSION, CODE_WIRE_IPC_TIMED_OUT, CODE_WIRE_IPC_TRUNCATED_FRAME,
    CODE_WIRE_IPC_ZERO_LENGTH, CODE_WIRE_PEER_FOREIGN_UID, CODE_WIRE_PEER_PID_REUSE,
    CODE_WIRE_PEER_PRIVILEGE_TOO_LOW, CODE_WIRE_PEER_PROFILE_MISMATCH,
    CODE_WIRE_PEER_PROTOCOL_REJECTED, CODE_WIRE_PEER_TRANSIENT_RESTART,
    CODE_WIRE_PEER_UNAUTHENTICATED, CODE_WIRE_PEER_UNSAFE_PATH, CODE_WIRE_PEER_UNTRUSTED_SERVER,
    CODE_WIRE_REPLAY_DETECTED, CODE_WIRE_TRUNCATED_FRAME, CODE_WIRE_UNSUPPORTED_VERSION,
};
pub use dialer::{
    DialPurpose, Dialer, EgressDialPlan, EgressDialReceipt, EgressDialRequest, EgressRouteError,
    IsolatedAllowRule, NetworkMode, ProxySelection, validate_egress_request,
};
pub mod floor_bin;
mod floor_cursor;
pub mod frame;
pub mod limits;
pub mod messages;
pub mod peer_auth;
pub mod peer_policy;
pub mod peer_types;

#[cfg(feature = "json-envelope")]
use std::collections::HashMap;
use std::fmt;

#[cfg(feature = "json-envelope")]
use grdr_crypto::{SigningKeypair, verify_bytes};
use grdr_crypto::{fill_random, sha256_hex};
#[cfg(feature = "json-envelope")]
use grdr_model::TrustedKeyInfo;
#[cfg(feature = "json-envelope")]
use jiff::Timestamp;
#[cfg(feature = "json-envelope")]
use serde::de::DeserializeOwned;
#[cfg(feature = "json-envelope")]
use serde::{Deserialize, Serialize};

pub const WIRE_PROTOCOL_VERSION: u16 = 1;
/// Runtime authoritative cap comes from `limits::embedded_limits()?.max_frame_bytes`;
/// kept public only for sibling crates (`grdr-acp`, `grdr-infer`).
pub const MAX_FRAME_BYTES: usize = 1_048_576;
#[cfg(feature = "json-envelope")]
const FRAME_MAGIC: [u8; 4] = *b"GRDR";
#[cfg(feature = "json-envelope")]
const HEADER_LEN: usize = 10;
#[cfg(feature = "json-envelope")]
const DOMAIN_WIRE_ENVELOPE: &str = "wire_envelope_v1";
#[cfg(feature = "json-envelope")]
const MAX_NONCE_LEN: usize = 256;
#[cfg(feature = "json-envelope")]
const MAX_REPLAY_SKEW_S: i64 = 31_536_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    FrameTooLarge { size: usize, max: usize },
    TruncatedFrame { needed: usize, available: usize },
    InvalidMagic,
    UnsupportedVersion(u16),
    Codec(String),
    Crypto(String),
    ReplayDetected { key_id: String, nonce: String },
    ExpiredTimestamp,
}

#[cfg(feature = "json-envelope")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireEnvelope<T> {
    pub version: u16,
    pub nonce: String,
    pub sent_at: Timestamp,
    pub sender_key_id: String,
    pub payload: T,
    pub signature: String,
}

#[cfg(feature = "json-envelope")]
#[derive(Serialize)]
struct CanonicalEnvelope<'a, T> {
    version: u16,
    nonce: &'a str,
    sent_at: Timestamp,
    sender_key_id: &'a str,
    payload: &'a T,
}

#[cfg(feature = "json-envelope")]
#[derive(Debug)]
pub struct ReplayWindow {
    max_entries: usize,
    max_skew_seconds: i64,
    seen: HashMap<(String, String), i64>,
}

impl WireError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::FrameTooLarge { .. } => codes::CODE_WIRE_FRAME_TOO_LARGE,
            Self::TruncatedFrame { .. } => codes::CODE_WIRE_TRUNCATED_FRAME,
            Self::InvalidMagic => codes::CODE_WIRE_INVALID_MAGIC,
            Self::UnsupportedVersion(_) => codes::CODE_WIRE_UNSUPPORTED_VERSION,
            Self::Codec(_) => codes::CODE_WIRE_CODEC,
            Self::Crypto(_) => codes::CODE_WIRE_CRYPTO,
            Self::ReplayDetected { .. } => codes::CODE_WIRE_REPLAY_DETECTED,
            Self::ExpiredTimestamp => codes::CODE_WIRE_EXPIRED_TIMESTAMP,
        }
    }
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameTooLarge { size, max } => write!(
                f,
                "{}: wire frame size {size} exceeds maximum {max}",
                self.code()
            ),
            Self::TruncatedFrame { needed, available } => write!(
                f,
                "{}: wire frame truncated (needed {needed} bytes, got {available})",
                self.code()
            ),
            Self::InvalidMagic => write!(f, "{}: invalid wire frame magic header", self.code()),
            Self::UnsupportedVersion(ver) => {
                write!(
                    f,
                    "{}: unsupported wire protocol version {ver}",
                    self.code()
                )
            }
            Self::Codec(detail) => write!(f, "{}: wire codec error: {detail}", self.code()),
            Self::Crypto(detail) => {
                write!(
                    f,
                    "{}: wire signature verification error: {detail}",
                    self.code()
                )
            }
            Self::ReplayDetected { .. } => write!(f, "{}: duplicate nonce replayed", self.code()),
            Self::ExpiredTimestamp => write!(
                f,
                "{}: wire envelope timestamp outside allowed skew window",
                self.code()
            ),
        }
    }
}

impl std::error::Error for WireError {}

pub fn generate_nonce() -> Result<String, WireError> {
    let mut raw = [0u8; 16];
    fill_random(&mut raw).map_err(|_| WireError::Crypto("csprng unavailable".into()))?;
    Ok(sha256_hex(&raw))
}

pub fn fill_random_bytes(buf: &mut [u8]) -> Result<(), WireError> {
    fill_random(buf).map_err(|_| WireError::Crypto("csprng unavailable".into()))
}

#[must_use]
pub fn sha256_hex_bytes(data: &[u8]) -> String {
    sha256_hex(data)
}

#[cfg(feature = "json-envelope")]
impl ReplayWindow {
    #[must_use]
    pub fn new(max_entries: usize, max_skew_seconds: i64) -> Self {
        Self {
            max_entries: max_entries.max(1),
            max_skew_seconds: max_skew_seconds.clamp(1, MAX_REPLAY_SKEW_S),
            seen: HashMap::new(),
        }
    }

    pub fn verify_and_record<T: Serialize>(
        &mut self,
        envelope: &WireEnvelope<T>,
        trusted_keys: &[TrustedKeyInfo],
        now: Timestamp,
    ) -> Result<(), WireError> {
        let sent_sec = envelope.sent_at.as_second();
        let now_sec = now.as_second();
        let delta = sent_sec.saturating_sub(now_sec);
        if delta.saturating_abs() > self.max_skew_seconds {
            return Err(WireError::ExpiredTimestamp);
        }
        verify_envelope(envelope, trusted_keys)?;

        let cutoff = now_sec.saturating_sub(self.max_skew_seconds);
        self.seen.retain(|_, ts| *ts >= cutoff);

        let key = (envelope.sender_key_id.clone(), envelope.nonce.clone());
        if self.seen.contains_key(&key) {
            return Err(WireError::ReplayDetected {
                key_id: key.0,
                nonce: key.1,
            });
        }
        if self.seen.len() >= self.max_entries {
            return Err(WireError::Crypto(
                "replay window saturated with active entries".into(),
            ));
        }
        self.seen.insert(key, sent_sec);
        Ok(())
    }
}

#[cfg(feature = "json-envelope")]
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

#[cfg(feature = "json-envelope")]
pub fn verify_envelope<T: Serialize>(
    envelope: &WireEnvelope<T>,
    trusted_keys: &[TrustedKeyInfo],
) -> Result<(), WireError> {
    if envelope.version != WIRE_PROTOCOL_VERSION {
        return Err(WireError::UnsupportedVersion(envelope.version));
    }
    if envelope.sender_key_id.trim().is_empty() {
        return Err(WireError::Crypto("sender_key_id cannot be empty".into()));
    }
    if envelope.nonce.trim().is_empty() || envelope.nonce.len() > MAX_NONCE_LEN {
        return Err(WireError::Crypto(
            "envelope nonce must be non-empty and bounded".into(),
        ));
    }
    let Some(trusted) = trusted_keys
        .iter()
        .find(|k| k.key_id == envelope.sender_key_id)
    else {
        return Err(WireError::Crypto("untrusted sender key_id".into()));
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
    .map_err(|_| WireError::Crypto("envelope signature rejected".into()))
}

#[cfg(feature = "json-envelope")]
pub fn encode_frame<T: Serialize>(envelope: &WireEnvelope<T>) -> Result<Vec<u8>, WireError> {
    if envelope.version != WIRE_PROTOCOL_VERSION {
        return Err(WireError::UnsupportedVersion(envelope.version));
    }
    let max_frame_bytes = limits::embedded_limits()
        .map_err(|err| WireError::Codec(err.to_string()))?
        .max_frame_bytes;
    let body = serde_json::to_vec(envelope).map_err(|e| WireError::Codec(e.to_string()))?;
    if body.len() > max_frame_bytes {
        return Err(WireError::FrameTooLarge {
            size: body.len(),
            max: max_frame_bytes,
        });
    }
    let len_u32 = u32::try_from(body.len()).map_err(|_| WireError::FrameTooLarge {
        size: body.len(),
        max: max_frame_bytes,
    })?;

    let total = HEADER_LEN
        .checked_add(body.len())
        .ok_or(WireError::FrameTooLarge {
            size: body.len(),
            max: max_frame_bytes,
        })?;
    let mut frame = Vec::with_capacity(total);
    frame.extend_from_slice(&FRAME_MAGIC);
    frame.extend_from_slice(&envelope.version.to_be_bytes());
    frame.extend_from_slice(&len_u32.to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

#[cfg(feature = "json-envelope")]
pub fn decode_frame<T: DeserializeOwned>(
    bytes: &[u8],
) -> Result<(WireEnvelope<T>, usize), WireError> {
    let max_frame_bytes = limits::embedded_limits()
        .map_err(|err| WireError::Codec(err.to_string()))?
        .max_frame_bytes;
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
            size: max_frame_bytes,
            max: max_frame_bytes,
        })?;
    if payload_len > max_frame_bytes {
        return Err(WireError::FrameTooLarge {
            size: payload_len,
            max: max_frame_bytes,
        });
    }

    let total_needed = HEADER_LEN
        .checked_add(payload_len)
        .ok_or(WireError::FrameTooLarge {
            size: payload_len,
            max: max_frame_bytes,
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
    #[cfg(feature = "json-envelope")]
    use super::*;

    #[cfg(feature = "json-envelope")]
    #[test]
    fn signs_frames_verifies_and_rejects_replay_or_tampering() {
        use grdr_model::{ActionClass, DecideInput, SigningKeypairExt as _};

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

        let n1 = generate_nonce().unwrap();
        let env = sign_envelope(&kp, n1, now, input).unwrap();
        let frame = encode_frame(&env).unwrap();
        let (mut decoded, consumed): (WireEnvelope<DecideInput>, usize) =
            decode_frame(&frame).unwrap();
        assert_eq!(consumed, frame.len());

        let mut window = ReplayWindow::new(2, 60);
        window.verify_and_record(&decoded, &trusted, now).unwrap();

        let replay_err = window
            .verify_and_record(&decoded, &trusted, now)
            .unwrap_err();
        assert!(matches!(replay_err, WireError::ReplayDetected { .. }));

        let n2 = generate_nonce().unwrap();
        let env2 = sign_envelope(&kp, n2, now, decoded.payload.clone()).unwrap();
        window.verify_and_record(&env2, &trusted, now).unwrap();
        let n3 = generate_nonce().unwrap();
        let env3 = sign_envelope(&kp, n3, now, decoded.payload.clone()).unwrap();
        assert!(matches!(
            window.verify_and_record(&env3, &trusted, now),
            Err(WireError::Crypto(_))
        ));

        decoded.payload.target = "cat /etc/shadow".into();
        let tamper_err = window
            .verify_and_record(&decoded, &trusted, now)
            .unwrap_err();
        assert!(matches!(tamper_err, WireError::Crypto(_)));

        let stale = Timestamp::from_second(1_700_000_200).unwrap();
        let n4 = generate_nonce().unwrap();
        let env_stale = sign_envelope(&kp, n4, now, decoded.payload.clone()).unwrap();
        assert_eq!(
            window.verify_and_record(&env_stale, &trusted, stale),
            Err(WireError::ExpiredTimestamp)
        );
        assert_eq!(
            MAX_FRAME_BYTES,
            limits::embedded_limits()
                .expect("embedded limits")
                .max_frame_bytes
        );
    }
}
