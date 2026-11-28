// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use zeroize::Zeroizing;

use grdr_crypto::SigningKeypair;
use grdr_model::CodedError;

use crate::config::CODE_NATS_CONFIG;

const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const PREFIX_BYTE_SEED: u8 = 18 << 3;
const PREFIX_BYTE_USER: u8 = 20 << 3;
const PREFIX_BYTE_ACCOUNT: u8 = 0;
const PREFIX_BYTE_SERVER: u8 = 13 << 3;
const PREFIX_BYTE_CLUSTER: u8 = 2 << 3;
const PREFIX_BYTE_OPERATOR: u8 = 14 << 3;
const SEED_ENCODED_PAYLOAD_LEN: usize = 36;
const SEED_ENCODED_BASE32_CHARS: usize = 58;
const PUBLIC_KEY_PAYLOAD_LEN: usize = 35;

#[derive(Clone, PartialEq, Eq)]
pub struct NKeyCredentialBundle {
    pub jwt: Option<Zeroizing<String>>,
    pub nkey_seed: Zeroizing<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NKeySignature {
    pub(crate) public_nkey: String,
    pub(crate) signature_b64: String,
}

impl fmt::Debug for NKeyCredentialBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NKeyCredentialBundle")
            .field("jwt", &self.jwt.as_ref().map(|_| "[REDACTED]"))
            .field("nkey_seed", &"[REDACTED]")
            .finish()
    }
}

pub fn encode_user_seed(seed: &[u8; 32]) -> String {
    let b0 = PREFIX_BYTE_SEED | (PREFIX_BYTE_USER >> 5);
    let b1 = (PREFIX_BYTE_USER & 0x1F) << 3;
    let mut raw = Zeroizing::new(Vec::with_capacity(SEED_ENCODED_PAYLOAD_LEN));
    raw.push(b0);
    raw.push(b1);
    raw.extend_from_slice(seed);
    let crc = crc16_xmodem(&raw);
    raw.extend_from_slice(&crc.to_le_bytes());
    base32_encode(&raw)
}

pub fn public_nkey_from_seed(seed_str: &str) -> Result<String, CodedError> {
    let (role_byte, seed) = decode_seed(seed_str)?;
    let kp = SigningKeypair::from_seed(*seed);
    Ok(encode_public_key(role_byte, &kp.public_key_bytes()))
}

pub fn parse_nats_creds(creds: &str) -> Result<NKeyCredentialBundle, CodedError> {
    let jwt = extract_pem_block(creds, "NATS USER JWT")
        .map(|s| Zeroizing::new(s.trim().to_string()))
        .filter(|s| !s.is_empty());
    let seed = extract_pem_block(creds, "USER NKEY SEED")
        .map(|s| Zeroizing::new(s.trim().to_string()))
        .ok_or_else(|| {
            CodedError::new(
                CODE_NATS_CONFIG,
                "NATS credentials file missing `BEGIN USER NKEY SEED` block.",
                "Provide a valid NATS .creds bundle or explicit nkey_seed.",
            )
        })?;
    let _ = decode_seed(&seed)?;
    Ok(NKeyCredentialBundle {
        jwt,
        nkey_seed: seed,
    })
}

pub(crate) fn validate_nkey_seed(seed_str: &str) -> Result<(), CodedError> {
    let _ = decode_seed(seed_str)?;
    Ok(())
}

pub(crate) fn sign_nonce_with_seed(
    seed_str: &str,
    nonce: &[u8],
) -> Result<NKeySignature, CodedError> {
    let (role_byte, seed) = decode_seed(seed_str)?;
    let kp = SigningKeypair::from_seed(*seed);
    let public_nkey = encode_public_key(role_byte, &kp.public_key_bytes());
    let sig = kp.sign_ed25519_raw(nonce);
    let signature_b64 = URL_SAFE_NO_PAD.encode(sig);
    Ok(NKeySignature {
        public_nkey,
        signature_b64,
    })
}

fn decode_seed(seed_str: &str) -> Result<(u8, Zeroizing<[u8; 32]>), CodedError> {
    let cleaned = seed_str.trim();
    if cleaned.len() != SEED_ENCODED_BASE32_CHARS {
        return Err(CodedError::new(
            CODE_NATS_CONFIG,
            "Invalid NATS NKey seed length.",
            "Provide a valid 58-character base32 NKey seed starting with S.",
        ));
    }
    let decoded = Zeroizing::new(base32_decode(cleaned)?);
    if decoded.len() != SEED_ENCODED_PAYLOAD_LEN {
        return Err(CodedError::new(
            CODE_NATS_CONFIG,
            "Invalid NATS NKey seed decoded payload length.",
            "Provide a valid 58-character base32 NKey seed starting with S.",
        ));
    }
    let payload_end = SEED_ENCODED_PAYLOAD_LEN.saturating_sub(2);
    let (payload, crc_bytes) = (
        decoded.get(..payload_end).unwrap_or(&[]),
        decoded.get(payload_end..).unwrap_or(&[]),
    );
    let expected_crc = crc16_xmodem(payload);
    let actual_crc = match crc_bytes {
        [lo, hi] => u16::from_le_bytes([*lo, *hi]),
        _ => return Err(invalid_nkey_err("missing CRC16")),
    };
    if actual_crc != expected_crc {
        return Err(invalid_nkey_err("CRC16 mismatch"));
    }

    let b0 = *decoded.first().unwrap_or(&0);
    let b1 = *decoded.get(1).unwrap_or(&0);
    if (b0 & 0xF8) != PREFIX_BYTE_SEED || (b1 & 0x07) != 0 {
        return Err(invalid_nkey_err("invalid seed prefix"));
    }
    let role_byte = ((b0 & 0x07) << 5) | (b1 >> 3);
    if !matches!(
        role_byte,
        PREFIX_BYTE_USER
            | PREFIX_BYTE_ACCOUNT
            | PREFIX_BYTE_SERVER
            | PREFIX_BYTE_CLUSTER
            | PREFIX_BYTE_OPERATOR
    ) {
        return Err(invalid_nkey_err("unsupported NKey role prefix"));
    }

    let seed_slice = decoded.get(2..34).unwrap_or(&[]);
    let seed: [u8; 32] = seed_slice
        .try_into()
        .map_err(|_| invalid_nkey_err("seed slice length mismatch"))?;
    Ok((role_byte, Zeroizing::new(seed)))
}

fn encode_public_key(role_byte: u8, public_bytes: &[u8; 32]) -> String {
    let mut raw = Vec::with_capacity(PUBLIC_KEY_PAYLOAD_LEN);
    raw.push(role_byte);
    raw.extend_from_slice(public_bytes);
    let crc = crc16_xmodem(&raw);
    raw.extend_from_slice(&crc.to_le_bytes());
    base32_encode(&raw)
}

fn crc16_xmodem(bytes: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in bytes {
        crc ^= u16::from(b) << 8;
        for _ in 0..8 {
            if (crc & 0x8000) != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(8).div_ceil(5));
    let mut buffer: u16 = 0;
    let mut bits_left: u8 = 0;
    for &b in bytes {
        buffer = (buffer << 8) | u16::from(b);
        bits_left = bits_left.saturating_add(8);
        while bits_left >= 5 {
            bits_left = bits_left.saturating_sub(5);
            let idx = usize::from((buffer >> bits_left) & 0x1F);
            out.push(char::from(*BASE32_ALPHABET.get(idx).unwrap_or(&b'A')));
        }
    }
    if bits_left > 0 {
        let idx = usize::from((buffer << (5u8.saturating_sub(bits_left))) & 0x1F);
        out.push(char::from(*BASE32_ALPHABET.get(idx).unwrap_or(&b'A')));
    }
    out
}

fn base32_decode(encoded: &str) -> Result<Vec<u8>, CodedError> {
    if encoded.contains('=') {
        return Err(invalid_nkey_err("unexpected base32 padding"));
    }
    let mut out = Vec::with_capacity(encoded.len().saturating_mul(5) / 8);
    let mut buffer: u16 = 0;
    let mut bits_left: u8 = 0;
    for byte in encoded.bytes() {
        let val = match byte.to_ascii_uppercase() {
            b'A'..=b'Z' => byte.to_ascii_uppercase().saturating_sub(b'A'),
            b'2'..=b'7' => byte.saturating_sub(b'2').saturating_add(26),
            _ => return Err(invalid_nkey_err("invalid base32 character")),
        };
        buffer = (buffer << 5) | u16::from(val);
        bits_left = bits_left.saturating_add(5);
        if bits_left >= 8 {
            bits_left = bits_left.saturating_sub(8);
            out.push(u8::try_from((buffer >> bits_left) & 0xFF).unwrap_or(0));
        }
    }
    if bits_left > 0 {
        let mask = (1u16 << bits_left).saturating_sub(1);
        if (buffer & mask) != 0 {
            return Err(invalid_nkey_err("non-zero base32 trailing padding bits"));
        }
    }
    Ok(out)
}

fn extract_pem_block(text: &str, label: &str) -> Option<String> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start_idx = text.find(&begin)?.saturating_add(begin.len());
    let rest = text.get(start_idx..)?;
    let end_idx = rest.find(&end)?;
    rest.get(..end_idx).map(ToString::to_string)
}

fn invalid_nkey_err(reason: &str) -> CodedError {
    CodedError::new(
        CODE_NATS_CONFIG,
        format!("Invalid NATS NKey credential: {reason}."),
        "Supply a valid base32 NATS NKey seed.",
    )
}
