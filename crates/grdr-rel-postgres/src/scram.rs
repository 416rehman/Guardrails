// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use grdr_crypto::{constant_time_eq, fill_random, hmac_sha256, sha256_digest};
use grdr_model::CodedError;

use crate::config::CODE_PG_WIRE;

pub(crate) const SCRAM_MECH_SHA256: &str = "SCRAM-SHA-256";
pub(crate) const SCRAM_MECH_SHA256_PLUS: &str = "SCRAM-SHA-256-PLUS";
const MIN_SCRAM_ITERATIONS: u32 = 4_096;
const MAX_SCRAM_ITERATIONS: u32 = 1_000_000;
const CLIENT_NONCE_BYTES: usize = 18;
const MIN_SERVER_NONCE_SUFFIX_LEN: usize = 8;

#[derive(Clone)]
pub(crate) struct ScramClientSession {
    mechanism: &'static str,
    channel_binding_b64: String,
    client_nonce: String,
    client_first_bare: String,
    client_first_message: Vec<u8>,
    password: Zeroizing<String>,
}

#[derive(Debug)]
struct ServerFirstFields<'a> {
    nonce: &'a str,
    salt: Vec<u8>,
    iterations: u32,
}

#[derive(Debug)]
pub(crate) struct ScramClientFinal {
    pub(crate) client_final_message: Vec<u8>,
    pub(crate) expected_server_signature: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for ScramClientSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScramClientSession")
            .field("mechanism", &self.mechanism)
            .field("channel_binding_b64", &self.channel_binding_b64)
            .field("client_nonce", &self.client_nonce)
            .field("client_first_bare", &self.client_first_bare)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

impl ScramClientSession {
    pub(crate) fn start(
        offered_mechanisms: &[String],
        password: &str,
        peer_cert_binding: Option<&[u8]>,
    ) -> Result<Self, CodedError> {
        if password.is_empty() {
            return Err(CodedError::new(
                CODE_PG_WIRE,
                "PostgreSQL requested SASL authentication without a configured password.",
                "Provide a PostgreSQL password in the DSN for SCRAM-SHA-256 authentication.",
            ));
        }

        let (mechanism, gs2_header, channel_binding_b64) =
            select_mechanism(offered_mechanisms, peer_cert_binding)?;

        let mut nonce_raw = [0u8; CLIENT_NONCE_BYTES];
        fill_random(&mut nonce_raw).map_err(|e| {
            CodedError::new(
                CODE_PG_WIRE,
                format!("Failed generating SCRAM client nonce: {e}"),
                "Ensure platform CSPRNG is operational.",
            )
        })?;
        let client_nonce = B64.encode(nonce_raw);
        let client_first_bare = format!("n=,r={client_nonce}");
        let client_first_message = format!("{gs2_header}{client_first_bare}").into_bytes();

        Ok(Self {
            mechanism,
            channel_binding_b64,
            client_nonce,
            client_first_bare,
            client_first_message,
            password: Zeroizing::new(password.to_string()),
        })
    }

    pub(crate) fn mechanism(&self) -> &'static str {
        self.mechanism
    }

    pub(crate) fn client_first_message(&self) -> &[u8] {
        &self.client_first_message
    }

    pub(crate) fn process_server_first(
        &self,
        server_first_bytes: &[u8],
    ) -> Result<ScramClientFinal, CodedError> {
        let server_first_str = std::str::from_utf8(server_first_bytes).map_err(|_| {
            CodedError::new(
                CODE_PG_WIRE,
                "PostgreSQL SCRAM server-first message is not valid UTF-8.",
                "Verify PostgreSQL SCRAM-SHA-256 server compliance.",
            )
        })?;
        let fields = parse_server_first(server_first_str, &self.client_nonce)?;

        let client_final_without_proof =
            format!("c={},r={}", self.channel_binding_b64, fields.nonce);
        let auth_message = format!(
            "{},{server_first_str},{client_final_without_proof}",
            self.client_first_bare
        );

        let normalized_pw = Zeroizing::new(saslprep_nfkc(&self.password)?);
        let salted_pw = grdr_crypto::pbkdf2_hmac_sha256(
            normalized_pw.as_bytes(),
            &fields.salt,
            fields.iterations,
        )
        .map_err(|e| malformed_scram_err(&format!("SCRAM key derivation failed: {e}")))?;
        let client_key = Zeroizing::new(hmac_sha256(&*salted_pw, b"Client Key"));
        let stored_key = Zeroizing::new(sha256_digest(&*client_key));
        let client_sig = hmac_sha256(&*stored_key, auth_message.as_bytes());
        let client_proof = xor_bytes_32(&client_key, &client_sig);
        let proof_b64 = B64.encode(*client_proof);

        let server_key = Zeroizing::new(hmac_sha256(&*salted_pw, b"Server Key"));
        let expected_server_signature =
            Zeroizing::new(hmac_sha256(&*server_key, auth_message.as_bytes()));

        let client_final_message =
            format!("{client_final_without_proof},p={proof_b64}").into_bytes();
        Ok(ScramClientFinal {
            client_final_message,
            expected_server_signature,
        })
    }
}

pub(crate) fn verify_server_final(
    server_final_bytes: &[u8],
    expected_signature: &[u8; 32],
) -> Result<(), CodedError> {
    let raw = std::str::from_utf8(server_final_bytes).map_err(|_| {
        CodedError::new(
            CODE_PG_WIRE,
            "PostgreSQL SCRAM server-final message is not valid UTF-8.",
            "Reject malformed SCRAM final frame.",
        )
    })?;
    let mut verifier_b64: Option<&str> = None;
    let mut error_val: Option<&str> = None;
    for part in raw.split(',') {
        if part.is_empty() || !part.contains('=') {
            return Err(malformed_scram_err(
                "Malformed attribute in PostgreSQL SCRAM server-final message.",
            ));
        }
        if part.starts_with("m=") {
            return Err(malformed_scram_err(
                "PostgreSQL SCRAM server-final contains unsupported mandatory extension.",
            ));
        }
        if let Some(err) = part.strip_prefix("e=") {
            if error_val.is_some() {
                return Err(malformed_scram_err(
                    "Duplicate error attribute in PostgreSQL SCRAM server-final message.",
                ));
            }
            error_val = Some(err);
        } else if let Some(v) = part.strip_prefix("v=") {
            if verifier_b64.is_some() {
                return Err(malformed_scram_err(
                    "Duplicate verifier attribute in PostgreSQL SCRAM server-final message.",
                ));
            }
            verifier_b64 = Some(v);
        }
    }
    if let Some(err) = error_val {
        return Err(CodedError::new(
            CODE_PG_WIRE,
            format!("PostgreSQL SCRAM authentication error: {err}"),
            "Verify PostgreSQL user credentials and pg_hba configuration.",
        ));
    }
    let b64 = verifier_b64.ok_or_else(|| {
        CodedError::new(
            CODE_PG_WIRE,
            "PostgreSQL SCRAM server-final message omitted server signature.",
            "Reject incomplete SCRAM authentication.",
        )
    })?;
    let actual_sig = B64.decode(b64).map_err(|_| {
        CodedError::new(
            CODE_PG_WIRE,
            "Invalid base64 in PostgreSQL SCRAM server signature.",
            "Reject malformed SCRAM server signature.",
        )
    })?;
    if !constant_time_eq(&actual_sig, expected_signature) {
        return Err(CodedError::new(
            CODE_PG_WIRE,
            "PostgreSQL SCRAM server signature verification failed.",
            "Refuse server connection because mutual SCRAM authentication did not match.",
        ));
    }
    Ok(())
}

fn select_mechanism(
    offered: &[String],
    peer_cert_binding: Option<&[u8]>,
) -> Result<(&'static str, String, String), CodedError> {
    if let Some(cert_hash) = peer_cert_binding {
        if offered.iter().any(|m| m == SCRAM_MECH_SHA256_PLUS) {
            let gs2 = "p=tls-server-end-point,,".to_string();
            let mut cbind_input = Vec::with_capacity(gs2.len().saturating_add(cert_hash.len()));
            cbind_input.extend_from_slice(gs2.as_bytes());
            cbind_input.extend_from_slice(cert_hash);
            let cbind_b64 = B64.encode(&cbind_input);
            return Ok((SCRAM_MECH_SHA256_PLUS, gs2, cbind_b64));
        }
        if offered.iter().any(|m| m == SCRAM_MECH_SHA256) {
            // RFC 5802 §6: client supports channel binding on TLS, server omitted -PLUS.
            let gs2 = "y,,".to_string();
            let cbind_b64 = B64.encode(gs2.as_bytes());
            return Ok((SCRAM_MECH_SHA256, gs2, cbind_b64));
        }
    } else if offered.iter().any(|m| m == SCRAM_MECH_SHA256) {
        let gs2 = "n,,".to_string();
        let cbind_b64 = B64.encode(gs2.as_bytes());
        return Ok((SCRAM_MECH_SHA256, gs2, cbind_b64));
    }

    Err(CodedError::new(
        CODE_PG_WIRE,
        format!("PostgreSQL server offered unsupported SASL mechanisms: {offered:?}."),
        "Configure PostgreSQL 18 pg_hba.conf for scram-sha-256.",
    ))
}

fn parse_server_first<'a>(
    raw: &'a str,
    client_nonce: &str,
) -> Result<ServerFirstFields<'a>, CodedError> {
    let mut nonce: Option<&str> = None;
    let mut salt_b64: Option<&str> = None;
    let mut iterations: Option<u32> = None;

    for part in raw.split(',') {
        if part.is_empty() || !part.contains('=') {
            return Err(malformed_scram_err(
                "Malformed attribute in PostgreSQL SCRAM server-first challenge.",
            ));
        }
        if part.starts_with("m=") {
            return Err(malformed_scram_err(
                "PostgreSQL SCRAM server-first contains unsupported mandatory extension.",
            ));
        }
        if let Some(val) = part.strip_prefix("r=") {
            if nonce.is_some() {
                return Err(malformed_scram_err(
                    "Duplicate nonce attribute in PostgreSQL SCRAM server-first challenge.",
                ));
            }
            nonce = Some(val);
        } else if let Some(val) = part.strip_prefix("s=") {
            if salt_b64.is_some() {
                return Err(malformed_scram_err(
                    "Duplicate salt attribute in PostgreSQL SCRAM server-first challenge.",
                ));
            }
            salt_b64 = Some(val);
        } else if let Some(val) = part.strip_prefix("i=") {
            if iterations.is_some() {
                return Err(malformed_scram_err(
                    "Duplicate iteration attribute in PostgreSQL SCRAM server-first challenge.",
                ));
            }
            let parsed = val
                .parse::<u32>()
                .map_err(|_| malformed_scram_err("Invalid PostgreSQL SCRAM iteration count."))?;
            iterations = Some(parsed);
        }
    }

    let nonce = nonce.ok_or_else(|| {
        malformed_scram_err("PostgreSQL SCRAM server-first challenge omitted nonce.")
    })?;
    let Some(server_suffix) = nonce.strip_prefix(client_nonce) else {
        return Err(malformed_scram_err(
            "PostgreSQL SCRAM server nonce failed client nonce prefix check.",
        ));
    };
    if server_suffix.len() < MIN_SERVER_NONCE_SUFFIX_LEN
        || !nonce.bytes().all(is_scram_printable_nonce_byte)
    {
        return Err(malformed_scram_err(
            "PostgreSQL SCRAM server nonce failed character set or entropy check.",
        ));
    }

    let salt_raw = salt_b64.ok_or_else(|| {
        malformed_scram_err("PostgreSQL SCRAM server-first challenge omitted salt.")
    })?;
    let salt = B64
        .decode(salt_raw)
        .map_err(|_| malformed_scram_err("PostgreSQL SCRAM server salt is not valid base64."))?;
    if salt.is_empty() {
        return Err(malformed_scram_err(
            "PostgreSQL SCRAM server salt cannot be empty.",
        ));
    }

    let iterations = iterations.ok_or_else(|| {
        malformed_scram_err("PostgreSQL SCRAM server-first challenge omitted iteration count.")
    })?;
    if !(MIN_SCRAM_ITERATIONS..=MAX_SCRAM_ITERATIONS).contains(&iterations) {
        return Err(CodedError::new(
            CODE_PG_WIRE,
            format!("PostgreSQL SCRAM iteration count {iterations} outside safe bounds."),
            "Require SCRAM-SHA-256 iteration count between 4096 and 1000000.",
        ));
    }

    Ok(ServerFirstFields {
        nonce,
        salt,
        iterations,
    })
}

fn is_scram_printable_nonce_byte(byte: u8) -> bool {
    byte.is_ascii_graphic() && byte != b','
}

fn malformed_scram_err(msg: &str) -> CodedError {
    CodedError::new(
        CODE_PG_WIRE,
        msg,
        "Reject malformed or downgraded SCRAM exchange.",
    )
}

fn saslprep_nfkc(raw: &str) -> Result<String, CodedError> {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.nfkc() {
        if ch == '\0' || ch.is_control() {
            return Err(CodedError::new(
                CODE_PG_WIRE,
                "PostgreSQL password contains forbidden control characters after NFKC normalization.",
                "Remove control or NUL characters from PostgreSQL password.",
            ));
        }
        out.push(ch);
    }
    Ok(out)
}

fn xor_bytes_32(lhs: &[u8; 32], rhs: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    for ((dst, a), b) in out.iter_mut().zip(lhs.iter()).zip(rhs.iter()) {
        *dst = a ^ b;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scram_sets_y_header_on_tls_without_plus_and_rejects_malformed_frames() {
        let mut pw_seed = [0u8; 16];
        fill_random(&mut pw_seed).unwrap();
        let test_pw = grdr_crypto::encode_lower_hex(&pw_seed);

        let tls_no_plus = ScramClientSession::start(
            &[SCRAM_MECH_SHA256.to_string()],
            &test_pw,
            Some(&[0x11u8; 32]),
        )
        .unwrap();
        assert_eq!(tls_no_plus.mechanism(), SCRAM_MECH_SHA256);
        assert!(tls_no_plus.client_first_message().starts_with(b"y,,n=,r="));
        let dbg = format!("{tls_no_plus:?}");
        assert!(!dbg.contains(&test_pw));
        assert!(dbg.contains("[REDACTED]"));

        let plain_sess =
            ScramClientSession::start(&[SCRAM_MECH_SHA256.to_string()], &test_pw, None).unwrap();
        assert!(plain_sess.client_first_message().starts_with(b"n,,n=,r="));

        let cnonce = &tls_no_plus.client_nonce;
        let dup_r = format!("r={cnonce}abcdefgh,r={cnonce}ijklmnop,s=c2FsdA==,i=4096");
        assert!(tls_no_plus.process_server_first(dup_r.as_bytes()).is_err());

        let mand_ext = format!("m=ext,r={cnonce}abcdefgh,s=c2FsdA==,i=4096");
        assert!(
            tls_no_plus
                .process_server_first(mand_ext.as_bytes())
                .is_err()
        );

        let bad_nonce = format!("r={cnonce}bad nonce!,s=c2FsdA==,i=4096");
        assert!(
            tls_no_plus
                .process_server_first(bad_nonce.as_bytes())
                .is_err()
        );

        let sig = [0x22u8; 32];
        let v_b64 = B64.encode(sig);
        let dup_v = format!("v={v_b64},v={v_b64}");
        assert!(verify_server_final(dup_v.as_bytes(), &sig).is_err());
        let mand_v = format!("m=req,v={v_b64}");
        assert!(verify_server_final(mand_v.as_bytes(), &sig).is_err());
    }
}
