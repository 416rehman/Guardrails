// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! RFC 9421 HTTP signature parameter parsing, header injection rejection,
//! canonical digest computation, and fleet response signing helpers (`D-22`).

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use grdr_crypto::{SigningKeypair, sha256_digest};

use crate::error::UplinkError;

use serde::{Deserialize, Serialize};

/// Request signature validity window in seconds (5 minutes).
pub const REQUEST_SIGNATURE_TTL_S: i64 = 300;
/// Maximum permitted response signature TTL (`expires - created`, 15 minutes).
pub const MAX_RESPONSE_SIGNATURE_TTL_S: i64 = 900;
/// Exact covered components list required on every verified server response.
pub const REQUIRED_RESPONSE_COVERED: &str = "(\"content-digest\")";

/// Signed RFC 9421 headers emitted on outbound `grdr-uplink` HTTP requests.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rfc9421RequestHeaders {
    pub content_digest: String,
    pub signature_input: String,
    pub signature: String,
    pub grdr_device: String,
    pub grdr_cert_b64: String,
    pub request_sig_digest_b64: String,
    pub created_unix_s: i64,
}

/// Verified response timestamp metadata returned by response verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedResponseMeta {
    pub server_time_unix_s: i64,
    pub clock_skew_detected: bool,
}

/// Parsed RFC 9421 `Signature-Input` components and key-value parameters.
#[derive(Clone, Debug)]
pub struct ParsedRfc9421<'a> {
    pub covered: &'a str,
    pub params: BTreeMap<&'a str, &'a str>,
}

/// Validate a string safe for interpolation into RFC 9421 signature base and quoted headers.
pub fn validate_rfc9421_token(field_name: &str, value: &str) -> Result<(), UplinkError> {
    if value.is_empty()
        || value
            .bytes()
            .any(|b| matches!(b, b'\r' | b'\n' | b'"' | b'\\' | b'\0') || b < 0x20 || b == 0x7f)
    {
        return Err(UplinkError::SignatureCreationFailed {
            detail: format!("unsafe character in RFC 9421 field '{field_name}'"),
        });
    }
    Ok(())
}

/// Format an RFC 9530 `Content-Digest` (`sha-256=:<base64>:`).
#[must_use]
pub fn compute_rfc9530_sha256_digest(body: &[u8]) -> String {
    let digest = sha256_digest(body);
    format!("sha-256=:{}:", STANDARD.encode(digest))
}

/// Parse RFC 9421 covered-components prefix and semicolon parameters, rejecting duplicates.
pub fn parse_rfc9421_params(params: &str) -> Result<ParsedRfc9421<'_>, UplinkError> {
    let close_idx = params.find(')').ok_or_else(|| UplinkError::AckUnverified {
        reason: "malformed covered components list in Signature-Input".to_string(),
    })?;
    let end_covered = close_idx.saturating_add(1);
    let covered = params.get(..end_covered).unwrap_or("");
    let after_covered = params.get(end_covered..).unwrap_or("");

    let mut values = BTreeMap::new();
    for raw_pair in after_covered.split(';') {
        let trimmed = raw_pair.trim();
        if trimmed.is_empty() {
            continue;
        }
        let (key, val) = trimmed
            .split_once('=')
            .ok_or_else(|| UplinkError::AckUnverified {
                reason: "malformed RFC 9421 signature parameter".to_string(),
            })?;
        if values.insert(key.trim(), val.trim()).is_some() {
            return Err(UplinkError::AckUnverified {
                reason: format!("duplicate RFC 9421 parameter '{key}'"),
            });
        }
    }
    Ok(ParsedRfc9421 {
        covered,
        params: values,
    })
}

/// Extract a non-empty quoted parameter value from a parsed parameter map.
pub fn quoted_param(map: &BTreeMap<&str, &str>, name: &str) -> Result<String, UplinkError> {
    let raw = map
        .get(name)
        .copied()
        .ok_or_else(|| UplinkError::AckUnverified {
            reason: format!("missing RFC 9421 parameter '{name}'"),
        })?;
    let unquoted = raw
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .filter(|s| !s.is_empty() && !s.contains('"') && !s.bytes().any(|b| b < 0x20 || b == 0x7f))
        .ok_or_else(|| UplinkError::AckUnverified {
            reason: format!("malformed RFC 9421 parameter '{name}'"),
        })?;
    Ok(unquoted.to_string())
}

/// Extract an integer parameter value from a parsed parameter map.
pub fn int_param(map: &BTreeMap<&str, &str>, name: &str) -> Result<i64, UplinkError> {
    let raw = map
        .get(name)
        .copied()
        .ok_or_else(|| UplinkError::AckUnverified {
            reason: format!("missing RFC 9421 integer parameter '{name}'"),
        })?;
    raw.parse::<i64>().map_err(|_| UplinkError::AckUnverified {
        reason: format!("invalid integer parameter '{name}'"),
    })
}

/// Sign a fleet server response matching `ResponseVerifier::verify_response`.
pub fn sign_fleet_response_with_keyid(
    response_signer: &SigningKeypair,
    keyid: &str,
    request_sig_digest_b64: &str,
    body: &[u8],
    server_time_unix_s: i64,
) -> Result<(String, String, String), UplinkError> {
    validate_rfc9421_token("keyid", keyid)?;
    validate_rfc9421_token("req", request_sig_digest_b64)?;
    let content_digest = compute_rfc9530_sha256_digest(body);
    let expires_s = server_time_unix_s.saturating_add(REQUEST_SIGNATURE_TTL_S);
    let params = format!(
        "(\"content-digest\");created={server_time_unix_s};expires={expires_s};keyid=\"{keyid}\";alg=\"ed25519\";tag=\"grdr-fleet-v1\";req=\"{request_sig_digest_b64}\""
    );
    let signature_base =
        format!("\"content-digest\": {content_digest}\n\"@signature-params\": {params}");
    let sig_b64 = response_signer.sign_bytes("grdr-fleet-v1", signature_base.as_bytes());
    Ok((
        content_digest,
        format!("sig1={params}"),
        format!("sig1=:{sig_b64}:"),
    ))
}
