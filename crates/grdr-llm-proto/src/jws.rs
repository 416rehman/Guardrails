// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! RFC 7515 compact/detached EdDSA JWS envelope parsing and RFC 8785 JCS canonicalization.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::ProtoError;
use crate::strict_json::{
    MAX_JSON_DEPTH, decode_base64_url, encode_base64_url_nopad, parse_strict_json_bytes,
};

const ALLOWED_JWS_ALGS: [&str; 1] = ["EdDSA"];
const FORBIDDEN_JWS_HEADER_PARAMS: [&str; 6] = ["jwk", "jku", "x5u", "x5c", "crit", "zip"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwsSignatureEnvelope {
    pub alg: String,
    pub kid: Option<String>,
    pub typ: Option<String>,
    pub protected_b64: String,
    pub payload_b64: String,
    pub signing_input: Vec<u8>,
    pub signature: Vec<u8>,
}

pub fn parse_jws_compact(token: &str) -> Result<JwsSignatureEnvelope, ProtoError> {
    let mut parts = token.trim().split('.');
    let protected_b64 = parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ProtoError::Parse("JWS missing protected header".to_string()))?;
    let payload_b64 = parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ProtoError::Parse("JWS missing payload segment".to_string()))?;
    let sig_b64 = parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ProtoError::Parse("JWS missing signature".to_string()))?;
    if parts.next().is_some() {
        return Err(ProtoError::Parse(
            "JWS must have exactly three segments".to_string(),
        ));
    }
    build_jws_envelope(protected_b64, payload_b64, sig_b64)
}

pub(crate) fn build_jws_envelope(
    protected_b64: &str,
    payload_b64: &str,
    sig_b64: &str,
) -> Result<JwsSignatureEnvelope, ProtoError> {
    if protected_b64.contains('=') || payload_b64.contains('=') || sig_b64.contains('=') {
        return Err(ProtoError::Parse(
            "RFC 7515 base64url segments must be unpadded".to_string(),
        ));
    }
    let hdr_bytes = decode_base64_url(protected_b64)
        .ok_or_else(|| ProtoError::Parse("invalid JWS protected base64url".to_string()))?;
    let hdr_val = parse_strict_json_bytes(&hdr_bytes, 16_384, 8)?;
    let hdr_obj = hdr_val
        .as_object()
        .ok_or_else(|| ProtoError::Parse("JWS protected header must be JSON object".to_string()))?;
    for forbidden in FORBIDDEN_JWS_HEADER_PARAMS {
        if hdr_obj.contains_key(forbidden) {
            return Err(ProtoError::Parse(format!(
                "disallowed JWS protected header parameter `{forbidden}`"
            )));
        }
    }
    if let Some(b64_val) = hdr_obj.get("b64")
        && b64_val != &Value::Bool(true)
    {
        return Err(ProtoError::Parse(
            "JWS unencoded payload (`b64: false`) is rejected".to_string(),
        ));
    }
    let alg = hdr_obj
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| ProtoError::Parse("JWS missing alg".to_string()))?;
    if !ALLOWED_JWS_ALGS.contains(&alg) {
        return Err(ProtoError::Parse(
            "disallowed JWS alg (only EdDSA accepted)".to_string(),
        ));
    }
    let signature = decode_base64_url(sig_b64)
        .ok_or_else(|| ProtoError::Parse("invalid JWS signature base64url".to_string()))?;
    if signature.len() != 64 {
        return Err(ProtoError::Parse(
            "EdDSA JWS signature must decode to 64 bytes".to_string(),
        ));
    }
    let mut signing_input = Vec::with_capacity(
        protected_b64
            .len()
            .saturating_add(1)
            .saturating_add(payload_b64.len()),
    );
    signing_input.extend_from_slice(protected_b64.as_bytes());
    signing_input.push(b'.');
    signing_input.extend_from_slice(payload_b64.as_bytes());
    Ok(JwsSignatureEnvelope {
        alg: alg.to_string(),
        kid: hdr_obj
            .get("kid")
            .and_then(Value::as_str)
            .map(str::to_string),
        typ: hdr_obj
            .get("typ")
            .and_then(Value::as_str)
            .map(str::to_string),
        protected_b64: protected_b64.to_string(),
        payload_b64: payload_b64.to_string(),
        signing_input,
        signature,
    })
}

pub(crate) fn canonicalize_jcs_payload(
    unsigned_obj: Map<String, Value>,
) -> Result<(String, String), ProtoError> {
    let jcs_value = canonicalize_jcs_value(&Value::Object(unsigned_obj), 0)?;
    let payload_json =
        serde_json::to_string(&jcs_value).map_err(|e| ProtoError::Serialize(e.to_string()))?;
    let payload_b64 = encode_base64_url_nopad(payload_json.as_bytes());
    Ok((payload_json, payload_b64))
}

fn canonicalize_jcs_value(val: &Value, depth: usize) -> Result<Value, ProtoError> {
    if depth > MAX_JSON_DEPTH {
        return Err(ProtoError::DepthLimitExceeded);
    }
    let next_depth = depth.saturating_add(1);
    match val {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = Map::new();
            for k in keys {
                if let Some(child) = map.get(k) {
                    out.insert(k.clone(), canonicalize_jcs_value(child, next_depth)?);
                }
            }
            Ok(Value::Object(out))
        }
        Value::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for item in arr {
                out.push(canonicalize_jcs_value(item, next_depth)?);
            }
            Ok(Value::Array(out))
        }
        other => Ok(other.clone()),
    }
}
