// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeSet;

use grdr_crypto::{constant_time_eq, domain_hmac_sha256, encode_lower_hex};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::AcpError;

const ACS_HMAC_DOMAIN: &str = "grdr.owasp.acs.v1";
pub const MIN_ACS_HMAC_KEY_LEN: usize = 32;
const HMAC_SHA256_HEX_LEN: usize = 64;

#[derive(Debug, Clone)]
pub struct AcsReplayGuard {
    max_entries: usize,
    max_skew_seconds: i64,
    seen: BTreeSet<String>,
    by_time: BTreeSet<(i64, String)>,
    last_evicted_s: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedAcsJsonRpcFrame {
    pub jsonrpc: String,
    pub id: Value,
    pub method: String,
    pub params: Value,
    pub nonce: String,
    pub timestamp_s: i64,
    pub hmac_hex: String,
}

impl AcsReplayGuard {
    #[must_use]
    pub fn new(max_entries: usize, max_skew_seconds: i64) -> Self {
        Self {
            max_entries: max_entries.max(16),
            max_skew_seconds: max_skew_seconds.max(1),
            seen: BTreeSet::new(),
            by_time: BTreeSet::new(),
            last_evicted_s: None,
        }
    }

    pub fn record_or_reject(
        &mut self,
        nonce: &str,
        issued_s: i64,
        now_s: i64,
    ) -> Result<(), AcpError> {
        let trimmed = nonce.trim();
        if trimmed.is_empty() {
            return Err(AcpError::ReplayOrSkew("missing ACS nonce".to_string()));
        }
        if issued_s.saturating_sub(now_s).saturating_abs() > self.max_skew_seconds {
            return Err(AcpError::ReplayOrSkew(
                "ACS timestamp skew exceeds window".to_string(),
            ));
        }
        while let Some((oldest_ts, _)) = self.by_time.first() {
            if now_s.saturating_sub(*oldest_ts) <= self.max_skew_seconds {
                break;
            }
            if let Some((_, expired_nonce)) = self.by_time.pop_first() {
                self.seen.remove(&expired_nonce);
            }
        }
        if self.last_evicted_s.is_some_and(|floor| issued_s <= floor) {
            return Err(AcpError::ReplayOrSkew(
                "ACS timestamp precedes evicted replay horizon".to_string(),
            ));
        }
        if !self.seen.insert(trimmed.to_string()) {
            return Err(AcpError::ReplayOrSkew("replayed ACS nonce".to_string()));
        }
        self.by_time.insert((issued_s, trimmed.to_string()));
        while self.by_time.len() > self.max_entries {
            if let Some((evicted_ts, evicted_nonce)) = self.by_time.pop_first() {
                self.seen.remove(&evicted_nonce);
                self.last_evicted_s = Some(
                    self.last_evicted_s
                        .map_or(evicted_ts, |prev| prev.max(evicted_ts)),
                );
            }
        }
        Ok(())
    }
}

pub fn sign_owasp_acs_jsonrpc(
    id: Value,
    method: &str,
    params: Value,
    nonce: &str,
    timestamp_s: i64,
    hmac_key: &[u8],
) -> Result<SignedAcsJsonRpcFrame, AcpError> {
    if hmac_key.len() < MIN_ACS_HMAC_KEY_LEN || method.trim().is_empty() || nonce.trim().is_empty()
    {
        return Err(AcpError::InvalidPayload(
            "ACS HMAC signing requires >= 32-byte key, non-empty method, and nonce".to_string(),
        ));
    }
    let canonical = canonical_acs_signing_input(&id, method, &params, nonce, timestamp_s)?;
    let mac = domain_hmac_sha256(hmac_key, ACS_HMAC_DOMAIN, canonical.as_bytes());
    Ok(SignedAcsJsonRpcFrame {
        jsonrpc: "2.0".to_string(),
        id,
        method: method.to_string(),
        params,
        nonce: nonce.to_string(),
        timestamp_s,
        hmac_hex: encode_lower_hex(&mac),
    })
}

pub fn verify_owasp_acs_jsonrpc(
    frame: &SignedAcsJsonRpcFrame,
    hmac_key: &[u8],
    replay: &mut AcsReplayGuard,
    now_unix_s: i64,
) -> Result<(), AcpError> {
    if frame.jsonrpc != "2.0" || hmac_key.len() < MIN_ACS_HMAC_KEY_LEN {
        return Err(AcpError::SignatureInvalid(
            "invalid ACS JSON-RPC version or key length".to_string(),
        ));
    }
    let mac_hex = frame.hmac_hex.as_str();
    if mac_hex.len() != HMAC_SHA256_HEX_LEN
        || !mac_hex
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(AcpError::SignatureInvalid(
            "invalid ACS HMAC encoding".to_string(),
        ));
    }
    let canonical = canonical_acs_signing_input(
        &frame.id,
        &frame.method,
        &frame.params,
        &frame.nonce,
        frame.timestamp_s,
    )?;
    let expected = domain_hmac_sha256(hmac_key, ACS_HMAC_DOMAIN, canonical.as_bytes());
    let expected_hex = encode_lower_hex(&expected);
    if !constant_time_eq(expected_hex.as_bytes(), mac_hex.as_bytes()) {
        return Err(AcpError::SignatureInvalid(
            "OWASP ACS HMAC verification failed".to_string(),
        ));
    }
    replay.record_or_reject(&frame.nonce, frame.timestamp_s, now_unix_s)
}

fn canonical_acs_signing_input(
    id: &Value,
    method: &str,
    params: &Value,
    nonce: &str,
    timestamp_s: i64,
) -> Result<String, AcpError> {
    let payload = json!({
        "id": id,
        "method": method,
        "params": params,
        "nonce": nonce,
        "timestamp_s": timestamp_s,
    });
    serde_json::to_string(&payload).map_err(|e| AcpError::InvalidPayload(e.to_string()))
}
