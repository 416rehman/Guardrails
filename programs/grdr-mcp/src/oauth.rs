// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::{BTreeMap, VecDeque};
use std::fmt;

use grdr_crypto::{
    constant_time_eq, domain_hmac_sha256, encode_lower_hex, fill_random, sha256_digest,
};
use grdr_llm_proto::strict_json::{MAX_JSON_DEPTH, MAX_SSE_EVENT_BYTES, parse_strict_json_str};
use serde::{Deserialize, Serialize};
use url::Url;
use zeroize::Zeroizing;

use crate::McpBrokerError;

const TOKEN_HMAC_DOMAIN: &str = "grdr.mcp.token-reuse.v1";
const MAX_TRACKED_TOKEN_DIGESTS: usize = 4_096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthProtectedResourceMetadata {
    pub resource: String,
    pub authorization_servers: Vec<String>,
    #[serde(default)]
    pub scopes_supported: Vec<String>,
    #[serde(default)]
    pub bearer_methods_supported: Vec<String>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PkceChallenge {
    pub code_verifier: Zeroizing<String>,
    pub code_challenge: String,
    pub method: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthServerBinding {
    pub issuer: String,
    pub resource_uri: String,
}

#[derive(Debug, Clone, Default)]
pub struct OAuthIssuerPinRegistry {
    bindings: BTreeMap<String, OAuthServerBinding>,
}

#[derive(Clone)]
pub struct TokenDigestRegistry {
    boot_key: Result<Zeroizing<[u8; 32]>, String>,
    seen_server_by_digest: BTreeMap<String, String>,
    digest_order: VecDeque<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepUpAuthChallenge {
    pub resource_metadata: String,
    pub scope: String,
}

impl fmt::Debug for PkceChallenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PkceChallenge")
            .field("code_verifier", &"<redacted>")
            .field("code_challenge", &self.code_challenge)
            .field("method", &self.method)
            .finish()
    }
}

impl fmt::Debug for TokenDigestRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenDigestRegistry")
            .field("boot_key_ready", &self.boot_key.is_ok())
            .field("tracked_digests", &self.seen_server_by_digest.len())
            .finish()
    }
}

impl Default for TokenDigestRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl OAuthIssuerPinRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            bindings: BTreeMap::new(),
        }
    }

    pub fn bind_or_verify(
        &mut self,
        server_id: &str,
        resource_uri: &str,
        issuer: &str,
    ) -> Result<(), McpBrokerError> {
        self.bind_or_verify_with_policy(server_id, resource_uri, issuer, false)
    }

    pub fn bind_or_verify_with_policy(
        &mut self,
        server_id: &str,
        resource_uri: &str,
        issuer: &str,
        allow_loopback_http: bool,
    ) -> Result<(), McpBrokerError> {
        let norm_resource = normalize_origin_url(resource_uri, allow_loopback_http)?;
        let norm_issuer = normalize_origin_url(issuer, allow_loopback_http)?;
        if let Some(existing) = self.bindings.get(server_id) {
            if existing.issuer != norm_issuer {
                return Err(McpBrokerError::OAuthOrSsrf(format!(
                    "OAuth issuer drifted for `{server_id}`: expected {}, got {norm_issuer}",
                    existing.issuer
                )));
            }
            if existing.resource_uri != norm_resource {
                return Err(McpBrokerError::OAuthOrSsrf(format!(
                    "RFC 8707 resource mismatch for `{server_id}`: expected {}, got {norm_resource}",
                    existing.resource_uri
                )));
            }
            return Ok(());
        }
        self.bindings.insert(
            server_id.to_string(),
            OAuthServerBinding {
                issuer: norm_issuer,
                resource_uri: norm_resource,
            },
        );
        Ok(())
    }
}

impl TokenDigestRegistry {
    #[must_use]
    pub fn new() -> Self {
        let mut key = Zeroizing::new([0u8; 32]);
        let boot_key = match fill_random(key.as_mut()) {
            Ok(()) => Ok(key),
            Err(err) => Err(format!("CSPRNG failed initializing token HMAC key: {err}")),
        };
        Self {
            boot_key,
            seen_server_by_digest: BTreeMap::new(),
            digest_order: VecDeque::new(),
        }
    }

    pub fn try_new() -> Result<Self, McpBrokerError> {
        let reg = Self::new();
        if let Err(ref err) = reg.boot_key {
            return Err(McpBrokerError::OAuthOrSsrf(err.clone()));
        }
        Ok(reg)
    }

    pub fn check_and_record_bearer(
        &mut self,
        server_id: &str,
        bearer_token: &str,
    ) -> Result<(), McpBrokerError> {
        let key = self
            .boot_key
            .as_ref()
            .map_err(|err| McpBrokerError::OAuthOrSsrf(err.clone()))?;
        let trimmed = bearer_token.trim();
        if trimmed.is_empty() {
            return Err(McpBrokerError::OAuthOrSsrf(
                "empty bearer token".to_string(),
            ));
        }
        let mac = domain_hmac_sha256(key.as_ref(), TOKEN_HMAC_DOMAIN, trimmed.as_bytes());
        let digest_hex = encode_lower_hex(&mac);
        if let Some(bound_server) = self.seen_server_by_digest.get(&digest_hex) {
            if bound_server != server_id {
                return Err(McpBrokerError::OAuthOrSsrf(format!(
                    "mcp.token-reuse: token bound to `{bound_server}` replayed on `{server_id}`"
                )));
            }
            return Ok(());
        }
        while self.seen_server_by_digest.len() >= MAX_TRACKED_TOKEN_DIGESTS {
            let Some(oldest) = self.digest_order.pop_front() else {
                break;
            };
            self.seen_server_by_digest.remove(&oldest);
        }
        self.digest_order.push_back(digest_hex.clone());
        self.seen_server_by_digest
            .insert(digest_hex, server_id.to_string());
        Ok(())
    }
}

pub fn parse_rfc9728_metadata(
    raw_json: &str,
    expected_resource_url: &str,
    allow_loopback_http: bool,
) -> Result<OAuthProtectedResourceMetadata, McpBrokerError> {
    let val = parse_strict_json_str(raw_json, MAX_SSE_EVENT_BYTES, MAX_JSON_DEPTH)
        .map_err(|e| McpBrokerError::OAuthOrSsrf(format!("invalid RFC 9728 metadata: {e}")))?;
    let meta: OAuthProtectedResourceMetadata = serde_json::from_value(val)
        .map_err(|e| McpBrokerError::OAuthOrSsrf(format!("invalid RFC 9728 schema: {e}")))?;
    let actual_res = normalize_origin_url(&meta.resource, allow_loopback_http)?;
    let expected_res = normalize_origin_url(expected_resource_url, allow_loopback_http)?;
    if actual_res != expected_res {
        return Err(McpBrokerError::OAuthOrSsrf(format!(
            "RFC 8707 resource mismatch: expected {expected_res}, got {actual_res}"
        )));
    }
    if meta.authorization_servers.is_empty() {
        return Err(McpBrokerError::OAuthOrSsrf(
            "RFC 9728 metadata missing authorization_servers".to_string(),
        ));
    }
    for authz in &meta.authorization_servers {
        let _ = normalize_origin_url(authz, allow_loopback_http)?;
    }
    Ok(meta)
}

pub fn generate_pkce_s256() -> Result<PkceChallenge, McpBrokerError> {
    let mut raw = Zeroizing::new([0u8; 32]);
    fill_random(raw.as_mut())
        .map_err(|e| McpBrokerError::OAuthOrSsrf(format!("PKCE entropy error: {e}")))?;
    let code_verifier = Zeroizing::new(encode_base64_url_nopad(raw.as_ref()));
    let digest = sha256_digest(code_verifier.as_bytes());
    let code_challenge = encode_base64_url_nopad(&digest);
    Ok(PkceChallenge {
        code_verifier,
        code_challenge,
        method: "S256",
    })
}

#[must_use]
pub fn verify_pkce_s256(verifier: &str, expected_challenge: &str) -> bool {
    if verifier.len() < 43 || verifier.len() > 128 {
        return false;
    }
    let digest = sha256_digest(verifier.as_bytes());
    let computed = encode_base64_url_nopad(&digest);
    constant_time_eq(computed.as_bytes(), expected_challenge.trim().as_bytes())
}

#[must_use]
pub fn parse_www_authenticate_step_up(header_val: &str) -> Option<StepUpAuthChallenge> {
    let trimmed = header_val.trim();
    let lower = trimmed.to_ascii_lowercase();
    if !lower.starts_with("bearer ") {
        return None;
    }
    let rest = trimmed.get(7..)?.trim();
    let params = split_rfc9110_auth_params(rest)?;
    let mut resource_metadata: Option<String> = None;
    let mut scope = String::new();
    for (raw_k, raw_v) in params {
        let k = raw_k.to_ascii_lowercase();
        if k == "resource_metadata" {
            if resource_metadata.is_some() || raw_v.trim().is_empty() {
                return None;
            }
            resource_metadata = Some(raw_v);
        } else if k == "scope" {
            scope = raw_v;
        }
    }
    Some(StepUpAuthChallenge {
        resource_metadata: resource_metadata?,
        scope,
    })
}

fn split_rfc9110_auth_params(input: &str) -> Option<Vec<(String, String)>> {
    let mut out = Vec::new();
    let mut chars = input.char_indices().peekable();
    loop {
        while matches!(chars.peek(), Some(&(_, ch)) if ch == ' ' || ch == '\t' || ch == ',') {
            chars.next();
        }
        if chars.peek().is_none() {
            break;
        }
        let mut key = String::new();
        while let Some(&(_, ch)) = chars.peek() {
            if ch == '=' || ch == ' ' || ch == '\t' {
                break;
            }
            key.push(ch);
            chars.next();
        }
        while matches!(chars.peek(), Some(&(_, ch)) if ch == ' ' || ch == '\t') {
            chars.next();
        }
        let (_, eq) = chars.next()?;
        if eq != '=' || key.is_empty() {
            return None;
        }
        while matches!(chars.peek(), Some(&(_, ch)) if ch == ' ' || ch == '\t') {
            chars.next();
        }
        let val = match chars.peek().map(|&(_, ch)| ch) {
            Some('"') => {
                chars.next();
                let mut quoted = String::new();
                let mut closed = false;
                while let Some((_, ch)) = chars.next() {
                    if ch == '\\' {
                        let (_, esc) = chars.next()?;
                        quoted.push(esc);
                    } else if ch == '"' {
                        closed = true;
                        break;
                    } else {
                        quoted.push(ch);
                    }
                }
                if !closed {
                    return None;
                }
                quoted
            }
            Some(_) => {
                let mut token = String::new();
                while let Some(&(_, ch)) = chars.peek() {
                    if ch == ',' {
                        break;
                    }
                    token.push(ch);
                    chars.next();
                }
                token.trim().to_string()
            }
            None => return None,
        };
        out.push((key.trim().to_string(), val));
    }
    Some(out)
}

fn normalize_origin_url(raw: &str, allow_loopback_http: bool) -> Result<String, McpBrokerError> {
    let parsed = Url::parse(raw.trim())
        .map_err(|e| McpBrokerError::OAuthOrSsrf(format!("invalid OAuth URL: {e}")))?;
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(McpBrokerError::OAuthOrSsrf(
            "OAuth URL must not contain query or fragment components".to_string(),
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(McpBrokerError::OAuthOrSsrf(
            "OAuth URL must not contain credentials".to_string(),
        ));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| McpBrokerError::OAuthOrSsrf("OAuth URL missing host".to_string()))?;
    let host_unbracketed = host.trim_start_matches('[').trim_end_matches(']');
    let is_loopback = host_unbracketed == "127.0.0.1"
        || host_unbracketed == "localhost"
        || host_unbracketed == "::1";
    let scheme = parsed.scheme();
    if scheme != "https" && !(allow_loopback_http && scheme == "http" && is_loopback) {
        return Err(McpBrokerError::OAuthOrSsrf(
            "OAuth metadata/issuer URL must use HTTPS".to_string(),
        ));
    }
    let port = parsed.port().map(|p| format!(":{p}")).unwrap_or_default();
    let path = parsed.path().trim_end_matches('/');
    Ok(format!("{scheme}://{host}{port}{path}"))
}

fn encode_base64_url_nopad(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(
        bytes
            .len()
            .saturating_mul(4)
            .saturating_div(3)
            .saturating_add(2),
    );
    let mut idx = 0usize;
    while idx < bytes.len() {
        let b0 = bytes.get(idx).copied().unwrap_or(0);
        let b1 = bytes.get(idx.saturating_add(1)).copied();
        let b2 = bytes.get(idx.saturating_add(2)).copied();
        let combined =
            (u32::from(b0) << 16) | (u32::from(b1.unwrap_or(0)) << 8) | u32::from(b2.unwrap_or(0));
        let push_idx = |out: &mut String, i: usize| {
            if let Some(&ch) = TABLE.get(i) {
                out.push(ch as char);
            }
        };
        push_idx(
            &mut out,
            usize::try_from((combined >> 18) & 0x3F).unwrap_or(0),
        );
        push_idx(
            &mut out,
            usize::try_from((combined >> 12) & 0x3F).unwrap_or(0),
        );
        if b1.is_some() {
            push_idx(
                &mut out,
                usize::try_from((combined >> 6) & 0x3F).unwrap_or(0),
            );
        }
        if b2.is_some() {
            push_idx(&mut out, usize::try_from(combined & 0x3F).unwrap_or(0));
        }
        idx = idx.saturating_add(3);
    }
    out
}
