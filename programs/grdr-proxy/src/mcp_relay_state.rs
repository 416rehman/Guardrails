// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Security state for `McpRelay` HTTP routes: bearer token reuse detection,
//! descriptor pinning, tool poisoning/NFKC shadowing filtering, and OAuth step-up pinning.

use std::collections::{BTreeMap, VecDeque};

use axum::http::HeaderMap;
use serde::Deserialize;
use serde_json::Value;
use unicode_normalization::UnicodeNormalization;
use url::Url;
use zeroize::Zeroizing;

use grdr_crypto::{domain_hmac_sha256, encode_lower_hex, fill_random};
use grdr_mcp_proto::{
    McpMethod, McpRequest, PinVerification, ToolDescriptor, ToolPin, canonical_tool_digest,
    detect_tool_poisoning, parse_strict_mcp_json, verify_tool_pin,
};

use crate::ProxyError;

const RELAY_TOKEN_DOMAIN: &str = "grdr.proxy.mcp-relay.token.v1";
const MAX_TRACKED_TOKENS: usize = 4_096;

#[derive(Debug, Clone, Deserialize)]
struct RawWireTool {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(alias = "inputSchema", default)]
    input_schema: Value,
}

#[derive(Debug, Clone)]
pub struct McpRelayState {
    token_key: Result<Zeroizing<[u8; 32]>, String>,
    token_owners: BTreeMap<String, String>,
    token_order: VecDeque<String>,
    approved_tools: BTreeMap<(String, String), ToolPin>,
    first_seen_digests: BTreeMap<(String, String), String>,
    canonical_owners: BTreeMap<String, (String, String)>,
    descriptors: BTreeMap<(String, String), ToolDescriptor>,
    oauth_resource_pins: BTreeMap<String, String>,
}

impl Default for McpRelayState {
    fn default() -> Self {
        Self::new()
    }
}

impl McpRelayState {
    #[must_use]
    pub fn new() -> Self {
        let mut key = Zeroizing::new([0_u8; 32]);
        let token_key = match fill_random(key.as_mut()) {
            Ok(()) => Ok(key),
            Err(e) => Err(format!("CSPRNG failed initializing McpRelay key: {e}")),
        };
        Self {
            token_key,
            token_owners: BTreeMap::new(),
            token_order: VecDeque::new(),
            approved_tools: BTreeMap::new(),
            first_seen_digests: BTreeMap::new(),
            canonical_owners: BTreeMap::new(),
            descriptors: BTreeMap::new(),
            oauth_resource_pins: BTreeMap::new(),
        }
    }

    pub fn approve_route_tool(&mut self, route_id: &str, desc: ToolDescriptor) {
        let key = (route_id.to_owned(), desc.name.clone());
        let digest = canonical_tool_digest(&desc);
        self.canonical_owners
            .insert(canonical_shadow_key(&desc.name), key.clone());
        self.approved_tools.insert(
            key.clone(),
            ToolPin {
                server_name: route_id.to_owned(),
                tool_name: desc.name.clone(),
                digest_sha256: digest,
                schema_version: 1,
            },
        );
        self.descriptors.insert(key, desc);
    }

    pub fn check_and_record_bearer(
        &mut self,
        route_id: &str,
        bearer: &str,
    ) -> Result<(), ProxyError> {
        let key = self
            .token_key
            .as_ref()
            .map_err(|e| ProxyError::Transport(e.clone()))?;
        let trimmed = bearer.trim();
        if trimmed.is_empty() {
            return Err(ProxyError::Sr39Rejected("empty MCP bearer token".into()));
        }
        let mac = domain_hmac_sha256(key.as_ref(), RELAY_TOKEN_DOMAIN, trimmed.as_bytes());
        let hex = encode_lower_hex(&mac);
        if let Some(owner) = self.token_owners.get(&hex) {
            if owner != route_id {
                return Err(ProxyError::PolicyDenied(format!(
                    "mcp.token-reuse: bearer bound to route `{owner}` replayed on `{route_id}`"
                )));
            }
            return Ok(());
        }
        while self.token_owners.len() >= MAX_TRACKED_TOKENS {
            let Some(oldest) = self.token_order.pop_front() else {
                break;
            };
            self.token_owners.remove(&oldest);
        }
        self.token_order.push_back(hex.clone());
        self.token_owners.insert(hex, route_id.to_owned());
        Ok(())
    }

    pub fn verify_tool_call(&self, route_id: &str, tool_name: &str) -> Result<(), ProxyError> {
        let key = (route_id.to_owned(), tool_name.to_owned());
        let shadow = canonical_shadow_key(tool_name);
        if let Some(owner) = self.canonical_owners.get(&shadow)
            && owner != &key
        {
            return Err(ProxyError::PolicyDenied(format!(
                "MCP tool shadowing rejected (`{tool_name}` conflicts with `{}::{}`)",
                owner.0, owner.1
            )));
        }
        let Some(desc) = self.descriptors.get(&key) else {
            return Ok(());
        };
        if !detect_tool_poisoning(desc).is_empty() {
            return Err(ProxyError::PolicyDenied(format!(
                "MCP tool `{tool_name}` failed poisoning inspection"
            )));
        }
        if let Some(pin) = self.approved_tools.get(&key) {
            return match verify_tool_pin(desc, Some(pin)) {
                PinVerification::Matched | PinVerification::Unpinned => Ok(()),
                PinVerification::Drifted { expected, actual } => Err(ProxyError::PolicyDenied(
                    format!("MCP tool pin drift `{tool_name}`: {expected} != {actual}"),
                )),
            };
        }
        Ok(())
    }

    pub fn bind_or_verify_oauth_metadata(
        &mut self,
        route_id: &str,
        resource_metadata_url: &str,
    ) -> Result<(), ProxyError> {
        let parsed = Url::parse(resource_metadata_url).map_err(|_| {
            ProxyError::SsrfDenied("invalid MCP OAuth resource_metadata URL".into())
        })?;
        if !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(ProxyError::SsrfDenied(
                "MCP OAuth resource_metadata URL must not include credentials, query, or fragment"
                    .into(),
            ));
        }
        let normalized = parsed.as_str().trim_end_matches('/').to_owned();
        if let Some(existing) = self.oauth_resource_pins.get(route_id)
            && existing != &normalized
        {
            return Err(ProxyError::PolicyDenied(format!(
                "MCP OAuth resource_metadata hijacked for `{route_id}`"
            )));
        }
        self.oauth_resource_pins
            .insert(route_id.to_owned(), normalized);
        Ok(())
    }

    pub fn filter_tools_list_json(
        &mut self,
        route_id: &str,
        raw: &str,
    ) -> Result<String, ProxyError> {
        let mut val = parse_strict_mcp_json(raw)
            .map_err(|e| ProxyError::Transport(format!("invalid upstream MCP JSON: {e}")))?;
        let changed = match &mut val {
            Value::Object(_) => self.filter_single_object(route_id, &mut val)?,
            Value::Array(items) => {
                let mut any = false;
                for item in items {
                    if !item.is_object() {
                        return Err(ProxyError::Transport(
                            "MCP batch item must be object".into(),
                        ));
                    }
                    if self.filter_single_object(route_id, item)? {
                        any = true;
                    }
                }
                any
            }
            _ => {
                return Err(ProxyError::Transport(
                    "MCP response must be object/array".into(),
                ));
            }
        };
        if !changed {
            return Ok(raw.to_owned());
        }
        serde_json::to_string(&val).map_err(|e| ProxyError::Transport(e.to_string()))
    }

    fn filter_single_object(
        &mut self,
        route_id: &str,
        val: &mut Value,
    ) -> Result<bool, ProxyError> {
        let Some(tools_val) = val.get("result").and_then(|r| r.get("tools")).cloned() else {
            return Ok(false);
        };
        let raw_tools: Vec<RawWireTool> = serde_json::from_value(tools_val)
            .map_err(|e| ProxyError::Transport(format!("malformed MCP tools/list: {e}")))?;
        let mut allowed = Vec::new();
        for raw in raw_tools {
            let desc = ToolDescriptor {
                name: raw.name,
                description: raw.description,
                input_schema: raw.input_schema,
            };
            if !detect_tool_poisoning(&desc).is_empty() {
                continue;
            }
            let key = (route_id.to_owned(), desc.name.clone());
            let shadow = canonical_shadow_key(&desc.name);
            if let Some(owner) = self.canonical_owners.get(&shadow)
                && owner != &key
            {
                continue;
            }
            let digest = canonical_tool_digest(&desc);
            if let Some(pin) = self.approved_tools.get(&key)
                && pin.digest_sha256 != digest
            {
                return Err(ProxyError::PolicyDenied(format!(
                    "MCP pin drift on tools/list for `{}`",
                    desc.name
                )));
            }
            if let Some(seen) = self.first_seen_digests.get(&key) {
                if seen != &digest {
                    return Err(ProxyError::PolicyDenied(format!(
                        "MCP mid-session rug pull detected for `{}`",
                        desc.name
                    )));
                }
            } else {
                self.first_seen_digests.insert(key.clone(), digest);
            }
            self.canonical_owners.insert(shadow, key.clone());
            self.descriptors.insert(key, desc.clone());
            allowed.push(desc);
        }
        if let Some(res_obj) = val.get_mut("result").and_then(Value::as_object_mut) {
            let tools_json =
                serde_json::to_value(allowed).map_err(|e| ProxyError::Transport(e.to_string()))?;
            res_obj.insert("tools".into(), tools_json);
        }
        Ok(true)
    }
}

pub(crate) fn validate_mcp_relay_headers(
    headers: &HeaderMap,
    session_id: &str,
    req: Option<&McpRequest>,
) -> Result<(), ProxyError> {
    for name in [
        "mcp-protocol-version",
        "mcp-session-id",
        "mcp-method",
        "mcp-name",
    ] {
        if headers.get_all(name).iter().count() > 1 {
            return Err(ProxyError::Sr39Rejected(format!(
                "duplicate `{name}` header rejected on McpRelay"
            )));
        }
    }
    if let Some(sid_hdr) = headers.get("mcp-session-id").and_then(|v| v.to_str().ok())
        && !grdr_crypto::constant_time_eq(sid_hdr.trim().as_bytes(), session_id.as_bytes())
    {
        return Err(ProxyError::Sr39Rejected(
            "Mcp-Session-Id disagrees with bound SR-39 session".into(),
        ));
    }
    let rev = match headers
        .get("mcp-protocol-version")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(v) if matches!(v, "2025-06-18" | "2025-11-25" | "2026-07-28") => v,
        Some(other) => {
            return Err(ProxyError::Sr39Rejected(format!(
                "unsupported Mcp-Protocol-Version `{other}`"
            )));
        }
        None => "2025-11-25",
    };

    let Some(req) = req else {
        return Ok(());
    };
    let hdr_method = headers
        .get("mcp-method")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if rev == "2026-07-28" && hdr_method.is_none() {
        return Err(ProxyError::Sr39Rejected(
            "MCP 2026-07-28 requires Mcp-Method header".into(),
        ));
    }
    if let Some(m) = hdr_method
        && m != req.method.as_wire()
    {
        return Err(ProxyError::Sr39Rejected(format!(
            "Mcp-Method `{m}` disagrees with JSON-RPC method `{}`",
            req.method.as_wire()
        )));
    }
    let expected_name = req.tool_name.as_deref().or_else(|| {
        matches!(
            req.method,
            McpMethod::ResourcesRead | McpMethod::ResourcesSubscribe
        )
        .then(|| req.target_hint.as_deref())
        .flatten()
    });
    let hdr_name = headers
        .get("mcp-name")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if let Some(actual) = hdr_name
        && expected_name != Some(actual)
    {
        return Err(ProxyError::Sr39Rejected(format!(
            "Mcp-Name `{actual}` disagrees with JSON-RPC target name"
        )));
    }
    if rev == "2026-07-28"
        && matches!(
            req.method,
            McpMethod::ToolsCall
                | McpMethod::ResourcesRead
                | McpMethod::ResourcesSubscribe
                | McpMethod::PromptsGet
        )
        && hdr_name.is_none()
    {
        return Err(ProxyError::Sr39Rejected(
            "MCP 2026-07-28 requires Mcp-Name header".into(),
        ));
    }
    Ok(())
}

pub(crate) fn parse_www_auth_resource_metadata(header_val: &str) -> Option<(String, String)> {
    let trimmed = header_val.trim();
    let lower = trimmed.to_ascii_lowercase();
    let rest = lower
        .strip_prefix("bearer")
        .filter(|tail| tail.starts_with(char::is_whitespace))
        .and_then(|_| trimmed.get(6..))?
        .trim();
    let mut resource_metadata = None;
    let mut scope = String::new();
    for part in split_rfc9110_auth_params(rest) {
        let Some((k, v)) = part.trim().split_once('=') else {
            continue;
        };
        let key = k.trim().to_ascii_lowercase();
        let val = unquote_rfc9110_value(v.trim());
        if key == "resource_metadata" && !val.is_empty() {
            resource_metadata = Some(val);
        } else if key == "scope" {
            scope = val;
        }
    }
    Some((resource_metadata?, scope))
}

fn split_rfc9110_auth_params(input: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut in_quotes = false;
    let mut escaped = false;
    let mut start = 0usize;
    for (idx, ch) in input.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' && in_quotes {
            escaped = true;
            continue;
        }
        if ch == '"' {
            in_quotes = !in_quotes;
            continue;
        }
        if ch == ',' && !in_quotes {
            if let Some(slice) = input.get(start..idx) {
                parts.push(slice);
            }
            start = idx.saturating_add(1);
        }
    }
    if let Some(tail) = input.get(start..) {
        parts.push(tail);
    }
    parts
}

fn unquote_rfc9110_value(raw: &str) -> String {
    if let Some(inner) = raw.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        let mut out = String::with_capacity(inner.len());
        let mut escaped = false;
        for ch in inner.chars() {
            if escaped {
                out.push(ch);
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else {
                out.push(ch);
            }
        }
        return out;
    }
    raw.to_string()
}

fn canonical_shadow_key(raw: &str) -> String {
    let nfkc: String = raw.nfkc().collect();
    let nfc: String = nfkc.nfc().collect();
    nfc.chars()
        .flat_map(char::to_lowercase)
        .filter(|ch| ch.is_alphanumeric())
        .collect()
}
