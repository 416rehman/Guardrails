// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! MCP protocol revisions (2025-06-18, 2025-11-25, 2026-07-28), session binding,
//! `isError` / `_meta["grdr/decision"]` responses, and `-32042` step-up elicitation.

use std::collections::{BTreeMap, VecDeque};

use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use grdr_crypto::{constant_time_eq, fill_random};
use grdr_mcp_proto::{McpMethod, McpRequest, McpResponse, McpRpcError};
use grdr_model::{DecisionReceipt, Verdict};
use grdr_strings::sanitize_untrusted_text;

use crate::McpBrokerError;

pub const JSONRPC_ERR_HEADER_MISMATCH: i64 = -32020;
pub const JSONRPC_ERR_ELICITATION_REQUIRED: i64 = -32042;
pub const JSONRPC_ERR_POLICY_DENIED: i64 = -32001;
pub const MCP_HEADER_PROTOCOL_VERSION: &str = "mcp-protocol-version";
pub const MCP_HEADER_SESSION_ID: &str = "mcp-session-id";
pub const MCP_HEADER_METHOD: &str = "mcp-method";
pub const MCP_HEADER_NAME: &str = "mcp-name";
pub const MAX_MCP_SESSIONS: usize = 1_024;
pub const MAX_HTTP_MCP_BODY_BYTES: usize = 1_048_576;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum McpProtocolRevision {
    Rev2025_06_18,
    Rev2025_11_25,
    Rev2026_07_28,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionBindingState {
    pub session_id: String,
    pub revision: McpProtocolRevision,
}

#[derive(Debug, Default)]
pub struct McpSessionStore {
    sessions: BTreeMap<String, SessionBindingState>,
    order: VecDeque<String>,
}

impl McpProtocolRevision {
    pub fn parse(raw: &str) -> Result<Self, McpBrokerError> {
        match raw.trim() {
            "2025-06-18" => Ok(Self::Rev2025_06_18),
            "2025-11-25" => Ok(Self::Rev2025_11_25),
            "2026-07-28" => Ok(Self::Rev2026_07_28),
            other => Err(McpBrokerError::HeaderMismatch(format!(
                "unsupported MCP-Protocol-Version `{other}`"
            ))),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rev2025_06_18 => "2025-06-18",
            Self::Rev2025_11_25 => "2025-11-25",
            Self::Rev2026_07_28 => "2026-07-28",
        }
    }

    #[must_use]
    pub const fn supports_url_elicitation_32042(self) -> bool {
        matches!(self, Self::Rev2025_11_25 | Self::Rev2026_07_28)
    }
}

impl McpSessionStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn close_session(&mut self, session_id: &str) -> bool {
        let removed = self.sessions.remove(session_id).is_some();
        if removed {
            self.order.retain(|id| id != session_id);
        }
        removed
    }

    pub fn issue_session(
        &mut self,
        revision: McpProtocolRevision,
    ) -> Result<SessionBindingState, McpBrokerError> {
        if self.sessions.len() >= MAX_MCP_SESSIONS
            && let Some(evicted) = self.order.pop_front()
        {
            self.sessions.remove(&evicted);
        }
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut entropy = [0_u8; 16];
        fill_random(&mut entropy).map_err(|e| McpBrokerError::Transport(e.to_string()))?;
        let mut suffix = String::with_capacity(32);
        for byte in entropy {
            let hi = usize::from(byte >> 4);
            let lo = usize::from(byte & 0x0f);
            if let (Some(&c1), Some(&c2)) = (HEX.get(hi), HEX.get(lo)) {
                suffix.push(char::from(c1));
                suffix.push(char::from(c2));
            }
        }
        let session_id = format!("mcpsess_{suffix}_{}", Uuid::now_v7().simple());
        let state = SessionBindingState {
            session_id: session_id.clone(),
            revision,
        };
        self.order.push_back(session_id.clone());
        self.sessions.insert(session_id, state.clone());
        Ok(state)
    }

    pub fn verify_headers(
        &self,
        session_id_header: Option<&str>,
        protocol_header: Option<&str>,
    ) -> Result<&SessionBindingState, McpBrokerError> {
        let Some(sid) = session_id_header.map(str::trim).filter(|s| !s.is_empty()) else {
            return Err(McpBrokerError::SessionBinding(
                "missing Mcp-Session-Id header".into(),
            ));
        };
        let Some(state) = find_constant_time_session(&self.sessions, sid) else {
            return Err(McpBrokerError::SessionBinding(
                "unknown Mcp-Session-Id".into(),
            ));
        };
        let Some(ver_raw) = protocol_header else {
            return Err(McpBrokerError::HeaderMismatch(
                "missing MCP-Protocol-Version header".into(),
            ));
        };
        let parsed = McpProtocolRevision::parse(ver_raw)?;
        if parsed != state.revision {
            return Err(McpBrokerError::HeaderMismatch(format!(
                "session bound to {}, got {}",
                state.revision.as_str(),
                parsed.as_str()
            )));
        }
        Ok(state)
    }
}

pub fn verify_revision_consistency_headers(
    revision: McpProtocolRevision,
    headers: &HeaderMap,
    req: &McpRequest,
) -> Result<(), McpBrokerError> {
    for hdr_name in [
        MCP_HEADER_PROTOCOL_VERSION,
        MCP_HEADER_SESSION_ID,
        MCP_HEADER_METHOD,
        MCP_HEADER_NAME,
    ] {
        if headers.get_all(hdr_name).iter().count() > 1 {
            return Err(McpBrokerError::HeaderMismatch(format!(
                "duplicate `{hdr_name}` header rejected"
            )));
        }
    }

    let expected_method = mcp_method_wire_name(&req.method);
    let hdr_method = headers
        .get(MCP_HEADER_METHOD)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty());

    if revision == McpProtocolRevision::Rev2026_07_28 && hdr_method.is_none() {
        return Err(McpBrokerError::HeaderMismatch(
            "MCP 2026-07-28 requires Mcp-Method header".into(),
        ));
    }
    if let Some(actual_method) = hdr_method
        && actual_method != expected_method
    {
        return Err(McpBrokerError::HeaderMismatch(format!(
            "Mcp-Method `{actual_method}` disagrees with JSON-RPC method `{expected_method}`"
        )));
    }

    let hdr_name = headers
        .get(MCP_HEADER_NAME)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let expected_name = expected_mcp_name(req);
    if let Some(actual_name) = hdr_name
        && expected_name != Some(actual_name)
    {
        return Err(McpBrokerError::HeaderMismatch(format!(
            "Mcp-Name `{actual_name}` disagrees with JSON-RPC target name"
        )));
    }
    let requires_name = matches!(
        req.method,
        McpMethod::ToolsCall
            | McpMethod::ResourcesRead
            | McpMethod::ResourcesSubscribe
            | McpMethod::PromptsGet
    );
    if revision == McpProtocolRevision::Rev2026_07_28 && requires_name && hdr_name.is_none() {
        return Err(McpBrokerError::HeaderMismatch(format!(
            "MCP 2026-07-28 {} requires Mcp-Name header",
            expected_method
        )));
    }
    Ok(())
}

fn expected_mcp_name(req: &McpRequest) -> Option<&str> {
    if let Some(name) = req.tool_name.as_deref() {
        return Some(name);
    }
    if matches!(
        req.method,
        McpMethod::ResourcesRead | McpMethod::ResourcesSubscribe
    ) {
        return req.target_hint.as_deref();
    }
    None
}

fn mcp_method_wire_name(method: &McpMethod) -> &str {
    method.as_wire()
}

fn find_constant_time_session<'a>(
    sessions: &'a BTreeMap<String, SessionBindingState>,
    candidate: &str,
) -> Option<&'a SessionBindingState> {
    let mut matched: Option<&'a SessionBindingState> = None;
    for (id, state) in sessions {
        if constant_time_eq(id.as_bytes(), candidate.as_bytes()) {
            matched = Some(state);
        }
    }
    matched
}

#[must_use]
pub fn header_mismatch_rpc_error(id: Option<Value>, detail: &str) -> McpResponse {
    McpResponse {
        jsonrpc: "2.0".into(),
        id: id.unwrap_or(Value::Null),
        result: None,
        error: Some(McpRpcError {
            code: JSONRPC_ERR_HEADER_MISMATCH,
            message: format!("HeaderMismatch: {}", sanitize_untrusted_text(detail)),
            data: Some(serde_json::json!({ "kind": "HeaderMismatch" })),
        }),
    }
}

/// Formats mediated denials or step-ups across MCP methods:
/// - `tools/call` emits `isError: true` with `_meta["grdr/decision"]` (or `-32042` on URL elicitation),
/// - all other MCP methods return standard JSON-RPC error envelopes (`-32042` / `-32001`).
#[must_use]
pub fn format_mediated_method_response(
    id: Option<Value>,
    method: &McpMethod,
    revision: McpProtocolRevision,
    receipt: &DecisionReceipt,
    manifest_pinned: bool,
    degraded: bool,
) -> McpResponse {
    if *method == McpMethod::ToolsCall {
        return format_mediated_tool_response(id, revision, receipt, manifest_pinned, degraded);
    }
    let req_id = id.unwrap_or(Value::Null);
    let reason = sanitize_untrusted_text(&receipt.reason);
    let next_step = sanitize_untrusted_text(&receipt.next_step);
    let decision_meta = serde_json::json!({
        "verdict": verdict_str(receipt.verdict),
        "receipt_id": receipt.receipt_id,
        "rule_id": receipt.rule_id,
        "reason": reason,
        "next_step": next_step,
        "manifest_pinned": manifest_pinned,
        "degraded": degraded,
        "input_required": receipt.verdict == Verdict::StepUp,
    });
    let code = if receipt.verdict == Verdict::StepUp && revision.supports_url_elicitation_32042() {
        JSONRPC_ERR_ELICITATION_REQUIRED
    } else {
        JSONRPC_ERR_POLICY_DENIED
    };
    McpResponse {
        jsonrpc: "2.0".into(),
        id: req_id,
        result: None,
        error: Some(McpRpcError {
            code,
            message: format!("Guardrails {}: {reason}", verdict_str(receipt.verdict)),
            data: Some(decision_meta),
        }),
    }
}

/// Formats `tools/call` policy denial or step-up following MCP + design/17 §7.3:
/// - `Verdict::StepUp` on revisions >= 2025-11-25 emits JSON-RPC `-32042` (`input_required`),
/// - `Verdict::Deny` / `Defer` / `StepUp` (tool result form) returns `isError: true` with `_meta["grdr/decision"]`.
#[must_use]
pub fn format_mediated_tool_response(
    id: Option<Value>,
    revision: McpProtocolRevision,
    receipt: &DecisionReceipt,
    manifest_pinned: bool,
    degraded: bool,
) -> McpResponse {
    let req_id = id.unwrap_or(Value::Null);
    let reason = sanitize_untrusted_text(&receipt.reason);
    let next_step = sanitize_untrusted_text(&receipt.next_step);
    let decision_meta = serde_json::json!({
        "verdict": verdict_str(receipt.verdict),
        "receipt_id": receipt.receipt_id,
        "rule_id": receipt.rule_id,
        "reason": reason,
        "next_step": next_step,
        "manifest_pinned": manifest_pinned,
        "degraded": degraded,
        "input_required": receipt.verdict == Verdict::StepUp,
    });

    if receipt.verdict == Verdict::StepUp && revision.supports_url_elicitation_32042() {
        return McpResponse {
            jsonrpc: "2.0".into(),
            id: req_id,
            result: None,
            error: Some(McpRpcError {
                code: JSONRPC_ERR_ELICITATION_REQUIRED,
                message: format!("input_required: {reason}"),
                data: Some(serde_json::json!({
                    "kind": "input_required",
                    "elicitation_mode": "url",
                    "grdr_decision": decision_meta,
                })),
            }),
        };
    }

    McpResponse {
        jsonrpc: "2.0".into(),
        id: req_id,
        result: Some(serde_json::json!({
            "content": [{
                "type": "text",
                "text": format!("[Guardrails {}] {reason} ({next_step})", verdict_str(receipt.verdict))
            }],
            "isError": true,
            "_meta": {
                "grdr/decision": decision_meta
            }
        })),
        error: None,
    }
}

const fn verdict_str(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Allow => "allow",
        Verdict::Modify => "modify",
        Verdict::StepUp => "step_up",
        Verdict::Defer => "defer",
        Verdict::Deny => "deny",
    }
}

#[must_use]
pub fn has_loopback_host_header(headers: &HeaderMap, expected_port: Option<u16>) -> bool {
    if headers.get_all("host").iter().count() != 1 {
        return false;
    }
    let Some(raw) = headers.get("host").and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let lower = raw.trim().to_ascii_lowercase();
    let (host_part, port_part) = if let Some(rest) = lower.strip_prefix('[') {
        let Some((ip6, tail)) = rest.split_once(']') else {
            return false;
        };
        if tail.is_empty() {
            (ip6, None)
        } else if let Some(p) = tail.strip_prefix(':') {
            (ip6, Some(p))
        } else {
            return false;
        }
    } else if let Some((h, p)) = lower.rsplit_once(':') {
        (h, Some(p))
    } else {
        (lower.as_str(), None)
    };
    if host_part != "127.0.0.1" && host_part != "localhost" && host_part != "::1" {
        return false;
    }
    let parsed_port = match port_part {
        Some(raw_p) => match raw_p.parse::<u16>() {
            Ok(p) if p > 0 => Some(p),
            _ => return false,
        },
        None => None,
    };
    match expected_port {
        Some(0) => false,
        Some(expected) => match parsed_port {
            Some(p) => p == expected,
            None => expected == 80 || expected == 443,
        },
        None => true,
    }
}

pub fn parse_http_mcp_request(raw: &str) -> Result<McpRequest, McpBrokerError> {
    if raw.len() > MAX_HTTP_MCP_BODY_BYTES {
        return Err(McpBrokerError::Transport(format!(
            "HTTP MCP payload exceeds {MAX_HTTP_MCP_BODY_BYTES} byte limit"
        )));
    }
    grdr_mcp_proto::parse_mcp_request(raw).map_err(|e| McpBrokerError::Transport(e.to_string()))
}
