// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Streamable HTTP and stdio line-broker transports for `grdr-mcp`.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use jiff::Timestamp;
use serde_json::Value;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;
use uuid::Uuid;

use grdr_broker::BrokerOutcome;
use grdr_mcp_proto::{
    McpAttemptContext, McpMethod, McpRequest, McpResponse, ToolDescriptor, parse_mcp_request,
};
use grdr_model::{CompiledFloorTable, TrustedKeyInfo, Verdict};

use crate::McpBrokerError;
use crate::decision::{AsyncDecisionSource, mediate_mcp_request, synthetic_floor_receipt};
use crate::pinning::PinRegistry;
use crate::revisions::{
    MCP_HEADER_PROTOCOL_VERSION, MCP_HEADER_SESSION_ID, McpProtocolRevision, McpSessionStore,
    format_mediated_tool_response, has_loopback_host_header, header_mismatch_rpc_error,
    verify_revision_consistency_headers,
};

pub const MAX_STDIO_LINE_BYTES: usize = 1_048_576;

pub struct McpBrokerService<S> {
    pub source: S,
    pub pins: PinRegistry,
    pub sessions: McpSessionStore,
    pub server_name: String,
    pub agent_name: String,
    pub session_id: String,
    pub default_revision: McpProtocolRevision,
    pub descriptors: BTreeMap<String, ToolDescriptor>,
    pub floor: Option<(CompiledFloorTable, Vec<TrustedKeyInfo>)>,
    pub degraded: bool,
    pub expected_http_port: Option<u16>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct RawWireToolDescriptor {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(alias = "inputSchema", default)]
    input_schema: Value,
}

impl<S: AsyncDecisionSource> McpBrokerService<S> {
    pub fn new(
        source: S,
        server_name: impl Into<String>,
        agent_name: impl Into<String>,
        session_id: impl Into<String>,
    ) -> Self {
        Self {
            source,
            pins: PinRegistry::new(),
            sessions: McpSessionStore::new(),
            server_name: server_name.into(),
            agent_name: agent_name.into(),
            session_id: session_id.into(),
            default_revision: McpProtocolRevision::Rev2025_11_25,
            descriptors: BTreeMap::new(),
            floor: None,
            degraded: false,
            expected_http_port: None,
        }
    }

    pub fn record_tools_list(&mut self, tools: &[ToolDescriptor]) -> Result<Value, McpBrokerError> {
        let inspected = self.pins.inspect_tools_list(&self.server_name, tools)?;
        for tool in &inspected.allowed_tools {
            self.descriptors.insert(tool.name.clone(), tool.clone());
        }
        Ok(serde_json::json!({
            "tools": inspected.allowed_tools,
            "_meta": {
                "grdr/manifest_hash": inspected.manifest_hash,
                "grdr/manifest_pinned": inspected.manifest_pinned,
                "grdr/blocked_count": inspected.blocked_tools.len()
            }
        }))
    }

    pub async fn handle_jsonrpc_request(
        &mut self,
        raw_line: &str,
        revision: McpProtocolRevision,
    ) -> Result<Option<McpResponse>, McpBrokerError> {
        let req =
            parse_mcp_request(raw_line).map_err(|e| McpBrokerError::Transport(e.to_string()))?;
        let ctx = McpAttemptContext {
            attempt_id: format!("att_{}", Uuid::now_v7().simple()),
            session_id: self.session_id.clone(),
            device_id: "dev-local".into(),
            device_name: "local-host".into(),
            agent_name: self.agent_name.clone(),
            server_name: self.server_name.clone(),
            timestamp: Timestamp::now(),
        };
        let desc = req
            .tool_name
            .as_deref()
            .and_then(|name| self.descriptors.get(name));
        let floor_ref = self
            .floor
            .as_ref()
            .map(|(table, keys)| (table, keys.as_slice()));

        match mediate_mcp_request(&self.source, &self.pins, &req, desc, &ctx, floor_ref).await {
            Ok(res) => {
                self.degraded = res.degraded;
                match res.outcome {
                    BrokerOutcome::Forward => Ok(None),
                    BrokerOutcome::Ask { receipt, .. } | BrokerOutcome::Block { receipt, .. } => {
                        Ok(Some(format_mediated_tool_response(
                            req.id,
                            revision,
                            &receipt,
                            res.manifest_pinned,
                            res.degraded,
                        )))
                    }
                }
            }
            Err(err) => {
                let attempt = grdr_mcp_proto::mcp_call_to_attempt(&req, &ctx)
                    .map_err(|e| McpBrokerError::Transport(e.to_string()))?;
                let receipt = synthetic_floor_receipt(
                    &attempt,
                    Verdict::Deny,
                    Some("mcp.security-gate"),
                    &err.to_string(),
                );
                Ok(Some(format_mediated_tool_response(
                    req.id,
                    revision,
                    &receipt,
                    self.pins.is_manifest_pinned(&self.server_name),
                    self.degraded,
                )))
            }
        }
    }
}

pub async fn mediate_stdio_lines<S, R1, W1, R2, W2>(
    service: &mut McpBrokerService<S>,
    mut client_in: R1,
    mut client_out: W1,
    mut child_in: W2,
    mut child_out: R2,
) -> Result<(), McpBrokerError>
where
    S: AsyncDecisionSource,
    R1: AsyncBufRead + Unpin,
    W1: AsyncWrite + Unpin,
    R2: AsyncBufRead + Unpin,
    W2: AsyncWrite + Unpin,
{
    let mut line = String::new();
    loop {
        if !read_bounded_line(&mut client_in, &mut line, MAX_STDIO_LINE_BYTES).await? {
            return Ok(());
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Some(denial_or_step_up) = service
            .handle_jsonrpc_request(trimmed, service.default_revision)
            .await?
        {
            let encoded = serde_json::to_string(&denial_or_step_up)
                .map_err(|e| McpBrokerError::Transport(e.to_string()))?;
            client_out
                .write_all(encoded.as_bytes())
                .await
                .map_err(|e| McpBrokerError::Transport(e.to_string()))?;
            client_out
                .write_all(b"\n")
                .await
                .map_err(|e| McpBrokerError::Transport(e.to_string()))?;
            client_out
                .flush()
                .await
                .map_err(|e| McpBrokerError::Transport(e.to_string()))?;
            continue;
        }

        child_in
            .write_all(trimmed.as_bytes())
            .await
            .map_err(|e| McpBrokerError::Transport(e.to_string()))?;
        child_in
            .write_all(b"\n")
            .await
            .map_err(|e| McpBrokerError::Transport(e.to_string()))?;
        child_in
            .flush()
            .await
            .map_err(|e| McpBrokerError::Transport(e.to_string()))?;

        let mut resp_line = String::new();
        if !read_bounded_line(&mut child_out, &mut resp_line, MAX_STDIO_LINE_BYTES).await? {
            return Err(McpBrokerError::Transport(
                "wrapped MCP child exited before responding".into(),
            ));
        }

        let filtered = filter_child_tools_list_response(service, resp_line.trim())?;
        client_out
            .write_all(filtered.as_bytes())
            .await
            .map_err(|e| McpBrokerError::Transport(e.to_string()))?;
        client_out
            .write_all(b"\n")
            .await
            .map_err(|e| McpBrokerError::Transport(e.to_string()))?;
        client_out
            .flush()
            .await
            .map_err(|e| McpBrokerError::Transport(e.to_string()))?;
    }
}

async fn read_bounded_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    out: &mut String,
    max_bytes: usize,
) -> Result<bool, McpBrokerError> {
    out.clear();
    let limit = u64::try_from(max_bytes).unwrap_or(1_048_576);
    let read_bytes = reader
        .take(limit.saturating_add(1))
        .read_line(out)
        .await
        .map_err(|e| McpBrokerError::Transport(e.to_string()))?;
    if read_bytes == 0 {
        return Ok(false);
    }
    if read_bytes > max_bytes {
        return Err(McpBrokerError::Transport(format!(
            "stdio JSON-RPC line exceeds {max_bytes} byte limit"
        )));
    }
    Ok(true)
}

fn filter_child_tools_list_response<S: AsyncDecisionSource>(
    service: &mut McpBrokerService<S>,
    raw_resp: &str,
) -> Result<String, McpBrokerError> {
    let mut val: Value = serde_json::from_str(raw_resp)
        .map_err(|e| McpBrokerError::Transport(format!("invalid JSON from MCP child: {e}")))?;
    match &mut val {
        Value::Object(_) => {
            if !filter_single_rpc_object(service, &mut val)? {
                return Ok(raw_resp.to_owned());
            }
        }
        Value::Array(items) => {
            let mut modified = false;
            for item in items {
                if !item.is_object() {
                    return Err(McpBrokerError::Transport(
                        "JSON-RPC batch element must be an object".into(),
                    ));
                }
                if filter_single_rpc_object(service, item)? {
                    modified = true;
                }
            }
            if !modified {
                return Ok(raw_resp.to_owned());
            }
        }
        _ => {
            return Err(McpBrokerError::Transport(
                "MCP child JSON-RPC response must be object or batch array".into(),
            ));
        }
    }
    serde_json::to_string(&val).map_err(|e| McpBrokerError::Transport(e.to_string()))
}

fn filter_single_rpc_object<S: AsyncDecisionSource>(
    service: &mut McpBrokerService<S>,
    val: &mut Value,
) -> Result<bool, McpBrokerError> {
    let Some(tools_val) = val.get("result").and_then(|r| r.get("tools")).cloned() else {
        return Ok(false);
    };
    let raw_tools: Vec<RawWireToolDescriptor> = serde_json::from_value(tools_val).map_err(|e| {
        McpBrokerError::Transport(format!("malformed tools/list descriptor payload: {e}"))
    })?;
    let tools: Vec<ToolDescriptor> = raw_tools
        .into_iter()
        .map(|raw| ToolDescriptor {
            name: raw.name,
            description: raw.description,
            input_schema: raw.input_schema,
        })
        .collect();

    let filtered_result = service.record_tools_list(&tools)?;
    if let Some(obj) = val.as_object_mut() {
        obj.insert("result".into(), filtered_result);
    }
    Ok(true)
}

pub fn build_http_router<S: AsyncDecisionSource + 'static>(
    service: Arc<Mutex<McpBrokerService<S>>>,
) -> Router {
    Router::new()
        .route("/mcp", post(handle_http_mcp_post::<S>))
        .with_state(service)
}

async fn handle_http_mcp_post<S: AsyncDecisionSource + 'static>(
    State(service): State<Arc<Mutex<McpBrokerService<S>>>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    if headers.contains_key("origin") {
        return (
            StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({
                "error": "GRDR-MCP-0005: browser Origin header rejected on local MCP listener"
            })),
        )
            .into_response();
    }
    let expected_port = service.lock().await.expected_http_port;
    if !has_loopback_host_header(&headers, expected_port) {
        return (
            StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({
                "error": "GRDR-MCP-0005: Host header missing or non-loopback on local MCP listener"
            })),
        )
            .into_response();
    }

    let req: McpRequest = match parse_mcp_request(&body) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };

    let ver_hdr = headers
        .get(MCP_HEADER_PROTOCOL_VERSION)
        .and_then(|v| v.to_str().ok());
    let sid_hdr = headers
        .get(MCP_HEADER_SESSION_ID)
        .and_then(|v| v.to_str().ok());

    let mut guard = service.lock().await;

    if req.method == McpMethod::Initialize {
        let rev = match ver_hdr {
            Some(v) => match McpProtocolRevision::parse(v) {
                Ok(parsed) => parsed,
                Err(err) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        axum::Json(header_mismatch_rpc_error(req.id, &err.to_string())),
                    )
                        .into_response();
                }
            },
            None => guard.default_revision,
        };
        let session = match guard.sessions.issue_session(rev) {
            Ok(s) => s,
            Err(err) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    axum::Json(serde_json::json!({ "error": err.to_string() })),
                )
                    .into_response();
            }
        };
        return (
            StatusCode::OK,
            [(MCP_HEADER_SESSION_ID, session.session_id.as_str())],
            axum::Json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": req.id.unwrap_or(Value::Null),
                "result": {
                    "protocolVersion": rev.as_str(),
                    "capabilities": { "tools": { "listChanged": false } },
                    "serverInfo": { "name": guard.server_name, "version": "0.1.0" }
                }
            })),
        )
            .into_response();
    }

    let bound_rev = match guard.sessions.verify_headers(sid_hdr, ver_hdr) {
        Ok(state) => state.revision,
        Err(err @ McpBrokerError::HeaderMismatch(_)) => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(header_mismatch_rpc_error(req.id, &err.to_string())),
            )
                .into_response();
        }
        Err(err) => {
            return (
                StatusCode::FORBIDDEN,
                axum::Json(serde_json::json!({ "error": err.to_string() })),
            )
                .into_response();
        }
    };

    if let Err(err) = verify_revision_consistency_headers(bound_rev, &headers, &req) {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(header_mismatch_rpc_error(req.id, &err.to_string())),
        )
            .into_response();
    }

    match guard.handle_jsonrpc_request(&body, bound_rev).await {
        Ok(Some(blocked)) => (StatusCode::OK, axum::Json(blocked)).into_response(),
        Ok(None) => (
            StatusCode::OK,
            axum::Json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": req.id.unwrap_or(Value::Null),
                "result": { "mediated": "allow" }
            })),
        )
            .into_response(),
        Err(err) => (
            StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({ "error": err.to_string() })),
        )
            .into_response(),
    }
}
