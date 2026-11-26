// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Streamable HTTP and stdio line-broker transports for `grdr-mcp`.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::post;
use serde_json::Value;
use tokio::io::{AsyncBufRead, AsyncWrite};
use tokio::sync::Mutex;
use uuid::Uuid;

use grdr_broker::BrokerOutcome;
use grdr_mcp_proto::{
    McpAttemptContext, McpMethod, McpRequest, McpResponse, ToolDescriptor,
    is_progressive_read_tool, parse_mcp_request, parse_strict_mcp_json, progressive_read_tools,
};
use grdr_model::{CompiledFloorTable, TrustedKeyInfo, Verdict};
use grdr_os_clock::{Clock, SystemClock};

use crate::McpBrokerError;
use crate::decision::{AsyncDecisionSource, mediate_mcp_request, synthetic_floor_receipt};
use crate::http_upstream::{
    HttpUpstreamConfig, handle_http_mcp_delete, handle_http_mcp_get, handle_http_mcp_post,
};
use crate::oauth::{OAuthIssuerPinRegistry, TokenDigestRegistry};
use crate::pinning::PinRegistry;
use crate::revisions::{
    MAX_HTTP_MCP_BODY_BYTES, McpProtocolRevision, McpSessionStore, format_mediated_method_response,
};
use crate::stdio_duplex::run_duplex_mediation;

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
    pub upstream: Option<HttpUpstreamConfig>,
    pub tokens: TokenDigestRegistry,
    pub issuer_pins: OAuthIssuerPinRegistry,
    pub include_progressive_tools: bool,
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
            upstream: None,
            tokens: TokenDigestRegistry::new(),
            issuer_pins: OAuthIssuerPinRegistry::new(),
            include_progressive_tools: false,
        }
    }

    #[must_use]
    pub fn with_upstream(mut self, upstream: HttpUpstreamConfig) -> Self {
        self.upstream = Some(upstream);
        self
    }

    #[must_use]
    pub fn with_progressive_tools(mut self, enabled: bool) -> Self {
        self.include_progressive_tools = enabled;
        self
    }

    pub fn record_tools_list(&mut self, tools: &[ToolDescriptor]) -> Result<Value, McpBrokerError> {
        let mut combined = tools.to_vec();
        if self.include_progressive_tools {
            for ptool in progressive_read_tools() {
                if !combined.iter().any(|t| t.name == ptool.name) {
                    combined.push(ptool);
                }
            }
        }
        let inspected = self.pins.inspect_tools_list(&self.server_name, &combined)?;
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
        self.handle_parsed_request(&req, revision).await
    }

    pub async fn handle_parsed_request(
        &mut self,
        req: &McpRequest,
        revision: McpProtocolRevision,
    ) -> Result<Option<McpResponse>, McpBrokerError> {
        let now = SystemClock::new()
            .now_wall()
            .map_err(|e| McpBrokerError::FailClosed(format!("wall clock unavailable: {e}")))?;
        let ctx = McpAttemptContext {
            attempt_id: format!("att_{}", Uuid::now_v7().simple()),
            session_id: self.session_id.clone(),
            device_id: "dev-local".into(),
            device_name: "local-host".into(),
            agent_name: self.agent_name.clone(),
            server_name: self.server_name.clone(),
            timestamp: now,
        };
        if self.include_progressive_tools
            && req.method == McpMethod::ToolsCall
            && req
                .tool_name
                .as_deref()
                .is_some_and(is_progressive_read_tool)
        {
            self.ensure_progressive_descriptors();
        }
        let desc = req
            .tool_name
            .as_deref()
            .and_then(|name| self.descriptors.get(name));
        let floor_ref = self
            .floor
            .as_ref()
            .map(|(table, keys)| (table, keys.as_slice()));

        match mediate_mcp_request(&self.source, &self.pins, req, desc, &ctx, floor_ref).await {
            Ok(res) => {
                self.degraded = res.degraded;
                match res.outcome {
                    BrokerOutcome::Forward => Ok(None),
                    BrokerOutcome::Ask { receipt, .. } | BrokerOutcome::Block { receipt, .. } => {
                        Ok(Some(format_mediated_method_response(
                            req.id.clone(),
                            &req.method,
                            revision,
                            &receipt,
                            res.manifest_pinned,
                            res.degraded,
                        )))
                    }
                }
            }
            Err(err) => {
                let attempt = grdr_mcp_proto::mcp_call_to_attempt(req, &ctx)
                    .map_err(|e| McpBrokerError::Transport(e.to_string()))?;
                let receipt = synthetic_floor_receipt(
                    &attempt,
                    Verdict::Deny,
                    Some("mcp.broker-error"),
                    &err.to_string(),
                );
                Ok(Some(format_mediated_method_response(
                    req.id.clone(),
                    &req.method,
                    revision,
                    &receipt,
                    false,
                    self.degraded,
                )))
            }
        }
    }

    fn ensure_progressive_descriptors(&mut self) {
        for tool in progressive_read_tools() {
            self.descriptors.entry(tool.name.clone()).or_insert(tool);
        }
    }
}

pub async fn mediate_stdio_lines<S, R1, W1, R2, W2>(
    service: &mut McpBrokerService<S>,
    client_in: R1,
    client_out: W1,
    child_in: W2,
    child_out: R2,
) -> Result<(), McpBrokerError>
where
    S: AsyncDecisionSource,
    R1: AsyncBufRead + Unpin,
    W1: AsyncWrite + Unpin,
    R2: AsyncBufRead + Unpin,
    W2: AsyncWrite + Unpin,
{
    run_duplex_mediation(service, client_in, client_out, child_in, child_out).await
}

pub(crate) fn filter_child_tools_list_response<S: AsyncDecisionSource>(
    service: &mut McpBrokerService<S>,
    raw_resp: &str,
) -> Result<String, McpBrokerError> {
    let mut val = parse_strict_mcp_json(raw_resp)
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
        .route(
            "/mcp",
            post(handle_http_mcp_post::<S>)
                .get(handle_http_mcp_get::<S>)
                .delete(handle_http_mcp_delete::<S>),
        )
        .layer(DefaultBodyLimit::max(MAX_HTTP_MCP_BODY_BYTES))
        .with_state(service)
}
