// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! `McpRelay` Streamable HTTP routes (`/mcp-relay/{token}/{route_id}`) enforcing
//! SR-39 instance token verification, MCP 2025/2026 header checks, descriptor pinning,
//! tools/list filtering, bearer token reuse detection, RFC 9728 401 -> -32042, and SSE streaming.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::header::{HeaderName, HeaderValue};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use uuid::Uuid;

use grdr_llm_proto::compression::{decompress_bounded, parse_content_encoding_header};
use grdr_mcp_proto::{
    McpAttemptContext, McpMethod, McpRequest, mcp_call_to_attempt, parse_mcp_request,
};
use grdr_model::{ActionAttempt, ActionClass, ControlPoint, ProvenanceSource, Verdict};
use grdr_os_clock::{Clock, SystemClock};
use grdr_strings::sanitize_untrusted_text;

use crate::egress::resolve_and_vet_target;
use crate::mcp_relay_sse::{handle_relay_401, stream_filtered_relay_sse};
use crate::mcp_relay_state::validate_mcp_relay_headers;
use crate::router::{MAX_PROXY_BODY_BYTES, MAX_UPSTREAM_RESPONSE_BYTES, ProxyGatewayState};
use crate::router_http::{
    bad_gateway_response, build_upstream_url, copy_safe_outbound_headers, denial_403,
};
use crate::sr39::{RouteUpstream, SessionRegistration};
use crate::streaming::{MAX_DECOMPRESSION_RATIO, inspect_and_decompress_request_body};
use crate::{ProxyDecisionClient, ProxyError};

struct McpUpstreamRequest {
    reg: SessionRegistration,
    route: RouteUpstream,
    method: Method,
    target_url: String,
    inbound_headers: HeaderMap,
    body: Vec<u8>,
    parsed_req: Option<McpRequest>,
}

pub async fn handle_mcp_relay_root<C: ProxyDecisionClient + 'static>(
    State(state): State<Arc<ProxyGatewayState<C>>>,
    Path((token, route_id)): Path<(String, String)>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    handle_mcp_relay(state, token, route_id, String::new(), method, headers, body).await
}

pub async fn handle_mcp_relay_tail<C: ProxyDecisionClient + 'static>(
    State(state): State<Arc<ProxyGatewayState<C>>>,
    Path((token, route_id, tail)): Path<(String, String, String)>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    handle_mcp_relay(state, token, route_id, tail, method, headers, body).await
}

async fn handle_mcp_relay<C: ProxyDecisionClient + 'static>(
    state: Arc<ProxyGatewayState<C>>,
    token: String,
    route_id: String,
    tail: String,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !matches!(method, Method::POST | Method::GET | Method::DELETE) {
        return (
            StatusCode::METHOD_NOT_ALLOWED,
            axum::Json(serde_json::json!({
                "error": "McpRelay supports POST, GET (SSE), and DELETE only",
                "code": "GRDR-PROXY-0001",
            })),
        )
            .into_response();
    }
    if state.is_globally_killed() {
        return denial_403(&ProxyError::SessionEgressCut("global-kill-switch".into()));
    }
    let inspected_body = match inspect_and_decompress_request_body(&headers, &body) {
        Ok(b) => b,
        Err(err) => return denial_403(&err),
    };
    if inspected_body.len() > MAX_PROXY_BODY_BYTES {
        return denial_403(&ProxyError::Sr39Rejected(
            "McpRelay payload exceeds bounded limit".into(),
        ));
    }

    let (reg, route) = match state.registry.lock().await.resolve_sr39_route(
        &headers,
        state.listener_port,
        &token,
        &route_id,
        !inspected_body.is_empty(),
    ) {
        Ok(found) => found,
        Err(err) => return denial_403(&err),
    };

    if let Some(bearer) = extract_bearer(&headers)
        && let Err(err) = state
            .mcp_relay
            .lock()
            .await
            .check_and_record_bearer(&route_id, bearer)
    {
        return denial_403(&err);
    }

    let parsed_req = match parse_mcp_post_req(&method, &inspected_body) {
        Ok(r) => r,
        Err(err) => return denial_403(&err),
    };
    if let Err(err) = validate_mcp_relay_headers(&headers, &reg.session_id, parsed_req.as_ref()) {
        return denial_403(&err);
    }
    if let Some(ref req) = parsed_req
        && req.method == McpMethod::ToolsCall
        && let Some(ref tool) = req.tool_name
        && let Err(err) = state
            .mcp_relay
            .lock()
            .await
            .verify_tool_call(&route_id, tool)
    {
        return denial_403(&err);
    }

    let target_url = match build_upstream_url(&route.base_url, &tail) {
        Ok(url) => url,
        Err(err) => return denial_403(&err),
    };
    let attempt = match build_mcp_relay_attempt(
        &reg.session_id,
        &reg.agent_name,
        &route_id,
        &method,
        &target_url,
        parsed_req.as_ref(),
    ) {
        Ok(a) => a,
        Err(err) => return denial_403(&err),
    };

    let receipt = match state.decision_client.decide(&attempt).await {
        Ok(r) => r,
        Err(err) => return denial_403(&err),
    };
    if receipt.verdict != Verdict::Allow {
        return (
            StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({
                "error": sanitize_untrusted_text(&receipt.reason),
                "code": "GRDR-PROXY-0003",
                "receipt_id": receipt.receipt_id,
                "verdict": format!("{:?}", receipt.verdict),
            })),
        )
            .into_response();
    }

    execute_mcp_relay_upstream(
        state,
        McpUpstreamRequest {
            reg,
            route,
            method,
            target_url,
            inbound_headers: headers,
            body: inspected_body,
            parsed_req,
        },
    )
    .await
}

async fn execute_mcp_relay_upstream<C: ProxyDecisionClient + 'static>(
    state: Arc<ProxyGatewayState<C>>,
    req: McpUpstreamRequest,
) -> Response {
    let vetted =
        match resolve_and_vet_target(&req.route.host, req.route.port, &state.egress_config).await {
            Ok(v) => v,
            Err(err) => return denial_403(&err),
        };
    let Some(&pinned_addr) = vetted.pinned_addrs.first() else {
        return denial_403(&ProxyError::SsrfDenied(
            "SSRF guard resolved zero addresses".into(),
        ));
    };
    let mut outbound = copy_safe_outbound_headers(&req.inbound_headers);
    if let Ok(sv) = HeaderValue::from_str(&sanitize_untrusted_text(&req.reg.session_id)) {
        outbound.insert(HeaderName::from_static("grdr-session"), sv);
    }
    outbound.insert(
        HeaderName::from_static("accept-encoding"),
        HeaderValue::from_static("identity"),
    );
    if let Err(err) = req.route.tenant_headers.apply_overwrite(&mut outbound) {
        return denial_403(&err);
    }
    if let Some(cred_id) = req.route.credential_id.as_deref() {
        let now = match SystemClock::new().now_wall() {
            Ok(t) => t,
            Err(e) => return denial_403(&ProxyError::Transport(format!("clock unavailable: {e}"))),
        };
        let mut creds = state.credentials.lock().await;
        if let Err(err) = creds.inject_for_route(
            &req.reg,
            cred_id,
            &vetted.host,
            &req.inbound_headers,
            &mut outbound,
            now,
        ) {
            return denial_403(&err);
        }
    }
    if let Some(signer) = state.web_bot_signer.lock().await.as_ref()
        && let Err(err) = signer.sign_outbound_request(
            req.method.as_str(),
            &req.target_url,
            &req.body,
            &mut outbound,
        )
    {
        return denial_403(&err);
    }

    let (client, expected_peer_addr) = match state
        .build_pinned_route_client(&vetted.host, pinned_addr)
        .await
    {
        Ok(c) => c,
        Err(err) => return denial_403(&err),
    };
    let upstream_resp = match client
        .request(req.method, &req.target_url)
        .headers(outbound)
        .body(req.body)
        .send()
        .await
    {
        Ok(r) => r,
        Err(err) => return bad_gateway_response(&ProxyError::Transport(err.to_string())),
    };
    if upstream_resp.remote_addr() != Some(expected_peer_addr) {
        return denial_403(&ProxyError::SsrfDenied(
            "McpRelay upstream remote_addr mismatched pinned socket".into(),
        ));
    }

    if upstream_resp.status() == StatusCode::UNAUTHORIZED {
        return handle_relay_401(
            &state,
            &req.route.route_id,
            &upstream_resp,
            req.parsed_req.as_ref(),
        )
        .await;
    }

    let encodings = match upstream_resp.headers().get("content-encoding") {
        Some(hdr) => {
            let Ok(enc_str) = hdr.to_str() else {
                return denial_403(&ProxyError::Sr39Rejected(
                    "non-ASCII McpRelay upstream Content-Encoding".into(),
                ));
            };
            match parse_content_encoding_header(enc_str) {
                Ok(e) => e,
                Err(err) => {
                    return denial_403(&ProxyError::Sr39Rejected(format!(
                        "McpRelay response Content-Encoding rejected: {err}"
                    )));
                }
            }
        }
        None => Vec::new(),
    };

    let ctype = upstream_resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json")
        .to_owned();
    let ctype_lower = ctype.to_ascii_lowercase();
    if ctype_lower.contains("text/event-stream") {
        if !encodings.is_empty() {
            return denial_403(&ProxyError::Sr39Rejected(
                "compressed McpRelay SSE response is forbidden".into(),
            ));
        }
        return stream_filtered_relay_sse(
            state,
            req.reg.session_id,
            req.reg.agent_name,
            req.route.route_id,
            upstream_resp,
        );
    }
    let status = upstream_resp.status();
    let resp_bytes = match read_bounded_bytes(upstream_resp, MAX_UPSTREAM_RESPONSE_BYTES).await {
        Ok(b) => b,
        Err(err) => return bad_gateway_response(&err),
    };
    let decoded = if encodings.is_empty() {
        resp_bytes
    } else {
        match decompress_bounded(
            &resp_bytes,
            &encodings,
            MAX_UPSTREAM_RESPONSE_BYTES,
            MAX_DECOMPRESSION_RATIO,
        ) {
            Ok(b) => b,
            Err(err) => {
                return denial_403(&ProxyError::Sr39Rejected(format!(
                    "McpRelay compressed upstream response rejected: {err}"
                )));
            }
        }
    };

    let trimmed_start = decoded.trim_ascii_start();
    let expects_json = ctype_lower.contains("json")
        || trimmed_start.starts_with(b"{")
        || trimmed_start.starts_with(b"[");
    if expects_json && !decoded.is_empty() {
        let Ok(text) = std::str::from_utf8(&decoded) else {
            return bad_gateway_response(&ProxyError::Transport(
                "McpRelay JSON response must be valid UTF-8".into(),
            ));
        };
        let filtered = state
            .mcp_relay
            .lock()
            .await
            .filter_tools_list_json(&req.route.route_id, text);
        match filtered {
            Ok(out_str) => {
                let mut resp = (status, out_str.into_bytes()).into_response();
                if let Ok(hv) = HeaderValue::from_str(&ctype) {
                    resp.headers_mut().insert("content-type", hv);
                }
                return resp;
            }
            Err(err) => return denial_403(&err),
        }
    }
    let mut resp = (status, decoded).into_response();
    if let Ok(hv) = HeaderValue::from_str(&ctype) {
        resp.headers_mut().insert("content-type", hv);
    }
    resp
}

fn parse_mcp_post_req(method: &Method, body: &[u8]) -> Result<Option<McpRequest>, ProxyError> {
    if method != Method::POST || body.is_empty() {
        return Ok(None);
    }
    let body_str = std::str::from_utf8(body).map_err(|_| {
        ProxyError::Sr39Rejected("McpRelay POST payload must be UTF-8 JSON-RPC".into())
    })?;
    parse_mcp_request(body_str)
        .map(Some)
        .map_err(|e| ProxyError::Sr39Rejected(format!("invalid MCP JSON-RPC: {e}")))
}

fn build_mcp_relay_attempt(
    session_id: &str,
    agent_name: &str,
    route_id: &str,
    method: &Method,
    target_url: &str,
    parsed_req: Option<&McpRequest>,
) -> Result<ActionAttempt, ProxyError> {
    let now = SystemClock::new()
        .now_wall()
        .map_err(|e| ProxyError::Transport(format!("wall clock unavailable: {e}")))?;
    if let Some(parsed) = parsed_req {
        let ctx = McpAttemptContext {
            attempt_id: format!("att_{}", Uuid::now_v7().simple()),
            session_id: session_id.to_owned(),
            device_id: "dev-local".into(),
            device_name: "local-host".into(),
            agent_name: agent_name.to_owned(),
            server_name: route_id.to_owned(),
            timestamp: now,
        };
        let mut attempt = mcp_call_to_attempt(parsed, &ctx)
            .map_err(|e| ProxyError::Sr39Rejected(format!("MCP attempt conversion failed: {e}")))?;
        attempt.provenance = ProvenanceSource::Mediated;
        attempt.summary = sanitize_untrusted_text(&attempt.summary);
        return Ok(attempt);
    }
    let action_class = if method == Method::DELETE {
        ActionClass::McpConnect
    } else {
        ActionClass::NetRequest
    };
    Ok(ActionAttempt {
        id: format!("att_{}", Uuid::now_v7().simple()),
        session_id: session_id.to_owned(),
        device_id: "dev-local".into(),
        device_name: "local-host".into(),
        agent_name: agent_name.to_owned(),
        action_class,
        control_point: ControlPoint::McpBroker,
        target: target_url.to_owned(),
        summary: sanitize_untrusted_text(&format!("mcp-relay {method} {route_id}")),
        timestamp: now,
        provenance: ProvenanceSource::Mediated,
        ..Default::default()
    })
}

async fn read_bounded_bytes(
    mut resp: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, ProxyError> {
    let mut out = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| ProxyError::Transport(e.to_string()))?
    {
        if out.len().saturating_add(chunk.len()) > max_bytes {
            return Err(ProxyError::Transport(
                "McpRelay upstream response exceeds bounded limit".into(),
            ));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

fn extract_bearer(headers: &HeaderMap) -> Option<&str> {
    let raw = headers.get("authorization")?.to_str().ok()?.trim();
    raw.strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))
}
