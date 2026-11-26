// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, Bytes, to_bytes};
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::Value;
use tokio::sync::Mutex;

use grdr_mcp_proto::{McpMethod, McpRequest, build_oauth_step_up_response};

use crate::McpBrokerError;
use crate::decision::AsyncDecisionSource;
use crate::oauth::parse_www_authenticate_step_up;
use crate::revisions::{
    MAX_HTTP_MCP_BODY_BYTES, MCP_HEADER_PROTOCOL_VERSION, MCP_HEADER_SESSION_ID,
    McpProtocolRevision, has_loopback_host_header, header_mismatch_rpc_error,
    parse_http_mcp_request, verify_revision_consistency_headers,
};
use crate::sse_filter::{reject_non_identity_encoding, stream_upstream_sse};
use crate::ssrf::{SsrfPolicy, VettedUpstream, build_pinned_http_client, resolve_and_vet_upstream};
use crate::transport::{McpBrokerService, filter_child_tools_list_response};

#[derive(Debug, Clone)]
pub struct HttpUpstreamConfig {
    pub upstream_url: String,
    pub ssrf_policy: SsrfPolicy,
    pub request_timeout: Duration,
}

impl HttpUpstreamConfig {
    #[must_use]
    pub fn new(upstream_url: impl Into<String>, ssrf_policy: SsrfPolicy) -> Self {
        Self {
            upstream_url: upstream_url.into(),
            ssrf_policy,
            request_timeout: Duration::from_secs(30),
        }
    }
}

pub(crate) async fn handle_http_mcp_post<S: AsyncDecisionSource + 'static>(
    State(service): State<Arc<Mutex<McpBrokerService<S>>>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if let Some(err_resp) = check_local_origin_and_host(&service, &headers).await {
        return err_resp;
    }
    let raw_bytes = match to_bytes(body, MAX_HTTP_MCP_BODY_BYTES).await {
        Ok(b) if b.len() <= MAX_HTTP_MCP_BODY_BYTES => b,
        _ => {
            return error_json(
                StatusCode::PAYLOAD_TOO_LARGE,
                "GRDR-MCP-0005: HTTP MCP request exceeds bounded body limit",
            );
        }
    };
    let Ok(body_str) = std::str::from_utf8(&raw_bytes) else {
        return error_json(
            StatusCode::BAD_REQUEST,
            "GRDR-MCP-0001: request must be UTF-8",
        );
    };
    let req: McpRequest = match parse_http_mcp_request(body_str) {
        Ok(r) => r,
        Err(e) => return error_json(StatusCode::BAD_REQUEST, &e.to_string()),
    };

    let ver_hdr = header_str(&headers, MCP_HEADER_PROTOCOL_VERSION);
    let sid_hdr = header_str(&headers, MCP_HEADER_SESSION_ID);
    let bearer_tok = extract_bearer(&headers);

    let (bound_rev, local_session_id, upstream_cfg) = {
        let mut guard = service.lock().await;
        if let Some(tok) = bearer_tok {
            let srv = guard.server_name.clone();
            if let Err(err) = guard.tokens.check_and_record_bearer(&srv, tok) {
                let rpc = build_oauth_step_up_response(
                    req.id.unwrap_or(Value::Null),
                    "",
                    "mcp:token",
                    &err.to_string(),
                );
                return (StatusCode::FORBIDDEN, axum::Json(rpc)).into_response();
            }
        }
        if req.method == McpMethod::Initialize {
            return handle_initialize_http(&mut guard, ver_hdr, req.id);
        }
        let bound_rev = match guard
            .sessions
            .verify_headers(sid_hdr.as_deref(), ver_hdr.as_deref())
        {
            Ok(state) => state.revision,
            Err(err @ McpBrokerError::HeaderMismatch(_)) => {
                return (
                    StatusCode::BAD_REQUEST,
                    axum::Json(header_mismatch_rpc_error(req.id, &err.to_string())),
                )
                    .into_response();
            }
            Err(err) => return error_json(StatusCode::FORBIDDEN, &err.to_string()),
        };
        if let Err(err) = verify_revision_consistency_headers(bound_rev, &headers, &req) {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(header_mismatch_rpc_error(req.id, &err.to_string())),
            )
                .into_response();
        }
        match guard.handle_parsed_request(&req, bound_rev).await {
            Ok(Some(blocked)) => return (StatusCode::OK, axum::Json(blocked)).into_response(),
            Ok(None) => {}
            Err(err) => return error_json(StatusCode::FORBIDDEN, &err.to_string()),
        }
        (bound_rev, sid_hdr, guard.upstream.clone())
    };

    let Some(cfg) = upstream_cfg else {
        return error_json(
            StatusCode::BAD_GATEWAY,
            "GRDR-MCP-0007: no vetted upstream MCP endpoint configured",
        );
    };
    forward_post_to_upstream(
        service,
        cfg,
        &headers,
        raw_bytes,
        &req,
        bound_rev,
        local_session_id,
    )
    .await
}

pub(crate) async fn handle_http_mcp_get<S: AsyncDecisionSource + 'static>(
    State(service): State<Arc<Mutex<McpBrokerService<S>>>>,
    headers: HeaderMap,
) -> Response {
    if let Some(err_resp) = check_local_origin_and_host(&service, &headers).await {
        return err_resp;
    }
    let sid_hdr = header_str(&headers, MCP_HEADER_SESSION_ID);
    let ver_hdr = header_str(&headers, MCP_HEADER_PROTOCOL_VERSION);
    let bearer_tok = extract_bearer(&headers);
    let cfg = {
        let mut guard = service.lock().await;
        if let Some(tok) = bearer_tok {
            let srv = guard.server_name.clone();
            if let Err(err) = guard.tokens.check_and_record_bearer(&srv, tok) {
                return error_json(StatusCode::FORBIDDEN, &err.to_string());
            }
        }
        if let Err(err) = guard
            .sessions
            .verify_headers(sid_hdr.as_deref(), ver_hdr.as_deref())
        {
            return error_json(StatusCode::FORBIDDEN, &err.to_string());
        }
        guard.upstream.clone()
    };
    let Some(cfg) = cfg else {
        return error_json(
            StatusCode::BAD_GATEWAY,
            "GRDR-MCP-0007: no vetted upstream MCP endpoint configured",
        );
    };
    let Ok(vetted) = resolve_and_vet_upstream(&cfg.upstream_url, cfg.ssrf_policy).await else {
        return error_json(
            StatusCode::FORBIDDEN,
            "GRDR-MCP-0008: upstream SSE target failed SSRF validation",
        );
    };
    let Ok(client) = build_pinned_http_client(&vetted, cfg.request_timeout) else {
        return error_json(
            StatusCode::BAD_GATEWAY,
            "GRDR-MCP-0007: HTTP client build failed",
        );
    };
    let mut outbound = collect_safe_mcp_headers(&headers);
    outbound.insert("accept", HeaderValue::from_static("text/event-stream"));
    match client
        .get(vetted.url.clone())
        .headers(outbound)
        .send()
        .await
    {
        Ok(resp) => {
            if let Err(err) = verify_pinned_peer(&resp, &vetted) {
                return error_json(StatusCode::FORBIDDEN, &err);
            }
            if let Err(err) = reject_non_identity_encoding(resp.headers()) {
                return error_json(StatusCode::FORBIDDEN, &err);
            }
            stream_upstream_sse(service, resp)
        }
        Err(err) => error_json(
            StatusCode::BAD_GATEWAY,
            &format!("GRDR-MCP-0007: upstream SSE connect failed: {err}"),
        ),
    }
}

pub(crate) async fn handle_http_mcp_delete<S: AsyncDecisionSource + 'static>(
    State(service): State<Arc<Mutex<McpBrokerService<S>>>>,
    headers: HeaderMap,
) -> Response {
    if let Some(err_resp) = check_local_origin_and_host(&service, &headers).await {
        return err_resp;
    }
    let sid_hdr = header_str(&headers, MCP_HEADER_SESSION_ID);
    let ver_hdr = header_str(&headers, MCP_HEADER_PROTOCOL_VERSION);
    let bearer_tok = extract_bearer(&headers);
    let cfg = {
        let mut guard = service.lock().await;
        if let Some(tok) = bearer_tok {
            let srv = guard.server_name.clone();
            if let Err(err) = guard.tokens.check_and_record_bearer(&srv, tok) {
                return error_json(StatusCode::FORBIDDEN, &err.to_string());
            }
        }
        if let Err(err) = guard
            .sessions
            .verify_headers(sid_hdr.as_deref(), ver_hdr.as_deref())
        {
            return error_json(StatusCode::FORBIDDEN, &err.to_string());
        }
        if let Some(sid) = sid_hdr.as_deref() {
            guard.sessions.close_session(sid);
        }
        guard.upstream.clone()
    };
    let Some(cfg) = cfg else {
        return StatusCode::NO_CONTENT.into_response();
    };
    let Ok(vetted) = resolve_and_vet_upstream(&cfg.upstream_url, cfg.ssrf_policy).await else {
        return error_json(
            StatusCode::FORBIDDEN,
            "GRDR-MCP-0008: upstream DELETE target failed SSRF validation",
        );
    };
    let Ok(client) = build_pinned_http_client(&vetted, cfg.request_timeout) else {
        return error_json(
            StatusCode::BAD_GATEWAY,
            "GRDR-MCP-0007: HTTP client build failed",
        );
    };
    let outbound = collect_safe_mcp_headers(&headers);
    match client
        .delete(vetted.url.clone())
        .headers(outbound)
        .send()
        .await
    {
        Ok(resp) => {
            if let Err(err) = verify_pinned_peer(&resp, &vetted) {
                return error_json(StatusCode::FORBIDDEN, &err);
            }
            (resp.status(), Body::empty()).into_response()
        }
        Err(err) => error_json(
            StatusCode::BAD_GATEWAY,
            &format!("GRDR-MCP-0007: upstream DELETE failed: {err}"),
        ),
    }
}

async fn forward_post_to_upstream<S: AsyncDecisionSource + 'static>(
    service: Arc<Mutex<McpBrokerService<S>>>,
    cfg: HttpUpstreamConfig,
    headers: &HeaderMap,
    raw_bytes: Bytes,
    req: &McpRequest,
    rev: McpProtocolRevision,
    local_sid: Option<String>,
) -> Response {
    let vetted = match resolve_and_vet_upstream(&cfg.upstream_url, cfg.ssrf_policy).await {
        Ok(v) => v,
        Err(err) => return error_json(StatusCode::FORBIDDEN, &err.to_string()),
    };
    let client = match build_pinned_http_client(&vetted, cfg.request_timeout) {
        Ok(c) => c,
        Err(err) => return error_json(StatusCode::BAD_GATEWAY, &err.to_string()),
    };
    let mut outbound = collect_safe_mcp_headers(headers);
    outbound.insert("content-type", HeaderValue::from_static("application/json"));
    if let Ok(hv) = HeaderValue::from_str(rev.as_str()) {
        outbound.insert(MCP_HEADER_PROTOCOL_VERSION, hv);
    }
    let upstream_resp = match client
        .post(vetted.url.clone())
        .headers(outbound)
        .body(raw_bytes.to_vec())
        .send()
        .await
    {
        Ok(r) => r,
        Err(err) => {
            return error_json(
                StatusCode::BAD_GATEWAY,
                &format!("GRDR-MCP-0007: upstream POST failed: {err}"),
            );
        }
    };
    if let Err(err) = verify_pinned_peer(&upstream_resp, &vetted) {
        return error_json(StatusCode::FORBIDDEN, &err);
    }
    if let Err(err) = reject_non_identity_encoding(upstream_resp.headers()) {
        return error_json(StatusCode::FORBIDDEN, &err);
    }
    if upstream_resp.status() == StatusCode::UNAUTHORIZED {
        return handle_upstream_401(service, &cfg, &upstream_resp, req).await;
    }
    let ctype = upstream_resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json")
        .to_string();
    if ctype.to_ascii_lowercase().contains("text/event-stream") {
        return stream_upstream_sse(service, upstream_resp);
    }
    let status = upstream_resp.status();
    let resp_bytes = match read_bounded_http_body(upstream_resp, MAX_HTTP_MCP_BODY_BYTES).await {
        Ok(b) => b,
        Err(err) => return error_json(StatusCode::BAD_GATEWAY, &err),
    };
    let Ok(text) = std::str::from_utf8(&resp_bytes) else {
        return error_json(
            StatusCode::BAD_GATEWAY,
            "GRDR-MCP-0007: upstream JSON response must be UTF-8",
        );
    };
    let body_out = {
        let mut guard = service.lock().await;
        match filter_child_tools_list_response(&mut *guard, text) {
            Ok(filtered) => filtered.into_bytes(),
            Err(err) => return error_json(StatusCode::FORBIDDEN, &err.to_string()),
        }
    };
    let mut out = (status, body_out).into_response();
    if let Ok(hv) = HeaderValue::from_str(&ctype) {
        out.headers_mut().insert("content-type", hv);
    }
    if let Some(sid) = local_sid
        && let Ok(hv) = HeaderValue::from_str(&sid)
    {
        out.headers_mut().insert(MCP_HEADER_SESSION_ID, hv);
    }
    out
}

async fn handle_upstream_401<S: AsyncDecisionSource>(
    service: Arc<Mutex<McpBrokerService<S>>>,
    cfg: &HttpUpstreamConfig,
    upstream_resp: &reqwest::Response,
    req: &McpRequest,
) -> Response {
    let Some(chall) = upstream_resp
        .headers()
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .and_then(parse_www_authenticate_step_up)
    else {
        return error_json(
            StatusCode::FORBIDDEN,
            "GRDR-MCP-0008: upstream 401 missing valid RFC 9110 Bearer resource_metadata",
        );
    };
    if let Err(err) = resolve_and_vet_upstream(&chall.resource_metadata, cfg.ssrf_policy).await {
        return error_json(StatusCode::FORBIDDEN, &err.to_string());
    }
    let allow_loopback = cfg.ssrf_policy == SsrfPolicy::AllowLoopbackTestOnly;
    {
        let mut guard = service.lock().await;
        let srv = guard.server_name.clone();
        if let Err(err) = guard.issuer_pins.bind_or_verify_with_policy(
            &srv,
            &cfg.upstream_url,
            &chall.resource_metadata,
            allow_loopback,
        ) {
            return error_json(StatusCode::FORBIDDEN, &err.to_string());
        }
    }
    let step_up = build_oauth_step_up_response(
        req.id.clone().unwrap_or(Value::Null),
        &chall.resource_metadata,
        &chall.scope,
        "OAuth step-up required by MCP server",
    );
    (StatusCode::OK, axum::Json(step_up)).into_response()
}

async fn read_bounded_http_body(
    mut resp: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| format!("GRDR-MCP-0007: upstream body read failed: {e}"))?
    {
        if out.len().saturating_add(chunk.len()) > max_bytes {
            return Err("GRDR-MCP-0007: oversized upstream JSON".to_string());
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

fn verify_pinned_peer(resp: &reqwest::Response, vetted: &VettedUpstream) -> Result<(), String> {
    if resp.remote_addr() != Some(vetted.pinned_addr) {
        return Err(format!(
            "GRDR-MCP-0008: upstream remote_addr mismatch (expected {})",
            vetted.pinned_addr
        ));
    }
    Ok(())
}

fn handle_initialize_http<S: AsyncDecisionSource>(
    guard: &mut McpBrokerService<S>,
    ver_hdr: Option<String>,
    req_id: Option<Value>,
) -> Response {
    let rev = match ver_hdr.as_deref() {
        Some(v) => match McpProtocolRevision::parse(v) {
            Ok(parsed) => parsed,
            Err(err) => {
                return (
                    StatusCode::BAD_REQUEST,
                    axum::Json(header_mismatch_rpc_error(req_id, &err.to_string())),
                )
                    .into_response();
            }
        },
        None => guard.default_revision,
    };
    let session = match guard.sessions.issue_session(rev) {
        Ok(s) => s,
        Err(err) => return error_json(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
    };
    (
        StatusCode::OK,
        [(MCP_HEADER_SESSION_ID, session.session_id.as_str())],
        axum::Json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": req_id.unwrap_or(Value::Null),
            "result": {
                "protocolVersion": rev.as_str(),
                "capabilities": { "tools": { "listChanged": false } },
                "serverInfo": { "name": guard.server_name, "version": "0.1.0" }
            }
        })),
    )
        .into_response()
}

async fn check_local_origin_and_host<S: AsyncDecisionSource>(
    service: &Arc<Mutex<McpBrokerService<S>>>,
    headers: &HeaderMap,
) -> Option<Response> {
    if headers.contains_key("origin") {
        return Some(error_json(
            StatusCode::FORBIDDEN,
            "GRDR-MCP-0005: browser Origin header rejected on local MCP listener",
        ));
    }
    let expected_port = service.lock().await.expected_http_port;
    if !has_loopback_host_header(headers, expected_port) {
        return Some(error_json(
            StatusCode::FORBIDDEN,
            "GRDR-MCP-0005: Host header missing or non-loopback on local MCP listener",
        ));
    }
    None
}

fn collect_safe_mcp_headers(src: &HeaderMap) -> reqwest::header::HeaderMap {
    let mut dst = reqwest::header::HeaderMap::new();
    dst.insert(
        reqwest::header::ACCEPT_ENCODING,
        reqwest::header::HeaderValue::from_static("identity"),
    );
    for name in ["accept", MCP_HEADER_PROTOCOL_VERSION] {
        if let Some(raw_val) = src.get(name).and_then(|v| v.to_str().ok())
            && let Ok(hn) = reqwest::header::HeaderName::from_bytes(name.as_bytes())
            && let Ok(hv) = reqwest::header::HeaderValue::from_str(raw_val)
        {
            dst.insert(hn, hv);
        }
    }
    dst
}

fn extract_bearer(headers: &HeaderMap) -> Option<&str> {
    let raw = headers.get("authorization")?.to_str().ok()?.trim();
    raw.strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))
}

fn header_str(headers: &HeaderMap, key: &str) -> Option<String> {
    headers
        .get(key)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

fn error_json(status: StatusCode, msg: &str) -> Response {
    (status, axum::Json(serde_json::json!({ "error": msg }))).into_response()
}
