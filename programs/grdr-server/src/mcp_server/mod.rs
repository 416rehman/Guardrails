// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

pub mod proposals;
pub mod read_dispatch;
pub mod secrecy;
pub mod tools;

#[cfg(test)]
mod tests;

use axum::Json;
use axum::Router;
use axum::body::Body;
use axum::extract::{Extension, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::auth::{
    AuthContext, AuthLayerState, AuthPlane, ServerSecurityConfig, require_console_auth,
};
use crate::store::AppState;

use super::gitops::{GitopsStore, api_error_json_response};
use super::rest::BrandInfo;
use super::rest::limits::rest_limits;
use super::rest::rate_limit::rate_limited_response;
use tools::{
    SCOPE_MCP_API_READ, SCOPE_MCP_PROPOSE, SCOPE_MCP_READ, execute_tool, has_scope,
    is_proposal_write_tool, list_tools_json, wrap_tool_result_mcp,
};

pub use proposals::McpProposalStore;

pub const MCP_PROTOCOL_VERSION: &str = "2026-07-28";

#[derive(Debug, Clone, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    #[serde(default)]
    pub id: Value,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

pub fn mcp_public_router() -> Router<AppState> {
    Router::new()
        .route(
            "/.well-known/oauth-protected-resource",
            get(get_protected_resource_metadata),
        )
        .route("/mcp/register", post(reject_dynamic_client_registration))
}

pub fn mcp_router(auth_state: AuthLayerState) -> Router<AppState> {
    let security = auth_state.security.clone();
    Router::new()
        .route(
            "/mcp",
            post(handle_mcp_rpc)
                .get(reject_stateless_stream)
                .delete(reject_stateless_stream),
        )
        .route_layer(middleware::from_fn_with_state(
            auth_state,
            require_console_auth,
        ))
        .route_layer(middleware::from_fn_with_state(
            security,
            mcp_www_authenticate_middleware,
        ))
}

async fn mcp_www_authenticate_middleware(
    State(security): State<ServerSecurityConfig>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let brand = BrandInfo::embedded();
    let origin = resolve_request_origin(request.headers(), Some(&security), &brand);
    let mut response = next.run(request).await;
    if response.status() == StatusCode::UNAUTHORIZED
        && !response.headers().contains_key(header::WWW_AUTHENTICATE)
    {
        let challenge = format!(
            r#"Bearer error="invalid_token", resource_metadata="{origin}/.well-known/oauth-protected-resource""#
        );
        if let Ok(hv) = HeaderValue::from_str(&challenge) {
            response.headers_mut().insert(header::WWW_AUTHENTICATE, hv);
        }
    }
    response
}

async fn get_protected_resource_metadata(
    security: Option<Extension<ServerSecurityConfig>>,
    headers: HeaderMap,
) -> Json<Value> {
    let brand = BrandInfo::embedded();
    let sec_ref = security.as_ref().map(|Extension(cfg)| cfg);
    let origin = resolve_request_origin(&headers, sec_ref, &brand);
    Json(json!({
        "resource": format!("{origin}/mcp"),
        "resource_name": format!("{} MCP Server", brand.product_name),
        "scopes_supported": [SCOPE_MCP_READ, SCOPE_MCP_PROPOSE, SCOPE_MCP_API_READ],
        "bearer_methods_supported": ["header"],
        "client_metadata_document_supported": true,
        "dynamic_client_registration_supported": false,
        "authorization_grant_types_supported": [
            "urn:ietf:params:oauth:grant-type:token-exchange",
            "urn:ietf:params:oauth:grant-type:jwt-bearer"
        ]
    }))
}

async fn reject_dynamic_client_registration() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "error": "unsupported_grant_type",
            "reason": "DCR_NOT_SUPPORTED",
            "message": "Dynamic Client Registration is disabled; use CIMD or OAuth ID-JAG token exchange."
        })),
    )
        .into_response()
}

async fn reject_stateless_stream() -> Response {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        Json(json!({
            "error": "stateless_streamable_http",
            "message": "Remote /mcp server is strictly stateless Streamable HTTP POST JSON-RPC; persistent GET/DELETE sessions are unsupported."
        })),
    )
        .into_response()
}

async fn handle_mcp_rpc(
    State(state): State<AppState>,
    Extension(gitops): Extension<GitopsStore>,
    Extension(proposals): Extension<McpProposalStore>,
    Extension(auth): Extension<AuthContext>,
    security: Option<Extension<ServerSecurityConfig>>,
    headers: HeaderMap,
    Json(req): Json<JsonRpcRequest>,
) -> Response {
    let brand = BrandInfo::embedded();
    let sec_ref = security.as_ref().map(|Extension(cfg)| cfg);
    let origin = resolve_request_origin(&headers, sec_ref, &brand);
    if auth.plane != AuthPlane::Console {
        return unauthorized_challenge(
            &origin,
            "Operator plane credentials cannot access /mcp (D-70).",
        );
    }
    if let Err(err_msg) = validate_mcp_audience(&headers, &req.params, sec_ref, &brand) {
        return unauthorized_challenge(&origin, err_msg);
    }

    if req.jsonrpc != "2.0" {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "jsonrpc": "2.0",
                "id": req.id,
                "error": { "code": -32600, "message": "jsonrpc must equal 2.0" }
            })),
        )
            .into_response();
    }
    if !has_any_mcp_scope(&auth) {
        let mut resp = (
            StatusCode::FORBIDDEN,
            Json(json!({
                "jsonrpc": "2.0",
                "id": req.id,
                "error": {
                    "code": -32001,
                    "message": "insufficient_scope: caller requires mcp:read, mcp:propose, or mcp:api-read"
                }
            })),
        )
            .into_response();
        let challenge = format!(
            r#"Bearer error="insufficient_scope", scope="mcp:read mcp:propose", resource_metadata="{origin}/.well-known/oauth-protected-resource""#
        );
        if let Ok(hv) = HeaderValue::from_str(&challenge) {
            resp.headers_mut().insert(header::WWW_AUTHENTICATE, hv);
        }
        return resp;
    }

    match req.method.as_str() {
        "initialize" => {
            let mut resp = Json(json!({
                "jsonrpc": "2.0",
                "id": req.id,
                "result": {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {
                        "tools": { "listChanged": false },
                        "resources": { "subscribe": false, "listChanged": false }
                    },
                    "serverInfo": {
                        "name": format!("{} MCP Server", brand.short_name),
                        "version": env!("CARGO_PKG_VERSION"),
                    },
                    "instructions": format!("Stateless read and proposal-only {} MCP endpoint. All untrusted fields are wrapped and policy rules/lists/grants remain confidential.", brand.product_name)
                }
            }))
            .into_response();
            if let Ok(hv) = HeaderValue::from_str(MCP_PROTOCOL_VERSION) {
                resp.headers_mut().insert("mcp-protocol-version", hv);
            }
            resp
        }
        "ping" => Json(json!({ "jsonrpc": "2.0", "id": req.id, "result": {} })).into_response(),
        "tools/list" => {
            let tools = list_tools_json(&auth);
            Json(json!({ "jsonrpc": "2.0", "id": req.id, "result": { "tools": tools } }))
                .into_response()
        }
        "resources/list" => {
            Json(json!({ "jsonrpc": "2.0", "id": req.id, "result": { "resources": [] } }))
                .into_response()
        }
        "tools/call" => {
            let Some(name) = req.params.get("name").and_then(Value::as_str) else {
                return Json(json!({
                    "jsonrpc": "2.0",
                    "id": req.id,
                    "error": { "code": -32602, "message": "Missing tool name" }
                }))
                .into_response();
            };
            let is_prop = is_proposal_write_tool(name);
            let quota = proposals.check_tool_quota(&auth, is_prop).await;
            if !quota.allowed {
                let win = if is_prop {
                    rest_limits().mcp_propose_window_secs
                } else {
                    rest_limits().rate_limit_window_secs
                };
                return rate_limited_response(&quota, win);
            }

            let args = req
                .params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            match execute_tool(&state, &gitops, &proposals, &auth, name, args).await {
                Ok(data) => Json(json!({
                    "jsonrpc": "2.0",
                    "id": req.id,
                    "result": wrap_tool_result_mcp(data),
                }))
                .into_response(),
                Err(err) => {
                    let resp = api_error_json_response(&err);
                    let msg = extract_api_error_message(resp).await;
                    Json(json!({
                        "jsonrpc": "2.0",
                        "id": req.id,
                        "error": {
                            "code": -32003,
                            "message": msg,
                        }
                    }))
                    .into_response()
                }
            }
        }
        _ => Json(json!({
            "jsonrpc": "2.0",
            "id": req.id,
            "error": { "code": -32601, "message": "Method not found" }
        }))
        .into_response(),
    }
}

fn canonical_mcp_origins(
    security: Option<&ServerSecurityConfig>,
    brand: &BrandInfo,
) -> Vec<String> {
    let mut origins = vec![format!("https://{}", brand.domain)];
    if let Some(sec) = security {
        for raw in &sec.cors_origins {
            if let Some(norm) = normalize_origin(raw)
                && !origins
                    .iter()
                    .any(|existing| existing.eq_ignore_ascii_case(&norm))
            {
                origins.push(norm);
            }
        }
    }
    origins
}

fn normalize_origin(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() || trimmed.contains('#') {
        return None;
    }
    let parsed: axum::http::Uri = trimmed.parse().ok()?;
    let scheme = parsed.scheme_str()?;
    if !matches!(scheme, "https" | "http") {
        return None;
    }
    if parsed.query().is_some() || !matches!(parsed.path(), "" | "/") {
        return None;
    }
    let authority = parsed.authority()?;
    if authority.as_str().contains('@') {
        return None;
    }
    let host = authority.host();
    if host.is_empty() {
        return None;
    }
    if scheme == "http" && !matches!(host, "127.0.0.1" | "localhost" | "[::1]" | "::1") {
        return None;
    }
    Some(format!("{scheme}://{authority}"))
}

fn resolve_request_origin(
    headers: &HeaderMap,
    security: Option<&ServerSecurityConfig>,
    brand: &BrandInfo,
) -> String {
    let allowed = canonical_mcp_origins(security, brand);
    if let Some(host_hdr) = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        && let Some(matched) = allowed.iter().find(|origin| {
            origin
                .parse::<axum::http::Uri>()
                .ok()
                .and_then(|u| {
                    u.authority()
                        .map(|a| a.as_str().eq_ignore_ascii_case(host_hdr))
                })
                .unwrap_or(false)
        })
    {
        return matched.clone();
    }
    allowed
        .into_iter()
        .next()
        .unwrap_or_else(|| format!("https://{}", brand.domain))
}

fn validate_mcp_audience(
    headers: &HeaderMap,
    params: &Value,
    security: Option<&ServerSecurityConfig>,
    brand: &BrandInfo,
) -> Result<(), &'static str> {
    let candidate = headers
        .get("x-grdr-token-audience")
        .or_else(|| headers.get("x-oauth-audience"))
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .or_else(|| {
            params
                .get("audience")
                .and_then(Value::as_str)
                .map(str::trim)
        });
    let Some(aud) = candidate.filter(|s| !s.is_empty()) else {
        return Ok(());
    };
    let clean = aud.trim_end_matches('/');
    let matched = canonical_mcp_origins(security, brand)
        .into_iter()
        .any(|origin| clean.eq_ignore_ascii_case(&format!("{origin}/mcp")));
    if matched {
        Ok(())
    } else {
        Err("Token audience does not match this MCP resource (RFC 8707).")
    }
}

fn unauthorized_challenge(origin: &str, msg: &str) -> Response {
    let mut resp = (
        StatusCode::UNAUTHORIZED,
        Json(json!({
            "error": "invalid_token",
            "message": msg,
        })),
    )
        .into_response();
    let challenge = format!(
        r#"Bearer error="invalid_token", resource_metadata="{origin}/.well-known/oauth-protected-resource""#
    );
    if let Ok(hv) = HeaderValue::from_str(&challenge) {
        resp.headers_mut().insert(header::WWW_AUTHENTICATE, hv);
    }
    resp
}

fn has_any_mcp_scope(auth: &AuthContext) -> bool {
    has_scope(auth, SCOPE_MCP_READ)
        || has_scope(auth, SCOPE_MCP_PROPOSE)
        || has_scope(auth, SCOPE_MCP_API_READ)
}

async fn extract_api_error_message(resp: Response) -> String {
    let Ok(bytes) = axum::body::to_bytes(resp.into_body(), 16_384).await else {
        return "MCP tool call failed.".into();
    };
    serde_json::from_slice::<Value>(&bytes)
        .ok()
        .and_then(|v| v.get("message").and_then(Value::as_str).map(str::to_owned))
        .unwrap_or_else(|| "MCP tool call failed.".into())
}
