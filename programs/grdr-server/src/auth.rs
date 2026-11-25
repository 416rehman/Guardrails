// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, header};
use axum::middleware::Next;
use axum::response::Response;
use grdr_crypto::{AeadKey, sha256_hex};
use tower_http::cors::CorsLayer;

use crate::connect_codec::extract_request_id;
use crate::connect_error::{ApiError, WireEncoding, encode_connect_error};
use crate::store::AppState;

pub const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;
const ENROLL_HEADER: &str = "x-guardrails-enroll-token";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthPlane {
    Console,
    Operator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConfirmAssertion {
    None,
    ConfirmedIntent,
    StepUpVerified,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalIdentity {
    pub principal_id: String,
    pub tenant_id: String,
    pub plane: AuthPlane,
    pub scopes: Vec<String>,
    pub assurance: ConfirmAssertion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthContext {
    pub principal_id: String,
    pub tenant_id: String,
    pub plane: AuthPlane,
    pub scopes: Vec<String>,
    pub confirmation: ConfirmAssertion,
}

#[derive(Debug, Clone)]
pub struct ServerSecurityConfig {
    pub api_token: Option<String>,
    pub operator_token: Option<String>,
    pub step_up_token: Option<String>,
    pub enroll_token: Option<String>,
    pub cors_origins: Vec<String>,
    pub operator_cors_origins: Vec<String>,
    pub max_body_bytes: usize,
    pub principal_tokens: BTreeMap<String, PrincipalIdentity>,
}

#[derive(Clone)]
pub struct AuthLayerState {
    pub security: ServerSecurityConfig,
    pub app: AppState,
}

impl ConfirmAssertion {
    pub fn is_confirmed(self) -> bool {
        matches!(self, Self::ConfirmedIntent | Self::StepUpVerified)
    }

    pub fn is_step_up(self) -> bool {
        matches!(self, Self::StepUpVerified)
    }
}

impl AuthContext {
    pub fn allows_scope(&self, required: &str) -> bool {
        if required.is_empty() {
            return true;
        }
        let service_prefix = required
            .split_once(':')
            .map(|(ns, _)| format!("{ns}:*"))
            .unwrap_or_default();
        self.scopes.iter().any(|s| {
            s == "*" || s == required || (!service_prefix.is_empty() && s == &service_prefix)
        })
    }
}

impl Default for ServerSecurityConfig {
    fn default() -> Self {
        Self {
            api_token: None,
            operator_token: None,
            step_up_token: None,
            enroll_token: None,
            cors_origins: Vec::new(),
            operator_cors_origins: Vec::new(),
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            principal_tokens: BTreeMap::new(),
        }
    }
}

pub fn random_csprng_hex(domain: &str, context: &[u8]) -> Option<String> {
    let key = AeadKey::generate().ok()?;
    let derived = key.derive_subkey(domain);
    let nonce_id = uuid::Uuid::now_v7();
    let sealed = grdr_crypto::seal_token(&derived, domain, context, nonce_id.as_bytes()).ok()?;
    Some(sha256_hex(sealed.as_bytes()))
}

pub fn generate_random_bearer_token() -> Option<String> {
    random_csprng_hex("grdr.bootstrap.bearer.v1", b"bootstrap")
}

pub fn build_cors_layer(security: &ServerSecurityConfig) -> CorsLayer {
    let defaults = [
        HeaderValue::from_static("http://127.0.0.1:5173"),
        HeaderValue::from_static("http://localhost:5173"),
        HeaderValue::from_static("http://127.0.0.1:8787"),
        HeaderValue::from_static("http://localhost:8787"),
    ];
    build_cors_from_origins(&security.cors_origins, &defaults)
}

pub fn build_operator_cors_layer(security: &ServerSecurityConfig) -> CorsLayer {
    let defaults = [
        HeaderValue::from_static("http://127.0.0.1:5174"),
        HeaderValue::from_static("http://localhost:5174"),
        HeaderValue::from_static("http://127.0.0.1:8788"),
        HeaderValue::from_static("http://localhost:8788"),
    ];
    build_cors_from_origins(&security.operator_cors_origins, &defaults)
}

fn build_cors_from_origins(configured: &[String], defaults: &[HeaderValue]) -> CorsLayer {
    let custom: Vec<HeaderValue> = configured
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .filter_map(|s| HeaderValue::from_str(s).ok())
        .collect();

    let origins = if custom.is_empty() {
        defaults.to_vec()
    } else {
        custom
    };

    CorsLayer::new()
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::IF_NONE_MATCH,
            header::HeaderName::from_static(ENROLL_HEADER),
            header::HeaderName::from_static("connect-protocol-version"),
            header::HeaderName::from_static("connect-timeout-ms"),
            header::HeaderName::from_static("grdr-request-id"),
            header::HeaderName::from_static("x-grdr-confirm"),
            header::HeaderName::from_static("x-grdr-step-up"),
        ])
        .expose_headers([
            header::ETAG,
            header::HeaderName::from_static("grdr-request-id"),
        ])
        .allow_origin(origins)
}

pub async fn require_console_auth(
    State(auth_state): State<AuthLayerState>,
    mut request: Request,
    next: Next,
) -> Response {
    let security = &auth_state.security;
    if request.uri().path() == "/grdr.api.overview.v1alpha1.OverviewService/LiveEvents"
        && let Some(query) = request.uri().query()
        && let Some(ticket) = extract_query_param(query, "ticket")
        && let Some(ctx) = auth_state.app.consume_live_ticket(&ticket)
        && ctx.plane == AuthPlane::Console
    {
        request.extensions_mut().insert(ctx);
        return next.run(request).await;
    }

    let Some(token) = bearer_token(request.headers()) else {
        let req_id = extract_request_id(request.headers());
        return unauthorized_response(
            &req_id,
            "Console bearer token required.",
            "Provide Authorization: Bearer <token> matching --api-token or GRDR_API_TOKEN.",
        );
    };

    if security
        .operator_token
        .as_deref()
        .is_some_and(|op| constant_time_eq(token, op))
    {
        let req_id = extract_request_id(request.headers());
        return unauthorized_response(
            &req_id,
            "Operator plane credentials are isolated and rejected on Console origin (D-70).",
            "Authenticate with the tenant console token instead.",
        );
    }

    if let Some(ctx) = resolve_console_principal(security, token, request.headers()) {
        request.extensions_mut().insert(ctx);
        return next.run(request).await;
    }

    let req_id = extract_request_id(request.headers());
    unauthorized_response(
        &req_id,
        "Invalid or missing console bearer token.",
        "Provide Authorization: Bearer <token> matching --api-token.",
    )
}

pub async fn require_dedicated_operator_auth(
    State(auth_state): State<AuthLayerState>,
    mut request: Request,
    next: Next,
) -> Response {
    let security = &auth_state.security;
    let Some(token) = bearer_token(request.headers()) else {
        let req_id = extract_request_id(request.headers());
        return unauthorized_response(
            &req_id,
            "Operator plane bearer token required (D-70).",
            "Provide Authorization: Bearer <operator-token> on the dedicated operator origin.",
        );
    };

    if security
        .api_token
        .as_deref()
        .is_some_and(|console| constant_time_eq(token, console))
    {
        let req_id = extract_request_id(request.headers());
        return unauthorized_response(
            &req_id,
            "Console tokens cannot access the isolated Operator Plane (D-70).",
            "Authenticate with a dedicated --operator-token credential.",
        );
    }

    if let Some(ctx) = resolve_operator_principal(security, token, request.headers()) {
        request.extensions_mut().insert(ctx);
        return next.run(request).await;
    }

    let req_id = extract_request_id(request.headers());
    unauthorized_response(
        &req_id,
        "Invalid or missing operator plane bearer token.",
        "Provide Authorization: Bearer <operator-token> matching --operator-token.",
    )
}

pub async fn require_device_or_console_auth(
    State(auth_state): State<AuthLayerState>,
    mut request: Request,
    next: Next,
) -> Response {
    let security = &auth_state.security;
    let is_checkin =
        request.uri().path() == "/grdr.api.inventory.v1alpha1.InventoryService/DeviceCheckin";
    let enroll_token = security.enroll_token.as_deref();

    if let Some(expected) = enroll_token
        && matches_enroll_or_bearer(request.headers(), expected)
    {
        let scopes = if is_checkin {
            vec!["device:checkin".into(), "ingest:write".into()]
        } else {
            vec!["ingest:write".into()]
        };
        request.extensions_mut().insert(AuthContext {
            principal_id: "device-enroller".into(),
            tenant_id: "org-default".into(),
            plane: AuthPlane::Console,
            scopes,
            confirmation: ConfirmAssertion::None,
        });
        return next.run(request).await;
    }

    if let Some(token) = bearer_token(request.headers()) {
        if security
            .operator_token
            .as_deref()
            .is_some_and(|op| constant_time_eq(token, op))
        {
            let req_id = extract_request_id(request.headers());
            return unauthorized_response(
                &req_id,
                "Operator plane credentials are isolated and rejected on Console origin (D-70).",
                "Authenticate with an enrollment or console bearer token instead.",
            );
        }
        if let Some(ctx) = resolve_console_principal(security, token, request.headers()) {
            request.extensions_mut().insert(ctx);
            return next.run(request).await;
        }
    }

    let (message, next_step) = if is_checkin {
        (
            "Device enrollment token required.",
            "Provide X-Guardrails-Enroll-Token or Authorization: Bearer matching --enroll-token.",
        )
    } else {
        (
            "Telemetry ingest token required.",
            "Provide an enrollment or console bearer token.",
        )
    };
    let req_id = extract_request_id(request.headers());
    unauthorized_response(&req_id, message, next_step)
}

fn resolve_console_principal(
    security: &ServerSecurityConfig,
    token: &str,
    headers: &HeaderMap,
) -> Option<AuthContext> {
    let hdr_confirm = parse_confirm_assertion(security, headers, ConfirmAssertion::None);
    if let Some(expected) = security.api_token.as_deref()
        && constant_time_eq(token, expected)
    {
        return Some(AuthContext {
            principal_id: "console-admin".into(),
            tenant_id: "org-default".into(),
            plane: AuthPlane::Console,
            scopes: vec!["*".into()],
            confirmation: hdr_confirm,
        });
    }
    for (cand_tok, id) in &security.principal_tokens {
        if id.plane == AuthPlane::Console && constant_time_eq(token, cand_tok) {
            return Some(AuthContext {
                principal_id: id.principal_id.clone(),
                tenant_id: id.tenant_id.clone(),
                plane: AuthPlane::Console,
                scopes: id.scopes.clone(),
                confirmation: parse_confirm_assertion(security, headers, id.assurance),
            });
        }
    }
    None
}

fn resolve_operator_principal(
    security: &ServerSecurityConfig,
    token: &str,
    headers: &HeaderMap,
) -> Option<AuthContext> {
    let hdr_confirm = parse_confirm_assertion(security, headers, ConfirmAssertion::None);
    if let Some(expected) = security.operator_token.as_deref()
        && constant_time_eq(token, expected)
    {
        return Some(AuthContext {
            principal_id: "operator-admin".into(),
            tenant_id: "operator-realm".into(),
            plane: AuthPlane::Operator,
            scopes: vec![
                "operator:*".into(),
                "overview:read".into(),
                "keys:read".into(),
                "audit:export".into(),
                "audit:read".into(),
            ],
            confirmation: hdr_confirm,
        });
    }
    for (cand_tok, id) in &security.principal_tokens {
        if id.plane == AuthPlane::Operator && constant_time_eq(token, cand_tok) {
            return Some(AuthContext {
                principal_id: id.principal_id.clone(),
                tenant_id: id.tenant_id.clone(),
                plane: AuthPlane::Operator,
                scopes: id.scopes.clone(),
                confirmation: parse_confirm_assertion(security, headers, id.assurance),
            });
        }
    }
    None
}

fn parse_confirm_assertion(
    security: &ServerSecurityConfig,
    headers: &HeaderMap,
    base: ConfirmAssertion,
) -> ConfirmAssertion {
    let has_valid_step_up = security.step_up_token.as_deref().is_some_and(|expected| {
        !expected.is_empty()
            && headers
                .get("x-grdr-step-up")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| constant_time_eq(v.trim(), expected))
    });
    let has_confirm = headers
        .get("x-grdr-confirm")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            matches!(
                v.trim(),
                "confirmed" | "consequence" | "typed" | "propose" | "quorum"
            )
        });
    if base == ConfirmAssertion::StepUpVerified || has_valid_step_up {
        ConfirmAssertion::StepUpVerified
    } else if base == ConfirmAssertion::ConfirmedIntent || has_confirm {
        ConfirmAssertion::ConfirmedIntent
    } else {
        ConfirmAssertion::None
    }
}

fn unauthorized_response(request_id: &str, message: &str, next_step: &str) -> Response {
    let err = ApiError::unauthenticated(message, next_step);
    encode_connect_error(WireEncoding::Json, request_id, &err)
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .map(str::trim)
}

fn matches_enroll_or_bearer(headers: &HeaderMap, expected: &str) -> bool {
    if let Some(raw) = headers.get(ENROLL_HEADER).and_then(|v| v.to_str().ok())
        && constant_time_eq(raw.trim(), expected)
    {
        return true;
    }
    bearer_token(headers).is_some_and(|token| constant_time_eq(token, expected))
}

fn extract_query_param(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=')
            && k == key
            && !v.is_empty()
        {
            return Some(v.to_string());
        }
    }
    None
}

pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    if ab.len() != bb.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in ab.iter().zip(bb.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
