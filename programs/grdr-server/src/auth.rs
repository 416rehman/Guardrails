// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use axum::Json;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use tower_http::cors::{Any, CorsLayer};

use grdr_model::CodedError;
use grdr_model::error::CODE_UNAUTHORIZED;

pub const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;
const ENROLL_HEADER: &str = "x-guardrails-enroll-token";

#[derive(Debug, Clone)]
pub struct ServerSecurityConfig {
    pub api_token: Option<String>,
    pub enroll_token: Option<String>,
    pub cors_origins: Vec<String>,
    pub max_body_bytes: usize,
}

impl Default for ServerSecurityConfig {
    fn default() -> Self {
        Self {
            api_token: None,
            enroll_token: None,
            cors_origins: Vec::new(),
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
        }
    }
}

pub fn build_cors_layer(security: &ServerSecurityConfig) -> CorsLayer {
    let custom: Vec<HeaderValue> = security
        .cors_origins
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .filter_map(|s| HeaderValue::from_str(s).ok())
        .collect();

    let auth_enabled = security.api_token.is_some() || security.enroll_token.is_some();

    let layer = CorsLayer::new().allow_methods(Any).allow_headers([
        header::AUTHORIZATION,
        header::CONTENT_TYPE,
        header::HeaderName::from_static(ENROLL_HEADER),
    ]);

    if !custom.is_empty() {
        return layer.allow_origin(custom);
    }

    if auth_enabled {
        let local_defaults = [
            HeaderValue::from_static("http://127.0.0.1:5173"),
            HeaderValue::from_static("http://localhost:5173"),
            HeaderValue::from_static("http://127.0.0.1:8787"),
            HeaderValue::from_static("http://localhost:8787"),
        ];
        return layer.allow_origin(local_defaults);
    }

    layer.allow_origin(Any)
}

pub async fn require_operator_auth(
    State(security): State<ServerSecurityConfig>,
    request: Request,
    next: Next,
) -> Response {
    let Some(expected) = security.api_token.as_deref() else {
        return next.run(request).await;
    };

    if let Some(token) = bearer_token(request.headers())
        && constant_time_eq(token, expected)
    {
        return next.run(request).await;
    }

    if request.uri().path() == "/api/v1/live"
        && let Some(query) = request.uri().query()
        && let Some(token) = extract_query_param(query, "access_token")
        && constant_time_eq(&token, expected)
    {
        return next.run(request).await;
    }

    unauthorized_response(
        "Operator bearer token required.",
        "Provide Authorization: Bearer <token> matching --api-token or GRDR_API_TOKEN.",
    )
}

pub async fn require_device_or_operator_auth(
    State(security): State<ServerSecurityConfig>,
    request: Request,
    next: Next,
) -> Response {
    let is_checkin = request.uri().path() == "/api/v1/devices/checkin";
    let enroll_token = security.enroll_token.as_deref();
    let api_token = security.api_token.as_deref();

    let authorized = if is_checkin {
        match enroll_token {
            Some(expected) => matches_enroll_or_bearer(request.headers(), expected),
            None => true,
        }
    } else {
        match (enroll_token, api_token) {
            (Some(enroll), Some(api)) => {
                matches_enroll_or_bearer(request.headers(), enroll)
                    || bearer_token(request.headers()).is_some_and(|t| constant_time_eq(t, api))
            }
            (Some(enroll), None) => matches_enroll_or_bearer(request.headers(), enroll),
            (None, Some(api)) => {
                bearer_token(request.headers()).is_some_and(|t| constant_time_eq(t, api))
            }
            (None, None) => true,
        }
    };

    if authorized {
        return next.run(request).await;
    }

    let (message, next_step) = if is_checkin {
        (
            "Device enrollment token required.",
            "Provide X-Guardrails-Enroll-Token or Authorization: Bearer matching --enroll-token.",
        )
    } else {
        (
            "Telemetry ingest token required.",
            "Provide an enrollment or operator bearer token.",
        )
    };
    unauthorized_response(message, next_step)
}

fn unauthorized_response(message: &str, next_step: &str) -> Response {
    let body = CodedError::new(CODE_UNAUTHORIZED, message, next_step);
    (StatusCode::UNAUTHORIZED, Json(body)).into_response()
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

fn constant_time_eq(a: &str, b: &str) -> bool {
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
