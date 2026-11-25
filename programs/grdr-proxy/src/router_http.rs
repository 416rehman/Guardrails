// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! HTTP header filtering, URL path confinement, and bounded response streaming helpers.

use std::collections::BTreeSet;

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use url::Url;

use grdr_strings::sanitize_untrusted_text;

use crate::ProxyError;

pub fn copy_safe_outbound_headers(headers: &HeaderMap) -> HeaderMap {
    let mut skip_names = BTreeSet::from([
        "connection".to_owned(),
        "keep-alive".to_owned(),
        "proxy-authenticate".to_owned(),
        "proxy-authorization".to_owned(),
        "te".to_owned(),
        "trailer".to_owned(),
        "transfer-encoding".to_owned(),
        "upgrade".to_owned(),
        "host".to_owned(),
        "authorization".to_owned(),
        "x-api-key".to_owned(),
        "cookie".to_owned(),
        "content-length".to_owned(),
        "forwarded".to_owned(),
        "x-forwarded-for".to_owned(),
        "x-forwarded-host".to_owned(),
        "x-forwarded-proto".to_owned(),
    ]);
    for conn_val in headers.get_all("connection") {
        if let Ok(raw) = conn_val.to_str() {
            for token in raw.split(',') {
                let lower = token.trim().to_ascii_lowercase();
                if !lower.is_empty() {
                    skip_names.insert(lower);
                }
            }
        }
    }

    let mut outbound = HeaderMap::new();
    for (k, v) in headers {
        let lower = k.as_str().to_ascii_lowercase();
        if !skip_names.contains(&lower) {
            outbound.insert(k.clone(), v.clone());
        }
    }
    outbound
}

pub async fn read_bounded_response(
    mut upstream_resp: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, ProxyError> {
    let mut out = Vec::new();
    while let Some(chunk) = upstream_resp
        .chunk()
        .await
        .map_err(|e| ProxyError::Transport(e.to_string()))?
    {
        let next_len = out
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| ProxyError::Transport("upstream response size overflow".into()))?;
        if next_len > max_bytes {
            return Err(ProxyError::Transport(format!(
                "upstream response exceeds {max_bytes} byte limit"
            )));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

pub fn build_upstream_url(base: &Url, tail: &str) -> Result<String, ProxyError> {
    let clean_tail = tail.trim_start_matches('/');
    if clean_tail.is_empty() {
        return Ok(base.as_str().to_owned());
    }
    let lower = clean_tail.to_ascii_lowercase();
    if clean_tail.chars().any(char::is_control)
        || clean_tail.contains('?')
        || clean_tail.contains('#')
        || clean_tail.contains('\\')
        || clean_tail.contains("//")
        || clean_tail.contains("..")
        || lower.contains("%2e")
        || lower.contains("%2f")
        || lower.contains("%5c")
        || lower.contains("%3f")
        || lower.contains("%23")
        || lower.contains("%00")
    {
        return Err(ProxyError::Sr39Rejected(
            "upstream path tail contains disallowed traversal, query, or control token".into(),
        ));
    }
    let mut segments = clean_tail.split('/').peekable();
    while let Some(seg) = segments.next() {
        let is_trailing_empty = seg.is_empty() && segments.peek().is_none();
        if (!is_trailing_empty && seg.is_empty()) || seg == "." || seg == ".." {
            return Err(ProxyError::Sr39Rejected(
                "upstream path tail contains dot or empty path segment".into(),
            ));
        }
    }
    let base_str = base.as_str().trim_end_matches('/');
    let joined = format!("{base_str}/{clean_tail}");
    let parsed = Url::parse(&joined)
        .map_err(|_| ProxyError::Sr39Rejected("invalid joined upstream route URL".into()))?;
    let base_prefix = base.path().trim_end_matches('/');
    let same_prefix = base_prefix.is_empty()
        || parsed.path() == base_prefix
        || parsed.path().starts_with(&format!("{base_prefix}/"));
    if parsed.origin() != base.origin() || !same_prefix {
        return Err(ProxyError::Sr39Rejected(
            "joined upstream URL escaped registered route origin or base path".into(),
        ));
    }
    Ok(parsed.to_string())
}

pub fn bad_gateway_response(err: &ProxyError) -> Response {
    (
        StatusCode::BAD_GATEWAY,
        axum::Json(serde_json::json!({
            "error": sanitize_untrusted_text(&err.to_string()),
            "code": "GRDR-PROXY-0006"
        })),
    )
        .into_response()
}

pub fn denial_403(err: &ProxyError) -> Response {
    (
        StatusCode::FORBIDDEN,
        axum::Json(serde_json::json!({
            "error": sanitize_untrusted_text(&err.to_string()),
            "verdict": "Deny"
        })),
    )
        .into_response()
}
