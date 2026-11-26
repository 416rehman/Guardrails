// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Bounded compression/decompression, unary JSON inspection, and streamed tool call policy
//! enforcement for `grdr-proxy`.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::Value;
use uuid::Uuid;

use grdr_llm_proto::compression::{
    ContentEncodingKind, decompress_bounded, parse_content_encoding_header,
};
use grdr_llm_proto::schema::ProviderFamily;
use grdr_llm_proto::stream::LlmStreamDelta;
use grdr_llm_proto::strict_json::{MAX_JSON_DEPTH, parse_strict_json_bytes};
use grdr_model::{ActionAttempt, ActionClass, ControlPoint, ProvenanceSource, Verdict};
use grdr_os_clock::{Clock, SystemClock};
use grdr_strings::sanitize_untrusted_text;

use crate::router::{MAX_PROXY_BODY_BYTES, ProxyGatewayState};
use crate::router_http::{bad_gateway_response, denial_403};
use crate::{ProxyDecisionClient, ProxyError};

pub const MAX_DECOMPRESSION_RATIO: usize = 100;
const MAX_TOOL_EXTRACT_DEPTH: usize = 16;

pub(crate) struct UnaryDecompressArgs {
    pub(crate) session_id: String,
    pub(crate) route_id: String,
    pub(crate) family: Option<ProviderFamily>,
    pub(crate) status: StatusCode,
    pub(crate) resp_headers: HeaderMap,
    pub(crate) encodings: Vec<ContentEncodingKind>,
    pub(crate) keepalive_interval: Duration,
    pub(crate) max_bytes: usize,
    pub(crate) expect_json: bool,
}

pub(crate) fn inspect_and_decompress_request(
    headers: &HeaderMap,
    raw_body: &[u8],
) -> Result<Vec<u8>, ProxyError> {
    let Some(enc_hdr) = headers.get("content-encoding") else {
        if raw_body.len() > MAX_PROXY_BODY_BYTES {
            return Err(ProxyError::Sr39Rejected(
                "request body exceeds bounded proxy limit".to_string(),
            ));
        }
        return Ok(raw_body.to_vec());
    };
    let enc_str = enc_hdr
        .to_str()
        .map_err(|_| ProxyError::Sr39Rejected("non-ASCII Content-Encoding header".to_string()))?;
    let encodings = parse_content_encoding_header(enc_str)
        .map_err(|e| ProxyError::Sr39Rejected(format!("Content-Encoding rejected: {e}")))?;
    if encodings.is_empty() {
        if raw_body.len() > MAX_PROXY_BODY_BYTES {
            return Err(ProxyError::Sr39Rejected(
                "request body exceeds bounded proxy limit".to_string(),
            ));
        }
        return Ok(raw_body.to_vec());
    }
    decompress_bounded(
        raw_body,
        &encodings,
        MAX_PROXY_BODY_BYTES,
        MAX_DECOMPRESSION_RATIO,
    )
    .map_err(|e| {
        ProxyError::Sr39Rejected(format!(
            "compressed request rejected (>100:1 bomb or malformed): {e}"
        ))
    })
}

pub(crate) fn parse_response_encodings(
    headers: &HeaderMap,
) -> Result<Vec<ContentEncodingKind>, ProxyError> {
    let Some(enc_hdr) = headers.get("content-encoding") else {
        return Ok(Vec::new());
    };
    let enc_str = enc_hdr
        .to_str()
        .map_err(|_| ProxyError::Sr39Rejected("non-ASCII response Content-Encoding".to_string()))?;
    parse_content_encoding_header(enc_str)
        .map_err(|e| ProxyError::Sr39Rejected(format!("response Content-Encoding rejected: {e}")))
}

pub(crate) async fn check_egress_alive<C: ProxyDecisionClient>(
    state: &ProxyGatewayState<C>,
    session_id: &str,
) -> Option<std::io::Error> {
    if state.is_globally_killed() || state.registry.lock().await.is_session_cut(session_id) {
        Some(std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            "GRDR-PROXY-0005: egress killed mid-stream",
        ))
    } else {
        None
    }
}

pub(crate) fn build_safe_response(
    status: StatusCode,
    resp_headers: &HeaderMap,
    body: Body,
    preserve_content_encoding: bool,
) -> Response {
    let mut out = (status, body).into_response();
    for hdr_name in ["content-type", "cache-control", "mcp-session-id"] {
        if let Some(val) = resp_headers.get(hdr_name) {
            out.headers_mut().insert(hdr_name, val.clone());
        }
    }
    if preserve_content_encoding && let Some(val) = resp_headers.get("content-encoding") {
        out.headers_mut().insert("content-encoding", val.clone());
    }
    out
}

pub(crate) async fn enforce_sse_deltas<C: ProxyDecisionClient + 'static>(
    state: &Arc<ProxyGatewayState<C>>,
    session_id: &str,
    route_id: &str,
    deltas: &[LlmStreamDelta],
) -> Result<(), std::io::Error> {
    let mut names = BTreeSet::new();
    for delta in deltas {
        for call in &delta.tool_calls {
            if let Some(ref name) = call.name {
                let trimmed = name.trim();
                if !trimmed.is_empty() {
                    names.insert(trimmed.to_owned());
                }
            }
        }
    }
    if names.is_empty() {
        return Ok(());
    }
    enforce_streamed_tool_calls(state, session_id, route_id, &names).await
}

pub(crate) async fn enforce_streamed_tool_calls<C: ProxyDecisionClient + 'static>(
    state: &Arc<ProxyGatewayState<C>>,
    session_id: &str,
    route_id: &str,
    tool_names: &BTreeSet<String>,
) -> Result<(), std::io::Error> {
    {
        let allow_map = state.allowed_route_tools.lock().await;
        if let Some(allowed) = allow_map.get(route_id) {
            for tool in tool_names {
                if !allowed.contains(tool) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        format!(
                            "GRDR-PROXY-0003: streamed tool `{}` not permitted on route `{route_id}`",
                            sanitize_untrusted_text(tool)
                        ),
                    ));
                }
            }
        }
    }

    let now = SystemClock::new()
        .now_wall()
        .map_err(|e| std::io::Error::other(format!("GRDR-PROXY-0002: clock unavailable: {e}")))?;

    for tool in tool_names {
        let attempt = ActionAttempt {
            id: format!("att_{}", Uuid::now_v7().simple()),
            session_id: session_id.to_owned(),
            device_id: "dev-local".into(),
            device_name: "local-host".into(),
            agent_name: "grdr-proxy".into(),
            action_class: ActionClass::LlmRequest,
            control_point: ControlPoint::Proxy,
            target: format!("route:{route_id}/tool:{tool}"),
            summary: sanitize_untrusted_text(&format!(
                "streamed LLM tool call route={route_id} tool={tool}"
            )),
            timestamp: now,
            provenance: ProvenanceSource::Mediated,
            ..Default::default()
        };
        let receipt = state
            .decision_client
            .decide(&attempt)
            .await
            .map_err(|err| {
                std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("GRDR-PROXY-0003: streamed tool policy check failed closed: {err}"),
                )
            })?;
        if receipt.verdict != Verdict::Allow {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "GRDR-PROXY-0003: streamed tool `{}` denied ({:?})",
                    sanitize_untrusted_text(tool),
                    receipt.verdict
                ),
            ));
        }
    }
    Ok(())
}

pub(crate) async fn decompress_and_forward_unary<C: ProxyDecisionClient + 'static>(
    state: Arc<ProxyGatewayState<C>>,
    mut upstream_resp: reqwest::Response,
    args: UnaryDecompressArgs,
) -> Response {
    let mut raw = Vec::new();
    let mut cut_rx = state.cut_watch.subscribe();
    loop {
        if check_egress_alive(&state, &args.session_id).await.is_some() {
            return denial_403(&ProxyError::SessionEgressCut(
                "egress killed mid-response".into(),
            ));
        }
        let step = tokio::select! {
            _ = cut_rx.changed() => {
                if check_egress_alive(&state, &args.session_id).await.is_some() {
                    return denial_403(&ProxyError::SessionEgressCut("D-30 egress cut".into()));
                }
                continue;
            }
            step = tokio::time::timeout(args.keepalive_interval, upstream_resp.chunk()) => step,
        };
        match step {
            Err(_) => {
                return bad_gateway_response(&ProxyError::Transport(
                    "upstream compressed response idle timeout".into(),
                ));
            }
            Ok(Err(err)) => {
                return bad_gateway_response(&ProxyError::Transport(err.to_string()));
            }
            Ok(Ok(None)) => break,
            Ok(Ok(Some(chunk))) => {
                if raw
                    .len()
                    .checked_add(chunk.len())
                    .is_none_or(|n| n > args.max_bytes)
                {
                    return denial_403(&ProxyError::Sr39Rejected(
                        "compressed upstream response exceeds byte limit".into(),
                    ));
                }
                raw.extend_from_slice(&chunk);
            }
        }
    }

    let decoded = match decompress_bounded(
        &raw,
        &args.encodings,
        args.max_bytes,
        MAX_DECOMPRESSION_RATIO,
    ) {
        Ok(bytes) => bytes,
        Err(err) => {
            return denial_403(&ProxyError::Sr39Rejected(format!(
                "GRDR-PROXY-0006: compressed upstream response rejected: {err}"
            )));
        }
    };

    if args.expect_json && args.family.is_some() && !decoded.is_empty() {
        let parsed = match parse_strict_json_bytes(&decoded, args.max_bytes, MAX_JSON_DEPTH) {
            Ok(v) => v,
            Err(err) => {
                return denial_403(&ProxyError::Sr39Rejected(format!(
                    "GRDR-PROXY-0006: decompressed JSON response rejected: {err}"
                )));
            }
        };
        let mut names = BTreeSet::new();
        collect_json_tool_names(&parsed, 0, &mut names);
        if !names.is_empty()
            && let Err(err) =
                enforce_streamed_tool_calls(&state, &args.session_id, &args.route_id, &names).await
        {
            return denial_403(&ProxyError::PolicyDenied(err.to_string()));
        }
    }

    build_safe_response(args.status, &args.resp_headers, Body::from(decoded), false)
}

pub(crate) fn collect_json_tool_names(val: &Value, depth: usize, out: &mut BTreeSet<String>) {
    if depth >= MAX_TOOL_EXTRACT_DEPTH {
        return;
    }
    match val {
        Value::Object(map) => {
            if let Some(Value::Array(calls)) = map.get("tool_calls") {
                for call in calls {
                    extract_tool_name_from_obj(call, out);
                }
            }
            if let Some(tu) = map.get("toolUse").or_else(|| map.get("functionCall")) {
                extract_tool_name_from_obj(tu, out);
            }
            if map.get("type").and_then(Value::as_str) == Some("tool_use")
                && let Some(name) = map.get("name").and_then(Value::as_str)
            {
                let trimmed = name.trim();
                if !trimmed.is_empty() {
                    out.insert(trimmed.to_owned());
                }
            }
            let next_depth = depth.saturating_add(1);
            for child in map.values() {
                collect_json_tool_names(child, next_depth, out);
            }
        }
        Value::Array(arr) => {
            let next_depth = depth.saturating_add(1);
            for item in arr {
                collect_json_tool_names(item, next_depth, out);
            }
        }
        _ => {}
    }
}

fn extract_tool_name_from_obj(val: &Value, out: &mut BTreeSet<String>) {
    let Some(obj) = val.as_object() else {
        return;
    };
    let direct = obj.get("name").and_then(Value::as_str);
    let nested = obj
        .get("function")
        .and_then(Value::as_object)
        .and_then(|f| f.get("name"))
        .and_then(Value::as_str);
    if let Some(name) = direct.or(nested) {
        let trimmed = name.trim();
        if !trimmed.is_empty() {
            out.insert(trimmed.to_owned());
        }
    }
}
