// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Fail-closed Streamable HTTP SSE filtering and server-initiated JSON-RPC mediation for `grdr-mcp`.

use std::collections::VecDeque;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::Value;
use tokio::sync::Mutex;

use grdr_llm_proto::compression::parse_content_encoding_header;
use grdr_llm_proto::stream::{SseFrame, SseLineDecoder};
use grdr_llm_proto::strict_json::MAX_SSE_EVENT_BYTES;
use grdr_mcp_proto::{McpMethod, parse_mcp_request, parse_strict_mcp_json};

use crate::decision::AsyncDecisionSource;
use crate::transport::{McpBrokerService, filter_child_tools_list_response};

const MAX_SSE_STREAM_BYTES: usize = 16 * 1024 * 1024;
const SSE_CHUNK_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

struct SseFilterState<S: AsyncDecisionSource + 'static> {
    service: Arc<Mutex<McpBrokerService<S>>>,
    resp: reqwest::Response,
    decoder: SseLineDecoder,
    total_bytes: usize,
    pending_out: VecDeque<Bytes>,
    done: bool,
}

pub(crate) fn reject_non_identity_encoding(
    headers: &reqwest::header::HeaderMap,
) -> Result<(), String> {
    let Some(hdr) = headers.get("content-encoding") else {
        return Ok(());
    };
    let enc_str = hdr
        .to_str()
        .map_err(|_| "GRDR-MCP-0007: non-ASCII upstream Content-Encoding header".to_string())?;
    let encodings = parse_content_encoding_header(enc_str)
        .map_err(|e| format!("GRDR-MCP-0007: upstream Content-Encoding rejected: {e}"))?;
    if !encodings.is_empty() {
        return Err("GRDR-MCP-0007: compressed upstream MCP response forbidden".to_string());
    }
    Ok(())
}

pub(crate) fn stream_upstream_sse<S: AsyncDecisionSource + 'static>(
    service: Arc<Mutex<McpBrokerService<S>>>,
    resp: reqwest::Response,
) -> Response {
    let status = resp.status();
    let state = SseFilterState {
        service,
        resp,
        decoder: SseLineDecoder::new(MAX_SSE_EVENT_BYTES),
        total_bytes: 0,
        pending_out: VecDeque::new(),
        done: false,
    };
    let stream = futures_util::stream::unfold(state, |mut st| async move {
        loop {
            if let Some(next_chunk) = st.pending_out.pop_front() {
                return Some((Ok::<Bytes, io::Error>(next_chunk), st));
            }
            if st.done {
                return None;
            }
            let chunk_res = tokio::time::timeout(SSE_CHUNK_IDLE_TIMEOUT, st.resp.chunk()).await;
            let bytes = match chunk_res {
                Err(_) => {
                    st.done = true;
                    return Some((
                        Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "upstream MCP SSE chunk idle timeout",
                        )),
                        st,
                    ));
                }
                Ok(Err(err)) => {
                    st.done = true;
                    return Some((Err(io::Error::other(err.to_string())), st));
                }
                Ok(Ok(Some(b))) => b,
                Ok(Ok(None)) => {
                    st.done = true;
                    match st.decoder.finish() {
                        Ok(Some(tail)) => {
                            if let Err(err) =
                                push_filtered_frame(&st.service, tail, &mut st.pending_out).await
                            {
                                return Some((Err(err), st));
                            }
                            continue;
                        }
                        Ok(None) => return None,
                        Err(err) => {
                            return Some((
                                Err(io::Error::new(io::ErrorKind::InvalidData, err.to_string())),
                                st,
                            ));
                        }
                    }
                }
            };
            st.total_bytes = st.total_bytes.saturating_add(bytes.len());
            if st.total_bytes > MAX_SSE_STREAM_BYTES {
                st.done = true;
                return Some((
                    Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "upstream MCP SSE exceeded total byte limit",
                    )),
                    st,
                ));
            }
            let frames = match st.decoder.push_chunk(&bytes) {
                Ok(f) => f,
                Err(err) => {
                    st.done = true;
                    return Some((
                        Err(io::Error::new(io::ErrorKind::InvalidData, err.to_string())),
                        st,
                    ));
                }
            };
            for frame in frames {
                if let Err(err) = push_filtered_frame(&st.service, frame, &mut st.pending_out).await
                {
                    st.done = true;
                    return Some((Err(err), st));
                }
            }
        }
    });
    Response::builder()
        .status(status)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

async fn push_filtered_frame<S: AsyncDecisionSource>(
    service: &Arc<Mutex<McpBrokerService<S>>>,
    frame: SseFrame,
    pending_out: &mut VecDeque<Bytes>,
) -> Result<(), io::Error> {
    let filtered_data = if !frame.data.trim().is_empty() && !frame.is_done {
        let val = parse_strict_mcp_json(&frame.data).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("GRDR-MCP-0006: strict SSE JSON-RPC parse rejected: {e}"),
            )
        })?;
        match val {
            Value::Object(_) => mediate_single_sse_rpc_item(service, &val).await?,
            Value::Array(items) => {
                let mut out_items = Vec::with_capacity(items.len());
                for item in &items {
                    if !item.is_object() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "GRDR-MCP-0006: SSE JSON-RPC batch element must be object",
                        ));
                    }
                    let item_out = mediate_single_sse_rpc_item(service, item).await?;
                    let parsed_out = parse_strict_mcp_json(&item_out)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                    out_items.push(parsed_out);
                }
                serde_json::to_string(&out_items)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "GRDR-MCP-0006: SSE JSON-RPC payload must be object or array",
                ));
            }
        }
    } else {
        frame.data
    };
    let mut out = String::new();
    if let Some(ev) = frame.event {
        out.push_str("event: ");
        out.push_str(&ev);
        out.push('\n');
    }
    if let Some(id) = frame.id {
        out.push_str("id: ");
        out.push_str(&id);
        out.push('\n');
    }
    if let Some(retry) = frame.retry_ms {
        out.push_str(&format!("retry: {retry}\n"));
    }
    if frame.is_done {
        out.push_str("data: [DONE]\n");
    } else {
        for line in filtered_data.split('\n') {
            out.push_str("data: ");
            out.push_str(line.trim_end_matches('\r'));
            out.push('\n');
        }
    }
    out.push('\n');
    pending_out.push_back(Bytes::from(out));
    Ok(())
}

async fn mediate_single_sse_rpc_item<S: AsyncDecisionSource>(
    service: &Arc<Mutex<McpBrokerService<S>>>,
    item: &Value,
) -> Result<String, io::Error> {
    let raw_item = serde_json::to_string(item)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let has_method = item.get("method").and_then(Value::as_str).is_some();
    if has_method {
        let req = parse_mcp_request(&raw_item).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("GRDR-MCP-0006: invalid MCP JSON-RPC SSE request: {e}"),
            )
        })?;
        if req.method == McpMethod::ElicitationCreate
            && req
                .arguments
                .get("mode")
                .and_then(Value::as_str)
                .unwrap_or("form")
                != "url"
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "GRDR-MCP-0003: non-URL MCP elicitation/create rejected in SSE stream",
            ));
        }
        let has_id = item.get("id").is_some_and(|v| !v.is_null());
        if has_id
            && matches!(
                req.method,
                McpMethod::RootsList
                    | McpMethod::SamplingCreateMessage
                    | McpMethod::ElicitationCreate
                    | McpMethod::ResourcesRead
                    | McpMethod::PromptsGet
                    | McpMethod::ToolsCall
            )
        {
            let mediated = {
                let mut guard = service.lock().await;
                let rev = guard.default_revision;
                guard.handle_parsed_request(&req, rev).await
            };
            match mediated {
                Ok(None) => {}
                Ok(Some(_)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!(
                            "GRDR-MCP-0003: server-initiated MCP SSE method {:?} denied by policy",
                            req.method
                        ),
                    ));
                }
                Err(err) => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!("GRDR-MCP-0003: server-initiated MCP SSE mediation failed: {err}"),
                    ));
                }
            }
        }
        return Ok(raw_item);
    }
    let mut guard = service.lock().await;
    filter_child_tools_list_response(&mut *guard, &raw_item)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}
