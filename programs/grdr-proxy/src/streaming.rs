// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Incremental bounded HTTP/SSE/AWS EventStream response streaming, split-chunk frame buffering,
//! SSE delta tool enforcement, 180s keepalive watchdog, and >100:1 decompression bomb rejection.

use std::collections::{BTreeSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::http::HeaderMap;
use axum::response::Response;
use futures_util::stream;

use grdr_llm_proto::bedrock_stream::decode_aws_eventstream_frames;
use grdr_llm_proto::schema::{ProviderFamily, ProviderSchemaRegistry};
use grdr_llm_proto::stream::LlmStreamInspector;
use grdr_llm_proto::strict_json::{MAX_JSON_DEPTH, MAX_SSE_EVENT_BYTES, parse_strict_json_bytes};

use crate::router::{MAX_UPSTREAM_RESPONSE_BYTES, ProxyGatewayState};
use crate::router_http::{denial_403, resolve_route_family};
use crate::streaming_policy::{
    UnaryDecompressArgs, build_safe_response, check_egress_alive, collect_json_tool_names,
    decompress_and_forward_unary, enforce_sse_deltas, enforce_streamed_tool_calls,
    inspect_and_decompress_request, parse_response_encodings,
};
use crate::{ProxyDecisionClient, ProxyError};

pub use crate::streaming_policy::MAX_DECOMPRESSION_RATIO;

pub const DEFAULT_SSE_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(180);
const MAX_AWS_FRAME_BUFFER_BYTES: usize = 1_048_576;
const MAX_SSE_FRAME_BUFFER_BYTES: usize = MAX_SSE_EVENT_BYTES * 2;

enum StreamInspectionMode {
    Plain,
    Sse {
        inspector: Option<LlmStreamInspector>,
        raw_event_buf: Vec<u8>,
    },
    AwsEventStream {
        buffer: Vec<u8>,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PumpStage {
    Active,
    Draining,
    Finished,
}

enum StepOutcome {
    Continue,
    Emit(Result<Bytes, std::io::Error>),
    DrainOrEnd,
}

struct StreamPumpState<C> {
    resp: reqwest::Response,
    state: Arc<ProxyGatewayState<C>>,
    session_id: String,
    route_id: String,
    cut_rx: tokio::sync::watch::Receiver<u64>,
    mode: StreamInspectionMode,
    pending_out: VecDeque<Bytes>,
    keepalive_interval: Duration,
    bytes_sent: usize,
    max_bytes: usize,
    stage: PumpStage,
}

pub fn inspect_and_decompress_request_body(
    headers: &HeaderMap,
    raw_body: &[u8],
) -> Result<Vec<u8>, ProxyError> {
    inspect_and_decompress_request(headers, raw_body)
}

pub async fn stream_upstream_response<C: ProxyDecisionClient + 'static>(
    state: Arc<ProxyGatewayState<C>>,
    session_id: String,
    route_id: String,
    provider: &str,
    upstream_resp: reqwest::Response,
) -> Response {
    stream_upstream_response_with_options(
        state,
        session_id,
        route_id,
        provider,
        upstream_resp,
        DEFAULT_SSE_KEEPALIVE_INTERVAL,
        MAX_UPSTREAM_RESPONSE_BYTES,
    )
    .await
}

pub async fn stream_upstream_response_with_options<C: ProxyDecisionClient + 'static>(
    state: Arc<ProxyGatewayState<C>>,
    session_id: String,
    route_id: String,
    provider: &str,
    upstream_resp: reqwest::Response,
    keepalive_interval: Duration,
    max_bytes: usize,
) -> Response {
    let status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();
    let content_type = resp_headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    let is_sse = content_type.contains("text/event-stream");
    let is_aws_eventstream = content_type.contains("application/vnd.amazon.eventstream");

    let encodings = match parse_response_encodings(&resp_headers) {
        Ok(enc) => enc,
        Err(err) => return denial_403(&err),
    };
    if !encodings.is_empty() && (is_sse || is_aws_eventstream) {
        return denial_403(&ProxyError::Sr39Rejected(
            "compressed SSE or AWS EventStream responses are forbidden".to_string(),
        ));
    }

    let family = provider_family_for_route(provider);
    if !encodings.is_empty() {
        let args = UnaryDecompressArgs {
            session_id,
            route_id,
            family,
            status,
            resp_headers,
            encodings,
            keepalive_interval,
            max_bytes,
            expect_json: content_type.contains("json"),
        };
        return decompress_and_forward_unary(state, upstream_resp, args).await;
    }

    let mode = if is_sse {
        StreamInspectionMode::Sse {
            inspector: family.map(LlmStreamInspector::new),
            raw_event_buf: Vec::new(),
        }
    } else if is_aws_eventstream {
        StreamInspectionMode::AwsEventStream { buffer: Vec::new() }
    } else {
        StreamInspectionMode::Plain
    };

    let cut_rx = state.cut_watch.subscribe();
    let pump = StreamPumpState {
        resp: upstream_resp,
        state,
        session_id,
        route_id,
        cut_rx,
        mode,
        pending_out: VecDeque::new(),
        keepalive_interval,
        bytes_sent: 0,
        max_bytes,
        stage: PumpStage::Active,
    };

    let body_stream = stream::unfold(pump, pump_next_frame);
    build_safe_response(status, &resp_headers, Body::from_stream(body_stream), true)
}

async fn pump_next_frame<C: ProxyDecisionClient + 'static>(
    mut st: StreamPumpState<C>,
) -> Option<(Result<Bytes, std::io::Error>, StreamPumpState<C>)> {
    if st.stage == PumpStage::Finished {
        return None;
    }
    loop {
        if let Some(abort_err) = check_egress_alive(&st.state, &st.session_id).await {
            st.stage = PumpStage::Finished;
            return Some((Err(abort_err), st));
        }
        if let Some(next_ready) = st.pending_out.pop_front() {
            return Some((Ok(next_ready), st));
        }
        if st.stage == PumpStage::Draining {
            return None;
        }
        let outcome = tokio::select! {
            _ = st.cut_rx.changed() => {
                if let Some(abort_err) = check_egress_alive(&st.state, &st.session_id).await {
                    StepOutcome::Emit(Err(abort_err))
                } else {
                    StepOutcome::Continue
                }
            }
            chunk_step = tokio::time::timeout(st.keepalive_interval, st.resp.chunk()) => {
                handle_stream_step(&mut st, chunk_step).await
            }
        };
        match outcome {
            StepOutcome::Continue => {}
            StepOutcome::Emit(item) => {
                if item.is_err() {
                    st.stage = PumpStage::Finished;
                }
                return Some((item, st));
            }
            StepOutcome::DrainOrEnd => {
                st.stage = PumpStage::Draining;
            }
        }
    }
}

async fn handle_stream_step<C: ProxyDecisionClient + 'static>(
    st: &mut StreamPumpState<C>,
    chunk_step: Result<Result<Option<Bytes>, reqwest::Error>, tokio::time::error::Elapsed>,
) -> StepOutcome {
    match chunk_step {
        Err(_) if matches!(st.mode, StreamInspectionMode::Sse { .. }) => {
            let ping = Bytes::from_static(b": keepalive\n\n");
            match account_bytes(&mut st.bytes_sent, ping.len(), st.max_bytes) {
                Ok(()) => StepOutcome::Emit(Ok(ping)),
                Err(err) => StepOutcome::Emit(Err(err)),
            }
        }
        Err(_) => StepOutcome::Emit(Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "upstream stream idle timeout",
        ))),
        Ok(Err(err)) => StepOutcome::Emit(Err(std::io::Error::other(err.to_string()))),
        Ok(Ok(None)) => match finish_stream_inspection(st).await {
            Ok(()) => StepOutcome::DrainOrEnd,
            Err(err) => StepOutcome::Emit(Err(err)),
        },
        Ok(Ok(Some(chunk))) => match inspect_and_queue_chunk(st, chunk).await {
            Ok(()) => StepOutcome::Continue,
            Err(err) => StepOutcome::Emit(Err(err)),
        },
    }
}

async fn finish_stream_inspection<C: ProxyDecisionClient + 'static>(
    st: &mut StreamPumpState<C>,
) -> Result<(), std::io::Error> {
    match &mut st.mode {
        StreamInspectionMode::Sse {
            inspector,
            raw_event_buf,
        } => {
            if let Some(insp) = inspector {
                if !raw_event_buf.is_empty() {
                    let deltas = insp.push_sse_chunk(raw_event_buf).map_err(|err| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("GRDR-PROXY-0006: malformed trailing SSE frame at EOF: {err}"),
                        )
                    })?;
                    enforce_sse_deltas(&st.state, &st.session_id, &st.route_id, &deltas).await?;
                }
                let tail = insp.finish_sse().map_err(|err| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("GRDR-PROXY-0006: malformed trailing SSE frame at EOF: {err}"),
                    )
                })?;
                enforce_sse_deltas(&st.state, &st.session_id, &st.route_id, tail.as_slice())
                    .await?;
            }
            if !raw_event_buf.is_empty() {
                st.pending_out
                    .push_back(Bytes::from(std::mem::take(raw_event_buf)));
            }
            Ok(())
        }
        StreamInspectionMode::AwsEventStream { buffer } if !buffer.is_empty() => {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "GRDR-PROXY-0006: truncated AWS EventStream frame at EOF",
            ))
        }
        _ => Ok(()),
    }
}

async fn inspect_and_queue_chunk<C: ProxyDecisionClient + 'static>(
    st: &mut StreamPumpState<C>,
    chunk: Bytes,
) -> Result<(), std::io::Error> {
    account_bytes(&mut st.bytes_sent, chunk.len(), st.max_bytes)?;
    match &mut st.mode {
        StreamInspectionMode::Plain => {
            st.pending_out.push_back(chunk);
            Ok(())
        }
        StreamInspectionMode::Sse {
            inspector,
            raw_event_buf,
        } => {
            let next_len = raw_event_buf
                .len()
                .checked_add(chunk.len())
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "SSE frame buffer overflow",
                    )
                })?;
            if next_len > MAX_SSE_FRAME_BUFFER_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "GRDR-PROXY-0006: SSE frame exceeded 2 MiB buffer bound",
                ));
            }
            raw_event_buf.extend_from_slice(&chunk);
            while let Some(end_idx) = find_sse_event_boundary(raw_event_buf) {
                let event_bytes: Vec<u8> = raw_event_buf.drain(..end_idx).collect();
                if let Some(insp) = inspector {
                    let deltas = if event_bytes.ends_with(b"\r") {
                        let mut normalized =
                            Vec::with_capacity(event_bytes.len().saturating_add(1));
                        normalized.extend_from_slice(&event_bytes);
                        normalized.push(b'\n');
                        insp.push_sse_chunk(&normalized)
                    } else {
                        insp.push_sse_chunk(&event_bytes)
                    }
                    .map_err(|err| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("GRDR-PROXY-0006: SSE chunk inspection rejected: {err}"),
                        )
                    })?;
                    if insp.has_unflushed_state() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "GRDR-PROXY-0006: SSE inspector retained unflushed state after event boundary",
                        ));
                    }
                    enforce_sse_deltas(&st.state, &st.session_id, &st.route_id, &deltas).await?;
                }
                st.pending_out.push_back(Bytes::from(event_bytes));
            }
            Ok(())
        }
        StreamInspectionMode::AwsEventStream { buffer } => {
            let next_buf_len = buffer.len().checked_add(chunk.len()).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "eventstream buffer overflow",
                )
            })?;
            if next_buf_len > MAX_AWS_FRAME_BUFFER_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "GRDR-PROXY-0006: AWS EventStream frame buffer exceeded limit",
                ));
            }
            buffer.extend_from_slice(&chunk);
            let (frames, consumed) =
                decode_aws_eventstream_frames(buffer, MAX_AWS_FRAME_BUFFER_BYTES).map_err(
                    |err| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("GRDR-PROXY-0006: AWS EventStream decode rejected: {err}"),
                        )
                    },
                )?;
            if consumed == 0 {
                return Ok(());
            }
            let validated_bytes: Vec<u8> = buffer.drain(..consumed).collect();
            let mut names = BTreeSet::new();
            for frame in frames {
                let is_json =
                    frame.content_type.contains("json") || frame.payload.first() == Some(&b'{');
                if is_json && !frame.payload.is_empty() {
                    let parsed = parse_strict_json_bytes(
                        &frame.payload,
                        MAX_AWS_FRAME_BUFFER_BYTES,
                        MAX_JSON_DEPTH,
                    )
                    .map_err(|err| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("GRDR-PROXY-0006: AWS EventStream JSON rejected: {err}"),
                        )
                    })?;
                    collect_json_tool_names(&parsed, 0, &mut names);
                }
            }
            if !names.is_empty() {
                enforce_streamed_tool_calls(&st.state, &st.session_id, &st.route_id, &names)
                    .await?;
            }
            st.pending_out.push_back(Bytes::from(validated_bytes));
            Ok(())
        }
    }
}

fn find_sse_event_boundary(buf: &[u8]) -> Option<usize> {
    let mut i = 0usize;
    let mut line_len = 0usize;
    while let Some(&b) = buf.get(i) {
        if b == b'\n' {
            let end = i.saturating_add(1);
            if line_len == 0 {
                return Some(end);
            }
            line_len = 0;
            i = end;
        } else if b == b'\r' {
            let next_pos = i.saturating_add(1);
            let Some(&next_b) = buf.get(next_pos) else {
                break;
            };
            let end = if next_b == b'\n' {
                i.saturating_add(2)
            } else {
                next_pos
            };
            if line_len == 0 {
                return Some(end);
            }
            line_len = 0;
            i = end;
        } else {
            line_len = line_len.saturating_add(1);
            i = i.saturating_add(1);
        }
    }
    None
}

fn account_bytes(sent: &mut usize, delta: usize, max_bytes: usize) -> Result<(), std::io::Error> {
    let next = sent.checked_add(delta).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "stream byte overflow")
    })?;
    if next > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::FileTooLarge,
            format!("streamed response exceeds {max_bytes} byte limit"),
        ));
    }
    *sent = next;
    Ok(())
}

fn provider_family_for_route(provider: &str) -> Option<ProviderFamily> {
    let registry = ProviderSchemaRegistry::default_embedded().ok()?;
    resolve_route_family(&registry, provider, None)
}
