// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! `McpRelay` fail-closed SSE server-initiated JSON-RPC mediation, D-30 egress cut / timeout
//! enforcement, SSE metadata preservation, and strict loopback-pinned OAuth 401 handling.

use std::collections::VecDeque;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::Value;
use tokio::sync::watch;
use url::Url;
use uuid::Uuid;

use grdr_llm_proto::stream::{SseFrame, SseLineDecoder};
use grdr_llm_proto::strict_json::MAX_SSE_EVENT_BYTES;
use grdr_mcp_proto::{
    McpAttemptContext, McpMethod, McpRequest, build_oauth_step_up_response, mcp_call_to_attempt,
    parse_mcp_request, parse_strict_mcp_json,
};
use grdr_model::{ProvenanceSource, Verdict};
use grdr_os_clock::{Clock, SystemClock};
use grdr_strings::sanitize_untrusted_text;

use crate::egress::{LoopbackUpstreamPolicy, resolve_and_vet_target};
use crate::mcp_relay_state::parse_www_auth_resource_metadata;
use crate::router::{MAX_UPSTREAM_RESPONSE_BYTES, ProxyGatewayState};
use crate::router_http::denial_403;
use crate::{ProxyDecisionClient, ProxyError};

const RELAY_SSE_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, PartialEq, Eq)]
enum RelayPumpStage {
    Active,
    Draining,
    Finished,
}

enum RelayStepOutcome {
    Continue,
    Emit(Result<Bytes, io::Error>),
    DrainOrEnd,
}

struct RelaySseState<C> {
    state: Arc<ProxyGatewayState<C>>,
    session_id: String,
    agent_name: String,
    route_id: String,
    resp: reqwest::Response,
    cut_rx: watch::Receiver<u64>,
    dec: SseLineDecoder,
    pending_out: VecDeque<Bytes>,
    total: usize,
    stage: RelayPumpStage,
}

pub(crate) async fn handle_relay_401<C: ProxyDecisionClient>(
    state: &ProxyGatewayState<C>,
    route_id: &str,
    upstream_resp: &reqwest::Response,
    req: Option<&McpRequest>,
) -> Response {
    let Some((meta_url, scope)) = upstream_resp
        .headers()
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .and_then(parse_www_auth_resource_metadata)
    else {
        return denial_403(&ProxyError::PolicyDenied(
            "McpRelay 401 missing valid Bearer resource_metadata".into(),
        ));
    };
    let Ok(parsed) = Url::parse(&meta_url) else {
        return denial_403(&ProxyError::SsrfDenied("invalid OAuth metadata URL".into()));
    };
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return denial_403(&ProxyError::SsrfDenied(
            "McpRelay OAuth metadata URL must not contain credentials, query, or fragment".into(),
        ));
    }
    let allow_http = state.egress_config.loopback_policy
        == LoopbackUpstreamPolicy::AllowExplicitLoopbackUpstreams;
    if parsed.scheme() != "https" && !(allow_http && parsed.scheme() == "http") {
        return denial_403(&ProxyError::SsrfDenied(
            "McpRelay OAuth metadata must use HTTPS".into(),
        ));
    }
    let Some(host) = parsed.host_str() else {
        return denial_403(&ProxyError::SsrfDenied("missing metadata host".into()));
    };
    let Some(port) = parsed.port_or_known_default() else {
        return denial_403(&ProxyError::SsrfDenied("missing metadata port".into()));
    };
    let vetted = match resolve_and_vet_target(host, port, &state.egress_config).await {
        Ok(v) => v,
        Err(err) => return denial_403(&err),
    };
    if parsed.scheme() == "http"
        && (vetted.pinned_addrs.is_empty()
            || !vetted
                .pinned_addrs
                .iter()
                .all(|addr| is_canonical_loopback_ip(addr.ip())))
    {
        return denial_403(&ProxyError::SsrfDenied(
            "HTTP OAuth metadata allowed only on canonical loopback address".into(),
        ));
    }
    let canonical_meta = parsed.as_str().to_owned();
    if let Err(err) = state
        .mcp_relay
        .lock()
        .await
        .bind_or_verify_oauth_metadata(route_id, &canonical_meta)
    {
        return denial_403(&err);
    }
    let req_id = req.and_then(|r| r.id.clone()).unwrap_or(Value::Null);
    let rpc =
        build_oauth_step_up_response(req_id, &canonical_meta, &scope, "OAuth step-up required");
    (StatusCode::OK, axum::Json(rpc)).into_response()
}

pub(crate) fn stream_filtered_relay_sse<C: ProxyDecisionClient + 'static>(
    state: Arc<ProxyGatewayState<C>>,
    session_id: String,
    agent_name: String,
    route_id: String,
    resp: reqwest::Response,
) -> Response {
    let status = resp.status();
    let cut_rx = state.cut_watch.subscribe();
    let pump = RelaySseState {
        state,
        session_id,
        agent_name,
        route_id,
        resp,
        cut_rx,
        dec: SseLineDecoder::new(MAX_SSE_EVENT_BYTES),
        pending_out: VecDeque::new(),
        total: 0,
        stage: RelayPumpStage::Active,
    };
    let stream = futures_util::stream::unfold(pump, pump_relay_sse);
    Response::builder()
        .status(status)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

async fn pump_relay_sse<C: ProxyDecisionClient + 'static>(
    mut st: RelaySseState<C>,
) -> Option<(Result<Bytes, io::Error>, RelaySseState<C>)> {
    if st.stage == RelayPumpStage::Finished {
        return None;
    }
    loop {
        if let Some(abort) = check_relay_egress_alive(&st.state, &st.session_id).await {
            st.stage = RelayPumpStage::Finished;
            return Some((Err(abort), st));
        }
        if let Some(next_chunk) = st.pending_out.pop_front() {
            return Some((Ok(next_chunk), st));
        }
        if st.stage == RelayPumpStage::Draining {
            return None;
        }
        let step = tokio::select! {
            _ = st.cut_rx.changed() => {
                if let Some(abort) = check_relay_egress_alive(&st.state, &st.session_id).await {
                    RelayStepOutcome::Emit(Err(abort))
                } else {
                    RelayStepOutcome::Continue
                }
            }
            chunk_res = tokio::time::timeout(RELAY_SSE_IDLE_TIMEOUT, st.resp.chunk()) => {
                handle_relay_sse_step(&mut st, chunk_res).await
            }
        };
        match step {
            RelayStepOutcome::Continue => {}
            RelayStepOutcome::Emit(item) => {
                if item.is_err() {
                    st.stage = RelayPumpStage::Finished;
                }
                return Some((item, st));
            }
            RelayStepOutcome::DrainOrEnd => {
                st.stage = RelayPumpStage::Draining;
            }
        }
    }
}

async fn handle_relay_sse_step<C: ProxyDecisionClient + 'static>(
    st: &mut RelaySseState<C>,
    chunk_res: Result<Result<Option<Bytes>, reqwest::Error>, tokio::time::error::Elapsed>,
) -> RelayStepOutcome {
    let bytes = match chunk_res {
        Err(_) => {
            return RelayStepOutcome::Emit(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "McpRelay SSE stream idle timeout",
            )));
        }
        Ok(Err(e)) => return RelayStepOutcome::Emit(Err(io::Error::other(e.to_string()))),
        Ok(Ok(None)) => match st.dec.finish() {
            Ok(Some(tail)) => {
                return match push_mediated_relay_frame(st, tail).await {
                    Ok(()) => RelayStepOutcome::DrainOrEnd,
                    Err(err) => RelayStepOutcome::Emit(Err(err)),
                };
            }
            Ok(None) => return RelayStepOutcome::DrainOrEnd,
            Err(e) => {
                return RelayStepOutcome::Emit(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("GRDR-PROXY-0006: malformed trailing McpRelay SSE frame: {e}"),
                )));
            }
        },
        Ok(Ok(Some(b))) => b,
    };

    st.total = st.total.saturating_add(bytes.len());
    if st.total > MAX_UPSTREAM_RESPONSE_BYTES {
        return RelayStepOutcome::Emit(Err(io::Error::new(
            io::ErrorKind::FileTooLarge,
            "McpRelay SSE stream exceeded bound",
        )));
    }
    let frames = match st.dec.push_chunk(&bytes) {
        Ok(f) => f,
        Err(e) => {
            return RelayStepOutcome::Emit(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                e.to_string(),
            )));
        }
    };
    for frame in frames {
        if let Err(err) = push_mediated_relay_frame(st, frame).await {
            return RelayStepOutcome::Emit(Err(err));
        }
    }
    RelayStepOutcome::Continue
}

async fn push_mediated_relay_frame<C: ProxyDecisionClient + 'static>(
    st: &mut RelaySseState<C>,
    frame: SseFrame,
) -> Result<(), io::Error> {
    let filtered_data = if !frame.data.trim().is_empty() && !frame.is_done {
        let val = parse_strict_mcp_json(&frame.data).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("GRDR-PROXY-0006: strict McpRelay SSE JSON rejected: {e}"),
            )
        })?;
        match val {
            Value::Object(_) => mediate_single_relay_rpc(st, &val).await?,
            Value::Array(items) => {
                let mut out_items = Vec::with_capacity(items.len());
                for item in &items {
                    if !item.is_object() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "GRDR-PROXY-0006: McpRelay SSE batch item must be object",
                        ));
                    }
                    let mediated_str = mediate_single_relay_rpc(st, item).await?;
                    let parsed = parse_strict_mcp_json(&mediated_str)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                    out_items.push(parsed);
                }
                serde_json::to_string(&out_items)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "GRDR-PROXY-0006: McpRelay SSE JSON payload must be object or array",
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
    st.pending_out.push_back(Bytes::from(out));
    Ok(())
}

async fn mediate_single_relay_rpc<C: ProxyDecisionClient + 'static>(
    st: &RelaySseState<C>,
    item: &Value,
) -> Result<String, io::Error> {
    let raw_item = serde_json::to_string(item)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let has_method = item.get("method").and_then(Value::as_str).is_some();
    if has_method {
        let req = parse_mcp_request(&raw_item).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("GRDR-PROXY-0006: invalid McpRelay SSE JSON-RPC request: {e}"),
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
                "GRDR-PROXY-0003: non-URL MCP elicitation/create rejected in McpRelay SSE",
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
            let now = SystemClock::new().now_wall().map_err(|e| {
                io::Error::other(format!("GRDR-PROXY-0002: clock unavailable: {e}"))
            })?;
            let ctx = McpAttemptContext {
                attempt_id: format!("att_{}", Uuid::now_v7().simple()),
                session_id: st.session_id.clone(),
                device_id: "dev-local".into(),
                device_name: "local-host".into(),
                agent_name: st.agent_name.clone(),
                server_name: st.route_id.clone(),
                timestamp: now,
            };
            let mut attempt = mcp_call_to_attempt(&req, &ctx)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            attempt.provenance = ProvenanceSource::Mediated;
            attempt.summary = sanitize_untrusted_text(&attempt.summary);
            let receipt = st
                .state
                .decision_client
                .decide(&attempt)
                .await
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!("GRDR-PROXY-0003: McpRelay SSE request policy failed closed: {e}"),
                    )
                })?;
            if receipt.verdict != Verdict::Allow {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "GRDR-PROXY-0003: server-initiated McpRelay SSE {:?} denied ({:?})",
                        req.method, receipt.verdict
                    ),
                ));
            }
        }
        return Ok(raw_item);
    }
    st.state
        .mcp_relay
        .lock()
        .await
        .filter_tools_list_json(&st.route_id, &raw_item)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

async fn check_relay_egress_alive<C: ProxyDecisionClient>(
    state: &ProxyGatewayState<C>,
    session_id: &str,
) -> Option<io::Error> {
    if state.is_globally_killed() || state.registry.lock().await.is_session_cut(session_id) {
        Some(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "GRDR-PROXY-0005: McpRelay egress killed mid-stream",
        ))
    } else {
        None
    }
}

fn is_canonical_loopback_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}
