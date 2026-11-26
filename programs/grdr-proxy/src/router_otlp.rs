// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Loopback OTLP HTTP route handlers enforcing Host verification, kill switch,
//! and fail-closed `decision_client.decide` gating prior to retention/export.

use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use grdr_model::Verdict;
use grdr_strings::sanitize_untrusted_text;

use crate::egress::{EgressGuardConfig, resolve_and_vet_target};
use crate::otlp::{MAX_OTLP_BODY_BYTES, OtlpSignalKind, SanitizedOtlpEvent, ingest_otlp_payload};
use crate::router::{MAX_RETAINED_OTLP_EVENTS, ProxyGatewayState};
use crate::router_http::denial_403;
use crate::sr39::validate_sr39_headers;
use crate::{ProxyDecisionClient, ProxyError};

pub(crate) async fn handle_otlp_traces<C: ProxyDecisionClient + 'static>(
    State(state): State<Arc<ProxyGatewayState<C>>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    handle_otlp(state, headers, OtlpSignalKind::Traces, body).await
}

pub(crate) async fn handle_otlp_logs<C: ProxyDecisionClient + 'static>(
    State(state): State<Arc<ProxyGatewayState<C>>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    handle_otlp(state, headers, OtlpSignalKind::Logs, body).await
}

pub(crate) async fn handle_otlp_metrics<C: ProxyDecisionClient + 'static>(
    State(state): State<Arc<ProxyGatewayState<C>>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    handle_otlp(state, headers, OtlpSignalKind::Metrics, body).await
}

async fn handle_otlp<C: ProxyDecisionClient + 'static>(
    state: Arc<ProxyGatewayState<C>>,
    headers: HeaderMap,
    signal: OtlpSignalKind,
    body: Body,
) -> Response {
    if state.is_globally_killed() {
        return denial_403(&ProxyError::SessionEgressCut("global-kill-switch".into()));
    }
    if let Err(err) = validate_sr39_headers(&headers, state.listener_port, false) {
        return denial_403(&err);
    }
    let raw_bytes = match to_bytes(body, MAX_OTLP_BODY_BYTES).await {
        Ok(b) => b,
        Err(_) => {
            return denial_403(&ProxyError::Sr39Rejected(
                "OTLP payload exceeds bounded limit or failed to read".into(),
            ));
        }
    };
    if raw_bytes.is_empty() || raw_bytes.len() > MAX_OTLP_BODY_BYTES {
        return denial_403(&ProxyError::Sr39Rejected(
            "OTLP body length out of allowed bounds".into(),
        ));
    }
    let event = match ingest_otlp_payload(&headers, signal, &raw_bytes) {
        Ok(ev) => ev,
        Err(err) => return denial_403(&err),
    };
    let attempt = event.attempt.clone();
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

    let ship_copy = event.clone();
    {
        let mut retained = state.otlp_events.lock().await;
        if retained.len() >= MAX_RETAINED_OTLP_EVENTS {
            drop(retained.pop_front());
        }
        retained.push_back(event);
    }
    if let Some(shipper) = state.otlp_shipper.lock().await.as_ref()
        && !shipper.try_enqueue(ship_copy)
    {
        tracing::debug!("OTLP upstream shipper queue full; dropping sanitized batch");
    }
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "accepted": true,
            "provenance": "claimed",
            "signal": signal.as_str(),
        })),
    )
        .into_response()
}

pub(crate) async fn send_sanitized_otlp_event(
    base_url: &str,
    host: &str,
    port: u16,
    egress_cfg: &EgressGuardConfig,
    event: &SanitizedOtlpEvent,
) -> Result<(), ProxyError> {
    let vetted = resolve_and_vet_target(host, port, egress_cfg).await?;
    let Some(&pinned_addr) = vetted.pinned_addrs.first() else {
        return Err(ProxyError::SsrfDenied(
            "OTLP collector SSRF guard resolved zero addresses".into(),
        ));
    };
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .resolve(&vetted.host, pinned_addr)
        .build()
        .map_err(|e| ProxyError::Transport(e.to_string()))?;

    let target = format!("{base_url}/v1/{}", event.signal.as_str());
    let body = serde_json::json!({
        "provenance": "claimed",
        "signal": event.signal.as_str(),
        "format": event.format.as_str(),
        "session_id": event.attempt.session_id,
        "agent_name": event.attempt.agent_name,
        "summary": event.attempt.summary,
        "sanitized_bytes": event.sanitized_bytes,
    });
    let resp = client
        .post(target)
        .json(&body)
        .send()
        .await
        .map_err(|e| ProxyError::Transport(e.to_string()))?;
    if resp.remote_addr() != Some(pinned_addr) {
        return Err(ProxyError::SsrfDenied(
            "OTLP collector remote_addr did not match pinned SSRF socket".into(),
        ));
    }
    if !resp.status().is_success() {
        return Err(ProxyError::Transport(format!(
            "OTLP collector returned HTTP {}",
            resp.status()
        )));
    }
    Ok(())
}
