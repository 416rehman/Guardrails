// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::convert::Infallible;
use std::time::Duration;

use axum::body::Body;
use axum::extract::State;
use axum::http::Request;
use axum::response::Response;
use axum::response::sse::{Event, KeepAlive, Sse};
use futures_util::Stream;
use jiff::Timestamp;
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::BroadcastStream;

use grdr_model::proto_conv::{
    health_to_proto, key_to_proto, live_event_to_proto, overview_to_proto,
};
use grdr_model::{HealthResponse, ServerHealth};
use grdr_proto::api::overview::{
    ExportAuditJsonlRequest, ExportAuditJsonlResponse, ExportOcsfRequest, ExportOcsfResponse,
    GetHealthRequest, GetOverviewRequest, IssueLiveTicketRequest, IssueLiveTicketResponse,
    ListKeysRequest, ListKeysResponse,
};
use grdr_proto::common::CollectionKind;

use crate::exports::{build_audit_jsonl, build_ocsf_events};
use crate::rpc::{revision_for, run_rpc, run_rpc_ctx};
use crate::store::AppState;

pub async fn get_health(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc(
        "/grdr.api.overview.v1alpha1.OverviewService/GetHealth",
        state,
        request,
        |state, _req: GetHealthRequest| async move {
            let health = HealthResponse {
                status: ServerHealth::Healthy,
                version: env!("CARGO_PKG_VERSION").into(),
                storage_mode: state.backend.storage_mode(),
                timestamp: Timestamp::now(),
            };
            Ok((health_to_proto(&health), None))
        },
    )
    .await
}

pub async fn get_overview(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc(
        "/grdr.api.overview.v1alpha1.OverviewService/GetOverview",
        state,
        request,
        |state, _req: GetOverviewRequest| async move {
            let rev = revision_for(&state, CollectionKind::Overview, "overview");
            let overview = state.overview().await;
            let proto = overview_to_proto(&overview, Some(rev.clone()));
            Ok((proto, Some(rev)))
        },
    )
    .await
}

pub async fn list_keys(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc(
        "/grdr.api.overview.v1alpha1.OverviewService/ListKeys",
        state,
        request,
        |state, _req: ListKeysRequest| async move {
            let rev = revision_for(&state, CollectionKind::Keys, "keys");
            let keys = state.trusted_keys().iter().map(key_to_proto).collect();
            Ok((
                ListKeysResponse {
                    keys,
                    revision: Some(rev.clone()),
                },
                Some(rev),
            ))
        },
    )
    .await
}

pub async fn export_ocsf(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc(
        "/grdr.api.overview.v1alpha1.OverviewService/ExportOcsf",
        state,
        request,
        |state, _req: ExportOcsfRequest| async move {
            let guard = state.inner.read().await;
            let events = build_ocsf_events(&guard);
            let payload = serde_json::to_string_pretty(&events).unwrap_or_else(|_| "[]".into());
            Ok((
                ExportOcsfResponse {
                    filename: "guardrails-ocsf-1.9.json".into(),
                    content_type: "application/json".into(),
                    payload,
                },
                None,
            ))
        },
    )
    .await
}

pub async fn export_audit_jsonl(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc(
        "/grdr.api.overview.v1alpha1.OverviewService/ExportAuditJsonl",
        state,
        request,
        |state, _req: ExportAuditJsonlRequest| async move {
            let incidents = state.incidents().await;
            let guard = state.inner.read().await;
            let payload = build_audit_jsonl(&guard, &incidents);
            Ok((
                ExportAuditJsonlResponse {
                    filename: "guardrails-audit.jsonl".into(),
                    content_type: "application/x-ndjson".into(),
                    payload,
                },
                None,
            ))
        },
    )
    .await
}

pub async fn issue_live_ticket(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc_ctx(
        "/grdr.api.overview.v1alpha1.OverviewService/IssueLiveTicket",
        state,
        request,
        |state, auth, _req: IssueLiveTicketRequest| async move {
            let ticket = state.issue_live_ticket(auth)?;
            Ok((
                IssueLiveTicketResponse {
                    ticket,
                    expires_in_seconds: 30,
                },
                None,
            ))
        },
    )
    .await
}

pub async fn live_stream(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.live_tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|msg| match msg {
        Ok(event) => {
            let topic = event.topic.clone();
            let proto_ev = live_event_to_proto(&event);
            serde_json::to_string(&proto_ev)
                .ok()
                .map(|json| Ok(Event::default().event(topic).data(json)))
        }
        Err(_) => None,
    });
    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keepalive"),
    )
}
