// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use axum::Json;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;

use grdr_model::proto_conv::{
    agent_to_proto, artifact_to_proto, attempt_to_proto, device_to_proto, mcp_to_proto,
    receipt_to_proto, session_to_proto, turn_to_proto, user_to_proto,
};
use grdr_proto::common::CollectionKind;

use crate::aip::collections::{
    AGENT_DEFAULT_ORDER, AGENT_FILTERS, AGENT_SORT, ARTIFACT_DEFAULT_ORDER, ARTIFACT_FILTERS,
    ARTIFACT_SORT, AgentInventoryRow, DEVICE_DEFAULT_ORDER, DEVICE_FILTERS, DEVICE_SORT,
    MCP_DEFAULT_ORDER, MCP_FILTERS, MCP_SORT, McpInventoryRow, SESSION_DEFAULT_ORDER,
    SESSION_FILTERS, SESSION_SORT,
};
use crate::auth::AuthContext;
use crate::rpc::{PageParams, page_collection_ctx, revision_for_ctx};
use crate::store::AppState;

use super::super::gitops::api_error_json_response;
use super::authz::{RestPolicy, authorize_rest};

#[derive(Debug, Clone, Deserialize, Default)]
pub struct CollectionQuery {
    #[serde(default)]
    pub page_size: Option<u32>,
    #[serde(default)]
    pub page_token: Option<String>,
    #[serde(default)]
    pub filter: Option<String>,
    #[serde(default)]
    pub order_by: Option<String>,
}

pub(crate) fn etag_not_modified(
    headers: &HeaderMap,
    rev: &grdr_proto::common::RevisionMeta,
) -> Option<Response> {
    let raw = rev.etag.trim_matches('"');
    let etag_val = format!("\"{raw}\"");
    if headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v == etag_val || v == raw)
    {
        let mut resp = StatusCode::NOT_MODIFIED.into_response();
        if let Ok(hv) = HeaderValue::from_str(&etag_val) {
            resp.headers_mut().insert(header::ETAG, hv);
        }
        return Some(resp);
    }
    None
}

pub(crate) fn with_etag(mut resp: Response, rev: &grdr_proto::common::RevisionMeta) -> Response {
    let raw = rev.etag.trim_matches('"');
    let etag_val = format!("\"{raw}\"");
    if let Ok(hv) = HeaderValue::from_str(&etag_val) {
        resp.headers_mut().insert(header::ETAG, hv);
    }
    resp
}

pub async fn get_health(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let rev = revision_for_ctx(&state, &default_sys_auth(), CollectionKind::Packs, "health");
    if let Some(not_mod) = etag_not_modified(&headers, &rev) {
        return not_mod;
    }
    let body = json!({
        "status": "SERVER_HEALTH_HEALTHY",
        "version": env!("CARGO_PKG_VERSION"),
        "timestamp": jiff::Timestamp::now().to_string(),
    });
    with_etag((StatusCode::OK, Json(body)).into_response(), &rev)
}

pub async fn get_overview(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    headers: HeaderMap,
) -> Response {
    if let Err(err) = authorize_rest(&auth, RestPolicy::read("overview:read")) {
        return api_error_json_response(&err);
    }
    let rev = revision_for_ctx(&state, &auth, CollectionKind::Packs, "overview");
    if let Some(not_mod) = etag_not_modified(&headers, &rev) {
        return not_mod;
    }
    let ov = state.overview().await;
    let body = json!({
        "totalDevices": ov.total_devices,
        "onlineDevices": ov.online_devices,
        "totalAgents": ov.total_agents,
        "totalMcpServers": ov.total_mcp_servers,
        "activeSessions": ov.active_sessions,
        "pendingApprovals": ov.pending_approvals,
        "openFindings": ov.open_findings,
        "openIncidents": ov.open_incidents,
        "revision": rev,
    });
    with_etag((StatusCode::OK, Json(body)).into_response(), &rev)
}

pub async fn list_devices(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    headers: HeaderMap,
    Query(q): Query<CollectionQuery>,
) -> Response {
    if let Err(err) = authorize_rest(&auth, RestPolicy::read("inventory:read")) {
        return api_error_json_response(&err);
    }
    let items = state.inner.read().await.devices.clone();
    match page_collection_ctx(
        &state,
        &auth,
        items,
        PageParams {
            page_size: q.page_size.unwrap_or(50),
            page_token: q.page_token.as_deref().unwrap_or(""),
            filter: q.filter.as_deref().unwrap_or(""),
            order_by: q.order_by.as_deref().unwrap_or(""),
        },
        crate::rpc::CollectionPageSpec {
            collection: CollectionKind::Devices,
            method: "ListDevices",
            allowed_filters: DEVICE_FILTERS,
            allowed_sort: DEVICE_SORT,
            default_order: DEVICE_DEFAULT_ORDER,
        },
    ) {
        Ok((paged, rev)) => {
            if let Some(not_mod) = etag_not_modified(&headers, &rev) {
                return not_mod;
            }
            let protos: Vec<_> = paged.items.iter().map(device_to_proto).collect();
            with_etag(
                (
                    StatusCode::OK,
                    Json(
                        json!({ "devices": protos, "pageInfo": paged.page_info, "revision": rev }),
                    ),
                )
                    .into_response(),
                &rev,
            )
        }
        Err(err) => api_error_json_response(&err),
    }
}

pub async fn list_agents(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<CollectionQuery>,
) -> Response {
    if let Err(err) = authorize_rest(&auth, RestPolicy::read("inventory:read")) {
        return api_error_json_response(&err);
    }
    let guard = state.inner.read().await;
    let mut rows = Vec::new();
    for dev in &guard.devices {
        for agent in &dev.agents {
            rows.push(AgentInventoryRow {
                composite_id: format!("{}:{}", dev.id, agent.id),
                device_id: dev.id.clone(),
                device_name: dev.hostname.clone(),
                agent: agent.clone(),
            });
        }
    }
    drop(guard);
    match page_collection_ctx(
        &state,
        &auth,
        rows,
        PageParams {
            page_size: q.page_size.unwrap_or(50),
            page_token: q.page_token.as_deref().unwrap_or(""),
            filter: q.filter.as_deref().unwrap_or(""),
            order_by: q.order_by.as_deref().unwrap_or(""),
        },
        crate::rpc::CollectionPageSpec {
            collection: CollectionKind::Agents,
            method: "ListAgents",
            allowed_filters: AGENT_FILTERS,
            allowed_sort: AGENT_SORT,
            default_order: AGENT_DEFAULT_ORDER,
        },
    ) {
        Ok((paged, rev)) => {
            let items: Vec<_> = paged
                .items
                .iter()
                .map(|r| {
                    json!({
                        "deviceId": r.device_id,
                        "deviceName": r.device_name,
                        "agent": agent_to_proto(&r.agent),
                    })
                })
                .collect();
            Json(json!({ "items": items, "pageInfo": paged.page_info, "revision": rev }))
                .into_response()
        }
        Err(err) => api_error_json_response(&err),
    }
}

pub async fn list_mcp_servers(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<CollectionQuery>,
) -> Response {
    if let Err(err) = authorize_rest(&auth, RestPolicy::read("inventory:read")) {
        return api_error_json_response(&err);
    }
    let guard = state.inner.read().await;
    let mut rows = Vec::new();
    for dev in &guard.devices {
        for server in &dev.mcp_servers {
            rows.push(McpInventoryRow {
                composite_id: format!("{}:{}:{}", dev.id, server.source_agent, server.name),
                device_id: dev.id.clone(),
                device_name: dev.hostname.clone(),
                server: server.clone(),
            });
        }
    }
    drop(guard);
    match page_collection_ctx(
        &state,
        &auth,
        rows,
        PageParams {
            page_size: q.page_size.unwrap_or(50),
            page_token: q.page_token.as_deref().unwrap_or(""),
            filter: q.filter.as_deref().unwrap_or(""),
            order_by: q.order_by.as_deref().unwrap_or(""),
        },
        crate::rpc::CollectionPageSpec {
            collection: CollectionKind::McpServers,
            method: "ListMcpServers",
            allowed_filters: MCP_FILTERS,
            allowed_sort: MCP_SORT,
            default_order: MCP_DEFAULT_ORDER,
        },
    ) {
        Ok((paged, rev)) => {
            let items: Vec<_> = paged
                .items
                .iter()
                .map(|r| {
                    json!({
                        "deviceId": r.device_id,
                        "deviceName": r.device_name,
                        "server": mcp_to_proto(&r.server),
                    })
                })
                .collect();
            Json(json!({ "items": items, "pageInfo": paged.page_info, "revision": rev }))
                .into_response()
        }
        Err(err) => api_error_json_response(&err),
    }
}

pub async fn list_artifacts(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<CollectionQuery>,
) -> Response {
    if let Err(err) = authorize_rest(&auth, RestPolicy::read("inventory:read")) {
        return api_error_json_response(&err);
    }
    let rows = state.artifacts().await;
    match page_collection_ctx(
        &state,
        &auth,
        rows,
        PageParams {
            page_size: q.page_size.unwrap_or(50),
            page_token: q.page_token.as_deref().unwrap_or(""),
            filter: q.filter.as_deref().unwrap_or(""),
            order_by: q.order_by.as_deref().unwrap_or(""),
        },
        crate::rpc::CollectionPageSpec {
            collection: CollectionKind::Artifacts,
            method: "ListArtifacts",
            allowed_filters: ARTIFACT_FILTERS,
            allowed_sort: ARTIFACT_SORT,
            default_order: ARTIFACT_DEFAULT_ORDER,
        },
    ) {
        Ok((paged, rev)) => {
            let items: Vec<_> = paged.items.iter().map(artifact_to_proto).collect();
            Json(json!({ "artifacts": items, "pageInfo": paged.page_info, "revision": rev }))
                .into_response()
        }
        Err(err) => api_error_json_response(&err),
    }
}

pub async fn list_sessions(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<CollectionQuery>,
) -> Response {
    if let Err(err) = authorize_rest(&auth, RestPolicy::read("activity:read")) {
        return api_error_json_response(&err);
    }
    let rows = state.sessions().await;
    match page_collection_ctx(
        &state,
        &auth,
        rows,
        PageParams {
            page_size: q.page_size.unwrap_or(50),
            page_token: q.page_token.as_deref().unwrap_or(""),
            filter: q.filter.as_deref().unwrap_or(""),
            order_by: q.order_by.as_deref().unwrap_or(""),
        },
        crate::rpc::CollectionPageSpec {
            collection: CollectionKind::Sessions,
            method: "ListSessions",
            allowed_filters: SESSION_FILTERS,
            allowed_sort: SESSION_SORT,
            default_order: SESSION_DEFAULT_ORDER,
        },
    ) {
        Ok((paged, rev)) => {
            let items: Vec<_> = paged.items.iter().map(session_to_proto).collect();
            Json(json!({ "sessions": items, "pageInfo": paged.page_info, "revision": rev }))
                .into_response()
        }
        Err(err) => api_error_json_response(&err),
    }
}

pub async fn get_session(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Response {
    if let Err(err) = authorize_rest(&auth, RestPolicy::read("activity:read")) {
        return api_error_json_response(&err);
    }
    match state.session_detail(&id).await {
        Ok(detail) => {
            let rev = revision_for_ctx(&state, &auth, CollectionKind::Sessions, &id);
            let attempts: Vec<_> = detail.attempts.iter().map(attempt_to_proto).collect();
            let receipts: Vec<_> = detail.receipts.iter().map(receipt_to_proto).collect();
            let turns: Vec<_> = detail.turns.iter().map(turn_to_proto).collect();
            Json(json!({
                "session": session_to_proto(&detail.session),
                "attempts": attempts,
                "receipts": receipts,
                "turns": turns,
                "user": detail.user.as_ref().map(user_to_proto),
                "revision": rev,
            }))
            .into_response()
        }
        Err(err) => api_error_json_response(&err.into()),
    }
}

fn default_sys_auth() -> AuthContext {
    AuthContext {
        principal_id: "public".into(),
        tenant_id: "default".into(),
        plane: crate::auth::AuthPlane::Console,
        scopes: Vec::new(),
        confirmation: crate::auth::ConfirmAssertion::None,
    }
}
