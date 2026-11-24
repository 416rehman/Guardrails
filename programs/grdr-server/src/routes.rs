// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::convert::Infallible;
use std::path::PathBuf;
use std::time::Duration;

use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{StatusCode, header};
use axum::middleware;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post};
use axum::{Json, Router};
use futures_util::stream::Stream;
use jiff::Timestamp;
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::BroadcastStream;
use tower_http::services::{ServeDir, ServeFile};

use grdr_model::{
    ApprovalRequest, ArtifactEntry, AuditEntry, BatchEventsInput, CodedError, CreateRuleInput,
    DecideApprovalInput, DecideInput, DecisionReceipt, Device, DiscoveredAgent, Finding,
    HealthResponse, Incident, KillSwitchInput, KillSwitchState, McpServerEntry, OrgPrivacyConfig,
    OverviewResponse, PolicyPack, PolicyRule, ReplayRuleInput, ReplaySummary,
    SessionDetailResponse, SessionSummary, TrustedKeyInfo, UpdateFindingInput,
    UpdatePrivacyConfigInput, UpdateRuleInput, UpdateRuleModeInput, UserDetailResponse,
    UserProfile,
};

use crate::auth::{
    self, ServerSecurityConfig, require_device_or_operator_auth, require_operator_auth,
};
use crate::exports::{build_audit_jsonl, build_ocsf_events};
use crate::store::AppState;

type ApiResult<T> = Result<Json<T>, (StatusCode, Json<CodedError>)>;

#[cfg(test)]
pub fn build_router(state: AppState, web_dir: Option<PathBuf>) -> Router {
    build_router_with_security(state, web_dir, ServerSecurityConfig::default())
}

pub fn build_router_with_security(
    state: AppState,
    web_dir: Option<PathBuf>,
    security: ServerSecurityConfig,
) -> Router {
    let cors = auth::build_cors_layer(&security);

    let public_routes = Router::new().route("/api/v1/health", get(health));

    let device_routes = Router::new()
        .route("/api/v1/devices/checkin", post(device_checkin))
        .route("/api/v1/events/batch", post(ingest_batch))
        .layer(middleware::from_fn_with_state(
            security.clone(),
            require_device_or_operator_auth,
        ));

    let operator_routes = Router::new()
        .route("/api/v1/overview", get(overview))
        .route("/api/v1/users", get(list_users))
        .route("/api/v1/users/{id}", get(get_user))
        .route(
            "/api/v1/privacy/config",
            get(get_privacy_config).patch(update_privacy_config),
        )
        .route("/api/v1/devices", get(list_devices))
        .route("/api/v1/inventory/agents", get(list_agents))
        .route("/api/v1/inventory/mcp-servers", get(list_mcp_servers))
        .route("/api/v1/inventory/artifacts", get(list_artifacts))
        .route("/api/v1/sessions", get(list_sessions))
        .route("/api/v1/sessions/{id}", get(get_session))
        .route("/api/v1/decide", post(decide))
        .route("/api/v1/policies/packs", get(list_packs))
        .route("/api/v1/policies/rules", post(create_rule))
        .route(
            "/api/v1/policies/rules/{id}",
            patch(update_rule).delete(delete_rule),
        )
        .route("/api/v1/policies/rules/{id}/mode", patch(update_rule_mode))
        .route("/api/v1/policies/rules/{id}/replay", post(replay_rule))
        .route("/api/v1/approvals", get(list_approvals))
        .route("/api/v1/approvals/{id}/decide", post(decide_approval))
        .route("/api/v1/findings", get(list_findings))
        .route("/api/v1/findings/{id}", patch(update_finding))
        .route("/api/v1/incidents", get(list_incidents))
        .route(
            "/api/v1/kill-switch",
            get(get_kill_switch).post(post_kill_switch),
        )
        .route("/api/v1/audit", get(list_audit))
        .route("/api/v1/keys", get(list_keys))
        .route("/api/v1/exports/ocsf", get(export_ocsf))
        .route("/api/v1/exports/audit.jsonl", get(export_audit_jsonl))
        .route("/api/v1/live", get(live_stream))
        .layer(middleware::from_fn_with_state(
            security.clone(),
            require_operator_auth,
        ));

    let api = Router::new()
        .merge(public_routes)
        .merge(device_routes)
        .merge(operator_routes)
        .with_state(state)
        .layer(DefaultBodyLimit::max(security.max_body_bytes))
        .layer(cors);

    if let Some(dir) = web_dir
        && dir.join("index.html").is_file()
    {
        let serve = ServeDir::new(&dir).fallback(ServeFile::new(dir.join("index.html")));
        return api.fallback_service(serve);
    }

    api
}

fn err_response(err: CodedError) -> (StatusCode, Json<CodedError>) {
    let status = if err.code.ends_with("0401") {
        StatusCode::UNAUTHORIZED
    } else if err.code.ends_with("0404") {
        StatusCode::NOT_FOUND
    } else if err.code.ends_with("0409") {
        StatusCode::CONFLICT
    } else if err.code.starts_with("GRDR-STORE") {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::BAD_REQUEST
    };
    (status, Json(err))
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        storage_mode: state.storage_mode,
        timestamp: Timestamp::now(),
    })
}

async fn overview(State(state): State<AppState>) -> Json<OverviewResponse> {
    Json(state.overview().await)
}

async fn list_users(State(state): State<AppState>) -> Json<Vec<UserProfile>> {
    Json(state.users().await)
}

async fn get_user(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<UserDetailResponse> {
    state.user_detail(&id).await.map(Json).map_err(err_response)
}

async fn get_privacy_config(State(state): State<AppState>) -> Json<OrgPrivacyConfig> {
    Json(state.privacy_config().await)
}

async fn update_privacy_config(
    State(state): State<AppState>,
    Json(input): Json<UpdatePrivacyConfigInput>,
) -> ApiResult<OrgPrivacyConfig> {
    state
        .update_privacy_config(input)
        .await
        .map(Json)
        .map_err(err_response)
}

async fn list_artifacts(State(state): State<AppState>) -> Json<Vec<ArtifactEntry>> {
    Json(state.artifacts().await)
}

async fn list_devices(State(state): State<AppState>) -> Json<Vec<Device>> {
    let guard = state.inner.read().await;
    Json(guard.devices.clone())
}

async fn device_checkin(
    State(state): State<AppState>,
    Json(req): Json<grdr_model::DeviceCheckinRequest>,
) -> ApiResult<grdr_model::DeviceCheckinResponse> {
    state
        .checkin_device(req)
        .await
        .map(Json)
        .map_err(err_response)
}

async fn list_agents(State(state): State<AppState>) -> Json<Vec<DiscoveredAgent>> {
    let guard = state.inner.read().await;
    let agents = guard
        .devices
        .iter()
        .flat_map(|d| d.agents.iter().cloned())
        .collect();
    Json(agents)
}

async fn list_mcp_servers(State(state): State<AppState>) -> Json<Vec<McpServerEntry>> {
    let guard = state.inner.read().await;
    let servers = guard
        .devices
        .iter()
        .flat_map(|d| d.mcp_servers.iter().cloned())
        .collect();
    Json(servers)
}

async fn list_sessions(State(state): State<AppState>) -> Json<Vec<SessionSummary>> {
    Json(state.sessions().await)
}

async fn get_session(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<SessionDetailResponse> {
    state
        .session_detail(&id)
        .await
        .map(Json)
        .map_err(err_response)
}

async fn ingest_batch(
    State(state): State<AppState>,
    Json(batch): Json<BatchEventsInput>,
) -> ApiResult<grdr_model::BatchEventsResponse> {
    state
        .ingest_batch(batch)
        .await
        .map(Json)
        .map_err(err_response)
}

async fn decide(
    State(state): State<AppState>,
    Json(input): Json<DecideInput>,
) -> ApiResult<DecisionReceipt> {
    state
        .evaluate_and_record(input)
        .await
        .map(Json)
        .map_err(err_response)
}

async fn list_packs(State(state): State<AppState>) -> Json<Vec<PolicyPack>> {
    let guard = state.inner.read().await;
    Json(guard.packs.clone())
}

async fn create_rule(
    State(state): State<AppState>,
    Json(input): Json<CreateRuleInput>,
) -> ApiResult<PolicyRule> {
    state
        .create_rule(input)
        .await
        .map(Json)
        .map_err(err_response)
}

async fn update_rule(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(input): Json<UpdateRuleInput>,
) -> ApiResult<PolicyRule> {
    state
        .update_rule(&id, input)
        .await
        .map(Json)
        .map_err(err_response)
}

async fn delete_rule(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<PolicyRule> {
    state.delete_rule(&id).await.map(Json).map_err(err_response)
}

async fn update_rule_mode(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(input): Json<UpdateRuleModeInput>,
) -> ApiResult<PolicyRule> {
    state
        .update_rule_mode(&id, input)
        .await
        .map(Json)
        .map_err(err_response)
}

async fn replay_rule(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(input): Json<ReplayRuleInput>,
) -> ApiResult<ReplaySummary> {
    state
        .replay_rule(&id, input.candidate_mode)
        .await
        .map(Json)
        .map_err(err_response)
}

async fn list_approvals(State(state): State<AppState>) -> Json<Vec<ApprovalRequest>> {
    Json(state.list_approvals().await)
}

async fn decide_approval(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(input): Json<DecideApprovalInput>,
) -> ApiResult<ApprovalRequest> {
    state
        .decide_approval(&id, input)
        .await
        .map(Json)
        .map_err(err_response)
}

async fn list_findings(State(state): State<AppState>) -> Json<Vec<Finding>> {
    let guard = state.inner.read().await;
    Json(guard.findings.clone())
}

async fn list_incidents(State(state): State<AppState>) -> Json<Vec<Incident>> {
    Json(state.incidents().await)
}

async fn update_finding(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(input): Json<UpdateFindingInput>,
) -> ApiResult<Finding> {
    state
        .update_finding(&id, input)
        .await
        .map(Json)
        .map_err(err_response)
}

async fn get_kill_switch(State(state): State<AppState>) -> Json<KillSwitchState> {
    let guard = state.inner.read().await;
    Json(guard.kill_switch.clone())
}

async fn post_kill_switch(
    State(state): State<AppState>,
    Json(input): Json<KillSwitchInput>,
) -> ApiResult<KillSwitchState> {
    state
        .set_kill_switch(input)
        .await
        .map(Json)
        .map_err(err_response)
}

async fn list_audit(State(state): State<AppState>) -> Json<Vec<AuditEntry>> {
    let guard = state.inner.read().await;
    Json(guard.audit.clone())
}

async fn list_keys(State(state): State<AppState>) -> Json<Vec<TrustedKeyInfo>> {
    Json(state.trusted_keys())
}

async fn export_ocsf(State(state): State<AppState>) -> Response {
    let events = {
        let guard = state.inner.read().await;
        build_ocsf_events(&guard)
    };
    let mut resp = Json(events).into_response();
    if let Ok(val) = "attachment; filename=\"guardrails-ocsf-1.9.json\"".parse() {
        resp.headers_mut().insert(header::CONTENT_DISPOSITION, val);
    }
    resp
}

async fn export_audit_jsonl(State(state): State<AppState>) -> Response {
    let incidents = state.incidents().await;
    let body = {
        let guard = state.inner.read().await;
        build_audit_jsonl(&guard, &incidents)
    };
    let mut headers = axum::http::HeaderMap::new();
    if let Ok(ct) = "application/x-ndjson; charset=utf-8".parse() {
        headers.insert(header::CONTENT_TYPE, ct);
    }
    if let Ok(cd) = "attachment; filename=\"guardrails-audit.jsonl\"".parse() {
        headers.insert(header::CONTENT_DISPOSITION, cd);
    }
    (StatusCode::OK, headers, body).into_response()
}

async fn live_stream(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.live_tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|item| match item {
        Ok(live_event) => serde_json::to_string(&live_event)
            .ok()
            .map(|json| Ok(Event::default().event(&live_event.topic).data(json))),
        Err(_) => None,
    });
    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
}
