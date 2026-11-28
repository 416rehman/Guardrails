// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use axum::Json;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};

use grdr_model::proto_conv::{
    approval_to_proto, deployment_key_to_proto, integration_to_proto, kill_switch_to_proto,
    proto_to_finding_lifecycle, proto_to_kill_action, proto_to_kill_scope,
};
use grdr_model::{
    CreateDeploymentKeyRequest as ModelCreateKeyReq, DecideApprovalInput, GrantScope, KillAction,
    KillScope, KillSwitchInput, UpdateFindingInput,
};
use grdr_proto::api::inventory::CreateDeploymentKeyRequest;
use grdr_proto::api::response::{
    DecideApprovalRequest, SetKillSwitchRequest, UpdateFindingRequest,
};
use grdr_proto::common::CollectionKind;

use crate::auth::AuthContext;
use crate::store::AppState;

use super::super::gitops::{GitopsStore, api_error_json_response};
use super::authz::{AssuranceRule, RestPolicy, authorize_rest};
use super::policy_rest::bad_arg;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RestKillSwitchBody {
    pub action: Value,
    pub scope: Value,
    #[serde(default, alias = "target_id")]
    pub target_id: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default, alias = "duration_minutes")]
    pub duration_minutes: Option<i64>,
}

pub async fn get_kill_switch(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    if let Err(err) = authorize_rest(&auth, RestPolicy::read("response:read")) {
        return api_error_json_response(&err);
    }
    let ks = state.inner.read().await.kill_switch.clone();
    Json(json!({ "killSwitch": kill_switch_to_proto(&ks) })).into_response()
}

pub async fn put_kill_switch(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(raw): Json<Value>,
) -> Response {
    if let Err(err) = authorize_rest(
        &auth,
        RestPolicy::human_write("response:kill", AssuranceRule::Confirmed),
    ) {
        return api_error_json_response(&err);
    }
    let input = if let Ok(proto_req) = serde_json::from_value::<SetKillSwitchRequest>(raw.clone())
        && let (Some(action), Some(scope)) = (
            proto_to_kill_action(proto_req.action),
            proto_to_kill_scope(proto_req.scope),
        ) {
        KillSwitchInput {
            action,
            scope,
            target_id: proto_req.target_id,
            reason: proto_req.reason,
            duration_minutes: proto_req.duration_minutes,
        }
    } else {
        let Ok(body) = serde_json::from_value::<RestKillSwitchBody>(raw) else {
            return bad_arg("Invalid kill-switch JSON payload");
        };
        let Some(action) = parse_kill_action(&body.action) else {
            return bad_arg("Missing or invalid kill-switch action");
        };
        let Some(scope) = parse_kill_scope(&body.scope) else {
            return bad_arg("Missing or invalid kill-switch scope");
        };
        KillSwitchInput {
            action,
            scope,
            target_id: body.target_id,
            reason: body.reason,
            duration_minutes: body.duration_minutes,
        }
    };
    match state.set_kill_switch(input).await {
        Ok(ks) => {
            state.bump_revision(CollectionKind::KillSwitch);
            state.bump_revision(CollectionKind::AuditEvents);
            Json(json!({ "killSwitch": kill_switch_to_proto(&ks) })).into_response()
        }
        Err(err) => api_error_json_response(&err.into()),
    }
}

pub async fn update_finding(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    Json(req): Json<UpdateFindingRequest>,
) -> Response {
    if let Err(err) = authorize_rest(
        &auth,
        RestPolicy::human_write("response:write", AssuranceRule::None),
    ) {
        return api_error_json_response(&err);
    }
    let Some(lifecycle) = proto_to_finding_lifecycle(req.lifecycle) else {
        return bad_arg("Invalid finding lifecycle");
    };
    match state
        .update_finding(
            &id,
            UpdateFindingInput {
                lifecycle,
                note: req.note,
            },
        )
        .await
    {
        Ok(finding) => {
            state.bump_revision(CollectionKind::Findings);
            Json(json!({ "finding": finding })).into_response()
        }
        Err(err) => api_error_json_response(&err.into()),
    }
}

pub async fn decide_approval(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(action_path): Path<String>,
    Json(req): Json<DecideApprovalRequest>,
) -> Response {
    let Some((id, action)) = action_path.split_once(':') else {
        return (StatusCode::NOT_FOUND, Json(json!({ "code": "not_found" }))).into_response();
    };
    if action != "decide" {
        return (StatusCode::NOT_FOUND, Json(json!({ "code": "not_found" }))).into_response();
    }
    if let Err(err) = authorize_rest(
        &auth,
        RestPolicy::human_write("response:approve", AssuranceRule::Confirmed),
    ) {
        return api_error_json_response(&err);
    }
    match state
        .decide_approval(
            id,
            DecideApprovalInput {
                approve: req.approve,
                scope: Some(GrantScope::Once),
                note: req.note,
                actor: Some(auth.principal_id),
            },
        )
        .await
    {
        Ok(approval) => Json(json!({ "approval": approval_to_proto(&approval) })).into_response(),
        Err(err) => api_error_json_response(&err.into()),
    }
}

pub async fn list_integrations(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    if let Err(err) = authorize_rest(&auth, RestPolicy::read("integrations:read")) {
        return api_error_json_response(&err);
    }
    let integrations: Vec<_> = state
        .list_integrations()
        .await
        .iter()
        .map(integration_to_proto)
        .collect();
    Json(json!({ "integrations": integrations })).into_response()
}

pub async fn create_deployment_key(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<CreateDeploymentKeyRequest>,
) -> Response {
    if let Err(err) = authorize_rest(
        &auth,
        RestPolicy::human_write("keys:write", AssuranceRule::Confirmed),
    ) {
        return api_error_json_response(&err);
    }
    match state
        .create_deployment_key(ModelCreateKeyReq {
            label: req.label,
            wave: req.wave,
            install_profile: req.install_profile,
            max_uses: req.max_uses,
            ttl_days: req.ttl_days,
        })
        .await
    {
        Ok(out) => Json(json!({
            "key": deployment_key_to_proto(&out.key),
            "plaintextToken": out.plaintext_token,
        }))
        .into_response(),
        Err(err) => api_error_json_response(&err.into()),
    }
}

pub async fn delete_deployment_key(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Response {
    if let Err(err) = authorize_rest(
        &auth,
        RestPolicy::human_write("keys:write", AssuranceRule::Confirmed),
    ) {
        return api_error_json_response(&err);
    }
    match state.revoke_deployment_key(&id).await {
        Ok(key) => Json(json!({ "key": deployment_key_to_proto(&key) })).into_response(),
        Err(err) => api_error_json_response(&err.into()),
    }
}

pub async fn get_operation(
    Extension(gitops): Extension<GitopsStore>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Response {
    if let Err(err) = authorize_rest(&auth, RestPolicy::read("policy:read")) {
        return api_error_json_response(&err);
    }
    match gitops.get_operation(&auth, &id).await {
        Ok(Some(op)) => Json(json!({ "operation": op })).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "code": "not_found", "message": "Operation not found" })),
        )
            .into_response(),
        Err(err) => api_error_json_response(&err),
    }
}

pub async fn operation_action(
    Extension(gitops): Extension<GitopsStore>,
    Extension(auth): Extension<AuthContext>,
    Path(action_path): Path<String>,
) -> Response {
    let Some((id, action)) = action_path.split_once(':') else {
        return (StatusCode::NOT_FOUND, Json(json!({ "code": "not_found" }))).into_response();
    };
    if action != "cancel" {
        return (StatusCode::NOT_FOUND, Json(json!({ "code": "not_found" }))).into_response();
    }
    if let Err(err) = authorize_rest(
        &auth,
        RestPolicy::human_write("policy:write", AssuranceRule::Confirmed),
    ) {
        return api_error_json_response(&err);
    }
    match gitops.cancel_operation(&auth, id).await {
        Ok(op) => Json(json!({ "operation": op })).into_response(),
        Err(err) => api_error_json_response(&err),
    }
}

fn parse_kill_action(val: &Value) -> Option<KillAction> {
    if let Some(n) = val.as_i64().and_then(|v| i32::try_from(v).ok()) {
        return proto_to_kill_action(n);
    }
    match val.as_str()?.trim().to_ascii_lowercase().as_str() {
        "freeze" | "kill_action_freeze" => Some(KillAction::Freeze),
        "kill" | "kill_action_kill" => Some(KillAction::Kill),
        "release" | "kill_action_release" => Some(KillAction::Release),
        _ => None,
    }
}

fn parse_kill_scope(val: &Value) -> Option<KillScope> {
    if let Some(n) = val.as_i64().and_then(|v| i32::try_from(v).ok()) {
        return proto_to_kill_scope(n);
    }
    match val.as_str()?.trim().to_ascii_lowercase().as_str() {
        "session" | "kill_scope_session" => Some(KillScope::Session),
        "device" | "kill_scope_device" => Some(KillScope::Device),
        "organisation" | "organization" | "kill_scope_organisation" => {
            Some(KillScope::Organisation)
        }
        _ => None,
    }
}
