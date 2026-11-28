// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

pub mod binding;
pub mod binding_verify;
pub mod diff;
pub mod lifecycle;
pub mod operations;
pub mod simulate;
pub mod store;
pub mod types;

#[cfg(test)]
mod tests;

use axum::extract::{Extension, Path, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{Value, json};

use crate::auth::{AuthContext, AuthLayerState};
use crate::connect_error::{ApiError, WireEncoding, encode_connect_error};
use crate::routes::rest::authz::{ActorRule, AssuranceRule, PlaneRule, RestPolicy, authorize_rest};
use crate::store::AppState;

pub use store::GitopsStore;
pub use types::{
    ApproveChangeRequest, CreatePolicyChangeRequest, DenyChangeRequest, EditAnywayRequest,
    PolicyChangeState, ReconcileBundleRequest, UpsertGitopsBindingRequest,
};

pub fn gitops_router() -> Router<AppState> {
    Router::new()
        .route("/policy-changes", get(list_changes).post(create_change))
        .route(
            "/policy-changes/{id}",
            get(get_change).post(dispatch_change_action),
        )
        .route(
            "/gitops-binding",
            get(get_binding)
                .put(upsert_binding)
                .post(dispatch_binding_action),
        )
        .route("/gitops-binding:edit-anyway", post(edit_anyway))
        .route("/gitops-binding:reconcile", post(reconcile_bundle))
        .route("/gitops-bundle", get(export_bundle))
}

pub async fn enforce_gitops_lock_middleware(
    Extension(gitops): Extension<GitopsStore>,
    request: Request,
    next: Next,
) -> Response {
    let Some(auth) = request.extensions().get::<AuthContext>().cloned() else {
        let err = ApiError::unauthenticated(
            "Authentication context required before policy mutation.",
            "Provide a valid console bearer token.",
        );
        return encode_connect_error(WireEncoding::Json, "gitops-lock", &err);
    };
    if let Err(err) = gitops.require_unlocked_for_direct_write(&auth).await {
        return encode_connect_error(WireEncoding::Json, "gitops-lock", &err);
    }
    next.run(request).await
}

pub fn api_error_json_response(err: &ApiError) -> Response {
    encode_connect_error(WireEncoding::Json, "rest-gitops", err)
}

async fn list_changes(
    Extension(gitops): Extension<GitopsStore>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    if let Err(err) = authorize_rest(
        &auth,
        RestPolicy {
            scope: "policy:read",
            alt_scope: Some("mcp:propose"),
            assurance: AssuranceRule::None,
            actor: ActorRule::AnyAuthenticated,
            plane: PlaneRule::ConsoleOnly,
        },
    ) {
        return api_error_json_response(&err);
    }
    let changes = gitops.list_changes(&auth).await;
    (StatusCode::OK, Json(json!({ "changes": changes }))).into_response()
}

async fn get_change(
    Extension(gitops): Extension<GitopsStore>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Response {
    if let Err(err) = authorize_rest(
        &auth,
        RestPolicy {
            scope: "policy:read",
            alt_scope: Some("mcp:propose"),
            assurance: AssuranceRule::None,
            actor: ActorRule::AnyAuthenticated,
            plane: PlaneRule::ConsoleOnly,
        },
    ) {
        return api_error_json_response(&err);
    }
    match gitops.get_change(&auth, &id).await {
        Ok(change) => (StatusCode::OK, Json(json!({ "change": change }))).into_response(),
        Err(err) => api_error_json_response(&err),
    }
}

async fn create_change(
    Extension(gitops): Extension<GitopsStore>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<CreatePolicyChangeRequest>,
) -> Response {
    if let Err(err) = authorize_rest(
        &auth,
        RestPolicy {
            scope: "policy:write",
            alt_scope: Some("mcp:propose"),
            assurance: AssuranceRule::Confirmed,
            actor: ActorRule::AnyAuthenticated,
            plane: PlaneRule::ConsoleOnly,
        },
    ) {
        return api_error_json_response(&err);
    }
    match gitops.create_change(&auth, req, false).await {
        Ok(change) => (StatusCode::OK, Json(json!({ "change": change }))).into_response(),
        Err(err) => api_error_json_response(&err),
    }
}

async fn dispatch_change_action(
    State(state): State<AppState>,
    Extension(gitops): Extension<GitopsStore>,
    Extension(auth): Extension<AuthContext>,
    Path(action_path): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let Some((id, action)) = action_path.split_once(':') else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "code": "not_found", "message": "Unknown policy-change path" })),
        )
            .into_response();
    };
    let policy = match action {
        "check" | "simulate" => RestPolicy {
            scope: "policy:write",
            alt_scope: Some("mcp:propose"),
            assurance: AssuranceRule::None,
            actor: ActorRule::AnyAuthenticated,
            plane: PlaneRule::ConsoleOnly,
        },
        "apply" => RestPolicy {
            scope: "policy:write",
            alt_scope: Some("mcp:propose"),
            assurance: AssuranceRule::Confirmed,
            actor: ActorRule::AnyAuthenticated,
            plane: PlaneRule::ConsoleOnly,
        },
        "approve" => RestPolicy::human_write("policy:approve", AssuranceRule::Confirmed),
        "deny" | "cancel" | "resume" => RestPolicy {
            scope: "policy:write",
            alt_scope: Some("policy:approve"),
            assurance: AssuranceRule::Confirmed,
            actor: ActorRule::HumanOnly,
            plane: PlaneRule::ConsoleOnly,
        },
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "code": "not_found", "message": "Unsupported action" })),
            )
                .into_response();
        }
    };
    if let Err(err) = authorize_rest(&auth, policy) {
        return api_error_json_response(&err);
    }

    let result = match action {
        "check" => gitops.check_change(&state, &auth, id).await,
        "simulate" => gitops.simulate_change(&state, &auth, id).await,
        "apply" => gitops.apply_change(&state, &auth, id).await,
        "approve" => {
            let parsed: ApproveChangeRequest = if body.is_empty() {
                ApproveChangeRequest::default()
            } else {
                match serde_json::from_slice(&body) {
                    Ok(v) => v,
                    Err(e) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(json!({ "code": "invalid_argument", "message": e.to_string() })),
                        )
                            .into_response();
                    }
                }
            };
            gitops.approve_change(&state, &auth, id, parsed).await
        }
        "deny" => {
            let parsed: DenyChangeRequest = serde_json::from_slice(&body).unwrap_or_default();
            gitops.deny_change(&auth, id, parsed).await
        }
        "cancel" => gitops.cancel_change(&auth, id).await,
        "resume" => gitops.resume_change(&state, &auth, id).await,
        _ => unreachable_action_error(),
    };
    match result {
        Ok(change) => (StatusCode::OK, Json(json!({ "change": change }))).into_response(),
        Err(err) => api_error_json_response(&err),
    }
}

fn unreachable_action_error() -> Result<types::PolicyChangeRecord, ApiError> {
    Err(binding::failed_precondition(
        "UNKNOWN_ACTION",
        "Unsupported policy-change action.",
    ))
}

async fn get_binding(
    State(state): State<AppState>,
    Extension(gitops): Extension<GitopsStore>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    if let Err(err) = authorize_rest(&auth, RestPolicy::read("policy:read")) {
        return api_error_json_response(&err);
    }
    let binding = gitops.get_binding(&state, &auth).await;
    (StatusCode::OK, Json(json!({ "binding": binding }))).into_response()
}

async fn upsert_binding(
    State(state): State<AppState>,
    Extension(gitops): Extension<GitopsStore>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<UpsertGitopsBindingRequest>,
) -> Response {
    if let Err(err) = authorize_rest(
        &auth,
        RestPolicy::human_write("policy:write", AssuranceRule::Confirmed),
    ) {
        return api_error_json_response(&err);
    }
    match gitops.upsert_binding(&state, &auth, req).await {
        Ok(binding) => (StatusCode::OK, Json(json!({ "binding": binding }))).into_response(),
        Err(err) => api_error_json_response(&err),
    }
}

async fn dispatch_binding_action(
    State(state): State<AppState>,
    Extension(gitops): Extension<GitopsStore>,
    Extension(auth): Extension<AuthContext>,
    Extension(auth_state): Extension<AuthLayerState>,
    headers: HeaderMap,
    Json(val): Json<Value>,
) -> Response {
    if let Err(err) = authorize_rest(
        &auth,
        RestPolicy::human_write("policy:write", AssuranceRule::Confirmed),
    ) {
        return api_error_json_response(&err);
    }
    if val.get("bundle").is_some()
        && let Ok(req) = serde_json::from_value::<ReconcileBundleRequest>(val.clone())
    {
        return match gitops.reconcile_bundle(&state, &auth, req).await {
            Ok(binding) => (StatusCode::OK, Json(json!({ "binding": binding }))).into_response(),
            Err(err) => api_error_json_response(&err),
        };
    }
    match serde_json::from_value::<EditAnywayRequest>(val) {
        Ok(req) => match gitops
            .edit_anyway(&state, &auth, &auth_state.security, &headers, req)
            .await
        {
            Ok(binding) => (StatusCode::OK, Json(json!({ "binding": binding }))).into_response(),
            Err(err) => api_error_json_response(&err),
        },
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "code": "invalid_argument", "message": e.to_string() })),
        )
            .into_response(),
    }
}

async fn edit_anyway(
    State(state): State<AppState>,
    Extension(gitops): Extension<GitopsStore>,
    Extension(auth): Extension<AuthContext>,
    Extension(auth_state): Extension<AuthLayerState>,
    headers: HeaderMap,
    Json(req): Json<EditAnywayRequest>,
) -> Response {
    if let Err(err) = authorize_rest(
        &auth,
        RestPolicy::human_write("policy:write", AssuranceRule::Confirmed),
    ) {
        return api_error_json_response(&err);
    }
    match gitops
        .edit_anyway(&state, &auth, &auth_state.security, &headers, req)
        .await
    {
        Ok(binding) => (StatusCode::OK, Json(json!({ "binding": binding }))).into_response(),
        Err(err) => api_error_json_response(&err),
    }
}

async fn reconcile_bundle(
    State(state): State<AppState>,
    Extension(gitops): Extension<GitopsStore>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<ReconcileBundleRequest>,
) -> Response {
    if let Err(err) = authorize_rest(
        &auth,
        RestPolicy::human_write("policy:write", AssuranceRule::Confirmed),
    ) {
        return api_error_json_response(&err);
    }
    match gitops.reconcile_bundle(&state, &auth, req).await {
        Ok(binding) => (StatusCode::OK, Json(json!({ "binding": binding }))).into_response(),
        Err(err) => api_error_json_response(&err),
    }
}

async fn export_bundle(
    State(state): State<AppState>,
    Extension(gitops): Extension<GitopsStore>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    if let Err(err) = authorize_rest(&auth, RestPolicy::read("policy:read")) {
        return api_error_json_response(&err);
    }
    (
        StatusCode::OK,
        Json(gitops.export_bundle(&state, &auth).await),
    )
        .into_response()
}
