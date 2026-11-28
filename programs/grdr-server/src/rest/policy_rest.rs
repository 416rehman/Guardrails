// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use axum::Json;
use axum::extract::{Extension, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};

use grdr_model::proto_conv::{
    browser_policy_to_proto, pack_to_proto, proto_to_approval_grade, proto_to_mode,
    proto_to_rule_match, replay_to_proto, rule_to_proto,
};
use grdr_model::{
    CreateRuleInput, UpdateBrowserAppPolicyInput, UpdateRuleInput, UpdateRuleModeInput,
};
use grdr_proto::api::policy::{
    CreateRuleRequest, ReplayRuleRequest, UpdateBrowserPolicyRequest, UpdateRuleModeRequest,
    UpdateRuleRequest,
};
use grdr_proto::common::CollectionKind;

use crate::auth::AuthContext;
use crate::rpc::revision_for_ctx;
use crate::store::AppState;

use super::super::gitops::{GitopsStore, api_error_json_response};
use super::authz::{AssuranceRule, RestPolicy, authorize_rest};
use super::collections::{etag_not_modified, with_etag};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RestBrowserPolicyBody {
    #[serde(default)]
    pub mode: Option<Value>,
    #[serde(default, alias = "block_file_uploads")]
    pub block_file_uploads: Option<bool>,
    #[serde(default, alias = "block_secret_paste")]
    pub block_secret_paste: Option<bool>,
    #[serde(default, alias = "managed_extension_only")]
    pub managed_extension_only: Option<bool>,
}

pub async fn list_packs(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    headers: HeaderMap,
) -> Response {
    if let Err(err) = authorize_rest(&auth, RestPolicy::read("policy:read")) {
        return api_error_json_response(&err);
    }
    let rev = revision_for_ctx(&state, &auth, CollectionKind::Packs, "packs");
    if let Some(not_mod) = etag_not_modified(&headers, &rev) {
        return not_mod;
    }
    let guard = state.inner.read().await;
    let packs: Vec<_> = guard.packs.iter().map(pack_to_proto).collect();
    with_etag(
        (
            StatusCode::OK,
            Json(json!({ "packs": packs, "revision": rev })),
        )
            .into_response(),
        &rev,
    )
}

pub async fn list_browser_policies(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    if let Err(err) = authorize_rest(&auth, RestPolicy::read("policy:read")) {
        return api_error_json_response(&err);
    }
    let policies: Vec<_> = state
        .list_browser_policies()
        .await
        .iter()
        .map(browser_policy_to_proto)
        .collect();
    Json(json!({ "policies": policies })).into_response()
}

pub async fn update_browser_policy(
    State(state): State<AppState>,
    Extension(gitops): Extension<GitopsStore>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    Json(raw): Json<Value>,
) -> Response {
    if let Err(err) = authorize_rest(
        &auth,
        RestPolicy::human_write("policy:write", AssuranceRule::Confirmed),
    ) {
        return api_error_json_response(&err);
    }
    if let Err(err) = gitops.require_unlocked_for_direct_write(&auth).await {
        return api_error_json_response(&err);
    }
    let input = if let Ok(mut proto_req) =
        serde_json::from_value::<UpdateBrowserPolicyRequest>(raw.clone())
    {
        if proto_req.id.is_empty() {
            proto_req.id = id.clone();
        }
        UpdateBrowserAppPolicyInput {
            mode: proto_req.mode.and_then(proto_to_mode),
            block_file_uploads: proto_req.block_file_uploads,
            block_secret_paste: proto_req.block_secret_paste,
            managed_extension_only: proto_req.managed_extension_only,
        }
    } else {
        let Ok(body) = serde_json::from_value::<RestBrowserPolicyBody>(raw) else {
            return bad_arg("Invalid UpdateBrowserPolicy JSON");
        };
        let mode = match body.mode {
            Some(ref v) => match v.as_str().map(str::to_ascii_lowercase).as_deref() {
                Some("off" | "mode_off") => Some(grdr_model::Mode::Off),
                Some("watch" | "mode_watch") => Some(grdr_model::Mode::Watch),
                Some("ask" | "mode_ask") => Some(grdr_model::Mode::Ask),
                Some("block" | "mode_block") => Some(grdr_model::Mode::Block),
                _ => v
                    .as_i64()
                    .and_then(|n| i32::try_from(n).ok())
                    .and_then(proto_to_mode),
            },
            None => None,
        };
        UpdateBrowserAppPolicyInput {
            mode,
            block_file_uploads: body.block_file_uploads,
            block_secret_paste: body.block_secret_paste,
            managed_extension_only: body.managed_extension_only,
        }
    };
    match state.update_browser_policy(&id, input).await {
        Ok(updated) => {
            state.bump_revision(CollectionKind::BrowserPolicies);
            state.bump_revision(CollectionKind::AuditEvents);
            Json(json!({ "policy": browser_policy_to_proto(&updated) })).into_response()
        }
        Err(err) => api_error_json_response(&err.into()),
    }
}

pub async fn create_rule(
    State(state): State<AppState>,
    Extension(gitops): Extension<GitopsStore>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<CreateRuleRequest>,
) -> Response {
    if let Err(err) = authorize_rest(
        &auth,
        RestPolicy::human_write("policy:write", AssuranceRule::Confirmed),
    ) {
        return api_error_json_response(&err);
    }
    if let Err(err) = gitops.require_unlocked_for_direct_write(&auth).await {
        return api_error_json_response(&err);
    }
    let Some(mode) = proto_to_mode(req.mode) else {
        return bad_arg("Invalid mode");
    };
    let matcher = match req.matcher.map(proto_to_rule_match).transpose() {
        Ok(Some(m)) => m,
        Ok(None) => return bad_arg("Rule matcher is required"),
        Err(msg) => return bad_arg(&msg),
    };
    match state
        .create_rule(CreateRuleInput {
            pack_id: req.pack_id,
            title: req.title,
            description: req.description,
            mode,
            min_grade: req.min_grade.and_then(proto_to_approval_grade),
            matcher,
            reason_template: req.reason_template,
            cedar: req.cedar,
        })
        .await
    {
        Ok(rule) => {
            state.bump_revision(CollectionKind::Packs);
            Json(json!({ "rule": rule_to_proto(&rule) })).into_response()
        }
        Err(err) => api_error_json_response(&err.into()),
    }
}

pub async fn update_rule(
    State(state): State<AppState>,
    Extension(gitops): Extension<GitopsStore>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    Json(req): Json<UpdateRuleRequest>,
) -> Response {
    if let Err(err) = authorize_rest(
        &auth,
        RestPolicy::human_write("policy:write", AssuranceRule::Confirmed),
    ) {
        return api_error_json_response(&err);
    }
    if let Err(err) = gitops.require_unlocked_for_direct_write(&auth).await {
        return api_error_json_response(&err);
    }
    let matcher = match req.matcher.map(proto_to_rule_match).transpose() {
        Ok(m) => m,
        Err(msg) => return bad_arg(&msg),
    };
    match state
        .update_rule(
            &id,
            UpdateRuleInput {
                title: req.title,
                description: req.description,
                mode: req.mode.and_then(proto_to_mode),
                min_grade: req.min_grade.and_then(proto_to_approval_grade),
                matcher,
                reason_template: req.reason_template,
                cedar: req.cedar,
                actor: Some(auth.principal_id),
            },
        )
        .await
    {
        Ok(rule) => {
            state.bump_revision(CollectionKind::Packs);
            Json(json!({ "rule": rule_to_proto(&rule) })).into_response()
        }
        Err(err) => api_error_json_response(&err.into()),
    }
}

pub async fn delete_rule(
    State(state): State<AppState>,
    Extension(gitops): Extension<GitopsStore>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Response {
    if let Err(err) = authorize_rest(
        &auth,
        RestPolicy::human_write("policy:write", AssuranceRule::Confirmed),
    ) {
        return api_error_json_response(&err);
    }
    if let Err(err) = gitops.require_unlocked_for_direct_write(&auth).await {
        return api_error_json_response(&err);
    }
    match state.delete_rule(&id).await {
        Ok(rule) => {
            state.bump_revision(CollectionKind::Packs);
            Json(json!({ "deleted": true, "id": rule.id })).into_response()
        }
        Err(err) => api_error_json_response(&err.into()),
    }
}

pub async fn rule_action(
    State(state): State<AppState>,
    Extension(gitops): Extension<GitopsStore>,
    Extension(auth): Extension<AuthContext>,
    Path(action_path): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let Some((id, action)) = action_path.split_once(':') else {
        return (StatusCode::NOT_FOUND, Json(json!({ "code": "not_found" }))).into_response();
    };
    match action {
        "mode" => {
            if let Err(err) = authorize_rest(
                &auth,
                RestPolicy::human_write("policy:write", AssuranceRule::Confirmed),
            ) {
                return api_error_json_response(&err);
            }
            if let Err(err) = gitops.require_unlocked_for_direct_write(&auth).await {
                return api_error_json_response(&err);
            }
            let Ok(req) = serde_json::from_slice::<UpdateRuleModeRequest>(&body) else {
                return bad_arg("Invalid UpdateRuleModeRequest JSON");
            };
            let Some(mode) = proto_to_mode(req.mode) else {
                return bad_arg("Invalid mode");
            };
            match state
                .update_rule_mode(
                    id,
                    UpdateRuleModeInput {
                        mode,
                        actor: Some(auth.principal_id),
                        replay_confirmed: req.replay_confirmed,
                    },
                )
                .await
            {
                Ok(rule) => {
                    state.bump_revision(CollectionKind::Packs);
                    Json(json!({ "rule": rule_to_proto(&rule) })).into_response()
                }
                Err(err) => api_error_json_response(&err.into()),
            }
        }
        "replay" => {
            if let Err(err) = authorize_rest(&auth, RestPolicy::read("policy:read")) {
                return api_error_json_response(&err);
            }
            let Ok(req) = serde_json::from_slice::<ReplayRuleRequest>(&body) else {
                return bad_arg("Invalid ReplayRuleRequest JSON");
            };
            let Some(candidate_mode) = proto_to_mode(req.candidate_mode) else {
                return bad_arg("Invalid candidate_mode");
            };
            match state.replay_rule(id, candidate_mode).await {
                Ok(sum) => Json(json!({ "summary": replay_to_proto(&sum) })).into_response(),
                Err(err) => api_error_json_response(&err.into()),
            }
        }
        _ => (StatusCode::NOT_FOUND, Json(json!({ "code": "not_found" }))).into_response(),
    }
}

pub(crate) fn bad_arg(msg: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "code": "invalid_argument", "message": msg })),
    )
        .into_response()
}
