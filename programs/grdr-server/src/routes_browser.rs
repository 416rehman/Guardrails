// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;

use grdr_model::{
    BrowserAppPolicy, BrowserEvaluateRequest, BrowserEvaluateResponse, CodedError,
    UpdateBrowserAppPolicyInput,
};

use crate::store::AppState;

type BrowserApiResult<T> = Result<Json<T>, (StatusCode, Json<CodedError>)>;

pub(crate) async fn get_browser_policies(
    State(state): State<AppState>,
) -> Json<Vec<BrowserAppPolicy>> {
    Json(state.list_browser_policies().await)
}

pub(crate) async fn patch_browser_policy(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(input): Json<UpdateBrowserAppPolicyInput>,
) -> BrowserApiResult<BrowserAppPolicy> {
    state
        .update_browser_policy(&id, input)
        .await
        .map(Json)
        .map_err(|err| (StatusCode::NOT_FOUND, Json(err)))
}

pub(crate) async fn post_browser_evaluate(
    State(state): State<AppState>,
    Json(input): Json<BrowserEvaluateRequest>,
) -> BrowserApiResult<BrowserEvaluateResponse> {
    state
        .evaluate_browser(input)
        .await
        .map(Json)
        .map_err(|err| (StatusCode::NOT_FOUND, Json(err)))
}
