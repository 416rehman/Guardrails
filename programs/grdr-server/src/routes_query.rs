// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;

use grdr_model::{
    CodedError, EntitySchema, EntitySummaryInfo, QueryRequest, QuerySampleResponse,
    UserIntentDescriptor,
};

use crate::store::AppState;

type QueryApiResult<T> = Result<Json<T>, (StatusCode, Json<CodedError>)>;

pub(crate) async fn get_query_schema(State(state): State<AppState>) -> Json<Vec<EntitySchema>> {
    Json(state.query_schema(false).await)
}

pub(crate) async fn get_query_entities(
    State(state): State<AppState>,
) -> Json<Vec<EntitySummaryInfo>> {
    Json(state.query_entities(false).await)
}

pub(crate) async fn get_query_user_intent(
    State(state): State<AppState>,
) -> Json<UserIntentDescriptor> {
    Json(state.query_user_intent(false).await)
}

pub(crate) async fn post_query_sample(
    State(state): State<AppState>,
    Json(input): Json<QueryRequest>,
) -> QueryApiResult<QuerySampleResponse> {
    state
        .query_sample(input, false)
        .await
        .map(Json)
        .map_err(|err| (StatusCode::BAD_REQUEST, Json(err)))
}
