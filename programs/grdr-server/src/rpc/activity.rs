// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use axum::body::Body;
use axum::extract::State;
use axum::http::Request;
use axum::response::Response;

use grdr_model::QueryRequest;
use grdr_model::proto_conv::{
    attempt_to_proto, query_sample_to_proto, receipt_to_proto, schema_list_to_proto,
    session_to_proto, turn_to_proto, user_intent_to_proto, user_to_proto,
};
use grdr_proto::api::activity::{
    EntitySummaryInfo, GetQueryEntitiesRequest, GetQueryEntitiesResponse, GetQuerySchemaRequest,
    GetQuerySchemaResponse, GetQueryUserIntentRequest, GetQueryUserIntentResponse,
    GetSessionRequest, GetSessionResponse, ListSessionsRequest, ListSessionsResponse,
    SampleQueryRequest,
};
use grdr_proto::common::CollectionKind;

use crate::aip::collections::{SESSION_DEFAULT_ORDER, SESSION_FILTERS, SESSION_SORT};
use crate::rpc::{CollectionPageSpec, PageParams, page_collection, revision_for, run_rpc};
use crate::store::AppState;

pub async fn list_sessions(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc(
        "/grdr.api.activity.v1alpha1.SessionService/ListSessions",
        state,
        request,
        |state, req: ListSessionsRequest| async move {
            let sessions = state.sessions().await;
            let (paged, rev) = page_collection(
                &state,
                sessions,
                PageParams {
                    page_size: req.page_size,
                    page_token: &req.page_token,
                    filter: &req.filter,
                    order_by: &req.order_by,
                },
                CollectionPageSpec {
                    collection: CollectionKind::Sessions,
                    method: "ListSessions",
                    allowed_filters: SESSION_FILTERS,
                    allowed_sort: SESSION_SORT,
                    default_order: SESSION_DEFAULT_ORDER,
                },
            )?;
            Ok((
                ListSessionsResponse {
                    sessions: paged.items.iter().map(session_to_proto).collect(),
                    page_info: Some(paged.page_info),
                    revision: Some(rev.clone()),
                },
                Some(rev),
            ))
        },
    )
    .await
}

pub async fn get_session(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc(
        "/grdr.api.activity.v1alpha1.SessionService/GetSession",
        state,
        request,
        |state, req: GetSessionRequest| async move {
            let rev = revision_for(
                &state,
                CollectionKind::Sessions,
                &format!("session={}", req.id),
            );
            let detail = state.session_detail(&req.id).await?;
            Ok((
                GetSessionResponse {
                    session: Some(session_to_proto(&detail.session)),
                    attempts: detail.attempts.iter().map(attempt_to_proto).collect(),
                    receipts: detail.receipts.iter().map(receipt_to_proto).collect(),
                    turns: detail.turns.iter().map(turn_to_proto).collect(),
                    user: detail.user.as_ref().map(user_to_proto),
                    revision: Some(rev.clone()),
                },
                Some(rev),
            ))
        },
    )
    .await
}

pub async fn get_query_schema(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc(
        "/grdr.api.activity.v1alpha1.SessionService/GetQuerySchema",
        state,
        request,
        |state, _req: GetQuerySchemaRequest| async move {
            let schemas = state.query_schema(false).await;
            Ok((
                GetQuerySchemaResponse {
                    entities: schema_list_to_proto(&schemas),
                },
                None,
            ))
        },
    )
    .await
}

pub async fn get_query_entities(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc(
        "/grdr.api.activity.v1alpha1.SessionService/GetQueryEntities",
        state,
        request,
        |state, _req: GetQueryEntitiesRequest| async move {
            let entities = state
                .query_entities(false)
                .await
                .into_iter()
                .map(|e| EntitySummaryInfo {
                    name: e.name,
                    description: e.description,
                    visible_columns: e.visible_columns,
                })
                .collect();
            Ok((GetQueryEntitiesResponse { entities }, None))
        },
    )
    .await
}

pub async fn get_query_user_intent(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Response {
    run_rpc(
        "/grdr.api.activity.v1alpha1.SessionService/GetQueryUserIntent",
        state,
        request,
        |state, _req: GetQueryUserIntentRequest| async move {
            let desc = state.query_user_intent(false).await;
            Ok((
                GetQueryUserIntentResponse {
                    descriptor: Some(user_intent_to_proto(&desc)),
                },
                None,
            ))
        },
    )
    .await
}

pub async fn sample_query(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc(
        "/grdr.api.activity.v1alpha1.SessionService/SampleQuery",
        state,
        request,
        |state, req: SampleQueryRequest| async move {
            let sample = state
                .query_sample(
                    QueryRequest {
                        entity: req.entity,
                        columns: req.columns,
                        limit: req.limit,
                        filter_text: req.filter_text,
                    },
                    false,
                )
                .await?;
            Ok((query_sample_to_proto(&sample), None))
        },
    )
    .await
}
