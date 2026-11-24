// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use axum::body::Body;
use axum::extract::State;
use axum::http::Request;
use axum::response::Response;

use grdr_model::UpdatePrivacyConfigInput;
use grdr_model::proto_conv::{
    privacy_to_proto, proto_to_identity_mode, user_detail_to_proto, user_to_proto,
};
use grdr_proto::api::tenancy::{
    GetPrivacyConfigRequest, GetPrivacyConfigResponse, GetUserRequest, ListUsersRequest,
    ListUsersResponse, UpdatePrivacyConfigRequest, UpdatePrivacyConfigResponse,
};
use grdr_proto::common::CollectionKind;

use crate::aip::collections::{USER_DEFAULT_ORDER, USER_FILTERS, USER_SORT};
use crate::rpc::{CollectionPageSpec, PageParams, page_collection, revision_for, run_rpc};
use crate::store::AppState;

pub async fn list_users(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc(
        "/grdr.api.tenancy.v1alpha1.UserService/ListUsers",
        state,
        request,
        |state, req: ListUsersRequest| async move {
            let users = state.users().await;
            let (paged, rev) = page_collection(
                &state,
                users,
                PageParams {
                    page_size: req.page_size,
                    page_token: &req.page_token,
                    filter: &req.filter,
                    order_by: &req.order_by,
                },
                CollectionPageSpec {
                    collection: CollectionKind::Users,
                    method: "ListUsers",
                    allowed_filters: USER_FILTERS,
                    allowed_sort: USER_SORT,
                    default_order: USER_DEFAULT_ORDER,
                },
            )?;
            Ok((
                ListUsersResponse {
                    users: paged.items.iter().map(user_to_proto).collect(),
                    page_info: Some(paged.page_info),
                    revision: Some(rev.clone()),
                },
                Some(rev),
            ))
        },
    )
    .await
}

pub async fn get_user(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc(
        "/grdr.api.tenancy.v1alpha1.UserService/GetUser",
        state,
        request,
        |state, req: GetUserRequest| async move {
            let rev = revision_for(&state, CollectionKind::Users, &format!("user={}", req.id));
            let detail = state.user_detail(&req.id).await?;
            Ok((user_detail_to_proto(&detail, Some(rev.clone())), Some(rev)))
        },
    )
    .await
}

pub async fn get_privacy_config(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc(
        "/grdr.api.tenancy.v1alpha1.UserService/GetPrivacyConfig",
        state,
        request,
        |state, _req: GetPrivacyConfigRequest| async move {
            let rev = revision_for(&state, CollectionKind::PrivacyConfig, "privacy");
            let cfg = state.privacy_config().await;
            Ok((
                GetPrivacyConfigResponse {
                    config: Some(privacy_to_proto(&cfg)),
                    revision: Some(rev.clone()),
                },
                Some(rev),
            ))
        },
    )
    .await
}

pub async fn update_privacy_config(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Response {
    run_rpc(
        "/grdr.api.tenancy.v1alpha1.UserService/UpdatePrivacyConfig",
        state,
        request,
        |state, req: UpdatePrivacyConfigRequest| async move {
            let updated = state
                .update_privacy_config(UpdatePrivacyConfigInput {
                    identity_mode: req.identity_mode.and_then(proto_to_identity_mode),
                    user_risk_scoring: req.user_risk_scoring,
                    actor: req.actor,
                })
                .await?;
            state.bump_revision(CollectionKind::PrivacyConfig);
            state.bump_revision(CollectionKind::Users);
            state.bump_revision(CollectionKind::Sessions);
            state.bump_revision(CollectionKind::AuditEvents);
            Ok((
                UpdatePrivacyConfigResponse {
                    config: Some(privacy_to_proto(&updated)),
                },
                None,
            ))
        },
    )
    .await
}
