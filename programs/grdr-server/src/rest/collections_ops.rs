// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use axum::Json;
use axum::extract::{Extension, Query, State};
use axum::response::{IntoResponse, Response};
use serde_json::json;

use grdr_model::proto_conv::{
    approval_to_proto, audit_to_proto, finding_to_proto, incident_to_proto, user_to_proto,
};
use grdr_proto::common::CollectionKind;

use crate::aip::collections::{USER_DEFAULT_ORDER, USER_FILTERS, USER_SORT};
use crate::aip::collections_ops::{
    APPROVAL_DEFAULT_ORDER, APPROVAL_FILTERS, APPROVAL_SORT, AUDIT_DEFAULT_ORDER, AUDIT_FILTERS,
    AUDIT_SORT, FINDING_DEFAULT_ORDER, FINDING_FILTERS, FINDING_SORT, INCIDENT_DEFAULT_ORDER,
    INCIDENT_FILTERS, INCIDENT_SORT,
};
use crate::auth::AuthContext;
use crate::rpc::{PageParams, page_collection_ctx};
use crate::store::AppState;

use super::super::gitops::api_error_json_response;
use super::authz::{RestPolicy, authorize_rest};
use super::collections::CollectionQuery;

pub async fn list_findings(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<CollectionQuery>,
) -> Response {
    if let Err(err) = authorize_rest(&auth, RestPolicy::read("response:read")) {
        return api_error_json_response(&err);
    }
    let rows = state.inner.read().await.findings.clone();
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
            collection: CollectionKind::Findings,
            method: "ListFindings",
            allowed_filters: FINDING_FILTERS,
            allowed_sort: FINDING_SORT,
            default_order: FINDING_DEFAULT_ORDER,
        },
    ) {
        Ok((paged, rev)) => {
            let items: Vec<_> = paged.items.iter().map(finding_to_proto).collect();
            Json(json!({ "findings": items, "pageInfo": paged.page_info, "revision": rev }))
                .into_response()
        }
        Err(err) => api_error_json_response(&err),
    }
}

pub async fn list_incidents(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<CollectionQuery>,
) -> Response {
    if let Err(err) = authorize_rest(&auth, RestPolicy::read("response:read")) {
        return api_error_json_response(&err);
    }
    let rows = state.incidents().await;
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
            collection: CollectionKind::Incidents,
            method: "ListIncidents",
            allowed_filters: INCIDENT_FILTERS,
            allowed_sort: INCIDENT_SORT,
            default_order: INCIDENT_DEFAULT_ORDER,
        },
    ) {
        Ok((paged, rev)) => {
            let items: Vec<_> = paged.items.iter().map(incident_to_proto).collect();
            Json(json!({ "incidents": items, "pageInfo": paged.page_info, "revision": rev }))
                .into_response()
        }
        Err(err) => api_error_json_response(&err),
    }
}

pub async fn list_approvals(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<CollectionQuery>,
) -> Response {
    if let Err(err) = authorize_rest(&auth, RestPolicy::read("response:read")) {
        return api_error_json_response(&err);
    }
    let rows = state.list_approvals().await;
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
            collection: CollectionKind::Approvals,
            method: "ListApprovals",
            allowed_filters: APPROVAL_FILTERS,
            allowed_sort: APPROVAL_SORT,
            default_order: APPROVAL_DEFAULT_ORDER,
        },
    ) {
        Ok((paged, rev)) => {
            let items: Vec<_> = paged.items.iter().map(approval_to_proto).collect();
            Json(json!({ "approvals": items, "pageInfo": paged.page_info, "revision": rev }))
                .into_response()
        }
        Err(err) => api_error_json_response(&err),
    }
}

pub async fn list_audit_events(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<CollectionQuery>,
) -> Response {
    if let Err(err) = authorize_rest(&auth, RestPolicy::read("audit:read")) {
        return api_error_json_response(&err);
    }
    let rows = state.inner.read().await.audit.clone();
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
            collection: CollectionKind::AuditEvents,
            method: "ListAuditEvents",
            allowed_filters: AUDIT_FILTERS,
            allowed_sort: AUDIT_SORT,
            default_order: AUDIT_DEFAULT_ORDER,
        },
    ) {
        Ok((paged, rev)) => {
            let items: Vec<_> = paged.items.iter().map(audit_to_proto).collect();
            Json(json!({ "entries": items, "pageInfo": paged.page_info, "revision": rev }))
                .into_response()
        }
        Err(err) => api_error_json_response(&err),
    }
}

pub async fn list_users(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<CollectionQuery>,
) -> Response {
    if let Err(err) = authorize_rest(&auth, RestPolicy::read("users:read")) {
        return api_error_json_response(&err);
    }
    let rows = state.users().await;
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
            collection: CollectionKind::Users,
            method: "ListUsers",
            allowed_filters: USER_FILTERS,
            allowed_sort: USER_SORT,
            default_order: USER_DEFAULT_ORDER,
        },
    ) {
        Ok((paged, rev)) => {
            let items: Vec<_> = paged.items.iter().map(user_to_proto).collect();
            Json(json!({ "users": items, "pageInfo": paged.page_info, "revision": rev }))
                .into_response()
        }
        Err(err) => api_error_json_response(&err),
    }
}
