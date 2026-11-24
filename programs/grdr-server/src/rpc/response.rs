// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use axum::body::Body;
use axum::extract::State;
use axum::http::Request;
use axum::response::Response;

use grdr_model::proto_conv::{
    approval_to_proto, audit_to_proto, finding_to_proto, incident_to_proto, kill_switch_to_proto,
    proto_to_finding_lifecycle, proto_to_grant_scope, proto_to_kill_action, proto_to_kill_scope,
};
use grdr_model::{DecideApprovalInput, KillSwitchInput, UpdateFindingInput};
use grdr_proto::api::response::{
    DecideApprovalRequest, DecideApprovalResponse, GetKillSwitchRequest, GetKillSwitchResponse,
    ListApprovalsRequest, ListApprovalsResponse, ListAuditEventsRequest, ListAuditEventsResponse,
    ListFindingsRequest, ListFindingsResponse, ListIncidentsRequest, ListIncidentsResponse,
    SetKillSwitchRequest, SetKillSwitchResponse, UpdateFindingRequest, UpdateFindingResponse,
};
use grdr_proto::common::CollectionKind;

use crate::aip::collections_ops::{
    APPROVAL_DEFAULT_ORDER, APPROVAL_FILTERS, APPROVAL_SORT, AUDIT_DEFAULT_ORDER, AUDIT_FILTERS,
    AUDIT_SORT, FINDING_DEFAULT_ORDER, FINDING_FILTERS, FINDING_SORT, INCIDENT_DEFAULT_ORDER,
    INCIDENT_FILTERS, INCIDENT_SORT,
};
use crate::connect_error::{ApiError, CODE_API_BAD_REQUEST};
use crate::rpc::{CollectionPageSpec, PageParams, page_collection, revision_for, run_rpc};
use crate::store::AppState;

pub async fn list_approvals(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc(
        "/grdr.api.response.v1alpha1.ResponseService/ListApprovals",
        state,
        request,
        |state, req: ListApprovalsRequest| async move {
            let approvals = state.list_approvals().await;
            let (paged, rev) = page_collection(
                &state,
                approvals,
                PageParams {
                    page_size: req.page_size,
                    page_token: &req.page_token,
                    filter: &req.filter,
                    order_by: &req.order_by,
                },
                CollectionPageSpec {
                    collection: CollectionKind::Approvals,
                    method: "ListApprovals",
                    allowed_filters: APPROVAL_FILTERS,
                    allowed_sort: APPROVAL_SORT,
                    default_order: APPROVAL_DEFAULT_ORDER,
                },
            )?;
            Ok((
                ListApprovalsResponse {
                    approvals: paged.items.iter().map(approval_to_proto).collect(),
                    page_info: Some(paged.page_info),
                    revision: Some(rev.clone()),
                },
                Some(rev),
            ))
        },
    )
    .await
}

pub async fn decide_approval(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc(
        "/grdr.api.response.v1alpha1.ResponseService/DecideApproval",
        state,
        request,
        |state, req: DecideApprovalRequest| async move {
            let approval = state
                .decide_approval(
                    &req.id,
                    DecideApprovalInput {
                        approve: req.approve,
                        scope: req.scope.and_then(proto_to_grant_scope),
                        note: req.note,
                        actor: req.actor,
                    },
                )
                .await?;
            state.bump_revision(CollectionKind::Approvals);
            state.bump_revision(CollectionKind::AuditEvents);
            Ok((
                DecideApprovalResponse {
                    approval: Some(approval_to_proto(&approval)),
                },
                None,
            ))
        },
    )
    .await
}

pub async fn list_findings(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc(
        "/grdr.api.response.v1alpha1.ResponseService/ListFindings",
        state,
        request,
        |state, req: ListFindingsRequest| async move {
            let findings = state.inner.read().await.findings.clone();
            let (paged, rev) = page_collection(
                &state,
                findings,
                PageParams {
                    page_size: req.page_size,
                    page_token: &req.page_token,
                    filter: &req.filter,
                    order_by: &req.order_by,
                },
                CollectionPageSpec {
                    collection: CollectionKind::Findings,
                    method: "ListFindings",
                    allowed_filters: FINDING_FILTERS,
                    allowed_sort: FINDING_SORT,
                    default_order: FINDING_DEFAULT_ORDER,
                },
            )?;
            Ok((
                ListFindingsResponse {
                    findings: paged.items.iter().map(finding_to_proto).collect(),
                    page_info: Some(paged.page_info),
                    revision: Some(rev.clone()),
                },
                Some(rev),
            ))
        },
    )
    .await
}

pub async fn update_finding(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc(
        "/grdr.api.response.v1alpha1.ResponseService/UpdateFinding",
        state,
        request,
        |state, req: UpdateFindingRequest| async move {
            let lifecycle = proto_to_finding_lifecycle(req.lifecycle).ok_or_else(|| {
                ApiError::invalid_argument(
                    CODE_API_BAD_REQUEST,
                    "INVALID_LIFECYCLE",
                    "Missing or invalid finding lifecycle.",
                    "Supply Open, Acknowledged, Contained, or Resolved.",
                )
            })?;
            let finding = state
                .update_finding(
                    &req.id,
                    UpdateFindingInput {
                        lifecycle,
                        note: req.note,
                    },
                )
                .await?;
            state.bump_revision(CollectionKind::Findings);
            state.bump_revision(CollectionKind::Incidents);
            state.bump_revision(CollectionKind::AuditEvents);
            Ok((
                UpdateFindingResponse {
                    finding: Some(finding_to_proto(&finding)),
                },
                None,
            ))
        },
    )
    .await
}

pub async fn list_incidents(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc(
        "/grdr.api.response.v1alpha1.ResponseService/ListIncidents",
        state,
        request,
        |state, req: ListIncidentsRequest| async move {
            let incidents = state.incidents().await;
            let (paged, rev) = page_collection(
                &state,
                incidents,
                PageParams {
                    page_size: req.page_size,
                    page_token: &req.page_token,
                    filter: &req.filter,
                    order_by: &req.order_by,
                },
                CollectionPageSpec {
                    collection: CollectionKind::Incidents,
                    method: "ListIncidents",
                    allowed_filters: INCIDENT_FILTERS,
                    allowed_sort: INCIDENT_SORT,
                    default_order: INCIDENT_DEFAULT_ORDER,
                },
            )?;
            Ok((
                ListIncidentsResponse {
                    incidents: paged.items.iter().map(incident_to_proto).collect(),
                    page_info: Some(paged.page_info),
                    revision: Some(rev.clone()),
                },
                Some(rev),
            ))
        },
    )
    .await
}

pub async fn get_kill_switch(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc(
        "/grdr.api.response.v1alpha1.ResponseService/GetKillSwitch",
        state,
        request,
        |state, _req: GetKillSwitchRequest| async move {
            let rev = revision_for(&state, CollectionKind::KillSwitch, "kill_switch");
            let ks = state.inner.read().await.kill_switch.clone();
            Ok((
                GetKillSwitchResponse {
                    kill_switch: Some(kill_switch_to_proto(&ks)),
                    revision: Some(rev.clone()),
                },
                Some(rev),
            ))
        },
    )
    .await
}

pub async fn set_kill_switch(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc(
        "/grdr.api.response.v1alpha1.ResponseService/SetKillSwitch",
        state,
        request,
        |state, req: SetKillSwitchRequest| async move {
            let action = proto_to_kill_action(req.action).ok_or_else(|| {
                ApiError::invalid_argument(
                    CODE_API_BAD_REQUEST,
                    "INVALID_KILL_ACTION",
                    "Missing or invalid kill-switch action.",
                    "Supply Freeze, Kill, or Release.",
                )
            })?;
            let scope = proto_to_kill_scope(req.scope).ok_or_else(|| {
                ApiError::invalid_argument(
                    CODE_API_BAD_REQUEST,
                    "INVALID_KILL_SCOPE",
                    "Missing or invalid kill-switch scope.",
                    "Supply Session, Device, or Organisation.",
                )
            })?;
            let ks = state
                .set_kill_switch(KillSwitchInput {
                    action,
                    scope,
                    target_id: req.target_id,
                    reason: req.reason,
                    duration_minutes: req.duration_minutes,
                })
                .await?;
            state.bump_revision(CollectionKind::KillSwitch);
            state.bump_revision(CollectionKind::AuditEvents);
            Ok((
                SetKillSwitchResponse {
                    kill_switch: Some(kill_switch_to_proto(&ks)),
                },
                None,
            ))
        },
    )
    .await
}

pub async fn list_audit_events(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc(
        "/grdr.api.response.v1alpha1.ResponseService/ListAuditEvents",
        state,
        request,
        |state, req: ListAuditEventsRequest| async move {
            let entries = state.inner.read().await.audit.clone();
            let (paged, rev) = page_collection(
                &state,
                entries,
                PageParams {
                    page_size: req.page_size,
                    page_token: &req.page_token,
                    filter: &req.filter,
                    order_by: &req.order_by,
                },
                CollectionPageSpec {
                    collection: CollectionKind::AuditEvents,
                    method: "ListAuditEvents",
                    allowed_filters: AUDIT_FILTERS,
                    allowed_sort: AUDIT_SORT,
                    default_order: AUDIT_DEFAULT_ORDER,
                },
            )?;
            Ok((
                ListAuditEventsResponse {
                    entries: paged.items.iter().map(audit_to_proto).collect(),
                    page_info: Some(paged.page_info),
                    revision: Some(rev.clone()),
                },
                Some(rev),
            ))
        },
    )
    .await
}
