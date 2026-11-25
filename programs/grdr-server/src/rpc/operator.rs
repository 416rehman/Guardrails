// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use axum::body::Body;
use axum::extract::State;
use axum::http::Request;
use axum::response::Response;

use grdr_proto::api::operator::{
    ApplyConfigRevisionRequest, ApplyConfigRevisionResponse, GetOperatorStateRequest,
    ResetTargetBreakerRequest, ResetTargetBreakerResponse, RollbackConfigRevisionRequest,
    RollbackConfigRevisionResponse, RunBackupDrillRequest, RunBackupDrillResponse,
    RunUpgradePreflightRequest, StageConfigRevisionRequest, StageConfigRevisionResponse,
};
use grdr_proto::common::CollectionKind;

use crate::rpc::{revision_for_ctx, run_rpc_ctx};
use crate::store::AppState;

pub async fn get_operator_state(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc_ctx(
        "/grdr.api.operator.v1alpha1.OperatorService/GetOperatorState",
        state,
        request,
        |state, auth, _req: GetOperatorStateRequest| async move {
            let rev = revision_for_ctx(&state, &auth, CollectionKind::OperatorState, "operator");
            let mut out = state.get_operator_state().await?;
            out.revision = Some(rev.clone());
            Ok((out, Some(rev)))
        },
    )
    .await
}

pub async fn stage_config_revision(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Response {
    run_rpc_ctx(
        "/grdr.api.operator.v1alpha1.OperatorService/StageConfigRevision",
        state,
        request,
        |state, auth, req: StageConfigRevisionRequest| async move {
            let revision = state.stage_config_revision(req, &auth).await?;
            state.bump_revision(CollectionKind::OperatorState);
            state.bump_revision(CollectionKind::AuditEvents);
            Ok((
                StageConfigRevisionResponse {
                    revision: Some(revision),
                },
                None,
            ))
        },
    )
    .await
}

pub async fn apply_config_revision(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Response {
    run_rpc_ctx(
        "/grdr.api.operator.v1alpha1.OperatorService/ApplyConfigRevision",
        state,
        request,
        |state, auth, req: ApplyConfigRevisionRequest| async move {
            let (cfg, rev) = state.apply_config_revision(&req.revision_id, &auth).await?;
            state.bump_revision(CollectionKind::OperatorState);
            state.bump_revision(CollectionKind::ComplianceWorkspace);
            state.bump_revision(CollectionKind::PrivacyConfig);
            state.bump_revision(CollectionKind::AuditEvents);
            Ok((
                ApplyConfigRevisionResponse {
                    runtime_config: Some(cfg),
                    applied_revision: Some(rev),
                },
                None,
            ))
        },
    )
    .await
}

pub async fn rollback_config_revision(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Response {
    run_rpc_ctx(
        "/grdr.api.operator.v1alpha1.OperatorService/RollbackConfigRevision",
        state,
        request,
        |state, auth, req: RollbackConfigRevisionRequest| async move {
            let (cfg, rev) = state
                .rollback_config_revision(req.target_revision_id.as_deref(), &req.reason, &auth)
                .await?;
            state.bump_revision(CollectionKind::OperatorState);
            state.bump_revision(CollectionKind::ComplianceWorkspace);
            state.bump_revision(CollectionKind::PrivacyConfig);
            state.bump_revision(CollectionKind::AuditEvents);
            Ok((
                RollbackConfigRevisionResponse {
                    runtime_config: Some(cfg),
                    rolled_back_revision: Some(rev),
                },
                None,
            ))
        },
    )
    .await
}

pub async fn run_upgrade_preflight(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Response {
    run_rpc_ctx(
        "/grdr.api.operator.v1alpha1.OperatorService/RunUpgradePreflight",
        state,
        request,
        |state, auth, req: RunUpgradePreflightRequest| async move {
            let out = state
                .run_upgrade_preflight(&req.target_version, &auth)
                .await?;
            state.bump_revision(CollectionKind::OperatorState);
            state.bump_revision(CollectionKind::AuditEvents);
            Ok((out, None))
        },
    )
    .await
}

pub async fn reset_target_breaker(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Response {
    run_rpc_ctx(
        "/grdr.api.operator.v1alpha1.OperatorService/ResetTargetBreaker",
        state,
        request,
        |state, auth, req: ResetTargetBreakerRequest| async move {
            let target = state.reset_target_breaker(&req.target_id, &auth).await?;
            state.bump_revision(CollectionKind::OperatorState);
            state.bump_revision(CollectionKind::AuditEvents);
            Ok((
                ResetTargetBreakerResponse {
                    target: Some(target),
                },
                None,
            ))
        },
    )
    .await
}

pub async fn run_backup_drill(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc_ctx(
        "/grdr.api.operator.v1alpha1.OperatorService/RunBackupDrill",
        state,
        request,
        |state, auth, req: RunBackupDrillRequest| async move {
            let drill = state
                .run_backup_drill(&req.kind, req.note.as_deref(), &auth)
                .await?;
            state.bump_revision(CollectionKind::OperatorState);
            state.bump_revision(CollectionKind::AuditEvents);
            Ok((RunBackupDrillResponse { drill: Some(drill) }, None))
        },
    )
    .await
}
