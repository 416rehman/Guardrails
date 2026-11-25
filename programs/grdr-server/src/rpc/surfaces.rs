// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use axum::body::Body;
use axum::extract::State;
use axum::http::Request;
use axum::response::Response;

use grdr_proto::api::surfaces::{
    AdvanceProviderRingRequest, AdvanceProviderRingResponse, ApproveLegalHoldRequest,
    ApproveLegalHoldResponse, ApproveReidentificationRequest, ApproveReidentificationResponse,
    CompleteFirstRunRequest, CompleteFirstRunResponse, CreateLegalHoldRequest,
    CreateLegalHoldResponse, DecideReviewClusterRequest, DecideReviewClusterResponse,
    ExplainReceiptRequest, ExplainReceiptResponse, ExportComplianceArtifactRequest,
    GetComplianceWorkspaceRequest, GetProviderWorkspaceRequest, ListReviewQueueRequest,
    PushGrcEvidenceRequest, RequestReidentificationRequest, RequestReidentificationResponse,
    SwitchProviderOrgRequest, UpdateCompliancePolicyRequest, UpdateCompliancePolicyResponse,
};
use grdr_proto::common::CollectionKind;

use crate::rpc::{revision_for_ctx, run_rpc, run_rpc_ctx};
use crate::store::AppState;

pub async fn explain_receipt(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc(
        "/grdr.api.surfaces.v1alpha1.SurfaceService/ExplainReceipt",
        state,
        request,
        |state, req: ExplainReceiptRequest| async move {
            let exp = state.explain_receipt(&req.reference).await?;
            Ok((
                ExplainReceiptResponse {
                    explanation: Some(exp),
                },
                None,
            ))
        },
    )
    .await
}

pub async fn list_review_queue(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc_ctx(
        "/grdr.api.surfaces.v1alpha1.SurfaceService/ListReviewQueue",
        state,
        request,
        |state, auth, req: ListReviewQueueRequest| async move {
            let rev = revision_for_ctx(&state, &auth, CollectionKind::ReviewQueue, &req.bucket);
            let mut out = state
                .list_review_queue(&auth.tenant_id, &req.bucket, &req.search)
                .await;
            out.revision = Some(rev.clone());
            Ok((out, Some(rev)))
        },
    )
    .await
}

pub async fn decide_review_cluster(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Response {
    run_rpc_ctx(
        "/grdr.api.surfaces.v1alpha1.SurfaceService/DecideReviewCluster",
        state,
        request,
        |state, auth, req: DecideReviewClusterRequest| async move {
            let cluster = state.decide_review_cluster(req, &auth).await?;
            state.bump_revision(CollectionKind::ReviewQueue);
            state.bump_revision(CollectionKind::Packs);
            state.bump_revision(CollectionKind::AuditEvents);
            Ok((
                DecideReviewClusterResponse {
                    cluster: Some(cluster),
                },
                None,
            ))
        },
    )
    .await
}

pub async fn get_compliance_workspace(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Response {
    run_rpc_ctx(
        "/grdr.api.surfaces.v1alpha1.SurfaceService/GetComplianceWorkspace",
        state,
        request,
        |state, auth, _req: GetComplianceWorkspaceRequest| async move {
            let rev = revision_for_ctx(
                &state,
                &auth,
                CollectionKind::ComplianceWorkspace,
                "compliance",
            );
            let mut out = state.get_compliance_workspace(&auth.tenant_id).await;
            out.revision = Some(rev.clone());
            Ok((out, Some(rev)))
        },
    )
    .await
}

pub async fn update_compliance_policy(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Response {
    run_rpc_ctx(
        "/grdr.api.surfaces.v1alpha1.SurfaceService/UpdateCompliancePolicy",
        state,
        request,
        |state, auth, req: UpdateCompliancePolicyRequest| async move {
            let retention = state.update_compliance_policy(req, &auth).await?;
            state.bump_revision(CollectionKind::ComplianceWorkspace);
            state.bump_revision(CollectionKind::PrivacyConfig);
            state.bump_revision(CollectionKind::AuditEvents);
            Ok((
                UpdateCompliancePolicyResponse {
                    retention: Some(retention),
                },
                None,
            ))
        },
    )
    .await
}

pub async fn create_legal_hold(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc_ctx(
        "/grdr.api.surfaces.v1alpha1.SurfaceService/CreateLegalHold",
        state,
        request,
        |state, auth, req: CreateLegalHoldRequest| async move {
            let hold = state.create_legal_hold(req, &auth).await?;
            state.bump_revision(CollectionKind::ComplianceWorkspace);
            state.bump_revision(CollectionKind::AuditEvents);
            Ok((CreateLegalHoldResponse { hold: Some(hold) }, None))
        },
    )
    .await
}

pub async fn approve_legal_hold(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc_ctx(
        "/grdr.api.surfaces.v1alpha1.SurfaceService/ApproveLegalHold",
        state,
        request,
        |state, auth, req: ApproveLegalHoldRequest| async move {
            let hold = state.approve_legal_hold(req, &auth).await?;
            state.bump_revision(CollectionKind::ComplianceWorkspace);
            state.bump_revision(CollectionKind::AuditEvents);
            Ok((ApproveLegalHoldResponse { hold: Some(hold) }, None))
        },
    )
    .await
}

pub async fn export_compliance_artifact(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Response {
    run_rpc_ctx(
        "/grdr.api.surfaces.v1alpha1.SurfaceService/ExportComplianceArtifact",
        state,
        request,
        |state, auth, req: ExportComplianceArtifactRequest| async move {
            let out = state.export_compliance_artifact(&req.format, &auth).await?;
            state.bump_revision(CollectionKind::ComplianceWorkspace);
            state.bump_revision(CollectionKind::AuditEvents);
            Ok((out, None))
        },
    )
    .await
}

pub async fn push_grc_evidence(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc_ctx(
        "/grdr.api.surfaces.v1alpha1.SurfaceService/PushGrcEvidence",
        state,
        request,
        |state, auth, req: PushGrcEvidenceRequest| async move {
            let out = state.push_grc_evidence(&req.target, &auth).await?;
            state.bump_revision(CollectionKind::ComplianceWorkspace);
            state.bump_revision(CollectionKind::AuditEvents);
            Ok((out, None))
        },
    )
    .await
}

pub async fn request_reidentification(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Response {
    run_rpc_ctx(
        "/grdr.api.surfaces.v1alpha1.SurfaceService/RequestReidentification",
        state,
        request,
        |state, auth, req: RequestReidentificationRequest| async move {
            let out = state.request_reidentification(req, &auth).await?;
            state.bump_revision(CollectionKind::ComplianceWorkspace);
            state.bump_revision(CollectionKind::AuditEvents);
            Ok((RequestReidentificationResponse { request: Some(out) }, None))
        },
    )
    .await
}

pub async fn approve_reidentification(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Response {
    run_rpc_ctx(
        "/grdr.api.surfaces.v1alpha1.SurfaceService/ApproveReidentification",
        state,
        request,
        |state, auth, req: ApproveReidentificationRequest| async move {
            let out = state.approve_reidentification(req, &auth).await?;
            state.bump_revision(CollectionKind::ComplianceWorkspace);
            state.bump_revision(CollectionKind::AuditEvents);
            Ok((ApproveReidentificationResponse { request: Some(out) }, None))
        },
    )
    .await
}

pub async fn complete_first_run(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc_ctx(
        "/grdr.api.surfaces.v1alpha1.SurfaceService/CompleteFirstRun",
        state,
        request,
        |state, auth, req: CompleteFirstRunRequest| async move {
            let out = state.complete_first_run(req, &auth).await?;
            state.bump_revision(CollectionKind::ComplianceWorkspace);
            state.bump_revision(CollectionKind::Devices);
            state.bump_revision(CollectionKind::AuditEvents);
            Ok((
                CompleteFirstRunResponse {
                    first_run: Some(out),
                },
                None,
            ))
        },
    )
    .await
}

pub async fn get_provider_workspace(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Response {
    run_rpc_ctx(
        "/grdr.api.surfaces.v1alpha1.SurfaceService/GetProviderWorkspace",
        state,
        request,
        |state, auth, req: GetProviderWorkspaceRequest| async move {
            let rev =
                revision_for_ctx(&state, &auth, CollectionKind::ProviderWorkspace, "provider");
            let mut out = state
                .get_provider_workspace(req.org_set.as_deref(), &auth.principal_id)
                .await;
            out.revision = Some(rev.clone());
            Ok((out, Some(rev)))
        },
    )
    .await
}

pub async fn switch_provider_org(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Response {
    run_rpc_ctx(
        "/grdr.api.surfaces.v1alpha1.SurfaceService/SwitchProviderOrg",
        state,
        request,
        |state, auth, req: SwitchProviderOrgRequest| async move {
            let out = state
                .switch_provider_org(req.org_id.as_deref(), req.reason.as_deref(), &auth)
                .await?;
            state.bump_revision(CollectionKind::ProviderWorkspace);
            state.bump_revision(CollectionKind::AuditEvents);
            Ok((out, None))
        },
    )
    .await
}

pub async fn advance_provider_ring(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Response {
    run_rpc_ctx(
        "/grdr.api.surfaces.v1alpha1.SurfaceService/AdvanceProviderRing",
        state,
        request,
        |state, auth, req: AdvanceProviderRingRequest| async move {
            let ring = state
                .advance_provider_ring(&req.ring, &req.target_version, &auth)
                .await?;
            state.bump_revision(CollectionKind::ProviderWorkspace);
            state.bump_revision(CollectionKind::AuditEvents);
            Ok((AdvanceProviderRingResponse { ring: Some(ring) }, None))
        },
    )
    .await
}
