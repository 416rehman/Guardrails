// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tower::ServiceExt as _;

use grdr_proto::api::operator::{
    ApplyConfigRevisionRequest, ApplyConfigRevisionResponse, GetOperatorStateRequest,
    GetOperatorStateResponse, ResetTargetBreakerRequest, ResetTargetBreakerResponse,
    RollbackConfigRevisionRequest, RollbackConfigRevisionResponse, RunBackupDrillRequest,
    RunBackupDrillResponse, RunUpgradePreflightRequest, RunUpgradePreflightResponse,
    StageConfigRevisionRequest, StageConfigRevisionResponse,
};
use grdr_proto::api::overview::{IssueLiveTicketRequest, IssueLiveTicketResponse};
use grdr_proto::api::surfaces::{
    AdvanceProviderRingRequest, AdvanceProviderRingResponse, ApproveLegalHoldRequest,
    ApproveLegalHoldResponse, ApproveReidentificationRequest, ApproveReidentificationResponse,
    CompleteFirstRunRequest, CompleteFirstRunResponse, CreateLegalHoldRequest,
    CreateLegalHoldResponse, DecideReviewClusterRequest, DecideReviewClusterResponse,
    ExplainReceiptRequest, ExplainReceiptResponse, ExportComplianceArtifactRequest,
    ExportComplianceArtifactResponse, GetComplianceWorkspaceRequest,
    GetComplianceWorkspaceResponse, GetProviderWorkspaceRequest, GetProviderWorkspaceResponse,
    ListReviewQueueRequest, ListReviewQueueResponse, PushGrcEvidenceRequest,
    PushGrcEvidenceResponse, RequestReidentificationRequest, RequestReidentificationResponse,
    SwitchProviderOrgRequest, SwitchProviderOrgResponse, UpdateCompliancePolicyRequest,
};

use crate::auth::{
    AuthPlane, ConfirmAssertion, PrincipalIdentity, ServerSecurityConfig,
    generate_random_bearer_token,
};
use crate::routes;
use crate::store::{AppState, StorageBackend};

const CONSOLE_TOK: &str = "console-admin-tok-e2e";
const OP_TOK: &str = "operator-admin-tok-e2e";
const STEP_UP_TOK: &str = "server-step-up-secret-e2e";
const ALICE_TOK: &str = "alice-reviewer-tok";
const BOB_TOK: &str = "bob-reviewer-tok";
const CHARLIE_TOK: &str = "charlie-reviewer-tok";
const DPO_STEPUP_TOK: &str = "dpo-step-up-tok";
const TENANT_B_TOK: &str = "tenant-b-admin-tok";

fn test_security() -> ServerSecurityConfig {
    let mut principal_tokens = BTreeMap::new();
    for (tok, id) in [
        (ALICE_TOK, "alice@acme.example"),
        (BOB_TOK, "bob@acme.example"),
        (CHARLIE_TOK, "charlie@acme.example"),
    ] {
        principal_tokens.insert(
            tok.to_owned(),
            PrincipalIdentity {
                principal_id: id.to_owned(),
                tenant_id: "org-default".to_owned(),
                plane: AuthPlane::Console,
                scopes: vec!["*".into()],
                assurance: ConfirmAssertion::ConfirmedIntent,
            },
        );
    }
    principal_tokens.insert(
        DPO_STEPUP_TOK.to_owned(),
        PrincipalIdentity {
            principal_id: "dpo@acme.example".to_owned(),
            tenant_id: "org-default".to_owned(),
            plane: AuthPlane::Console,
            scopes: vec!["*".into()],
            assurance: ConfirmAssertion::StepUpVerified,
        },
    );
    principal_tokens.insert(
        TENANT_B_TOK.to_owned(),
        PrincipalIdentity {
            principal_id: "admin@beta.example".to_owned(),
            tenant_id: "org-tenant-b".to_owned(),
            plane: AuthPlane::Console,
            scopes: vec!["*".into()],
            assurance: ConfirmAssertion::ConfirmedIntent,
        },
    );
    ServerSecurityConfig {
        api_token: Some(CONSOLE_TOK.into()),
        operator_token: Some(OP_TOK.into()),
        step_up_token: Some(STEP_UP_TOK.into()),
        enroll_token: Some("enroll-tok-test".into()),
        cors_origins: Vec::new(),
        operator_cors_origins: Vec::new(),
        max_body_bytes: 1024 * 1024,
        principal_tokens,
    }
}

async fn post_json<Req: Serialize, Resp: DeserializeOwned>(
    app: &Router,
    path: &str,
    token: &str,
    confirm: bool,
    step_up: bool,
    req: &Req,
) -> (StatusCode, Resp) {
    let mut builder = Request::post(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header("connect-protocol-version", "1");
    if confirm {
        builder = builder.header("x-grdr-confirm", "confirmed");
    }
    if step_up {
        builder = builder.header("x-grdr-step-up", STEP_UP_TOK);
    }
    let resp = app
        .clone()
        .oneshot(
            builder
                .body(Body::from(serde_json::to_vec(req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let parsed: Resp = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
        panic!(
            "decode error for {path}: {e}: {}",
            String::from_utf8_lossy(&bytes)
        )
    });
    (status, parsed)
}

async fn post_raw_json_with_headers<Req: Serialize>(
    app: &Router,
    path: &str,
    token: Option<&str>,
    confirm: bool,
    step_up_header: Option<&str>,
    req: &Req,
) -> (StatusCode, String) {
    let mut builder = Request::post(path)
        .header(header::CONTENT_TYPE, "application/json")
        .header("connect-protocol-version", "1");
    if let Some(tok) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {tok}"));
    }
    if confirm {
        builder = builder.header("x-grdr-confirm", "confirmed");
    }
    if let Some(su) = step_up_header {
        builder = builder.header("x-grdr-step-up", su);
    }
    let resp = app
        .clone()
        .oneshot(
            builder
                .body(Body::from(serde_json::to_vec(req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn post_raw_json<Req: Serialize>(
    app: &Router,
    path: &str,
    token: Option<&str>,
    confirm: bool,
    req: &Req,
) -> (StatusCode, String) {
    post_raw_json_with_headers(app, path, token, confirm, None, req).await
}

#[tokio::test]
async fn surfaces_and_operator_rpcs_exercise_live_domains() {
    let state = AppState::init(StorageBackend::Memory, true).expect("init store");
    let sec = test_security();
    let console_app = routes::build_console_router_with_security(state.clone(), None, sec.clone());
    let operator_app = routes::build_operator_router_with_security(state.clone(), None, sec);

    let (st, queue): (_, ListReviewQueueResponse) = post_json(
        &console_app,
        "/grdr.api.surfaces.v1alpha1.SurfaceService/ListReviewQueue",
        CONSOLE_TOK,
        false,
        false,
        &ListReviewQueueRequest::default(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(!queue.clusters.is_empty());

    let first_cluster = queue.clusters.first().expect("cluster");
    let (st, why): (_, ExplainReceiptResponse) = post_json(
        &console_app,
        "/grdr.api.surfaces.v1alpha1.SurfaceService/ExplainReceipt",
        CONSOLE_TOK,
        false,
        false,
        &ExplainReceiptRequest {
            reference: first_cluster.receipt_ref.clone(),
        },
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(!why.explanation.expect("explanation").agent_told.is_empty());

    // Exact match only (Hardening 1): short suffix no longer matches.
    let (st_suffix, _) = post_raw_json(
        &console_app,
        "/grdr.api.surfaces.v1alpha1.SurfaceService/ExplainReceipt",
        Some(CONSOLE_TOK),
        false,
        &ExplainReceiptRequest {
            reference: first_cluster
                .receipt_ref
                .chars()
                .rev()
                .take(4)
                .collect::<String>()
                .chars()
                .rev()
                .collect(),
        },
    )
    .await;
    assert_eq!(st_suffix, StatusCode::NOT_FOUND);

    let (st, decided): (_, DecideReviewClusterResponse) = post_json(
        &console_app,
        "/grdr.api.surfaces.v1alpha1.SurfaceService/DecideReviewCluster",
        ALICE_TOK,
        true,
        false,
        &DecideReviewClusterRequest {
            id: first_cluster.id.clone(),
            decision: "suppress".into(),
            target_mode: None,
            note: Some("Expected dev test read".into()),
            actor: None,
        },
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(decided.cluster.is_some());

    // Framework titles scope EO 14434 strictly to US federal docs (international keeps AI).
    let (st, comp): (_, GetComplianceWorkspaceResponse) = post_json(
        &console_app,
        "/grdr.api.surfaces.v1alpha1.SurfaceService/GetComplianceWorkspace",
        CONSOLE_TOK,
        false,
        false,
        &GetComplianceWorkspaceRequest {},
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(
        comp.frameworks
            .iter()
            .any(|f| f.display_title.contains("EU AI Act"))
    );
    assert!(
        !comp
            .frameworks
            .iter()
            .any(|f| f.display_title.contains("EU SI Act"))
    );

    let (st, oscal): (_, ExportComplianceArtifactResponse) = post_json(
        &console_app,
        "/grdr.api.surfaces.v1alpha1.SurfaceService/ExportComplianceArtifact",
        CONSOLE_TOK,
        true,
        false,
        &ExportComplianceArtifactRequest {
            format: "oscal-component".into(),
            framework_id: None,
        },
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(oscal.oscal_version, "1.2.3");

    let (st, grc): (_, PushGrcEvidenceResponse) = post_json(
        &console_app,
        "/grdr.api.surfaces.v1alpha1.SurfaceService/PushGrcEvidence",
        CONSOLE_TOK,
        true,
        false,
        &PushGrcEvidenceRequest {
            target: "ciso-assistant".into(),
        },
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(grc.outbox_state, "queued");

    // Dual-principal legal hold workflow
    let (st, proposed_hold): (_, CreateLegalHoldResponse) = post_json(
        &console_app,
        "/grdr.api.surfaces.v1alpha1.SurfaceService/CreateLegalHold",
        ALICE_TOK,
        true,
        false,
        &CreateLegalHoldRequest {
            matter_ref: "MATTER-TEST-9".into(),
            reason: "Preservation check".into(),
            pseudonym_or_session: "prn_alice_01".into(),
        },
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let hold = proposed_hold.hold.expect("hold");
    assert_eq!(hold.lifecycle, "pending_quorum");
    assert_eq!(hold.created_by, "alice@acme.example");

    let (st_self_hold, _) = post_raw_json(
        &console_app,
        "/grdr.api.surfaces.v1alpha1.SurfaceService/ApproveLegalHold",
        Some(ALICE_TOK),
        true,
        &ApproveLegalHoldRequest {
            hold_id: hold.hold_id.clone(),
            note: None,
        },
    )
    .await;
    assert_eq!(st_self_hold, StatusCode::BAD_REQUEST);

    let (st_cosign, active_hold): (_, ApproveLegalHoldResponse) = post_json(
        &console_app,
        "/grdr.api.surfaces.v1alpha1.SurfaceService/ApproveLegalHold",
        BOB_TOK,
        true,
        false,
        &ApproveLegalHoldRequest {
            hold_id: hold.hold_id,
            note: None,
        },
    )
    .await;
    assert_eq!(st_cosign, StatusCode::OK);
    assert_eq!(active_hold.hold.expect("active hold").lifecycle, "active");

    // Re-identification 2-approver quorum enforced via authenticated principals
    let (st, reid_req): (_, RequestReidentificationResponse) = post_json(
        &console_app,
        "/grdr.api.surfaces.v1alpha1.SurfaceService/RequestReidentification",
        ALICE_TOK,
        true,
        false,
        &RequestReidentificationRequest {
            pseudonym_id: "prn_test_01".into(),
            reason: "Verify owner".into(),
            legal_basis: "Art. 6(1)(f)".into(),
        },
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let reid_id = reid_req.request.expect("req").request_id;

    let (st_self_reid, _) = post_raw_json(
        &console_app,
        "/grdr.api.surfaces.v1alpha1.SurfaceService/ApproveReidentification",
        Some(ALICE_TOK),
        true,
        &ApproveReidentificationRequest {
            request_id: reid_id.clone(),
            note: None,
        },
    )
    .await;
    assert_eq!(st_self_reid, StatusCode::BAD_REQUEST);

    let (st_bob, _) = post_raw_json(
        &console_app,
        "/grdr.api.surfaces.v1alpha1.SurfaceService/ApproveReidentification",
        Some(BOB_TOK),
        true,
        &ApproveReidentificationRequest {
            request_id: reid_id.clone(),
            note: None,
        },
    )
    .await;
    assert_eq!(st_bob, StatusCode::OK);

    let (st_charlie, approved_reid): (_, ApproveReidentificationResponse) = post_json(
        &console_app,
        "/grdr.api.surfaces.v1alpha1.SurfaceService/ApproveReidentification",
        CHARLIE_TOK,
        true,
        false,
        &ApproveReidentificationRequest {
            request_id: reid_id,
            note: None,
        },
    )
    .await;
    assert_eq!(st_charlie, StatusCode::OK);
    assert!(
        approved_reid
            .request
            .expect("reid")
            .resolved_identity
            .is_some()
    );

    // First-run + per-principal Provider acting-as isolation + Ring promotion
    let (st, fr): (_, CompleteFirstRunResponse) = post_json(
        &console_app,
        "/grdr.api.surfaces.v1alpha1.SurfaceService/CompleteFirstRun",
        CONSOLE_TOK,
        true,
        false,
        &CompleteFirstRunRequest {
            profile: "protected".into(),
            confirm_protection: true,
            step_up_enabled: true,
        },
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(fr.first_run.expect("first_run").confirmed);

    let (st, switched): (_, SwitchProviderOrgResponse) = post_json(
        &console_app,
        "/grdr.api.surfaces.v1alpha1.SurfaceService/SwitchProviderOrg",
        ALICE_TOK,
        true,
        false,
        &SwitchProviderOrgRequest {
            org_id: Some("org-acme-core".into()),
            reason: Some("Review queue drill".into()),
        },
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(switched.acting_as_org_id.as_deref(), Some("org-acme-core"));

    // Bob must NOT see Alice's acting-as session
    let (st, bob_ws): (_, GetProviderWorkspaceResponse) = post_json(
        &console_app,
        "/grdr.api.surfaces.v1alpha1.SurfaceService/GetProviderWorkspace",
        BOB_TOK,
        false,
        false,
        &GetProviderWorkspaceRequest::default(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(bob_ws.acting_as_org_id.is_none());

    let (st, promoted_ring): (_, AdvanceProviderRingResponse) = post_json(
        &console_app,
        "/grdr.api.surfaces.v1alpha1.SurfaceService/AdvanceProviderRing",
        CONSOLE_TOK,
        true,
        false,
        &AdvanceProviderRingRequest {
            ring: "canary".into(),
            target_version: "1.3.0".into(),
        },
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(promoted_ring.ring.expect("ring").target_version, "1.3.0");

    // Live stream ticket (never puts api_token in URL)
    let (st, ticket): (_, IssueLiveTicketResponse) = post_json(
        &console_app,
        "/grdr.api.overview.v1alpha1.OverviewService/IssueLiveTicket",
        CONSOLE_TOK,
        false,
        false,
        &IssueLiveTicketRequest {},
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(!ticket.ticket.is_empty());

    // Operator Plane isolated router workflows
    let (st, op_state): (_, GetOperatorStateResponse) = post_json(
        &operator_app,
        "/grdr.api.operator.v1alpha1.OperatorService/GetOperatorState",
        OP_TOK,
        false,
        false,
        &GetOperatorStateRequest {},
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(op_state.runtime_config.is_some());

    let (st, staged): (_, StageConfigRevisionResponse) = post_json(
        &operator_app,
        "/grdr.api.operator.v1alpha1.OperatorService/StageConfigRevision",
        OP_TOK,
        true,
        false,
        &StageConfigRevisionRequest {
            capture_level: "metadata-and-signals".into(),
            privacy_profile: "standard".into(),
            retention_preset: "default".into(),
            otlp_enabled: false,
            release_channel: "canary".into(),
            summary: "Enable telemetry signals".into(),
        },
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let rev_id = staged.revision.expect("staged").revision_id;

    let (st, applied): (_, ApplyConfigRevisionResponse) = post_json(
        &operator_app,
        "/grdr.api.operator.v1alpha1.OperatorService/ApplyConfigRevision",
        OP_TOK,
        true,
        false,
        &ApplyConfigRevisionRequest {
            revision_id: rev_id,
        },
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        applied.runtime_config.expect("cfg").capture_level,
        "metadata-and-signals"
    );

    let (st, rolled): (_, RollbackConfigRevisionResponse) = post_json(
        &operator_app,
        "/grdr.api.operator.v1alpha1.OperatorService/RollbackConfigRevision",
        OP_TOK,
        true,
        false,
        &RollbackConfigRevisionRequest {
            target_revision_id: None,
            reason: "Revert baseline".into(),
        },
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        rolled.runtime_config.expect("cfg").capture_level,
        "metadata-only"
    );

    let (st, preflight): (_, RunUpgradePreflightResponse) = post_json(
        &operator_app,
        "/grdr.api.operator.v1alpha1.OperatorService/RunUpgradePreflight",
        OP_TOK,
        true,
        false,
        &RunUpgradePreflightRequest {
            target_version: "0.3.0".into(),
        },
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(preflight.overall_compatible);

    let (st, reset): (_, ResetTargetBreakerResponse) = post_json(
        &operator_app,
        "/grdr.api.operator.v1alpha1.OperatorService/ResetTargetBreaker",
        OP_TOK,
        true,
        false,
        &ResetTargetBreakerRequest {
            target_id: "target-relational".into(),
        },
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(reset.target.expect("target").circuit_state, "closed");

    let (st, otlp_reset): (_, ResetTargetBreakerResponse) = post_json(
        &operator_app,
        "/grdr.api.operator.v1alpha1.OperatorService/ResetTargetBreaker",
        OP_TOK,
        true,
        false,
        &ResetTargetBreakerRequest {
            target_id: "target-otlp-fanout".into(),
        },
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(otlp_reset.target.expect("otlp").circuit_state, "closed");

    let (st, disable_staged): (_, StageConfigRevisionResponse) = post_json(
        &operator_app,
        "/grdr.api.operator.v1alpha1.OperatorService/StageConfigRevision",
        OP_TOK,
        true,
        false,
        &StageConfigRevisionRequest {
            capture_level: "metadata-only".into(),
            privacy_profile: "standard".into(),
            retention_preset: "default".into(),
            otlp_enabled: false,
            release_channel: "stable".into(),
            summary: "Disable OTLP to verify probe half-open degradation".into(),
        },
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let disable_id = disable_staged.revision.expect("disable staged").revision_id;
    let (st, _): (_, ApplyConfigRevisionResponse) = post_json(
        &operator_app,
        "/grdr.api.operator.v1alpha1.OperatorService/ApplyConfigRevision",
        OP_TOK,
        true,
        false,
        &ApplyConfigRevisionRequest {
            revision_id: disable_id,
        },
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    let (st, otlp_degraded): (_, ResetTargetBreakerResponse) = post_json(
        &operator_app,
        "/grdr.api.operator.v1alpha1.OperatorService/ResetTargetBreaker",
        OP_TOK,
        true,
        false,
        &ResetTargetBreakerRequest {
            target_id: "target-otlp-fanout".into(),
        },
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        otlp_degraded.target.expect("otlp").circuit_state,
        "half_open"
    );

    let (st, drill): (_, RunBackupDrillResponse) = post_json(
        &operator_app,
        "/grdr.api.operator.v1alpha1.OperatorService/RunBackupDrill",
        OP_TOK,
        true,
        false,
        &RunBackupDrillRequest {
            kind: "restore".into(),
            note: Some("Pre-upgrade verification".into()),
        },
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(drill.drill.expect("drill").kind, "restore");
}

#[tokio::test]
async fn security_planes_fail_closed_and_block_downgrades() {
    let state = AppState::init(StorageBackend::Memory, true).expect("init store");
    let sec = test_security();
    let console_app = routes::build_console_router_with_security(state.clone(), None, sec.clone());
    let operator_app = routes::build_operator_router_with_security(state.clone(), None, sec);

    // 1. Fail-closed auth on both planes (missing and wrong tokens -> 401)
    let (st, _) = post_raw_json(
        &console_app,
        "/grdr.api.surfaces.v1alpha1.SurfaceService/ListReviewQueue",
        None,
        false,
        &ListReviewQueueRequest::default(),
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);

    let (st, _) = post_raw_json(
        &operator_app,
        "/grdr.api.operator.v1alpha1.OperatorService/GetOperatorState",
        None,
        false,
        &GetOperatorStateRequest::default(),
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);

    // 2. D-70 cross-plane token rejection & route isolation
    let (st, _) = post_raw_json(
        &operator_app,
        "/grdr.api.operator.v1alpha1.OperatorService/GetOperatorState",
        Some(CONSOLE_TOK),
        false,
        &GetOperatorStateRequest::default(),
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);

    let (st, _) = post_raw_json(
        &console_app,
        "/grdr.api.surfaces.v1alpha1.SurfaceService/ListReviewQueue",
        Some(OP_TOK),
        false,
        &ListReviewQueueRequest::default(),
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);

    let op_on_console = console_app
        .clone()
        .oneshot(
            Request::post("/grdr.api.operator.v1alpha1.OperatorService/GetOperatorState")
                .header(header::AUTHORIZATION, format!("Bearer {CONSOLE_TOK}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(op_on_console.status(), StatusCode::NOT_FOUND);

    // 3. Mutating RunUpgradePreflight rejects GET -> 405 Method Not Allowed
    let preflight_get = operator_app
        .clone()
        .oneshot(
            Request::get(
                "/grdr.api.operator.v1alpha1.OperatorService/RunUpgradePreflight?encoding=json",
            )
            .header(header::AUTHORIZATION, format!("Bearer {OP_TOK}"))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(preflight_get.status(), StatusCode::METHOD_NOT_ALLOWED);

    // 4. AdvanceProviderRing rejects downward rollback (1.2.0 -> 0.0.1)
    let (st_down, _) = post_raw_json(
        &console_app,
        "/grdr.api.surfaces.v1alpha1.SurfaceService/AdvanceProviderRing",
        Some(CONSOLE_TOK),
        true,
        &AdvanceProviderRingRequest {
            ring: "canary".into(),
            target_version: "0.0.1".into(),
        },
    )
    .await;
    assert_eq!(st_down, StatusCode::BAD_REQUEST);

    // 5. Locked rule promotion via DecideReviewCluster is rejected explicitly
    let (_, queue): (_, ListReviewQueueResponse) = post_json(
        &console_app,
        "/grdr.api.surfaces.v1alpha1.SurfaceService/ListReviewQueue",
        CONSOLE_TOK,
        false,
        false,
        &ListReviewQueueRequest::default(),
    )
    .await;
    let locked_cluster = queue
        .clusters
        .iter()
        .find(|c| c.rule_id == "essentials.agent-control-files")
        .expect("locked cluster");
    let (st_lock, _) = post_raw_json(
        &console_app,
        "/grdr.api.surfaces.v1alpha1.SurfaceService/DecideReviewCluster",
        Some(CONSOLE_TOK),
        true,
        &DecideReviewClusterRequest {
            id: locked_cluster.id.clone(),
            decision: "promote".into(),
            target_mode: Some("watch".into()),
            note: None,
            actor: None,
        },
    )
    .await;
    assert_eq!(st_lock, StatusCode::BAD_REQUEST);

    // 6. Works-council downgrade to standard rejected without step-up
    let (st_wc, _) = post_raw_json(
        &console_app,
        "/grdr.api.surfaces.v1alpha1.SurfaceService/UpdateCompliancePolicy",
        Some(CONSOLE_TOK),
        true,
        &UpdateCompliancePolicyRequest {
            privacy_profile: "works-council".into(),
            presets: vec!["default".into()],
            override_legal_basis: None,
            capture_level: None,
        },
    )
    .await;
    assert_eq!(st_wc, StatusCode::OK);

    let (st_downgrade, _) = post_raw_json(
        &console_app,
        "/grdr.api.surfaces.v1alpha1.SurfaceService/UpdateCompliancePolicy",
        Some(CONSOLE_TOK),
        true,
        &UpdateCompliancePolicyRequest {
            privacy_profile: "standard".into(),
            presets: vec!["default".into()],
            override_legal_basis: None,
            capture_level: None,
        },
    )
    .await;
    assert_eq!(st_downgrade, StatusCode::BAD_REQUEST);

    // 7. Static `X-Grdr-Step-Up: verified` MUST NOT bypass step-up (neither ConfirmedIntent nor admin)
    let (st_alice_spoof, _) = post_raw_json_with_headers(
        &console_app,
        "/grdr.api.surfaces.v1alpha1.SurfaceService/UpdateCompliancePolicy",
        Some(ALICE_TOK),
        true,
        Some("verified"),
        &UpdateCompliancePolicyRequest {
            privacy_profile: "standard".into(),
            presets: vec!["default".into()],
            override_legal_basis: Some("Legal Art. 6(1)(c)".into()),
            capture_level: None,
        },
    )
    .await;
    assert_eq!(st_alice_spoof, StatusCode::BAD_REQUEST);

    let (st_admin_spoof, _) = post_raw_json_with_headers(
        &console_app,
        "/grdr.api.surfaces.v1alpha1.SurfaceService/UpdateCompliancePolicy",
        Some(CONSOLE_TOK),
        true,
        Some("verified"),
        &UpdateCompliancePolicyRequest {
            privacy_profile: "standard".into(),
            presets: vec!["default".into()],
            override_legal_basis: Some("Legal Art. 6(1)(c)".into()),
            capture_level: None,
        },
    )
    .await;
    assert_eq!(st_admin_spoof, StatusCode::BAD_REQUEST);

    // StepUpVerified principal succeeds cleanly without static header spoof
    let (st_dpo_ok, _) = post_raw_json(
        &console_app,
        "/grdr.api.surfaces.v1alpha1.SurfaceService/UpdateCompliancePolicy",
        Some(DPO_STEPUP_TOK),
        true,
        &UpdateCompliancePolicyRequest {
            privacy_profile: "standard".into(),
            presets: vec!["default".into()],
            override_legal_basis: Some("DPO approved review".into()),
            capture_level: None,
        },
    )
    .await;
    assert_eq!(st_dpo_ok, StatusCode::OK);

    // 8. Tenant isolation across Reidentification, Disclosures, Legal Holds, and Review Overrides
    let (st, reid_a): (_, RequestReidentificationResponse) = post_json(
        &console_app,
        "/grdr.api.surfaces.v1alpha1.SurfaceService/RequestReidentification",
        ALICE_TOK,
        true,
        false,
        &RequestReidentificationRequest {
            pseudonym_id: "prn_iso_a".into(),
            reason: "Tenant A incident".into(),
            legal_basis: "Art. 6(1)(f)".into(),
        },
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let reid_a_id = reid_a.request.expect("reid_a").request_id;

    let (st_cross_reid, _) = post_raw_json(
        &console_app,
        "/grdr.api.surfaces.v1alpha1.SurfaceService/ApproveReidentification",
        Some(TENANT_B_TOK),
        true,
        &ApproveReidentificationRequest {
            request_id: reid_a_id.clone(),
            note: None,
        },
    )
    .await;
    assert_eq!(st_cross_reid, StatusCode::NOT_FOUND);

    let (st, comp_b): (_, GetComplianceWorkspaceResponse) = post_json(
        &console_app,
        "/grdr.api.surfaces.v1alpha1.SurfaceService/GetComplianceWorkspace",
        TENANT_B_TOK,
        false,
        false,
        &GetComplianceWorkspaceRequest {},
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(
        !comp_b
            .reid_requests
            .iter()
            .any(|r| r.request_id == reid_a_id)
    );
    assert!(
        !comp_b
            .disclosures
            .iter()
            .any(|d| d.target_ref == "Standard")
    );

    let (st, _) = post_json::<_, DecideReviewClusterResponse>(
        &console_app,
        "/grdr.api.surfaces.v1alpha1.SurfaceService/DecideReviewCluster",
        ALICE_TOK,
        true,
        false,
        &DecideReviewClusterRequest {
            id: locked_cluster.id.clone(),
            decision: "suppress".into(),
            target_mode: None,
            note: Some("Tenant A note".into()),
            actor: None,
        },
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    let (st, queue_b): (_, ListReviewQueueResponse) = post_json(
        &console_app,
        "/grdr.api.surfaces.v1alpha1.SurfaceService/ListReviewQueue",
        TENANT_B_TOK,
        false,
        false,
        &ListReviewQueueRequest::default(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let b_cluster = queue_b
        .clusters
        .iter()
        .find(|c| c.id == locked_cluster.id)
        .expect("tenant b cluster");
    assert_eq!(b_cluster.status, 1);
}

#[tokio::test]
async fn persistence_roundtrip_compliance_honesty_and_csprng_work() {
    // 1. CSPRNG bearer tokens & single-use live tickets emit full-entropy distinct hex values
    let tok1 = generate_random_bearer_token().expect("token1");
    let tok2 = generate_random_bearer_token().expect("token2");
    assert_eq!(tok1.len(), 64);
    assert_eq!(tok2.len(), 64);
    assert_ne!(tok1, tok2);
    assert!(tok1.chars().all(|c| c.is_ascii_hexdigit()));

    // 2. Empty unseeded store reports real `not-met` compliance evidence and AL0 assurance
    let empty_state = AppState::init(StorageBackend::Memory, false).expect("init empty");
    let sec = test_security();
    let empty_console =
        routes::build_console_router_with_security(empty_state.clone(), None, sec.clone());
    let (st, empty_comp): (_, GetComplianceWorkspaceResponse) = post_json(
        &empty_console,
        "/grdr.api.surfaces.v1alpha1.SurfaceService/GetComplianceWorkspace",
        CONSOLE_TOK,
        false,
        false,
        &GetComplianceWorkspaceRequest {},
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(!empty_comp.evidence_items.is_empty());
    assert!(
        empty_comp
            .evidence_items
            .iter()
            .all(|e| e.result == "not-met")
    );

    let (st, grc_empty): (_, PushGrcEvidenceResponse) = post_json(
        &empty_console,
        "/grdr.api.surfaces.v1alpha1.SurfaceService/PushGrcEvidence",
        CONSOLE_TOK,
        true,
        false,
        &PushGrcEvidenceRequest {
            target: "ciso-assistant".into(),
        },
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(grc_empty.payload_preview.contains("\"AL0\""));

    let (st, ticket1): (_, IssueLiveTicketResponse) = post_json(
        &empty_console,
        "/grdr.api.overview.v1alpha1.OverviewService/IssueLiveTicket",
        CONSOLE_TOK,
        false,
        false,
        &IssueLiveTicketRequest {},
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let (st, ticket2): (_, IssueLiveTicketResponse) = post_json(
        &empty_console,
        "/grdr.api.overview.v1alpha1.OverviewService/IssueLiveTicket",
        CONSOLE_TOK,
        false,
        false,
        &IssueLiveTicketRequest {},
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_ne!(ticket1.ticket, ticket2.ticket);
    assert_eq!(ticket1.ticket.len(), 64);
    assert!(empty_state.consume_live_ticket(&ticket1.ticket).is_some());
    assert!(empty_state.consume_live_ticket(&ticket1.ticket).is_none());

    // 3. Disk persistence preserves StoreData.surfaces across reopen
    let dir = std::env::temp_dir().join(format!(
        "grdr-surfaces-sqlite-{}",
        uuid::Uuid::now_v7().simple()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let hold_id;
    let rev_id;
    {
        let disk_state =
            AppState::init(StorageBackend::Disk(dir.clone()), true).expect("disk init");
        let console_app =
            routes::build_console_router_with_security(disk_state.clone(), None, sec.clone());
        let operator_app =
            routes::build_operator_router_with_security(disk_state, None, sec.clone());

        let (st, proposed): (_, CreateLegalHoldResponse) = post_json(
            &console_app,
            "/grdr.api.surfaces.v1alpha1.SurfaceService/CreateLegalHold",
            ALICE_TOK,
            true,
            false,
            &CreateLegalHoldRequest {
                matter_ref: "MATTER-DISK-01".into(),
                reason: "Disk persistence test".into(),
                pseudonym_or_session: "prn_disk_01".into(),
            },
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        hold_id = proposed.hold.expect("hold").hold_id;

        let (st, staged): (_, StageConfigRevisionResponse) = post_json(
            &operator_app,
            "/grdr.api.operator.v1alpha1.OperatorService/StageConfigRevision",
            OP_TOK,
            true,
            false,
            &StageConfigRevisionRequest {
                capture_level: "metadata-and-signals".into(),
                privacy_profile: "standard".into(),
                retention_preset: "default".into(),
                otlp_enabled: false,
                release_channel: "canary".into(),
                summary: "Disk persisted revision".into(),
            },
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        rev_id = staged.revision.expect("rev").revision_id;
    }

    {
        let reopened = AppState::init(StorageBackend::Disk(dir.clone()), false).expect("reopen");
        let console_app =
            routes::build_console_router_with_security(reopened.clone(), None, sec.clone());
        let operator_app = routes::build_operator_router_with_security(reopened, None, sec);

        let (st, comp): (_, GetComplianceWorkspaceResponse) = post_json(
            &console_app,
            "/grdr.api.surfaces.v1alpha1.SurfaceService/GetComplianceWorkspace",
            CONSOLE_TOK,
            false,
            false,
            &GetComplianceWorkspaceRequest {},
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert!(comp.legal_holds.iter().any(|h| h.hold_id == hold_id));

        let (st, op): (_, GetOperatorStateResponse) = post_json(
            &operator_app,
            "/grdr.api.operator.v1alpha1.OperatorService/GetOperatorState",
            OP_TOK,
            false,
            false,
            &GetOperatorStateRequest {},
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert!(op.revisions.iter().any(|r| r.revision_id == rev_id));
    }
    let _ = std::fs::remove_dir_all(&dir);
}
