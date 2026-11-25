// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use prost::Message as _;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tower::ServiceExt as _;

use grdr_model::proto_conv::{
    action_class_to_proto, browser_dlp_to_proto, grant_scope_to_proto, identity_mode_to_proto,
    mdm_format_to_proto, mode_to_proto,
};
use grdr_model::{BrowserDlpClass, GrantScope, IdentityMode, MdmFormat, Mode};
use grdr_ports::ProfileKind;
use grdr_proto::api::activity::{
    GetQueryEntitiesResponse, GetQuerySchemaResponse, GetQueryUserIntentResponse,
    GetSessionRequest, GetSessionResponse, ListSessionsRequest, SampleQueryRequest,
    SampleQueryResponse,
};
use grdr_proto::api::inventory::{
    CheckIntegrationReadinessRequest, CheckIntegrationReadinessResponse,
    CreateDeploymentKeyRequest, CreateDeploymentKeyResponse, DeviceCheckinRequest,
    DeviceCheckinResponse, GetConnectConfigResponse, ListDevicesRequest, ListDevicesResponse,
    RenderMdmConfigRequest, RenderMdmConfigResponse, RevokeDeploymentKeyRequest,
    RevokeDeploymentKeyResponse,
};
use grdr_proto::api::overview::{
    ExportAuditJsonlResponse, ExportOcsfResponse, GetHealthResponse, GetOverviewResponse,
    ListKeysResponse,
};
use grdr_proto::api::policy::{
    CreateRuleRequest, CreateRuleResponse, DeleteRuleRequest, ListBrowserPoliciesResponse,
    ListPacksResponse, ReplayRuleRequest, ReplayRuleResponse, UpdateBrowserPolicyRequest,
    UpdateBrowserPolicyResponse, UpdateRuleModeRequest, UpdateRuleModeResponse, UpdateRuleRequest,
};
use grdr_proto::api::response::{
    DecideApprovalRequest, DecideApprovalResponse, ListApprovalsRequest, ListApprovalsResponse,
    ListIncidentsRequest, ListIncidentsResponse, SetKillSwitchRequest, SetKillSwitchResponse,
};
use grdr_proto::api::tenancy::{
    GetUserRequest, GetUserResponse, ListUsersRequest, ListUsersResponse,
    UpdatePrivacyConfigRequest,
};
use grdr_proto::api::verdict::{
    EvaluateBrowserRequest, EvaluateBrowserResponse, EvaluateRequest, EvaluateResponse,
};
use grdr_proto::common::{
    ActionClass, ApprovalStatus, DeploymentKeyStatus, InstallProfile, KillAction, KillScope,
    KillState, RuleMatch, Verdict,
};

use crate::auth::ServerSecurityConfig;
use crate::routes;
use crate::store::{AppState, StorageBackend};

async fn rpc_post_json<Req: Serialize, Resp: DeserializeOwned>(
    app: &Router,
    path: &str,
    req: &Req,
) -> (StatusCode, Resp) {
    let resp = app
        .clone()
        .oneshot(
            Request::post(path)
                .header(header::AUTHORIZATION, "Bearer test-console-token")
                .header("x-grdr-confirm", "confirmed")
                .header(header::CONTENT_TYPE, "application/json")
                .header("connect-protocol-version", "1")
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
            "decode {path} status={status}: {e}: {}",
            String::from_utf8_lossy(&bytes)
        )
    });
    (status, parsed)
}

async fn rpc_post_raw<Req: Serialize>(
    app: &Router,
    path: &str,
    req: &Req,
) -> (StatusCode, axum::http::HeaderMap, serde_json::Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::post(path)
                .header(header::AUTHORIZATION, "Bearer test-console-token")
                .header("x-grdr-confirm", "confirmed")
                .header(header::CONTENT_TYPE, "application/json")
                .header("connect-protocol-version", "1")
                .body(Body::from(serde_json::to_vec(req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    (status, headers, val)
}

#[tokio::test]
async fn connect_unary_json_proto_get_etag_and_error_envelope() {
    let state = AppState::init(StorageBackend::Memory, true).unwrap();
    let app = routes::build_router(state, None);

    // Connect GET health
    let health_resp = app
        .clone()
        .oneshot(
            Request::get("/grdr.api.overview.v1alpha1.OverviewService/GetHealth?encoding=json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(health_resp.status(), StatusCode::OK);
    assert!(health_resp.headers().contains_key("grdr-request-id"));
    let health_bytes = axum::body::to_bytes(health_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let health: GetHealthResponse = serde_json::from_slice(&health_bytes).unwrap();
    assert!(!health.version.is_empty());

    // Connect GET Overview with ETag + If-None-Match -> 304 Not Modified
    let ov_resp = app
        .clone()
        .oneshot(
            Request::get("/grdr.api.overview.v1alpha1.OverviewService/GetOverview?encoding=json")
                .header(header::AUTHORIZATION, "Bearer test-console-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ov_resp.status(), StatusCode::OK);
    let etag = ov_resp
        .headers()
        .get(header::ETAG)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let ov_bytes = axum::body::to_bytes(ov_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let ov: GetOverviewResponse = serde_json::from_slice(&ov_bytes).unwrap();
    assert!(ov.total_devices > 0);

    let not_mod = app
        .clone()
        .oneshot(
            Request::get("/grdr.api.overview.v1alpha1.OverviewService/GetOverview?encoding=json")
                .header(header::AUTHORIZATION, "Bearer test-console-token")
                .header(header::IF_NONE_MATCH, &etag)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(not_mod.status(), StatusCode::NOT_MODIFIED);

    // Connect binary Protobuf wire encoding (application/proto)
    let list_req = ListDevicesRequest {
        page_size: 2,
        page_token: String::new(),
        filter: String::new(),
        order_by: "hostname asc".into(),
    };
    let proto_resp = app
        .clone()
        .oneshot(
            Request::post("/grdr.api.inventory.v1alpha1.InventoryService/ListDevices")
                .header(header::AUTHORIZATION, "Bearer test-console-token")
                .header(header::CONTENT_TYPE, "application/proto")
                .header("connect-protocol-version", "1")
                .body(Body::from(list_req.encode_to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(proto_resp.status(), StatusCode::OK);
    assert_eq!(
        proto_resp
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap(),
        "application/proto"
    );
    let proto_bytes = axum::body::to_bytes(proto_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let decoded = ListDevicesResponse::decode(proto_bytes.as_ref()).unwrap();
    assert_eq!(decoded.devices.len(), 2);
    assert!(decoded.page_info.unwrap().total_size_estimate >= 2);
}

#[tokio::test]
async fn aip158_sealed_pagination_and_aip160_filtering() {
    let state = AppState::init(StorageBackend::Memory, true).unwrap();
    let app = routes::build_router(state, None);

    // Seed extra devices so we span multiple pages
    for i in 1..=5 {
        let req = DeviceCheckinRequest {
            device_id: Some(format!("dev-page-{i}")),
            hostname: format!("host-page-{i:02}"),
            os: if i % 2 == 0 {
                "linux".into()
            } else {
                "macos".into()
            },
            arch: "arm64".into(),
            install_profile: InstallProfile::Protected as i32,
            daemon_version: "0.1.0".into(),
            hook_effective: true,
            ..Default::default()
        };
        let (st, _): (_, DeviceCheckinResponse) = rpc_post_json(
            &app,
            "/grdr.api.inventory.v1alpha1.InventoryService/DeviceCheckin",
            &req,
        )
        .await;
        assert_eq!(st, StatusCode::OK);
    }

    let (st1, p1): (_, ListDevicesResponse) = rpc_post_json(
        &app,
        "/grdr.api.inventory.v1alpha1.InventoryService/ListDevices",
        &ListDevicesRequest {
            page_size: 2,
            page_token: String::new(),
            filter: "os = macos".into(),
            order_by: "hostname asc".into(),
        },
    )
    .await;
    assert_eq!(st1, StatusCode::OK);
    assert_eq!(p1.devices.len(), 2);
    let info1 = p1.page_info.unwrap();
    assert!(info1.has_more);
    assert!(info1.total_size_estimate >= 3);
    assert!(!info1.next_page_token.is_empty());

    let (st2, p2): (_, ListDevicesResponse) = rpc_post_json(
        &app,
        "/grdr.api.inventory.v1alpha1.InventoryService/ListDevices",
        &ListDevicesRequest {
            page_size: 2,
            page_token: info1.next_page_token.clone(),
            filter: "os = macos".into(),
            order_by: "hostname asc".into(),
        },
    )
    .await;
    assert_eq!(st2, StatusCode::OK);
    assert!(!p2.devices.is_empty());
    assert_ne!(p2.devices[0].id, p1.devices[0].id);

    // Filter mismatch with existing page_token -> PAGE_TOKEN_INVALID + ErrorInfo
    let (err_status, headers, err_json) = rpc_post_raw(
        &app,
        "/grdr.api.inventory.v1alpha1.InventoryService/ListDevices",
        &ListDevicesRequest {
            page_size: 2,
            page_token: info1.next_page_token.clone(),
            filter: "os = linux".into(),
            order_by: "hostname asc".into(),
        },
    )
    .await;
    assert_eq!(err_status, StatusCode::BAD_REQUEST);
    assert!(headers.contains_key("grdr-request-id"));
    assert_eq!(err_json["code"], "invalid_argument");
    assert_eq!(err_json["details"][0]["type"], "google.rpc.ErrorInfo");
    assert_eq!(err_json["details"][0]["debug"]["domain"], "grdr.api");
    assert_eq!(
        err_json["details"][0]["debug"]["reason"],
        "PAGE_TOKEN_INVALID"
    );
    assert_eq!(
        err_json["details"][0]["debug"]["metadata"]["code"],
        "GRDR-API-0011"
    );

    // Tampered token fails
    let (tamper_status, _, tamper_json) = rpc_post_raw(
        &app,
        "/grdr.api.inventory.v1alpha1.InventoryService/ListDevices",
        &ListDevicesRequest {
            page_size: 2,
            page_token: "tampered_token_xyz".into(),
            filter: String::new(),
            order_by: String::new(),
        },
    )
    .await;
    assert_eq!(tamper_status, StatusCode::BAD_REQUEST);
    assert_eq!(
        tamper_json["details"][0]["debug"]["reason"],
        "PAGE_TOKEN_INVALID"
    );

    // Non-filterable / content field rejected with INVALID_FILTER
    let (bad_filter_status, _, bad_filter_json) = rpc_post_raw(
        &app,
        "/grdr.api.activity.v1alpha1.SessionService/ListSessions",
        &ListSessionsRequest {
            page_size: 10,
            page_token: String::new(),
            filter: "target = secret".into(),
            order_by: String::new(),
        },
    )
    .await;
    assert_eq!(bad_filter_status, StatusCode::BAD_REQUEST);
    assert_eq!(
        bad_filter_json["details"][0]["debug"]["reason"],
        "INVALID_FILTER"
    );
}

#[tokio::test]
async fn lifecycle_evaluate_approve_replay_and_kill_switch() {
    let state = AppState::init(StorageBackend::Memory, true).unwrap();
    let app = routes::build_router(state, None);

    let (st, _) = rpc_post_json::<_, DeviceCheckinResponse>(
        &app,
        "/grdr.api.inventory.v1alpha1.InventoryService/DeviceCheckin",
        &DeviceCheckinRequest {
            device_id: Some("dev-test-1".into()),
            hostname: "ci-runner".into(),
            os: "linux".into(),
            arch: "x86_64".into(),
            install_profile: InstallProfile::User as i32,
            daemon_version: "0.1.0".into(),
            hook_effective: true,
            ..Default::default()
        },
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    let (st, eval_resp): (_, EvaluateResponse) = rpc_post_json(
        &app,
        "/grdr.api.verdict.v1alpha1.VerdictService/Evaluate",
        &EvaluateRequest {
            session_id: Some("sess-int-1".into()),
            device_id: Some("dev-test-1".into()),
            device_name: Some("ci-runner".into()),
            agent_name: "claude-code".into(),
            action_class: action_class_to_proto(grdr_model::ActionClass::FileRead),
            control_point: None,
            target: "/home/ci/.ssh/id_rsa".into(),
            summary: None,
        },
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let receipt = eval_resp.receipt.unwrap();
    assert_eq!(receipt.verdict, Verdict::StepUp as i32);

    let (st, approvals_resp): (_, ListApprovalsResponse) = rpc_post_json(
        &app,
        "/grdr.api.response.v1alpha1.ResponseService/ListApprovals",
        &ListApprovalsRequest {
            filter: "session_id = sess-int-1".into(),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let pending = approvals_resp.approvals.into_iter().next().unwrap();
    assert_eq!(pending.status, ApprovalStatus::Pending as i32);

    let (st, decided): (_, DecideApprovalResponse) = rpc_post_json(
        &app,
        "/grdr.api.response.v1alpha1.ResponseService/DecideApproval",
        &DecideApprovalRequest {
            id: pending.id,
            approve: true,
            scope: Some(grant_scope_to_proto(GrantScope::Session)),
            note: Some("Verified CI key read".into()),
            actor: Some("tester".into()),
        },
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        decided.approval.unwrap().status,
        ApprovalStatus::Approved as i32
    );

    let (st, granted_resp): (_, EvaluateResponse) = rpc_post_json(
        &app,
        "/grdr.api.verdict.v1alpha1.VerdictService/Evaluate",
        &EvaluateRequest {
            session_id: Some("sess-int-1".into()),
            device_id: Some("dev-test-1".into()),
            device_name: Some("ci-runner".into()),
            agent_name: "claude-code".into(),
            action_class: action_class_to_proto(grdr_model::ActionClass::FileRead),
            control_point: None,
            target: "/home/ci/.ssh/id_rsa".into(),
            summary: None,
        },
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let granted = granted_resp.receipt.unwrap();
    assert_eq!(granted.verdict, Verdict::Allow as i32);
    assert!(granted.grant_id.is_some());

    let (st, replay_resp): (_, ReplayRuleResponse) = rpc_post_json(
        &app,
        "/grdr.api.policy.v1alpha1.PolicyService/ReplayRule",
        &ReplayRuleRequest {
            id: "essentials.secret-exfil-egress".into(),
            candidate_mode: mode_to_proto(Mode::Block),
        },
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(replay_resp.summary.unwrap().total_scanned >= 1);

    let (st, ks_resp): (_, SetKillSwitchResponse) = rpc_post_json(
        &app,
        "/grdr.api.response.v1alpha1.ResponseService/SetKillSwitch",
        &SetKillSwitchRequest {
            action: KillAction::Freeze as i32,
            scope: KillScope::Organisation as i32,
            target_id: "org-default".into(),
            reason: "Drill".into(),
            duration_minutes: Some(15),
        },
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(ks_resp.kill_switch.unwrap().state, KillState::Frozen as i32);
}

#[tokio::test]
async fn connect_auth_rules_exports_keys_and_privacy_modes() {
    let state = AppState::init(StorageBackend::Memory, true).unwrap();
    let app = routes::build_router_with_security(
        state,
        None,
        ServerSecurityConfig {
            api_token: Some("op-secret".into()),
            operator_token: Some("dedicated-op-secret".into()),
            enroll_token: Some("enroll-secret".into()),
            ..Default::default()
        },
    );

    // Public health succeeds without auth
    let health = app
        .clone()
        .oneshot(
            Request::get("/grdr.api.overview.v1alpha1.OverviewService/GetHealth")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::OK);

    // Operator RPC without token -> Connect 401 Unauthenticated
    let unauth = app
        .clone()
        .oneshot(
            Request::post("/grdr.api.overview.v1alpha1.OverviewService/GetOverview")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);
    let unauth_json: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(unauth.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(unauth_json["code"], "unauthenticated");

    // With operator bearer token -> ListKeys, ExportOcsf, ExportAuditJsonl work
    let keys_resp = app
        .clone()
        .oneshot(
            Request::post("/grdr.api.overview.v1alpha1.OverviewService/ListKeys")
                .header(header::AUTHORIZATION, "Bearer op-secret")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(keys_resp.status(), StatusCode::OK);
    let keys: ListKeysResponse = serde_json::from_slice(
        &axum::body::to_bytes(keys_resp.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(!keys.keys.is_empty());

    let ocsf_resp = app
        .clone()
        .oneshot(
            Request::post("/grdr.api.overview.v1alpha1.OverviewService/ExportOcsf")
                .header(header::AUTHORIZATION, "Bearer op-secret")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    let ocsf: ExportOcsfResponse = serde_json::from_slice(
        &axum::body::to_bytes(ocsf_resp.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(ocsf.payload.contains("activity_id"));

    let audit_resp = app
        .oneshot(
            Request::post("/grdr.api.overview.v1alpha1.OverviewService/ExportAuditJsonl")
                .header(header::AUTHORIZATION, "Bearer op-secret")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    let audit: ExportAuditJsonlResponse = serde_json::from_slice(
        &axum::body::to_bytes(audit_resp.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(!audit.payload.is_empty());
}

#[tokio::test]
async fn connect_inventory_query_browser_policy_and_sqlite_persistence() {
    let state = AppState::init(StorageBackend::Memory, true).unwrap();
    let app = routes::build_router(state, None);

    // Connect config + deployment key + MDM + readiness
    let (st, cfg): (_, GetConnectConfigResponse) = rpc_post_json(
        &app,
        "/grdr.api.inventory.v1alpha1.InventoryService/GetConnectConfig",
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(cfg.installers.len(), 3);

    let (st, created): (_, CreateDeploymentKeyResponse) = rpc_post_json(
        &app,
        "/grdr.api.inventory.v1alpha1.InventoryService/CreateDeploymentKey",
        &CreateDeploymentKeyRequest {
            label: "Finance Pilot".into(),
            wave: "wave-3".into(),
            install_profile: "enforced".into(),
            max_uses: 25,
            ttl_days: 30,
        },
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let key = created.key.unwrap();
    let (st, mdm): (_, RenderMdmConfigResponse) = rpc_post_json(
        &app,
        "/grdr.api.inventory.v1alpha1.InventoryService/RenderMdmConfig",
        &RenderMdmConfigRequest {
            format: mdm_format_to_proto(MdmFormat::JamfMobileconfig),
            deployment_key_id: Some(key.id.clone()),
            include_browser_extension: true,
            update_authority: "managed".into(),
        },
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(mdm.payload.contains(&key.token_preview));

    let (st, revoked): (_, RevokeDeploymentKeyResponse) = rpc_post_json(
        &app,
        "/grdr.api.inventory.v1alpha1.InventoryService/RevokeDeploymentKey",
        &RevokeDeploymentKeyRequest { id: key.id },
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        revoked.key.unwrap().status,
        DeploymentKeyStatus::Revoked as i32
    );

    let (st, ready): (_, CheckIntegrationReadinessResponse) = rpc_post_json(
        &app,
        "/grdr.api.inventory.v1alpha1.InventoryService/CheckIntegrationReadiness",
        &CheckIntegrationReadinessRequest {
            id: cfg.integrations[0].id.clone(),
        },
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(!ready.integration.unwrap().readiness_checks.is_empty());

    // Progressive query + users + privacy
    let (st, schema): (_, GetQuerySchemaResponse) = rpc_post_json(
        &app,
        "/grdr.api.activity.v1alpha1.SessionService/GetQuerySchema",
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(schema.entities.iter().any(|e| e.name == "users"));

    let (st, _): (_, GetQueryEntitiesResponse) = rpc_post_json(
        &app,
        "/grdr.api.activity.v1alpha1.SessionService/GetQueryEntities",
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    let (st, _): (_, GetQueryUserIntentResponse) = rpc_post_json(
        &app,
        "/grdr.api.activity.v1alpha1.SessionService/GetQueryUserIntent",
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    let (st, sample): (_, SampleQueryResponse) = rpc_post_json(
        &app,
        "/grdr.api.activity.v1alpha1.SessionService/SampleQuery",
        &SampleQueryRequest {
            entity: "attempts".into(),
            columns: vec!["id".into(), "agent_name".into()],
            limit: Some(50),
            filter_text: None,
        },
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        sample.plan.unwrap().effective_limit,
        grdr_model::MAX_SAMPLE_LIMIT
    );

    // Rule create/update/delete + privacy toggle
    let (st, created_rule): (_, CreateRuleResponse) = rpc_post_json(
        &app,
        "/grdr.api.policy.v1alpha1.PolicyService/CreateRule",
        &CreateRuleRequest {
            pack_id: None,
            title: "Custom Net Guard".into(),
            description: "Block suspicious curl".into(),
            mode: mode_to_proto(Mode::Watch),
            min_grade: None,
            matcher: Some(RuleMatch {
                action_classes: vec![ActionClass::NetRequest as i32],
                target_prefixes: vec!["http://".into()],
                target_contains: vec![],
                agents: vec![],
            }),
            reason_template: "Blocked plaintext HTTP".into(),
            cedar: None,
        },
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let rule_id = created_rule.rule.unwrap().id;
    let (st, _): (_, UpdateRuleModeResponse) = rpc_post_json(
        &app,
        "/grdr.api.policy.v1alpha1.PolicyService/UpdateRuleMode",
        &UpdateRuleModeRequest {
            id: rule_id.clone(),
            mode: mode_to_proto(Mode::Ask),
            actor: None,
            replay_confirmed: Some(true),
        },
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let (st, _): (_, serde_json::Value) = rpc_post_json(
        &app,
        "/grdr.api.policy.v1alpha1.PolicyService/UpdateRule",
        &UpdateRuleRequest {
            id: rule_id.clone(),
            title: Some("Custom Net Guard v2".into()),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let (st, _): (_, serde_json::Value) = rpc_post_json(
        &app,
        "/grdr.api.policy.v1alpha1.PolicyService/DeleteRule",
        &DeleteRuleRequest { id: rule_id },
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    let (st, packs): (_, ListPacksResponse) = rpc_post_json(
        &app,
        "/grdr.api.policy.v1alpha1.PolicyService/ListPacks",
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(!packs.packs.is_empty());

    let (st, users): (_, ListUsersResponse) = rpc_post_json(
        &app,
        "/grdr.api.tenancy.v1alpha1.UserService/ListUsers",
        &ListUsersRequest::default(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let first_uid = users.users[0].id.clone();
    let (st, udetail): (_, GetUserResponse) = rpc_post_json(
        &app,
        "/grdr.api.tenancy.v1alpha1.UserService/GetUser",
        &GetUserRequest { id: first_uid },
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(udetail.user.is_some());

    let (st, _): (_, serde_json::Value) = rpc_post_json(
        &app,
        "/grdr.api.tenancy.v1alpha1.UserService/UpdatePrivacyConfig",
        &UpdatePrivacyConfigRequest {
            identity_mode: Some(identity_mode_to_proto(IdentityMode::Pseudonymous)),
            user_risk_scoring: Some(false),
            actor: Some("admin".into()),
        },
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    // Browser policies + evaluate
    let (st, bp_list): (_, ListBrowserPoliciesResponse) = rpc_post_json(
        &app,
        "/grdr.api.policy.v1alpha1.PolicyService/ListBrowserPolicies",
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(bp_list.policies.len(), 5);
    let (st, bp_upd): (_, UpdateBrowserPolicyResponse) = rpc_post_json(
        &app,
        "/grdr.api.policy.v1alpha1.PolicyService/UpdateBrowserPolicy",
        &UpdateBrowserPolicyRequest {
            id: "gemini".into(),
            mode: Some(mode_to_proto(Mode::Ask)),
            block_file_uploads: Some(true),
            block_secret_paste: None,
            managed_extension_only: Some(true),
        },
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(bp_upd.policy.unwrap().mode, mode_to_proto(Mode::Ask));
    let (st, bp_eval): (_, EvaluateBrowserResponse) = rpc_post_json(
        &app,
        "/grdr.api.verdict.v1alpha1.VerdictService/EvaluateBrowser",
        &EvaluateBrowserRequest {
            app_id: "chatgpt".into(),
            domain: "chatgpt.com".into(),
            dlp_class: browser_dlp_to_proto(BrowserDlpClass::FileUpload),
            file_extension: Some(".env".into()),
            has_secret_match: true,
        },
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(bp_eval.verdict, Verdict::Deny as i32);

    let (st, inc_list): (_, ListIncidentsResponse) = rpc_post_json(
        &app,
        "/grdr.api.response.v1alpha1.ResponseService/ListIncidents",
        &ListIncidentsRequest::default(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(!inc_list.incidents.is_empty());

    let (st, sess_det): (_, GetSessionResponse) = rpc_post_json(
        &app,
        "/grdr.api.activity.v1alpha1.SessionService/GetSession",
        &GetSessionRequest {
            id: "sess-demo-refactor".into(),
        },
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(sess_det.session.is_some());

    // Embedded storage reopen check
    let dir = std::env::temp_dir().join(format!(
        "grdr-server-connect-sqlite-{}",
        uuid::Uuid::now_v7().simple()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    {
        let disk_state = AppState::init(StorageBackend::Disk(dir.clone()), false).unwrap();
        let disk_app = routes::build_router(disk_state, None);
        let (st, _): (_, DeviceCheckinResponse) = rpc_post_json(
            &disk_app,
            "/grdr.api.inventory.v1alpha1.InventoryService/DeviceCheckin",
            &DeviceCheckinRequest {
                device_id: Some("dev-sqlite-1".into()),
                hostname: "sqlite-runner".into(),
                os: "linux".into(),
                arch: "x86_64".into(),
                install_profile: InstallProfile::Protected as i32,
                daemon_version: "0.1.0".into(),
                hook_effective: true,
                ..Default::default()
            },
        )
        .await;
        assert_eq!(st, StatusCode::OK);
    }
    let reopened = AppState::init(StorageBackend::Disk(dir.clone()), false).unwrap();
    assert_eq!(reopened.overview().await.total_devices, 1);
    assert!(
        AppState::init_with_profile(ProfileKind::Ha, StorageBackend::Disk(dir.clone()), false)
            .is_err()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn profile_validation_and_embedded_lake_pipeline_work() {
    use crate::store::{
        BlobAdapterKind, BusAdapterKind, CODE_STORE_PROFILE_MISMATCH, LakeAdapterKind,
        ProfileAdapterSet, RelationalAdapterKind, validate_profile_adapters,
    };
    use grdr_ports::{LakeAggOp, LakeAggSpec, LakeQueryIr, RetentionClass};

    assert!(
        validate_profile_adapters(
            ProfileKind::Embedded,
            &ProfileAdapterSet::expected_for_profile(ProfileKind::Embedded),
        )
        .is_ok()
    );
    let bad_ha = ProfileAdapterSet {
        relational: RelationalAdapterKind::Sqlite,
        bus: BusAdapterKind::Log,
        blobs: BlobAdapterKind::ObjectStore,
        lake: LakeAdapterKind::ObjectStorage,
    };
    let err = validate_profile_adapters(ProfileKind::Ha, &bad_ha).unwrap_err();
    assert_eq!(err.code, CODE_STORE_PROFILE_MISMATCH);

    let bad_dist = ProfileAdapterSet {
        relational: RelationalAdapterKind::Postgres,
        bus: BusAdapterKind::Log,
        blobs: BlobAdapterKind::ObjectStore,
        lake: LakeAdapterKind::ObjectStorage,
    };
    let err = validate_profile_adapters(ProfileKind::Distributed, &bad_dist).unwrap_err();
    assert_eq!(err.code, CODE_STORE_PROFILE_MISMATCH);

    let dir = std::env::temp_dir().join(format!(
        "grdr-server-lake-e2e-{}",
        uuid::Uuid::now_v7().simple()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let state = AppState::init(StorageBackend::Disk(dir.clone()), false).unwrap();
    let app = routes::build_router(state.clone(), None);

    let (st, _): (_, EvaluateResponse) = rpc_post_json(
        &app,
        "/grdr.api.verdict.v1alpha1.VerdictService/Evaluate",
        &EvaluateRequest {
            session_id: Some("sess-lake-e2e".into()),
            device_id: Some("dev-lake-1".into()),
            device_name: Some("lake-host".into()),
            agent_name: "claude-code".into(),
            action_class: ActionClass::FileRead as i32,
            target: "~/.ssh/id_rsa".into(),
            summary: Some("Read ssh key".into()),
            control_point: Some(grdr_proto::common::ControlPoint::Hook as i32),
        },
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    let future_ms = jiff::Timestamp::now()
        .as_millisecond()
        .saturating_add(60_000);
    let flushed = state.flush_lake(future_ms).unwrap();
    assert!(flushed.rows_flushed >= 1);
    assert!(state.lake_manifest().unwrap().is_some());

    let timeline = state
        .query_lake(&LakeQueryIr::Timeline {
            root_session_id: "sess-lake-e2e".into(),
            include_content: false,
            limit: 10,
        })
        .unwrap();
    assert_eq!(timeline.rows.len(), 1);

    let agg = state
        .query_lake(&LakeQueryIr::Aggregate {
            retention_class: RetentionClass::Decision,
            group_by: vec!["device_id".into()],
            aggregations: vec![LakeAggSpec {
                alias: "total".into(),
                op: LakeAggOp::Count,
                field: None,
            }],
            predicates: vec![],
        })
        .unwrap();
    assert_eq!(agg.rows.len(), 1);

    let compacted = state.compact_lake(future_ms).unwrap();
    assert!(compacted.segments_compacted >= 1);

    let receipt = state
        .erase_lake_session("sess-lake-e2e", "retention_drill", future_ms)
        .unwrap();
    assert_eq!(receipt.archive_segments_reduced, 1);

    // Ensure raw unencrypted ingest/events/offset-*.json copies are never written.
    assert!(
        !dir.join("blobs")
            .join("org=org-embedded")
            .join("ingest")
            .exists()
    );

    // Profile mismatch flag validation (P6/D-33)
    assert_eq!(
        StorageBackend::from_profile_flags(
            ProfileKind::Embedded,
            false,
            None,
            Some("postgres://grdr@localhost:5432/grdr".into()),
            None,
            None,
        )
        .unwrap_err()
        .code,
        CODE_STORE_PROFILE_MISMATCH
    );
    assert_eq!(
        StorageBackend::from_profile_flags(
            ProfileKind::Ha,
            true,
            None,
            Some("postgres://grdr@localhost:5432/grdr".into()),
            None,
            Some(dir.join("bucket")),
        )
        .unwrap_err()
        .code,
        CODE_STORE_PROFILE_MISMATCH
    );
    assert_eq!(
        StorageBackend::from_profile_flags(
            ProfileKind::Ha,
            false,
            Some(dir.join("bucket")),
            Some("postgres://grdr@localhost:5432/grdr".into()),
            None,
            Some(dir.join("bucket")),
        )
        .unwrap_err()
        .code,
        CODE_STORE_PROFILE_MISMATCH
    );
    assert_eq!(
        StorageBackend::from_profile_flags(
            ProfileKind::Ha,
            false,
            Some(dir.join("other").join("..").join("bucket")),
            Some("postgres://grdr@localhost:5432/grdr".into()),
            None,
            Some(dir.join("bucket")),
        )
        .unwrap_err()
        .code,
        CODE_STORE_PROFILE_MISMATCH
    );
    let existing_bucket = dir.join("existing-bucket");
    std::fs::create_dir_all(&existing_bucket).unwrap();
    assert_eq!(
        StorageBackend::from_profile_flags(
            ProfileKind::Ha,
            false,
            Some(existing_bucket.join("nested-nonexistent-state")),
            Some("postgres://grdr@localhost:5432/grdr".into()),
            None,
            Some(existing_bucket),
        )
        .unwrap_err()
        .code,
        CODE_STORE_PROFILE_MISMATCH
    );
    let ha_backend = StorageBackend::from_profile_flags(
        ProfileKind::Ha,
        false,
        None,
        Some("postgres://grdr@localhost:5432/grdr".into()),
        None,
        Some(dir.join("ha-bucket")),
    )
    .unwrap();
    match &ha_backend {
        StorageBackend::Ha {
            object_store_dir,
            state_dir,
            ..
        } => {
            assert!(!state_dir.starts_with(object_store_dir));
        }
        other => panic!("expected Ha backend, got {other:?}"),
    }

    let _ = std::fs::remove_dir_all(&dir);
}
