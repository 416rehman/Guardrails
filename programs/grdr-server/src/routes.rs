// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::path::PathBuf;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::middleware;
use axum::routing::{get, post};
use tower_http::services::{ServeDir, ServeFile};

use crate::auth::{
    self, AuthLayerState, ServerSecurityConfig, require_console_auth,
    require_dedicated_operator_auth, require_device_or_console_auth,
};
use crate::rpc;
use crate::store::AppState;

#[cfg(test)]
pub fn build_router(state: AppState, web_dir: Option<PathBuf>) -> Router {
    build_console_router_with_security(
        state,
        web_dir,
        ServerSecurityConfig {
            api_token: Some("test-console-token".into()),
            operator_token: Some("test-operator-token".into()),
            enroll_token: Some("test-enroll-token".into()),
            ..Default::default()
        },
    )
}

#[cfg(test)]
pub fn build_router_with_security(
    state: AppState,
    web_dir: Option<PathBuf>,
    security: ServerSecurityConfig,
) -> Router {
    build_console_router_with_security(state, web_dir, security)
}

pub fn build_console_router_with_security(
    state: AppState,
    web_dir: Option<PathBuf>,
    security: ServerSecurityConfig,
) -> Router {
    let cors = auth::build_cors_layer(&security);
    let auth_state = AuthLayerState {
        security: security.clone(),
        app: state.clone(),
    };

    let public_routes = Router::new().route(
        "/grdr.api.overview.v1alpha1.OverviewService/GetHealth",
        get(rpc::overview::get_health).post(rpc::overview::get_health),
    );

    let device_routes = Router::new()
        .route(
            "/grdr.api.inventory.v1alpha1.InventoryService/DeviceCheckin",
            post(rpc::inventory::device_checkin),
        )
        .route(
            "/grdr.api.verdict.v1alpha1.VerdictService/IngestBatch",
            post(rpc::verdict::ingest_batch),
        )
        .layer(middleware::from_fn_with_state(
            auth_state.clone(),
            require_device_or_console_auth,
        ));

    let console_routes = Router::new()
        .route(
            "/grdr.api.overview.v1alpha1.OverviewService/GetOverview",
            get(rpc::overview::get_overview).post(rpc::overview::get_overview),
        )
        .route(
            "/grdr.api.overview.v1alpha1.OverviewService/ListKeys",
            get(rpc::overview::list_keys).post(rpc::overview::list_keys),
        )
        .route(
            "/grdr.api.overview.v1alpha1.OverviewService/ExportOcsf",
            get(rpc::overview::export_ocsf).post(rpc::overview::export_ocsf),
        )
        .route(
            "/grdr.api.overview.v1alpha1.OverviewService/ExportAuditJsonl",
            get(rpc::overview::export_audit_jsonl).post(rpc::overview::export_audit_jsonl),
        )
        .route(
            "/grdr.api.overview.v1alpha1.OverviewService/IssueLiveTicket",
            post(rpc::overview::issue_live_ticket),
        )
        .route(
            "/grdr.api.overview.v1alpha1.OverviewService/LiveEvents",
            get(rpc::overview::live_stream),
        )
        .route(
            "/grdr.api.verdict.v1alpha1.VerdictService/Evaluate",
            post(rpc::verdict::evaluate),
        )
        .route(
            "/grdr.api.verdict.v1alpha1.VerdictService/EvaluateBrowser",
            post(rpc::verdict::evaluate_browser),
        )
        .route(
            "/grdr.api.policy.v1alpha1.PolicyService/ListPacks",
            get(rpc::policy::list_packs).post(rpc::policy::list_packs),
        )
        .route(
            "/grdr.api.policy.v1alpha1.PolicyService/CreateRule",
            post(rpc::policy::create_rule),
        )
        .route(
            "/grdr.api.policy.v1alpha1.PolicyService/UpdateRule",
            post(rpc::policy::update_rule),
        )
        .route(
            "/grdr.api.policy.v1alpha1.PolicyService/DeleteRule",
            post(rpc::policy::delete_rule),
        )
        .route(
            "/grdr.api.policy.v1alpha1.PolicyService/UpdateRuleMode",
            post(rpc::policy::update_rule_mode),
        )
        .route(
            "/grdr.api.policy.v1alpha1.PolicyService/ReplayRule",
            get(rpc::policy::replay_rule).post(rpc::policy::replay_rule),
        )
        .route(
            "/grdr.api.policy.v1alpha1.PolicyService/ListBrowserPolicies",
            get(rpc::policy::list_browser_policies).post(rpc::policy::list_browser_policies),
        )
        .route(
            "/grdr.api.policy.v1alpha1.PolicyService/UpdateBrowserPolicy",
            post(rpc::policy::update_browser_policy),
        )
        .route(
            "/grdr.api.inventory.v1alpha1.InventoryService/ListDevices",
            get(rpc::inventory::list_devices).post(rpc::inventory::list_devices),
        )
        .route(
            "/grdr.api.inventory.v1alpha1.InventoryService/ListAgents",
            get(rpc::inventory::list_agents).post(rpc::inventory::list_agents),
        )
        .route(
            "/grdr.api.inventory.v1alpha1.InventoryService/ListMcpServers",
            get(rpc::inventory::list_mcp_servers).post(rpc::inventory::list_mcp_servers),
        )
        .route(
            "/grdr.api.inventory.v1alpha1.InventoryService/ListArtifacts",
            get(rpc::inventory::list_artifacts).post(rpc::inventory::list_artifacts),
        )
        .route(
            "/grdr.api.inventory.v1alpha1.InventoryService/GetConnectConfig",
            get(rpc::inventory::get_connect_config).post(rpc::inventory::get_connect_config),
        )
        .route(
            "/grdr.api.inventory.v1alpha1.InventoryService/CreateDeploymentKey",
            post(rpc::inventory::create_deployment_key),
        )
        .route(
            "/grdr.api.inventory.v1alpha1.InventoryService/RevokeDeploymentKey",
            post(rpc::inventory::revoke_deployment_key),
        )
        .route(
            "/grdr.api.inventory.v1alpha1.InventoryService/RenderMdmConfig",
            get(rpc::inventory::render_mdm_config).post(rpc::inventory::render_mdm_config),
        )
        .route(
            "/grdr.api.inventory.v1alpha1.InventoryService/ListIntegrations",
            get(rpc::inventory::list_integrations).post(rpc::inventory::list_integrations),
        )
        .route(
            "/grdr.api.inventory.v1alpha1.InventoryService/CheckIntegrationReadiness",
            post(rpc::inventory::check_integration_readiness),
        )
        .route(
            "/grdr.api.activity.v1alpha1.SessionService/ListSessions",
            get(rpc::activity::list_sessions).post(rpc::activity::list_sessions),
        )
        .route(
            "/grdr.api.activity.v1alpha1.SessionService/GetSession",
            get(rpc::activity::get_session).post(rpc::activity::get_session),
        )
        .route(
            "/grdr.api.activity.v1alpha1.SessionService/GetQuerySchema",
            get(rpc::activity::get_query_schema).post(rpc::activity::get_query_schema),
        )
        .route(
            "/grdr.api.activity.v1alpha1.SessionService/GetQueryEntities",
            get(rpc::activity::get_query_entities).post(rpc::activity::get_query_entities),
        )
        .route(
            "/grdr.api.activity.v1alpha1.SessionService/GetQueryUserIntent",
            get(rpc::activity::get_query_user_intent).post(rpc::activity::get_query_user_intent),
        )
        .route(
            "/grdr.api.activity.v1alpha1.SessionService/SampleQuery",
            get(rpc::activity::sample_query).post(rpc::activity::sample_query),
        )
        .route(
            "/grdr.api.tenancy.v1alpha1.UserService/ListUsers",
            get(rpc::tenancy::list_users).post(rpc::tenancy::list_users),
        )
        .route(
            "/grdr.api.tenancy.v1alpha1.UserService/GetUser",
            get(rpc::tenancy::get_user).post(rpc::tenancy::get_user),
        )
        .route(
            "/grdr.api.tenancy.v1alpha1.UserService/GetPrivacyConfig",
            get(rpc::tenancy::get_privacy_config).post(rpc::tenancy::get_privacy_config),
        )
        .route(
            "/grdr.api.tenancy.v1alpha1.UserService/UpdatePrivacyConfig",
            post(rpc::tenancy::update_privacy_config),
        )
        .route(
            "/grdr.api.response.v1alpha1.ResponseService/ListApprovals",
            get(rpc::response::list_approvals).post(rpc::response::list_approvals),
        )
        .route(
            "/grdr.api.response.v1alpha1.ResponseService/DecideApproval",
            post(rpc::response::decide_approval),
        )
        .route(
            "/grdr.api.response.v1alpha1.ResponseService/ListFindings",
            get(rpc::response::list_findings).post(rpc::response::list_findings),
        )
        .route(
            "/grdr.api.response.v1alpha1.ResponseService/UpdateFinding",
            post(rpc::response::update_finding),
        )
        .route(
            "/grdr.api.response.v1alpha1.ResponseService/ListIncidents",
            get(rpc::response::list_incidents).post(rpc::response::list_incidents),
        )
        .route(
            "/grdr.api.response.v1alpha1.ResponseService/GetKillSwitch",
            get(rpc::response::get_kill_switch).post(rpc::response::get_kill_switch),
        )
        .route(
            "/grdr.api.response.v1alpha1.ResponseService/SetKillSwitch",
            post(rpc::response::set_kill_switch),
        )
        .route(
            "/grdr.api.response.v1alpha1.ResponseService/ListAuditEvents",
            get(rpc::response::list_audit_events).post(rpc::response::list_audit_events),
        )
        .route(
            "/grdr.api.surfaces.v1alpha1.SurfaceService/ExplainReceipt",
            get(rpc::surfaces::explain_receipt).post(rpc::surfaces::explain_receipt),
        )
        .route(
            "/grdr.api.surfaces.v1alpha1.SurfaceService/ListReviewQueue",
            get(rpc::surfaces::list_review_queue).post(rpc::surfaces::list_review_queue),
        )
        .route(
            "/grdr.api.surfaces.v1alpha1.SurfaceService/DecideReviewCluster",
            post(rpc::surfaces::decide_review_cluster),
        )
        .route(
            "/grdr.api.surfaces.v1alpha1.SurfaceService/GetComplianceWorkspace",
            get(rpc::surfaces::get_compliance_workspace)
                .post(rpc::surfaces::get_compliance_workspace),
        )
        .route(
            "/grdr.api.surfaces.v1alpha1.SurfaceService/UpdateCompliancePolicy",
            post(rpc::surfaces::update_compliance_policy),
        )
        .route(
            "/grdr.api.surfaces.v1alpha1.SurfaceService/CreateLegalHold",
            post(rpc::surfaces::create_legal_hold),
        )
        .route(
            "/grdr.api.surfaces.v1alpha1.SurfaceService/ApproveLegalHold",
            post(rpc::surfaces::approve_legal_hold),
        )
        .route(
            "/grdr.api.surfaces.v1alpha1.SurfaceService/ExportComplianceArtifact",
            post(rpc::surfaces::export_compliance_artifact),
        )
        .route(
            "/grdr.api.surfaces.v1alpha1.SurfaceService/PushGrcEvidence",
            post(rpc::surfaces::push_grc_evidence),
        )
        .route(
            "/grdr.api.surfaces.v1alpha1.SurfaceService/RequestReidentification",
            post(rpc::surfaces::request_reidentification),
        )
        .route(
            "/grdr.api.surfaces.v1alpha1.SurfaceService/ApproveReidentification",
            post(rpc::surfaces::approve_reidentification),
        )
        .route(
            "/grdr.api.surfaces.v1alpha1.SurfaceService/CompleteFirstRun",
            post(rpc::surfaces::complete_first_run),
        )
        .route(
            "/grdr.api.surfaces.v1alpha1.SurfaceService/GetProviderWorkspace",
            get(rpc::surfaces::get_provider_workspace).post(rpc::surfaces::get_provider_workspace),
        )
        .route(
            "/grdr.api.surfaces.v1alpha1.SurfaceService/SwitchProviderOrg",
            post(rpc::surfaces::switch_provider_org),
        )
        .route(
            "/grdr.api.surfaces.v1alpha1.SurfaceService/AdvanceProviderRing",
            post(rpc::surfaces::advance_provider_ring),
        )
        .layer(middleware::from_fn_with_state(
            auth_state.clone(),
            require_console_auth,
        ));

    let fed_state = crate::federation::FederationState::from_app(state.clone());
    let fed_protected = crate::federation::protected_routes(fed_state.clone()).layer(
        middleware::from_fn_with_state(auth_state, require_console_auth),
    );

    let api = Router::new()
        .merge(public_routes)
        .merge(device_routes)
        .merge(console_routes)
        .with_state(state)
        .merge(crate::federation::public_routes(fed_state))
        .merge(fed_protected)
        .layer(DefaultBodyLimit::max(security.max_body_bytes))
        .layer(cors);

    attach_static_dir(api, web_dir)
}

pub fn build_operator_router_with_security(
    state: AppState,
    operator_web_dir: Option<PathBuf>,
    security: ServerSecurityConfig,
) -> Router {
    let cors = auth::build_operator_cors_layer(&security);
    let auth_state = AuthLayerState {
        security: security.clone(),
        app: state.clone(),
    };

    let public_routes = Router::new().route(
        "/grdr.api.overview.v1alpha1.OverviewService/GetHealth",
        get(rpc::overview::get_health).post(rpc::overview::get_health),
    );

    let operator_routes = Router::new()
        .route(
            "/grdr.api.overview.v1alpha1.OverviewService/GetOverview",
            get(rpc::overview::get_overview).post(rpc::overview::get_overview),
        )
        .route(
            "/grdr.api.overview.v1alpha1.OverviewService/ListKeys",
            get(rpc::overview::list_keys).post(rpc::overview::list_keys),
        )
        .route(
            "/grdr.api.overview.v1alpha1.OverviewService/ExportOcsf",
            get(rpc::overview::export_ocsf).post(rpc::overview::export_ocsf),
        )
        .route(
            "/grdr.api.overview.v1alpha1.OverviewService/ExportAuditJsonl",
            get(rpc::overview::export_audit_jsonl).post(rpc::overview::export_audit_jsonl),
        )
        .route(
            "/grdr.api.response.v1alpha1.ResponseService/ListAuditEvents",
            get(rpc::response::list_audit_events).post(rpc::response::list_audit_events),
        )
        .route(
            "/grdr.api.operator.v1alpha1.OperatorService/GetOperatorState",
            get(rpc::operator::get_operator_state).post(rpc::operator::get_operator_state),
        )
        .route(
            "/grdr.api.operator.v1alpha1.OperatorService/StageConfigRevision",
            post(rpc::operator::stage_config_revision),
        )
        .route(
            "/grdr.api.operator.v1alpha1.OperatorService/ApplyConfigRevision",
            post(rpc::operator::apply_config_revision),
        )
        .route(
            "/grdr.api.operator.v1alpha1.OperatorService/RollbackConfigRevision",
            post(rpc::operator::rollback_config_revision),
        )
        .route(
            "/grdr.api.operator.v1alpha1.OperatorService/RunUpgradePreflight",
            post(rpc::operator::run_upgrade_preflight),
        )
        .route(
            "/grdr.api.operator.v1alpha1.OperatorService/ResetTargetBreaker",
            post(rpc::operator::reset_target_breaker),
        )
        .route(
            "/grdr.api.operator.v1alpha1.OperatorService/RunBackupDrill",
            post(rpc::operator::run_backup_drill),
        )
        .layer(middleware::from_fn_with_state(
            auth_state,
            require_dedicated_operator_auth,
        ));

    let api = Router::new()
        .merge(public_routes)
        .merge(operator_routes)
        .with_state(state)
        .layer(DefaultBodyLimit::max(security.max_body_bytes))
        .layer(cors);

    attach_static_dir(api, operator_web_dir)
}

fn attach_static_dir(router: Router, web_dir: Option<PathBuf>) -> Router {
    if let Some(dir) = web_dir
        && dir.join("index.html").is_file()
    {
        let serve = ServeDir::new(&dir).fallback(ServeFile::new(dir.join("index.html")));
        return router.fallback_service(serve);
    }
    router
}
