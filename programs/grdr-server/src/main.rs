// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

mod auth;
mod demo;
mod exports;
mod routes;
mod store;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use tokio::net::TcpListener;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use crate::auth::{DEFAULT_MAX_BODY_BYTES, ServerSecurityConfig};
use crate::store::AppState;

#[derive(Debug, Parser)]
#[command(
    name = "grdr-server",
    about = "Guardrails ADR API server and console host"
)]
struct Args {
    #[arg(long, env = "GRDR_SERVER_BIND", default_value = "127.0.0.1:8787")]
    bind: String,

    #[arg(long, env = "GRDR_DATA_DIR")]
    data_dir: Option<PathBuf>,

    #[arg(long, default_value_t = false)]
    memory: bool,

    #[arg(long, env = "GRDR_WEB_DIR")]
    web_dir: Option<PathBuf>,

    #[arg(long, default_value_t = false)]
    demo_seed: bool,

    #[arg(long, env = "GRDR_API_TOKEN")]
    api_token: Option<String>,

    #[arg(long, env = "GRDR_ENROLL_TOKEN")]
    enroll_token: Option<String>,

    #[arg(long, env = "GRDR_CORS_ORIGIN", value_delimiter = ',')]
    cors_origin: Vec<String>,

    #[arg(long, env = "GRDR_MAX_BODY_BYTES", default_value_t = DEFAULT_MAX_BODY_BYTES)]
    max_body_bytes: usize,
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let data_dir = if args.memory { None } else { args.data_dir };
    let web_dir = args.web_dir.or_else(|| {
        let candidate = PathBuf::from("web/dist");
        candidate.join("index.html").is_file().then_some(candidate)
    });

    let state = match AppState::init(data_dir, args.demo_seed) {
        Ok(state) => state,
        Err(err) => {
            error!(error = %err, "Failed to initialize server store");
            return ExitCode::FAILURE;
        }
    };

    let security = ServerSecurityConfig {
        api_token: args.api_token.filter(|s| !s.trim().is_empty()),
        enroll_token: args.enroll_token.filter(|s| !s.trim().is_empty()),
        cors_origins: args.cors_origin,
        max_body_bytes: args.max_body_bytes,
    };

    let router = routes::build_router_with_security(state, web_dir.clone(), security.clone());
    let listener = match TcpListener::bind(&args.bind).await {
        Ok(listener) => listener,
        Err(err) => {
            error!(bind = %args.bind, error = %err, "Failed to bind TCP listener");
            return ExitCode::FAILURE;
        }
    };

    info!(
        bind = %args.bind,
        web_dir = ?web_dir,
        demo_seed = args.demo_seed,
        api_auth_enabled = security.api_token.is_some(),
        enroll_auth_enabled = security.enroll_token.is_some(),
        "Guardrails ADR API server listening"
    );

    if let Err(err) = axum::serve(listener, router).await {
        error!(error = %err, "Server terminated unexpectedly");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt as _;

    use grdr_model::{
        ActionClass, ApprovalGrade, ApprovalRequest, ApprovalState, CreateRuleInput,
        DecideApprovalInput, DecideInput, DecisionReceipt, DeviceCheckinRequest, GrantScope,
        Incident, InstallProfile, KillAction, KillScope, KillSwitchInput, KillSwitchState, Mode,
        PolicyPack, PolicyRule, ReplayRuleInput, ReplaySummary, RuleMatch, SessionDetailResponse,
        SessionLabel, SessionSummary, TrustedKeyInfo, UpdateRuleModeInput, Verdict,
    };

    #[tokio::test]
    async fn server_lifecycle_decide_approve_replay_and_kill_switch() {
        let state = AppState::init(None, true).unwrap();
        let app = routes::build_router(state.clone(), None);

        let resp = app
            .clone()
            .oneshot(Request::get("/api/v1/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let checkin = DeviceCheckinRequest {
            device_id: Some("dev-test-1".into()),
            hostname: "ci-runner".into(),
            os: "linux".into(),
            arch: "x86_64".into(),
            install_profile: InstallProfile::User,
            daemon_version: "0.1.0".into(),
            hook_effective: true,
            agents: vec![],
            mcp_servers: vec![],
            artifacts: vec![],
            user_id: None,
            user_display: None,
            device_public_key: None,
        };
        let resp = app
            .clone()
            .oneshot(
                Request::post("/api/v1/devices/checkin")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&checkin).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let decide_req = DecideInput {
            session_id: Some("sess-int-1".into()),
            device_id: Some("dev-test-1".into()),
            device_name: Some("ci-runner".into()),
            agent_name: "claude-code".into(),
            action_class: ActionClass::FileRead,
            control_point: None,
            target: "/home/ci/.ssh/id_rsa".into(),
            summary: None,
        };
        let resp = app
            .clone()
            .oneshot(
                Request::post("/api/v1/decide")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&decide_req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let receipt: DecisionReceipt = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(receipt.verdict, Verdict::StepUp);

        let resp = app
            .clone()
            .oneshot(
                Request::get("/api/v1/approvals")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let approvals: Vec<ApprovalRequest> = serde_json::from_slice(&bytes).unwrap();
        let pending = approvals
            .into_iter()
            .find(|a| a.session_id == "sess-int-1")
            .unwrap();
        assert!(matches!(pending.state, ApprovalState::Pending { .. }));

        let approve_body = DecideApprovalInput {
            approve: true,
            scope: Some(GrantScope::Session),
            note: Some("Verified CI key read".into()),
            actor: Some("tester".into()),
        };
        let resp = app
            .clone()
            .oneshot(
                Request::post(format!("/api/v1/approvals/{}/decide", pending.id))
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&approve_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = app
            .clone()
            .oneshot(
                Request::post("/api/v1/decide")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&decide_req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let granted_receipt: DecisionReceipt = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(granted_receipt.verdict, Verdict::Allow);
        assert!(granted_receipt.grant_id.is_some());

        let replay_body = ReplayRuleInput {
            candidate_mode: Mode::Ask,
        };
        let resp = app
            .clone()
            .oneshot(
                Request::post("/api/v1/policies/rules/essentials.secret-exfil-egress/replay")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&replay_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let replay: ReplaySummary = serde_json::from_slice(&bytes).unwrap();
        assert!(replay.matched >= 1);

        let mode_update = UpdateRuleModeInput {
            mode: Mode::Ask,
            actor: Some("tester".into()),
            replay_confirmed: Some(true),
        };
        let resp = app
            .clone()
            .oneshot(
                Request::patch("/api/v1/policies/rules/essentials.secret-exfil-egress/mode")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&mode_update).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let ks_input = KillSwitchInput {
            action: KillAction::Kill,
            scope: KillScope::Session,
            target_id: "sess-int-1".into(),
            reason: "Emergency stop".into(),
            duration_minutes: None,
        };
        let resp = app
            .clone()
            .oneshot(
                Request::post("/api/v1/kill-switch")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&ks_input).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let ks: KillSwitchState = serde_json::from_slice(&bytes).unwrap();
        assert!(matches!(ks, KillSwitchState::Killed { .. }));
    }

    #[tokio::test]
    async fn server_enforces_once_grant_device_scope_expiry_and_rule_grade() {
        let state = AppState::init(None, false).unwrap();
        let app = routes::build_router(state.clone(), None);

        let custom_rule = CreateRuleInput {
            pack_id: None,
            title: "Production DB gate".into(),
            description: "Require G2 approval for prod db access".into(),
            mode: Mode::Ask,
            min_grade: Some(ApprovalGrade::G2),
            matcher: RuleMatch {
                action_classes: vec![ActionClass::Exec],
                target_prefixes: vec![],
                target_contains: vec!["psql prod".into()],
                agents: vec![],
            },
            reason_template: "Production database access requires admin approval.".into(),
        };
        let resp = app
            .clone()
            .oneshot(
                Request::post("/api/v1/policies/rules")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&custom_rule).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let created_rule: PolicyRule = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(created_rule.min_grade, ApprovalGrade::G2);

        let req_dev_a = DecideInput {
            session_id: Some("sess-once".into()),
            device_id: Some("dev-a".into()),
            device_name: Some("host-a".into()),
            agent_name: "claude-code".into(),
            action_class: ActionClass::Exec,
            control_point: None,
            target: "psql prod".into(),
            summary: None,
        };
        let resp = app
            .clone()
            .oneshot(
                Request::post("/api/v1/decide")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&req_dev_a).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let first_receipt: DecisionReceipt = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(first_receipt.verdict, Verdict::StepUp);

        let resp = app
            .clone()
            .oneshot(
                Request::get("/api/v1/approvals")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let approvals: Vec<ApprovalRequest> = serde_json::from_slice(&bytes).unwrap();
        let pending = approvals
            .into_iter()
            .find(|a| a.session_id == "sess-once")
            .unwrap();
        assert_eq!(pending.required_grade, ApprovalGrade::G2);

        let approve_once = DecideApprovalInput {
            approve: true,
            scope: Some(GrantScope::Once),
            note: Some("One-off prod check".into()),
            actor: Some("admin".into()),
        };
        let resp = app
            .clone()
            .oneshot(
                Request::post(format!("/api/v1/approvals/{}/decide", pending.id))
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&approve_once).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let mut req_dev_b = req_dev_a.clone();
        req_dev_b.device_id = Some("dev-b".into());
        let resp = app
            .clone()
            .oneshot(
                Request::post("/api/v1/decide")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&req_dev_b).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let dev_b_receipt: DecisionReceipt = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(dev_b_receipt.verdict, Verdict::StepUp);

        let resp = app
            .clone()
            .oneshot(
                Request::post("/api/v1/decide")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&req_dev_a).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let dev_a_retry: DecisionReceipt = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(dev_a_retry.verdict, Verdict::Allow);
        assert!(dev_a_retry.grant_id.is_some());

        let resp = app
            .clone()
            .oneshot(
                Request::post("/api/v1/decide")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&req_dev_a).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let dev_a_second: DecisionReceipt = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(dev_a_second.verdict, Verdict::StepUp);

        let expired_id = {
            let mut guard = state.inner.write().await;
            let expired = guard
                .approvals
                .iter_mut()
                .find(|a| matches!(a.state, ApprovalState::Pending { .. }))
                .unwrap();
            expired.state = ApprovalState::Pending {
                expires_at: jiff::Timestamp::from_second(1_000_000_000).unwrap(),
            };
            expired.id.clone()
        };

        let resp = app
            .clone()
            .oneshot(
                Request::post(format!("/api/v1/approvals/{expired_id}/decide"))
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&approve_once).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);

        let resp = app
            .clone()
            .oneshot(
                Request::get("/api/v1/approvals")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let updated_approvals: Vec<ApprovalRequest> = serde_json::from_slice(&bytes).unwrap();
        let marked = updated_approvals
            .into_iter()
            .find(|a| a.id == expired_id)
            .unwrap();
        assert!(matches!(marked.state, ApprovalState::Expired { .. }));
    }

    #[tokio::test]
    async fn server_enforces_normalizers_session_labels_and_incidents() {
        let state = AppState::init(None, false).unwrap();
        let app = routes::build_router(state, None);

        let traversal = DecideInput {
            session_id: Some("sess-chain".into()),
            device_id: Some("dev-chain".into()),
            device_name: Some("chain-box".into()),
            agent_name: "claude-code".into(),
            action_class: ActionClass::FileWrite,
            control_point: None,
            target: "repo/src/../../.claude/settings.json".into(),
            summary: None,
        };
        let resp = app
            .clone()
            .oneshot(
                Request::post("/api/v1/decide")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&traversal).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let traversal_receipt: DecisionReceipt = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(traversal_receipt.verdict, Verdict::Deny);

        let cred_read = DecideInput {
            session_id: Some("sess-chain".into()),
            device_id: Some("dev-chain".into()),
            device_name: Some("chain-box".into()),
            agent_name: "claude-code".into(),
            action_class: ActionClass::FileRead,
            control_point: None,
            target: "~/.ssh/id_rsa".into(),
            summary: None,
        };
        let _ = app
            .clone()
            .oneshot(
                Request::post("/api/v1/decide")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&cred_read).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let egress = DecideInput {
            session_id: Some("sess-chain".into()),
            device_id: Some("dev-chain".into()),
            device_name: Some("chain-box".into()),
            agent_name: "claude-code".into(),
            action_class: ActionClass::NetRequest,
            control_point: None,
            target: "https://example.test/upload".into(),
            summary: None,
        };
        let resp = app
            .clone()
            .oneshot(
                Request::post("/api/v1/decide")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&egress).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let egress_receipt: DecisionReceipt = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(egress_receipt.verdict, Verdict::StepUp);
        assert_eq!(
            egress_receipt.rule_id.as_deref(),
            Some("session.tainted-exfil-escalation")
        );

        let resp = app
            .clone()
            .oneshot(
                Request::get("/api/v1/sessions")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let sessions: Vec<SessionSummary> = serde_json::from_slice(&bytes).unwrap();
        let chain = sessions.into_iter().find(|s| s.id == "sess-chain").unwrap();
        assert!(chain.labels.contains(&SessionLabel::CredentialAccessed));
        assert!(chain.labels.contains(&SessionLabel::TaintedExfilRisk));

        let resp = app
            .oneshot(
                Request::get("/api/v1/incidents")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let incidents: Vec<Incident> = serde_json::from_slice(&bytes).unwrap();
        let inc = incidents
            .into_iter()
            .find(|i| i.session_id == "sess-chain")
            .unwrap();
        assert_eq!(inc.finding_count, 3);
        assert!(inc.labels.contains(&SessionLabel::TaintedExfilRisk));
    }

    #[tokio::test]
    async fn server_signs_packs_receipts_and_verifies_via_public_keys() {
        use grdr_crypto::{verify_pack, verify_receipt};
        use grdr_model::SignatureStatus;

        let state = AppState::init(None, false).unwrap();
        let app = routes::build_router(state, None);

        let resp = app
            .clone()
            .oneshot(Request::get("/api/v1/keys").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let keys: Vec<TrustedKeyInfo> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(keys.len(), 1);

        let resp = app
            .clone()
            .oneshot(
                Request::get("/api/v1/policies/packs")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let packs: Vec<PolicyPack> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(verify_pack(&packs[0], &keys), SignatureStatus::Verified);

        let decide_req = DecideInput {
            session_id: Some("sess-sig".into()),
            device_id: Some("dev-sig".into()),
            device_name: Some("sig-host".into()),
            agent_name: "claude-code".into(),
            action_class: ActionClass::Exec,
            control_point: None,
            target: "git status".into(),
            summary: None,
        };
        let resp = app
            .clone()
            .oneshot(
                Request::post("/api/v1/decide")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&decide_req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let receipt: DecisionReceipt = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(verify_receipt(&receipt, &keys), SignatureStatus::Verified);

        let resp = app
            .oneshot(
                Request::get("/api/v1/sessions/sess-sig")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let detail: SessionDetailResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(detail.receipts[0].signature_verified, Some(true));
    }

    #[tokio::test]
    async fn server_auth_enforces_operator_and_enroll_tokens_and_exports_work() {
        let state = AppState::init(None, true).unwrap();
        let security = ServerSecurityConfig {
            api_token: Some("op-secret-123".into()),
            enroll_token: Some("enroll-secret-456".into()),
            cors_origins: vec!["https://console.guardrails.local".into()],
            max_body_bytes: 16 * 1024,
        };
        let app = routes::build_router_with_security(state, None, security);

        // Public health remains reachable without credentials.
        let health = app
            .clone()
            .oneshot(Request::get("/api/v1/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(health.status(), StatusCode::OK);

        // Operator route rejects unauthenticated access with GRDR-API-0401.
        let unauth = app
            .clone()
            .oneshot(
                Request::get("/api/v1/overview")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

        // Device enrollment rejects missing/invalid token and accepts valid header.
        let checkin_body = DeviceCheckinRequest {
            device_id: Some("dev-auth-1".into()),
            hostname: "auth-host".into(),
            os: "linux".into(),
            arch: "x86_64".into(),
            install_profile: InstallProfile::Protected,
            daemon_version: "0.1.0".into(),
            hook_effective: true,
            agents: vec![],
            mcp_servers: vec![],
            artifacts: vec![],
            user_id: None,
            user_display: None,
            device_public_key: None,
        };
        let checkin_unauth = app
            .clone()
            .oneshot(
                Request::post("/api/v1/devices/checkin")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&checkin_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(checkin_unauth.status(), StatusCode::UNAUTHORIZED);

        let checkin_ok = app
            .clone()
            .oneshot(
                Request::post("/api/v1/devices/checkin")
                    .header("content-type", "application/json")
                    .header("x-guardrails-enroll-token", "enroll-secret-456")
                    .body(Body::from(serde_json::to_vec(&checkin_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(checkin_ok.status(), StatusCode::OK);

        // Valid operator bearer token accesses overview and OCSF/JSONL exports.
        let ocsf_resp = app
            .clone()
            .oneshot(
                Request::get("/api/v1/exports/ocsf")
                    .header("authorization", "Bearer op-secret-123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ocsf_resp.status(), StatusCode::OK);
        let ocsf_bytes = axum::body::to_bytes(ocsf_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let ocsf_json: Vec<serde_json::Value> = serde_json::from_slice(&ocsf_bytes).unwrap();
        assert!(!ocsf_json.is_empty());
        assert_eq!(ocsf_json[0]["metadata"]["version"], "1.9.0");

        let jsonl_resp = app
            .clone()
            .oneshot(
                Request::get("/api/v1/exports/audit.jsonl")
                    .header("authorization", "Bearer op-secret-123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(jsonl_resp.status(), StatusCode::OK);
        let jsonl_bytes = axum::body::to_bytes(jsonl_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let lines: Vec<&str> = std::str::from_utf8(&jsonl_bytes)
            .unwrap()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .collect();
        assert!(!lines.is_empty());
        let first_line: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert!(first_line.get("record_type").is_some());

        // Rule edit/delete rejects locked baseline rule with 409 Conflict.
        let locked_delete = app
            .clone()
            .oneshot(
                Request::delete("/api/v1/policies/rules/essentials.agent-control-files")
                    .header("authorization", "Bearer op-secret-123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(locked_delete.status(), StatusCode::CONFLICT);

        // Custom rule create -> update -> delete round-trip.
        let create_body = CreateRuleInput {
            pack_id: None,
            title: "Audit temp secret writes".into(),
            description: "Warn on /tmp/secret writes".into(),
            mode: Mode::Watch,
            min_grade: None,
            matcher: RuleMatch {
                action_classes: vec![ActionClass::FileWrite],
                target_prefixes: vec![],
                target_contains: vec!["/tmp/secret".into()],
                agents: vec![],
            },
            reason_template: "Monitor /tmp/secret".into(),
        };
        let created_resp = app
            .clone()
            .oneshot(
                Request::post("/api/v1/policies/rules")
                    .header("authorization", "Bearer op-secret-123")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&create_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(created_resp.status(), StatusCode::OK);
        let created_rule: PolicyRule = serde_json::from_slice(
            &axum::body::to_bytes(created_resp.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();

        let patch_resp = app
            .clone()
            .oneshot(
                Request::patch(format!("/api/v1/policies/rules/{}", created_rule.id))
                    .header("authorization", "Bearer op-secret-123")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&grdr_model::UpdateRuleInput {
                            title: Some("Ask on temp secret writes".into()),
                            description: None,
                            mode: Some(Mode::Ask),
                            min_grade: Some(ApprovalGrade::G2),
                            matcher: None,
                            reason_template: None,
                            actor: None,
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(patch_resp.status(), StatusCode::OK);
        let patched_rule: PolicyRule = serde_json::from_slice(
            &axum::body::to_bytes(patch_resp.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(patched_rule.mode, Mode::Ask);
        assert_eq!(patched_rule.title, "Ask on temp secret writes");

        let del_resp = app
            .clone()
            .oneshot(
                Request::delete(format!("/api/v1/policies/rules/{}", created_rule.id))
                    .header("authorization", "Bearer op-secret-123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(del_resp.status(), StatusCode::OK);

        // Users directory, risk ranking, artifacts, trace turns, and works-council privacy toggle.
        let users_resp = app
            .clone()
            .oneshot(
                Request::get("/api/v1/users")
                    .header("authorization", "Bearer op-secret-123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(users_resp.status(), StatusCode::OK);
        let users: Vec<grdr_model::UserProfile> = serde_json::from_slice(
            &axum::body::to_bytes(users_resp.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(users.len(), 3);
        assert_eq!(users[0].id, "usr-maya-chen");
        assert!(users[0].risk_score >= users[1].risk_score);

        let user_detail_resp = app
            .clone()
            .oneshot(
                Request::get("/api/v1/users/usr-maya-chen")
                    .header("authorization", "Bearer op-secret-123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(user_detail_resp.status(), StatusCode::OK);
        let user_detail: grdr_model::UserDetailResponse = serde_json::from_slice(
            &axum::body::to_bytes(user_detail_resp.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(!user_detail.recent_attempts.is_empty());

        let sess_resp = app
            .clone()
            .oneshot(
                Request::get("/api/v1/sessions/sess-demo-refactor")
                    .header("authorization", "Bearer op-secret-123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(sess_resp.status(), StatusCode::OK);
        let sess_detail: grdr_model::SessionDetailResponse = serde_json::from_slice(
            &axum::body::to_bytes(sess_resp.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(sess_detail.turns.len(), 3);
        assert!(sess_detail.turns.iter().any(|t| t.has_compaction));

        let artifacts_resp = app
            .clone()
            .oneshot(
                Request::get("/api/v1/inventory/artifacts")
                    .header("authorization", "Bearer op-secret-123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(artifacts_resp.status(), StatusCode::OK);
        let artifacts: Vec<grdr_model::ArtifactEntry> = serde_json::from_slice(
            &axum::body::to_bytes(artifacts_resp.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(artifacts.len() >= 3);

        let privacy_resp = app
            .clone()
            .oneshot(
                Request::patch("/api/v1/privacy/config")
                    .header("authorization", "Bearer op-secret-123")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&grdr_model::UpdatePrivacyConfigInput {
                            identity_mode: Some(grdr_model::IdentityMode::Pseudonymous),
                            user_risk_scoring: None,
                            actor: Some("privacy-officer".into()),
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(privacy_resp.status(), StatusCode::OK);

        let masked_users_resp = app
            .oneshot(
                Request::get("/api/v1/users")
                    .header("authorization", "Bearer op-secret-123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let masked_users: Vec<grdr_model::UserProfile> = serde_json::from_slice(
            &axum::body::to_bytes(masked_users_resp.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(
            masked_users
                .iter()
                .all(|u| u.display_name.starts_with("prn_") && u.risk_score == 0)
        );
    }
}
