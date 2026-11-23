// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

mod routes;
mod state;
mod uplink;

use std::process::ExitCode;

use clap::{Parser, ValueEnum};
use tokio::net::TcpListener;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use grdr_model::InstallProfile;

use crate::state::DaemonState;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ProfileArg {
    User,
    Protected,
}

#[derive(Debug, Parser)]
#[command(name = "grdr-daemon", about = "Guardrails ADR endpoint agent daemon")]
struct Args {
    #[arg(long, env = "GRDR_DAEMON_BIND", default_value = "127.0.0.1:8788")]
    bind: String,

    #[arg(long, env = "GRDR_SERVER_URL")]
    server: Option<String>,

    #[arg(long, value_enum, default_value_t = ProfileArg::User)]
    profile: ProfileArg,

    #[arg(long, env = "GRDR_DEVICE_NAME")]
    device_name: Option<String>,

    #[arg(long, default_value_t = 15)]
    interval_secs: u64,

    #[arg(long, default_value_t = false)]
    scan_once: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let profile = match args.profile {
        ProfileArg::User => InstallProfile::User,
        ProfileArg::Protected => InstallProfile::Protected,
    };

    let state = DaemonState::init(profile, args.device_name, args.server.clone());
    let status = state.status().await;
    info!(
        device_id = %status.device_id,
        agents = status.agent_count,
        mcp_servers = status.mcp_count,
        "Initial endpoint agent discovery completed"
    );

    if args.scan_once {
        if let Some(server_url) = args.server.as_deref() {
            let client = reqwest::Client::new();
            if let Err(err) = uplink::sync_once(&state, &client, server_url).await {
                error!(error = %err, "Check-in sync failed during --scan-once");
                return ExitCode::FAILURE;
            }
        }
        return ExitCode::SUCCESS;
    }

    if let Some(server_url) = args.server {
        let bg_state = state.clone();
        tokio::spawn(uplink::run_sync_loop(
            bg_state,
            server_url,
            args.interval_secs,
        ));
    }

    let app = routes::build_router(state);
    let listener = match TcpListener::bind(&args.bind).await {
        Ok(listener) => listener,
        Err(err) => {
            error!(bind = %args.bind, error = %err, "Failed to bind daemon loopback listener");
            return ExitCode::FAILURE;
        }
    };

    info!(bind = %args.bind, "Endpoint agent daemon listening on loopback");
    if let Err(err) = axum::serve(listener, app).await {
        error!(error = %err, "Daemon server exited unexpectedly");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use grdr_model::eval::add_seconds;
    use grdr_model::{
        ActionClass, ApprovalGrade, DecideInput, DecisionReceipt, Grant, GrantScope, Verdict,
    };
    use tower::ServiceExt as _;

    #[tokio::test]
    async fn daemon_evaluates_offline_decisions_with_essentials_pack() {
        let state = DaemonState::init(InstallProfile::User, Some("test-host".into()), None);
        let app = routes::build_router(state.clone());

        let block_req = DecideInput {
            session_id: Some("s-local".into()),
            device_id: None,
            device_name: None,
            agent_name: "claude-code".into(),
            action_class: ActionClass::FileWrite,
            control_point: None,
            target: ".claude/settings.json".into(),
            summary: None,
        };
        let resp = app
            .clone()
            .oneshot(
                Request::post("/local/v1/decide")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&block_req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let receipt: DecisionReceipt = serde_json::from_slice(&body).unwrap();
        assert_eq!(receipt.verdict, Verdict::Deny);
        assert_eq!(state.status().await.pending_events, 1);
    }

    #[tokio::test]
    async fn daemon_consumes_once_grant_on_first_matching_decision() {
        let state = DaemonState::init(InstallProfile::User, Some("test-host".into()), None);
        let now = jiff::Timestamp::now();
        {
            let mut guard = state.inner.write().await;
            let device_id = guard.device_id.clone();
            guard.grants.push(Grant {
                grant_id: "grn_daemon_once".into(),
                rule_id: "essentials.credential-stores".into(),
                session_id: "sess-local".into(),
                device_id,
                action_class: ActionClass::FileRead,
                target_pattern: "/home/dev/.ssh/id_rsa".into(),
                scope: GrantScope::Once,
                grade: ApprovalGrade::G1,
                granted_at: now,
                expires_at: Some(add_seconds(now, 300)),
                remaining_uses: Some(1),
                note: "Daemon once grant".into(),
            });
        }
        let app = routes::build_router(state);

        let req = DecideInput {
            session_id: Some("sess-local".into()),
            device_id: None,
            device_name: None,
            agent_name: "claude-code".into(),
            action_class: ActionClass::FileRead,
            control_point: None,
            target: "/home/dev/.ssh/id_rsa".into(),
            summary: None,
        };

        let first_resp = app
            .clone()
            .oneshot(
                Request::post("/local/v1/decide")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(first_resp.status(), StatusCode::OK);
        let first_body = axum::body::to_bytes(first_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let first_receipt: DecisionReceipt = serde_json::from_slice(&first_body).unwrap();
        assert_eq!(first_receipt.verdict, Verdict::Allow);
        assert_eq!(first_receipt.grant_id.as_deref(), Some("grn_daemon_once"));

        let second_resp = app
            .oneshot(
                Request::post("/local/v1/decide")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(second_resp.status(), StatusCode::OK);
        let second_body = axum::body::to_bytes(second_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let second_receipt: DecisionReceipt = serde_json::from_slice(&second_body).unwrap();
        assert_eq!(second_receipt.verdict, Verdict::StepUp);
        assert!(second_receipt.grant_id.is_none());
    }
}
