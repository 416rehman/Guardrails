// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

mod routes;
mod state;
mod uplink;

use std::path::PathBuf;
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

    #[arg(long, env = "GRDR_FLOOR_TABLE")]
    floor_table: Option<PathBuf>,

    #[arg(long, env = "GRDR_DAEMON_DATA_DIR")]
    data_dir: Option<PathBuf>,
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

    let floor_path = args
        .floor_table
        .or_else(|| Some(state::default_floor_table_path()));
    let state = match DaemonState::init_with_store(
        profile,
        args.device_name,
        args.server.clone(),
        floor_path,
        args.data_dir,
    ) {
        Ok(state) => state,
        Err(err) => {
            error!(error = %err, "Failed to initialize endpoint agent daemon");
            return ExitCode::FAILURE;
        }
    };
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
        let state = DaemonState::init_with_store(
            InstallProfile::User,
            Some("test-host".into()),
            None,
            None,
            None,
        )
        .unwrap();
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
        let state = DaemonState::init_with_store(
            InstallProfile::User,
            Some("test-host".into()),
            None,
            None,
            None,
        )
        .unwrap();
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
                key_id: None,
                signature: None,
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

    #[tokio::test]
    async fn daemon_rejects_tampered_server_packs_and_writes_signed_floor_bundle() {
        use grdr_crypto::{SigningKeypair, verify_floor_table};
        use grdr_model::{Device, DeviceCheckinResponse, Mode, SignatureStatus, SignedFloorBundle};

        let floor_dir =
            std::env::temp_dir().join(format!("grdr-daemon-floor-{}", std::process::id()));
        let floor_path = floor_dir.join("floor.json");
        let _ = std::fs::remove_dir_all(&floor_dir);

        let daemon = DaemonState::init_with_store(
            InstallProfile::User,
            Some("test-host".into()),
            None,
            Some(floor_path.clone()),
            None,
        )
        .unwrap();

        let bundle_raw = std::fs::read_to_string(&floor_path).unwrap();
        let key_raw = std::fs::read_to_string(floor_path.with_extension("pub")).unwrap();
        let bundle: SignedFloorBundle = serde_json::from_str(&bundle_raw).unwrap();
        let pinned_key: grdr_model::TrustedKeyInfo = serde_json::from_str(&key_raw).unwrap();
        assert_eq!(
            verify_floor_table(&bundle.table, &[pinned_key]),
            SignatureStatus::Verified
        );

        let server_kp = SigningKeypair::generate().unwrap();
        let mut tampered_pack = grdr_model::eval::essentials_pack();
        server_kp.sign_pack(&mut tampered_pack).unwrap();
        tampered_pack.rules[0].mode = Mode::Off;

        let mut guard = daemon.inner.write().await;
        let original_pack_version = guard.packs[0].version.clone();
        tampered_pack.version = "9.9.9-tampered".into();
        let resp = DeviceCheckinResponse {
            device: Device {
                id: guard.device_id.clone(),
                hostname: guard.hostname.clone(),
                os: "linux".into(),
                arch: "x86_64".into(),
                install_profile: InstallProfile::User,
                daemon_version: "0.1.0".into(),
                online: true,
                hook_effective: false,
                agents: vec![],
                mcp_servers: vec![],
                artifacts: vec![],
                user_id: None,
                user_display: None,
                last_seen: jiff::Timestamp::now(),
                public_key: None,
            },
            packs: vec![tampered_pack],
            grants: vec![],
            kill_switch: grdr_model::KillSwitchState::Inactive,
            server_time: jiff::Timestamp::now(),
            trusted_keys: vec![server_kp.public_info()],
        };
        uplink::apply_verified_checkin(&mut guard, resp);
        assert_eq!(guard.packs[0].version, original_pack_version);

        drop(guard);
        let _ = std::fs::remove_dir_all(&floor_dir);
    }

    #[tokio::test]
    async fn daemon_persists_signing_key_and_pending_events_across_restart() {
        let data_dir =
            std::env::temp_dir().join(format!("grdr-daemon-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&data_dir);

        let key_id_first = {
            let daemon = DaemonState::init_with_store(
                InstallProfile::User,
                Some("persist-host".into()),
                None,
                None,
                Some(data_dir.clone()),
            )
            .unwrap();
            let _ = daemon
                .decide_local(DecideInput {
                    session_id: Some("sess-persist".into()),
                    device_id: None,
                    device_name: None,
                    agent_name: "claude-code".into(),
                    action_class: ActionClass::FileWrite,
                    control_point: None,
                    target: ".claude/settings.json".into(),
                    summary: None,
                })
                .await;
            let guard = daemon.inner.read().await;
            assert_eq!(guard.pending_receipts.len(), 1);
            guard.signing_key.key_id().to_string()
        };

        let restarted = DaemonState::init_with_store(
            InstallProfile::User,
            Some("persist-host".into()),
            None,
            None,
            Some(data_dir.clone()),
        )
        .unwrap();
        let guard = restarted.inner.read().await;
        assert_eq!(guard.signing_key.key_id(), key_id_first);
        assert_eq!(guard.pending_receipts.len(), 1);
        assert_eq!(restarted.status().await.pending_events, 1);

        drop(guard);
        let _ = std::fs::remove_dir_all(&data_dir);
    }
}
