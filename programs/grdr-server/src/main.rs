// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

mod aip;
mod auth;
mod connect_codec;
mod connect_error;
#[cfg(test)]
mod connect_tests;
mod demo;
mod demo_devices;
mod exports;
#[deny(clippy::arithmetic_side_effects)]
mod federation;
mod routes;
mod rpc;
mod store;
#[cfg(test)]
mod surfaces_tests;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use grdr_ports::ProfileKind;
use tokio::net::TcpListener;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use crate::auth::{
    DEFAULT_MAX_BODY_BYTES, ServerSecurityConfig, constant_time_eq, generate_random_bearer_token,
};
use crate::store::{AppState, StorageBackend};

#[derive(Debug, Parser)]
#[command(
    name = "grdr-server",
    about = "Guardrails ADR API server and isolated Operator Plane host"
)]
struct Args {
    #[arg(long, env = "GRDR_SERVER_BIND", default_value = "127.0.0.1:8787")]
    bind: String,

    #[arg(long, env = "GRDR_OPERATOR_BIND", default_value = "127.0.0.1:8788")]
    operator_bind: String,

    #[arg(long, env = "GRDR_DATA_DIR")]
    data_dir: Option<PathBuf>,

    #[arg(long, env = "GRDR_SERVER_PROFILE", default_value = "embedded")]
    profile: String,

    #[arg(long, env = "GRDR_POSTGRES_DSN")]
    postgres_dsn: Option<String>,

    #[arg(long, env = "GRDR_NATS_URL")]
    nats_url: Option<String>,

    #[arg(long, env = "GRDR_OBJECT_STORE_DIR")]
    object_store_dir: Option<PathBuf>,

    #[arg(long, default_value_t = false)]
    memory: bool,

    #[arg(long, env = "GRDR_WEB_DIR")]
    web_dir: Option<PathBuf>,

    #[arg(long, env = "GRDR_OPERATOR_WEB_DIR")]
    operator_web_dir: Option<PathBuf>,

    #[arg(long, default_value_t = false)]
    demo_seed: bool,

    #[arg(long, env = "GRDR_API_TOKEN")]
    api_token: Option<String>,

    #[arg(long, env = "GRDR_OPERATOR_TOKEN")]
    operator_token: Option<String>,

    #[arg(long, env = "GRDR_STEP_UP_TOKEN")]
    step_up_token: Option<String>,

    #[arg(long, env = "GRDR_ENROLL_TOKEN")]
    enroll_token: Option<String>,

    #[arg(long, env = "GRDR_CORS_ORIGINS", value_delimiter = ',')]
    cors_origins: Vec<String>,

    #[arg(long, env = "GRDR_OPERATOR_CORS_ORIGINS", value_delimiter = ',')]
    operator_cors_origins: Vec<String>,

    #[arg(long, env = "GRDR_MAX_BODY_BYTES", default_value_t = DEFAULT_MAX_BODY_BYTES)]
    max_body_bytes: usize,
}

fn is_loopback_bind(addr: &str) -> bool {
    if let Ok(parsed) = addr.parse::<SocketAddr>() {
        return parsed.ip().is_loopback();
    }
    let trimmed = addr.trim();
    trimmed.starts_with("127.0.0.1:")
        || trimmed.starts_with("[::1]:")
        || trimmed.starts_with("localhost:")
}

fn resolve_plane_token(
    explicit: Option<String>,
    bind_addr: &str,
    flag_name: &str,
) -> Result<(String, bool), ExitCode> {
    if let Some(tok) = explicit.filter(|t| !t.trim().is_empty()) {
        return Ok((tok, false));
    }
    if !is_loopback_bind(bind_addr) {
        error!(
            bind = %bind_addr,
            flag = %flag_name,
            "Non-loopback listener refuses startup without explicit bearer token"
        );
        return Err(ExitCode::FAILURE);
    }
    match generate_random_bearer_token() {
        Some(tok) => Ok((tok, true)),
        None => {
            error!(flag = %flag_name, "OS entropy failure generating bootstrap bearer token");
            Err(ExitCode::FAILURE)
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("grdr_server=info,tower_http=info")),
        )
        .init();

    let args = Args::parse();
    if args.bind.trim() == args.operator_bind.trim() {
        error!(
            bind = %args.bind,
            operator_bind = %args.operator_bind,
            "Console --bind and --operator-bind listeners must be distinct (D-70)"
        );
        return ExitCode::FAILURE;
    }

    let profile = match ProfileKind::parse(&args.profile) {
        Ok(p) => p,
        Err(err) => {
            error!(error = %err, "Invalid --profile flag");
            return ExitCode::FAILURE;
        }
    };
    let backend = match StorageBackend::from_profile_flags(
        profile,
        args.memory,
        args.data_dir,
        args.postgres_dsn,
        args.nats_url,
        args.object_store_dir,
    ) {
        Ok(b) => b,
        Err(err) => {
            error!(code = %err.code, message = %err.message, "Invalid profile storage configuration");
            return ExitCode::FAILURE;
        }
    };
    let state = match AppState::init_with_profile(profile, backend, args.demo_seed) {
        Ok(s) => s,
        Err(err) => {
            error!(code = %err.code, message = %err.message, "Failed initializing server state");
            return ExitCode::FAILURE;
        }
    };
    if let Err(err) = crate::federation::FederationState::try_new(state.clone()) {
        error!(code = %err.code, message = %err.message, "Failed initializing federation state");
        return ExitCode::FAILURE;
    }

    let Ok((api_token, api_ephemeral)) =
        resolve_plane_token(args.api_token, &args.bind, "--api-token")
    else {
        return ExitCode::FAILURE;
    };
    let Ok((operator_token, op_ephemeral)) =
        resolve_plane_token(args.operator_token, &args.operator_bind, "--operator-token")
    else {
        return ExitCode::FAILURE;
    };
    if constant_time_eq(&api_token, &operator_token) {
        error!("Console --api-token and Operator --operator-token must be distinct (D-70)");
        return ExitCode::FAILURE;
    }
    let step_up_token = match args.step_up_token.filter(|t| !t.trim().is_empty()) {
        Some(tok)
            if tok.trim() == "verified"
                || constant_time_eq(tok.trim(), &api_token)
                || constant_time_eq(tok.trim(), &operator_token) =>
        {
            error!("--step-up-token must be an independent non-placeholder secret");
            return ExitCode::FAILURE;
        }
        Some(tok) => tok,
        None => match generate_random_bearer_token() {
            Some(tok) => tok,
            None => {
                error!("OS entropy failure generating step-up credential");
                return ExitCode::FAILURE;
            }
        },
    };

    let security = ServerSecurityConfig {
        api_token: Some(api_token),
        operator_token: Some(operator_token),
        step_up_token: Some(step_up_token),
        enroll_token: args.enroll_token.filter(|t| !t.trim().is_empty()),
        cors_origins: args.cors_origins,
        operator_cors_origins: args.operator_cors_origins,
        max_body_bytes: args.max_body_bytes.max(16 * 1024),
        principal_tokens: BTreeMap::new(),
    };

    let console_router = routes::build_console_router_with_security(
        state.clone(),
        args.web_dir.clone(),
        security.clone(),
    );
    let operator_router = routes::build_operator_router_with_security(
        state.clone(),
        args.operator_web_dir.clone(),
        security,
    );

    let console_listener = match TcpListener::bind(&args.bind).await {
        Ok(l) => l,
        Err(err) => {
            error!(bind = %args.bind, error = %err, "Failed binding console listener");
            return ExitCode::FAILURE;
        }
    };
    let operator_listener = match TcpListener::bind(&args.operator_bind).await {
        Ok(l) => l,
        Err(err) => {
            error!(operator_bind = %args.operator_bind, error = %err, "Failed binding operator plane listener");
            return ExitCode::FAILURE;
        }
    };

    info!(
        bind = %args.bind,
        operator_bind = %args.operator_bind,
        profile = %profile.as_str(),
        storage = %state.backend.storage_mode().label(),
        console_ephemeral_token = api_ephemeral,
        operator_ephemeral_token = op_ephemeral,
        web_dir = ?args.web_dir,
        operator_web_dir = ?args.operator_web_dir,
        demo_seed = args.demo_seed,
        "Guardrails ADR Console and isolated Operator Plane listeners ready"
    );

    if let Err(err) = tokio::try_join!(
        axum::serve(console_listener, console_router),
        axum::serve(operator_listener, operator_router),
    ) {
        error!(error = %err, "Server terminated unexpectedly");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
