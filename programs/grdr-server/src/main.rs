// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

mod aip;
mod auth;
mod connect_codec;
mod connect_error;
#[cfg(test)]
mod connect_tests;
mod demo;
mod exports;
mod routes;
mod rpc;
mod store;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use grdr_ports::ProfileKind;
use tokio::net::TcpListener;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use crate::auth::{DEFAULT_MAX_BODY_BYTES, ServerSecurityConfig};
use crate::store::{AppState, StorageBackend};

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

    #[arg(long, env = "GRDR_SERVER_PROFILE", default_value = "embedded")]
    profile: String,

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

    #[arg(long, env = "GRDR_CORS_ORIGINS", value_delimiter = ',')]
    cors_origins: Vec<String>,

    #[arg(long, env = "GRDR_MAX_BODY_BYTES", default_value_t = DEFAULT_MAX_BODY_BYTES)]
    max_body_bytes: usize,
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
    let profile = match ProfileKind::parse(&args.profile) {
        Ok(p) => p,
        Err(err) => {
            error!(error = %err, "Invalid --profile flag");
            return ExitCode::FAILURE;
        }
    };
    let backend = StorageBackend::from_flags(args.memory, args.data_dir);
    let state = match AppState::init_with_profile(profile, backend, args.demo_seed) {
        Ok(s) => s,
        Err(err) => {
            error!(code = %err.code, message = %err.message, "Failed initializing server state");
            return ExitCode::FAILURE;
        }
    };

    let security = ServerSecurityConfig {
        api_token: args.api_token.filter(|t| !t.trim().is_empty()),
        enroll_token: args.enroll_token.filter(|t| !t.trim().is_empty()),
        cors_origins: args.cors_origins,
        max_body_bytes: args.max_body_bytes.max(16 * 1024),
    };

    let router = routes::build_router_with_security(state.clone(), args.web_dir.clone(), security);
    let listener = match TcpListener::bind(&args.bind).await {
        Ok(l) => l,
        Err(err) => {
            error!(bind = %args.bind, error = %err, "Failed binding server listener");
            return ExitCode::FAILURE;
        }
    };

    info!(
        bind = %args.bind,
        profile = %profile.as_str(),
        storage = %state.backend.storage_mode().label(),
        web_dir = ?args.web_dir,
        demo_seed = args.demo_seed,
        "Guardrails ADR Connect API server listening"
    );

    if let Err(err) = axum::serve(listener, router).await {
        error!(error = %err, "Server terminated unexpectedly");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
