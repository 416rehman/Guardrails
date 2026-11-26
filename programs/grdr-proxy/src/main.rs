// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;
use url::Url;

use grdr_wire::peer_auth::Profile;

use grdr_proxy::control_ipc_server::{bind_local_control_endpoint, run_local_control_ipc_server};
use grdr_proxy::egress::EgressGuardConfig;
use grdr_proxy::local_control::poll_daemon_local_once;
use grdr_proxy::otlp::{OtlpCollectorConfig, OtlpUpstreamShipper};
use grdr_proxy::router::{ProxyGatewayState, build_proxy_router};
use grdr_proxy::tunnel::{UpstreamProxyConfig, run_tunnel_listener};
use grdr_proxy::web_bot_auth::WebBotAuthSigner;
use grdr_proxy::{DEFAULT_DECIDE_TIMEOUT_MS, IpcProxyDecisionClient};

#[derive(Debug, Parser)]
#[command(
    name = "grdr-proxy",
    about = "Guardrails explicit base-URL HTTP gateway, OTLP receiver, and CONNECT/SOCKS5 proxy"
)]
struct Cli {
    /// Loopback port for the HTTP + OTLP + McpRelay gateway listener.
    #[arg(long, default_value_t = 18080)]
    http_port: u16,
    /// Loopback port for the CONNECT / SOCKS5 tunnel listener.
    #[arg(long, default_value_t = 18081)]
    tunnel_port: u16,
    /// Optional non-Protected override for grdr-daemon Decide IPC endpoint.
    #[arg(long)]
    daemon_endpoint: Option<String>,
    /// Optional non-Protected override for grdr-daemon Local IPC endpoint.
    #[arg(long)]
    local_endpoint: Option<String>,
    /// Optional peer-verified Local IPC endpoint where daemon pushes proxy control updates.
    #[arg(long)]
    control_endpoint: Option<String>,
    /// Optional non-Protected floor state directory override.
    #[arg(long)]
    state_dir: Option<PathBuf>,
    /// Enforce Protected profile (prohibits endpoint or floor directory overrides).
    #[arg(long, default_value_t = false)]
    protected: bool,
    /// Timeout in milliseconds waiting for daemon decisions before failing closed / floor.
    #[arg(long, default_value_t = DEFAULT_DECIDE_TIMEOUT_MS)]
    timeout_ms: u64,
    /// Optional OTLP HTTP upstream collector base URL (e.g. https://otlp.internal:4318).
    #[arg(long)]
    otlp_collector_url: Option<String>,
    /// Optional env var holding a base64 Ed25519 seed for RFC 9421 Web Bot Auth signing.
    #[arg(long)]
    web_bot_auth_seed_env: Option<String>,
    /// Optional Signature-Agent URL emitted with RFC 9421 Web Bot Auth signatures.
    #[arg(long)]
    signature_agent: Option<String>,
    /// Poll interval in milliseconds for fetching control updates via daemon Local IPC.
    #[arg(long, default_value_t = 5_000)]
    control_poll_ms: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let profile = if cli.protected {
        Profile::Protected
    } else {
        Profile::User
    };
    let http_addr = SocketAddr::from((IpAddr::V4(Ipv4Addr::LOCALHOST), cli.http_port));
    let tunnel_addr = SocketAddr::from((IpAddr::V4(Ipv4Addr::LOCALHOST), cli.tunnel_port));
    let http_listener = TcpListener::bind(http_addr).await?;
    let actual_http_port = http_listener.local_addr()?.port();
    if actual_http_port == 0 {
        return Err("GRDR-PROXY-0005: loopback HTTP listener bound to port 0".into());
    }
    let tunnel_listener = TcpListener::bind(tunnel_addr).await?;

    let env_map: BTreeMap<String, String> = std::env::vars().collect();
    let upstream_chain = UpstreamProxyConfig::try_from_env_map(&env_map)?;
    let egress_cfg = EgressGuardConfig::default();

    let client = IpcProxyDecisionClient::new(
        profile,
        cli.daemon_endpoint,
        cli.local_endpoint,
        cli.state_dir,
        cli.timeout_ms,
    )?;

    let otlp_shipper = if let Some(raw_url) = cli.otlp_collector_url.as_deref() {
        let parsed = Url::parse(raw_url)?;
        Some(OtlpUpstreamShipper::spawn(OtlpCollectorConfig {
            endpoint_base_url: parsed,
            egress_config: egress_cfg,
            queue_capacity: 256,
        })?)
    } else {
        None
    };

    let signer = match cli.web_bot_auth_seed_env.as_deref() {
        Some(env_var) => Some(WebBotAuthSigner::from_env(env_var, cli.signature_agent)?),
        None => None,
    };

    let poll_client = client.clone();
    let state = Arc::new(
        ProxyGatewayState::new_with_profile(profile, client, actual_http_port, egress_cfg)?
            .with_upstream_chain(upstream_chain.clone())
            .with_otlp_shipper(otlp_shipper)
            .with_web_bot_signer(signer)
            .with_swg_env(&env_map),
    );

    if let Some(ctrl_ep) = cli.control_endpoint {
        let bound = bind_local_control_endpoint(profile, Some(&ctrl_ep))?;
        let ctrl_state = Arc::clone(&state);
        tokio::spawn(async move {
            run_local_control_ipc_server(bound, ctrl_state).await;
        });
    }

    let poll_state = Arc::clone(&state);
    let poll_interval = Duration::from_millis(cli.control_poll_ms.clamp(500, 60_000));
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(poll_interval);
        loop {
            ticker.tick().await;
            if let Err(err) = poll_daemon_local_once(&poll_client, &poll_state).await {
                tracing::debug!(error = %err, "daemon local control poll skipped");
            }
        }
    });

    let router = build_proxy_router(Arc::clone(&state));
    let http_task = tokio::spawn(async move {
        if let Err(err) = axum::serve(http_listener, router).await {
            tracing::error!(error = %err, "proxy HTTP listener stopped with error");
        }
    });
    let tunnel_task = tokio::spawn(async move {
        if let Err(err) = run_tunnel_listener(tunnel_listener, state, upstream_chain).await {
            tracing::error!(error = %err, "proxy tunnel listener stopped with error");
        }
    });

    tokio::try_join!(http_task, tunnel_task)?;
    Ok(())
}
