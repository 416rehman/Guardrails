// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use clap::Parser;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use grdr_proxy::egress::EgressGuardConfig;
use grdr_proxy::router::{ProxyGatewayState, build_proxy_router};
use grdr_proxy::tunnel::{UpstreamProxyConfig, run_tunnel_listener};
use grdr_proxy::{DEFAULT_DAEMON_PORT, DEFAULT_DECIDE_TIMEOUT_MS, LoopbackDaemonProxyClient};

#[derive(Debug, Parser)]
#[command(
    name = "grdr-proxy",
    about = "Guardrails explicit base-URL HTTP gateway, OTLP receiver, and CONNECT/SOCKS5 proxy"
)]
struct Cli {
    /// Loopback port for the HTTP + OTLP gateway listener.
    #[arg(long, default_value_t = 18080)]
    http_port: u16,
    /// Loopback port for the CONNECT / SOCKS5 tunnel listener.
    #[arg(long, default_value_t = 18081)]
    tunnel_port: u16,
    /// Loopback port where grdr-daemon serves /local/v1/decide.
    #[arg(long, default_value_t = DEFAULT_DAEMON_PORT)]
    daemon_port: u16,
    /// Timeout in milliseconds waiting for daemon decisions before failing closed.
    #[arg(long, default_value_t = DEFAULT_DECIDE_TIMEOUT_MS)]
    timeout_ms: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let http_addr = SocketAddr::from((IpAddr::V4(Ipv4Addr::LOCALHOST), cli.http_port));
    let tunnel_addr = SocketAddr::from((IpAddr::V4(Ipv4Addr::LOCALHOST), cli.tunnel_port));
    let http_listener = TcpListener::bind(http_addr).await?;
    let actual_http_port = http_listener.local_addr()?.port();
    if actual_http_port == 0 {
        return Err("GRDR-PROXY-0005: loopback HTTP listener bound to port 0".into());
    }
    let tunnel_listener = TcpListener::bind(tunnel_addr).await?;

    let env_map: BTreeMap<String, String> = std::env::vars().collect();
    let upstream_chain = UpstreamProxyConfig::from_env_map(&env_map);

    let client = LoopbackDaemonProxyClient::from_loopback_port(cli.daemon_port, cli.timeout_ms)?;
    let state = Arc::new(
        ProxyGatewayState::new(client, actual_http_port, EgressGuardConfig::default())?
            .with_upstream_chain(upstream_chain.clone()),
    );

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
