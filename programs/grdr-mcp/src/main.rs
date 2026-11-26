// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Stdio;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tokio::io::BufReader;
use tokio::sync::Mutex;
use tracing_subscriber::EnvFilter;

use grdr_mcp::decision::{DEFAULT_DECIDE_TIMEOUT_MS, IpcDaemonDecisionSource};
use grdr_mcp::http_upstream::HttpUpstreamConfig;
use grdr_mcp::ssrf::SsrfPolicy;
use grdr_mcp::transport::{McpBrokerService, build_http_router, mediate_stdio_lines};
use grdr_sandbox_engine::{ContainmentMode, SandboxSpec, prepare_contained_command};
use grdr_wire::peer_auth::Profile;

#[derive(Debug, Parser)]
#[command(
    name = "grdr-mcp",
    about = "Guardrails stdio and Streamable HTTP MCP broker"
)]
struct Cli {
    /// Optional non-Protected daemon Decide IPC endpoint override.
    #[arg(long)]
    daemon_endpoint: Option<String>,
    /// Optional non-Protected daemon Local IPC endpoint override.
    #[arg(long)]
    local_endpoint: Option<String>,
    /// Enforce Protected profile (prohibits endpoint or floor directory overrides).
    #[arg(long)]
    protected: bool,
    /// Timeout in milliseconds before falling back to signed floor or fail-closed deny.
    #[arg(long, default_value_t = DEFAULT_DECIDE_TIMEOUT_MS)]
    timeout_ms: u64,
    /// Server name label used for pinning and receipt provenance.
    #[arg(long, default_value = "mcp-server")]
    server_name: String,
    /// Agent identifier attached to MCP attempts.
    #[arg(long, default_value = "mcp-client")]
    agent_name: String,
    /// Guardrails session id binding MCP invocations.
    #[arg(long, default_value = "sess-mcp")]
    session_id: String,
    /// Expose built-in progressive read-only inspection tools cleanly.
    #[arg(long)]
    progressive_tools: bool,
    #[command(subcommand)]
    mode: BrokerMode,
}

#[derive(Debug, Subcommand)]
enum BrokerMode {
    /// Wrap a child stdio MCP server command inside broker mediation.
    Stdio {
        #[arg(required = true, trailing_var_arg = true)]
        command: Vec<String>,
    },
    /// Serve Streamable HTTP MCP endpoint on loopback forwarding to a vetted upstream URL.
    Http {
        #[arg(long, default_value_t = 18090)]
        port: u16,
        /// Vetted upstream Streamable HTTP MCP endpoint URL.
        #[arg(long)]
        upstream_url: Option<String>,
        /// Allow loopback HTTP upstreams only in non-Protected development/test mode.
        #[arg(long)]
        allow_loopback_upstream: bool,
    },
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
    let source = IpcDaemonDecisionSource::new(
        profile,
        cli.daemon_endpoint,
        cli.local_endpoint,
        None,
        cli.timeout_ms,
    )?;
    let mut service =
        McpBrokerService::new(source, cli.server_name, cli.agent_name, cli.session_id)
            .with_progressive_tools(cli.progressive_tools);

    match cli.mode {
        BrokerMode::Stdio { command } => {
            let Some(program) = command.first() else {
                return Err("GRDR-MCP-0007: missing child MCP command".into());
            };
            let args: Vec<String> = command.iter().skip(1).cloned().collect();
            let env_pairs: Vec<(String, String)> = std::env::vars().collect();
            let spec = SandboxSpec {
                session_id: service.session_id.clone(),
                agent_name: service.agent_name.clone(),
                mode: ContainmentMode::SanitizedEnv,
                workdir: None,
                extra_allow_env: Vec::new(),
                strip_secret_env: true,
            };
            let (std_cmd, _report) = prepare_contained_command(program, &args, &spec, &env_pairs)?;
            let mut cmd = tokio::process::Command::from(std_cmd);
            cmd.stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit());
            let mut child = cmd.spawn()?;
            let child_stdin = child
                .stdin
                .take()
                .ok_or("GRDR-MCP-0007: child stdin pipe unavailable")?;
            let child_stdout = child
                .stdout
                .take()
                .ok_or("GRDR-MCP-0007: child stdout pipe unavailable")?;

            let client_in = BufReader::new(tokio::io::stdin());
            let child_out = BufReader::new(child_stdout);
            mediate_stdio_lines(
                &mut service,
                client_in,
                tokio::io::stdout(),
                child_stdin,
                child_out,
            )
            .await?;
            if let Err(err) = child.wait().await {
                tracing::warn!(error = %err, "wrapped MCP child wait failed");
            }
            Ok(())
        }
        BrokerMode::Http {
            port,
            upstream_url,
            allow_loopback_upstream,
        } => {
            if let Some(url) = upstream_url {
                let policy = if allow_loopback_upstream && !cli.protected {
                    SsrfPolicy::AllowLoopbackTestOnly
                } else {
                    SsrfPolicy::StrictPublicOnly
                };
                service = service.with_upstream(HttpUpstreamConfig::new(url, policy));
            }
            let addr = SocketAddr::from((IpAddr::V4(Ipv4Addr::LOCALHOST), port));
            let listener = tokio::net::TcpListener::bind(addr).await?;
            let actual_port = listener.local_addr()?.port();
            if actual_port == 0 {
                return Err("GRDR-MCP-0005: HTTP listener bound to port 0".into());
            }
            service.expected_http_port = Some(actual_port);
            let router = build_http_router(Arc::new(Mutex::new(service)));
            axum::serve(listener, router).await?;
            Ok(())
        }
    }
}
