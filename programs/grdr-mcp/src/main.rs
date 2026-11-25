// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Stdio;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tokio::io::BufReader;
use tokio::sync::Mutex;
use tracing_subscriber::EnvFilter;

use grdr_mcp::decision::{DEFAULT_DAEMON_PORT, DEFAULT_DECIDE_TIMEOUT_MS, LoopbackDaemonSource};
use grdr_mcp::transport::{McpBrokerService, build_http_router, mediate_stdio_lines};
use grdr_sandbox_engine::{ContainmentMode, SandboxSpec, prepare_contained_command};

#[derive(Debug, Parser)]
#[command(
    name = "grdr-mcp",
    about = "Guardrails stdio and Streamable HTTP MCP broker"
)]
struct Cli {
    /// Loopback port where grdr-daemon exposes /local/v1/decide.
    #[arg(long, default_value_t = DEFAULT_DAEMON_PORT)]
    daemon_port: u16,
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
    /// Serve Streamable HTTP MCP endpoint on loopback.
    Http {
        #[arg(long, default_value_t = 18090)]
        port: u16,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let source = LoopbackDaemonSource::from_loopback_port(cli.daemon_port, cli.timeout_ms)?;
    let mut service =
        McpBrokerService::new(source, cli.server_name, cli.agent_name, cli.session_id);

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
        BrokerMode::Http { port } => {
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
