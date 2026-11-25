// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

use std::io::Read;

use clap::{Parser, ValueEnum};
use jiff::Timestamp;
use serde_json::Value;
use tracing_subscriber::EnvFilter;

use grdr_acp::adapters::{AcpProtocolDialect, evaluate_dialect_request, format_dialect_response};
use grdr_acp::envelope::AcpWireServer;
use grdr_acp::{
    DEFAULT_DAEMON_PORT, DEFAULT_DECIDE_TIMEOUT_MS, LoopbackDaemonClient, NormalizedControlCall,
    build_attempt, fail_closed_receipt,
};
use grdr_crypto::SigningKeypair;
use grdr_model::{ActionClass, TrustedKeyInfo};

const MAX_HOOK_STDIN_BYTES: usize = 512 * 1024;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum DialectArg {
    OwaspAcs,
    MsHooks,
    AcpConductor,
}

#[derive(Debug, Parser)]
#[command(
    name = "grdr-acp",
    about = "Signed OWASP ACS, Microsoft agent-hooks, and ACP conductor control adapter"
)]
struct Cli {
    /// Serve framed Ed25519 + replay-checked grdr-wire RPC loop over stdin/stdout.
    #[arg(long)]
    stdio_wire: bool,
    /// Evaluate a single hook JSON object from stdin for the chosen protocol dialect.
    #[arg(long)]
    hook_stdin: bool,
    /// Adapter protocol dialect when running --hook-stdin.
    #[arg(long, value_enum, default_value_t = DialectArg::OwaspAcs)]
    dialect: DialectArg,
    /// Loopback port where grdr-daemon exposes /local/v1/decide.
    #[arg(long, default_value_t = DEFAULT_DAEMON_PORT)]
    daemon_port: u16,
    /// Request timeout in milliseconds before failing closed.
    #[arg(long, default_value_t = DEFAULT_DECIDE_TIMEOUT_MS)]
    timeout_ms: u64,
    /// Trusted peer key id for --stdio-wire.
    #[arg(long)]
    peer_key_id: Option<String>,
    /// Base64 Ed25519 public key for --stdio-wire caller verification.
    #[arg(long)]
    peer_pub_key: Option<String>,
    /// Maximum allowed clock skew in seconds for signed wire frames.
    #[arg(long, default_value_t = 60)]
    max_skew_secs: i64,
}

impl From<DialectArg> for AcpProtocolDialect {
    fn from(arg: DialectArg) -> Self {
        match arg {
            DialectArg::OwaspAcs => Self::OwaspAcs,
            DialectArg::MsHooks => Self::MicrosoftAgentHooks,
            DialectArg::AcpConductor => Self::AcpConductor,
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let client = LoopbackDaemonClient::from_loopback_port(cli.daemon_port, cli.timeout_ms)?;

    if cli.stdio_wire {
        let Some(pub_b64) = cli.peer_pub_key else {
            return Err("GRDR-ACP-0003: --peer-pub-key is required with --stdio-wire".into());
        };
        let key_id = cli.peer_key_id.unwrap_or_else(|| "acp-peer".into());
        let host_keypair = SigningKeypair::generate().map_err(|e| e.to_string())?;
        let peer = TrustedKeyInfo {
            key_id,
            public_key_b64: pub_b64,
        };
        let mut server = AcpWireServer::new(host_keypair, vec![peer], cli.max_skew_secs, client);
        server
            .serve_stream(tokio::io::stdin(), tokio::io::stdout())
            .await?;
        return Ok(());
    }

    if cli.hook_stdin {
        let mut buf = String::new();
        let limit = u64::try_from(MAX_HOOK_STDIN_BYTES).unwrap_or(512 * 1024);
        let read_bytes = std::io::stdin()
            .take(limit.saturating_add(1))
            .read_to_string(&mut buf)?;
        let dialect: AcpProtocolDialect = cli.dialect.into();
        let now = Timestamp::now();
        let resp = if read_bytes > MAX_HOOK_STDIN_BYTES {
            let synth = NormalizedControlCall {
                request_id: "oversized-stdin".into(),
                spec_version: dialect.default_version().into(),
                session_id: "sess-fail-closed".into(),
                agent_name: "hook-stdin".into(),
                action_class: ActionClass::Exec,
                target: "oversized-stdin".into(),
                summary: "GRDR-ACP-0001: hook stdin exceeded 512 KiB bound".into(),
            };
            let attempt = build_attempt(&synth, now);
            let receipt = fail_closed_receipt(
                &attempt,
                "GRDR-ACP-0001: hook stdin exceeded 512 KiB bound",
                now,
            );
            format_dialect_response(dialect, &synth, &receipt)
        } else {
            match serde_json::from_str::<Value>(&buf) {
                Ok(parsed) => evaluate_dialect_request(dialect, &parsed, &client, now).await,
                Err(parse_err) => {
                    let reason = format!("GRDR-ACP-0001: invalid hook stdin JSON: {parse_err}");
                    let synth = NormalizedControlCall {
                        request_id: "malformed-stdin".into(),
                        spec_version: dialect.default_version().into(),
                        session_id: "sess-fail-closed".into(),
                        agent_name: "hook-stdin".into(),
                        action_class: ActionClass::Exec,
                        target: "malformed-stdin".into(),
                        summary: reason.clone(),
                    };
                    let attempt = build_attempt(&synth, now);
                    let receipt = fail_closed_receipt(&attempt, &reason, now);
                    format_dialect_response(dialect, &synth, &receipt)
                }
            }
        };
        println!("{}", serde_json::to_string(&resp)?);
        return Ok(());
    }

    println!(
        "{}",
        serde_json::json!({
            "program": "grdr-acp",
            "dialects": ["owasp-acs:0.1.0,0.1.4", "ms-hooks:0.1.0-beta.3", "acp-conductor:1.30.0,v2"]
        })
    );
    Ok(())
}
