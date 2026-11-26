// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

use clap::Parser;
use tokio::io::AsyncWriteExt as _;
use tracing_subscriber::EnvFilter;

use grdr_crypto::SigningKeypair;
use grdr_infer::detector::{
    DEFAULT_INFER_TIMEOUT_MS, HeuristicJudgeDetector, evaluate_framed_with_budget,
};
use grdr_infer::framing::{FramedDataClass, SessionMacKey};
use grdr_infer::ipc::{InferIpcHost, OsClockAdapter};
use grdr_model::TrustedKeyInfo;

#[derive(Debug, Parser)]
#[command(
    name = "grdr-infer",
    about = "Sandboxed networkless P2 restrict-only advisory inference host"
)]
struct Cli {
    /// Run framed grdr-wire RPC loop over stdin/stdout.
    #[arg(long)]
    stdio: bool,
    /// Trusted caller key identifier paired with --caller-pub-key.
    #[arg(long)]
    caller_key_id: Option<String>,
    /// Base64-encoded Ed25519 caller public key for --stdio IPC verification.
    #[arg(long)]
    caller_pub_key: Option<String>,
    /// Maximum allowed clock skew in seconds for incoming wire envelopes.
    #[arg(long, default_value_t = 60)]
    max_skew_secs: i64,
    /// Single-shot offline inspection text emitting ModelAdvisorySignal JSON.
    #[arg(long)]
    inspect_text: Option<String>,
    /// Budget in milliseconds before collapsing into CouldNotLook(Timeout).
    #[arg(long, default_value_t = DEFAULT_INFER_TIMEOUT_MS)]
    timeout_ms: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    if let Some(text) = cli.inspect_text {
        let mac_key = SessionMacKey::generate()?;
        let framed = mac_key.seal_record("cli-0", FramedDataClass::Untrusted, &text)?;
        let signal = evaluate_framed_with_budget(
            &HeuristicJudgeDetector,
            &mac_key,
            "cli-0",
            &framed,
            cli.timeout_ms,
        )
        .await;
        println!("{}", serde_json::to_string_pretty(&signal)?);
        return Ok(());
    }

    if cli.stdio {
        let Some(pub_b64) = cli.caller_pub_key else {
            return Err("GRDR-INFER-0006: --caller-pub-key is required with --stdio".into());
        };
        let key_id = cli.caller_key_id.unwrap_or_else(|| "daemon-caller".into());
        let host_keypair = SigningKeypair::generate().map_err(|e| e.to_string())?;
        let caller = TrustedKeyInfo {
            key_id,
            public_key_b64: pub_b64,
        };
        let mut host =
            InferIpcHost::with_default_detector(host_keypair, vec![caller], cli.max_skew_secs)?;
        let handshake = serde_json::json!({
            "protocol_version": grdr_wire::WIRE_PROTOCOL_VERSION,
            "host_public_info": host.host_public_info(),
        })
        .to_string();
        let mut stdout = tokio::io::stdout();
        stdout.write_all(handshake.as_bytes()).await?;
        stdout.write_all(b"\n").await?;
        stdout.flush().await?;
        let clock = OsClockAdapter::new();
        host.serve_stream(tokio::io::stdin(), stdout, &clock)
            .await?;
        return Ok(());
    }

    println!(
        "{}",
        serde_json::json!({
            "program": "grdr-infer",
            "mode": "networkless_p2_restrict_only",
            "max_risk_score": 250
        })
    );
    Ok(())
}
