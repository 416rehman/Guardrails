// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

use std::path::PathBuf;

use clap::Parser;
use tokio::io::AsyncWriteExt as _;
use tracing_subscriber::EnvFilter;

use grdr_crypto::SigningKeypair;
use grdr_infer::detector::{
    DEFAULT_INFER_TIMEOUT_MS, DetectorAdapter, HeuristicJudgeDetector, evaluate_framed_with_budget,
};
use grdr_infer::framing::{FramedDataClass, SessionMacKey};
use grdr_infer::ipc::{InferIpcHost, OsClockAdapter};
use grdr_infer::model_pack::{OnnxJudgeDetector, VerifiedModelPack};
use grdr_model::TrustedKeyInfo;

#[derive(Debug, Parser)]
#[command(
    name = "grdr-infer",
    about = "Sandboxed networkless P2 restrict-only ONNX advisory inference host"
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
    /// Optional signed offline ONNX model-pack directory.
    #[arg(long)]
    model_dir: Option<PathBuf>,
    /// Signer key identifier for verifying --model-dir manifest.json.
    #[arg(long)]
    model_key_id: Option<String>,
    /// Base64-encoded Ed25519 signer public key for --model-dir manifest verification.
    #[arg(long)]
    model_pub_key: Option<String>,
}

enum RuntimeDetector {
    Heuristic(HeuristicJudgeDetector),
    Onnx(OnnxJudgeDetector),
}

impl DetectorAdapter for RuntimeDetector {
    fn adapter_id(&self) -> &'static str {
        match self {
            Self::Heuristic(d) => d.adapter_id(),
            Self::Onnx(d) => d.adapter_id(),
        }
    }

    fn inspect_verified<'a>(
        &'a self,
        record: &'a grdr_infer::framing::VerifiedRecord,
    ) -> grdr_infer::detector::DetectFuture<'a> {
        match self {
            Self::Heuristic(d) => d.inspect_verified(record),
            Self::Onnx(d) => d.inspect_verified(record),
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
    let detector = build_runtime_detector(&cli)?;

    if let Some(text) = cli.inspect_text {
        let mac_key = SessionMacKey::generate()?;
        let framed = mac_key.seal_record("cli-0", FramedDataClass::Untrusted, &text)?;
        let signal =
            evaluate_framed_with_budget(&detector, &mac_key, "cli-0", &framed, cli.timeout_ms)
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
        let mut host = InferIpcHost::new(detector, host_keypair, vec![caller], cli.max_skew_secs)?;
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
            "detector_id": detector.adapter_id(),
            "max_risk_score": 250
        })
    );
    Ok(())
}

fn build_runtime_detector(cli: &Cli) -> Result<RuntimeDetector, Box<dyn std::error::Error>> {
    let Some(ref dir) = cli.model_dir else {
        return Ok(RuntimeDetector::Heuristic(HeuristicJudgeDetector));
    };
    let Some(ref pub_b64) = cli.model_pub_key else {
        return Err("GRDR-INFER-0005: --model-pub-key is required with --model-dir".into());
    };
    let key_id = cli
        .model_key_id
        .clone()
        .unwrap_or_else(|| "project-content".into());
    let pack = VerifiedModelPack::load_and_verify(
        dir,
        &[TrustedKeyInfo {
            key_id,
            public_key_b64: pub_b64.clone(),
        }],
    )?;
    let onnx = OnnxJudgeDetector::from_verified_pack(pack)?;
    Ok(RuntimeDetector::Onnx(onnx))
}
