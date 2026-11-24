// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use jiff::Timestamp;
use uuid::Uuid;

use grdr_core::policy::{essentials_pack, evaluate_with_session};
use grdr_core::session::SessionRuleState;
use grdr_crypto::SigningKeypair;
use grdr_model::{
    ActionAttempt, ActionClass, CodedError, ControlPoint, DecisionReceipt, Grant, KillSwitchState,
    PolicyPack, TrustedKeyInfo, Verdict,
};
use grdr_ports::{DecisionEnginePort, StorePort};
use grdr_proto::{EngineCommand, EngineReply, EvaluateAttemptPayload, IpcMessage, VerdictReply};
use grdr_store_local::LocalStore;
use grdr_wire::{
    MAX_FRAME_BYTES, ReplayWindow, WireEnvelope, decode_frame, encode_frame, generate_nonce,
    sign_envelope,
};

#[derive(Debug, Parser)]
#[command(
    name = "grdr-engine",
    about = "Sandboxed Guardrails ADR standalone evaluation engine"
)]
struct Cli {
    #[arg(long, env = "GRDR_ENGINE_DATA_DIR")]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: SubcommandMode,
}

#[derive(Debug, Subcommand)]
enum SubcommandMode {
    /// Read bounded grdr-wire IPC frames on stdin and emit signed replies on stdout
    Stdio {
        #[arg(long)]
        peer_key_file: Option<PathBuf>,
    },
    /// Evaluate a single normalized action attempt and emit a signed DecisionReceipt JSON
    Eval {
        #[arg(long, default_value = "exec")]
        action: String,
        #[arg(long, default_value = "claude-code")]
        agent: String,
        #[arg(long)]
        target: String,
        #[arg(long, default_value = "sess-engine")]
        session_id: String,
    },
    /// Print the engine verifying public key JSON
    Keygen,
}

struct SandboxEngine {
    packs: Vec<PolicyPack>,
    grants: Vec<Grant>,
    kill_switch: KillSwitchState,
    session_state: SessionRuleState,
    signing_key: SigningKeypair,
    store: Option<LocalStore>,
    signed_receipts: u64,
}

impl SandboxEngine {
    fn open(data_dir: Option<PathBuf>) -> Result<Self, CodedError> {
        let (signing_key, store, packs, grants, kill_switch) = match data_dir {
            Some(dir) => {
                let store = LocalStore::open(dir).map_err(CodedError::from)?;
                let kp = store
                    .load_or_create_signing_key()
                    .map_err(CodedError::from)?;
                let snapshot = StorePort::load_snapshot(&store)?;
                match snapshot {
                    Some(snap) => {
                        let packs = if snap.packs.is_empty() {
                            vec![essentials_pack()]
                        } else {
                            snap.packs
                        };
                        (kp, Some(store), packs, snap.grants, snap.kill_switch)
                    }
                    None => (
                        kp,
                        Some(store),
                        vec![essentials_pack()],
                        Vec::new(),
                        KillSwitchState::Inactive,
                    ),
                }
            }
            None => {
                let kp = SigningKeypair::generate().map_err(|e| {
                    CodedError::new(
                        "GRDR-ENGINE-0001",
                        format!("Failed generating ephemeral keypair: {e}"),
                        "Check OS entropy or pass --data-dir.",
                    )
                })?;
                (
                    kp,
                    None,
                    vec![essentials_pack()],
                    Vec::new(),
                    KillSwitchState::Inactive,
                )
            }
        };

        Ok(Self {
            packs,
            grants,
            kill_switch,
            session_state: SessionRuleState::default(),
            signing_key,
            store,
            signed_receipts: 0,
        })
    }

    fn process_framed_stream(
        &mut self,
        input: &[u8],
        trusted_peers: &[TrustedKeyInfo],
    ) -> Result<Vec<u8>, CodedError> {
        let mut cursor = 0usize;
        let mut out = Vec::new();
        let mut replay = ReplayWindow::new(4096, 300);
        let now = Timestamp::now();

        while cursor < input.len() {
            let Some(slice) = input.get(cursor..) else {
                break;
            };
            let (envelope, consumed): (WireEnvelope<IpcMessage<EngineCommand>>, usize) =
                decode_frame(slice).map_err(|e| {
                    CodedError::new(
                        "GRDR-ENGINE-0002",
                        e.to_string(),
                        "Send valid GRDR v1 framed WireEnvelope messages.",
                    )
                })?;
            cursor = cursor.saturating_add(consumed);

            let peer_keys = if trusted_peers.is_empty() {
                vec![self.signing_key.public_info()]
            } else {
                trusted_peers.to_vec()
            };
            replay
                .verify_and_record(&envelope, &peer_keys, now)
                .map_err(|e| {
                    CodedError::new(
                        "GRDR-ENGINE-0003",
                        e.to_string(),
                        "Check sender key trust, timestamp skew, and nonce uniqueness.",
                    )
                })?;

            envelope.payload.validate().map_err(|e| {
                CodedError::new(
                    "GRDR-ENGINE-0004",
                    e.to_string(),
                    "Use protocol version 1 with non-empty correlation_id.",
                )
            })?;

            let corr_id = envelope.payload.correlation_id.clone();
            let (reply, should_exit) = self.handle_command(envelope.payload.body);
            let nonce = generate_nonce().map_err(|e| {
                CodedError::new(
                    "GRDR-ENGINE-0005",
                    e.to_string(),
                    "Check OS CSPRNG availability.",
                )
            })?;
            let reply_env = sign_envelope(
                &self.signing_key,
                nonce,
                Timestamp::now(),
                IpcMessage::new(corr_id, reply),
            )
            .map_err(|e| CodedError::new("GRDR-ENGINE-0005", e.to_string(), "Retry."))?;
            let frame = encode_frame(&reply_env)
                .map_err(|e| CodedError::new("GRDR-ENGINE-0005", e.to_string(), "Retry."))?;
            out.extend_from_slice(&frame);

            if should_exit {
                break;
            }
        }

        Ok(out)
    }

    fn handle_command(&mut self, cmd: EngineCommand) -> (EngineReply, bool) {
        match cmd {
            EngineCommand::Ping => (
                EngineReply::Pong {
                    version: env!("CARGO_PKG_VERSION").into(),
                    protocol_version: grdr_proto::PROTO_VERSION,
                },
                false,
            ),
            EngineCommand::Status => (
                EngineReply::Status {
                    loaded_packs: self.packs.len(),
                    active_grants: self.grants.len(),
                    signed_receipts: self.signed_receipts,
                },
                false,
            ),
            EngineCommand::Shutdown => (EngineReply::Ack, true),
            EngineCommand::EvaluateAttempt(payload) => {
                let EvaluateAttemptPayload {
                    attempt_id,
                    session_id,
                    device_id,
                    device_name,
                    agent_name,
                    action_class,
                    control_point,
                    target,
                    summary,
                } = *payload;
                let attempt = ActionAttempt {
                    id: attempt_id,
                    session_id,
                    device_id,
                    device_name,
                    agent_name,
                    action_class: ActionClass::from_name(&action_class),
                    control_point: parse_control_point(&control_point),
                    target,
                    summary,
                    timestamp: Timestamp::now(),
                };
                match self.evaluate(&attempt) {
                    Ok(receipt) => (
                        EngineReply::Verdict(Box::new(VerdictReply {
                            receipt_id: receipt.receipt_id,
                            attempt_id: receipt.attempt_id,
                            verdict: format!("{:?}", receipt.verdict).to_lowercase(),
                            rule_id: receipt.rule_id,
                            reason: receipt.reason,
                            next_step: receipt.next_step,
                            receipt_digest: receipt.receipt_digest,
                            key_id: receipt.key_id,
                            signature: receipt.signature,
                        })),
                        false,
                    ),
                    Err(err) => (
                        EngineReply::Error {
                            code: err.code,
                            message: err.message,
                        },
                        false,
                    ),
                }
            }
        }
    }
}

impl DecisionEnginePort for SandboxEngine {
    fn load_packs(&mut self, packs: Vec<PolicyPack>) -> Result<(), CodedError> {
        self.packs = packs;
        Ok(())
    }

    fn add_grant(&mut self, grant: Grant) -> Result<(), CodedError> {
        self.grants.push(grant);
        Ok(())
    }

    fn evaluate(&mut self, attempt: &ActionAttempt) -> Result<DecisionReceipt, CodedError> {
        let mut receipt = evaluate_with_session(
            attempt,
            &self.packs,
            &mut self.grants,
            &self.kill_switch,
            &mut self.session_state,
            attempt.timestamp,
        );
        let _ = self.signing_key.sign_receipt(&mut receipt);
        self.signed_receipts = self.signed_receipts.saturating_add(1);
        if let Some(store) = &self.store {
            StorePort::append_receipt(store, &receipt)?;
        }
        Ok(receipt)
    }
}

fn parse_control_point(raw: &str) -> ControlPoint {
    match raw.trim().to_ascii_lowercase().as_str() {
        "mcp" | "mcp-broker" => ControlPoint::McpBroker,
        "proxy" => ControlPoint::Proxy,
        "sandbox" => ControlPoint::Sandbox,
        "sensor" => ControlPoint::Sensor,
        "browser" => ControlPoint::Browser,
        "gateway" => ControlPoint::Gateway,
        "connector" => ControlPoint::Connector,
        _ => ControlPoint::Hook,
    }
}

fn load_trusted_peers(path: Option<PathBuf>) -> Result<Vec<TrustedKeyInfo>, CodedError> {
    let Some(p) = path else {
        return Ok(Vec::new());
    };
    let raw = std::fs::read_to_string(&p).map_err(|e| {
        CodedError::new(
            "GRDR-ENGINE-0006",
            format!("Failed reading peer key file {}: {e}", p.display()),
            "Pass a valid TrustedKeyInfo JSON file.",
        )
    })?;
    let key: TrustedKeyInfo = serde_json::from_str(&raw).map_err(|e| {
        CodedError::new(
            "GRDR-ENGINE-0006",
            format!("Invalid peer key JSON: {e}"),
            "Check TrustedKeyInfo JSON format.",
        )
    })?;
    Ok(vec![key])
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let mut engine = match SandboxEngine::open(cli.data_dir) {
        Ok(e) => e,
        Err(err) => {
            eprintln!("{}", err.display_line());
            return ExitCode::from(1);
        }
    };

    match cli.command {
        SubcommandMode::Keygen => {
            if let Ok(json) = serde_json::to_string_pretty(&engine.signing_key.public_info()) {
                println!("{json}");
                return ExitCode::SUCCESS;
            }
            ExitCode::from(1)
        }
        SubcommandMode::Eval {
            action,
            agent,
            target,
            session_id,
        } => {
            let attempt = ActionAttempt {
                id: format!("att_{}", Uuid::now_v7().simple()),
                session_id,
                device_id: "engine-local".into(),
                device_name: "engine-host".into(),
                agent_name: agent,
                action_class: ActionClass::from_name(&action),
                control_point: ControlPoint::Sandbox,
                target,
                summary: "Standalone engine evaluation".into(),
                timestamp: Timestamp::now(),
            };
            match engine.evaluate(&attempt) {
                Ok(receipt) => {
                    if let Ok(json) = serde_json::to_string_pretty(&receipt) {
                        println!("{json}");
                    }
                    match receipt.verdict {
                        Verdict::Deny => ExitCode::from(2),
                        Verdict::StepUp | Verdict::Defer => ExitCode::from(3),
                        Verdict::Allow | Verdict::Modify => ExitCode::SUCCESS,
                    }
                }
                Err(err) => {
                    eprintln!("{}", err.display_line());
                    ExitCode::from(1)
                }
            }
        }
        SubcommandMode::Stdio { peer_key_file } => {
            let peers = match load_trusted_peers(peer_key_file) {
                Ok(p) => p,
                Err(err) => {
                    eprintln!("{}", err.display_line());
                    return ExitCode::from(1);
                }
            };
            let mut buf = Vec::new();
            let cap = u64::try_from(MAX_FRAME_BYTES).unwrap_or(4 * 1024 * 1024);
            if let Err(err) = io::stdin().take(cap).read_to_end(&mut buf) {
                eprintln!("GRDR-ENGINE-0002: stdin read failed: {err}");
                return ExitCode::from(1);
            }
            match engine.process_framed_stream(&buf, &peers) {
                Ok(out) => {
                    if let Err(err) = io::stdout().write_all(&out) {
                        eprintln!("GRDR-ENGINE-0005: stdout write failed: {err}");
                        return ExitCode::from(1);
                    }
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("{}", err.display_line());
                    ExitCode::from(1)
                }
            }
        }
    }
}

// Validate signed framed stdio processing end-to-end.
#[cfg(test)]
mod tests {
    use super::*;
    use grdr_wire::verify_envelope;

    #[test]
    fn sandbox_engine_satisfies_decision_port_contract() {
        let mut engine = SandboxEngine::open(None).unwrap();
        assert!(
            grdr_ports_testkit::assert_decision_engine_contract(
                &mut engine,
                vec![essentials_pack()],
                vec![],
            )
            .is_ok()
        );
    }

    #[test]
    fn processes_framed_wire_stream_and_writes_signed_wal() {
        let dir = std::env::temp_dir().join(format!("grdr-engine-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let mut engine = SandboxEngine::open(Some(dir.clone())).unwrap();
        let peer_kp = engine.signing_key.clone();
        let peer_info = peer_kp.public_info();
        let now = Timestamp::now();

        let n1 = generate_nonce().unwrap();
        let n2 = generate_nonce().unwrap();
        let n3 = generate_nonce().unwrap();

        let f1 = encode_frame(
            &sign_envelope(
                &peer_kp,
                n1,
                now,
                IpcMessage::new("c1", EngineCommand::Ping),
            )
            .unwrap(),
        )
        .unwrap();
        let f2 = encode_frame(
            &sign_envelope(
                &peer_kp,
                n2,
                now,
                IpcMessage::new(
                    "c2",
                    EngineCommand::EvaluateAttempt(Box::new(EvaluateAttemptPayload {
                        attempt_id: "att-e1".into(),
                        session_id: "sess-e1".into(),
                        device_id: "dev-e1".into(),
                        device_name: "host-e1".into(),
                        agent_name: "claude-code".into(),
                        action_class: "file.write".into(),
                        control_point: "hook".into(),
                        target: ".claude/settings.json".into(),
                        summary: "Write protected settings".into(),
                    })),
                ),
            )
            .unwrap(),
        )
        .unwrap();
        let f3 = encode_frame(
            &sign_envelope(
                &peer_kp,
                n3,
                now,
                IpcMessage::new("c3", EngineCommand::Status),
            )
            .unwrap(),
        )
        .unwrap();

        let mut stream = Vec::new();
        stream.extend_from_slice(&f1);
        stream.extend_from_slice(&f2);
        stream.extend_from_slice(&f3);

        let reply_bytes = engine
            .process_framed_stream(&stream, std::slice::from_ref(&peer_info))
            .unwrap();
        let mut cursor = 0usize;
        let mut replies = Vec::new();
        while cursor < reply_bytes.len() {
            let Some(chunk) = reply_bytes.get(cursor..) else {
                break;
            };
            let (env, used): (WireEnvelope<IpcMessage<EngineReply>>, usize) =
                decode_frame(chunk).unwrap();
            verify_envelope(&env, std::slice::from_ref(&peer_info)).unwrap();
            replies.push(env.payload);
            cursor = cursor.saturating_add(used);
        }

        assert_eq!(replies.len(), 3);
        assert!(matches!(replies[0].body, EngineReply::Pong { .. }));
        assert!(matches!(
            &replies[1].body,
            EngineReply::Verdict(reply) if reply.verdict == "deny"
        ));
        assert!(matches!(
            replies[2].body,
            EngineReply::Status {
                signed_receipts: 1,
                ..
            }
        ));

        let store = engine.store.as_ref().unwrap();
        let wal = store.read_receipts().unwrap();
        assert_eq!(wal.len(), 1);
        assert_eq!(wal[0].verdict, Verdict::Deny);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
