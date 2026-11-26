// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Stateless, key-free policy evaluation child (`grdr-engine`).
//! Receives `WireFrame` protobuf messages from `grdr-daemon` over inherited stdin/stdout pipes,
//! maintains a bounded per-session `SessionRuleState` LRU map, and returns unsigned
//! `EngineResultFrame` verdicts and authored records for daemon signing and spooling.

mod session_store;

use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use grdr_core::policy::{
    essentials_pack, evaluate_with_session, render_rule_cedar, validate_cedar_rule,
};
use grdr_ipc_os::inherited_stdio_pipe;
use grdr_ipc_os::proto_io::ProtoIpcStream;
use grdr_model::{
    ActionAttempt, ActionClass, ControlPoint, DecisionReceipt, Grant, KillScope, KillSwitchState,
    Mode, PolicyPack, Verdict,
};
use grdr_os_clock::{Clock, SystemClock};
use grdr_os_service::current_process_rss_bytes;
use grdr_wire::frame::{
    DEFAULT_INITIAL_CREDIT, IPC_FRAME_HEADER_LEN, IpcFrameError, WireFrame, WirePayload,
    embedded_max_frame_bytes,
};
use grdr_wire::limits::embedded_limits;
use grdr_wire::messages::{
    BundleLoadFrame, EndpointServiceKind, EngineAuthoredRecord, EngineForwardFrame,
    EngineResultFrame, HandoverStage, HeartbeatFrame, WireActionClass, WireControlPoint,
    WireVerdict,
};
use grdr_wire::peer_auth::{
    Evidence, OsPeerClaims, Profile, Refusal, ServerIdentityPolicy, accept,
};
use jiff::Timestamp;
use thiserror::Error;

use crate::session_store::{BoundedSessionMap, DEFAULT_MAX_ENGINE_SESSIONS};

const DAEMON_HEARTBEAT_TIMEOUT_MS: u64 = 5_000;
const CREDIT_REPLENISH_BATCH: u32 = DEFAULT_INITIAL_CREDIT / 2;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
enum EngineError {
    #[error("GRDR-ENGINE-0001: IPC framing error: {0}")]
    IpcFrame(String),
    #[error("GRDR-ENGINE-0002: inherited peer handshake rejected: {0}")]
    PeerRejected(String),
    #[error("GRDR-ENGINE-0003: invalid policy bundle payload: {0}")]
    InvalidBundle(String),
    #[error("GRDR-ENGINE-0004: invalid engine command sequence: {0}")]
    ProtocolError(String),
    #[error("GRDR-ENGINE-0005: daemon heartbeat watchdog timeout after {elapsed_ms} ms")]
    DaemonHeartbeatLost { elapsed_ms: u64 },
    #[error("GRDR-ENGINE-0006: engine self-test failed: {0}")]
    SelfTestFailed(String),
}

#[derive(Debug, Parser)]
#[command(
    name = "grdr-engine",
    about = "Stateless Guardrails ADR policy evaluator"
)]
struct Args {
    #[arg(long)]
    self_test: bool,
    #[arg(long, default_value_t = DEFAULT_MAX_ENGINE_SESSIONS)]
    max_sessions: usize,
    #[arg(long, default_value = "local-endpoint")]
    device_id: String,
}

struct StatelessEngine {
    default_device_id: String,
    packs: Vec<PolicyPack>,
    grants: Vec<Grant>,
    kill_switch: KillSwitchState,
    sessions: BoundedSessionMap,
    epoch: u64,
    last_daemon_hb_mono_ms: u64,
}

impl StatelessEngine {
    fn new(default_device_id: String, max_sessions: usize, now_mono_ms: u64) -> Self {
        Self {
            default_device_id,
            packs: vec![essentials_pack()],
            grants: Vec::new(),
            kill_switch: KillSwitchState::Inactive,
            sessions: BoundedSessionMap::new(max_sessions),
            epoch: 1,
            last_daemon_hb_mono_ms: now_mono_ms,
        }
    }

    fn apply_bundle(
        &mut self,
        bundle: &BundleLoadFrame,
        now_wall: Timestamp,
    ) -> Result<(), EngineError> {
        if bundle.epoch < self.epoch {
            return Err(EngineError::InvalidBundle(format!(
                "bundle epoch {} regressed below current epoch {}",
                bundle.epoch, self.epoch
            )));
        }

        let limits = embedded_limits().map_err(|err| EngineError::IpcFrame(err.to_string()))?;
        let max_blob_bytes = limits.max_pack_bundle_bytes.min(limits.max_frame_bytes);
        let mut loaded_packs = Vec::with_capacity(bundle.pack_blobs.len().saturating_add(1));
        for raw in &bundle.pack_blobs {
            if raw.len() > max_blob_bytes {
                return Err(EngineError::InvalidBundle(format!(
                    "pack blob {} exceeds {max_blob_bytes} bytes",
                    raw.len()
                )));
            }
            let pack: PolicyPack = serde_json::from_slice(raw)
                .map_err(|err| EngineError::InvalidBundle(format!("decode pack: {err}")))?;
            loaded_packs.push(pack);
        }

        let mut loaded_grants = Vec::with_capacity(bundle.grant_blobs.len());
        for raw in &bundle.grant_blobs {
            if raw.len() > max_blob_bytes {
                return Err(EngineError::InvalidBundle(format!(
                    "grant blob {} exceeds {max_blob_bytes} bytes",
                    raw.len()
                )));
            }
            let grant: Grant = serde_json::from_slice(raw)
                .map_err(|err| EngineError::InvalidBundle(format!("decode grant: {err}")))?;
            loaded_grants.push(grant);
        }

        let essentials = essentials_pack();
        let mut next_packs = Vec::with_capacity(loaded_packs.len().saturating_add(1));
        next_packs.push(essentials.clone());
        for pack in loaded_packs {
            if pack.id != essentials.id {
                next_packs.push(pack);
            }
        }
        validate_packs_before_swap(&next_packs)?;

        self.packs = next_packs;
        self.grants = loaded_grants;
        self.kill_switch = if bundle.kill_switch_active {
            KillSwitchState::Frozen {
                scope: KillScope::Device,
                target_id: "*".to_string(),
                reason: bundle.kill_switch_reason.clone(),
                issued_at: now_wall,
                expires_at: Timestamp::MAX,
            }
        } else {
            KillSwitchState::Inactive
        };
        self.epoch = bundle.epoch;
        Ok(())
    }

    fn evaluate_forward(
        &mut self,
        fwd: &EngineForwardFrame,
        now_wall: Timestamp,
    ) -> Result<EngineResultFrame, EngineError> {
        let attempt = build_attempt(fwd, &self.default_device_id, now_wall)?;
        let session_entry = self.sessions.get_or_insert_mut(&fwd.session_id);
        let unsigned_receipt = evaluate_with_session(
            &attempt,
            &self.packs,
            &mut self.grants,
            &self.kill_switch,
            &mut session_entry.state,
            now_wall,
        );
        let labels: Vec<String> = session_entry
            .state
            .labels_vec()
            .into_iter()
            .map(|lbl| lbl.as_str().to_string())
            .collect();

        let authored_records = encode_authored_records(&attempt, &unsigned_receipt)?;
        Ok(EngineResultFrame {
            request_id: fwd.request_id.clone(),
            attempt_id: unsigned_receipt.attempt_id,
            verdict: map_verdict_to_wire(unsigned_receipt.verdict) as i32,
            rule_id: unsigned_receipt.rule_id.unwrap_or_default(),
            reason: unsigned_receipt.reason,
            labels,
            obligations: if unsigned_receipt.next_step.is_empty() {
                Vec::new()
            } else {
                vec![unsigned_receipt.next_step]
            },
            authored_records,
            session_step: session_entry.eval_count,
            consumed_grant_id: unsigned_receipt.grant_id.unwrap_or_default(),
        })
    }
}

fn main() -> ExitCode {
    let args = Args::parse();
    if args.self_test {
        return match run_self_test(&args.device_id, args.max_sessions) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("{err}");
                ExitCode::FAILURE
            }
        };
    }

    match run_inherited_loop(&args.device_id, args.max_sessions) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}

fn validate_packs_before_swap(packs: &[PolicyPack]) -> Result<(), EngineError> {
    for pack in packs {
        for rule in &pack.rules {
            if !rule.enabled || rule.mode == Mode::Off {
                continue;
            }
            let cedar_src = rule
                .cedar
                .as_deref()
                .filter(|s| !s.trim().is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| render_rule_cedar(rule));
            validate_cedar_rule(&cedar_src).map_err(|err| {
                EngineError::InvalidBundle(format!(
                    "Cedar validation failed for rule `{}` in pack `{}`: {err}",
                    rule.id, pack.id
                ))
            })?;
        }
    }
    Ok(())
}

fn run_self_test(device_id: &str, max_sessions: usize) -> Result<(), EngineError> {
    let clock = SystemClock::new();
    let now_wall = clock
        .now_wall()
        .map_err(|e| EngineError::SelfTestFailed(format!("wall clock failed: {e}")))?;
    let now_mono =
        mono_ms_checked(&clock).map_err(|e| EngineError::SelfTestFailed(e.to_string()))?;
    let mut engine = StatelessEngine::new(device_id.to_string(), max_sessions, now_mono);
    let res = engine
        .evaluate_forward(
            &EngineForwardFrame {
                request_id: "self-1".to_string(),
                attempt_id: "att-1".to_string(),
                agent: "claude-code".to_string(),
                control_point: WireControlPoint::Hook as i32,
                action_class: WireActionClass::Exec as i32,
                session_id: "self-session".to_string(),
                target: "git status".to_string(),
                summary: "Bash".to_string(),
                command_line: "git status".to_string(),
                received_mono_ms: 1,
                epoch: 1,
                tool_name: "Bash".to_string(),
                device_id: device_id.to_string(),
            },
            now_wall,
        )
        .map_err(|e| EngineError::SelfTestFailed(e.to_string()))?;
    if res.authored_records.is_empty() {
        return Err(EngineError::SelfTestFailed(
            "expected unsigned authored records from StatelessEngine".to_string(),
        ));
    }
    Ok(())
}

fn run_inherited_loop(device_id: &str, max_sessions: usize) -> Result<(), EngineError> {
    let max_frame_bytes =
        embedded_max_frame_bytes().map_err(|err| EngineError::IpcFrame(err.to_string()))?;
    let pipe = inherited_stdio_pipe().map_err(|err| EngineError::IpcFrame(err.to_string()))?;
    let hb_dur = Duration::from_millis(DAEMON_HEARTBEAT_TIMEOUT_MS);
    let stream = ProtoIpcStream::with_timeouts(pipe, hb_dur, hb_dur);

    let policy = ServerIdentityPolicy {
        profile: Profile::Inherited,
        allowed_client_uids: vec![],
        allowed_windows_sids: vec![],
        minimum_integrity_rid: 0,
        reject_app_container: false,
        require_start_time_before_connect: false,
        require_open_as_self_pipe_check: false,
        require_kernel_peer_token: false,
    };
    let pending = accept(stream, &OsPeerClaims::Inherited, 0, &policy)
        .map_err(|err| EngineError::PeerRejected(err.to_string()))?;
    let (mut chan, _hello) = pending
        .first_frame(
            EndpointServiceKind::ProviderEngine,
            "",
            1,
            HandoverStage::Normal,
            max_frame_bytes,
        )
        .map_err(|err| EngineError::PeerRejected(err.to_string()))?;

    let clock = SystemClock::new();
    let initial_mono = mono_ms_checked(&clock)?;
    let mut engine = StatelessEngine::new(device_id.to_string(), max_sessions, initial_mono);

    loop {
        let now_mono = mono_ms_checked(&clock)?;
        let since_hb = now_mono.saturating_sub(engine.last_daemon_hb_mono_ms);
        if since_hb > DAEMON_HEARTBEAT_TIMEOUT_MS {
            return Err(EngineError::DaemonHeartbeatLost {
                elapsed_ms: since_hb,
            });
        }

        let frame = match chan.recv_frame() {
            Ok(f) => f,
            Err(Refusal::ProtocolRejected(Evidence::FrameError { detail })) => {
                if detail.contains("GRDR-WIRE-0036") {
                    return Ok(());
                }
                if detail.contains("GRDR-WIRE-0037") {
                    let elapsed_ms =
                        mono_ms_checked(&clock)?.saturating_sub(engine.last_daemon_hb_mono_ms);
                    return Err(EngineError::DaemonHeartbeatLost { elapsed_ms });
                }
                return Err(EngineError::IpcFrame(detail));
            }
            Err(err) => {
                return Err(EngineError::IpcFrame(err.to_string()));
            }
        };

        let now_wall = clock
            .now_wall()
            .map_err(|e| EngineError::ProtocolError(format!("wall clock failed: {e}")))?;
        match frame.payload {
            Some(WirePayload::Heartbeat(hb)) => {
                engine.last_daemon_hb_mono_ms = mono_ms_checked(&clock)?;
                let reply = WireFrame::with_payload(
                    frame.stream_id,
                    0,
                    WirePayload::Heartbeat(HeartbeatFrame {
                        seq: hb.seq,
                        monotonic_ms: engine.last_daemon_hb_mono_ms,
                        rss_bytes: current_process_rss_bytes(),
                        queue_depth: 0,
                        epoch: engine.epoch,
                    }),
                );
                send_with_credit_grant(&mut chan, reply)?;
            }
            Some(WirePayload::CreditGrant(_)) => {
                engine.last_daemon_hb_mono_ms = mono_ms_checked(&clock)?;
            }
            Some(WirePayload::BundleLoad(bundle)) => {
                engine.last_daemon_hb_mono_ms = mono_ms_checked(&clock)?;
                engine.apply_bundle(&bundle, now_wall)?;
                if let Some(delta) = chan.credit().recommended_inbound_grant() {
                    chan.send_credit_grant(delta.max(CREDIT_REPLENISH_BATCH))
                        .map_err(|err| EngineError::IpcFrame(err.to_string()))?;
                }
            }
            Some(WirePayload::EngineForward(fwd)) => {
                engine.last_daemon_hb_mono_ms = mono_ms_checked(&clock)?;
                let res = engine.evaluate_forward(&fwd, now_wall)?;
                let reply =
                    WireFrame::with_payload(frame.stream_id, 0, WirePayload::EngineResult(res));
                send_with_credit_grant(&mut chan, reply)?;
            }
            Some(_) => {
                return Err(EngineError::ProtocolError(
                    "unsupported payload on engine provider channel".to_string(),
                ));
            }
            None => {
                let _ = (IPC_FRAME_HEADER_LEN, IpcFrameError::EmptyPayload);
                return Err(EngineError::ProtocolError("empty wire payload".to_string()));
            }
        }
    }
}

fn send_with_credit_grant<S: grdr_wire::peer_auth::FrameStream>(
    chan: &mut grdr_wire::peer_auth::AuthenticatedChannel<S>,
    frame: WireFrame,
) -> Result<(), EngineError> {
    if let Some(delta) = chan.credit().recommended_inbound_grant() {
        chan.send_credit_grant(delta.max(CREDIT_REPLENISH_BATCH))
            .map_err(|err| EngineError::IpcFrame(err.to_string()))?;
    }
    chan.send_frame(frame)
        .map_err(|err| EngineError::IpcFrame(err.to_string()))
}

fn encode_authored_records(
    attempt: &ActionAttempt,
    unsigned_receipt: &DecisionReceipt,
) -> Result<Vec<EngineAuthoredRecord>, EngineError> {
    let receipt_json = serde_json::to_vec(unsigned_receipt)
        .map_err(|err| EngineError::ProtocolError(format!("serialize unsigned receipt: {err}")))?;
    let attempt_json = serde_json::to_vec(attempt)
        .map_err(|err| EngineError::ProtocolError(format!("serialize attempt: {err}")))?;
    Ok(vec![
        EngineAuthoredRecord {
            lane: "decision".to_string(),
            record_type: "unsigned_receipt".to_string(),
            session_id: attempt.session_id.clone(),
            payload: receipt_json,
        },
        EngineAuthoredRecord {
            lane: "spine".to_string(),
            record_type: "action_attempt".to_string(),
            session_id: attempt.session_id.clone(),
            payload: attempt_json,
        },
    ])
}

fn build_attempt(
    fwd: &EngineForwardFrame,
    default_device_id: &str,
    now: Timestamp,
) -> Result<ActionAttempt, EngineError> {
    let action_class = decode_action_class(fwd.action_class)?;
    let control_point = decode_control_point(fwd.control_point)?;
    let resolved_target = if matches!(action_class, ActionClass::Exec | ActionClass::Elevate)
        && !fwd.command_line.trim().is_empty()
    {
        fwd.command_line.clone()
    } else if !fwd.target.trim().is_empty() {
        fwd.target.clone()
    } else if !fwd.command_line.trim().is_empty() {
        fwd.command_line.clone()
    } else {
        fwd.summary.clone()
    };
    let summary = if !fwd.summary.trim().is_empty() {
        fwd.summary.clone()
    } else if !fwd.tool_name.trim().is_empty() {
        fwd.tool_name.clone()
    } else {
        resolved_target.clone()
    };
    let device_id = if fwd.device_id.trim().is_empty() {
        default_device_id.to_string()
    } else {
        fwd.device_id.clone()
    };
    Ok(ActionAttempt {
        id: if fwd.attempt_id.is_empty() {
            fwd.request_id.clone()
        } else {
            fwd.attempt_id.clone()
        },
        session_id: if fwd.session_id.is_empty() {
            "default".to_string()
        } else {
            fwd.session_id.clone()
        },
        device_id,
        device_name: "localhost".to_string(),
        agent_name: fwd.agent.clone(),
        action_class,
        control_point,
        target: resolved_target,
        summary,
        timestamp: now,
        ..ActionAttempt::default()
    })
}

fn decode_action_class(raw: i32) -> Result<ActionClass, EngineError> {
    WireActionClass::from_wire_i32(raw)
        .and_then(WireActionClass::to_model)
        .ok_or_else(|| EngineError::ProtocolError(format!("invalid WireActionClass {raw}")))
}

fn decode_control_point(raw: i32) -> Result<ControlPoint, EngineError> {
    WireControlPoint::from_wire_i32(raw)
        .and_then(WireControlPoint::to_model)
        .ok_or_else(|| EngineError::ProtocolError(format!("invalid WireControlPoint {raw}")))
}

const fn map_verdict_to_wire(verdict: Verdict) -> WireVerdict {
    match verdict {
        Verdict::Allow => WireVerdict::Allow,
        Verdict::Modify | Verdict::StepUp | Verdict::Defer => WireVerdict::Ask,
        Verdict::Deny => WireVerdict::Block,
    }
}

fn mono_ms_checked(clock: &SystemClock) -> Result<u64, EngineError> {
    let dur = clock
        .boot_uptime()
        .map_err(|e| EngineError::ProtocolError(format!("monotonic clock failed: {e}")))?;
    Ok(u64::try_from(dur.as_millis()).unwrap_or(u64::MAX))
}
