// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

//! Pre-launch authorization gate using peer-verified local IPC (`grdr-daemon`)
//! or cryptographically verified signed `CompiledFloorTable` / `GRDRFLT1` floor fallback.

use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::time::{Duration, Instant};

use jiff::Timestamp;
use uuid::Uuid;

use grdr_core::analyze::content::redact_sensitive_text;
use grdr_core::policy::{ReceiptDigestInput, compute_receipt_digest};
use grdr_ipc_os::proto_io::ProtoIpcStream;
use grdr_ipc_os::transport::{Connector, FixedTimestampSource, IpcDeadline, SystemConnector};
use grdr_model::log_safe::sanitize_log_fragment;
use grdr_model::{
    ActionAttempt, ActionClass, CompiledFloorTable, ControlPoint, DecisionReceipt,
    ProvenanceSource, TrustedKeyInfo, Verdict,
};
use grdr_os_clock::{Clock, SystemClock};
use grdr_wire::frame::{
    IPC_WIRE_VERSION, WireFrame, WirePayload, embedded_max_frame_bytes, encode_proto_payload,
};
use grdr_wire::limits::embedded_limits;
use grdr_wire::messages::{
    ChannelProfileKind, DecideRequestFrame, DecideVerdictFrame, EndpointServiceKind, HelloFrame,
    WireActionClass, WireControlPoint, WireVerdict,
};
use grdr_wire::peer_auth::{AuthenticatedChannel, FrameStream, Profile, open};

use crate::RunError;
use crate::floor_fallback::{
    default_state_dir, evaluate_in_memory_floor, evaluate_signed_floor_file,
};
use crate::ipc_transport::{
    TimeoutConfigurableStream, boot_mono_ms, client_identity_policy, extract_server_claims,
    probe_guardrails_scm, remaining_dur, resolve_decide_address, verify_unix_server_path_post,
    verify_unix_server_path_pre,
};
use crate::planner::{ContainmentStrategy, LaunchRequestSpec};

const MAX_CREDIT_FRAMES_PER_WAIT: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateVerdict {
    Allow {
        source: GateDecisionSource,
    },
    Deny {
        source: GateDecisionSource,
        reason: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateDecisionSource {
    Daemon,
    SignedCompiledFloor { degraded: bool },
}

pub type GateFuture<'a> =
    Pin<Box<dyn Future<Output = Result<DecisionReceipt, RunError>> + Send + 'a>>;

pub trait LaunchGateClient: Send + Sync {
    fn authorize<'a>(&'a self, attempt: &'a ActionAttempt) -> GateFuture<'a>;

    fn authorize_request<'a>(
        &'a self,
        attempt: &'a ActionAttempt,
        _command_line: &'a str,
        _cwd: &'a str,
    ) -> GateFuture<'a> {
        self.authorize(attempt)
    }
}

#[derive(Debug, Clone)]
pub struct IpcGateClient {
    profile: Profile,
    socket_override: Option<String>,
    timeout: Duration,
}

impl IpcGateClient {
    pub fn new(profile: Profile, socket_override: Option<String>, timeout_ms: u64) -> Self {
        let bounded_ms = timeout_ms.clamp(50, 15_000);
        let clean_override = socket_override.filter(|s| !s.trim().is_empty());
        Self {
            profile,
            socket_override: clean_override,
            timeout: Duration::from_millis(bounded_ms),
        }
    }
}

impl LaunchGateClient for IpcGateClient {
    fn authorize<'a>(&'a self, attempt: &'a ActionAttempt) -> GateFuture<'a> {
        self.authorize_request(attempt, &attempt.target, "")
    }

    fn authorize_request<'a>(
        &'a self,
        attempt: &'a ActionAttempt,
        command_line: &'a str,
        cwd: &'a str,
    ) -> GateFuture<'a> {
        let profile = self.profile;
        let socket_override = self.socket_override.clone();
        let timeout = self.timeout;
        let attempt_owned = attempt.clone();
        let command_line_owned = command_line.to_string();
        let cwd_owned = cwd.to_string();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                authorize_over_peer_ipc(
                    &attempt_owned,
                    &command_line_owned,
                    &cwd_owned,
                    profile,
                    socket_override.as_deref(),
                    timeout,
                )
            })
            .await
            .map_err(|e| RunError::GateUnavailable(format!("ipc worker join error: {e}")))?
        })
    }
}

pub fn default_gate_timeout_ms() -> Result<u64, RunError> {
    Ok(embedded_limits()
        .map_err(|e| RunError::InvalidPlan(format!("embedded limits unavailable: {e}")))?
        .read_timeout_ms)
}

#[must_use]
pub fn launch_attempt(req: &LaunchRequestSpec, now: Timestamp) -> ActionAttempt {
    let action_class = match req.strategy {
        ContainmentStrategy::WrapTools => ActionClass::Exec,
        ContainmentStrategy::WrapAgent
        | ContainmentStrategy::Delegate
        | ContainmentStrategy::RequestOnly => ActionClass::AgentSpawn,
    };
    let safe_target = sanitize_log_fragment(&redact_sensitive_text(&req.program), 256);
    let safe_ws = sanitize_log_fragment(&req.workspace_root, 256);
    ActionAttempt {
        id: format!("att_{}", Uuid::now_v7().simple()),
        session_id: req.session_id.clone(),
        device_id: "dev-local".into(),
        device_name: "local-host".into(),
        agent_name: req.agent_name.clone(),
        action_class,
        control_point: ControlPoint::Sandbox,
        target: safe_target,
        summary: format!(
            "grdr-run strategy={} workspace={safe_ws}",
            req.strategy.as_str(),
        ),
        timestamp: now,
        provenance: ProvenanceSource::Mediated,
        ..Default::default()
    }
}

pub fn redacted_command_and_cwd(req: &LaunchRequestSpec) -> (String, String) {
    let joined = if req.args.is_empty() {
        req.program.clone()
    } else {
        format!("{} {}", req.program, req.args.join(" "))
    };
    let safe_cmd = sanitize_log_fragment(&redact_sensitive_text(&joined), 1024);
    let safe_cwd = sanitize_log_fragment(&req.workspace_root, 512);
    (safe_cmd, safe_cwd)
}

pub async fn authorize_launch<C: LaunchGateClient>(
    client: &C,
    req: &LaunchRequestSpec,
    floor: Option<(&CompiledFloorTable, &[TrustedKeyInfo])>,
    now: Timestamp,
) -> Result<GateVerdict, RunError> {
    authorize_launch_with_state_dir(client, req, floor, None, Profile::User, now).await
}

pub async fn authorize_launch_with_state_dir<C: LaunchGateClient>(
    client: &C,
    req: &LaunchRequestSpec,
    floor: Option<(&CompiledFloorTable, &[TrustedKeyInfo])>,
    state_dir_root: Option<&Path>,
    profile: Profile,
    now: Timestamp,
) -> Result<GateVerdict, RunError> {
    let attempt = launch_attempt(req, now);
    let (cmd_line, cwd) = redacted_command_and_cwd(req);
    match client.authorize_request(&attempt, &cmd_line, &cwd).await {
        Ok(receipt) => match receipt.verdict {
            Verdict::Allow => Ok(GateVerdict::Allow {
                source: GateDecisionSource::Daemon,
            }),
            other => Ok(GateVerdict::Deny {
                source: GateDecisionSource::Daemon,
                reason: format!("verdict {other:?}: {}", receipt.reason),
            }),
        },
        Err(daemon_err @ RunError::GateUnavailable(_)) => {
            if let Some((table, trusted_keys)) = floor {
                return evaluate_in_memory_floor(table, trusted_keys, &attempt, now);
            }
            let dir = default_state_dir(profile, state_dir_root)?;
            let outcome = evaluate_signed_floor_file(
                &dir,
                profile == Profile::Protected,
                &attempt,
                now,
                &daemon_err.to_string(),
            )?;
            let source = GateDecisionSource::SignedCompiledFloor { degraded: true };
            if attempt.action_class == ActionClass::AgentSpawn {
                return Ok(GateVerdict::Deny {
                    source,
                    reason: "D-15: session container launch denied while grdr-daemon is offline"
                        .into(),
                });
            }
            if outcome.stale {
                return Ok(GateVerdict::Deny {
                    source,
                    reason: format!(
                        "stale signed floor table rejected (rule `{}`): {}",
                        outcome.rule_id, outcome.reason
                    ),
                });
            }
            match outcome.verdict {
                WireVerdict::Allow => Ok(GateVerdict::Allow { source }),
                WireVerdict::Ask | WireVerdict::Block | WireVerdict::Unspecified => {
                    Ok(GateVerdict::Deny {
                        source,
                        reason: format!("rule `{}`: {}", outcome.rule_id, outcome.reason),
                    })
                }
            }
        }
        Err(fatal_err) => Err(fatal_err),
    }
}

fn authorize_over_peer_ipc(
    attempt: &ActionAttempt,
    command_line: &str,
    cwd: &str,
    profile: Profile,
    socket_override: Option<&str>,
    timeout: Duration,
) -> Result<DecisionReceipt, RunError> {
    if profile == Profile::Protected
        && (socket_override.is_some()
            || std::env::var_os("GRDR_DECIDE_ENDPOINT").is_some_and(|v| !v.is_empty()))
    {
        return Err(RunError::PolicyDenied(
            "protected profile prohibits decide endpoint overrides".into(),
        ));
    }

    let addr =
        resolve_decide_address(profile, socket_override).map_err(RunError::GateUnavailable)?;
    let policy = client_identity_policy(profile)
        .map_err(|e| RunError::PolicyDenied(format!("client identity policy invalid: {e}")))?;
    let deadline_at = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| RunError::GateUnavailable("deadline overflow".into()))?;
    let max_frame_bytes = embedded_limits()
        .map(|l| l.max_frame_bytes)
        .unwrap_or_else(|_| embedded_max_frame_bytes().unwrap_or(1_048_576));

    let pre_facts = match verify_unix_server_path_pre(&addr) {
        Ok(facts) => facts,
        Err((true, detail)) => return Err(RunError::GateUnavailable(detail)),
        Err((false, detail)) => return Err(RunError::PolicyDenied(detail)),
    };
    let rem_ms = u64::try_from(timeout.as_millis())
        .unwrap_or(2_000)
        .clamp(50, 15_000);
    let ipc_deadline = IpcDeadline::from_millis_capped(rem_ms, 15_000);
    let clock = SystemClock::new();
    let pre_scm = probe_guardrails_scm();
    let link = SystemConnector::default()
        .connect(
            &addr,
            ipc_deadline,
            &FixedTimestampSource::new(clock.now_wall().unwrap_or(Timestamp::UNIX_EPOCH)),
        )
        .map_err(|e| RunError::GateUnavailable(format!("ipc connect failed: {e}")))?;

    verify_unix_server_path_post(&addr, profile, pre_facts)
        .map_err(|e| RunError::PolicyDenied(format!("peer path check rejected: {e}")))?;
    let (claims, connected_ticks, _peer_hold) = extract_server_claims(&link, profile, &pre_scm)
        .map_err(|e| RunError::PolicyDenied(format!("peer claims rejected: {e}")))?;

    let mut nonce = [0u8; 32];
    grdr_wire::fill_random_bytes(&mut nonce)
        .map_err(|e| RunError::PolicyDenied(format!("nonce rng failed: {e}")))?;
    let hello = HelloFrame {
        protocol_version: IPC_WIRE_VERSION,
        service: EndpointServiceKind::Decide as i32,
        profile: match profile {
            Profile::Protected => ChannelProfileKind::Protected as i32,
            Profile::User => ChannelProfileKind::User as i32,
            Profile::Inherited => ChannelProfileKind::Inherited as i32,
        },
        client_nonce: nonce.to_vec(),
        pid: std::process::id(),
        capabilities: vec!["decide.v1".into()],
    };

    let io_rem = remaining_dur(deadline_at)
        .ok_or_else(|| RunError::GateUnavailable("ipc handshake timed out".into()))?;
    let (mut chan, ready) = open(
        ProtoIpcStream::with_timeouts(link, io_rem, io_rem),
        &claims,
        connected_ticks,
        &policy,
        hello,
        max_frame_bytes,
    )
    .map_err(|e| RunError::PolicyDenied(format!("peer auth rejected: {e}")))?;

    let frame_cap = max_frame_bytes
        .min(usize::try_from(ready.max_frame_bytes).unwrap_or(usize::MAX))
        .max(1024);
    let req_id = attempt.id.clone();
    let now_mono = boot_mono_ms(&clock);
    let req_frame = WireFrame::with_payload(
        1,
        1,
        WirePayload::DecideRequest(DecideRequestFrame {
            request_id: req_id.clone(),
            hook_seq: 1,
            agent: attempt.agent_name.clone(),
            control_point: WireControlPoint::Sandbox as i32,
            action_class: to_wire_action_class(attempt.action_class) as i32,
            session_id: attempt.session_id.clone(),
            target: attempt.target.clone(),
            summary: attempt.summary.clone(),
            command_line: command_line.to_string(),
            cwd: cwd.to_string(),
            sha256: String::new(),
            emitted_mono_ms: now_mono,
            tool_name: String::new(),
            raw_payload: Vec::new(),
        }),
    );
    encode_proto_payload(&req_frame, frame_cap)
        .map_err(|e| RunError::InvalidPlan(format!("decide frame overflow: {e}")))?;
    chan.send_frame(req_frame)
        .map_err(|e| RunError::GateUnavailable(format!("ipc send failed: {e}")))?;

    let first = recv_non_credit_frame(&mut chan, deadline_at)?;
    let verdict_frame = match first.payload {
        Some(WirePayload::DecideVerdict(verdict)) => verdict,
        Some(WirePayload::DecideAck(ack)) => {
            if ack.request_id != req_id {
                return Err(RunError::PolicyDenied("ipc ack request_id mismatch".into()));
            }
            let second = recv_non_credit_frame(&mut chan, deadline_at)?;
            match second.payload {
                Some(WirePayload::DecideVerdict(verdict)) => verdict,
                Some(WirePayload::Error(err)) => {
                    return Err(RunError::PolicyDenied(format!(
                        "daemon error {}: {}",
                        err.code, err.message
                    )));
                }
                _ => {
                    return Err(RunError::PolicyDenied("unexpected frame after ack".into()));
                }
            }
        }
        Some(WirePayload::Error(err)) => {
            return Err(RunError::PolicyDenied(format!(
                "daemon error {}: {}",
                err.code, err.message
            )));
        }
        _ => {
            return Err(RunError::PolicyDenied(
                "unexpected initial response frame".into(),
            ));
        }
    };

    if verdict_frame.request_id != req_id {
        return Err(RunError::PolicyDenied(
            "ipc verdict request_id mismatch".into(),
        ));
    }

    Ok(verdict_frame_to_receipt(attempt, &verdict_frame))
}

fn verdict_frame_to_receipt(
    attempt: &ActionAttempt,
    frame: &DecideVerdictFrame,
) -> DecisionReceipt {
    let verdict = match WireVerdict::try_from(frame.verdict).unwrap_or(WireVerdict::Block) {
        WireVerdict::Allow => Verdict::Allow,
        WireVerdict::Ask => Verdict::StepUp,
        WireVerdict::Block | WireVerdict::Unspecified => Verdict::Deny,
    };
    let rule_id = (!frame.rule_id.trim().is_empty()).then(|| frame.rule_id.clone());
    let digest = compute_receipt_digest(&ReceiptDigestInput {
        attempt_id: &attempt.id,
        session_id: &attempt.session_id,
        agent_name: &attempt.agent_name,
        action_class: attempt.action_class,
        target: &attempt.target,
        verdict,
        rule_id: rule_id.as_deref(),
        decided_at: attempt.timestamp,
    });
    DecisionReceipt {
        receipt_id: if frame.receipt_id.trim().is_empty() {
            format!("rcp-ipc-{}", attempt.id)
        } else {
            frame.receipt_id.clone()
        },
        attempt_id: attempt.id.clone(),
        session_id: attempt.session_id.clone(),
        device_id: attempt.device_id.clone(),
        agent_name: attempt.agent_name.clone(),
        action_class: attempt.action_class,
        control_point: attempt.control_point,
        target: attempt.target.clone(),
        verdict,
        would_be: None,
        rule_id,
        pack_id: Some("grdr-ipc".into()),
        mode_applied: None,
        grant_id: None,
        reason: frame.reason.clone(),
        next_step: "enforced".into(),
        receipt_digest: digest,
        decided_at: attempt.timestamp,
        key_id: None,
        signature: None,
        signature_verified: None,
    }
}

fn recv_non_credit_frame<S: FrameStream + TimeoutConfigurableStream>(
    chan: &mut AuthenticatedChannel<S>,
    deadline: Instant,
) -> Result<WireFrame, RunError> {
    for _ in 0..MAX_CREDIT_FRAMES_PER_WAIT {
        let rem = remaining_dur(deadline)
            .ok_or_else(|| RunError::GateUnavailable("ipc response timed out".into()))?;
        chan.stream_mut()
            .configure_io_timeouts(rem, rem)
            .map_err(|e| RunError::GateUnavailable(format!("ipc set timeout: {e}")))?;
        let frame = chan
            .recv_frame()
            .map_err(|e| RunError::GateUnavailable(format!("ipc recv failed: {e}")))?;
        if matches!(frame.payload, Some(WirePayload::CreditGrant(_))) {
            continue;
        }
        return Ok(frame);
    }
    Err(RunError::GateUnavailable("ipc credit grant flood".into()))
}

const fn to_wire_action_class(class: ActionClass) -> WireActionClass {
    match class {
        ActionClass::Exec => WireActionClass::Exec,
        ActionClass::FileRead => WireActionClass::FileRead,
        ActionClass::FileWrite => WireActionClass::FileWrite,
        ActionClass::FileDelete => WireActionClass::FileDelete,
        ActionClass::NetConnect => WireActionClass::NetConnect,
        ActionClass::NetRequest => WireActionClass::NetRequest,
        ActionClass::LlmRequest => WireActionClass::LlmRequest,
        ActionClass::McpConnect => WireActionClass::McpConnect,
        ActionClass::McpCall => WireActionClass::McpCall,
        ActionClass::CredUse => WireActionClass::CredUse,
        ActionClass::AgentSpawn => WireActionClass::AgentSpawn,
        ActionClass::ConfigChange => WireActionClass::ConfigChange,
        ActionClass::Elevate => WireActionClass::Elevate,
        ActionClass::UiAct => WireActionClass::UiAct,
        ActionClass::DataFlow => WireActionClass::DataFlow,
    }
}
