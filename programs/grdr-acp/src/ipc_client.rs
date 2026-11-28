// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::path::PathBuf;
use std::time::{Duration, Instant};

use grdr_crypto::fill_random;
use grdr_ipc_os::transport::{Connector, FixedTimestampSource, IpcDeadline, SystemConnector};
use grdr_ipc_os::{IpcError, LocalEndpointAddress, proto_io::ProtoIpcStream};
use grdr_model::{ActionAttempt, ActionClass, DecisionReceipt, Verdict};
use grdr_os_clock::{Clock, SystemClock};
use grdr_wire::frame::{
    IPC_WIRE_VERSION, WireFrame, WirePayload, embedded_max_frame_bytes, encode_proto_payload,
};
use grdr_wire::limits::embedded_limits;
use grdr_wire::messages::{
    ChannelProfileKind, DecideRequestFrame, DecideVerdictFrame, EndpointServiceKind, HelloFrame,
    WireActionClass, WireControlPoint, WireVerdict,
};
use grdr_wire::peer_auth::{AuthenticatedChannel, ClientIdentityPolicy, Profile, open};
use jiff::Timestamp;

use crate::floor_fallback::evaluate_signed_floor;
use crate::ipc_transport::{
    RoundError, TimeoutConfigurableStream, boot_mono_ms, client_identity_policy, default_state_dir,
    extract_server_claims, probe_guardrails_scm, remaining_dur, resolve_service_address,
    verify_unix_server_path_post, verify_unix_server_path_pre,
};
use crate::{AcpError, DecisionClient, EvalFuture, build_acp_receipt, fail_closed_receipt};

const DEFAULT_ACK_TIMEOUT_MS: u64 = 500;
const MAX_VERDICT_BUDGET_MS: u64 = 2_000;
const MAX_CREDIT_FRAMES_PER_WAIT: usize = 16;

#[derive(Debug, Clone)]
pub struct PeerDaemonClient {
    profile: Profile,
    endpoint_override: Option<String>,
    state_dir: PathBuf,
    timeout_ms: u64,
}

impl PeerDaemonClient {
    pub fn from_user_defaults(timeout_ms: u64) -> Result<Self, AcpError> {
        Self::new(Profile::User, None, None, timeout_ms)
    }

    pub fn new(
        profile: Profile,
        endpoint_override: Option<String>,
        state_dir_override: Option<PathBuf>,
        timeout_ms: u64,
    ) -> Result<Self, AcpError> {
        let protected = profile == Profile::Protected;
        if protected && (endpoint_override.is_some() || state_dir_override.is_some()) {
            return Err(AcpError::InvalidPayload(
                "Protected profile prohibits endpoint or state directory overrides".to_string(),
            ));
        }
        let state_dir = state_dir_override.unwrap_or_else(|| default_state_dir(protected));
        let _ = resolve_service_address(
            EndpointServiceKind::Decide,
            profile,
            endpoint_override.as_deref(),
        )
        .map_err(AcpError::Transport)?;
        Ok(Self {
            profile,
            endpoint_override,
            state_dir,
            timeout_ms: timeout_ms.clamp(50, MAX_VERDICT_BUDGET_MS),
        })
    }

    fn evaluate_blocking(&self, attempt: &ActionAttempt) -> Result<DecisionReceipt, AcpError> {
        let protected = self.profile == Profile::Protected;
        let now = SystemClock::new()
            .now_wall()
            .map_err(|err| AcpError::DaemonUnavailable(format!("wall clock unavailable: {err}")))?;
        match call_daemon_decide(
            attempt,
            self.profile,
            self.endpoint_override.as_deref(),
            self.timeout_ms,
        ) {
            Ok(verdict) => Ok(verdict_to_receipt(attempt, verdict, now)),
            Err(RoundError::Unreachable(reason)) => {
                let mut receipt =
                    evaluate_signed_floor(attempt, &self.state_dir, protected, &reason, now);
                if receipt.rule_id.as_deref() == Some("acp.fail-closed")
                    && receipt.verdict == Verdict::Deny
                {
                    receipt.next_step = reason;
                }
                Ok(receipt)
            }
            Err(RoundError::FailClosed(reason)) => Ok(fail_closed_receipt(
                attempt,
                &format!("GRDR-ACP-0005: {reason}"),
                now,
            )),
        }
    }
}

impl DecisionClient for PeerDaemonClient {
    fn decide<'a>(&'a self, attempt: &'a ActionAttempt) -> EvalFuture<'a> {
        let client = self.clone();
        let owned_attempt = attempt.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || client.evaluate_blocking(&owned_attempt))
                .await
                .map_err(|err| AcpError::Transport(format!("blocking IPC task failed: {err}")))?
        })
    }
}

fn call_daemon_decide(
    attempt: &ActionAttempt,
    profile: Profile,
    endpoint_override: Option<&str>,
    timeout_ms: u64,
) -> Result<DecideVerdictFrame, RoundError> {
    let limits = embedded_limits().ok();
    let ack_ms = limits
        .as_ref()
        .map_or(DEFAULT_ACK_TIMEOUT_MS, |l| l.connect_timeout_ms)
        .min(timeout_ms);
    let max_frame_bytes = embedded_max_frame_bytes().unwrap_or(1_048_576);
    let addr = resolve_service_address(EndpointServiceKind::Decide, profile, endpoint_override)
        .map_err(RoundError::FailClosed)?;
    let policy = client_identity_policy(profile).map_err(RoundError::FailClosed)?;
    let now = Instant::now();
    let ack_deadline = now
        .checked_add(Duration::from_millis(ack_ms))
        .ok_or_else(|| RoundError::FailClosed("ack timeout arithmetic overflow".to_string()))?;
    let verdict_deadline = now
        .checked_add(Duration::from_millis(timeout_ms))
        .ok_or_else(|| RoundError::FailClosed("verdict timeout arithmetic overflow".to_string()))?;
    run_single_decide_round(
        attempt,
        &addr,
        profile,
        &policy,
        ack_deadline,
        verdict_deadline,
        max_frame_bytes,
    )
}

fn run_single_decide_round(
    attempt: &ActionAttempt,
    addr: &LocalEndpointAddress,
    profile: Profile,
    policy: &ClientIdentityPolicy,
    ack_deadline: Instant,
    verdict_deadline: Instant,
    max_frame_bytes: usize,
) -> Result<DecideVerdictFrame, RoundError> {
    let pre_facts = verify_unix_server_path_pre(addr)?;
    let rem_connect = remaining_dur(ack_deadline)
        .ok_or_else(|| RoundError::Unreachable("ack timeout".to_string()))?;
    let rem_ms = u64::try_from(rem_connect.as_millis())
        .unwrap_or(2_000)
        .max(1);
    let clock = SystemClock::new();
    let wall_now = clock
        .now_wall()
        .map_err(|err| RoundError::FailClosed(format!("wall clock unavailable: {err}")))?;
    let pre_scm = probe_guardrails_scm();
    let link = SystemConnector::default()
        .connect(
            addr,
            IpcDeadline::from_millis_capped(rem_ms, 2_000),
            &FixedTimestampSource::new(wall_now),
        )
        .map_err(|err| match err {
            IpcError::Unavailable(_) | IpcError::DeadlineExceeded { .. } => {
                RoundError::Unreachable(format!("daemon IPC connect: {err}"))
            }
            other => RoundError::FailClosed(format!("daemon IPC connect error: {other}")),
        })?;

    verify_unix_server_path_post(addr, profile, pre_facts).map_err(RoundError::FailClosed)?;
    let (claims, connected_ticks, _hold) =
        extract_server_claims(&link, profile, &pre_scm).map_err(RoundError::FailClosed)?;
    let mut nonce = [0u8; 16];
    fill_random(&mut nonce)
        .map_err(|err| RoundError::FailClosed(format!("CSPRNG failed: {err}")))?;
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
        capabilities: vec!["decide.v1".to_string()],
    };
    let io_open = remaining_dur(ack_deadline)
        .ok_or_else(|| RoundError::Unreachable("ack deadline elapsed".to_string()))?;
    let (mut chan, _ready) = open(
        ProtoIpcStream::with_timeouts(link, io_open, io_open),
        &claims,
        connected_ticks,
        policy,
        hello,
        max_frame_bytes,
    )
    .map_err(|err| RoundError::FailClosed(format!("peer auth failed: {err}")))?;

    let req_id = attempt.id.clone();
    let frame = build_decide_request_frame(attempt, &clock, max_frame_bytes)?;
    chan.send_frame(frame)
        .map_err(|err| RoundError::FailClosed(format!("post-auth send decide frame: {err}")))?;
    await_verdict(&mut chan, &req_id, ack_deadline, verdict_deadline)
}

fn await_verdict<S>(
    chan: &mut AuthenticatedChannel<S>,
    req_id: &str,
    ack_deadline: Instant,
    verdict_deadline: Instant,
) -> Result<DecideVerdictFrame, RoundError>
where
    S: grdr_wire::peer_auth::FrameStream + TimeoutConfigurableStream,
{
    let first = recv_non_credit_frame(chan, ack_deadline, "ack deadline elapsed")
        .map_err(RoundError::FailClosed)?;
    match first.payload {
        Some(WirePayload::DecideVerdict(verdict)) => validate_verdict_id(verdict, req_id),
        Some(WirePayload::DecideAck(ack)) => {
            if ack.request_id != req_id {
                return Err(RoundError::FailClosed(
                    "daemon ack request_id mismatch".to_string(),
                ));
            }
            let second = recv_non_credit_frame(chan, verdict_deadline, "verdict deadline elapsed")
                .map_err(RoundError::FailClosed)?;
            match second.payload {
                Some(WirePayload::DecideVerdict(verdict)) => validate_verdict_id(verdict, req_id),
                Some(WirePayload::Error(err)) => Err(RoundError::FailClosed(format!(
                    "daemon-{}: {}",
                    err.code, err.message
                ))),
                _ => Err(RoundError::FailClosed(
                    "unexpected frame after DecideAck".to_string(),
                )),
            }
        }
        Some(WirePayload::Error(err)) => Err(RoundError::FailClosed(format!(
            "daemon-{}: {}",
            err.code, err.message
        ))),
        _ => Err(RoundError::FailClosed(
            "unexpected response frame".to_string(),
        )),
    }
}

fn recv_non_credit_frame<S>(
    chan: &mut AuthenticatedChannel<S>,
    deadline: Instant,
    timeout_label: &str,
) -> Result<WireFrame, String>
where
    S: grdr_wire::peer_auth::FrameStream + TimeoutConfigurableStream,
{
    for _ in 0..MAX_CREDIT_FRAMES_PER_WAIT {
        let rem = remaining_dur(deadline).ok_or_else(|| timeout_label.to_string())?;
        chan.stream_mut()
            .configure_io_timeouts(rem, rem)
            .map_err(|e| format!("configure IPC timeout: {e}"))?;
        let frame = chan.recv_frame().map_err(|e| format!("recv frame: {e}"))?;
        match &frame.payload {
            Some(WirePayload::CreditGrant(_)) | Some(WirePayload::Heartbeat(_)) => continue,
            _ => return Ok(frame),
        }
    }
    Err("exceeded non-verdict control frame budget".to_string())
}

fn validate_verdict_id(
    verdict: DecideVerdictFrame,
    expected_id: &str,
) -> Result<DecideVerdictFrame, RoundError> {
    if verdict.request_id != expected_id {
        return Err(RoundError::FailClosed(
            "daemon verdict request_id mismatch".to_string(),
        ));
    }
    Ok(verdict)
}

fn build_decide_request_frame(
    attempt: &ActionAttempt,
    clock: &SystemClock,
    frame_cap: usize,
) -> Result<WireFrame, RoundError> {
    let raw_payload = serde_json::to_vec(attempt)
        .map_err(|err| RoundError::FailClosed(format!("serialize ActionAttempt: {err}")))?;
    let emitted_mono_ms = boot_mono_ms(clock).map_err(RoundError::FailClosed)?;
    let frame = WireFrame::with_payload(
        1,
        1,
        WirePayload::DecideRequest(DecideRequestFrame {
            request_id: attempt.id.clone(),
            hook_seq: 1,
            agent: attempt.agent_name.clone(),
            control_point: WireControlPoint::Gateway as i32,
            action_class: model_to_wire_action(attempt.action_class) as i32,
            session_id: attempt.session_id.clone(),
            target: attempt.target.clone(),
            summary: attempt.summary.clone(),
            command_line: String::new(),
            cwd: String::new(),
            sha256: String::new(),
            emitted_mono_ms,
            tool_name: attempt.skill_used.clone().unwrap_or_default(),
            raw_payload,
        }),
    );
    encode_proto_payload(&frame, frame_cap)
        .map_err(|err| RoundError::FailClosed(format!("request frame exceeds cap: {err}")))?;
    Ok(frame)
}

fn verdict_to_receipt(
    attempt: &ActionAttempt,
    frame: DecideVerdictFrame,
    now: Timestamp,
) -> DecisionReceipt {
    let verdict = match WireVerdict::try_from(frame.verdict).unwrap_or(WireVerdict::Block) {
        WireVerdict::Allow => Verdict::Allow,
        WireVerdict::Ask => Verdict::StepUp,
        WireVerdict::Block | WireVerdict::Unspecified => Verdict::Deny,
    };
    let reason = if frame.reason.is_empty() {
        "daemon verdict".to_string()
    } else {
        frame.reason
    };
    let rty_token = frame
        .labels
        .iter()
        .find_map(|l| l.strip_prefix("retry_token:"))
        .filter(|tok| crate::is_valid_rty_token(tok))
        .map(str::to_owned);
    let next_step = match verdict {
        Verdict::Allow => String::new(),
        Verdict::StepUp => match rty_token {
            Some(tok) => format!("Step-up approval required; retry_token:{tok}"),
            None => "Step-up approval required".to_string(),
        },
        _ => "Denied by daemon policy".to_string(),
    };
    let receipt_id = if frame.receipt_id.is_empty() {
        attempt.id.as_str()
    } else {
        frame.receipt_id.as_str()
    };
    let rule = (!frame.rule_id.is_empty()).then_some(frame.rule_id.as_str());
    build_acp_receipt(
        attempt,
        verdict,
        rule,
        &reason,
        &next_step,
        Some(receipt_id),
        now,
    )
}

fn model_to_wire_action(class: ActionClass) -> WireActionClass {
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
