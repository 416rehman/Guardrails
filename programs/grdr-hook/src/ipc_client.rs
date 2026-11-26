// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Local IPC client for `grdr-hook`: drives `Decide` (`250 ms` ack / `<= 2000 ms` handover /
//! cumulative deadline enforcement) with signed binary floor fallback when unreachable.

use std::path::Path;
use std::time::{Duration, Instant};

use grdr_ipc_os::LocalEndpointAddress;
use grdr_ipc_os::proto_io::ProtoIpcStream;
use grdr_ipc_os::transport::{Connector, FixedTimestampSource, IpcDeadline, SystemConnector};
use grdr_os_clock::{Clock, SystemClock};
use grdr_wire::frame::{
    IPC_WIRE_VERSION, WireFrame, WirePayload, embedded_max_frame_bytes, encode_proto_payload,
};
use grdr_wire::limits::embedded_limits;
use grdr_wire::messages::{
    ChannelProfileKind, DecideRequestFrame, DecideVerdictFrame, EndpointServiceKind, HelloFrame,
    WireActionClass, WireControlPoint, WireVerdict,
};
use grdr_wire::peer_auth::{ClientIdentityPolicy, Profile, open};

use crate::floor_fallback::{
    HookVerdictOutcome, evaluate_signed_floor_fallback, fail_closed_outcome,
};
use crate::ipc_transport::{
    TimeoutConfigurableStream, boot_mono_ms, client_identity_policy, extract_server_claims,
    probe_guardrails_scm, remaining_dur, resolve_decide_address, verify_unix_server_path_post,
    verify_unix_server_path_pre,
};
use crate::json_lexer::bounded_utf8_prefix;
use crate::json_scan::ScannedHookInput;
use crate::offline_spool::active_handover_remaining_ms;

pub const DEFAULT_ACK_TIMEOUT_MS: u64 = 250;
pub const MAX_VERDICT_BUDGET_MS: u64 = 1800;
const HANDOVER_RETRY_SLEEP_MS: u64 = 20;
const MAX_CREDIT_FRAMES_PER_WAIT: usize = 16;

enum DaemonCallError {
    Unreachable(String),
    FailClosed(String),
}

enum RoundError {
    RetryableUnreachable(String),
    NonRetryableUnreachable(String),
    FailClosed(String),
}

#[must_use]
pub fn is_protected_profile_active() -> bool {
    #[cfg(target_os = "linux")]
    {
        Path::new("/run/guardrails").exists() || Path::new("/var/lib/guardrails/state").exists()
    }
    #[cfg(target_os = "macos")]
    {
        Path::new("/Library/Application Support/grdr").exists()
            || Path::new("/var/lib/guardrails/state").exists()
    }
    #[cfg(windows)]
    {
        grdr_peer_os::win_peer::probe_scm_services(&["Guardrails", "GuardrailsHandover"])
            .into_iter()
            .any(|probe| probe.is_some())
            || crate::offline_spool::system_state_dir().exists()
    }
}

#[allow(clippy::too_many_arguments)]
pub fn evaluate_against_daemon_or_floor(
    input: &ScannedHookInput,
    state_dir: &Path,
    socket_override: Option<&str>,
    protected: bool,
    req_id: &str,
    hook_seq: u64,
    started: Instant,
) -> HookVerdictOutcome {
    let clock = SystemClock::new();
    let now_mono = boot_mono_ms(&clock);
    let (ack_default_ms, verdict_budget_ms, max_frame_bytes) = runtime_ipc_budgets();
    let handover_ms = active_handover_remaining_ms(state_dir, now_mono);
    let ack_ceiling_ms = handover_ms.map_or(ack_default_ms, |h| h.min(verdict_budget_ms));

    match call_daemon_decide(
        input,
        socket_override,
        protected,
        req_id,
        hook_seq,
        now_mono,
        ack_ceiling_ms,
        verdict_budget_ms,
        max_frame_bytes,
        handover_ms.is_some(),
        started,
    ) {
        Ok(verdict) => {
            let decoded = WireVerdict::try_from(verdict.verdict).unwrap_or(WireVerdict::Block);
            if decoded == WireVerdict::Unspecified {
                return fail_closed_outcome(
                    input.control_point,
                    "daemon returned unspecified WireVerdict",
                );
            }
            HookVerdictOutcome {
                verdict: decoded,
                rule_id: verdict.rule_id,
                reason: verdict.reason,
                receipt_id: verdict.receipt_id,
                floor_fallback: verdict.floor_fallback,
                degraded_reason: verdict.degraded_reason,
            }
        }
        Err(DaemonCallError::Unreachable(err_reason)) => {
            evaluate_signed_floor_fallback(input, state_dir, protected, &err_reason)
        }
        Err(DaemonCallError::FailClosed(reason)) => {
            fail_closed_outcome(input.control_point, &reason)
        }
    }
}

fn runtime_ipc_budgets() -> (u64, u64, usize) {
    let fallback_max = embedded_max_frame_bytes().unwrap_or(1_048_576);
    match embedded_limits() {
        Ok(limits) => {
            let ack = limits.connect_timeout_ms.clamp(50, DEFAULT_ACK_TIMEOUT_MS);
            let verdict = limits.shim_hang_max_ms.saturating_sub(200).max(1_500);
            (ack, verdict, limits.max_frame_bytes)
        }
        Err(_) => (DEFAULT_ACK_TIMEOUT_MS, MAX_VERDICT_BUDGET_MS, fallback_max),
    }
}

#[allow(clippy::too_many_arguments)]
fn call_daemon_decide(
    input: &ScannedHookInput,
    socket_override: Option<&str>,
    protected: bool,
    req_id: &str,
    hook_seq: u64,
    now_mono: u64,
    ack_ceiling_ms: u64,
    verdict_budget_ms: u64,
    max_frame_bytes: usize,
    handover_active: bool,
    started: Instant,
) -> Result<DecideVerdictFrame, DaemonCallError> {
    let profile = if protected {
        Profile::Protected
    } else {
        Profile::User
    };
    if protected
        && (socket_override.is_some()
            || std::env::var_os("GRDR_DECIDE_ENDPOINT").is_some_and(|v| !v.is_empty()))
    {
        return Err(DaemonCallError::FailClosed(
            "protected profile prohibits endpoint overrides".to_string(),
        ));
    }

    let addr =
        resolve_decide_address(profile, socket_override).map_err(DaemonCallError::FailClosed)?;
    let policy = client_identity_policy(profile).map_err(DaemonCallError::FailClosed)?;
    let Some(ack_deadline) = started.checked_add(Duration::from_millis(ack_ceiling_ms)) else {
        return Err(DaemonCallError::Unreachable(
            "ack-deadline-overflow".to_string(),
        ));
    };
    let Some(verdict_deadline) = started.checked_add(Duration::from_millis(verdict_budget_ms))
    else {
        return Err(DaemonCallError::FailClosed(
            "verdict-deadline-overflow".to_string(),
        ));
    };

    let mut attempt: u32 = 0;
    loop {
        if Instant::now() >= ack_deadline {
            return Err(DaemonCallError::Unreachable(
                "ack-deadline-exceeded".to_string(),
            ));
        }
        match try_single_decide_round(
            input,
            &addr,
            profile,
            &policy,
            req_id,
            hook_seq,
            now_mono,
            ack_deadline,
            verdict_deadline,
            max_frame_bytes,
        ) {
            Ok(verdict) => return Ok(verdict),
            Err(RoundError::RetryableUnreachable(err)) => {
                let can_retry = handover_active || attempt == 0;
                attempt = attempt.saturating_add(1);
                let sleep_dur = Duration::from_millis(HANDOVER_RETRY_SLEEP_MS);
                if can_retry
                    && Instant::now()
                        .checked_add(sleep_dur)
                        .is_some_and(|wake| wake < ack_deadline)
                {
                    std::thread::sleep(sleep_dur);
                    continue;
                }
                return Err(DaemonCallError::Unreachable(err));
            }
            Err(RoundError::NonRetryableUnreachable(err)) => {
                return Err(DaemonCallError::Unreachable(err));
            }
            Err(RoundError::FailClosed(err)) => return Err(DaemonCallError::FailClosed(err)),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn try_single_decide_round(
    input: &ScannedHookInput,
    addr: &LocalEndpointAddress,
    profile: Profile,
    policy: &ClientIdentityPolicy,
    req_id: &str,
    hook_seq: u64,
    now_mono: u64,
    ack_deadline: Instant,
    verdict_deadline: Instant,
    max_frame_bytes: usize,
) -> Result<DecideVerdictFrame, RoundError> {
    let unix_pre_facts = verify_unix_server_path_pre(addr).map_err(|(retryable, detail)| {
        if retryable {
            RoundError::RetryableUnreachable(detail)
        } else {
            RoundError::FailClosed(detail)
        }
    })?;

    let rem_connect = remaining_dur(ack_deadline)
        .ok_or_else(|| RoundError::RetryableUnreachable("ack-deadline-exceeded".to_string()))?;
    let rem_connect_ms = u64::try_from(rem_connect.as_millis())
        .unwrap_or(2_000)
        .max(1);
    let deadline = IpcDeadline::from_millis_capped(rem_connect_ms, 2_000);
    let connector = SystemConnector::default();
    let clock = SystemClock::new();
    let pre_scm = probe_guardrails_scm();
    let link = connector
        .connect(
            addr,
            deadline,
            &FixedTimestampSource::new(clock.now_wall().unwrap_or(jiff::Timestamp::UNIX_EPOCH)),
        )
        .map_err(|err| RoundError::RetryableUnreachable(format!("daemon-ipc-connect: {err}")))?;

    verify_unix_server_path_post(addr, profile, unix_pre_facts).map_err(RoundError::FailClosed)?;

    let (claims, connected_ticks, _peer_hold) =
        extract_server_claims(&link, profile, &pre_scm).map_err(RoundError::FailClosed)?;

    let mut nonce = [0u8; 32];
    grdr_wire::fill_random_bytes(&mut nonce)
        .map_err(|e| RoundError::FailClosed(format!("nonce-rng: {e}")))?;
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

    let io_open_timeout = remaining_dur(ack_deadline)
        .ok_or_else(|| RoundError::RetryableUnreachable("ack-deadline-exceeded".to_string()))?;
    let (mut chan, ready) = open(
        ProtoIpcStream::with_timeouts(link, io_open_timeout, io_open_timeout),
        &claims,
        connected_ticks,
        policy,
        hello,
        max_frame_bytes,
    )
    .map_err(|err| RoundError::FailClosed(format!("daemon-peer-auth: {err}")))?;

    let frame_cap = max_frame_bytes
        .min(usize::try_from(ready.max_frame_bytes).unwrap_or(usize::MAX))
        .max(1024);
    let req_frame = build_bounded_decide_request(input, req_id, hook_seq, now_mono, frame_cap)?;

    let send_timeout = remaining_dur(ack_deadline)
        .ok_or_else(|| RoundError::RetryableUnreachable("ack-deadline-exceeded".to_string()))?;
    chan.stream_mut()
        .set_timeouts(send_timeout, send_timeout)
        .map_err(|err| RoundError::NonRetryableUnreachable(format!("daemon-set-timeout: {err}")))?;
    chan.send_frame(req_frame).map_err(|err| {
        let msg = err.to_string();
        if msg.contains("GRDR-WIRE-0010") || msg.contains("too large") {
            RoundError::FailClosed(format!("daemon-req-too-large: {msg}"))
        } else {
            RoundError::RetryableUnreachable(format!("daemon-send-req: {msg}"))
        }
    })?;

    let first_reply = recv_non_credit_frame(&mut chan, ack_deadline, "ack-deadline-exceeded")
        .map_err(RoundError::RetryableUnreachable)?;
    match first_reply.payload {
        Some(WirePayload::DecideVerdict(verdict)) => validate_verdict_id(verdict, req_id),
        Some(WirePayload::DecideAck(ack)) => {
            if ack.request_id != req_id {
                return Err(RoundError::FailClosed(
                    "daemon ack request_id mismatch".to_string(),
                ));
            }
            let second_reply =
                recv_non_credit_frame(&mut chan, verdict_deadline, "verdict-budget-exceeded")
                    .map_err(RoundError::NonRetryableUnreachable)?;
            match second_reply.payload {
                Some(WirePayload::DecideVerdict(verdict)) => validate_verdict_id(verdict, req_id),
                Some(WirePayload::Error(err)) => Err(RoundError::FailClosed(format!(
                    "daemon-error-{}: {}",
                    err.code, err.message
                ))),
                _ => Err(RoundError::FailClosed(
                    "unexpected-frame-after-ack".to_string(),
                )),
            }
        }
        Some(WirePayload::Error(err)) => Err(RoundError::FailClosed(format!(
            "daemon-error-{}: {}",
            err.code, err.message
        ))),
        _ => Err(RoundError::FailClosed(
            "unexpected-response-frame".to_string(),
        )),
    }
}

fn validate_verdict_id(
    verdict: DecideVerdictFrame,
    expected_req_id: &str,
) -> Result<DecideVerdictFrame, RoundError> {
    if verdict.request_id != expected_req_id {
        return Err(RoundError::FailClosed(
            "daemon verdict request_id mismatch".to_string(),
        ));
    }
    Ok(verdict)
}

fn build_bounded_decide_request(
    input: &ScannedHookInput,
    req_id: &str,
    hook_seq: u64,
    now_mono: u64,
    frame_cap: usize,
) -> Result<WireFrame, RoundError> {
    let field_cap = frame_cap.saturating_div(6).max(256);
    let target = bounded_utf8_prefix(input.target.as_bytes(), field_cap);
    let command_line = bounded_utf8_prefix(input.command_line.as_bytes(), field_cap);
    let cwd = bounded_utf8_prefix(input.cwd.as_bytes(), field_cap);
    let summary = bounded_utf8_prefix(input.tool_name.as_bytes(), field_cap);
    let raw_payload = bounded_utf8_prefix(input.raw_payload.as_bytes(), field_cap);

    let frame = WireFrame::with_payload(
        1,
        1,
        WirePayload::DecideRequest(DecideRequestFrame {
            request_id: req_id.to_string(),
            hook_seq,
            agent: input.dialect.as_agent_str().to_string(),
            control_point: i32::try_from(input.control_point)
                .unwrap_or(WireControlPoint::Hook as i32),
            action_class: WireActionClass::from_fast(input.action_class) as i32,
            session_id: input.session_id.clone(),
            target,
            summary,
            command_line,
            cwd,
            sha256: input.payload_sha256.clone(),
            emitted_mono_ms: now_mono,
            tool_name: input.tool_name.clone(),
            raw_payload: raw_payload.into_bytes(),
        }),
    );
    encode_proto_payload(&frame, frame_cap)
        .map_err(|err| RoundError::FailClosed(format!("request-frame-too-large: {err}")))?;
    Ok(frame)
}

fn recv_non_credit_frame<S: grdr_wire::peer_auth::FrameStream + TimeoutConfigurableStream>(
    chan: &mut grdr_wire::peer_auth::AuthenticatedChannel<S>,
    deadline: Instant,
    timeout_label: &str,
) -> Result<WireFrame, String> {
    for _ in 0..MAX_CREDIT_FRAMES_PER_WAIT {
        let rem = remaining_dur(deadline).ok_or_else(|| timeout_label.to_string())?;
        chan.stream_mut()
            .configure_io_timeouts(rem, rem)
            .map_err(|err| format!("daemon-set-timeout: {err}"))?;
        let frame = chan
            .recv_frame()
            .map_err(|err| format!("daemon-recv: {err}"))?;
        if matches!(frame.payload, Some(WirePayload::CreditGrant(_))) {
            continue;
        }
        return Ok(frame);
    }
    Err("daemon-recv-credit-flood".to_string())
}
