// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Peer-verified `grdr-ipc-os` + `grdr-wire` daemon client (`Decide` & `Local`) with
//! signed `GRDRFLT1` floor fallback for `grdr-proxy`.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use grdr_crypto::fill_random;
use grdr_ipc_os::transport::{Connector, FixedTimestampSource, IpcDeadline, SystemConnector};
use grdr_ipc_os::{IpcError, LocalEndpointAddress, proto_io::ProtoIpcStream};
use grdr_model::{ActionAttempt, DecisionReceipt};
use grdr_os_clock::{Clock, SystemClock};
use grdr_wire::frame::{IPC_WIRE_VERSION, WireFrame, WirePayload, embedded_max_frame_bytes};
use grdr_wire::limits::embedded_limits;
use grdr_wire::messages::{
    ChannelProfileKind, DaemonHealthSummary, DecideVerdictFrame, EndpointServiceKind, HelloFrame,
    LocalCommandKind, LocalRequestFrame, LocalResponseFrame,
};
use grdr_wire::peer_auth::{AuthenticatedChannel, ClientIdentityPolicy, Profile, open};
use jiff::Timestamp;

use crate::floor_fallback::{evaluate_signed_floor, synthetic_deny_receipt};
use crate::ipc_transport::{
    RoundError, TimeoutConfigurableStream, build_decide_request_frame, client_identity_policy,
    default_state_dir, extract_server_claims, probe_guardrails_scm, remaining_dur,
    resolve_service_address, verify_unix_server_path_post, verify_unix_server_path_pre,
    wire_verdict_to_receipt,
};
use crate::{ProxyDecideFuture, ProxyDecisionClient, ProxyError};

const DEFAULT_ACK_TIMEOUT_MS: u64 = 500;
const MAX_VERDICT_BUDGET_MS: u64 = 2_000;
const MAX_CREDIT_FRAMES_PER_WAIT: usize = 16;

#[derive(Debug, Clone)]
pub struct IpcProxyDecisionClient {
    profile: Profile,
    endpoint_override: Option<String>,
    local_override: Option<String>,
    state_dir: PathBuf,
    timeout_ms: u64,
}

impl IpcProxyDecisionClient {
    pub fn from_user_defaults(timeout_ms: u64) -> Result<Self, ProxyError> {
        Self::new(Profile::User, None, None, None, timeout_ms)
    }

    pub fn new(
        profile: Profile,
        endpoint_override: Option<String>,
        local_override: Option<String>,
        state_dir_override: Option<PathBuf>,
        timeout_ms: u64,
    ) -> Result<Self, ProxyError> {
        let protected = profile == Profile::Protected;
        if protected
            && (endpoint_override.is_some()
                || local_override.is_some()
                || state_dir_override.is_some())
        {
            return Err(ProxyError::Sr39Rejected(
                "Protected profile prohibits endpoint or floor overrides".to_string(),
            ));
        }
        let state_dir = state_dir_override.unwrap_or_else(|| default_state_dir(protected));
        let _ = resolve_service_address(
            EndpointServiceKind::Decide,
            profile,
            endpoint_override.as_deref(),
        )
        .map_err(ProxyError::Transport)?;
        Ok(Self {
            profile,
            endpoint_override,
            local_override,
            state_dir,
            timeout_ms: timeout_ms.clamp(50, MAX_VERDICT_BUDGET_MS),
        })
    }

    #[must_use]
    pub fn state_dir(&self) -> &PathBuf {
        &self.state_dir
    }

    #[must_use]
    pub fn is_protected(&self) -> bool {
        self.profile == Profile::Protected
    }

    pub async fn query_daemon_health(&self) -> Result<DaemonHealthSummary, ProxyError> {
        let resp = self
            .send_local_cmd(LocalCommandKind::Status, "", Vec::new())
            .await?;
        resp.health
            .ok_or_else(|| ProxyError::Transport("daemon Local status omitted health".to_string()))
    }

    pub async fn fetch_local_control_payload(&self) -> Result<Vec<u8>, ProxyError> {
        let resp = self
            .send_local_cmd(LocalCommandKind::Status, "proxy-control", Vec::new())
            .await?;
        Ok(resp.payload)
    }

    async fn send_local_cmd(
        &self,
        kind: LocalCommandKind,
        argument: &str,
        payload: Vec<u8>,
    ) -> Result<LocalResponseFrame, ProxyError> {
        let profile = self.profile;
        let local_ep = self.local_override.clone();
        let timeout_ms = self.timeout_ms;
        let arg = argument.to_string();
        tokio::task::spawn_blocking(move || {
            send_local_request(
                profile,
                local_ep.as_deref(),
                timeout_ms,
                kind,
                &arg,
                payload,
            )
        })
        .await
        .map_err(|e| ProxyError::Transport(format!("local IPC worker error: {e}")))?
    }
}

impl ProxyDecisionClient for IpcProxyDecisionClient {
    fn decide<'a>(&'a self, attempt: &'a ActionAttempt) -> ProxyDecideFuture<'a> {
        let owned = attempt.clone();
        let profile = self.profile;
        let endpoint = self.endpoint_override.clone();
        let state_dir = self.state_dir.clone();
        let timeout_ms = self.timeout_ms;
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                evaluate_decide_or_floor(
                    &owned,
                    profile,
                    endpoint.as_deref(),
                    &state_dir,
                    timeout_ms,
                )
            })
            .await
            .map_err(|e| ProxyError::Transport(format!("decide IPC worker error: {e}")))?
        })
    }
}

fn evaluate_decide_or_floor(
    attempt: &ActionAttempt,
    profile: Profile,
    endpoint_override: Option<&str>,
    state_dir: &Path,
    timeout_ms: u64,
) -> Result<DecisionReceipt, ProxyError> {
    let now = SystemClock::new()
        .now_wall()
        .map_err(|e| ProxyError::DaemonDegraded(format!("wall clock unavailable: {e}")))?;
    match send_decide_attempt(attempt, profile, endpoint_override, timeout_ms, now) {
        Ok(receipt) => Ok(receipt),
        Err(RoundError::Unreachable(daemon_err)) => {
            let protected = profile == Profile::Protected;
            if let Some(receipt) =
                evaluate_signed_floor(attempt, state_dir, protected, &daemon_err, now)
            {
                return Ok(receipt);
            }
            Ok(synthetic_deny_receipt(
                attempt,
                "proxy.fail-closed",
                &format!("daemon unreachable ({daemon_err}); signed floor missing or invalid"),
                now,
            ))
        }
        Err(RoundError::FailClosed(reason)) => Ok(synthetic_deny_receipt(
            attempt,
            "proxy.fail-closed",
            &format!("GRDR-PROXY-0006: fail-closed IPC refusal: {reason}"),
            now,
        )),
    }
}

fn send_decide_attempt(
    attempt: &ActionAttempt,
    profile: Profile,
    endpoint_override: Option<&str>,
    timeout_ms: u64,
    now: Timestamp,
) -> Result<DecisionReceipt, RoundError> {
    let max_frame_bytes = embedded_max_frame_bytes().unwrap_or(1_048_576);
    let addr = resolve_service_address(EndpointServiceKind::Decide, profile, endpoint_override)
        .map_err(RoundError::FailClosed)?;
    let policy = client_identity_policy(profile).map_err(RoundError::FailClosed)?;
    let (ack_deadline, verdict_deadline) = compute_deadlines(timeout_ms)?;
    let mut chan = connect_and_open(
        EndpointServiceKind::Decide,
        &addr,
        profile,
        &policy,
        ack_deadline,
        max_frame_bytes,
    )?;

    let frame = build_decide_request_frame(attempt, max_frame_bytes)?;
    chan.send_frame(frame)
        .map_err(|err| RoundError::FailClosed(format!("post-auth send DecideRequest: {err}")))?;
    let verdict = await_verdict(&mut chan, &attempt.id, ack_deadline, verdict_deadline)?;
    Ok(wire_verdict_to_receipt(attempt, &verdict, now))
}

fn send_local_request(
    profile: Profile,
    endpoint_override: Option<&str>,
    timeout_ms: u64,
    kind: LocalCommandKind,
    argument: &str,
    payload: Vec<u8>,
) -> Result<LocalResponseFrame, ProxyError> {
    let max_frame_bytes = embedded_max_frame_bytes().unwrap_or(1_048_576);
    let addr = resolve_service_address(EndpointServiceKind::Local, profile, endpoint_override)
        .map_err(ProxyError::Transport)?;
    let policy = client_identity_policy(profile).map_err(ProxyError::Transport)?;
    let (ack_deadline, verdict_deadline) =
        compute_deadlines(timeout_ms).map_err(|e| ProxyError::Transport(e.into_string()))?;
    let mut chan = connect_and_open(
        EndpointServiceKind::Local,
        &addr,
        profile,
        &policy,
        ack_deadline,
        max_frame_bytes,
    )
    .map_err(|e| ProxyError::Transport(e.into_string()))?;

    let req_id = format!("pxloc_{}", uuid::Uuid::now_v7().simple());
    let req_frame = WireFrame::with_payload(
        1,
        1,
        WirePayload::LocalRequest(LocalRequestFrame {
            request_id: req_id.clone(),
            kind: kind as i32,
            argument: argument.to_string(),
            payload,
            limit: 1,
        }),
    );
    chan.send_frame(req_frame)
        .map_err(|e| ProxyError::Transport(format!("send LocalRequest failed: {e}")))?;

    let reply = recv_non_credit_frame(&mut chan, verdict_deadline, "local IPC deadline elapsed")
        .map_err(ProxyError::Transport)?;
    match reply.payload {
        Some(WirePayload::LocalResponse(resp)) if resp.request_id == req_id => {
            if !resp.ok {
                return Err(ProxyError::Transport(format!(
                    "{}: {}",
                    resp.error_code, resp.message
                )));
            }
            Ok(resp)
        }
        Some(WirePayload::Error(err)) => Err(ProxyError::Transport(format!(
            "daemon-{}: {}",
            err.code, err.message
        ))),
        _ => Err(ProxyError::Transport(
            "unexpected frame on Local IPC channel".to_string(),
        )),
    }
}

impl RoundError {
    fn into_string(self) -> String {
        match self {
            Self::Unreachable(s) | Self::FailClosed(s) => s,
        }
    }
}

fn compute_deadlines(timeout_ms: u64) -> Result<(Instant, Instant), RoundError> {
    let ack_ms = embedded_limits()
        .map_or(DEFAULT_ACK_TIMEOUT_MS, |l| l.connect_timeout_ms)
        .min(timeout_ms);
    let now = Instant::now();
    let ack_deadline = now
        .checked_add(Duration::from_millis(ack_ms))
        .ok_or_else(|| RoundError::FailClosed("ack deadline overflow".to_string()))?;
    let verdict_deadline = now
        .checked_add(Duration::from_millis(timeout_ms))
        .ok_or_else(|| RoundError::FailClosed("verdict deadline overflow".to_string()))?;
    Ok((ack_deadline, verdict_deadline))
}

fn connect_and_open(
    service: EndpointServiceKind,
    addr: &LocalEndpointAddress,
    profile: Profile,
    policy: &ClientIdentityPolicy,
    ack_deadline: Instant,
    max_frame_bytes: usize,
) -> Result<
    AuthenticatedChannel<ProtoIpcStream<<SystemConnector as Connector>::ConnectedLink>>,
    RoundError,
> {
    let pre_facts = verify_unix_server_path_pre(addr)?;
    let rem_connect = remaining_dur(ack_deadline)
        .ok_or_else(|| RoundError::Unreachable("ack deadline".to_string()))?;
    let rem_ms = u64::try_from(rem_connect.as_millis())
        .unwrap_or(2_000)
        .max(1);
    let clock = SystemClock::new();
    let wall_now = clock
        .now_wall()
        .map_err(|e| RoundError::FailClosed(format!("wall clock unavailable: {e}")))?;
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
    fill_random(&mut nonce).map_err(|e| RoundError::FailClosed(format!("CSPRNG failed: {e}")))?;
    let cap = if service == EndpointServiceKind::Local {
        "local.v1"
    } else {
        "decide.v1"
    };
    let hello = HelloFrame {
        protocol_version: IPC_WIRE_VERSION,
        service: service as i32,
        profile: match profile {
            Profile::Protected => ChannelProfileKind::Protected as i32,
            Profile::User => ChannelProfileKind::User as i32,
            Profile::Inherited => ChannelProfileKind::Inherited as i32,
        },
        client_nonce: nonce.to_vec(),
        pid: std::process::id(),
        capabilities: vec![cap.to_string()],
    };
    let io_open = remaining_dur(ack_deadline)
        .ok_or_else(|| RoundError::Unreachable("open timeout".to_string()))?;
    let (chan, _ready) = open(
        ProtoIpcStream::with_timeouts(link, io_open, io_open),
        &claims,
        connected_ticks,
        policy,
        hello,
        max_frame_bytes,
    )
    .map_err(|err| RoundError::FailClosed(format!("peer auth failed: {err}")))?;
    Ok(chan)
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
