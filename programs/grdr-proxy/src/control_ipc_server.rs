// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Peer-verified OS IPC control receiver (`Local` channel) allowing `grdr-daemon`
//! to push live session tokens, vaulted credentials, and D-30 egress cuts to `grdr-proxy`.

use std::sync::Arc;
use std::time::Duration;

use grdr_ipc_os::LocalEndpointAddress;
use grdr_ipc_os::proto_io::ProtoIpcStream;
#[cfg(unix)]
use grdr_ipc_os::transport::{Acceptor, FixedTimestampSource, IpcDeadline};
#[cfg(unix)]
use grdr_os_clock::{Clock, SystemClock};
#[cfg(windows)]
use grdr_os_service::pipe_dacl::{
    NamedPipeAccessRight, PipeMandatoryLabel, PipeSecurityProfile, build_named_pipe_dacl,
};
use grdr_wire::frame::{WireFrame, WirePayload, embedded_max_frame_bytes};
use grdr_wire::messages::{
    EndpointServiceKind, HandoverStage, LocalCommandKind, LocalResponseFrame,
};
#[cfg(unix)]
use grdr_wire::peer_auth::accept;
use grdr_wire::peer_auth::{AuthenticatedChannel, OsPeerClaims, Profile, ServerIdentityPolicy};
#[cfg(windows)]
use grdr_wire::peer_auth::{Evidence, Refusal, accept_deferred_windows};
#[cfg(unix)]
use jiff::Timestamp;

use crate::ipc_transport::resolve_service_address;
use crate::local_control::{
    ProxyControlUpdate, apply_local_control_payload, apply_local_control_update,
};
use crate::router::ProxyGatewayState;
use crate::{ProxyDecisionClient, ProxyError};

const CONTROL_IO_TIMEOUT: Duration = Duration::from_millis(1_500);

#[cfg(windows)]
type ControlStream = ProtoIpcStream<grdr_ipc_os::windows_pipe_server::WindowsServerPipeStream>;
#[cfg(unix)]
type ControlStream = ProtoIpcStream<grdr_ipc_os::unix_domain::UnixDomainLink>;

#[derive(Clone)]
pub struct BoundControlEndpoint {
    inner: Arc<std::sync::Mutex<InnerBoundControlEndpoint>>,
}

struct InnerBoundControlEndpoint {
    profile: Profile,
    policy: ServerIdentityPolicy,
    max_frame_bytes: usize,
    #[cfg(windows)]
    acceptor: grdr_ipc_os::windows_pipe_server::WindowsNamedPipeAcceptor,
    #[cfg(unix)]
    acceptor: grdr_ipc_os::unix_domain::UnixDomainAcceptor,
}

pub fn bind_local_control_endpoint(
    profile: Profile,
    endpoint_override: Option<&str>,
) -> Result<BoundControlEndpoint, ProxyError> {
    if profile == Profile::Protected && endpoint_override.is_some() {
        return Err(ProxyError::Sr39Rejected(
            "Protected profile prohibits custom local control endpoint".to_string(),
        ));
    }
    let addr = resolve_service_address(EndpointServiceKind::Local, profile, endpoint_override)
        .map_err(ProxyError::Transport)?;
    let max_frame_bytes = embedded_max_frame_bytes().unwrap_or(1_048_576);

    #[cfg(windows)]
    {
        let LocalEndpointAddress::WindowsPipe { pipe_name } = addr else {
            return Err(ProxyError::Transport(
                "expected Windows named pipe for local control IPC".to_string(),
            ));
        };
        let (sddl, allowed_sids) = build_windows_control_security(&pipe_name, profile)?;
        let acceptor =
            grdr_ipc_os::windows_pipe_server::WindowsNamedPipeAcceptor::bind(&pipe_name, &sddl)
                .map_err(|e| ProxyError::Transport(format!("bind `{pipe_name}` failed: {e}")))?;
        let policy = build_server_policy(profile, allowed_sids);
        Ok(BoundControlEndpoint {
            inner: Arc::new(std::sync::Mutex::new(InnerBoundControlEndpoint {
                profile,
                policy,
                max_frame_bytes,
                acceptor,
            })),
        })
    }

    #[cfg(unix)]
    {
        use std::io::ErrorKind;
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
        let LocalEndpointAddress::UnixSocket { path } = addr else {
            return Err(ProxyError::Transport(
                "expected Unix socket for local control IPC".to_string(),
            ));
        };
        if let Some(parent) = path.parent() {
            grdr_peer_os::fs_open::check_no_ancestor_symlinks(parent)
                .map_err(|e| ProxyError::Transport(e.to_string()))?;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .map_err(|e| ProxyError::Transport(format!("create control socket dir: {e}")))?;
            grdr_peer_os::fs_open::check_no_ancestor_symlinks(parent)
                .map_err(|e| ProxyError::Transport(e.to_string()))?;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| ProxyError::Transport(format!("chmod control socket dir: {e}")))?;
        }
        match std::fs::symlink_metadata(&path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(ProxyError::Transport(
                        "refusing symlink at control socket path".to_string(),
                    ));
                }
                std::fs::remove_file(&path).map_err(|e| {
                    ProxyError::Transport(format!("remove stale control socket: {e}"))
                })?;
            }
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => {
                return Err(ProxyError::Transport(format!(
                    "inspect control socket metadata: {err}"
                )));
            }
        }
        let acceptor = grdr_ipc_os::unix_domain::UnixDomainAcceptor::bind_with_mode(
            LocalEndpointAddress::UnixSocket { path },
            0o600,
        )
        .map_err(|e| ProxyError::Transport(format!("bind control socket failed: {e}")))?;
        let policy = build_server_policy(profile, Vec::new());
        Ok(BoundControlEndpoint {
            inner: Arc::new(std::sync::Mutex::new(InnerBoundControlEndpoint {
                profile,
                policy,
                max_frame_bytes,
                acceptor,
            })),
        })
    }
}

pub async fn serve_local_control_once<C: ProxyDecisionClient + 'static>(
    bound: &BoundControlEndpoint,
    state: Arc<ProxyGatewayState<C>>,
    accept_timeout_ms: u64,
) -> Result<usize, ProxyError> {
    let handle = tokio::runtime::Handle::current();
    let bound_clone = bound.clone();
    tokio::task::spawn_blocking(move || {
        let mut guard = bound_clone
            .inner
            .lock()
            .map_err(|_| ProxyError::Transport("control endpoint mutex poisoned".to_string()))?;
        serve_blocking_cycle(&mut guard, &state, &handle, accept_timeout_ms)
    })
    .await
    .map_err(|e| ProxyError::Transport(format!("control IPC worker join error: {e}")))?
}

pub async fn run_local_control_ipc_server<C: ProxyDecisionClient + 'static>(
    bound: BoundControlEndpoint,
    state: Arc<ProxyGatewayState<C>>,
) {
    loop {
        match serve_local_control_once(&bound, Arc::clone(&state), 5_000).await {
            Ok(_) => {}
            Err(ProxyError::Transport(msg)) if msg.contains("timed out") => {}
            Err(err) => {
                tracing::debug!(error = %err, "control IPC cycle warning");
            }
        }
        tokio::task::yield_now().await;
    }
}

fn serve_blocking_cycle<C: ProxyDecisionClient + 'static>(
    bound: &mut InnerBoundControlEndpoint,
    state: &ProxyGatewayState<C>,
    handle: &tokio::runtime::Handle,
    accept_timeout_ms: u64,
) -> Result<usize, ProxyError> {
    #[cfg(windows)]
    let link = bound
        .acceptor
        .accept(Duration::from_millis(accept_timeout_ms.clamp(100, 10_000)))
        .map_err(|e| ProxyError::Transport(format!("control IPC accept: {e}")))?;
    #[cfg(unix)]
    let link = {
        let deadline = IpcDeadline::from_millis_capped(accept_timeout_ms.max(100), 10_000);
        let ts = FixedTimestampSource::new(Timestamp::now());
        bound
            .acceptor
            .accept(deadline, &ts)
            .map_err(|e| ProxyError::Transport(format!("control IPC accept: {e}")))?
    };
    let mut chan = authenticate_client(link, bound.profile, &bound.policy, bound.max_frame_bytes)?;

    let frame = chan
        .recv_frame()
        .map_err(|e| ProxyError::Transport(format!("control IPC recv: {e}")))?;
    let Some(WirePayload::LocalRequest(req)) = frame.payload else {
        return Err(ProxyError::Sr39Rejected(
            "expected LocalRequest frame on control IPC".to_string(),
        ));
    };

    let (applied, message) = handle.block_on(dispatch_control_request(state, &req))?;
    let reply = WireFrame::with_payload(
        frame.stream_id,
        frame.seq.saturating_add(1),
        WirePayload::LocalResponse(LocalResponseFrame {
            request_id: req.request_id,
            ok: true,
            error_code: String::new(),
            message,
            payload: Vec::new(),
            health: None,
        }),
    );
    chan.send_frame(reply)
        .map_err(|e| ProxyError::Transport(format!("control IPC reply: {e}")))?;
    Ok(applied)
}

async fn dispatch_control_request<C: ProxyDecisionClient>(
    state: &ProxyGatewayState<C>,
    req: &grdr_wire::messages::LocalRequestFrame,
) -> Result<(usize, String), ProxyError> {
    let kind = LocalCommandKind::try_from(req.kind).unwrap_or(LocalCommandKind::Unspecified);
    match kind {
        LocalCommandKind::Ping | LocalCommandKind::Status => Ok((0, "pong".to_string())),
        LocalCommandKind::SetKillSwitch => {
            if !req.payload.is_empty() {
                let count = apply_local_control_payload(state, &req.payload).await?;
                return Ok((count, "applied kill-switch payload".to_string()));
            }
            let session_id = req.argument.trim();
            if session_id.is_empty() {
                let msg = apply_local_control_update(
                    state,
                    ProxyControlUpdate::SetGlobalKillSwitch {
                        active: true,
                        reason: "local IPC kill-switch".to_string(),
                    },
                )
                .await?;
                Ok((1, msg))
            } else {
                let msg = apply_local_control_update(
                    state,
                    ProxyControlUpdate::CutSessionEgress {
                        session_id: session_id.to_string(),
                        reason: "local IPC session cut".to_string(),
                    },
                )
                .await?;
                Ok((1, msg))
            }
        }
        LocalCommandKind::Reload => {
            let count = apply_local_control_payload(state, &req.payload).await?;
            Ok((count, format!("applied {count} control updates")))
        }
        _ => Err(ProxyError::Sr39Rejected(
            "unsupported LocalCommandKind on proxy control IPC".to_string(),
        )),
    }
}

#[cfg(windows)]
fn authenticate_client(
    stream: grdr_ipc_os::windows_pipe_server::WindowsServerPipeStream,
    _profile: Profile,
    policy: &ServerIdentityPolicy,
    max_frame_bytes: usize,
) -> Result<AuthenticatedChannel<ControlStream>, ProxyError> {
    let connected_at = stream.connected_at_100ns();
    let (pre_claims, proc_hold) =
        grdr_peer_os::win_peer::read_windows_pipe_client_pre(stream.borrowed_handle())
            .map_err(|e| ProxyError::Transport(format!("pre-auth peer failed: {e}")))?;
    let expected_pid = pre_claims.pid;
    let expected_sid = pre_claims.peer_sid.clone();
    if expected_sid.trim().is_empty()
        || matches!(expected_sid.as_str(), "S-1-5-7" | "S-1-5-32-546")
        || expected_sid.ends_with("-501")
    {
        return Err(ProxyError::PolicyDenied(
            "anonymous or guest SID refused on control IPC".to_string(),
        ));
    }
    let proto = ProtoIpcStream::with_timeouts(stream, CONTROL_IO_TIMEOUT, CONTROL_IO_TIMEOUT);
    let pending = accept_deferred_windows(proto, connected_at, policy)
        .map_err(|r| ProxyError::Transport(format!("control peer refused ({}): {r}", r.code())))?;
    let (chan, _hello) = pending
        .first_frame_with_claims(
            EndpointServiceKind::Local,
            "proxy-control",
            1,
            HandoverStage::Normal,
            max_frame_bytes,
            Some(move |s: &mut ControlStream| {
                let verified = grdr_peer_os::win_peer::verify_windows_pipe_client_post_read(
                    s.get_ref().borrowed_handle(),
                    &proc_hold,
                    expected_pid,
                    &expected_sid,
                )
                .map_err(|err| {
                    Refusal::UnauthenticatedPeer(Evidence::MissingPeerToken {
                        detail: err.to_string(),
                    })
                })?;
                Ok(OsPeerClaims::Windows(verified))
            }),
        )
        .map_err(|r| {
            ProxyError::Transport(format!("control handshake failed ({}): {r}", r.code()))
        })?;
    Ok(chan)
}

#[cfg(unix)]
fn authenticate_client(
    link: grdr_ipc_os::unix_domain::UnixDomainLink,
    _profile: Profile,
    policy: &ServerIdentityPolicy,
    max_frame_bytes: usize,
) -> Result<AuthenticatedChannel<ControlStream>, ProxyError> {
    let clock = SystemClock::new();
    let boot_uptime_ms = clock
        .boot_uptime()
        .map_err(|e| ProxyError::Transport(format!("boot clock unavailable: {e}")))?
        .as_millis();
    let boot_uptime_ms =
        u64::try_from(boot_uptime_ms).map_err(|_| ProxyError::Transport("boot overflow".into()))?;
    let wall_now = clock
        .now_wall()
        .map_err(|e| ProxyError::Transport(format!("wall clock unavailable: {e}")))?;
    let wall_unix_us = u64::try_from(wall_now.as_microsecond())
        .map_err(|_| ProxyError::Transport("negative wall clock timestamp".into()))?;
    let stamp = grdr_peer_os::unix_peer::UnixConnectStamp {
        boot_uptime_ms,
        wall_unix_us,
    };
    let hold = grdr_peer_os::unix_peer::read_unix_socket_peer(link.borrowed_fd(), stamp)
        .map_err(|e| ProxyError::Transport(format!("unix peer check failed: {e}")))?;
    if hold.claims.uid == u32::MAX {
        return Err(ProxyError::PolicyDenied(
            "unverified unix uid refused on control IPC".to_string(),
        ));
    }
    let claims = OsPeerClaims::Unix(hold.claims.clone());
    let stream = ProtoIpcStream::with_timeouts(link, CONTROL_IO_TIMEOUT, CONTROL_IO_TIMEOUT);
    let pending = accept(stream, &claims, stamp.for_platform(), policy).map_err(|r| {
        ProxyError::Transport(format!("unix control peer refused ({}): {r}", r.code()))
    })?;
    let (chan, _hello) = pending
        .first_frame(
            EndpointServiceKind::Local,
            "proxy-control",
            1,
            HandoverStage::Normal,
            max_frame_bytes,
        )
        .map_err(|r| {
            ProxyError::Transport(format!("unix control handshake ({}): {r}", r.code()))
        })?;
    drop(hold);
    Ok(chan)
}

#[cfg(windows)]
fn build_windows_control_security(
    pipe_name: &str,
    profile: Profile,
) -> Result<(String, Vec<String>), ProxyError> {
    let rights = [
        NamedPipeAccessRight::FileReadData,
        NamedPipeAccessRight::FileWriteData,
        NamedPipeAccessRight::FileReadAttributes,
        NamedPipeAccessRight::ReadControl,
        NamedPipeAccessRight::Synchronize,
    ];
    let current_sid = grdr_peer_os::win_peer::current_process_sid()
        .map_err(|e| ProxyError::Transport(format!("current SID lookup failed: {e}")))?;
    let (dacl, allowed) = if profile == Profile::Protected {
        (
            PipeSecurityProfile::ProtectedService {
                service_sid: current_sid.clone(),
                mandatory_label: PipeMandatoryLabel::High,
            },
            vec![
                "S-1-5-18".to_string(),
                "S-1-5-19".to_string(),
                "S-1-5-20".to_string(),
            ],
        )
    } else {
        (
            PipeSecurityProfile::UserSession {
                user_sid: current_sid.clone(),
            },
            vec![current_sid],
        )
    };
    let spec = build_named_pipe_dacl(pipe_name, &dacl, &rights)
        .map_err(|e| ProxyError::Transport(format!("control pipe DACL: {e}")))?;
    Ok((spec.sddl, allowed))
}

fn build_server_policy(
    profile: Profile,
    allowed_windows_sids: Vec<String>,
) -> ServerIdentityPolicy {
    let uid = grdr_peer_os::unix_peer::current_effective_ids().map_or(u32::MAX, |ids| ids.0);
    ServerIdentityPolicy {
        profile,
        allowed_client_uids: match profile {
            Profile::Protected => vec![0],
            Profile::Inherited => vec![uid, 0],
            Profile::User => vec![uid],
        },
        allowed_windows_sids,
        minimum_integrity_rid: if profile == Profile::Protected {
            0x3000
        } else {
            0x2000
        },
        reject_app_container: true,
        require_start_time_before_connect: true,
        require_open_as_self_pipe_check: cfg!(windows),
        require_kernel_peer_token: cfg!(unix),
    }
}
