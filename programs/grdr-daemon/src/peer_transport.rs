// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! OS-specific endpoint path checks, named pipe SDDL DACLs, Unix domain socket binding,
//! and worker-side kernel peer credential verification (`1500 ms` handshake budget).

use std::time::Duration;

use grdr_ipc_os::proto_io::ProtoIpcStream;
#[cfg(unix)]
use grdr_os_clock::{Clock, SystemClock};
#[cfg(windows)]
use grdr_os_service::pipe_dacl::{
    NamedPipeAccessRight, PipeMandatoryLabel, PipeSecurityProfile, build_named_pipe_dacl,
};
use grdr_wire::endpoint::ResolvedEndpoint;
#[cfg(unix)]
use grdr_wire::endpoint::{PathExpectation, check_directory_path};
use grdr_wire::frame::embedded_max_frame_bytes;
use grdr_wire::messages::{EndpointServiceKind, HandoverStage};
#[cfg(unix)]
use grdr_wire::peer_auth::accept;
use grdr_wire::peer_auth::{AuthenticatedChannel, OsPeerClaims, Profile, ServerIdentityPolicy};
#[cfg(windows)]
use grdr_wire::peer_auth::{Evidence, Refusal, accept_deferred_windows};
use thiserror::Error;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(1_500);

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IpcServerError {
    #[error("GRDR-DAEM-0003: endpoint IPC server failed: {0}")]
    Failed(String),
}

#[cfg(windows)]
pub type PlatformChannelStream =
    ProtoIpcStream<grdr_ipc_os::windows_pipe_server::WindowsServerPipeStream>;
#[cfg(unix)]
pub type PlatformChannelStream = ProtoIpcStream<grdr_ipc_os::unix_domain::UnixDomainLink>;

#[derive(Clone)]
pub struct AuthContext {
    pub service: EndpointServiceKind,
    pub profile: Profile,
    pub policy: ServerIdentityPolicy,
    pub max_frame_bytes: usize,
}

#[cfg(windows)]
pub struct BoundEndpoint {
    pub auth: AuthContext,
    pub endpoint_label: String,
    pub acceptor: grdr_ipc_os::windows_pipe_server::WindowsNamedPipeAcceptor,
}

#[cfg(unix)]
pub struct BoundEndpoint {
    pub auth: AuthContext,
    pub endpoint_label: String,
    pub sock_path: std::path::PathBuf,
    pub adopted_from_launchd: bool,
    pub acceptor: grdr_ipc_os::unix_domain::UnixDomainAcceptor,
}

#[cfg(windows)]
pub fn bind_platform_endpoint(
    service: EndpointServiceKind,
    profile: Profile,
    resolved: &ResolvedEndpoint,
) -> Result<BoundEndpoint, IpcServerError> {
    use grdr_ipc_os::windows_pipe_server::WindowsNamedPipeAcceptor;

    let pipe_name = resolved
        .pipe_name
        .as_deref()
        .ok_or_else(|| IpcServerError::Failed("missing Windows named pipe endpoint".to_string()))?;
    let (sddl, allowed_sids) = build_windows_pipe_security(pipe_name, service, profile)?;
    let acceptor = WindowsNamedPipeAcceptor::bind(pipe_name, &sddl)
        .map_err(|err| IpcServerError::Failed(format!("bind `{pipe_name}` failed: {err}")))?;
    let policy = server_identity_policy(profile, service, allowed_sids);
    let max_frame_bytes = embedded_max_frame_bytes().unwrap_or(1_048_576);
    Ok(BoundEndpoint {
        auth: AuthContext {
            service,
            profile,
            policy,
            max_frame_bytes,
        },
        endpoint_label: pipe_name.to_string(),
        acceptor,
    })
}

#[cfg(windows)]
pub fn authenticate_accepted_stream(
    stream: grdr_ipc_os::windows_pipe_server::WindowsServerPipeStream,
    auth: &AuthContext,
    digest: &str,
    epoch: u64,
) -> Result<AuthenticatedChannel<PlatformChannelStream>, String> {
    let connected_at = stream.connected_at_100ns();
    let (pre_claims, proc_hold) =
        grdr_peer_os::win_peer::read_windows_pipe_client_pre(stream.borrowed_handle())
            .map_err(|e| format!("GRDR-DAEM-0004: pre-auth peer failed: {e}"))?;
    let expected_pid = pre_claims.pid;
    let expected_sid = pre_claims.peer_sid.clone();
    let mut policy = auth.policy.clone();
    if auth.profile == Profile::Protected {
        if is_anonymous_or_guest_sid(&expected_sid) {
            return Err("GRDR-DAEM-0004: anonymous or guest SID refused".to_string());
        }
        policy.allowed_windows_sids = vec![expected_sid.clone()];
    }

    let proto = ProtoIpcStream::with_timeouts(stream, HANDSHAKE_TIMEOUT, HANDSHAKE_TIMEOUT);
    let pending = accept_deferred_windows(proto, connected_at, &policy)
        .map_err(|r| format!("GRDR-DAEM-0004: peer rejected ({}): {r}", r.code()))?;
    let (chan, _hello) = pending
        .first_frame_with_claims(
            auth.service,
            digest,
            epoch,
            HandoverStage::Normal,
            auth.max_frame_bytes,
            Some(move |s: &mut PlatformChannelStream| {
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
        .map_err(|r| format!("handshake refused ({}): {r}", r.code()))?;
    Ok(chan)
}

#[cfg(windows)]
fn is_anonymous_or_guest_sid(sid: &str) -> bool {
    sid.trim().is_empty() || matches!(sid, "S-1-5-7" | "S-1-5-32-546") || sid.ends_with("-501")
}

#[cfg(windows)]
fn build_windows_pipe_security(
    pipe_name: &str,
    service: EndpointServiceKind,
    profile: Profile,
) -> Result<(String, Vec<String>), IpcServerError> {
    let client_rights = [
        NamedPipeAccessRight::FileReadData,
        NamedPipeAccessRight::FileWriteData,
        NamedPipeAccessRight::FileReadAttributes,
        NamedPipeAccessRight::ReadControl,
        NamedPipeAccessRight::Synchronize,
    ];
    let current_sid = grdr_peer_os::win_peer::current_process_sid().ok();
    let (dacl_profile, allowed_sids) = match (profile, current_sid) {
        (Profile::Protected, cur_opt) => {
            let service_sid = cur_opt.clone().unwrap_or_else(|| "S-1-5-18".to_string());
            let mandatory_label = if service == EndpointServiceKind::Decide {
                PipeMandatoryLabel::Low
            } else {
                PipeMandatoryLabel::Medium
            };
            let mut sids = vec!["S-1-5-18".to_string()];
            if let Some(cur) = cur_opt {
                sids.push(cur);
            }
            (
                PipeSecurityProfile::ProtectedService {
                    service_sid,
                    mandatory_label,
                },
                sids,
            )
        }
        (_, Some(user_sid)) => (
            PipeSecurityProfile::UserSession {
                user_sid: user_sid.clone(),
            },
            vec![user_sid],
        ),
        (_, None) => {
            return Err(IpcServerError::Failed(
                "unable to query current process user SID for named pipe DACL".to_string(),
            ));
        }
    };

    let spec = build_named_pipe_dacl(pipe_name, &dacl_profile, &client_rights)
        .map_err(|err| IpcServerError::Failed(format!("pipe DACL failed: {err}")))?;
    Ok((spec.sddl, allowed_sids))
}

#[cfg(unix)]
pub fn bind_platform_endpoint(
    service: EndpointServiceKind,
    profile: Profile,
    resolved: &ResolvedEndpoint,
) -> Result<BoundEndpoint, IpcServerError> {
    use grdr_ipc_os::LocalEndpointAddress;
    use grdr_ipc_os::unix_domain::UnixDomainAcceptor;

    let sock_path = resolved
        .unix_path
        .clone()
        .ok_or_else(|| IpcServerError::Failed("missing Unix socket endpoint path".to_string()))?;

    let (acceptor, adopted_from_launchd) =
        if let Some(listener) = try_adopt_launchd_listener(service) {
            let acc = UnixDomainAcceptor::from_listener(
                listener,
                LocalEndpointAddress::UnixSocket {
                    path: sock_path.clone(),
                },
            )
            .map_err(|err| IpcServerError::Failed(err.to_string()))?;
            (acc, true)
        } else {
            prepare_unix_socket_parent(&sock_path, profile)?;
            let sock_mode = if profile == Profile::Protected {
                if service == EndpointServiceKind::Decide {
                    0o666
                } else {
                    0o660
                }
            } else {
                0o600
            };
            let bound = UnixDomainAcceptor::bind_with_mode(
                LocalEndpointAddress::UnixSocket {
                    path: sock_path.clone(),
                },
                sock_mode,
            )
            .map_err(|err| IpcServerError::Failed(format!("bind endpoint socket failed: {err}")))?;
            (bound, false)
        };

    let policy = server_identity_policy(profile, service, Vec::new());
    let max_frame_bytes = embedded_max_frame_bytes().unwrap_or(1_048_576);
    Ok(BoundEndpoint {
        auth: AuthContext {
            service,
            profile,
            policy,
            max_frame_bytes,
        },
        endpoint_label: format!("{:?}", service),
        sock_path,
        adopted_from_launchd,
        acceptor,
    })
}

#[cfg(unix)]
pub fn authenticate_accepted_stream(
    link: grdr_ipc_os::unix_domain::UnixDomainLink,
    auth: &AuthContext,
    digest: &str,
    epoch: u64,
) -> Result<AuthenticatedChannel<PlatformChannelStream>, String> {
    let clock = SystemClock::new();
    let stamp = grdr_peer_os::unix_peer::UnixConnectStamp {
        boot_uptime_ms: clock
            .boot_uptime()
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
        wall_unix_us: clock
            .now_wall()
            .ok()
            .and_then(|t| u64::try_from(t.as_microsecond()).ok())
            .unwrap_or(0),
    };
    let peer_hold = grdr_peer_os::unix_peer::read_unix_socket_peer(link.borrowed_fd(), stamp)
        .map_err(|e| format!("GRDR-DAEM-0004: unix peer check failed: {e}"))?;
    let mut policy = auth.policy.clone();
    if auth.profile == Profile::Protected {
        if peer_hold.claims.uid == u32::MAX {
            return Err("GRDR-DAEM-0004: unverified unix uid refused".to_string());
        }
        policy.allowed_client_uids = vec![peer_hold.claims.uid];
    }

    let claims = OsPeerClaims::Unix(peer_hold.claims.clone());
    let stream = ProtoIpcStream::with_timeouts(link, HANDSHAKE_TIMEOUT, HANDSHAKE_TIMEOUT);
    let pending = accept(stream, &claims, stamp.for_platform(), &policy)
        .map_err(|r| format!("GRDR-DAEM-0004: unix peer refused ({}): {r}", r.code()))?;
    let (chan, _hello) = pending
        .first_frame(
            auth.service,
            digest,
            epoch,
            HandoverStage::Normal,
            auth.max_frame_bytes,
        )
        .map_err(|r| format!("handshake refused ({}): {r}", r.code()))?;
    drop(peer_hold);
    Ok(chan)
}

#[cfg(unix)]
fn try_adopt_launchd_listener(
    service: EndpointServiceKind,
) -> Option<std::os::unix::net::UnixListener> {
    let sock_name = match service {
        EndpointServiceKind::Decide => "decide",
        EndpointServiceKind::Local => "local",
        _ => return None,
    };
    let mut fds = grdr_os_service::unix_control::activate_macos_sockets(sock_name).ok()?;
    let fd = fds.drain(..).next()?;
    Some(std::os::unix::net::UnixListener::from(fd))
}

#[cfg(unix)]
fn prepare_unix_socket_parent(
    sock_path: &std::path::Path,
    profile: Profile,
) -> Result<(), IpcServerError> {
    use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};

    let Some(parent) = sock_path.parent() else {
        return Err(IpcServerError::Failed(
            "socket path has no parent directory".to_string(),
        ));
    };
    grdr_peer_os::fs_open::check_no_ancestor_symlinks(parent)
        .map_err(|e| IpcServerError::Failed(e.to_string()))?;
    std::fs::create_dir_all(parent)
        .map_err(|err| IpcServerError::Failed(format!("create socket dir: {err}")))?;
    let dir_mode = if profile == Profile::Protected {
        0o755
    } else {
        0o700
    };
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(dir_mode))
        .map_err(|err| IpcServerError::Failed(format!("chmod socket dir: {err}")))?;

    let (uid, gid) = grdr_peer_os::unix_peer::current_effective_ids()
        .ok_or_else(|| IpcServerError::Failed("effective uid unavailable".to_string()))?;
    let mut facts = grdr_peer_os::unix_peer::inspect_unix_directory_live(parent)
        .map_err(|err| IpcServerError::Failed(format!("root-down path check failed: {err}")))?;
    grdr_peer_os::unix_peer::refresh_unix_directory_post_check(&mut facts, parent)
        .map_err(|err| IpcServerError::Failed(format!("root-down post check failed: {err}")))?;
    check_directory_path(
        &facts,
        &PathExpectation {
            profile,
            trusted_owner_uids: vec![0, uid],
            trusted_group_gids: vec![0, gid],
            allow_world_writable_socket_leaf: false,
        },
    )
    .map_err(|err| IpcServerError::Failed(format!("unsafe socket parent directory: {err}")))?;

    if let Ok(meta) = std::fs::symlink_metadata(sock_path) {
        if meta.file_type().is_symlink() || !meta.file_type().is_socket() {
            return Err(IpcServerError::Failed(
                "refusing non-socket or symlink file at endpoint path".to_string(),
            ));
        }
        use grdr_ipc_os::transport::{Connector, FixedTimestampSource, IpcDeadline};
        use grdr_ipc_os::unix_domain::UnixDomainConnector;
        let clock = SystemClock::new();
        let now_ts = clock
            .now_wall()
            .map_err(|e| IpcServerError::Failed(e.to_string()))?;
        let probe = UnixDomainConnector.connect(
            &grdr_ipc_os::LocalEndpointAddress::UnixSocket {
                path: sock_path.to_path_buf(),
            },
            IpcDeadline::from_millis_capped(150, 250),
            &FixedTimestampSource::new(now_ts),
        );
        match probe {
            Ok(_) => {
                return Err(IpcServerError::Failed(
                    "refusing stale-socket unlink while listener is active".to_string(),
                ));
            }
            Err(grdr_ipc_os::IpcError::Unavailable(_)) => {
                std::fs::remove_file(sock_path).map_err(|err| {
                    IpcServerError::Failed(format!("remove stale socket failed: {err}"))
                })?;
            }
            Err(err) => {
                return Err(IpcServerError::Failed(format!(
                    "socket probe failed unexpectedly: {err}"
                )));
            }
        }
    }
    Ok(())
}

fn server_identity_policy(
    profile: Profile,
    service: EndpointServiceKind,
    allowed_windows_sids: Vec<String>,
) -> ServerIdentityPolicy {
    let uid = grdr_peer_os::unix_peer::current_effective_ids().map_or(u32::MAX, |ids| ids.0);
    let allowed_client_uids = match profile {
        Profile::Protected | Profile::Inherited => vec![uid, 0],
        Profile::User => vec![uid],
    };
    ServerIdentityPolicy {
        profile,
        allowed_client_uids,
        allowed_windows_sids,
        minimum_integrity_rid: 0x2000,
        reject_app_container: service != EndpointServiceKind::Decide,
        require_start_time_before_connect: true,
        require_open_as_self_pipe_check: cfg!(windows),
        require_kernel_peer_token: cfg!(unix),
    }
}
