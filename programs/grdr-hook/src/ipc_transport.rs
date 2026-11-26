// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Endpoint address resolution, root-down Unix path TOCTOU validation, and kernel peer claims
//! extraction for `grdr-hook`.

use std::time::{Duration, Instant};

use grdr_ipc_os::LocalEndpointAddress;
use grdr_ipc_os::proto_io::{ProtoIpcStream, ProtoTransportIo};
use grdr_os_clock::{Clock, SystemClock};
use grdr_wire::endpoint::{EndpointOverrides, PathExpectation, PlatformKind, resolve_endpoint};
use grdr_wire::frame::IpcFrameError;
use grdr_wire::messages::EndpointServiceKind;
use grdr_wire::peer_auth::{ClientIdentityPolicy, OsPeerClaims, Profile};

#[cfg(unix)]
pub(crate) type PeerHoldGuard = Option<grdr_peer_os::unix_peer::UnixPeerHold>;
#[cfg(not(unix))]
pub(crate) type PeerHoldGuard = ();

#[cfg(unix)]
pub(crate) type ScmProbeResult = Vec<Option<()>>;
#[cfg(windows)]
pub(crate) type ScmProbeResult = Vec<Option<grdr_peer_os::win_peer::ScmServiceProbe>>;

#[cfg(unix)]
pub(crate) type UnixPreFacts = Option<Vec<grdr_wire::endpoint::PathComponentFact>>;
#[cfg(not(unix))]
pub(crate) struct UnixPreFacts;

pub(crate) trait TimeoutConfigurableStream {
    fn configure_io_timeouts(
        &mut self,
        read: Duration,
        write: Duration,
    ) -> Result<(), IpcFrameError>;
}

impl<L: ProtoTransportIo> TimeoutConfigurableStream for ProtoIpcStream<L> {
    fn configure_io_timeouts(
        &mut self,
        read: Duration,
        write: Duration,
    ) -> Result<(), IpcFrameError> {
        self.set_timeouts(read, write)
    }
}

pub(crate) fn remaining_dur(deadline: Instant) -> Option<Duration> {
    let rem = deadline.checked_duration_since(Instant::now())?;
    if rem.is_zero() {
        None
    } else {
        Some(rem.max(Duration::from_millis(1)))
    }
}

pub(crate) fn resolve_decide_address(
    profile: Profile,
    socket_override: Option<&str>,
) -> Result<LocalEndpointAddress, String> {
    let mut overrides = EndpointOverrides {
        home_dir: std::env::var_os("HOME").map(std::path::PathBuf::from),
        xdg_runtime_dir: std::env::var_os("XDG_RUNTIME_DIR").map(std::path::PathBuf::from),
        local_app_data: std::env::var_os("LOCALAPPDATA").map(std::path::PathBuf::from),
        #[cfg(windows)]
        windows_user_sid: (profile != Profile::Protected)
            .then(|| grdr_peer_os::win_peer::current_process_sid().ok())
            .flatten(),
        ..EndpointOverrides::default()
    };

    if profile != Profile::Protected {
        let raw_override = socket_override.map(str::to_string).or_else(|| {
            std::env::var("GRDR_DECIDE_ENDPOINT")
                .ok()
                .filter(|v| !v.trim().is_empty())
        });
        if let Some(raw) = raw_override {
            if cfg!(windows) {
                overrides.env_override_pipe_name = Some(raw);
            } else {
                overrides.env_override_unix_path = Some(std::path::PathBuf::from(raw));
            }
        }
    }

    let resolved = resolve_endpoint(
        EndpointServiceKind::Decide,
        profile,
        &overrides,
        current_platform(),
    )
    .map_err(|err| format!("endpoint-resolve: {err}"))?;
    to_local_address(&resolved)
}

#[cfg(unix)]
pub(crate) fn verify_unix_server_path_pre(
    addr: &LocalEndpointAddress,
) -> Result<UnixPreFacts, (bool, String)> {
    let LocalEndpointAddress::UnixSocket { path } = addr else {
        return Ok(None);
    };
    if let Err(err) = std::fs::symlink_metadata(path)
        && err.kind() == std::io::ErrorKind::NotFound
    {
        return Err((true, "daemon-socket-missing".to_string()));
    }
    let facts = grdr_peer_os::unix_peer::inspect_unix_path_live(path)
        .map_err(|e| (false, e.to_string()))?;
    Ok(Some(facts))
}

#[cfg(not(unix))]
pub(crate) fn verify_unix_server_path_pre(
    _addr: &LocalEndpointAddress,
) -> Result<UnixPreFacts, (bool, String)> {
    let _ = PathExpectation {
        profile: Profile::User,
        trusted_owner_uids: vec![],
        trusted_group_gids: vec![],
        allow_world_writable_socket_leaf: false,
    };
    Ok(UnixPreFacts)
}

#[cfg(unix)]
pub(crate) fn verify_unix_server_path_post(
    addr: &LocalEndpointAddress,
    profile: Profile,
    pre: UnixPreFacts,
) -> Result<(), String> {
    let LocalEndpointAddress::UnixSocket { path } = addr else {
        return Ok(());
    };
    let mut facts = pre.ok_or_else(|| "missing unix pre-connect path facts".to_string())?;
    grdr_peer_os::unix_peer::refresh_unix_path_post_connect(&mut facts, path)
        .map_err(|e| e.to_string())?;
    grdr_wire::endpoint::check_path(
        &facts,
        &PathExpectation {
            profile,
            trusted_owner_uids: vec![0, current_uid()],
            trusted_group_gids: vec![0, current_gid()],
            allow_world_writable_socket_leaf: profile == Profile::Protected,
        },
    )
    .map_err(|e| e.to_string())
}

#[cfg(not(unix))]
pub(crate) fn verify_unix_server_path_post(
    _addr: &LocalEndpointAddress,
    _profile: Profile,
    _pre: UnixPreFacts,
) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
pub(crate) fn probe_guardrails_scm() -> ScmProbeResult {
    Vec::new()
}

#[cfg(windows)]
pub(crate) fn probe_guardrails_scm() -> ScmProbeResult {
    grdr_peer_os::win_peer::probe_scm_services(&["Guardrails", "GuardrailsHandover"])
}

#[cfg(unix)]
pub(crate) fn extract_server_claims(
    link: &grdr_ipc_os::unix_domain::UnixDomainLink,
    _profile: Profile,
    _pre_scm: &ScmProbeResult,
) -> Result<(OsPeerClaims, u64, PeerHoldGuard), String> {
    let clock = SystemClock::new();
    let stamp = grdr_peer_os::unix_peer::UnixConnectStamp {
        boot_uptime_ms: boot_mono_ms(&clock),
        wall_unix_us: clock
            .now_wall()
            .ok()
            .and_then(|t| u64::try_from(t.as_microsecond()).ok())
            .unwrap_or(0),
    };
    let hold = grdr_peer_os::unix_peer::read_unix_socket_peer(link.borrowed_fd(), stamp)
        .map_err(|e| e.to_string())?;
    let claims = hold.claims.clone();
    Ok((OsPeerClaims::Unix(claims), stamp.for_platform(), Some(hold)))
}

#[cfg(windows)]
pub(crate) fn extract_server_claims(
    link: &grdr_ipc_os::windows_pipe::WindowsNamedPipeLink,
    profile: Profile,
    pre_scm: &ScmProbeResult,
) -> Result<(OsPeerClaims, u64, PeerHoldGuard), String> {
    let connected_at = grdr_peer_os::win_peer::current_filetime_100ns();
    let claims = grdr_peer_os::win_peer::read_windows_pipe_server(
        link.borrowed_handle(),
        profile,
        &["Guardrails", "GuardrailsHandover"],
        pre_scm,
    )
    .map_err(|e| e.to_string())?;
    Ok((OsPeerClaims::Windows(claims), connected_at, ()))
}

pub(crate) fn client_identity_policy(profile: Profile) -> Result<ClientIdentityPolicy, String> {
    #[cfg(windows)]
    let expected_windows_sids = if profile == Profile::Protected {
        vec![
            "S-1-5-18".to_string(),
            "S-1-5-19".to_string(),
            "S-1-5-20".to_string(),
        ]
    } else {
        vec![grdr_peer_os::win_peer::current_process_sid().map_err(|e| e.to_string())?]
    };
    #[cfg(not(windows))]
    let expected_windows_sids = Vec::new();

    Ok(ClientIdentityPolicy {
        profile,
        allowed_server_uids: if profile == Profile::Protected {
            vec![0]
        } else {
            vec![current_uid(), 0]
        },
        expected_windows_sids,
        minimum_integrity_rid: if profile == Profile::Protected {
            0x3000
        } else {
            0x2000
        },
        require_start_time_before_connect: true,
        require_kernel_peer_token: true,
    })
}

pub(crate) fn boot_mono_ms(clock: &SystemClock) -> u64 {
    clock
        .boot_uptime()
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn current_platform() -> PlatformKind {
    if cfg!(windows) {
        PlatformKind::Windows
    } else if cfg!(target_os = "macos") {
        PlatformKind::MacOs
    } else {
        PlatformKind::Linux
    }
}

fn to_local_address(
    resolved: &grdr_wire::endpoint::ResolvedEndpoint,
) -> Result<LocalEndpointAddress, String> {
    if let Some(ref p) = resolved.unix_path {
        return Ok(LocalEndpointAddress::UnixSocket { path: p.clone() });
    }
    if let Some(ref pipe) = resolved.pipe_name {
        return Ok(LocalEndpointAddress::WindowsPipe {
            pipe_name: pipe.clone(),
        });
    }
    Err("resolved endpoint has neither unix_path nor pipe_name".to_string())
}

fn current_uid() -> u32 {
    grdr_peer_os::unix_peer::current_effective_ids().map_or(u32::MAX, |ids| ids.0)
}

#[cfg(unix)]
fn current_gid() -> u32 {
    grdr_peer_os::unix_peer::current_effective_ids().map_or(u32::MAX, |ids| ids.1)
}
