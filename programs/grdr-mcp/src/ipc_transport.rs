// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::path::PathBuf;
use std::time::{Duration, Instant};

use grdr_ipc_os::LocalEndpointAddress;
use grdr_ipc_os::proto_io::{ProtoIpcStream, ProtoTransportIo};
use grdr_os_clock::{Clock, SystemClock};
#[cfg(unix)]
use grdr_wire::endpoint::PathExpectation;
use grdr_wire::endpoint::{EndpointOverrides, PlatformKind, resolve_endpoint};
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

pub(crate) enum RoundError {
    Unreachable(String),
    FailClosed(String),
}

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
    let now = Instant::now();
    (deadline > now).then(|| deadline.duration_since(now))
}

pub(crate) fn resolve_service_address(
    service: EndpointServiceKind,
    profile: Profile,
    endpoint_override: Option<&str>,
) -> Result<LocalEndpointAddress, String> {
    let mut overrides = EndpointOverrides {
        home_dir: std::env::var_os("HOME").map(PathBuf::from),
        xdg_runtime_dir: std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from),
        local_app_data: std::env::var_os("LOCALAPPDATA").map(PathBuf::from),
        #[cfg(windows)]
        windows_user_sid: (profile != Profile::Protected)
            .then(|| grdr_peer_os::win_peer::current_process_sid().ok())
            .flatten(),
        ..EndpointOverrides::default()
    };

    let env_name = match service {
        EndpointServiceKind::Local => "GRDR_LOCAL_ENDPOINT",
        _ => "GRDR_DECIDE_ENDPOINT",
    };
    let raw_override = endpoint_override
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| {
            std::env::var(env_name)
                .ok()
                .filter(|v| !v.trim().is_empty())
        });
    if let Some(raw) = raw_override {
        if profile == Profile::Protected {
            return Err("endpoint overrides prohibited in Protected profile".to_string());
        }
        if cfg!(windows) {
            overrides.env_override_pipe_name = Some(raw);
        } else {
            overrides.env_override_unix_path = Some(PathBuf::from(raw));
        }
    }

    let resolved = resolve_endpoint(service, profile, &overrides, current_platform())
        .map_err(|e| e.to_string())?;
    resolved_to_address(&resolved)
}

#[cfg(unix)]
pub(crate) fn verify_unix_server_path_pre(
    addr: &LocalEndpointAddress,
) -> Result<UnixPreFacts, RoundError> {
    let LocalEndpointAddress::UnixSocket { path } = addr else {
        return Ok(None);
    };
    match std::fs::symlink_metadata(path) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(RoundError::Unreachable(format!(
                "daemon socket missing: {err}"
            )));
        }
        Err(err) => {
            return Err(RoundError::FailClosed(format!(
                "inspect unix socket metadata: {err}"
            )));
        }
        Ok(_) => {}
    }
    let facts = grdr_peer_os::unix_peer::inspect_unix_path_live(path)
        .map_err(|e| RoundError::FailClosed(e.to_string()))?;
    Ok(Some(facts))
}

#[cfg(not(unix))]
pub(crate) fn verify_unix_server_path_pre(
    _addr: &LocalEndpointAddress,
) -> Result<UnixPreFacts, RoundError> {
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

#[cfg(windows)]
pub(crate) fn probe_guardrails_scm() -> ScmProbeResult {
    grdr_peer_os::win_peer::probe_scm_services(&["Guardrails", "GuardrailsHandover"])
}

#[cfg(not(windows))]
pub(crate) fn probe_guardrails_scm() -> ScmProbeResult {
    Vec::new()
}

#[cfg(unix)]
pub(crate) fn extract_server_claims(
    link: &grdr_ipc_os::unix_domain::UnixDomainLink,
    _profile: Profile,
    _pre_scm: &ScmProbeResult,
) -> Result<(OsPeerClaims, u64, PeerHoldGuard), String> {
    let clock = SystemClock::new();
    let boot_uptime_ms = boot_mono_ms(&clock)?;
    let wall_now = clock
        .now_wall()
        .map_err(|e| format!("wall clock unavailable: {e}"))?;
    let wall_unix_us = u64::try_from(wall_now.as_microsecond())
        .map_err(|_| "negative wall clock timestamp".to_string())?;
    let stamp = grdr_peer_os::unix_peer::UnixConnectStamp {
        boot_uptime_ms,
        wall_unix_us,
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

pub(crate) fn boot_mono_ms(clock: &SystemClock) -> Result<u64, String> {
    let up = clock
        .boot_uptime()
        .map_err(|e| format!("boot clock unavailable: {e}"))?;
    u64::try_from(up.as_millis()).map_err(|_| "boot uptime overflow".to_string())
}

pub(crate) fn default_state_dir(protected: bool) -> PathBuf {
    if protected {
        return system_state_dir();
    }
    #[cfg(windows)]
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        return PathBuf::from(local).join("Guardrails").join("state");
    }
    if let Some(xdg) = std::env::var_os("XDG_STATE_HOME") {
        return PathBuf::from(xdg).join("guardrails");
    }
    if let Some(rt) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(rt).join("guardrails");
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home)
            .join(".local")
            .join("state")
            .join("guardrails");
    }
    system_state_dir()
}

pub(crate) fn system_state_dir() -> PathBuf {
    #[cfg(windows)]
    {
        PathBuf::from(
            std::env::var_os("ProgramData")
                .unwrap_or_else(|| std::ffi::OsString::from("C:\\ProgramData")),
        )
        .join("Guardrails")
        .join("state")
    }
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Application Support/grdr/state")
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        PathBuf::from("/var/lib/guardrails")
    }
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

fn resolved_to_address(
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

#[cfg(unix)]
fn current_uid() -> u32 {
    grdr_peer_os::unix_peer::current_effective_ids().map_or(u32::MAX, |ids| ids.0)
}

#[cfg(not(unix))]
fn current_uid() -> u32 {
    0
}

#[cfg(unix)]
fn current_gid() -> u32 {
    grdr_peer_os::unix_peer::current_effective_ids().map_or(u32::MAX, |ids| ids.1)
}
