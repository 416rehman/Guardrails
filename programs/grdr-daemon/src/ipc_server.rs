// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! OS-peer-authenticated local IPC listener lifecycle for `grdr-daemon` (`decide` and `local`
//! endpoints) with worker-offloaded handshakes so stalling clients cannot DoS the accept loop.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use grdr_ipc_os::Acceptor;
use grdr_wire::endpoint::{EndpointOverrides, PlatformKind, ResolvedEndpoint, resolve_endpoint};
use grdr_wire::messages::EndpointServiceKind;
use grdr_wire::peer_auth::Profile;

use crate::local_dispatch::handle_authenticated_client;
use crate::peer_transport::{
    AuthContext, PlatformChannelStream, authenticate_accepted_stream, bind_platform_endpoint,
};
pub use crate::peer_transport::{BoundEndpoint, IpcServerError};
use crate::state::DaemonState;

const ACCEPT_SLICE: Duration = Duration::from_millis(250);
const MAX_CONCURRENT_IPC_CLIENTS: usize = 32;

#[derive(Debug, Clone)]
pub struct ListenerConfig {
    pub service: EndpointServiceKind,
    pub profile: Profile,
    pub endpoint_override: Option<String>,
}

struct ActiveWorkerPermit(Arc<AtomicUsize>);

impl Drop for ActiveWorkerPermit {
    fn drop(&mut self) {
        let _ = self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

pub fn bind_endpoint(config: &ListenerConfig) -> Result<BoundEndpoint, IpcServerError> {
    let resolved = resolve_service_endpoint(config)?;
    bind_platform_endpoint(config.service, config.profile, &resolved)
}

pub fn serve_bound_until(
    mut bound: BoundEndpoint,
    state: DaemonState,
    stop: Arc<AtomicBool>,
) -> Result<(), IpcServerError> {
    let active_workers = Arc::new(AtomicUsize::new(0));
    let res = serve_platform_loop(&mut bound, &state, &stop, &active_workers);
    stop.store(true, Ordering::SeqCst);
    res
}

fn resolve_service_endpoint(config: &ListenerConfig) -> Result<ResolvedEndpoint, IpcServerError> {
    if config.profile == Profile::Protected && config.endpoint_override.is_some() {
        return Err(IpcServerError::Failed(
            "Protected profile prohibits explicit endpoint overrides".to_string(),
        ));
    }

    let mut overrides = EndpointOverrides {
        home_dir: std::env::var_os("HOME").map(std::path::PathBuf::from),
        xdg_runtime_dir: std::env::var_os("XDG_RUNTIME_DIR").map(std::path::PathBuf::from),
        local_app_data: std::env::var_os("LOCALAPPDATA").map(std::path::PathBuf::from),
        #[cfg(windows)]
        windows_user_sid: (config.profile != Profile::Protected)
            .then(|| grdr_peer_os::win_peer::current_process_sid().ok())
            .flatten(),
        ..EndpointOverrides::default()
    };

    if config.profile != Profile::Protected {
        let env_key = match config.service {
            EndpointServiceKind::Decide => Some("GRDR_DECIDE_ENDPOINT"),
            EndpointServiceKind::Local => Some("GRDR_LOCAL_ENDPOINT"),
            _ => None,
        };
        let raw_override = config.endpoint_override.clone().or_else(|| {
            env_key
                .and_then(|k| std::env::var(k).ok())
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

    let platform = if cfg!(windows) {
        PlatformKind::Windows
    } else if cfg!(target_os = "macos") {
        PlatformKind::MacOs
    } else {
        PlatformKind::Linux
    };

    resolve_endpoint(config.service, config.profile, &overrides, platform)
        .map_err(|err| IpcServerError::Failed(format!("resolve endpoint: {err}")))
}

#[cfg(windows)]
fn serve_platform_loop(
    bound: &mut BoundEndpoint,
    state: &DaemonState,
    stop: &Arc<AtomicBool>,
    active_workers: &Arc<AtomicUsize>,
) -> Result<(), IpcServerError> {
    let auth = Arc::new(bound.auth.clone());
    let mut workers: Vec<JoinHandle<()>> = Vec::new();
    while !stop.load(Ordering::SeqCst) && !grdr_os_service::unix_control::shutdown_requested() {
        reap_finished_workers(&mut workers);
        let stream = match bound.acceptor.accept(ACCEPT_SLICE) {
            Ok(s) => s,
            Err(grdr_ipc_os::IpcError::DeadlineExceeded { .. }) => continue,
            Err(grdr_ipc_os::IpcError::Stopped) => break,
            Err(err) => {
                tracing::warn!(error = %err, "pipe accept error on `{}`", bound.endpoint_label);
                continue;
            }
        };

        let Some(permit) = try_acquire_worker_permit(active_workers) else {
            state.record_ipc_drop();
            tracing::warn!("IPC concurrency cap reached; dropping incoming client");
            continue;
        };
        let auth_ref = Arc::clone(&auth);
        let st = state.clone();
        let stop_ref = Arc::clone(stop);
        let (digest, epoch) = floor_snapshot(state);
        if let Ok(handle) = std::thread::Builder::new()
            .name(format!("ipc-{:?}", auth.service))
            .spawn(move || {
                let _permit = permit;
                match authenticate_accepted_stream(stream, &auth_ref, &digest, epoch) {
                    Ok(chan) => handle_authenticated_client(chan, auth_ref.service, &st, &stop_ref),
                    Err(reason) => tracing::warn!("{reason}"),
                }
            })
        {
            workers.push(handle);
        }
    }
    bound.acceptor.stop();
    join_all_workers(workers);
    Ok(())
}

#[cfg(unix)]
fn serve_platform_loop(
    bound: &mut BoundEndpoint,
    state: &DaemonState,
    stop: &Arc<AtomicBool>,
    active_workers: &Arc<AtomicUsize>,
) -> Result<(), IpcServerError> {
    use grdr_ipc_os::transport::{FixedTimestampSource, IpcDeadline};
    use grdr_os_clock::{Clock, SystemClock};
    use std::os::unix::fs::FileTypeExt as _;

    let clock = SystemClock::new();
    let cap_ms = u64::try_from(ACCEPT_SLICE.as_millis()).unwrap_or(250);
    let auth = Arc::new(bound.auth.clone());
    let mut workers: Vec<JoinHandle<()>> = Vec::new();
    while !stop.load(Ordering::SeqCst) && !grdr_os_service::unix_control::shutdown_requested() {
        reap_finished_workers(&mut workers);
        let Ok(now_ts) = clock.now_wall() else {
            return Err(IpcServerError::Failed(
                "system wall clock unavailable during accept loop".to_string(),
            ));
        };
        let link = match bound.acceptor.accept(
            IpcDeadline::from_millis_capped(cap_ms, 2_000),
            &FixedTimestampSource::new(now_ts),
        ) {
            Ok(l) => l,
            Err(grdr_ipc_os::IpcError::DeadlineExceeded { .. }) => continue,
            Err(grdr_ipc_os::IpcError::Stopped) => break,
            Err(err) => {
                tracing::warn!(error = %err, "unix accept error on `{}`", bound.endpoint_label);
                continue;
            }
        };

        let Some(permit) = try_acquire_worker_permit(active_workers) else {
            state.record_ipc_drop();
            tracing::warn!("IPC concurrency cap reached; dropping incoming client");
            continue;
        };
        let auth_ref = Arc::clone(&auth);
        let st = state.clone();
        let stop_ref = Arc::clone(stop);
        let (digest, epoch) = floor_snapshot(state);
        if let Ok(handle) = std::thread::Builder::new()
            .name(format!("ipc-{:?}", auth.service))
            .spawn(move || {
                let _permit = permit;
                match authenticate_accepted_stream(link, &auth_ref, &digest, epoch) {
                    Ok(chan) => handle_authenticated_client(chan, auth_ref.service, &st, &stop_ref),
                    Err(reason) => tracing::warn!("{reason}"),
                }
            })
        {
            workers.push(handle);
        }
    }
    bound.acceptor.stop();
    join_all_workers(workers);
    if !bound.adopted_from_launchd
        && let Ok(meta) = std::fs::symlink_metadata(&bound.sock_path)
        && !meta.file_type().is_symlink()
        && meta.file_type().is_socket()
        && let Err(err) = std::fs::remove_file(&bound.sock_path)
    {
        tracing::warn!(error = %err, "failed removing unix socket on shutdown");
    }
    Ok(())
}

fn reap_finished_workers(workers: &mut Vec<JoinHandle<()>>) {
    let mut idx = 0usize;
    while idx < workers.len() {
        let finished = workers.get(idx).is_some_and(JoinHandle::is_finished);
        if finished {
            let handle = workers.swap_remove(idx);
            if handle.join().is_err() {
                tracing::warn!("IPC worker thread panicked");
            }
        } else {
            idx = idx.saturating_add(1);
        }
    }
}

fn join_all_workers(workers: Vec<JoinHandle<()>>) {
    for handle in workers {
        if handle.join().is_err() {
            tracing::warn!("IPC worker thread panicked during shutdown");
        }
    }
}

fn try_acquire_worker_permit(counter: &Arc<AtomicUsize>) -> Option<ActiveWorkerPermit> {
    let mut current = counter.load(Ordering::Acquire);
    loop {
        if current >= MAX_CONCURRENT_IPC_CLIENTS {
            return None;
        }
        match counter.compare_exchange(
            current,
            current.saturating_add(1),
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Some(ActiveWorkerPermit(Arc::clone(counter))),
            Err(observed) => current = observed,
        }
    }
}

fn floor_snapshot(state: &DaemonState) -> (String, u64) {
    let Ok(guard) = state.inner.lock() else {
        return (String::new(), 1);
    };
    (guard.floor.digest_hex.clone(), guard.epoch)
}

pub(crate) fn _check_auth_types(
    _ctx: &AuthContext,
    _chan: &grdr_wire::peer_auth::AuthenticatedChannel<PlatformChannelStream>,
) {
}
