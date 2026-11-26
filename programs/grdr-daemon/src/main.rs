// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Privileged Guardrails ADR daemon (`grdr-daemon`): OS peer-authenticated IPC listeners,
//! inherited child supervision (`grdr-engine`/`grdr-uplink`/`grdr-updater`), key/spool/recorder
//! ownership, and signed binary floor cache (`docs/design/11`). Zero HTTP/TCP listeners.

mod child_loop;
mod dir_guard;
mod floor_compiler;
mod grant_ops;
mod ipc_server;
mod ladder_codec;
mod local_dispatch;
mod peer_transport;
mod receipt_audit;
mod self_test;
mod state;
mod supervisor;
mod uplink;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use clap::{Parser, ValueEnum};
use grdr_model::InstallProfile;
use grdr_os_clock::SystemClock;
use grdr_os_service::unix_control::{
    install_signal_handlers, send_systemd_notify, shutdown_requested, take_reload_requested,
};
use grdr_os_service::win_scm::{ScmState, register_scm_handler, report_scm_state};
use grdr_wire::messages::EndpointServiceKind;
use grdr_wire::peer_auth::Profile;
use thiserror::Error;

use crate::child_loop::{
    build_updater_args, build_uplink_args, collect_pinned_keys, kill_slot, supervise_children,
};
use crate::ipc_server::{ListenerConfig, bind_endpoint, serve_bound_until};
use crate::self_test::{run_ephemeral_self_test, run_readonly_self_test};
use crate::state::{DaemonState, now_wall};
use crate::supervisor::{ChildRole, RestartSpec, SupervisedChild};

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum DaemonError {
    #[error("GRDR-DAEM-0001: daemon initialization failed: {0}")]
    InitFailed(String),
    #[error("GRDR-DAEM-0002: daemon supervision loop error: {0}")]
    RuntimeFailed(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum CliProfile {
    Protected,
    User,
}

#[derive(Debug, Parser)]
#[command(
    name = "grdr-daemon",
    about = "Guardrails ADR privileged endpoint daemon"
)]
struct Args {
    #[arg(long, value_enum, default_value = "user")]
    profile: CliProfile,
    #[arg(long)]
    data_dir: Option<PathBuf>,
    #[arg(long)]
    state_dir: Option<PathBuf>,
    #[arg(long)]
    decide_endpoint: Option<String>,
    #[arg(long)]
    local_endpoint: Option<String>,
    #[arg(long)]
    engine_bin: Option<PathBuf>,
    #[arg(long)]
    uplink_bin: Option<PathBuf>,
    #[arg(long)]
    updater_bin: Option<PathBuf>,
    #[arg(long)]
    server: Option<String>,
    #[arg(long)]
    isolated: bool,
    #[arg(long)]
    deployment_id: Option<String>,
    #[arg(long)]
    pinned_key: Vec<String>,
    #[arg(long)]
    self_test: bool,
}

fn main() -> ExitCode {
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_target(false)
        .try_init();
    let args = Args::parse();

    let res = if args.self_test {
        run_self_test(&args)
    } else {
        run_daemon(&args)
    };
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}

fn run_self_test(args: &Args) -> Result<(), DaemonError> {
    if args.profile == CliProfile::Protected {
        return Err(DaemonError::InitFailed(
            "Protected profile prohibits --self-test".to_string(),
        ));
    }
    if let Some(ref existing_data) = args.data_dir {
        let state_dir = args
            .state_dir
            .clone()
            .unwrap_or_else(|| existing_data.join("state"));
        return run_readonly_self_test(existing_data, &state_dir);
    }
    run_ephemeral_self_test(args.state_dir.as_deref())
}

fn run_daemon(args: &Args) -> Result<(), DaemonError> {
    install_signal_handlers().map_err(|e| DaemonError::InitFailed(e.to_string()))?;
    if let Err(err) = register_scm_handler("Guardrails") {
        tracing::debug!(error = %err, "SCM handler registration skipped");
    }
    if let Err(err) = report_scm_state(ScmState::StartPending, 0) {
        tracing::debug!(error = %err, "SCM start-pending report skipped");
    }

    let (install_profile, profile) = match args.profile {
        CliProfile::Protected => (InstallProfile::Protected, Profile::Protected),
        CliProfile::User => (InstallProfile::User, Profile::User),
    };
    if profile == Profile::Protected
        && (args.decide_endpoint.is_some()
            || args.local_endpoint.is_some()
            || args.data_dir.is_some()
            || args.state_dir.is_some()
            || args.engine_bin.is_some()
            || args.uplink_bin.is_some()
            || args.updater_bin.is_some()
            || args.server.is_some())
    {
        return Err(DaemonError::InitFailed(
            "Protected profile prohibits CLI directory, binary, server, or endpoint overrides"
                .to_string(),
        ));
    }

    let data_dir = args
        .data_dir
        .clone()
        .unwrap_or_else(|| default_data_dir(profile));
    let state_dir = args
        .state_dir
        .clone()
        .unwrap_or_else(|| data_dir.join("state"));
    let state = DaemonState::initialize(data_dir.clone(), state_dir.clone(), install_profile)
        .map_err(DaemonError::InitFailed)?;
    let is_protected = profile == Profile::Protected;
    let device_id = state.device_id();

    if let Some(ref engine_path) = args.engine_bin {
        let spec = RestartSpec {
            role: ChildRole::Engine,
            bin_path: engine_path.clone(),
            extra_args: vec!["--device-id".to_string(), device_id.clone()],
            work_dir: state_dir.join("engine-work"),
            ladder_path: data_dir.join("engine-ladder.bin"),
            protected_profile: is_protected,
        };
        let mut child = SupervisedChild::spawn(&spec, now_wall())
            .map_err(|e| DaemonError::InitFailed(e.to_string()))?;
        let partial = child.sandbox_partial_reason.clone();
        let bundle = state.current_bundle().map_err(DaemonError::InitFailed)?;
        child
            .send_bundle(bundle)
            .map_err(|e| DaemonError::InitFailed(e.to_string()))?;
        if let Ok(mut guard) = state.inner.lock() {
            guard.sandbox_partial_reason = partial;
        }
        if let Ok(mut slot) = state.engine.lock() {
            slot.spec = Some(spec);
            slot.last_ladder_rung = child.ladder.rung();
            slot.child = Some(child);
        }
    }

    if let Some(ref uplink_path) = args.uplink_bin {
        let pinned_keys = collect_pinned_keys(&state, &args.pinned_key);
        let uplink_args = build_uplink_args(
            &state_dir,
            &device_id,
            args.server.as_deref(),
            args.isolated,
            args.deployment_id.as_deref(),
            &pinned_keys,
        );
        let spec = RestartSpec {
            role: ChildRole::Uplink,
            bin_path: uplink_path.clone(),
            extra_args: uplink_args,
            work_dir: state_dir.clone(),
            ladder_path: data_dir.join("uplink-ladder.bin"),
            protected_profile: is_protected,
        };
        let child = SupervisedChild::spawn(&spec, now_wall())
            .map_err(|e| DaemonError::InitFailed(e.to_string()))?;
        if let Ok(mut slot) = state.uplink_child.lock() {
            slot.spec = Some(spec);
            slot.last_ladder_rung = child.ladder.rung();
            slot.child = Some(child);
        }
    }

    if let Some(ref updater_path) = args.updater_bin {
        let spec = RestartSpec {
            role: ChildRole::Updater,
            bin_path: updater_path.clone(),
            extra_args: build_updater_args(&state_dir, &data_dir),
            work_dir: state_dir.clone(),
            ladder_path: data_dir.join("updater-ladder.bin"),
            protected_profile: is_protected,
        };
        let child = SupervisedChild::spawn(&spec, now_wall())
            .map_err(|e| DaemonError::InitFailed(e.to_string()))?;
        if let Ok(mut slot) = state.updater_child.lock() {
            slot.spec = Some(spec);
            slot.last_ladder_rung = child.ladder.rung();
            slot.child = Some(child);
        }
    }

    // Bind endpoints once child pipelines are live and immediately enter accept threads before READY=1.
    let decide_bound = bind_endpoint(&ListenerConfig {
        service: EndpointServiceKind::Decide,
        profile,
        endpoint_override: args.decide_endpoint.clone(),
    })
    .map_err(|e| DaemonError::InitFailed(e.to_string()))?;
    let local_bound = bind_endpoint(&ListenerConfig {
        service: EndpointServiceKind::Local,
        profile,
        endpoint_override: args.local_endpoint.clone(),
    })
    .map_err(|e| DaemonError::InitFailed(e.to_string()))?;

    let stop = Arc::new(AtomicBool::new(false));
    let d_state = state.clone();
    let d_stop = Arc::clone(&stop);
    let decide_thread =
        std::thread::spawn(move || serve_bound_until(decide_bound, d_state, d_stop));
    let l_state = state.clone();
    let l_stop = Arc::clone(&stop);
    let local_thread = std::thread::spawn(move || serve_bound_until(local_bound, l_state, l_stop));

    notify_systemd_msg("READY=1\n")?;
    if let Err(err) = report_scm_state(ScmState::Running, 0) {
        tracing::debug!(error = %err, "SCM running report skipped");
    }

    let clock = SystemClock::new();
    let mut hb_seq = 1u64;
    let mut loop_err: Option<DaemonError> = None;
    while !shutdown_requested() && !stop.load(Ordering::SeqCst) {
        if decide_thread.is_finished() || local_thread.is_finished() {
            stop.store(true, Ordering::SeqCst);
            loop_err = Some(DaemonError::RuntimeFailed(
                "IPC listener thread exited unexpectedly".to_string(),
            ));
            break;
        }
        if take_reload_requested() {
            if let Err(err) = notify_systemd_msg("RELOADING=1\n") {
                tracing::warn!(error = %err, "systemd RELOADING notify failed");
            }
            if let Err(err) = state.recompile_floor(None) {
                tracing::warn!(error = %err, "SIGHUP floor recompile failed");
            }
            if let Err(err) = notify_systemd_msg("READY=1\n") {
                tracing::warn!(error = %err, "systemd READY notify failed");
            }
        }
        supervise_children(&state, &clock, hb_seq);
        hb_seq = hb_seq.saturating_add(1);
        std::thread::sleep(Duration::from_secs(1));
    }

    stop.store(true, Ordering::SeqCst);
    if let Err(err) = report_scm_state(ScmState::StopPending, 0) {
        tracing::debug!(error = %err, "SCM stop-pending report skipped");
    }
    kill_slot(&state.engine);
    kill_slot(&state.uplink_child);
    kill_slot(&state.updater_child);
    let d_res = decide_thread
        .join()
        .map_err(|_| DaemonError::RuntimeFailed("decide listener panicked".to_string()))?;
    let l_res = local_thread
        .join()
        .map_err(|_| DaemonError::RuntimeFailed("local listener panicked".to_string()))?;
    d_res.map_err(|e| DaemonError::RuntimeFailed(e.to_string()))?;
    l_res.map_err(|e| DaemonError::RuntimeFailed(e.to_string()))?;
    if let Err(err) = report_scm_state(ScmState::Stopped, 0) {
        tracing::debug!(error = %err, "SCM stopped report skipped");
    }
    if let Some(err) = loop_err {
        return Err(err);
    }
    Ok(())
}

fn notify_systemd_msg(msg: &str) -> Result<(), DaemonError> {
    if let Ok(notify_sock) = std::env::var("NOTIFY_SOCKET")
        && !notify_sock.trim().is_empty()
    {
        send_systemd_notify(&notify_sock, msg)
            .map_err(|e| DaemonError::RuntimeFailed(format!("systemd notify: {e}")))?;
    }
    Ok(())
}

fn default_data_dir(profile: Profile) -> PathBuf {
    if profile != Profile::Protected
        && let Ok(d) = std::env::var("GRDR_STATE_DIR")
        && !d.trim().is_empty()
    {
        return PathBuf::from(d);
    }
    #[cfg(windows)]
    {
        if profile != Profile::Protected
            && let Ok(local) = std::env::var("LOCALAPPDATA")
            && !local.trim().is_empty()
        {
            return PathBuf::from(local).join("Guardrails").join("data");
        }
        if profile != Profile::Protected
            && let Ok(program_data) = std::env::var("ProgramData")
            && !program_data.trim().is_empty()
        {
            return PathBuf::from(program_data).join("Guardrails").join("data");
        }
        PathBuf::from(r"C:\ProgramData\Guardrails\data")
    }
    #[cfg(not(windows))]
    {
        if profile != Profile::Protected
            && let Ok(home) = std::env::var("HOME")
            && !home.trim().is_empty()
        {
            return PathBuf::from(home).join(".local/state/guardrails/data");
        }
        PathBuf::from("/var/lib/guardrails")
    }
}
