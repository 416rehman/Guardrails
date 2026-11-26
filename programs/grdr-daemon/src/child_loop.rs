// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Child supervision loop (`grdr-engine`, `grdr-uplink`, `grdr-updater`) and CLI arg assembly.

use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};

use grdr_model::TrustedKeyInfo;
use grdr_os_clock::{Clock, SystemClock};
use grdr_os_service::ladder::{LadderAction, LadderRung};
use grdr_peer_os::fs_open::{
    OpenNofollowAccess, check_no_ancestor_symlinks, create_private_dir_all, open_nofollow_file,
    verify_open_file_trust,
};
use grdr_sandbox_engine::{ContainmentMode, SandboxSpec, prepare_contained_command};
use grdr_store_local::fs_hardening::redact_path_label;
use jiff::Timestamp;

use crate::state::{ChildSlot, DaemonState, now_wall};
use crate::supervisor::{RestartSpec, SupervisedChild, SupervisorError};

const SAFE_ENV_ALLOWLIST: &[&str] = &[
    "PATH",
    "SYSTEMROOT",
    "COMSPEC",
    "WINDIR",
    "TEMP",
    "TMP",
    "TMPDIR",
    "HOME",
    "XDG_RUNTIME_DIR",
    "RUST_LOG",
];

fn minimal_child_env() -> Vec<(String, String)> {
    SAFE_ENV_ALLOWLIST
        .iter()
        .filter_map(|&key| {
            std::env::var(key)
                .ok()
                .filter(|v| !v.is_empty())
                .map(|val| (key.to_string(), val))
        })
        .collect()
}

pub(crate) fn build_child_command(
    spec: &RestartSpec,
) -> Result<(Command, Option<String>), SupervisorError> {
    check_no_ancestor_symlinks(&spec.bin_path).map_err(|e| {
        SupervisorError::ChildError(format!(
            "unsafe child binary ancestor {}: {e}",
            redact_path_label(&spec.bin_path)
        ))
    })?;
    let bin_file = open_nofollow_file(&spec.bin_path, OpenNofollowAccess::ReadOnly, 0o600)
        .map_err(|e| {
            SupervisorError::ChildError(format!(
                "open child binary {}: {e}",
                redact_path_label(&spec.bin_path)
            ))
        })?;
    if spec.protected_profile {
        verify_open_file_trust(&bin_file, true).map_err(|e| {
            SupervisorError::ChildError(format!(
                "untrusted protected child binary {}: {e}",
                redact_path_label(&spec.bin_path)
            ))
        })?;
    }
    drop(bin_file);

    let safe_env = minimal_child_env();
    if spec.role == crate::supervisor::ChildRole::Engine {
        create_private_dir_all(&spec.work_dir).map_err(|e| {
            SupervisorError::ChildError(format!(
                "create engine workdir {}: {e}",
                redact_path_label(&spec.work_dir)
            ))
        })?;
        let prog_str = spec.bin_path.to_string_lossy().into_owned();
        let sandbox = SandboxSpec {
            session_id: "daemon-engine".to_string(),
            agent_name: "grdr-daemon".to_string(),
            mode: ContainmentMode::WorkspaceContained,
            strip_secret_env: true,
            extra_allow_env: vec!["RUST_LOG".to_string()],
            workdir: Some(spec.work_dir.clone()),
        };
        let (cmd, report) =
            prepare_contained_command(&prog_str, &spec.extra_args, &sandbox, &safe_env).map_err(
                |err| SupervisorError::ChildError(format!("sandbox prepare failed: {err}")),
            )?;
        return Ok((cmd, report.partial_reason));
    }

    let mut cmd = Command::new(&spec.bin_path);
    cmd.args(&spec.extra_args);
    cmd.env_clear();
    for (k, v) in safe_env {
        cmd.env(k, v);
    }
    Ok((cmd, None))
}

pub(crate) fn supervise_children(state: &DaemonState, clock: &SystemClock, hb_seq: u64) {
    let mono = clock
        .boot_uptime()
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    let now = now_wall();
    let now_s = now.as_second();
    let (epoch, active_digests) = state.inner.lock().map_or((1, Vec::new()), |g| {
        let digests = g
            .packs
            .iter()
            .map(|p| format!("{}:{}", p.id, p.version))
            .collect();
        (g.epoch, digests)
    });

    supervise_engine_slot(state, hb_seq, mono, epoch, now, now_s, &active_digests);
    supervise_auxiliary_slot(&state.uplink_child, hb_seq, mono, epoch, now, now_s);
    supervise_auxiliary_slot(&state.updater_child, hb_seq, mono, epoch, now, now_s);
}

fn supervise_engine_slot(
    state: &DaemonState,
    hb_seq: u64,
    mono: u64,
    epoch: u64,
    now: Timestamp,
    now_s: i64,
    active_digests: &[String],
) {
    let Ok(mut slot) = state.engine.lock() else {
        return;
    };
    let mut respawn_needed = false;
    if let Some(child) = slot.child.as_mut() {
        let healthy = child
            .heartbeat_tick(hb_seq, mono, epoch, now)
            .unwrap_or(false);
        if !healthy {
            let reason = child
                .unhealthy_reason
                .clone()
                .unwrap_or_else(|| "child-unresponsive".to_string());
            let transition = child.record_crash_event(now, active_digests);
            let fail_closed_ids = child.ladder.effective_floor().fail_closed_rule_ids.clone();
            slot.last_ladder_rung = transition.to;
            if let LadderAction::EnterSafeMode { retry_after_secs } = transition.action {
                slot.retry_not_before_s = now_s.saturating_add(retry_after_secs.max(1));
            }
            if let Ok(mut data) = state.inner.lock() {
                data.degraded_reason = reason;
                for rule_id in fail_closed_ids {
                    data.forced_deny_rule_ids.insert(rule_id);
                }
            }
            slot.child = None;
            respawn_needed = !matches!(
                transition.action,
                LadderAction::StopServiceSuppressed { .. }
            );
        }
    } else if slot.spec.is_some() && now_s >= slot.retry_not_before_s {
        respawn_needed = true;
    }

    if !respawn_needed || matches!(slot.last_ladder_rung, LadderRung::Stopped) {
        return;
    }
    let Some(spec) = slot.spec.clone() else {
        return;
    };
    drop(slot);

    let bundle_res = state.current_bundle();
    let spawn_res = SupervisedChild::spawn(&spec, now).and_then(|mut child| {
        if let Ok(ref bundle) = bundle_res {
            child.send_bundle(bundle.clone())?;
        }
        Ok(child)
    });
    if let Ok(mut slot) = state.engine.lock() {
        match spawn_res {
            Ok(child) => {
                let partial = child.sandbox_partial_reason.clone();
                slot.child = Some(child);
                slot.retry_not_before_s = 0;
                if let Ok(mut data) = state.inner.lock() {
                    data.sandbox_partial_reason = partial;
                }
            }
            Err(err) => {
                tracing::warn!(error = %err, "engine respawn attempt failed; retaining spec for backoff");
                slot.retry_not_before_s = now_s.saturating_add(2);
            }
        }
    }
}

fn supervise_auxiliary_slot(
    slot_mutex: &Arc<Mutex<ChildSlot>>,
    hb_seq: u64,
    mono: u64,
    epoch: u64,
    now: Timestamp,
    now_s: i64,
) {
    let Ok(mut slot) = slot_mutex.lock() else {
        return;
    };
    let mut respawn_needed = false;
    if let Some(child) = slot.child.as_mut() {
        if !child
            .heartbeat_tick(hb_seq, mono, epoch, now)
            .unwrap_or(false)
        {
            let transition = child.record_crash_event(now, &[]);
            slot.last_ladder_rung = transition.to;
            if let LadderAction::EnterSafeMode { retry_after_secs } = transition.action {
                slot.retry_not_before_s = now_s.saturating_add(retry_after_secs.max(1));
            }
            slot.child = None;
            respawn_needed = !matches!(
                transition.action,
                LadderAction::StopServiceSuppressed { .. }
            );
        }
    } else if slot.spec.is_some() && now_s >= slot.retry_not_before_s {
        respawn_needed = true;
    }

    if !respawn_needed || matches!(slot.last_ladder_rung, LadderRung::Stopped) {
        return;
    }
    let Some(spec) = slot.spec.clone() else {
        return;
    };
    drop(slot);
    if let Ok(child) = SupervisedChild::spawn(&spec, now)
        && let Ok(mut slot) = slot_mutex.lock()
    {
        slot.child = Some(child);
        slot.retry_not_before_s = 0;
    } else if let Ok(mut slot) = slot_mutex.lock() {
        slot.retry_not_before_s = now_s.saturating_add(2);
    }
}

pub(crate) fn kill_slot(slot_mutex: &Arc<Mutex<ChildSlot>>) {
    if let Ok(mut guard) = slot_mutex.lock()
        && let Some(mut child) = guard.child.take()
    {
        child.kill_and_wait();
    }
}

pub(crate) fn collect_pinned_keys(state: &DaemonState, cli_keys: &[String]) -> Vec<String> {
    let mut out = cli_keys.to_vec();
    if let Ok(guard) = state.inner.lock() {
        for TrustedKeyInfo {
            key_id,
            public_key_b64,
        } in &guard.trusted_keys
        {
            out.push(format!("{key_id}:{public_key_b64}"));
        }
    }
    out
}

pub(crate) fn build_uplink_args(
    state_dir: &Path,
    device_id: &str,
    server: Option<&str>,
    isolated: bool,
    deployment_id: Option<&str>,
    pinned_keys: &[String],
) -> Vec<String> {
    let staging = state_dir.join("uplink-staging");
    let mut args = vec![
        "daemon-worker".to_string(),
        "--staging-root".to_string(),
        staging.display().to_string(),
        "--device-id".to_string(),
        device_id.to_string(),
    ];
    if isolated {
        args.push("--isolated".to_string());
    }
    if let Some(dep) = deployment_id {
        args.push("--deployment-id".to_string());
        args.push(dep.to_string());
    }
    if let Some(srv) = server {
        args.push("--allow".to_string());
        args.push(srv.to_string());
    }
    for pk in pinned_keys {
        args.push("--pinned-key".to_string());
        args.push(pk.clone());
    }
    args
}

pub(crate) fn build_updater_args(state_dir: &Path, data_dir: &Path) -> Vec<String> {
    let updater_root = state_dir.join("updater-slots");
    let mut args = vec![
        "daemon-worker".to_string(),
        "--state-root".to_string(),
        updater_root.display().to_string(),
        "--authority".to_string(),
        "self".to_string(),
    ];
    let proj_root = data_dir.join("project-root.json");
    if proj_root.is_file() {
        args.push("--project-root-json".to_string());
        args.push(proj_root.display().to_string());
    }
    args
}
