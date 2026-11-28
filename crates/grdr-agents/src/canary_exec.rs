// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Live hook binary canary execution probe (`docs/design/07`).

use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use grdr_ports::{LocalFsPort, RegularEntryKind};

use crate::canary::{CanaryStatus, HookCanaryReport, HookHealthState};
use crate::catalogue::AgentManifest;

const CANARY_EXEC_TIMEOUT_MS: u64 = 2_000;
const CANARY_STDOUT_MAX_BYTES: usize = 64 * 1024;
#[cfg(windows)]
const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;

pub(crate) fn execute_live_canary_probe(
    manifest: &AgentManifest,
    hook_command: &str,
    probe_json: &str,
    attempt_summary: &str,
    fs: &dyn LocalFsPort,
) -> HookCanaryReport {
    let canonical = match verify_trusted_hook_binary(manifest, Path::new(hook_command), fs) {
        Ok(path) => path,
        Err(report) => return report,
    };

    let mut cmd = Command::new(&canonical);
    cmd.env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    configure_process_group(&mut cmd);

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(err) => {
            return canary_err(
                &manifest.id,
                HookHealthState::CanaryFailed,
                CanaryStatus::ProbeRejected,
                format!("failed spawning hook binary: {err}"),
            );
        }
    };

    let stdout_rx = child.stdout.take().map(|mut stdout| {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut buf = Vec::new();
            let cap = u64::try_from(CANARY_STDOUT_MAX_BYTES)
                .unwrap_or(u64::MAX)
                .saturating_add(1);
            let res = stdout.by_ref().take(cap).read_to_end(&mut buf).map(|_| buf);
            if tx.send(res).is_err() {
                // Receiver already timed out and dropped channel.
            }
        });
        rx
    });

    if let Some(mut stdin) = child.stdin.take()
        && let Err(err) = stdin.write_all(probe_json.as_bytes())
    {
        terminate_child(&mut child);
        return canary_err(
            &manifest.id,
            HookHealthState::CanaryFailed,
            CanaryStatus::ProbeRejected,
            format!("failed writing canary stdin: {err}"),
        );
    }

    let Some(deadline) = Instant::now().checked_add(Duration::from_millis(CANARY_EXEC_TIMEOUT_MS))
    else {
        terminate_child(&mut child);
        return canary_err(
            &manifest.id,
            HookHealthState::CanaryFailed,
            CanaryStatus::ProbeRejected,
            "system monotonic clock overflow computing canary deadline",
        );
    };
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let buf = match read_stdout_receiver(stdout_rx) {
                    Ok(b) => b,
                    Err(msg) => {
                        return canary_err(
                            &manifest.id,
                            HookHealthState::CanaryFailed,
                            CanaryStatus::ProbeRejected,
                            msg,
                        );
                    }
                };
                if buf.len() > CANARY_STDOUT_MAX_BYTES {
                    return canary_err(
                        &manifest.id,
                        HookHealthState::CanaryFailed,
                        CanaryStatus::ProbeRejected,
                        "hook canary stdout exceeded bounded cap",
                    );
                }
                let parsed: Result<serde_json::Value, _> = serde_json::from_slice(&buf);
                let has_decision = parsed.as_ref().is_ok_and(|val| {
                    val.get("verdict").is_some()
                        || val.get("decision").is_some()
                        || val.get("hookSpecificOutput").is_some()
                });
                if !status.success() || !has_decision {
                    return canary_err(
                        &manifest.id,
                        HookHealthState::CanaryFailed,
                        CanaryStatus::ProbeRejected,
                        format!(
                            "hook binary exited with {:?} without valid decision payload",
                            status.code()
                        ),
                    );
                }
                return HookCanaryReport {
                    agent_id: manifest.id.clone(),
                    health: HookHealthState::Effective,
                    canary: CanaryStatus::Passed,
                    detail: format!(
                        "canary executed and verified for dialect `{}` ({attempt_summary})",
                        manifest.hook.dialect
                    ),
                };
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    terminate_child(&mut child);
                    return canary_err(
                        &manifest.id,
                        HookHealthState::CanaryFailed,
                        CanaryStatus::Missed,
                        "hook canary execution timed out",
                    );
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(err) => {
                terminate_child(&mut child);
                return canary_err(
                    &manifest.id,
                    HookHealthState::CanaryFailed,
                    CanaryStatus::ProbeRejected,
                    format!("failed waiting for hook canary child: {err}"),
                );
            }
        }
    }
}

fn verify_trusted_hook_binary(
    manifest: &AgentManifest,
    cmd_path: &Path,
    fs: &dyn LocalFsPort,
) -> Result<PathBuf, HookCanaryReport> {
    if !cmd_path.is_absolute()
        || cmd_path
            .components()
            .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
    {
        return Err(canary_err(
            &manifest.id,
            HookHealthState::ConfiguredNotEffective,
            CanaryStatus::Missed,
            "hook command must be an absolute canonical path for live execution canary",
        ));
    }
    if let Err(err) = fs.check_no_ancestor_symlinks(cmd_path) {
        return Err(canary_err(
            &manifest.id,
            HookHealthState::Tampered,
            CanaryStatus::ProbeRejected,
            format!("hook executable ancestor symlink check failed: {err}"),
        ));
    }
    match fs.inspect_nofollow(cmd_path) {
        Ok(RegularEntryKind::File) => {}
        Ok(RegularEntryKind::Missing) => {
            return Err(canary_err(
                &manifest.id,
                HookHealthState::ConfiguredNotEffective,
                CanaryStatus::Missed,
                format!("hook executable missing: {}", cmd_path.display()),
            ));
        }
        Ok(RegularEntryKind::Dir | RegularEntryKind::UnsafeOrOther) => {
            return Err(canary_err(
                &manifest.id,
                HookHealthState::Tampered,
                CanaryStatus::ProbeRejected,
                "hook executable cannot be a symlink, junction, or non-regular file",
            ));
        }
        Err(err) => {
            return Err(canary_err(
                &manifest.id,
                HookHealthState::Tampered,
                CanaryStatus::ProbeRejected,
                format!("hook executable trust check failed: {err}"),
            ));
        }
    }
    let meta = std::fs::symlink_metadata(cmd_path).map_err(|err| {
        canary_err(
            &manifest.id,
            HookHealthState::ConfiguredNotEffective,
            CanaryStatus::Missed,
            format!("hook executable missing: {err}"),
        )
    })?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return Err(canary_err(
            &manifest.id,
            HookHealthState::Tampered,
            CanaryStatus::ProbeRejected,
            "hook executable cannot be a symlink or non-regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (meta.mode() & 0o022) != 0 {
            return Err(canary_err(
                &manifest.id,
                HookHealthState::Tampered,
                CanaryStatus::ProbeRejected,
                "hook executable cannot be group- or world-writable",
            ));
        }
    }
    std::fs::canonicalize(cmd_path).map_err(|_| {
        canary_err(
            &manifest.id,
            HookHealthState::CanaryFailed,
            CanaryStatus::ProbeRejected,
            "failed canonicalizing hook executable",
        )
    })
}

fn configure_process_group(cmd: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(CREATE_NEW_PROCESS_GROUP);
    }
}

fn read_stdout_receiver(
    rx: Option<mpsc::Receiver<std::io::Result<Vec<u8>>>>,
) -> Result<Vec<u8>, String> {
    let Some(rx) = rx else {
        return Ok(Vec::new());
    };
    match rx.recv_timeout(Duration::from_millis(250)) {
        Ok(Ok(buf)) => Ok(buf),
        Ok(Err(err)) => Err(format!("failed reading hook canary stdout: {err}")),
        Err(_) => Err("timed out draining hook canary stdout".into()),
    }
}

fn terminate_child(child: &mut Child) {
    let pid = child.id();
    #[cfg(windows)]
    {
        let taskkill = std::env::var_os("SystemRoot")
            .map(PathBuf::from)
            .filter(|root| root.is_absolute())
            .map(|root| root.join("System32").join("taskkill.exe"))
            .and_then(|candidate| std::fs::canonicalize(candidate).ok());
        if let Some(exe) = taskkill {
            drop(
                Command::new(exe)
                    .env_clear()
                    .args(["/F", "/T", "/PID", &pid.to_string()])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status(),
            );
        }
    }
    #[cfg(unix)]
    {
        drop(
            Command::new("/bin/kill")
                .env_clear()
                .args(["-KILL", &format!("-{pid}")])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status(),
        );
    }
    drop(child.kill());
    drop(child.wait());
}

fn canary_err(
    agent_id: &str,
    health: HookHealthState,
    canary: CanaryStatus,
    detail: impl Into<String>,
) -> HookCanaryReport {
    HookCanaryReport {
        agent_id: agent_id.to_owned(),
        health,
        canary,
        detail: detail.into(),
    }
}
