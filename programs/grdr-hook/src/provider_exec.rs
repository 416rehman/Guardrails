// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Chrome/Firefox Native Messaging 4-byte LE framing and sandboxed `command-hook` executor.

use std::io::{ErrorKind, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use grdr_peer_os::fs_open::{
    OpenNofollowAccess, check_no_ancestor_symlinks, open_nofollow_file, verify_open_file_trust,
};

use crate::json_scan::HookCodecError;
pub use crate::provider_index::{
    MAX_COMMAND_HOOK_TIMEOUT_MS, MAX_PROVIDER_INDEX_BYTES, ProviderFailureMode,
    ProviderHookOutcome, ProviderIndexEntry, evaluate_command_hook_outcome, failure_mode_outcome,
    lookup_provider_index, parse_provider_index_entry, verify_signed_provider_index,
};

pub const MAX_PROVIDER_STDOUT_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandHookOutput {
    pub provider_id: String,
    pub exit_code: i32,
    pub stdout_bounded: Vec<u8>,
    pub stdout_truncated: bool,
    pub timed_out: bool,
}

pub fn read_native_messaging_frame<R: Read>(
    reader: &mut R,
    max_bytes: usize,
) -> Result<Vec<u8>, HookCodecError> {
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .map_err(|e| HookCodecError::MalformedJson {
            detail: format!("native messaging length prefix read error: {e}"),
        })?;
    let frame_len = u32::from_le_bytes(len_buf) as usize;
    if frame_len == 0 {
        return Err(HookCodecError::EmptyPayload);
    }
    if frame_len > max_bytes {
        return Err(HookCodecError::PayloadTooLarge { max: max_bytes });
    }
    let mut payload = vec![0u8; frame_len];
    reader
        .read_exact(&mut payload)
        .map_err(|e| HookCodecError::MalformedJson {
            detail: format!("native messaging body read error: {e}"),
        })?;
    Ok(payload)
}

pub fn read_native_messaging_frame_bounded<R: Read + Send + 'static>(
    mut reader: R,
    max_bytes: usize,
    timeout: Duration,
) -> Result<Vec<u8>, HookCodecError> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let res = read_native_messaging_frame(&mut reader, max_bytes);
        if tx.send(res).is_err() {
            eprintln!("native messaging stdin read timed out before frame completed");
        }
    });
    match rx.recv_timeout(timeout) {
        Ok(res) => res,
        Err(_) => Err(HookCodecError::MalformedJson {
            detail: "native messaging stdin read timed out".to_string(),
        }),
    }
}

pub fn write_native_messaging_frame<W: Write>(writer: &mut W, body: &[u8]) -> std::io::Result<()> {
    let len = u32::try_from(body.len())
        .map_err(|_| std::io::Error::new(ErrorKind::InvalidInput, "frame > 4 GiB"))?;
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(body)?;
    writer.flush()
}

pub fn execute_command_hook(
    entry: &ProviderIndexEntry,
    stdin_payload: &[u8],
    protected: bool,
) -> Result<CommandHookOutput, String> {
    let canon_cmd = resolve_canonical_executable(Path::new(&entry.command), protected)?;
    let mut cmd = Command::new(&canon_cmd);
    cmd.args(&entry.args)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        cmd.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        cmd.creation_flags(CREATE_NEW_PROCESS_GROUP);
    }
    let mut child = cmd.spawn().map_err(|e| {
        format!(
            "failed spawning re-hosted provider `{}`: {e}",
            entry.provider_id
        )
    })?;

    let stdout_handle = child.stdout.take().map(|out| {
        std::thread::spawn(move || -> Result<(Vec<u8>, bool), String> {
            let mut buf = Vec::new();
            let cap =
                u64::try_from(MAX_PROVIDER_STDOUT_BYTES.saturating_add(1)).unwrap_or(u64::MAX);
            out.take(cap)
                .read_to_end(&mut buf)
                .map_err(|e| format!("stdout read error: {e}"))?;
            let truncated = buf.len() > MAX_PROVIDER_STDOUT_BYTES;
            if truncated {
                buf.truncate(MAX_PROVIDER_STDOUT_BYTES);
            }
            Ok((buf, truncated))
        })
    });

    let owned_payload = stdin_payload.to_vec();
    let stdin_handle = child.stdin.take().map(|mut child_stdin| {
        std::thread::spawn(move || -> std::io::Result<()> {
            child_stdin.write_all(&owned_payload)?;
            child_stdin.flush()
        })
    });

    let deadline = Instant::now()
        .checked_add(Duration::from_millis(
            entry.timeout_ms.clamp(1, MAX_COMMAND_HOOK_TIMEOUT_MS),
        ))
        .ok_or_else(|| "provider deadline overflow".to_string())?;

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                join_stdin_thread(stdin_handle, &entry.provider_id);
                let (stdout_bounded, stdout_truncated) = match stdout_handle {
                    Some(handle) => handle
                        .join()
                        .map_err(|_| "provider stdout reader thread panicked".to_string())??,
                    None => (Vec::new(), false),
                };
                return Ok(CommandHookOutput {
                    provider_id: entry.provider_id.clone(),
                    exit_code: status.code().unwrap_or(1),
                    stdout_bounded,
                    stdout_truncated,
                    timed_out: false,
                });
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    terminate_process_tree(&mut child);
                    join_stdin_thread(stdin_handle, &entry.provider_id);
                    if let Some(handle) = stdout_handle
                        && handle.join().is_err()
                    {
                        eprintln!(
                            "provider `{}` stdout thread panicked after kill",
                            entry.provider_id
                        );
                    }
                    return Ok(CommandHookOutput {
                        provider_id: entry.provider_id.clone(),
                        exit_code: if entry.is_fail_closed() { 2 } else { 0 },
                        stdout_bounded: Vec::new(),
                        stdout_truncated: false,
                        timed_out: true,
                    });
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(err) => {
                terminate_process_tree(&mut child);
                join_stdin_thread(stdin_handle, &entry.provider_id);
                return Err(format!(
                    "wait failed on provider `{}`: {err}",
                    entry.provider_id
                ));
            }
        }
    }
}

fn resolve_canonical_executable(path: &Path, protected: bool) -> Result<PathBuf, String> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
    {
        return Err("provider command must be an absolute canonical path".to_string());
    }
    check_no_ancestor_symlinks(path).map_err(|e| e.to_string())?;
    let file = open_nofollow_file(path, OpenNofollowAccess::ReadOnly, 0)
        .map_err(|e| format!("provider command binary unsafe: {e}"))?;
    verify_open_file_trust(&file, protected)
        .map_err(|e| format!("provider command binary untrusted: {e}"))?;
    drop(file);
    std::fs::canonicalize(path).map_err(|e| format!("cannot canonicalize provider command: {e}"))
}

fn terminate_process_tree(child: &mut Child) {
    let pid = child.id();
    #[cfg(windows)]
    {
        let taskkill = std::env::var_os("SystemRoot")
            .map(PathBuf::from)
            .filter(|root| root.is_absolute())
            .map(|root| root.join("System32").join("taskkill.exe"))
            .and_then(|candidate| std::fs::canonicalize(candidate).ok());
        if let Some(exe) = taskkill {
            match Command::new(exe)
                .env_clear()
                .args(["/F", "/T", "/PID", &pid.to_string()])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
            {
                Ok(_) => {}
                Err(err) => eprintln!("taskkill failed for provider pid {pid}: {err}"),
            }
        }
    }
    #[cfg(unix)]
    {
        match Command::new("/bin/kill")
            .env_clear()
            .args(["-KILL", &format!("-{pid}")])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
        {
            Ok(_) => {}
            Err(err) => eprintln!("kill -KILL -{pid} failed: {err}"),
        }
    }
    if let Err(err) = child.kill()
        && err.kind() != ErrorKind::InvalidInput
    {
        eprintln!("child.kill failed for provider pid {pid}: {err}");
    }
    if let Err(err) = child.wait() {
        eprintln!("child.wait failed for provider pid {pid}: {err}");
    }
}

fn join_stdin_thread(
    handle: Option<std::thread::JoinHandle<std::io::Result<()>>>,
    provider_id: &str,
) {
    if let Some(h) = handle {
        match h.join() {
            Ok(Ok(())) => {}
            Ok(Err(err)) if err.kind() == ErrorKind::BrokenPipe => {}
            Ok(Err(err)) => {
                eprintln!("provider `{provider_id}` stdin write error: {err}");
            }
            Err(_) => {
                eprintln!("provider `{provider_id}` stdin writer thread panicked");
            }
        }
    }
}
