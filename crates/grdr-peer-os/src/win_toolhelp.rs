// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Native Win32 ToolHelp32 process snapshot with PID-reuse verification (`ARCH-032`).

use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::path::Path;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{
    ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_FILES, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TokenSessionId};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};

use crate::win_proc::{read_process_id, read_process_start_time_100ns};
use crate::win_token::ScopedWinHandle;
use crate::{OsProcessSnapshotEntry, PeerError};

const MAX_TOOLHELP_PROCESSES: usize = 65_536;
const INIT_IMAGE_PATH_WCHARS: usize = 1_024;
const MAX_IMAGE_PATH_WCHARS: usize = 32_768;

#[allow(
    unsafe_code,
    reason = "Win32 ToolHelp32 APIs enumerate running Windows processes natively"
)]
pub(crate) fn enumerate_windows_processes_native() -> Result<Vec<OsProcessSnapshotEntry>, PeerError>
{
    // SAFETY: `TH32CS_SNAPPROCESS` with pid=0 requires no pointers and returns INVALID_HANDLE_VALUE on failure.
    let snapshot_handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot_handle == INVALID_HANDLE_VALUE || snapshot_handle.is_null() {
        return Err(PeerError::Unverifiable(format!(
            "CreateToolhelp32Snapshot failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    let _snap_guard = ScopedWinHandle(snapshot_handle);

    // SAFETY: `PROCESSENTRY32W` is POD and `dwSize` is initialized before calling `Process32FirstW`.
    let mut entry: PROCESSENTRY32W = unsafe { zeroed() };
    entry.dwSize = u32::try_from(size_of::<PROCESSENTRY32W>())
        .map_err(|_| PeerError::Unverifiable("PROCESSENTRY32W size overflow".to_owned()))?;

    // SAFETY: `snapshot_handle` is valid and `entry.dwSize` equals `size_of::<PROCESSENTRY32W>()`.
    if unsafe { Process32FirstW(snapshot_handle, &mut entry) } == 0 {
        let os_err = std::io::Error::last_os_error();
        if os_err.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
            return Ok(Vec::new());
        }
        return Err(PeerError::Unverifiable(format!(
            "Process32FirstW failed: {os_err}"
        )));
    }

    let mut out = Vec::new();
    let mut seen = 0usize;
    loop {
        if seen >= MAX_TOOLHELP_PROCESSES {
            break;
        }
        seen = seen.saturating_add(1);
        let image_name = utf16_z_to_string(&entry.szExeFile);
        let pid = entry.th32ProcessID;
        let parent_pid = entry.th32ParentProcessID;
        if !image_name.is_empty() {
            let (executable_path, session_id, started_100ns) =
                query_process_details(pid, &image_name);
            out.push(OsProcessSnapshotEntry {
                pid,
                parent_pid,
                image_name,
                executable_path,
                session_id,
                started_100ns,
            });
        }

        // SAFETY: `snapshot_handle` remains open and `entry.dwSize` stays valid.
        if unsafe { Process32NextW(snapshot_handle, &mut entry) } == 0 {
            let os_err = std::io::Error::last_os_error();
            if os_err.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
                break;
            }
            return Err(PeerError::Unverifiable(format!(
                "Process32NextW failed: {os_err}"
            )));
        }
    }

    Ok(out)
}

#[allow(
    unsafe_code,
    reason = "OpenProcess, QueryFullProcessImageNameW, and GetTokenInformation inspect live process metadata"
)]
fn query_process_details(pid: u32, snap_image_name: &str) -> (Option<String>, Option<u32>, u64) {
    if pid == 0 {
        return (None, None, 0);
    }
    // SAFETY: scalar arguments only; null and INVALID_HANDLE_VALUE are checked immediately.
    let proc_handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if proc_handle.is_null() || proc_handle == INVALID_HANDLE_VALUE {
        return (None, None, 0);
    }
    let _proc_guard = ScopedWinHandle(proc_handle);

    let Ok(actual_pid) = read_process_id(proc_handle) else {
        return (None, None, 0);
    };
    if actual_pid != pid {
        return (None, None, 0);
    }
    let Ok(started_before) = read_process_start_time_100ns(proc_handle) else {
        return (None, None, 0);
    };
    if started_before == 0 {
        return (None, None, 0);
    }

    let image_path = query_image_path_growing(proc_handle);
    if let Some(ref path) = image_path
        && !basename_matches_snapshot(path, snap_image_name)
    {
        return (None, None, 0);
    }

    let mut tok_handle: HANDLE = null_mut();
    // SAFETY: `proc_handle` is open and `tok_handle` is stack-local writable storage.
    let tok_ok = unsafe { OpenProcessToken(proc_handle, TOKEN_QUERY, &mut tok_handle) };
    let session_id = if tok_ok != 0 && !tok_handle.is_null() && tok_handle != INVALID_HANDLE_VALUE {
        let _tok_guard = ScopedWinHandle(tok_handle);
        let mut sid: u32 = 0;
        let mut ret_len: u32 = 0;
        let sid_size = u32::try_from(size_of::<u32>()).unwrap_or(4);
        // SAFETY: `sid` points to writable u32 stack storage of exact size `sid_size`.
        let info_ok = unsafe {
            GetTokenInformation(
                tok_handle,
                TokenSessionId,
                (&raw mut sid).cast::<c_void>(),
                sid_size,
                &mut ret_len,
            )
        };
        if info_ok != 0 && ret_len == sid_size {
            Some(sid)
        } else {
            None
        }
    } else {
        None
    };

    let Ok(started_after) = read_process_start_time_100ns(proc_handle) else {
        return (None, None, 0);
    };
    if started_after != started_before {
        return (None, None, 0);
    }

    (image_path, session_id, started_before)
}

#[allow(
    unsafe_code,
    reason = "QueryFullProcessImageNameW writes bounded UTF-16 image path with dynamic retry up to 32768 WCHARs"
)]
fn query_image_path_growing(proc_handle: HANDLE) -> Option<String> {
    let mut cap = INIT_IMAGE_PATH_WCHARS;
    loop {
        let mut buf = vec![0u16; cap];
        let mut len = u32::try_from(buf.len()).ok()?;
        // SAFETY: `proc_handle` is open and `buf` holds `len` writable u16 elements.
        let ok = unsafe { QueryFullProcessImageNameW(proc_handle, 0, buf.as_mut_ptr(), &mut len) };
        if ok != 0 {
            let used = usize::try_from(len).ok()?.min(buf.len());
            if used == 0 {
                return None;
            }
            return buf.get(..used).map(String::from_utf16_lossy);
        }
        let err_code = std::io::Error::last_os_error().raw_os_error();
        if err_code == Some(ERROR_INSUFFICIENT_BUFFER as i32) && cap < MAX_IMAGE_PATH_WCHARS {
            cap = cap.saturating_mul(2).min(MAX_IMAGE_PATH_WCHARS);
            continue;
        }
        return None;
    }
}

fn basename_matches_snapshot(exe_path: &str, snap_image_name: &str) -> bool {
    let Some(base) = Path::new(exe_path).file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    if base.eq_ignore_ascii_case(snap_image_name) {
        return true;
    }
    snap_image_name.len() >= 259
        && base
            .to_ascii_lowercase()
            .starts_with(&snap_image_name.to_ascii_lowercase())
}

fn utf16_z_to_string(slice: &[u16]) -> String {
    let end = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
    slice
        .get(..end)
        .map(String::from_utf16_lossy)
        .unwrap_or_default()
}
