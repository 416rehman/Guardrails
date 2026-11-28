// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Win32 live process observation and parent-chain inspection (`CreateToolhelp32Snapshot`,
//! `OpenProcess`, `GetProcessTimes`, and `QueryFullProcessImageNameW`).

#[cfg(windows)]
use std::collections::BTreeMap;
#[cfg(windows)]
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
#[cfg(windows)]
use std::ptr::null_mut;

#[cfg(windows)]
use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, FILETIME, HANDLE, INVALID_HANDLE_VALUE};
#[cfg(windows)]
use windows_sys::Win32::Security::TOKEN_QUERY;
#[cfg(windows)]
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
#[cfg(windows)]
use windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW;
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    GetProcessId, GetProcessTimes, OpenProcess, OpenProcessToken,
    PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};

#[cfg(windows)]
use crate::win_token::{
    ScopedWinHandle, read_token_integrity_rid, read_token_is_app_container, read_token_user_sid,
};
#[cfg(windows)]
use crate::{
    ExeIdentity, PeerCredentials, PeerError, PeerObservation, ProcessHold, WindowsPipePeer,
};

#[cfg(windows)]
const MAX_SNAPSHOT_PROCESSES: usize = 65_536;
#[cfg(windows)]
const KERNEL_SYSTEM_PID: u32 = 4;

#[cfg(windows)]
pub(crate) struct SnapshotProcEntry {
    pub(crate) ppid: u32,
    pub(crate) exe_name: String,
}

#[cfg(windows)]
pub(crate) fn read_windows_peer_observation(pid: u32) -> Result<PeerObservation, PeerError> {
    if pid == 0 {
        return Err(PeerError::Unverifiable(
            "pid 0 is invalid for Windows peer inspection".to_string(),
        ));
    }
    let snap = snapshot_process_map()?;
    let snap_entry = snap.get(&pid);

    if pid == KERNEL_SYSTEM_PID {
        if let Some(entry) = snap_entry
            && entry.ppid == 0
            && entry.exe_name.eq_ignore_ascii_case("System")
        {
            return Ok(tcb_root_observation(pid, 1, None));
        }
        return Err(PeerError::Unverifiable(
            "unexpected metadata for Windows System PID 4".to_string(),
        ));
    }

    match open_limited_query(pid) {
        Ok(proc_owned) => {
            let entry = snap_entry.ok_or_else(|| {
                PeerError::Unverifiable(format!("pid {pid} absent from process snapshot"))
            })?;
            let proc_raw = proc_owned.as_raw_handle() as HANDLE;
            let actual_pid = read_process_id(proc_raw)?;
            if actual_pid != pid {
                return Err(PeerError::PidReuse);
            }
            let started_100ns = read_process_start_time_100ns(proc_raw)?;
            if started_100ns == 0 {
                return Err(PeerError::Unverifiable(format!(
                    "zero creation time for pid {pid}"
                )));
            }
            let exe_path = query_process_image_path(proc_raw)?;
            let (sid, integrity_rid) = read_optional_process_token(proc_raw);
            let mut parent_pid = entry.ppid;
            if parent_pid != 0
                && is_trusted_win_root_exe(&exe_path)
                && parent_missing_or_newer(&snap, parent_pid, started_100ns)
            {
                parent_pid = 0;
            }
            Ok(PeerObservation {
                credentials: PeerCredentials::Windows(WindowsPipePeer {
                    client_pid: pid,
                    pipe_owner_sid: sid,
                    expected_service_sid: None,
                    pipe_server_pid: None,
                    scm_pid_sample_1: None,
                    scm_pid_sample_2: None,
                    message_identity_sid: None,
                    integrity_rid,
                    open_as_self_verified: false,
                    process_created_ns: started_100ns.saturating_mul(100),
                    connected_at_ns: 0,
                }),
                hold: ProcessHold::Unheld,
                parent_pid,
                started_at_ticks: started_100ns,
                exe: Some(ExeIdentity {
                    exe_path: Some(exe_path),
                    signer_team_id: None,
                    signing_id: None,
                }),
            })
        }
        Err((Some(err_code), _)) if err_code == ERROR_ACCESS_DENIED => {
            crate::win_tcb::verify_tcb_process_on_access_denied(&snap, pid).map(
                |(verified_exe, started_100ns)| {
                    tcb_root_observation(pid, started_100ns, Some(verified_exe))
                },
            )
        }
        Err((_, err)) => Err(err),
    }
}

#[cfg(windows)]
pub(crate) fn read_windows_exe_identity(pid: u32) -> Result<ExeIdentity, PeerError> {
    if pid == 0 {
        return Err(PeerError::Unverifiable(
            "pid 0 is invalid for executable lookup".to_string(),
        ));
    }
    let proc_owned = match open_limited_query(pid) {
        Ok(handle) => handle,
        Err((Some(err_code), _)) if err_code == ERROR_ACCESS_DENIED => {
            let snap = snapshot_process_map()?;
            let (verified_exe, _) =
                crate::win_tcb::verify_tcb_process_on_access_denied(&snap, pid)?;
            return Ok(ExeIdentity {
                exe_path: Some(verified_exe),
                signer_team_id: None,
                signing_id: None,
            });
        }
        Err((_, e)) => return Err(e),
    };
    let proc_raw = proc_owned.as_raw_handle() as HANDLE;
    if read_process_id(proc_raw)? != pid {
        return Err(PeerError::PidReuse);
    }
    let exe_path = query_process_image_path(proc_raw)?;
    Ok(ExeIdentity {
        exe_path: Some(exe_path),
        signer_team_id: None,
        signing_id: None,
    })
}

#[cfg(windows)]
fn tcb_root_observation(
    pid: u32,
    started_100ns: u64,
    verified_exe: Option<String>,
) -> PeerObservation {
    PeerObservation {
        credentials: PeerCredentials::Windows(WindowsPipePeer {
            client_pid: pid,
            pipe_owner_sid: String::new(),
            expected_service_sid: None,
            pipe_server_pid: None,
            scm_pid_sample_1: None,
            scm_pid_sample_2: None,
            message_identity_sid: None,
            integrity_rid: None,
            open_as_self_verified: false,
            process_created_ns: started_100ns.saturating_mul(100),
            connected_at_ns: 0,
        }),
        hold: ProcessHold::Unheld,
        parent_pid: 0,
        started_at_ticks: started_100ns,
        exe: Some(ExeIdentity {
            exe_path: verified_exe,
            signer_team_id: None,
            signing_id: None,
        }),
    }
}

#[cfg(windows)]
fn parent_missing_or_newer(
    snap: &BTreeMap<u32, SnapshotProcEntry>,
    parent_pid: u32,
    child_started_100ns: u64,
) -> bool {
    if !snap.contains_key(&parent_pid) {
        return true;
    }
    let Ok(parent_handle) = open_limited_query(parent_pid) else {
        return false;
    };
    let raw = parent_handle.as_raw_handle() as HANDLE;
    match read_process_start_time_100ns(raw) {
        Ok(parent_start) => parent_start > child_started_100ns,
        Err(_) => true,
    }
}

#[cfg(windows)]
fn is_trusted_win_root_exe(exe_path: &str) -> bool {
    let Some(win_dir) = windows_system_directory() else {
        return false;
    };
    let root = win_dir.trim_end_matches(['\\', '/']);
    let explorer = format!("{root}\\explorer.exe");
    let wininit = format!("{root}\\System32\\wininit.exe");
    let services = format!("{root}\\System32\\services.exe");
    let winlogon = format!("{root}\\System32\\winlogon.exe");
    let smss = format!("{root}\\System32\\smss.exe");
    exe_path.eq_ignore_ascii_case(&explorer)
        || exe_path.eq_ignore_ascii_case(&wininit)
        || exe_path.eq_ignore_ascii_case(&services)
        || exe_path.eq_ignore_ascii_case(&winlogon)
        || exe_path.eq_ignore_ascii_case(&smss)
}

#[cfg(windows)]
#[allow(unsafe_code, reason = "Win32 GetWindowsDirectoryW stack buffer lookup")]
fn windows_system_directory() -> Option<String> {
    let mut buf = [0u16; 260];
    let buf_cap = u32::try_from(buf.len()).unwrap_or(260);
    // SAFETY: `buf` is a stack UTF-16 buffer of exact capacity `buf_cap`.
    let len = unsafe { GetWindowsDirectoryW(buf.as_mut_ptr(), buf_cap) };
    let len_usize = usize::try_from(len).ok()?;
    if len_usize == 0 || len_usize >= buf.len() {
        return None;
    }
    Some(String::from_utf16_lossy(buf.get(..len_usize)?))
}

#[cfg(windows)]
#[allow(
    unsafe_code,
    reason = "Win32 CreateToolhelp32Snapshot / Process32FirstW / Process32NextW table walk"
)]
fn snapshot_process_map() -> Result<BTreeMap<u32, SnapshotProcEntry>, PeerError> {
    // SAFETY: `TH32CS_SNAPPROCESS` with pid 0 captures system process snapshot into RAII handle.
    let snap_raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap_raw.is_null() || snap_raw == INVALID_HANDLE_VALUE {
        return Err(PeerError::Unverifiable(format!(
            "CreateToolhelp32Snapshot failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    let _snap_guard = ScopedWinHandle(snap_raw);

    // SAFETY: `PROCESSENTRY32W` is POD and requires `dwSize` set to struct byte size.
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = u32::try_from(std::mem::size_of::<PROCESSENTRY32W>())
        .map_err(|_| PeerError::Unverifiable("PROCESSENTRY32W size overflow".to_string()))?;

    // SAFETY: `snap_raw` is valid process snapshot and `entry.dwSize` is initialized.
    let mut has_next = unsafe { Process32FirstW(snap_raw, &mut entry) };
    let mut map = BTreeMap::new();
    let mut count = 0usize;
    while has_next != 0 && count < MAX_SNAPSHOT_PROCESSES {
        let nul = entry
            .szExeFile
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(entry.szExeFile.len());
        let exe_name = entry
            .szExeFile
            .get(..nul)
            .map(String::from_utf16_lossy)
            .unwrap_or_default();
        map.insert(
            entry.th32ProcessID,
            SnapshotProcEntry {
                ppid: entry.th32ParentProcessID,
                exe_name,
            },
        );
        count = count.saturating_add(1);
        // SAFETY: `snap_raw` remains open and `entry.dwSize` stays valid.
        has_next = unsafe { Process32NextW(snap_raw, &mut entry) };
    }
    Ok(map)
}

#[cfg(windows)]
#[allow(
    unsafe_code,
    reason = "Win32 OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) wrapped in OwnedHandle"
)]
fn open_limited_query(pid: u32) -> Result<OwnedHandle, (Option<u32>, PeerError)> {
    // SAFETY: opens target PID with limited query access and checks validity before wrapping.
    let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        let os_err = std::io::Error::last_os_error();
        let code = os_err.raw_os_error().and_then(|c| u32::try_from(c).ok());
        return Err((
            code,
            PeerError::Unverifiable(format!("OpenProcess({pid}) failed: {os_err}")),
        ));
    }
    // SAFETY: `raw` checked non-null and not INVALID_HANDLE_VALUE above.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}

#[cfg(windows)]
#[allow(unsafe_code, reason = "Win32 GetProcessId on held process handle")]
pub(crate) fn read_process_id(proc_raw: HANDLE) -> Result<u32, PeerError> {
    // SAFETY: `proc_raw` is an open valid process handle.
    let pid = unsafe { GetProcessId(proc_raw) };
    if pid == 0 {
        return Err(PeerError::Unverifiable(format!(
            "GetProcessId failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(pid)
}

#[cfg(windows)]
#[allow(unsafe_code, reason = "Win32 GetProcessTimes on held process handle")]
pub(crate) fn read_process_start_time_100ns(proc_raw: HANDLE) -> Result<u64, PeerError> {
    let zero = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut created = zero;
    let mut exited = zero;
    let mut kernel = zero;
    let mut user = zero;
    let ok = {
        // SAFETY: `proc_raw` is a valid open process handle and all FILETIME pointers are stack-local.
        unsafe { GetProcessTimes(proc_raw, &mut created, &mut exited, &mut kernel, &mut user) }
    };
    if ok == 0 {
        return Err(PeerError::Unverifiable(format!(
            "GetProcessTimes failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
}

#[cfg(windows)]
#[allow(
    unsafe_code,
    reason = "Win32 QueryFullProcessImageNameW bounded stack UTF-16 buffer"
)]
fn query_process_image_path(proc_raw: HANDLE) -> Result<String, PeerError> {
    let mut buf = [0u16; 1024];
    let mut len = u32::try_from(buf.len()).unwrap_or(1024);
    // SAFETY: `proc_raw` is an open handle and `buf`/`len` follow `QueryFullProcessImageNameW`.
    let ok = unsafe { QueryFullProcessImageNameW(proc_raw, 0, buf.as_mut_ptr(), &mut len) };
    if ok == 0 {
        return Err(PeerError::Unverifiable(format!(
            "QueryFullProcessImageNameW failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    let used = usize::try_from(len)
        .ok()
        .filter(|&n| n > 0 && n <= buf.len())
        .ok_or_else(|| PeerError::Unverifiable("invalid process image path length".to_string()))?;
    Ok(buf
        .get(..used)
        .map(String::from_utf16_lossy)
        .unwrap_or_default())
}

#[cfg(windows)]
#[allow(
    unsafe_code,
    reason = "Best-effort ancestor token query under OpenProcessToken(TOKEN_QUERY)"
)]
fn read_optional_process_token(proc_raw: HANDLE) -> (String, Option<u32>) {
    let mut tok_raw: HANDLE = null_mut();
    // SAFETY: `proc_raw` is open for `PROCESS_QUERY_LIMITED_INFORMATION`.
    let ok = unsafe { OpenProcessToken(proc_raw, TOKEN_QUERY, &mut tok_raw) };
    if ok == 0 || tok_raw.is_null() {
        return (String::new(), None);
    }
    let _tok_guard = ScopedWinHandle(tok_raw);
    let _ = read_token_is_app_container(tok_raw);
    let sid = read_token_user_sid(tok_raw).unwrap_or_default();
    let rid = read_token_integrity_rid(tok_raw).ok();
    (sid, rid)
}
