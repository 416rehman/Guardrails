// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Windows named pipe kernel peer credential checks (`GetNamedPipeClientProcessId`,
//! `GetSecurityInfo`, deferred `OpenThreadToken(..., OpenAsSelf = TRUE)`, and dual SCM validation).

pub use crate::scm_probe::{ScmServiceProbe, probe_scm_services};
use grdr_wire::peer_auth::WindowsPeerClaims;

#[cfg(windows)]
mod win_impl {
    use std::ffi::c_void;
    use std::os::windows::io::{AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
    use std::ptr::null_mut;

    use grdr_wire::peer_auth::{Profile, ScmServiceState};
    use windows_sys::Win32::Foundation::{FILETIME, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
    use windows_sys::Win32::Security::{
        OWNER_SECURITY_INFORMATION, PSID, RevertToSelf, SecurityIdentification, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Pipes::{
        GetNamedPipeClientProcessId, GetNamedPipeServerProcessId, ImpersonateNamedPipeClient,
    };
    use windows_sys::Win32::System::SystemInformation::GetSystemTimeAsFileTime;
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetCurrentThread, GetProcessTimes, OpenProcess, OpenProcessToken,
        OpenThreadToken, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    };

    use super::{ScmServiceProbe, WindowsPeerClaims, probe_scm_services};
    use crate::PeerError;
    use crate::win_token::{
        LocalAllocGuard, ScopedWinHandle, psid_to_string, read_token_impersonation_level,
        read_token_integrity_rid, read_token_is_app_container, read_token_user_sid,
    };

    const SYSTEM_INTEGRITY_RID: u32 = 0x4000;
    const HIGH_INTEGRITY_RID: u32 = 0x3000;
    const BROAD_SIDS: &[&str] = &["S-1-1-0", "S-1-5-7", "S-1-5-11", "S-1-5-32-545"];

    struct ImpersonateGuard {
        active: bool,
    }

    impl ImpersonateGuard {
        #[allow(
            unsafe_code,
            reason = "Restores Win32 thread security context via RevertToSelf"
        )]
        fn revert(mut self) -> Result<(), PeerError> {
            self.active = false;
            // SAFETY: caller previously succeeded in `ImpersonateNamedPipeClient`.
            let ok = unsafe { RevertToSelf() };
            if ok == 0 {
                return Err(PeerError::Unverifiable(format!(
                    "RevertToSelf failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            Ok(())
        }
    }

    impl Drop for ImpersonateGuard {
        #[allow(
            unsafe_code,
            reason = "Drop fallback RevertToSelf prevents leaked impersonation"
        )]
        fn drop(&mut self) {
            if self.active {
                // SAFETY: restores thread security context on early return or panic.
                unsafe {
                    let _ = RevertToSelf();
                }
            }
        }
    }

    #[allow(unsafe_code, reason = "Win32 GetSystemTimeAsFileTime stack write")]
    pub fn current_filetime_100ns() -> u64 {
        let mut ft = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        // SAFETY: `GetSystemTimeAsFileTime` populates stack `FILETIME`.
        unsafe {
            GetSystemTimeAsFileTime(&mut ft);
        }
        (u64::from(ft.dwHighDateTime) << 32) | u64::from(ft.dwLowDateTime)
    }

    #[allow(
        unsafe_code,
        reason = "Win32 GetNamedPipeClientProcessId and OpenProcess pre-frame client lookup"
    )]
    pub fn read_windows_pipe_client_pre(
        pipe_handle: BorrowedHandle<'_>,
    ) -> Result<(WindowsPeerClaims, OwnedHandle), PeerError> {
        let handle = pipe_handle.as_raw_handle() as HANDLE;
        let mut client_pid: u32 = 0;
        // SAFETY: `pipe_handle` is a live `BorrowedHandle` for an open named pipe instance.
        let ok = unsafe { GetNamedPipeClientProcessId(handle, &mut client_pid) };
        if ok == 0 || client_pid == 0 {
            return Err(PeerError::Unverifiable(format!(
                "GetNamedPipeClientProcessId failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        let (started_100ns, peer_sid, integrity_rid, is_app_container, proc_handle) =
            read_process_claims_held(client_pid)?;

        Ok((
            WindowsPeerClaims {
                pid: client_pid,
                peer_sid,
                integrity_rid,
                is_app_container,
                thread_token_open_as_self: false,
                peer_started_at_100ns: Some(started_100ns),
                server_pid_from_pipe: None,
                pipe_owner_sid: None,
                scm_pre_pids: Vec::new(),
                scm_post_pids: Vec::new(),
                scm_state: ScmServiceState::Unknown,
                scm_expected_sid: None,
            },
            proc_handle,
        ))
    }

    #[allow(
        unsafe_code,
        reason = "Win32 post-first-frame ImpersonateNamedPipeClient and OpenThreadToken(OpenAsSelf=TRUE)"
    )]
    pub fn verify_windows_pipe_client_post_read(
        pipe_handle: BorrowedHandle<'_>,
        client_proc: &OwnedHandle,
        expected_pid: u32,
        expected_proc_sid: &str,
    ) -> Result<WindowsPeerClaims, PeerError> {
        let handle = pipe_handle.as_raw_handle() as HANDLE;
        let mut live_pid: u32 = 0;
        // SAFETY: `pipe_handle` is live and `live_pid` is stack storage.
        let ok = unsafe { GetNamedPipeClientProcessId(handle, &mut live_pid) };
        if ok == 0 || live_pid != expected_pid {
            return Err(PeerError::PidReuse);
        }

        let started_100ns = read_process_start_time(client_proc.as_raw_handle() as HANDLE)?;

        // SAFETY: called post-first-frame on live server pipe handle; `ImpersonateGuard` enforces revert.
        let imp_ok = unsafe { ImpersonateNamedPipeClient(handle) };
        if imp_ok == 0 {
            return Err(PeerError::Unverifiable(format!(
                "ImpersonateNamedPipeClient failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        let guard = ImpersonateGuard { active: true };
        let read_res = read_impersonated_thread_token();
        // Always surface explicit RevertToSelf failure ahead of any token inspection failure.
        guard.revert()?;
        let (imp_level, thread_sid, thread_il, thread_ac) = read_res?;
        if imp_level < SecurityIdentification {
            return Err(PeerError::Unverifiable(
                "pipe impersonation level below SecurityIdentification".to_string(),
            ));
        }

        if thread_sid != expected_proc_sid {
            return Err(PeerError::Unverifiable(
                "pipe OpenAsSelf thread SID disagrees with client process SID".to_string(),
            ));
        }

        Ok(WindowsPeerClaims {
            pid: expected_pid,
            peer_sid: thread_sid,
            integrity_rid: thread_il,
            is_app_container: thread_ac,
            thread_token_open_as_self: true,
            peer_started_at_100ns: Some(started_100ns),
            server_pid_from_pipe: None,
            pipe_owner_sid: None,
            scm_pre_pids: Vec::new(),
            scm_post_pids: Vec::new(),
            scm_state: ScmServiceState::Unknown,
            scm_expected_sid: None,
        })
    }

    #[allow(
        unsafe_code,
        reason = "Win32 OpenThreadToken(OpenAsSelf=TRUE) while pipe impersonation guard is active"
    )]
    fn read_impersonated_thread_token() -> Result<(i32, String, u32, bool), PeerError> {
        let mut thread_tok: HANDLE = null_mut();
        let tok_ok;
        // SAFETY: `OpenAsSelf = 1 (TRUE)` validates against daemon self context while impersonating.
        unsafe {
            tok_ok = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut thread_tok);
        }
        if tok_ok == 0 || thread_tok.is_null() {
            return Err(PeerError::Unverifiable(format!(
                "OpenThreadToken(OpenAsSelf=TRUE) failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        let _tok_guard = ScopedWinHandle(thread_tok);
        let imp_level = read_token_impersonation_level(thread_tok)?;
        let thread_sid = read_token_user_sid(thread_tok)?;
        let thread_il = read_token_integrity_rid(thread_tok)?;
        let thread_ac = read_token_is_app_container(thread_tok)?;
        Ok((imp_level, thread_sid, thread_il, thread_ac))
    }

    fn pair_scm_service_pids(
        service_names: &[&str],
        pre_scm: &[Option<ScmServiceProbe>],
        post_scm: &[Option<ScmServiceProbe>],
        server_pid: u32,
    ) -> (Vec<u32>, Vec<u32>, bool) {
        if service_names.is_empty()
            || pre_scm.len() != service_names.len()
            || post_scm.len() != service_names.len()
        {
            return (Vec::new(), Vec::new(), false);
        }
        for (pre, post) in pre_scm.iter().zip(post_scm.iter()) {
            let Some(p_pre) = pre else { continue };
            let Some(p_post) = post else { continue };
            if !p_post.running {
                continue;
            }
            if p_pre.pid == Some(server_pid) && p_post.pid == Some(server_pid) {
                return (vec![server_pid], vec![server_pid], true);
            }
            if p_post.pid == Some(server_pid)
                && let Some(old_pid) = p_pre.pid
            {
                return (vec![old_pid], vec![server_pid], true);
            }
        }
        let pre_pids: Vec<u32> = pre_scm.iter().flatten().filter_map(|p| p.pid).collect();
        let post_pids: Vec<u32> = post_scm.iter().flatten().filter_map(|p| p.pid).collect();
        let any_running = post_scm.iter().flatten().any(|p| p.running);
        (pre_pids, post_pids, any_running)
    }

    fn service_account_integrity_rid(sid: &str) -> u32 {
        if BROAD_SIDS.contains(&sid) || !sid.starts_with("S-1-") {
            return 0;
        }
        if matches!(sid, "S-1-5-18" | "S-1-5-19" | "S-1-5-20") || sid.starts_with("S-1-5-80-") {
            SYSTEM_INTEGRITY_RID
        } else {
            HIGH_INTEGRITY_RID
        }
    }

    #[allow(
        unsafe_code,
        reason = "Win32 GetNamedPipeServerProcessId and GetSecurityInfo pipe owner verification"
    )]
    pub fn read_windows_pipe_server(
        pipe_handle: BorrowedHandle<'_>,
        profile: Profile,
        service_names: &[&str],
        pre_scm: &[Option<ScmServiceProbe>],
    ) -> Result<WindowsPeerClaims, PeerError> {
        let handle = pipe_handle.as_raw_handle() as HANDLE;
        let mut server_pid: u32 = 0;
        // SAFETY: `pipe_handle` is open client pipe handle and `server_pid` is stack storage.
        let ok = unsafe { GetNamedPipeServerProcessId(handle, &mut server_pid) };
        if ok == 0 || server_pid == 0 {
            return Err(PeerError::Unverifiable(format!(
                "GetNamedPipeServerProcessId failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        let mut owner_psid: PSID = null_mut();
        let mut sec_desc: *mut c_void = null_mut();
        // SAFETY: `GetSecurityInfo` writes `owner_psid` into `sec_desc`, freed by `LocalAllocGuard`.
        let sec_err = unsafe {
            GetSecurityInfo(
                handle,
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner_psid,
                null_mut(),
                null_mut(),
                null_mut(),
                &mut sec_desc,
            )
        };
        let _sd_guard = LocalAllocGuard(sec_desc);
        if sec_err != 0 || owner_psid.is_null() {
            return Err(PeerError::Unverifiable(format!(
                "GetSecurityInfo(OWNER_SECURITY_INFORMATION) failed with win32 error {sec_err}"
            )));
        }
        let pipe_owner_sid = psid_to_string(owner_psid)?;

        let post_scm = probe_scm_services(service_names);
        let (scm_pre_pids, scm_post_pids, scm_running) =
            pair_scm_service_pids(service_names, pre_scm, &post_scm, server_pid);
        let scm_state = if service_names.is_empty() {
            ScmServiceState::Unknown
        } else if scm_running {
            ScmServiceState::Running
        } else {
            ScmServiceState::Stopped
        };

        if profile == Profile::Protected {
            let pid_matched = scm_running
                && !scm_pre_pids.is_empty()
                && scm_pre_pids == scm_post_pids
                && scm_post_pids.contains(&server_pid);
            let integrity_rid = if pid_matched {
                service_account_integrity_rid(&pipe_owner_sid)
            } else {
                0
            };
            return Ok(WindowsPeerClaims {
                pid: server_pid,
                peer_sid: pipe_owner_sid.clone(),
                integrity_rid,
                is_app_container: false,
                thread_token_open_as_self: false,
                peer_started_at_100ns: None,
                server_pid_from_pipe: Some(server_pid),
                pipe_owner_sid: Some(pipe_owner_sid),
                scm_pre_pids,
                scm_post_pids,
                scm_state,
                scm_expected_sid: None,
            });
        }

        let (started_100ns, proc_sid, integrity_rid, is_app_container, _proc_hold) =
            read_process_claims_held(server_pid)?;
        if proc_sid != pipe_owner_sid {
            return Err(PeerError::ServerForeign);
        }
        Ok(WindowsPeerClaims {
            pid: server_pid,
            peer_sid: proc_sid,
            integrity_rid,
            is_app_container,
            thread_token_open_as_self: false,
            peer_started_at_100ns: Some(started_100ns),
            server_pid_from_pipe: Some(server_pid),
            pipe_owner_sid: Some(pipe_owner_sid),
            scm_pre_pids,
            scm_post_pids,
            scm_state,
            scm_expected_sid: None,
        })
    }

    #[allow(
        unsafe_code,
        reason = "Win32 OpenProcess and OpenProcessToken inspection"
    )]
    fn read_process_claims_held(
        pid: u32,
    ) -> Result<(u64, String, u32, bool, OwnedHandle), PeerError> {
        let access = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE;
        // SAFETY: opens target PID with limited query/sync rights, wrapped immediately in OwnedHandle.
        let proc_raw = unsafe { OpenProcess(access, 0, pid) };
        if proc_raw.is_null() || proc_raw == INVALID_HANDLE_VALUE {
            return Err(PeerError::Unverifiable(format!(
                "OpenProcess({pid}) failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: `proc_raw` validated non-null and not INVALID_HANDLE_VALUE.
        let proc_owned = unsafe { OwnedHandle::from_raw_handle(proc_raw) };
        let started_100ns = read_process_start_time(proc_raw)?;

        let mut tok_raw: HANDLE = null_mut();
        // SAFETY: `proc_raw` is open for PROCESS_QUERY_LIMITED_INFORMATION.
        let tok_ok = unsafe { OpenProcessToken(proc_raw, TOKEN_QUERY, &mut tok_raw) };
        if tok_ok == 0 || tok_raw.is_null() {
            return Err(PeerError::Unverifiable(format!(
                "OpenProcessToken({pid}) failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        let _tok_guard = ScopedWinHandle(tok_raw);
        let sid = read_token_user_sid(tok_raw)?;
        let integrity_rid = read_token_integrity_rid(tok_raw)?;
        let app_container = read_token_is_app_container(tok_raw)?;
        Ok((started_100ns, sid, integrity_rid, app_container, proc_owned))
    }

    #[allow(unsafe_code, reason = "Win32 GetProcessTimes on held process handle")]
    fn read_process_start_time(proc_raw: HANDLE) -> Result<u64, PeerError> {
        let mut created = zero_ft();
        let mut exited = zero_ft();
        let mut kernel = zero_ft();
        let mut user = zero_ft();
        let times_ok;
        // SAFETY: `proc_raw` is valid open process handle and four FILETIME pointers are stack-local.
        unsafe {
            times_ok = GetProcessTimes(proc_raw, &mut created, &mut exited, &mut kernel, &mut user);
        }
        if times_ok == 0 {
            return Err(PeerError::Unverifiable(format!(
                "GetProcessTimes failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
    }

    #[allow(
        unsafe_code,
        reason = "Queries current process token SID via GetCurrentProcess"
    )]
    pub fn current_process_sid() -> Result<String, PeerError> {
        let mut tok_raw: HANDLE = null_mut();
        // SAFETY: `GetCurrentProcess` pseudo-handle with `OpenProcessToken`.
        let tok_ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok_raw) };
        if tok_ok == 0 || tok_raw.is_null() {
            return Err(PeerError::Unverifiable(format!(
                "OpenProcessToken(current) failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        let _tok_guard = ScopedWinHandle(tok_raw);
        read_token_user_sid(tok_raw)
    }

    const fn zero_ft() -> FILETIME {
        FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        }
    }
}

#[cfg(windows)]
pub use crate::win_acl::{restrict_windows_dir_handle_dacl, verify_windows_path_security};
#[cfg(windows)]
pub use win_impl::{
    current_filetime_100ns, current_process_sid, read_windows_pipe_client_pre,
    read_windows_pipe_server, verify_windows_pipe_client_post_read,
};

#[cfg(not(windows))]
pub fn current_filetime_100ns() -> u64 {
    0
}

#[cfg(not(windows))]
pub fn current_process_sid() -> Result<String, crate::PeerError> {
    Err(crate::PeerError::Unverifiable(
        "Windows SID unavailable on non-Windows host".to_string(),
    ))
}

#[cfg(not(windows))]
pub fn read_windows_pipe_server(
    _profile: grdr_wire::peer_auth::Profile,
    _service_names: &[&str],
    _pre_scm: &[Option<ScmServiceProbe>],
) -> Result<WindowsPeerClaims, crate::PeerError> {
    Err(crate::PeerError::Unverifiable(
        "Windows pipe peer checks unavailable on non-Windows host".to_string(),
    ))
}
