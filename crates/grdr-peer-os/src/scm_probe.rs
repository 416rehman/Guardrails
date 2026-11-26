// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Read-only Windows Service Control Manager (SCM) process probe for server peer authentication
//! (`ADR-0051`, without pulling `grdr-os-service` into `grdr-peer-os` / `grdr-hook`).

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScmServiceProbe {
    pub state_code: u32,
    pub pid: Option<u32>,
    pub running: bool,
}

const MAX_SERVICE_NAME_LEN: usize = 256;
const WINDOWS_SID_MAX_AUTHORITY: u64 = 0x0000_FFFF_FFFF_FFFF;
const WINDOWS_SID_MAX_SUBAUTHORITIES: usize = 15;
const BROAD_SIDS: &[&str] = &["S-1-1-0", "S-1-5-7", "S-1-5-11", "S-1-5-32-545"];

pub(crate) fn validate_windows_sid(raw_sid: &str) -> Result<&str, ()> {
    let sid = raw_sid.trim();
    if BROAD_SIDS.contains(&sid) {
        return Err(());
    }
    let rest = sid.strip_prefix("S-1-").ok_or(())?;
    let mut parts = rest.split('-');
    let first = parts.next().ok_or(())?;
    let auth_ok = !first.is_empty()
        && first.bytes().all(|b| b.is_ascii_digit())
        && first
            .parse::<u64>()
            .is_ok_and(|val| val <= WINDOWS_SID_MAX_AUTHORITY);
    if !auth_ok {
        return Err(());
    }
    let mut subauth_count = 0usize;
    for part in parts {
        if part.is_empty()
            || !part.bytes().all(|b| b.is_ascii_digit())
            || part.parse::<u32>().is_err()
        {
            return Err(());
        }
        subauth_count = subauth_count.saturating_add(1);
    }
    if subauth_count == 0 || subauth_count > WINDOWS_SID_MAX_SUBAUTHORITIES {
        return Err(());
    }
    Ok(sid)
}

fn validate_service_name(service_name: &str) -> Option<&str> {
    let trimmed = service_name.trim();
    if trimmed.is_empty()
        || trimmed.len() > MAX_SERVICE_NAME_LEN
        || service_name.contains('\0')
        || service_name.contains('\\')
        || service_name.contains('/')
    {
        return None;
    }
    Some(trimmed)
}

#[cfg(windows)]
mod win_scm_probe {
    use std::ptr::null;

    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_HANDLE,
        SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_RUNNING,
        SERVICE_STATUS_PROCESS,
    };

    use super::{ScmServiceProbe, validate_service_name};

    struct ScopedScHandle(SC_HANDLE);

    impl Drop for ScopedScHandle {
        #[allow(unsafe_code, reason = "Closes Win32 SC_HANDLE owned by ScopedScHandle")]
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` is an open non-null handle returned by OpenSCManagerW/OpenServiceW.
                unsafe {
                    CloseServiceHandle(self.0);
                }
            }
        }
    }

    #[allow(
        unsafe_code,
        reason = "OpenSCManagerW, OpenServiceW, and QueryServiceStatusEx query SCM service PID"
    )]
    pub(crate) fn query_service_process(service_name: &str) -> Option<ScmServiceProbe> {
        let name = validate_service_name(service_name)?;
        // SAFETY: null database and machine strings open local active SCM with connect access.
        let scm_raw = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT) };
        if scm_raw.is_null() {
            return None;
        }
        let _scm = ScopedScHandle(scm_raw);
        let mut wide_name: Vec<u16> = name.encode_utf16().collect();
        wide_name.push(0);
        // SAFETY: `scm_raw` is valid and `wide_name` is NUL-terminated UTF-16.
        let svc_raw = unsafe { OpenServiceW(scm_raw, wide_name.as_ptr(), SERVICE_QUERY_STATUS) };
        if svc_raw.is_null() {
            return None;
        }
        let _svc = ScopedScHandle(svc_raw);
        let mut ssp = SERVICE_STATUS_PROCESS {
            dwServiceType: 0,
            dwCurrentState: 0,
            dwControlsAccepted: 0,
            dwWin32ExitCode: 0,
            dwServiceSpecificExitCode: 0,
            dwCheckPoint: 0,
            dwWaitHint: 0,
            dwProcessId: 0,
            dwServiceFlags: 0,
        };
        let mut needed: u32 = 0;
        let struct_size = u32::try_from(std::mem::size_of::<SERVICE_STATUS_PROCESS>()).unwrap_or(0);
        // SAFETY: `ssp` is stack storage sized to `SERVICE_STATUS_PROCESS`.
        let ok = unsafe {
            QueryServiceStatusEx(
                svc_raw,
                SC_STATUS_PROCESS_INFO,
                (&raw mut ssp).cast::<u8>(),
                struct_size,
                &mut needed,
            )
        };
        if ok == 0 || needed < struct_size {
            return None;
        }
        Some(ScmServiceProbe {
            state_code: ssp.dwCurrentState,
            pid: (ssp.dwProcessId != 0).then_some(ssp.dwProcessId),
            running: ssp.dwCurrentState == SERVICE_RUNNING,
        })
    }
}

#[cfg(windows)]
pub fn probe_scm_services(service_names: &[&str]) -> Vec<Option<ScmServiceProbe>> {
    service_names
        .iter()
        .map(|&svc| win_scm_probe::query_service_process(svc))
        .collect()
}

#[cfg(not(windows))]
pub fn probe_scm_services(service_names: &[&str]) -> Vec<Option<ScmServiceProbe>> {
    let _ = service_names
        .iter()
        .all(|s| validate_service_name(s).is_some());
    Vec::new()
}
