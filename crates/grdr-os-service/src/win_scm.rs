// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Win32 Service Control Manager (SCM) status query, demand-start, and handler bridge.

use crate::ServiceError;

const MAX_SERVICE_NAME_LEN: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScmState {
    StartPending,
    Running,
    StopPending,
    Stopped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScmServiceProbe {
    pub state_code: u32,
    pub pid: Option<u32>,
    pub running: bool,
}

fn validate_service_name(service_name: &str) -> Result<&str, ServiceError> {
    let trimmed = service_name.trim();
    if trimmed.is_empty()
        || trimmed.len() > MAX_SERVICE_NAME_LEN
        || service_name.contains('\0')
        || service_name.contains('\\')
        || service_name.contains('/')
    {
        return Err(ServiceError::NotifyFailed(
            "invalid SCM service name".to_string(),
        ));
    }
    Ok(trimmed)
}

#[cfg(windows)]
mod win_impl {
    use std::ffi::c_void;
    use std::ptr::{null, null_mut};
    use std::sync::atomic::{AtomicPtr, AtomicU32, Ordering};
    use std::time::{Duration, Instant};

    use windows_sys::Win32::Foundation::{
        ERROR_CALL_NOT_IMPLEMENTED, ERROR_SERVICE_ALREADY_RUNNING, ERROR_SERVICE_DOES_NOT_EXIST,
        GetLastError, NO_ERROR,
    };
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx,
        RegisterServiceCtrlHandlerExW, SC_HANDLE, SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO,
        SERVICE_ACCEPT_PARAMCHANGE, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
        SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_PARAMCHANGE, SERVICE_CONTROL_SHUTDOWN,
        SERVICE_CONTROL_STOP, SERVICE_PAUSED, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START,
        SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STATUS_PROCESS,
        SERVICE_STOP_PENDING, SERVICE_STOPPED, SERVICE_WIN32_OWN_PROCESS, SetServiceStatus,
        StartServiceW,
    };

    use super::{ScmServiceProbe, ScmState, validate_service_name};
    use crate::ServiceError;
    use crate::unix_control::{request_reload, request_shutdown};

    const MAX_DEMAND_START_MS: u64 = 60_000;

    static ACTIVE_STATUS_HANDLE: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
    static CHECKPOINT_COUNTER: AtomicU32 = AtomicU32::new(1);

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

    fn to_wide_nul(s: &str) -> Vec<u16> {
        let mut out: Vec<u16> = s.encode_utf16().collect();
        out.push(0);
        out
    }

    #[allow(
        unsafe_code,
        reason = "OpenSCManagerW and OpenServiceW require Win32 SCM FFI"
    )]
    pub fn query_service_process(
        service_name: &str,
    ) -> Result<Option<ScmServiceProbe>, ServiceError> {
        let name = validate_service_name(service_name)?;
        // SAFETY: null database and machine strings open local active SCM.
        let scm_raw = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT) };
        if scm_raw.is_null() {
            return Err(ServiceError::NotifyFailed(format!(
                "OpenSCManagerW failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        let _scm = ScopedScHandle(scm_raw);
        let wide_name = to_wide_nul(name);
        // SAFETY: `scm_raw` is valid and `wide_name` is NUL-terminated UTF-16.
        let svc_raw = unsafe { OpenServiceW(scm_raw, wide_name.as_ptr(), SERVICE_QUERY_STATUS) };
        if svc_raw.is_null() {
            // SAFETY: GetLastError has no safety preconditions.
            let err = unsafe { GetLastError() };
            if err == ERROR_SERVICE_DOES_NOT_EXIST {
                return Ok(None);
            }
            return Err(ServiceError::NotifyFailed(format!(
                "OpenServiceW failed with win32 error {err}"
            )));
        }
        let _svc = ScopedScHandle(svc_raw);
        query_handle_status(svc_raw, name).map(Some)
    }

    #[allow(
        unsafe_code,
        reason = "OpenSCManagerW, OpenServiceW, and StartServiceW require Win32 SCM FFI"
    )]
    pub fn demand_start_service(service_name: &str, timeout_ms: u64) -> Result<u32, ServiceError> {
        let name = validate_service_name(service_name)?;
        // SAFETY: opens local SCM cleanly.
        let scm_raw = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT) };
        if scm_raw.is_null() {
            return Err(ServiceError::NotifyFailed(format!(
                "OpenSCManagerW failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        let _scm = ScopedScHandle(scm_raw);
        let wide_name = to_wide_nul(name);
        // SAFETY: `wide_name` is NUL-terminated UTF-16.
        let svc_raw = unsafe {
            OpenServiceW(
                scm_raw,
                wide_name.as_ptr(),
                SERVICE_QUERY_STATUS | SERVICE_START,
            )
        };
        if svc_raw.is_null() {
            return Err(ServiceError::NotifyFailed(format!(
                "OpenServiceW failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        let _svc = ScopedScHandle(svc_raw);

        let initial = query_handle_status(svc_raw, name)?;
        if initial.running
            && let Some(pid) = initial.pid
        {
            return Ok(pid);
        }
        if initial.state_code == SERVICE_STOP_PENDING || initial.state_code == SERVICE_PAUSED {
            return Err(ServiceError::NotifyFailed(
                "SCM service cannot demand-start while stopping or paused".to_string(),
            ));
        }
        if initial.state_code == SERVICE_STOPPED {
            // SAFETY: valid handle opened with SERVICE_START.
            let ok = unsafe { StartServiceW(svc_raw, 0, null()) };
            if ok == 0 {
                // SAFETY: GetLastError has no safety preconditions.
                let err = unsafe { GetLastError() };
                if err != ERROR_SERVICE_ALREADY_RUNNING {
                    return Err(ServiceError::NotifyFailed(format!(
                        "StartServiceW failed with win32 error {err}"
                    )));
                }
            }
        }

        let start = Instant::now();
        let max_wait = Duration::from_millis(timeout_ms.clamp(100, MAX_DEMAND_START_MS));
        loop {
            let status = query_handle_status(svc_raw, name)?;
            if status.running
                && let Some(pid) = status.pid
            {
                return Ok(pid);
            }
            if status.state_code == SERVICE_STOP_PENDING || status.state_code == SERVICE_PAUSED {
                return Err(ServiceError::NotifyFailed(
                    "SCM service entered stop-pending or paused during start".to_string(),
                ));
            }
            if start.elapsed() >= max_wait {
                return Err(ServiceError::NotifyFailed(format!(
                    "timed out waiting {} ms for SCM service",
                    max_wait.as_millis()
                )));
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    #[allow(
        unsafe_code,
        reason = "RegisterServiceCtrlHandlerExW registers Win32 SCM callback"
    )]
    pub fn register_scm_handler(service_name: &str) -> Result<(), ServiceError> {
        let name = validate_service_name(service_name)?;
        let wide_name = to_wide_nul(name);
        // SAFETY: `wide_name` is NUL-terminated UTF-16 and `scm_control_callback` matches LPHANDLER_FUNCTION_EX.
        let handle = unsafe {
            RegisterServiceCtrlHandlerExW(wide_name.as_ptr(), Some(scm_control_callback), null())
        };
        if handle.is_null() {
            return Err(ServiceError::NotifyFailed(format!(
                "RegisterServiceCtrlHandlerExW failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        CHECKPOINT_COUNTER.store(1, Ordering::SeqCst);
        ACTIVE_STATUS_HANDLE.store(handle, Ordering::SeqCst);
        Ok(())
    }

    #[allow(unsafe_code, reason = "SetServiceStatus notifies Win32 SCM")]
    pub fn report_scm_state(state: ScmState, exit_code: u32) -> Result<(), ServiceError> {
        let handle: SERVICE_STATUS_HANDLE = ACTIVE_STATUS_HANDLE.load(Ordering::SeqCst);
        if handle.is_null() {
            return Ok(());
        }
        let current_state = match state {
            ScmState::StartPending => SERVICE_START_PENDING,
            ScmState::Running => SERVICE_RUNNING,
            ScmState::StopPending => SERVICE_STOP_PENDING,
            ScmState::Stopped => SERVICE_STOPPED,
        };
        let controls = if state == ScmState::Running {
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_PARAMCHANGE
        } else {
            0
        };
        let check_point = if matches!(state, ScmState::StartPending | ScmState::StopPending) {
            CHECKPOINT_COUNTER.fetch_add(1, Ordering::SeqCst)
        } else {
            CHECKPOINT_COUNTER.store(1, Ordering::SeqCst);
            0
        };
        let status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: current_state,
            dwControlsAccepted: controls,
            dwWin32ExitCode: exit_code,
            dwServiceSpecificExitCode: 0,
            dwCheckPoint: check_point,
            dwWaitHint: if matches!(state, ScmState::StartPending | ScmState::StopPending) {
                2000
            } else {
                0
            },
        };
        // SAFETY: `handle` came from `RegisterServiceCtrlHandlerExW` and `status` stays pinned on stack.
        let ok = unsafe { SetServiceStatus(handle, &status) };
        if ok == 0 {
            return Err(ServiceError::NotifyFailed(format!(
                "SetServiceStatus failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        if state == ScmState::Stopped {
            ACTIVE_STATUS_HANDLE.store(null_mut(), Ordering::SeqCst);
        }
        Ok(())
    }

    #[allow(unsafe_code, reason = "QueryServiceStatusEx queries Win32 service PID")]
    fn query_handle_status(
        svc_raw: SC_HANDLE,
        _service_name: &str,
    ) -> Result<ScmServiceProbe, ServiceError> {
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
        // SAFETY: `ssp` is stack-allocated storage sized to `SERVICE_STATUS_PROCESS`.
        let ok = unsafe {
            QueryServiceStatusEx(
                svc_raw,
                SC_STATUS_PROCESS_INFO,
                (&raw mut ssp).cast::<u8>(),
                struct_size,
                &mut needed,
            )
        };
        if ok == 0 {
            return Err(ServiceError::NotifyFailed(format!(
                "QueryServiceStatusEx failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        if needed < struct_size {
            return Err(ServiceError::NotifyFailed(
                "QueryServiceStatusEx returned truncated status bytes".to_string(),
            ));
        }
        Ok(ScmServiceProbe {
            state_code: ssp.dwCurrentState,
            pid: (ssp.dwProcessId != 0).then_some(ssp.dwProcessId),
            running: ssp.dwCurrentState == SERVICE_RUNNING,
        })
    }

    #[allow(unsafe_code, reason = "Win32 SCM LPHANDLER_FUNCTION_EX ABI")]
    unsafe extern "system" fn scm_control_callback(
        control: u32,
        _event_type: u32,
        _event_data: *mut c_void,
        _context: *mut c_void,
    ) -> u32 {
        match control {
            SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
                request_shutdown();
                NO_ERROR
            }
            SERVICE_CONTROL_PARAMCHANGE => {
                request_reload();
                NO_ERROR
            }
            SERVICE_CONTROL_INTERROGATE => NO_ERROR,
            _ => ERROR_CALL_NOT_IMPLEMENTED,
        }
    }
}

#[cfg(windows)]
pub use win_impl::{
    demand_start_service, query_service_process, register_scm_handler, report_scm_state,
};

#[cfg(not(windows))]
pub fn query_service_process(service_name: &str) -> Result<Option<ScmServiceProbe>, ServiceError> {
    let _ = validate_service_name(service_name)?;
    Ok(None)
}

#[cfg(not(windows))]
pub fn demand_start_service(service_name: &str, _timeout_ms: u64) -> Result<u32, ServiceError> {
    let name = validate_service_name(service_name)?;
    Err(ServiceError::NotifyFailed(format!(
        "Win32 SCM demand-start unavailable on non-Windows host for '{name}'"
    )))
}

#[cfg(not(windows))]
pub fn register_scm_handler(service_name: &str) -> Result<(), ServiceError> {
    let _ = validate_service_name(service_name)?;
    Ok(())
}

#[cfg(not(windows))]
pub fn report_scm_state(_state: ScmState, _exit_code: u32) -> Result<(), ServiceError> {
    Ok(())
}
