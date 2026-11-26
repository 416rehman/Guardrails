// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, FALSE, GetLastError, HANDLE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows_sys::Win32::Security::{
    CreateRestrictedToken, DISABLE_MAX_PRIVILEGE, FreeSid, GetTokenInformation, LUA_TOKEN, PSID,
    SID_AND_ATTRIBUTES, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_ELEVATION_TYPE, TOKEN_QUERY,
    TokenElevationType, TokenElevationTypeFull, WRITE_RESTRICTED,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_LIMIT_PROCESS_MEMORY, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectExtendedLimitInformation, SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_SET_QUOTA, PROCESS_TERMINATE,
};

use crate::WindowsSensorError;
use crate::containment::{JobObjectPlan, WriteRestrictedTokenPlan};
use crate::win_containment::AppContainerProvisioned;

const HRESULT_ALREADY_EXISTS: i32 = 0x8007_00b7_u32 as i32;

#[derive(Debug)]
pub(crate) struct WinJobHandle {
    owned: OwnedHandle,
}

#[derive(Debug)]
pub(crate) struct WinRestrictedToken {
    owned: OwnedHandle,
}

struct LocalSidGuard {
    sid: PSID,
}

struct AppContainerSidGuard {
    sid: PSID,
}

#[derive(Debug)]
pub(crate) struct WinSecurityCapabilities {
    app_container_sid: PSID,
}

impl Drop for LocalSidGuard {
    fn drop(&mut self) {
        if !self.sid.is_null() {
            #[allow(
                unsafe_code,
                reason = "Release SID buffer allocated by ConvertStringSidToSidW."
            )]
            // SAFETY: self.sid was allocated by ConvertStringSidToSidW and freed once via LocalFree.
            unsafe {
                let _ = LocalFree(self.sid);
            }
            self.sid = null_mut();
        }
    }
}

impl Drop for AppContainerSidGuard {
    fn drop(&mut self) {
        if !self.sid.is_null() {
            #[allow(unsafe_code, reason = "Release AppContainer SID via FreeSid.")]
            // SAFETY: self.sid came from CreateAppContainerProfile or DeriveAppContainerSidFromAppContainerName.
            unsafe {
                let _ = FreeSid(self.sid);
            }
            self.sid = null_mut();
        }
    }
}

impl WinJobHandle {
    pub(crate) fn from_plan(plan: &JobObjectPlan) -> Result<Self, WindowsSensorError> {
        let wide_name = encode_utf16_nul(&plan.job_name)?;
        #[allow(
            unsafe_code,
            reason = "Create Win32 Job Object and check GetLastError for duplicate job name."
        )]
        // SAFETY: wide_name is NUL-terminated UTF-16 matching CreateJobObjectW contract.
        let (raw_job, last_err) = unsafe {
            let h = CreateJobObjectW(null(), wide_name.as_ptr());
            (h, GetLastError())
        };
        if raw_job.is_null() {
            return Err(WindowsSensorError::Containment(format!(
                "CreateJobObjectW failed for `{}`",
                plan.job_name
            )));
        }
        #[allow(unsafe_code, reason = "Wrap Job Object HANDLE in RAII OwnedHandle.")]
        // SAFETY: raw_job was verified non-null immediately above.
        let owned = unsafe { OwnedHandle::from_raw_handle(raw_job as RawHandle) };
        if last_err == ERROR_ALREADY_EXISTS {
            return Err(WindowsSensorError::Containment(format!(
                "Job Object `{}` already exists; refusing to alias",
                plan.job_name
            )));
        }
        let mem_bytes = usize::try_from(plan.memory_limit_bytes).unwrap_or(usize::MAX);

        let mut flags = JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        if plan.kill_on_close {
            flags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        }
        if plan.active_process_limit.is_some() {
            flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        }

        #[allow(unsafe_code, reason = "Initialize Win32 extended job limit struct.")]
        // SAFETY: Zeroed JOBOBJECT_EXTENDED_LIMIT_INFORMATION matches expected Windows layout.
        let info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe {
            let mut st: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            st.BasicLimitInformation.LimitFlags = flags;
            st.BasicLimitInformation.ActiveProcessLimit = plan.active_process_limit.unwrap_or(0);
            st.ProcessMemoryLimit = mem_bytes;
            st.JobMemoryLimit = mem_bytes;
            st
        };
        let info_size =
            u32::try_from(std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()).unwrap_or(0);
        #[allow(unsafe_code, reason = "Apply extended limits to Win32 Job Object.")]
        // SAFETY: owned handle is valid and info points to initialized stack memory.
        let ok = unsafe {
            SetInformationJobObject(
                owned.as_raw_handle() as HANDLE,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const core::ffi::c_void,
                info_size,
            )
        };
        if ok == 0 {
            return Err(WindowsSensorError::Containment(
                "SetInformationJobObject failed".to_string(),
            ));
        }
        Ok(Self { owned })
    }

    pub(crate) fn assign_process(&self, pid: u32) -> Result<(), WindowsSensorError> {
        if pid == 0 {
            return Err(WindowsSensorError::Containment(
                "cannot assign pid 0 to Job Object".to_string(),
            ));
        }
        #[allow(
            unsafe_code,
            reason = "Open target process handle for Job Object assignment."
        )]
        // SAFETY: OpenProcess returns null on denial or nonexistent process.
        let raw_proc = unsafe { OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, FALSE, pid) };
        if raw_proc.is_null() {
            return Err(WindowsSensorError::Containment(format!(
                "OpenProcess denied or exited for pid {pid}"
            )));
        }
        #[allow(unsafe_code, reason = "Wrap process HANDLE in RAII OwnedHandle.")]
        // SAFETY: raw_proc was verified non-null immediately above.
        let proc_guard = unsafe { OwnedHandle::from_raw_handle(raw_proc as RawHandle) };
        #[allow(unsafe_code, reason = "Assign target process to Job Object.")]
        // SAFETY: Both self.owned and proc_guard hold live Win32 handles.
        let ok = unsafe {
            AssignProcessToJobObject(
                self.owned.as_raw_handle() as HANDLE,
                proc_guard.as_raw_handle() as HANDLE,
            )
        };
        if ok == 0 {
            return Err(WindowsSensorError::Containment(format!(
                "AssignProcessToJobObject failed for pid {pid}"
            )));
        }
        Ok(())
    }

    pub(crate) fn terminate(&self, exit_code: u32) -> Result<(), WindowsSensorError> {
        #[allow(unsafe_code, reason = "Terminate all processes inside Job Object.")]
        // SAFETY: self.owned holds an active Job Object handle.
        let ok = unsafe { TerminateJobObject(self.owned.as_raw_handle() as HANDLE, exit_code) };
        if ok == 0 {
            return Err(WindowsSensorError::Containment(
                "TerminateJobObject failed".to_string(),
            ));
        }
        Ok(())
    }
}

impl WinRestrictedToken {
    pub(crate) fn from_plan(plan: &WriteRestrictedTokenPlan) -> Result<Self, WindowsSensorError> {
        if plan.sandbox_sid.starts_with("S-1-15-") {
            return Err(WindowsSensorError::Containment(format!(
                "AppContainer SID `{}` requires WinSecurityCapabilitiesHandle rather than CreateRestrictedToken",
                plan.sandbox_sid
            )));
        }
        let mut current_token: HANDLE = null_mut();
        #[allow(
            unsafe_code,
            reason = "Open current process token for restricted token creation."
        )]
        // SAFETY: GetCurrentProcess returns pseudo-handle; current_token receives valid token handle.
        let open_ok = unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY,
                &mut current_token,
            )
        };
        if open_ok == 0 || current_token.is_null() {
            return Err(WindowsSensorError::Containment(
                "OpenProcessToken failed for restricted token".to_string(),
            ));
        }
        #[allow(unsafe_code, reason = "Wrap current token HANDLE in RAII OwnedHandle.")]
        // SAFETY: current_token was verified non-null immediately above.
        let cur_guard = unsafe { OwnedHandle::from_raw_handle(current_token as RawHandle) };

        let sid_wide = encode_utf16_nul(&plan.sandbox_sid)?;
        let mut raw_sid: PSID = null_mut();
        #[allow(
            unsafe_code,
            reason = "Parse sandbox SID string for write-restricted token."
        )]
        // SAFETY: sid_wide is NUL-terminated UTF-16 and raw_sid receives LocalAlloc SID buffer.
        let sid_ok = unsafe { ConvertStringSidToSidW(sid_wide.as_ptr(), &mut raw_sid) };
        if sid_ok == 0 || raw_sid.is_null() {
            return Err(WindowsSensorError::Containment(format!(
                "invalid sandbox SID `{}`",
                plan.sandbox_sid
            )));
        }
        let sid_guard = LocalSidGuard { sid: raw_sid };

        let mut elev_type: TOKEN_ELEVATION_TYPE = 0;
        let mut elev_len: u32 = 0;
        let elev_size = u32::try_from(std::mem::size_of::<TOKEN_ELEVATION_TYPE>()).unwrap_or(4);
        #[allow(
            unsafe_code,
            reason = "Query TokenElevationType upfront before setting LUA_TOKEN."
        )]
        // SAFETY: cur_guard holds a valid TOKEN_QUERY token and elev_type fits elev_size bytes.
        let elev_ok = unsafe {
            GetTokenInformation(
                cur_guard.as_raw_handle() as HANDLE,
                TokenElevationType,
                (&mut elev_type as *mut TOKEN_ELEVATION_TYPE).cast(),
                elev_size,
                &mut elev_len,
            )
        };
        if elev_ok == 0 {
            return Err(WindowsSensorError::Containment(format!(
                "GetTokenInformation(TokenElevationType) failed ({})",
                std::io::Error::last_os_error()
            )));
        }

        let restrict_sids = [SID_AND_ATTRIBUTES {
            Sid: sid_guard.sid,
            Attributes: 0,
        }];
        let mut base_flags = WRITE_RESTRICTED;
        if plan.deny_elevate {
            base_flags |= DISABLE_MAX_PRIVILEGE;
            if elev_type == TokenElevationTypeFull {
                base_flags |= LUA_TOKEN;
            }
        }

        let mut new_token: HANDLE = null_mut();
        #[allow(unsafe_code, reason = "Create Win32 write-restricted access token.")]
        // SAFETY: cur_guard and restrict_sids remain alive across CreateRestrictedToken.
        let res_ok = unsafe {
            CreateRestrictedToken(
                cur_guard.as_raw_handle() as HANDLE,
                base_flags,
                0,
                null(),
                0,
                null(),
                1,
                restrict_sids.as_ptr(),
                &mut new_token,
            )
        };
        if res_ok == 0 || new_token.is_null() {
            return Err(WindowsSensorError::Containment(format!(
                "CreateRestrictedToken failed ({})",
                std::io::Error::last_os_error()
            )));
        }
        #[allow(
            unsafe_code,
            reason = "Wrap derived restricted token HANDLE in OwnedHandle."
        )]
        // SAFETY: new_token was verified non-null immediately above.
        let owned = unsafe { OwnedHandle::from_raw_handle(new_token as RawHandle) };
        Ok(Self { owned })
    }

    pub(crate) fn is_valid(&self) -> bool {
        !self.owned.as_raw_handle().is_null()
    }
}

#[allow(
    unsafe_code,
    reason = "Owned LocalAlloc AppContainer PSID is immutable across threads."
)]
// SAFETY: app_container_sid is uniquely owned and released once via LocalFree in Drop.
unsafe impl Send for WinSecurityCapabilities {}

#[allow(
    unsafe_code,
    reason = "Owned LocalAlloc AppContainer PSID supports shared immutable pointer reads."
)]
// SAFETY: app_container_sid is immutable after construction and only freed in Drop.
unsafe impl Sync for WinSecurityCapabilities {}

impl Drop for WinSecurityCapabilities {
    fn drop(&mut self) {
        if !self.app_container_sid.is_null() {
            #[allow(unsafe_code, reason = "Release LocalAlloc AppContainer PSID.")]
            // SAFETY: app_container_sid came from ConvertStringSidToSidW and is freed once.
            unsafe {
                let _ = LocalFree(self.app_container_sid);
            }
            self.app_container_sid = null_mut();
        }
    }
}

impl WinSecurityCapabilities {
    pub(crate) fn from_app_container_sid(sid_str: &str) -> Result<Self, WindowsSensorError> {
        if !sid_str.starts_with("S-1-15-") {
            return Err(WindowsSensorError::Containment(format!(
                "Win32 AppContainer SECURITY_CAPABILITIES requires S-1-15-* SID, got `{sid_str}`"
            )));
        }
        let sid_wide = encode_utf16_nul(sid_str)?;
        let mut raw_sid: PSID = null_mut();
        #[allow(
            unsafe_code,
            reason = "Parse AppContainer SID string into binary PSID for SECURITY_CAPABILITIES."
        )]
        // SAFETY: sid_wide is NUL-terminated UTF-16 and raw_sid receives LocalAlloc SID buffer.
        let ok = unsafe { ConvertStringSidToSidW(sid_wide.as_ptr(), &mut raw_sid) };
        if ok == 0 || raw_sid.is_null() {
            return Err(WindowsSensorError::Containment(format!(
                "ConvertStringSidToSidW failed for `{sid_str}`"
            )));
        }
        Ok(Self {
            app_container_sid: raw_sid,
        })
    }

    pub(crate) fn app_container_sid_ptr(&self) -> PSID {
        self.app_container_sid
    }
}

pub(crate) fn provision_win_app_container(
    profile_name: &str,
    display_name: &str,
    description: &str,
) -> Result<AppContainerProvisioned, WindowsSensorError> {
    let wide_name = encode_utf16_nul(profile_name)?;
    let wide_disp = encode_utf16_nul(display_name)?;
    let wide_desc = encode_utf16_nul(description)?;
    let mut sid: PSID = null_mut();

    #[allow(unsafe_code, reason = "Create Windows AppContainer isolation profile.")]
    // SAFETY: All strings are NUL-terminated UTF-16 and sid receives profile SID on S_OK.
    let hr = unsafe {
        CreateAppContainerProfile(
            wide_name.as_ptr(),
            wide_disp.as_ptr(),
            wide_desc.as_ptr(),
            null(),
            0,
            &mut sid,
        )
    };
    let sid_guard = if hr == 0 && !sid.is_null() {
        AppContainerSidGuard { sid }
    } else if hr == HRESULT_ALREADY_EXISTS
        || hr == i32::from_ne_bytes((0x8007_0000_u32 | ERROR_ALREADY_EXISTS).to_ne_bytes())
    {
        let mut derived: PSID = null_mut();
        #[allow(unsafe_code, reason = "Derive existing Windows AppContainer SID.")]
        let d_hr = {
            // SAFETY: wide_name is NUL-terminated UTF-16 and derived receives profile SID.
            unsafe { DeriveAppContainerSidFromAppContainerName(wide_name.as_ptr(), &mut derived) }
        };
        if d_hr != 0 || derived.is_null() {
            return Err(WindowsSensorError::Containment(format!(
                "DeriveAppContainerSidFromAppContainerName failed (0x{d_hr:08x})"
            )));
        }
        AppContainerSidGuard { sid: derived }
    } else {
        return Err(WindowsSensorError::Containment(format!(
            "CreateAppContainerProfile failed (0x{hr:08x})"
        )));
    };

    let sid_string = sid_to_string(sid_guard.sid)?;
    Ok(AppContainerProvisioned {
        profile_name: profile_name.to_string(),
        sid_string,
    })
}

pub(crate) fn delete_win_app_container(profile_name: &str) -> Result<(), WindowsSensorError> {
    let wide = encode_utf16_nul(profile_name)?;
    #[allow(unsafe_code, reason = "Remove Windows AppContainer isolation profile.")]
    // SAFETY: wide is NUL-terminated UTF-16 profile name.
    let hr = unsafe { DeleteAppContainerProfile(wide.as_ptr()) };
    if hr != 0 && hr != i32::from_ne_bytes(0x8007_0002_u32.to_ne_bytes()) {
        return Err(WindowsSensorError::Containment(format!(
            "DeleteAppContainerProfile failed (0x{hr:08x})"
        )));
    }
    Ok(())
}

fn sid_to_string(sid: PSID) -> Result<String, WindowsSensorError> {
    let mut raw_str: windows_sys::core::PWSTR = null_mut();
    #[allow(unsafe_code, reason = "Format binary Win32 SID into SDDL string.")]
    // SAFETY: sid is non-null PSID and raw_str receives LocalAlloc UTF-16 string.
    let ok = unsafe { ConvertSidToStringSidW(sid, &mut raw_str) };
    if ok == 0 || raw_str.is_null() {
        return Err(WindowsSensorError::Containment(
            "ConvertSidToStringSidW failed".to_string(),
        ));
    }
    let mut len = 0usize;
    while len < 512 {
        #[allow(unsafe_code, reason = "Measure NUL-terminated SID string length.")]
        // SAFETY: raw_str is NUL-terminated UTF-16 string allocated by ConvertSidToStringSidW.
        let ch = unsafe { *raw_str.add(len) };
        if ch == 0 {
            break;
        }
        len = len.saturating_add(1);
    }
    #[allow(unsafe_code, reason = "Convert Win32 SID UTF-16 slice to Rust String.")]
    // SAFETY: Verified NUL-terminated slice of len UTF-16 units; freed immediately after copying.
    let formatted = unsafe {
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(raw_str, len));
        let _ = LocalFree(raw_str as *mut core::ffi::c_void);
        s
    };
    Ok(formatted)
}

pub(crate) fn encode_utf16_nul(value: &str) -> Result<Vec<u16>, WindowsSensorError> {
    if value.trim().is_empty() || value.chars().any(|c| c == '\0') {
        return Err(WindowsSensorError::Containment(
            "Win32 containment string must be non-empty and NUL-free".to_string(),
        ));
    }
    let mut out: Vec<u16> = value.encode_utf16().collect();
    out.push(0);
    Ok(out)
}
