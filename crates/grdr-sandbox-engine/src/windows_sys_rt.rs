// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#![deny(clippy::arithmetic_side_effects)]

#[cfg(windows)]
use std::ffi::c_void;
#[cfg(windows)]
use std::mem::size_of;
#[cfg(windows)]
use std::ptr::{null, null_mut};

#[cfg(windows)]
use windows_sys::Win32::Foundation::{
    CloseHandle, FALSE, GetHandleInformation, GetLastError, HANDLE, HANDLE_FLAG_INHERIT,
    INVALID_HANDLE_VALUE, STILL_ACTIVE, TRUE, WAIT_OBJECT_0,
};
#[cfg(windows)]
use windows_sys::Win32::Security::{
    CreateRestrictedToken, DISABLE_MAX_PRIVILEGE, LUA_TOKEN, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE,
    TOKEN_QUERY,
};
#[cfg(windows)]
use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
#[cfg(windows)]
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_JOB_MEMORY,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_UILIMIT_DESKTOP,
    JOB_OBJECT_UILIMIT_DISPLAYSETTINGS, JOB_OBJECT_UILIMIT_EXITWINDOWS,
    JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_HANDLES, JOB_OBJECT_UILIMIT_READCLIPBOARD,
    JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS, JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
    JOBOBJECT_BASIC_UI_RESTRICTIONS, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectBasicUIRestrictions, JobObjectExtendedLimitInformation, SetInformationJobObject,
};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW, CreateProcessW,
    DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess,
    GetExitCodeProcess, INFINITE, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
    OpenProcessToken, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
    PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess,
    UpdateProcThreadAttribute, WaitForSingleObject,
};
#[cfg(windows)]
use windows_sys::Win32::System::WindowsProgramming::{
    PROCESS_CREATION_MITIGATION_POLICY_DEP_ATL_THUNK_ENABLE,
    PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE, PROCESS_CREATION_MITIGATION_POLICY_SEHOP_ENABLE,
};

use crate::SandboxError;
use crate::policy::{EnforcedMechanism, WindowsTokenMode};

#[cfg(windows)]
struct ScopedWinHandle(HANDLE);

#[cfg(windows)]
struct ScopedAttrList {
    buffer: Vec<u64>,
}

#[cfg(windows)]
impl Drop for ScopedWinHandle {
    #[allow(unsafe_code, reason = "close owned Win32 HANDLE on drop")]
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: self.0 is a valid Win32 handle owned exclusively by this guard.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

#[cfg(windows)]
impl ScopedAttrList {
    fn list_ptr(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.buffer.as_mut_ptr().cast()
    }
}

#[cfg(windows)]
impl Drop for ScopedAttrList {
    #[allow(
        unsafe_code,
        reason = "release initialized Win32 proc thread attribute list"
    )]
    fn drop(&mut self) {
        if !self.buffer.is_empty() {
            // SAFETY: buffer was successfully initialized via InitializeProcThreadAttributeList.
            unsafe {
                DeleteProcThreadAttributeList(self.buffer.as_mut_ptr().cast());
            }
        }
    }
}

#[cfg(windows)]
#[allow(unsafe_code, reason = "read thread-local Win32 last error code")]
fn last_win32_error() -> u32 {
    // SAFETY: GetLastError has no pointer arguments or aliasing constraints.
    unsafe { GetLastError() }
}

#[cfg(windows)]
#[allow(
    unsafe_code,
    reason = "allocate and initialize Win32 proc thread attribute list with mitigation policy and optional explicit handle list"
)]
fn create_process_attr_list(
    mitigation_flags: &mut u64,
    handle_list: &mut [HANDLE],
) -> Result<(ScopedAttrList, LPPROC_THREAD_ATTRIBUTE_LIST), SandboxError> {
    let attr_count: u32 = if handle_list.is_empty() { 1 } else { 2 };
    let mut size: usize = 0;
    // SAFETY: querying attribute list buffer size by passing null pointer and exact attribute count.
    unsafe {
        InitializeProcThreadAttributeList(null_mut(), attr_count, 0, &raw mut size);
    }
    if size == 0 {
        return Err(SandboxError::ContainmentSetup(
            "InitializeProcThreadAttributeList returned zero size".into(),
        ));
    }
    let u64_words = size.div_ceil(size_of::<u64>()).max(1);
    let mut buffer = vec![0u64; u64_words];
    // SAFETY: buffer has sufficient 8-byte aligned capacity matching size returned above.
    let ok_init = unsafe {
        InitializeProcThreadAttributeList(buffer.as_mut_ptr().cast(), attr_count, 0, &raw mut size)
    };
    if ok_init == FALSE {
        return Err(SandboxError::ContainmentSetup(format!(
            "InitializeProcThreadAttributeList failed: win32 error {}",
            last_win32_error()
        )));
    }
    let mut guard = ScopedAttrList { buffer };
    let list_ptr = guard.list_ptr();
    // SAFETY: mitigation_flags outlives CreateProcess* call and size matches u64 attribute spec.
    let ok_upd = unsafe {
        UpdateProcThreadAttribute(
            list_ptr,
            0,
            PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY as usize,
            (mitigation_flags as *const u64).cast::<c_void>(),
            size_of::<u64>(),
            null_mut(),
            null(),
        )
    };
    if ok_upd == FALSE {
        return Err(SandboxError::ContainmentSetup(format!(
            "UpdateProcThreadAttribute(MITIGATION) failed: win32 error {}",
            last_win32_error()
        )));
    }
    if !handle_list.is_empty() {
        let byte_len = handle_list.len().saturating_mul(size_of::<HANDLE>());
        // SAFETY: handle_list contains deduplicated inheritable handles that outlive CreateProcess* call.
        let ok_handles = unsafe {
            UpdateProcThreadAttribute(
                list_ptr,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handle_list.as_mut_ptr().cast::<c_void>(),
                byte_len,
                null_mut(),
                null(),
            )
        };
        if ok_handles == FALSE {
            return Err(SandboxError::ContainmentSetup(format!(
                "UpdateProcThreadAttribute(HANDLE_LIST) failed: win32 error {}",
                last_win32_error()
            )));
        }
    }
    Ok((guard, list_ptr))
}

#[cfg(windows)]
#[allow(
    unsafe_code,
    reason = "create Win32 Job Object and apply KILL_ON_JOB_CLOSE, memory, active-process, and UI limits"
)]
fn create_configured_job(
    memory_limit_bytes: u64,
    active_process_limit: u32,
) -> Result<ScopedWinHandle, SandboxError> {
    // SAFETY: anonymous CreateJobObjectW allocates a fresh kernel Job Object owned by this guard.
    let raw_job = unsafe { CreateJobObjectW(null(), null()) };
    if raw_job.is_null() {
        return Err(SandboxError::ContainmentSetup(format!(
            "CreateJobObjectW failed: win32 error {}",
            last_win32_error()
        )));
    }
    let job = ScopedWinHandle(raw_job);

    let mut ext = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    let mut flags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    if memory_limit_bytes > 0 {
        flags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
        ext.JobMemoryLimit = usize::try_from(memory_limit_bytes)
            .unwrap_or(usize::MAX)
            .max(1);
    }
    if active_process_limit > 0 {
        flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        ext.BasicLimitInformation.ActiveProcessLimit = active_process_limit.max(1);
    }
    ext.BasicLimitInformation.LimitFlags = flags;

    // SAFETY: job.0 is a valid Job Object and ext points to properly initialized limit struct.
    let ok_ext = unsafe {
        SetInformationJobObject(
            job.0,
            JobObjectExtendedLimitInformation,
            (&raw const ext).cast::<c_void>(),
            u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()).unwrap_or(u32::MAX),
        )
    };
    if ok_ext == FALSE {
        return Err(SandboxError::ContainmentSetup(format!(
            "SetInformationJobObject(ExtendedLimit) failed: win32 error {}",
            last_win32_error()
        )));
    }

    let ui = JOBOBJECT_BASIC_UI_RESTRICTIONS {
        UIRestrictionsClass: JOB_OBJECT_UILIMIT_HANDLES
            | JOB_OBJECT_UILIMIT_READCLIPBOARD
            | JOB_OBJECT_UILIMIT_WRITECLIPBOARD
            | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
            | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
            | JOB_OBJECT_UILIMIT_GLOBALATOMS
            | JOB_OBJECT_UILIMIT_DESKTOP
            | JOB_OBJECT_UILIMIT_EXITWINDOWS,
    };
    // SAFETY: job.0 is valid and ui matches JOBOBJECT_BASIC_UI_RESTRICTIONS size.
    let ok_ui = unsafe {
        SetInformationJobObject(
            job.0,
            JobObjectBasicUIRestrictions,
            (&raw const ui).cast::<c_void>(),
            u32::try_from(size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>()).unwrap_or(u32::MAX),
        )
    };
    if ok_ui == FALSE {
        return Err(SandboxError::ContainmentSetup(format!(
            "SetInformationJobObject(BasicUIRestrictions) failed: win32 error {}",
            last_win32_error()
        )));
    }

    Ok(job)
}

#[cfg(windows)]
#[allow(
    unsafe_code,
    reason = "derive least-privilege restricted primary token from current process token"
)]
fn create_restricted_primary_token() -> Result<ScopedWinHandle, SandboxError> {
    let mut raw_current: HANDLE = null_mut();
    // SAFETY: GetCurrentProcess returns pseudo-handle; OpenProcessToken writes newly owned handle on TRUE.
    let ok_open = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY,
            &raw mut raw_current,
        )
    };
    if ok_open == FALSE || raw_current.is_null() {
        return Err(SandboxError::ContainmentSetup(format!(
            "OpenProcessToken failed: win32 error {}",
            last_win32_error()
        )));
    }
    let current = ScopedWinHandle(raw_current);

    let mut raw_restricted: HANDLE = null_mut();
    // SAFETY: current.0 is a valid primary token opened above; CreateRestrictedToken writes new restricted primary token.
    let ok_restr = unsafe {
        CreateRestrictedToken(
            current.0,
            DISABLE_MAX_PRIVILEGE | LUA_TOKEN,
            0,
            null(),
            0,
            null(),
            0,
            null(),
            &raw mut raw_restricted,
        )
    };
    if ok_restr == FALSE || raw_restricted.is_null() {
        return Err(SandboxError::ContainmentSetup(format!(
            "CreateRestrictedToken failed: win32 error {}",
            last_win32_error()
        )));
    }
    Ok(ScopedWinHandle(raw_restricted))
}

#[cfg(windows)]
#[allow(
    unsafe_code,
    reason = "spawn suspended Win32 process under Job Object, restricted token, explicit handle allowlist, and mitigation policy"
)]
pub(crate) fn launch_and_wait_windows_contained(
    app_utf16: Vec<u16>,
    mut cmd_utf16: Vec<u16>,
    env_utf16: Vec<u16>,
    workdir_utf16: Option<Vec<u16>>,
    memory_limit_bytes: u64,
    active_process_limit: u32,
    token_mode: WindowsTokenMode,
) -> Result<(i32, Vec<EnforcedMechanism>), SandboxError> {
    if cmd_utf16.len() <= 1 || cmd_utf16.last() != Some(&0) {
        return Err(SandboxError::EmptyProgram);
    }
    if env_utf16.len() < 2 || !env_utf16.ends_with(&[0, 0]) {
        return Err(SandboxError::InvalidPolicy(
            "Windows Unicode environment block must end with double NUL".into(),
        ));
    }
    if let Some(dir) = &workdir_utf16
        && (dir.len() <= 1 || dir.last() != Some(&0))
    {
        return Err(SandboxError::InvalidPolicy(
            "Windows working directory UTF-16 string must be non-empty and NUL-terminated".into(),
        ));
    }
    if app_utf16.len() <= 1 || app_utf16.last() != Some(&0) {
        return Err(SandboxError::InvalidPolicy(
            "Windows application path UTF-16 string must be non-empty and NUL-terminated".into(),
        ));
    }

    let job = create_configured_job(memory_limit_bytes, active_process_limit)?;
    let restricted_token = match token_mode {
        WindowsTokenMode::Restricted => Some(create_restricted_primary_token()?),
        WindowsTokenMode::StandardJobOnly => None,
    };

    // SAFETY: GetStdHandle queries caller console handles without taking ownership.
    let (h_in, h_out, h_err) = unsafe {
        (
            GetStdHandle(STD_INPUT_HANDLE),
            GetStdHandle(STD_OUTPUT_HANDLE),
            GetStdHandle(STD_ERROR_HANDLE),
        )
    };
    let mut handle_list: Vec<HANDLE> = Vec::with_capacity(3);
    for h in [h_in, h_out, h_err] {
        if h.is_null() || h == INVALID_HANDLE_VALUE {
            continue;
        }
        let mut h_flags: u32 = 0;
        // SAFETY: GetHandleInformation checks HANDLE_FLAG_INHERIT on non-null OS handle.
        let ok_info = unsafe { GetHandleInformation(h, &raw mut h_flags) };
        if ok_info != FALSE && (h_flags & HANDLE_FLAG_INHERIT) != 0 && !handle_list.contains(&h) {
            handle_list.push(h);
        }
    }
    let all_three_stdio_inheritable = !h_in.is_null()
        && h_in != INVALID_HANDLE_VALUE
        && !h_out.is_null()
        && h_out != INVALID_HANDLE_VALUE
        && !h_err.is_null()
        && h_err != INVALID_HANDLE_VALUE
        && handle_list.contains(&h_in)
        && handle_list.contains(&h_out)
        && handle_list.contains(&h_err);
    if !all_three_stdio_inheritable {
        handle_list.clear();
    }

    let mut mitigation_flags = u64::from(
        PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE
            | PROCESS_CREATION_MITIGATION_POLICY_DEP_ATL_THUNK_ENABLE
            | PROCESS_CREATION_MITIGATION_POLICY_SEHOP_ENABLE,
    );
    let (_attr_guard, attr_list) =
        create_process_attr_list(&mut mitigation_flags, &mut handle_list)?;

    let mut si = STARTUPINFOEXW::default();
    si.StartupInfo.cb = u32::try_from(size_of::<STARTUPINFOEXW>()).unwrap_or(0);
    si.lpAttributeList = attr_list;

    let inherit_handles = if !handle_list.is_empty() {
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        si.StartupInfo.hStdInput = h_in;
        si.StartupInfo.hStdOutput = h_out;
        si.StartupInfo.hStdError = h_err;
        TRUE
    } else {
        FALSE
    };

    let mut pi = PROCESS_INFORMATION::default();
    let creation_flags =
        CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT;
    let app_ptr = app_utf16.as_ptr();
    let cwd_ptr = workdir_utf16.as_ref().map_or(null(), |w| w.as_ptr());

    // SAFETY: cmd_utf16 is mutable nul-terminated UTF-16, env_utf16 is double-nul-terminated UTF-16, si.StartupInfo.cb == size_of::<STARTUPINFOEXW>(), and inherit_handles is TRUE only with PROC_THREAD_ATTRIBUTE_HANDLE_LIST.
    let spawned = unsafe {
        if let Some(tok) = &restricted_token {
            CreateProcessAsUserW(
                tok.0,
                app_ptr,
                cmd_utf16.as_mut_ptr(),
                null(),
                null(),
                inherit_handles,
                creation_flags,
                env_utf16.as_ptr().cast::<c_void>(),
                cwd_ptr,
                &raw const si.StartupInfo,
                &raw mut pi,
            )
        } else {
            CreateProcessW(
                app_ptr,
                cmd_utf16.as_mut_ptr(),
                null(),
                null(),
                inherit_handles,
                creation_flags,
                env_utf16.as_ptr().cast::<c_void>(),
                cwd_ptr,
                &raw const si.StartupInfo,
                &raw mut pi,
            )
        }
    };
    if spawned == FALSE {
        return Err(SandboxError::ProcessLaunch(format!(
            "Win32 CreateProcess failed: win32 error {}",
            last_win32_error()
        )));
    }
    let proc_guard = ScopedWinHandle(pi.hProcess);
    let thread_guard = ScopedWinHandle(pi.hThread);

    // SAFETY: proc_guard.0 is suspended child process; assigning Job Object before ResumeThread guarantees containment from first user instruction.
    let assigned = unsafe { AssignProcessToJobObject(job.0, proc_guard.0) };
    if assigned == FALSE {
        let code = last_win32_error();
        // SAFETY: terminate suspended uncontained child immediately before returning error.
        unsafe {
            TerminateProcess(proc_guard.0, 1);
        }
        return Err(SandboxError::ContainmentSetup(format!(
            "AssignProcessToJobObject failed: win32 error {code}"
        )));
    }

    // SAFETY: thread_guard.0 is suspended primary thread of the job-contained process.
    let resume_rc = unsafe { ResumeThread(thread_guard.0) };
    if resume_rc == u32::MAX {
        let code = last_win32_error();
        // SAFETY: terminate child if primary thread could not be resumed cleanly.
        unsafe {
            TerminateProcess(proc_guard.0, 1);
        }
        return Err(SandboxError::ProcessLaunch(format!(
            "ResumeThread failed: win32 error {code}"
        )));
    }

    // SAFETY: proc_guard.0 is a live owned process handle; INFINITE waits until exit.
    let wait_rc = unsafe { WaitForSingleObject(proc_guard.0, INFINITE) };
    if wait_rc != WAIT_OBJECT_0 {
        let code = last_win32_error();
        // SAFETY: terminate process if WaitForSingleObject failed unexpectedly.
        unsafe {
            TerminateProcess(proc_guard.0, 1);
        }
        return Err(SandboxError::ProcessLaunch(format!(
            "WaitForSingleObject returned {wait_rc}: win32 error {code}"
        )));
    }
    let mut exit_code: u32 = 1;
    // SAFETY: proc_guard.0 has exited and exit_code points to stack u32.
    let got_code = unsafe { GetExitCodeProcess(proc_guard.0, &raw mut exit_code) };
    if got_code == FALSE || exit_code == u32::try_from(STILL_ACTIVE).unwrap_or(259) {
        return Err(SandboxError::ProcessLaunch(format!(
            "GetExitCodeProcess invalid after wait (ok={got_code}, code={exit_code}): win32 error {}",
            last_win32_error()
        )));
    }

    let mut mechs = vec![
        EnforcedMechanism::WindowsJobObject,
        EnforcedMechanism::WindowsMitigationPolicy,
    ];
    if restricted_token.is_some() {
        mechs.push(EnforcedMechanism::WindowsRestrictedToken);
    }
    Ok((i32::try_from(exit_code).unwrap_or(1), mechs))
}
