// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Win32 kernel system process queries (`NtQuerySystemInformation`, `QueryDosDeviceW`, `ProcessIdToSessionId`, SCM).

use std::ffi::c_void;
use std::mem::size_of;
use std::ptr::{null, null_mut};

use windows_sys::Win32::System::Services::{
    CloseServiceHandle, ENUM_SERVICE_STATUS_PROCESSW, EnumServicesStatusExW, OpenSCManagerW,
    SC_ENUM_PROCESS_INFO, SC_HANDLE, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_ACTIVE, SERVICE_WIN32,
};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

use crate::PeerError;

const SYSTEM_PROCESS_INFORMATION_CLASS: u32 = 5;
const SYSTEM_PROCESS_ID_INFORMATION_CLASS: u32 = 88;
const STATUS_INFO_LENGTH_MISMATCH: i32 = -1073741820;
const ERROR_MORE_DATA: u32 = 234;
const MAX_NT_PATH_BYTES: usize = 16_384;
const MAX_PROC_LIST_BYTES: usize = 16 * 1024 * 1024;

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[repr(C)]
struct SystemProcessIdInformation {
    process_id: *mut c_void,
    image_name: UnicodeString,
}

#[repr(C)]
struct SystemProcessInfoPrefix {
    next_entry_offset: u32,
    number_of_threads: u32,
    working_set_private_size: i64,
    hard_fault_count: u32,
    number_of_threads_high_watermark: u32,
    cycle_time: u64,
    create_time: i64,
    user_time: i64,
    kernel_time: i64,
    image_name: UnicodeString,
    base_priority: i32,
    unique_process_id: usize,
    inherited_from_unique_process_id: usize,
}

struct ScopedScHandle(SC_HANDLE);

#[allow(
    unsafe_code,
    reason = "Win32 ntdll and kernel32 process query ABI bindings"
)]
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQuerySystemInformation(
        system_information_class: u32,
        system_information: *mut c_void,
        system_information_length: u32,
        return_length: *mut u32,
    ) -> i32;
}

#[allow(
    unsafe_code,
    reason = "Win32 kernel32 QueryDosDeviceW and ProcessIdToSessionId ABI bindings"
)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn ProcessIdToSessionId(dw_process_id: u32, p_session_id: *mut u32) -> i32;
    fn QueryDosDeviceW(lp_device_name: *const u16, lp_target_path: *mut u16, ucch_max: u32) -> u32;
}

impl Drop for ScopedScHandle {
    #[allow(unsafe_code, reason = "Closes Win32 SC_HANDLE owned by ScopedScHandle")]
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` was returned by `OpenSCManagerW`.
            unsafe {
                let _ = CloseServiceHandle(self.0);
            }
        }
    }
}

#[allow(unsafe_code, reason = "Win32 GetSystemDirectoryW stack UTF-16 buffer")]
pub(crate) fn system32_directory() -> Result<String, PeerError> {
    let mut buf = [0u16; 260];
    let cap = u32::try_from(buf.len()).unwrap_or(260);
    // SAFETY: `buf` is stack-local UTF-16 storage of exact capacity `cap`.
    let len = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), cap) };
    let used = usize::try_from(len)
        .ok()
        .filter(|&n| n > 0 && n < buf.len())
        .ok_or_else(|| PeerError::Unverifiable("GetSystemDirectoryW failed".to_string()))?;
    Ok(buf
        .get(..used)
        .map(String::from_utf16_lossy)
        .unwrap_or_default())
}

#[allow(unsafe_code, reason = "Win32 QueryDosDeviceW bounded UTF-16 lookup")]
pub(crate) fn query_dos_device(drive_prefix: &str) -> Result<String, PeerError> {
    let mut dev_w: Vec<u16> = drive_prefix.encode_utf16().collect();
    dev_w.push(0);
    let mut out = [0u16; 1024];
    let cap = u32::try_from(out.len()).unwrap_or(1024);
    // SAFETY: `dev_w` is NUL-terminated UTF-16 and `out` has capacity `cap`.
    let len = unsafe { QueryDosDeviceW(dev_w.as_ptr(), out.as_mut_ptr(), cap) };
    let used = usize::try_from(len)
        .ok()
        .filter(|&n| n > 0 && n <= out.len())
        .ok_or_else(|| PeerError::Unverifiable("QueryDosDeviceW failed".to_string()))?;
    let slice = out.get(..used).unwrap_or(&[]);
    let nul = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
    Ok(String::from_utf16_lossy(slice.get(..nul).unwrap_or(&[])))
}

#[allow(
    unsafe_code,
    reason = "Win32 ProcessIdToSessionId kernel session lookup"
)]
pub(crate) fn query_process_session_id(pid: u32) -> Result<u32, PeerError> {
    let mut session_id = 0u32;
    // SAFETY: `session_id` is valid stack storage for output u32.
    let ok = unsafe { ProcessIdToSessionId(pid, &mut session_id) };
    if ok == 0 {
        return Err(PeerError::Unverifiable(format!(
            "ProcessIdToSessionId({pid}) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(session_id)
}

#[allow(
    unsafe_code,
    reason = "Win32 NtQuerySystemInformation(SystemProcessIdInformation) kernel path query"
)]
pub(crate) fn query_kernel_process_image_path(pid: u32) -> Result<String, PeerError> {
    let mut buf = vec![0u16; 1024];
    for _ in 0..3 {
        let max_bytes = u16::try_from(buf.len().saturating_mul(2))
            .unwrap_or(u16::MAX)
            .min(u16::try_from(MAX_NT_PATH_BYTES).unwrap_or(u16::MAX));
        let mut info = SystemProcessIdInformation {
            process_id: std::ptr::without_provenance_mut(pid as usize),
            image_name: UnicodeString {
                length: 0,
                maximum_length: max_bytes,
                buffer: buf.as_mut_ptr(),
            },
        };
        let mut ret_len = 0u32;
        let info_sz = u32::try_from(size_of::<SystemProcessIdInformation>()).unwrap_or(24);
        // SAFETY: `info` points to bounded mutable `buf` matching `maximum_length` bytes.
        let status = unsafe {
            NtQuerySystemInformation(
                SYSTEM_PROCESS_ID_INFORMATION_CLASS,
                (&mut info as *mut SystemProcessIdInformation).cast(),
                info_sz,
                &mut ret_len,
            )
        };
        if status == STATUS_INFO_LENGTH_MISMATCH {
            let needed_units = usize::from(info.image_name.maximum_length)
                .saturating_add(1)
                .saturating_div(2)
                .min(MAX_NT_PATH_BYTES.saturating_div(2));
            if needed_units > buf.len() {
                buf.resize(needed_units, 0);
                continue;
            }
        }
        if status < 0 {
            return Err(PeerError::Unverifiable(format!(
                "NtQuerySystemInformation(SystemProcessIdInformation, {pid}) status 0x{status:08x}"
            )));
        }
        let units = usize::from(info.image_name.length)
            .saturating_div(2)
            .min(buf.len());
        return Ok(buf
            .get(..units)
            .map(String::from_utf16_lossy)
            .unwrap_or_default());
    }
    Err(PeerError::Unverifiable(format!(
        "NtQuerySystemInformation(SystemProcessIdInformation, {pid}) buffer overflow"
    )))
}

#[allow(
    unsafe_code,
    reason = "Win32 NtQuerySystemInformation(SystemProcessInformation) CreateTime lookup"
)]
pub(crate) fn kernel_process_create_time_100ns(pid: u32) -> Result<u64, PeerError> {
    let mut size = 512usize.saturating_mul(1024);
    for _ in 0..6 {
        let mut buf = vec![0u8; size];
        let mut ret_len = 0u32;
        let len_u32 = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        // SAFETY: `buf` is a contiguous writable byte allocation of exact length `len_u32`.
        let status = unsafe {
            NtQuerySystemInformation(
                SYSTEM_PROCESS_INFORMATION_CLASS,
                buf.as_mut_ptr().cast(),
                len_u32,
                &mut ret_len,
            )
        };
        if status == STATUS_INFO_LENGTH_MISMATCH {
            let next = usize::try_from(ret_len)
                .unwrap_or(size)
                .saturating_add(65_536)
                .max(size.saturating_mul(2))
                .min(MAX_PROC_LIST_BYTES);
            if next > size {
                size = next;
                continue;
            }
            return Err(PeerError::Unverifiable(
                "SystemProcessInformation exceeded 16 MiB cap".to_string(),
            ));
        }
        if status < 0 {
            return Err(PeerError::Unverifiable(format!(
                "NtQuerySystemInformation(SystemProcessInformation) status 0x{status:08x}"
            )));
        }
        let valid_len = usize::try_from(ret_len)
            .ok()
            .filter(|&n| n > 0 && n <= buf.len())
            .unwrap_or(buf.len());
        let mut offset = 0usize;
        while offset.saturating_add(size_of::<SystemProcessInfoPrefix>()) <= valid_len {
            let ptr = buf
                .as_ptr()
                .wrapping_add(offset)
                .cast::<SystemProcessInfoPrefix>();
            // SAFETY: bounds checked above against `valid_len`; `read_unaligned` handles arbitrary `NextEntryOffset`.
            let rec = unsafe { ptr.read_unaligned() };
            if rec.unique_process_id == usize::try_from(pid).unwrap_or(usize::MAX) {
                return u64::try_from(rec.create_time)
                    .ok()
                    .filter(|&t| t > 0)
                    .ok_or_else(|| {
                        PeerError::Unverifiable(format!("invalid kernel CreateTime for {pid}"))
                    });
            }
            if rec.next_entry_offset == 0 {
                break;
            }
            let step = usize::try_from(rec.next_entry_offset).unwrap_or(0);
            if step == 0 {
                break;
            }
            let Some(next_off) = offset.checked_add(step) else {
                break;
            };
            offset = next_off;
        }
        return Err(PeerError::Unverifiable(format!(
            "pid {pid} not found in kernel process list"
        )));
    }
    Err(PeerError::Unverifiable(
        "SystemProcessInformation retry budget exhausted".to_string(),
    ))
}

#[allow(
    unsafe_code,
    reason = "Win32 OpenSCManagerW / EnumServicesStatusExW checks svchost PID owns active Win32 service"
)]
pub(crate) fn scm_pid_hosts_active_service(pid: u32) -> bool {
    // SAFETY: null local machine and database opens local active SCM for enumeration.
    let scm = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_ENUMERATE_SERVICE) };
    if scm.is_null() {
        return false;
    }
    let _guard = ScopedScHandle(scm);

    let mut needed = 0u32;
    let mut count = 0u32;
    let mut resume = 0u32;
    // SAFETY: initial probe with 0 buffer length returns required byte size in `needed`.
    let _ = unsafe {
        EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_ACTIVE,
            null_mut(),
            0,
            &mut needed,
            &mut count,
            &mut resume,
            null(),
        )
    };
    let last_err = std::io::Error::last_os_error().raw_os_error();
    if last_err != Some(i32::try_from(ERROR_MORE_DATA).unwrap_or(234)) || needed == 0 {
        return false;
    }

    let buf_len = usize::try_from(needed)
        .unwrap_or(0)
        .saturating_add(4096)
        .min(4 * 1024 * 1024);
    let mut buf = vec![0u8; buf_len];
    let cap_u32 = u32::try_from(buf.len()).unwrap_or(u32::MAX);
    resume = 0;
    // SAFETY: `buf` holds `cap_u32` writable bytes; output count bounds entries returned.
    let ok = unsafe {
        EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_ACTIVE,
            buf.as_mut_ptr(),
            cap_u32,
            &mut needed,
            &mut count,
            &mut resume,
            null(),
        )
    };
    if ok == 0 {
        return false;
    }

    let elem_sz = size_of::<ENUM_SERVICE_STATUS_PROCESSW>();
    let total = usize::try_from(count).unwrap_or(0);
    for idx in 0..total {
        let Some(off) = idx.checked_mul(elem_sz) else {
            break;
        };
        if off.saturating_add(elem_sz) > buf.len() {
            break;
        }
        let ptr = buf
            .as_ptr()
            .wrapping_add(off)
            .cast::<ENUM_SERVICE_STATUS_PROCESSW>();
        // SAFETY: `off + elem_sz <= buf.len()` verified above.
        let entry = unsafe { ptr.read_unaligned() };
        if entry.ServiceStatusProcess.dwProcessId == pid {
            return true;
        }
    }
    false
}
