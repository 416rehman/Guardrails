// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Cross-platform live resident set size (RSS) probe for self and supervised child processes.

#[cfg(windows)]
use std::ffi::c_void;

#[cfg(windows)]
#[repr(C)]
struct ProcessMemoryCounters {
    cb: u32,
    page_fault_count: u32,
    peak_working_set_size: usize,
    working_set_size: usize,
    quota_peak_paged_pool_usage: usize,
    quota_paged_pool_usage: usize,
    quota_peak_non_paged_pool_usage: usize,
    quota_non_paged_pool_usage: usize,
    pagefile_usage: usize,
    peak_pagefile_usage: usize,
}

#[cfg(windows)]
#[allow(unsafe_code, reason = "Win32 kernel32 process memory counter FFI")]
unsafe extern "system" {
    fn GetCurrentProcess() -> *mut c_void;
    fn K32GetProcessMemoryInfo(
        process: *mut c_void,
        ppsmemcounters: *mut ProcessMemoryCounters,
        cb: u32,
    ) -> i32;
}

/// Return current process resident set size in bytes, or `0` if unavailable.
#[must_use]
pub fn current_process_rss_bytes() -> u64 {
    #[cfg(windows)]
    {
        win_current_rss_bytes().unwrap_or(0)
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        linux_proc_vm_rss_path("/proc/self/status").unwrap_or(0)
    }
    #[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
    {
        unix_rusage_rss_bytes()
    }
    #[cfg(not(any(windows, unix)))]
    {
        0
    }
}

/// Probe OS resident set size for a live child process handle/PID (`None` if unsupported or unreadable).
#[must_use]
pub fn child_process_rss_bytes(child: &std::process::Child) -> Option<u64> {
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle as _;
        let handle = child.as_raw_handle();
        win_handle_rss_bytes(handle)
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        linux_proc_vm_rss_path(&format!("/proc/{}/status", child.id()))
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "android")))]
    {
        let _ = child;
        None
    }
}

#[cfg(windows)]
#[allow(
    unsafe_code,
    reason = "Queries Win32 current process pseudo-handle for K32GetProcessMemoryInfo"
)]
fn win_current_rss_bytes() -> Option<u64> {
    let cur = {
        // SAFETY: `GetCurrentProcess` returns the current process pseudo-handle with no preconditions.
        unsafe { GetCurrentProcess() }
    };
    win_handle_rss_bytes(cur)
}

#[cfg(windows)]
#[allow(
    unsafe_code,
    reason = "Calls Win32 K32GetProcessMemoryInfo on open process HANDLE into stack counters struct"
)]
fn win_handle_rss_bytes(process: *mut c_void) -> Option<u64> {
    if process.is_null() {
        return None;
    }
    let cb = u32::try_from(std::mem::size_of::<ProcessMemoryCounters>()).ok()?;
    let mut counters = ProcessMemoryCounters {
        cb,
        page_fault_count: 0,
        peak_working_set_size: 0,
        working_set_size: 0,
        quota_peak_paged_pool_usage: 0,
        quota_paged_pool_usage: 0,
        quota_peak_non_paged_pool_usage: 0,
        quota_non_paged_pool_usage: 0,
        pagefile_usage: 0,
        peak_pagefile_usage: 0,
    };
    let ok = {
        // SAFETY: `process` is a valid non-null process handle (current pseudo-handle or open `Child` handle) and `counters` matches `cb`.
        unsafe { K32GetProcessMemoryInfo(process, &mut counters, cb) }
    };
    if ok == 0 {
        return None;
    }
    Some(u64::try_from(counters.working_set_size).unwrap_or(u64::MAX))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn linux_proc_vm_rss_path(path: &str) -> Option<u64> {
    let status = std::fs::read_to_string(path).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb = rest
                .split_whitespace()
                .next()
                .and_then(|num| num.parse::<u64>().ok())?;
            return Some(kb.saturating_mul(1024));
        }
    }
    None
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
#[allow(
    unsafe_code,
    reason = "Calls POSIX getrusage(RUSAGE_SELF) into zeroed stack rusage struct"
)]
fn unix_rusage_rss_bytes() -> u64 {
    // SAFETY: `libc::rusage` is a plain C struct valid when zero-initialized.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: `RUSAGE_SELF` queries the current process and writes into valid `&mut usage`.
    let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    if rc != 0 || usage.ru_maxrss <= 0 {
        return 0;
    }
    let raw = u64::try_from(usage.ru_maxrss).unwrap_or(0);
    #[cfg(target_os = "macos")]
    {
        raw
    }
    #[cfg(not(target_os = "macos"))]
    {
        raw.saturating_mul(1024)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_process_rss_bytes_reports_nonzero_working_set() {
        assert!(current_process_rss_bytes() > 0);
    }
}
