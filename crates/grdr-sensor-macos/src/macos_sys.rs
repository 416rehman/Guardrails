// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::ptr::{null, null_mut};

use crate::MacOsSensorError;
use crate::es_tree::ProcessTreeKey;
use crate::macos_probes::{MacOsProcessIdentity, parse_kern_procargs2};
use crate::macos_seccode::{
    SigningTrust, darwin_read_guest_seccode_by_audit, darwin_read_guest_seccode_info,
};

const PROC_PIDUNIQIDENTIFIERINFO: c_int = 17;
const DARWIN_PROC_ALL_PIDS: u32 = 1;
const DARWIN_CTL_KERN: c_int = 1;
const DARWIN_KERN_ARGMAX: c_int = 8;
const DARWIN_KERN_PROCARGS2: c_int = 49;
const MAX_PROCARGS_BYTES: usize = 262_144;
const MAX_LIST_PIDS: usize = 32_768;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
struct ProcUniqIdentifierInfo {
    p_uuid: [u8; 16],
    p_uniqueid: u64,
    p_puniqueid: u64,
    p_idversion: i32,
    p_orig_ppidversion: i32,
    p_reserve2: u64,
    p_reserve3: u64,
}

#[allow(
    unsafe_code,
    reason = "Darwin libSystem process enumeration, sysctl argv lookup, and Seatbelt bindings."
)]
// SAFETY: Standard Darwin libSystem C ABI symbols matching <libproc.h>, <sys/sysctl.h>, and <sandbox.h>.
unsafe extern "C" {
    fn proc_listpids(type_: u32, typeinfo: u32, buffer: *mut c_void, buffersize: c_int) -> c_int;
    fn sysctl(
        name: *mut c_int,
        namelen: u32,
        oldp: *mut c_void,
        oldlenp: *mut usize,
        newp: *mut c_void,
        newlen: usize,
    ) -> c_int;
    fn sandbox_init_with_parameters(
        profile: *const c_char,
        flags: u64,
        parameters: *const *const c_char,
        errorbuf: *mut *mut c_char,
    ) -> c_int;
    fn sandbox_free_error(errorbuf: *mut c_char);
}

pub(crate) fn darwin_list_pids() -> Result<Vec<u32>, MacOsSensorError> {
    #[allow(
        unsafe_code,
        reason = "Query required buffer size from Darwin proc_listpids."
    )]
    // SAFETY: Passing null buffer with zero size returns required byte count per Darwin libproc ABI.
    let needed = unsafe { proc_listpids(DARWIN_PROC_ALL_PIDS, 0, null_mut(), 0) };
    if needed <= 0 {
        return Ok(Vec::new());
    }
    let elem_size = std::mem::size_of::<libc::pid_t>();
    let needed_usize = usize::try_from(needed).unwrap_or(0);
    let est_count = needed_usize
        .saturating_add(elem_size.saturating_mul(64))
        .checked_div(elem_size)
        .unwrap_or(0)
        .min(MAX_LIST_PIDS);
    if est_count == 0 {
        return Ok(Vec::new());
    }
    let mut pids: Vec<libc::pid_t> = vec![0; est_count];
    let byte_cap = c_int::try_from(est_count.saturating_mul(elem_size)).unwrap_or(c_int::MAX);
    #[allow(
        unsafe_code,
        reason = "Read active Darwin process ID list via proc_listpids."
    )]
    // SAFETY: pids buffer holds at least byte_cap writable bytes.
    let written = unsafe {
        proc_listpids(
            DARWIN_PROC_ALL_PIDS,
            0,
            pids.as_mut_ptr().cast::<c_void>(),
            byte_cap,
        )
    };
    if written <= 0 {
        return Ok(Vec::new());
    }
    let count = usize::try_from(written)
        .unwrap_or(0)
        .checked_div(elem_size)
        .unwrap_or(0)
        .min(pids.len());
    let mut out = Vec::with_capacity(count);
    for &raw_pid in pids.get(..count).unwrap_or_default() {
        if let Ok(pid) = u32::try_from(raw_pid)
            && pid > 0
        {
            out.push(pid);
        }
    }
    Ok(out)
}

pub(crate) fn darwin_inspect_process(
    pid: u32,
) -> Result<Option<MacOsProcessIdentity>, MacOsSensorError> {
    let raw_pid = c_int::try_from(pid)
        .map_err(|_| MacOsSensorError::Source(format!("macOS pid {pid} exceeds c_int range")))?;
    if raw_pid <= 0 {
        return Err(MacOsSensorError::Source(
            "pid must be positive for macOS process inspection".to_string(),
        ));
    }

    let Some(uniq_before) = read_proc_uniq_info(raw_pid) else {
        return Ok(None);
    };
    let Some(bsd_before) = read_proc_bsd_info(raw_pid) else {
        return Ok(None);
    };

    let pidversion = u32::try_from(uniq_before.p_idversion)
        .ok()
        .filter(|v| *v != 0)
        .unwrap_or_else(|| u32::try_from(uniq_before.p_uniqueid & 0xffff_ffff).unwrap_or(0));

    let cap = usize::try_from(libc::PROC_PIDPATHINFO_MAXSIZE).unwrap_or(4_096);
    let mut path_buf = vec![0u8; cap];
    let path_buf_u32 = u32::try_from(path_buf.len()).unwrap_or(4_096);
    #[allow(unsafe_code, reason = "Read macOS executable path via proc_pidpath.")]
    // SAFETY: path_buf is writable for path_buf_u32 bytes.
    let path_len = unsafe {
        libc::proc_pidpath(
            raw_pid,
            path_buf.as_mut_ptr().cast::<c_void>(),
            path_buf_u32,
        )
    };
    let executable_path = if path_len > 0 {
        let len_usize = usize::try_from(path_len).unwrap_or(0).min(path_buf.len());
        String::from_utf8_lossy(path_buf.get(..len_usize).unwrap_or_default()).into_owned()
    } else {
        String::new()
    };

    let sec = darwin_read_guest_seccode_info(raw_pid);
    let argv = darwin_read_procargs2(raw_pid);

    // Eliminate PID-reuse TOCTOU across proc_pidinfo / kSecGuestAttributePid / sysctl lookups.
    let Some(uniq_after) = read_proc_uniq_info(raw_pid) else {
        return Ok(None);
    };
    let Some(bsd_after) = read_proc_bsd_info(raw_pid) else {
        return Ok(None);
    };
    if uniq_before.p_uniqueid != uniq_after.p_uniqueid
        || uniq_before.p_idversion != uniq_after.p_idversion
        || bsd_before.pbi_start_tvsec != bsd_after.pbi_start_tvsec
    {
        return Ok(None);
    }

    Ok(Some(MacOsProcessIdentity {
        key: ProcessTreeKey { pid, pidversion },
        parent_pid: bsd_before.pbi_ppid,
        uid: bsd_before.pbi_uid,
        executable_path,
        team_id: sec.team_id,
        signing_id: sec.signing_id,
        cdhash: sec.cdhash,
        argv,
        adhoc_signed: sec.trust != SigningTrust::ValidSigned,
    }))
}

#[allow(dead_code)]
pub(crate) fn darwin_verify_audit_token_cdhash(audit_token_bytes: &[u8; 32]) -> Option<String> {
    let outcome = darwin_read_guest_seccode_by_audit(audit_token_bytes);
    if outcome.trust != SigningTrust::ValidSigned {
        return None;
    }
    outcome.cdhash
}

fn read_proc_bsd_info(raw_pid: c_int) -> Option<libc::proc_bsdinfo> {
    #[allow(
        unsafe_code,
        reason = "Zero-initialize Darwin proc_bsdinfo buffer for proc_pidinfo."
    )]
    // SAFETY: proc_bsdinfo is a C POD struct valid when zeroed.
    let mut bsd_info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let bsd_size = c_int::try_from(std::mem::size_of::<libc::proc_bsdinfo>()).unwrap_or(0);
    #[allow(
        unsafe_code,
        reason = "Read macOS process parent PID, UID, and start timestamp via proc_pidinfo."
    )]
    // SAFETY: bsd_info points to valid writable storage of bsd_size bytes.
    let got_info = unsafe {
        libc::proc_pidinfo(
            raw_pid,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut bsd_info as *mut libc::proc_bsdinfo).cast::<c_void>(),
            bsd_size,
        )
    };
    (got_info == bsd_size).then_some(bsd_info)
}

fn read_proc_uniq_info(raw_pid: c_int) -> Option<ProcUniqIdentifierInfo> {
    #[allow(
        unsafe_code,
        reason = "Zero-initialize Darwin proc_uniqidentifierinfo buffer for proc_pidinfo."
    )]
    // SAFETY: ProcUniqIdentifierInfo matches XNU struct proc_uniqidentifierinfo POD layout.
    let mut uniq_info: ProcUniqIdentifierInfo = unsafe { std::mem::zeroed() };
    let uniq_size = c_int::try_from(std::mem::size_of::<ProcUniqIdentifierInfo>()).unwrap_or(0);
    #[allow(
        unsafe_code,
        reason = "Read macOS process p_idversion and unique ID via PROC_PIDUNIQIDENTIFIERINFO."
    )]
    // SAFETY: uniq_info points to writable storage of uniq_size bytes matching XNU layout.
    let got_uniq = unsafe {
        libc::proc_pidinfo(
            raw_pid,
            PROC_PIDUNIQIDENTIFIERINFO,
            0,
            (&mut uniq_info as *mut ProcUniqIdentifierInfo).cast::<c_void>(),
            uniq_size,
        )
    };
    (got_uniq == uniq_size).then_some(uniq_info)
}

fn darwin_read_procargs2(raw_pid: c_int) -> Vec<String> {
    let mut argmax: c_int = 0;
    let mut argmax_len = std::mem::size_of::<c_int>();
    let mut argmax_mib = [DARWIN_CTL_KERN, DARWIN_KERN_ARGMAX];
    #[allow(
        unsafe_code,
        reason = "Query KERN_ARGMAX buffer size limit via sysctl."
    )]
    // SAFETY: argmax_mib is 2 elements and argmax holds argmax_len bytes.
    let rc_max = unsafe {
        sysctl(
            argmax_mib.as_mut_ptr(),
            2,
            (&mut argmax as *mut c_int).cast::<c_void>(),
            &mut argmax_len,
            null_mut(),
            0,
        )
    };
    let cap = if rc_max == 0 && argmax > 0 {
        usize::try_from(argmax)
            .unwrap_or(65_536)
            .min(MAX_PROCARGS_BYTES)
    } else {
        65_536
    };
    let mut buf = vec![0u8; cap];
    let mut buf_len = buf.len();
    let mut mib = [DARWIN_CTL_KERN, DARWIN_KERN_PROCARGS2, raw_pid];
    #[allow(
        unsafe_code,
        reason = "Read process argc and argv strings via sysctl KERN_PROCARGS2."
    )]
    // SAFETY: mib is 3 elements and buf holds buf_len writable bytes.
    let rc = unsafe {
        sysctl(
            mib.as_mut_ptr(),
            3,
            buf.as_mut_ptr().cast::<c_void>(),
            &mut buf_len,
            null_mut(),
            0,
        )
    };
    if rc != 0 || buf_len == 0 {
        return Vec::new();
    }
    let slice = buf.get(..buf_len.min(buf.len())).unwrap_or_default();
    parse_kern_procargs2(slice)
}

pub(crate) fn darwin_apply_seatbelt_profile(profile_sbpl: &str) -> Result<(), MacOsSensorError> {
    let c_profile = CString::new(profile_sbpl).map_err(|_| {
        MacOsSensorError::Seatbelt("Seatbelt SBPL profile contains interior NUL byte".to_string())
    })?;
    let mut err_buf: *mut c_char = null_mut();
    #[allow(
        unsafe_code,
        reason = "Apply compiled Seatbelt SBPL profile to current sandboxed process."
    )]
    // SAFETY: c_profile is NUL-terminated SBPL text; err_buf is freed immediately via sandbox_free_error.
    let rc = unsafe { sandbox_init_with_parameters(c_profile.as_ptr(), 0, null(), &mut err_buf) };
    if rc != 0 {
        let msg = if !err_buf.is_null() {
            #[allow(
                unsafe_code,
                reason = "Extract Seatbelt error string before calling sandbox_free_error."
            )]
            // SAFETY: err_buf is a non-null NUL-terminated C string from sandbox_init_with_parameters.
            unsafe {
                let s = CStr::from_ptr(err_buf).to_string_lossy().into_owned();
                sandbox_free_error(err_buf);
                s
            }
        } else {
            format!("sandbox_init_with_parameters returned {rc}")
        };
        return Err(MacOsSensorError::Seatbelt(msg));
    }
    if !err_buf.is_null() {
        #[allow(unsafe_code, reason = "Release non-null Seatbelt diagnostic buffer.")]
        // SAFETY: err_buf came from sandbox_init_with_parameters.
        let () = unsafe {
            sandbox_free_error(err_buf);
        };
    }
    Ok(())
}
