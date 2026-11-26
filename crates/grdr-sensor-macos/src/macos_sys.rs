// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::ptr::{null, null_mut};

use crate::MacOsSensorError;
use crate::es_tree::ProcessTreeKey;
use crate::macos_probes::MacOsProcessIdentity;

const PROC_PIDUNIQIDENTIFIERINFO: c_int = 17;
const CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
const K_CF_NUMBER_SINT32_TYPE: isize = 3;
const K_CF_NUMBER_SINT64_TYPE: isize = 4;
const K_SEC_CS_SIGNING_INFORMATION: u32 = 1 << 1;
const K_SEC_CS_DYNAMIC_INFORMATION: u32 = 1 << 3;
const CS_VALID: u32 = 0x0000_0001;
const CS_ADHOC: u32 = 0x0000_0002;

struct CfGuard(*const c_void);

#[repr(C)]
struct ProcUniqIdentifierInfo {
    p_uuid: [u8; 16],
    p_uniqueid: u64,
    p_puniqueid: u64,
    p_idversion: i32,
    p_orig_ppidversion: i32,
    p_reserve2: u64,
    p_reserve3: u64,
}

struct SecCodeOutcome {
    team_id: Option<String>,
    signing_id: Option<String>,
    adhoc_signed: bool,
}

#[link(name = "CoreFoundation", kind = "framework")]
#[allow(
    unsafe_code,
    reason = "Apple CoreFoundation bindings for Security framework calls."
)]
// SAFETY: Standard Apple CoreFoundation C ABI declarations matching CFBase/CFString/CFNumber/CFDictionary headers.
unsafe extern "C" {
    static kCFTypeDictionaryKeyCallBacks: u8;
    static kCFTypeDictionaryValueCallBacks: u8;
    fn CFRelease(cf: *const c_void);
    fn CFStringGetCString(
        the_string: *const c_void,
        buffer: *mut c_char,
        buffer_size: isize,
        encoding: u32,
    ) -> u8;
    fn CFNumberCreate(
        allocator: *const c_void,
        the_type: isize,
        value_ptr: *const c_void,
    ) -> *const c_void;
    fn CFNumberGetValue(number: *const c_void, the_type: isize, value_ptr: *mut c_void) -> u8;
    fn CFDictionaryCreate(
        allocator: *const c_void,
        keys: *const *const c_void,
        values: *const *const c_void,
        num_values: isize,
        key_callbacks: *const c_void,
        value_callbacks: *const c_void,
    ) -> *const c_void;
    fn CFDictionaryGetValue(the_dict: *const c_void, key: *const c_void) -> *const c_void;
}

#[link(name = "Security", kind = "framework")]
#[allow(
    unsafe_code,
    non_upper_case_globals,
    reason = "Apple Security framework bindings for SecCodeCopyGuestWithAttributes and SecCodeCheckValidity."
)]
// SAFETY: Standard Apple Security.framework C ABI symbols matching <Security/SecCode.h>.
unsafe extern "C" {
    static kSecGuestAttributePid: *const c_void;
    static kSecCodeInfoTeamIdentifier: *const c_void;
    static kSecCodeInfoIdentifier: *const c_void;
    static kSecCodeInfoFlags: *const c_void;
    static kSecCodeInfoStatus: *const c_void;
    fn SecCodeCopyGuestWithAttributes(
        host: *const c_void,
        attributes: *const c_void,
        flags: u32,
        guest: *mut *const c_void,
    ) -> i32;
    fn SecCodeCheckValidity(code: *const c_void, flags: u32, requirement: *const c_void) -> i32;
    fn SecCodeCopySigningInformation(
        code: *const c_void,
        flags: u32,
        information: *mut *const c_void,
    ) -> i32;
}

#[allow(
    unsafe_code,
    reason = "Apple libSystem Seatbelt sandbox initialization bindings."
)]
// SAFETY: Darwin libSystem sandbox_init_with_parameters / sandbox_free_error C ABI.
unsafe extern "C" {
    fn sandbox_init_with_parameters(
        profile: *const c_char,
        flags: u64,
        parameters: *const *const c_char,
        errorbuf: *mut *mut c_char,
    ) -> c_int;
    fn sandbox_free_error(errorbuf: *mut c_char);
}

impl Drop for CfGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            #[allow(unsafe_code, reason = "Release owned CoreFoundation object reference.")]
            // SAFETY: Non-null CFTypeRef created/retained by CoreFoundation or Security framework.
            let () = unsafe {
                CFRelease(self.0);
            };
            self.0 = null();
        }
    }
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
    if got_info != bsd_size {
        return Ok(None);
    }

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
    let pidversion = if got_uniq == uniq_size {
        u32::try_from(uniq_info.p_idversion)
            .ok()
            .filter(|v| *v != 0)
            .unwrap_or_else(|| u32::try_from(uniq_info.p_uniqueid & 0xffff_ffff).unwrap_or(0))
    } else {
        u32::try_from(bsd_info.pbi_start_tvsec & 0xffff_ffff).unwrap_or(0)
    };

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

    Ok(Some(MacOsProcessIdentity {
        key: ProcessTreeKey { pid, pidversion },
        parent_pid: bsd_info.pbi_ppid,
        uid: bsd_info.pbi_uid,
        executable_path,
        team_id: sec.team_id,
        signing_id: sec.signing_id,
        adhoc_signed: sec.adhoc_signed,
    }))
}

fn darwin_read_guest_seccode_info(raw_pid: c_int) -> SecCodeOutcome {
    let empty = SecCodeOutcome {
        team_id: None,
        signing_id: None,
        adhoc_signed: false,
    };

    #[allow(
        unsafe_code,
        reason = "Allocate CFNumberRef wrapping process PID for guest attribute lookup."
    )]
    // SAFETY: raw_pid lives on stack for duration of CFNumberCreate; retained object is freed by CfGuard.
    let cf_pid = unsafe {
        CFNumberCreate(
            null(),
            K_CF_NUMBER_SINT32_TYPE,
            (&raw_pid as *const c_int).cast::<c_void>(),
        )
    };
    if cf_pid.is_null() {
        return empty;
    }
    let _pid_guard = CfGuard(cf_pid);

    #[allow(
        unsafe_code,
        reason = "Build CFDictionaryRef with kSecGuestAttributePid for SecCodeCopyGuestWithAttributes."
    )]
    // SAFETY: kSecGuestAttributePid is a constant CFStringRef and cf_pid is valid; dictionary freed by CfGuard.
    let attrs_dict = unsafe {
        let keys = [kSecGuestAttributePid];
        let vals = [cf_pid];
        CFDictionaryCreate(
            null(),
            keys.as_ptr(),
            vals.as_ptr(),
            1,
            (&raw const kCFTypeDictionaryKeyCallBacks).cast::<c_void>(),
            (&raw const kCFTypeDictionaryValueCallBacks).cast::<c_void>(),
        )
    };
    if attrs_dict.is_null() {
        return empty;
    }
    let _attrs_guard = CfGuard(attrs_dict);

    let mut guest_code: *const c_void = null();
    #[allow(
        unsafe_code,
        reason = "Resolve running guest SecCodeRef by PID to avoid path TOCTOU."
    )]
    let guest_rc = {
        // SAFETY: attrs_dict is a valid CFDictionaryRef and guest_code receives retained SecCodeRef.
        unsafe { SecCodeCopyGuestWithAttributes(null(), attrs_dict, 0, &mut guest_code) }
    };
    if guest_rc != 0 || guest_code.is_null() {
        return empty;
    }
    let _code_guard = CfGuard(guest_code);

    #[allow(
        unsafe_code,
        reason = "Verify live running guest code signature validity."
    )]
    // SAFETY: guest_code is a retained live SecCodeRef checked with default flags and null requirement.
    let valid_rc = unsafe { SecCodeCheckValidity(guest_code, 0, null()) };
    if valid_rc != 0 {
        return empty;
    }

    let mut info_dict: *const c_void = null();
    #[allow(
        unsafe_code,
        reason = "Copy dynamic and static signing metadata from verified SecCodeRef."
    )]
    // SAFETY: guest_code is live and info_dict receives retained CFDictionaryRef released by CfGuard.
    let info_rc = unsafe {
        SecCodeCopySigningInformation(
            guest_code,
            K_SEC_CS_SIGNING_INFORMATION | K_SEC_CS_DYNAMIC_INFORMATION,
            &mut info_dict,
        )
    };
    if info_rc != 0 || info_dict.is_null() {
        return empty;
    }
    let _dict_guard = CfGuard(info_dict);

    #[allow(
        unsafe_code,
        reason = "Read signing status, flags, TeamIdentifier, and Identifier from verified SecCode dictionary."
    )]
    // SAFETY: info_dict is a valid CFDictionaryRef and kSecCodeInfo* keys are Apple constant CFStringRefs.
    let outcome = unsafe {
        let status_flags = cfnumber_to_u32(CFDictionaryGetValue(info_dict, kSecCodeInfoStatus));
        if (status_flags.unwrap_or(0) & CS_VALID) == 0 {
            empty
        } else {
            let code_flags = cfnumber_to_u32(CFDictionaryGetValue(info_dict, kSecCodeInfoFlags));
            let adhoc_signed = code_flags.is_some_and(|f| (f & CS_ADHOC) != 0);
            let team_id =
                cfstring_to_rust(CFDictionaryGetValue(info_dict, kSecCodeInfoTeamIdentifier));
            let signing_id =
                cfstring_to_rust(CFDictionaryGetValue(info_dict, kSecCodeInfoIdentifier));
            SecCodeOutcome {
                team_id,
                signing_id,
                adhoc_signed,
            }
        }
    };
    outcome
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
            let msg_owned = unsafe {
                let s = CStr::from_ptr(err_buf).to_string_lossy().into_owned();
                sandbox_free_error(err_buf);
                s
            };
            msg_owned
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

#[allow(
    unsafe_code,
    reason = "Extract u32 value from borrowed CFNumberRef inside verified CFDictionaryRef."
)]
// SAFETY: Caller passes null or a borrowed CFNumberRef inside a live retained CFDictionaryRef.
unsafe fn cfnumber_to_u32(cf_num: *const c_void) -> Option<u32> {
    if cf_num.is_null() {
        return None;
    }
    let mut out: i64 = 0;
    #[allow(unsafe_code, reason = "Copy integer value from borrowed CFNumberRef.")]
    // SAFETY: cf_num is verified non-null and out points to valid i64 stack storage.
    let ok = unsafe {
        CFNumberGetValue(
            cf_num,
            K_CF_NUMBER_SINT64_TYPE,
            (&mut out as *mut i64).cast::<c_void>(),
        )
    };
    if ok == 0 {
        return None;
    }
    u32::try_from(out).ok()
}

#[allow(
    unsafe_code,
    reason = "Extract UTF-8 string bytes from borrowed CFStringRef."
)]
// SAFETY: Caller passes null or a borrowed CFStringRef value inside a retained CFDictionaryRef.
unsafe fn cfstring_to_rust(cf_str: *const c_void) -> Option<String> {
    if cf_str.is_null() {
        return None;
    }
    let mut buf = [0u8; 512];
    #[allow(
        unsafe_code,
        reason = "Copy CFStringRef bytes into fixed stack buffer."
    )]
    // SAFETY: cf_str is verified non-null borrowed CFStringRef and buf holds 512 writable bytes.
    let ok = unsafe {
        CFStringGetCString(
            cf_str,
            buf.as_mut_ptr().cast::<c_char>(),
            isize::try_from(buf.len()).unwrap_or(512),
            CF_STRING_ENCODING_UTF8,
        )
    };
    if ok == 0 {
        return None;
    }
    let nul = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8(buf.get(..nul)?.to_vec()).ok()
}
