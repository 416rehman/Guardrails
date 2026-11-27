// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Win32 file and directory owner/DACL security verification (`GetSecurityInfo` + SDDL).

use std::ffi::c_void;
use std::os::windows::io::{AsRawHandle, BorrowedHandle};
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SE_FILE_OBJECT,
    SetSecurityInfo,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
};

use crate::PeerError;
use crate::win_peer::current_process_sid;
use crate::win_token::{LocalAllocGuard, psid_to_string};

const MAX_SDDL_CODE_UNITS: usize = 65_536;
const SDDL_REVISION_1: u32 = 1;
// Generic/standard/file-specific write, append, delete, DAC, owner, and take-control bits.
const WIN_WRITE_ACCESS_MASK: u32 = 0x500D_0156;

#[allow(
    unsafe_code,
    reason = "Win32 GetSecurityInfo and ConvertSecurityDescriptorToStringSecurityDescriptorW on open file handle"
)]
pub fn verify_windows_path_security(
    handle: BorrowedHandle<'_>,
    protected: bool,
) -> Result<(), PeerError> {
    let raw = handle.as_raw_handle() as HANDLE;
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err(PeerError::PathUnsafe(
            "invalid Windows file handle for ACL inspection".to_string(),
        ));
    }

    let mut owner_psid: PSID = null_mut();
    let mut dacl_ptr: *mut ACL = null_mut();
    let mut sec_desc: PSECURITY_DESCRIPTOR = null_mut();
    let sec_err = {
        // SAFETY: `raw` is a valid open handle from `BorrowedHandle<'_>`; stack pointers receive owner/DACL/SD freed via `LocalAllocGuard`.
        unsafe {
            GetSecurityInfo(
                raw,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner_psid,
                null_mut(),
                &mut dacl_ptr,
                null_mut(),
                &mut sec_desc,
            )
        }
    };
    let _sd_guard = LocalAllocGuard(sec_desc);
    if sec_err != 0 || owner_psid.is_null() {
        return Err(PeerError::Unverifiable(format!(
            "GetSecurityInfo(OWNER|DACL) failed with win32 error {sec_err}"
        )));
    }
    if dacl_ptr.is_null() {
        return Err(PeerError::PathUnsafe(
            "object has a NULL DACL granting universal write access".to_string(),
        ));
    }

    let owner_sid = psid_to_string(owner_psid)?;
    let owner_sddl = dacl_to_sddl(sec_desc, OWNER_SECURITY_INFORMATION)?;
    let owner_token = parse_owner_sddl_token(&owner_sddl);
    let caller_sid = if protected {
        None
    } else {
        Some(current_process_sid()?)
    };
    validate_owner_sid(&owner_sid, owner_token, caller_sid.as_deref(), protected)?;

    let sddl = dacl_to_sddl(sec_desc, DACL_SECURITY_INFORMATION)?;
    validate_dacl_sddl(
        &sddl,
        &owner_sid,
        owner_token,
        caller_sid.as_deref(),
        protected,
    )
}

#[allow(
    unsafe_code,
    reason = "Win32 GetSecurityInfo owner verify + ConvertStringSecurityDescriptorToSecurityDescriptorW + SetSecurityInfo protected DACL on open handle"
)]
pub fn restrict_windows_dir_handle_dacl(handle: BorrowedHandle<'_>) -> Result<(), PeerError> {
    let raw = handle.as_raw_handle() as HANDLE;
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err(PeerError::PathUnsafe(
            "invalid Windows directory handle for DACL restriction".to_string(),
        ));
    }
    let mut owner_psid: PSID = null_mut();
    let mut cur_sd: PSECURITY_DESCRIPTOR = null_mut();
    let owner_err = {
        // SAFETY: `raw` is a valid open directory handle; stack pointers receive owner PSID and SD freed via `LocalAllocGuard`.
        unsafe {
            GetSecurityInfo(
                raw,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner_psid,
                null_mut(),
                null_mut(),
                null_mut(),
                &mut cur_sd,
            )
        }
    };
    let _cur_guard = LocalAllocGuard(cur_sd);
    if owner_err != 0 || owner_psid.is_null() {
        return Err(PeerError::Unverifiable(format!(
            "GetSecurityInfo(OWNER) failed with win32 error {owner_err}"
        )));
    }
    let owner_sid = psid_to_string(owner_psid)?;
    let owner_sddl = dacl_to_sddl(cur_sd, OWNER_SECURITY_INFORMATION)?;
    let owner_token = parse_owner_sddl_token(&owner_sddl);
    let caller_sid = current_process_sid()?;
    validate_owner_sid(&owner_sid, owner_token, Some(&caller_sid), false)?;
    if !caller_sid.starts_with("S-1-")
        || !caller_sid
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'S' | b'-'))
    {
        return Err(PeerError::Unverifiable(
            "unexpected characters in current process SID".to_string(),
        ));
    }

    let sddl = format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{caller_sid})");
    let wide: Vec<u16> = sddl.encode_utf16().chain([0]).collect();
    let mut new_sd: PSECURITY_DESCRIPTOR = null_mut();
    let conv_ok = {
        // SAFETY: `wide` is NUL-terminated SDDL UTF-16 string and `new_sd` receives LocalAlloc security descriptor.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut new_sd,
                null_mut(),
            )
        }
    };
    let _new_sd_guard = LocalAllocGuard(new_sd);
    if conv_ok == 0 || new_sd.is_null() {
        return Err(PeerError::Unverifiable(format!(
            "ConvertStringSecurityDescriptorToSecurityDescriptorW failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    let mut dacl_present: i32 = 0;
    let mut dacl_defaulted: i32 = 0;
    let mut new_dacl: *mut ACL = null_mut();
    let dacl_ok = {
        // SAFETY: `new_sd` is a valid self-relative security descriptor returned above.
        unsafe {
            GetSecurityDescriptorDacl(
                new_sd,
                &mut dacl_present,
                &mut new_dacl,
                &mut dacl_defaulted,
            )
        }
    };
    if dacl_ok == 0 || dacl_present == 0 || new_dacl.is_null() {
        return Err(PeerError::Unverifiable(
            "constructed security descriptor has no DACL".to_string(),
        ));
    }

    let set_err = {
        // SAFETY: `raw` is open handle owned by caller and `new_dacl` lives inside `_new_sd_guard`.
        unsafe {
            SetSecurityInfo(
                raw,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                new_dacl,
                null_mut(),
            )
        }
    };
    if set_err != 0 {
        return Err(PeerError::PathUnsafe(format!(
            "SetSecurityInfo(PROTECTED_DACL) failed with win32 error {set_err}"
        )));
    }
    Ok(())
}

#[allow(
    unsafe_code,
    reason = "Win32 ConvertSecurityDescriptorToStringSecurityDescriptorW reads validated SD and NUL-scans bounded UTF-16 output"
)]
fn dacl_to_sddl(sec_desc: PSECURITY_DESCRIPTOR, info: u32) -> Result<String, PeerError> {
    let mut sddl_ptr: *mut u16 = null_mut();
    let mut sddl_len: u32 = 0;
    let ok = {
        // SAFETY: `sec_desc` came from `GetSecurityInfo` containing the requested `info` section (`OWNER_SECURITY_INFORMATION` or `DACL_SECURITY_INFORMATION`) and remains alive in caller.
        unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sec_desc,
                SDDL_REVISION_1,
                info,
                &mut sddl_ptr,
                &mut sddl_len,
            )
        }
    };
    let _sddl_guard = LocalAllocGuard(sddl_ptr.cast::<c_void>());
    if ok == 0 || sddl_ptr.is_null() {
        return Err(PeerError::Unverifiable(format!(
            "ConvertSecurityDescriptorToStringSecurityDescriptorW failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    let mut units = Vec::with_capacity(usize::try_from(sddl_len).unwrap_or(64).min(1024));
    let mut terminated = false;
    for offset in 0..MAX_SDDL_CODE_UNITS {
        let off_isize = isize::try_from(offset).unwrap_or(isize::MAX);
        let ch = {
            // SAFETY: `ConvertSecurityDescriptorToStringSecurityDescriptorW` allocates a NUL-terminated UTF-16 string; loop terminates at NUL or `MAX_SDDL_CODE_UNITS`.
            unsafe { *sddl_ptr.offset(off_isize) }
        };
        if ch == 0 {
            terminated = true;
            break;
        }
        units.push(ch);
    }
    if !terminated {
        return Err(PeerError::Unverifiable(
            "SDDL string exceeded bounded UTF-16 limit without NUL".to_string(),
        ));
    }
    String::from_utf16(&units)
        .map_err(|_| PeerError::Unverifiable("invalid UTF-16 SDDL string".to_string()))
}

fn parse_owner_sddl_token(sddl: &str) -> Option<&str> {
    sddl.strip_prefix("O:")
        .filter(|token| !token.is_empty() && !token.contains(':'))
}

fn validate_owner_sid(
    owner_sid: &str,
    owner_sddl_token: Option<&str>,
    caller_sid: Option<&str>,
    protected: bool,
) -> Result<(), PeerError> {
    if is_privileged_windows_sid(owner_sid)
        || owner_sddl_token.is_some_and(is_privileged_windows_sid)
    {
        return Ok(());
    }
    if !protected && caller_sid.is_some_and(|caller| caller == owner_sid) {
        return Ok(());
    }
    Err(PeerError::PathForeign)
}

fn validate_dacl_sddl(
    sddl: &str,
    owner_sid: &str,
    owner_sddl_token: Option<&str>,
    caller_sid: Option<&str>,
    protected: bool,
) -> Result<(), PeerError> {
    if sddl.contains("NO_ACCESS_CONTROL") || !sddl.starts_with("D:") {
        return Err(PeerError::PathUnsafe(
            "DACL missing or grants unrestricted access".to_string(),
        ));
    }
    for segment in sddl.split('(').skip(1) {
        let Some((ace_body, _)) = segment.split_once(')') else {
            return Err(PeerError::PathUnsafe("malformed SDDL ACE".to_string()));
        };
        let mut fields = ace_body.split(';');
        let ace_type = fields.next().unwrap_or("");
        let ace_flags = fields.next().unwrap_or("");
        let rights = fields.next().unwrap_or("");
        let _obj_guid = fields.next();
        let _inherit_guid = fields.next();
        let trustee = fields.next().unwrap_or("");

        if !matches!(ace_type, "A" | "OA") {
            continue;
        }
        if !ace_grants_write(rights) {
            continue;
        }
        let inherit_only = ace_has_flag(ace_flags, b"IO");
        if is_trusted_write_trustee(
            trustee,
            owner_sid,
            owner_sddl_token,
            caller_sid,
            protected,
            inherit_only,
        ) {
            continue;
        }
        if is_broad_sddl_trustee(trustee) {
            return Err(PeerError::PathUnsafe(format!(
                "untrusted broad write ACE for principal {trustee}"
            )));
        }
        return Err(PeerError::PathForeign);
    }
    Ok(())
}

fn is_privileged_windows_sid(sid: &str) -> bool {
    matches!(
        sid,
        "S-1-5-18" | "S-1-5-19" | "S-1-5-20" | "S-1-5-32-544" | "SY" | "BA" | "LA" | "LS" | "NS"
    ) || sid.starts_with("S-1-5-80-")
}

fn is_broad_sddl_trustee(trustee: &str) -> bool {
    matches!(
        trustee,
        "WD" | "AN"
            | "AU"
            | "BU"
            | "IU"
            | "NU"
            | "SU"
            | "DU"
            | "AC"
            | "S-1-1-0"
            | "S-1-5-7"
            | "S-1-5-11"
            | "S-1-5-32-545"
            | "S-1-15-2-1"
    )
}

fn is_trusted_write_trustee(
    trustee: &str,
    owner_sid: &str,
    owner_sddl_token: Option<&str>,
    caller_sid: Option<&str>,
    protected: bool,
    inherit_only: bool,
) -> bool {
    if is_privileged_windows_sid(trustee) {
        return true;
    }
    if inherit_only && matches!(trustee, "CO" | "CG" | "S-1-3-0" | "S-1-3-1") {
        return true;
    }
    if !protected {
        if caller_sid.is_some_and(|caller| caller == trustee) {
            return true;
        }
        if matches!(trustee, "OW" | "S-1-3-4")
            && (is_privileged_windows_sid(owner_sid)
                || owner_sddl_token.is_some_and(is_privileged_windows_sid)
                || caller_sid.is_some_and(|caller| caller == owner_sid))
        {
            return true;
        }
    }
    false
}

fn ace_has_flag(flags: &str, target: &[u8; 2]) -> bool {
    let bytes = flags.as_bytes();
    bytes.len().is_multiple_of(2) && bytes.as_chunks::<2>().0.iter().any(|pair| pair == target)
}

fn ace_grants_write(rights: &str) -> bool {
    if rights.is_empty() {
        return false;
    }
    if let Some(hex) = rights
        .strip_prefix("0x")
        .or_else(|| rights.strip_prefix("0X"))
    {
        return match u32::from_str_radix(hex, 16) {
            Ok(mask) => (mask & WIN_WRITE_ACCESS_MASK) != 0,
            Err(_) => true,
        };
    }
    let bytes = rights.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return true;
    }
    bytes.as_chunks::<2>().0.iter().any(|pair| {
        matches!(
            pair,
            b"FA" | b"FW" | b"GA" | b"GW" | b"WD" | b"WO" | b"SD" | b"DC" | b"CC" | b"WP"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sddl_write_classification_distinguishes_read_from_write_and_broad_principals() {
        assert!(!ace_grants_write("FRFX"));
        assert!(!ace_grants_write("0x1200a9"));
        assert!(ace_grants_write("FA"));
        assert!(ace_grants_write("GW"));
        assert!(ace_grants_write("0x1301bf"));
        assert!(ace_grants_write("0x40000000"));

        assert!(
            validate_dacl_sddl(
                "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a9;;;AU)",
                "S-1-5-18",
                Some("SY"),
                None,
                true,
            )
            .is_ok()
        );
        assert!(
            validate_dacl_sddl(
                "D:(A;;FA;;;SY)(A;;FW;;;WD)",
                "S-1-5-18",
                Some("SY"),
                Some("S-1-5-21-100-200"),
                false,
            )
            .is_err()
        );
        assert!(
            validate_dacl_sddl(
                "D:(A;;FA;;;SY)(A;;FA;;;S-1-5-21-100-200)",
                "S-1-5-18",
                Some("SY"),
                Some("S-1-5-21-100-200"),
                true,
            )
            .is_err()
        );
        assert!(
            validate_dacl_sddl(
                "D:(A;;FA;;;SY)(A;;FA;;;S-1-5-21-100-200)",
                "S-1-5-21-100-200",
                Some("S-1-5-21-100-200"),
                Some("S-1-5-21-100-200"),
                false,
            )
            .is_ok()
        );
    }

    #[test]
    fn local_admin_sddl_la_and_owner_token_are_accepted_while_foreign_500_fails_closed() {
        let local_admin_numeric = "S-1-5-21-100-200-300-500";
        let foreign_admin_numeric = "S-1-5-21-999-888-777-500";
        let local_caller = "S-1-5-21-100-200-300-1001";

        assert!(is_privileged_windows_sid("LA"));
        assert_eq!(parse_owner_sddl_token("O:LA"), Some("LA"));
        assert_eq!(
            parse_owner_sddl_token("O:S-1-5-21-999-888-777-500"),
            Some(foreign_admin_numeric)
        );
        for malformed in ["", "D:P", "O:", "O:LA:extra"] {
            assert_eq!(parse_owner_sddl_token(malformed), None);
            assert_eq!(
                validate_owner_sid(
                    local_admin_numeric,
                    parse_owner_sddl_token(malformed),
                    None,
                    true,
                ),
                Err(PeerError::PathForeign)
            );
        }

        let la_token = parse_owner_sddl_token("O:LA");
        assert!(validate_owner_sid(local_admin_numeric, la_token, None, true).is_ok());
        assert!(
            validate_owner_sid(local_admin_numeric, la_token, Some(local_caller), false).is_ok()
        );
        assert!(
            validate_dacl_sddl(
                "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;LA)",
                local_admin_numeric,
                la_token,
                Some(local_caller),
                false,
            )
            .is_ok()
        );
        assert!(
            validate_dacl_sddl(
                "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;LA)(A;;FA;;;OW)",
                local_admin_numeric,
                la_token,
                Some(local_caller),
                false,
            )
            .is_ok()
        );
        assert!(
            validate_dacl_sddl(
                "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;LA)",
                local_admin_numeric,
                la_token,
                None,
                true,
            )
            .is_ok()
        );
        assert_eq!(
            validate_dacl_sddl(
                "D:P(A;OICI;FA;;;SY)(A;;FA;;;OW)",
                local_admin_numeric,
                la_token,
                None,
                true,
            ),
            Err(PeerError::PathForeign)
        );

        let foreign_token = parse_owner_sddl_token("O:S-1-5-21-999-888-777-500");
        assert_eq!(
            validate_owner_sid(foreign_admin_numeric, foreign_token, None, true),
            Err(PeerError::PathForeign)
        );
        assert_eq!(
            validate_owner_sid(
                foreign_admin_numeric,
                foreign_token,
                Some(local_caller),
                false,
            ),
            Err(PeerError::PathForeign)
        );
        assert_eq!(
            validate_dacl_sddl(
                "D:P(A;OICI;FA;;;SY)(A;;FA;;;OW)",
                foreign_admin_numeric,
                foreign_token,
                Some(local_caller),
                false,
            ),
            Err(PeerError::PathForeign)
        );
    }

    #[test]
    fn unprivileged_and_broad_sddl_trustees_fail_closed() {
        let foreign_user = "S-1-5-21-100-200-300-1001";
        for sid in ["LG", "BU", "WD", foreign_user] {
            assert!(!is_privileged_windows_sid(sid));
            assert_eq!(
                validate_owner_sid(sid, Some(sid), None, true),
                Err(PeerError::PathForeign)
            );
            assert_eq!(
                validate_owner_sid(sid, Some(sid), Some("S-1-5-21-100-200-300-500"), false),
                Err(PeerError::PathForeign)
            );
        }

        assert_eq!(
            validate_dacl_sddl(
                "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;LG)",
                "S-1-5-18",
                Some("SY"),
                Some("S-1-5-21-100-200-300-500"),
                false,
            ),
            Err(PeerError::PathForeign)
        );
        assert!(matches!(
            validate_dacl_sddl(
                "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BU)",
                "S-1-5-18",
                Some("SY"),
                Some("S-1-5-21-100-200-300-500"),
                false,
            ),
            Err(PeerError::PathUnsafe(_))
        ));
        assert!(matches!(
            validate_dacl_sddl(
                "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;WD)",
                "S-1-5-18",
                Some("SY"),
                Some("S-1-5-21-100-200-300-500"),
                false,
            ),
            Err(PeerError::PathUnsafe(_))
        ));
        assert_eq!(
            validate_dacl_sddl(
                "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;S-1-5-21-100-200-300-1001)",
                "S-1-5-18",
                Some("SY"),
                Some("S-1-5-21-100-200-300-500"),
                false,
            ),
            Err(PeerError::PathForeign)
        );
        assert_eq!(
            validate_dacl_sddl(
                "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;S-1-5-21-100-200-300-1001)",
                "S-1-5-18",
                Some("SY"),
                Some(foreign_user),
                true,
            ),
            Err(PeerError::PathForeign)
        );
    }
}
