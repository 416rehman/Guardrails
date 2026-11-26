// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::fs;
use std::os::windows::fs::MetadataExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{
    FALSE, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
    TRUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW, DENY_ACCESS,
    EXPLICIT_ACCESS_W, GetSecurityInfo, SE_FILE_OBJECT, SetEntriesInAclW, SetSecurityInfo,
    TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    ACL, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, GetSecurityDescriptorControl,
    GetSecurityDescriptorDacl, NO_INHERITANCE, OBJECT_INHERIT_ACE,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
    UNPROTECTED_DACL_SECURITY_INFORMATION,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, GetFileInformationByHandle, OPEN_EXISTING, READ_CONTROL, WRITE_DAC,
};

use crate::WindowsSensorError;
use crate::containment::DenyAcePlan;
use crate::win_containment::AclJournalEntry;
use crate::win_containment_sys::encode_utf16_nul;

const SDDL_REVISION_1: u32 = 1;
const MAX_SDDL_WCHARS: usize = 262_144;

struct LocalMemGuard {
    ptr: *mut core::ffi::c_void,
}

impl Drop for LocalMemGuard {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            #[allow(unsafe_code, reason = "Release Win32 LocalAlloc security buffer.")]
            // SAFETY: self.ptr came from Win32 security APIs and is freed once via LocalFree.
            unsafe {
                let _ = LocalFree(self.ptr);
            }
            self.ptr = null_mut();
        }
    }
}

pub(crate) fn apply_win_deny_aces(
    plans: &[DenyAcePlan],
) -> Result<Vec<AclJournalEntry>, WindowsSensorError> {
    let mut journal = Vec::with_capacity(plans.len());
    for plan in plans {
        if let Err(err) = apply_single_deny_ace(plan, &mut journal) {
            let _ = restore_win_deny_aces(&journal);
            return Err(err);
        }
    }
    Ok(journal)
}

fn apply_single_deny_ace(
    plan: &DenyAcePlan,
    journal: &mut Vec<AclJournalEntry>,
) -> Result<(), WindowsSensorError> {
    let (handle_guard, is_dir) = open_non_reparse_acl_handle(&plan.target_path)?;
    let obj_handle = handle_guard.as_raw_handle() as HANDLE;
    let (prior_dacl_sddl, protected_dacl) = read_handle_dacl_sddl(obj_handle)?;

    let sid_wide = encode_utf16_nul(&plan.sandbox_sid)?;
    let mut target_sid: PSID = null_mut();
    #[allow(
        unsafe_code,
        reason = "Convert target sandbox SID string for Deny ACE."
    )]
    // SAFETY: sid_wide is NUL-terminated UTF-16 and target_sid receives LocalAlloc SID.
    let sid_ok = unsafe { ConvertStringSidToSidW(sid_wide.as_ptr(), &mut target_sid) };
    if sid_ok == 0 || target_sid.is_null() {
        return Err(WindowsSensorError::Containment(format!(
            "ConvertStringSidToSidW failed for `{}`",
            plan.sandbox_sid
        )));
    }
    let _sid_guard = LocalMemGuard { ptr: target_sid };

    let mut cur_dacl: *mut ACL = null_mut();
    let mut cur_sd: PSECURITY_DESCRIPTOR = null_mut();
    #[allow(
        unsafe_code,
        reason = "Read existing object DACL on non-reparse handle before inserting Deny ACE."
    )]
    // SAFETY: obj_handle is open and cur_sd receives LocalAlloc descriptor freed by LocalMemGuard.
    let get_rc = unsafe {
        GetSecurityInfo(
            obj_handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut cur_dacl,
            null_mut(),
            &mut cur_sd,
        )
    };
    if get_rc != 0 {
        return Err(WindowsSensorError::Containment(format!(
            "GetSecurityInfo failed on `{}` (win32={get_rc})",
            plan.target_path
        )));
    }
    let _sd_guard = LocalMemGuard { ptr: cur_sd };

    let mut access_mask = 0u32;
    if plan.deny_read_write {
        access_mask |= GENERIC_READ | GENERIC_WRITE;
    }
    if plan.deny_execute {
        access_mask |= GENERIC_EXECUTE;
    }
    let ea = EXPLICIT_ACCESS_W {
        grfAccessPermissions: access_mask,
        grfAccessMode: DENY_ACCESS,
        grfInheritance: if is_dir {
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
        } else {
            NO_INHERITANCE
        },
        Trustee: TRUSTEE_W {
            pMultipleTrustee: null_mut(),
            MultipleTrusteeOperation: 0,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: target_sid as windows_sys::core::PWSTR,
        },
    };
    let mut new_dacl: *mut ACL = null_mut();
    #[allow(unsafe_code, reason = "Merge explicit Deny ACE into object DACL.")]
    // SAFETY: ea Trustee SID and cur_dacl are live during SetEntriesInAclW; new_dacl freed below.
    let acl_rc = unsafe { SetEntriesInAclW(1, &ea, cur_dacl, &mut new_dacl) };
    if acl_rc != 0 || new_dacl.is_null() {
        return Err(WindowsSensorError::Containment(format!(
            "SetEntriesInAclW failed on `{}` (win32={acl_rc})",
            plan.target_path
        )));
    }
    let _new_dacl_guard = LocalMemGuard {
        ptr: new_dacl as *mut core::ffi::c_void,
    };

    #[allow(
        unsafe_code,
        reason = "Apply updated DACL on verified non-reparse object handle."
    )]
    // SAFETY: obj_handle and new_dacl are valid for SetSecurityInfo.
    let set_rc = unsafe {
        SetSecurityInfo(
            obj_handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            new_dacl,
            null_mut(),
        )
    };
    if set_rc != 0 {
        return Err(WindowsSensorError::Containment(format!(
            "SetSecurityInfo failed on `{}` (win32={set_rc})",
            plan.target_path
        )));
    }
    journal.push(AclJournalEntry {
        target_path: plan.target_path.clone(),
        prior_dacl_sddl,
        protected_dacl,
    });
    Ok(())
}

pub(crate) fn restore_win_deny_aces(
    entries: &[AclJournalEntry],
) -> Result<usize, WindowsSensorError> {
    let mut restored = 0usize;
    for entry in entries.iter().rev() {
        let (handle_guard, _) = open_non_reparse_acl_handle(&entry.target_path)?;
        let obj_handle = handle_guard.as_raw_handle() as HANDLE;
        let wide_sddl = encode_utf16_nul(&entry.prior_dacl_sddl)?;
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        let mut sd_size: u32 = 0;
        #[allow(
            unsafe_code,
            reason = "Parse journaled SDDL back into security descriptor."
        )]
        // SAFETY: wide_sddl is NUL-terminated UTF-16 and sd receives LocalAlloc descriptor.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide_sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                &mut sd_size,
            )
        };
        if ok == 0 || sd.is_null() {
            return Err(WindowsSensorError::Containment(format!(
                "SDDL parse failed while restoring `{}`",
                entry.target_path
            )));
        }
        let _sd_guard = LocalMemGuard { ptr: sd };

        let mut dacl_present = FALSE;
        let mut dacl_defaulted = FALSE;
        let mut dacl: *mut ACL = null_mut();
        #[allow(
            unsafe_code,
            reason = "Extract prior DACL from journaled security descriptor."
        )]
        let dacl_ok = {
            // SAFETY: sd is a valid security descriptor owned by _sd_guard.
            unsafe {
                GetSecurityDescriptorDacl(sd, &mut dacl_present, &mut dacl, &mut dacl_defaulted)
            }
        };
        if dacl_ok == 0 || dacl_present != TRUE || dacl.is_null() {
            return Err(WindowsSensorError::Containment(format!(
                "missing or null DACL in SDDL restore for `{}`",
                entry.target_path
            )));
        }

        let sec_info = DACL_SECURITY_INFORMATION
            | if entry.protected_dacl {
                PROTECTED_DACL_SECURITY_INFORMATION
            } else {
                UNPROTECTED_DACL_SECURITY_INFORMATION
            };
        #[allow(
            unsafe_code,
            reason = "Restore journaled pre-containment DACL and protection flag on handle."
        )]
        // SAFETY: obj_handle is open non-reparse handle and dacl points inside live _sd_guard.
        let rc = unsafe {
            SetSecurityInfo(
                obj_handle,
                SE_FILE_OBJECT,
                sec_info,
                null_mut(),
                null_mut(),
                dacl,
                null_mut(),
            )
        };
        if rc != 0 {
            return Err(WindowsSensorError::Containment(format!(
                "SetSecurityInfo restore failed for `{}` (win32={rc})",
                entry.target_path
            )));
        }
        restored = restored.saturating_add(1);
    }
    Ok(restored)
}

fn open_non_reparse_acl_handle(
    target_path: &str,
) -> Result<(OwnedHandle, bool), WindowsSensorError> {
    let link_meta = fs::symlink_metadata(target_path).map_err(|e| {
        WindowsSensorError::Containment(format!("cannot stat `{target_path}`: {e}"))
    })?;
    if link_meta.file_type().is_symlink()
        || (link_meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
    {
        return Err(WindowsSensorError::Containment(format!(
            "refusing symlink or reparse target `{target_path}`"
        )));
    }
    let is_dir = link_meta.is_dir();
    if !is_dir && !link_meta.is_file() {
        return Err(WindowsSensorError::Containment(format!(
            "target `{target_path}` is not a regular file or directory"
        )));
    }

    let wide_path = encode_utf16_nul(target_path)?;
    #[allow(
        unsafe_code,
        reason = "Open ACL handle without following symlinks or reparse points."
    )]
    // SAFETY: wide_path is NUL-terminated UTF-16 and FILE_FLAG_OPEN_REPARSE_POINT prevents traversal.
    let raw = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            READ_CONTROL | WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null_mut(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE || raw.is_null() {
        return Err(WindowsSensorError::Containment(format!(
            "CreateFileW ACL handle failed for `{target_path}` ({})",
            std::io::Error::last_os_error()
        )));
    }
    #[allow(unsafe_code, reason = "Wrap ACL handle in RAII OwnedHandle.")]
    // SAFETY: raw was verified valid immediately above.
    let owned = unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) };
    #[allow(
        unsafe_code,
        reason = "Verify opened handle attributes via GetFileInformationByHandle without cloning handle."
    )]
    // SAFETY: owned holds a valid open handle and info is zero-initialized POD stack storage.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    #[allow(
        unsafe_code,
        reason = "Query file attributes directly on opened ACL handle."
    )]
    // SAFETY: owned is a live Win32 handle and info points to initialized stack struct.
    let info_ok = unsafe { GetFileInformationByHandle(owned.as_raw_handle() as HANDLE, &mut info) };
    if info_ok == 0 {
        return Err(WindowsSensorError::Containment(format!(
            "GetFileInformationByHandle failed for `{target_path}` ({})",
            std::io::Error::last_os_error()
        )));
    }
    if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
        return Err(WindowsSensorError::Containment(format!(
            "opened handle `{target_path}` resolved to reparse point"
        )));
    }
    Ok((owned, is_dir))
}

fn read_handle_dacl_sddl(handle: HANDLE) -> Result<(String, bool), WindowsSensorError> {
    let mut sd: PSECURITY_DESCRIPTOR = null_mut();
    #[allow(
        unsafe_code,
        reason = "Capture original DACL descriptor on handle for ACL journal."
    )]
    // SAFETY: handle is valid open object HANDLE and sd receives LocalAlloc descriptor.
    let rc = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut sd,
        )
    };
    if rc != 0 || sd.is_null() {
        return Err(WindowsSensorError::Containment(format!(
            "GetSecurityInfo SDDL read failed (win32={rc})"
        )));
    }
    let _sd_guard = LocalMemGuard { ptr: sd };

    let mut control: u16 = 0;
    let mut revision: u32 = 0;
    #[allow(
        unsafe_code,
        reason = "Check SE_DACL_PROTECTED control flag on original security descriptor."
    )]
    let ctrl_ok = {
        // SAFETY: sd is live security descriptor owned by _sd_guard.
        unsafe { GetSecurityDescriptorControl(sd, &mut control, &mut revision) }
    };
    if ctrl_ok == 0 {
        return Err(WindowsSensorError::Containment(
            "GetSecurityDescriptorControl failed".to_string(),
        ));
    }
    let protected = (control & SE_DACL_PROTECTED) != 0;

    let mut sddl_ptr: windows_sys::core::PWSTR = null_mut();
    let mut sddl_len: u32 = 0;
    #[allow(
        unsafe_code,
        reason = "Serialize prior DACL into reversible SDDL string."
    )]
    // SAFETY: sd is live and sddl_ptr receives LocalAlloc UTF-16 buffer freed by _sddl_guard.
    let sddl_ok = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut sddl_ptr,
            &mut sddl_len,
        )
    };
    if sddl_ok == 0 || sddl_ptr.is_null() {
        return Err(WindowsSensorError::Containment(
            "ConvertSecurityDescriptorToStringSecurityDescriptorW failed".to_string(),
        ));
    }
    let _sddl_guard = LocalMemGuard {
        ptr: sddl_ptr as *mut core::ffi::c_void,
    };
    let declared_len = usize::try_from(sddl_len)
        .map_err(|_| WindowsSensorError::Containment("SDDL length overflows usize".to_string()))?;
    if declared_len > MAX_SDDL_WCHARS {
        return Err(WindowsSensorError::Containment(format!(
            "SDDL descriptor length {declared_len} exceeds 262144 code unit limit"
        )));
    }
    let mut len = 0usize;
    while len < declared_len {
        #[allow(
            unsafe_code,
            reason = "Find first NUL terminator in bounded SDDL UTF-16 buffer."
        )]
        // SAFETY: sddl_ptr is valid up to declared_len WCHARs as returned by Windows.
        let ch = unsafe { *sddl_ptr.add(len) };
        if ch == 0 {
            break;
        }
        len = len.saturating_add(1);
    }
    #[allow(
        unsafe_code,
        reason = "Convert serialized SDDL UTF-16 string to Rust String."
    )]
    // SAFETY: sddl_ptr is NUL-free for len UTF-16 code units.
    let slice = unsafe { std::slice::from_raw_parts(sddl_ptr, len) };
    Ok((String::from_utf16_lossy(slice), protected))
}
