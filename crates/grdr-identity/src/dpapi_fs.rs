// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::Path;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicU64, Ordering};

use windows_sys::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, FALSE, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SE_FILE_OBJECT,
    SetSecurityInfo,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetTokenInformation,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
    TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateDirectoryW, CreateFileW,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, GetFileInformationByHandle, MOVEFILE_REPLACE_EXISTING,
    MOVEFILE_WRITE_THROUGH, MoveFileExW, OPEN_EXISTING, READ_CONTROL, WRITE_DAC,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::IdentityError;
use crate::dpapi::MAX_DPAPI_CIPHER_BYTES;

const SDDL_REVISION_1: u32 = 1;
static TMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(1);

struct LocalFreePtr(*mut core::ffi::c_void);

impl Drop for LocalFreePtr {
    fn drop(&mut self) {
        if !self.0.is_null() {
            #[allow(unsafe_code, reason = "Release Win32 LocalAlloc SDDL/SD buffer.")]
            // SAFETY: self.0 was returned by Win32 security conversion API and freed once.
            unsafe {
                let _ = LocalFree(self.0);
            }
            self.0 = null_mut();
        }
    }
}

fn parse_sddl_descriptor(sddl: &str) -> Result<LocalFreePtr, IdentityError> {
    let wide_sddl = encode_utf16_nul(sddl)?;
    let mut sd: PSECURITY_DESCRIPTOR = null_mut();
    #[allow(
        unsafe_code,
        reason = "Parse owner-only SDDL security descriptor for DPAPI storage."
    )]
    // SAFETY: wide_sddl is NUL-terminated UTF-16 and sd receives LocalAlloc descriptor freed by LocalFreePtr.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            null_mut(),
        )
    };
    if ok == 0 || sd.is_null() {
        return Err(IdentityError::SecretStore(
            "failed creating owner-only DACL for DPAPI storage".to_string(),
        ));
    }
    Ok(LocalFreePtr(sd))
}

pub(crate) fn ensure_real_vault_dir(dir: &Path) -> Result<(), IdentityError> {
    if let Some(parent) = dir.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        fs::create_dir_all(parent).map_err(|e| {
            IdentityError::SecretStore(format!("cannot create DPAPI parent dir: {e}"))
        })?;
    }
    let user_sid = current_user_sid_string()?;
    let dir_sddl = format!("D:P(A;OICI;FA;;;{user_sid})(A;OICI;FA;;;SY)");
    let sd_guard = parse_sddl_descriptor(&dir_sddl)?;
    let sa = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(24),
        lpSecurityDescriptor: sd_guard.0,
        bInheritHandle: FALSE,
    };
    let wide_dir = encode_utf16_nul(&dir.to_string_lossy())?;
    #[allow(
        unsafe_code,
        reason = "Create DPAPI vault directory atomically with protected owner-only DACL."
    )]
    // SAFETY: wide_dir is NUL-terminated UTF-16 and sa references live sd_guard descriptor.
    let created = unsafe { CreateDirectoryW(wide_dir.as_ptr(), &sa) };
    if created == 0 {
        let last_err = std::io::Error::last_os_error();
        let already_exists = last_err
            .raw_os_error()
            .and_then(|code| u32::try_from(code).ok())
            == Some(ERROR_ALREADY_EXISTS);
        if !already_exists {
            return Err(IdentityError::SecretStore(format!(
                "cannot create DPAPI vault dir: {last_err}"
            )));
        }
    }

    #[allow(
        unsafe_code,
        reason = "Open DPAPI vault directory without traversing reparse points."
    )]
    // SAFETY: wide_dir is NUL-terminated UTF-16 path.
    let raw_dir = unsafe {
        CreateFileW(
            wide_dir.as_ptr(),
            READ_CONTROL | WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null_mut(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if raw_dir == INVALID_HANDLE_VALUE || raw_dir.is_null() {
        return Err(IdentityError::SecretStore(format!(
            "cannot open DPAPI vault dir handle: {}",
            std::io::Error::last_os_error()
        )));
    }
    #[allow(
        unsafe_code,
        reason = "Transfer CreateFileW directory handle ownership to OwnedHandle."
    )]
    // SAFETY: raw_dir was verified valid immediately above.
    let dir_handle = unsafe { OwnedHandle::from_raw_handle(raw_dir as RawHandle) };

    let mut info: BY_HANDLE_FILE_INFORMATION = {
        #[allow(
            unsafe_code,
            reason = "Zero-initialize Win32 file info struct for GetFileInformationByHandle."
        )]
        // SAFETY: BY_HANDLE_FILE_INFORMATION is plain old data where zero-init is valid.
        unsafe {
            core::mem::zeroed()
        }
    };
    let info_ok = {
        #[allow(
            unsafe_code,
            reason = "Query opened DPAPI vault handle attributes to reject reparse points."
        )]
        // SAFETY: dir_handle is a valid open handle and info is initialized.
        unsafe {
            GetFileInformationByHandle(dir_handle.as_raw_handle() as HANDLE, &mut info)
        }
    };
    if info_ok == 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
    {
        return Err(IdentityError::SecretStore(
            "DPAPI vault root must be a real non-reparse directory".to_string(),
        ));
    }

    let mut dacl_present = FALSE;
    let mut dacl_defaulted = FALSE;
    let mut dacl: *mut ACL = null_mut();
    #[allow(
        unsafe_code,
        reason = "Extract parsed DACL from protected SDDL descriptor."
    )]
    // SAFETY: sd_guard.0 is a valid initialized self-relative security descriptor.
    let dacl_ok = unsafe {
        GetSecurityDescriptorDacl(
            sd_guard.0,
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    };
    if dacl_ok == 0 || dacl_present == 0 || dacl.is_null() {
        return Err(IdentityError::SecretStore(
            "parsed DPAPI directory descriptor missing DACL".to_string(),
        ));
    }
    #[allow(
        unsafe_code,
        reason = "Enforce protected owner-only DACL on opened DPAPI vault directory handle."
    )]
    // SAFETY: dir_handle and dacl are valid and non-null for this call.
    let sec_err = unsafe {
        SetSecurityInfo(
            dir_handle.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl,
            null_mut(),
        )
    };
    if sec_err != 0 {
        return Err(IdentityError::SecretStore(format!(
            "failed enforcing protected DACL on DPAPI vault dir (Win32 {sec_err})"
        )));
    }
    Ok(())
}

pub(crate) fn write_dpapi_file_secure(
    root_dir: &Path,
    target_path: &Path,
    sealed: &[u8],
) -> Result<(), IdentityError> {
    ensure_real_vault_dir(root_dir)?;
    if let Ok(meta) = fs::symlink_metadata(target_path)
        && (meta.file_type().is_symlink()
            || (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
            || !meta.is_file())
    {
        return Err(IdentityError::SecretStore(
            "DPAPI target path is a symlink, reparse point, or non-regular file".to_string(),
        ));
    }

    let user_sid = current_user_sid_string()?;
    let sddl = format!("D:P(A;;FA;;;{user_sid})(A;;FA;;;SY)");
    let sd_guard = parse_sddl_descriptor(&sddl)?;

    let seq = TMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp_name = format!(".grdr-dpapi-{}-{seq}.tmp", std::process::id());
    let tmp_path = root_dir.join(tmp_name);
    let wide_tmp = encode_utf16_nul(&tmp_path.to_string_lossy())?;
    let sa = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(24),
        lpSecurityDescriptor: sd_guard.0,
        bInheritHandle: FALSE,
    };
    #[allow(
        unsafe_code,
        reason = "Create DPAPI staging file atomically with owner-only DACL and no reparse."
    )]
    // SAFETY: wide_tmp is NUL-terminated UTF-16 and sa references live sd_guard descriptor.
    let raw_handle = unsafe {
        CreateFileW(
            wide_tmp.as_ptr(),
            GENERIC_WRITE,
            0,
            &sa,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if raw_handle == INVALID_HANDLE_VALUE || raw_handle.is_null() {
        return Err(IdentityError::SecretStore(format!(
            "cannot create DPAPI staging file: {}",
            std::io::Error::last_os_error()
        )));
    }
    #[allow(
        unsafe_code,
        reason = "Transfer CreateFileW handle ownership to std::fs::File."
    )]
    // SAFETY: raw_handle was just created and verified valid immediately above.
    let mut file = unsafe { File::from_raw_handle(raw_handle as RawHandle) };

    if let Err(e) = file.write_all(sealed).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&tmp_path);
        return Err(IdentityError::SecretStore(format!(
            "failed writing DPAPI staging file: {e}"
        )));
    }
    drop(file);

    let wide_dst = encode_utf16_nul(&target_path.to_string_lossy())?;
    #[allow(unsafe_code, reason = "Atomically replace DPAPI secret file.")]
    // SAFETY: wide_tmp and wide_dst are NUL-terminated UTF-16 paths; tmp is local staging file.
    let moved = unsafe {
        MoveFileExW(
            wide_tmp.as_ptr(),
            wide_dst.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved == 0 {
        let err = std::io::Error::last_os_error();
        let _ = fs::remove_file(&tmp_path);
        return Err(IdentityError::SecretStore(format!(
            "failed replacing DPAPI secret file: {err}"
        )));
    }
    Ok(())
}

pub(crate) fn read_dpapi_file_secure(
    root_dir: &Path,
    target_path: &Path,
) -> Result<Option<Vec<u8>>, IdentityError> {
    ensure_real_vault_dir(root_dir)?;
    let meta = match fs::symlink_metadata(target_path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(IdentityError::SecretStore(format!(
                "cannot stat DPAPI secret file: {e}"
            )));
        }
    };
    if meta.file_type().is_symlink()
        || (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || !meta.is_file()
    {
        return Err(IdentityError::SecretStore(
            "DPAPI secret path is a symlink, reparse point, or non-regular file".to_string(),
        ));
    }

    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(target_path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(IdentityError::SecretStore(format!(
                "cannot open DPAPI secret file: {e}"
            )));
        }
    };
    let handle_meta = file.metadata().map_err(|e| {
        IdentityError::SecretStore(format!("cannot query open DPAPI handle metadata: {e}"))
    })?;
    if !handle_meta.is_file() || (handle_meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
    {
        return Err(IdentityError::SecretStore(
            "opened DPAPI secret file is not a regular file".to_string(),
        ));
    }
    let cap = u64::try_from(MAX_DPAPI_CIPHER_BYTES.saturating_add(1)).unwrap_or(u64::MAX);
    let mut sealed = Vec::new();
    file.take(cap).read_to_end(&mut sealed).map_err(|e| {
        IdentityError::SecretStore(format!("failed reading DPAPI secret file: {e}"))
    })?;
    if sealed.len() > MAX_DPAPI_CIPHER_BYTES {
        return Err(IdentityError::SecretStore(
            "DPAPI secret file exceeds bounded maximum ciphertext size".to_string(),
        ));
    }
    Ok(Some(sealed))
}

pub(crate) fn delete_dpapi_file_secure(
    root_dir: &Path,
    target_path: &Path,
) -> Result<(), IdentityError> {
    ensure_real_vault_dir(root_dir)?;
    let meta = match fs::symlink_metadata(target_path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(IdentityError::SecretStore(format!(
                "cannot stat DPAPI secret before delete: {e}"
            )));
        }
    };
    if meta.file_type().is_symlink()
        || (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || !meta.is_file()
    {
        return Err(IdentityError::SecretStore(
            "refusing to delete non-regular or reparse DPAPI entry".to_string(),
        ));
    }
    fs::remove_file(target_path)
        .map_err(|e| IdentityError::SecretStore(format!("failed deleting DPAPI secret: {e}")))
}

fn current_user_sid_string() -> Result<String, IdentityError> {
    let mut token: HANDLE = null_mut();
    #[allow(unsafe_code, reason = "Open current process token to read user SID.")]
    // SAFETY: GetCurrentProcess returns current process pseudo-handle; token receives handle.
    let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if opened == 0 || token.is_null() {
        return Err(IdentityError::SecretStore(
            "OpenProcessToken failed reading current user SID".to_string(),
        ));
    }
    #[allow(unsafe_code, reason = "Wrap process token HANDLE in RAII OwnedHandle.")]
    // SAFETY: token was verified non-null immediately above.
    let tok_guard = unsafe { OwnedHandle::from_raw_handle(token as RawHandle) };

    let mut needed: u32 = 0;
    #[allow(unsafe_code, reason = "Query TokenUser buffer size.")]
    // SAFETY: Querying size with null buffer and zero length writes required length into needed.
    unsafe {
        let _ = GetTokenInformation(
            tok_guard.as_raw_handle() as HANDLE,
            TokenUser,
            null_mut(),
            0,
            &mut needed,
        );
    }
    let len = usize::try_from(needed).unwrap_or(0);
    if len == 0 || len > 4_096 {
        return Err(IdentityError::SecretStore(
            "unexpected TokenUser buffer length".to_string(),
        ));
    }
    let mut buf = vec![0u64; len.div_ceil(8)];
    #[allow(unsafe_code, reason = "Read TokenUser SID from current process token.")]
    // SAFETY: buf is 8-byte aligned and sized for needed bytes.
    let ok = unsafe {
        GetTokenInformation(
            tok_guard.as_raw_handle() as HANDLE,
            TokenUser,
            buf.as_mut_ptr().cast::<core::ffi::c_void>(),
            needed,
            &mut needed,
        )
    };
    if ok == 0 {
        return Err(IdentityError::SecretStore(
            "GetTokenInformation(TokenUser) failed".to_string(),
        ));
    }
    #[allow(
        unsafe_code,
        reason = "Interpret TokenUser header and convert SID to string."
    )]
    // SAFETY: GetTokenInformation succeeded writing valid TOKEN_USER into aligned buf.
    let sid_str = unsafe {
        let tu = &*(buf.as_ptr().cast::<TOKEN_USER>());
        sid_to_string(tu.User.Sid)?
    };
    Ok(sid_str)
}

#[allow(unsafe_code, reason = "Convert Win32 PSID pointer to SDDL SID string.")]
// SAFETY: Caller passes valid initialized PSID inside live TOKEN_USER buffer.
unsafe fn sid_to_string(sid: PSID) -> Result<String, IdentityError> {
    let mut ptr: windows_sys::core::PWSTR = null_mut();
    #[allow(unsafe_code, reason = "Convert binary Win32 SID to UTF-16 string.")]
    // SAFETY: sid is non-null initialized Win32 SID and ptr receives LocalAlloc string.
    let ok = unsafe { ConvertSidToStringSidW(sid, &mut ptr) };
    if ok == 0 || ptr.is_null() {
        return Err(IdentityError::SecretStore(
            "ConvertSidToStringSidW failed".to_string(),
        ));
    }
    let _guard = LocalFreePtr(ptr as *mut core::ffi::c_void);
    let mut len = 0usize;
    while len < 512 {
        #[allow(unsafe_code, reason = "Scan NUL-terminated UTF-16 SID string.")]
        // SAFETY: ptr is NUL-terminated UTF-16 SID string returned by Windows.
        let ch = unsafe { *ptr.add(len) };
        if ch == 0 {
            break;
        }
        len = len.saturating_add(1);
    }
    #[allow(unsafe_code, reason = "Convert UTF-16 SID units to Rust String.")]
    // SAFETY: ptr is valid for len UTF-16 code units.
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    Ok(String::from_utf16_lossy(slice))
}

fn encode_utf16_nul(value: &str) -> Result<Vec<u16>, IdentityError> {
    if value.chars().any(|c| c == '\0') {
        return Err(IdentityError::SecretStore(
            "DPAPI path/SDDL contains interior NUL byte".to_string(),
        ));
    }
    let mut out: Vec<u16> = value.encode_utf16().collect();
    out.push(0);
    Ok(out)
}
