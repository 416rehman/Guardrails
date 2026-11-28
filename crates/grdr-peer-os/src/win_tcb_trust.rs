// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! WinVerifyTrust Authenticode and Windows Catalog (`CatRoot`) signature verification.

use std::ffi::c_void;
use std::fs::{self, OpenOptions};
use std::mem::size_of;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{FILETIME, HANDLE};

use crate::PeerError;
use crate::win_tcb_signer::verify_wvt_microsoft_os_signer;

const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0010;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const TRUST_E_NOSIGNATURE_CODE: i32 = -2146762496;
const WTD_UI_NONE: u32 = 2;
const WTD_REVOKE_WHOLECHAIN: u32 = 1;
const WTD_CHOICE_FILE: u32 = 1;
const WTD_CHOICE_CATALOG: u32 = 2;
const WTD_STATEACTION_VERIFY: u32 = 1;
const WTD_STATEACTION_CLOSE: u32 = 2;
const WTD_REVOCATION_CHECK_CHAIN: u32 = 0x0040;
const WTD_CACHE_ONLY_URL_RETRIEVAL: u32 = 0x1000;
const MAX_CATALOG_ENUM_COUNT: usize = 64;

const WINTRUST_ACTION_GENERIC_VERIFY_V2: Guid = Guid {
    data1: 0x00aa_c56b,
    data2: 0xcd44,
    data3: 0x11d0,
    data4: [0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee],
};
const DRIVER_ACTION_VERIFY: Guid = Guid {
    data1: 0xf750_e6c3,
    data2: 0x38ee,
    data3: 0x11d1,
    data4: [0x85, 0xe5, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee],
};

#[repr(C)]
#[derive(Clone, Copy)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

#[repr(C)]
struct ByHandleFileInformation {
    dw_file_attributes: u32,
    ft_creation_time: FILETIME,
    ft_last_access_time: FILETIME,
    ft_last_write_time: FILETIME,
    dw_volume_serial_number: u32,
    n_file_size_high: u32,
    n_file_size_low: u32,
    n_number_of_links: u32,
    n_file_index_high: u32,
    n_file_index_low: u32,
}

#[repr(C)]
struct WinTrustFileInfo {
    cb_struct: u32,
    pcwsz_file_path: *const u16,
    h_file: HANDLE,
    pg_known_subject: *const Guid,
}

#[repr(C)]
struct WinTrustCatalogInfo {
    cb_struct: u32,
    dw_catalog_version: u32,
    pcwsz_catalog_file_path: *const u16,
    pcwsz_member_tag: *const u16,
    pcwsz_member_file_path: *const u16,
    h_member_file: HANDLE,
    pb_calculated_file_hash: *const u8,
    cb_calculated_file_hash: u32,
    pc_catalog_context: *const c_void,
    h_cat_admin: isize,
}

#[repr(C)]
struct WinTrustData {
    cb_struct: u32,
    p_policy_callback_data: *mut c_void,
    p_sip_client_data: *mut c_void,
    dw_ui_choice: u32,
    fdw_revocation_checks: u32,
    dw_union_choice: u32,
    union_ptr: *mut c_void,
    dw_state_action: u32,
    h_wvt_state_data: HANDLE,
    pwsz_url_reference: *mut u16,
    dw_prov_flags: u32,
    dw_ui_context: u32,
    p_signature_settings: *mut c_void,
}

#[repr(C)]
struct CatalogInfo {
    cb_struct: u32,
    wsz_catalog_file: [u16; 260],
}

struct CatAdminGuard(isize);

struct CatContextGuard {
    admin: isize,
    ctx: isize,
}

struct WvtStateGuard {
    action: Guid,
    data: WinTrustData,
    active: bool,
}

#[allow(
    unsafe_code,
    reason = "Win32 kernel32 open-handle attribute and final path verification ABI bindings"
)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetFileInformationByHandle(
        h_file: HANDLE,
        lp_file_information: *mut ByHandleFileInformation,
    ) -> i32;
    fn GetFinalPathNameByHandleW(
        h_file: HANDLE,
        lpsz_file_path: *mut u16,
        cch_file_path: u32,
        dw_flags: u32,
    ) -> u32;
}

#[allow(
    unsafe_code,
    reason = "Win32 wintrust Authenticode and catalog verification ABI bindings"
)]
#[link(name = "wintrust")]
unsafe extern "system" {
    fn WinVerifyTrust(hwnd: HANDLE, pg_action_id: *const Guid, p_wvt_data: *mut c_void) -> i32;
    fn CryptCATAdminAcquireContext2(
        ph_cat_admin: *mut isize,
        pg_subsystem: *const Guid,
        pwsz_hash_algorithm: *const u16,
        p_strong_hash_policy: *const c_void,
        dw_flags: u32,
    ) -> i32;
    fn CryptCATAdminCalcHashFromFileHandle2(
        h_cat_admin: isize,
        h_file: HANDLE,
        pcb_hash: *mut u32,
        pb_hash: *mut u8,
        dw_flags: u32,
    ) -> i32;
    fn CryptCATAdminEnumCatalogFromHash(
        h_cat_admin: isize,
        pb_hash: *const u8,
        cb_hash: u32,
        dw_flags: u32,
        ph_prev_cat_info: *mut isize,
    ) -> isize;
    fn CryptCATCatalogInfoFromContext(
        h_cat_info: isize,
        ps_cat_info: *mut CatalogInfo,
        dw_flags: u32,
    ) -> i32;
    fn CryptCATAdminReleaseCatalogContext(
        h_cat_admin: isize,
        h_cat_info: isize,
        dw_flags: u32,
    ) -> i32;
    fn CryptCATAdminReleaseContext(h_cat_admin: isize, dw_flags: u32) -> i32;
}

impl Drop for CatAdminGuard {
    #[allow(unsafe_code, reason = "Releases Win32 HCATADMIN handle on drop")]
    fn drop(&mut self) {
        if self.0 != 0 {
            // SAFETY: `self.0` was opened via `CryptCATAdminAcquireContext2`.
            unsafe {
                let _ = CryptCATAdminReleaseContext(self.0, 0);
            }
        }
    }
}

impl Drop for CatContextGuard {
    #[allow(unsafe_code, reason = "Releases Win32 HCATINFO context on drop")]
    fn drop(&mut self) {
        if self.admin != 0 && self.ctx != 0 {
            // SAFETY: `self.ctx` belongs to open `self.admin` and was not already freed by `EnumCatalogFromHash`.
            unsafe {
                let _ = CryptCATAdminReleaseCatalogContext(self.admin, self.ctx, 0);
            }
        }
    }
}

impl Drop for WvtStateGuard {
    #[allow(
        unsafe_code,
        reason = "Closes WinVerifyTrust verification state handle"
    )]
    fn drop(&mut self) {
        if self.active && !self.data.h_wvt_state_data.is_null() {
            self.data.dw_state_action = WTD_STATEACTION_CLOSE;
            // SAFETY: `self.data` and `self.action` match prior `WTD_STATEACTION_VERIFY` call.
            unsafe {
                let _ = WinVerifyTrust(
                    null_mut(),
                    &self.action,
                    (&mut self.data as *mut WinTrustData).cast(),
                );
            }
            self.active = false;
        }
    }
}

pub(crate) fn ensure_no_reparse_points(system_dir: &str, disk_exe: &str) -> Result<(), PeerError> {
    let exe_path = Path::new(disk_exe);
    let sys_path = Path::new(system_dir);
    let win_dir = sys_path
        .parent()
        .ok_or_else(|| PeerError::Unverifiable("System32 parent directory missing".to_string()))?;
    for check in [win_dir, sys_path, exe_path] {
        check_path_not_reparse(check)?;
    }
    Ok(())
}

fn check_path_not_reparse(path: &Path) -> Result<(), PeerError> {
    let meta = fs::symlink_metadata(path)
        .map_err(|e| PeerError::Unverifiable(format!("cannot stat {}: {e}", path.display())))?;
    let attrs = meta.file_attributes();
    if meta.file_type().is_symlink() || (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
        return Err(PeerError::Unverifiable(format!(
            "reparse/symlink forbidden on {}",
            path.display()
        )));
    }
    Ok(())
}

#[allow(
    unsafe_code,
    reason = "Queries GetFileInformationByHandle and GetFinalPathNameByHandleW on open HANDLE"
)]
fn verify_open_handle_not_reparse(handle: HANDLE, expected_disk_path: &str) -> bool {
    let mut info = ByHandleFileInformation {
        dw_file_attributes: 0,
        ft_creation_time: FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        },
        ft_last_access_time: FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        },
        ft_last_write_time: FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        },
        dw_volume_serial_number: 0,
        n_file_size_high: 0,
        n_file_size_low: 0,
        n_number_of_links: 0,
        n_file_index_high: 0,
        n_file_index_low: 0,
    };
    // SAFETY: `handle` is an open file handle owned by `File` and `info` is stack POD.
    let ok = unsafe { GetFileInformationByHandle(handle, &mut info) };
    if ok == 0
        || (info.dw_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || (info.dw_file_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0
    {
        return false;
    }

    let mut path_buf = [0u16; 1024];
    let cap = u32::try_from(path_buf.len()).unwrap_or(1024);
    // SAFETY: `handle` is open and `path_buf` has exact capacity `cap`.
    let len = unsafe { GetFinalPathNameByHandleW(handle, path_buf.as_mut_ptr(), cap, 0) };
    let used = usize::try_from(len).unwrap_or(0);
    if used == 0 || used >= path_buf.len() {
        return false;
    }
    let decoded = String::from_utf16_lossy(path_buf.get(..used).unwrap_or(&[]));
    let normalized = decoded.strip_prefix("\\\\?\\").unwrap_or(&decoded);
    let expected = expected_disk_path
        .strip_prefix("\\\\?\\")
        .unwrap_or(expected_disk_path);
    normalized.eq_ignore_ascii_case(expected)
}

#[allow(
    unsafe_code,
    reason = "Win32 WinVerifyTrust and CryptCATAdmin digital signature verification"
)]
pub(crate) fn verify_disk_binary_trusted(disk_path: &str) -> bool {
    let Ok(file) = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(disk_path)
    else {
        return false;
    };
    let handle = file.as_raw_handle() as HANDLE;
    if !verify_open_handle_not_reparse(handle, disk_path) {
        return false;
    }

    let mut path_w: Vec<u16> = disk_path.encode_utf16().collect();
    path_w.push(0);

    let mut file_info = WinTrustFileInfo {
        cb_struct: u32::try_from(size_of::<WinTrustFileInfo>()).unwrap_or(0),
        pcwsz_file_path: path_w.as_ptr(),
        h_file: handle,
        pg_known_subject: null(),
    };
    let mut wvt = WvtStateGuard {
        action: WINTRUST_ACTION_GENERIC_VERIFY_V2,
        data: WinTrustData {
            cb_struct: u32::try_from(size_of::<WinTrustData>()).unwrap_or(0),
            p_policy_callback_data: null_mut(),
            p_sip_client_data: null_mut(),
            dw_ui_choice: WTD_UI_NONE,
            fdw_revocation_checks: WTD_REVOKE_WHOLECHAIN,
            dw_union_choice: WTD_CHOICE_FILE,
            union_ptr: (&mut file_info as *mut WinTrustFileInfo).cast(),
            dw_state_action: WTD_STATEACTION_VERIFY,
            h_wvt_state_data: null_mut(),
            pwsz_url_reference: null_mut(),
            dw_prov_flags: WTD_REVOCATION_CHECK_CHAIN | WTD_CACHE_ONLY_URL_RETRIEVAL,
            dw_ui_context: 0,
            p_signature_settings: null_mut(),
        },
        active: true,
    };
    // SAFETY: `wvt.action` and `wvt.data` are initialized C ABI WinTrust structs referencing live `file_info` and `file` handle.
    let status = unsafe {
        WinVerifyTrust(
            null_mut(),
            &wvt.action,
            (&mut wvt.data as *mut WinTrustData).cast(),
        )
    };
    if status == 0 {
        let trusted = verify_wvt_microsoft_os_signer(wvt.data.h_wvt_state_data);
        drop(wvt);
        return trusted;
    }
    drop(wvt);
    if status != TRUST_E_NOSIGNATURE_CODE {
        return false;
    }
    verify_catalog_signature(handle, &path_w)
}

#[allow(
    unsafe_code,
    reason = "Win32 CryptCATAdmin catalog signature verification for Windows OS binaries"
)]
fn verify_catalog_signature(handle: HANDLE, path_w: &[u16]) -> bool {
    let alg_w: Vec<u16> = "SHA256\0".encode_utf16().collect();
    let mut admin: isize = 0;
    // SAFETY: initializes local `admin` HCATADMIN handle against Microsoft `DRIVER_ACTION_VERIFY`.
    let ok = unsafe {
        CryptCATAdminAcquireContext2(&mut admin, &DRIVER_ACTION_VERIFY, alg_w.as_ptr(), null(), 0)
    };
    if ok == 0 || admin == 0 {
        return false;
    }
    let _admin_guard = CatAdminGuard(admin);

    let mut hash = [0u8; 64];
    let mut hash_len = u32::try_from(hash.len()).unwrap_or(64);
    // SAFETY: `admin` is valid HCATADMIN and `handle` is open regular file handle; writes <= 64 hash bytes.
    let hashed = unsafe {
        CryptCATAdminCalcHashFromFileHandle2(admin, handle, &mut hash_len, hash.as_mut_ptr(), 0)
    };
    let used = usize::try_from(hash_len).unwrap_or(0);
    if hashed == 0 || used == 0 || used > hash.len() {
        return false;
    }

    let tag: String = hash
        .get(..used)
        .unwrap_or(&[])
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect();
    let mut tag_w: Vec<u16> = tag.encode_utf16().collect();
    tag_w.push(0);

    let mut ctx_guard = CatContextGuard { admin, ctx: 0 };
    for _ in 0..MAX_CATALOG_ENUM_COUNT {
        let mut prev = ctx_guard.ctx;
        ctx_guard.ctx = 0;
        // SAFETY: `CryptCATAdminEnumCatalogFromHash` consumes `prev` when non-zero and yields the next HCATINFO.
        let next_ctx = unsafe {
            CryptCATAdminEnumCatalogFromHash(admin, hash.as_ptr(), hash_len, 0, &mut prev)
        };
        if next_ctx == 0 {
            break;
        }
        ctx_guard.ctx = next_ctx;

        let mut cat_info = CatalogInfo {
            cb_struct: u32::try_from(size_of::<CatalogInfo>()).unwrap_or(0),
            wsz_catalog_file: [0u16; 260],
        };
        // SAFETY: queries catalog file path into stack `CatalogInfo`.
        let got = unsafe { CryptCATCatalogInfoFromContext(next_ctx, &mut cat_info, 0) };
        if got == 0 {
            continue;
        }
        let cat_end = cat_info
            .wsz_catalog_file
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(cat_info.wsz_catalog_file.len());
        let cat_path =
            String::from_utf16_lossy(cat_info.wsz_catalog_file.get(..cat_end).unwrap_or(&[]));
        if cat_path.is_empty() || check_path_not_reparse(Path::new(&cat_path)).is_err() {
            continue;
        }

        let mut cat_wvt_info = WinTrustCatalogInfo {
            cb_struct: u32::try_from(size_of::<WinTrustCatalogInfo>()).unwrap_or(0),
            dw_catalog_version: 0,
            pcwsz_catalog_file_path: cat_info.wsz_catalog_file.as_ptr(),
            pcwsz_member_tag: tag_w.as_ptr(),
            pcwsz_member_file_path: path_w.as_ptr(),
            h_member_file: handle,
            pb_calculated_file_hash: hash.as_ptr(),
            cb_calculated_file_hash: hash_len,
            pc_catalog_context: null(),
            h_cat_admin: admin,
        };
        let mut wvt = WvtStateGuard {
            action: WINTRUST_ACTION_GENERIC_VERIFY_V2,
            data: WinTrustData {
                cb_struct: u32::try_from(size_of::<WinTrustData>()).unwrap_or(0),
                p_policy_callback_data: null_mut(),
                p_sip_client_data: null_mut(),
                dw_ui_choice: WTD_UI_NONE,
                fdw_revocation_checks: WTD_REVOKE_WHOLECHAIN,
                dw_union_choice: WTD_CHOICE_CATALOG,
                union_ptr: (&mut cat_wvt_info as *mut WinTrustCatalogInfo).cast(),
                dw_state_action: WTD_STATEACTION_VERIFY,
                h_wvt_state_data: null_mut(),
                pwsz_url_reference: null_mut(),
                dw_prov_flags: WTD_REVOCATION_CHECK_CHAIN | WTD_CACHE_ONLY_URL_RETRIEVAL,
                dw_ui_context: 0,
                p_signature_settings: null_mut(),
            },
            active: true,
        };
        // SAFETY: verifies catalog trust against open catalog info and member file handle.
        let verify_status = unsafe {
            WinVerifyTrust(
                null_mut(),
                &wvt.action,
                (&mut wvt.data as *mut WinTrustData).cast(),
            )
        };
        let trusted =
            verify_status == 0 && verify_wvt_microsoft_os_signer(wvt.data.h_wvt_state_data);
        drop(wvt);
        if trusted {
            return true;
        }
    }
    false
}
