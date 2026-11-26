// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Win32 aligned token and SID reading helpers (`crate::win_peer` helper module).

use std::ffi::c_void;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, PSID, TOKEN_MANDATORY_LABEL,
    TOKEN_USER, TokenImpersonationLevel, TokenIntegrityLevel, TokenIsAppContainer, TokenUser,
};

use crate::PeerError;

pub(crate) struct ScopedWinHandle(pub(crate) HANDLE);

pub(crate) struct LocalAllocGuard(pub(crate) *mut c_void);

impl Drop for ScopedWinHandle {
    #[allow(unsafe_code, reason = "Closes Win32 HANDLE owned by ScopedWinHandle")]
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: `self.0` is an open valid Win32 handle owned exclusively by this guard.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

impl Drop for LocalAllocGuard {
    #[allow(unsafe_code, reason = "Frees Win32 LocalAlloc pointer on drop")]
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` came from `ConvertSidToStringSidW` or `GetSecurityInfo`.
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

#[allow(
    unsafe_code,
    reason = "Reads aligned TOKEN_USER PSID from 8-byte aligned buffer"
)]
pub(crate) fn read_token_user_sid(tok: HANDLE) -> Result<String, PeerError> {
    let (buf, written) = query_token_info(tok, TokenUser)?;
    let min_len = std::mem::size_of::<TOKEN_USER>();
    if written < min_len {
        return Err(PeerError::Unverifiable("truncated TOKEN_USER".to_string()));
    }
    let user_ptr = buf.as_ptr().cast::<TOKEN_USER>();
    // SAFETY: `buf` is `Vec<u64>` (8-byte aligned) and `written >= size_of::<TOKEN_USER>()`.
    let user = unsafe { user_ptr.read() };
    psid_to_string(user.User.Sid)
}

#[allow(
    unsafe_code,
    reason = "Reads aligned TOKEN_MANDATORY_LABEL integrity RID"
)]
pub(crate) fn read_token_integrity_rid(tok: HANDLE) -> Result<u32, PeerError> {
    let (buf, written) = query_token_info(tok, TokenIntegrityLevel)?;
    let min_len = std::mem::size_of::<TOKEN_MANDATORY_LABEL>();
    if written < min_len {
        return Err(PeerError::Unverifiable(
            "truncated TOKEN_MANDATORY_LABEL".to_string(),
        ));
    }
    let label_ptr = buf.as_ptr().cast::<TOKEN_MANDATORY_LABEL>();
    // SAFETY: `buf` is `Vec<u64>` (8-byte aligned) and `written >= size_of::<TOKEN_MANDATORY_LABEL>()`.
    let label = unsafe { label_ptr.read() };
    let psid = label.Label.Sid;
    if psid.is_null() {
        return Err(PeerError::Unverifiable("null integrity SID".to_string()));
    }
    // SAFETY: `psid` is validated non-null SID inside kernel buffer.
    let count_ptr = unsafe { GetSidSubAuthorityCount(psid) };
    if count_ptr.is_null() {
        return Err(PeerError::Unverifiable(
            "null subauthority count".to_string(),
        ));
    }
    // SAFETY: `count_ptr` points to valid `u8` subauthority count.
    let count = unsafe { *count_ptr };
    if count == 0 {
        return Err(PeerError::Unverifiable(
            "empty integrity SID subauthorities".to_string(),
        ));
    }
    let last_idx = u32::from(count.saturating_sub(1));
    // SAFETY: `last_idx < count` validated cleanly.
    let rid_ptr = unsafe { GetSidSubAuthority(psid, last_idx) };
    if rid_ptr.is_null() {
        return Err(PeerError::Unverifiable("null integrity RID".to_string()));
    }
    // SAFETY: `rid_ptr` points to valid `u32` RID inside `psid`.
    Ok(unsafe { *rid_ptr })
}

#[allow(
    unsafe_code,
    reason = "Queries TokenImpersonationLevel onto stack storage"
)]
pub(crate) fn read_token_impersonation_level(tok: HANDLE) -> Result<i32, PeerError> {
    let mut level: i32 = 0;
    let mut ret_len: u32 = 0;
    let sz = u32::try_from(std::mem::size_of::<i32>()).unwrap_or(4);
    // SAFETY: stack-aligned `i32` buffer sized exactly to `size_of::<i32>()`.
    let ok = unsafe {
        GetTokenInformation(
            tok,
            TokenImpersonationLevel,
            (&raw mut level).cast::<c_void>(),
            sz,
            &mut ret_len,
        )
    };
    if ok == 0 || usize::try_from(ret_len).ok() != Some(std::mem::size_of::<i32>()) {
        return Err(PeerError::Unverifiable(format!(
            "GetTokenInformation(TokenImpersonationLevel) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(level)
}

#[allow(
    unsafe_code,
    reason = "Queries TokenIsAppContainer onto stack u32 storage"
)]
pub(crate) fn read_token_is_app_container(tok: HANDLE) -> Result<bool, PeerError> {
    let mut val: u32 = 0;
    let mut ret_len: u32 = 0;
    let sz = u32::try_from(std::mem::size_of::<u32>()).unwrap_or(4);
    // SAFETY: `val` is 4-byte aligned stack storage sized for `TokenIsAppContainer`.
    let ok = unsafe {
        GetTokenInformation(
            tok,
            TokenIsAppContainer,
            (&raw mut val).cast::<c_void>(),
            sz,
            &mut ret_len,
        )
    };
    if ok == 0 {
        return Err(PeerError::Unverifiable(format!(
            "GetTokenInformation(TokenIsAppContainer) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(val != 0)
}

#[allow(
    unsafe_code,
    reason = "Win32 GetTokenInformation size probe and aligned Vec<u64> read"
)]
fn query_token_info(tok: HANDLE, class: i32) -> Result<(Vec<u64>, usize), PeerError> {
    let mut needed: u32 = 0;
    // SAFETY: probe buffer length cleanly.
    let probe_ok = unsafe { GetTokenInformation(tok, class, null_mut(), 0, &mut needed) };
    if probe_ok != 0 {
        return Err(PeerError::Unverifiable(
            "unexpected empty probe success from GetTokenInformation".to_string(),
        ));
    }
    // SAFETY: GetLastError has no safety preconditions.
    let probe_err = unsafe { GetLastError() };
    if probe_err != ERROR_INSUFFICIENT_BUFFER {
        return Err(PeerError::Unverifiable(format!(
            "GetTokenInformation probe failed with win32 error {probe_err}"
        )));
    }
    let alloc_len = usize::try_from(needed).unwrap_or(0);
    if alloc_len == 0 || alloc_len > 64 * 1024 {
        return Err(PeerError::Unverifiable(format!(
            "invalid token info buffer size {alloc_len}"
        )));
    }
    let words = alloc_len.div_ceil(std::mem::size_of::<u64>());
    let mut buf = vec![0u64; words];
    let buf_bytes = words.saturating_mul(std::mem::size_of::<u64>());
    let buf_u32 = u32::try_from(buf_bytes).unwrap_or(u32::MAX);
    let mut written: u32 = 0;
    // SAFETY: `buf` is 8-byte aligned `Vec<u64>` with capacity `buf_bytes >= needed`.
    let ok = unsafe {
        GetTokenInformation(
            tok,
            class,
            buf.as_mut_ptr().cast::<c_void>(),
            buf_u32,
            &mut written,
        )
    };
    let written_usize = usize::try_from(written).unwrap_or(0);
    if ok == 0 || written_usize == 0 || written_usize > buf_bytes {
        return Err(PeerError::Unverifiable(format!(
            "GetTokenInformation failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok((buf, written_usize))
}

#[allow(
    unsafe_code,
    reason = "Win32 ConvertSidToStringSidW with bounded NUL check"
)]
pub(crate) fn psid_to_string(psid: PSID) -> Result<String, PeerError> {
    if psid.is_null() {
        return Err(PeerError::Unverifiable("null PSID pointer".to_string()));
    }
    let mut wide_ptr: *mut u16 = null_mut();
    // SAFETY: `ConvertSidToStringSidW` allocates NUL-terminated UTF-16 freed by `LocalAllocGuard`.
    let ok = unsafe { ConvertSidToStringSidW(psid, &mut wide_ptr) };
    let _guard = LocalAllocGuard(wide_ptr.cast::<c_void>());
    if ok == 0 || wide_ptr.is_null() {
        return Err(PeerError::Unverifiable(format!(
            "ConvertSidToStringSidW failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    let mut units = Vec::with_capacity(64);
    let mut terminated = false;
    for offset in 0..256isize {
        // SAFETY: `wide_ptr` is NUL-terminated UTF-16 and stopped within 256 code units.
        let ch = unsafe { *wide_ptr.offset(offset) };
        if ch == 0 {
            terminated = true;
            break;
        }
        units.push(ch);
    }
    if !terminated {
        return Err(PeerError::Unverifiable(
            "SID string exceeded 256 UTF-16 code units without NUL".to_string(),
        ));
    }
    String::from_utf16(&units)
        .map_err(|_| PeerError::Unverifiable("invalid UTF-16 SID string".to_string()))
}
