// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::ffi::{CString, c_long, c_void};

use zeroize::Zeroizing;

use crate::IdentityError;

const KEY_TYPE_USER: &[u8] = b"user\0";
const KEY_SPEC_USER_KEYRING: libc::c_int = -4;
const DEST_UNLINKED: libc::c_int = 0;
const KEYCTL_REVOKE: c_long = 3;
const KEYCTL_UNLINK: c_long = 9;
const KEYCTL_SEARCH: c_long = 10;
const KEYCTL_READ: c_long = 11;
const MAX_KEYRING_BYTES: usize = 65_536;

pub(crate) fn add_user_key(description: &str, payload: &[u8]) -> Result<i32, IdentityError> {
    if payload.is_empty() || payload.len() > MAX_KEYRING_BYTES {
        return Err(IdentityError::SecretStore(
            "Linux keyring payload must be 1..=64KiB".to_string(),
        ));
    }
    let desc = CString::new(description).map_err(|_| {
        IdentityError::SecretStore("Linux keyring description contains NUL byte".to_string())
    })?;
    #[allow(
        unsafe_code,
        reason = "Insert secret payload into Linux user kernel keyring via SYS_add_key."
    )]
    // SAFETY: Static KEY_TYPE_USER, CString desc, and payload pointer remain valid during SYS_add_key.
    let serial = unsafe {
        libc::syscall(
            libc::SYS_add_key,
            KEY_TYPE_USER.as_ptr().cast::<libc::c_char>(),
            desc.as_ptr(),
            payload.as_ptr().cast::<c_void>(),
            payload.len(),
            KEY_SPEC_USER_KEYRING,
        )
    };
    if serial < 0 {
        return Err(IdentityError::SecretStore(format!(
            "Linux add_key failed ({})",
            std::io::Error::last_os_error()
        )));
    }
    i32::try_from(serial)
        .map_err(|_| IdentityError::SecretStore("key serial out of range".to_string()))
}

pub(crate) fn lookup_user_key_serial(description: &str) -> Result<Option<i32>, IdentityError> {
    let desc = CString::new(description).map_err(|_| {
        IdentityError::SecretStore("Linux keyring description contains NUL byte".to_string())
    })?;
    #[allow(
        unsafe_code,
        reason = "Locate secret key serial in Linux kernel keyring via SYS_request_key."
    )]
    // SAFETY: Static KEY_TYPE_USER and CString desc are NUL-terminated for SYS_request_key.
    let mut serial = unsafe {
        libc::syscall(
            libc::SYS_request_key,
            KEY_TYPE_USER.as_ptr().cast::<libc::c_char>(),
            desc.as_ptr(),
            std::ptr::null::<libc::c_char>(),
            DEST_UNLINKED,
        )
    };
    if serial < 0 {
        let req_err = std::io::Error::last_os_error();
        let req_raw = req_err.raw_os_error();
        if req_raw == Some(libc::EKEYREVOKED) {
            return Ok(None);
        }
        if req_raw != Some(libc::ENOKEY) {
            return Err(IdentityError::SecretStore(format!(
                "Linux request_key failed ({req_err})"
            )));
        }
        #[allow(
            unsafe_code,
            reason = "Fallback key search in KEY_SPEC_USER_KEYRING via KEYCTL_SEARCH."
        )]
        // SAFETY: KEY_TYPE_USER and CString desc are NUL-terminated for SYS_keyctl KEYCTL_SEARCH.
        serial = unsafe {
            libc::syscall(
                libc::SYS_keyctl,
                KEYCTL_SEARCH,
                KEY_SPEC_USER_KEYRING,
                KEY_TYPE_USER.as_ptr().cast::<libc::c_char>(),
                desc.as_ptr(),
                DEST_UNLINKED,
            )
        };
        if serial < 0 {
            let search_err = std::io::Error::last_os_error();
            let search_raw = search_err.raw_os_error();
            if search_raw == Some(libc::ENOKEY) || search_raw == Some(libc::EKEYREVOKED) {
                return Ok(None);
            }
            return Err(IdentityError::SecretStore(format!(
                "Linux keyctl KEYCTL_SEARCH failed ({search_err})"
            )));
        }
    }

    let key_id = i32::try_from(serial)
        .map_err(|_| IdentityError::SecretStore("key serial out of range".to_string()))?;
    Ok(Some(key_id))
}

pub(crate) fn request_user_key(
    description: &str,
) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
    let Some(key_id) = lookup_user_key_serial(description)? else {
        return Ok(None);
    };
    let mut buf = Zeroizing::new(vec![0u8; MAX_KEYRING_BYTES]);
    #[allow(
        unsafe_code,
        reason = "Read secret payload bytes from Linux kernel keyring via SYS_keyctl."
    )]
    // SAFETY: buf is writable for MAX_KEYRING_BYTES bytes during KEYCTL_READ.
    let read_len = unsafe {
        libc::syscall(
            libc::SYS_keyctl,
            KEYCTL_READ,
            key_id,
            buf.as_mut_ptr().cast::<c_void>(),
            buf.len(),
        )
    };
    if read_len < 0 {
        return Err(IdentityError::SecretStore(format!(
            "Linux keyctl KEYCTL_READ failed ({})",
            std::io::Error::last_os_error()
        )));
    }
    let used = usize::try_from(read_len)
        .map_err(|_| IdentityError::SecretStore("negative keyring read length".to_string()))?;
    if used > buf.len() {
        return Err(IdentityError::SecretStore(format!(
            "Linux keyring payload size {used} exceeds 64KiB cap"
        )));
    }
    buf.truncate(used);
    Ok(Some(buf))
}

pub(crate) fn revoke_user_key(serial: i32) -> Result<(), IdentityError> {
    #[allow(
        unsafe_code,
        reason = "Revoke key and unlink from Linux user kernel keyring via SYS_keyctl."
    )]
    // SAFETY: KEYCTL_REVOKE and KEYCTL_UNLINK take no pointers, only kernel key serial and keyring constant.
    let (revoke_rc, unlink_rc) = unsafe {
        let r = libc::syscall(libc::SYS_keyctl, KEYCTL_REVOKE, serial);
        let u = libc::syscall(
            libc::SYS_keyctl,
            KEYCTL_UNLINK,
            serial,
            KEY_SPEC_USER_KEYRING,
        );
        (r, u)
    };
    if revoke_rc < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ENOKEY) && err.raw_os_error() != Some(libc::EKEYREVOKED)
        {
            return Err(IdentityError::SecretStore(format!(
                "Linux keyctl KEYCTL_REVOKE failed ({err})"
            )));
        }
    }
    if unlink_rc < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ENOKEY) {
            return Err(IdentityError::SecretStore(format!(
                "Linux keyctl KEYCTL_UNLINK failed ({err})"
            )));
        }
    }
    Ok(())
}
