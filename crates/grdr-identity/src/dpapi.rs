// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};
use zeroize::{Zeroize, Zeroizing};

use crate::IdentityError;

const MAX_DPAPI_PAYLOAD_BYTES: usize = 1024 * 1024;
const DPAPI_ENVELOPE_OVERHEAD_BYTES: usize = 4_096;
pub(crate) const MAX_DPAPI_CIPHER_BYTES: usize =
    MAX_DPAPI_PAYLOAD_BYTES + DPAPI_ENVELOPE_OVERHEAD_BYTES;

struct LocalBlobGuard {
    ptr: *mut u8,
    len: usize,
}

impl Drop for LocalBlobGuard {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            if self.len > 0 {
                #[allow(
                    unsafe_code,
                    reason = "Zeroize decrypted DPAPI plaintext before LocalFree."
                )]
                // SAFETY: self.ptr covers self.len writable bytes allocated by Win32 CryptProtectData/CryptUnprotectData.
                let slice = unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) };
                slice.zeroize();
            }
            #[allow(
                unsafe_code,
                reason = "Release Win32 LocalAlloc blob returned by DPAPI."
            )]
            // SAFETY: self.ptr originated from DPAPI pbData and is freed once via LocalFree.
            unsafe {
                let _ = LocalFree(self.ptr as *mut core::ffi::c_void);
            }
            self.ptr = null_mut();
        }
    }
}

pub(crate) fn protect_bytes(plaintext: &[u8], entropy: &[u8]) -> Result<Vec<u8>, IdentityError> {
    if plaintext.is_empty() || plaintext.len() > MAX_DPAPI_PAYLOAD_BYTES {
        return Err(IdentityError::SecretStore(
            "DPAPI plaintext must be 1..=1MiB".to_string(),
        ));
    }
    let in_len = u32::try_from(plaintext.len())
        .map_err(|_| IdentityError::SecretStore("DPAPI plaintext length overflow".to_string()))?;
    let ent_len = u32::try_from(entropy.len())
        .map_err(|_| IdentityError::SecretStore("DPAPI entropy length overflow".to_string()))?;

    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: in_len,
        pbData: plaintext.as_ptr().cast_mut(),
    };
    let ent_blob = CRYPT_INTEGER_BLOB {
        cbData: ent_len,
        pbData: if entropy.is_empty() {
            null_mut()
        } else {
            entropy.as_ptr().cast_mut()
        },
    };
    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };

    let ent_ptr = if entropy.is_empty() {
        null()
    } else {
        &ent_blob as *const _
    };
    #[allow(
        unsafe_code,
        reason = "Encrypt secret bytes under Windows user DPAPI master key."
    )]
    // SAFETY: Input blobs stay alive across CryptProtectData; out_blob is guarded by LocalBlobGuard.
    let ok = unsafe {
        CryptProtectData(
            &in_blob,
            null(),
            ent_ptr,
            null(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
    };
    if ok == 0 || out_blob.pbData.is_null() {
        return Err(IdentityError::SecretStore(format!(
            "CryptProtectData failed ({})",
            std::io::Error::last_os_error()
        )));
    }
    let out_len = usize::try_from(out_blob.cbData).unwrap_or(0);
    let guard = LocalBlobGuard {
        ptr: out_blob.pbData,
        len: out_len,
    };
    #[allow(unsafe_code, reason = "Copy DPAPI encrypted bytes into owned Vec<u8>.")]
    // SAFETY: guard.ptr covers guard.len initialized bytes returned by CryptProtectData.
    let cipher = unsafe { std::slice::from_raw_parts(guard.ptr, guard.len) }.to_vec();
    Ok(cipher)
}

pub(crate) fn unprotect_bytes(
    ciphertext: &[u8],
    entropy: &[u8],
) -> Result<Zeroizing<Vec<u8>>, IdentityError> {
    if ciphertext.is_empty() || ciphertext.len() > MAX_DPAPI_CIPHER_BYTES {
        return Err(IdentityError::SecretStore(
            "DPAPI ciphertext must be 1..=MAX_DPAPI_CIPHER_BYTES".to_string(),
        ));
    }
    let in_len = u32::try_from(ciphertext.len())
        .map_err(|_| IdentityError::SecretStore("DPAPI ciphertext length overflow".to_string()))?;
    let ent_len = u32::try_from(entropy.len())
        .map_err(|_| IdentityError::SecretStore("DPAPI entropy length overflow".to_string()))?;

    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: in_len,
        pbData: ciphertext.as_ptr().cast_mut(),
    };
    let ent_blob = CRYPT_INTEGER_BLOB {
        cbData: ent_len,
        pbData: if entropy.is_empty() {
            null_mut()
        } else {
            entropy.as_ptr().cast_mut()
        },
    };
    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };

    let ent_ptr = if entropy.is_empty() {
        null()
    } else {
        &ent_blob as *const _
    };
    #[allow(
        unsafe_code,
        reason = "Decrypt DPAPI protected secret bytes under current Windows user."
    )]
    // SAFETY: Input blobs stay alive across CryptUnprotectData; out_blob is zeroized and freed on Drop.
    let ok = unsafe {
        CryptUnprotectData(
            &in_blob,
            null_mut(),
            ent_ptr,
            null(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
    };
    if ok == 0 || out_blob.pbData.is_null() {
        return Err(IdentityError::SecretStore(format!(
            "CryptUnprotectData failed ({})",
            std::io::Error::last_os_error()
        )));
    }
    let out_len = usize::try_from(out_blob.cbData).unwrap_or(0);
    let guard = LocalBlobGuard {
        ptr: out_blob.pbData,
        len: out_len,
    };
    #[allow(
        unsafe_code,
        reason = "Copy decrypted DPAPI bytes into Zeroizing container."
    )]
    // SAFETY: guard.ptr covers guard.len initialized plaintext bytes until guard drops and zeroizes.
    let plain = unsafe { std::slice::from_raw_parts(guard.ptr, guard.len) }.to_vec();
    Ok(Zeroizing::new(plain))
}
