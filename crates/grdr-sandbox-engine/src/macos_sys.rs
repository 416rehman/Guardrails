// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::ffi::{CStr, c_char, c_int};
use std::io;
use std::ptr::{null, null_mut};

#[allow(
    unsafe_code,
    reason = "Apple libSystem Seatbelt bindings for async-signal-safe pre_exec enforcement."
)]
// SAFETY: Darwin libSystem sandbox_init_with_parameters / sandbox_free_error C ABI declarations.
unsafe extern "C" {
    fn sandbox_init_with_parameters(
        profile: *const c_char,
        flags: u64,
        parameters: *const *const c_char,
        errorbuf: *mut *mut c_char,
    ) -> c_int;
    fn sandbox_free_error(errorbuf: *mut c_char);
}

pub(crate) fn apply_seatbelt_in_pre_exec(profile: &CStr) -> io::Result<()> {
    let mut err_buf: *mut c_char = null_mut();
    #[allow(
        unsafe_code,
        reason = "Invoke Apple sandbox_init_with_parameters inside child pre_exec before execvp."
    )]
    // SAFETY: profile is a pre-allocated NUL-terminated CString living in the closure until exec; no heap allocation occurs here.
    let rc = unsafe { sandbox_init_with_parameters(profile.as_ptr(), 0, null(), &mut err_buf) };
    if !err_buf.is_null() {
        #[allow(
            unsafe_code,
            reason = "Free Seatbelt diagnostic buffer returned by sandbox_init_with_parameters."
        )]
        // SAFETY: Non-null error buffer allocated by sandbox_init_with_parameters.
        let () = unsafe {
            sandbox_free_error(err_buf);
        };
    }
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(libc::EPERM));
    }
    Ok(())
}
