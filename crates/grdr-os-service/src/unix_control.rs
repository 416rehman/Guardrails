// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Unix signal handlers (`SIGHUP` reload, `SIGTERM`/`SIGINT` stop), systemd
//! `NOTIFY_SOCKET` datagrams, and macOS `launch_activate_socket` plumbing.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::ServiceError;

#[cfg(target_os = "macos")]
const MAX_LAUNCHD_ACTIVATE_FDS: usize = 64;

static RELOAD_FLAG: AtomicBool = AtomicBool::new(false);
static SHUTDOWN_FLAG: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "macos")]
struct MallocGuard(*mut libc::c_void);

#[cfg(target_os = "macos")]
impl Drop for MallocGuard {
    #[allow(unsafe_code, reason = "Frees launch_activate_socket malloc allocation")]
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` was allocated by libsystem `launch_activate_socket` via malloc.
            unsafe {
                libc::free(self.0);
            }
        }
    }
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code, reason = "Apple libsystem launch_activate_socket C ABI")]
unsafe extern "C" {
    fn launch_activate_socket(
        name: *const libc::c_char,
        fds: *mut *mut libc::c_int,
        cnt: *mut libc::size_t,
    ) -> libc::c_int;
}

pub fn request_reload() {
    RELOAD_FLAG.store(true, Ordering::SeqCst);
}

#[must_use]
pub fn take_reload_requested() -> bool {
    RELOAD_FLAG.swap(false, Ordering::SeqCst)
}

pub fn request_shutdown() {
    SHUTDOWN_FLAG.store(true, Ordering::SeqCst);
}

#[must_use]
pub fn shutdown_requested() -> bool {
    SHUTDOWN_FLAG.load(Ordering::SeqCst)
}

#[cfg(unix)]
extern "C" fn handle_sighup(_sig: libc::c_int) {
    RELOAD_FLAG.store(true, Ordering::Release);
}

#[cfg(unix)]
extern "C" fn handle_shutdown(_sig: libc::c_int) {
    SHUTDOWN_FLAG.store(true, Ordering::Release);
}

#[cfg(unix)]
pub fn install_signal_handlers() -> Result<(), ServiceError> {
    register_unix_signal(libc::SIGHUP, handle_sighup, libc::SA_RESTART)?;
    register_unix_signal(libc::SIGTERM, handle_shutdown, 0)?;
    register_unix_signal(libc::SIGINT, handle_shutdown, 0)?;
    Ok(())
}

#[cfg(not(unix))]
pub fn install_signal_handlers() -> Result<(), ServiceError> {
    Ok(())
}

#[cfg(unix)]
#[allow(
    unsafe_code,
    reason = "POSIX sigaction signal registration requires FFI"
)]
fn register_unix_signal(
    signal: libc::c_int,
    handler: extern "C" fn(libc::c_int),
    flags: libc::c_int,
) -> Result<(), ServiceError> {
    // SAFETY: sigaction is populated with a valid async-signal-safe fn pointer and initialized sa_mask.
    let rc = unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = handler as libc::sighandler_t;
        action.sa_flags = flags;
        if libc::sigemptyset(&mut action.sa_mask) != 0 {
            return Err(ServiceError::NotifyFailed(format!(
                "sigemptyset failed for signal {signal}: {}",
                std::io::Error::last_os_error()
            )));
        }
        libc::sigaction(signal, &action, std::ptr::null_mut())
    };
    if rc != 0 {
        return Err(ServiceError::NotifyFailed(format!(
            "sigaction failed for signal {signal}: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(unix)]
pub fn send_systemd_notify(notify_socket: &str, payload: &str) -> Result<(), ServiceError> {
    if notify_socket.trim().is_empty() {
        return Err(ServiceError::InvalidActivation(
            "NOTIFY_SOCKET cannot be empty".to_string(),
        ));
    }
    crate::lifecycle::send_systemd_notify_to_socket(notify_socket, payload)
}

#[cfg(not(unix))]
pub fn send_systemd_notify(_notify_socket: &str, _payload: &str) -> Result<(), ServiceError> {
    Ok(())
}

#[cfg(target_os = "macos")]
#[allow(
    unsafe_code,
    reason = "launch_activate_socket FFI and fcntl FD_CLOEXEC setup"
)]
pub fn activate_macos_sockets(
    socket_name: &str,
) -> Result<Vec<std::os::fd::OwnedFd>, ServiceError> {
    use std::ffi::CString;
    use std::os::fd::{FromRawFd, OwnedFd};

    if socket_name.trim().is_empty() {
        return Err(ServiceError::InvalidActivation(
            "launchd socket name cannot be empty".to_string(),
        ));
    }
    let cname = CString::new(socket_name).map_err(|_| {
        ServiceError::InvalidActivation("launchd socket name contains interior NUL".to_string())
    })?;
    let mut raw_ptr: *mut libc::c_int = std::ptr::null_mut();
    let mut count: libc::size_t = 0;

    // SAFETY: `cname` is NUL-terminated; `MallocGuard` guarantees `raw_ptr` is freed on every exit.
    let rc = unsafe { launch_activate_socket(cname.as_ptr(), &mut raw_ptr, &mut count) };
    let _free_guard = MallocGuard(raw_ptr.cast::<libc::c_void>());
    if rc != 0 {
        return Err(ServiceError::InvalidActivation(format!(
            "launch_activate_socket('{socket_name}') failed with errno {rc}"
        )));
    }
    if raw_ptr.is_null() || count == 0 {
        return Ok(Vec::new());
    }
    if count > MAX_LAUNCHD_ACTIVATE_FDS {
        return Err(ServiceError::InvalidActivation(format!(
            "launch_activate_socket returned {count} fds exceeding limit {MAX_LAUNCHD_ACTIVATE_FDS}"
        )));
    }

    let mut owned = Vec::with_capacity(count);
    // SAFETY: `raw_ptr` holds `count` open descriptors returned by launchd for this call.
    let slice = unsafe { std::slice::from_raw_parts(raw_ptr, count) };
    for (idx, &fd) in slice.iter().enumerate() {
        if fd <= 2 {
            close_remaining_raw_fds(slice.get(idx..).unwrap_or_default());
            return Err(ServiceError::InvalidActivation(format!(
                "launch_activate_socket returned reserved stdio fd {fd}"
            )));
        }
        // SAFETY: `fd` is a valid descriptor >= 3 returned by launchd.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            close_remaining_raw_fds(slice.get(idx..).unwrap_or_default());
            return Err(ServiceError::InvalidActivation(format!(
                "fcntl(F_GETFD) failed for launchd fd {fd}: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: setting `FD_CLOEXEC` prevents leaking activated listening sockets into child processes.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } != 0 {
            close_remaining_raw_fds(slice.get(idx..).unwrap_or_default());
            return Err(ServiceError::InvalidActivation(format!(
                "fcntl(F_SETFD, FD_CLOEXEC) failed for launchd fd {fd}: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: validated non-stdio fd wrapped exclusively in OwnedFd here.
        owned.push(unsafe { OwnedFd::from_raw_fd(fd) });
    }
    Ok(owned)
}

#[cfg(target_os = "macos")]
#[allow(
    unsafe_code,
    reason = "Closes remaining launchd descriptors on validation error"
)]
fn close_remaining_raw_fds(fds: &[libc::c_int]) {
    for &raw_fd in fds {
        if raw_fd > 2 {
            // SAFETY: `raw_fd` was returned by launchd, not yet wrapped in `OwnedFd`, and not yet closed.
            unsafe {
                libc::close(raw_fd);
            }
        }
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn activate_macos_sockets(
    _socket_name: &str,
) -> Result<Vec<std::os::fd::OwnedFd>, ServiceError> {
    Ok(Vec::new())
}
