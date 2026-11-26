// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::os::unix::net::UnixListener;
use std::path::Path;

use crate::IpcError;
use crate::endpoint::{
    LINUX_SUN_PATH_LIMIT, LocalEndpointAddress, MACOS_SUN_PATH_LIMIT, TargetOsKind,
    validate_endpoint_address,
};

#[allow(unsafe_code, reason = "POSIX fcntl(FD_CLOEXEC) on unix socket fd")]
pub(crate) fn set_fd_cloexec<F: std::os::fd::AsRawFd>(fd_owner: &F) -> Result<(), IpcError> {
    let raw = fd_owner.as_raw_fd();
    // SAFETY: `raw` is an open valid file descriptor borrowed from `fd_owner`.
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFD) };
    if flags < 0 {
        return Err(IpcError::Io(std::io::Error::last_os_error().to_string()));
    }
    // SAFETY: sets `FD_CLOEXEC` on `raw` to prevent leaking socket handles across exec.
    if unsafe { libc::fcntl(raw, libc::F_SETFD, flags | libc::FD_CLOEXEC) } != 0 {
        return Err(IpcError::Io(std::io::Error::last_os_error().to_string()));
    }
    Ok(())
}

pub(crate) fn bind_unix_listener_with_mode(
    address: &LocalEndpointAddress,
    socket_mode: u32,
) -> Result<(UnixListener, &Path), IpcError> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    validate_endpoint_address(TargetOsKind::current(), address)?;
    let LocalEndpointAddress::UnixSocket { path } = address else {
        return Err(IpcError::InvalidAddress(
            "UnixDomainAcceptor requires UnixSocket address".into(),
        ));
    };
    let parent = path.parent().ok_or_else(|| {
        IpcError::InvalidAddress("unix socket path must have parent directory".into())
    })?;
    let max_sun_path = if cfg!(target_os = "macos") {
        MACOS_SUN_PATH_LIMIT
    } else {
        LINUX_SUN_PATH_LIMIT
    };
    let stage_dir = parent.join(format!(".grdr-s-{}", std::process::id()));
    let stage_sock = stage_dir.join("s");
    if stage_sock.to_string_lossy().len() < max_sun_path {
        let _ = std::fs::remove_dir_all(&stage_dir);
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(&stage_dir).map_err(|e| {
            IpcError::Io(format!(
                "create staging dir `{}` failed: {e}",
                stage_dir.display()
            ))
        })?;
        let listener = UnixListener::bind(&stage_sock).map_err(|e| {
            let _ = std::fs::remove_dir_all(&stage_dir);
            IpcError::Io(format!("bind `{}` failed: {e}", path.display()))
        })?;
        if let Err(err) = set_fd_cloexec(&listener).and_then(|()| {
            std::fs::set_permissions(
                &stage_sock,
                std::fs::Permissions::from_mode(socket_mode & 0o777),
            )
            .map_err(|e| IpcError::Io(format!("set_permissions `{}` failed: {e}", path.display())))
        }) {
            drop(listener);
            let _ = std::fs::remove_dir_all(&stage_dir);
            return Err(err);
        }
        if let Err(err) = std::fs::rename(&stage_sock, path) {
            drop(listener);
            let _ = std::fs::remove_dir_all(&stage_dir);
            return Err(IpcError::Io(format!(
                "rename socket `{}` failed: {err}",
                path.display()
            )));
        }
        let _ = std::fs::remove_dir(&stage_dir);
        return Ok((listener, path.as_path()));
    }
    let listener = UnixListener::bind(path)
        .map_err(|e| IpcError::Io(format!("bind `{}` failed: {e}", path.display())))?;
    set_fd_cloexec(&listener)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(socket_mode & 0o777))
        .map_err(|e| IpcError::Io(format!("set_permissions `{}` failed: {e}", path.display())))?;
    Ok((listener, path.as_path()))
}
