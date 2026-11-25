// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Symlink-resistant staging file I/O helpers with per-platform `O_NOFOLLOW` /
//! `FILE_FLAG_OPEN_REPARSE_POINT` enforcement and regular-file identity checks.

use std::fs::{File, Metadata, OpenOptions};
use std::path::Path;

use crate::error::UplinkError;

#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;

#[cfg(unix)]
const fn unix_o_nofollow() -> i32 {
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "openbsd"
    ))]
    {
        0x0100
    }
    #[cfg(target_os = "netbsd")]
    {
        0x0001_0000
    }
    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        any(
            target_arch = "aarch64",
            target_arch = "arm",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "m68k"
        )
    ))]
    {
        0o100_000
    }
    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        any(
            target_arch = "mips",
            target_arch = "mips64",
            target_arch = "sparc",
            target_arch = "sparc64"
        )
    ))]
    {
        0x20000
    }
    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        not(any(
            target_arch = "aarch64",
            target_arch = "arm",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "m68k",
            target_arch = "mips",
            target_arch = "mips64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ))]
    {
        0o400_000
    }
}

/// Apply kernel-level symlink/reparse non-following flags to an `OpenOptions` handle.
pub(crate) fn apply_nofollow_flags(opts: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.custom_flags(unix_o_nofollow());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
}

/// Open an existing regular file strictly with `O_NOFOLLOW` / `FILE_FLAG_OPEN_REPARSE_POINT`
/// and verify handle identity matches `lstat` metadata.
pub(crate) fn open_regular_nofollow_read(path: &Path) -> Result<(File, Metadata), UplinkError> {
    let lstat_meta = std::fs::symlink_metadata(path).map_err(|e| UplinkError::Io {
        detail: format!("failed to inspect staging file {}: {e}", path.display()),
    })?;
    let mut opts = OpenOptions::new();
    opts.read(true);
    apply_nofollow_flags(&mut opts);
    let file = opts.open(path).map_err(|e| UplinkError::Io {
        detail: format!("failed to open staging file {}: {e}", path.display()),
    })?;
    let fd_meta = file.metadata().map_err(|e| UplinkError::Io {
        detail: format!("failed to stat staging file {}: {e}", path.display()),
    })?;
    verify_same_regular_file(&lstat_meta, &fd_meta)?;
    Ok((file, fd_meta))
}

/// Create or open a `.part` file for append with `O_NOFOLLOW` / `FILE_FLAG_OPEN_REPARSE_POINT`,
/// refusing any symlink or reparse swap before bytes are written.
pub(crate) fn open_part_nofollow_append(path: &Path) -> Result<(File, Metadata), UplinkError> {
    ensure_not_symlink_if_exists(path)?;
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    apply_nofollow_flags(&mut opts);
    let file = opts.open(path).map_err(|e| UplinkError::Io {
        detail: format!("failed to open staging partial file: {e}"),
    })?;
    let fd_meta = file.metadata().map_err(|e| UplinkError::Io {
        detail: format!("failed to stat opened staging file: {e}"),
    })?;
    let lstat_meta = std::fs::symlink_metadata(path).map_err(|e| UplinkError::Io {
        detail: format!("failed to lstat staging partial file: {e}"),
    })?;
    verify_same_regular_file(&lstat_meta, &fd_meta)?;
    Ok((file, fd_meta))
}

pub(crate) fn ensure_ancestors_safe(path: &Path) -> Result<(), UplinkError> {
    let mut cur = path.parent();
    while let Some(dir) = cur {
        if dir.as_os_str().is_empty() {
            break;
        }
        if let Ok(meta) = std::fs::symlink_metadata(dir)
            && is_symlink_or_reparse(&meta)
        {
            return Err(UplinkError::StagingError {
                detail: format!("refusing symlinked staging ancestor {}", dir.display()),
            });
        }
        cur = dir.parent();
    }
    Ok(())
}

pub(crate) fn ensure_not_symlink_if_exists(path: &Path) -> Result<(), UplinkError> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if is_symlink_or_reparse(&meta) {
                return Err(UplinkError::StagingError {
                    detail: format!("refusing symlinked staging path {}", path.display()),
                });
            }
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(UplinkError::Io {
            detail: format!("failed to inspect staging path {}: {err}", path.display()),
        }),
    }
}

fn is_symlink_or_reparse(meta: &Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        meta.file_type().is_symlink()
            || (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
    }
    #[cfg(not(windows))]
    {
        meta.file_type().is_symlink()
    }
}

#[cfg(unix)]
pub(crate) fn verify_same_regular_file(
    lstat_meta: &Metadata,
    fd_meta: &Metadata,
) -> Result<(), UplinkError> {
    use std::os::unix::fs::MetadataExt as _;
    if lstat_meta.file_type().is_symlink()
        || !fd_meta.file_type().is_file()
        || lstat_meta.dev() != fd_meta.dev()
        || lstat_meta.ino() != fd_meta.ino()
    {
        return Err(UplinkError::StagingError {
            detail: "staging file identity changed during open".to_string(),
        });
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) fn verify_same_regular_file(
    lstat_meta: &Metadata,
    fd_meta: &Metadata,
) -> Result<(), UplinkError> {
    use std::os::windows::fs::MetadataExt as _;
    if is_symlink_or_reparse(lstat_meta)
        || is_symlink_or_reparse(fd_meta)
        || !fd_meta.file_type().is_file()
        || lstat_meta.file_attributes() != fd_meta.file_attributes()
        || lstat_meta.creation_time() != fd_meta.creation_time()
        || lstat_meta.file_size() != fd_meta.file_size()
    {
        return Err(UplinkError::StagingError {
            detail: "staging file identity or reparse state invalid".to_string(),
        });
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn verify_same_regular_file(
    lstat_meta: &Metadata,
    fd_meta: &Metadata,
) -> Result<(), UplinkError> {
    if lstat_meta.file_type().is_symlink() || !fd_meta.file_type().is_file() {
        return Err(UplinkError::StagingError {
            detail: "staging path is not a regular file".to_string(),
        });
    }
    Ok(())
}
