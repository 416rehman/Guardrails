// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Symlink-resistant staging file I/O helpers with per-platform `O_NOFOLLOW` /
//! `FILE_FLAG_OPEN_REPARSE_POINT` enforcement and regular-file identity checks.

use std::fs::{File, Metadata, OpenOptions};
use std::path::{Component, Path};

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

pub(crate) fn reject_staging_traversal(path: &Path) -> Result<(), UplinkError> {
    if path.as_os_str().is_empty()
        || path.to_string_lossy().contains('\0')
        || path.components().any(|c| matches!(c, Component::ParentDir))
    {
        return Err(UplinkError::StagingError {
            detail: "staging path empty, NUL, or contains '..' traversal".to_string(),
        });
    }
    Ok(())
}

/// Ensure `dir` is an existing or freshly created private non-symlink directory (`0o700` on Unix).
pub(crate) fn ensure_private_staging_dir(dir: &Path) -> Result<(), UplinkError> {
    reject_staging_traversal(dir)?;
    let shared_temp = std::env::temp_dir();
    if dir == Path::new("/tmp")
        || dir == Path::new("/private/tmp")
        || dir == Path::new("/dev/shm")
        || dir == shared_temp
    {
        return Err(UplinkError::StagingError {
            detail: "refusing shared temporary directory directly as staging root".to_string(),
        });
    }
    ensure_ancestors_safe(dir)?;
    ensure_not_symlink_if_exists(dir)?;
    #[cfg(windows)]
    {
        grdr_peer_os::fs_open::create_private_dir_all(dir).map_err(|e| {
            UplinkError::StagingError {
                detail: e.to_string(),
            }
        })?;
    }
    #[cfg(not(windows))]
    create_private_dir_components(dir)?;

    let dir_file = open_dir_nofollow(dir)?;
    let meta = dir_file.metadata().map_err(|e| UplinkError::Io {
        detail: format!("failed to inspect staging root {}: {e}", dir.display()),
    })?;
    if is_symlink_or_reparse(&meta) || !meta.is_dir() {
        return Err(UplinkError::StagingError {
            detail: format!("staging root {} is not a safe directory", dir.display()),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let (my_uid, _) = grdr_peer_os::unix_peer::current_effective_ids().ok_or_else(|| {
            UplinkError::StagingError {
                detail: "unable to determine effective UID for staging root ownership check"
                    .to_string(),
            }
        })?;
        if meta.uid() != my_uid {
            return Err(UplinkError::StagingError {
                detail: format!("staging root {} owned by unexpected uid", dir.display()),
            });
        }
        dir_file
            .set_permissions(std::fs::Permissions::from_mode(0o700))
            .map_err(|e| UplinkError::Io {
                detail: format!("failed to enforce 0o700 mode on staging root: {e}"),
            })?;
        let re_meta = dir_file.metadata().map_err(|e| UplinkError::Io {
            detail: format!("failed to re-stat staging root {}: {e}", dir.display()),
        })?;
        if (re_meta.mode() & 0o077) != 0 || is_symlink_or_reparse(&re_meta) {
            return Err(UplinkError::StagingError {
                detail: format!("staging root {} permissions are not private", dir.display()),
            });
        }
    }
    #[cfg(windows)]
    {
        grdr_peer_os::fs_open::verify_open_dir_trust(&dir_file, dir, false).map_err(|e| {
            UplinkError::StagingError {
                detail: e.to_string(),
            }
        })?;
    }
    Ok(())
}

#[cfg(not(windows))]
fn create_private_dir_components(dir: &Path) -> Result<(), UplinkError> {
    let mut acc = std::path::PathBuf::new();
    for comp in dir.components() {
        acc.push(comp.as_os_str());
        if matches!(
            comp,
            Component::Prefix(_) | Component::RootDir | Component::CurDir
        ) {
            continue;
        }
        match std::fs::symlink_metadata(&acc) {
            Ok(meta) => {
                if is_symlink_or_reparse(&meta) && !is_os_root_alias(&acc, &meta) {
                    return Err(UplinkError::StagingError {
                        detail: format!("refusing symlink staging component {}", acc.display()),
                    });
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt as _;
                    std::fs::DirBuilder::new()
                        .mode(0o700)
                        .create(&acc)
                        .map_err(|e| UplinkError::Io {
                            detail: format!("failed to create staging dir {}: {e}", acc.display()),
                        })?;
                }
                #[cfg(not(unix))]
                {
                    std::fs::create_dir(&acc).map_err(|e| UplinkError::Io {
                        detail: format!("failed to create staging dir {}: {e}", acc.display()),
                    })?;
                }
            }
            Err(err) => {
                return Err(UplinkError::Io {
                    detail: format!(
                        "failed to inspect staging component {}: {err}",
                        acc.display()
                    ),
                });
            }
        }
    }
    Ok(())
}

fn open_dir_nofollow(dir: &Path) -> Result<File, UplinkError> {
    grdr_peer_os::fs_open::open_nofollow_dir(dir).map_err(|e| UplinkError::StagingError {
        detail: e.to_string(),
    })
}

/// Set private `0o600` file permissions via an open non-symlink file handle.
pub(crate) fn set_private_file_handle_permissions(
    file: &File,
    path: &Path,
) -> Result<(), UplinkError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| UplinkError::Io {
                detail: format!("failed to enforce 0o600 mode on {}: {e}", path.display()),
            })?;
    }
    #[cfg(not(unix))]
    {
        let _ = (file, path);
    }
    Ok(())
}

/// Sync the parent directory of `path` after atomic rename on Unix.
pub(crate) fn sync_parent_dir(path: &Path) -> Result<(), UplinkError> {
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        let dir = File::open(parent).map_err(|e| UplinkError::Io {
            detail: format!("failed to open parent dir {}: {e}", parent.display()),
        })?;
        dir.sync_all().map_err(|e| UplinkError::Io {
            detail: format!("failed to sync parent dir {}: {e}", parent.display()),
        })?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Create or open a `.part` file for append with `O_NOFOLLOW` / `FILE_FLAG_OPEN_REPARSE_POINT`,
/// refusing any symlink or reparse swap before bytes are written.
pub(crate) fn open_part_nofollow_append(path: &Path) -> Result<(File, Metadata), UplinkError> {
    ensure_not_symlink_if_exists(path)?;
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if (fd_meta.mode() & 0o077) != 0 {
            return Err(UplinkError::StagingError {
                detail: "staging partial file has insecure group/other permissions".to_string(),
            });
        }
    }
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
            && !is_os_root_alias(dir, &meta)
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

#[cfg(any(target_os = "macos", test))]
fn is_expected_macos_root_alias_target(path: &Path, target: &Path) -> bool {
    matches!(
        (path.to_str(), target.to_str()),
        (Some("/var"), Some("private/var" | "/private/var"))
            | (Some("/tmp"), Some("private/tmp" | "/private/tmp"))
            | (Some("/etc"), Some("private/etc" | "/private/etc"))
    )
}

fn is_os_root_alias(path: &Path, meta: &Metadata) -> bool {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::MetadataExt as _;
        meta.uid() == 0
            && std::fs::read_link(path)
                .is_ok_and(|target| is_expected_macos_root_alias_target(path, &target))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (path, meta);
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_expected_macos_root_alias_targets() {
        assert!(is_expected_macos_root_alias_target(
            Path::new("/var"),
            Path::new("private/var")
        ));
        assert!(is_expected_macos_root_alias_target(
            Path::new("/var"),
            Path::new("/private/var")
        ));
        assert!(is_expected_macos_root_alias_target(
            Path::new("/tmp"),
            Path::new("private/tmp")
        ));
        assert!(is_expected_macos_root_alias_target(
            Path::new("/etc"),
            Path::new("/private/etc")
        ));
        assert!(!is_expected_macos_root_alias_target(
            Path::new("/var"),
            Path::new("/tmp/evil")
        ));
        assert!(!is_expected_macos_root_alias_target(
            Path::new("/var/folders"),
            Path::new("private/var")
        ));
        assert!(!is_expected_macos_root_alias_target(
            Path::new("var"),
            Path::new("private/var")
        ));
    }

    #[test]
    fn rejects_non_directory_ancestor_and_validates_regular_files() {
        let base =
            std::env::temp_dir().join(format!("grdr-uplink-fs-{}", uuid::Uuid::now_v7().simple()));
        std::fs::create_dir_all(&base).unwrap();
        let file_blocker = base.join("blocker");
        std::fs::write(&file_blocker, b"orig").unwrap();
        assert!(matches!(
            open_regular_nofollow_read(&file_blocker),
            Ok((_, _))
        ));
        assert!(ensure_not_symlink_if_exists(&file_blocker).is_ok());
        assert!(open_regular_nofollow_read(&base.join("missing")).is_err());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_ancestors_and_leaf_targets() {
        use std::os::unix::fs::symlink;

        let base =
            std::env::temp_dir().join(format!("grdr-uplink-sym-{}", uuid::Uuid::now_v7().simple()));
        let real_dir = base.join("real_dir");
        std::fs::create_dir_all(&real_dir).unwrap();
        let real_file = base.join("real_file");
        std::fs::write(&real_file, b"keep").unwrap();

        let dir_link = base.join("dir_link");
        symlink(&real_dir, &dir_link).unwrap();
        assert!(matches!(
            ensure_ancestors_safe(&dir_link.join("payload.part")),
            Err(UplinkError::StagingError { .. })
        ));

        let leaf_link = base.join("leaf_link");
        symlink(&real_file, &leaf_link).unwrap();
        assert!(matches!(
            ensure_not_symlink_if_exists(&leaf_link),
            Err(UplinkError::StagingError { .. })
        ));
        assert!(open_part_nofollow_append(&leaf_link).is_err());
        assert!(open_regular_nofollow_read(&leaf_link).is_err());

        let dangling_link = base.join("dangling_link");
        symlink(base.join("nonexistent"), &dangling_link).unwrap();
        assert!(matches!(
            ensure_not_symlink_if_exists(&dangling_link),
            Err(UplinkError::StagingError { .. })
        ));
        assert!(open_part_nofollow_append(&dangling_link).is_err());
        assert!(open_regular_nofollow_read(&dangling_link).is_err());

        assert_eq!(std::fs::read(&real_file).unwrap(), b"keep");
        let _ = std::fs::remove_dir_all(&base);
    }
}
