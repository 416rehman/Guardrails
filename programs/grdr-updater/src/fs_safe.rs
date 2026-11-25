// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Symlink-resistant filesystem helpers (`ancestor` + `leaf` verification,
//! bounded reads, single-handle validation, and atomic temp-file rename).

use std::fs::OpenOptions;
use std::io::{Read as _, Write as _};
use std::path::{Component, Path, PathBuf};

use grdr_crypto::fill_random;

use crate::error::UpdaterError;

#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;

/// Write `bytes` atomically inside `parent` (`create_new` nonce temp -> `sync_all` -> atomic `rename`).
pub fn atomic_write_bytes(path: &Path, bytes: &[u8]) -> Result<(), UpdaterError> {
    reject_parent_traversal(path)?;
    let parent = path.parent().ok_or_else(|| UpdaterError::PathUnsafe {
        detail: format!("missing parent directory for {}", path.display()),
    })?;
    ensure_safe_dir(parent)?;
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if is_symlink_or_reparse(&meta) || !meta.file_type().is_file() {
                return Err(UpdaterError::PathUnsafe {
                    detail: format!("refusing symlink or non-regular path {}", path.display()),
                });
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(UpdaterError::Io {
                detail: format!("failed to inspect {}: {err}", path.display()),
            });
        }
    }

    let file_name =
        path.file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| UpdaterError::PathUnsafe {
                detail: "invalid UTF-8 filename".to_string(),
            })?;
    let mut nonce = [0u8; 8];
    fill_random(&mut nonce).map_err(|e| UpdaterError::Io {
        detail: format!("failed to generate temp nonce: {e}"),
    })?;
    let tmp_path = parent.join(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        u64::from_le_bytes(nonce)
    ));

    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&tmp_path)
        .map_err(|e| UpdaterError::Io {
            detail: format!("failed to create staging file {}: {e}", tmp_path.display()),
        })?;
    file.write_all(bytes).map_err(|e| UpdaterError::Io {
        detail: format!("failed to write staging file: {e}"),
    })?;
    file.sync_all().map_err(|e| UpdaterError::Io {
        detail: format!("failed to sync staging file: {e}"),
    })?;
    drop(file);

    std::fs::rename(&tmp_path, path).map_err(|e| UpdaterError::Io {
        detail: format!(
            "failed to rename {} into {}: {e}",
            tmp_path.display(),
            path.display()
        ),
    })?;
    Ok(())
}

/// Read at most `max_bytes` from a non-symlink regular file cleanly via a single open handle.
pub fn read_bounded_bytes(path: &Path, max_bytes: u64) -> Result<Vec<u8>, UpdaterError> {
    reject_parent_traversal(path)?;
    ensure_ancestors_not_symlink(path)?;
    let lstat_meta = std::fs::symlink_metadata(path).map_err(|e| UpdaterError::Io {
        detail: format!("failed to inspect {}: {e}", path.display()),
    })?;
    if is_symlink_or_reparse(&lstat_meta) || !lstat_meta.file_type().is_file() {
        return Err(UpdaterError::PathUnsafe {
            detail: format!("refusing non-regular or symlinked path {}", path.display()),
        });
    }

    let mut opts = OpenOptions::new();
    opts.read(true);
    apply_nofollow_flags(&mut opts);
    let file = opts.open(path).map_err(|e| UpdaterError::Io {
        detail: format!("failed to open {}: {e}", path.display()),
    })?;
    let fd_meta = file.metadata().map_err(|e| UpdaterError::Io {
        detail: format!("failed to stat opened {}: {e}", path.display()),
    })?;
    verify_same_regular_file(&lstat_meta, &fd_meta, path)?;

    let mut buf = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| UpdaterError::Io {
            detail: format!("failed to read {}: {e}", path.display()),
        })?;
    let len_u64 = u64::try_from(buf.len()).unwrap_or(u64::MAX);
    if len_u64 > max_bytes {
        return Err(UpdaterError::BudgetExceeded {
            channel: path.display().to_string(),
            actual_bytes: len_u64,
            max_bytes,
        });
    }
    Ok(buf)
}

/// Ensure `path` itself and every existing ancestor component contain zero symlinks.
pub fn ensure_not_symlink(path: &Path) -> Result<(), UpdaterError> {
    reject_parent_traversal(path)?;
    ensure_ancestors_not_symlink(path)?;
    let meta = std::fs::symlink_metadata(path).map_err(|e| UpdaterError::Io {
        detail: format!("symlink metadata check failed on {}: {e}", path.display()),
    })?;
    if is_symlink_or_reparse(&meta) {
        return Err(UpdaterError::PathUnsafe {
            detail: format!("refusing symlink at privileged path {}", path.display()),
        });
    }
    Ok(())
}

/// Ensure `dir` exists and contains no symlink along its ancestor chain, creating missing segments one by one.
pub fn ensure_safe_dir(dir: &Path) -> Result<(), UpdaterError> {
    reject_parent_traversal(dir)?;
    if dir.as_os_str().is_empty() {
        return Err(UpdaterError::PathUnsafe {
            detail: "missing parent directory path".to_string(),
        });
    }
    let mut acc = PathBuf::new();
    let mut comps = dir.components().peekable();
    while let Some(comp) = comps.next() {
        acc.push(comp.as_os_str());
        if matches!(
            comp,
            Component::Prefix(_) | Component::RootDir | Component::CurDir
        ) {
            continue;
        }
        match std::fs::symlink_metadata(&acc) {
            Ok(meta) => {
                if is_symlink_or_reparse(&meta) {
                    if comps.peek().is_some() && is_os_root_alias(&acc, &meta) {
                        continue;
                    }
                    return Err(UpdaterError::PathUnsafe {
                        detail: format!("refusing symlink at state dir {}", acc.display()),
                    });
                }
                if !meta.is_dir() {
                    return Err(UpdaterError::PathUnsafe {
                        detail: format!("expected directory at {}", acc.display()),
                    });
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&acc).map_err(|e| UpdaterError::Io {
                    detail: format!("failed to create state dir {}: {e}", acc.display()),
                })?;
            }
            Err(err) => {
                return Err(UpdaterError::Io {
                    detail: format!("failed to inspect state dir {}: {err}", acc.display()),
                });
            }
        }
    }
    Ok(())
}

/// Verify `candidate_path` resolves strictly inside `canonical_root` with zero symlinks.
pub fn confine_path_under_root(
    canonical_root: &Path,
    candidate_path: &Path,
) -> Result<PathBuf, UpdaterError> {
    reject_parent_traversal(candidate_path)?;
    ensure_not_symlink(candidate_path)?;
    let canonical_target =
        std::fs::canonicalize(candidate_path).map_err(|e| UpdaterError::PathUnsafe {
            detail: format!(
                "failed to canonicalize target path {}: {e}",
                candidate_path.display()
            ),
        })?;
    if !canonical_target.starts_with(canonical_root) {
        return Err(UpdaterError::PathUnsafe {
            detail: format!(
                "path {} escapes confined state root {}",
                canonical_target.display(),
                canonical_root.display()
            ),
        });
    }
    Ok(canonical_target)
}

/// Reject `..` parent directory segments cleanly.
pub fn reject_parent_traversal(path: &Path) -> Result<(), UpdaterError> {
    if path.components().any(|c| c == Component::ParentDir) {
        return Err(UpdaterError::PathUnsafe {
            detail: format!("parent path traversal disallowed in {}", path.display()),
        });
    }
    Ok(())
}

fn ensure_ancestors_not_symlink(path: &Path) -> Result<(), UpdaterError> {
    let mut cur = path.parent();
    while let Some(dir) = cur {
        if dir.as_os_str().is_empty() {
            break;
        }
        if let Ok(meta) = std::fs::symlink_metadata(dir)
            && is_symlink_or_reparse(&meta)
            && !is_os_root_alias(dir, &meta)
        {
            return Err(UpdaterError::PathUnsafe {
                detail: format!("refusing symlinked ancestor {}", dir.display()),
            });
        }
        cur = dir.parent();
    }
    Ok(())
}

fn is_symlink_or_reparse(meta: &std::fs::Metadata) -> bool {
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

fn apply_nofollow_flags(opts: &mut OpenOptions) {
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

#[cfg(unix)]
fn verify_same_regular_file(
    lstat_meta: &std::fs::Metadata,
    fd_meta: &std::fs::Metadata,
    path: &Path,
) -> Result<(), UpdaterError> {
    use std::os::unix::fs::MetadataExt as _;
    if lstat_meta.dev() != fd_meta.dev() || lstat_meta.ino() != fd_meta.ino() {
        return Err(UpdaterError::PathUnsafe {
            detail: format!("file identity changed during open on {}", path.display()),
        });
    }
    Ok(())
}

#[cfg(windows)]
fn verify_same_regular_file(
    lstat_meta: &std::fs::Metadata,
    fd_meta: &std::fs::Metadata,
    path: &Path,
) -> Result<(), UpdaterError> {
    use std::os::windows::fs::MetadataExt as _;
    if is_symlink_or_reparse(lstat_meta)
        || is_symlink_or_reparse(fd_meta)
        || !fd_meta.file_type().is_file()
        || lstat_meta.file_attributes() != fd_meta.file_attributes()
        || lstat_meta.creation_time() != fd_meta.creation_time()
        || lstat_meta.file_size() != fd_meta.file_size()
    {
        return Err(UpdaterError::PathUnsafe {
            detail: format!(
                "opened handle failed reparse or identity check on {}",
                path.display()
            ),
        });
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn verify_same_regular_file(
    _lstat_meta: &std::fs::Metadata,
    fd_meta: &std::fs::Metadata,
    path: &Path,
) -> Result<(), UpdaterError> {
    if !fd_meta.file_type().is_file() {
        return Err(UpdaterError::PathUnsafe {
            detail: format!("opened handle is not a regular file: {}", path.display()),
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

fn is_os_root_alias(path: &Path, meta: &std::fs::Metadata) -> bool {
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
    fn rejects_empty_and_non_directory_ancestors() {
        assert!(matches!(
            ensure_safe_dir(Path::new("")),
            Err(UpdaterError::PathUnsafe { .. })
        ));
        let base =
            std::env::temp_dir().join(format!("grdr-upd-file-{}", uuid::Uuid::now_v7().simple()));
        std::fs::create_dir_all(&base).unwrap();
        let file_blocker = base.join("blocker");
        std::fs::write(&file_blocker, b"data").unwrap();
        assert!(matches!(
            ensure_safe_dir(&file_blocker.join("child")),
            Err(UpdaterError::PathUnsafe { .. })
        ));
        assert!(matches!(
            atomic_write_bytes(&file_blocker.join("child/bin"), b"x"),
            Err(UpdaterError::PathUnsafe { .. })
        ));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_ancestors_leaf_and_dangling_targets() {
        use std::os::unix::fs::symlink;

        let base =
            std::env::temp_dir().join(format!("grdr-upd-sym-{}", uuid::Uuid::now_v7().simple()));
        let real_dir = base.join("real_dir");
        std::fs::create_dir_all(&real_dir).unwrap();
        let real_file = base.join("real_file");
        std::fs::write(&real_file, b"keep").unwrap();

        let dir_link = base.join("dir_link");
        symlink(&real_dir, &dir_link).unwrap();
        assert!(matches!(
            ensure_safe_dir(&dir_link.join("sub")),
            Err(UpdaterError::PathUnsafe { .. })
        ));
        assert!(!real_dir.join("sub").exists());
        assert!(matches!(
            atomic_write_bytes(&dir_link.join("sub/bin"), b"1"),
            Err(UpdaterError::PathUnsafe { .. })
        ));
        assert!(matches!(
            read_bounded_bytes(&dir_link.join("sub/bin"), 64),
            Err(UpdaterError::PathUnsafe { .. })
        ));
        assert!(matches!(
            ensure_not_symlink(&dir_link),
            Err(UpdaterError::PathUnsafe { .. })
        ));

        let leaf_link = base.join("leaf_link");
        symlink(&real_file, &leaf_link).unwrap();
        assert!(matches!(
            atomic_write_bytes(&leaf_link, b"overwrite"),
            Err(UpdaterError::PathUnsafe { .. })
        ));
        assert!(matches!(
            read_bounded_bytes(&leaf_link, 64),
            Err(UpdaterError::PathUnsafe { .. })
        ));
        assert!(matches!(
            ensure_not_symlink(&leaf_link),
            Err(UpdaterError::PathUnsafe { .. })
        ));

        let dangling_link = base.join("dangling_link");
        symlink(base.join("nonexistent"), &dangling_link).unwrap();
        assert!(matches!(
            atomic_write_bytes(&dangling_link, b"overwrite"),
            Err(UpdaterError::PathUnsafe { .. })
        ));
        assert!(matches!(
            read_bounded_bytes(&dangling_link, 64),
            Err(UpdaterError::PathUnsafe { .. })
        ));
        assert!(matches!(
            ensure_not_symlink(&dangling_link),
            Err(UpdaterError::PathUnsafe { .. })
        ));

        assert_eq!(std::fs::read(&real_file).unwrap(), b"keep");
        let _ = std::fs::remove_dir_all(&base);
    }
}
