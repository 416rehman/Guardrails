// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! OS-hardened `LocalFsPort` adapter (`O_NOFOLLOW | O_CLOEXEC`, Windows reparse checks, atomic temp writes).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(windows)]
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};

use grdr_ports::{LocalFsPort, RegularEntryKind};

#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

#[derive(Debug, Clone, Copy, Default)]
pub struct OsLocalFs;

impl LocalFsPort for OsLocalFs {
    fn check_no_ancestor_symlinks(&self, path: &Path) -> Result<(), String> {
        check_no_ancestor_symlinks_impl(path)
    }

    fn inspect_nofollow(&self, path: &Path) -> Result<RegularEntryKind, String> {
        check_no_ancestor_symlinks_impl(path)?;
        match fs::symlink_metadata(path) {
            Ok(meta) => {
                if is_symlink_or_reparse(&meta) {
                    Ok(RegularEntryKind::UnsafeOrOther)
                } else if meta.file_type().is_file() {
                    Ok(RegularEntryKind::File)
                } else if meta.file_type().is_dir() {
                    Ok(RegularEntryKind::Dir)
                } else {
                    Ok(RegularEntryKind::UnsafeOrOther)
                }
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(RegularEntryKind::Missing),
            Err(err) => Err(format!("failed inspecting {}: {err}", path.display())),
        }
    }

    fn read_bounded_regular_bytes(&self, path: &Path, max_bytes: u64) -> Result<Vec<u8>, String> {
        read_bounded_regular_bytes_impl(path, max_bytes)
    }

    fn read_bounded_regular_string(&self, path: &Path, max_bytes: u64) -> Result<String, String> {
        let bytes = read_bounded_regular_bytes_impl(path, max_bytes)?;
        String::from_utf8(bytes).map_err(|e| format!("invalid UTF-8 in {}: {e}", path.display()))
    }

    fn read_dir_entries(&self, dir: &Path) -> Result<Vec<PathBuf>, String> {
        if self.inspect_nofollow(dir)? != RegularEntryKind::Dir {
            return Err(format!(
                "refusing symlink or non-directory at {}",
                dir.display()
            ));
        }
        let mut out = Vec::new();
        for item in fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
            let entry = item.map_err(|e| format!("{}: {e}", dir.display()))?;
            out.push(entry.path());
        }
        out.sort();
        Ok(out)
    }

    fn ensure_dir_nofollow(&self, dir: &Path, private_dir: bool) -> Result<(), String> {
        ensure_dir_nofollow_impl(dir, private_dir)
    }

    fn atomic_write_nofollow(
        &self,
        path: &Path,
        bytes: &[u8],
        private_file: bool,
    ) -> Result<(), String> {
        atomic_write_nofollow_impl(path, bytes, private_file)
    }

    fn remove_regular_file_nofollow(&self, path: &Path) -> Result<(), String> {
        remove_regular_file_nofollow_impl(path)
    }
}

fn is_symlink_or_reparse(meta: &fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        if (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return true;
        }
    }
    false
}

#[cfg(unix)]
fn is_os_root_alias(acc: &Path) -> bool {
    acc == Path::new("/var") || acc == Path::new("/tmp")
}

#[cfg(not(unix))]
fn is_os_root_alias(_acc: &Path) -> bool {
    false
}

fn reject_path_traversal(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Err("empty filesystem path".to_string());
    }
    let text = path.to_string_lossy();
    if text.chars().any(|c| c == '\0' || c.is_control()) {
        return Err("path contains NUL or control character".to_string());
    }
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(format!("path traversal disallowed at {}", path.display()));
    }
    Ok(())
}

fn check_no_ancestor_symlinks_impl(path: &Path) -> Result<(), String> {
    reject_path_traversal(path)?;
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    let mut acc = PathBuf::new();
    let mut comps = parent.components().peekable();
    while let Some(comp) = comps.next() {
        acc.push(comp.as_os_str());
        if matches!(
            comp,
            Component::Prefix(_) | Component::RootDir | Component::CurDir
        ) {
            continue;
        }
        match fs::symlink_metadata(&acc) {
            Ok(meta) => {
                if is_symlink_or_reparse(&meta) {
                    if comps.peek().is_some() && is_os_root_alias(&acc) {
                        continue;
                    }
                    return Err(format!("refusing symlink ancestor at {}", acc.display()));
                }
                if !meta.is_dir() {
                    return Err(format!("non-directory ancestor at {}", acc.display()));
                }
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => return Err(format!("failed inspecting {}: {err}", acc.display())),
        }
    }
    Ok(())
}

fn ensure_dir_nofollow_impl(dir: &Path, private_dir: bool) -> Result<(), String> {
    reject_path_traversal(dir)?;
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
        let is_target = comps.peek().is_none();
        match fs::symlink_metadata(&acc) {
            Ok(meta) => {
                if is_symlink_or_reparse(&meta) {
                    if !is_target && is_os_root_alias(&acc) {
                        continue;
                    }
                    return Err(format!("refusing symlink directory at {}", acc.display()));
                }
                if !meta.is_dir() {
                    return Err(format!("non-directory path at {}", acc.display()));
                }
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                create_dir_step(&acc, private_dir && is_target)?;
            }
            Err(err) => return Err(format!("failed inspecting {}: {err}", acc.display())),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn create_dir_step(dir: &Path, private_dir: bool) -> Result<(), String> {
    let mut builder = fs::DirBuilder::new();
    if private_dir {
        builder.mode(0o700);
    }
    match builder.create(dir) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
            let meta = fs::symlink_metadata(dir)
                .map_err(|e| format!("failed re-stating {}: {e}", dir.display()))?;
            if is_symlink_or_reparse(&meta) || !meta.is_dir() {
                return Err(format!("unsafe directory created at {}", dir.display()));
            }
            Ok(())
        }
        Err(err) => Err(format!("failed creating {}: {err}", dir.display())),
    }
}

#[cfg(not(unix))]
fn create_dir_step(dir: &Path, _private_dir: bool) -> Result<(), String> {
    match fs::create_dir(dir) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
            let meta = fs::symlink_metadata(dir)
                .map_err(|e| format!("failed re-stating {}: {e}", dir.display()))?;
            if is_symlink_or_reparse(&meta) || !meta.is_dir() {
                return Err(format!("unsafe directory created at {}", dir.display()));
            }
            Ok(())
        }
        Err(err) => Err(format!("failed creating {}: {err}", dir.display())),
    }
}

fn open_nofollow_read(path: &Path) -> io::Result<File> {
    if let Err(reason) = check_no_ancestor_symlinks_impl(path) {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, reason));
    }
    let lstat = fs::symlink_metadata(path)?;
    if is_symlink_or_reparse(&lstat) || !lstat.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("refusing symlink or non-regular file at {}", path.display()),
        ));
    }

    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    opts.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    #[cfg(windows)]
    opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = opts.open(path)?;
    let fd_meta = file.metadata()?;
    if !fd_meta.file_type().is_file() || is_symlink_or_reparse(&fd_meta) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("opened descriptor mismatch at {}", path.display()),
        ));
    }
    #[cfg(unix)]
    if lstat.dev() != fd_meta.dev() || lstat.ino() != fd_meta.ino() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("file swapped during open at {}", path.display()),
        ));
    }
    #[cfg(windows)]
    if lstat.creation_time() != fd_meta.creation_time() || lstat.file_size() != fd_meta.file_size()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("file swapped during open at {}", path.display()),
        ));
    }
    Ok(file)
}

fn read_bounded_regular_bytes_impl(path: &Path, max_bytes: u64) -> Result<Vec<u8>, String> {
    let file = open_nofollow_read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let cap = max_bytes.saturating_add(1);
    let mut buf = Vec::new();
    file.take(cap)
        .read_to_end(&mut buf)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if u64::try_from(buf.len()).unwrap_or(u64::MAX) > max_bytes {
        return Err(format!(
            "file {} exceeds maximum {} bytes",
            path.display(),
            max_bytes
        ));
    }
    Ok(buf)
}

fn remove_regular_file_nofollow_impl(path: &Path) -> Result<(), String> {
    check_no_ancestor_symlinks_impl(path)?;
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if is_symlink_or_reparse(&meta) || !meta.file_type().is_file() {
                return Err(format!(
                    "refusing to delete symlink or non-regular file at {}",
                    path.display()
                ));
            }
            fs::remove_file(path).map_err(|e| format!("failed removing {}: {e}", path.display()))
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!("failed inspecting {}: {err}", path.display())),
    }
}

fn atomic_write_nofollow_impl(path: &Path, bytes: &[u8], private_file: bool) -> Result<(), String> {
    reject_path_traversal(path)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    ensure_dir_nofollow_impl(parent, private_file)?;

    if let Ok(meta) = fs::symlink_metadata(path)
        && (is_symlink_or_reparse(&meta) || !meta.file_type().is_file())
    {
        return Err(format!(
            "refusing symlink or non-regular target at {}",
            path.display()
        ));
    }

    let leaf = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| format!("invalid UTF-8 target filename at {}", path.display()))?;
    let tmp_path = parent.join(format!(
        ".{leaf}.{}.{}.tmp",
        std::process::id(),
        uuid::Uuid::now_v7().simple()
    ));

    let mut opts = OpenOptions::new();
    opts.create_new(true).write(true);
    #[cfg(unix)]
    {
        if private_file {
            opts.mode(0o600);
        }
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);

    let mut tmp = opts
        .open(&tmp_path)
        .map_err(|e| format!("failed creating {}: {e}", tmp_path.display()))?;
    let write_res = (|| -> Result<(), String> {
        tmp.write_all(bytes)
            .map_err(|e| format!("failed writing {}: {e}", tmp_path.display()))?;
        tmp.sync_all()
            .map_err(|e| format!("failed syncing {}: {e}", tmp_path.display()))?;
        Ok(())
    })();
    drop(tmp);

    if let Err(err) = write_res {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }

    if let Err(err) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(format!("failed committing {}: {err}", path.display()));
    }

    #[cfg(unix)]
    if private_file {
        let meta = fs::symlink_metadata(path)
            .map_err(|e| format!("failed inspecting {}: {e}", path.display()))?;
        if is_symlink_or_reparse(&meta) {
            return Err(format!("refusing symlink at {}", path.display()));
        }
        if (meta.mode() & 0o777) != 0o600 {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("failed setting permissions on {}: {e}", path.display()))?;
        }
    }
    sync_parent_dir(parent)?;
    Ok(())
}

#[cfg(unix)]
fn sync_parent_dir(parent: &Path) -> Result<(), String> {
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    let mut opts = OpenOptions::new();
    opts.read(true);
    opts.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY);
    let dir = opts
        .open(parent)
        .map_err(|e| format!("failed opening parent {}: {e}", parent.display()))?;
    dir.sync_all()
        .map_err(|e| format!("failed syncing parent {}: {e}", parent.display()))
}

#[cfg(not(unix))]
fn sync_parent_dir(_parent: &Path) -> Result<(), String> {
    Ok(())
}
