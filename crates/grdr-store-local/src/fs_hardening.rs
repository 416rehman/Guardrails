// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Symlink-safe filesystem helpers, `0o700`/`0o600` permissions, atomic temp writes,
//! directory fsync, and P8 path redaction shared across `grdr-store-local`.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

use grdr_crypto::fill_random;

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(windows)]
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};

#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

/// Redact ancestor user-profile directories from errors (P8).
#[must_use]
pub fn redact_path_label(path: &Path) -> String {
    let mut parts = Vec::new();
    for comp in path.components() {
        if let Component::Normal(seg) = comp {
            parts.push(seg.to_string_lossy().into_owned());
        }
    }
    match parts.as_slice() {
        [] => "<empty>".to_string(),
        [only] => only.clone(),
        [.., prev, leaf] if prev != "Users" && prev != "home" => format!("{prev}/{leaf}"),
        [.., leaf] => leaf.clone(),
    }
}

pub fn reject_traversal(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Err("empty storage path".to_string());
    }
    let text = path.to_string_lossy();
    if text.contains('\0') {
        return Err("storage path contains NUL byte".to_string());
    }
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(format!(
            "storage path traversal disallowed at {}",
            redact_path_label(path)
        ));
    }
    Ok(())
}

pub fn is_symlink_or_reparse(meta: &fs::Metadata) -> bool {
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
fn is_os_root_alias(acc: &Path, meta: &fs::Metadata) -> bool {
    let _ = meta;
    acc == Path::new("/var") || acc == Path::new("/tmp")
}

#[cfg(unix)]
fn is_shared_parent_root(acc: &Path, meta: &fs::Metadata) -> bool {
    if (meta.mode() & 0o1000) != 0 {
        return true;
    }
    matches!(
        acc.to_str(),
        Some(
            "/" | "/var"
                | "/tmp"
                | "/var/tmp"
                | "/private"
                | "/private/tmp"
                | "/private/var"
                | "/run"
                | "/home"
                | "/Users"
                | "/Library"
                | "/System"
                | "/Volumes"
                | "/opt"
                | "/etc"
        )
    )
}

#[cfg(not(unix))]
fn is_os_root_alias(_acc: &Path, _meta: &fs::Metadata) -> bool {
    false
}

pub fn ensure_ancestors_safe(path: &Path) -> Result<(), String> {
    reject_traversal(path)?;
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
                    if comps.peek().is_some() && is_os_root_alias(&acc, &meta) {
                        continue;
                    }
                    return Err(format!(
                        "refusing symlink ancestor near {}",
                        redact_path_label(&acc)
                    ));
                }
                if !meta.is_dir() {
                    return Err(format!(
                        "non-directory ancestor at {}",
                        redact_path_label(&acc)
                    ));
                }
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => {
                return Err(format!(
                    "failed to stat ancestor {}: {err}",
                    redact_path_label(&acc)
                ));
            }
        }
    }
    Ok(())
}

pub fn ensure_private_dir_all(dir: &Path) -> Result<(), String> {
    reject_traversal(dir)?;
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
                    if !is_target && is_os_root_alias(&acc, &meta) {
                        continue;
                    }
                    return Err(format!(
                        "refusing symlink directory at {}",
                        redact_path_label(&acc)
                    ));
                }
                if !meta.is_dir() {
                    return Err(format!("expected directory at {}", redact_path_label(&acc)));
                }
                if is_target {
                    enforce_private_dir_perms(&acc, &meta)?;
                } else {
                    enforce_intermediate_dir_safety(&acc, &meta)?;
                }
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                create_private_dir(&acc)?;
                let meta = fs::symlink_metadata(&acc)
                    .map_err(|e| format!("stat created dir {}: {e}", redact_path_label(&acc)))?;
                enforce_private_dir_perms(&acc, &meta)?;
            }
            Err(err) => {
                return Err(format!(
                    "inspect directory {}: {err}",
                    redact_path_label(&acc)
                ));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn create_private_dir(dir: &Path) -> Result<(), String> {
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(dir)
        .map_err(|e| format!("create directory {}: {e}", redact_path_label(dir)))
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> Result<(), String> {
    fs::create_dir(dir).map_err(|e| format!("create directory {}: {e}", redact_path_label(dir)))
}

#[cfg(unix)]
fn enforce_intermediate_dir_safety(dir: &Path, meta: &fs::Metadata) -> Result<(), String> {
    if is_shared_parent_root(dir, meta) {
        return Ok(());
    }
    let mode = meta.mode();
    if (mode & 0o022) != 0 {
        fs::set_permissions(dir, fs::Permissions::from_mode(mode & !0o022))
            .map_err(|e| format!("strip write bits on {}: {e}", redact_path_label(dir)))?;
        let recheck = fs::symlink_metadata(dir)
            .map_err(|e| format!("re-stat {}: {e}", redact_path_label(dir)))?;
        if (recheck.mode() & 0o022) != 0 {
            return Err(format!(
                "directory {} remains group/world-writable",
                redact_path_label(dir)
            ));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn enforce_intermediate_dir_safety(_dir: &Path, _meta: &fs::Metadata) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn enforce_private_dir_perms(dir: &Path, meta: &fs::Metadata) -> Result<(), String> {
    let mode = meta.mode();
    if (mode & 0o022) != 0 || (mode & 0o777) != 0o700 {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("chmod 0700 {}: {e}", redact_path_label(dir)))?;
        let recheck = fs::symlink_metadata(dir)
            .map_err(|e| format!("re-stat {}: {e}", redact_path_label(dir)))?;
        if (recheck.mode() & 0o022) != 0 {
            return Err(format!(
                "directory {} remains group/world-writable",
                redact_path_label(dir)
            ));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn enforce_private_dir_perms(_dir: &Path, _meta: &fs::Metadata) -> Result<(), String> {
    Ok(())
}

pub fn set_private_file_perms(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        let meta = fs::symlink_metadata(path)
            .map_err(|e| format!("stat file {}: {e}", redact_path_label(path)))?;
        if is_symlink_or_reparse(&meta) {
            return Err(format!("refusing symlink file {}", redact_path_label(path)));
        }
        if (meta.mode() & 0o777) != 0o600 {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("chmod 0600 {}: {e}", redact_path_label(path)))?;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

pub fn ensure_regular_non_symlink_if_exists(path: &Path) -> Result<(), String> {
    ensure_ancestors_safe(path)?;
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if is_symlink_or_reparse(&meta) || !meta.file_type().is_file() {
                return Err(format!(
                    "refusing symlink or non-regular file at {}",
                    redact_path_label(path)
                ));
            }
            Ok(())
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!("inspect path {}: {err}", redact_path_label(path))),
    }
}

pub fn open_nofollow_read(path: &Path) -> Result<File, io::Error> {
    if let Err(reason) = ensure_ancestors_safe(path) {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, reason));
    }
    let lstat = fs::symlink_metadata(path)?;
    if is_symlink_or_reparse(&lstat) || !lstat.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("refusing symlink at {}", redact_path_label(path)),
        ));
    }

    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    opts.custom_flags(libc::O_NOFOLLOW);
    #[cfg(windows)]
    opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = opts.open(path)?;
    let fd_meta = file.metadata()?;
    if !fd_meta.file_type().is_file() || is_symlink_or_reparse(&fd_meta) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("opened descriptor mismatch at {}", redact_path_label(path)),
        ));
    }
    #[cfg(unix)]
    if lstat.dev() != fd_meta.dev() || lstat.ino() != fd_meta.ino() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("file swapped during open at {}", redact_path_label(path)),
        ));
    }
    #[cfg(windows)]
    if lstat.creation_time() != fd_meta.creation_time() || lstat.file_size() != fd_meta.file_size()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("file swapped during open at {}", redact_path_label(path)),
        ));
    }
    Ok(file)
}

pub fn read_bounded_nofollow(path: &Path, max_bytes: usize) -> Result<Vec<u8>, io::Error> {
    let file = open_nofollow_read(path)?;
    let cap = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut buf = Vec::new();
    file.take(cap).read_to_end(&mut buf)?;
    if buf.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "file {} exceeds maximum {max_bytes} bytes",
                redact_path_label(path)
            ),
        ));
    }
    Ok(buf)
}

pub fn open_nofollow_append_create(path: &Path) -> Result<File, io::Error> {
    if let Err(reason) = ensure_regular_non_symlink_if_exists(path) {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, reason));
    }
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        opts.mode(0o600);
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = opts.open(path)?;
    let fd_meta = file.metadata()?;
    if !fd_meta.file_type().is_file() || is_symlink_or_reparse(&fd_meta) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("non-regular file opened at {}", redact_path_label(path)),
        ));
    }
    if let Err(reason) = set_private_file_perms(path) {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, reason));
    }
    Ok(file)
}

pub fn sync_parent_dir(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            let dir = File::open(parent)
                .map_err(|e| format!("open parent dir {}: {e}", redact_path_label(parent)))?;
            dir.sync_all()
                .map_err(|e| format!("fsync parent dir {}: {e}", redact_path_label(parent)))?;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

pub fn atomic_write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    atomic_write_private_inner(path, bytes, true)
}

pub fn atomic_write_private_in_verified_dir(path: &Path, bytes: &[u8]) -> Result<(), String> {
    atomic_write_private_inner(path, bytes, false)
}

fn atomic_write_private_inner(
    path: &Path,
    bytes: &[u8],
    force_private_parent: bool,
) -> Result<(), String> {
    reject_traversal(path)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if force_private_parent || !parent.exists() {
        ensure_private_dir_all(parent)?;
    } else {
        ensure_ancestors_safe(path)?;
        #[cfg(unix)]
        {
            let meta = fs::symlink_metadata(parent)
                .map_err(|e| format!("inspect directory {}: {e}", redact_path_label(parent)))?;
            if is_symlink_or_reparse(&meta) || !meta.is_dir() {
                return Err(format!(
                    "refusing symlink or non-directory at {}",
                    redact_path_label(parent)
                ));
            }
            enforce_intermediate_dir_safety(parent, &meta)?;
        }
    }
    ensure_regular_non_symlink_if_exists(path)?;

    let leaf = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| "invalid UTF-8 target filename".to_string())?;
    let mut nonce = [0u8; 8];
    fill_random(&mut nonce).map_err(|e| format!("temp nonce entropy failed: {e}"))?;
    let tmp_path = parent.join(format!(
        ".{leaf}.{}.{}.tmp",
        std::process::id(),
        u64::from_le_bytes(nonce)
    ));

    let mut opts = OpenOptions::new();
    opts.create_new(true).write(true);
    #[cfg(unix)]
    {
        opts.mode(0o600);
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let mut tmp = opts
        .open(&tmp_path)
        .map_err(|e| format!("create tmp {}: {e}", redact_path_label(&tmp_path)))?;

    let write_res = (|| -> Result<(), String> {
        tmp.write_all(bytes)
            .map_err(|e| format!("write tmp {}: {e}", redact_path_label(&tmp_path)))?;
        tmp.sync_all()
            .map_err(|e| format!("fsync tmp {}: {e}", redact_path_label(&tmp_path)))?;
        Ok(())
    })();
    drop(tmp);

    if let Err(err) = write_res {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }

    if let Err(err) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(format!("rename to {}: {err}", redact_path_label(path)));
    }
    set_private_file_perms(path)?;
    sync_parent_dir(path)?;
    Ok(())
}
