// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Symlink-resistant, reparse-safe file and directory opening and trust verification helpers.

use std::fs::{self, File, OpenOptions};
use std::path::{Component, Path};

use grdr_wire::endpoint::{PathExpectation, check_directory_path};
use grdr_wire::peer_auth::Profile;

use crate::PeerError;

#[cfg(windows)]
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenNofollowAccess {
    ReadOnly,
    ReadWriteCreate,
    TruncateCreate,
    AppendCreate,
}

pub fn open_nofollow_file(
    path: &Path,
    access: OpenNofollowAccess,
    unix_mode: u32,
) -> Result<File, PeerError> {
    if let Ok(pre) = fs::symlink_metadata(path) {
        if is_reparse_or_symlink(&pre) || !pre.is_file() {
            return Err(PeerError::PathUnsafe(format!(
                "refusing symlink, reparse point, or non-regular file at {}",
                path.display()
            )));
        }
    } else if access == OpenNofollowAccess::ReadOnly {
        return Err(PeerError::PathUnsafe(format!(
            "cannot stat file {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        )));
    }

    let mut opts = OpenOptions::new();
    match access {
        OpenNofollowAccess::ReadOnly => {
            opts.read(true);
        }
        OpenNofollowAccess::ReadWriteCreate => {
            opts.create(true).read(true).write(true);
        }
        OpenNofollowAccess::TruncateCreate => {
            opts.create(true).truncate(true).write(true);
        }
        OpenNofollowAccess::AppendCreate => {
            opts.create(true).append(true);
        }
    }
    apply_platform_open_flags(&mut opts, false, unix_mode);
    let file = opts
        .open(path)
        .map_err(|e| PeerError::PathUnsafe(format!("open {} failed: {e}", path.display())))?;
    let post = file
        .metadata()
        .map_err(|e| PeerError::PathUnsafe(format!("metadata {} failed: {e}", path.display())))?;
    if is_reparse_or_symlink(&post) || !post.is_file() {
        return Err(PeerError::PathUnsafe(format!(
            "opened handle {} is not a regular file",
            path.display()
        )));
    }
    Ok(file)
}

pub fn open_nofollow_dir(dir: &Path) -> Result<File, PeerError> {
    let pre = fs::symlink_metadata(dir)
        .map_err(|e| PeerError::PathUnsafe(format!("stat dir {} failed: {e}", dir.display())))?;
    if is_reparse_or_symlink(&pre) || !pre.is_dir() {
        return Err(PeerError::PathUnsafe(format!(
            "directory {} is a symlink, reparse point, or non-directory",
            dir.display()
        )));
    }
    let mut opts = OpenOptions::new();
    opts.read(true);
    apply_platform_open_flags(&mut opts, true, 0o700);
    let file = opts
        .open(dir)
        .map_err(|e| PeerError::PathUnsafe(format!("open dir {} failed: {e}", dir.display())))?;
    let post = file.metadata().map_err(|e| {
        PeerError::PathUnsafe(format!("metadata dir {} failed: {e}", dir.display()))
    })?;
    if is_reparse_or_symlink(&post) || !post.is_dir() {
        return Err(PeerError::PathUnsafe(format!(
            "opened dir handle {} is not a regular directory",
            dir.display()
        )));
    }
    Ok(file)
}

pub fn check_no_ancestor_symlinks(path: &Path) -> Result<(), PeerError> {
    if path
        .components()
        .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
    {
        return Err(PeerError::PathUnsafe(
            "path cannot contain `.` or `..` traversal components".to_string(),
        ));
    }
    for anc in path.ancestors() {
        if anc.as_os_str().is_empty() {
            continue;
        }
        if let Ok(meta) = fs::symlink_metadata(anc)
            && is_reparse_or_symlink(&meta)
        {
            return Err(PeerError::PathUnsafe(format!(
                "refusing symlink or reparse point in path ancestry: {}",
                anc.display()
            )));
        }
    }
    Ok(())
}

pub fn create_private_dir_all(dir: &Path) -> Result<File, PeerError> {
    check_no_ancestor_symlinks(dir)?;
    create_dir_all_with_mode(dir)?;
    #[cfg(windows)]
    {
        let dac_handle = open_nofollow_dir_write_dac(dir)?;
        crate::win_peer::restrict_windows_dir_handle_dacl(
            std::os::windows::io::AsHandle::as_handle(&dac_handle),
        )?;
    }
    let handle = open_nofollow_dir(dir)?;
    verify_open_dir_trust(&handle, dir, false)?;
    restrict_dir_mode(&handle)?;
    Ok(handle)
}

#[cfg(windows)]
fn open_nofollow_dir_write_dac(dir: &Path) -> Result<File, PeerError> {
    use std::os::windows::fs::OpenOptionsExt as _;
    const WRITE_DAC_AND_QUERY: u32 = 0x0016_0081;
    let pre = fs::symlink_metadata(dir)
        .map_err(|e| PeerError::PathUnsafe(format!("stat dir {} failed: {e}", dir.display())))?;
    if is_reparse_or_symlink(&pre) || !pre.is_dir() {
        return Err(PeerError::PathUnsafe(format!(
            "directory {} is a symlink, reparse point, or non-directory",
            dir.display()
        )));
    }
    let mut opts = OpenOptions::new();
    opts.access_mode(WRITE_DAC_AND_QUERY);
    opts.custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let file = opts
        .open(dir)
        .map_err(|e| PeerError::PathUnsafe(format!("open dir {} failed: {e}", dir.display())))?;
    let post = file.metadata().map_err(|e| {
        PeerError::PathUnsafe(format!("metadata dir {} failed: {e}", dir.display()))
    })?;
    if is_reparse_or_symlink(&post) || !post.is_dir() {
        return Err(PeerError::PathUnsafe(format!(
            "opened dir handle {} is not a regular directory",
            dir.display()
        )));
    }
    Ok(file)
}

#[cfg(unix)]
pub fn verify_open_file_trust(file: &File, protected: bool) -> Result<(), PeerError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let meta = file
        .metadata()
        .map_err(|e| PeerError::PathUnsafe(e.to_string()))?;
    if meta.file_type().is_symlink() {
        return Err(PeerError::PathUnsafe(
            "regular non-symlink file required".to_string(),
        ));
    }
    let (my_uid, _) = crate::unix_peer::current_effective_ids()
        .ok_or_else(|| PeerError::Unverifiable("effective uid/gid unavailable".to_string()))?;
    let uid = meta.uid();
    let mode = meta.permissions().mode();
    let trusted_owner = if protected {
        uid == 0
    } else {
        uid == my_uid || uid == 0
    };
    if !trusted_owner {
        return Err(PeerError::PathForeign);
    }
    if (mode & 0o022) != 0 {
        return Err(PeerError::PathUnsafe(
            "file must not be group-writable or world-writable".to_string(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
pub fn verify_open_file_trust(file: &File, protected: bool) -> Result<(), PeerError> {
    use std::os::windows::io::AsHandle as _;
    crate::win_peer::verify_windows_path_security(file.as_handle(), protected)
}

#[cfg(not(any(unix, windows)))]
pub fn verify_open_file_trust(_file: &File, _protected: bool) -> Result<(), PeerError> {
    Err(PeerError::Unverifiable(
        "unsupported platform for file trust check".to_string(),
    ))
}

#[cfg(unix)]
pub fn verify_open_dir_trust(
    _dir: &File,
    dir_path: &Path,
    protected: bool,
) -> Result<(), PeerError> {
    let (my_uid, my_gid) = crate::unix_peer::current_effective_ids()
        .ok_or_else(|| PeerError::Unverifiable("effective uid/gid unavailable".to_string()))?;
    let mut facts = crate::unix_peer::inspect_unix_directory_live(dir_path)?;
    crate::unix_peer::refresh_unix_directory_post_check(&mut facts, dir_path)?;
    let exp = PathExpectation {
        profile: if protected {
            Profile::Protected
        } else {
            Profile::User
        },
        trusted_owner_uids: if protected { vec![0] } else { vec![0, my_uid] },
        trusted_group_gids: if protected { vec![0] } else { vec![0, my_gid] },
        allow_world_writable_socket_leaf: false,
    };
    check_directory_path(&facts, &exp).map_err(|e| PeerError::PathUnsafe(e.to_string()))
}

#[cfg(windows)]
pub fn verify_open_dir_trust(
    dir: &File,
    _dir_path: &Path,
    protected: bool,
) -> Result<(), PeerError> {
    use std::os::windows::io::AsHandle as _;
    let _ = (
        check_directory_path,
        PathExpectation {
            profile: Profile::User,
            trusted_owner_uids: vec![],
            trusted_group_gids: vec![],
            allow_world_writable_socket_leaf: false,
        },
    );
    crate::win_peer::verify_windows_path_security(dir.as_handle(), protected)
}

#[cfg(not(any(unix, windows)))]
pub fn verify_open_dir_trust(
    _dir: &File,
    _dir_path: &Path,
    _protected: bool,
) -> Result<(), PeerError> {
    let _ = (
        check_directory_path,
        PathExpectation {
            profile: Profile::User,
            trusted_owner_uids: vec![],
            trusted_group_gids: vec![],
            allow_world_writable_socket_leaf: false,
        },
    );
    Err(PeerError::Unverifiable(
        "unsupported platform for directory trust check".to_string(),
    ))
}

#[cfg(unix)]
pub fn set_private_file_mode(file: &File) -> Result<(), PeerError> {
    use std::os::unix::fs::PermissionsExt as _;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|e| PeerError::PathUnsafe(format!("chmod 0600 failed: {e}")))
}

#[cfg(not(unix))]
pub fn set_private_file_mode(_file: &File) -> Result<(), PeerError> {
    Ok(())
}

#[cfg(unix)]
pub fn restrict_dir_mode(dir: &File) -> Result<(), PeerError> {
    restrict_dir_mode_value(dir, 0o700)
}

#[cfg(not(unix))]
pub fn restrict_dir_mode(_dir: &File) -> Result<(), PeerError> {
    Ok(())
}

#[cfg(unix)]
pub fn restrict_dir_mode_value(dir: &File, unix_mode: u32) -> Result<(), PeerError> {
    use std::os::unix::fs::PermissionsExt as _;
    dir.set_permissions(fs::Permissions::from_mode(unix_mode))
        .map_err(|e| PeerError::PathUnsafe(format!("chmod {unix_mode:o} failed: {e}")))
}

#[cfg(not(unix))]
pub fn restrict_dir_mode_value(_dir: &File, _unix_mode: u32) -> Result<(), PeerError> {
    Ok(())
}

#[cfg(unix)]
pub fn sync_parent_dir(dir: &Path) -> Result<(), PeerError> {
    let handle = open_nofollow_dir(dir)?;
    handle
        .sync_all()
        .map_err(|e| PeerError::PathUnsafe(format!("fsync dir {} failed: {e}", dir.display())))
}

#[cfg(not(unix))]
pub fn sync_parent_dir(_dir: &Path) -> Result<(), PeerError> {
    Ok(())
}

#[cfg(unix)]
fn is_reparse_or_symlink(meta: &fs::Metadata) -> bool {
    meta.file_type().is_symlink()
}

#[cfg(windows)]
fn is_reparse_or_symlink(meta: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;
    meta.file_type().is_symlink() || (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
}

#[cfg(not(any(unix, windows)))]
fn is_reparse_or_symlink(meta: &fs::Metadata) -> bool {
    meta.file_type().is_symlink()
}

#[cfg(unix)]
fn create_dir_all_with_mode(dir: &Path) -> Result<(), PeerError> {
    use std::os::unix::fs::DirBuilderExt as _;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| PeerError::PathUnsafe(format!("create_dir_all {} failed: {e}", dir.display())))
}

#[cfg(not(unix))]
fn create_dir_all_with_mode(dir: &Path) -> Result<(), PeerError> {
    fs::create_dir_all(dir)
        .map_err(|e| PeerError::PathUnsafe(format!("create_dir_all {} failed: {e}", dir.display())))
}

#[cfg(unix)]
fn apply_platform_open_flags(opts: &mut OpenOptions, is_dir: bool, unix_mode: u32) {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut flags = libc::O_NOFOLLOW | libc::O_CLOEXEC;
    if is_dir {
        flags |= libc::O_DIRECTORY;
    }
    opts.custom_flags(flags);
    if !is_dir {
        opts.mode(unix_mode);
    }
}

#[cfg(windows)]
fn apply_platform_open_flags(opts: &mut OpenOptions, is_dir: bool, _unix_mode: u32) {
    use std::os::windows::fs::OpenOptionsExt as _;
    let flags = if is_dir {
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT
    } else {
        FILE_FLAG_OPEN_REPARSE_POINT
    };
    opts.custom_flags(flags);
}

#[cfg(not(any(unix, windows)))]
fn apply_platform_open_flags(_opts: &mut OpenOptions, _is_dir: bool, _unix_mode: u32) {}
