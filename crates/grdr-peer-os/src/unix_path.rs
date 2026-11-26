// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Root-down `openat(O_NOFOLLOW | O_DIRECTORY)` + `fstatat` path inspection and effective IDs.

use std::path::Path;

use grdr_wire::endpoint::PathComponentFact;
#[cfg(unix)]
use grdr_wire::endpoint::PathNodeKind;

use crate::PeerError;

#[cfg(unix)]
pub fn inspect_unix_path_live(path: &Path) -> Result<Vec<PathComponentFact>, PeerError> {
    inspect_unix_chain(path, false)
}

#[cfg(unix)]
pub fn inspect_unix_directory_live(dir: &Path) -> Result<Vec<PathComponentFact>, PeerError> {
    inspect_unix_chain(dir, true)
}

#[cfg(unix)]
#[allow(
    unsafe_code,
    reason = "openat(O_NOFOLLOW | O_DIRECTORY), fstat, and fstatat(AT_SYMLINK_NOFOLLOW)"
)]
fn inspect_unix_chain(
    path: &Path,
    terminal_is_dir: bool,
) -> Result<Vec<PathComponentFact>, PeerError> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Component;

    if !path.is_absolute() {
        return Err(PeerError::PathUnsafe(
            "endpoint path must be absolute for root-down check".to_string(),
        ));
    }
    let components: Vec<_> = path.components().collect();
    if components.is_empty()
        || components
            .iter()
            .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
    {
        return Err(PeerError::PathUnsafe(
            "endpoint path cannot contain `.` or `..`".to_string(),
        ));
    }

    let total = components.len();
    let dir_flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    // SAFETY: static `"/"` C-string opened read-only with O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC.
    let root_fd_raw = unsafe { libc::open(c"/".as_ptr(), dir_flags) };
    if root_fd_raw < 0 {
        return Err(PeerError::PathUnsafe(format!(
            "open root `/` failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: validated non-negative fd returned by `open("/")`.
    let mut cur_dir = unsafe { OwnedFd::from_raw_fd(root_fd_raw) };
    let mut facts = Vec::with_capacity(total);
    let mut current_path = std::path::PathBuf::new();

    for (idx, comp) in components.into_iter().enumerate() {
        let is_terminal_socket = !terminal_is_dir && idx.saturating_add(1) == total;
        current_path.push(comp.as_os_str());
        if idx == 0 {
            let st = fstat_fd(cur_dir.as_raw_fd())?;
            facts.push(fact_from_stat(&current_path, false, &st));
            continue;
        }
        let seg_cstr = CString::new(comp.as_os_str().as_bytes())
            .map_err(|_| PeerError::PathUnsafe("interior NUL in endpoint path".to_string()))?;
        if is_terminal_socket {
            let st = fstatat_nofollow(cur_dir.as_raw_fd(), &seg_cstr)?;
            facts.push(fact_from_stat(&current_path, true, &st));
        } else {
            let next_raw;
            // SAFETY: `cur_dir` is an open directory fd and `seg_cstr` is NUL-terminated.
            unsafe {
                next_raw = libc::openat(cur_dir.as_raw_fd(), seg_cstr.as_ptr(), dir_flags);
            }
            if next_raw < 0 {
                return Err(PeerError::PathUnsafe(format!(
                    "openat(O_NOFOLLOW | O_DIRECTORY) failed at segment {idx}: {}",
                    std::io::Error::last_os_error()
                )));
            }
            // SAFETY: validated non-negative fd returned by `openat`.
            let next_dir = unsafe { OwnedFd::from_raw_fd(next_raw) };
            let st = fstat_fd(next_dir.as_raw_fd())?;
            facts.push(fact_from_stat(&current_path, false, &st));
            cur_dir = next_dir;
        }
    }
    Ok(facts)
}

#[cfg(unix)]
pub fn refresh_unix_path_post_connect(
    facts: &mut [PathComponentFact],
    path: &Path,
) -> Result<(), PeerError> {
    let post = inspect_unix_path_live(path)?;
    merge_post_facts(facts, post)
}

#[cfg(unix)]
pub fn refresh_unix_directory_post_check(
    facts: &mut [PathComponentFact],
    dir: &Path,
) -> Result<(), PeerError> {
    let post = inspect_unix_directory_live(dir)?;
    merge_post_facts(facts, post)
}

#[cfg(unix)]
fn merge_post_facts(
    facts: &mut [PathComponentFact],
    post: Vec<PathComponentFact>,
) -> Result<(), PeerError> {
    if post.len() != facts.len() {
        return Err(PeerError::PathUnsafe(
            "endpoint path component count changed across connect".to_string(),
        ));
    }
    for (orig, after) in facts.iter_mut().zip(post.into_iter()) {
        orig.post_dev = after.dev;
        orig.post_ino = after.ino;
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn inspect_unix_path_live(_path: &Path) -> Result<Vec<PathComponentFact>, PeerError> {
    Err(PeerError::PathUnsafe(
        "unix path inspection unavailable on non-unix host".to_string(),
    ))
}

#[cfg(not(unix))]
pub fn inspect_unix_directory_live(_dir: &Path) -> Result<Vec<PathComponentFact>, PeerError> {
    Err(PeerError::PathUnsafe(
        "unix path inspection unavailable on non-unix host".to_string(),
    ))
}

#[cfg(not(unix))]
pub fn refresh_unix_path_post_connect(
    _facts: &mut [PathComponentFact],
    _path: &Path,
) -> Result<(), PeerError> {
    Err(PeerError::PathUnsafe(
        "unix path inspection unavailable on non-unix host".to_string(),
    ))
}

#[cfg(not(unix))]
pub fn refresh_unix_directory_post_check(
    _facts: &mut [PathComponentFact],
    _dir: &Path,
) -> Result<(), PeerError> {
    Err(PeerError::PathUnsafe(
        "unix path inspection unavailable on non-unix host".to_string(),
    ))
}

#[cfg(unix)]
#[allow(
    unsafe_code,
    reason = "POSIX fstat on validated open directory descriptor"
)]
fn fstat_fd(fd: libc::c_int) -> Result<libc::stat, PeerError> {
    // SAFETY: `libc::stat` is valid zero-initialized before `fstat`.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `fd` is a valid open descriptor and `st` points to stack storage.
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(PeerError::PathUnsafe(format!(
            "fstat failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(st)
}

#[cfg(unix)]
#[allow(
    unsafe_code,
    reason = "POSIX fstatat(AT_SYMLINK_NOFOLLOW) on open directory fd"
)]
fn fstatat_nofollow(dir_fd: libc::c_int, name: &std::ffi::CStr) -> Result<libc::stat, PeerError> {
    // SAFETY: `libc::stat` is valid zero-initialized before `fstatat`.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `dir_fd` is open and `name` is NUL-terminated.
    if unsafe { libc::fstatat(dir_fd, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        return Err(PeerError::PathUnsafe(format!(
            "fstatat(AT_SYMLINK_NOFOLLOW) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(st)
}

#[cfg(unix)]
fn fact_from_stat(path: &Path, is_leaf: bool, st: &libc::stat) -> PathComponentFact {
    let mode = u32::from(st.st_mode);
    let ftype = st.st_mode & libc::S_IFMT;
    let node_kind = if ftype == libc::S_IFLNK {
        PathNodeKind::Symlink
    } else if ftype == libc::S_IFDIR {
        PathNodeKind::Directory
    } else if ftype == libc::S_IFSOCK {
        PathNodeKind::Socket
    } else {
        PathNodeKind::Other
    };
    #[allow(clippy::cast_sign_loss)]
    let dev = u64::try_from(st.st_dev).unwrap_or(0);
    #[allow(clippy::cast_sign_loss)]
    let ino = u64::try_from(st.st_ino).unwrap_or(0);
    PathComponentFact {
        path: path.display().to_string(),
        is_leaf,
        node_kind,
        owner_uid: st.st_uid,
        gid: st.st_gid,
        posix_mode: mode,
        dev,
        ino,
        post_dev: 0,
        post_ino: 0,
    }
}

#[cfg(unix)]
#[allow(unsafe_code, reason = "POSIX geteuid and getegid read-only calls")]
#[must_use]
pub fn current_effective_ids() -> Option<(u32, u32)> {
    // SAFETY: `geteuid` and `getegid` are thread-safe read-only POSIX calls with no preconditions.
    Some(unsafe { (libc::geteuid(), libc::getegid()) })
}

#[cfg(not(unix))]
#[must_use]
pub const fn current_effective_ids() -> Option<(u32, u32)> {
    None
}
