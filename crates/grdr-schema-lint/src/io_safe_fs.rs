// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Low-level symlink/reparse ancestor checks, bounded reads, and atomic writes.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::LintError;

static ATOMIC_TMP_SEQ: AtomicU64 = AtomicU64::new(0);

pub(crate) fn is_reparse_point(meta: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
    }
    #[cfg(not(windows))]
    {
        let _ = meta;
        false
    }
}

pub(crate) fn is_symlink_or_reparse(meta: &fs::Metadata) -> bool {
    meta.file_type().is_symlink() || is_reparse_point(meta)
}

pub(crate) fn canonicalize_real_dir(dir: &Path, label: &str) -> Result<PathBuf, LintError> {
    let meta = fs::symlink_metadata(dir).map_err(|e| io_err(dir, &e.to_string()))?;
    if is_symlink_or_reparse(&meta) || !meta.is_dir() {
        return Err(io_err(
            dir,
            &format!("{label} must be a real non-symlink directory"),
        ));
    }
    fs::canonicalize(dir).map_err(|e| io_err(dir, &e.to_string()))
}

pub(crate) fn relative_under_root(canon_root: &Path, target: &Path) -> Result<PathBuf, LintError> {
    if target.is_relative() {
        for comp in target.components() {
            match comp {
                Component::Normal(_) | Component::CurDir => {}
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    return Err(io_err(
                        target,
                        "path contains disallowed traversal or root component",
                    ));
                }
            }
        }
        return Ok(target.to_path_buf());
    }
    if let Ok(rel) = target.strip_prefix(canon_root) {
        return verify_clean_relative(target, rel);
    }
    let root_no_verb = strip_verbatim_str(canon_root);
    let tgt_no_verb = strip_verbatim_str(target);
    if let (Some(rs), Some(ts)) = (root_no_verb, tgt_no_verb)
        && let Ok(rel) = Path::new(ts).strip_prefix(Path::new(rs))
    {
        return verify_clean_relative(target, rel);
    }
    Err(io_err(target, "path escapes repository root"))
}

fn strip_verbatim_str(p: &Path) -> Option<&str> {
    let s = p.to_str()?;
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        let _ = rest;
        None
    } else if let Some(rest) = s.strip_prefix(r"\\?\") {
        Some(rest)
    } else {
        Some(s)
    }
}

fn verify_clean_relative(full: &Path, rel: &Path) -> Result<PathBuf, LintError> {
    let mut cleaned = PathBuf::new();
    for comp in rel.components() {
        match comp {
            Component::Normal(seg) => cleaned.push(seg),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(io_err(
                    full,
                    "path contains traversal or root outside repository root",
                ));
            }
        }
    }
    Ok(cleaned)
}

pub(crate) fn reject_symlinks_under(
    canon_root: &Path,
    path: &Path,
    expect_dir_leaf: bool,
) -> Result<PathBuf, LintError> {
    let rel = relative_under_root(canon_root, path)?;
    let mut cur = canon_root.to_path_buf();
    let mut comps = rel.components().peekable();
    while let Some(comp) = comps.next() {
        cur.push(comp.as_os_str());
        let has_more = comps.peek().is_some();
        match fs::symlink_metadata(&cur) {
            Ok(meta) => {
                if is_symlink_or_reparse(&meta) {
                    return Err(io_err(&cur, "symlink or reparse point is forbidden"));
                }
                if (has_more || expect_dir_leaf) && !meta.is_dir() {
                    return Err(io_err(
                        &cur,
                        "expected real non-symlink directory component",
                    ));
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => break,
            Err(err) => return Err(io_err(&cur, &err.to_string())),
        }
    }
    Ok(canon_root.join(rel))
}

pub(crate) fn read_bounded_regular_bytes(
    canon_root: &Path,
    path: &Path,
    max_bytes: u64,
) -> Result<Vec<u8>, LintError> {
    let checked = reject_symlinks_under(canon_root, path, false)?;
    let meta = fs::symlink_metadata(&checked).map_err(|e| io_err(path, &e.to_string()))?;
    if is_symlink_or_reparse(&meta) || !meta.is_file() {
        return Err(io_err(path, "refusing to read symlink or non-regular file"));
    }
    if meta.len() > max_bytes {
        return Err(io_err(
            path,
            &format!("file size {} exceeds cap {max_bytes}", meta.len()),
        ));
    }
    let canon_path = fs::canonicalize(&checked).map_err(|e| io_err(path, &e.to_string()))?;
    if !canon_path.starts_with(canon_root) {
        return Err(io_err(path, "resolved path escapes allowed schema root"));
    }
    let mut opts = OpenOptions::new();
    opts.read(true);
    apply_nofollow_flags(&mut opts);
    let file = opts
        .open(&canon_path)
        .map_err(|e| io_err(path, &e.to_string()))?;
    let handle_meta = file.metadata().map_err(|e| io_err(path, &e.to_string()))?;
    if is_symlink_or_reparse(&handle_meta)
        || !handle_meta.is_file()
        || handle_meta.len() > max_bytes
    {
        return Err(io_err(
            path,
            "opened file handle failed regular-file or size check",
        ));
    }
    verify_same_file_identity(path, &meta, &handle_meta)?;

    let mut out = Vec::new();
    let mut reader = file.take(max_bytes.saturating_add(1));
    reader
        .read_to_end(&mut out)
        .map_err(|e| io_err(path, &e.to_string()))?;
    if u64::try_from(out.len()).unwrap_or(u64::MAX) > max_bytes {
        return Err(io_err(
            path,
            &format!("file content exceeds cap {max_bytes}"),
        ));
    }
    Ok(out)
}

pub(crate) fn write_regular_atomically(
    canon_root: &Path,
    abs: &Path,
    bytes: &[u8],
) -> Result<(), LintError> {
    let Some(parent) = abs.parent() else {
        return Err(io_err(abs, "missing parent directory"));
    };
    let Some(file_name) = abs.file_name().and_then(|n| n.to_str()) else {
        return Err(io_err(abs, "missing UTF-8 output filename"));
    };
    if file_name.is_empty() || file_name == "." || file_name == ".." {
        return Err(io_err(abs, "invalid output filename"));
    }
    let rel_parent = relative_under_root(canon_root, parent)?;
    reject_symlinks_under(canon_root, parent, true)?;
    let mut cur = canon_root.to_path_buf();
    for comp in rel_parent.components() {
        cur.push(comp.as_os_str());
        match fs::symlink_metadata(&cur) {
            Ok(meta) => {
                if is_symlink_or_reparse(&meta) || !meta.is_dir() {
                    return Err(io_err(&cur, "refusing symlink or non-directory ancestor"));
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                if let Err(ce) = fs::create_dir(&cur)
                    && ce.kind() != std::io::ErrorKind::AlreadyExists
                {
                    return Err(io_err(&cur, &ce.to_string()));
                }
                let post = fs::symlink_metadata(&cur).map_err(|e| io_err(&cur, &e.to_string()))?;
                if is_symlink_or_reparse(&post) || !post.is_dir() {
                    return Err(io_err(&cur, "created directory failed non-symlink check"));
                }
            }
            Err(err) => return Err(io_err(&cur, &err.to_string())),
        }
    }
    let canon_parent = fs::canonicalize(&cur).map_err(|e| io_err(parent, &e.to_string()))?;
    if !canon_parent.starts_with(canon_root) {
        return Err(io_err(abs, "output parent escapes repository root"));
    }
    let dest = canon_parent.join(file_name);
    match fs::symlink_metadata(&dest) {
        Ok(meta) => {
            if is_symlink_or_reparse(&meta) || !meta.is_file() {
                return Err(io_err(
                    &dest,
                    "refusing to overwrite symlink or non-regular output file",
                ));
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(io_err(&dest, &err.to_string())),
    }
    let seq = ATOMIC_TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp_name = format!(".{file_name}.tmp-{}-{seq}", std::process::id());
    let tmp_path = canon_parent.join(tmp_name);
    let write_res: Result<(), LintError> = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .map_err(|e| io_err(&tmp_path, &e.to_string()))?;
        f.write_all(bytes)
            .map_err(|e| io_err(&tmp_path, &e.to_string()))?;
        f.sync_all()
            .map_err(|e| io_err(&tmp_path, &e.to_string()))?;
        Ok(())
    })();
    if let Err(err) = write_res {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }
    fs::rename(&tmp_path, &dest).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        io_err(&dest, &e.to_string())
    })
}

fn verify_same_file_identity(
    path: &Path,
    pre: &fs::Metadata,
    handle: &fs::Metadata,
) -> Result<(), LintError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if pre.dev() != handle.dev() || pre.ino() != handle.ino() {
            return Err(io_err(path, "file identity changed between stat and open"));
        }
    }
    #[cfg(not(unix))]
    {
        if pre.len() != handle.len() {
            return Err(io_err(path, "file size changed between stat and open"));
        }
    }
    Ok(())
}

fn apply_nofollow_flags(opts: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(unix_o_nofollow());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
}

#[cfg(unix)]
const fn unix_o_nofollow() -> i32 {
    #[cfg(all(
        target_os = "linux",
        any(
            target_arch = "arm",
            target_arch = "aarch64",
            target_arch = "powerpc",
            target_arch = "powerpc64"
        )
    ))]
    {
        0o100_000
    }
    #[cfg(all(
        target_os = "linux",
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
        target_os = "linux",
        not(any(
            target_arch = "arm",
            target_arch = "aarch64",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "mips",
            target_arch = "mips64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ))]
    {
        0o400_000
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        target_os = "netbsd"
    ))]
    {
        0x0100
    }
}

fn io_err(path: &Path, detail: &str) -> LintError {
    LintError::Io {
        path: path.display().to_string(),
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_traversal_root_escape_and_non_regular_paths() {
        let base = std::env::temp_dir().join(format!("grdr_io_safe_fs_{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let root = base.join("root");
        let outside = base.join("outside");
        fs::create_dir_all(root.join("sub")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("secret.txt"), b"nope").unwrap();
        let canon_root = canonicalize_real_dir(&root, "root").unwrap();

        assert!(relative_under_root(&canon_root, Path::new("../outside/secret.txt")).is_err());
        assert!(
            read_bounded_regular_bytes(&canon_root, Path::new("../outside/secret.txt"), 1024)
                .is_err()
        );
        assert!(
            write_regular_atomically(&canon_root, Path::new("../outside/out.txt"), b"x").is_err()
        );
        assert!(
            read_bounded_regular_bytes(&canon_root, &outside.join("secret.txt"), 1024).is_err()
        );
        assert!(canonicalize_real_dir(&root.join("missing"), "missing").is_err());
        assert!(read_bounded_regular_bytes(&canon_root, &root.join("sub"), 1024).is_err());
        assert!(write_regular_atomically(&canon_root, &root.join("sub"), b"x").is_err());

        let ok_file = canon_root.join("sub/good.txt");
        write_regular_atomically(&canon_root, &ok_file, b"hello").unwrap();
        assert_eq!(
            read_bounded_regular_bytes(&canon_root, &ok_file, 1024).unwrap(),
            b"hello"
        );

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&outside, root.join("link_dir")).unwrap();
            assert!(
                reject_symlinks_under(&canon_root, &root.join("link_dir/secret.txt"), false)
                    .is_err()
            );
            assert!(
                read_bounded_regular_bytes(&canon_root, &root.join("link_dir/secret.txt"), 1024)
                    .is_err()
            );
            assert!(
                write_regular_atomically(&canon_root, &root.join("link_dir/out.txt"), b"x")
                    .is_err()
            );

            std::os::unix::fs::symlink(outside.join("secret.txt"), root.join("sub/term_link.txt"))
                .unwrap();
            assert!(
                read_bounded_regular_bytes(&canon_root, &root.join("sub/term_link.txt"), 1024)
                    .is_err()
            );
            assert!(
                write_regular_atomically(&canon_root, &root.join("sub/term_link.txt"), b"x")
                    .is_err()
            );
        }

        #[cfg(windows)]
        {
            let junc = root.join("junc_dir");
            let status = std::process::Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(&junc)
                .arg(&outside)
                .status()
                .unwrap();
            assert!(status.success());
            assert!(canonicalize_real_dir(&junc, "junc").is_err());
            assert!(reject_symlinks_under(&canon_root, &junc.join("secret.txt"), false).is_err());
            assert!(
                read_bounded_regular_bytes(&canon_root, &junc.join("secret.txt"), 1024).is_err()
            );
            assert!(write_regular_atomically(&canon_root, &junc.join("out.txt"), b"x").is_err());
            let _ = fs::remove_dir(&junc);
        }

        let _ = fs::remove_dir_all(&base);
    }
}
