// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Symlink-safe bounded filesystem helpers and `0600` private key storage for `grdr`.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use grdr_crypto::{SigningKeypair, fill_random};
use zeroize::Zeroize;

const MAX_KEY_FILE_BYTES: u64 = 4096;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FsSafeError {
    #[error("GRDR-FS-0001: I/O error on `{path}`: {detail}")]
    Io { path: String, detail: String },
    #[error("GRDR-FS-0002: symlink or unsafe path component refused at `{0}`")]
    SymlinkForbidden(String),
    #[error("GRDR-FS-0003: file `{path}` violates size or permission policy: {detail}")]
    PolicyViolation { path: String, detail: String },
    #[error("GRDR-FS-0004: cryptographic key error on `{path}`: {detail}")]
    Crypto { path: String, detail: String },
}

pub fn reject_symlinks_on_existing_prefixes(path: &Path) -> Result<(), FsSafeError> {
    let mut acc = PathBuf::new();
    let mut comps = path.components().peekable();
    while let Some(comp) = comps.next() {
        acc.push(comp.as_os_str());
        if matches!(comp, Component::Prefix(_) | Component::RootDir) {
            continue;
        }
        match fs::symlink_metadata(&acc) {
            Ok(meta) => {
                if is_symlink_or_reparse(&meta) {
                    if comps.peek().is_some() && is_os_root_alias(&acc, &meta) {
                        continue;
                    }
                    return Err(FsSafeError::SymlinkForbidden(acc.display().to_string()));
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => break,
            Err(err) => return Err(io_err(&acc, &err.to_string())),
        }
    }
    Ok(())
}

pub fn ensure_safe_dir_all(dir: &Path, private_mode: bool) -> Result<(), FsSafeError> {
    reject_symlinks_on_existing_prefixes(dir)?;
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
        match fs::symlink_metadata(&acc) {
            Ok(meta) => {
                if is_symlink_or_reparse(&meta) {
                    if comps.peek().is_some() && is_os_root_alias(&acc, &meta) {
                        continue;
                    }
                    return Err(FsSafeError::SymlinkForbidden(acc.display().to_string()));
                }
                if !meta.is_dir() {
                    return Err(FsSafeError::SymlinkForbidden(acc.display().to_string()));
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&acc).map_err(|e| io_err(&acc, &e.to_string()))?;
                if private_mode {
                    set_private_dir_mode(&acc)?;
                }
            }
            Err(err) => return Err(io_err(&acc, &err.to_string())),
        }
    }
    Ok(())
}

pub fn read_bounded_regular(path: &Path, max_bytes: u64) -> Result<Vec<u8>, FsSafeError> {
    reject_symlinks_on_existing_prefixes(path)?;
    let meta = fs::symlink_metadata(path).map_err(|e| io_err(path, &e.to_string()))?;
    if is_symlink_or_reparse(&meta) || !meta.is_file() {
        return Err(FsSafeError::SymlinkForbidden(path.display().to_string()));
    }
    if meta.len() > max_bytes {
        return Err(FsSafeError::PolicyViolation {
            path: path.display().to_string(),
            detail: format!("size {} exceeds bound {max_bytes}", meta.len()),
        });
    }

    let mut open_opts = OpenOptions::new();
    open_opts.read(true);
    apply_nofollow_flags(&mut open_opts);
    let file = open_opts
        .open(path)
        .map_err(|e| io_err(path, &e.to_string()))?;
    let handle_meta = file.metadata().map_err(|e| io_err(path, &e.to_string()))?;
    if is_symlink_or_reparse(&handle_meta) || !handle_meta.is_file() {
        return Err(FsSafeError::SymlinkForbidden(path.display().to_string()));
    }
    verify_same_file_identity(path, &meta, &handle_meta)?;

    let mut raw = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut raw)
        .map_err(|e| io_err(path, &e.to_string()))?;
    if u64::try_from(raw.len()).unwrap_or(u64::MAX) > max_bytes {
        return Err(FsSafeError::PolicyViolation {
            path: path.display().to_string(),
            detail: format!("stream exceeds bound {max_bytes}"),
        });
    }
    Ok(raw)
}

pub fn read_bounded_utf8(path: &Path, max_bytes: u64) -> Result<String, FsSafeError> {
    let raw = read_bounded_regular(path, max_bytes)?;
    String::from_utf8(raw).map_err(|e| io_err(path, &format!("invalid UTF-8: {e}")))
}

pub fn atomic_write_bytes(
    dest: &Path,
    bytes: &[u8],
    private_mode: bool,
) -> Result<(), FsSafeError> {
    reject_symlinks_on_existing_prefixes(dest)?;
    if let Some(parent) = dest.parent()
        && !parent.as_os_str().is_empty()
    {
        ensure_safe_dir_all(parent, private_mode)?;
    }
    match fs::symlink_metadata(dest) {
        Ok(meta) => {
            if is_symlink_or_reparse(&meta) || !meta.is_file() {
                return Err(FsSafeError::SymlinkForbidden(dest.display().to_string()));
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(io_err(dest, &err.to_string())),
    }

    let tmp_path = unique_staging_path(dest)?;
    let write_res = (|| -> Result<(), FsSafeError> {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(if private_mode { 0o600 } else { 0o644 });
        }
        let mut file = opts
            .open(&tmp_path)
            .map_err(|e| io_err(&tmp_path, &e.to_string()))?;
        file.write_all(bytes)
            .map_err(|e| io_err(&tmp_path, &e.to_string()))?;
        file.sync_all()
            .map_err(|e| io_err(&tmp_path, &e.to_string()))?;
        drop(file);
        if private_mode {
            set_private_file_mode(&tmp_path)?;
        }
        Ok(())
    })();

    if let Err(err) = write_res {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }

    if let Err(err) = fs::rename(&tmp_path, dest) {
        let _ = fs::remove_file(&tmp_path);
        return Err(io_err(dest, &err.to_string()));
    }
    Ok(())
}

pub fn load_or_create_private_keypair(path: &Path) -> Result<SigningKeypair, FsSafeError> {
    reject_symlinks_on_existing_prefixes(path)?;
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if is_symlink_or_reparse(&meta) || !meta.is_file() {
                return Err(FsSafeError::SymlinkForbidden(path.display().to_string()));
            }
            check_private_file_mode(path, &meta)?;
            let mut raw = read_bounded_utf8(path, MAX_KEY_FILE_BYTES)?;
            let kp = SigningKeypair::from_seed_b64(&raw).map_err(|e| FsSafeError::Crypto {
                path: path.display().to_string(),
                detail: e.to_string(),
            });
            raw.zeroize();
            kp
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let kp = SigningKeypair::generate().map_err(|e| FsSafeError::Crypto {
                path: path.display().to_string(),
                detail: e.to_string(),
            })?;
            let mut seed = kp.seed_b64();
            let res = atomic_write_bytes(path, seed.as_bytes(), true);
            seed.zeroize();
            res?;
            Ok(kp)
        }
        Err(err) => Err(io_err(path, &err.to_string())),
    }
}

pub fn secure_delete_file(path: &Path) -> Result<(), FsSafeError> {
    reject_symlinks_on_existing_prefixes(path)?;
    let meta = fs::symlink_metadata(path).map_err(|e| io_err(path, &e.to_string()))?;
    if is_symlink_or_reparse(&meta) || !meta.is_file() {
        return Err(FsSafeError::SymlinkForbidden(path.display().to_string()));
    }
    let len = usize::try_from(meta.len().min(1024 * 1024)).unwrap_or(1024);
    if len > 0 {
        let mut del_opts = OpenOptions::new();
        del_opts.write(true);
        apply_nofollow_flags(&mut del_opts);
        if let Ok(mut file) = del_opts.open(path) {
            let zeros = vec![0_u8; len];
            let _ = file.write_all(&zeros);
            let _ = file.sync_all();
        }
    }
    fs::remove_file(path).map_err(|e| io_err(path, &e.to_string()))
}

fn unique_staging_path(dest: &Path) -> Result<PathBuf, FsSafeError> {
    let mut rnd = [0_u8; 8];
    fill_random(&mut rnd).map_err(|e| FsSafeError::Crypto {
        path: dest.display().to_string(),
        detail: e.to_string(),
    })?;
    let hex = grdr_crypto::sha256_hex(&rnd);
    let tag = hex.get(..12).unwrap_or("tmp");
    let file_name = dest
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("artifact");
    let parent = dest.parent().unwrap_or_else(|| Path::new("."));
    let dir = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    Ok(dir.join(format!(".{file_name}.{tag}.tmp")))
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

fn is_os_root_alias(path: &Path, meta: &fs::Metadata) -> bool {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::MetadataExt as _;
        meta.uid() == 0
            && fs::read_link(path)
                .is_ok_and(|target| is_expected_macos_root_alias_target(path, &target))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (path, meta);
        false
    }
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
        target_os = "dragonfly"
    ))]
    {
        0x0100
    }
    #[cfg(target_os = "netbsd")]
    {
        0x0001_0000
    }
}

fn is_symlink_or_reparse(meta: &fs::Metadata) -> bool {
    meta.file_type().is_symlink() || is_reparse_point(meta)
}

fn is_reparse_point(meta: &fs::Metadata) -> bool {
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

fn verify_same_file_identity(
    path: &Path,
    pre_meta: &fs::Metadata,
    handle_meta: &fs::Metadata,
) -> Result<(), FsSafeError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if pre_meta.dev() != handle_meta.dev() || pre_meta.ino() != handle_meta.ino() {
            return Err(FsSafeError::SymlinkForbidden(path.display().to_string()));
        }
    }
    #[cfg(not(unix))]
    {
        if pre_meta.len() != handle_meta.len() {
            return Err(FsSafeError::SymlinkForbidden(path.display().to_string()));
        }
    }
    Ok(())
}

fn set_private_dir_mode(dir: &Path) -> Result<(), FsSafeError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .map_err(|e| io_err(dir, &e.to_string()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

fn set_private_file_mode(path: &Path) -> Result<(), FsSafeError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|e| io_err(path, &e.to_string()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

fn check_private_file_mode(path: &Path, meta: &fs::Metadata) -> Result<(), FsSafeError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if (meta.permissions().mode() & 0o077) != 0 {
            return Err(FsSafeError::PolicyViolation {
                path: path.display().to_string(),
                detail: "private key file permissions must restrict group/other access (0600)"
                    .into(),
            });
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, meta);
    }
    Ok(())
}

fn io_err(path: &Path, detail: &str) -> FsSafeError {
    FsSafeError::Io {
        path: path.display().to_string(),
        detail: detail.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_keypair_writes_atomically_and_rejects_symlinks() {
        let dir = std::env::temp_dir().join(format!("grdr-fs-{}", uuid::Uuid::now_v7().simple()));
        let key_path = dir.join("device.key");
        let kp1 = load_or_create_private_keypair(&key_path).unwrap();
        let kp2 = load_or_create_private_keypair(&key_path).unwrap();
        assert_eq!(kp1.key_id(), kp2.key_id());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::symlink_metadata(&key_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
        let _ = fs::remove_dir_all(&dir);
    }

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
    fn rejects_non_directory_ancestor_obstruction() {
        let base =
            std::env::temp_dir().join(format!("grdr-fs-file-{}", uuid::Uuid::now_v7().simple()));
        fs::create_dir_all(&base).unwrap();
        let file_blocker = base.join("blocker");
        fs::write(&file_blocker, b"data").unwrap();
        assert!(matches!(
            ensure_safe_dir_all(&file_blocker.join("nested"), true),
            Err(FsSafeError::SymlinkForbidden(_))
        ));
        assert!(matches!(
            atomic_write_bytes(&file_blocker.join("nested/k"), b"x", true),
            Err(FsSafeError::SymlinkForbidden(_))
        ));
        #[cfg(target_os = "macos")]
        {
            assert!(matches!(
                ensure_safe_dir_all(Path::new("/tmp"), true),
                Err(FsSafeError::SymlinkForbidden(_))
            ));
            assert!(matches!(
                reject_symlinks_on_existing_prefixes(Path::new("/var")),
                Err(FsSafeError::SymlinkForbidden(_))
            ));
        }
        let _ = fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_ancestors_leaf_and_dangling_targets() {
        use std::os::unix::fs::symlink;

        let base =
            std::env::temp_dir().join(format!("grdr-fs-sym-{}", uuid::Uuid::now_v7().simple()));
        let real_dir = base.join("real_dir");
        fs::create_dir_all(&real_dir).unwrap();
        let real_file = base.join("real_file");
        fs::write(&real_file, b"keep").unwrap();

        let dir_link = base.join("dir_link");
        symlink(&real_dir, &dir_link).unwrap();
        assert!(matches!(
            ensure_safe_dir_all(&dir_link.join("nested"), true),
            Err(FsSafeError::SymlinkForbidden(_))
        ));
        assert!(!real_dir.join("nested").exists());
        assert!(matches!(
            atomic_write_bytes(&dir_link.join("nested/k"), b"x", true),
            Err(FsSafeError::SymlinkForbidden(_))
        ));
        assert!(matches!(
            read_bounded_regular(&dir_link.join("k"), 64),
            Err(FsSafeError::SymlinkForbidden(_))
        ));

        let leaf_link = base.join("leaf_link");
        symlink(&real_file, &leaf_link).unwrap();
        assert!(matches!(
            read_bounded_regular(&leaf_link, 64),
            Err(FsSafeError::SymlinkForbidden(_))
        ));
        assert!(matches!(
            atomic_write_bytes(&leaf_link, b"overwrite", true),
            Err(FsSafeError::SymlinkForbidden(_))
        ));
        assert!(matches!(
            load_or_create_private_keypair(&leaf_link),
            Err(FsSafeError::SymlinkForbidden(_))
        ));
        assert!(matches!(
            secure_delete_file(&leaf_link),
            Err(FsSafeError::SymlinkForbidden(_))
        ));

        let dangling_link = base.join("dangling_link");
        symlink(base.join("nonexistent"), &dangling_link).unwrap();
        assert!(matches!(
            atomic_write_bytes(&dangling_link, b"overwrite", true),
            Err(FsSafeError::SymlinkForbidden(_))
        ));
        assert!(matches!(
            load_or_create_private_keypair(&dangling_link),
            Err(FsSafeError::SymlinkForbidden(_))
        ));
        assert!(matches!(
            secure_delete_file(&dangling_link),
            Err(FsSafeError::SymlinkForbidden(_))
        ));

        assert_eq!(fs::read(&real_file).unwrap(), b"keep");
        let _ = fs::remove_dir_all(&base);
    }
}
