// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Hardened handle-based bounded pack I/O, symlink/reparse checks, and schema limits (`contracts/limits.toml`).

use std::fs::{self, OpenOptions};
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use grdr_crypto::sha256_hex;
use grdr_schema::limits::{PackLimits, load_embedded_limits};

const MAX_PACK_WALK_DEPTH: usize = 8;
const MAX_YAML_LIST_FILE_CAP_BYTES: u64 = 1_048_576;

pub(crate) fn pack_limits() -> Result<&'static PackLimits, String> {
    static CACHE: OnceLock<Result<PackLimits, String>> = OnceLock::new();
    match CACHE.get_or_init(|| {
        load_embedded_limits()
            .map(|l| l.packs)
            .map_err(|e| e.to_string())
    }) {
        Ok(limits) => Ok(limits),
        Err(msg) => Err(format!("embedded limits unavailable: {msg}")),
    }
}

pub(crate) fn essentials_max_bytes() -> Result<u64, String> {
    let kb = u64::from(pack_limits()?.essentials_max_kb);
    Ok(kb.saturating_mul(1024))
}

pub(crate) fn detections_max_bytes() -> Result<u64, String> {
    let mb = u64::from(pack_limits()?.detections_max_mb);
    Ok(mb.saturating_mul(1_048_576))
}

pub(crate) fn pack_list_max_bytes() -> Result<u64, String> {
    let bundle_mb = u64::from(pack_limits()?.max_pack_bundle_mb);
    let bundle_bytes = bundle_mb.saturating_mul(1_048_576);
    Ok(bundle_bytes.min(MAX_YAML_LIST_FILE_CAP_BYTES))
}

pub(crate) fn is_symlink_or_reparse(meta: &fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

pub(crate) fn ensure_real_dir(dir: &Path, label: &str) -> Result<(), String> {
    let meta = fs::symlink_metadata(dir)
        .map_err(|e| format!("failed inspecting {label} `{}`: {e}", dir.display()))?;
    if is_symlink_or_reparse(&meta) || !meta.is_dir() {
        return Err(format!(
            "{label} `{}` must be a real non-symlink directory",
            dir.display()
        ));
    }
    Ok(())
}

pub(crate) fn safe_pack_child_path(pack_dir: &Path, rel: &str) -> Result<PathBuf, String> {
    ensure_real_dir(pack_dir, "pack root")?;
    if rel.is_empty() {
        return Err("empty relative path inside signed pack".into());
    }
    let mut cur = pack_dir.to_path_buf();
    let segs: Vec<&str> = rel.split('/').collect();
    for (idx, seg) in segs.iter().enumerate() {
        if seg.is_empty() || *seg == "." || *seg == ".." || seg.contains('\\') || seg.contains('\0')
        {
            return Err(format!("unsafe signed pack relative path `{rel}`"));
        }
        cur.push(seg);
        let meta = fs::symlink_metadata(&cur)
            .map_err(|e| format!("missing signed pack path `{rel}`: {e}"))?;
        if is_symlink_or_reparse(&meta) {
            return Err(format!("symlink or reparse point forbidden at `{rel}`"));
        }
        if idx.saturating_add(1) < segs.len() && !meta.is_dir() {
            return Err(format!(
                "intermediate component in `{rel}` is not directory"
            ));
        }
    }
    Ok(cur)
}

pub(crate) fn read_bounded_regular_bytes(path: &Path, max_bytes: u64) -> Result<Vec<u8>, String> {
    let meta = fs::symlink_metadata(path)
        .map_err(|e| format!("failed inspecting `{}`: {e}", path.display()))?;
    if is_symlink_or_reparse(&meta) || !meta.is_file() {
        return Err(format!(
            "`{}`: refusing symlink, reparse point, or non-regular file",
            path.display()
        ));
    }
    if meta.len() > max_bytes {
        return Err(format!(
            "`{}` exceeds max byte bound ({} > {max_bytes})",
            path.display(),
            meta.len()
        ));
    }

    let mut opts = OpenOptions::new();
    opts.read(true);
    apply_nofollow_flags(&mut opts);
    let file = opts
        .open(path)
        .map_err(|e| format!("failed opening `{}`: {e}", path.display()))?;
    let handle_meta = file.metadata().map_err(|e| {
        format!(
            "failed reading handle metadata for `{}`: {e}",
            path.display()
        )
    })?;
    if is_symlink_or_reparse(&handle_meta) || !handle_meta.is_file() {
        return Err(format!(
            "`{}`: opened handle failed regular-file check",
            path.display()
        ));
    }
    verify_same_file_identity(path, &meta, &handle_meta)?;
    if handle_meta.len() > max_bytes {
        return Err(format!(
            "`{}` handle length exceeds max byte bound ({} > {max_bytes})",
            path.display(),
            handle_meta.len()
        ));
    }

    let mut out = Vec::new();
    let mut reader = file.take(max_bytes.saturating_add(1));
    reader
        .read_to_end(&mut out)
        .map_err(|e| format!("failed reading `{}`: {e}", path.display()))?;
    if u64::try_from(out.len()).unwrap_or(u64::MAX) > max_bytes {
        return Err(format!(
            "`{}` exceeds max byte bound ({max_bytes})",
            path.display()
        ));
    }
    Ok(out)
}

pub(crate) fn read_bounded_regular_text(path: &Path, max_bytes: u64) -> Result<String, String> {
    let bytes = read_bounded_regular_bytes(path, max_bytes)?;
    String::from_utf8(bytes).map_err(|_| format!("`{}` is not valid UTF-8", path.display()))
}

pub(crate) fn read_pack_child_text(
    pack_dir: &Path,
    rel: &str,
    max_bytes: u64,
) -> Result<String, String> {
    let full = safe_pack_child_path(pack_dir, rel)?;
    read_bounded_regular_text(&full, max_bytes)
}

pub(crate) fn collect_signed_pack_digests(
    root: &Path,
    max_file_bytes: u64,
    max_total_bytes: u64,
) -> Result<Vec<(String, String, u64)>, String> {
    ensure_real_dir(root, "pack root")?;
    let mut out = Vec::new();
    let mut total_bytes: u64 = 0;
    walk_pack_dir(
        root,
        root,
        0,
        max_file_bytes,
        max_total_bytes,
        &mut total_bytes,
        &mut out,
    )?;
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

fn walk_pack_dir(
    root: &Path,
    dir: &Path,
    depth: usize,
    max_file_bytes: u64,
    max_total_bytes: u64,
    total_bytes: &mut u64,
    out: &mut Vec<(String, String, u64)>,
) -> Result<(), String> {
    if depth > MAX_PACK_WALK_DEPTH {
        return Err("pack directory nesting depth exceeded".into());
    }
    let mut children: Vec<PathBuf> = fs::read_dir(dir)
        .map_err(|e| format!("failed listing `{}`: {e}", dir.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("failed reading dir entry under `{}`: {e}", dir.display()))?
        .into_iter()
        .map(|ent| ent.path())
        .collect();
    children.sort();
    for path in children {
        let meta = fs::symlink_metadata(&path)
            .map_err(|e| format!("failed inspecting `{}`: {e}", path.display()))?;
        if is_symlink_or_reparse(&meta) {
            return Err(format!(
                "symlinks or reparse points forbidden inside signed pack (`{}`)",
                path.display()
            ));
        }
        if meta.is_dir() {
            walk_pack_dir(
                root,
                &path,
                depth.saturating_add(1),
                max_file_bytes,
                max_total_bytes,
                total_bytes,
                out,
            )?;
            continue;
        }
        if !meta.is_file() {
            return Err(format!(
                "non-regular entry `{}` forbidden in signed pack",
                path.display()
            ));
        }
        let rel = path
            .strip_prefix(root)
            .map_err(|e| format!("pack path strip_prefix failed: {e}"))?
            .to_string_lossy()
            .replace('\\', "/");
        if rel == "signature.json" {
            continue;
        }
        let raw = read_bounded_regular_bytes(&path, max_file_bytes)?;
        let len = u64::try_from(raw.len()).unwrap_or(u64::MAX);
        *total_bytes = total_bytes
            .checked_add(len)
            .ok_or_else(|| "pack cumulative byte length overflow".to_owned())?;
        if *total_bytes > max_total_bytes {
            return Err(format!(
                "signed pack total bytes ({}) exceeds limit ({max_total_bytes})",
                *total_bytes
            ));
        }
        out.push((rel, sha256_hex(&raw), len));
    }
    Ok(())
}

fn verify_same_file_identity(
    path: &Path,
    pre: &fs::Metadata,
    handle: &fs::Metadata,
) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if pre.dev() != handle.dev() || pre.ino() != handle.ino() {
            return Err(format!(
                "`{}`: file identity changed between stat and open",
                path.display()
            ));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, pre, handle);
    }
    Ok(())
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
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
}

#[cfg(unix)]
const fn unix_o_nofollow() -> i32 {
    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
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
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        target_os = "netbsd"
    )))]
    {
        0
    }
}
