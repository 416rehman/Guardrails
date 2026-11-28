// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Bounded, symlink-safe filesystem readers and exact finite probability conversions.

use std::fs::{self, OpenOptions};
use std::io::Read as _;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Component, Path, PathBuf};

use crate::InferError;

pub(crate) const MAX_MANIFEST_BYTES: usize = 64 * 1024;
pub(crate) const MAX_VOCAB_BYTES: usize = 4 * 1024 * 1024;

/// Verifies that `pack_dir` is a real non-symlink directory and returns its canonical path.
pub(crate) fn canonical_pack_dir(pack_dir: &Path) -> Result<PathBuf, InferError> {
    let meta = fs::symlink_metadata(pack_dir)
        .map_err(|e| InferError::InvalidInput(format!("failed inspecting model pack dir: {e}")))?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(InferError::InvalidInput(
            "model pack directory must not be a symlink or non-directory".into(),
        ));
    }
    let canon = pack_dir.canonicalize().map_err(|e| {
        InferError::InvalidInput(format!("failed canonicalizing model pack dir: {e}"))
    })?;
    let mut cur = pack_dir.to_path_buf();
    while let Some(parent) = cur.parent() {
        if cur.as_os_str().is_empty() {
            break;
        }
        if let Ok(m) = fs::symlink_metadata(&cur)
            && m.file_type().is_symlink()
        {
            return Err(InferError::InvalidInput(
                "model pack ancestor directory symlink rejected".into(),
            ));
        }
        cur = parent.to_path_buf();
    }
    Ok(canon)
}

/// Reads a bounded regular file strictly inside `canon_dir` (`O_NOFOLLOW` on Unix).
pub(crate) fn read_pack_member_bounded(
    canon_dir: &Path,
    rel: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, InferError> {
    let rel_path = Path::new(rel);
    if rel.trim().is_empty()
        || !rel_path
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
    {
        return Err(InferError::InvalidInput(
            "invalid pack relative file path".into(),
        ));
    }
    let candidate = canon_dir.join(rel_path);
    let mut walk = canon_dir.to_path_buf();
    for comp in rel_path.components() {
        walk.push(comp);
        let meta = fs::symlink_metadata(&walk).map_err(|e| {
            InferError::InvalidInput(format!("failed inspecting model pack member: {e}"))
        })?;
        if meta.file_type().is_symlink() {
            return Err(InferError::InvalidInput(
                "model pack member symlink rejected".into(),
            ));
        }
    }
    let final_meta = fs::symlink_metadata(&candidate)
        .map_err(|e| InferError::InvalidInput(format!("failed inspecting model pack file: {e}")))?;
    if final_meta.file_type().is_symlink() || !final_meta.is_file() {
        return Err(InferError::InvalidInput(
            "model pack member must be a regular non-symlink file".into(),
        ));
    }
    let canon_member = candidate.canonicalize().map_err(|e| {
        InferError::InvalidInput(format!("failed canonicalizing model pack file: {e}"))
    })?;
    if !canon_member.starts_with(canon_dir) {
        return Err(InferError::InvalidInput(
            "model pack member escapes pack root".into(),
        ));
    }
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        let nofollow = unix_o_nofollow_flag().ok_or_else(|| {
            InferError::InvalidInput(
                "unsupported Unix target lacks verified O_NOFOLLOW constant".into(),
            )
        })?;
        opts.custom_flags(nofollow);
    }
    let file = opts
        .open(&canon_member)
        .map_err(|e| InferError::InvalidInput(format!("failed opening model pack member: {e}")))?;
    let opened_meta = file.metadata().map_err(|e| {
        InferError::InvalidInput(format!("failed stat opened model pack member: {e}"))
    })?;
    if !opened_meta.is_file() {
        return Err(InferError::InvalidInput(
            "opened model pack member is not a regular file".into(),
        ));
    }
    #[cfg(unix)]
    if opened_meta.dev() != final_meta.dev() || opened_meta.ino() != final_meta.ino() {
        return Err(InferError::InvalidInput(
            "model pack file changed between verification and open".into(),
        ));
    }
    let cap = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut buf = Vec::new();
    file.take(cap)
        .read_to_end(&mut buf)
        .map_err(|e| InferError::InvalidInput(format!("failed reading model pack member: {e}")))?;
    if buf.len() > max_bytes {
        return Err(InferError::InvalidInput(format!(
            "model pack member `{rel}` exceeds maximum bound {max_bytes} bytes"
        )));
    }
    Ok(buf)
}

#[cfg(unix)]
const fn unix_o_nofollow_flag() -> Option<i32> {
    #[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "x86")))]
    {
        Some(0o400_000)
    }
    #[cfg(all(target_os = "linux", any(target_arch = "aarch64", target_arch = "arm")))]
    {
        Some(0o100_000)
    }
    #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
    {
        Some(0x0100)
    }
    #[cfg(not(any(
        all(
            target_os = "linux",
            any(
                target_arch = "x86_64",
                target_arch = "x86",
                target_arch = "aarch64",
                target_arch = "arm"
            )
        ),
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd"
    )))]
    {
        None
    }
}

/// Converts a finite `[0.0, 1.0]` probability to `[0, scale]` without unchecked float casts.
pub(crate) fn finite_prob_to_u16_scaled(prob: f32, scale: u16) -> Result<u16, InferError> {
    if !prob.is_finite() {
        return Err(InferError::InvalidInput(
            "non-finite ONNX model probability rejected".into(),
        ));
    }
    let clamped = f64::from(prob.clamp(0.0, 1.0));
    let target = (clamped * f64::from(scale)).round();
    let mut lo: u16 = 0;
    let mut hi: u16 = scale;
    while lo < hi {
        let mid = lo.saturating_add(hi.saturating_sub(lo).saturating_add(1) >> 1);
        if f64::from(mid) <= target {
            lo = mid;
        } else {
            hi = mid.saturating_sub(1);
        }
    }
    Ok(lo)
}
