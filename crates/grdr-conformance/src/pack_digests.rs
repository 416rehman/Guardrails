// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Deterministic manifest formatting and bounded digest traversal for signed packs.

use std::fs;
use std::path::{Path, PathBuf};

use grdr_crypto::sha256_hex;

use crate::ConformanceError;
use crate::pack_manifest::{
    MAX_PACK_FILE_BYTES, conf_err, is_symlink_or_reparse, read_regular_bounded_bytes,
};
use crate::pack_verify::{PACK_SIG_DOMAIN, PackFileDigest};

pub(crate) fn collect_pack_digests(
    root: &Path,
    dir: &Path,
    depth: usize,
) -> Result<Vec<PackFileDigest>, ConformanceError> {
    if depth == 0 {
        let root_meta =
            fs::symlink_metadata(root).map_err(|e| conf_err("pack-sig", &e.to_string()))?;
        if is_symlink_or_reparse(&root_meta) || !root_meta.is_dir() {
            return Err(conf_err(
                "pack-sig",
                "pack root must be a real non-symlink directory",
            ));
        }
    }
    if depth > 8 {
        return Err(conf_err("pack-sig", "directory depth exceeded"));
    }
    let mut children: Vec<PathBuf> = fs::read_dir(dir)
        .map_err(|e| conf_err("pack-sig", &e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| conf_err("pack-sig", &e.to_string()))?
        .into_iter()
        .map(|e| e.path())
        .collect();
    children.sort();
    let mut out = Vec::new();
    for p in children {
        let meta = fs::symlink_metadata(&p).map_err(|e| conf_err("pack-sig", &e.to_string()))?;
        if is_symlink_or_reparse(&meta) {
            return Err(conf_err(
                "pack-sig",
                "symlinks or reparse points forbidden in pack directory",
            ));
        }
        if meta.is_dir() {
            out.extend(collect_pack_digests(root, &p, depth.saturating_add(1))?);
        } else if meta.is_file() {
            let rel = p
                .strip_prefix(root)
                .map_err(|e| conf_err("pack-sig", &e.to_string()))?
                .to_string_lossy()
                .replace('\\', "/");
            if rel == "signature.json" {
                continue;
            }
            let raw = read_regular_bounded_bytes(&p, MAX_PACK_FILE_BYTES)?;
            out.push(PackFileDigest {
                path: rel,
                sha256: sha256_hex(&raw),
                length: u64::try_from(raw.len()).unwrap_or(u64::MAX),
            });
        } else {
            return Err(conf_err(
                "pack-sig",
                &format!(
                    "non-regular filesystem entry `{}` forbidden in pack directory",
                    p.display()
                ),
            ));
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

pub(crate) fn canonical_manifest_text(
    pack_id: &str,
    version: &str,
    files: &[PackFileDigest],
) -> Result<String, ConformanceError> {
    validate_manifest_token(pack_id, "pack_id")?;
    validate_manifest_token(version, "version")?;
    let mut lines = Vec::with_capacity(files.len().saturating_add(3));
    lines.push(PACK_SIG_DOMAIN.to_owned());
    lines.push(pack_id.to_owned());
    lines.push(version.to_owned());
    for f in files {
        validate_manifest_token(&f.path, "file.path")?;
        validate_manifest_token(&f.sha256, "file.sha256")?;
        lines.push(format!("{} {} {}", f.path, f.sha256, f.length));
    }
    Ok(lines.join("\n"))
}

fn validate_manifest_token(val: &str, label: &str) -> Result<(), ConformanceError> {
    if val.is_empty() || val.chars().any(|ch| ch.is_control() || ch.is_whitespace()) {
        return Err(conf_err(
            "pack-sig",
            &format!("canonical manifest `{label}` contains empty, whitespace, or control chars"),
        ));
    }
    Ok(())
}
