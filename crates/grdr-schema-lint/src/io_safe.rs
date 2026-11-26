// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Descriptor/capture orchestration and bounded artifact verification delegated to `io_safe_fs`.

use std::fs;
use std::path::Path;

use grdr_proto::descriptor::decode_descriptor_set;

use crate::capture_toml::{
    CaptureConfig, ReclassificationEntry, parse_capture_toml, parse_reclassifications_toml,
    validate_capture_sl13,
};
use crate::descriptor_env::ResolvedSchemaContext;
use crate::descriptor_lint::check_descriptor_set;
pub(crate) use crate::io_safe_fs::{
    canonicalize_real_dir, is_symlink_or_reparse, read_bounded_regular_bytes,
    reject_symlinks_under, write_regular_atomically,
};
use crate::proto_lint::check_proto_sources_against_descriptors;
use crate::schema_compare::validate_reclassifications_entries;
use crate::{
    LintError, LintFinding, MAX_DESCRIPTOR_BINPB_BYTES, MAX_LINT_DIR_DEPTH, MAX_LINT_FILE_BYTES,
};

pub(crate) fn run_descriptor_and_capture_checks(
    canon_root: &Path,
    proto_dir: &Path,
    brand_raw: &str,
    findings: &mut Vec<LintFinding>,
) -> Result<
    (
        ResolvedSchemaContext,
        CaptureConfig,
        Vec<ReclassificationEntry>,
    ),
    LintError,
> {
    let checked_proto = reject_symlinks_under(canon_root, proto_dir, true)?;
    let dir_meta = fs::symlink_metadata(&checked_proto).map_err(|e| LintError::Io {
        path: proto_dir.display().to_string(),
        detail: e.to_string(),
    })?;
    if is_symlink_or_reparse(&dir_meta) || !dir_meta.is_dir() {
        return Err(LintError::Io {
            path: proto_dir.display().to_string(),
            detail: "proto root must be a real non-symlink directory".into(),
        });
    }
    let canon_proto = fs::canonicalize(&checked_proto).map_err(|e| LintError::Io {
        path: proto_dir.display().to_string(),
        detail: e.to_string(),
    })?;
    if !canon_proto.starts_with(canon_root) {
        return Err(LintError::Io {
            path: proto_dir.display().to_string(),
            detail: "proto root escapes repository root".into(),
        });
    }
    let mut disk_paths = Vec::new();
    collect_proto_rel_paths(&canon_proto, &canon_proto, 0, &mut disk_paths)?;

    let binpb_bytes = read_bounded_regular_bytes(
        canon_root,
        &canon_root.join("crates/grdr-proto/descriptors/proto.binpb"),
        MAX_DESCRIPTOR_BINPB_BYTES,
    )?;
    let set = decode_descriptor_set(&binpb_bytes).map_err(|e| LintError::ProtoViolation {
        file: "crates/grdr-proto/descriptors/proto.binpb".into(),
        detail: e.to_string(),
    })?;

    let foreign_raw = read_bounded_regular_file(
        canon_root,
        &canon_root.join("crates/grdr-schema-lint/foreign_files.toml"),
        MAX_LINT_FILE_BYTES,
    )?;
    let surfaces_raw = read_bounded_regular_file(
        canon_root,
        &canon_root.join("contracts/surfaces.toml"),
        MAX_LINT_FILE_BYTES,
    )?;
    let capture_raw = read_bounded_regular_file(
        canon_root,
        &canon_root.join("crates/grdr-schema/capture.toml"),
        MAX_LINT_FILE_BYTES,
    )?;
    let reclass_raw = read_bounded_regular_file(
        canon_root,
        &canon_root.join("crates/grdr-schema/reclassifications.toml"),
        MAX_LINT_FILE_BYTES,
    )?;

    let ctx = check_descriptor_set(
        &set,
        &disk_paths,
        &foreign_raw,
        brand_raw,
        &surfaces_raw,
        findings,
    )?;
    check_proto_sources_against_descriptors(
        &canon_proto,
        &set,
        &ctx.namespace,
        &ctx.options_ext,
        &ctx.dc_wire_to_num,
        &ctx.ck_wire_to_num,
        findings,
    )?;

    let capture_cfg = parse_capture_toml(&capture_raw)?;
    validate_capture_sl13(&capture_cfg, &ctx.options_class_wire_names, findings);
    let reclass = parse_reclassifications_toml(&reclass_raw)?;
    validate_reclassifications_entries(&reclass, findings);

    Ok((ctx, capture_cfg, reclass))
}

fn collect_proto_rel_paths(
    base: &Path,
    dir: &Path,
    depth: usize,
    out: &mut Vec<String>,
) -> Result<(), LintError> {
    if depth > MAX_LINT_DIR_DEPTH {
        return Err(LintError::Io {
            path: dir.display().to_string(),
            detail: format!("proto recursion exceeded {MAX_LINT_DIR_DEPTH}"),
        });
    }
    let entries = fs::read_dir(dir).map_err(|e| LintError::Io {
        path: dir.display().to_string(),
        detail: e.to_string(),
    })?;
    for entry in entries {
        let entry = entry.map_err(|e| LintError::Io {
            path: dir.display().to_string(),
            detail: e.to_string(),
        })?;
        let ft = entry.file_type().map_err(|e| LintError::Io {
            path: entry.path().display().to_string(),
            detail: e.to_string(),
        })?;
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).map_err(|e| LintError::Io {
            path: path.display().to_string(),
            detail: e.to_string(),
        })?;
        if ft.is_symlink() || is_symlink_or_reparse(&meta) {
            return Err(LintError::Io {
                path: path.display().to_string(),
                detail: "symlinks are forbidden inside proto schema directories".into(),
            });
        }
        if meta.is_dir() {
            let canon_sub = canonicalize_real_dir(&path, "proto subdirectory")?;
            if !canon_sub.starts_with(base) {
                return Err(LintError::Io {
                    path: path.display().to_string(),
                    detail: "proto subdirectory escapes schema root".into(),
                });
            }
            collect_proto_rel_paths(base, &canon_sub, depth.saturating_add(1), out)?;
        } else if meta.is_file()
            && path.extension().and_then(|s| s.to_str()) == Some("proto")
            && let Ok(rel) = path.strip_prefix(base)
        {
            out.push(rel.to_string_lossy().replace('\\', "/"));
        }
    }
    Ok(())
}

pub(crate) fn read_bounded_regular_file(
    canon_root: &Path,
    path: &Path,
    max_bytes: u64,
) -> Result<String, LintError> {
    let bytes = read_bounded_regular_bytes(canon_root, path, max_bytes)?;
    String::from_utf8(bytes).map_err(|e| LintError::Io {
        path: path.display().to_string(),
        detail: format!("invalid UTF-8: {e}"),
    })
}

pub(crate) fn sync_selected_targets(
    root: &Path,
    targets: &[(&str, String)],
    check_only: bool,
) -> Result<(), LintError> {
    let canon_root = canonicalize_real_dir(root, "repository root")?;
    let mut drifted = Vec::new();
    for (rel, expected) in targets {
        let abs = canon_root.join(rel);
        if check_only {
            let actual = read_bounded_regular_file(&canon_root, &abs, MAX_LINT_FILE_BYTES)?;
            if actual != *expected {
                drifted.push(*rel);
            }
        } else {
            write_regular_atomically(&canon_root, &abs, expected.as_bytes())?;
        }
    }
    if !drifted.is_empty() {
        let list = drifted.join(", ");
        return Err(LintError::CaptureOrCodegenViolation {
            target: list.clone(),
            detail: format!("generated artifacts drifted from descriptor/capture schema: {list}"),
        });
    }
    Ok(())
}
