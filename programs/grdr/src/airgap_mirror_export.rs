// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Air-gap site TUF mirror delta, content, and metadata tar bundle export helpers.

use std::fs;
use std::path::PathBuf;

use clap::{Args, ValueEnum};
use grdr_update::mirror::plan_mirror_export;
use grdr_update::{MirrorExportKind, SignedMetadata, SnapshotMetadata, TargetsMetadata};
use serde::{Deserialize, Serialize};

use crate::airgap::AirgapCliError;
use crate::airgap::airgap_mirror::{
    MAX_MIRROR_JSON_BYTES, MAX_MIRROR_TARGET_BYTES, io_err, load_sync_state, parse_json_signed,
};
use crate::airgap::airgap_policy::split_archive_to_parts;
use crate::fs_safe::{atomic_write_bytes, read_bounded_regular};
use crate::tar_archive::{TarEntry, encode_tar, validate_archive_rel_path};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum MirrorKindCli {
    Delta,
    Content,
    Metadata,
}

#[derive(Debug, Clone, Args)]
pub struct MirrorExportArgs {
    #[arg(long)]
    pub mirror_dir: PathBuf,
    #[arg(long)]
    pub out: PathBuf,
    #[arg(long, value_enum)]
    pub kind: MirrorKindCli,
    #[arg(long)]
    pub base: Option<String>,
    #[arg(long)]
    pub split_bytes: Option<u64>,
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MirrorExportSummary {
    pub kind: MirrorExportKind,
    pub out: String,
    pub target_snapshot_sha256: String,
    pub files_exported: usize,
    pub metadata_files_exported: usize,
    pub parts_count: usize,
}

pub fn run_mirror_export(args: &MirrorExportArgs) -> Result<MirrorExportSummary, AirgapCliError> {
    let state_path = args.mirror_dir.join("mirror-sync-state.json");
    let state = load_sync_state(&state_path)?;
    let mut meta_files: Vec<(&str, Vec<u8>)> = Vec::new();
    for (rel, required) in [
        ("tuf/root.json", true),
        ("tuf/timestamp.json", true),
        ("tuf/snapshot.json", true),
        ("tuf/targets.json", true),
        ("tuf/rollout.json", false),
    ] {
        let p = args.mirror_dir.join(rel);
        if fs::symlink_metadata(&p).is_err() {
            if required {
                return Err(io_err(&p, "missing committed TUF mirror metadata"));
            }
            continue;
        }
        let bytes = read_bounded_regular(&p, MAX_MIRROR_JSON_BYTES)
            .map_err(|e| io_err(&p, &e.to_string()))?;
        meta_files.push((rel, bytes));
    }

    let snap_bytes = meta_files
        .iter()
        .find(|(rel, _)| *rel == "tuf/snapshot.json")
        .map(|(_, b)| b.as_slice())
        .ok_or_else(|| {
            io_err(
                &args.mirror_dir.join("tuf/snapshot.json"),
                "missing mirror snapshot",
            )
        })?;
    let targets_bytes = meta_files
        .iter()
        .find(|(rel, _)| *rel == "tuf/targets.json")
        .map(|(_, b)| b.as_slice())
        .ok_or_else(|| {
            io_err(
                &args.mirror_dir.join("tuf/targets.json"),
                "missing mirror targets",
            )
        })?;
    let snap: SignedMetadata<SnapshotMetadata> = parse_json_signed(snap_bytes, "mirror snapshot")?;
    let targets: SignedMetadata<TargetsMetadata> =
        parse_json_signed(targets_bytes, "mirror targets")?;

    let meta_pairs: Vec<(&str, u64)> = meta_files
        .iter()
        .map(|(rel, b)| (*rel, u64::try_from(b.len()).unwrap_or(0)))
        .collect();
    let kind = match args.kind {
        MirrorKindCli::Delta => MirrorExportKind::Delta,
        MirrorKindCli::Content => MirrorExportKind::Content,
        MirrorKindCli::Metadata => MirrorExportKind::Metadata,
    };
    let base_digests = args
        .base
        .as_deref()
        .and_then(|b| state.snapshot_targets.get(b));
    let plan = plan_mirror_export(
        kind,
        args.base.as_deref(),
        &state.known_snapshot_digests,
        base_digests,
        &snap.signed,
        &targets.signed,
        &meta_pairs,
    )?;

    let mut tar_entries = Vec::new();
    for (rel, bytes) in meta_files {
        tar_entries.push(TarEntry {
            path: rel.to_owned(),
            bytes,
        });
    }
    for rel in &plan.included_paths {
        validate_archive_rel_path(rel).map_err(|e| AirgapCliError::InvalidInput(e.to_string()))?;
        let src = rel
            .split('/')
            .fold(args.mirror_dir.join("targets"), |a, s| a.join(s));
        let bytes = read_bounded_regular(&src, MAX_MIRROR_TARGET_BYTES)
            .map_err(|e| io_err(&src, &e.to_string()))?;
        tar_entries.push(TarEntry {
            path: rel.clone(),
            bytes,
        });
    }
    let tar_bytes =
        encode_tar(&tar_entries).map_err(|e| AirgapCliError::InvalidInput(e.to_string()))?;
    atomic_write_bytes(&args.out, &tar_bytes, false)
        .map_err(|e| io_err(&args.out, &e.to_string()))?;

    let parts_count = match args.split_bytes {
        Some(chunk_bytes) => {
            let (pm, _) = split_archive_to_parts(
                &tar_bytes,
                &args.out,
                chunk_bytes,
                "mirror-export",
                "1.0.0",
            )?;
            pm.parts.len()
        }
        None => 0,
    };

    Ok(MirrorExportSummary {
        kind,
        out: args.out.display().to_string(),
        target_snapshot_sha256: plan.target_snapshot_sha256,
        files_exported: plan.included_paths.len(),
        metadata_files_exported: plan.included_metadata_paths.len(),
        parts_count,
    })
}
