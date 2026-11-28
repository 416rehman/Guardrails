// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::UpdateError;
use crate::tuf_types::{SnapshotMetadata, TargetsMetadata, canonical_json, canonical_sha256};

pub const DEFAULT_PLATFORM_MARKERS: &[&str] = &[
    "linux-amd64",
    "linux-arm64",
    "linux-x86_64",
    "linux-aarch64",
    "windows-amd64",
    "windows-arm64",
    "darwin-amd64",
    "darwin-arm64",
    "macos-universal",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MirrorExportKind {
    Delta,
    Content,
    Metadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MirrorExportPlan {
    pub kind: MirrorExportKind,
    pub base_snapshot_sha256: Option<String>,
    pub target_snapshot_sha256: String,
    pub included_metadata_paths: Vec<String>,
    pub included_paths: Vec<String>,
    pub skipped_unchanged_count: usize,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MirrorConvergenceReport {
    pub expected_count: usize,
    pub converged_count: usize,
    pub missing_paths: Vec<String>,
    pub mismatched_paths: Vec<String>,
    pub fully_converged: bool,
}

pub fn plan_mirror_export(
    kind: MirrorExportKind,
    base_snapshot_sha256: Option<&str>,
    available_base_snapshots: &BTreeSet<String>,
    base_target_digests: Option<&BTreeMap<String, String>>,
    snapshot: &SnapshotMetadata,
    targets: &TargetsMetadata,
    metadata_paths: &[(&str, u64)],
) -> Result<MirrorExportPlan, UpdateError> {
    let snap_bytes = canonical_json(snapshot)?;
    let target_snapshot_sha256 = canonical_sha256(&snap_bytes);
    let mut included_metadata_paths = Vec::new();
    let mut included_paths = Vec::new();
    let mut skipped_unchanged_count = 0usize;
    let mut total_bytes: u64 = 0;

    for (path, len) in metadata_paths {
        included_metadata_paths.push((*path).to_owned());
        total_bytes = total_bytes.saturating_add(*len);
    }

    match kind {
        MirrorExportKind::Delta => {
            let Some(base) = base_snapshot_sha256 else {
                return Err(UpdateError::ArtifactIntegrity {
                    target: "mirror-export::delta".into(),
                    detail: "delta export requires --base snapshot digest".into(),
                });
            };
            if !available_base_snapshots.contains(base) {
                return Err(UpdateError::ArtifactIntegrity {
                    target: base.to_owned(),
                    detail: format!("missing base snapshot digest `{base}` for delta export"),
                });
            }
            let Some(base_map) = base_target_digests else {
                return Err(UpdateError::ArtifactIntegrity {
                    target: base.to_owned(),
                    detail: format!(
                        "missing base snapshot target digest map for `{base}` delta diff"
                    ),
                });
            };
            for (path, desc) in &targets.targets {
                if base_map.get(path) == Some(&desc.sha256) {
                    skipped_unchanged_count = skipped_unchanged_count.saturating_add(1);
                    continue;
                }
                included_paths.push(path.clone());
                total_bytes = total_bytes.saturating_add(desc.length);
            }
        }
        MirrorExportKind::Content => {
            for (path, desc) in &targets.targets {
                included_paths.push(path.clone());
                total_bytes = total_bytes.saturating_add(desc.length);
            }
        }
        MirrorExportKind::Metadata => {}
    }

    Ok(MirrorExportPlan {
        kind,
        base_snapshot_sha256: base_snapshot_sha256.map(ToOwned::to_owned),
        target_snapshot_sha256,
        included_metadata_paths,
        included_paths,
        skipped_unchanged_count,
        total_bytes,
    })
}

#[must_use]
pub fn evaluate_mirror_convergence(
    targets: &TargetsMetadata,
    synced_digests: &BTreeMap<String, String>,
) -> MirrorConvergenceReport {
    evaluate_mirror_convergence_scoped(targets, synced_digests, &[])
}

#[must_use]
pub fn evaluate_mirror_convergence_scoped(
    targets: &TargetsMetadata,
    synced_digests: &BTreeMap<String, String>,
    platforms: &[String],
) -> MirrorConvergenceReport {
    let mut missing_paths = Vec::new();
    let mut mismatched_paths = Vec::new();
    let mut converged_count: usize = 0;
    let mut expected_count: usize = 0;

    for (path, desc) in &targets.targets {
        if !target_matches_platforms(path, platforms) {
            continue;
        }
        expected_count = expected_count.saturating_add(1);
        match synced_digests.get(path) {
            None => missing_paths.push(path.clone()),
            Some(sha) if sha != &desc.sha256 => mismatched_paths.push(path.clone()),
            Some(_) => converged_count = converged_count.saturating_add(1),
        }
    }

    let fully_converged = missing_paths.is_empty() && mismatched_paths.is_empty();
    MirrorConvergenceReport {
        expected_count,
        converged_count,
        missing_paths,
        mismatched_paths,
        fully_converged,
    }
}

#[must_use]
pub fn target_matches_platforms(rel_path: &str, platforms: &[String]) -> bool {
    if platforms.is_empty() {
        return true;
    }
    let mentions_platform = DEFAULT_PLATFORM_MARKERS
        .iter()
        .any(|marker| rel_path.contains(marker));
    if !mentions_platform {
        return true;
    }
    platforms.iter().any(|p| rel_path.contains(p.as_str()))
}
