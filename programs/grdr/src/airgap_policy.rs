// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Extended air-gap policies: copyleft/redistributability checks, notice/terms
//! generation, OpenVEX CVE filtering, delta/upgrade metadata, and FAT32 split parts.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use grdr_update::{
    AirgapArtifact, UpdateError, YankRecord, canonical_sha256, target_matches_platforms,
};
use serde::{Deserialize, Serialize};

use crate::airgap::AirgapCliError;
use crate::fs_safe::{
    atomic_write_bytes, read_bounded_regular, reject_symlinks_on_existing_prefixes,
};
use crate::tar_archive::validate_archive_rel_path;

pub const PATH_BUNDLE_EXTENDED: &str = "meta/bundle-extended.json";
pub const PATH_UPGRADE_PATH: &str = "meta/upgrade-path.json";
pub const PATH_RELEASE_MANIFEST: &str = "meta/release-manifest.json";
pub const PATH_TRUSTED_ROOT: &str = "meta/sigstore-trusted-root.json";
pub const PATH_ROLLOUT_JSON: &str = "meta/rollout.json";
pub const PATH_YANKS_JSON: &str = "meta/yanks.json";
pub const PATH_DEPS_LOCK: &str = "meta/dependencies.lock.json";
pub const MAX_PACK_FILES: usize = 384;
pub const MAX_ASSET_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_PART_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PARTS_COUNT: usize = 256;
const MAX_REASSEMBLED_ARCHIVE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AirgapArchiveLimits {
    pub max_part_bytes: u64,
    pub max_parts_count: usize,
    pub max_archive_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CopyleftCategory {
    Permissive,
    WeakCopyleft,
    StrongCopyleft,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockedDependency {
    pub name: String,
    pub version: String,
    pub license: String,
    pub redistributable: bool,
    pub copyleft_category: CopyleftCategory,
    pub source_tarball: Option<String>,
    pub copyright_notice: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependenciesLockFile {
    pub schema: String,
    pub dependencies: Vec<LockedDependency>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VexStatus {
    NotAffected,
    Affected,
    Fixed,
    UnderInvestigation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenVexStatement {
    pub vulnerability_id: String,
    pub product_id: String,
    pub status: VexStatus,
    pub justification: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenVexDocument {
    pub document_id: String,
    pub statements: Vec<OpenVexStatement>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VexExposureReport {
    pub suppressed_cves: Vec<String>,
    pub active_affected_cves: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtefactClass {
    Packs,
    Binaries,
    Images,
    Charts,
    AptPackages,
    RpmPackages,
    Docs,
    Terraform,
    Models,
    Sbom,
    Vex,
    Csaf,
    Sources,
    TufMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BundleTransferKind {
    Full,
    Delta {
        base_version: String,
        base_manifest_sha256: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradePathMetadata {
    pub from_version: Option<String>,
    pub to_version: String,
    pub minimum_base_version: Option<String>,
    pub requires_delta_base_sha256: Option<String>,
    pub allowed_platforms: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtendedBundleDescriptor {
    pub bundle_kind: BundleTransferKind,
    pub platforms: Vec<String>,
    pub included_classes: Vec<ArtefactClass>,
    pub yanked_releases: Vec<YankRecord>,
    pub upgrade_path: UpgradePathMetadata,
    pub notices_sha256: String,
    pub terms_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitPartRecord {
    pub index: usize,
    pub filename: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartsSplitManifest {
    pub bundle_id: String,
    pub bundle_version: String,
    pub whole_sha256: String,
    pub whole_bytes: u64,
    pub part_size_bytes: u64,
    pub parts: Vec<SplitPartRecord>,
}

impl Default for AirgapArchiveLimits {
    fn default() -> Self {
        Self {
            max_part_bytes: MAX_PART_BYTES,
            max_parts_count: MAX_PARTS_COUNT,
            max_archive_bytes: MAX_REASSEMBLED_ARCHIVE_BYTES,
        }
    }
}

pub fn validate_dependencies_and_generate_notices(
    deps_lock: &DependenciesLockFile,
    present_source_paths: &BTreeSet<String>,
    bundle_id: &str,
    version: &str,
) -> Result<(String, String), AirgapCliError> {
    let mut by_license: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for dep in &deps_lock.dependencies {
        if !dep.redistributable {
            return Err(AirgapCliError::InvalidInput(format!(
                "GRDR-AIRGAP-0002: dependency `{}@{}` ({}) is marked non-redistributable",
                dep.name, dep.version, dep.license
            )));
        }
        let needs_source = matches!(
            dep.copyleft_category,
            CopyleftCategory::WeakCopyleft | CopyleftCategory::StrongCopyleft
        );
        if needs_source {
            let Some(src_path) = dep.source_tarball.as_deref() else {
                return Err(AirgapCliError::InvalidInput(format!(
                    "GRDR-AIRGAP-0002: copyleft dependency `{}@{}` ({}) requires source tarball path",
                    dep.name, dep.version, dep.license
                )));
            };
            if !present_source_paths.contains(src_path) {
                return Err(UpdateError::ArtifactIntegrity {
                    target: src_path.to_owned(),
                    detail: format!(
                        "copyleft source archive missing for `{}@{}`",
                        dep.name, dep.version
                    ),
                }
                .into());
            }
        }
        let notice = dep.copyright_notice.as_deref().unwrap_or("");
        let line = if notice.is_empty() {
            format!("  - {} {}", dep.name, dep.version)
        } else {
            format!("  - {} {} ({})", dep.name, dep.version, notice)
        };
        by_license
            .entry(dep.license.clone())
            .or_default()
            .push(line);
    }

    let mut notices = String::from("Guardrails ADR Air-Gap Bundle Notices (Apache-2.0)\n");
    for (lic, mut items) in by_license {
        items.sort();
        notices.push_str("\n[License: ");
        notices.push_str(&lic);
        notices.push_str("]\n");
        for item in items {
            notices.push_str(&item);
            notices.push('\n');
        }
    }
    let notices_sha = canonical_sha256(notices.as_bytes());
    let terms = format!(
        "bundle_id={bundle_id}\nversion={version}\nlicense=Apache-2.0\nnotices=THIRD-PARTY-NOTICES\nnotices_sha256={notices_sha}\n"
    );
    Ok((notices, terms))
}

/// Evaluate OpenVEX vulnerability status fail-closed: any `Affected` or `UnderInvestigation` status
/// prevents suppression even if a trailing `NotAffected` or `Fixed` statement exists.
#[must_use]
pub fn evaluate_openvex_exposure(doc: &OpenVexDocument, known_cves: &[&str]) -> VexExposureReport {
    let mut suppressed = BTreeSet::new();
    let mut affected = BTreeSet::new();
    for cve in known_cves {
        let mut saw_any = false;
        let mut has_active_risk = false;
        let mut all_mitigated = true;
        for st in &doc.statements {
            if st.vulnerability_id != *cve {
                continue;
            }
            saw_any = true;
            match st.status {
                VexStatus::Affected | VexStatus::UnderInvestigation => {
                    has_active_risk = true;
                    all_mitigated = false;
                }
                VexStatus::NotAffected | VexStatus::Fixed => {}
            }
        }
        if saw_any && !has_active_risk && all_mitigated {
            suppressed.insert((*cve).to_owned());
        } else {
            affected.insert((*cve).to_owned());
        }
    }
    VexExposureReport {
        suppressed_cves: suppressed.into_iter().collect(),
        active_affected_cves: affected.into_iter().collect(),
    }
}

pub fn split_archive_to_parts(
    archive_bytes: &[u8],
    base_out_path: &Path,
    part_size_bytes: u64,
    bundle_id: &str,
    version: &str,
) -> Result<(PartsSplitManifest, PathBuf), AirgapCliError> {
    let limits = AirgapArchiveLimits::default();
    if part_size_bytes == 0 || part_size_bytes > limits.max_part_bytes {
        return Err(AirgapCliError::InvalidInput(format!(
            "split part size {part_size_bytes} must be between 1 and {}",
            limits.max_part_bytes
        )));
    }
    let chunk_usize = usize::try_from(part_size_bytes)
        .map_err(|_| AirgapCliError::InvalidInput("split part size exceeds usize".into()))?;
    let whole_sha256 = canonical_sha256(archive_bytes);
    let whole_bytes = u64::try_from(archive_bytes.len()).unwrap_or(u64::MAX);
    let parent_dir = base_out_path.parent().unwrap_or_else(|| Path::new("."));
    let stem = base_out_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("airgap-bundle.tar");

    reject_symlinks_on_existing_prefixes(base_out_path).map_err(|e| AirgapCliError::Io {
        path: base_out_path.display().to_string(),
        detail: e.to_string(),
    })?;

    let mut parts = Vec::new();
    for (idx, chunk) in archive_bytes.chunks(chunk_usize).enumerate() {
        if idx >= limits.max_parts_count {
            return Err(AirgapCliError::InvalidInput(
                "split part count exceeds MAX_PARTS_COUNT".into(),
            ));
        }
        let filename = format!("{stem}.part-{:04}", idx.saturating_add(1));
        let part_path = parent_dir.join(&filename);
        atomic_write_bytes(&part_path, chunk, false).map_err(|e| AirgapCliError::Io {
            path: part_path.display().to_string(),
            detail: e.to_string(),
        })?;
        parts.push(SplitPartRecord {
            index: idx.saturating_add(1),
            filename,
            bytes: u64::try_from(chunk.len()).unwrap_or(u64::MAX),
            sha256: canonical_sha256(chunk),
        });
    }

    let manifest = PartsSplitManifest {
        bundle_id: bundle_id.to_owned(),
        bundle_version: version.to_owned(),
        whole_sha256,
        whole_bytes,
        part_size_bytes,
        parts,
    };
    let parts_manifest_path = parent_dir.join(format!("{stem}.parts.json"));
    let json = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| AirgapCliError::InvalidInput(e.to_string()))?;
    atomic_write_bytes(&parts_manifest_path, &json, false).map_err(|e| AirgapCliError::Io {
        path: parts_manifest_path.display().to_string(),
        detail: e.to_string(),
    })?;
    Ok((manifest, parts_manifest_path))
}

pub fn reassemble_verified_parts(parts_manifest_path: &Path) -> Result<Vec<u8>, AirgapCliError> {
    let limits = AirgapArchiveLimits::default();
    let raw_manifest = read_bounded_regular(parts_manifest_path, 2 * 1024 * 1024).map_err(|e| {
        AirgapCliError::Io {
            path: parts_manifest_path.display().to_string(),
            detail: e.to_string(),
        }
    })?;
    let manifest: PartsSplitManifest = serde_json::from_slice(&raw_manifest)
        .map_err(|e| UpdateError::MalformedMetadata(format!("invalid parts manifest JSON: {e}")))?;
    if manifest.parts.is_empty() || manifest.parts.len() > limits.max_parts_count {
        return Err(UpdateError::MalformedMetadata(
            "split parts manifest has empty or excessive parts list".into(),
        )
        .into());
    }
    if manifest.whole_bytes == 0 || manifest.whole_bytes > limits.max_archive_bytes {
        return Err(UpdateError::MalformedMetadata(format!(
            "split parts whole_bytes {} exceeds safe archive bound {}",
            manifest.whole_bytes, limits.max_archive_bytes
        ))
        .into());
    }

    let mut ordered = manifest.parts.clone();
    ordered.sort_by_key(|p| p.index);
    let mut cumulative_bytes: u64 = 0;
    for (pos, part) in ordered.iter().enumerate() {
        let expected_idx = pos.saturating_add(1);
        if part.index != expected_idx {
            return Err(UpdateError::ArtifactIntegrity {
                target: part.filename.clone(),
                detail: format!(
                    "part sequence gap: expected {expected_idx}, got {}",
                    part.index
                ),
            }
            .into());
        }
        validate_part_filename(&part.filename)?;
        if part.bytes == 0 || part.bytes > limits.max_part_bytes {
            return Err(UpdateError::MalformedMetadata(format!(
                "split part `{}` size {} out of bounds",
                part.filename, part.bytes
            ))
            .into());
        }
        cumulative_bytes = cumulative_bytes.checked_add(part.bytes).ok_or_else(|| {
            UpdateError::MalformedMetadata("split part cumulative size overflow".into())
        })?;
        if cumulative_bytes > limits.max_archive_bytes || cumulative_bytes > manifest.whole_bytes {
            return Err(UpdateError::MalformedMetadata(
                "split part cumulative size exceeds declared or maximum archive cap".into(),
            )
            .into());
        }
    }
    if cumulative_bytes != manifest.whole_bytes {
        return Err(UpdateError::ArtifactIntegrity {
            target: manifest.bundle_id,
            detail: "split part sizes do not sum to manifest whole_bytes".into(),
        }
        .into());
    }

    let base_dir = parts_manifest_path
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let capacity = usize::try_from(manifest.whole_bytes)
        .map_err(|_| UpdateError::MalformedMetadata("whole_bytes exceeds usize".into()))?;
    let mut reassembled = Vec::with_capacity(capacity);
    for part in &ordered {
        let part_path = base_dir.join(&part.filename);
        let chunk =
            read_bounded_regular(&part_path, part.bytes).map_err(|e| AirgapCliError::Io {
                path: part_path.display().to_string(),
                detail: e.to_string(),
            })?;
        let actual_len = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
        if actual_len != part.bytes || canonical_sha256(&chunk) != part.sha256 {
            return Err(UpdateError::ArtifactIntegrity {
                target: part.filename.clone(),
                detail: "split part size or digest mismatch".into(),
            }
            .into());
        }
        reassembled.extend_from_slice(&chunk);
    }

    let actual_total = u64::try_from(reassembled.len()).unwrap_or(u64::MAX);
    if actual_total != manifest.whole_bytes
        || canonical_sha256(&reassembled) != manifest.whole_sha256
    {
        return Err(UpdateError::ArtifactIntegrity {
            target: manifest.bundle_id,
            detail: "reassembled archive digest mismatch".into(),
        }
        .into());
    }
    Ok(reassembled)
}

pub fn validate_real_dir(dir: &Path, label: &str) -> Result<(), AirgapCliError> {
    reject_symlinks_on_existing_prefixes(dir).map_err(|e| policy_io_err(dir, &e.to_string()))?;
    let meta = fs::symlink_metadata(dir).map_err(|e| policy_io_err(dir, &e.to_string()))?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(policy_io_err(
            dir,
            &format!("{label} must be a real non-symlink directory"),
        ));
    }
    Ok(())
}

pub fn collect_scoped_files(
    root: &Path,
    dir: &Path,
    prefix: &str,
    platforms: &[String],
    out: &mut Vec<AirgapArtifact>,
    depth: usize,
) -> Result<(), AirgapCliError> {
    if depth > 12 {
        return Err(AirgapCliError::InvalidInput(
            "directory depth exceeded 12".into(),
        ));
    }
    let mut children: Vec<PathBuf> = fs::read_dir(dir)
        .map_err(|e| policy_io_err(dir, &e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| policy_io_err(dir, &e.to_string()))?
        .into_iter()
        .map(|e| e.path())
        .collect();
    children.sort();
    for path in children {
        let meta = fs::symlink_metadata(&path).map_err(|e| policy_io_err(&path, &e.to_string()))?;
        if meta.file_type().is_symlink() {
            return Err(policy_io_err(
                &path,
                "symlinks forbidden in bundle source directories",
            ));
        }
        if meta.is_dir() {
            collect_scoped_files(root, &path, prefix, platforms, out, depth.saturating_add(1))?;
        } else if meta.is_file() {
            if out.len() >= MAX_PACK_FILES || meta.len() > MAX_ASSET_FILE_BYTES {
                return Err(AirgapCliError::InvalidInput(
                    "bundle asset count or size limit exceeded".into(),
                ));
            }
            let rel = path
                .strip_prefix(root)
                .map_err(|e| policy_io_err(&path, &e.to_string()))?;
            let rel_posix = format!("{prefix}/{}", rel.to_string_lossy().replace('\\', "/"));
            if !target_matches_platforms(&rel_posix, platforms) {
                continue;
            }
            validate_archive_rel_path(&rel_posix)
                .map_err(|e| AirgapCliError::InvalidInput(e.to_string()))?;
            let bytes = read_bounded_regular(&path, MAX_ASSET_FILE_BYTES)
                .map_err(|e| policy_io_err(&path, &e.to_string()))?;
            out.push(AirgapArtifact {
                path: rel_posix,
                bytes,
            });
        }
    }
    Ok(())
}

fn validate_part_filename(name: &str) -> Result<(), AirgapCliError> {
    if name.contains('/') {
        return Err(UpdateError::MalformedMetadata(format!(
            "split part filename `{name}` cannot include path separators"
        ))
        .into());
    }
    validate_archive_rel_path(name).map_err(|_| {
        UpdateError::MalformedMetadata(format!("unsafe split part filename `{name}`")).into()
    })
}

fn policy_io_err(path: &Path, detail: &str) -> AirgapCliError {
    AirgapCliError::Io {
        path: path.display().to_string(),
        detail: detail.to_owned(),
    }
}
