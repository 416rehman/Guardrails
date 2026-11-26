// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Air-gap OCI-layout / POSIX tar bundle construction helpers.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use grdr_crypto::SigningKeypair;
use grdr_model::SigningKeypairExt as _;
use grdr_update::{
    AirgapArtifact, AirgapBundleEntry, AirgapBundleManifest, RolloutHaltEntry, RootKeyRole,
    RootMetadata, SignedMetadata, TufRole, TufRootKind, canonical_sha256, sign_dsse_envelope,
    sign_metadata,
};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::airgap::AirgapCliError;
use crate::fs_safe::{
    load_or_create_private_keypair, read_bounded_regular, reject_symlinks_on_existing_prefixes,
};
use crate::tar_archive::{TarEntry, validate_archive_rel_path, write_tar_file};

pub const PATH_OCI_LAYOUT: &str = "oci-layout";
pub const PATH_INDEX_JSON: &str = "index.json";
pub const PATH_MANIFEST_JSON: &str = "meta/airgap-manifest.json";
pub const PATH_MANIFEST_DSSE: &str = "meta/airgap-manifest.dsse.json";
pub const PATH_PROJECT_ROOT: &str = "meta/project-root.json";
pub const PATH_NOTICES: &str = "THIRD-PARTY-NOTICES";
pub const PATH_TERMS: &str = "terms.txt";
pub const AIRGAP_PAYLOAD_TYPE: &str = "application/vnd.grdr.airgap-manifest+json";
pub const OCI_LAYOUT_BYTES: &[u8] = br#"{"imageLayoutVersion":"1.0.0"}"#;
const MAX_PACK_FILES: usize = 256;
const MAX_PACK_FILE_BYTES: u64 = 4 * 1024 * 1024;
const SECONDS_PER_DAY: i64 = 86_400;

#[derive(Debug, Clone)]
pub struct AirgapBuildRequest<'a> {
    pub packs_dir: &'a Path,
    pub out: &'a Path,
    pub bundle_id: &'a str,
    pub version: &'a str,
    pub expires_days: i64,
    pub halted_releases: &'a [RolloutHaltEntry],
    pub key_dir: Option<&'a Path>,
    pub allow_ephemeral_dev_keys: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AirgapBuildSummary {
    pub bundle_id: String,
    pub bundle_version: String,
    pub root_fingerprint: String,
    pub manifest_sha256: String,
    pub entries_count: usize,
    pub out: String,
}

pub fn build_airgap_tar(
    req: &AirgapBuildRequest<'_>,
) -> Result<AirgapBuildSummary, AirgapCliError> {
    let packs_dir = req.packs_dir;
    let out = req.out;
    let bundle_id = req.bundle_id;
    let version = req.version;
    let expires_days = req.expires_days;
    let halted_releases = req.halted_releases;
    let key_dir = req.key_dir;
    let allow_ephemeral_dev_keys = req.allow_ephemeral_dev_keys;
    reject_symlinks_on_existing_prefixes(packs_dir)
        .map_err(|e| io_err(packs_dir, &e.to_string()))?;
    let dir_meta =
        fs::symlink_metadata(packs_dir).map_err(|e| io_err(packs_dir, &e.to_string()))?;
    if dir_meta.file_type().is_symlink() || !dir_meta.is_dir() {
        return Err(io_err(
            packs_dir,
            "packs_dir must be a real non-symlink directory",
        ));
    }

    let mut files = Vec::new();
    collect_pack_files(packs_dir, packs_dir, &mut files, 0)?;
    if files.is_empty() {
        return Err(AirgapCliError::InvalidInput(
            "no pack files found to bundle".into(),
        ));
    }
    files.extend([
        AirgapArtifact {
            path: PATH_OCI_LAYOUT.into(),
            bytes: OCI_LAYOUT_BYTES.to_vec(),
        },
        AirgapArtifact {
            path: PATH_NOTICES.into(),
            bytes: b"Guardrails ADR (Apache-2.0).\n".to_vec(),
        },
        AirgapArtifact {
            path: PATH_TERMS.into(),
            bytes: format!(
                "bundle_id={bundle_id}\nversion={version}\nlicense=Apache-2.0\nnotices={PATH_NOTICES}\n"
            )
            .into_bytes(),
        },
    ]);
    files.sort_by(|a, b| a.path.cmp(&b.path));

    let (signer_a, signer_b) = resolve_signing_pair(key_dir, allow_ephemeral_dev_keys)?;
    let now = Timestamp::now();
    let expires = Timestamp::from_second(
        now.as_second()
            .saturating_add(expires_days.max(1).saturating_mul(SECONDS_PER_DAY)),
    )
    .unwrap_or(now);

    let root_meta = build_project_root_metadata(&signer_a, &signer_b, expires)?;
    let root_fp = root_fingerprint(&root_meta.signed)?;
    let root_json = serde_json::to_vec_pretty(&root_meta).map_err(bad_input)?;

    let mut manifest_entries = Vec::with_capacity(files.len());
    let mut tar_entries = Vec::new();
    for item in &files {
        let (pack_id, pack_ver) = infer_pack_id_and_version(&item.path, version);
        manifest_entries.push(AirgapBundleEntry {
            path: item.path.clone(),
            pack_id,
            version: pack_ver,
            sha256: canonical_sha256(&item.bytes),
            length: u64::try_from(item.bytes.len()).unwrap_or(u64::MAX),
        });
        tar_entries.push(TarEntry {
            path: item.path.clone(),
            bytes: item.bytes.clone(),
        });
    }

    let manifest = AirgapBundleManifest {
        bundle_id: bundle_id.to_owned(),
        bundle_version: version.to_owned(),
        created_at: now,
        entries: manifest_entries,
        halted_releases: halted_releases.to_vec(),
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).map_err(bad_input)?;
    let manifest_sha = canonical_sha256(&manifest_bytes);
    let dsse = sign_dsse_envelope(
        AIRGAP_PAYLOAD_TYPE,
        &manifest_bytes,
        &[&signer_a, &signer_b],
    )?;
    let dsse_bytes = serde_json::to_vec_pretty(&dsse).map_err(bad_input)?;
    let index_json = serde_json::to_vec_pretty(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{
            "mediaType": AIRGAP_PAYLOAD_TYPE,
            "digest": format!("sha256:{manifest_sha}"),
            "size": manifest_bytes.len(),
            "annotations": {
                "org.guardrails.airgap.bundle_id": bundle_id,
                "org.guardrails.airgap.bundle_version": version,
                "org.guardrails.airgap.root_fingerprint": root_fp,
            }
        }]
    }))
    .map_err(bad_input)?;

    tar_entries.extend([
        TarEntry {
            path: PATH_INDEX_JSON.into(),
            bytes: index_json,
        },
        TarEntry {
            path: format!("blobs/sha256/{manifest_sha}"),
            bytes: manifest_bytes.clone(),
        },
        TarEntry {
            path: PATH_MANIFEST_JSON.into(),
            bytes: manifest_bytes,
        },
        TarEntry {
            path: PATH_MANIFEST_DSSE.into(),
            bytes: dsse_bytes,
        },
        TarEntry {
            path: PATH_PROJECT_ROOT.into(),
            bytes: root_json,
        },
    ]);
    tar_entries.sort_by(|a, b| a.path.cmp(&b.path));
    write_tar_file(out, &tar_entries).map_err(bad_input)?;

    Ok(AirgapBuildSummary {
        bundle_id: bundle_id.to_owned(),
        bundle_version: version.to_owned(),
        root_fingerprint: root_fp,
        manifest_sha256: manifest_sha,
        entries_count: files.len(),
        out: out.display().to_string(),
    })
}

pub fn root_fingerprint(root: &RootMetadata) -> Result<String, AirgapCliError> {
    Ok(format!(
        "fp_{}",
        canonical_sha256(&serde_json::to_vec(root).map_err(bad_input)?)
    ))
}

fn collect_pack_files(
    root: &Path,
    dir: &Path,
    out: &mut Vec<AirgapArtifact>,
    depth: usize,
) -> Result<(), AirgapCliError> {
    if depth > 12 {
        return Err(AirgapCliError::InvalidInput(
            "directory depth exceeded 12".into(),
        ));
    }
    let mut children: Vec<PathBuf> = fs::read_dir(dir)
        .map_err(|e| io_err(dir, &e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| io_err(dir, &e.to_string()))?
        .into_iter()
        .map(|e| e.path())
        .collect();
    children.sort();
    for path in children {
        let meta = fs::symlink_metadata(&path).map_err(|e| io_err(&path, &e.to_string()))?;
        if meta.file_type().is_symlink() {
            return Err(io_err(&path, "symlinks forbidden in packs_dir"));
        }
        if meta.is_dir() {
            collect_pack_files(root, &path, out, depth.saturating_add(1))?;
        } else if meta.is_file() {
            if out.len() >= MAX_PACK_FILES || meta.len() > MAX_PACK_FILE_BYTES {
                return Err(AirgapCliError::InvalidInput(
                    "pack file limit exceeded".into(),
                ));
            }
            let rel = path
                .strip_prefix(root)
                .map_err(|e| io_err(&path, &e.to_string()))?;
            let rel_posix = format!("packs/{}", rel.to_string_lossy().replace('\\', "/"));
            validate_archive_rel_path(&rel_posix).map_err(bad_input)?;
            let bytes = read_bounded_regular(&path, MAX_PACK_FILE_BYTES)
                .map_err(|e| io_err(&path, &e.to_string()))?;
            out.push(AirgapArtifact {
                path: rel_posix,
                bytes,
            });
        }
    }
    Ok(())
}

fn infer_pack_id_and_version(rel_path: &str, bundle_version: &str) -> (String, String) {
    if !rel_path.starts_with("packs/") {
        return ("grdr.bundle".into(), bundle_version.to_owned());
    }
    let mut parts = rel_path.split('/');
    let _ = parts.next();
    let pack_id = match parts.next() {
        Some("essentials") => "grdr.essentials".into(),
        Some("detections") => "grdr.det.core".into(),
        Some("compliance") => "grdr.compliance".into(),
        Some(other) => format!("grdr.{other}"),
        None => "grdr.bundle".into(),
    };
    (pack_id, bundle_version.to_owned())
}

fn resolve_signing_pair(
    key_dir: Option<&Path>,
    allow_ephemeral_dev_keys: bool,
) -> Result<(SigningKeypair, SigningKeypair), AirgapCliError> {
    if let Some(dir) = key_dir {
        let s1 =
            load_or_create_private_keypair(&dir.join("release-signer.key")).map_err(bad_input)?;
        let s2 = load_or_create_private_keypair(&dir.join("rebuilder.key")).map_err(bad_input)?;
        if s1.key_id() == s2.key_id() {
            return Err(AirgapCliError::InvalidInput(
                "GRDR-AIRGAP-0004: release-signer and rebuilder keys must be distinct".into(),
            ));
        }
        return Ok((s1, s2));
    }
    if !allow_ephemeral_dev_keys {
        return Err(AirgapCliError::InvalidInput(
            "GRDR-AIRGAP-0003: --key-dir is required unless --ephemeral-dev-keys is explicitly enabled".into(),
        ));
    }
    Ok((
        SigningKeypair::generate().map_err(bad_input)?,
        SigningKeypair::generate().map_err(bad_input)?,
    ))
}

fn build_project_root_metadata(
    signer_a: &SigningKeypair,
    signer_b: &SigningKeypair,
    expires: Timestamp,
) -> Result<SignedMetadata<RootMetadata>, AirgapCliError> {
    let mut keys = BTreeMap::new();
    keys.insert(signer_a.key_id().to_owned(), signer_a.public_info());
    keys.insert(signer_b.key_id().to_owned(), signer_b.public_info());
    let mut roles = BTreeMap::new();
    for role in [TufRole::Root, TufRole::Binaries, TufRole::Content] {
        roles.insert(
            role,
            RootKeyRole {
                key_ids: vec![signer_a.key_id().to_owned(), signer_b.key_id().to_owned()],
                threshold: 2,
            },
        );
    }
    for role in [TufRole::Timestamp, TufRole::Snapshot, TufRole::Targets] {
        roles.insert(
            role,
            RootKeyRole {
                key_ids: vec![signer_a.key_id().to_owned()],
                threshold: 1,
            },
        );
    }
    Ok(sign_metadata(
        RootMetadata {
            root_kind: TufRootKind::Project,
            version: 1,
            expires,
            keys,
            roles,
        },
        &[signer_a, signer_b],
    )?)
}

fn io_err(path: &Path, detail: &str) -> AirgapCliError {
    AirgapCliError::Io {
        path: path.display().to_string(),
        detail: detail.to_owned(),
    }
}

fn bad_input(err: impl ToString) -> AirgapCliError {
    AirgapCliError::InvalidInput(err.to_string())
}
