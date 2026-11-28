// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Public site TUF mirror sync and delta/content/metadata export helpers.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use clap::Args;
use grdr_update::mirror::evaluate_mirror_convergence_scoped;
use grdr_update::tuf_types::canonical_json;
use grdr_update::{
    FreshnessStatement, MirrorConvergenceReport, RootMetadata, SignedMetadata, SnapshotMetadata,
    TargetsMetadata, TimestampMetadata, TufRootKind, UpdateError, UpdateTrust, canonical_sha256,
    target_matches_platforms,
};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::airgap::AirgapCliError;
pub use crate::airgap::airgap_ceremony::{
    CeremonyKindCli, KeysCeremonyArgs, MirrorVouchArgs, run_keys_ceremony, run_mirror_vouch,
};
pub use crate::airgap::airgap_mirror_export::{MirrorExportArgs, MirrorKindCli, run_mirror_export};
use crate::fs_safe::{atomic_write_bytes, ensure_safe_dir_all, read_bounded_regular};
use crate::tar_archive::validate_archive_rel_path;

pub(crate) const MAX_MIRROR_JSON_BYTES: u64 = 16 * 1024 * 1024;
pub(crate) const MAX_MIRROR_TARGET_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Debug, Clone, Args)]
pub struct MirrorSyncArgs {
    #[arg(long)]
    pub origin_dir: PathBuf,
    #[arg(long)]
    pub mirror_dir: PathBuf,
    #[arg(long)]
    pub root: Option<PathBuf>,
    #[arg(long)]
    pub deployment_root: Option<PathBuf>,
    #[arg(long)]
    pub freshness: Option<PathBuf>,
    #[arg(long = "platform")]
    pub platforms: Vec<String>,
    #[arg(long, default_value_t = false)]
    pub all: bool,
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MirrorSyncState {
    pub etags: BTreeMap<String, String>,
    pub immutable_targets: BTreeMap<String, String>,
    pub known_snapshot_digests: BTreeSet<String>,
    #[serde(default)]
    pub snapshot_targets: BTreeMap<String, BTreeMap<String, String>>,
    pub active_snapshot_sha256: Option<String>,
    #[serde(default)]
    pub last_root_version: u64,
    #[serde(default)]
    pub last_timestamp_version: u64,
    #[serde(default)]
    pub last_snapshot_version: u64,
    #[serde(default)]
    pub last_targets_version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MirrorSyncSummary {
    pub synced_files: usize,
    pub cache_hits_immutable: usize,
    pub convergence: MirrorConvergenceReport,
    pub active_snapshot_committed: bool,
}

pub fn run_mirror_sync(args: &MirrorSyncArgs) -> Result<MirrorSyncSummary, AirgapCliError> {
    ensure_safe_dir_all(&args.mirror_dir, false)
        .map_err(|e| io_err(&args.mirror_dir, &e.to_string()))?;
    ensure_safe_dir_all(&args.mirror_dir.join("tuf"), false)
        .map_err(|e| io_err(&args.mirror_dir, &e.to_string()))?;
    ensure_safe_dir_all(&args.mirror_dir.join("targets"), false)
        .map_err(|e| io_err(&args.mirror_dir, &e.to_string()))?;

    let state_path = args.mirror_dir.join("mirror-sync-state.json");
    let mut state = load_sync_state(&state_path)?;
    let now = Timestamp::now();

    let (mut trust, active_root) = load_and_verify_mirror_root(args, &state, now)?;
    if let Some(ref dep_path) = args.deployment_root {
        let dep_root: SignedMetadata<RootMetadata> = read_json_signed(dep_path, "deployment root")?;
        trust = trust.with_deployment_root(dep_root, now)?;
    }

    let ts_path = args.origin_dir.join("tuf/timestamp.json");
    let snap_path = args.origin_dir.join("tuf/snapshot.json");
    let targets_path = args.origin_dir.join("tuf/targets.json");
    let ts_raw = read_bounded_regular(&ts_path, MAX_MIRROR_JSON_BYTES)
        .map_err(|e| io_err(&ts_path, &e.to_string()))?;
    let snap_raw = read_bounded_regular(&snap_path, MAX_MIRROR_JSON_BYTES)
        .map_err(|e| io_err(&snap_path, &e.to_string()))?;
    let targets_raw = read_bounded_regular(&targets_path, MAX_MIRROR_JSON_BYTES)
        .map_err(|e| io_err(&targets_path, &e.to_string()))?;

    let ts: SignedMetadata<TimestampMetadata> = parse_json_signed(&ts_raw, "timestamp")?;
    let snap: SignedMetadata<SnapshotMetadata> = parse_json_signed(&snap_raw, "snapshot")?;
    let targets: SignedMetadata<TargetsMetadata> = parse_json_signed(&targets_raw, "targets")?;
    let binaries: Option<SignedMetadata<TargetsMetadata>> = read_optional_json(
        &args.origin_dir.join("tuf/binaries.json"),
        "binaries metadata",
    )?;
    let freshness: Option<SignedMetadata<FreshnessStatement>> = args
        .freshness
        .as_deref()
        .map(|p| read_json_signed(p, "freshness statement"))
        .transpose()?;

    check_role_watermark(
        "project::timestamp",
        ts.signed.version,
        state.last_timestamp_version,
    )?;
    check_role_watermark(
        "project::snapshot",
        snap.signed.version,
        state.last_snapshot_version,
    )?;
    check_role_watermark(
        "project::targets",
        targets.signed.version,
        state.last_targets_version,
    )?;
    trust.verify_project_chain(
        &ts,
        &snap,
        &targets,
        binaries.as_ref(),
        freshness.as_ref(),
        now,
    )?;

    let scope: &[String] = if args.all || args.platforms.is_empty() {
        &[]
    } else {
        &args.platforms
    };
    let mut synced_files = 0usize;
    let mut cache_hits_immutable = 0usize;
    let mut missing_target: Option<String> = None;

    for (rel_path, desc) in &targets.signed.targets {
        if !target_matches_platforms(rel_path, scope) {
            continue;
        }
        validate_archive_rel_path(rel_path)
            .map_err(|e| AirgapCliError::InvalidInput(e.to_string()))?;
        let dest_path = rel_path
            .split('/')
            .fold(args.mirror_dir.join("targets"), |acc, seg| acc.join(seg));
        if state.immutable_targets.get(rel_path) == Some(&desc.sha256) && dest_path.is_file() {
            cache_hits_immutable = cache_hits_immutable.saturating_add(1);
            continue;
        }
        let origin_file = rel_path
            .split('/')
            .fold(args.origin_dir.join("targets"), |acc, seg| acc.join(seg));
        if !origin_file.is_file() {
            missing_target.get_or_insert_with(|| rel_path.clone());
            continue;
        }
        let raw = read_bounded_regular(&origin_file, MAX_MIRROR_TARGET_BYTES)
            .map_err(|e| io_err(&origin_file, &e.to_string()))?;
        let actual_len = u64::try_from(raw.len()).unwrap_or(u64::MAX);
        let actual_sha = canonical_sha256(&raw);
        if actual_len != desc.length || actual_sha != desc.sha256 {
            return Err(UpdateError::ArtifactIntegrity {
                target: rel_path.clone(),
                detail: format!(
                    "mirror target digest/size mismatch (sha={actual_sha} len={actual_len}, expected sha={} len={})",
                    desc.sha256, desc.length
                ),
            }
            .into());
        }
        atomic_write_bytes(&dest_path, &raw, false)
            .map_err(|e| io_err(&dest_path, &e.to_string()))?;
        state
            .etags
            .insert(rel_path.clone(), format!("\"{actual_sha}\""));
        state.immutable_targets.insert(rel_path.clone(), actual_sha);
        synced_files = synced_files.saturating_add(1);
    }

    if let Some(missing) = missing_target {
        save_sync_state(&state_path, &state)?;
        return Err(UpdateError::ArtifactIntegrity {
            target: missing,
            detail: "requested origin target file missing during mirror sync".into(),
        }
        .into());
    }

    let convergence =
        evaluate_mirror_convergence_scoped(&targets.signed, &state.immutable_targets, scope);
    let snap_bytes = canonical_json(&snap.signed)?;
    let snap_sha = canonical_sha256(&snap_bytes);
    let active_snapshot_committed = convergence.fully_converged;
    if active_snapshot_committed {
        let root_raw = serde_json::to_vec_pretty(&active_root)
            .map_err(|e| AirgapCliError::InvalidInput(e.to_string()))?;
        atomic_write_bytes(&args.mirror_dir.join("tuf/root.json"), &root_raw, false)
            .map_err(|e| io_err(&args.mirror_dir, &e.to_string()))?;
        atomic_write_bytes(&args.mirror_dir.join("tuf/timestamp.json"), &ts_raw, false)
            .map_err(|e| io_err(&args.mirror_dir, &e.to_string()))?;
        atomic_write_bytes(&args.mirror_dir.join("tuf/snapshot.json"), &snap_raw, false)
            .map_err(|e| io_err(&args.mirror_dir, &e.to_string()))?;
        atomic_write_bytes(
            &args.mirror_dir.join("tuf/targets.json"),
            &targets_raw,
            false,
        )
        .map_err(|e| io_err(&args.mirror_dir, &e.to_string()))?;
        let rollout_origin = args.origin_dir.join("tuf/rollout.json");
        if rollout_origin.is_file() {
            let rollout_raw = read_bounded_regular(&rollout_origin, MAX_MIRROR_JSON_BYTES)
                .map_err(|e| io_err(&rollout_origin, &e.to_string()))?;
            atomic_write_bytes(
                &args.mirror_dir.join("tuf/rollout.json"),
                &rollout_raw,
                false,
            )
            .map_err(|e| io_err(&args.mirror_dir, &e.to_string()))?;
        }
        let target_digests: BTreeMap<String, String> = targets
            .signed
            .targets
            .iter()
            .map(|(k, v)| (k.clone(), v.sha256.clone()))
            .collect();
        state.known_snapshot_digests.insert(snap_sha.clone());
        state
            .snapshot_targets
            .insert(snap_sha.clone(), target_digests);
        state.active_snapshot_sha256 = Some(snap_sha);
        state.last_root_version = active_root.signed.version;
        state.last_timestamp_version = ts.signed.version;
        state.last_snapshot_version = snap.signed.version;
        state.last_targets_version = targets.signed.version;
    }

    save_sync_state(&state_path, &state)?;

    Ok(MirrorSyncSummary {
        synced_files,
        cache_hits_immutable,
        convergence,
        active_snapshot_committed,
    })
}

fn load_and_verify_mirror_root(
    args: &MirrorSyncArgs,
    state: &MirrorSyncState,
    now: Timestamp,
) -> Result<(UpdateTrust, SignedMetadata<RootMetadata>), AirgapCliError> {
    let pinned_path = args.mirror_dir.join("tuf/root.json");
    let pinned: Option<SignedMetadata<RootMetadata>> =
        read_optional_json(&pinned_path, "pinned mirror root")?;
    let supplied: Option<SignedMetadata<RootMetadata>> = args
        .root
        .as_deref()
        .map(|p| read_json_signed(p, "supplied root"))
        .transpose()?;

    let mut active_root = match (pinned, supplied) {
        (Some(pin), Some(sup)) => {
            if sup.signed.version > pin.signed.version {
                let mut t = UpdateTrust::new(pin, now)?;
                t.rotate_root(TufRootKind::Project, sup.clone(), now)?;
                sup
            } else if sup.signed.version < pin.signed.version {
                return Err(UpdateError::RollbackDetected {
                    role: "project::root".into(),
                    found: sup.signed.version,
                    trusted: pin.signed.version,
                }
                .into());
            } else {
                ensure_same_signed_root(&pin, &sup)?;
                pin
            }
        }
        (Some(pin), None) => pin,
        (None, Some(sup)) => sup,
        (None, None) => {
            return Err(UpdateError::UnauthorizedRoot(
                "mirror sync requires --root or an already-pinned mirror tuf/root.json".into(),
            )
            .into());
        }
    };

    check_role_watermark(
        "project::root",
        active_root.signed.version,
        state.last_root_version,
    )?;
    let mut trust = UpdateTrust::new(active_root.clone(), now)?;

    let origin_root_path = args.origin_dir.join("tuf/root.json");
    if let Some(origin_root) =
        read_optional_json::<SignedMetadata<RootMetadata>>(&origin_root_path, "origin root")?
    {
        if origin_root.signed.version > active_root.signed.version {
            trust.rotate_root(TufRootKind::Project, origin_root.clone(), now)?;
            active_root = origin_root;
        } else if origin_root.signed.version < active_root.signed.version {
            return Err(UpdateError::RollbackDetected {
                role: "project::root".into(),
                found: origin_root.signed.version,
                trusted: active_root.signed.version,
            }
            .into());
        } else {
            ensure_same_signed_root(&active_root, &origin_root)?;
        }
    }
    Ok((trust, active_root))
}

fn ensure_same_signed_root(
    a: &SignedMetadata<RootMetadata>,
    b: &SignedMetadata<RootMetadata>,
) -> Result<(), AirgapCliError> {
    if canonical_sha256(&canonical_json(&a.signed)?)
        != canonical_sha256(&canonical_json(&b.signed)?)
    {
        return Err(UpdateError::UnauthorizedRoot(
            "root metadata conflicts with pinned root at identical version".into(),
        )
        .into());
    }
    Ok(())
}

fn check_role_watermark(role: &str, actual: u64, min_ver: u64) -> Result<(), AirgapCliError> {
    if actual < min_ver {
        return Err(UpdateError::RollbackDetected {
            role: role.to_owned(),
            found: actual,
            trusted: min_ver,
        }
        .into());
    }
    Ok(())
}

pub(crate) fn load_sync_state(path: &Path) -> Result<MirrorSyncState, AirgapCliError> {
    if fs::symlink_metadata(path).is_err() {
        return Ok(MirrorSyncState::default());
    }
    let raw = read_bounded_regular(path, MAX_MIRROR_JSON_BYTES)
        .map_err(|e| io_err(path, &e.to_string()))?;
    serde_json::from_slice(&raw)
        .map_err(|e| AirgapCliError::InvalidInput(format!("corrupt mirror sync state: {e}")))
}

fn save_sync_state(path: &Path, state: &MirrorSyncState) -> Result<(), AirgapCliError> {
    let bytes = serde_json::to_vec_pretty(state)
        .map_err(|e| AirgapCliError::InvalidInput(e.to_string()))?;
    atomic_write_bytes(path, &bytes, false).map_err(|e| io_err(path, &e.to_string()))
}

fn read_optional_json<T: serde::de::DeserializeOwned>(
    path: &Path,
    label: &str,
) -> Result<Option<T>, AirgapCliError> {
    if fs::symlink_metadata(path).is_err() {
        return Ok(None);
    }
    read_json_signed(path, label).map(Some)
}

fn read_json_signed<T: serde::de::DeserializeOwned>(
    path: &Path,
    label: &str,
) -> Result<T, AirgapCliError> {
    let raw = read_bounded_regular(path, MAX_MIRROR_JSON_BYTES)
        .map_err(|e| io_err(path, &e.to_string()))?;
    parse_json_signed(&raw, label)
}

pub(crate) fn parse_json_signed<T: serde::de::DeserializeOwned>(
    raw: &[u8],
    label: &str,
) -> Result<T, AirgapCliError> {
    serde_json::from_slice(raw)
        .map_err(|e| UpdateError::MalformedMetadata(format!("invalid {label} JSON: {e}")).into())
}

pub(crate) fn io_err(path: &Path, detail: &str) -> AirgapCliError {
    AirgapCliError::Io {
        path: path.display().to_string(),
        detail: detail.to_owned(),
    }
}
