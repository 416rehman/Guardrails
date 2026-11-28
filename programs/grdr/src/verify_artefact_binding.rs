// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! TUF chain/watermark binding, signed release-manifest checks, and signed platform attestation checks.

use std::path::Path;

use grdr_crypto::constant_time_eq;
use grdr_model::TrustedKeyInfo;
use grdr_update::{
    DsseEnvelope, DsseLimits, FreshnessStatement, RootMetadata, SignedMetadata,
    SigstoreTrustedRoot, SnapshotMetadata, TargetsMetadata, TimestampMetadata, TufRole,
    TufRootKind, UpdateError, UpdateTrust, verify_dsse_envelope_with_limits,
};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::airgap::AirgapCliError;
pub use crate::airgap::verify_artefact_manifest::verify_release_manifest_binding;
use crate::airgap::verify_artefact_sigstore::{VerifyArtefactPolicy, repo_matches_prefix};
use crate::airgap::verify_artefact_types::{
    PLATFORM_SIG_PAYLOAD_TYPE, PlatformSignaturePayload, PlatformSignatureStatus,
    SignedPlatformSignatureAttestation,
};
use crate::fs_safe::{atomic_write_bytes, ensure_safe_dir_all, read_bounded_regular};

pub const MAX_META_JSON_BYTES: u64 = 8 * 1024 * 1024;
const WATERMARK_FILE: &str = "verify-artefact-watermarks.json";

#[derive(Debug, Clone, Default)]
pub struct VerifyArtefactTufInputs<'a> {
    pub tuf_root: Option<&'a Path>,
    pub tuf_timestamp: Option<&'a Path>,
    pub tuf_snapshot: Option<&'a Path>,
    pub tuf_targets: Option<&'a Path>,
    pub deployment_root: Option<&'a Path>,
    pub tuf_freshness: Option<&'a Path>,
    pub tuf_state_dir: Option<&'a Path>,
    pub release_manifest_dsse: Option<&'a Path>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ArtefactTufWatermarks {
    root_version: u64,
    timestamp_version: u64,
    snapshot_version: u64,
    targets_version: u64,
}

pub fn verify_tuf_targets_chain(
    targets_path: &Path,
    tuf: &VerifyArtefactTufInputs<'_>,
    artefact_bytes: &[u8],
    artefact_sha256: &str,
    now: Timestamp,
) -> Result<SignedMetadata<TargetsMetadata>, AirgapCliError> {
    let (Some(root_path), Some(ts_path), Some(snap_path)) =
        (tuf.tuf_root, tuf.tuf_timestamp, tuf.tuf_snapshot)
    else {
        return Err(UpdateError::UnauthorizedRoot(
            "--tuf-targets requires --tuf-root, --tuf-timestamp, and --tuf-snapshot".into(),
        )
        .into());
    };
    let root_meta: SignedMetadata<RootMetadata> = read_json_meta(root_path, "TUF root")?;
    let ts_meta: SignedMetadata<TimestampMetadata> = read_json_meta(ts_path, "TUF timestamp")?;
    let snap_meta: SignedMetadata<SnapshotMetadata> = read_json_meta(snap_path, "TUF snapshot")?;
    let targets_meta: SignedMetadata<TargetsMetadata> =
        read_json_meta(targets_path, "TUF targets")?;
    let dep_root = tuf
        .deployment_root
        .map(|p| read_json_meta::<SignedMetadata<RootMetadata>>(p, "deployment root"))
        .transpose()?;
    let freshness = tuf
        .tuf_freshness
        .map(|p| read_json_meta::<SignedMetadata<FreshnessStatement>>(p, "freshness statement"))
        .transpose()?;

    if let Some(state_dir) = tuf.tuf_state_dir {
        let wm = load_watermarks(state_dir)?;
        check_watermarks(&wm, &root_meta, &ts_meta, &snap_meta, &targets_meta)?;
    }

    let mut trust = UpdateTrust::new(root_meta.clone(), now)?;
    if let Some(dep) = dep_root {
        trust = trust.with_deployment_root(dep, now)?;
    }
    if targets_meta.signed.role == TufRole::Targets {
        trust.verify_project_chain(
            &ts_meta,
            &snap_meta,
            &targets_meta,
            None,
            freshness.as_ref(),
            now,
        )?;
    } else {
        trust.verify_project_timestamp_snapshot(&ts_meta, &snap_meta, freshness.as_ref(), now)?;
    }
    let matched_path = targets_meta
        .signed
        .targets
        .iter()
        .find(|(_, d)| d.sha256 == artefact_sha256)
        .map(|(p, _)| p.clone())
        .ok_or_else(|| {
            UpdateError::TargetNotFound(format!(
                "sha256:{artefact_sha256} not found in TUF targets"
            ))
        })?;
    trust.verify_target_artifact(
        TufRootKind::Project,
        &snap_meta,
        &targets_meta,
        freshness.as_ref(),
        &matched_path,
        artefact_bytes,
        None,
        now,
    )?;

    if let Some(state_dir) = tuf.tuf_state_dir {
        persist_watermarks(state_dir, &root_meta, &ts_meta, &snap_meta, &targets_meta)?;
    }
    Ok(targets_meta)
}

pub fn resolve_platform_sig_status(
    platform_sig_path: Option<&Path>,
    artefact_sha256: &str,
    trusted_root: &SigstoreTrustedRoot,
    verified_tuf_root: Option<&SignedMetadata<RootMetadata>>,
    policy: &VerifyArtefactPolicy<'_>,
    now: Timestamp,
) -> Result<PlatformSignatureStatus, AirgapCliError> {
    let Some(path) = platform_sig_path else {
        return Ok(PlatformSignatureStatus::NotPlatformSigned);
    };
    let signed: SignedPlatformSignatureAttestation =
        read_json_meta(path, "platform signature attestation")?;
    if signed.dsse_envelope.payload_type != PLATFORM_SIG_PAYLOAD_TYPE {
        return Err(UpdateError::MalformedMetadata(format!(
            "unexpected platform attestation payloadType `{}`",
            signed.dsse_envelope.payload_type
        ))
        .into());
    }

    let mut ca_expired: Option<AirgapCliError> = None;
    let ca_keys: Vec<TrustedKeyInfo> = trusted_root
        .certificate_authorities
        .iter()
        .map(|ca| TrustedKeyInfo {
            key_id: ca.key_id.clone(),
            public_key_b64: ca.public_key_b64.clone(),
        })
        .collect();
    if !ca_keys.is_empty()
        && let Ok(payload_bytes) = verify_dsse_envelope_with_limits(
            &signed.dsse_envelope,
            &ca_keys,
            1,
            &DsseLimits::default(),
        )
    {
        let payload =
            parse_and_check_platform_payload(&payload_bytes, path, artefact_sha256, policy)?;
        match verify_ca_authority_window(&signed.dsse_envelope, &payload, trusted_root) {
            Ok(()) => return Ok(payload.status),
            Err(err @ AirgapCliError::Update(UpdateError::MetadataExpired { .. })) => {
                ca_expired = Some(err);
            }
            Err(_) => {}
        }
    }

    if let Some(tuf_root) = verified_tuf_root {
        let trust = UpdateTrust::new(tuf_root.clone(), now)?;
        let (bin_keys, bin_threshold) = trust.project_binaries_role_keys()?;
        if bin_threshold == 0
            || bin_keys.len() < usize::try_from(bin_threshold).unwrap_or(usize::MAX)
        {
            return Err(UpdateError::UnauthorizedRoot(
                "TUF Binaries role lacks sufficient keys for platform signature threshold".into(),
            )
            .into());
        }
        match verify_dsse_envelope_with_limits(
            &signed.dsse_envelope,
            &bin_keys,
            bin_threshold,
            &DsseLimits::default(),
        ) {
            Ok(payload_bytes) => {
                let payload = parse_and_check_platform_payload(
                    &payload_bytes,
                    path,
                    artefact_sha256,
                    policy,
                )?;
                if payload.verified_at > tuf_root.signed.expires {
                    return Err(UpdateError::MetadataExpired {
                        role: "platform-signature-authority".into(),
                        expired_at: tuf_root.signed.expires.to_string(),
                    }
                    .into());
                }
                return Ok(payload.status);
            }
            Err(err) => {
                return Err(ca_expired.unwrap_or_else(|| err.into()));
            }
        }
    }

    if let Some(err) = ca_expired {
        return Err(err);
    }
    Err(UpdateError::UnauthorizedRoot(
        "platform signature attestation did not meet trusted CA or TUF Binaries quorum".into(),
    )
    .into())
}

fn parse_and_check_platform_payload(
    payload_bytes: &[u8],
    path: &Path,
    artefact_sha256: &str,
    policy: &VerifyArtefactPolicy<'_>,
) -> Result<PlatformSignaturePayload, AirgapCliError> {
    let payload: PlatformSignaturePayload = serde_json::from_slice(payload_bytes).map_err(|e| {
        UpdateError::MalformedMetadata(format!("invalid platform signature payload JSON: {e}"))
    })?;
    if !constant_time_eq(
        payload.artefact_sha256.as_bytes(),
        artefact_sha256.as_bytes(),
    ) {
        return Err(UpdateError::ArtifactIntegrity {
            target: path.display().to_string(),
            detail: "platform signature attestation bound to different artefact sha256".into(),
        }
        .into());
    }
    if payload.issuer != policy.expected_issuer
        || payload.signer_subject != policy.expected_repository
    {
        return Err(UpdateError::UnauthorizedRoot(
            "platform signature attestation publisher identity fails policy".into(),
        )
        .into());
    }
    Ok(payload)
}

fn verify_ca_authority_window(
    env: &DsseEnvelope,
    payload: &PlatformSignaturePayload,
    trusted_root: &SigstoreTrustedRoot,
) -> Result<(), AirgapCliError> {
    let mut expired_match: Option<Timestamp> = None;
    for sig in &env.signatures {
        let single_env = DsseEnvelope {
            payload_type: env.payload_type.clone(),
            payload: env.payload.clone(),
            signatures: vec![sig.clone()],
        };
        for ca in trusted_root
            .certificate_authorities
            .iter()
            .filter(|ca| ca.key_id == sig.keyid)
        {
            if !ca.subject_issuer.is_empty() && payload.issuer != ca.subject_issuer {
                continue;
            }
            if !ca.repository_prefix.is_empty()
                && !repo_matches_prefix(&payload.signer_subject, &ca.repository_prefix)
            {
                continue;
            }
            let key = [TrustedKeyInfo {
                key_id: ca.key_id.clone(),
                public_key_b64: ca.public_key_b64.clone(),
            }];
            if verify_dsse_envelope_with_limits(&single_env, &key, 1, &DsseLimits::default())
                .is_ok()
            {
                let in_window = payload.verified_at >= ca.valid_from
                    && ca.valid_to.is_none_or(|to| payload.verified_at <= to);
                if in_window {
                    return Ok(());
                }
                expired_match = ca.valid_to.or(Some(ca.valid_from));
            }
        }
    }
    if let Some(expired_at) = expired_match {
        return Err(UpdateError::MetadataExpired {
            role: "platform-signature-authority".into(),
            expired_at: expired_at.to_string(),
        }
        .into());
    }
    Err(UpdateError::UnauthorizedRoot(
        "platform signature attestation did not verify within an authorized CA constraint".into(),
    )
    .into())
}

pub fn read_file_bounded(path: &Path, max: u64) -> Result<Vec<u8>, AirgapCliError> {
    read_bounded_regular(path, max).map_err(|e| AirgapCliError::Io {
        path: path.display().to_string(),
        detail: e.to_string(),
    })
}

pub fn read_json_meta<T: for<'de> Deserialize<'de>>(
    path: &Path,
    label: &str,
) -> Result<T, AirgapCliError> {
    let raw = read_file_bounded(path, MAX_META_JSON_BYTES)?;
    serde_json::from_slice(&raw)
        .map_err(|e| UpdateError::MalformedMetadata(format!("invalid {label}: {e}")).into())
}

fn load_watermarks(state_dir: &Path) -> Result<ArtefactTufWatermarks, AirgapCliError> {
    let p = state_dir.join(WATERMARK_FILE);
    if std::fs::symlink_metadata(&p).is_err() {
        return Ok(ArtefactTufWatermarks::default());
    }
    read_json_meta(&p, "TUF artefact watermarks")
}

fn check_watermarks(
    wm: &ArtefactTufWatermarks,
    root: &SignedMetadata<RootMetadata>,
    ts: &SignedMetadata<TimestampMetadata>,
    snap: &SignedMetadata<SnapshotMetadata>,
    targets: &SignedMetadata<TargetsMetadata>,
) -> Result<(), UpdateError> {
    let checks = [
        ("root", root.signed.version, wm.root_version),
        ("timestamp", ts.signed.version, wm.timestamp_version),
        ("snapshot", snap.signed.version, wm.snapshot_version),
        ("targets", targets.signed.version, wm.targets_version),
    ];
    for (role, found, trusted) in checks {
        if found < trusted {
            return Err(UpdateError::RollbackDetected {
                role: role.to_owned(),
                found,
                trusted,
            });
        }
    }
    Ok(())
}

fn persist_watermarks(
    state_dir: &Path,
    root: &SignedMetadata<RootMetadata>,
    ts: &SignedMetadata<TimestampMetadata>,
    snap: &SignedMetadata<SnapshotMetadata>,
    targets: &SignedMetadata<TargetsMetadata>,
) -> Result<(), AirgapCliError> {
    ensure_safe_dir_all(state_dir, false).map_err(|e| AirgapCliError::Io {
        path: state_dir.display().to_string(),
        detail: e.to_string(),
    })?;
    let wm = ArtefactTufWatermarks {
        root_version: root.signed.version,
        timestamp_version: ts.signed.version,
        snapshot_version: snap.signed.version,
        targets_version: targets.signed.version,
    };
    let bytes =
        serde_json::to_vec_pretty(&wm).map_err(|e| AirgapCliError::InvalidInput(e.to_string()))?;
    atomic_write_bytes(&state_dir.join(WATERMARK_FILE), &bytes, false).map_err(|e| {
        AirgapCliError::Io {
            path: state_dir.display().to_string(),
            detail: e.to_string(),
        }
    })
}
