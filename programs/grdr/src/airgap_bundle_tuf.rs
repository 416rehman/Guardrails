// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Air-gap bundle TUF chain signing and fail-closed key loading helpers.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use grdr_crypto::SigningKeypair;
use grdr_model::SigningKeypairExt as _;
use grdr_update::{
    PackKind, RootKeyRole, RootMetadata, SignedMetadata, SignerClass, SnapshotMetadata,
    SnapshotTargetRef, TargetDescriptor, TargetsMetadata, TimestampMetadata, TufRole, TufRootKind,
    UpdateError, canonical_sha256, decode_ed25519_pubkey, sign_metadata,
};
use jiff::Timestamp;
use zeroize::Zeroize;

use crate::airgap::AirgapCliError;
use crate::airgap_bundle::PATH_MANIFEST_JSON;
use crate::fs_safe::{
    load_or_create_private_keypair, read_bounded_utf8, reject_symlinks_on_existing_prefixes,
};

const MAX_KEY_FILE_BYTES: u64 = 4_096;
pub type SignedTufChainJson = (Vec<u8>, Vec<u8>, Vec<u8>);

pub fn root_fingerprint(root: &RootMetadata) -> Result<String, AirgapCliError> {
    Ok(format!(
        "fp_{}",
        canonical_sha256(&serde_json::to_vec(root).map_err(bad_input)?)
    ))
}

pub fn build_signed_tuf_chain(
    ops_signer: &SigningKeypair,
    version: &str,
    manifest_sha: &str,
    manifest_bytes: &[u8],
    expires: Timestamp,
) -> Result<SignedTufChainJson, AirgapCliError> {
    let manifest_len = u64::try_from(manifest_bytes.len()).unwrap_or(u64::MAX);
    let targets = sign_metadata(
        TargetsMetadata {
            role: TufRole::Targets,
            version: 1,
            expires,
            targets: BTreeMap::from([(
                PATH_MANIFEST_JSON.into(),
                TargetDescriptor {
                    role: TufRole::Targets,
                    pack_kind: PackKind::SchemaPolicy,
                    signer_class: SignerClass::ProjectContent,
                    version: version.to_owned(),
                    generation: 1,
                    sha256: manifest_sha.to_owned(),
                    length: manifest_len,
                },
            )]),
        },
        &[ops_signer],
    )?;
    let targets_bytes = serde_json::to_vec(&targets.signed).map_err(bad_input)?;
    let snapshot = sign_metadata(
        SnapshotMetadata {
            version: 1,
            expires,
            meta: BTreeMap::from([(
                TufRole::Targets,
                SnapshotTargetRef {
                    version: 1,
                    sha256: canonical_sha256(&targets_bytes),
                    length: u64::try_from(targets_bytes.len()).unwrap_or(u64::MAX),
                },
            )]),
        },
        &[ops_signer],
    )?;
    let snap_bytes = serde_json::to_vec(&snapshot.signed).map_err(bad_input)?;
    let timestamp = sign_metadata(
        TimestampMetadata {
            version: 1,
            expires,
            snapshot: SnapshotTargetRef {
                version: 1,
                sha256: canonical_sha256(&snap_bytes),
                length: u64::try_from(snap_bytes.len()).unwrap_or(u64::MAX),
            },
        },
        &[ops_signer],
    )?;
    Ok((
        serde_json::to_vec_pretty(&timestamp).map_err(bad_input)?,
        serde_json::to_vec_pretty(&snapshot).map_err(bad_input)?,
        serde_json::to_vec_pretty(&targets).map_err(bad_input)?,
    ))
}

pub fn resolve_signing_pair(
    key_dir: Option<&Path>,
    allow_ephemeral_dev_keys: bool,
) -> Result<(SigningKeypair, SigningKeypair), AirgapCliError> {
    if let Some(dir) = key_dir {
        let p1 = dir.join("release-signer.key");
        let p2 = dir.join("rebuilder.key");
        let (s1, s2) = if allow_ephemeral_dev_keys {
            (
                load_or_create_private_keypair(&p1).map_err(bad_input)?,
                load_or_create_private_keypair(&p2).map_err(bad_input)?,
            )
        } else {
            (
                load_existing_private_keypair(&p1)?,
                load_existing_private_keypair(&p2)?,
            )
        };
        if s1.key_id() == s2.key_id() || s1.public_key_bytes() == s2.public_key_bytes() {
            return Err(AirgapCliError::InvalidInput(
                "GRDR-AIRGAP-0004: release-signer and rebuilder keys must be distinct".into(),
            ));
        }
        return Ok((s1, s2));
    }
    if !allow_ephemeral_dev_keys {
        return Err(AirgapCliError::InvalidInput(
            "GRDR-AIRGAP-0003: --key-dir with existing release-signer.key and rebuilder.key is required unless --ephemeral-dev-keys is enabled"
                .into(),
        ));
    }
    Ok((
        SigningKeypair::generate().map_err(bad_input)?,
        SigningKeypair::generate().map_err(bad_input)?,
    ))
}

pub fn load_existing_private_keypair(path: &Path) -> Result<SigningKeypair, AirgapCliError> {
    reject_symlinks_on_existing_prefixes(path).map_err(|e| io_err(path, &e.to_string()))?;
    let meta = fs::symlink_metadata(path).map_err(|e| {
        AirgapCliError::InvalidInput(format!(
            "GRDR-AIRGAP-0003: missing required existing key `{}` ({e}); run keys-ceremony or pass --ephemeral-dev-keys",
            path.display()
        ))
    })?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(io_err(
            path,
            "signing key must be a regular non-symlink file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if (meta.permissions().mode() & 0o077) != 0 {
            return Err(io_err(
                path,
                "private key permissions must restrict group/other access (0600)",
            ));
        }
    }
    let mut raw =
        read_bounded_utf8(path, MAX_KEY_FILE_BYTES).map_err(|e| io_err(path, &e.to_string()))?;
    let kp = SigningKeypair::from_seed_b64(&raw).map_err(bad_input);
    raw.zeroize();
    kp
}

pub fn build_project_root_metadata(
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
    for role in [
        TufRole::Timestamp,
        TufRole::Snapshot,
        TufRole::Targets,
        TufRole::Rollout,
    ] {
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

pub fn load_deployment_signers(
    key_dir: &Path,
    dep_root: &RootMetadata,
) -> Result<Vec<SigningKeypair>, AirgapCliError> {
    let role_def = dep_root
        .roles
        .get(&TufRole::Fleet)
        .or_else(|| dep_root.roles.get(&TufRole::Targets))
        .ok_or_else(|| {
            UpdateError::UnauthorizedRoot(
                "deployment root missing fleet and targets role definitions".into(),
            )
        })?;
    if role_def.threshold == 0 {
        return Err(
            UpdateError::UnauthorizedRoot("deployment role threshold must be >= 1".into()).into(),
        );
    }
    let mut candidates = vec![key_dir.join("deployment-fleet.key")];
    for idx in 1..=8 {
        candidates.push(key_dir.join(format!("custodian-{idx}.key")));
    }
    let mut signers = Vec::new();
    let mut seen_pubkeys: BTreeSet<[u8; 32]> = BTreeSet::new();
    for path in candidates {
        if fs::symlink_metadata(&path).is_err() {
            continue;
        }
        let kp = load_existing_private_keypair(&path)?;
        if !role_def.key_ids.iter().any(|k| k == kp.key_id()) {
            continue;
        }
        let Ok(pk_info) = dep_root
            .keys
            .get(kp.key_id())
            .ok_or(())
            .and_then(|info| decode_ed25519_pubkey(&info.public_key_b64).map_err(|_| ()))
        else {
            continue;
        };
        if pk_info != kp.public_key_bytes() {
            continue;
        }
        if seen_pubkeys.insert(kp.public_key_bytes()) {
            signers.push(kp);
        }
    }
    if u32::try_from(signers.len()).unwrap_or(u32::MAX) < role_def.threshold {
        return Err(AirgapCliError::InvalidInput(format!(
            "GRDR-AIRGAP-0003: found {} authorized deployment key(s) in `{}` but threshold requires {}",
            signers.len(),
            key_dir.display(),
            role_def.threshold
        )));
    }
    Ok(signers)
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
