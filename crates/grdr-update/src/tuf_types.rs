// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::{BTreeMap, BTreeSet};

use grdr_crypto::{SigningKeypair, sha256_hex, verify_bytes};
use grdr_model::TrustedKeyInfo;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::UpdateError;

pub const TUF_SIG_DOMAIN: &str = "tuf.metadata.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TufRootKind {
    Project,
    Deployment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TufRole {
    Root,
    Timestamp,
    Snapshot,
    Targets,
    Binaries,
    Content,
    Rollout,
    Fleet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerClass {
    ProjectBinaries,
    ProjectContent,
    Deployment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackKind {
    Binary,
    SchemaPolicy,
    Detection,
    Intel,
    Integration,
    Rollout,
    LayerDocument,
    AgentConfig,
    OrgCatalogue,
    OrgIntel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateFreshness {
    Current,
    Stale,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootKeyRole {
    pub key_ids: Vec<String>,
    pub threshold: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootMetadata {
    pub root_kind: TufRootKind,
    pub version: u64,
    pub expires: Timestamp,
    pub keys: BTreeMap<String, TrustedKeyInfo>,
    pub roles: BTreeMap<TufRole, RootKeyRole>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotTargetRef {
    pub version: u64,
    pub sha256: String,
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimestampMetadata {
    pub version: u64,
    pub expires: Timestamp,
    pub snapshot: SnapshotTargetRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotMetadata {
    pub version: u64,
    pub expires: Timestamp,
    pub meta: BTreeMap<TufRole, SnapshotTargetRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetDescriptor {
    pub role: TufRole,
    pub pack_kind: PackKind,
    pub signer_class: SignerClass,
    pub version: String,
    pub generation: u64,
    pub sha256: String,
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetsMetadata {
    pub role: TufRole,
    pub version: u64,
    pub expires: Timestamp,
    pub targets: BTreeMap<String, TargetDescriptor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreshnessStatement {
    pub deployment_id: String,
    pub project_root_version: u64,
    pub project_snapshot_version: u64,
    pub project_snapshot_sha256: String,
    pub imported_at: Timestamp,
    pub issued_at: Timestamp,
    pub expires: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TufSignature {
    pub keyid: String,
    pub sig: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedMetadata<T> {
    pub signed: T,
    pub signatures: Vec<TufSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreshnessEvaluation {
    pub freshness: UpdateFreshness,
    pub enforcement_active: bool,
    pub install_permitted: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustVerificationResult {
    pub root_kind: TufRootKind,
    pub freshness: UpdateFreshness,
    pub enforcement_active: bool,
    pub snapshot_version: u64,
    pub targets_version: u64,
}

#[must_use]
pub fn canonical_sha256(bytes: &[u8]) -> String {
    sha256_hex(bytes)
}

pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, UpdateError> {
    serde_json::to_vec(value).map_err(|e| {
        UpdateError::MalformedMetadata(format!("canonical JSON serialization failed: {e}"))
    })
}

pub fn sign_metadata<T: Serialize>(
    payload: T,
    signers: &[&SigningKeypair],
) -> Result<SignedMetadata<T>, UpdateError> {
    let raw = canonical_json(&payload)?;
    let mut signatures = Vec::with_capacity(signers.len());
    for signer in signers {
        signatures.push(TufSignature {
            keyid: signer.key_id().to_owned(),
            sig: signer.sign_bytes(TUF_SIG_DOMAIN, &raw),
        });
    }
    Ok(SignedMetadata {
        signed: payload,
        signatures,
    })
}

pub(crate) fn collect_role_keys(
    root: &RootMetadata,
    role: TufRole,
) -> Result<(Vec<TrustedKeyInfo>, u32), UpdateError> {
    let Some(role_def) = root.roles.get(&role) else {
        return Err(UpdateError::UnauthorizedRoot(format!(
            "role {role:?} missing from root"
        )));
    };
    let mut keys = Vec::with_capacity(role_def.key_ids.len());
    for kid in &role_def.key_ids {
        if let Some(info) = root.keys.get(kid) {
            keys.push(info.clone());
        }
    }
    Ok((keys, role_def.threshold))
}

pub(crate) fn verify_root_self(
    root: &SignedMetadata<RootMetadata>,
    now: Timestamp,
) -> Result<(), UpdateError> {
    if root.signed.expires <= now {
        return Err(UpdateError::MetadataExpired {
            role: format!("{:?}::root", root.signed.root_kind),
            expired_at: root.signed.expires.to_string(),
        });
    }
    verify_role_signatures(&root.signed, TufRole::Root, root)
}

pub(crate) fn verify_role_signatures<T: Serialize>(
    root: &RootMetadata,
    role: TufRole,
    meta: &SignedMetadata<T>,
) -> Result<(), UpdateError> {
    let Some(role_def) = root.roles.get(&role) else {
        return Err(UpdateError::UnauthorizedRoot(format!(
            "role {role:?} is not authorized by {:?} root",
            root.root_kind
        )));
    };
    if role_def.threshold == 0 {
        return Err(UpdateError::InvalidSignature(
            "TUF role threshold must be >= 1".into(),
        ));
    }

    let raw = canonical_json(&meta.signed)?;
    let mut verified_kids = BTreeSet::new();
    for entry in &meta.signatures {
        if verified_kids.contains(&entry.keyid) {
            continue;
        }
        if !role_def.key_ids.iter().any(|k| k == &entry.keyid) {
            continue;
        }
        let Some(key_info) = root.keys.get(&entry.keyid) else {
            continue;
        };
        if verify_bytes(&key_info.public_key_b64, TUF_SIG_DOMAIN, &raw, &entry.sig).is_ok() {
            verified_kids.insert(entry.keyid.clone());
        }
    }

    let count = u32::try_from(verified_kids.len()).unwrap_or(u32::MAX);
    if count < role_def.threshold {
        return Err(UpdateError::InvalidSignature(format!(
            "role {role:?} verified {count} signatures, required threshold {}",
            role_def.threshold
        )));
    }
    Ok(())
}

pub(crate) fn check_monotonic(role: &str, found: u64, trusted: u64) -> Result<(), UpdateError> {
    if found < trusted {
        return Err(UpdateError::RollbackDetected {
            role: role.to_owned(),
            found,
            trusted,
        });
    }
    Ok(())
}

pub(crate) fn verify_snapshot_link<T: Serialize>(
    snapshot: &SnapshotMetadata,
    role: TufRole,
    role_version: u64,
    role_payload: &T,
) -> Result<(), UpdateError> {
    let Some(expected) = snapshot.meta.get(&role) else {
        return Err(UpdateError::MixAndMatchDetected(format!(
            "snapshot missing reference for role {role:?}"
        )));
    };
    let bytes = canonical_json(role_payload)?;
    let actual_len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let actual_sha = canonical_sha256(&bytes);
    if expected.version != role_version
        || expected.length != actual_len
        || expected.sha256 != actual_sha
    {
        return Err(UpdateError::MixAndMatchDetected(format!(
            "snapshot reference for {role:?} mismatches payload"
        )));
    }
    Ok(())
}

pub(crate) fn enforce_root_separation(
    root_kind: TufRootKind,
    targets_role: TufRole,
    descriptor: &TargetDescriptor,
) -> Result<(), UpdateError> {
    if descriptor.pack_kind == PackKind::Binary
        || descriptor.signer_class == SignerClass::ProjectBinaries
        || descriptor.role == TufRole::Binaries
        || targets_role == TufRole::Binaries
    {
        if root_kind != TufRootKind::Project
            || descriptor.pack_kind != PackKind::Binary
            || descriptor.signer_class != SignerClass::ProjectBinaries
            || descriptor.role != TufRole::Binaries
            || targets_role != TufRole::Binaries
        {
            return Err(UpdateError::UnauthorizedRoot(
                "binaries may only be authorized by project root binaries role".into(),
            ));
        }
        return Ok(());
    }

    match root_kind {
        TufRootKind::Project => {
            let is_project_content_kind = matches!(
                descriptor.pack_kind,
                PackKind::SchemaPolicy
                    | PackKind::Detection
                    | PackKind::Intel
                    | PackKind::Integration
                    | PackKind::Rollout
            );
            let is_project_content_role = matches!(
                descriptor.role,
                TufRole::Content | TufRole::Rollout | TufRole::Targets
            );
            if descriptor.signer_class != SignerClass::ProjectContent
                || !is_project_content_kind
                || !is_project_content_role
            {
                return Err(UpdateError::UnauthorizedRoot(
                    "project root requires ProjectContent content roles and pack kinds".into(),
                ));
            }
        }
        TufRootKind::Deployment => {
            let is_deployment_role = matches!(descriptor.role, TufRole::Targets | TufRole::Fleet);
            if descriptor.signer_class != SignerClass::Deployment
                || !is_deployment_role
                || !matches!(
                    descriptor.pack_kind,
                    PackKind::LayerDocument
                        | PackKind::AgentConfig
                        | PackKind::OrgCatalogue
                        | PackKind::OrgIntel
                )
            {
                return Err(UpdateError::UnauthorizedRoot(
                    "deployment root requires Deployment Targets/Fleet role and policy/config packs"
                        .into(),
                ));
            }
        }
    }
    Ok(())
}
