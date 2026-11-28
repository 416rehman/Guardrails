// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use grdr_crypto::SigningKeypair;
use grdr_model::TrustedKeyInfo;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::UpdateError;
pub use crate::mirror::{
    MirrorConvergenceReport, MirrorExportKind, MirrorExportPlan, evaluate_mirror_convergence,
    evaluate_mirror_convergence_scoped, plan_mirror_export,
};
use crate::tuf_types::{
    FreshnessStatement, RootKeyRole, RootMetadata, SignatureAlgorithm, SignedMetadata,
    SnapshotMetadata, TufRole, TufRootKind, canonical_json, canonical_sha256, sign_metadata,
    verify_role_signatures,
};

pub const TRUSTED_ROOT_MEDIA_TYPE: &str =
    "application/vnd.dev.sigstore.trustedroot+json;version=0.1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CeremonyIdentityConfig {
    pub rekor_base_url: String,
    pub subject_issuer: String,
    pub repository_prefix: String,
    pub workflow_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CeremonyParticipant {
    pub participant_id: String,
    pub role: String,
    pub key_id: String,
    pub public_key_b64: String,
    pub algorithm: SignatureAlgorithm,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CeremonyTranscript {
    pub ceremony_id: String,
    pub root_kind: TufRootKind,
    pub root_version: u64,
    pub created_at: Timestamp,
    pub root_sha256: String,
    pub root_fingerprint: String,
    pub participants: Vec<CeremonyParticipant>,
    pub signature_key_ids: Vec<String>,
    pub redaction_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedRootLogEntry {
    pub log_id: String,
    pub base_url: String,
    pub hash_algorithm: String,
    pub public_key_b64: String,
    pub valid_from: Timestamp,
    pub valid_to: Option<Timestamp>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedRootAuthority {
    pub subject_issuer: String,
    pub repository_prefix: String,
    pub workflow_path: String,
    pub public_key_b64: String,
    pub key_id: String,
    pub valid_from: Timestamp,
    pub valid_to: Option<Timestamp>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigstoreTrustedRoot {
    pub media_type: String,
    pub tlogs: Vec<TrustedRootLogEntry>,
    pub timestamp_authorities: Vec<TrustedRootAuthority>,
    pub certificate_authorities: Vec<TrustedRootAuthority>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectCeremonyBundle {
    pub signed_root: SignedMetadata<RootMetadata>,
    pub trusted_root: SigstoreTrustedRoot,
    pub transcript: CeremonyTranscript,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentCeremonyBundle {
    pub deployment_id: String,
    pub signed_root: SignedMetadata<RootMetadata>,
    pub transcript: CeremonyTranscript,
}

impl Default for CeremonyIdentityConfig {
    fn default() -> Self {
        Self {
            rekor_base_url: "https://rekor.sigstore.dev".into(),
            subject_issuer: "https://token.actions.githubusercontent.com".into(),
            repository_prefix: "416rehman/Guardrails".into(),
            workflow_path: ".github/workflows/release.yml".into(),
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn run_project_root_ceremony(
    ceremony_id: &str,
    release_signer: &SigningKeypair,
    rebuilder: &SigningKeypair,
    operational_signer: &SigningKeypair,
    rekor_log_key: &SigningKeypair,
    tsa_key: &SigningKeypair,
    fulcio_ca_key: &SigningKeypair,
    identity: &CeremonyIdentityConfig,
    expires: Timestamp,
    now: Timestamp,
) -> Result<ProjectCeremonyBundle, UpdateError> {
    if ceremony_id.trim().is_empty() {
        return Err(UpdateError::MalformedMetadata(
            "ceremony_id cannot be empty".into(),
        ));
    }
    if release_signer.key_id() == rebuilder.key_id()
        || release_signer.public_key_bytes() == rebuilder.public_key_bytes()
    {
        return Err(UpdateError::UnauthorizedRoot(
            "project root ceremony requires distinct release_signer and rebuilder keys".into(),
        ));
    }
    if expires <= now {
        return Err(UpdateError::MetadataExpired {
            role: "project::root".into(),
            expired_at: expires.to_string(),
        });
    }

    let mut keys = BTreeMap::new();
    for kp in [release_signer, rebuilder, operational_signer] {
        keys.insert(
            kp.key_id().to_owned(),
            TrustedKeyInfo {
                key_id: kp.key_id().to_owned(),
                public_key_b64: kp.public_key_b64(),
            },
        );
    }

    let mut roles = BTreeMap::new();
    for role in [TufRole::Root, TufRole::Binaries, TufRole::Content] {
        roles.insert(
            role,
            RootKeyRole {
                key_ids: vec![
                    release_signer.key_id().to_owned(),
                    rebuilder.key_id().to_owned(),
                ],
                threshold: 2,
            },
        );
    }
    for role in [
        TufRole::Timestamp,
        TufRole::Snapshot,
        TufRole::Targets,
        TufRole::Rollout,
        TufRole::Mirror,
    ] {
        roles.insert(
            role,
            RootKeyRole {
                key_ids: vec![operational_signer.key_id().to_owned()],
                threshold: 1,
            },
        );
    }

    let root = RootMetadata {
        root_kind: TufRootKind::Project,
        version: 1,
        expires,
        keys,
        roles,
    };
    let signed_root = sign_metadata(root, &[release_signer, rebuilder])?;
    let root_bytes = canonical_json(&signed_root.signed)?;
    let root_sha256 = canonical_sha256(&root_bytes);
    let root_fingerprint = format!("fp_{root_sha256}");

    let participants = vec![
        participant_entry("release-signer", "root,binaries,content", release_signer),
        participant_entry("rebuilder", "root,binaries,content", rebuilder),
        participant_entry(
            "release-ops",
            "timestamp,snapshot,targets,rollout",
            operational_signer,
        ),
    ];

    let trusted_root = SigstoreTrustedRoot {
        media_type: TRUSTED_ROOT_MEDIA_TYPE.into(),
        tlogs: vec![TrustedRootLogEntry {
            log_id: rekor_log_key.key_id().to_owned(),
            base_url: identity.rekor_base_url.clone(),
            hash_algorithm: "sha2-256".into(),
            public_key_b64: rekor_log_key.public_key_b64(),
            valid_from: now,
            valid_to: Some(expires),
        }],
        timestamp_authorities: vec![TrustedRootAuthority {
            subject_issuer: identity.subject_issuer.clone(),
            repository_prefix: identity.repository_prefix.clone(),
            workflow_path: identity.workflow_path.clone(),
            public_key_b64: tsa_key.public_key_b64(),
            key_id: tsa_key.key_id().to_owned(),
            valid_from: now,
            valid_to: Some(expires),
        }],
        certificate_authorities: vec![TrustedRootAuthority {
            subject_issuer: identity.subject_issuer.clone(),
            repository_prefix: identity.repository_prefix.clone(),
            workflow_path: identity.workflow_path.clone(),
            public_key_b64: fulcio_ca_key.public_key_b64(),
            key_id: fulcio_ca_key.key_id().to_owned(),
            valid_from: now,
            valid_to: Some(expires),
        }],
    };

    let transcript = build_transcript(
        ceremony_id,
        now,
        root_sha256,
        root_fingerprint,
        participants,
        &signed_root,
    )?;

    Ok(ProjectCeremonyBundle {
        signed_root,
        trusted_root,
        transcript,
    })
}

pub fn run_deployment_root_ceremony(
    ceremony_id: &str,
    deployment_id: &str,
    custodians: &[&SigningKeypair],
    threshold: u32,
    expires: Timestamp,
    now: Timestamp,
) -> Result<DeploymentCeremonyBundle, UpdateError> {
    if ceremony_id.trim().is_empty() || deployment_id.trim().is_empty() {
        return Err(UpdateError::MalformedMetadata(
            "ceremony_id and deployment_id cannot be empty".into(),
        ));
    }
    let signer_count = u32::try_from(custodians.len()).unwrap_or(0);
    if threshold == 0 || threshold > signer_count {
        return Err(UpdateError::InvalidSignature(
            "deployment ceremony threshold must satisfy 1 <= threshold <= custodian count".into(),
        ));
    }
    if expires <= now {
        return Err(UpdateError::MetadataExpired {
            role: "deployment::root".into(),
            expired_at: expires.to_string(),
        });
    }

    let mut keys = BTreeMap::new();
    let mut key_ids = Vec::with_capacity(custodians.len());
    let mut participants = Vec::with_capacity(custodians.len());
    for (idx, kp) in custodians.iter().enumerate() {
        let kid = kp.key_id().to_owned();
        if keys.contains_key(&kid) {
            return Err(UpdateError::UnauthorizedRoot(format!(
                "duplicate deployment custodian key id `{kid}`"
            )));
        }
        keys.insert(
            kid.clone(),
            TrustedKeyInfo {
                key_id: kid.clone(),
                public_key_b64: kp.public_key_b64(),
            },
        );
        key_ids.push(kid);
        participants.push(participant_entry(
            &format!("custodian-{}", idx.saturating_add(1)),
            "root,fleet,targets,timestamp,snapshot",
            kp,
        ));
    }

    let mut roles = BTreeMap::new();
    for role in [
        TufRole::Root,
        TufRole::Targets,
        TufRole::Fleet,
        TufRole::Timestamp,
        TufRole::Snapshot,
    ] {
        roles.insert(
            role,
            RootKeyRole {
                key_ids: key_ids.clone(),
                threshold,
            },
        );
    }

    let root = RootMetadata {
        root_kind: TufRootKind::Deployment,
        version: 1,
        expires,
        keys,
        roles,
    };
    let signed_root = sign_metadata(root, custodians)?;
    let root_bytes = canonical_json(&signed_root.signed)?;
    let root_sha256 = canonical_sha256(&root_bytes);
    let root_fingerprint = format!("fp_{root_sha256}");

    let transcript = build_transcript(
        ceremony_id,
        now,
        root_sha256,
        root_fingerprint,
        participants,
        &signed_root,
    )?;

    Ok(DeploymentCeremonyBundle {
        deployment_id: deployment_id.to_owned(),
        signed_root,
        transcript,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn issue_freshness_vouch(
    deployment_root: &RootMetadata,
    fleet_signers: &[&SigningKeypair],
    deployment_id: &str,
    project_root_version: u64,
    project_snapshot: &SnapshotMetadata,
    imported_at: Timestamp,
    issued_at: Timestamp,
    expires: Timestamp,
) -> Result<SignedMetadata<FreshnessStatement>, UpdateError> {
    if deployment_root.root_kind != TufRootKind::Deployment {
        return Err(UpdateError::UnauthorizedRoot(
            "freshness vouch requires TufRootKind::Deployment root".into(),
        ));
    }
    if deployment_root.expires <= issued_at {
        return Err(UpdateError::MetadataExpired {
            role: "deployment::root".into(),
            expired_at: deployment_root.expires.to_string(),
        });
    }
    if expires <= issued_at {
        return Err(UpdateError::MetadataExpired {
            role: "freshness_statement".into(),
            expired_at: expires.to_string(),
        });
    }
    let snapshot_bytes = canonical_json(project_snapshot)?;
    let snapshot_sha = canonical_sha256(&snapshot_bytes);
    let stmt = FreshnessStatement {
        deployment_id: deployment_id.to_owned(),
        project_root_version,
        project_snapshot_version: project_snapshot.version,
        project_snapshot_sha256: snapshot_sha,
        imported_at,
        issued_at,
        expires,
    };
    let signed = sign_metadata(stmt, fleet_signers)?;
    verify_role_signatures(deployment_root, TufRole::Fleet, &signed)?;
    Ok(signed)
}

fn participant_entry(id: &str, role: &str, kp: &SigningKeypair) -> CeremonyParticipant {
    CeremonyParticipant {
        participant_id: id.to_owned(),
        role: role.to_owned(),
        key_id: kp.key_id().to_owned(),
        public_key_b64: kp.public_key_b64(),
        algorithm: SignatureAlgorithm::Ed25519,
    }
}

fn build_transcript(
    ceremony_id: &str,
    created_at: Timestamp,
    root_sha256: String,
    root_fingerprint: String,
    participants: Vec<CeremonyParticipant>,
    signed_root: &SignedMetadata<RootMetadata>,
) -> Result<CeremonyTranscript, UpdateError> {
    let sig_kids: Vec<String> = signed_root
        .signatures
        .iter()
        .map(|s| s.keyid.clone())
        .collect();
    let transcript = CeremonyTranscript {
        ceremony_id: ceremony_id.to_owned(),
        root_kind: signed_root.signed.root_kind,
        root_version: signed_root.signed.version,
        created_at,
        root_sha256,
        root_fingerprint,
        participants,
        signature_key_ids: sig_kids,
        redaction_verified: true,
    };
    let serialized = serde_json::to_string(&transcript).map_err(|e| {
        UpdateError::MalformedMetadata(format!("transcript serialization failed: {e}"))
    })?;
    if serialized.contains("PRIVATE KEY") || serialized.contains("seed_b64") {
        return Err(UpdateError::MalformedMetadata(
            "secret key material detected in ceremony transcript".into(),
        ));
    }
    Ok(transcript)
}
