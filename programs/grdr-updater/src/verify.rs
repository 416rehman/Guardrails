// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Dual-root TUF + DSSE verification, signed artifact typestate witness, CDN lag
//! gating, and compatibility range verification (`D-22`, `D-36`, `D-37`, `D-71`).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use grdr_compat::{CompatMatrix, ProtocolCapability, SemVer};
use grdr_crypto::SigningKeypair;
use grdr_model::api::TrustedKeyInfo;
use grdr_os_clock::Clock;
use grdr_update::{
    DsseEnvelope, DsseLimits, FreshnessStatement, PackKind, RootMetadata, SignedMetadata,
    SnapshotMetadata, TargetsMetadata, TimestampMetadata, TufRole, TufRootKind, UpdateTrust,
    canonical_sha256,
};

use crate::dsse_guard::{decode_ed25519_pubkey_b64_strict, verify_dsse_envelope_strict};
use crate::error::UpdaterError;
use crate::p7_delta::{
    SignedPackCompatHeader, enforce_p7_json_purity, max_bytes_for_pack, validate_safe_target_path,
};
use crate::tuf_journal::{
    TufJournalState, check_persisted_versions, load_or_init_tuf_state, persist_tuf_journal,
    record_persisted_versions, verify_freshness_statement_strict,
};

pub use crate::p7_delta::{ComponentVersionCheck, check_bundle_compatibility};

/// Maximum allowed CDN replication lag tolerance before refusing stale manifests (24 hours).
pub const DEFAULT_MAX_CDN_LAG_S: i64 = 86_400;

const DEFAULT_HOST_CAPABILITIES: [ProtocolCapability; 6] = [
    ProtocolCapability::McpToolPinning,
    ProtocolCapability::SignedReceipts,
    ProtocolCapability::SessionLabels,
    ProtocolCapability::FastpathFloor,
    ProtocolCapability::Ocsf19Export,
    ProtocolCapability::StepUpApproval,
];

/// CDN replication freshness classification relative to trusted clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CdnFreshnessStatus {
    Current,
    ToleratedCdnLag { lag_s: i64 },
}

/// Cryptographically verified update artifact witness produced strictly by [`DualRootVerifier::verify_bundle`].
///
/// Private fields guarantee downstream slot activation cannot substitute unverified bytes or metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedUpdateArtifact {
    root_kind: TufRootKind,
    pack_kind: PackKind,
    channel: String,
    target_path: String,
    version: String,
    generation: u64,
    sha256: String,
    verified_bytes: Vec<u8>,
    cdn_status: CdnFreshnessStatus,
}

/// Bundle passed to [`DualRootVerifier::verify_bundle`] prior to A/B slot activation.
pub struct StagedUpdateBundle<'a> {
    pub root_kind: TufRootKind,
    pub pack_kind: PackKind,
    pub channel: &'a str,
    pub target_path: &'a str,
    pub component_name: &'a str,
    pub snapshot_published_unix_s: i64,
    pub artifact_bytes: &'a [u8],
    pub timestamp: &'a SignedMetadata<TimestampMetadata>,
    pub snapshot: &'a SignedMetadata<SnapshotMetadata>,
    pub targets: &'a SignedMetadata<TargetsMetadata>,
    pub binaries_targets: Option<&'a SignedMetadata<TargetsMetadata>>,
    pub freshness: Option<&'a SignedMetadata<FreshnessStatement>>,
    pub dsse_envelope: &'a DsseEnvelope,
    pub compat_matrix: &'a CompatMatrix,
}

struct VerifierPersistence {
    state_root: PathBuf,
    signer: SigningKeypair,
    state: TufJournalState,
}

/// Dual-root TUF + DSSE + compatibility gate verifier (`ARCH-004`).
pub struct DualRootVerifier {
    trust: UpdateTrust,
    project_root: RootMetadata,
    deployment_root: Option<RootMetadata>,
    max_cdn_lag_s: i64,
    dsse_limits: DsseLimits,
    host_capabilities: Vec<ProtocolCapability>,
    persistence: Option<VerifierPersistence>,
}

impl VerifiedUpdateArtifact {
    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn pack_kind(&self) -> PackKind {
        self.pack_kind
    }

    #[must_use]
    pub const fn root_kind(&self) -> TufRootKind {
        self.root_kind
    }

    #[must_use]
    pub fn channel(&self) -> &str {
        &self.channel
    }

    #[must_use]
    pub fn target_path(&self) -> &str {
        &self.target_path
    }

    #[must_use]
    pub fn verified_bytes(&self) -> &[u8] {
        &self.verified_bytes
    }

    #[must_use]
    pub const fn cdn_status(&self) -> CdnFreshnessStatus {
        self.cdn_status
    }
}

impl DualRootVerifier {
    /// Construct a verifier rooted at pinned `Project` root (and optional `Deployment` root).
    pub fn new(
        project_root: SignedMetadata<RootMetadata>,
        deployment_root: Option<SignedMetadata<RootMetadata>>,
        clock: &dyn Clock,
    ) -> Result<Self, UpdaterError> {
        let now = clock.now_wall().map_err(|e| UpdaterError::ClockFailed {
            detail: e.to_string(),
        })?;
        Self::with_timestamp(project_root, deployment_root, now)
    }

    /// Construct and persist TUF root + monotonic metadata version watermarks under `state_root`.
    pub fn open_or_init(
        state_root: &Path,
        signer: &SigningKeypair,
        project_root: SignedMetadata<RootMetadata>,
        deployment_root: Option<SignedMetadata<RootMetadata>>,
        clock: &dyn Clock,
    ) -> Result<Self, UpdaterError> {
        let now = clock.now_wall().map_err(|e| UpdaterError::ClockFailed {
            detail: e.to_string(),
        })?;
        let state = load_or_init_tuf_state(state_root, signer, project_root, deployment_root)?;
        let mut verifier = Self::with_timestamp(
            state.project_root.clone(),
            state.deployment_root.clone(),
            now,
        )?;
        verifier.persistence = Some(VerifierPersistence {
            state_root: state_root.to_path_buf(),
            signer: signer.clone(),
            state,
        });
        Ok(verifier)
    }

    /// Construct deterministically at explicit `jiff::Timestamp`.
    pub fn with_timestamp(
        project_root: SignedMetadata<RootMetadata>,
        deployment_root: Option<SignedMetadata<RootMetadata>>,
        now: jiff::Timestamp,
    ) -> Result<Self, UpdaterError> {
        let project_meta = project_root.signed.clone();
        let dep_meta = deployment_root.as_ref().map(|d| d.signed.clone());
        let mut trust =
            UpdateTrust::new(project_root, now).map_err(|e| UpdaterError::TufVerification {
                detail: e.to_string(),
            })?;
        if let Some(dep_root) = deployment_root {
            trust = trust.with_deployment_root(dep_root, now).map_err(|e| {
                UpdaterError::TufVerification {
                    detail: e.to_string(),
                }
            })?;
        }
        Ok(Self {
            trust,
            project_root: project_meta,
            deployment_root: dep_meta,
            max_cdn_lag_s: DEFAULT_MAX_CDN_LAG_S,
            dsse_limits: DsseLimits::default(),
            host_capabilities: DEFAULT_HOST_CAPABILITIES.to_vec(),
            persistence: None,
        })
    }

    /// Restrict supported host capabilities used during `D-71` compatibility negotiation.
    #[must_use]
    pub fn with_host_capabilities(mut self, host_capabilities: Vec<ProtocolCapability>) -> Self {
        self.host_capabilities = host_capabilities;
        self
    }

    /// Configure strict DSSE decode bounds enforced before TUF target payload parsing.
    #[must_use]
    pub fn with_dsse_limits(mut self, dsse_limits: DsseLimits) -> Self {
        self.dsse_limits = dsse_limits;
        self
    }

    /// Perform TUF root/chain rotation cleanly via `UpdateTrust`, persisting signed state if enabled.
    pub fn rotate_root(
        &mut self,
        kind: TufRootKind,
        next_root: SignedMetadata<RootMetadata>,
        now: jiff::Timestamp,
    ) -> Result<(), UpdaterError> {
        let next_meta = next_root.signed.clone();
        self.trust
            .rotate_root(kind, next_root.clone(), now)
            .map_err(|e| UpdaterError::TufVerification {
                detail: e.to_string(),
            })?;
        match kind {
            TufRootKind::Project => self.project_root = next_meta,
            TufRootKind::Deployment => self.deployment_root = Some(next_meta),
        }
        if let Some(pers) = &mut self.persistence {
            match kind {
                TufRootKind::Project => pers.state.project_root = next_root,
                TufRootKind::Deployment => pers.state.deployment_root = Some(next_root),
            }
            persist_tuf_journal(&pers.state_root, &pers.signer, &pers.state)?;
        }
        Ok(())
    }

    /// Verify CDN freshness, dual-root authority, DSSE limits + TUF, P7 purity, and compatibility.
    pub fn verify_bundle(
        &mut self,
        bundle: &StagedUpdateBundle<'_>,
        now: jiff::Timestamp,
    ) -> Result<VerifiedUpdateArtifact, UpdaterError> {
        validate_safe_target_path(bundle.target_path)?;
        if bundle.component_name.trim().is_empty() {
            return Err(UpdaterError::CompatibilityRejected {
                component: String::new(),
                code: "GRDR-COMPAT-0003".to_string(),
                reason: "bundle component_name cannot be empty".to_string(),
            });
        }
        enforce_pack_authority(bundle.root_kind, bundle.pack_kind)?;

        let max_bytes = max_bytes_for_pack(bundle.pack_kind);
        let actual_bytes = u64::try_from(bundle.artifact_bytes.len()).unwrap_or(u64::MAX);
        if actual_bytes > max_bytes {
            return Err(UpdaterError::BudgetExceeded {
                channel: bundle.channel.to_string(),
                actual_bytes,
                max_bytes,
            });
        }

        if let Some(pers) = &self.persistence {
            check_persisted_versions(
                &pers.state,
                bundle.root_kind,
                bundle.timestamp.signed.version,
                bundle.snapshot.signed.version,
                bundle.targets.signed.version,
                bundle.binaries_targets.as_ref().map(|b| b.signed.version),
            )?;
        }

        match bundle.root_kind {
            TufRootKind::Project => {
                self.trust
                    .verify_project_chain(
                        bundle.timestamp,
                        bundle.snapshot,
                        bundle.targets,
                        bundle.binaries_targets,
                        bundle.freshness,
                        now,
                    )
                    .map_err(|e| UpdaterError::TufVerification {
                        detail: e.to_string(),
                    })?;
            }
            TufRootKind::Deployment => {
                self.trust
                    .verify_deployment_chain(bundle.timestamp, bundle.snapshot, bundle.targets, now)
                    .map_err(|e| UpdaterError::TufVerification {
                        detail: e.to_string(),
                    })?;
            }
        }

        let effective_published_s = if let Some(freshness) = bundle.freshness {
            let dep_root =
                self.deployment_root
                    .as_ref()
                    .ok_or_else(|| UpdaterError::TufVerification {
                        detail: "FreshnessStatement requires pinned deployment root".to_string(),
                    })?;
            verify_freshness_statement_strict(
                dep_root,
                freshness,
                &bundle.snapshot.signed,
                self.project_root.version,
                now,
            )?;
            let signed_s = freshness.signed.issued_at.as_second();
            if signed_s.abs_diff(bundle.snapshot_published_unix_s) > 300 {
                return Err(UpdaterError::StaleOrRollback {
                    detail: "snapshot_published_unix_s disagrees with signed FreshnessStatement"
                        .to_string(),
                });
            }
            signed_s
        } else {
            bundle.snapshot_published_unix_s
        };

        if effective_published_s > bundle.snapshot.signed.expires.as_second()
            || effective_published_s > bundle.timestamp.signed.expires.as_second()
        {
            return Err(UpdaterError::StaleOrRollback {
                detail: "snapshot published timestamp exceeds signed snapshot/timestamp expiration"
                    .to_string(),
            });
        }
        let cdn_status = self.assess_cdn_lag(effective_published_s, now.as_second())?;

        let target_meta = if bundle.pack_kind == PackKind::Binary {
            bundle
                .binaries_targets
                .ok_or_else(|| UpdaterError::TufVerification {
                    detail: "PackKind::Binary requires mandatory TufRole::Binaries metadata"
                        .to_string(),
                })?
        } else {
            bundle.targets
        };

        let target_descriptor = target_meta
            .signed
            .targets
            .get(bundle.target_path)
            .ok_or_else(|| UpdaterError::TufVerification {
                detail: format!(
                    "target path '{}' missing from TUF metadata",
                    bundle.target_path
                ),
            })?;
        let (trusted_keys, threshold) =
            self.trusted_keys_for_role(bundle.root_kind, target_descriptor.role)?;
        verify_dsse_envelope_strict(
            bundle.dsse_envelope,
            bundle.pack_kind,
            &trusted_keys,
            threshold,
            &self.dsse_limits,
        )?;

        let verified_target = self
            .trust
            .verify_target_artifact(
                bundle.root_kind,
                target_meta,
                bundle.target_path,
                bundle.artifact_bytes,
                Some(bundle.dsse_envelope),
            )
            .map_err(|e| UpdaterError::TufVerification {
                detail: e.to_string(),
            })?;

        let parsed_target_ver = SemVer::parse(&verified_target.version).map_err(|e| {
            UpdaterError::CompatibilityRejected {
                component: bundle.component_name.to_string(),
                code: "GRDR-UPDATER-0002".to_string(),
                reason: format!("invalid signed TUF target version: {e}"),
            }
        })?;

        if bundle.pack_kind == PackKind::Binary {
            let specs = [ComponentVersionCheck {
                component: bundle.component_name.to_string(),
                version: parsed_target_ver,
            }];
            check_bundle_compatibility(bundle.compat_matrix, &specs, &[], &self.host_capabilities)?;
        } else {
            enforce_p7_json_purity(bundle.channel, bundle.artifact_bytes)?;
            let signed_compat: SignedPackCompatHeader =
                serde_json::from_slice(bundle.artifact_bytes).map_err(|e| {
                    UpdaterError::TufVerification {
                        detail: format!("failed to inspect signed pack compat header: {e}"),
                    }
                })?;
            let mut specs = signed_compat.components;
            specs.push(ComponentVersionCheck {
                component: bundle.component_name.to_string(),
                version: parsed_target_ver,
            });
            check_bundle_compatibility(
                bundle.compat_matrix,
                &specs,
                &signed_compat.required_capabilities,
                &self.host_capabilities,
            )?;
        }

        if let Some(pers) = &mut self.persistence {
            record_persisted_versions(
                &mut pers.state,
                bundle.root_kind,
                bundle.timestamp.signed.version,
                bundle.snapshot.signed.version,
                bundle.targets.signed.version,
                bundle.binaries_targets.as_ref().map(|b| b.signed.version),
            );
            persist_tuf_journal(&pers.state_root, &pers.signer, &pers.state)?;
        }

        Ok(VerifiedUpdateArtifact {
            root_kind: bundle.root_kind,
            pack_kind: bundle.pack_kind,
            channel: bundle.channel.to_string(),
            target_path: bundle.target_path.to_string(),
            version: verified_target.version.clone(),
            generation: verified_target.generation,
            sha256: canonical_sha256(bundle.artifact_bytes),
            verified_bytes: bundle.artifact_bytes.to_vec(),
            cdn_status,
        })
    }

    /// Distinguish tolerated CDN replication lag from hard >24h staleness or clock rollback.
    pub fn assess_cdn_lag(
        &self,
        snapshot_published_unix_s: i64,
        trusted_now_unix_s: i64,
    ) -> Result<CdnFreshnessStatus, UpdaterError> {
        if snapshot_published_unix_s > trusted_now_unix_s.saturating_add(300) {
            return Err(UpdaterError::StaleOrRollback {
                detail: "snapshot timestamp lies beyond 5-minute clock tolerance".to_string(),
            });
        }
        let lag_s = trusted_now_unix_s.saturating_sub(snapshot_published_unix_s);
        if lag_s > self.max_cdn_lag_s {
            return Err(UpdaterError::StaleOrRollback {
                detail: format!(
                    "manifest lag {lag_s}s exceeds max tolerated CDN window {}s",
                    self.max_cdn_lag_s
                ),
            });
        }
        if lag_s > 60 {
            Ok(CdnFreshnessStatus::ToleratedCdnLag { lag_s })
        } else {
            Ok(CdnFreshnessStatus::Current)
        }
    }

    fn trusted_keys_for_role(
        &self,
        root_kind: TufRootKind,
        role: TufRole,
    ) -> Result<(Vec<TrustedKeyInfo>, u32), UpdaterError> {
        let root = match root_kind {
            TufRootKind::Project => &self.project_root,
            TufRootKind::Deployment => {
                self.deployment_root
                    .as_ref()
                    .ok_or_else(|| UpdaterError::TufVerification {
                        detail: "deployment root not initialized".to_string(),
                    })?
            }
        };
        let role_def = root
            .roles
            .get(&role)
            .ok_or_else(|| UpdaterError::TufVerification {
                detail: format!("missing role {:?} in TUF root", role),
            })?;
        let mut seen_kids = BTreeSet::new();
        let mut seen_pks = BTreeSet::new();
        let mut keys = Vec::new();
        for key_id in &role_def.key_ids {
            if !seen_kids.insert(key_id.as_str()) {
                return Err(UpdaterError::TufVerification {
                    detail: format!("duplicate key_id '{key_id}' in role {role:?}"),
                });
            }
            if let Some(info) = root.keys.get(key_id) {
                let raw_pk = decode_ed25519_pubkey_b64_strict(&info.public_key_b64)?;
                if !seen_pks.insert(raw_pk) {
                    return Err(UpdaterError::TufVerification {
                        detail: format!("duplicate Ed25519 public key in role {role:?}"),
                    });
                }
                keys.push(info.clone());
            }
        }
        let key_count = u32::try_from(keys.len()).unwrap_or(u32::MAX);
        if role_def.threshold == 0 || key_count < role_def.threshold {
            return Err(UpdaterError::TufVerification {
                detail: format!(
                    "role {role:?} unique key count {key_count} below threshold {}",
                    role_def.threshold
                ),
            });
        }
        Ok((keys, role_def.threshold))
    }
}

/// Enforce `D-37` / `ARCH-004` separation between `Project` binaries and `Deployment` packs.
pub fn enforce_pack_authority(
    root_kind: TufRootKind,
    pack_kind: PackKind,
) -> Result<(), UpdaterError> {
    if pack_kind == PackKind::Binary && root_kind != TufRootKind::Project {
        return Err(UpdaterError::TufVerification {
            detail: "Deployment root cannot authorize binary executables".to_string(),
        });
    }
    Ok(())
}
