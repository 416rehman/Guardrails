// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use grdr_model::TrustedKeyInfo;
use jiff::Timestamp;

use crate::UpdateError;
use crate::dsse::{DsseEnvelope, verify_dsse_envelope};
use crate::tuf_helpers::{
    evaluate_deployment_vouch, validate_target_signing_role, verify_dsse_binding,
    verify_timestamp_snapshot_pair,
};
use crate::tuf_types::{
    FreshnessEvaluation, FreshnessStatement, RootMetadata, SignedMetadata, SnapshotMetadata,
    TargetDescriptor, TargetsMetadata, TimestampMetadata, TrustVerificationResult, TufRole,
    TufRootKind, UpdateFreshness, canonical_sha256, check_monotonic, collect_role_keys,
    enforce_root_separation, verify_role_signatures, verify_root_self, verify_snapshot_link,
};

#[derive(Debug, Clone)]
pub struct UpdateTrust {
    project_root: RootMetadata,
    deployment_root: Option<RootMetadata>,
    trusted_timestamps: BTreeMap<TufRootKind, u64>,
    trusted_snapshots: BTreeMap<TufRootKind, u64>,
    trusted_targets: BTreeMap<(TufRootKind, TufRole), u64>,
}

impl UpdateTrust {
    pub fn new(
        project_root: SignedMetadata<RootMetadata>,
        now: Timestamp,
    ) -> Result<Self, UpdateError> {
        if project_root.signed.root_kind != TufRootKind::Project {
            return Err(UpdateError::UnauthorizedRoot(
                "initial root must be TufRootKind::Project".into(),
            ));
        }
        verify_root_self(&project_root, now)?;
        Ok(Self {
            project_root: project_root.signed,
            deployment_root: None,
            trusted_timestamps: BTreeMap::new(),
            trusted_snapshots: BTreeMap::new(),
            trusted_targets: BTreeMap::new(),
        })
    }

    pub fn with_deployment_root(
        mut self,
        deployment_root: SignedMetadata<RootMetadata>,
        now: Timestamp,
    ) -> Result<Self, UpdateError> {
        if self.deployment_root.is_some() {
            return Err(UpdateError::UnauthorizedRoot(
                "deployment root already pinned; use rotate_root".into(),
            ));
        }
        if deployment_root.signed.root_kind != TufRootKind::Deployment {
            return Err(UpdateError::UnauthorizedRoot(
                "deployment root must be TufRootKind::Deployment".into(),
            ));
        }
        verify_root_self(&deployment_root, now)?;
        self.deployment_root = Some(deployment_root.signed);
        Ok(self)
    }

    #[must_use]
    pub fn project_root_expires(&self) -> Timestamp {
        self.project_root.expires
    }

    #[must_use]
    pub fn project_root_version(&self) -> u64 {
        self.project_root.version
    }

    pub fn project_content_role_keys(&self) -> Result<(Vec<TrustedKeyInfo>, u32), UpdateError> {
        collect_role_keys(&self.project_root, TufRole::Content)
    }

    pub fn project_binaries_role_keys(&self) -> Result<(Vec<TrustedKeyInfo>, u32), UpdateError> {
        collect_role_keys(&self.project_root, TufRole::Binaries)
    }

    pub fn rotate_root(
        &mut self,
        kind: TufRootKind,
        next_root: SignedMetadata<RootMetadata>,
        now: Timestamp,
    ) -> Result<(), UpdateError> {
        if next_root.signed.root_kind != kind {
            return Err(UpdateError::UnauthorizedRoot(
                "root rotation kind mismatch".into(),
            ));
        }
        if next_root.signed.expires <= now {
            return Err(UpdateError::MetadataExpired {
                role: format!("{kind:?}::root"),
                expired_at: next_root.signed.expires.to_string(),
            });
        }
        let current = self.root_for_kind(kind)?;
        if next_root.signed.version <= current.version {
            return Err(UpdateError::RollbackDetected {
                role: format!("{kind:?}::root"),
                found: next_root.signed.version,
                trusted: current.version,
            });
        }
        verify_role_signatures(current, TufRole::Root, &next_root)?;
        verify_role_signatures(&next_root.signed, TufRole::Root, &next_root)?;

        match kind {
            TufRootKind::Project => self.project_root = next_root.signed,
            TufRootKind::Deployment => self.deployment_root = Some(next_root.signed),
        }
        Ok(())
    }

    pub fn verify_project_chain(
        &mut self,
        timestamp: &SignedMetadata<TimestampMetadata>,
        snapshot: &SignedMetadata<SnapshotMetadata>,
        targets: &SignedMetadata<TargetsMetadata>,
        binaries: Option<&SignedMetadata<TargetsMetadata>>,
        freshness: Option<&SignedMetadata<FreshnessStatement>>,
        now: Timestamp,
    ) -> Result<TrustVerificationResult, UpdateError> {
        self.verify_chain_core(TufRootKind::Project, timestamp, snapshot, targets, now)?;

        if let Some(bin_meta) = binaries {
            if bin_meta.signed.role != TufRole::Binaries {
                return Err(UpdateError::UnauthorizedRoot(
                    "binaries metadata role must be TufRole::Binaries".into(),
                ));
            }
            if bin_meta.signed.version < 1 {
                return Err(UpdateError::MalformedMetadata(
                    "binaries metadata version must be >= 1".into(),
                ));
            }
            verify_role_signatures(&self.project_root, TufRole::Binaries, bin_meta)?;
            let trusted_bin = self
                .trusted_targets
                .get(&(TufRootKind::Project, TufRole::Binaries))
                .copied()
                .unwrap_or(0);
            check_monotonic("project::binaries", bin_meta.signed.version, trusted_bin)?;
            verify_snapshot_link(
                &snapshot.signed,
                TufRole::Binaries,
                bin_meta.signed.version,
                &bin_meta.signed,
            )?;
        }

        let eval = self.evaluate_freshness(
            &timestamp.signed,
            &snapshot.signed,
            &targets.signed,
            binaries.map(|b| &b.signed),
            freshness,
            now,
        )?;
        if !eval.install_permitted {
            return Err(UpdateError::MetadataExpired {
                role: "project::chain".into(),
                expired_at: eval.reason.unwrap_or_else(|| "expired".into()),
            });
        }

        self.record_verified(
            TufRootKind::Project,
            timestamp.signed.version,
            snapshot.signed.version,
            targets.signed.version,
        );
        if let Some(bin_meta) = binaries {
            self.trusted_targets.insert(
                (TufRootKind::Project, TufRole::Binaries),
                bin_meta.signed.version,
            );
        }

        Ok(TrustVerificationResult {
            root_kind: TufRootKind::Project,
            freshness: eval.freshness,
            enforcement_active: true,
            snapshot_version: snapshot.signed.version,
            targets_version: targets.signed.version,
        })
    }

    pub fn verify_project_timestamp_snapshot(
        &mut self,
        timestamp: &SignedMetadata<TimestampMetadata>,
        snapshot: &SignedMetadata<SnapshotMetadata>,
        freshness: Option<&SignedMetadata<FreshnessStatement>>,
        now: Timestamp,
    ) -> Result<(), UpdateError> {
        let trusted_ts = self
            .trusted_timestamps
            .get(&TufRootKind::Project)
            .copied()
            .unwrap_or(0);
        let trusted_snap = self
            .trusted_snapshots
            .get(&TufRootKind::Project)
            .copied()
            .unwrap_or(0);
        verify_timestamp_snapshot_pair(
            TufRootKind::Project,
            &self.project_root,
            timestamp,
            snapshot,
            trusted_ts,
            trusted_snap,
            now,
        )?;
        if (timestamp.signed.expires <= now || snapshot.signed.expires <= now)
            && !freshness
                .zip(self.deployment_root.as_ref())
                .is_some_and(|(stmt, dep)| {
                    evaluate_deployment_vouch(
                        dep,
                        self.project_root.version,
                        &snapshot.signed,
                        stmt,
                        now,
                    )
                    .is_ok_and(|ev| ev.install_permitted)
                })
        {
            return Err(UpdateError::MetadataExpired {
                role: "Project::timestamp".into(),
                expired_at: timestamp
                    .signed
                    .expires
                    .min(snapshot.signed.expires)
                    .to_string(),
            });
        }
        self.trusted_timestamps
            .insert(TufRootKind::Project, timestamp.signed.version);
        Ok(())
    }

    pub fn verify_deployment_chain(
        &mut self,
        timestamp: &SignedMetadata<TimestampMetadata>,
        snapshot: &SignedMetadata<SnapshotMetadata>,
        targets: &SignedMetadata<TargetsMetadata>,
        now: Timestamp,
    ) -> Result<TrustVerificationResult, UpdateError> {
        self.verify_chain_core(TufRootKind::Deployment, timestamp, snapshot, targets, now)?;

        if timestamp.signed.expires <= now
            || snapshot.signed.expires <= now
            || targets.signed.expires <= now
        {
            return Err(UpdateError::MetadataExpired {
                role: "deployment::chain".into(),
                expired_at: now.to_string(),
            });
        }

        self.record_verified(
            TufRootKind::Deployment,
            timestamp.signed.version,
            snapshot.signed.version,
            targets.signed.version,
        );

        Ok(TrustVerificationResult {
            root_kind: TufRootKind::Deployment,
            freshness: UpdateFreshness::Current,
            enforcement_active: true,
            snapshot_version: snapshot.signed.version,
            targets_version: targets.signed.version,
        })
    }

    pub fn evaluate_freshness(
        &self,
        timestamp: &TimestampMetadata,
        snapshot: &SnapshotMetadata,
        targets: &TargetsMetadata,
        binaries: Option<&TargetsMetadata>,
        freshness: Option<&SignedMetadata<FreshnessStatement>>,
        now: Timestamp,
    ) -> Result<FreshnessEvaluation, UpdateError> {
        if self.project_root.expires <= now {
            return Ok(FreshnessEvaluation {
                freshness: UpdateFreshness::Expired,
                enforcement_active: true,
                install_permitted: false,
                reason: Some("project root expired; freshness statement cannot revive root".into()),
            });
        }

        let any_role_expired = timestamp.expires <= now
            || snapshot.expires <= now
            || targets.expires <= now
            || binaries.is_some_and(|b| b.expires <= now);

        if !any_role_expired {
            return Ok(FreshnessEvaluation {
                freshness: UpdateFreshness::Current,
                enforcement_active: true,
                install_permitted: true,
                reason: None,
            });
        }

        if let Some(stmt) = freshness
            && let Some(dep_root) = &self.deployment_root
        {
            return evaluate_deployment_vouch(
                dep_root,
                self.project_root.version,
                snapshot,
                stmt,
                now,
            );
        }

        Ok(FreshnessEvaluation {
            freshness: UpdateFreshness::Stale,
            enforcement_active: true,
            install_permitted: false,
            reason: Some(
                "TUF metadata expired without valid freshness statement; enforcement stays active"
                    .into(),
            ),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify_target_artifact(
        &mut self,
        root_kind: TufRootKind,
        snapshot: &SignedMetadata<SnapshotMetadata>,
        targets_meta: &SignedMetadata<TargetsMetadata>,
        freshness: Option<&SignedMetadata<FreshnessStatement>>,
        target_path: &str,
        artifact_bytes: &[u8],
        dsse: Option<&DsseEnvelope>,
        now: Timestamp,
    ) -> Result<TargetDescriptor, UpdateError> {
        if snapshot.signed.version < 1 || targets_meta.signed.version < 1 {
            return Err(UpdateError::MalformedMetadata(
                "TUF snapshot and targets versions must be >= 1".into(),
            ));
        }
        let signing_role = validate_target_signing_role(root_kind, targets_meta.signed.role)?;

        let (descriptor, snapshot_ver, targets_ver) = {
            let root = self.root_for_kind(root_kind)?;
            if root.expires <= now {
                return Err(UpdateError::MetadataExpired {
                    role: format!("{root_kind:?}::root"),
                    expired_at: root.expires.to_string(),
                });
            }
            verify_role_signatures(root, TufRole::Snapshot, snapshot)?;
            verify_role_signatures(root, signing_role, targets_meta)?;

            if snapshot.signed.expires <= now || targets_meta.signed.expires <= now {
                let permitted = root_kind == TufRootKind::Project
                    && freshness
                        .zip(self.deployment_root.as_ref())
                        .map(|(stmt, dep)| {
                            evaluate_deployment_vouch(
                                dep,
                                self.project_root.version,
                                &snapshot.signed,
                                stmt,
                                now,
                            )
                            .is_ok_and(|ev| ev.install_permitted)
                        })
                        .unwrap_or(false);
                if !permitted {
                    return Err(UpdateError::MetadataExpired {
                        role: format!("{root_kind:?}::{signing_role:?}"),
                        expired_at: targets_meta
                            .signed
                            .expires
                            .min(snapshot.signed.expires)
                            .to_string(),
                    });
                }
            }

            let trusted_snap = self.trusted_snapshots.get(&root_kind).copied().unwrap_or(0);
            check_monotonic(
                &format!("{root_kind:?}::snapshot"),
                snapshot.signed.version,
                trusted_snap,
            )?;
            let trusted_role = self
                .trusted_targets
                .get(&(root_kind, signing_role))
                .copied()
                .unwrap_or(0);
            check_monotonic(
                &format!("{root_kind:?}::{signing_role:?}"),
                targets_meta.signed.version,
                trusted_role,
            )?;

            verify_snapshot_link(
                &snapshot.signed,
                signing_role,
                targets_meta.signed.version,
                &targets_meta.signed,
            )?;

            let Some(descriptor) = targets_meta.signed.targets.get(target_path) else {
                return Err(UpdateError::TargetNotFound(target_path.to_owned()));
            };
            enforce_root_separation(root_kind, signing_role, descriptor)?;

            let actual_len = u64::try_from(artifact_bytes.len()).unwrap_or(u64::MAX);
            if actual_len != descriptor.length {
                return Err(UpdateError::ArtifactIntegrity {
                    target: target_path.to_owned(),
                    detail: format!("length {actual_len} != expected {}", descriptor.length),
                });
            }
            let actual_sha = canonical_sha256(artifact_bytes);
            if actual_sha != descriptor.sha256 {
                return Err(UpdateError::ArtifactIntegrity {
                    target: target_path.to_owned(),
                    detail: format!("sha256 {actual_sha} != expected {}", descriptor.sha256),
                });
            }

            if let Some(env) = dsse {
                let (keys, threshold) = collect_role_keys(root, descriptor.role)?;
                let payload_bytes = verify_dsse_envelope(env, &keys, threshold)?;
                verify_dsse_binding(&payload_bytes, target_path, descriptor, artifact_bytes)?;
            }
            (
                descriptor.clone(),
                snapshot.signed.version,
                targets_meta.signed.version,
            )
        };

        self.trusted_snapshots.insert(root_kind, snapshot_ver);
        self.trusted_targets
            .insert((root_kind, signing_role), targets_ver);
        Ok(descriptor)
    }

    fn root_for_kind(&self, kind: TufRootKind) -> Result<&RootMetadata, UpdateError> {
        match kind {
            TufRootKind::Project => Ok(&self.project_root),
            TufRootKind::Deployment => self
                .deployment_root
                .as_ref()
                .ok_or_else(|| UpdateError::UnauthorizedRoot("no deployment root pinned".into())),
        }
    }

    fn verify_chain_core(
        &self,
        kind: TufRootKind,
        timestamp: &SignedMetadata<TimestampMetadata>,
        snapshot: &SignedMetadata<SnapshotMetadata>,
        targets: &SignedMetadata<TargetsMetadata>,
        now: Timestamp,
    ) -> Result<(), UpdateError> {
        if targets.signed.version < 1 {
            return Err(UpdateError::MalformedMetadata(
                "TUF targets version must be >= 1".into(),
            ));
        }
        if targets.signed.role != TufRole::Targets {
            return Err(UpdateError::UnauthorizedRoot(
                "top-level targets metadata must carry TufRole::Targets".into(),
            ));
        }
        let root = self.root_for_kind(kind)?;
        let trusted_ts = self.trusted_timestamps.get(&kind).copied().unwrap_or(0);
        let trusted_snap = self.trusted_snapshots.get(&kind).copied().unwrap_or(0);
        verify_timestamp_snapshot_pair(
            kind,
            root,
            timestamp,
            snapshot,
            trusted_ts,
            trusted_snap,
            now,
        )?;
        verify_role_signatures(root, TufRole::Targets, targets)?;
        let trusted_tgt = self
            .trusted_targets
            .get(&(kind, TufRole::Targets))
            .copied()
            .unwrap_or(0);
        check_monotonic(
            &format!("{kind:?}::targets"),
            targets.signed.version,
            trusted_tgt,
        )?;
        verify_snapshot_link(
            &snapshot.signed,
            TufRole::Targets,
            targets.signed.version,
            &targets.signed,
        )
    }

    fn record_verified(&mut self, kind: TufRootKind, ts_ver: u64, snap_ver: u64, targets_ver: u64) {
        self.trusted_timestamps.insert(kind, ts_ver);
        self.trusted_snapshots.insert(kind, snap_ver);
        self.trusted_targets
            .insert((kind, TufRole::Targets), targets_ver);
    }
}
