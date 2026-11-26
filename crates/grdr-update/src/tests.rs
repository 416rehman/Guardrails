// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use grdr_crypto::SigningKeypair;
use grdr_model::SigningKeypairExt as _;
use jiff::Timestamp;

use crate::{
    AirgapArtifact, AirgapBundleEntry, AirgapBundleManifest, BundleApprovalState,
    FreshnessStatement, PackKind, RolloutHaltEntry, RootKeyRole, RootMetadata, SignedMetadata,
    SignerClass, SlotState, SnapshotMetadata, SnapshotTargetRef, TargetDescriptor, TargetsMetadata,
    TimestampMetadata, TufRole, TufRootKind, UpdateError, UpdateFreshness, UpdateSlot, UpdateTrust,
    canonical_sha256, sign_dsse_envelope, sign_metadata, verify_airgap_bundle,
};

fn ts(sec: i64) -> Timestamp {
    Timestamp::from_second(sec).expect("valid timestamp")
}

fn build_project_root(
    release_signer: &SigningKeypair,
    rebuilder: &SigningKeypair,
    version: u64,
    expires: Timestamp,
) -> SignedMetadata<RootMetadata> {
    let mut keys = BTreeMap::new();
    keys.insert(
        release_signer.key_id().to_owned(),
        release_signer.public_info(),
    );
    keys.insert(rebuilder.key_id().to_owned(), rebuilder.public_info());

    let mut roles = BTreeMap::new();
    roles.insert(
        TufRole::Root,
        RootKeyRole {
            key_ids: vec![
                release_signer.key_id().to_owned(),
                rebuilder.key_id().to_owned(),
            ],
            threshold: 2,
        },
    );
    roles.insert(
        TufRole::Binaries,
        RootKeyRole {
            key_ids: vec![
                release_signer.key_id().to_owned(),
                rebuilder.key_id().to_owned(),
            ],
            threshold: 2,
        },
    );
    for role in [
        TufRole::Timestamp,
        TufRole::Snapshot,
        TufRole::Targets,
        TufRole::Content,
    ] {
        roles.insert(
            role,
            RootKeyRole {
                key_ids: vec![release_signer.key_id().to_owned()],
                threshold: 1,
            },
        );
    }

    sign_metadata(
        RootMetadata {
            root_kind: TufRootKind::Project,
            version,
            expires,
            keys,
            roles,
        },
        &[release_signer, rebuilder],
    )
    .expect("sign project root")
}

type ProjectChain = (
    SignedMetadata<TimestampMetadata>,
    SignedMetadata<SnapshotMetadata>,
    SignedMetadata<TargetsMetadata>,
    SignedMetadata<TargetsMetadata>,
);

fn build_project_chain_with_keys(
    release_signer: &SigningKeypair,
    rebuilder: &SigningKeypair,
    expires: Timestamp,
    version: u64,
    binary_bytes: &[u8],
) -> ProjectChain {
    let mut bin_targets = BTreeMap::new();
    bin_targets.insert(
        "binaries/linux/x86_64/grdr-daemon/1.0.0".into(),
        TargetDescriptor {
            role: TufRole::Binaries,
            pack_kind: PackKind::Binary,
            signer_class: SignerClass::ProjectBinaries,
            version: format!("1.0.{version}"),
            generation: 10u64.saturating_add(version),
            sha256: canonical_sha256(binary_bytes),
            length: u64::try_from(binary_bytes.len()).expect("len"),
        },
    );
    let binaries = sign_metadata(
        TargetsMetadata {
            role: TufRole::Binaries,
            version,
            expires,
            targets: bin_targets,
        },
        &[release_signer, rebuilder],
    )
    .expect("sign binaries");

    let mut content_targets = BTreeMap::new();
    content_targets.insert(
        "content/detection/essentials/1.0.0".into(),
        TargetDescriptor {
            role: TufRole::Content,
            pack_kind: PackKind::Detection,
            signer_class: SignerClass::ProjectContent,
            version: "1.0.0".into(),
            generation: version,
            sha256: canonical_sha256(b"essentials-pack"),
            length: 15,
        },
    );
    let targets = sign_metadata(
        TargetsMetadata {
            role: TufRole::Targets,
            version,
            expires,
            targets: content_targets,
        },
        &[release_signer],
    )
    .expect("sign targets");

    let mut snap_meta = BTreeMap::new();
    let targets_bytes = serde_json::to_vec(&targets.signed).expect("targets json");
    let bin_bytes = serde_json::to_vec(&binaries.signed).expect("binaries json");
    snap_meta.insert(
        TufRole::Targets,
        SnapshotTargetRef {
            version,
            sha256: canonical_sha256(&targets_bytes),
            length: u64::try_from(targets_bytes.len()).expect("len"),
        },
    );
    snap_meta.insert(
        TufRole::Binaries,
        SnapshotTargetRef {
            version,
            sha256: canonical_sha256(&bin_bytes),
            length: u64::try_from(bin_bytes.len()).expect("len"),
        },
    );

    let snapshot = sign_metadata(
        SnapshotMetadata {
            version,
            expires,
            meta: snap_meta,
        },
        &[release_signer],
    )
    .expect("sign snapshot");

    let snap_bytes = serde_json::to_vec(&snapshot.signed).expect("snapshot json");
    let timestamp = sign_metadata(
        TimestampMetadata {
            version,
            expires,
            snapshot: SnapshotTargetRef {
                version,
                sha256: canonical_sha256(&snap_bytes),
                length: u64::try_from(snap_bytes.len()).expect("len"),
            },
        },
        &[release_signer],
    )
    .expect("sign timestamp");

    (timestamp, snapshot, targets, binaries)
}

fn build_deployment_root(expires: Timestamp) -> (SigningKeypair, SignedMetadata<RootMetadata>) {
    let fleet = SigningKeypair::generate().expect("fleet key");
    let mut keys = BTreeMap::new();
    keys.insert(fleet.key_id().to_owned(), fleet.public_info());

    let mut roles = BTreeMap::new();
    for role in [
        TufRole::Root,
        TufRole::Timestamp,
        TufRole::Snapshot,
        TufRole::Targets,
        TufRole::Fleet,
    ] {
        roles.insert(
            role,
            RootKeyRole {
                key_ids: vec![fleet.key_id().to_owned()],
                threshold: 1,
            },
        );
    }

    let root = sign_metadata(
        RootMetadata {
            root_kind: TufRootKind::Deployment,
            version: 1,
            expires,
            keys,
            roles,
        },
        &[&fleet],
    )
    .expect("sign deployment root");
    (fleet, root)
}

#[test]
fn dual_root_separates_binaries_from_deployment_policy() {
    let now = ts(1_760_000_000);
    let expires = ts(now.as_second().saturating_add(86_400));
    let binary_payload = b"grdr-daemon-elf-binary";

    let release_signer = SigningKeypair::generate().expect("release");
    let rebuilder = SigningKeypair::generate().expect("rebuilder");
    let proj_root = build_project_root(
        &release_signer,
        &rebuilder,
        1,
        ts(now.as_second().saturating_add(86_400 * 365)),
    );
    let (proj_ts, proj_snap, proj_targets, proj_bins) =
        build_project_chain_with_keys(&release_signer, &rebuilder, expires, 1, binary_payload);
    let (fleet, dep_root) = build_deployment_root(ts(now.as_second().saturating_add(86_400 * 30)));

    let mut trust = UpdateTrust::new(proj_root, now)
        .expect("proj trust")
        .with_deployment_root(dep_root, now)
        .expect("dep trust");

    let res = trust
        .verify_project_chain(
            &proj_ts,
            &proj_snap,
            &proj_targets,
            Some(&proj_bins),
            None,
            now,
        )
        .expect("verify project chain");
    assert_eq!(res.freshness, UpdateFreshness::Current);
    assert!(res.enforcement_active);

    let partial_dsse = sign_dsse_envelope(
        "application/vnd.grdr.pack-manifest+json",
        binary_payload,
        &[&release_signer],
    )
    .expect("partial dsse");
    assert!(matches!(
        trust.verify_target_artifact(
            TufRootKind::Project,
            &proj_bins,
            "binaries/linux/x86_64/grdr-daemon/1.0.0",
            binary_payload,
            Some(&partial_dsse),
        ),
        Err(UpdateError::InvalidSignature(_))
    ));

    let dsse = sign_dsse_envelope(
        "application/vnd.grdr.pack-manifest+json",
        binary_payload,
        &[&release_signer, &rebuilder],
    )
    .expect("full dsse");
    let desc = trust
        .verify_target_artifact(
            TufRootKind::Project,
            &proj_bins,
            "binaries/linux/x86_64/grdr-daemon/1.0.0",
            binary_payload,
            Some(&dsse),
        )
        .expect("verified binary");
    assert_eq!(desc.generation, 11);

    let err = trust
        .verify_target_artifact(
            TufRootKind::Deployment,
            &proj_bins,
            "binaries/linux/x86_64/grdr-daemon/1.0.0",
            binary_payload,
            None,
        )
        .expect_err("deployment root must not authorize binary");
    assert!(matches!(err, UpdateError::UnauthorizedRoot(_)));

    let policy_bytes = br#"{"layer":"org","mode":"block"}"#;
    let mut dep_targets_map = BTreeMap::new();
    dep_targets_map.insert(
        "policy/org/layer-1".into(),
        TargetDescriptor {
            role: TufRole::Targets,
            pack_kind: PackKind::LayerDocument,
            signer_class: SignerClass::Deployment,
            version: "1.0.0".into(),
            generation: 2,
            sha256: canonical_sha256(policy_bytes),
            length: u64::try_from(policy_bytes.len()).expect("len"),
        },
    );
    let dep_targets = sign_metadata(
        TargetsMetadata {
            role: TufRole::Targets,
            version: 1,
            expires,
            targets: dep_targets_map,
        },
        &[&fleet],
    )
    .expect("dep targets");
    let dep_dsse = sign_dsse_envelope(
        "application/vnd.grdr.pack-manifest+json",
        policy_bytes,
        &[&fleet],
    )
    .expect("dep dsse");
    assert!(
        trust
            .verify_target_artifact(
                TufRootKind::Deployment,
                &dep_targets,
                "policy/org/layer-1",
                policy_bytes,
                Some(&dep_dsse),
            )
            .is_ok()
    );
}

#[test]
fn rejects_rollback_freeze_and_mix_and_match_and_continues_enforcement_when_stale() {
    let now = ts(1_760_000_000);
    let expires = ts(now.as_second().saturating_add(3600));
    let release_signer = SigningKeypair::generate().expect("release");
    let rebuilder = SigningKeypair::generate().expect("rebuilder");
    let proj_root = build_project_root(
        &release_signer,
        &rebuilder,
        1,
        ts(now.as_second().saturating_add(86_400 * 365)),
    );
    let (proj_ts_v2, proj_snap_v2, proj_targets_v2, proj_bins_v2) =
        build_project_chain_with_keys(&release_signer, &rebuilder, expires, 2, b"bin-v2");
    let (fleet, dep_root) = build_deployment_root(ts(now.as_second().saturating_add(86_400 * 30)));

    let mut trust = UpdateTrust::new(proj_root, now)
        .expect("trust")
        .with_deployment_root(dep_root, now)
        .expect("dep");

    trust
        .verify_project_chain(
            &proj_ts_v2,
            &proj_snap_v2,
            &proj_targets_v2,
            Some(&proj_bins_v2),
            None,
            now,
        )
        .expect("v2 valid");

    let (proj_ts_v1, proj_snap_v1, proj_targets_v1, proj_bins_v1) =
        build_project_chain_with_keys(&release_signer, &rebuilder, expires, 1, b"bin-v1");
    assert!(matches!(
        trust.verify_project_chain(
            &proj_ts_v1,
            &proj_snap_v1,
            &proj_targets_v1,
            Some(&proj_bins_v1),
            None,
            now
        ),
        Err(UpdateError::RollbackDetected { .. })
    ));

    let (_proj_ts_v3, _proj_snap_v3, proj_targets_v3, _) =
        build_project_chain_with_keys(&release_signer, &rebuilder, expires, 3, b"bin-v3");
    assert!(matches!(
        trust.verify_project_chain(
            &proj_ts_v2,
            &proj_snap_v2,
            &proj_targets_v3,
            None,
            None,
            now
        ),
        Err(UpdateError::MixAndMatchDetected(_))
    ));

    let after_expiry = ts(expires.as_second().saturating_add(60));
    assert!(matches!(
        trust.verify_project_chain(
            &proj_ts_v2,
            &proj_snap_v2,
            &proj_targets_v2,
            Some(&proj_bins_v2),
            None,
            after_expiry
        ),
        Err(UpdateError::MetadataExpired { .. })
    ));

    let stale_eval = trust
        .evaluate_freshness(
            &proj_ts_v2.signed,
            &proj_snap_v2.signed,
            &proj_targets_v2.signed,
            Some(&proj_bins_v2.signed),
            None,
            after_expiry,
        )
        .expect("evaluate stale");
    assert_eq!(stale_eval.freshness, UpdateFreshness::Stale);
    assert!(stale_eval.enforcement_active);
    assert!(!stale_eval.install_permitted);

    let snap_bytes = serde_json::to_vec(&proj_snap_v2.signed).expect("snap json");
    let stmt = sign_metadata(
        FreshnessStatement {
            deployment_id: "dep-airgap-1".into(),
            project_root_version: 1,
            project_snapshot_version: 2,
            project_snapshot_sha256: canonical_sha256(&snap_bytes),
            imported_at: now,
            issued_at: after_expiry,
            expires: ts(after_expiry.as_second().saturating_add(86_400)),
        },
        &[&fleet],
    )
    .expect("sign freshness");
    let vouched = trust
        .verify_project_chain(
            &proj_ts_v2,
            &proj_snap_v2,
            &proj_targets_v2,
            Some(&proj_bins_v2),
            Some(&stmt),
            after_expiry,
        )
        .expect("freshness vouched");
    assert_eq!(vouched.freshness, UpdateFreshness::Current);
    assert!(vouched.enforcement_active);

    let past_project_root_expiry = ts(now.as_second().saturating_add(86_400 * 400));
    let root_eval = trust
        .evaluate_freshness(
            &proj_ts_v2.signed,
            &proj_snap_v2.signed,
            &proj_targets_v2.signed,
            None,
            Some(&stmt),
            past_project_root_expiry,
        )
        .expect("root expired eval");
    assert_eq!(root_eval.freshness, UpdateFreshness::Expired);
    assert!(root_eval.enforcement_active);
    assert!(!root_eval.install_permitted);
}

#[test]
fn root_rotation_requires_old_and_new_threshold_and_ab_slots_verify() {
    let now = ts(1_760_000_000);
    let release_signer = SigningKeypair::generate().expect("release");
    let rebuilder = SigningKeypair::generate().expect("rebuilder");
    let next_release = SigningKeypair::generate().expect("next release");
    let next_rebuilder = SigningKeypair::generate().expect("next rebuilder");

    let proj_root = build_project_root(
        &release_signer,
        &rebuilder,
        1,
        ts(now.as_second().saturating_add(86_400 * 365)),
    );
    let mut trust = UpdateTrust::new(proj_root, now).expect("trust");

    let mut next_meta = build_project_root(
        &next_release,
        &next_rebuilder,
        2,
        ts(now.as_second().saturating_add(86_400 * 730)),
    );
    assert!(matches!(
        trust.rotate_root(TufRootKind::Project, next_meta.clone(), now),
        Err(UpdateError::InvalidSignature(_))
    ));

    next_meta = sign_metadata(
        next_meta.signed,
        &[&release_signer, &rebuilder, &next_release, &next_rebuilder],
    )
    .expect("cross-signed root");
    trust
        .rotate_root(TufRootKind::Project, next_meta, now)
        .expect("root rotated");
    assert_eq!(trust.project_root_version(), 2);

    let slot = SlotState::initial("1.0.0", 10, "sha-v1", 5);
    assert!(matches!(
        slot.clone().stage_candidate("0.9.0", 4, "sha-old"),
        Err(UpdateError::SecurityFloorViolation { .. })
    ));
    assert!(matches!(
        slot.clone().stage_candidate("1.0.0", 10, "sha-same"),
        Err(UpdateError::RollbackDetected { .. })
    ));

    let staged = slot.stage_candidate("1.1.0", 11, "sha-v2").expect("staged");
    let pending = staged.mark_verified().expect("verified");
    let active_b = pending.activate().expect("activated");
    assert!(matches!(
        active_b,
        SlotState::Active {
            slot: UpdateSlot::SlotB,
            generation: 11,
            ..
        }
    ));

    let rolled = active_b
        .rollback_to_previous("1.0.0", 10, "sha-v1", "crash-loop")
        .expect("rolled back");
    assert!(matches!(
        rolled,
        SlotState::RolledBack {
            active: UpdateSlot::SlotA,
            failed_slot: UpdateSlot::SlotB,
            ..
        }
    ));

    let pack_bytes = b"airgap-pack-tar-zst";
    let manifest = AirgapBundleManifest {
        bundle_id: "bndl-1".into(),
        bundle_version: "2026.11.1".into(),
        created_at: now,
        entries: vec![AirgapBundleEntry {
            path: "packs/essentials.grdrpack".into(),
            pack_id: "pack-essentials".into(),
            version: "1.0.0".into(),
            sha256: canonical_sha256(pack_bytes),
            length: u64::try_from(pack_bytes.len()).expect("len"),
        }],
        halted_releases: Vec::new(),
    };
    let manifest_bytes = serde_json::to_vec(&manifest).expect("manifest json");
    let envelope = sign_dsse_envelope(
        "application/vnd.grdr.airgap-manifest+json",
        &manifest_bytes,
        &[&next_release],
    )
    .expect("airgap dsse");
    let artifacts = vec![AirgapArtifact {
        path: "packs/essentials.grdrpack".into(),
        bytes: pack_bytes.to_vec(),
    }];

    assert!(matches!(
        verify_airgap_bundle(
            &trust,
            &envelope,
            &artifacts,
            &BundleApprovalState::AwaitingTermsAcceptance,
            &[],
            now
        ),
        Err(UpdateError::TermsNotAccepted)
    ));

    let accepted = BundleApprovalState::TermsAccepted {
        operator_id: "opa_admin".into(),
        accepted_at: now,
    };
    let ok = verify_airgap_bundle(&trust, &envelope, &artifacts, &accepted, &[], now)
        .expect("airgap verified");
    assert_eq!(ok.verified_entries, 1);

    let halt = vec![RolloutHaltEntry {
        pack_id: "pack-essentials".into(),
        version: "1.0.0".into(),
        reason: "regression in ring 1".into(),
    }];
    assert!(matches!(
        verify_airgap_bundle(&trust, &envelope, &artifacts, &accepted, &halt, now),
        Err(UpdateError::HaltedRelease(_))
    ));
}

#[test]
fn rejects_role_confusion_dsse_mismatch_snapshot_len_airgap_traversal_and_staging_rollback() {
    let now = ts(1_760_000_000);
    let expires = ts(now.as_second().saturating_add(86_400));
    let release_signer = SigningKeypair::generate().expect("release");
    let rebuilder = SigningKeypair::generate().expect("rebuilder");
    let proj_root = build_project_root(
        &release_signer,
        &rebuilder,
        1,
        ts(now.as_second().saturating_add(86_400 * 365)),
    );
    let (mut proj_ts, mut proj_snap, proj_targets, proj_bins) =
        build_project_chain_with_keys(&release_signer, &rebuilder, expires, 1, b"bin-v1");
    let (_fleet, dep_root) = build_deployment_root(ts(now.as_second().saturating_add(86_400 * 30)));

    let trust = UpdateTrust::new(proj_root, now)
        .expect("proj trust")
        .with_deployment_root(dep_root.clone(), now)
        .expect("dep trust");

    // Refuse re-pinning an already trusted deployment root without rotation.
    assert!(matches!(
        trust.clone().with_deployment_root(dep_root, now),
        Err(UpdateError::UnauthorizedRoot(_))
    ));

    // Reject Targets->Binaries role confusion even when signed by authorized keys.
    let mut forged_bins_targets = BTreeMap::new();
    forged_bins_targets.insert(
        "binaries/linux/x86_64/grdr-daemon/9.9.9".into(),
        TargetDescriptor {
            role: TufRole::Binaries,
            pack_kind: PackKind::Binary,
            signer_class: SignerClass::ProjectBinaries,
            version: "9.9.9".into(),
            generation: 99,
            sha256: canonical_sha256(b"evil-bin"),
            length: 8,
        },
    );
    let targets_role_as_bins = sign_metadata(
        TargetsMetadata {
            role: TufRole::Targets,
            version: 1,
            expires,
            targets: forged_bins_targets,
        },
        &[&release_signer, &rebuilder],
    )
    .expect("forged binaries with Targets role");
    let mut trust_role = trust.clone();
    assert!(matches!(
        trust_role.verify_project_chain(
            &proj_ts,
            &proj_snap,
            &proj_targets,
            Some(&targets_role_as_bins),
            None,
            now,
        ),
        Err(UpdateError::UnauthorizedRoot(_))
    ));

    // Reject snapshot length tampering even if sha256 matches or vice versa.
    if let Some(targets_ref) = proj_snap.signed.meta.get_mut(&TufRole::Targets) {
        targets_ref.length = targets_ref.length.saturating_add(1);
    }
    let tampered_snap = sign_metadata(proj_snap.signed.clone(), &[&release_signer]).expect("snap");
    let snap_bytes = serde_json::to_vec(&tampered_snap.signed).expect("snap json");
    proj_ts.signed.snapshot.sha256 = canonical_sha256(&snap_bytes);
    proj_ts.signed.snapshot.length = u64::try_from(snap_bytes.len()).expect("len");
    let tampered_ts = sign_metadata(proj_ts.signed.clone(), &[&release_signer]).expect("ts");
    let mut trust_len = trust.clone();
    assert!(matches!(
        trust_len.verify_project_chain(
            &tampered_ts,
            &tampered_snap,
            &proj_targets,
            None,
            None,
            now
        ),
        Err(UpdateError::MixAndMatchDetected(_))
    ));

    // Reject unrelated DSSE envelope signed by the same valid threshold signers.
    let unrelated_dsse = sign_dsse_envelope(
        "application/vnd.grdr.pack-manifest+json",
        b"completely-different-artifact",
        &[&release_signer, &rebuilder],
    )
    .expect("unrelated dsse");
    assert!(matches!(
        trust.verify_target_artifact(
            TufRootKind::Project,
            &proj_bins,
            "binaries/linux/x86_64/grdr-daemon/1.0.0",
            b"bin-v1",
            Some(&unrelated_dsse),
        ),
        Err(UpdateError::MixAndMatchDetected(_))
    ));

    // Reject project root attempting to sign deployment LayerDocument targets.
    let mut layer_targets = BTreeMap::new();
    layer_targets.insert(
        "policy/org/evil".into(),
        TargetDescriptor {
            role: TufRole::Targets,
            pack_kind: PackKind::LayerDocument,
            signer_class: SignerClass::ProjectContent,
            version: "1.0.0".into(),
            generation: 1,
            sha256: canonical_sha256(b"{}"),
            length: 2,
        },
    );
    let proj_layer_meta = sign_metadata(
        TargetsMetadata {
            role: TufRole::Targets,
            version: 1,
            expires,
            targets: layer_targets,
        },
        &[&release_signer],
    )
    .expect("proj layer meta");
    assert!(matches!(
        trust.verify_target_artifact(
            TufRootKind::Project,
            &proj_layer_meta,
            "policy/org/evil",
            b"{}",
            None,
        ),
        Err(UpdateError::UnauthorizedRoot(_))
    ));

    // Reject content packs attempting to use TufRole::Timestamp for DSSE verification.
    let mut ts_role_content = BTreeMap::new();
    ts_role_content.insert(
        "content/detection/spoof".into(),
        TargetDescriptor {
            role: TufRole::Timestamp,
            pack_kind: PackKind::Detection,
            signer_class: SignerClass::ProjectContent,
            version: "1.0.0".into(),
            generation: 1,
            sha256: canonical_sha256(b"rule"),
            length: 4,
        },
    );
    let ts_role_meta = sign_metadata(
        TargetsMetadata {
            role: TufRole::Targets,
            version: 1,
            expires,
            targets: ts_role_content,
        },
        &[&release_signer],
    )
    .expect("ts role meta");
    assert!(matches!(
        trust.verify_target_artifact(
            TufRootKind::Project,
            &ts_role_meta,
            "content/detection/spoof",
            b"rule",
            None,
        ),
        Err(UpdateError::UnauthorizedRoot(_))
    ));

    // Air-gap path traversal and unmanifested artifacts must fail closed.
    let pack_bytes = b"bad-pack";
    let traversal_manifest = AirgapBundleManifest {
        bundle_id: "bndl-bad".into(),
        bundle_version: "1.0.0".into(),
        created_at: now,
        entries: vec![AirgapBundleEntry {
            path: "../etc/passwd".into(),
            pack_id: "pack-bad".into(),
            version: "1.0.0".into(),
            sha256: canonical_sha256(pack_bytes),
            length: u64::try_from(pack_bytes.len()).expect("len"),
        }],
        halted_releases: Vec::new(),
    };
    let traversal_env = sign_dsse_envelope(
        "application/vnd.grdr.airgap-manifest+json",
        &serde_json::to_vec(&traversal_manifest).expect("json"),
        &[&release_signer],
    )
    .expect("env");
    let accepted = BundleApprovalState::TermsAccepted {
        operator_id: "op_1".into(),
        accepted_at: now,
    };
    assert!(matches!(
        verify_airgap_bundle(
            &trust,
            &traversal_env,
            &[AirgapArtifact {
                path: "../etc/passwd".into(),
                bytes: pack_bytes.to_vec(),
            }],
            &accepted,
            &[],
            now,
        ),
        Err(UpdateError::MalformedMetadata(_))
    ));

    // Rollback from Staging keeps the stored active slot metadata rather than forging new ones.
    let staged = SlotState::initial("1.0.0", 10, "sha-v1", 5)
        .stage_candidate("1.1.0", 11, "sha-v2")
        .expect("staged");
    let rolled = staged
        .rollback_to_previous("9.9.9", 99, "forged", "verify-failed")
        .expect("rollback");
    assert!(matches!(
        rolled,
        SlotState::RolledBack {
            active: UpdateSlot::SlotA,
            active_generation: 10,
            failed_slot: UpdateSlot::SlotB,
            ..
        }
    ));
}
