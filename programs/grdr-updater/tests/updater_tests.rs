// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#![deny(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;
use std::error::Error;
use std::path::PathBuf;

use grdr_compat::{CompatMatrix, ProtocolCapability, SemVer};
use grdr_crypto::SigningKeypair;
use grdr_model::api::TrustedKeyInfo;
use grdr_os_clock::ManualClock;
use grdr_update::{
    DsseTargetStatement, PackKind, RootKeyRole, RootMetadata, SignedMetadata, SignerClass,
    SnapshotMetadata, SnapshotTargetRef, TargetDescriptor, TargetsMetadata, TimestampMetadata,
    TufRole, TufRootKind, UpdateSlot, canonical_sha256, sign_dsse_envelope, sign_metadata,
};

use grdr_updater::error::UpdaterError;
use grdr_updater::fs_safe::atomic_write_bytes;
use grdr_updater::handover::{DEFAULT_HANDOVER_WINDOW_MS, HandoverCoordinator};
use grdr_updater::p7_delta::{
    DeltaOp, DeltaPackage, enforce_p7_json_purity, reconstruct_delta_or_request_full,
};
use grdr_updater::slots::{BinaryIntegrityOutcome, SlotActivationManager, UpdateAuthority};
use grdr_updater::verify::{CdnFreshnessStatus, DualRootVerifier, StagedUpdateBundle};

type TestResult = Result<(), Box<dyn Error>>;

struct TufChainFixture {
    root: SignedMetadata<RootMetadata>,
    timestamp: SignedMetadata<TimestampMetadata>,
    snapshot: SignedMetadata<SnapshotMetadata>,
    targets: SignedMetadata<TargetsMetadata>,
    binaries: Option<SignedMetadata<TargetsMetadata>>,
    signer: SigningKeypair,
}

fn check(cond: bool, msg: &str) -> TestResult {
    if !cond {
        return Err(msg.into());
    }
    Ok(())
}

fn unique_test_dir(prefix: &str) -> PathBuf {
    std::env::temp_dir().join(format!("{prefix}-{}", uuid::Uuid::now_v7()))
}

fn build_single_root_chain(
    kind: TufRootKind,
    target_path: &str,
    pack_kind: PackKind,
    target_version: &str,
    generation: u64,
    artifact_bytes: &[u8],
    now: jiff::Timestamp,
) -> Result<TufChainFixture, Box<dyn Error>> {
    let root_signer = SigningKeypair::generate()?;
    let role_signer = SigningKeypair::generate()?;
    let expires = now.checked_add(jiff::Span::new().seconds(86_400))?;

    let mut keys: BTreeMap<String, TrustedKeyInfo> = BTreeMap::new();
    keys.insert(root_signer.key_id().to_string(), root_signer.public_info());
    keys.insert(role_signer.key_id().to_string(), role_signer.public_info());

    let mut roles = BTreeMap::new();
    let role_key_list = vec![role_signer.key_id().to_string()];
    roles.insert(
        TufRole::Root,
        RootKeyRole {
            key_ids: vec![root_signer.key_id().to_string()],
            threshold: 1,
        },
    );
    for r in [TufRole::Timestamp, TufRole::Snapshot, TufRole::Targets] {
        roles.insert(
            r,
            RootKeyRole {
                key_ids: role_key_list.clone(),
                threshold: 1,
            },
        );
    }
    if kind == TufRootKind::Project {
        roles.insert(
            TufRole::Binaries,
            RootKeyRole {
                key_ids: role_key_list,
                threshold: 1,
            },
        );
    }

    let root_meta = RootMetadata {
        root_kind: kind,
        version: generation,
        expires,
        keys,
        roles,
    };
    let root = sign_metadata(root_meta, &[&root_signer])?;

    let mut snapshot_meta_map = BTreeMap::new();
    let (targets, binaries) = if pack_kind == PackKind::Binary {
        let top_targets = sign_metadata(
            TargetsMetadata {
                role: TufRole::Targets,
                version: generation,
                expires,
                targets: BTreeMap::new(),
            },
            &[&role_signer],
        )?;
        let top_bytes = serde_json::to_vec(&top_targets.signed)?;
        snapshot_meta_map.insert(
            TufRole::Targets,
            SnapshotTargetRef {
                version: generation,
                sha256: canonical_sha256(&top_bytes),
                length: u64::try_from(top_bytes.len()).unwrap_or(0),
            },
        );

        let mut bin_entries = BTreeMap::new();
        bin_entries.insert(
            target_path.to_string(),
            TargetDescriptor {
                pack_kind: PackKind::Binary,
                role: TufRole::Binaries,
                signer_class: SignerClass::ProjectBinaries,
                version: target_version.to_string(),
                sha256: canonical_sha256(artifact_bytes),
                length: u64::try_from(artifact_bytes.len()).unwrap_or(0),
                generation,
            },
        );
        let bin_targets = sign_metadata(
            TargetsMetadata {
                role: TufRole::Binaries,
                version: generation,
                expires,
                targets: bin_entries,
            },
            &[&role_signer],
        )?;
        let bin_bytes = serde_json::to_vec(&bin_targets.signed)?;
        snapshot_meta_map.insert(
            TufRole::Binaries,
            SnapshotTargetRef {
                version: generation,
                sha256: canonical_sha256(&bin_bytes),
                length: u64::try_from(bin_bytes.len()).unwrap_or(0),
            },
        );
        (top_targets, Some(bin_targets))
    } else {
        let signer_class = match kind {
            TufRootKind::Project => SignerClass::ProjectContent,
            TufRootKind::Deployment => SignerClass::Deployment,
        };
        let mut entries = BTreeMap::new();
        entries.insert(
            target_path.to_string(),
            TargetDescriptor {
                pack_kind,
                role: TufRole::Targets,
                signer_class,
                version: target_version.to_string(),
                sha256: canonical_sha256(artifact_bytes),
                length: u64::try_from(artifact_bytes.len()).unwrap_or(0),
                generation,
            },
        );
        let t = sign_metadata(
            TargetsMetadata {
                role: TufRole::Targets,
                version: generation,
                expires,
                targets: entries,
            },
            &[&role_signer],
        )?;
        let t_bytes = serde_json::to_vec(&t.signed)?;
        snapshot_meta_map.insert(
            TufRole::Targets,
            SnapshotTargetRef {
                version: generation,
                sha256: canonical_sha256(&t_bytes),
                length: u64::try_from(t_bytes.len()).unwrap_or(0),
            },
        );
        (t, None)
    };

    let snapshot_meta = SnapshotMetadata {
        version: generation,
        expires,
        meta: snapshot_meta_map,
    };
    let snapshot = sign_metadata(snapshot_meta, &[&role_signer])?;

    let snap_bytes = serde_json::to_vec(&snapshot.signed)?;
    let ts_meta = TimestampMetadata {
        version: generation,
        expires,
        snapshot: SnapshotTargetRef {
            version: generation,
            sha256: canonical_sha256(&snap_bytes),
            length: u64::try_from(snap_bytes.len()).unwrap_or(0),
        },
    };
    let timestamp = sign_metadata(ts_meta, &[&role_signer])?;

    Ok(TufChainFixture {
        root,
        timestamp,
        snapshot,
        targets,
        binaries,
        signer: role_signer,
    })
}

fn sign_target_dsse(
    target_path: &str,
    bytes: &[u8],
    signer: &SigningKeypair,
) -> Result<grdr_update::DsseEnvelope, Box<dyn Error>> {
    let statement = DsseTargetStatement {
        target_path: target_path.to_string(),
        sha256: canonical_sha256(bytes),
        length: u64::try_from(bytes.len()).unwrap_or(0),
    };
    let statement_bytes = serde_json::to_vec(&statement)?;
    Ok(sign_dsse_envelope(
        "application/vnd.guardrails.tuf-target+json",
        &statement_bytes,
        &[signer],
    )?)
}

#[test]
fn verifier_enforces_p7_purity_delta_fallback_and_compat_range() {
    let res = run_verifier_tests();
    assert!(res.is_ok(), "updater test failed");
}

fn run_verifier_tests() -> TestResult {
    let clean = br#"{"schemaVersion":1,"rules":[{"id":"deny-rm","action":"block"}]}"#;
    enforce_p7_json_purity("schema-policy", clean)?;

    for non_obj in [br#"[1, 2]"#.as_slice(), br#""command""#.as_slice(), b"true"] {
        check(
            matches!(
                enforce_p7_json_purity("schema-policy", non_obj),
                Err(UpdaterError::TufVerification { .. })
            ),
            "non-object JSON pack must fail P7",
        )?;
    }
    for key in [
        "command",
        "cmd",
        "args",
        "argv",
        "shell",
        "script",
        "exec",
        "executable",
        "executable_path",
        "binary",
        "url",
        "uri",
        "endpoint",
        "webhook",
        "env",
        "environment",
        "env_vars",
        "mcp_server",
        "mcp_servers",
        "stdio",
    ] {
        let dirty = format!(r#"{{"rules":[{{"{key}":"malicious"}}]}}"#);
        let err = enforce_p7_json_purity("schema-policy", dirty.as_bytes());
        check(
            matches!(err, Err(UpdaterError::ForbiddenField { .. })),
            "P7 forbidden key must be rejected",
        )?;
    }

    let base = b"AAAA-BASE-BINARY-CONTENT-ZZZZ";
    let target_expected = b"AAAA-PATCHED-CONTENT-ZZZZ";
    let delta_ok = DeltaPackage {
        target_path: "bin/grdrd".to_string(),
        base_sha256: canonical_sha256(base),
        expected_target_sha256: canonical_sha256(target_expected),
        operations: vec![
            DeltaOp::CopyBase { offset: 0, len: 5 },
            DeltaOp::Insert {
                data: b"PATCHED".to_vec(),
            },
            DeltaOp::CopyBase {
                offset: 16,
                len: 13,
            },
        ],
    };
    let rebuilt = reconstruct_delta_or_request_full(base, &delta_ok, 1024)?;
    check(
        rebuilt == target_expected,
        "valid delta must reconstruct identically",
    )?;

    let mut bad_delta = delta_ok;
    bad_delta.expected_target_sha256 = canonical_sha256(b"corrupted");
    check(
        matches!(
            reconstruct_delta_or_request_full(base, &bad_delta, 1024),
            Err(UpdaterError::DeltaFallbackRequired { .. })
        ),
        "corrupt delta must request full fallback",
    )?;

    let now = jiff::Timestamp::from_second(1_760_000_000)?;
    let clock = ManualClock::new(now, std::time::Duration::from_secs(100));
    let matrix = CompatMatrix::default_v1();
    let (sample_component, sample_caps) = matrix
        .entries
        .first()
        .map(|entry| (entry.component.clone(), entry.required_capabilities.clone()))
        .unwrap_or_else(|| {
            (
                "grdr-daemon".to_string(),
                vec![ProtocolCapability::SignedReceipts],
            )
        });

    let good_pack = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 1,
        "components": [{ "component": sample_component, "version": SemVer::new(0, 1, 0) }],
        "requiredCapabilities": sample_caps,
        "rules": []
    }))?;
    let bin = b"bin-v2";
    let proj = build_single_root_chain(
        TufRootKind::Project,
        "bin/grdrd",
        PackKind::Binary,
        "0.2.0",
        2,
        bin,
        now,
    )?;
    let dep = build_single_root_chain(
        TufRootKind::Deployment,
        "packs/agent-config.json",
        PackKind::AgentConfig,
        "0.2.0",
        2,
        &good_pack,
        now,
    )?;

    let mut verifier = DualRootVerifier::new(proj.root, Some(dep.root), &clock)?;
    let dsse = sign_target_dsse("packs/agent-config.json", &good_pack, &dep.signer)?;
    let bin_dsse = sign_target_dsse("bin/grdrd", bin, &proj.signer)?;

    let missing_bins = verifier.verify_bundle(
        &StagedUpdateBundle {
            root_kind: TufRootKind::Project,
            pack_kind: PackKind::Binary,
            channel: "binary",
            target_path: "bin/grdrd",
            component_name: &sample_component,
            snapshot_published_unix_s: now.as_second(),
            artifact_bytes: bin,
            timestamp: &proj.timestamp,
            snapshot: &proj.snapshot,
            targets: &proj.targets,
            binaries_targets: None,
            freshness: None,
            dsse_envelope: &bin_dsse,
            compat_matrix: &matrix,
        },
        now,
    );
    check(
        matches!(missing_bins, Err(UpdaterError::TufVerification { .. })),
        "PackKind::Binary without TufRole::Binaries must fail closed",
    )?;

    let bad_path = verifier.verify_bundle(
        &StagedUpdateBundle {
            root_kind: TufRootKind::Project,
            pack_kind: PackKind::Binary,
            channel: "binary",
            target_path: "../bin/grdrd",
            component_name: &sample_component,
            snapshot_published_unix_s: now.as_second(),
            artifact_bytes: bin,
            timestamp: &proj.timestamp,
            snapshot: &proj.snapshot,
            targets: &proj.targets,
            binaries_targets: proj.binaries.as_ref(),
            freshness: None,
            dsse_envelope: &bin_dsse,
            compat_matrix: &matrix,
        },
        now,
    );
    check(
        matches!(bad_path, Err(UpdaterError::PathUnsafe { .. })),
        "unsafe target_path traversal must fail",
    )?;

    let verified_bin = verifier.verify_bundle(
        &StagedUpdateBundle {
            root_kind: TufRootKind::Project,
            pack_kind: PackKind::Binary,
            channel: "binary",
            target_path: "bin/grdrd",
            component_name: &sample_component,
            snapshot_published_unix_s: now.as_second(),
            artifact_bytes: bin,
            timestamp: &proj.timestamp,
            snapshot: &proj.snapshot,
            targets: &proj.targets,
            binaries_targets: proj.binaries.as_ref(),
            freshness: None,
            dsse_envelope: &bin_dsse,
            compat_matrix: &matrix,
        },
        now,
    )?;
    check(
        verified_bin.generation() == 2,
        "verified binary gen mismatch",
    )?;

    let verified_pack = verifier.verify_bundle(
        &StagedUpdateBundle {
            root_kind: TufRootKind::Deployment,
            pack_kind: PackKind::AgentConfig,
            channel: "agent-config",
            target_path: "packs/agent-config.json",
            component_name: &sample_component,
            snapshot_published_unix_s: now.as_second().saturating_sub(300),
            artifact_bytes: &good_pack,
            timestamp: &dep.timestamp,
            snapshot: &dep.snapshot,
            targets: &dep.targets,
            binaries_targets: None,
            freshness: None,
            dsse_envelope: &dsse,
            compat_matrix: &matrix,
        },
        now,
    )?;
    check(
        verified_pack.cdn_status() == CdnFreshnessStatus::ToleratedCdnLag { lag_s: 300 },
        "verified pack CDN lag status mismatch",
    )?;

    let bad_compat_pack = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 1,
        "components": [{ "component": sample_component, "version": SemVer::new(99, 0, 0) }],
        "requiredCapabilities": sample_caps,
        "rules": []
    }))?;
    let dep_bad_compat = build_single_root_chain(
        TufRootKind::Deployment,
        "packs/agent-config.json",
        PackKind::AgentConfig,
        "99.0.0",
        3,
        &bad_compat_pack,
        now,
    )?;
    let bad_dsse = sign_target_dsse(
        "packs/agent-config.json",
        &bad_compat_pack,
        &dep_bad_compat.signer,
    )?;
    let mut verifier_bad_compat = DualRootVerifier::with_timestamp(
        build_single_root_chain(
            TufRootKind::Project,
            "bin/grdrd",
            PackKind::Binary,
            "0.2.0",
            2,
            bin,
            now,
        )?
        .root,
        Some(dep_bad_compat.root),
        now,
    )?;
    check(
        matches!(
            verifier_bad_compat.verify_bundle(
                &StagedUpdateBundle {
                    root_kind: TufRootKind::Deployment,
                    pack_kind: PackKind::AgentConfig,
                    channel: "agent-config",
                    target_path: "packs/agent-config.json",
                    component_name: &sample_component,
                    snapshot_published_unix_s: now.as_second(),
                    artifact_bytes: &bad_compat_pack,
                    timestamp: &dep_bad_compat.timestamp,
                    snapshot: &dep_bad_compat.snapshot,
                    targets: &dep_bad_compat.targets,
                    binaries_targets: None,
                    freshness: None,
                    dsse_envelope: &bad_dsse,
                    compat_matrix: &matrix,
                },
                now,
            ),
            Err(UpdaterError::CompatibilityRejected { .. })
        ),
        "signed pack incompatible component version must fail before activation",
    )?;

    let bad_bin_proj = build_single_root_chain(
        TufRootKind::Project,
        "bin/grdrd",
        PackKind::Binary,
        "0.0.1",
        3,
        bin,
        now,
    )?;
    let bad_bin_dsse = sign_target_dsse("bin/grdrd", bin, &bad_bin_proj.signer)?;
    let mut bad_bin_verifier = DualRootVerifier::with_timestamp(bad_bin_proj.root, None, now)?;
    check(
        matches!(
            bad_bin_verifier.verify_bundle(
                &StagedUpdateBundle {
                    root_kind: TufRootKind::Project,
                    pack_kind: PackKind::Binary,
                    channel: "binary",
                    target_path: "bin/grdrd",
                    component_name: &sample_component,
                    snapshot_published_unix_s: now.as_second(),
                    artifact_bytes: bin,
                    timestamp: &bad_bin_proj.timestamp,
                    snapshot: &bad_bin_proj.snapshot,
                    targets: &bad_bin_proj.targets,
                    binaries_targets: bad_bin_proj.binaries.as_ref(),
                    freshness: None,
                    dsse_envelope: &bad_bin_dsse,
                    compat_matrix: &matrix,
                },
                now,
            ),
            Err(UpdaterError::CompatibilityRejected { .. })
        ),
        "PackKind::Binary incompatible version must fail compatibility gate",
    )?;

    let restricted_proj = build_single_root_chain(
        TufRootKind::Project,
        "bin/grdrd",
        PackKind::Binary,
        "0.2.0",
        2,
        bin,
        now,
    )?;
    let restricted_dsse = sign_target_dsse("bin/grdrd", bin, &restricted_proj.signer)?;
    let mut restricted_verifier =
        DualRootVerifier::with_timestamp(restricted_proj.root, None, now)?
            .with_host_capabilities(vec![ProtocolCapability::SignedReceipts]);
    check(
        matches!(
            restricted_verifier.verify_bundle(
                &StagedUpdateBundle {
                    root_kind: TufRootKind::Project,
                    pack_kind: PackKind::Binary,
                    channel: "binary",
                    target_path: "bin/grdrd",
                    component_name: &sample_component,
                    snapshot_published_unix_s: now.as_second(),
                    artifact_bytes: bin,
                    timestamp: &restricted_proj.timestamp,
                    snapshot: &restricted_proj.snapshot,
                    targets: &restricted_proj.targets,
                    binaries_targets: restricted_proj.binaries.as_ref(),
                    freshness: None,
                    dsse_envelope: &restricted_dsse,
                    compat_matrix: &matrix,
                },
                now,
            ),
            Err(UpdaterError::CompatibilityRejected { .. })
        ),
        "host missing required matrix capability must fail PackKind::Binary",
    )?;

    let dsse_bounded_proj = build_single_root_chain(
        TufRootKind::Project,
        "bin/grdrd",
        PackKind::Binary,
        "0.2.0",
        2,
        bin,
        now,
    )?;
    let dsse_bounded_env = sign_target_dsse("bin/grdrd", bin, &dsse_bounded_proj.signer)?;
    let mut dsse_bounded_verifier =
        DualRootVerifier::with_timestamp(dsse_bounded_proj.root, None, now)?.with_dsse_limits(
            grdr_update::DsseLimits {
                max_payload_bytes: 16,
            },
        );
    check(
        matches!(
            dsse_bounded_verifier.verify_bundle(
                &StagedUpdateBundle {
                    root_kind: TufRootKind::Project,
                    pack_kind: PackKind::Binary,
                    channel: "binary",
                    target_path: "bin/grdrd",
                    component_name: &sample_component,
                    snapshot_published_unix_s: now.as_second(),
                    artifact_bytes: bin,
                    timestamp: &dsse_bounded_proj.timestamp,
                    snapshot: &dsse_bounded_proj.snapshot,
                    targets: &dsse_bounded_proj.targets,
                    binaries_targets: dsse_bounded_proj.binaries.as_ref(),
                    freshness: None,
                    dsse_envelope: &dsse_bounded_env,
                    compat_matrix: &matrix,
                },
                now,
            ),
            Err(UpdaterError::TufVerification { .. })
        ),
        "strict dsse_limits must bound DSSE payload before TUF verification",
    )?;

    check(
        matches!(
            verifier.assess_cdn_lag(1_760_000_000 - 90_000, 1_760_000_000),
            Err(UpdaterError::StaleOrRollback { .. })
        ),
        "lag beyond 24h must fail closed",
    )
}

#[test]
fn ab_slot_rollback_security_floor_authority_and_2s_handover() {
    let res = run_slots_and_handover_tests();
    assert!(res.is_ok(), "updater test failed");
}

fn verify_signed_binary_fixture(
    version: &str,
    generation: u64,
    bytes: &[u8],
    now: jiff::Timestamp,
) -> Result<grdr_updater::verify::VerifiedUpdateArtifact, Box<dyn Error>> {
    let proj = build_single_root_chain(
        TufRootKind::Project,
        "bin/grdrd",
        PackKind::Binary,
        version,
        generation,
        bytes,
        now,
    )?;
    let bin_dsse = sign_target_dsse("bin/grdrd", bytes, &proj.signer)?;
    let mut verifier = DualRootVerifier::with_timestamp(proj.root, None, now)?;
    let matrix = CompatMatrix::default_v1();
    Ok(verifier.verify_bundle(
        &StagedUpdateBundle {
            root_kind: TufRootKind::Project,
            pack_kind: PackKind::Binary,
            channel: "binary",
            target_path: "bin/grdrd",
            component_name: "grdr-daemon",
            snapshot_published_unix_s: now.as_second(),
            artifact_bytes: bytes,
            timestamp: &proj.timestamp,
            snapshot: &proj.snapshot,
            targets: &proj.targets,
            binaries_targets: proj.binaries.as_ref(),
            freshness: None,
            dsse_envelope: &bin_dsse,
            compat_matrix: &matrix,
        },
        now,
    )?)
}

fn run_slots_and_handover_tests() -> TestResult {
    let now = jiff::Timestamp::from_second(1_760_000_000)?;
    let dir = unique_test_dir("grdr-updater-slots");
    let journal_signer = SigningKeypair::generate()?;
    let signer_seed = journal_signer.seed_b64();
    let v1 = b"binary-v1";
    let mut mgr = SlotActivationManager::open_or_init(
        dir.clone(),
        UpdateAuthority::SelfManaged,
        journal_signer,
        "0.1.0",
        1,
        canonical_sha256(v1),
    )?;
    check(
        mgr.active_slot().slot == UpdateSlot::SlotA,
        "must initialize on SlotA",
    )?;

    let v2 = b"binary-v2";
    let verified_v2 = verify_signed_binary_fixture("0.2.0", 2, v2, now)?;
    let slot_b = mgr.activate_verified_binary(&verified_v2, Some(2), now.as_second())?;
    check(slot_b.slot == UpdateSlot::SlotB, "must activate SlotB")?;
    check(
        mgr.security_floor() == 2,
        "security floor must advance to 2",
    )?;

    let verified_v1 = verify_signed_binary_fixture("0.1.0", 1, v1, now)?;
    check(
        matches!(
            mgr.activate_verified_binary(&verified_v1, None, now.as_second()),
            Err(UpdaterError::SecurityFloorViolation { .. })
        ),
        "downgrade below security floor must fail",
    )?;
    check(
        mgr.record_startup_crash("crash-1", now.as_second().saturating_add(10))?
            .is_none(),
        "crash 1 no revert",
    )?;
    check(
        mgr.record_startup_crash("crash-2", now.as_second().saturating_add(20))?
            .is_none(),
        "crash 2 no revert",
    )?;
    check(
        matches!(
            mgr.record_startup_crash("crash-3", now.as_second().saturating_add(30)),
            Err(UpdaterError::SecurityFloorViolation { .. })
        ),
        "revert below security floor must be blocked",
    )?;

    let v3 = b"binary-v3";
    let verified_v3 = verify_signed_binary_fixture("0.3.0", 3, v3, now)?;
    mgr.activate_verified_binary(&verified_v3, None, now.as_second().saturating_add(40))?;
    check(
        mgr.record_startup_crash("ntp-backwards", now.as_second().saturating_sub(100))?
            .is_none(),
        "NTP backward jump prior to stabilization start must not extend crash revert window",
    )?;
    check(
        mgr.record_startup_crash("crash-1", now.as_second().saturating_add(50))?
            .is_none(),
        "crash 1",
    )?;
    check(
        mgr.record_startup_crash("crash-2", now.as_second().saturating_add(60))?
            .is_none(),
        "crash 2",
    )?;
    let rolled = mgr
        .record_startup_crash("crash-3", now.as_second().saturating_add(70))?
        .ok_or("reverts cleanly to v2")?;
    check(rolled.version == "0.2.0", "rolled back slot mismatch")?;

    let wrong_signer = SigningKeypair::generate()?;
    check(
        matches!(
            SlotActivationManager::open_or_init(
                dir.clone(),
                UpdateAuthority::SelfManaged,
                wrong_signer,
                "0.1.0",
                1,
                canonical_sha256(v1),
            ),
            Err(UpdaterError::SlotTransitionInvalid { .. })
        ),
        "reopening signed journal with wrong key must fail",
    )?;
    check(
        matches!(
            SlotActivationManager::open_or_init(
                dir.clone(),
                UpdateAuthority::Image,
                SigningKeypair::from_seed_b64(&signer_seed)?,
                "0.1.0",
                1,
                canonical_sha256(v1),
            ),
            Err(UpdaterError::AuthorityDisallowed { .. })
        ),
        "authority mismatch against signed journal must fail",
    )?;

    let mut journal_bytes = std::fs::read(dir.join("slots.journal.json"))?;
    if let Some(first) = journal_bytes.first_mut() {
        *first = b' ';
    }
    let tampered_dir = unique_test_dir("grdr-updater-tampered");
    std::fs::create_dir_all(&tampered_dir)?;
    std::fs::write(tampered_dir.join("slots.journal.json"), &journal_bytes)?;
    check(
        matches!(
            SlotActivationManager::open_or_init(
                tampered_dir.clone(),
                UpdateAuthority::SelfManaged,
                SigningKeypair::from_seed_b64(&signer_seed)?,
                "0.1.0",
                1,
                canonical_sha256(v1),
            ),
            Err(UpdaterError::SlotTransitionInvalid { .. })
        ),
        "tampered signed journal must fail signature check",
    )?;

    let clock = ManualClock::new(now, std::time::Duration::from_secs(20));
    let handover = HandoverCoordinator::new(&dir);
    let bin_path = mgr.slot_binary_path(UpdateSlot::SlotB);
    let outside_dir = unique_test_dir("grdr-outside");
    std::fs::create_dir_all(&outside_dir)?;
    let outside_bin = outside_dir.join("evil.bin");
    atomic_write_bytes(&outside_bin, v2)?;
    check(
        matches!(
            handover.prepare_handover(
                UpdateSlot::SlotB,
                &outside_bin,
                &slot_b.sha256,
                DEFAULT_HANDOVER_WINDOW_MS,
                &clock,
            ),
            Err(UpdaterError::PathUnsafe { .. })
        ),
        "binary path escaping state_root must fail handover confinement",
    )?;

    let marker = handover.prepare_handover(
        UpdateSlot::SlotB,
        &bin_path,
        &slot_b.sha256,
        DEFAULT_HANDOVER_WINDOW_MS,
        &clock,
    )?;
    check(
        marker
            .expires_mono_ms
            .saturating_sub(marker.created_mono_ms)
            == DEFAULT_HANDOVER_WINDOW_MS,
        "marker TTL mismatch",
    )?;
    let consumed = handover.validate_and_consume(&clock)?;
    check(consumed.target_slot == UpdateSlot::SlotB, "slot mismatch")?;

    let reboot_clock = ManualClock::new(
        now.checked_add(jiff::Span::new().seconds(10))?,
        std::time::Duration::from_millis(500),
    );
    handover.prepare_handover(
        UpdateSlot::SlotB,
        &bin_path,
        &slot_b.sha256,
        DEFAULT_HANDOVER_WINDOW_MS,
        &clock,
    )?;
    check(
        matches!(
            handover.validate_and_consume(&reboot_clock),
            Err(UpdaterError::HandoverInvalid { .. })
        ),
        "post-reboot monotonic reset must invalidate pre-reboot marker",
    )?;

    let managed_dir = unique_test_dir("grdr-updater-managed");
    let mut managed = SlotActivationManager::open_or_init(
        managed_dir.clone(),
        UpdateAuthority::Managed,
        SigningKeypair::generate()?,
        "0.2.0",
        2,
        canonical_sha256(v2),
    )?;
    check(
        matches!(
            managed.activate_verified_binary(&verified_v3, None, now.as_second()),
            Err(UpdaterError::AuthorityDisallowed { .. })
        ),
        "Managed mode must refuse binary slot writes",
    )?;

    let pack_bytes = br#"{"schemaVersion":1,"rules":[]}"#;
    let dep = build_single_root_chain(
        TufRootKind::Deployment,
        "packs/policy.json",
        PackKind::AgentConfig,
        "1.0.0",
        5,
        pack_bytes,
        now,
    )?;
    let dep_dsse = sign_target_dsse("packs/policy.json", pack_bytes, &dep.signer)?;
    let mut dep_verifier = DualRootVerifier::with_timestamp(
        build_single_root_chain(
            TufRootKind::Project,
            "bin/grdrd",
            PackKind::Binary,
            "0.2.0",
            2,
            v2,
            now,
        )?
        .root,
        Some(dep.root.clone()),
        now,
    )?;
    let matrix = CompatMatrix::default_v1();
    let verified_pack = dep_verifier.verify_bundle(
        &StagedUpdateBundle {
            root_kind: TufRootKind::Deployment,
            pack_kind: PackKind::AgentConfig,
            channel: "schema-policy",
            target_path: "packs/policy.json",
            component_name: "grdr-daemon",
            snapshot_published_unix_s: now.as_second(),
            artifact_bytes: pack_bytes,
            timestamp: &dep.timestamp,
            snapshot: &dep.snapshot,
            targets: &dep.targets,
            binaries_targets: None,
            freshness: None,
            dsse_envelope: &dep_dsse,
            compat_matrix: &matrix,
        },
        now,
    )?;
    let pack_rec = managed.activate_verified_pack(&verified_pack)?;
    check(pack_rec.active_generation == 5, "pack gen mismatch")?;

    let mut restricted_dep_verifier = DualRootVerifier::with_timestamp(
        build_single_root_chain(
            TufRootKind::Project,
            "bin/grdrd",
            PackKind::Binary,
            "0.2.0",
            2,
            v2,
            now,
        )?
        .root,
        Some(dep.root),
        now,
    )?
    .with_host_capabilities(vec![ProtocolCapability::SignedReceipts]);
    check(
        matches!(
            restricted_dep_verifier.verify_bundle(
                &StagedUpdateBundle {
                    root_kind: TufRootKind::Deployment,
                    pack_kind: PackKind::AgentConfig,
                    channel: "schema-policy",
                    target_path: "packs/policy.json",
                    component_name: "grdr-daemon",
                    snapshot_published_unix_s: now.as_second(),
                    artifact_bytes: pack_bytes,
                    timestamp: &dep.timestamp,
                    snapshot: &dep.snapshot,
                    targets: &dep.targets,
                    binaries_targets: None,
                    freshness: None,
                    dsse_envelope: &dep_dsse,
                    compat_matrix: &matrix,
                },
                now,
            ),
            Err(UpdaterError::CompatibilityRejected { .. })
        ),
        "non-binary pack without components field must still check host capabilities",
    )?;

    let ext_bin = managed_dir.join("external_grdrd");
    atomic_write_bytes(&ext_bin, b"tampered-binary")?;
    check(
        matches!(
            managed.verify_managed_binary_integrity(&ext_bin, &canonical_sha256(v2))?,
            BinaryIntegrityOutcome::ExternalBinaryTamperDetected { .. }
        ),
        "external binary tamper must be surfaced",
    )?;

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&tampered_dir);
    let _ = std::fs::remove_dir_all(&outside_dir);
    let _ = std::fs::remove_dir_all(&managed_dir);
    Ok(())
}
