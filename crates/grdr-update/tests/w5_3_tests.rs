// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use grdr_crypto::{SigningKeypair, constant_time_eq, domain_sha256_digest};
use grdr_model::TrustedKeyInfo;
use grdr_update::{
    AdmissionDecision, CeremonyIdentityConfig, CohortTelemetrySnapshot, DualSignedPayload,
    FailClosedPqBackend, FipsMode, FipsSelfTestState, HaltReason, HandshakeContractOffer,
    HandshakePolicy, HandshakeResolution, HostOsProfile, KatOutcome, LatencyDdSketch,
    ML_DSA_65_PUBKEY_BYTES, ML_DSA_65_SIG_BYTES, MirrorExportKind, OperatorResumeStatement,
    PackKind, PqPolicyActivation, PqPublicKeyRecord, PqSignatureEntry, PqVerifierBackend,
    ReleasePublishStatus, ResumeAuthorization, RollbackTargetKind, RolloutCoordinator,
    RolloutGatePolicy, RolloutPhase, RolloutScope, RootKeyRole, RootMetadata, SignatureAlgorithm,
    SignerClass, SnapshotMetadata, SnapshotTargetRef, TargetDescriptor, TargetsMetadata, TufRole,
    TufRootKind, UpdateError, YankReason, admit_device_at, canonical_sha256, default_canary_rings,
    evaluate_mirror_convergence, evaluate_mirror_convergence_scoped, evaluate_offer_handshake,
    issue_freshness_vouch, plan_mirror_export, run_deployment_root_ceremony,
    run_fips_startup_self_test, run_project_root_ceremony, sign_metadata,
    verify_dual_signed_payload,
};
use jiff::Timestamp;

struct TestMockPqBackend;

impl PqVerifierBackend for TestMockPqBackend {
    fn verify_ml_dsa_65(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), UpdateError> {
        let expected = domain_sha256_digest("test.pq.mldsa65", &[public_key, message].concat());
        let prefix = signature
            .get(..32)
            .ok_or_else(|| UpdateError::InvalidSignature("missing prefix".into()))?;
        if !constant_time_eq(prefix, &expected) {
            return Err(UpdateError::InvalidSignature("pq mock mismatch".into()));
        }
        Ok(())
    }
}

fn mock_pq_sig(keyid: &str, pk: &[u8], msg: &[u8]) -> PqSignatureEntry {
    let tag = domain_sha256_digest("test.pq.mldsa65", &[pk, msg].concat());
    let mut sig = vec![0x41u8; ML_DSA_65_SIG_BYTES];
    for (d, s) in sig.iter_mut().zip(tag.iter()) {
        *d = *s;
    }
    PqSignatureEntry {
        keyid: keyid.to_owned(),
        algorithm: SignatureAlgorithm::MlDsa65,
        sig_b64: B64.encode(sig),
        pubkey_sha256: canonical_sha256(pk),
    }
}

fn ts(sec: i64) -> Timestamp {
    Timestamp::from_second(sec).unwrap_or(Timestamp::UNIX_EPOCH)
}

fn check(cond: bool, msg: &str) -> Result<(), Box<dyn Error>> {
    if !cond {
        return Err(msg.into());
    }
    Ok(())
}

#[test]
fn rollout_ddsketch_gates_halt_rollback_manual_resume_and_admission_ramp() {
    let res = run_rollout_test();
    assert!(res.is_ok(), "{res:?}");
}

#[test]
fn ceremony_freshness_vouch_and_mirror_export_enforce_constraints() {
    let res = run_ceremony_mirror_test();
    assert!(res.is_ok(), "{res:?}");
}

#[test]
fn fips_self_test_pq_dual_root_and_handshake_p99_checks() {
    let res = run_fips_pq_test();
    assert!(res.is_ok(), "{res:?}");
}

fn run_rollout_test() -> Result<(), Box<dyn Error>> {
    let now = ts(1_750_000_000);
    let expires = ts(now.as_second().saturating_add(86_400 * 30));

    let bogus_sketch = LatencyDdSketch {
        total_count: 1,
        min_us: 10,
        max_us: 100,
        buckets: BTreeMap::from([(i32::MAX, 1)]),
    };
    check(
        matches!(
            bogus_sketch.validate(),
            Err(UpdateError::MalformedMetadata(_))
        ),
        "unbounded deserialized ddsketch bucket must fail validation",
    )?;
    let _ = bogus_sketch.quantile_us(9_900);

    let mut coord = RolloutCoordinator::new_for_scope(
        RolloutScope::Deployment,
        "rel-2.1.0",
        5,
        4,
        default_canary_rings(),
        RolloutGatePolicy::default(),
    )?;
    coord.start_ring(0, now)?;

    let mut shard_a = LatencyDdSketch::new();
    let mut shard_b = LatencyDdSketch::new();
    for _ in 0..90 {
        shard_a.record_us(800)?;
        shard_b.record_us(1_100)?;
    }
    shard_a.record_us(12_000)?;
    let mut merged = shard_a.clone();
    merged.merge(&shard_b)?;
    check(merged.total_count == 181, "merged total count")?;
    check(merged.quantile_us(9_900) <= 5_000, "p99 bound")?;

    let healthy = CohortTelemetrySnapshot {
        baseline_crash_free_bps: 9_995,
        cohort_crash_free_bps: 9_993,
        checkin_loss_bps: 20,
        baseline_cpu_milli: 200,
        cohort_cpu_milli: 220,
        baseline_mem_mib: 100,
        cohort_mem_mib: 110,
        baseline_deny_bps: 10,
        cohort_deny_bps: 20,
        baseline_events_per_min: 1_000,
        cohort_events_per_min: 1_100,
        agent_start_failures: 0,
        hook_latency: merged,
    };
    let ok_verdict =
        coord.evaluate_cohort(&healthy, RollbackTargetKind::AgentConfigJournal, now)?;
    check(ok_verdict.admitted, "healthy cohort should admit")?;

    check(
        !coord.advance_ring_if_baked(ts(1_750_000_000 + 3600))?,
        "should not advance before bake window",
    )?;
    check(
        coord.advance_ring_if_baked(ts(1_750_000_000 + 12 * 3600))?,
        "should advance after bake window",
    )?;
    check(
        matches!(coord.phase, RolloutPhase::RingBaking { ring_index: 1, .. }),
        "ring 1 baking expected",
    )?;

    let mut bad_crash = healthy;
    bad_crash.agent_start_failures = 1;
    let halt_verdict =
        coord.evaluate_cohort(&bad_crash, RollbackTargetKind::AgentConfigJournal, now)?;
    check(
        !halt_verdict.admitted && halt_verdict.halt_reason == Some(HaltReason::AgentStartFailure),
        "expected agent-start halt",
    )?;
    let directive = halt_verdict.rollback.as_ref().ok_or("missing rollback")?;
    check(directive.revert_to_generation == 4, "revert target")?;
    check(matches!(coord.phase, RolloutPhase::Halted { .. }), "halted")?;

    check(
        matches!(
            coord.start_ring(1, ts(1_750_100_000)),
            Err(UpdateError::HaltedRelease(_))
        ),
        "auto restart blocked",
    )?;

    let fleet = SigningKeypair::generate()?;
    let dep = run_deployment_root_ceremony("c-op", "dep-42", &[&fleet], 1, expires, now)?;
    let resume_stmt = OperatorResumeStatement {
        release_id: "rel-2.1.0".into(),
        ring_index: 1,
        operator_id: "sre-1".into(),
        note: "root cause reverted".into(),
        issued_at: now,
        expires,
    };
    let signed_resume = sign_metadata(resume_stmt, &[&fleet])?;

    check(
        matches!(
            coord.resume_after_halt(
                ResumeAuthorization::OperatorApproval {
                    approval: signed_resume.clone(),
                },
                Some(&dep.signed_root.signed),
                now,
            ),
            Err(UpdateError::HaltedRelease(_))
        ),
        "cannot resume rollback_required halt before rollback applied",
    )?;
    coord.confirm_rollback_applied()?;

    let mut proj_coord = RolloutCoordinator::new(
        "rel-2.1.0",
        5,
        4,
        default_canary_rings(),
        RolloutGatePolicy::default(),
    )?;
    proj_coord.start_ring(1, now)?;
    let _ = proj_coord.evaluate_cohort(&bad_crash, RollbackTargetKind::BinarySlot, now)?;
    proj_coord.confirm_rollback_applied()?;
    check(
        matches!(
            proj_coord.resume_after_halt(
                ResumeAuthorization::OperatorApproval {
                    approval: signed_resume.clone(),
                },
                Some(&dep.signed_root.signed),
                now,
            ),
            Err(UpdateError::UnauthorizedRoot(_))
        ),
        "project-scoped halt must forbid OperatorApproval bypass",
    )?;

    coord.resume_after_halt(
        ResumeAuthorization::OperatorApproval {
            approval: signed_resume,
        },
        Some(&dep.signed_root.signed),
        now,
    )?;
    let active_plan = coord.to_signed_plan(now, 7_200, 10_000);
    let d1 = admit_device_at("device-alpha", &active_plan, true, "dep-42", now);
    check(
        matches!(d1, AdmissionDecision::Deferred { .. }),
        "self-hosted deferred",
    )?;
    let later = ts(now.as_second().saturating_add(75 * 3600));
    check(
        matches!(
            admit_device_at("device-alpha", &active_plan, true, "dep-42", later),
            AdmissionDecision::Admitted { .. }
        ),
        "admitted after 48h+24h+ramp",
    )?;

    let yank = coord.yank_release(
        "grdr.essentials",
        "2.1.0",
        "sha_bad",
        YankReason::Compromised,
        None,
        later,
    );
    check(yank.reason == YankReason::Compromised, "yank reason")?;
    let withdrawn_plan = coord.to_signed_plan(now, 7_200, 10_000);
    check(
        withdrawn_plan.publish_status == ReleasePublishStatus::Withdrawn,
        "withdrawn status",
    )?;
    Ok(())
}

fn run_ceremony_mirror_test() -> Result<(), Box<dyn Error>> {
    let now = ts(1_750_000_000);
    let expires = ts(1_781_536_000);
    let rel_signer = SigningKeypair::generate()?;
    let rebuilder = SigningKeypair::generate()?;
    let ops = SigningKeypair::generate()?;
    let rekor = SigningKeypair::generate()?;
    let tsa = SigningKeypair::generate()?;
    let fulcio_ca = SigningKeypair::generate()?;
    let id_cfg = CeremonyIdentityConfig::default();

    check(
        matches!(
            run_project_root_ceremony(
                "c-dup",
                &rel_signer,
                &rel_signer,
                &ops,
                &rekor,
                &tsa,
                &fulcio_ca,
                &id_cfg,
                expires,
                now
            ),
            Err(UpdateError::UnauthorizedRoot(_))
        ),
        "duplicate root ceremony signer rejected",
    )?;

    let proj = run_project_root_ceremony(
        "ceremony-2026",
        &rel_signer,
        &rebuilder,
        &ops,
        &rekor,
        &tsa,
        &fulcio_ca,
        &id_cfg,
        expires,
        now,
    )?;
    check(
        !proj.trusted_root.certificate_authorities.is_empty(),
        "ceremony must populate certificate_authorities",
    )?;
    check(proj.transcript.redaction_verified, "transcript redacted")?;
    let transcript_json = serde_json::to_string(&proj.transcript)?;
    check(
        !transcript_json.contains(&rel_signer.seed_b64())
            && !transcript_json.contains("PRIVATE KEY"),
        "no private keys in transcript",
    )?;

    let dep_k1 = SigningKeypair::generate()?;
    let dep_k2 = SigningKeypair::generate()?;
    let dep = run_deployment_root_ceremony(
        "dep-cer",
        "org-airgap",
        &[&dep_k1, &dep_k2],
        2,
        expires,
        now,
    )?;

    let mut targets_map = BTreeMap::new();
    targets_map.insert(
        "packs/essentials.json".into(),
        TargetDescriptor {
            role: TufRole::ContentPolicy,
            pack_kind: PackKind::SchemaPolicy,
            signer_class: SignerClass::ProjectContent,
            version: "1.0.0".into(),
            generation: 1,
            sha256: "unchanged-sha".into(),
            length: 42,
        },
    );
    targets_map.insert(
        "binaries/linux-amd64/grdr".into(),
        TargetDescriptor {
            role: TufRole::Binaries,
            pack_kind: PackKind::Binary,
            signer_class: SignerClass::ProjectBinaries,
            version: "1.0.1".into(),
            generation: 2,
            sha256: "new-bin-sha".into(),
            length: 100,
        },
    );
    targets_map.insert(
        "binaries/windows-amd64/grdr.exe".into(),
        TargetDescriptor {
            role: TufRole::Binaries,
            pack_kind: PackKind::Binary,
            signer_class: SignerClass::ProjectBinaries,
            version: "1.0.1".into(),
            generation: 2,
            sha256: "win-bin-sha".into(),
            length: 100,
        },
    );
    let targets = TargetsMetadata {
        role: TufRole::Targets,
        version: 2,
        expires,
        targets: targets_map,
    };
    let targets_bytes = serde_json::to_vec(&targets)?;
    let snap = SnapshotMetadata {
        version: 3,
        expires,
        meta: BTreeMap::from([(
            TufRole::Targets,
            SnapshotTargetRef {
                version: 2,
                sha256: canonical_sha256(&targets_bytes),
                length: u64::try_from(targets_bytes.len())?,
            },
        )]),
    };

    check(
        matches!(
            issue_freshness_vouch(
                &dep.signed_root.signed,
                &[&dep_k1],
                "org-airgap",
                1,
                &snap,
                now,
                now,
                ts(now.as_second().saturating_add(86_400)),
            ),
            Err(UpdateError::InvalidSignature(_))
        ),
        "threshold 2 enforced on vouch",
    )?;
    let vouch = issue_freshness_vouch(
        &dep.signed_root.signed,
        &[&dep_k1, &dep_k2],
        "org-airgap",
        1,
        &snap,
        now,
        now,
        ts(now.as_second().saturating_add(86_400)),
    )?;
    check(vouch.signed.project_snapshot_version == 3, "vouch version")?;

    let bases = BTreeSet::from(["known-base".to_owned()]);
    let base_digests = BTreeMap::from([
        ("packs/essentials.json".into(), "unchanged-sha".into()),
        (
            "binaries/windows-amd64/grdr.exe".into(),
            "win-bin-sha".into(),
        ),
    ]);
    check(
        matches!(
            plan_mirror_export(
                MirrorExportKind::Delta,
                Some("unknown-base"),
                &bases,
                Some(&base_digests),
                &snap,
                &targets,
                &[],
            ),
            Err(UpdateError::ArtifactIntegrity { .. })
        ),
        "unknown delta base refused",
    )?;
    let plan = plan_mirror_export(
        MirrorExportKind::Delta,
        Some("known-base"),
        &bases,
        Some(&base_digests),
        &snap,
        &targets,
        &[("tuf/root.json", 50)],
    )?;
    check(
        plan.included_paths == vec!["binaries/linux-amd64/grdr".to_owned()]
            && plan.skipped_unchanged_count == 2
            && plan.included_metadata_paths == vec!["tuf/root.json".to_owned()],
        "delta export must exclude unchanged targets and include metadata",
    )?;

    let incomplete = evaluate_mirror_convergence(&targets, &BTreeMap::new());
    check(!incomplete.fully_converged, "incomplete should be false")?;
    let linux_scoped = evaluate_mirror_convergence_scoped(
        &targets,
        &BTreeMap::from([
            ("packs/essentials.json".into(), "unchanged-sha".into()),
            ("binaries/linux-amd64/grdr".into(), "new-bin-sha".into()),
        ]),
        &["linux-amd64".to_owned()],
    );
    check(
        linux_scoped.fully_converged && linux_scoped.expected_count == 2,
        "scoped convergence must ignore unrequested platforms",
    )?;
    Ok(())
}

fn run_fips_pq_test() -> Result<(), Box<dyn Error>> {
    let now = ts(1_750_000_000);
    let linux_opt = run_fips_startup_self_test(HostOsProfile::Linux, FipsMode::Disabled, now)?;
    check(
        matches!(
            linux_opt.state,
            FipsSelfTestState::NotSupportedNoClaim { .. }
        ) && linux_opt
            .kat_checks
            .iter()
            .all(|c| c.outcome == KatOutcome::Passed)
            && linux_opt
                .sbom_properties
                .iter()
                .any(|p| p.value == "not-claimed-non-fips-build"),
        "non-FIPS pure-Rust build must not claim FIPS passed",
    )?;

    check(
        matches!(
            run_fips_startup_self_test(HostOsProfile::Linux, FipsMode::Required, now),
            Err(UpdateError::SecurityFloorViolation { .. })
        ),
        "FIPS required without active CMVP provider must fail closed",
    )?;
    check(
        matches!(
            run_fips_startup_self_test(HostOsProfile::MacOs, FipsMode::Required, now),
            Err(UpdateError::SecurityFloorViolation { .. })
        ),
        "macos required rejected",
    )?;

    let k1 = SigningKeypair::generate()?;
    let pq_pub = vec![0x7au8; ML_DSA_65_PUBKEY_BYTES];
    let pq_id = "pq-mldsa65-1".to_owned();
    let pq_rec = PqPublicKeyRecord {
        keyid: pq_id.clone(),
        algorithm: SignatureAlgorithm::MlDsa65,
        public_key_b64: B64.encode(&pq_pub),
        pubkey_sha256: canonical_sha256(&pq_pub),
    };
    let root = RootMetadata {
        root_kind: TufRootKind::Project,
        version: 1,
        expires: ts(1_780_000_000),
        keys: BTreeMap::from([(
            k1.key_id().to_owned(),
            TrustedKeyInfo {
                key_id: k1.key_id().to_owned(),
                public_key_b64: k1.public_key_b64(),
            },
        )]),
        roles: BTreeMap::from([
            (
                TufRole::Targets,
                RootKeyRole {
                    key_ids: vec![k1.key_id().to_owned()],
                    threshold: 1,
                },
            ),
            (
                TufRole::PostQuantum,
                RootKeyRole {
                    key_ids: vec![pq_id.clone()],
                    threshold: 1,
                },
            ),
        ]),
    };
    let targets = TargetsMetadata {
        role: TufRole::Targets,
        version: 1,
        expires: ts(1_780_000_000),
        targets: BTreeMap::new(),
    };
    let signed_classical = sign_metadata(targets, &[&k1])?;
    let raw_payload = serde_json::to_vec(&signed_classical.signed)?;
    let pq_sig = mock_pq_sig(&pq_id, &pq_pub, &raw_payload);
    let both = DualSignedPayload {
        classical: signed_classical,
        pq_signatures: vec![pq_sig],
    };
    check(
        matches!(
            verify_dual_signed_payload(
                &root,
                TufRole::Targets,
                PqPolicyActivation::HybridDualRequired,
                std::slice::from_ref(&pq_rec),
                &both,
                &FailClosedPqBackend,
            ),
            Err(UpdateError::InvalidSignature(_))
        ),
        "FailClosedPqBackend must fail closed under HybridDualRequired",
    )?;
    verify_dual_signed_payload(
        &root,
        TufRole::Targets,
        PqPolicyActivation::HybridDualRequired,
        &[pq_rec],
        &both,
        &TestMockPqBackend,
    )?;

    let policy = HandshakePolicy {
        server_major: 1,
        server_minor: 5,
        server_patch: 0,
        max_minor_behind: 2,
        max_minor_ahead: 1,
        expected_wire_major: 1,
        min_schema_rev: 2,
        required_contracts: vec!["bootstrap.v1".into()],
        retry_base_ms: 5_000,
        retry_jitter_ms: 2_000,
    };
    let ceiling_fail = HandshakeContractOffer {
        node_id: "node-9".into(),
        component: "grdr-daemon".into(),
        version_major: 1,
        version_minor: 4,
        version_patch: 0,
        sensor_ceiling: Some((1, 4, 9)),
        wire_major: 1,
        schema_rev: 2,
        contracts: vec!["bootstrap.v1".into()],
        capabilities: vec![
            "signed_receipts".into(),
            "session_labels".into(),
            "fastpath_floor".into(),
        ],
    };
    check(
        matches!(
            evaluate_offer_handshake(&ceiling_fail, &policy, now),
            HandshakeResolution::UpgradeRequired { .. }
        ),
        "sensor_ceiling below target requires upgrade",
    )?;

    let valid_offer = HandshakeContractOffer {
        sensor_ceiling: Some((1, 6, 0)),
        ..ceiling_fail
    };
    check(
        matches!(
            evaluate_offer_handshake(&valid_offer, &policy, now),
            HandshakeResolution::Admitted { .. }
        ),
        "valid offer admits",
    )?;
    Ok(())
}
