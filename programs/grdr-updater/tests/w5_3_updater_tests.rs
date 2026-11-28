// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;
use std::error::Error;

use grdr_compat::{CompatEntry, CompatMatrix, ProtocolCapability, SemVer, VersionRange};
use grdr_crypto::{SigningKeypair, constant_time_eq, domain_sha256_digest};
use grdr_model::api::TrustedKeyInfo;
use grdr_os_clock::ManualClock;
use grdr_update::{
    CohortTelemetrySnapshot, DualSignedPayload, FipsMode, FipsSelfTestState, HaltReason,
    HandshakeContractOffer, HandshakePolicy, HandshakeResolution, HostOsProfile, LatencyDdSketch,
    ML_DSA_65_PUBKEY_BYTES, ML_DSA_65_SIG_BYTES, PqPolicyActivation, PqPublicKeyRecord,
    PqSignatureEntry, PqVerifierBackend, RollbackTargetKind, RolloutCoordinator, RolloutGatePolicy,
    RootKeyRole, RootMetadata, SignatureAlgorithm, TargetsMetadata, TufRole, TufRootKind,
    UpdateError, canonical_sha256, default_canary_rings, sign_dsse_envelope, sign_metadata,
};
use grdr_updater::cohort_fips::{
    commit_agent_config_generation, enforce_fips_startup, evaluate_cohort_and_maybe_revert,
    negotiate_offer_with_matrix, verify_dual_root_payload, verify_dual_root_payload_with_backend,
};
use grdr_updater::compat_config::{
    COMPAT_MATRIX_DSSE_PAYLOAD_TYPE, SignedCompatMatrixPayload, load_support_toml_compat_matrix,
};
use grdr_updater::error::UpdaterError;
use grdr_updater::slots::UpdateAuthority;
use grdr_updater::worker::{UpdaterWorkerConfig, UpdaterWorkerState};
use grdr_wire::messages::UpdaterCommandFrame;
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
            return Err(UpdateError::InvalidSignature("mock PQ mismatch".into()));
        }
        Ok(())
    }
}

fn mk_test_pq_sig(keyid: &str, pk: &[u8], msg: &[u8]) -> PqSignatureEntry {
    let expected = domain_sha256_digest("test.pq.mldsa65", &[pk, msg].concat());
    let mut sig = vec![0x51u8; ML_DSA_65_SIG_BYTES];
    for (d, s) in sig.iter_mut().zip(expected.iter()) {
        *d = *s;
    }
    PqSignatureEntry {
        keyid: keyid.to_owned(),
        algorithm: SignatureAlgorithm::MlDsa65,
        sig_b64: encode_b64(&sig),
        pubkey_sha256: canonical_sha256(pk),
    }
}

fn ts(sec: i64) -> Timestamp {
    Timestamp::from_second(sec).unwrap_or(Timestamp::UNIX_EPOCH)
}

#[test]
fn agent_start_failure_triggers_halt_and_native_agent_config_journal_revert() {
    let res = run_agent_start_revert_test();
    assert!(res.is_ok(), "{res:?}");
}

#[test]
fn updater_enforces_fips_self_test_pq_dual_root_and_worker_handshake() {
    let res = run_fips_pq_handshake_test();
    assert!(res.is_ok(), "{res:?}");
}

fn check(cond: bool, msg: &str) -> Result<(), Box<dyn Error>> {
    if !cond {
        return Err(msg.into());
    }
    Ok(())
}

fn run_agent_start_revert_test() -> Result<(), Box<dyn Error>> {
    let base = std::env::temp_dir().join(format!("grdr-updater-w53-{}", uuid::Uuid::now_v7()));
    let _ = std::fs::remove_dir_all(&base);
    let signer = SigningKeypair::generate()?;
    let now = ts(1_750_000_000);

    let g1 = commit_agent_config_generation(&base, &signer, 1, b"agent-cfg-v1")?;
    check(g1.active_generation == 1, "gen 1 active")?;
    let g2 = commit_agent_config_generation(&base, &signer, 2, b"agent-cfg-v2")?;
    check(
        g2.active_generation == 2 && g2.previous_generation == Some(1),
        "gen 2 active",
    )?;

    let mut coord = RolloutCoordinator::new(
        "rel-cfg-2",
        2,
        1,
        default_canary_rings(),
        RolloutGatePolicy::default(),
    )?;
    coord.start_ring(0, now)?;

    let snap = CohortTelemetrySnapshot {
        baseline_crash_free_bps: 9_995,
        cohort_crash_free_bps: 9_995,
        checkin_loss_bps: 0,
        baseline_cpu_milli: 100,
        cohort_cpu_milli: 100,
        baseline_mem_mib: 100,
        cohort_mem_mib: 100,
        baseline_deny_bps: 0,
        cohort_deny_bps: 0,
        baseline_events_per_min: 500,
        cohort_events_per_min: 500,
        agent_start_failures: 1,
        hook_latency: LatencyDdSketch::new(),
    };

    let verdict = evaluate_cohort_and_maybe_revert(
        &base,
        &signer,
        &mut coord,
        &snap,
        RollbackTargetKind::AgentConfigJournal,
        now,
    )?;
    check(
        !verdict.admitted && verdict.halt_reason == Some(HaltReason::AgentStartFailure),
        "expected agent start halt",
    )?;

    // Re-applying the exact crashed/reverted payload at generation 2 or 3 must be refused.
    check(
        matches!(
            commit_agent_config_generation(&base, &signer, 2, b"agent-cfg-v2"),
            Err(UpdaterError::StaleOrRollback { .. })
        ),
        "crashed generation 2 must not re-apply",
    )?;
    check(
        matches!(
            commit_agent_config_generation(&base, &signer, 3, b"agent-cfg-v2"),
            Err(UpdaterError::StaleOrRollback { .. })
        ),
        "crashed payload must not re-apply even at bumped generation",
    )?;

    let g_next = commit_agent_config_generation(&base, &signer, 2, b"agent-cfg-v2-fixed")?;
    check(
        g_next.previous_generation == Some(1)
            && g_next.revert_count == 1
            && g_next.failed_configs.len() == 1,
        "journal revert history mismatch",
    )?;
    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

fn run_fips_pq_handshake_test() -> Result<(), Box<dyn Error>> {
    let now = ts(1_750_000_000);
    let win_opt = enforce_fips_startup(HostOsProfile::Windows, FipsMode::Disabled, now)?;
    check(
        matches!(win_opt.state, FipsSelfTestState::NotSupportedNoClaim { .. }),
        "non-FIPS build must report NotSupportedNoClaim honestly",
    )?;
    check(
        matches!(
            enforce_fips_startup(HostOsProfile::Windows, FipsMode::Required, now),
            Err(UpdaterError::SecurityFloorViolation { .. })
        ),
        "FIPS required without active CMVP module expected reject",
    )?;
    check(
        matches!(
            enforce_fips_startup(HostOsProfile::MacOs, FipsMode::Required, now),
            Err(UpdaterError::SecurityFloorViolation { .. })
        ),
        "macos fips required expected reject",
    )?;

    let k1 = SigningKeypair::generate()?;
    let pq_pub = vec![0x33u8; ML_DSA_65_PUBKEY_BYTES];
    let pq_id = "pq-root-1".to_owned();
    let pq_rec = PqPublicKeyRecord {
        keyid: pq_id.clone(),
        algorithm: SignatureAlgorithm::MlDsa65,
        public_key_b64: encode_b64(&pq_pub),
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
    let pq_sig = mk_test_pq_sig(&pq_id, &pq_pub, &raw_payload);
    let dual = DualSignedPayload {
        classical: signed_classical,
        pq_signatures: vec![pq_sig],
    };

    // Production verify_dual_root_payload must fail closed under HybridDualRequired without active FIPS 204 module.
    check(
        matches!(
            verify_dual_root_payload(
                &root,
                TufRole::Targets,
                PqPolicyActivation::HybridDualRequired,
                std::slice::from_ref(&pq_rec),
                &dual,
            ),
            Err(UpdaterError::TufVerification { .. })
        ),
        "production fail-closed PQ backend must reject HybridDualRequired",
    )?;
    verify_dual_root_payload_with_backend(
        &root,
        TufRole::Targets,
        PqPolicyActivation::HybridDualRequired,
        &[pq_rec],
        &dual,
        &TestMockPqBackend,
    )?;

    let matrix = CompatMatrix::default_v1();
    let policy = HandshakePolicy {
        server_major: 1,
        server_minor: 2,
        server_patch: 0,
        max_minor_behind: 2,
        max_minor_ahead: 1,
        expected_wire_major: 1,
        min_schema_rev: 1,
        required_contracts: vec!["bootstrap.v1".into()],
        retry_base_ms: 4_000,
        retry_jitter_ms: 1_000,
    };
    let offer_ok = HandshakeContractOffer {
        node_id: "node-1".into(),
        component: "grdr-daemon".into(),
        version_major: 1,
        version_minor: 0,
        version_patch: 0,
        sensor_ceiling: Some((1, 2, 0)),
        wire_major: 1,
        schema_rev: 1,
        contracts: vec!["bootstrap.v1".into()],
        capabilities: vec![
            "signed_receipts".into(),
            "session_labels".into(),
            "fastpath_floor".into(),
        ],
    };
    check(
        matches!(
            negotiate_offer_with_matrix(&offer_ok, &policy, &matrix, now)?,
            HandshakeResolution::Admitted { .. }
        ),
        "valid offer should admit",
    )?;
    let mut offer_missing_cap = offer_ok.clone();
    offer_missing_cap.capabilities = vec!["signed_receipts".into()];
    check(
        matches!(
            negotiate_offer_with_matrix(&offer_missing_cap, &policy, &matrix, now)?,
            HandshakeResolution::UpgradeRequired { .. }
        ),
        "offer missing required protocol capabilities must fail closed",
    )?;

    let base = std::env::temp_dir().join(format!("grdr-worker-w53-{}", uuid::Uuid::now_v7()));
    let _ = std::fs::remove_dir_all(&base);
    let clock = ManualClock::new(now, std::time::Duration::from_secs(10));
    let mut state = UpdaterWorkerState::open_with_config(
        base.clone(),
        UpdaterWorkerConfig {
            authority: UpdateAuthority::SelfManaged,
            project_root: None,
            deployment_root: None,
        },
        &clock,
    )?;

    let hs_bad = state.handle_command(
        &UpdaterCommandFrame {
            command_id: "hs-1".into(),
            action: "verify_handshake".into(),
            security_floor: 0,
            payload: serde_json::to_vec(&serde_json::json!({
                "offer": {
                    "node_id": "node-bad",
                    "component": "grdr-daemon",
                    "version_major": 1,
                    "version_minor": 0,
                    "version_patch": 0,
                    "sensor_ceiling": [1, 1, 0],
                    "wire_major": 1,
                    "schema_rev": 1,
                    "contracts": ["bootstrap.v1"]
                },
                "policy": policy
            }))?,
        },
        &clock,
    );
    check(
        !hs_bad.ok && hs_bad.error_code == "GRDR-UPDATER-0002",
        "bad handshake error code mismatch",
    )?;

    let fips_cmd = state.handle_command(
        &UpdaterCommandFrame {
            command_id: "fips-1".into(),
            action: "fips_self_test".into(),
            security_floor: 0,
            payload: serde_json::to_vec(&serde_json::json!({"fips_mode": "disabled"}))?,
        },
        &clock,
    );
    check(
        fips_cmd.ok && fips_cmd.detail.contains("not-claimed"),
        "worker fips disabled should honestly report non-claim",
    )?;
    let fips_req_cmd = state.handle_command(
        &UpdaterCommandFrame {
            command_id: "fips-2".into(),
            action: "fips_self_test".into(),
            security_floor: 0,
            payload: serde_json::to_vec(&serde_json::json!({"fips_mode": "required"}))?,
        },
        &clock,
    );
    check(!fips_req_cmd.ok, "worker fips required must fail closed")?;
    let fips_bad_json = state.handle_command(
        &UpdaterCommandFrame {
            command_id: "fips-3".into(),
            action: "fips_self_test".into(),
            security_floor: 0,
            payload: b"required-untyped".to_vec(),
        },
        &clock,
    );
    check(
        !fips_bad_json.ok,
        "worker fips untyped raw bytes must fail closed",
    )?;

    let cfg_matrix = load_support_toml_compat_matrix()?;
    check(
        cfg_matrix.protocol_version == SemVer::new(1, 0, 0)
            && cfg_matrix
                .entries
                .iter()
                .any(|e| e.component == "grdr-daemon"),
        "support.toml compatibility matrix did not resolve expected v1 daemon contract",
    )?;

    let custom_matrix = CompatMatrix {
        protocol_version: SemVer::new(1, 0, 0),
        entries: vec![CompatEntry {
            component: "grdr-daemon".into(),
            range: VersionRange {
                min_inclusive: SemVer::new(1, 1, 0),
                max_exclusive: Some(SemVer::new(2, 0, 0)),
            },
            required_capabilities: vec![ProtocolCapability::SignedReceipts],
        }],
    };
    let custom_bytes = serde_json::to_vec(&SignedCompatMatrixPayload {
        version: 2,
        expires: ts(1_780_000_000),
        matrix: custom_matrix.clone(),
    })?;
    let rollback_bytes = serde_json::to_vec(&SignedCompatMatrixPayload {
        version: 1,
        expires: ts(1_780_000_000),
        matrix: cfg_matrix.clone(),
    })?;
    let expired_bytes = serde_json::to_vec(&SignedCompatMatrixPayload {
        version: 3,
        expires: ts(1_740_000_000),
        matrix: cfg_matrix,
    })?;
    let worker_root_meta = RootMetadata {
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
        roles: [
            TufRole::Root,
            TufRole::Timestamp,
            TufRole::Snapshot,
            TufRole::Targets,
        ]
        .into_iter()
        .map(|role| {
            (
                role,
                RootKeyRole {
                    key_ids: vec![k1.key_id().to_owned()],
                    threshold: 1,
                },
            )
        })
        .collect(),
    };
    let signed_worker_root = sign_metadata(worker_root_meta, &[&k1])?;
    let signed_custom = sign_dsse_envelope(COMPAT_MATRIX_DSSE_PAYLOAD_TYPE, &custom_bytes, &[&k1])?;
    let signed_rollback =
        sign_dsse_envelope(COMPAT_MATRIX_DSSE_PAYLOAD_TYPE, &rollback_bytes, &[&k1])?;
    let signed_expired =
        sign_dsse_envelope(COMPAT_MATRIX_DSSE_PAYLOAD_TYPE, &expired_bytes, &[&k1])?;
    let rogue_kp = SigningKeypair::generate()?;
    let rogue_signed =
        sign_dsse_envelope(COMPAT_MATRIX_DSSE_PAYLOAD_TYPE, &custom_bytes, &[&rogue_kp])?;

    let signed_base =
        std::env::temp_dir().join(format!("grdr-worker-compat-{}", uuid::Uuid::now_v7()));
    let _ = std::fs::remove_dir_all(&signed_base);
    let mut signed_worker = UpdaterWorkerState::open_with_config(
        signed_base.clone(),
        UpdaterWorkerConfig {
            authority: UpdateAuthority::SelfManaged,
            project_root: Some(signed_worker_root.clone()),
            deployment_root: None,
        },
        &clock,
    )?;
    let rejected_old = signed_worker.handle_command(
        &UpdaterCommandFrame {
            command_id: "hs-signed-1".into(),
            action: "verify_handshake".into(),
            security_floor: 0,
            payload: serde_json::to_vec(&serde_json::json!({
                "offer": offer_ok,
                "policy": policy,
                "compat_matrix_dsse": signed_custom
            }))?,
        },
        &clock,
    );
    check(
        !rejected_old.ok,
        "signed compat matrix raising min_inclusive to 1.1.0 must reject 1.0.0 offer",
    )?;
    let rogue_rejected = signed_worker.handle_command(
        &UpdaterCommandFrame {
            command_id: "hs-signed-2".into(),
            action: "verify_handshake".into(),
            security_floor: 0,
            payload: serde_json::to_vec(&serde_json::json!({
                "offer": offer_ok,
                "policy": policy,
                "compat_matrix_dsse": rogue_signed
            }))?,
        },
        &clock,
    );
    check(
        !rogue_rejected.ok,
        "untrusted compat_matrix_dsse signer must fail closed",
    )?;
    let mut newer_offer = offer_ok.clone();
    newer_offer.version_minor = 1;
    let admitted_signed = signed_worker.handle_command(
        &UpdaterCommandFrame {
            command_id: "hs-signed-3".into(),
            action: "verify_handshake".into(),
            security_floor: 0,
            payload: serde_json::to_vec(&serde_json::json!({
                "offer": newer_offer,
                "policy": policy,
                "compat_matrix_dsse": signed_custom
            }))?,
        },
        &clock,
    );
    check(
        admitted_signed.ok,
        "signed compat matrix should admit 1.1.0 offer after persisting verified envelope",
    )?;
    let persisted_old_rejected = signed_worker.handle_command(
        &UpdaterCommandFrame {
            command_id: "hs-signed-4".into(),
            action: "verify_handshake".into(),
            security_floor: 0,
            payload: serde_json::to_vec(&serde_json::json!({
                "offer": offer_ok,
                "policy": policy
            }))?,
        },
        &clock,
    );
    check(
        !persisted_old_rejected.ok,
        "persisted compat-matrix.dsse.json must continue rejecting 1.0.0 offers",
    )?;
    let rollback_rejected = signed_worker.handle_command(
        &UpdaterCommandFrame {
            command_id: "hs-signed-5".into(),
            action: "verify_handshake".into(),
            security_floor: 0,
            payload: serde_json::to_vec(&serde_json::json!({
                "offer": offer_ok,
                "policy": policy,
                "compat_matrix_dsse": signed_rollback
            }))?,
        },
        &clock,
    );
    check(
        !rollback_rejected.ok,
        "older version compat_matrix_dsse must fail closed as rollback",
    )?;
    let expired_rejected = signed_worker.handle_command(
        &UpdaterCommandFrame {
            command_id: "hs-signed-6".into(),
            action: "verify_handshake".into(),
            security_floor: 0,
            payload: serde_json::to_vec(&serde_json::json!({
                "offer": newer_offer,
                "policy": policy,
                "compat_matrix_dsse": signed_expired
            }))?,
        },
        &clock,
    );
    check(
        !expired_rejected.ok,
        "expired compat_matrix_dsse must fail closed",
    )?;
    let mut missing_cap_newer = newer_offer;
    missing_cap_newer.capabilities = vec!["session_labels".into()];
    let missing_cap_rejected = signed_worker.handle_command(
        &UpdaterCommandFrame {
            command_id: "hs-signed-7".into(),
            action: "verify_handshake".into(),
            security_floor: 0,
            payload: serde_json::to_vec(&serde_json::json!({
                "offer": missing_cap_newer,
                "policy": policy
            }))?,
        },
        &clock,
    );
    check(
        !missing_cap_rejected.ok,
        "worker verify_handshake must reject client lacking required capability",
    )?;
    let _ = std::fs::remove_dir_all(&signed_base);

    // Seed expired persisted compat-matrix.dsse.json (version 2) and recover via newer valid override (version 3).
    let rec_base =
        std::env::temp_dir().join(format!("grdr-worker-compat-rec-{}", uuid::Uuid::now_v7()));
    let _ = std::fs::remove_dir_all(&rec_base);
    let mut rec_worker = UpdaterWorkerState::open_with_config(
        rec_base.clone(),
        UpdaterWorkerConfig {
            authority: UpdateAuthority::SelfManaged,
            project_root: Some(signed_worker_root),
            deployment_root: None,
        },
        &clock,
    )?;
    let expired_v2_bytes = serde_json::to_vec(&SignedCompatMatrixPayload {
        version: 2,
        expires: ts(1_740_000_000),
        matrix: custom_matrix.clone(),
    })?;
    let expired_v2_env =
        sign_dsse_envelope(COMPAT_MATRIX_DSSE_PAYLOAD_TYPE, &expired_v2_bytes, &[&k1])?;
    std::fs::write(
        rec_base.join("compat-matrix.dsse.json"),
        serde_json::to_vec_pretty(&expired_v2_env)?,
    )?;
    let stale_denied = rec_worker.handle_command(
        &UpdaterCommandFrame {
            command_id: "hs-rec-1".into(),
            action: "verify_handshake".into(),
            security_floor: 0,
            payload: serde_json::to_vec(&serde_json::json!({
                "offer": offer_ok,
                "policy": policy
            }))?,
        },
        &clock,
    );
    check(
        !stale_denied.ok,
        "expired persisted compat-matrix.dsse.json must fail closed without override",
    )?;
    let mut rec_offer = offer_ok.clone();
    rec_offer.version_minor = 1;
    let equal_v2_bytes = serde_json::to_vec(&SignedCompatMatrixPayload {
        version: 2,
        expires: ts(1_780_000_000),
        matrix: custom_matrix.clone(),
    })?;
    let equal_v2_env =
        sign_dsse_envelope(COMPAT_MATRIX_DSSE_PAYLOAD_TYPE, &equal_v2_bytes, &[&k1])?;
    let equal_v2_denied = rec_worker.handle_command(
        &UpdaterCommandFrame {
            command_id: "hs-rec-eq-v2".into(),
            action: "verify_handshake".into(),
            security_floor: 0,
            payload: serde_json::to_vec(&serde_json::json!({
                "offer": rec_offer,
                "policy": policy,
                "compat_matrix_dsse": equal_v2_env
            }))?,
        },
        &clock,
    );
    check(
        !equal_v2_denied.ok,
        "re-signed equal version (v2 == v2) override with modified expiry/payload must fail closed",
    )?;
    let recovery_v3_bytes = serde_json::to_vec(&SignedCompatMatrixPayload {
        version: 3,
        expires: ts(1_780_000_000),
        matrix: custom_matrix,
    })?;
    let recovery_v3_env =
        sign_dsse_envelope(COMPAT_MATRIX_DSSE_PAYLOAD_TYPE, &recovery_v3_bytes, &[&k1])?;
    let recovered_ok = rec_worker.handle_command(
        &UpdaterCommandFrame {
            command_id: "hs-rec-2".into(),
            action: "verify_handshake".into(),
            security_floor: 0,
            payload: serde_json::to_vec(&serde_json::json!({
                "offer": rec_offer,
                "policy": policy,
                "compat_matrix_dsse": recovery_v3_env
            }))?,
        },
        &clock,
    );
    check(
        recovered_ok.ok,
        "newer valid compat_matrix_dsse (v3) must recover cleanly past expired persisted v2",
    )?;
    let _ = std::fs::remove_dir_all(&rec_base);

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

fn encode_b64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk.first().copied().unwrap_or(0));
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(b64_char(TABLE, (n >> 18) & 0x3f));
        out.push(b64_char(TABLE, (n >> 12) & 0x3f));
        out.push(if chunk.len() > 1 {
            b64_char(TABLE, (n >> 6) & 0x3f)
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            b64_char(TABLE, n & 0x3f)
        } else {
            '='
        });
    }
    out
}

fn b64_char(table: &[u8; 64], idx: u32) -> char {
    let i = usize::try_from(idx).unwrap_or(0);
    char::from(table.get(i).copied().unwrap_or(b'A'))
}
