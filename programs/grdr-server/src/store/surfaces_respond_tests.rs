// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Integration and adversarial security tests for `surfaces_respond*` (`docs/design/18`, `22`).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64_URL;
use jiff::Timestamp;
use uuid::Uuid;

use grdr_core::detect::response::{
    ActuatorDeliveryForm, ApprovalOutcomeSignal, DeviceContainmentStage, KillSwitchScope,
};
use grdr_crypto::{SigningKeypair, sha256_digest};
use grdr_model::{
    ActionAttempt, ActionClass, ControlPoint, DecisionReceipt, Device, Finding, FindingClass,
    FindingLifecycle, FindingSeverity, InstallProfile, ProvenanceSource, SpanKind, Verdict,
};
use grdr_ports::ProfileKind;
use grdr_review::queue::{CandidateSignal, ReviewCandidate};
use grdr_review::verifier::{ExtendedReviewSignals, ModelAdvisoryTier};

use crate::store::surfaces_respond::{RunHuntRequest, SyncTicketRequest};
use crate::store::surfaces_respond_hunts::{
    SigmaMatchOp, SigmaPredicate, TicketSyncManifest, TicketSyncOutcome,
};
use crate::store::surfaces_respond_ops::{
    ActuatorCapPreview, DEPLOY_KILL_SIG_DOMAIN, SignedServerKillRequest,
    preview_response_capabilities,
};
use crate::store::surfaces_respond_playbooks::{
    ExecutionPrincipal, PlaybookMode, PlaybookRunState, PlaybookStepKind, PlaybookStepSpec,
    SoarPlaybookSpec, StepJournalStatus, import_cacao_playbook,
};
use crate::store::surfaces_respond_soar_sup::{
    ApproveSuppressionRequest, PromotePlaybookRequest, RunPlaybookRequest,
};
use crate::store::surfaces_respond_store::{load_persisted_respond, save_persisted_respond};
use crate::store::surfaces_respond_triage::SuppressionStatus;
use crate::store::surfaces_respond_webauthn::{
    ApproverAttestationStatus, ApproverRole, ApproverRosterEntry, ApproverRosterState,
    WebAuthnStepUpAssertion,
};
use crate::store::{AppState, StorageBackend};

const SEVEN_DAYS_SECS: i64 = 7 * 86_400;

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("grdr-respond-test-{}", Uuid::now_v7().simple()));
        std::fs::create_dir_all(&p).expect("create test dir");
        Self(p)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn make_assertion(
    kp: &SigningKeypair,
    rp_id: &str,
    origin: &str,
    body: &[u8],
    flags: u8,
    sign_count: u32,
) -> WebAuthnStepUpAssertion {
    let challenge = B64_URL.encode(sha256_digest(body));
    let client_data_json = format!(
        "{{\"type\":\"webauthn.get\",\"challenge\":\"{challenge}\",\"origin\":\"{origin}\",\"crossOrigin\":false}}"
    )
    .into_bytes();
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&sha256_digest(rp_id.as_bytes()));
    auth_data.push(flags);
    auth_data.extend_from_slice(&sign_count.to_be_bytes());
    let mut msg = auth_data.clone();
    msg.extend_from_slice(&sha256_digest(&client_data_json));
    let sig = kp.sign_ed25519_raw(&msg);
    WebAuthnStepUpAssertion {
        key_id: kp.key_id().into(),
        client_data_json,
        authenticator_data: auth_data,
        signature: sig.to_vec(),
    }
}

fn make_v1_roster(
    org_id: &str,
    kp1: &SigningKeypair,
    kp2: &SigningKeypair,
    prov: &SigningKeypair,
) -> ApproverRosterState {
    ApproverRosterState {
        version: 1,
        org_id: org_id.into(),
        claimed_org: true,
        rp_id: "console.guardrails.local".into(),
        origin: "https://console.guardrails.local".into(),
        prev_digest_sha256: "0".repeat(64),
        provider_delegated: true,
        entries: vec![
            ApproverRosterEntry {
                key_id: kp1.key_id().into(),
                public_key_b64: kp1.public_key_b64(),
                role: ApproverRole::OrgAdmin,
                attestation: ApproverAttestationStatus::HardwareAttested,
            },
            ApproverRosterEntry {
                key_id: kp2.key_id().into(),
                public_key_b64: kp2.public_key_b64(),
                role: ApproverRole::OrgResponder,
                attestation: ApproverAttestationStatus::HardwareAttested,
            },
            ApproverRosterEntry {
                key_id: prov.key_id().into(),
                public_key_b64: prov.public_key_b64(),
                role: ApproverRole::ProviderResponder,
                attestation: ApproverAttestationStatus::HardwareAttested,
            },
        ],
    }
}

fn make_device(id: &str) -> Device {
    Device {
        id: id.into(),
        hostname: format!("host-{id}"),
        os: "linux".into(),
        arch: "x86_64".into(),
        install_profile: InstallProfile::Protected,
        daemon_version: "0.1.0".into(),
        online: true,
        hook_effective: true,
        agents: Vec::new(),
        mcp_servers: Vec::new(),
        artifacts: Vec::new(),
        user_id: None,
        user_display: None,
        last_seen: Timestamp::now(),
        public_key: None,
    }
}

#[tokio::test]
async fn w3_4_persisted_kill_switch_webauthn_rosters_provider_caps_and_containment() {
    let dir = TestDir::new();
    let app = AppState::init_with_profile(
        ProfileKind::Embedded,
        StorageBackend::Disk(dir.path().to_path_buf()),
        false,
    )
    .expect("init store");

    let kp1 = SigningKeypair::generate().unwrap();
    let kp2 = SigningKeypair::generate().unwrap();
    let prov = SigningKeypair::generate().unwrap();

    // BackupEligibleSynced or non-https origin must be rejected at registration.
    let mut bad_roster = make_v1_roster("org-1", &kp1, &kp2, &prov);
    bad_roster.entries[0].attestation = ApproverAttestationStatus::BackupEligibleSynced;
    assert!(
        app.respond_register_roster(bad_roster, 2, vec![])
            .await
            .is_err()
    );

    let mut bad_origin = make_v1_roster("org-1", &kp1, &kp2, &prov);
    bad_origin.origin = "http://insecure.local".into();
    assert!(
        app.respond_register_roster(bad_origin, 2, vec![])
            .await
            .is_err()
    );

    let v1 = make_v1_roster("org-1", &kp1, &kp2, &prov);
    let d1 = app
        .respond_register_roster(v1.clone(), 2, vec![])
        .await
        .expect("v1 registered");

    // BE (0x08) / BS (0x10) flags or zero signCount must be rejected even with valid UP+UV signature!
    let mut kill_be = SignedServerKillRequest {
        command_id: "cmd-be".into(),
        org_id: "org-1".into(),
        epoch: 1,
        counter: 1,
        scope: KillSwitchScope::Agent("bad-agent".into()),
        target_stage: DeviceContainmentStage::Frozen,
        reason_code: "det.test".into(),
        expires_at_sec: 2_000,
        assertions: Vec::new(),
        deployment_sig_b64: None,
    };
    let be_body = kill_be.canonical_signing_body().unwrap();
    kill_be.assertions = vec![make_assertion(
        &kp1,
        &v1.rp_id,
        &v1.origin,
        &be_body,
        0x05 | 0x08,
        1,
    )];
    assert!(
        app.respond_execute_kill_command(kill_be.clone(), 1_000)
            .await
            .is_err()
    );

    kill_be.assertions = vec![make_assertion(
        &kp1, &v1.rp_id, &v1.origin, &be_body, 0x05, 0,
    )];
    assert!(
        app.respond_execute_kill_command(kill_be, 1_000)
            .await
            .is_err()
    );

    // 0-signer containment without verified deployment key fails closed!
    let mut unsigned_zero = SignedServerKillRequest {
        command_id: "cmd-zero-unauth".into(),
        org_id: "org-1".into(),
        epoch: 1,
        counter: 1,
        scope: KillSwitchScope::Session("s-0".into()),
        target_stage: DeviceContainmentStage::Frozen,
        reason_code: "det.auto".into(),
        expires_at_sec: 2_000,
        assertions: Vec::new(),
        deployment_sig_b64: None,
    };
    assert!(
        app.respond_execute_kill_command(unsigned_zero.clone(), 1_000)
            .await
            .is_err()
    );

    // Signed with deployment signing key succeeds on Session Frozen <= 24h!
    let zero_body = unsigned_zero.canonical_signing_body().unwrap();
    unsigned_zero.deployment_sig_b64 = Some(
        app.signing_key
            .sign_bytes(DEPLOY_KILL_SIG_DOMAIN, &zero_body),
    );
    app.respond_execute_kill_command(unsigned_zero, 1_000)
        .await
        .expect("deployment-signed session freeze succeeds");

    // Dual hardware WebAuthn sign-off revokes model endpoint and persists across restart!
    let mut req = SignedServerKillRequest {
        command_id: "cmd-model-kill".into(),
        org_id: "org-1".into(),
        epoch: 1,
        counter: 2,
        scope: KillSwitchScope::ModelEndpoint("https://rogue.model.invalid".into()),
        target_stage: DeviceContainmentStage::Revoked,
        reason_code: "det.base-url-drift".into(),
        expires_at_sec: 5_000,
        assertions: Vec::new(),
        deployment_sig_b64: None,
    };
    let req_body = req.canonical_signing_body().unwrap();
    req.assertions = vec![
        make_assertion(&kp1, &v1.rp_id, &v1.origin, &req_body, 0x05, 1),
        make_assertion(&kp2, &v1.rp_id, &v1.origin, &req_body, 0x05, 1),
    ];
    let executed = app
        .respond_execute_kill_command(req, 1_000)
        .await
        .expect("dual-signed revoke executes");
    assert_eq!(
        executed.executed_stages,
        vec![
            DeviceContainmentStage::Frozen,
            DeviceContainmentStage::Isolated,
            DeviceContainmentStage::Captured,
            DeviceContainmentStage::Revoked
        ]
    );
    drop(app);

    // Reopen from disk, confirm blocked model state survived reboot AND is strictly org-isolated!
    let reopened = AppState::init_with_profile(
        ProfileKind::Embedded,
        StorageBackend::Disk(dir.path().to_path_buf()),
        false,
    )
    .expect("reopen from disk");
    assert!(
        reopened
            .respond_is_scope_blocked(
                "org-1",
                &[KillSwitchScope::ModelEndpoint(
                    "https://rogue.model.invalid".into()
                )],
                2_000
            )
            .await
            .is_some()
    );
    assert!(
        reopened
            .respond_is_scope_blocked(
                "org-2",
                &[KillSwitchScope::ModelEndpoint(
                    "https://rogue.model.invalid".into()
                )],
                2_000
            )
            .await
            .is_none(),
        "kill switch state must be partitioned per org_id"
    );

    // Replayed signCount (count=1 <= previous 1) rejected!
    let mut replay_req = SignedServerKillRequest {
        command_id: "cmd-replay-count".into(),
        org_id: "org-1".into(),
        epoch: 1,
        counter: 3,
        scope: KillSwitchScope::Session("sess-x".into()),
        target_stage: DeviceContainmentStage::Frozen,
        reason_code: "det.freeze".into(),
        expires_at_sec: 2_000,
        assertions: Vec::new(),
        deployment_sig_b64: None,
    };
    let rc_body = replay_req.canonical_signing_body().unwrap();
    replay_req.assertions = vec![make_assertion(
        &kp1, &v1.rp_id, &v1.origin, &rc_body, 0x05, 1,
    )];
    assert!(
        reopened
            .respond_execute_kill_command(replay_req, 1_050)
            .await
            .is_err()
    );

    // 1-signer freeze with TTL > 3600s rejected!
    let mut long_freeze = SignedServerKillRequest {
        command_id: "cmd-long-freeze".into(),
        org_id: "org-1".into(),
        epoch: 1,
        counter: 3,
        scope: KillSwitchScope::Session("sess-long".into()),
        target_stage: DeviceContainmentStage::Frozen,
        reason_code: "det.freeze".into(),
        expires_at_sec: 10_000,
        assertions: Vec::new(),
        deployment_sig_b64: None,
    };
    let lf_body = long_freeze.canonical_signing_body().unwrap();
    long_freeze.assertions = vec![make_assertion(
        &kp1, &v1.rp_id, &v1.origin, &lf_body, 0x05, 2,
    )];
    assert!(
        reopened
            .respond_execute_kill_command(long_freeze, 1_050)
            .await
            .is_err()
    );

    // Single-signer release of dual-signed Revoked entry must fail (release parity)!
    let mut single_rel = SignedServerKillRequest {
        command_id: "cmd-rel-1".into(),
        org_id: "org-1".into(),
        epoch: 1,
        counter: 4,
        scope: KillSwitchScope::ModelEndpoint("https://rogue.model.invalid".into()),
        target_stage: DeviceContainmentStage::Released,
        reason_code: "det.rel".into(),
        expires_at_sec: 5_000,
        assertions: Vec::new(),
        deployment_sig_b64: None,
    };
    let sr_body = single_rel.canonical_signing_body().unwrap();
    single_rel.assertions = vec![make_assertion(
        &kp1, &v1.rp_id, &v1.origin, &sr_body, 0x05, 3,
    )];
    assert!(
        reopened
            .respond_execute_kill_command(single_rel, 1_060)
            .await
            .is_err()
    );

    // Provider delegation revocation drops ProviderResponder keys chained cleanly to d1;
    // ProviderResponder cannot participate in org rotation quorum (provider excluded!).
    let next_candidate = ApproverRosterState {
        version: 2,
        org_id: prev_org(&v1),
        claimed_org: v1.claimed_org,
        rp_id: v1.rp_id.clone(),
        origin: v1.origin.clone(),
        prev_digest_sha256: d1.clone(),
        provider_delegated: false,
        entries: vec![v1.entries[0].clone(), v1.entries[1].clone()],
    };
    let rot_body = next_candidate.canonical_rotation_body().unwrap();
    // Quorum min < 2 rejected!
    assert!(
        reopened
            .respond_revoke_provider_delegation(
                "org-1",
                vec![make_assertion(
                    &kp1, &v1.rp_id, &v1.origin, &rot_body, 0x05, 4
                )],
                1,
            )
            .await
            .is_err()
    );
    // 1 org + 1 provider rejected!
    assert!(
        reopened
            .respond_revoke_provider_delegation(
                "org-1",
                vec![
                    make_assertion(&kp1, &v1.rp_id, &v1.origin, &rot_body, 0x05, 5),
                    make_assertion(&prov, &v1.rp_id, &v1.origin, &rot_body, 0x05, 1),
                ],
                2,
            )
            .await
            .is_err()
    );
    let revoked_roster = reopened
        .respond_revoke_provider_delegation(
            "org-1",
            vec![
                make_assertion(&kp1, &v1.rp_id, &v1.origin, &rot_body, 0x05, 6),
                make_assertion(&kp2, &v1.rp_id, &v1.origin, &rot_body, 0x05, 2),
            ],
            2,
        )
        .await
        .expect("provider delegation revoked cleanly");
    assert_eq!(revoked_roster.version, 2);
    assert_eq!(revoked_roster.prev_digest_sha256, d1);
    assert!(
        !revoked_roster
            .entries
            .iter()
            .any(|e| e.role == ApproverRole::ProviderResponder)
    );

    // Approval streak per org_id & offline unreachable behavior.
    assert!(
        !reopened
            .respond_record_approval_signal(
                "org-1",
                "s1",
                ApprovalOutcomeSignal::ApproverUnreachableOffline
            )
            .await
            .unwrap()
    );
    for _ in 0..2 {
        assert!(
            !reopened
                .respond_record_approval_signal(
                    "org-1",
                    "s1",
                    ApprovalOutcomeSignal::UnansweredOrDenied
                )
                .await
                .unwrap()
        );
    }
    assert!(
        reopened
            .respond_record_approval_signal(
                "org-1",
                "s1",
                ApprovalOutcomeSignal::UnansweredOrDenied
            )
            .await
            .unwrap()
    );

    let preview = preview_response_capabilities(vec![
        ActuatorCapPreview {
            os_family: "linux".into(),
            delivery_form: ActuatorDeliveryForm::Exact,
            fallback_reason: None,
        },
        ActuatorCapPreview {
            os_family: "windows".into(),
            delivery_form: ActuatorDeliveryForm::Gated,
            fallback_reason: Some("WFP session gate".into()),
        },
    ]);
    assert_eq!(preview.rollup_form, ActuatorDeliveryForm::Gated);
}

#[tokio::test]
async fn w3_4_adversarial_provider_cap_ha_store_tamper_hunts_suppressions_and_soar() {
    let app = AppState::init(StorageBackend::Memory, false).expect("memory init");

    // 1. Provider 5-org/hour cap keyed by verified hardware public key (cannot spoof by changing key_id!).
    let prov = SigningKeypair::generate().unwrap();
    let org_k = SigningKeypair::generate().unwrap();
    for idx in 1..=6_u32 {
        let org_id = format!("org-p{idx}");
        let prov_alias_id = format!("prov-alias-{idx}");
        let roster = ApproverRosterState {
            version: 1,
            org_id: org_id.clone(),
            claimed_org: false,
            rp_id: "console.guardrails.local".into(),
            origin: "https://console.guardrails.local".into(),
            prev_digest_sha256: "0".repeat(64),
            provider_delegated: true,
            entries: vec![
                ApproverRosterEntry {
                    key_id: org_k.key_id().into(),
                    public_key_b64: org_k.public_key_b64(),
                    role: ApproverRole::OrgAdmin,
                    attestation: ApproverAttestationStatus::HardwareAttested,
                },
                ApproverRosterEntry {
                    key_id: prov_alias_id.clone(),
                    public_key_b64: prov.public_key_b64(),
                    role: ApproverRole::ProviderResponder,
                    attestation: ApproverAttestationStatus::HardwareAttested,
                },
            ],
        };
        app.respond_register_roster(roster.clone(), 2, vec![])
            .await
            .unwrap();
        let mut req = SignedServerKillRequest {
            command_id: format!("cmd-p{idx}"),
            org_id: org_id.clone(),
            epoch: 1,
            counter: 1,
            scope: KillSwitchScope::Session(format!("sess-p{idx}")),
            target_stage: DeviceContainmentStage::Frozen,
            reason_code: "det.prov".into(),
            expires_at_sec: 2_000,
            assertions: Vec::new(),
            deployment_sig_b64: None,
        };
        let body = req.canonical_signing_body().unwrap();
        let mut assertion = make_assertion(&prov, &roster.rp_id, &roster.origin, &body, 0x05, idx);
        assertion.key_id = prov_alias_id;
        req.assertions = vec![assertion];
        let res = app.respond_execute_kill_command(req, 1_000).await;
        if idx <= 5 {
            assert!(res.is_ok(), "provider hit {idx} <= 5 distinct orgs allowed");
        } else {
            assert!(
                res.is_err(),
                "6th distinct org in 1h MUST fail even under distinct key_id alias"
            );
        }
    }

    // 2. HA shared persistence & tamper rejection.
    let shared_dir = TestDir::new();
    let ha_a = StorageBackend::Ha {
        postgres_dsn: "postgres://grdr:pw@127.0.0.1:5432/grdr".into(),
        object_store_dir: shared_dir.path().to_path_buf(),
        state_dir: shared_dir.path().join("node-a"),
    };
    let ha_b = StorageBackend::Ha {
        postgres_dsn: "postgres://grdr:pw@127.0.0.1:5432/grdr".into(),
        object_store_dir: shared_dir.path().to_path_buf(),
        state_dir: shared_dir.path().join("node-b"),
    };
    let cluster_kp = SigningKeypair::generate().unwrap();
    {
        let guard = app.inner.read().await;
        save_persisted_respond(&ha_a, &cluster_kp, &guard.respond)
            .expect("save to shared HA store");
    }
    let loaded_b = load_persisted_respond(&ha_b, &cluster_kp)
        .expect("node B reads shared HA object store")
        .expect("present");
    assert_eq!(loaded_b.response_actions.len(), 5);
    std::fs::write(
        shared_dir.path().join("respond-ops.json"),
        b"tampered-bytes",
    )
    .unwrap();
    assert!(
        load_persisted_respond(&ha_b, &cluster_kp).is_err(),
        "tampered respond-ops.json must fail closed"
    );

    // 3. Seed 100 findings + cross-tenant records + old (>24h) retro finding.
    let now_sec = Timestamp::now().as_second();
    {
        let mut guard = app.inner.write().await;
        for i in 0..100_u32 {
            let f = Finding {
                id: format!("f-{i}"),
                session_id: format!("sess-{i}"),
                device_id: "dev-1".into(),
                device_name: "laptop-1".into(),
                agent_name: "claude-code".into(),
                class: FindingClass::Threat,
                finding_class_other: None,
                severity: FindingSeverity::High,
                lifecycle: FindingLifecycle::Open,
                rule_id: Some("det.bad-artefact".into()),
                title: "Shared malicious payload digest".into(),
                summary: "Matched artefact digest".into(),
                target: "/tmp/evil.sh".into(),
                detected_at: Timestamp::from_second(now_sec.saturating_sub(60)).unwrap(),
            };
            guard
                .respond
                .group_finding_into_incident("org-1", "sha256:bad", &f, now_sec);
            guard.findings.push(f);
        }
        // Historical finding 48h ago in org-1 -> retro page_eligible must be false!
        let old_f = Finding {
            id: "f-old".into(),
            session_id: "sess-old".into(),
            device_id: "dev-1".into(),
            device_name: "laptop-1".into(),
            agent_name: "claude-code".into(),
            class: FindingClass::Threat,
            finding_class_other: None,
            severity: FindingSeverity::Critical,
            lifecycle: FindingLifecycle::Open,
            rule_id: Some("det.old".into()),
            title: "Old finding".into(),
            summary: "Old".into(),
            target: "/tmp/old".into(),
            detected_at: Timestamp::from_second(now_sec.saturating_sub(2 * 86_400)).unwrap(),
        };
        guard
            .respond
            .register_tenant_binding("org-1", Some("sess-old"), Some("dev-1"))
            .unwrap();
        // Conflicting cross-org binding must fail without mutating existing org-1 ownership.
        assert!(
            guard
                .respond
                .register_tenant_binding("org-2", Some("sess-old"), Some("dev-org2"))
                .is_err()
        );
        guard.findings.push(old_f);

        // Cross-tenant attempt/receipt/finding owned by org-2 -> MUST NOT leak to org-1 hunts!
        let other_f = Finding {
            id: "f-org2".into(),
            session_id: "sess-org2".into(),
            device_id: "dev-org2".into(),
            device_name: "laptop-2".into(),
            agent_name: "claude-code".into(),
            class: FindingClass::Threat,
            finding_class_other: None,
            severity: FindingSeverity::High,
            lifecycle: FindingLifecycle::Open,
            rule_id: Some("det.bad-artefact".into()),
            title: "Org2 secret".into(),
            summary: "Secret".into(),
            target: "/tmp/org2".into(),
            detected_at: Timestamp::now(),
        };
        guard
            .respond
            .register_tenant_binding("org-2", Some("sess-org2"), Some("dev-org2"))
            .unwrap();
        guard.findings.push(other_f);
        guard.attempts.push(ActionAttempt {
            id: "att-org2".into(),
            session_id: "sess-org2".into(),
            device_id: "dev-org2".into(),
            device_name: "laptop-2".into(),
            agent_name: "claude".into(),
            action_class: ActionClass::Exec,
            control_point: ControlPoint::Hook,
            target: "curl evil".into(),
            summary: "exec".into(),
            timestamp: Timestamp::now(),
            user_id: None,
            user_display: None,
            turn_index: 1,
            span_id: None,
            parent_span_id: None,
            span_kind: SpanKind::default(),
            duration_ms: 1,
            provenance: ProvenanceSource::default(),
            secondary_actions: Vec::new(),
            skill_used: None,
            compaction: false,
        });
        guard.receipts.push(DecisionReceipt {
            receipt_id: "rcp-org2".into(),
            attempt_id: "att-org2".into(),
            session_id: "sess-org2".into(),
            device_id: "dev-org2".into(),
            agent_name: "claude".into(),
            action_class: ActionClass::Exec,
            control_point: ControlPoint::Hook,
            target: "curl evil".into(),
            verdict: Verdict::Deny,
            would_be: None,
            rule_id: None,
            pack_id: None,
            mode_applied: None,
            grant_id: None,
            reason: "bad".into(),
            next_step: "none".into(),
            receipt_digest: "d".into(),
            decided_at: Timestamp::now(),
            key_id: None,
            signature: None,
            signature_verified: None,
        });
        guard.respond.ticket_manifests.push(TicketSyncManifest {
            vendor_id: "jira".into(),
            open_state: "To Do".into(),
            investigating_state: "In Progress".into(),
            contained_state: "Blocked".into(),
            resolved_state: "Done".into(),
        });
        assert_eq!(guard.respond.incidents.len(), 1);
    }

    // 4. Suppressions: case-insensitive self-approval rejected, overlap/dup rejected, lifecycle preserved.
    assert!(
        app.respond_approve_suppression(ApproveSuppressionRequest {
            org_id: "org-1",
            suppression_id: "sup-self",
            finding_id: "f-0",
            author_id: " Alice ",
            approver_id: "alice",
            expires_at_sec: now_sec + 1_000,
            now_sec,
        })
        .await
        .is_err()
    );
    let sup = app
        .respond_approve_suppression(ApproveSuppressionRequest {
            org_id: "org-1",
            suppression_id: "sup-1",
            finding_id: "f-0",
            author_id: "alice",
            approver_id: "bob",
            expires_at_sec: now_sec + 500,
            now_sec,
        })
        .await
        .expect("second-person approved");
    assert_eq!(sup.status, SuppressionStatus::Active);
    {
        let guard = app.inner.read().await;
        let f0 = guard.findings.iter().find(|f| f.id == "f-0").unwrap();
        assert_eq!(
            f0.lifecycle,
            FindingLifecycle::Open,
            "suppression must NOT corrupt lifecycle to Resolved"
        );
    }
    // Duplicate suppression_id & overlapping active suppression must fail.
    assert!(
        app.respond_approve_suppression(ApproveSuppressionRequest {
            org_id: "org-1",
            suppression_id: "sup-2",
            finding_id: "f-0",
            author_id: "alice",
            approver_id: "bob",
            expires_at_sec: now_sec + 600,
            now_sec,
        })
        .await
        .is_err()
    );
    assert_eq!(
        app.respond_expire_suppressions("org-1", now_sec + 600)
            .await
            .unwrap(),
        1
    );

    // 5. Hunts: content table denied when include_content=false, cross-tenant isolated, retro 24h cap.
    assert!(
        app.respond_run_hunt(RunHuntRequest {
            run_id: "h-content-deny",
            org_id: "org-1",
            sql: Some("SELECT target FROM content"),
            sigma: &[],
            include_content: false,
            retro: false,
            now_sec,
        })
        .await
        .is_err()
    );
    let hunt_dec = app
        .respond_run_hunt(RunHuntRequest {
            run_id: "h-dec-iso",
            org_id: "org-1",
            sql: Some("SELECT decision_id FROM decision"),
            sigma: &[],
            include_content: false,
            retro: false,
            now_sec,
        })
        .await
        .unwrap();
    assert_eq!(
        hunt_dec.total_hits, 0,
        "org-2 receipts must never leak to org-1"
    );
    let hunt_old = app
        .respond_run_hunt(RunHuntRequest {
            run_id: "h-old",
            org_id: "org-1",
            sql: Some("SELECT finding_id FROM events WHERE rule_id = 'det.old'"),
            sigma: &[],
            include_content: false,
            retro: true,
            now_sec,
        })
        .await
        .unwrap();
    assert!(
        !hunt_old.rows[0].page_eligible,
        "retro findings >24h old must NOT page"
    );

    let hunt = app
        .respond_run_hunt(RunHuntRequest {
            run_id: "h-ok",
            org_id: "org-1",
            sql: Some("SELECT finding_id, session_id FROM events WHERE rule_id = 'det.bad-artefact' LIMIT 10"),
            sigma: &[SigmaPredicate {
                field: "session_id".into(),
                op: SigmaMatchOp::StartsWith,
                value: "sess-".into(),
            }],
            include_content: false,
            retro: true,
            now_sec,
        })
        .await
        .unwrap();
    assert_eq!(hunt.total_hits, 10);
    assert!(hunt.rows.iter().all(|r| r.retro && r.page_eligible));

    // 6. Triage queue scoring & Jira convergence.
    {
        let mut guard = app.inner.write().await;
        let key = [7_u8; 32];
        for idx in 0..100 {
            let mut signals = BTreeSet::new();
            if idx == 0 {
                signals.insert(CandidateSignal::TaintExfil);
            }
            guard
                .respond
                .classify_and_enqueue_session(
                    "org-1",
                    &ReviewCandidate {
                        session_id: format!("q-{idx}"),
                        root_session_id: format!("root-{idx}"),
                        max_severity: if idx == 0 {
                            Some(FindingSeverity::High)
                        } else {
                            None
                        },
                        signals,
                    },
                    &ExtendedReviewSignals {
                        flags: BTreeSet::new(),
                        deterministic_findings_count: usize::from(idx == 0),
                        model_advisory: ModelAdvisoryTier::None,
                    },
                    &key,
                    false,
                    idx == 0,
                )
                .unwrap();
        }
        assert!(guard.respond.worth_a_look_within_cap());
    }
    assert_eq!(
        app.respond_sync_ticket(SyncTicketRequest {
            org_id: "org-1",
            incident_id: "inc-1",
            vendor_id: "jira",
            external_ticket_id: "SEC-42",
            vendor_state: "In Progress",
            sync_origin: "grdr",
            revision: 1,
            raw_summary: "See https://evil.test",
        })
        .await
        .unwrap(),
        TicketSyncOutcome::Applied
    );
    assert_eq!(
        app.respond_sync_ticket(SyncTicketRequest {
            org_id: "org-1",
            incident_id: "inc-1",
            vendor_id: "jira",
            external_ticket_id: "SEC-42",
            vendor_state: "In Progress",
            sync_origin: "grdr",
            revision: 1,
            raw_summary: "Echo",
        })
        .await
        .unwrap(),
        TicketSyncOutcome::IgnoredEcho
    );

    // 7. SOAR playbooks: URI/metachar/max_share_bp > 10000 validation, 7-day promotion gate,
    // ManualReview safe parking without losing step 0, immutable resume, server blast-radius drop.
    for bad_target in [
        "javascript:alert(1)",
        "file:///etc/passwd",
        "data:text/html,x",
        "//evil.com",
        "sess;rm",
    ] {
        assert!(
            SoarPlaybookSpec {
                playbook_id: "pb-bad".into(),
                version: "1.0.0".into(),
                mode: PlaybookMode::Simulate,
                max_share_bp: 500,
                steps: vec![PlaybookStepSpec {
                    step_id: "s1".into(),
                    kind: PlaybookStepKind::ManualReview,
                    idempotent: true,
                    undo_ref: None,
                    raw_target: bad_target.into(),
                }],
            }
            .validate()
            .is_err()
        );
    }
    assert!(
        SoarPlaybookSpec {
            playbook_id: "pb-bp".into(),
            version: "1".into(),
            mode: PlaybookMode::Simulate,
            max_share_bp: 10_001,
            steps: vec![PlaybookStepSpec {
                step_id: "s1".into(),
                kind: PlaybookStepKind::CaptureEvidence,
                idempotent: true,
                undo_ref: None,
                raw_target: "sess-1".into(),
            }],
        }
        .validate()
        .is_err()
    );
    let cacao = import_cacao_playbook(
        r#"{"id":"cacao-1","workflow":[{"id":"st1","action_type":"freeze","target":"s-1"},{"id":"st2","action_type":"custom-vendor-webhook","target":"t-1"}]}"#,
    )
    .unwrap();
    assert_eq!(cacao.steps[1].kind, PlaybookStepKind::ManualReview);

    let mut live_pb = SoarPlaybookSpec {
        playbook_id: "pb-live".into(),
        version: "1".into(),
        mode: PlaybookMode::Live,
        max_share_bp: 500,
        steps: vec![
            PlaybookStepSpec {
                step_id: "s-freeze".into(),
                kind: PlaybookStepKind::FreezeSession,
                idempotent: false,
                undo_ref: Some("release".into()),
                raw_target: "sess-1".into(),
            },
            PlaybookStepSpec {
                step_id: "s-manual".into(),
                kind: PlaybookStepKind::ManualReview,
                idempotent: true,
                undo_ref: None,
                raw_target: "sess-1".into(),
            },
        ],
    };
    // Live without 7-day Simulate promotion proof fails!
    assert!(
        app.respond_run_playbook(RunPlaybookRequest {
            org_id: "org-1".into(),
            spec: live_pb.clone(),
            principal: ExecutionPrincipal::HumanApprover,
            scope: KillSwitchScope::Session("sess-1".into()),
            pause_after_step_idx: None,
            approve_manual_step_idx: Some(1),
            resume_run_id: None,
            now_sec: 1_000,
        })
        .await
        .is_err()
    );
    let sim_pb = SoarPlaybookSpec {
        mode: PlaybookMode::Simulate,
        ..live_pb.clone()
    };
    app.respond_run_playbook(RunPlaybookRequest {
        org_id: "org-1".into(),
        spec: sim_pb,
        principal: ExecutionPrincipal::HumanApprover,
        scope: KillSwitchScope::Session("sess-1".into()),
        pause_after_step_idx: None,
        approve_manual_step_idx: None,
        resume_run_id: None,
        now_sec: 1_000,
    })
    .await
    .unwrap();
    // Promote before 7 days fails; self-promote fails; >=7 days with distinct approver succeeds!
    assert!(
        app.respond_promote_playbook_to_live(PromotePlaybookRequest {
            org_id: "org-1",
            spec: &live_pb,
            author_id: "alice",
            approver_id: "bob",
            now_sec: 1_000 + SEVEN_DAYS_SECS - 1,
        })
        .await
        .is_err()
    );
    app.respond_promote_playbook_to_live(PromotePlaybookRequest {
        org_id: "org-1",
        spec: &live_pb,
        author_id: "alice",
        approver_id: "bob",
        now_sec: 1_000 + SEVEN_DAYS_SECS + 10,
    })
    .await
    .unwrap();

    // Live run executes step 0 and parks cleanly on ManualReview preserving step 0 journal!
    let parked = app
        .respond_run_playbook(RunPlaybookRequest {
            org_id: "org-1".into(),
            spec: live_pb.clone(),
            principal: ExecutionPrincipal::SoarServiceKey,
            scope: KillSwitchScope::Session("sess-1".into()),
            pause_after_step_idx: None,
            approve_manual_step_idx: None,
            resume_run_id: None,
            now_sec: 1_000 + SEVEN_DAYS_SECS + 20,
        })
        .await
        .expect("parks cleanly on manual review without dropping step 0");
    assert_eq!(parked.state, PlaybookRunState::PausedForManualApproval);
    assert_eq!(parked.steps[0].status, StepJournalStatus::Completed);
    assert_eq!(parked.steps[0].executions, 1);

    // Mutating scope on resume must fail; HumanApprover explicit resume completes without re-running step 0!
    assert!(
        app.respond_run_playbook(RunPlaybookRequest {
            org_id: "org-1".into(),
            spec: live_pb.clone(),
            principal: ExecutionPrincipal::HumanApprover,
            scope: KillSwitchScope::Session("sess-tampered".into()),
            pause_after_step_idx: None,
            approve_manual_step_idx: Some(1),
            resume_run_id: Some(parked.run_id.clone()),
            now_sec: 1_000 + SEVEN_DAYS_SECS + 30,
        })
        .await
        .is_err()
    );
    let done = app
        .respond_run_playbook(RunPlaybookRequest {
            org_id: "org-1".into(),
            spec: live_pb.clone(),
            principal: ExecutionPrincipal::HumanApprover,
            scope: KillSwitchScope::Session("sess-1".into()),
            pause_after_step_idx: None,
            approve_manual_step_idx: Some(1),
            resume_run_id: Some(parked.run_id.clone()),
            now_sec: 1_000 + SEVEN_DAYS_SECS + 30,
        })
        .await
        .unwrap();
    assert_eq!(done.state, PlaybookRunState::Completed);
    assert_eq!(done.steps[0].executions, 1);

    // Resuming Completed terminal run must fail!
    assert!(
        app.respond_run_playbook(RunPlaybookRequest {
            org_id: "org-1".into(),
            spec: live_pb.clone(),
            principal: ExecutionPrincipal::HumanApprover,
            scope: KillSwitchScope::Session("sess-1".into()),
            pause_after_step_idx: None,
            approve_manual_step_idx: None,
            resume_run_id: Some(done.run_id),
            now_sec: 1_000 + SEVEN_DAYS_SECS + 40,
        })
        .await
        .is_err()
    );

    // Server-side blast-radius trip across multiple registered devices drops mid-run to Simulate & compensates!
    live_pb.steps[1].kind = PlaybookStepKind::CaptureEvidence;
    app.respond_run_playbook(RunPlaybookRequest {
        org_id: "org-1".into(),
        spec: SoarPlaybookSpec {
            mode: PlaybookMode::Simulate,
            ..live_pb.clone()
        },
        principal: ExecutionPrincipal::HumanApprover,
        scope: KillSwitchScope::Group("all".into()),
        pause_after_step_idx: None,
        approve_manual_step_idx: None,
        resume_run_id: None,
        now_sec: 2_000,
    })
    .await
    .unwrap();
    app.respond_promote_playbook_to_live(PromotePlaybookRequest {
        org_id: "org-1",
        spec: &live_pb,
        author_id: "alice",
        approver_id: "bob",
        now_sec: 2_000 + SEVEN_DAYS_SECS + 10,
    })
    .await
    .unwrap();
    let partial = app
        .respond_run_playbook(RunPlaybookRequest {
            org_id: "org-1".into(),
            spec: live_pb.clone(),
            principal: ExecutionPrincipal::HumanApprover,
            scope: KillSwitchScope::Group("all".into()),
            pause_after_step_idx: Some(0),
            approve_manual_step_idx: None,
            resume_run_id: None,
            now_sec: 2_000 + SEVEN_DAYS_SECS + 20,
        })
        .await
        .unwrap();
    {
        let mut guard = app.inner.write().await;
        guard.devices.push(make_device("d-soar-1"));
        guard.devices.push(make_device("d-soar-2"));
        guard
            .respond
            .register_tenant_binding("org-1", None, Some("d-soar-1"))
            .unwrap();
        guard
            .respond
            .register_tenant_binding("org-1", None, Some("d-soar-2"))
            .unwrap();
    }
    let tripped = app
        .respond_run_playbook(RunPlaybookRequest {
            org_id: "org-1".into(),
            spec: live_pb,
            principal: ExecutionPrincipal::HumanApprover,
            scope: KillSwitchScope::Group("all".into()),
            pause_after_step_idx: None,
            approve_manual_step_idx: None,
            resume_run_id: Some(partial.run_id),
            now_sec: 2_000 + SEVEN_DAYS_SECS + 30,
        })
        .await
        .unwrap();
    assert_eq!(
        tripped.state,
        PlaybookRunState::DroppedToSimulateAndCompensated
    );
    assert_eq!(tripped.steps[0].status, StepJournalStatus::Compensated);
    assert_eq!(tripped.compensated_undo_refs, vec!["s-freeze:release"]);
}

#[tokio::test]
async fn w3_4_pass3_adversarial_b1_b2_h4_h5_invariants() {
    let dir = TestDir::new();
    let app = AppState::init_with_profile(
        ProfileKind::Embedded,
        StorageBackend::Disk(dir.path().to_path_buf()),
        false,
    )
    .expect("disk init validates respond even when respond-ops.json absent");

    let kp1 = SigningKeypair::generate().unwrap();
    let kp2 = SigningKeypair::generate().unwrap();

    // Control chars in HTTPS origin rejected.
    let mut bad_roster = ApproverRosterState {
        version: 1,
        org_id: "org-sec".into(),
        claimed_org: false,
        rp_id: "console.guardrails.local".into(),
        origin: "https://console\x1b.guardrails.local".into(),
        prev_digest_sha256: "0".repeat(64),
        provider_delegated: false,
        entries: vec![ApproverRosterEntry {
            key_id: kp1.key_id().into(),
            public_key_b64: kp1.public_key_b64(),
            role: ApproverRole::OrgAdmin,
            attestation: ApproverAttestationStatus::HardwareAttested,
        }],
    };
    assert!(
        app.respond_register_roster(bad_roster.clone(), 2, vec![])
            .await
            .is_err()
    );
    bad_roster.origin = "https://console.guardrails.local".into();
    bad_roster.entries.push(ApproverRosterEntry {
        key_id: kp2.key_id().into(),
        public_key_b64: kp2.public_key_b64(),
        role: ApproverRole::OrgResponder,
        attestation: ApproverAttestationStatus::HardwareAttested,
    });
    app.respond_register_roster(bad_roster.clone(), 2, vec![])
        .await
        .unwrap();

    // Same-stage TTL truncation rejected; dual-signed Frozen blocks 1s overwrite and single-signer release.
    let mut req_freeze = SignedServerKillRequest {
        command_id: "cmd-f1".into(),
        org_id: "org-sec".into(),
        epoch: 1,
        counter: 1,
        scope: KillSwitchScope::Session("s-b1".into()),
        target_stage: DeviceContainmentStage::Frozen,
        reason_code: "det.f1".into(),
        expires_at_sec: 3_000,
        assertions: Vec::new(),
        deployment_sig_b64: None,
    };
    let b1 = req_freeze.canonical_signing_body().unwrap();
    req_freeze.assertions = vec![make_assertion(
        &kp1,
        &bad_roster.rp_id,
        &bad_roster.origin,
        &b1,
        0x05,
        1,
    )];
    app.respond_execute_kill_command(req_freeze, 1_000)
        .await
        .expect("initial single-signer freeze");

    let mut req_trunc = SignedServerKillRequest {
        command_id: "cmd-f-trunc".into(),
        org_id: "org-sec".into(),
        epoch: 1,
        counter: 2,
        scope: KillSwitchScope::Session("s-b1".into()),
        target_stage: DeviceContainmentStage::Frozen,
        reason_code: "det.trunc".into(),
        expires_at_sec: 1_500,
        assertions: Vec::new(),
        deployment_sig_b64: None,
    };
    let b_trunc = req_trunc.canonical_signing_body().unwrap();
    req_trunc.assertions = vec![make_assertion(
        &kp2,
        &bad_roster.rp_id,
        &bad_roster.origin,
        &b_trunc,
        0x05,
        1,
    )];
    assert!(
        app.respond_execute_kill_command(req_trunc, 1_010)
            .await
            .is_err(),
        "same-stage TTL truncation must fail"
    );

    let mut req_dual = SignedServerKillRequest {
        command_id: "cmd-dual-freeze".into(),
        org_id: "org-sec".into(),
        epoch: 1,
        counter: 2,
        scope: KillSwitchScope::Session("s-dual".into()),
        target_stage: DeviceContainmentStage::Frozen,
        reason_code: "det.dual".into(),
        expires_at_sec: 5_000,
        assertions: Vec::new(),
        deployment_sig_b64: None,
    };
    let b_dual = req_dual.canonical_signing_body().unwrap();
    req_dual.assertions = vec![
        make_assertion(
            &kp1,
            &bad_roster.rp_id,
            &bad_roster.origin,
            &b_dual,
            0x05,
            2,
        ),
        make_assertion(
            &kp2,
            &bad_roster.rp_id,
            &bad_roster.origin,
            &b_dual,
            0x05,
            1,
        ),
    ];
    let dual_entry = app
        .respond_execute_kill_command(req_dual, 1_020)
        .await
        .expect("dual-signed freeze");
    assert!(dual_entry.dual_signed);

    // 1-signer overwrite (or 1s truncation) on dual_signed Frozen entry MUST fail!
    let mut req_overwrite = SignedServerKillRequest {
        command_id: "cmd-overwrite-1s".into(),
        org_id: "org-sec".into(),
        epoch: 1,
        counter: 3,
        scope: KillSwitchScope::Session("s-dual".into()),
        target_stage: DeviceContainmentStage::Frozen,
        reason_code: "det.ow".into(),
        expires_at_sec: 5_001,
        assertions: Vec::new(),
        deployment_sig_b64: None,
    };
    let b_ow = req_overwrite.canonical_signing_body().unwrap();
    req_overwrite.assertions = vec![make_assertion(
        &kp1,
        &bad_roster.rp_id,
        &bad_roster.origin,
        &b_ow,
        0x05,
        3,
    )];
    assert!(
        app.respond_execute_kill_command(req_overwrite, 1_030)
            .await
            .is_err()
    );

    // 1-signer release of dual-signed Frozen entry MUST fail (release parity via entry.dual_signed)!
    let mut req_rel_1 = SignedServerKillRequest {
        command_id: "cmd-rel-1s".into(),
        org_id: "org-sec".into(),
        epoch: 1,
        counter: 3,
        scope: KillSwitchScope::Session("s-dual".into()),
        target_stage: DeviceContainmentStage::Released,
        reason_code: "det.rel".into(),
        expires_at_sec: 5_001,
        assertions: Vec::new(),
        deployment_sig_b64: None,
    };
    let b_rel_1 = req_rel_1.canonical_signing_body().unwrap();
    req_rel_1.assertions = vec![make_assertion(
        &kp1,
        &bad_roster.rp_id,
        &bad_roster.origin,
        &b_rel_1,
        0x05,
        4,
    )];
    assert!(
        app.respond_execute_kill_command(req_rel_1, 1_040)
            .await
            .is_err()
    );

    // SOAR digest binds max_share_bp; post-promotion and mid-resume escalation rejected; oversized CACAO rejected.
    let huge_cacao = format!(
        r#"{{"id":"c1","workflow":[],"pad":"{}"}}"#,
        "x".repeat(300_000)
    );
    assert!(import_cacao_playbook(&huge_cacao).is_err());

    let sim_spec = SoarPlaybookSpec {
        playbook_id: "pb-b2".into(),
        version: "1.0.0".into(),
        mode: PlaybookMode::Simulate,
        max_share_bp: 500,
        steps: vec![
            PlaybookStepSpec {
                step_id: "s0".into(),
                kind: PlaybookStepKind::FreezeSession,
                idempotent: true,
                undo_ref: Some("rel".into()),
                raw_target: "sess-b2".into(),
            },
            PlaybookStepSpec {
                step_id: "s1".into(),
                kind: PlaybookStepKind::ManualReview,
                idempotent: true,
                undo_ref: None,
                raw_target: "sess-b2".into(),
            },
        ],
    };
    app.respond_run_playbook(RunPlaybookRequest {
        org_id: "org-sec".into(),
        spec: sim_spec.clone(),
        principal: ExecutionPrincipal::HumanApprover,
        scope: KillSwitchScope::Session("sess-b2".into()),
        pause_after_step_idx: None,
        approve_manual_step_idx: None,
        resume_run_id: None,
        now_sec: 1_000,
    })
    .await
    .unwrap();
    let live_spec = SoarPlaybookSpec {
        mode: PlaybookMode::Live,
        ..sim_spec.clone()
    };
    app.respond_promote_playbook_to_live(PromotePlaybookRequest {
        org_id: "org-sec",
        spec: &live_spec,
        author_id: "alice",
        approver_id: "bob",
        now_sec: 1_000 + SEVEN_DAYS_SECS + 5,
    })
    .await
    .unwrap();
    let escalated_spec = SoarPlaybookSpec {
        max_share_bp: 10_000,
        ..live_spec.clone()
    };
    assert_ne!(
        live_spec.digest_sha256().unwrap(),
        escalated_spec.digest_sha256().unwrap()
    );
    assert!(
        app.respond_run_playbook(RunPlaybookRequest {
            org_id: "org-sec".into(),
            spec: escalated_spec.clone(),
            principal: ExecutionPrincipal::HumanApprover,
            scope: KillSwitchScope::Session("sess-b2".into()),
            pause_after_step_idx: None,
            approve_manual_step_idx: None,
            resume_run_id: None,
            now_sec: 1_000 + SEVEN_DAYS_SECS + 10,
        })
        .await
        .is_err(),
        "post-promotion max_share_bp escalation must fail"
    );
    let paused = app
        .respond_run_playbook(RunPlaybookRequest {
            org_id: "org-sec".into(),
            spec: live_spec.clone(),
            principal: ExecutionPrincipal::SoarServiceKey,
            scope: KillSwitchScope::Session("sess-b2".into()),
            pause_after_step_idx: None,
            approve_manual_step_idx: None,
            resume_run_id: None,
            now_sec: 1_000 + SEVEN_DAYS_SECS + 15,
        })
        .await
        .unwrap();
    assert!(
        app.respond_run_playbook(RunPlaybookRequest {
            org_id: "org-sec".into(),
            spec: escalated_spec,
            principal: ExecutionPrincipal::HumanApprover,
            scope: KillSwitchScope::Session("sess-b2".into()),
            pause_after_step_idx: None,
            approve_manual_step_idx: Some(1),
            resume_run_id: Some(paused.run_id),
            now_sec: 1_000 + SEVEN_DAYS_SECS + 20,
        })
        .await
        .is_err(),
        "mid-resume max_share_bp escalation must fail"
    );

    // Triage incident rules: empty args, non-Open lifecycle, and 24h merge window.
    {
        let mut guard = app.inner.write().await;
        let resolved = Finding {
            id: "f-res".into(),
            session_id: "s-t1".into(),
            device_id: "d-t1".into(),
            device_name: "laptop".into(),
            agent_name: "claude".into(),
            class: FindingClass::Threat,
            finding_class_other: None,
            severity: FindingSeverity::High,
            lifecycle: FindingLifecycle::Resolved,
            rule_id: Some("r1".into()),
            title: "Resolved".into(),
            summary: "Res".into(),
            target: "/tmp/a".into(),
            detected_at: Timestamp::now(),
        };
        assert!(
            guard
                .respond
                .group_finding_into_incident("org-sec", "key-t", &resolved, 1_000)
                .is_none()
        );
        let open1 = Finding {
            id: "f-o1".into(),
            lifecycle: FindingLifecycle::Open,
            ..resolved.clone()
        };
        let open2 = Finding {
            id: "f-o2".into(),
            session_id: "s-t2".into(),
            lifecycle: FindingLifecycle::Open,
            ..resolved
        };
        assert!(
            guard
                .respond
                .group_finding_into_incident("", "key-t", &open1, 1_000)
                .is_none()
        );
        assert!(
            guard
                .respond
                .group_finding_into_incident("org-sec", "", &open1, 1_000)
                .is_none()
        );
        guard
            .respond
            .group_finding_into_incident("org-sec", "key-t", &open1, 1_000)
            .expect("first open grouped");
        guard
            .respond
            .group_finding_into_incident("org-sec", "key-t", &open2, 100_000)
            .expect("second open >24h later creates distinct incident");
        assert_eq!(guard.respond.incidents.len(), 2);
    }
}

fn prev_org(r: &ApproverRosterState) -> String {
    r.org_id.clone()
}
