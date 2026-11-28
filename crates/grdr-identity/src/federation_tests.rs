// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use grdr_crypto::SigningKeypair;
use grdr_model::{InstallProfile, SessionLabel};
use jiff::Timestamp;
use zeroize::Zeroizing;

use crate::attest::{
    AgentInstanceAliasMap, AgentInstanceRecord, FederatedWorkloadClaim, FederatedWorkloadSource,
    InstanceSponsorKind, SponsorRef, SponsorState, sign_local_attestation,
    verify_federated_workload_claim, verify_signed_local_attestation,
};
use crate::broker_types::{
    BrokerPolicy, BrokerRequest, BrokeredToken, Ceiling, ContainmentStatus, CredentialBinding,
    CredentialClass, CredentialMode, LeaseState,
};
use crate::ceiling_ref::{
    CeilingProbe, is_safe_resource_string, reference_intersect_ceilings,
    verify_no_widening_with_ref,
};
use crate::cred_bindings::{
    AttributionGradeKind, build_session_env_bindings, build_tag_grade_env_markers,
    detect_helper_config_conflicts,
};
use crate::cred_helpers::{
    format_gh_credential_token, format_npm_userconfig, format_pypi_twine_env,
};
use crate::jwt_keys::{
    TokenKeyRing, discovery_metadata, keypair_to_jwk, protected_resource_metadata,
};
#[cfg(windows)]
use crate::keystore::{OsKeystore, adopt_credential_into_store, verify_secret_store_port_contract};
use crate::locator::{CredentialLocatorPack, HygieneRuleId, HygieneSignal};
use crate::locator_scan::{
    OsPermissionSnapshot, ScanOptions, evaluate_readable_by_oracle, scan_roots_for_credentials,
};
use crate::model_cred::{
    ModelCredentialMode, ModelCredentialSpec, compile_model_credential_env,
    detect_model_credential_drift,
};
use crate::phantom::{
    PeerProcessContext, PhantomMisuseReason, PhantomResolution, PhantomTokenTable,
    mint_locator_shaped_phantom,
};
use crate::registry_correlation::{
    Agent365LicenseState, EntraTokenClaims, correlate_registry_records, normalize_agent365_entry,
    normalize_aws_agentcore_arn, normalize_entra_agent_id, normalize_google_workload,
    normalize_okta_ud_agent,
};
#[cfg(windows)]
use crate::secret_store::{SecretStore, SecretStoreKind};
use crate::spiffe::{
    AgentLifecycle, AttestationEvidence, IdentityProof, LocalAttestation, SpiffeId, derive_agi_id,
    derive_aid_id, derive_ci_workload_key, derive_k8s_workload_key,
};
use crate::ssh_agent::{
    SSH_AGENT_FAILURE, SSH_AGENT_IDENTITIES_ANSWER, SSH_AGENT_SIGN_RESPONSE,
    SSH_AGENTC_ADD_IDENTITY, SSH_AGENTC_REQUEST_IDENTITIES, SSH_AGENTC_SIGN_REQUEST,
    SignOnlySshAgent, SshCallerContext,
};
use crate::standards_adapters::{
    CimdClientMetadata, ID_JAG_TYP_V06, IdJagClaims, IdJagReplayCache, SecurityEventKind,
    SetSubjectIdentifier, TokenStatusList, TransactionTokenClaims, build_security_event_token,
};
use crate::token_exchange::{
    ActorClaim, DpopPayload, DpopProofVerifier, GrdrAccessClaims, JtiDenyList,
    TokenExchangeRequest, TokenExchangeService, sign_dpop_proof,
};
use crate::{CredentialBroker, RevocationScope};

fn now_ts() -> Timestamp {
    Timestamp::from_second(1_760_000_000).expect("valid timestamp")
}

#[test]
fn ten_thousand_spiffe_ids_round_trip_and_malformed_rejected() {
    for i in 0..10_000u32 {
        let org = format!("org{}", i % 37);
        let agi = format!("agi_{i:05}");
        let spiffe = SpiffeId::agent_instance(&org, &agi).expect("valid spiffe");
        let reparsed = SpiffeId::parse(spiffe.as_str()).expect("reparse spiffe");
        assert_eq!(spiffe, reparsed);
    }

    assert!(SpiffeId::device("acme", "dev-01").is_ok());
    assert!(SpiffeId::gateway("acme", "gw-01").is_ok());
    assert!(SpiffeId::workload("org-acme", "k8s", "runner.default").is_ok());

    for bad in [
        "https://org/agi/1",
        "spiffe://org:8443/agi/1",
        "spiffe://org/agi/../secret",
        "spiffe://org/agi/1?x=1",
        "spiffe://org/agi/1#frag",
        "spiffe://user@org/agi/1",
    ] {
        assert!(SpiffeId::parse(bad).is_err(), "expected failure for {bad}");
    }
}

#[test]
fn attestation_user_or_exec_tag_never_attested_and_lifecycle_machine_enforced() {
    let kp = SigningKeypair::generate().expect("kp");
    let ts = now_ts();
    let local_agi = derive_agi_id(&[7u8; 32], "sha256_bin", "sha256_cfg");
    assert_eq!(
        local_agi,
        derive_agi_id(&[7u8; 32], "sha256_bin", "sha256_cfg")
    );
    let aid = derive_aid_id(&[9u8; 32], &local_agi, 1);
    assert!(aid.starts_with("aid_1_"));
    assert!(derive_k8s_workload_key("prod", "builder", "sha256:abc").is_ok());
    assert!(
        derive_ci_workload_key(
            "https://token.actions.githubusercontent.com",
            "org/repo",
            "main"
        )
        .is_ok()
    );

    let org_spiffe = SpiffeId::agent_instance("acme", &local_agi).expect("spiffe");
    let mut aliases = AgentInstanceAliasMap::default();
    aliases
        .record_join_alias(&local_agi, &org_spiffe)
        .expect("alias");
    assert_eq!(
        aliases.resolve_enrolled_id(&local_agi),
        Some(org_spiffe.as_str())
    );

    let user_att = LocalAttestation {
        process_key: "p1".into(),
        program_identity: "claude-code".into(),
        session_id: "ses_1".into(),
        container_ref: Some("ctr_1".into()),
        lineage_grade: 4,
        evidence: vec![AttestationEvidence::SessionContainer],
        profile: InstallProfile::User,
        attested_at: ts,
        boot_id: "boot_1".into(),
    };
    let signed_user = sign_local_attestation(user_att, &kp).expect("sign");
    assert_eq!(
        verify_signed_local_attestation(
            &signed_user,
            "claude-code",
            true,
            Some(&kp.public_key_b64())
        )
        .expect("verify"),
        IdentityProof::Observed
    );

    let exec_only_att = LocalAttestation {
        process_key: "p2".into(),
        program_identity: "claude-code".into(),
        session_id: "ses_2".into(),
        container_ref: Some("ctr_2".into()),
        lineage_grade: 3,
        evidence: vec![AttestationEvidence::ExecTag],
        profile: InstallProfile::Protected,
        attested_at: ts,
        boot_id: "boot_1".into(),
    };
    let signed_exec = sign_local_attestation(exec_only_att, &kp).expect("sign");
    assert_eq!(
        verify_signed_local_attestation(
            &signed_exec,
            "claude-code",
            true,
            Some(&kp.public_key_b64())
        )
        .expect("verify"),
        IdentityProof::Observed
    );

    let good_att = LocalAttestation {
        process_key: "p3".into(),
        program_identity: "claude-code".into(),
        session_id: "ses_3".into(),
        container_ref: Some("ctr_3".into()),
        lineage_grade: 4,
        evidence: vec![
            AttestationEvidence::SessionContainer,
            AttestationEvidence::KernelPeerHandle,
        ],
        profile: InstallProfile::Protected,
        attested_at: ts,
        boot_id: "boot_1".into(),
    };
    let signed_good = sign_local_attestation(good_att, &kp).expect("sign");
    assert!(verify_signed_local_attestation(&signed_good, "claude-code", true, None).is_err());
    assert_eq!(
        verify_signed_local_attestation(
            &signed_good,
            "claude-code",
            true,
            Some(&kp.public_key_b64())
        )
        .expect("verify"),
        IdentityProof::Attested
    );

    let fed = FederatedWorkloadClaim {
        source: FederatedWorkloadSource::KubernetesOidc,
        issuer: "https://kubernetes.default.svc".into(),
        subject: "system:serviceaccount:ci:runner".into(),
        trust_domain: "org-acme".into(),
        cluster_or_repo: "prod-us".into(),
        workload_ref: "runner".into(),
        digest: None,
        expires_at: Timestamp::from_second(ts.as_second() + 300).expect("exp"),
    };
    assert!(
        verify_federated_workload_claim(&fed, &["https://kubernetes.default.svc".into()], ts)
            .is_ok()
    );

    let fed_slash = FederatedWorkloadClaim {
        cluster_or_repo: "org/app".into(),
        ..fed.clone()
    };
    let fed_dash = FederatedWorkloadClaim {
        cluster_or_repo: "org-app".into(),
        ..fed
    };
    let s1 =
        verify_federated_workload_claim(&fed_slash, &["https://kubernetes.default.svc".into()], ts)
            .expect("slash");
    let s2 =
        verify_federated_workload_claim(&fed_dash, &["https://kubernetes.default.svc".into()], ts)
            .expect("dash");
    assert_ne!(s1.as_str(), s2.as_str());
    assert_ne!(
        derive_agi_id(&[7u8; 32], "a|b", "c"),
        derive_agi_id(&[7u8; 32], "a", "b|c")
    );

    let mut rec = AgentInstanceRecord::new_discovered(&local_agi, org_spiffe);
    assert!(
        rec.transition_lifecycle(AgentLifecycle::Active, ts)
            .is_err()
    );
    rec.sponsor = Some(SponsorRef {
        sponsor_id: "initial_sponsor".into(),
        sponsor_kind: InstanceSponsorKind::HumanUser,
        state: SponsorState::Active,
    });
    rec.transition_lifecycle(AgentLifecycle::Active, ts)
        .expect("activate");
    rec.transition_lifecycle(AgentLifecycle::Orphaned, ts)
        .expect("orphan");
    rec.initiate_sponsor_transfer(
        SponsorRef {
            sponsor_id: "alice".into(),
            sponsor_kind: InstanceSponsorKind::HumanUser,
            state: SponsorState::Active,
        },
        "admin",
        ts,
    )
    .expect("initiate");
    rec.accept_sponsor_transfer("alice").expect("accept");
    assert_eq!(rec.lifecycle, AgentLifecycle::Active);
    rec.transition_lifecycle(AgentLifecycle::Retired, ts)
        .expect("retire");
    assert!(
        rec.transition_lifecycle(AgentLifecycle::Active, ts)
            .is_err()
    );
    let retired_ev = rec
        .observe_runtime_session("ses_late", ts)
        .expect("retired-seen");
    assert_eq!(retired_ev.event_kind, "identity.retired-seen");
}

#[test]
fn one_million_differential_scope_intersections_zero_widening() {
    let classes = [
        CredentialClass::Model,
        CredentialClass::Cloud,
        CredentialClass::Forge,
    ];
    let accounts = ["acct_a", "acct_b"];
    let actions = ["read", "write", "invoke"];
    let prefixes = [
        "https://api.example.com/v1",
        "https://api.example.com/v1/repos",
        "https://api.example.com/v2",
    ];
    let probes = [
        "https://api.example.com/v1",
        "https://api.example.com/v1/repos/app",
        "https://api.example.com/v2/items",
        "https://api.example.com/v1/../secret",
        "https://api.example.com@evil.com/v1",
    ];
    assert!(!is_safe_resource_string(
        "https://api.example.com/v1/../secret"
    ));
    assert!(!is_safe_resource_string(
        "https://api.example.com@evil.com/v1"
    ));

    let mut state: u64 = 0x5eed_cafe_1234_5678;
    let mut next_u64 = || -> u64 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        state
    };

    let mut parent = Ceiling {
        allowed_classes: BTreeSet::new(),
        allowed_accounts: BTreeSet::new(),
        allowed_actions: BTreeSet::new(),
        allowed_resource_prefixes: Vec::new(),
        max_ttl_secs: 600,
        max_depth: 3,
    };
    let mut child = parent.clone();

    let mut checked: usize = 0;
    for _iter in 0..200_000usize {
        parent.allowed_classes.clear();
        child.allowed_classes.clear();
        parent.allowed_accounts.clear();
        child.allowed_accounts.clear();
        parent.allowed_actions.clear();
        child.allowed_actions.clear();
        parent.allowed_resource_prefixes.clear();
        child.allowed_resource_prefixes.clear();

        let m1 = next_u64();
        let m2 = next_u64();
        for (idx, c) in classes.iter().enumerate() {
            if (m1 >> idx) & 1 == 1 {
                parent.allowed_classes.insert(*c);
            }
            if (m2 >> idx) & 1 == 1 {
                child.allowed_classes.insert(*c);
            }
        }
        parent
            .allowed_accounts
            .insert(accounts[(m1 as usize) & 1].to_string());
        child
            .allowed_accounts
            .insert(accounts[(m2 as usize) & 1].to_string());
        parent
            .allowed_actions
            .insert(actions[((m1 >> 4) as usize) % 3].to_string());
        child
            .allowed_actions
            .insert(actions[((m2 >> 4) as usize) % 3].to_string());
        parent
            .allowed_resource_prefixes
            .push(prefixes[((m1 >> 7) as usize) % 3].to_string());
        child
            .allowed_resource_prefixes
            .push(prefixes[((m2 >> 7) as usize) % 3].to_string());
        parent.max_depth = u32::try_from((m1 >> 10) & 3).unwrap_or(0);
        child.max_depth = u32::try_from((m2 >> 10) & 3).unwrap_or(0);

        let intersected = parent.intersect(&child);
        let ref_ceiled = reference_intersect_ceilings(&parent, &child);
        for probe in probes {
            let cls = classes[((m1 >> 14) as usize) % 3];
            let acc = accounts[((m2 >> 14) as usize) & 1];
            let act = actions[((m1 >> 16) as usize) % 3];
            let probe_req = CeilingProbe {
                class: cls,
                account_id: acc,
                action: act,
                resource: probe,
                depth: 1,
            };
            verify_no_widening_with_ref(&parent, &child, &ref_ceiled, &intersected, &probe_req)
                .expect("differential match");
            checked = checked.saturating_add(1);
        }
    }
    assert_eq!(checked, 1_000_000);
}

#[test]
fn tm19_phantom_swap_misuse_revocation_and_ssh_agent() {
    let ts = now_ts();
    let mut broker = CredentialBroker::new(BrokerPolicy::default());
    let binding = CredentialBinding {
        credential_id: "cred_forge_1".into(),
        class: CredentialClass::Forge,
        account_id: "org-1".into(),
        allowed_programs: vec!["git".into()],
        allowed_hosts: vec!["github.com".into()],
        upstream_revocable: true,
        upstream_min_ttl_secs: 60,
        phantom_prefix: "ghs_".into(),
    };
    let req = BrokerRequest {
        session_id: "ses_contained".into(),
        instance_spiffe_id: SpiffeId::agent_instance("org1", "agi_1").expect("spiffe"),
        device_id: "dev_1".into(),
        caller_program: "git".into(),
        requested_class: CredentialClass::Forge,
        requested_action: "read".into(),
        requested_resource: "https://github.com/org/repo".into(),
        requested_mode: CredentialMode::Inject,
        requested_ttl_secs: 600,
        session_remaining_secs: 1800,
        attribution_grade: 3,
        has_session_container: true,
        containment: ContainmentStatus::Contained,
        lifecycle: AgentLifecycle::Active,
        ceiling: Some(Ceiling {
            allowed_classes: BTreeSet::from([CredentialClass::Forge]),
            allowed_accounts: BTreeSet::from(["org-1".into()]),
            allowed_actions: BTreeSet::from(["read".into()]),
            allowed_resource_prefixes: vec!["https://github.com/org".into()],
            max_ttl_secs: 600,
            max_depth: 2,
        }),
        act_chain_depth: 0,
        dpop_jkt: None,
    };
    let phantom = broker
        .request_credential(&binding, &req, ts)
        .expect("lease");
    broker.register_lease_principal(&phantom.lease_id, "user_alice");
    assert!(mint_locator_shaped_phantom("grdr_").expect("mint").len() >= 27);

    let mut table = PhantomTokenTable::new();
    table
        .register_for_lease(
            &phantom,
            "ghs_",
            "store_key_1",
            vec!["github.com".into()],
            Some(4242),
            Some(1000),
        )
        .expect("register");

    let valid_caller = PeerProcessContext {
        session_id: "ses_contained".into(),
        instance_spiffe_id: phantom.bound_instance_spiffe_id.clone(),
        device_id: "dev_1".into(),
        pid: 4242,
        uid: 1000,
        containment: ContainmentStatus::Contained,
        target_host: Some("github.com".into()),
    };
    assert!(matches!(
        table.swap_credential(&phantom.token_value, &valid_caller, &mut broker, ts),
        PhantomResolution::Authorized { .. }
    ));

    let uncontained = PeerProcessContext {
        containment: ContainmentStatus::Uncontained,
        ..valid_caller.clone()
    };
    let denied = table.swap_credential(&phantom.token_value, &uncontained, &mut broker, ts);
    match denied {
        PhantomResolution::Denied {
            finding,
            revoked_lease_count,
        } => {
            assert_eq!(finding.finding_kind, "cred.phantom.misuse");
            assert_eq!(finding.reason, PhantomMisuseReason::UncontainedCaller);
            assert_eq!(revoked_lease_count, 1);
        }
        PhantomResolution::Authorized { .. } => panic!("uncontained must be denied"),
    }

    let req2 = BrokerRequest {
        session_id: "ses_two".into(),
        ..req
    };
    let tok2 = broker
        .request_credential(&binding, &req2, ts)
        .expect("lease2");
    broker.register_lease_principal(&tok2.lease_id, "user_alice");
    let t0 = Instant::now();
    let count = broker.revoke_scope(&RevocationScope::Principal("user_alice".into()));
    assert_eq!(count, 1);
    assert!(t0.elapsed().as_secs() < 5);

    let tok3 = broker
        .request_credential(&binding, &req2, ts)
        .expect("lease3");
    let mut ssh_agent = SignOnlySshAgent::new();
    let kp = SigningKeypair::generate().expect("ssh kp");
    let pk_blob = ssh_agent
        .register_lease_key(
            "bot@dev",
            kp,
            &tok3.lease_id,
            "ses_two",
            vec!["github.com".into()],
        )
        .expect("reg ssh");
    let caller = SshCallerContext {
        session_id: "ses_two".into(),
        containment: ContainmentStatus::Contained,
        target_host: Some("github.com".into()),
    };
    let list_pkt = frame_wire(&[SSH_AGENTC_REQUEST_IDENTITIES]);
    let list_rep = ssh_agent
        .handle_framed_packet(&list_pkt, &caller, &broker, ts)
        .expect("list");
    assert_eq!(list_rep[4], SSH_AGENT_IDENTITIES_ANSWER);

    let mut sign_body = vec![SSH_AGENTC_SIGN_REQUEST];
    push_wire_bytes(&mut sign_body, &pk_blob);
    push_wire_bytes(&mut sign_body, b"ssh-auth-challenge");
    sign_body.extend_from_slice(&0u32.to_be_bytes());
    let sign_rep = ssh_agent
        .handle_framed_packet(&frame_wire(&sign_body), &caller, &broker, ts)
        .expect("sign");
    assert_eq!(sign_rep[4], SSH_AGENT_SIGN_RESPONSE);

    let add_rep = ssh_agent
        .handle_framed_packet(
            &frame_wire(&[SSH_AGENTC_ADD_IDENTITY]),
            &caller,
            &broker,
            ts,
        )
        .expect("reject add");
    assert_eq!(add_rep[4], SSH_AGENT_FAILURE);
    assert_eq!(
        broker.lease(&tok3.lease_id).map(|l| l.state),
        Some(LeaseState::Active)
    );
}

#[test]
fn locator_pack_has_40_plus_stores_h8_h12_model_compiler_and_helpers() {
    let pack_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .join("packs")
        .join("credential-locator");
    let pack = CredentialLocatorPack::load_from_dir(&pack_dir).expect("load locator pack");
    assert!(
        pack.locators().len() >= 40,
        "expected >=40 locators, got {}",
        pack.locators().len()
    );

    let tmp_root =
        std::env::temp_dir().join(format!("grdr_scan_{}", uuid::Uuid::now_v7().simple()));
    let k8s_dir = tmp_root.join("var/run/secrets/kubernetes.io/serviceaccount");
    std::fs::create_dir_all(&k8s_dir).expect("mkdir");
    let token_path = k8s_dir.join("token");
    std::fs::write(
        &token_path,
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzYSJ9.sig1234567890abcdef",
    )
    .expect("write sa token");
    let snap = OsPermissionSnapshot {
        path: token_path.to_string_lossy().into_owned(),
        unix_mode: Some(0o644),
        human_principal: Some("alice".into()),
        agent_lineages: vec!["claude-code".into()],
        world_or_group_readable: true,
        acl_shared_with_human: true,
    };
    let (readers, sigs) = evaluate_readable_by_oracle(&snap);
    assert_eq!(readers, vec!["claude-code".to_string()]);
    assert!(sigs.contains(&HygieneSignal::SharedWithHuman));
    assert!(sigs.contains(&HygieneSignal::K8sAutomountSaToken));

    let report = scan_roots_for_credentials(
        &pack,
        b"hmac-key-test",
        &[tmp_root.as_path()],
        &[snap],
        &ScanOptions::default(),
    )
    .expect("scan");
    let _ = std::fs::remove_dir_all(&tmp_root);
    assert_eq!(report.findings.len(), 1);
    let f = &report.findings[0];
    assert!(f.crd_id.starts_with("crd_"));
    assert!(
        f.hygiene_findings
            .iter()
            .any(|h| h.rule_id == HygieneRuleId::H8)
    );
    assert!(
        f.hygiene_findings
            .iter()
            .any(|h| h.rule_id == HygieneRuleId::H12)
    );
    let finding_json = serde_json::to_string(f).expect("json");
    assert!(!finding_json.contains("eyJhbGciOiJSUzI1NiIs"));

    let model_spec = ModelCredentialSpec {
        agent_family: "claude".into(),
        mode: ModelCredentialMode::VendorLogin,
        gateway_base_url: None,
        key_helper_command: None,
        federated_audience: None,
    };
    let bad_env = BTreeMap::from([("ANTHROPIC_API_KEY".into(), "sk-ant-raw".into())]);
    assert!(compile_model_credential_env(&model_spec, None, &bad_env).is_err());
    let compiled = compile_model_credential_env(&model_spec, None, &BTreeMap::new()).expect("ok");
    assert_eq!(
        compiled
            .set_env
            .get("CLAUDE_CODE_USE_OAUTH")
            .map(String::as_str),
        Some("1")
    );
    let drift = detect_model_credential_drift(&model_spec, &bad_env, &[]).expect("drift");
    assert_eq!(drift.rule_id, HygieneRuleId::H11);

    let remote_http_gw = ModelCredentialSpec {
        agent_family: "claude".into(),
        mode: ModelCredentialMode::Gateway,
        gateway_base_url: Some("http://evil.example.test/v1".into()),
        key_helper_command: None,
        federated_audience: None,
    };
    assert!(
        compile_model_credential_env(&remote_http_gw, Some("gw_tok_123"), &BTreeMap::new())
            .is_err()
    );

    let https_gw = ModelCredentialSpec {
        agent_family: "claude".into(),
        mode: ModelCredentialMode::Gateway,
        gateway_base_url: Some("https://gw.example.test/v1".into()),
        key_helper_command: None,
        federated_audience: None,
    };
    let compiled_gw =
        compile_model_credential_env(&https_gw, Some("gw_tok_123"), &BTreeMap::new()).expect("gw");
    assert_eq!(
        compiled_gw
            .set_env
            .get("ANTHROPIC_BASE_URL")
            .map(String::as_str),
        Some("https://gw.example.test/v1")
    );

    let bindings =
        build_session_env_bindings("grdr", "/tmp/ssh.sock", "/tmp/cfg").expect("bindings");
    assert_eq!(bindings.len(), 9);
    assert!(bindings.iter().all(|b| !b.edits_user_dotfiles));
    assert!(
        !detect_helper_config_conflicts(
            &BTreeMap::from([("NPM_TOKEN".into(), "x".into())]),
            &["~/.npmrc"]
        )
        .is_empty()
    );

    let markers = build_tag_grade_env_markers(
        AttributionGradeKind::Tag,
        "agi_very_long_identifier_1234567890",
        "ses_very_long_12345",
        "trc_1",
    );
    assert!(markers.env_vars["AWS_SDK_UA_APP_ID"].len() <= 50);

    let dummy = dummy_brokered_token("tok_val_123");
    assert_eq!(
        format_gh_credential_token(&dummy).expect("gh").as_str(),
        "tok_val_123"
    );
    assert!(
        format_npm_userconfig("https://registry.npmjs.org", &dummy)
            .expect("npm")
            .contains("_authToken=tok_val_123")
    );
    assert!(
        format_pypi_twine_env("https://upload.pypi.org/legacy/", &dummy)
            .expect("pypi")
            .contains("TWINE_PASSWORD=tok_val_123")
    );
}

#[tokio::test]
async fn os_keystore_and_federation_crypto_adapters_end_to_end() {
    #[cfg(windows)]
    {
        let root = std::env::temp_dir().join(format!("grdr_ks_{}", uuid::Uuid::now_v7().simple()));
        let store = OsKeystore::open_platform(Some(root.clone()), b"ent".to_vec(), "grdr-test")
            .expect("open dpapi");
        assert_eq!(store.store_kind(), SecretStoreKind::Win32Dpapi);
        verify_secret_store_port_contract(&store, "test_secret_1", b"super-secret")
            .await
            .expect("contract");
        let adopted = adopt_credential_into_store(
            &store,
            b"hmac",
            "dotenv-file",
            "OPENAI_API_KEY",
            Zeroizing::new(b"sk-secret-value".to_vec()),
            now_ts(),
        )
        .await
        .expect("adopt");
        assert!(adopted.crd_id.starts_with("crd_"));
        let _ = std::fs::remove_dir_all(&root);
    }

    let ts = now_ts();
    let mut ring = TokenKeyRing::generate().expect("ring");
    let client_kp = SigningKeypair::generate().expect("dpop");
    let meta = discovery_metadata("https://auth.example.test");
    assert!(meta.jwks_uri.ends_with("/.well-known/jwks.json"));
    assert!(
        protected_resource_metadata("https://auth.example.test", "https://mcp.example.test")
            .resource
            .contains("mcp.example.test")
    );

    let mut dpop_verifier = DpopProofVerifier::new();
    let proof = sign_dpop_proof(
        &client_kp,
        &DpopPayload {
            jti: "dpop_1".into(),
            htm: "POST".into(),
            htu: "https://auth.example.test/oauth2/token".into(),
            iat: ts.as_second(),
            ath: None,
        },
    )
    .expect("dpop");
    let jkt = dpop_verifier
        .verify_proof(
            &proof,
            "POST",
            "https://auth.example.test/oauth2/token",
            None,
            ts,
        )
        .expect("verify dpop");
    assert!(
        dpop_verifier
            .verify_proof(
                &proof,
                "POST",
                "https://auth.example.test/oauth2/token",
                None,
                ts
            )
            .is_err()
    );

    let subject_claims = GrdrAccessClaims {
        iss: "https://auth.example.test".into(),
        sub: "prn_org_1_abc".into(),
        aud: "https://auth.example.test".into(),
        iat: ts.as_second(),
        exp: ts.as_second() + 900,
        jti: "jti_subj_1".into(),
        client_id: "cli_1".into(),
        scope: "broker:lease identity:read".into(),
        agi_id: "agi_1".into(),
        spiffe_id: "spiffe://org-acme/agi/agi_1".into(),
        act: Some(ActorClaim {
            sub: "spiffe://org-acme/agi/agi_0".into(),
            act: None,
        }),
        cnf: None,
    };
    let signed_sub = ring.sign_jwt("at+jwt", &subject_claims).expect("sign");
    let next_kp = SigningKeypair::generate().expect("next");
    ring.rotate(next_kp);
    assert!(
        ring.verify_jwt::<GrdrAccessClaims>(&signed_sub, Some("at+jwt"))
            .is_ok()
    );

    let mut deny = JtiDenyList::new();
    let ex_svc = TokenExchangeService {
        issuer: "https://auth.example.test".into(),
        trusted_spiffe_domains: BTreeSet::from(["org-acme".into()]),
    };
    let ex_req = TokenExchangeRequest {
        subject_claims: subject_claims.clone(),
        requested_audience: "https://api.example.com/v1/tools".into(),
        requested_scope: "broker:lease".into(),
        actor_subject: "spiffe://org-acme/agi/agi_1".into(),
        parent_ceiling: Ceiling {
            allowed_classes: BTreeSet::from([CredentialClass::Model]),
            allowed_accounts: BTreeSet::from(["a".into()]),
            allowed_actions: BTreeSet::from(["read".into()]),
            allowed_resource_prefixes: vec!["https://api.example.com".into()],
            max_ttl_secs: 600,
            max_depth: 4,
        },
        child_ceiling: Ceiling {
            allowed_classes: BTreeSet::from([CredentialClass::Model]),
            allowed_accounts: BTreeSet::from(["a".into()]),
            allowed_actions: BTreeSet::from(["read".into()]),
            allowed_resource_prefixes: vec!["https://api.example.com/v1".into()],
            max_ttl_secs: 300,
            max_depth: 3,
        },
        requested_ttl_secs: 300,
        federated_trust_domain: Some("org-acme".into()),
        dpop_jkt: Some(jkt.clone()),
    };
    let (exchanged, _) = ex_svc.exchange(&ex_req, &deny, ts).expect("exchange");
    assert_eq!(exchanged.exp - exchanged.iat, 300);

    // Exchanging DPoP-bound token without matching cnf.jkt or outside ceiling fails.
    let mut cnf_req = ex_req.clone();
    cnf_req.subject_claims.cnf = Some(crate::token_exchange::DpopCnfClaim {
        jkt: "different_jkt".into(),
    });
    assert!(ex_svc.exchange(&cnf_req, &deny, ts).is_err());
    let mut bad_aud_req = ex_req.clone();
    bad_aud_req.requested_audience = "https://api.example.com-evil/v1".into();
    assert!(ex_svc.exchange(&bad_aud_req, &deny, ts).is_err());

    deny.revoke("jti_subj_1", ts.as_second() + 900, ts.as_second())
        .expect("revoke");
    assert!(ex_svc.exchange(&ex_req, &deny, ts).is_err());

    let idp_kp = SigningKeypair::generate().expect("idp kp");
    let idp_ring = TokenKeyRing::from_active(Arc::new(idp_kp.clone()));
    let trusted_idp_keys = vec![keypair_to_jwk(&idp_kp)];
    let trusted_issuers = vec!["https://idp.example.test".to_string()];
    let jag_claims = IdJagClaims {
        iss: "https://idp.example.test".into(),
        sub: "alice".into(),
        aud: "https://auth.example.test".into(),
        resource: "https://mcp.example.test".into(),
        client_id: "https://auth.example.test/clients/mcp-broker".into(),
        jti: "jag_single_use_1".into(),
        iat: ts.as_second(),
        exp: ts.as_second() + 120,
        scope: "mcp:invoke".into(),
        spiffe_id: Some("spiffe://org-acme/agi/agi_1".into()),
    };
    let jag_jwt = idp_ring
        .sign_jwt(ID_JAG_TYP_V06, &jag_claims)
        .expect("jag jwt");
    let mut jag_cache = IdJagReplayCache::new();
    // Self-signed or untrusted key fails ID-JAG verification.
    let self_signed_jag = ring
        .sign_jwt(ID_JAG_TYP_V06, &jag_claims)
        .expect("self jag");
    assert!(
        jag_cache
            .validate_and_consume(
                &trusted_idp_keys,
                &trusted_issuers,
                &self_signed_jag,
                "https://auth.example.test",
                "https://mcp.example.test",
                ts
            )
            .is_err()
    );
    assert!(
        jag_cache
            .validate_and_consume(
                &trusted_idp_keys,
                &trusted_issuers,
                &jag_jwt,
                "https://auth.example.test",
                "https://mcp.example.test",
                ts
            )
            .is_ok()
    );
    assert!(
        jag_cache
            .validate_and_consume(
                &trusted_idp_keys,
                &trusted_issuers,
                &jag_jwt,
                "https://auth.example.test",
                "https://mcp.example.test",
                ts
            )
            .is_err()
    );
    let _ = jkt;

    let cimd = CimdClientMetadata {
        client_id: "https://auth.example.test/clients/mcp-broker".into(),
        client_name: "Broker".into(),
        grant_types: vec![],
        token_endpoint_auth_method: "private_key_jwt".into(),
        scope: "mcp:invoke".into(),
        jwks_uri: None,
        spiffe_trust_domain: None,
    };
    assert!(cimd.validate().is_ok());

    let txn = TransactionTokenClaims {
        iss: "https://auth.example.test".into(),
        sub: "alice".into(),
        aud: "https://svc.example.test".into(),
        txn: "txn_1".into(),
        purp: "tool_call".into(),
        tctx: serde_json::json!({}),
        rctx: serde_json::json!({}),
        iat: ts.as_second(),
        exp: ts.as_second() + 120,
    };
    assert!(txn.validate(ts).is_ok());

    let mut sl = TokenStatusList::with_capacity_bits(64);
    sl.set_revoked(17, true).expect("set bit");
    let doc = sl.to_document(
        "https://auth.example.test",
        "https://auth.example.test/status",
        ts,
    );
    let parsed_sl = TokenStatusList::from_document(&doc).expect("decode");
    assert!(parsed_sl.is_revoked(17));
    assert!(!parsed_sl.is_revoked(18));

    let set_ev = build_security_event_token(
        "https://auth.example.test",
        "rp",
        "set_1",
        SecurityEventKind::CaepAssuranceLevelChange,
        &SetSubjectIdentifier {
            format: "iss_sub".into(),
            iss: None,
            sub: "agi_1".into(),
        },
        Some("AL3"),
        ts,
    );
    assert!(!set_ev.events.is_empty());

    let local = vec![AgentInstanceRecord::new_discovered(
        "agi_1",
        SpiffeId::agent_instance("acme", "agi_1").expect("spiffe"),
    )];
    let entra = normalize_entra_agent_id(&EntraTokenClaims {
        oid: "oid_1".into(),
        azp: Some("app_1".into()),
        appid: None,
        xms_act_fct: Some("AgentId".into()),
        xms_sub_fct: Some("Autonomous".into()),
        xms_idrel: Some("2".into()),
        spiffe_id: Some("spiffe://org-acme/agi/agi_1".into()),
        sponsor_oid: Some("alice".into()),
        display_name: "Different Display Name".into(),
    })
    .expect("entra");
    let (a365, a365_state) =
        normalize_agent365_entry("bp_1", None, None, "Unmatched Name", false).expect("365");
    let okta = normalize_okta_ud_agent(
        "okta_1",
        Some("aid_99".into()),
        None,
        None,
        "Same Name Trap",
    )
    .expect("okta");
    let aws = normalize_aws_agentcore_arn(
        "arn:aws:bedrock-agentcore:us-east-1:123:agent/ag1",
        None,
        "AWS",
    )
    .expect("aws");
    let gcp = normalize_google_workload(
        "principal://iam.googleapis.com/p1",
        "spiffe://org-acme/wl/gcp/p1",
        "GCP",
    )
    .expect("gcp");
    let corr = correlate_registry_records(&local, &[entra, a365, okta, aws, gcp], a365_state);
    assert_eq!(corr.correlated.len(), 1);
    assert_eq!(corr.correlated[0].matched_by, "spiffe_id");
    assert_eq!(
        corr.agent365_license_state,
        Agent365LicenseState::UnlicensedDegraded
    );
    let _ = Arc::new(ring);
}

fn dummy_brokered_token(val: &str) -> BrokeredToken {
    BrokeredToken {
        jti: "jti_1".into(),
        lease_id: "lse_1".into(),
        mode: CredentialMode::Inject,
        token_value: Zeroizing::new(val.into()),
        non_transferable: true,
        bound_session_id: "ses_1".into(),
        bound_instance_spiffe_id: "spiffe://org-1/agi/agi_1".into(),
        bound_device_id: "dev_1".into(),
        dpop_jkt: None,
        scope_digest: "abc".into(),
        issued_at: now_ts(),
        expires_at: Timestamp::from_second(now_ts().as_second().saturating_add(300)).expect("exp"),
        session_label: Some(SessionLabel::CredentialAccessed),
    }
}

fn frame_wire(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&u32::try_from(body.len()).expect("len").to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn push_wire_bytes(dst: &mut Vec<u8>, bytes: &[u8]) {
    dst.extend_from_slice(&u32::try_from(bytes.len()).expect("len").to_be_bytes());
    dst.extend_from_slice(bytes);
}

#[test]
fn hardens_bypass_vectors_ssrf_phantom_ssh_helpers_drift_and_openssh_bcrypt() {
    use crate::ceiling_ref::reference_prefix_allows;
    use crate::http_security::validate_exact_endpoint_url;
    use crate::jwt_keys::OkpEd25519Jwk;

    for (prefix, cand) in [
        (
            "https://api.example.com/v1",
            "https://api.example.com/v1/%2e%2e/secret",
        ),
        (
            "https://api.example.com/v1",
            "https://api.example.com/v1/%2f..",
        ),
        (
            "https://api.example.com/v1",
            "https://api.example.com/v1/..;x/secret",
        ),
        (
            "https://api.example.com/v1",
            "https://api.example.com:8443/v1",
        ),
        ("https://api.example.com", "https://api.example.com-evil"),
        ("https://", "https://evil.example/v1"),
        ("http://api.example.com/v1", "https://api.example.com/v1"),
        ("arn:aws:iam::123:role-", "arn:aws:iam::123:role-admin"),
    ] {
        assert!(
            !reference_prefix_allows(prefix, cand),
            "must reject ({prefix}, {cand})"
        );
    }

    for bad_url in [
        "https://example.test/\nv1",
        "https://metadata.google.internal./computeMetadata",
        "https://100.64.0.1/token",
        "https://[fd00:ec2::254]/latest",
    ] {
        assert!(
            validate_exact_endpoint_url(bad_url, false).is_err(),
            "must reject {bad_url}"
        );
    }

    assert!(build_session_env_bindings("grdr;rm -rf /", "/tmp/ssh.sock", "/tmp/cfg").is_err());
    assert!(build_session_env_bindings("grdr with space", "/tmp/ssh.sock", "/tmp/cfg").is_err());
    let bindings = build_session_env_bindings("grdr", "/tmp/ssh.sock", "/tmp/cfg").expect("ok");
    let git_env = &bindings
        .iter()
        .find(|b| b.tool == crate::cred_bindings::HelperTool::Git)
        .expect("git")
        .env_vars;
    assert_eq!(
        git_env.get("GIT_CONFIG_COUNT").map(String::as_str),
        Some("3")
    );
    assert_eq!(
        git_env.get("GIT_CONFIG_VALUE_0").map(String::as_str),
        Some("")
    );
    let gcp_env = &bindings
        .iter()
        .find(|b| b.tool == crate::cred_bindings::HelperTool::Gcp)
        .expect("gcp")
        .env_vars;
    assert_eq!(
        gcp_env
            .get("GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES")
            .map(String::as_str),
        Some("1")
    );

    let dummy = dummy_brokered_token("tok_safe_123");
    assert!(format_npm_userconfig("http://registry.npmjs.org", &dummy).is_err());
    assert!(format_npm_userconfig("https://registry.npmjs.org/${EVIL}", &dummy).is_err());
    assert!(format_pypi_twine_env("http://pypi.example.test/", &dummy).is_err());
    assert!(format_pypi_twine_env("https://pypi.example.test/${SECRET}", &dummy).is_err());

    let gw_spec = ModelCredentialSpec {
        agent_family: "claude".into(),
        mode: ModelCredentialMode::Gateway,
        gateway_base_url: Some("https://gw.example.test/v1".into()),
        key_helper_command: None,
        federated_audience: None,
    };
    let compiled =
        compile_model_credential_env(&gw_spec, Some("gw_secret_1"), &BTreeMap::new()).expect("gw");
    assert!(!format!("{compiled:?}").contains("gw_secret_1"));
    let half_drifted = BTreeMap::from([(
        "ANTHROPIC_BASE_URL".into(),
        "https://gw.example.test/v1".into(),
    )]);
    assert!(detect_model_credential_drift(&gw_spec, &half_drifted, &[]).is_some());

    let ts = now_ts();
    let mut broker = CredentialBroker::new(BrokerPolicy::default());
    let broker_dbg = format!("{broker:?}");
    assert!(broker_dbg.contains("CredentialBroker"));
    let binding = CredentialBinding {
        credential_id: "cred_ssh_1".into(),
        class: CredentialClass::Ssh,
        account_id: "org-1".into(),
        allowed_programs: vec!["ssh".into()],
        allowed_hosts: vec!["github.com".into()],
        upstream_revocable: true,
        upstream_min_ttl_secs: 60,
        phantom_prefix: "ghs_".into(),
    };
    let req = BrokerRequest {
        session_id: "ses_1".into(),
        instance_spiffe_id: SpiffeId::agent_instance("org1", "agi_1").expect("spiffe"),
        device_id: "dev_1".into(),
        caller_program: "ssh".into(),
        requested_class: CredentialClass::Ssh,
        requested_action: "sign".into(),
        requested_resource: "https://github.com/org/repo".into(),
        requested_mode: CredentialMode::Inject,
        requested_ttl_secs: 300,
        session_remaining_secs: 600,
        attribution_grade: 3,
        has_session_container: true,
        containment: ContainmentStatus::Contained,
        lifecycle: AgentLifecycle::Active,
        ceiling: Some(Ceiling {
            allowed_classes: BTreeSet::from([CredentialClass::Ssh]),
            allowed_accounts: BTreeSet::from(["org-1".into()]),
            allowed_actions: BTreeSet::from(["sign".into()]),
            allowed_resource_prefixes: vec!["https://github.com/org".into()],
            max_ttl_secs: 300,
            max_depth: 2,
        }),
        act_chain_depth: 0,
        dpop_jkt: None,
    };
    let tok = broker.request_credential(&binding, &req, ts).expect("tok");
    let mut table = PhantomTokenTable::new();
    assert!(
        table
            .register_for_lease(&tok, "ghs_", "ref", vec![], None, None)
            .is_err()
    );
    let short_tok = BrokeredToken {
        token_value: Zeroizing::new("ghs_tooshort".into()),
        ..tok.clone()
    };
    assert!(
        table
            .register_for_lease(
                &short_tok,
                "ghs_",
                "ref",
                vec!["github.com".into()],
                None,
                None
            )
            .is_err()
    );
    table
        .register_for_lease(&tok, "ghs_", "ref", vec!["github.com".into()], None, None)
        .expect("reg");
    let no_host_caller = PeerProcessContext {
        session_id: "ses_1".into(),
        instance_spiffe_id: tok.bound_instance_spiffe_id.clone(),
        device_id: "dev_1".into(),
        pid: 1,
        uid: 1,
        containment: ContainmentStatus::Contained,
        target_host: None,
    };
    assert!(matches!(
        table.swap_credential(&tok.token_value, &no_host_caller, &mut broker, ts),
        PhantomResolution::Denied {
            finding: crate::phantom::PhantomMisuseFinding {
                reason: PhantomMisuseReason::DisallowedHost,
                ..
            },
            ..
        }
    ));

    let tok2 = broker.request_credential(&binding, &req, ts).expect("tok2");
    let mut ssh = SignOnlySshAgent::new();
    let sk = SigningKeypair::generate().expect("sk");
    assert!(
        ssh.register_lease_key("c", sk.clone(), &tok2.lease_id, "ses_1", vec![])
            .is_err()
    );
    ssh.register_lease_key("c", sk, &tok2.lease_id, "ses_1", vec!["github.com".into()])
        .expect("ssh");
    let no_host_ssh = SshCallerContext {
        session_id: "ses_1".into(),
        containment: ContainmentStatus::Contained,
        target_host: None,
    };
    let list_pkt = frame_wire(&[crate::ssh_agent::SSH_AGENTC_REQUEST_IDENTITIES]);
    let rep = ssh
        .handle_framed_packet(&list_pkt, &no_host_ssh, &broker, ts)
        .expect("rep");
    assert_eq!(rep.get(5..9), Some(&[0, 0, 0, 0][..]));

    let bad_alg_jwk = OkpEd25519Jwk {
        kty: "OKP".into(),
        crv: "Ed25519".into(),
        alg: "HS256".into(),
        key_use: "sig".into(),
        kid: "k1".into(),
        x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
    };
    assert!(bad_alg_jwk.thumbprint_sha256_b64().is_err());

    let enc_use_jwk = OkpEd25519Jwk {
        kty: "OKP".into(),
        crv: "Ed25519".into(),
        alg: "EdDSA".into(),
        key_use: "enc".into(),
        kid: "k_enc".into(),
        x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
    };
    assert!(enc_use_jwk.public_key_bytes().is_err());

    for bad_cid in [
        "https://169.254.169.254/clients/mcp",
        "https://metadata.google.internal/clients/mcp",
        "https://user@client.example.com/clients/mcp",
        "https://127.0.0.1/clients/mcp",
    ] {
        let bad_cimd = crate::standards_adapters::CimdClientMetadata {
            client_id: bad_cid.into(),
            client_name: "Evil".into(),
            grant_types: vec!["urn:ietf:params:oauth:grant-type:token-exchange".into()],
            token_endpoint_auth_method: "private_key_jwt".into(),
            scope: "broker:lease".into(),
            jwks_uri: None,
            spiffe_trust_domain: None,
        };
        assert!(
            bad_cimd.validate().is_err(),
            "SSRF client_id {bad_cid} must fail"
        );
    }
    let bad_jwks_cimd = crate::standards_adapters::CimdClientMetadata {
        client_id: "https://client.example.com/clients/mcp".into(),
        client_name: "GoodCidBadJwks".into(),
        grant_types: vec!["urn:ietf:params:oauth:grant-type:token-exchange".into()],
        token_endpoint_auth_method: "private_key_jwt".into(),
        scope: "broker:lease".into(),
        jwks_uri: Some("https://169.254.169.254/jwks.json".into()),
        spiffe_trust_domain: None,
    };
    assert!(bad_jwks_cimd.validate().is_err());

    let empty_doc = crate::standards_adapters::TokenStatusListDocument {
        iss: "https://grdr.example".into(),
        sub: "https://grdr.example/status".into(),
        iat: ts.as_second(),
        bits: 1,
        lst: "".into(),
    };
    assert!(crate::standards_adapters::TokenStatusList::from_document(&empty_doc).is_err());
    assert!(
        crate::registry_correlation::normalize_google_workload(
            "g-sa-1",
            "spiffe://bad/seg?query=1",
            "wl",
        )
        .is_err()
    );

    let mut enc_blob = Vec::from(b"openssh-key-v1\0".as_slice());
    push_wire_bytes(&mut enc_blob, b"aes256-ctr");
    push_wire_bytes(&mut enc_blob, b"bcrypt");
    let enc_pem = format!(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n",
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &enc_blob)
    );
    let pack_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("root")
        .join("packs")
        .join("credential-locator");
    let pack = CredentialLocatorPack::load_from_dir(&pack_dir).expect("pack");
    let ssh_finding = pack
        .scan_artifact(
            b"k",
            &enc_pem,
            &crate::locator::ArtifactScanContext {
                artifact_path: "/home/dev/.ssh/id_ed25519".into(),
                readable_by_agent_lineages: vec![],
                containment: ContainmentStatus::Contained,
                signals: BTreeSet::new(),
            },
        )
        .expect("scan")
        .expect("ssh");
    assert!(
        !ssh_finding
            .hygiene_findings
            .iter()
            .any(|h| h.rule_id == HygieneRuleId::H4),
        "encrypted OpenSSH bcrypt key must not false-positive H4"
    );
}
