// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeSet;

use grdr_crypto::{AeadKey, fill_random};
use grdr_model::{InstallProfile, SessionLabel};
use jiff::Timestamp;

use crate::{
    AgentLifecycle, ApproverRole, AttestationEvidence, BrokerPolicy, BrokerRequest, Ceiling,
    ContainmentStatus, CredentialBinding, CredentialBroker, CredentialClass, CredentialMode,
    IdentityError, IdentityProof, IdentityVault, LeaseState, LocalAttestation, QuarterKey,
    ReidentQuorumState, SpiffeId, VaultPolicy, derive_device_pseudonym, evaluate_attestation_proof,
    re_pseudonymize_for_org,
};

fn ts(sec: i64) -> Timestamp {
    Timestamp::from_second(sec).expect("valid timestamp")
}

fn sample_ceiling() -> Ceiling {
    let mut classes = BTreeSet::new();
    classes.insert(CredentialClass::Cloud);
    classes.insert(CredentialClass::Forge);
    classes.insert(CredentialClass::Production);

    let mut accounts = BTreeSet::new();
    accounts.insert("acct-dev".into());

    let mut actions = BTreeSet::new();
    actions.insert("sts:AssumeRole".into());
    actions.insert("git:push".into());

    Ceiling {
        allowed_classes: classes,
        allowed_accounts: accounts,
        allowed_actions: actions,
        allowed_resource_prefixes: vec![
            "arn:aws:iam::123:role/".into(),
            "https://forge.test/".into(),
        ],
        max_ttl_secs: 900,
        max_depth: 4,
    }
}

#[test]
fn spiffe_and_attestation_enforce_protected_profile_and_session_container() {
    let spiffe = SpiffeId::agent_instance("abc123", "agi_01").expect("spiffe");
    assert_eq!(spiffe.as_str(), "spiffe://org-abc123/agi/agi_01");
    assert!(SpiffeId::parse("spiffe://org-abc:8443/agi/1").is_err());
    assert!(SpiffeId::parse("spiffe://org-abc/agi/1?x=1").is_err());

    let now = ts(1_760_000_000);
    let exec_only = LocalAttestation {
        process_key: "pk-1".into(),
        program_identity: "claude-code@2.1".into(),
        session_id: "ses-1".into(),
        container_ref: None,
        lineage_grade: 2,
        evidence: vec![AttestationEvidence::ExecTag],
        profile: InstallProfile::Protected,
        attested_at: now,
        boot_id: "boot-1".into(),
    };
    assert_eq!(
        evaluate_attestation_proof(&exec_only, "claude-code@2.1", true),
        IdentityProof::Observed
    );

    let contained = LocalAttestation {
        container_ref: Some("cgroup:/grdr/ses-1".into()),
        lineage_grade: 3,
        evidence: vec![
            AttestationEvidence::SessionContainer,
            AttestationEvidence::KernelPeerHandle,
        ],
        ..exec_only
    };
    assert_eq!(
        evaluate_attestation_proof(&contained, "claude-code@2.1", true),
        IdentityProof::Attested
    );
}

#[test]
fn broker_enforces_containment_gating_ceiling_intersection_and_leases() {
    let now = ts(1_760_000_000);
    let mut broker = CredentialBroker::new(BrokerPolicy::default());
    let spiffe = SpiffeId::agent_instance("org1", "agi_1").expect("spiffe");

    let parent_ceiling = sample_ceiling();
    let mut child_classes = BTreeSet::new();
    child_classes.insert(CredentialClass::Cloud);
    let mut child_actions = BTreeSet::new();
    child_actions.insert("sts:AssumeRole".into());
    let child_ceiling = Ceiling {
        allowed_classes: child_classes,
        allowed_accounts: parent_ceiling.allowed_accounts.clone(),
        allowed_actions: child_actions,
        allowed_resource_prefixes: vec!["arn:aws:iam::123:role/readonly-".into()],
        max_ttl_secs: 600,
        max_depth: 2,
    };
    let narrowed = parent_ceiling.intersect(&child_ceiling);
    assert_eq!(narrowed.max_ttl_secs, 600);
    assert_eq!(narrowed.max_depth, 2);
    assert!(!narrowed.permits(
        CredentialClass::Cloud,
        "acct-dev",
        "sts:AssumeRole",
        "arn:aws:iam::123:role/admin",
        1,
    ));

    let cloud_binding = CredentialBinding {
        credential_id: "crd_aws_1".into(),
        class: CredentialClass::Cloud,
        account_id: "acct-dev".into(),
        allowed_programs: vec!["grdr-cred".into()],
        allowed_hosts: vec!["sts.amazonaws.com".into()],
        upstream_revocable: true,
        upstream_min_ttl_secs: 900,
        phantom_prefix: "AKIA_PHANTOM_".into(),
    };

    let mut req = BrokerRequest {
        session_id: "ses_1".into(),
        instance_spiffe_id: spiffe,
        device_id: "dev_1".into(),
        caller_program: "grdr-cred".into(),
        requested_class: CredentialClass::Cloud,
        requested_action: "sts:AssumeRole".into(),
        requested_resource: "arn:aws:iam::123:role/dev".into(),
        requested_mode: CredentialMode::Release,
        requested_ttl_secs: 1800,
        session_remaining_secs: 3600,
        attribution_grade: 3,
        has_session_container: true,
        containment: ContainmentStatus::Uncontained,
        lifecycle: AgentLifecycle::Active,
        ceiling: Some(parent_ceiling),
        act_chain_depth: 1,
        dpop_jkt: Some("jkt-thumb-1".into()),
    };

    assert!(matches!(
        broker.request_credential(&cloud_binding, &req, now),
        Err(IdentityError::UncontainedReleaseRefused)
    ));

    let mut no_ceiling_req = req.clone();
    no_ceiling_req.ceiling = None;
    assert!(matches!(
        broker.request_credential(&cloud_binding, &no_ceiling_req, now),
        Err(IdentityError::NoCeiling)
    ));

    req.requested_mode = CredentialMode::Inject;
    let inject_tok = broker
        .request_credential(&cloud_binding, &req, now)
        .expect("inject allowed");
    assert_eq!(inject_tok.mode, CredentialMode::Inject);
    assert!(inject_tok.token_value.starts_with("AKIA_PHANTOM_"));
    assert!(inject_tok.non_transferable);
    assert_eq!(inject_tok.session_label, None);
    assert_eq!(
        inject_tok
            .expires_at
            .as_second()
            .saturating_sub(now.as_second()),
        900
    );

    let prod_binding = CredentialBinding {
        credential_id: "crd_prod".into(),
        class: CredentialClass::Production,
        ..cloud_binding.clone()
    };
    let prod_req = BrokerRequest {
        requested_class: CredentialClass::Production,
        requested_mode: CredentialMode::Inject,
        ..req.clone()
    };
    assert!(matches!(
        broker.request_credential(&prod_binding, &prod_req, now),
        Err(IdentityError::ProductionRequiresContainment)
    ));

    req.requested_mode = CredentialMode::Release;
    req.containment = ContainmentStatus::Contained;
    let release_tok = broker
        .request_credential(&cloud_binding, &req, now)
        .expect("contained release");
    assert_eq!(release_tok.mode, CredentialMode::Release);
    assert_eq!(
        release_tok.session_label,
        Some(SessionLabel::CredentialAccessed)
    );
    assert!(release_tok.token_value.starts_with("grdr_rel_"));

    assert_eq!(broker.revoke_by_session("ses_1"), 2);
    assert_eq!(
        broker.lease(&release_tok.lease_id).expect("lease").state,
        LeaseState::Revoked
    );
}

#[test]
fn vault_two_layer_pseudonyms_quorum_and_90_day_deferral_cap() {
    let now = ts(1_760_000_000);
    let mut device_key = [0u8; 32];
    let mut org_key = [0u8; 32];
    fill_random(&mut device_key).expect("device key entropy");
    fill_random(&mut org_key).expect("org key entropy");
    let aead_key = AeadKey::generate().expect("vault aead key");

    let mut vault = IdentityVault::new("org_01", org_key, aead_key, 1, VaultPolicy::default());
    let (dev_prn, org_prn) = vault
        .register_subject(&device_key, "alice@example.test", "Alice")
        .expect("register subject");
    assert!(dev_prn.starts_with("prn_dev_"));
    assert!(org_prn.starts_with("prn_org_1_"));
    assert_ne!(dev_prn, org_prn);
    assert_eq!(
        dev_prn,
        derive_device_pseudonym(&device_key, "alice@example.test")
    );
    assert_eq!(org_prn, re_pseudonymize_for_org(&org_key, 1, &dev_prn));

    let pending = vault
        .request_reidentification(
            "req_1",
            "acc_investigator",
            &org_prn,
            "incident-response",
            "inc_42",
            now,
        )
        .expect("request");
    assert!(matches!(pending, ReidentQuorumState::Pending { .. }));

    assert!(matches!(
        vault.approve_reidentification(
            "req_1",
            "acc_investigator",
            ApproverRole::PrivacyOfficer,
            now
        ),
        Err(IdentityError::SelfApprovalForbidden)
    ));
    assert!(vault.resolve_reidentified_subject("req_1").is_err());

    let partial = vault
        .approve_reidentification("req_1", "acc_po_1", ApproverRole::PrivacyOfficer, now)
        .expect("first approval");
    assert!(matches!(
        partial,
        ReidentQuorumState::PartialApproval { .. }
    ));

    assert!(matches!(
        vault.approve_reidentification("req_1", "acc_po_1", ApproverRole::PrivacyOfficer, now),
        Err(IdentityError::DuplicateApprover(_))
    ));

    let approved = vault
        .approve_reidentification("req_1", "acc_owner_1", ApproverRole::OrgOwner, now)
        .expect("second approval");
    assert!(matches!(approved, ReidentQuorumState::Approved { .. }));

    let resolved = vault
        .resolve_reidentified_subject("req_1")
        .expect("resolved");
    assert_eq!(resolved.raw_subject, "alice@example.test");

    let over_cap = ts(now.as_second().saturating_add(91 * 86_400));
    assert!(matches!(
        vault.defer_subject_notification("req_1", over_cap, now),
        Err(IdentityError::DeferralCapExceeded { .. })
    ));
    let within_cap = ts(now.as_second().saturating_add(90 * 86_400));
    assert_eq!(
        vault
            .defer_subject_notification("req_1", within_cap, now)
            .expect("90-day deferral"),
        within_cap
    );

    let report = vault.quarterly_disclosure_report(QuarterKey::from_timestamp(now));
    assert_eq!(report.requested_count, 1);
    assert_eq!(report.approved_count, 1);
    assert_eq!(report.legal_hold_deferred_count, 1);
}

#[test]
fn rejects_empty_ceiling_prefix_bypass_role_violation_and_debug_leakage() {
    let now = ts(1_760_000_000);
    // Disjoint Ceiling::intersect must never produce an empty wildcard account set.
    let mut c1 = sample_ceiling();
    c1.allowed_resource_prefixes = vec!["arn:aws:iam::123:role/readonly".into()];
    let mut c2 = sample_ceiling();
    c2.allowed_accounts.clear();
    c2.allowed_accounts.insert("acct-other".into());
    c2.allowed_resource_prefixes = vec!["arn:aws:iam::123:role/readonly-extra".into()];
    let disjoint = c1.intersect(&c2);
    assert!(!disjoint.permits(
        CredentialClass::Cloud,
        "acct-dev",
        "sts:AssumeRole",
        "arn:aws:iam::123:role/readonly",
        1,
    ));
    assert!(!disjoint.permits(
        CredentialClass::Cloud,
        "acct-other",
        "sts:AssumeRole",
        "arn:aws:iam::123:role/readonly-extra",
        1,
    ));

    // Resource prefix segment boundary must block `role/dev-admin` under `role/dev`.
    let mut seg_ceiling = sample_ceiling();
    seg_ceiling.allowed_resource_prefixes = vec!["https://forge.test/org/app".into()];
    assert!(seg_ceiling.permits(
        CredentialClass::Forge,
        "acct-dev",
        "git:push",
        "https://forge.test/org/app/pulls",
        1,
    ));
    assert!(!seg_ceiling.permits(
        CredentialClass::Forge,
        "acct-dev",
        "git:push",
        "https://forge.test/org/app-evil",
        1,
    ));

    // SPIFFE segments reject path separators and control characters.
    assert!(SpiffeId::agent_instance("org1/evil", "agi_1").is_err());
    assert!(SpiffeId::agent_instance("org1", "agi_1\n").is_err());

    // Unrevocable upstream with min TTL > effective TTL must fail closed.
    let mut broker = CredentialBroker::new(BrokerPolicy::default());
    let spiffe = SpiffeId::agent_instance("org1", "agi_1").expect("spiffe");
    let unrevocable = CredentialBinding {
        credential_id: "crd_unrev".into(),
        class: CredentialClass::Cloud,
        account_id: "acct-dev".into(),
        allowed_programs: vec!["grdr-cred".into()],
        allowed_hosts: vec!["sts.amazonaws.com".into()],
        upstream_revocable: false,
        upstream_min_ttl_secs: 600,
        phantom_prefix: "TOK_".into(),
    };
    let req_short_ttl = BrokerRequest {
        session_id: "ses_ttl".into(),
        instance_spiffe_id: spiffe,
        device_id: "dev_1".into(),
        caller_program: "grdr-cred".into(),
        requested_class: CredentialClass::Cloud,
        requested_action: "sts:AssumeRole".into(),
        requested_resource: "arn:aws:iam::123:role/dev".into(),
        requested_mode: CredentialMode::Release,
        requested_ttl_secs: 300,
        session_remaining_secs: 300,
        attribution_grade: 3,
        has_session_container: true,
        containment: ContainmentStatus::Contained,
        lifecycle: AgentLifecycle::Active,
        ceiling: Some(sample_ceiling()),
        act_chain_depth: 1,
        dpop_jkt: None,
    };
    assert!(matches!(
        broker.request_credential(&unrevocable, &req_short_ttl, now),
        Err(IdentityError::ReleaseUnsupportedByUpstream)
    ));

    // Random release tokens must not repeat across identical requests.
    let revocable = CredentialBinding {
        upstream_revocable: true,
        ..unrevocable
    };
    let tok1 = broker
        .request_credential(&revocable, &req_short_ttl, now)
        .expect("tok1");
    let tok2 = broker
        .request_credential(&revocable, &req_short_ttl, now)
        .expect("tok2");
    assert_ne!(tok1.token_value, tok2.token_value);

    // Enforces hard max_retained_leases cap and preserves rate window counts after revocation.
    let mut capped_broker = CredentialBroker::new(BrokerPolicy {
        max_retained_leases: 2,
        max_leases_per_window: 2,
        ..BrokerPolicy::default()
    });
    let mut r_cap = req_short_ttl.clone();
    r_cap.session_id = "cap_1".into();
    let l1 = capped_broker
        .request_credential(&revocable, &r_cap, now)
        .expect("l1");
    assert_eq!(capped_broker.revoke_by_session("cap_1"), 1);
    let _ = capped_broker
        .request_credential(&revocable, &r_cap, now)
        .expect("l2");
    assert!(matches!(
        capped_broker.request_credential(&revocable, &r_cap, now),
        Err(IdentityError::RateLimitExceeded(_))
    ));
    let mut r_cap2 = req_short_ttl;
    r_cap2.session_id = "cap_2".into();
    let _ = capped_broker
        .request_credential(&revocable, &r_cap2, now)
        .expect("l3");
    // Wait until cap_1 lease stays active? Actually cap_1 revoked, so cap_2 replaced it.
    // Fill remaining active slot so 2 active leases prevent 3rd session insertion.
    r_cap2.session_id = "cap_3".into();
    assert!(
        capped_broker
            .request_credential(&revocable, &r_cap2, now)
            .is_err()
    );
    let _ = l1;

    // Vault enforces PrivacyOfficer quorum role and redacts sensitive fields in Debug.
    let mut device_key = [0u8; 32];
    let mut org_key = [0u8; 32];
    fill_random(&mut device_key).expect("device key");
    fill_random(&mut org_key).expect("org key");
    let mut vault = IdentityVault::new(
        "org_01",
        org_key,
        AeadKey::generate().expect("aead"),
        1,
        VaultPolicy {
            require_works_council_coapproval: true,
            ..VaultPolicy::default()
        },
    );
    let (_dev, org_prn) = vault
        .register_subject(&device_key, "sensitive-bob@example.test", "SecretBob")
        .expect("register");
    let vault_debug = format!("{vault:?}");
    assert!(!vault_debug.contains("sensitive-bob@example.test"));
    assert!(!vault_debug.contains("SecretBob"));

    vault
        .request_reidentification("req_wc", "acc_req", &org_prn, "audit", "inc_9", now)
        .expect("req");
    vault
        .approve_reidentification("req_wc", "acc_po", ApproverRole::PrivacyOfficer, now)
        .expect("po ok");
    assert!(matches!(
        vault.approve_reidentification("req_wc", "acc_owner", ApproverRole::OrgOwner, now),
        Err(IdentityError::InsufficientApproverRole)
    ));
    vault
        .approve_reidentification("req_wc", "acc_wc", ApproverRole::WorksCouncilDelegate, now)
        .expect("wc ok");
    vault
        .record_subject_disclosure("req_wc", now)
        .expect("disclose ok");
    assert!(matches!(
        vault.defer_subject_notification("req_wc", ts(now.as_second() + 86_400), now),
        Err(IdentityError::VaultState(_))
    ));
}
