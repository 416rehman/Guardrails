// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Integration tests covering YAML pack loading/verification, privacy hierarchy, DSAR/RoPA,
//! privacy docs, works-council governance, oversight reports, OSCAL validation, CRA/SOC2/VPAT.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use grdr_comply::{
    AgentLadderSnapshot, BannedTelemetryGuard, CaptureLevel, CoApproverQuorumPolicy, ComplyError,
    ComputeLadderLevel, ErasureLegalBasis, EvidenceDataClass, EvidencePipelineInput, EvidenceQuery,
    EvidenceResult, FieldRead, FiveEyesControlState, GitNotesPolicy, HoldNotice, HoldScope,
    HoldsLedger, IncidentFixtureInput, LocalDisclosureVisibility, ModelReviewPolicy,
    NetworkLadderLevel, NoticeChangeState, NoticeLocale, OversightAssignment,
    OversightDecisionOutcome, OversightEventInput, PackFieldReadSpec, PackPromotionVerdict,
    PlaceHoldInput, PrivacyArtefact, PrivacyCeilingProfile, PrivacyDocConfig, PrivacyExclusions,
    PrivacyLayerKind, RetentionPreset, RetentionProposal, RopaInput, RuleCatalogSummary,
    SubjectRequestKind, SubjectRequestLifecycle, UserRiskScoringState, VpatSurface,
    assess_privacy_pack_promotion, compute_oversight_quality_report,
    default_compliance_pack_digest, default_evidence_queries, default_privacy_doc_config,
    default_registry, default_retention_catalogue, evaluate_evidence_item,
    evaluate_five_eyes_report, evaluate_ncsc_containment, execute_subject_request,
    export_assessment_results, export_component_definition, export_incident_timeline,
    format_utc_quarter, generate_cra_annex_i_matrix, generate_impact_assessment_pack,
    generate_monitoring_catalogue, generate_ropa, generate_soc2_readiness_pack,
    generate_vpat_report, generate_worker_notice, generate_works_agreement_annex,
    load_compliance_pack_from_dir, load_compliance_pack_with_trusted,
    load_retention_catalogue_yaml, parse_registry_from_yaml, render_ropa_markdown,
    render_vpat_markdown, render_worker_notice_markdown, resolve_retention_policy,
    resolve_retention_policy_with_catalogue, schedule_capture_change, sign_privacy_artefact,
    validate_evidence_query, validate_oscal_assessment_json, validate_oscal_component_json,
    validate_purpose_bound_drill_down, validate_works_council_quorum,
    verify_and_enforce_privacy_hierarchy, verify_crypto_allowlist,
};
use grdr_crypto::{SigningKeypair, sha256_hex};
use grdr_model::{ApprovalGrade, AssuranceLevel, IdentityMode, SigningKeypairExt as _};
use jiff::Timestamp;
use uuid::Uuid;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn scratch_dir(prefix: &str) -> PathBuf {
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .or_else(|| std::env::var_os("HOME"))
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target"));
    let dir = base.join(format!("{prefix}-{}", Uuid::now_v7().simple()));
    let _ = fs::create_dir_all(&dir);
    dir
}

fn ts(sec: i64) -> Timestamp {
    Timestamp::from_second(sec).unwrap_or(Timestamp::UNIX_EPOCH)
}

#[test]
fn yaml_pack_loader_verifies_disk_pack_and_rejects_tamper_untrusted_and_bound_violations() {
    let pack_dir = repo_root().join("packs").join("compliance");
    let loaded_res = load_compliance_pack_from_dir(&pack_dir, None);
    assert!(loaded_res.is_ok(), "embedded signed disk pack must load");
    let Ok(loaded) = loaded_res else {
        return;
    };

    let embedded_reg = default_registry().expect("embedded registry");
    assert_eq!(
        loaded.registry.capabilities.len(),
        embedded_reg.capabilities.len()
    );
    assert_eq!(
        loaded.digest_sha256,
        default_compliance_pack_digest().expect("embedded digest")
    );
    assert!(
        !default_evidence_queries()
            .expect("embedded queries")
            .is_empty()
    );

    // Tampered YAML file fails SHA-256 manifest verification.
    let tmp = scratch_dir("grdr-comply-pack-tamper");
    let controls_dst = tmp.join("controls");
    let _ = fs::create_dir_all(&controls_dst);
    for file in ["pack.toml", "signature.json"] {
        let _ = fs::copy(pack_dir.join(file), tmp.join(file));
    }
    for file in ["capabilities.yaml", "crosswalks.yaml", "frameworks.yaml"] {
        let _ = fs::copy(
            pack_dir.join("controls").join(file),
            controls_dst.join(file),
        );
    }
    let _ = fs::write(
        controls_dst.join("capabilities.yaml"),
        "schema: grdr.compliance.capabilities.v1\ncapabilities: []\n",
    );
    let trust_roots = repo_root().join("packs").join("trust-roots.toml");
    assert!(matches!(
        load_compliance_pack_from_dir(&tmp, Some(&trust_roots)),
        Err(ComplyError::VerificationFailed { .. })
    ));

    // Restore file and test untrusted signer rejection.
    let _ = fs::copy(
        pack_dir.join("controls").join("capabilities.yaml"),
        controls_dst.join("capabilities.yaml"),
    );
    let bogus_kp = SigningKeypair::generate();
    if let Ok(kp) = bogus_kp {
        let bogus_pub = kp.public_info().public_key_b64;
        assert!(matches!(
            load_compliance_pack_with_trusted(&tmp, &[("untrusted-signer", bogus_pub.as_str())]),
            Err(ComplyError::VerificationFailed { .. })
        ));
    }
    let _ = fs::remove_dir_all(&tmp);

    // Over-20-word framework paraphrase fails closed during YAML registry parsing.
    let caps_yaml =
        fs::read_to_string(pack_dir.join("controls").join("capabilities.yaml")).unwrap_or_default();
    let long_paraphrase = (0..22)
        .map(|i| format!("word{i}"))
        .collect::<Vec<_>>()
        .join(" ");
    let bad_fws = format!(
        "schema: grdr.compliance.frameworks.v1\nframeworks:\n  - id: test-fw\n    title: Test\n    version: \"1.0\"\n    controls:\n      - control_id: C1\n        paraphrase: \"{long_paraphrase}\"\n        default_status: not-met\n"
    );
    assert!(parse_registry_from_yaml(&caps_yaml, &bad_fws, "schema: x\ncrosswalks: []\n").is_err());

    // Malformed retention YAML fails closed.
    assert!(load_retention_catalogue_yaml("presets: []\n").is_err());
}

#[test]
fn privacy_hierarchy_enforces_signed_strict_narrowing_works_council_locks_and_notices() {
    let org_kp = SigningKeypair::generate().unwrap_or_else(|_| unreachable_key());
    let parent_kp = SigningKeypair::generate().unwrap_or_else(|_| unreachable_key());
    let org_pub = org_kp.public_info();
    let parent_pub = parent_kp.public_info();

    let mut device = PrivacyArtefact {
        layer: PrivacyLayerKind::DeviceFloor,
        organisation: "org-wc".into(),
        capture_level: CaptureLevel::MetadataAndSignals,
        profile: PrivacyCeilingProfile::WorksCouncil,
        identity_mode: IdentityMode::Pseudonymous,
        user_risk_scoring: UserRiskScoringState::Disabled,
        local_disclosure: LocalDisclosureVisibility::Visible,
        banned_telemetry: BannedTelemetryGuard::Blocked,
        git_notes: GitNotesPolicy::Off,
        model_review: ModelReviewPolicy::CoSigned,
        privacy_contact: "dpo@acme.example".into(),
        co_approver_group: BTreeSet::from(["works-council-alice".into()]),
        exclusions: PrivacyExclusions {
            principals: BTreeSet::new(),
            paths: BTreeSet::new(),
            repositories: BTreeSet::new(),
        },
        key_id: None,
        signature: None,
    };
    assert!(sign_privacy_artefact(&org_kp, &mut device).is_ok());

    let mut narrowing_operator = device.clone();
    narrowing_operator.layer = PrivacyLayerKind::Operator;
    narrowing_operator.capture_level = CaptureLevel::MetadataOnly;
    narrowing_operator
        .exclusions
        .repositories
        .insert("git.internal/hr-vault".into());
    assert!(sign_privacy_artefact(&parent_kp, &mut narrowing_operator).is_ok());

    let eff = verify_and_enforce_privacy_hierarchy(
        &device,
        &[&narrowing_operator],
        std::slice::from_ref(&org_pub),
        std::slice::from_ref(&parent_pub),
    );
    assert!(eff.is_ok());
    if let Ok(resolved) = eff {
        assert_eq!(resolved.capture_level, CaptureLevel::MetadataOnly);
        assert!(
            resolved
                .exclusions
                .repositories
                .contains("git.internal/hr-vault")
        );
    }

    // Operator attempting to widen capture level is rejected (SR-26 strict narrowing).
    let mut widening_operator = narrowing_operator.clone();
    widening_operator.capture_level = CaptureLevel::ContentGrantOnly;
    assert!(sign_privacy_artefact(&parent_kp, &mut widening_operator).is_ok());
    assert!(matches!(
        verify_and_enforce_privacy_hierarchy(
            &device,
            &[&widening_operator],
            std::slice::from_ref(&org_pub),
            std::slice::from_ref(&parent_pub),
        ),
        Err(ComplyError::VerificationFailed { .. })
    ));

    // Unsigned or tampered operator signature fails.
    let mut forged = narrowing_operator.clone();
    forged.privacy_contact = "tampered@evil.example".into();
    assert!(matches!(
        verify_and_enforce_privacy_hierarchy(
            &device,
            &[&forged],
            std::slice::from_ref(&org_pub),
            std::slice::from_ref(&parent_pub),
        ),
        Err(ComplyError::VerificationFailed { .. })
    ));

    // Notice windows: 7d under Standard, 14d under WorksCouncil, immediate on narrowing.
    let t0 = ts(1_700_000_000);
    let std_up = schedule_capture_change(
        PrivacyCeilingProfile::Standard,
        CaptureLevel::MetadataOnly,
        CaptureLevel::MetadataAndSignals,
        t0,
    );
    assert!(matches!(
        std_up.as_ref().map(|s| s.schedule),
        Ok(NoticeChangeState::Scheduled { notice_days: 7, .. })
    ));
    let wc_up = schedule_capture_change(
        PrivacyCeilingProfile::WorksCouncil,
        CaptureLevel::MetadataOnly,
        CaptureLevel::MetadataAndSignals,
        t0,
    );
    assert!(matches!(
        wc_up.as_ref().map(|s| s.schedule),
        Ok(NoticeChangeState::Scheduled {
            notice_days: 14,
            ..
        })
    ));
    let down = schedule_capture_change(
        PrivacyCeilingProfile::WorksCouncil,
        CaptureLevel::MetadataAndSignals,
        CaptureLevel::MetadataOnly,
        t0,
    );
    assert!(matches!(
        down.as_ref().map(|s| s.schedule),
        Ok(NoticeChangeState::Immediate)
    ));
}

#[test]
fn works_council_quorum_drill_down_and_dsar_ropa_end_to_end() {
    let now = ts(1_760_000_000);
    let policy = CoApproverQuorumPolicy {
        profile: PrivacyCeilingProfile::WorksCouncil,
        co_approver_group: BTreeSet::from(["wc-rep-1".into(), "wc-rep-2".into()]),
    };
    // Two non-council approvers rejected under WorksCouncil.
    assert!(
        validate_works_council_quorum(
            "hold_wc_1",
            &["officer@acme.example".into(), "owner@acme.example".into()],
            &policy,
        )
        .is_err()
    );
    // Privacy officer + co-approver quorum succeeds.
    assert!(
        validate_works_council_quorum(
            "hold_wc_1",
            &["officer@acme.example".into(), "wc-rep-1".into()],
            &policy,
        )
        .is_ok()
    );

    // Works-council drill-down without incident/finding fails; with incident emits audit.access.
    assert!(
        validate_purpose_bound_drill_down(
            PrivacyCeilingProfile::WorksCouncil,
            "responder@acme.example",
            "prn_123",
            None,
            None,
            "investigate",
            now,
        )
        .is_err()
    );
    let drill = validate_purpose_bound_drill_down(
        PrivacyCeilingProfile::WorksCouncil,
        "responder@acme.example",
        "prn_123",
        Some("inc-42"),
        None,
        "Contain unauthorized SSH key exfiltration",
        now,
    );
    assert!(drill.is_ok());
    if let Ok(rec) = drill {
        assert_eq!(rec.audit_kind, "audit.access");
    }

    // Legal hold + DSAR Access (24h SLA), Erasure deferral (undisclosed), release cascade, Restriction.
    let mut ledger = HoldsLedger::default();
    let hold_res = ledger.place_hold(PlaceHoldInput {
        organisation: "org-eu".into(),
        scope: HoldScope {
            pseudonyms: vec!["prn_eva".into()],
            session_ids: vec![],
            incident_id: None,
            classes: vec!["decision".into(), "audit".into()],
            from: None,
            to: None,
        },
        matter_ref: "MATTER-WC-9".into(),
        reason: "Preservation pending investigation".into(),
        created_by: "dpo@acme.example".into(),
        approvers: vec!["dpo@acme.example".into(), "wc-rep-1".into()],
        created_at: now,
        review_by: ts(now.as_second() + 30 * 86_400),
        notice: HoldNotice::Deferred {
            until: ts(now.as_second() + 14 * 86_400),
            renewals: 0,
        },
    });
    let Ok(hold) = hold_res else {
        return;
    };

    let access = execute_subject_request(
        "org-eu",
        SubjectRequestKind::Access,
        "eva@acme.example",
        &["prn_eva".into()],
        &["sess-1".into()],
        &ledger,
        now,
    );
    assert!(access.is_ok());
    if let Ok(exec) = access
        && let Some(bundle) = exec.access_bundle
    {
        assert_eq!(
            bundle.sla_due_at.as_second() - bundle.generated_at.as_second(),
            24 * 3_600
        );
        assert_eq!(bundle.session_records, vec!["sess-1"]);
    }

    let held_erasure = execute_subject_request(
        "org-eu",
        SubjectRequestKind::Erasure,
        "eva@acme.example",
        &["prn_eva".into()],
        &["sess-1".into()],
        &ledger,
        now,
    );
    assert!(matches!(
        held_erasure.as_ref().map(|e| &e.record.lifecycle),
        Ok(SubjectRequestLifecycle::PendingHeld {
            disclose_hold: false,
            ..
        })
    ));

    assert!(
        ledger
            .release_hold(
                "org-eu",
                &hold.hold_id,
                &["dpo@acme.example".into(), "wc-rep-1".into()],
                "Closed investigation",
                ts(now.as_second() + 86_400),
            )
            .is_ok()
    );
    let released_erasure = execute_subject_request(
        "org-eu",
        SubjectRequestKind::Erasure,
        "eva@acme.example",
        &["prn_eva".into()],
        &["sess-1".into()],
        &ledger,
        ts(now.as_second() + 86_400),
    );
    assert!(released_erasure.is_ok());
    if let Ok(exec) = released_erasure
        && let Some(cascade) = exec.erasure_cascade
    {
        assert_eq!(cascade.backup_age_out_max_days, 35);
        assert_eq!(
            cascade.residual_records_basis,
            ErasureLegalBasis::Art17_3bLegalObligation
        );
        assert_eq!(cascade.destroyed_session_content_keys, vec!["sess-1"]);
    }

    let restriction = execute_subject_request(
        "org-eu",
        SubjectRequestKind::Restriction,
        "eva@acme.example",
        &["prn_eva".into()],
        &[],
        &ledger,
        now,
    );
    assert!(restriction.is_ok());
    if let Ok(exec) = restriction {
        assert!(!exec.exclusion_added.is_empty());
    }

    // GDPR Art. 30 RoPA generation + markdown rendering.
    let reg = default_registry().expect("embedded registry");
    let mut legal = BTreeMap::new();
    legal.insert(
        RetentionPreset::Default,
        "Legitimate interest Art. 6(1)(f)".into(),
    );
    let ret = resolve_retention_policy(&RetentionProposal {
        organisation: "org-eu".into(),
        presets: vec![RetentionPreset::Default],
        ceiling_profile: PrivacyCeilingProfile::WorksCouncil,
        legal_basis: legal,
        override_legal_basis: None,
        content_days: None,
        activity_days: None,
        decision_days: None,
        audit_days: None,
        hot_days: None,
    });
    if let Ok(policy) = ret {
        let ropa = generate_ropa(
            &RopaInput {
                organisation: "org-eu".into(),
                controller_name: "Acme GmbH".into(),
                dpo_contact: "dpo@acme.example".into(),
                org_region: "eu-central-1".into(),
                judge_region: "eu-central-1".into(),
                capture_level: "metadata-only".into(),
                data_categories: vec!["pseudonymous-session-metadata".into()],
                recipients: vec!["security-team".into()],
                subprocessors: vec!["Anthropic (optional model judge)".into()],
                residual_erasure_basis: ErasureLegalBasis::Art17_3eLegalClaims,
                generated_at: now,
            },
            &policy,
            &reg,
        );
        assert!(ropa.is_ok());
        if let Ok(doc) = ropa {
            let md = render_ropa_markdown(&doc);
            assert!(md.contains("GDPR Article 30 Record of Processing"));
            assert!(md.contains("Acme GmbH"));
        }
    }
}

#[test]
fn privacy_docs_diff_gate_oversight_p8_and_ncsc_five_eyes_work() {
    let now = ts(1_760_000_000);
    let co_group = BTreeSet::from(["wc-rep".into()]);
    let base_reads = vec![PackFieldReadSpec {
        field_path: "decision.verdict".into(),
        data_class: EvidenceDataClass::Derived,
    }];
    let elevated_reads = vec![
        PackFieldReadSpec {
            field_path: "decision.verdict".into(),
            data_class: EvidenceDataClass::Derived,
        },
        PackFieldReadSpec {
            field_path: "command.argv".into(),
            data_class: EvidenceDataClass::Identifier,
        },
    ];

    // Auto-promotes non-elevating change.
    let same = assess_privacy_pack_promotion(
        PrivacyCeilingProfile::WorksCouncil,
        &base_reads,
        &base_reads,
        None,
        None,
        &co_group,
    );
    assert_eq!(same.verdict, PackPromotionVerdict::AutoPromoted);

    // Blocks privacy-relevant elevation without officer + co-approver acknowledgement.
    let blocked = assess_privacy_pack_promotion(
        PrivacyCeilingProfile::WorksCouncil,
        &base_reads,
        &elevated_reads,
        Some("officer"),
        None,
        &co_group,
    );
    assert!(blocked.privacy_relevant);
    assert_eq!(
        blocked.verdict,
        PackPromotionVerdict::BlockedAwaitingAcknowledgement
    );

    let approved = assess_privacy_pack_promotion(
        PrivacyCeilingProfile::WorksCouncil,
        &base_reads,
        &elevated_reads,
        Some("officer"),
        Some("wc-rep"),
        &co_group,
    );
    assert_eq!(approved.verdict, PackPromotionVerdict::ApprovedByQuorum);

    // Generate all 4 privacy docs across En / De / Pseudo.
    let cfg = PrivacyDocConfig {
        organisation: "org-eu".into(),
        profile: PrivacyCeilingProfile::WorksCouncil,
        capture_level: "metadata-only".into(),
        retention_summary: "90d activity / 396d audit".into(),
        exclusions: vec!["repo:hr-secrets".into()],
        reader_roles: vec![("privacy-officer".into(), 2, "always".into())],
        privacy_contact: "dpo@acme.example".into(),
        co_approver_group: co_group,
        effective_change_notice: "14d prior notice".into(),
        is_annex_iii_deployer: true,
        recipients: vec!["sec-ops".into()],
        generated_at: now,
    };
    let cat = generate_monitoring_catalogue(
        &cfg,
        vec![RuleCatalogSummary {
            pack_id: "essentials".into(),
            rule_id: "ssh-key-read".into(),
            rule_sentence: "Blocks reads of user SSH private keys".into(),
            reads: base_reads,
            outputs: vec!["decision".into()],
            reader_roles: vec!["security-reviewer".into()],
        }],
        vec!["v1.0.0: initial baseline".into()],
    );
    assert!(cat.is_ok());

    for locale in [NoticeLocale::En, NoticeLocale::De, NoticeLocale::Pseudo] {
        let notice = generate_worker_notice(&cfg, locale);
        assert!(notice.is_ok());
        if let Ok(doc) = notice {
            let md = render_worker_notice_markdown(&doc);
            if locale == NoticeLocale::Pseudo {
                assert!(md.contains("[!! Monitored Person Privacy Notice !!"));
            }
        }
    }
    let dpia = generate_impact_assessment_pack(&cfg);
    assert!(dpia.as_ref().is_ok_and(|d| d.fria_appendix_applicable));
    let annex = generate_works_agreement_annex(&cfg);
    assert!(annex.as_ref().is_ok_and(|a| a.national_variants.len() >= 4));

    // Oversight P8 guard rejects <5 member group, computes quarterly metrics & flags rubber-stamp.
    assert_eq!(format_utc_quarter(ts(1_771_113_600)), "2026-Q1");
    let small_group_ev = vec![OversightEventInput {
        rule_id: "r1".into(),
        rule_class: "credential".into(),
        queue: "sec-queue".into(),
        group_name: Some("tiny-team".into()),
        group_member_count: Some(4),
        min_grade: ApprovalGrade::G1,
        effective_grade: ApprovalGrade::G1,
        outcome: OversightDecisionOutcome::Approved,
        latency_ms: 150,
        pending_age_seconds: 10,
        has_written_justification: false,
    }];
    assert!(matches!(
        compute_oversight_quality_report(
            "org-eu",
            &small_group_ev,
            &[],
            &["credential".into()],
            now,
        ),
        Err(ComplyError::InvalidEvidenceQuery { .. })
    ));

    let rubber_events: Vec<OversightEventInput> = (0..20)
        .map(|i| OversightEventInput {
            rule_id: "r-rubber".into(),
            rule_class: "network".into(),
            queue: "default".into(),
            group_name: Some("platform-sec".into()),
            group_member_count: Some(7),
            min_grade: ApprovalGrade::G1,
            effective_grade: ApprovalGrade::G1,
            outcome: OversightDecisionOutcome::Approved,
            latency_ms: 100 + i * 5,
            pending_age_seconds: 15,
            has_written_justification: true,
        })
        .collect();
    let rep = compute_oversight_quality_report(
        "org-eu",
        &rubber_events,
        &[OversightAssignment {
            rule_class: "network".into(),
            group: "platform-sec".into(),
            attested_on: "2026-01-01".into(),
            attested_by: "sec-lead".into(),
        }],
        &["network".into()],
        now,
    );
    assert!(rep.is_ok());
    if let Ok(r) = rep {
        assert_eq!(r.rubber_stamp_flagged_rules, vec!["r-rubber"]);
        assert_eq!(r.oversight_assignment_coverage_bp, 10_000);
    }

    // NCSC ladder downgrade & Five Eyes single-sourced check.
    let prev = vec![AgentLadderSnapshot {
        agent_type: "claude-code".into(),
        group: "eng".into(),
        network_ladder: NetworkLadderLevel::DomainAllowList,
        compute_ladder: ComputeLadderLevel::Container,
        assurance: AssuranceLevel::Al2Guided,
        identity_mode: IdentityMode::Pseudonymous,
        signed_receipts_enforced: true,
        kill_switch_ready: true,
    }];
    let mut cur = prev.clone();
    if let Some(first) = cur.first_mut() {
        first.network_ladder = NetworkLadderLevel::Unrestricted;
    }
    let ncsc = evaluate_ncsc_containment("org-eu", &prev, &cur);
    assert!(!ncsc.downgrade_findings.is_empty());

    let five = evaluate_five_eyes_report(
        "org-eu",
        FiveEyesControlState::Covered,
        FiveEyesControlState::Covered,
        FiveEyesControlState::Covered,
        10,
        0,
    );
    assert!(five.crosscheck_source_status.starts_with("single-sourced"));
}

#[test]
fn oscal_validation_incident_timelines_crypto_allowlist_cra_soc2_and_vpat_pass_and_reject_bad() {
    let now = ts(1_760_000_000);
    let reg = default_registry().expect("embedded registry");
    let kp = SigningKeypair::generate().unwrap_or_else(|_| unreachable_key());

    // OSCAL 1.2.3 component + assessment structural validation.
    let comp = export_component_definition(&reg, "Guardrails ADR", "0.1.0", now);
    let comp_json = serde_json::to_string_pretty(&comp).unwrap_or_default();
    assert!(validate_oscal_component_json(&comp_json).is_ok());
    let bad_comp = comp_json.replace("\"1.2.3\"", "\"1.0.0\"");
    assert!(matches!(
        validate_oscal_component_json(&bad_comp),
        Err(ComplyError::VerificationFailed { .. })
    ));

    let query = EvidenceQuery {
        id: "q.test".into(),
        version: "1.0.0".into(),
        capability: "cap.preexec.enforce".into(),
        reads: vec![FieldRead {
            field_path: "decision.verdict".into(),
            data_class: EvidenceDataClass::Derived,
        }],
        max_class: EvidenceDataClass::Derived,
        group_by: vec!["capability".into()],
    };
    let item_res = evaluate_evidence_item(
        &query,
        &EvidencePipelineInput {
            organisation: "org-test".into(),
            period_start: ts(now.as_second() - 3_600),
            period_end: now,
            pipeline_lag_seconds: 5,
            max_lag_seconds: 300,
            total_observations: 10,
            covered_observations: 10,
            sample_ids: vec!["rcp_1".into()],
            query_digest: sha256_hex(b"q.test"),
            pack_digest: default_compliance_pack_digest().expect("embedded digest"),
            schema_rev: "v1alpha1".into(),
        },
        &reg,
        &kp,
    );
    if let Ok(item) = item_res {
        assert_eq!(item.result, EvidenceResult::Met);
        let assess = export_assessment_results("org-test", &[item], now);
        if let Ok(doc) = assess {
            let assess_json = serde_json::to_string_pretty(&doc).unwrap_or_default();
            assert!(validate_oscal_assessment_json(&assess_json).is_ok());
        }
    }

    // Incident timeline calculator: CRA (24h/72h/14d/30d) + SEC 8-K (4 business days over weekend).
    let detected = "2026-10-09T12:00:00Z".parse::<Timestamp>().unwrap_or(now);
    let cra = export_incident_timeline(&IncidentFixtureInput {
        incident_id: "inc-cra-1".into(),
        regime_id: "cra-eu-2024-2847".into(),
        summary: "Actively exploited dependency flaw".into(),
        detected_at: detected,
        fixed_at: None,
        notified_at: None,
        materiality_determined_at: None,
    });
    assert!(cra.is_ok());
    if let Ok(rep) = cra {
        assert_eq!(rep.deadlines.len(), 4);
        assert_eq!(
            rep.deadlines
                .first()
                .map(|d| d.due_at.as_second() - detected.as_second()),
            Some(24 * 3_600)
        );
        assert_eq!(
            rep.deadlines
                .get(1)
                .map(|d| d.due_at.as_second() - detected.as_second()),
            Some(72 * 3_600)
        );
    }

    // Friday 2026-10-09 + 4 business days skips Sat/Sun -> Thursday 2026-10-15.
    let sec = export_incident_timeline(&IncidentFixtureInput {
        incident_id: "inc-sec-1".into(),
        regime_id: "sec-8k-1.05".into(),
        summary: "Material cyber incident".into(),
        detected_at: detected,
        fixed_at: None,
        notified_at: None,
        materiality_determined_at: Some(detected),
    });
    assert!(sec.is_ok());
    if let Ok(rep) = sec {
        assert!(
            rep.deadlines
                .first()
                .is_some_and(|d| d.due_at.to_string().starts_with("2026-10-15"))
        );
    }

    // Crypto allow-list passes approved crates + export.md and rejects planted weak primitives.
    let export_md = fs::read_to_string(repo_root().join("docs").join("legal").join("export.md"))
        .unwrap_or_default();
    assert!(
        verify_crypto_allowlist(
            &["ed25519-dalek", "chacha20poly1305", "sha2"],
            Some(&export_md)
        )
        .is_ok()
    );
    assert!(matches!(
        verify_crypto_allowlist(&["md5", "ring"], Some(&export_md)),
        Err(ComplyError::VerificationFailed { .. })
    ));

    // CRA Annex I, SOC 2 100% owner mapping, and VPAT 2.5 INT (Web + Desktop).
    let cra_matrix = generate_cra_annex_i_matrix(&reg);
    assert!(
        cra_matrix
            .as_ref()
            .is_ok_and(|m| m.rows.iter().all(|r| r.all_capabilities_registered))
    );

    let soc2 = generate_soc2_readiness_pack(&reg);
    assert!(soc2.as_ref().is_ok_and(
        |s| s.owner_mapped_percent == 100 && s.controls.iter().all(|c| c.mapped_in_registry)
    ));

    let vpat_web = generate_vpat_report(VpatSurface::WebConsole, "0.1.0", &BTreeMap::new(), now);
    let vpat_desktop =
        generate_vpat_report(VpatSurface::RuneDesktop, "0.1.0", &BTreeMap::new(), now);
    assert!(
        vpat_web
            .as_ref()
            .is_ok_and(|v| render_vpat_markdown(v).contains("VPAT 2.5 INT")
                && render_vpat_markdown(v).contains("Not Evaluated")
                && !render_vpat_markdown(v).contains("| Supports |"))
    );
    assert!(
        vpat_desktop
            .as_ref()
            .is_ok_and(|v| render_vpat_markdown(v).contains("WCAG 2.2 AA")
                && render_vpat_markdown(v).contains("Not Evaluated"))
    );
}

#[test]
fn adversarial_security_hardening_invariants_hold() {
    let now = ts(1_760_000_000);
    let pack_dir = repo_root().join("packs").join("compliance");

    // 1. Sibling ../trust-roots.toml is NOT auto-discovered when trust_roots == None.
    let tmp = scratch_dir("grdr-comply-sibling-trust");
    let sub_pack = tmp.join("compliance");
    let sub_controls = sub_pack.join("controls");
    let _ = fs::create_dir_all(&sub_controls);
    let attacker_kp = SigningKeypair::generate().unwrap_or_else(|_| unreachable_key());
    let attacker_pk = attacker_kp.public_info().public_key_b64;
    let _ = fs::write(
        tmp.join("trust-roots.toml"),
        format!(
            "format = \"grdr.trust-roots.v1\"\n\n[[signers]]\nsigner_ref = \"attacker-root\"\nverifier_ed25519_b64 = \"{attacker_pk}\"\nstatus = \"active\"\n"
        ),
    );
    let _ = fs::copy(pack_dir.join("pack.toml"), sub_pack.join("pack.toml"));
    for f in ["capabilities.yaml", "frameworks.yaml", "crosswalks.yaml"] {
        let _ = fs::copy(pack_dir.join("controls").join(f), sub_controls.join(f));
    }
    let manifest_bytes = fs::read(sub_pack.join("pack.toml")).unwrap_or_default();
    let caps_bytes = fs::read(sub_controls.join("capabilities.yaml")).unwrap_or_default();
    let fws_bytes = fs::read(sub_controls.join("frameworks.yaml")).unwrap_or_default();
    let cw_bytes = fs::read(sub_controls.join("crosswalks.yaml")).unwrap_or_default();
    let entries = [
        ("controls/capabilities.yaml", caps_bytes.as_slice()),
        ("controls/crosswalks.yaml", cw_bytes.as_slice()),
        ("controls/frameworks.yaml", fws_bytes.as_slice()),
        ("pack.toml", manifest_bytes.as_slice()),
    ];
    let mut file_json = Vec::new();
    let mut lines = vec![
        "grdr.pack.manifest.v1".to_owned(),
        "grdr.compliance".to_owned(),
        "1.0.0".to_owned(),
    ];
    for (p, raw) in entries {
        let hex = sha256_hex(raw);
        lines.push(format!("{p} {hex} {}", raw.len()));
        file_json.push(serde_json::json!({"path": p, "sha256": hex, "length": raw.len()}));
    }
    let payload = lines.join("\n");
    let sig_b64 = attacker_kp.sign_bytes("grdr.pack.manifest.v1", payload.as_bytes());
    let sig_doc = serde_json::json!({
        "format": "grdr.pack.signature.v1",
        "pack_id": "grdr.compliance",
        "version": "1.0.0",
        "domain": "grdr.pack.manifest.v1",
        "signer_ref": "attacker-root",
        "verifier_ed25519_b64": attacker_pk,
        "manifest_sha256": sha256_hex(payload.as_bytes()),
        "files": file_json,
        "signature_b64": sig_b64,
    });
    let _ = fs::write(
        sub_pack.join("signature.json"),
        serde_json::to_string_pretty(&sig_doc).unwrap_or_default(),
    );
    // Fails when trust_roots=None (pins embedded trust root), passes only if explicitly passed.
    assert!(load_compliance_pack_from_dir(&sub_pack, None).is_err());
    assert!(load_compliance_pack_from_dir(&sub_pack, Some(&tmp.join("trust-roots.toml"))).is_ok());
    let _ = fs::remove_dir_all(&tmp);

    // 2. Session-scoped legal holds block DSAR erasure; hold org/release/approver guards work.
    let mut ledger = HoldsLedger::default();
    let hold = ledger
        .place_hold(PlaceHoldInput {
            organisation: "org-a".into(),
            scope: HoldScope {
                pseudonyms: vec![],
                session_ids: vec!["sess-locked".into()],
                incident_id: None,
                classes: vec![],
                from: None,
                to: None,
            },
            matter_ref: "M-SESS".into(),
            reason: "Session hold".into(),
            created_by: "Alice@Acme.Example".into(),
            approvers: vec!["Alice@Acme.Example".into(), "bob@acme.example".into()],
            created_at: now,
            review_by: ts(now.as_second() + 10 * 86_400),
            notice: HoldNotice::Immediate,
        })
        .expect("session hold");
    let dsar = execute_subject_request(
        "org-a",
        SubjectRequestKind::Erasure,
        "alice@acme.example",
        &[],
        &["sess-locked".into()],
        &ledger,
        now,
    )
    .expect("dsar held");
    assert!(matches!(
        dsar.record.lifecycle,
        SubjectRequestLifecycle::PendingHeld { .. }
    ));

    // Case-insensitive duplicate approver rejected, whitespace co-approver rejected, cross-org rejected.
    assert!(
        ledger
            .renew_hold(
                "org-a",
                &hold.hold_id,
                &["Alice@acme.example".into(), "alice@acme.example".into()],
                ts(now.as_second() + 20 * 86_400),
                None,
                now,
            )
            .is_err()
    );
    assert!(
        ledger
            .release_hold(
                "org-b",
                &hold.hold_id,
                &["alice@acme.example".into(), "bob@acme.example".into()],
                "wrong org",
                now,
            )
            .is_err()
    );
    assert!(
        validate_works_council_quorum(
            "op",
            &["alice@acme.example".into(), "bob@acme.example".into()],
            &CoApproverQuorumPolicy {
                profile: PrivacyCeilingProfile::WorksCouncil,
                co_approver_group: BTreeSet::from(["  ".into(), "bob@acme.example".into()]),
            },
        )
        .is_err()
    );

    // 3. P8 Oversight rejects group_name=None with count<5, difference attacks, and excludes Pending latency.
    assert!(
        compute_oversight_quality_report(
            "org-a",
            &[OversightEventInput {
                rule_id: "r1".into(),
                rule_class: "exec".into(),
                queue: "q".into(),
                group_name: None,
                group_member_count: Some(2),
                min_grade: ApprovalGrade::G1,
                effective_grade: ApprovalGrade::G1,
                outcome: OversightDecisionOutcome::Approved,
                latency_ms: 50,
                pending_age_seconds: 0,
                has_written_justification: false,
            }],
            &[],
            &["exec".into()],
            now,
        )
        .is_err()
    );
    // Inconsistent group_member_count within same group is rejected.
    assert!(
        compute_oversight_quality_report(
            "org-a",
            &[
                OversightEventInput {
                    rule_id: "r1".into(),
                    rule_class: "exec".into(),
                    queue: "q".into(),
                    group_name: Some("team-a".into()),
                    group_member_count: Some(5),
                    min_grade: ApprovalGrade::G1,
                    effective_grade: ApprovalGrade::G1,
                    outcome: OversightDecisionOutcome::Approved,
                    latency_ms: 100,
                    pending_age_seconds: 0,
                    has_written_justification: true,
                },
                OversightEventInput {
                    rule_id: "r1".into(),
                    rule_class: "exec".into(),
                    queue: "q".into(),
                    group_name: Some("team-a".into()),
                    group_member_count: Some(7),
                    min_grade: ApprovalGrade::G1,
                    effective_grade: ApprovalGrade::G1,
                    outcome: OversightDecisionOutcome::Approved,
                    latency_ms: 120,
                    pending_age_seconds: 0,
                    has_written_justification: true,
                },
            ],
            &[],
            &["exec".into()],
            now,
        )
        .is_err()
    );
    // Pending events with latency_ms=0 are excluded from queue latency percentiles.
    let pending_excl = compute_oversight_quality_report(
        "org-a",
        &[
            OversightEventInput {
                rule_id: "r1".into(),
                rule_class: "exec".into(),
                queue: "q".into(),
                group_name: Some("team-a".into()),
                group_member_count: Some(6),
                min_grade: ApprovalGrade::G1,
                effective_grade: ApprovalGrade::G1,
                outcome: OversightDecisionOutcome::Pending,
                latency_ms: 0,
                pending_age_seconds: 90,
                has_written_justification: false,
            },
            OversightEventInput {
                rule_id: "r1".into(),
                rule_class: "exec".into(),
                queue: "q".into(),
                group_name: Some("team-a".into()),
                group_member_count: Some(6),
                min_grade: ApprovalGrade::G1,
                effective_grade: ApprovalGrade::G1,
                outcome: OversightDecisionOutcome::Approved,
                latency_ms: 250,
                pending_age_seconds: 0,
                has_written_justification: true,
            },
        ],
        &[],
        &["exec".into()],
        now,
    )
    .expect("oversight report with pending row");
    assert_eq!(
        pending_excl
            .queue_latencies
            .first()
            .map(|q| q.median_latency_ms),
        Some(250)
    );
    assert_eq!(
        pending_excl
            .queue_latencies
            .first()
            .map(|q| q.oldest_pending_seconds),
        Some(90)
    );

    // 4. Privacy floor rejects non-DeviceFloor root, DeviceFloor in parents, and overflow schedule.
    let kp = SigningKeypair::generate().unwrap_or_else(|_| unreachable_key());
    let mut bad_root = PrivacyArtefact {
        layer: PrivacyLayerKind::Org,
        organisation: "org-a".into(),
        capture_level: CaptureLevel::MetadataOnly,
        profile: PrivacyCeilingProfile::WorksCouncil,
        identity_mode: IdentityMode::Pseudonymous,
        user_risk_scoring: UserRiskScoringState::Disabled,
        local_disclosure: LocalDisclosureVisibility::Visible,
        banned_telemetry: BannedTelemetryGuard::Blocked,
        git_notes: GitNotesPolicy::Off,
        model_review: ModelReviewPolicy::CoSigned,
        privacy_contact: "dpo@acme.example".into(),
        co_approver_group: BTreeSet::from(["wc".into()]),
        exclusions: PrivacyExclusions {
            principals: BTreeSet::new(),
            paths: BTreeSet::new(),
            repositories: BTreeSet::new(),
        },
        key_id: None,
        signature: None,
    };
    let _ = sign_privacy_artefact(&kp, &mut bad_root);
    assert!(
        verify_and_enforce_privacy_hierarchy(
            &bad_root,
            &[],
            std::slice::from_ref(&kp.public_info()),
            &[],
        )
        .is_err()
    );
    assert!(
        schedule_capture_change(
            PrivacyCeilingProfile::Standard,
            CaptureLevel::MetadataOnly,
            CaptureLevel::MetadataAndSignals,
            Timestamp::MAX,
        )
        .is_err()
    );

    // 5. Third-party transitive Cargo.lock crypto parsing catches single-line/registry ring & md5.
    let third_party_lock = r#"
[[package]]
name = "third-party-http"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = ["ring 0.17.14", "md5"]
"#;
    assert!(grdr_comply::verify_cargo_lock_crypto(third_party_lock, None).is_err());

    // 6. OSCAL validation rejects empty observations, missing methods, duplicate UUIDs, and oversized JSON.
    assert!(validate_oscal_assessment_json("{\"assessment-results\":{}}").is_err());
    assert!(validate_oscal_component_json("{\"component-definition\":{\"uuid\":\"00000000-0000-5000-8000-000000000001\",\"metadata\":{\"title\":\"t\",\"version\":\"1\",\"last-modified\":\"2026-01-01T00:00:00Z\",\"oscal-version\":\"1.2.3\"},\"components\":[{\"uuid\":\"00000000-0000-5000-8000-000000000001\",\"type\":\"software\",\"title\":\"t\",\"description\":\"d\",\"control-implementations\":[]}]}}").is_err());

    // 7. H1/H4/H5 guards: ancestor obstruction, dynamic doc config, empty evidence query fields, hot_days > activity_days, trimmed org.
    let mut empty_id_q = EvidenceQuery {
        id: "".into(),
        version: "1.0.0".into(),
        capability: "cap.preexec.enforce".into(),
        reads: vec![FieldRead {
            field_path: "decision.verdict".into(),
            data_class: EvidenceDataClass::Derived,
        }],
        max_class: EvidenceDataClass::Derived,
        group_by: vec!["capability".into()],
    };
    assert!(validate_evidence_query(&empty_id_q).is_err());
    empty_id_q.id = "q.valid".into();
    empty_id_q.version = "  ".into();
    assert!(validate_evidence_query(&empty_id_q).is_err());
    empty_id_q.version = "1.0.0".into();
    empty_id_q.capability = "".into();
    assert!(validate_evidence_query(&empty_id_q).is_err());
    empty_id_q.capability = "cap.preexec.enforce".into();
    if let Some(first) = empty_id_q.reads.first_mut() {
        first.field_path = " ".into();
    }
    assert!(validate_evidence_query(&empty_id_q).is_err());

    let cfg = default_privacy_doc_config(
        "org-dyn",
        PrivacyCeilingProfile::WorksCouncil,
        "metadata-only",
        "privacy@guardrailshq.com",
        now,
    )
    .unwrap();
    assert!(cfg.retention_summary.contains("90d activity"));
    assert!(cfg.effective_change_notice.contains("14 days"));

    let mut cat = default_retention_catalogue().unwrap();
    if let Some(p) = cat.presets.get_mut(&RetentionPreset::Default) {
        p.hot_days = 400;
        p.activity_days = 90;
    }
    assert!(
        resolve_retention_policy_with_catalogue(
            &RetentionProposal {
                organisation: "org-hot".into(),
                presets: vec![RetentionPreset::Default],
                ceiling_profile: PrivacyCeilingProfile::Standard,
                legal_basis: BTreeMap::from([(RetentionPreset::Default, "Art. 6(1)(f)".into())]),
                override_legal_basis: None,
                content_days: None,
                activity_days: None,
                decision_days: None,
                audit_days: None,
                hot_days: None,
            },
            &cat,
        )
        .is_err()
    );

    let mut trim_ledger = HoldsLedger::default();
    let trim_hold = trim_ledger
        .place_hold(PlaceHoldInput {
            organisation: "  org-trim  ".into(),
            scope: HoldScope {
                pseudonyms: vec!["prn_trim".into()],
                session_ids: Vec::new(),
                incident_id: None,
                classes: vec!["decision".into()],
                from: None,
                to: None,
            },
            matter_ref: "M-TRIM".into(),
            reason: "Trim org check".into(),
            created_by: "a@acme.example".into(),
            approvers: vec!["a@acme.example".into(), "b@acme.example".into()],
            created_at: now,
            review_by: ts(now.as_second() + 10 * 86_400),
            notice: HoldNotice::Immediate,
        })
        .unwrap();
    assert!(!trim_hold.hold_id.is_empty());
    assert!(
        trim_ledger
            .check_erasure_targets("  org-trim ", &["prn_trim".into()], &[], now)
            .is_some()
    );

    let file_blocker_dir = scratch_dir("h1-blocker");
    let file_anc = file_blocker_dir.join("not-a-dir");
    let _ = fs::write(&file_anc, b"blocker");
    assert!(load_compliance_pack_from_dir(&file_anc.join("pack"), None).is_err());
    assert!(
        load_compliance_pack_from_dir(
            &repo_root().join("packs/compliance"),
            Some(&file_anc.join("roots.toml"))
        )
        .is_err()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let sym_anc = file_blocker_dir.join("sym-anc");
        let _ = symlink(repo_root().join("packs"), &sym_anc);
        assert!(load_compliance_pack_from_dir(&sym_anc.join("compliance"), None).is_err());
    }
    let _ = fs::remove_dir_all(&file_blocker_dir);
}

fn unreachable_key() -> SigningKeypair {
    SigningKeypair::from_seed([0x11; 32])
}
