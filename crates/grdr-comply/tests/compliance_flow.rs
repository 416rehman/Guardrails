// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Integration tests for grdr-comply (crosswalks, OSCAL, offline verify, retention, holds, RFP).

use std::collections::BTreeMap;

use grdr_comply::{
    BrokerReadiness, CertificationStatus, ComplyError, ConnectorCoverage, DeploymentTopology,
    ErasureOutcome, EvidenceDataClass, EvidencePipelineInput, EvidenceQuery, EvidenceResult,
    FieldRead, HoldCheckQuery, HoldCheckResult, HoldLifecycle, HoldNotice, HoldScope, HoldsLedger,
    PlaceHoldInput, PlatformReadiness, PrivacyCeilingProfile, RetentionPreset, RetentionProposal,
    RfpItemStatus, default_registry, deployment_fingerprint, eo14434_display_label,
    evaluate_evidence_item, export_component_definition, export_evidence_csv,
    export_evidence_markdown, export_offline_bundle, generate_rfp_response, render_rfp_markdown,
    resolve_retention_policy, validate_evidence_query, verify_evidence_bundle,
};
use grdr_crypto::SigningKeypair;
use grdr_model::SigningKeypairExt as _;
use jiff::Timestamp;
use uuid::Uuid;

fn full_green_acceptance_map() -> BTreeMap<String, bool> {
    (1..=17).map(|n| (format!("T{n}"), true)).collect()
}

#[test]
fn registry_covers_all_fifteen_capabilities_nine_frameworks_and_paraphrase_bounds() {
    let Ok(reg) = default_registry() else {
        panic!("embedded compliance registry must load");
    };
    assert_eq!(reg.capabilities.len(), 15);

    let expected_frameworks = [
        "aicpa-tsc-2017",
        "iso-27001-2022",
        "iso-42001-2023",
        "nist-sp-800-53r5",
        "eu-ai-act-2024-1689-c2026-07-27",
        "sg-mgf-agentic-1.5",
        "csa-aarm-1.0",
        "pci-dss-4.0.1",
        "hipaa-security-45cfr164",
    ];
    for fw_id in expected_frameworks {
        let report_res = reg.framework_coverage(fw_id);
        assert!(report_res.is_ok(), "framework {fw_id} must exist");
        if let Ok(report) = report_res {
            assert!(report.total_controls > 0);
            assert!(report.addressed_controls > 0);
        }
        if let Some(fw) = reg.frameworks.get(fw_id) {
            for ctrl in &fw.controls {
                let word_count = ctrl.paraphrase.split_whitespace().count();
                assert!(
                    word_count <= 20,
                    "control {} paraphrase exceeded 20 words ({word_count})",
                    ctrl.control_id
                );
            }
        }
    }

    assert_eq!(eo14434_display_label("NIST AI RMF 1.0"), "NIST SI RMF 1.0");
}

#[test]
fn evidence_query_enforces_derived_ceiling_allow_list_group_by_and_input_validation() {
    let Ok(reg) = default_registry() else {
        return;
    };
    let kp_res = SigningKeypair::generate();
    assert!(kp_res.is_ok(), "generate keypair");
    let Ok(kp) = kp_res else {
        return;
    };
    let now = Timestamp::from_second(1_700_000_000).unwrap_or(Timestamp::UNIX_EPOCH);
    let end = Timestamp::from_second(1_700_086_400).unwrap_or(Timestamp::UNIX_EPOCH);

    for bad_dim in [
        "user_id",
        "attempt.user_id",
        "envelope.principal",
        "email",
        "uid",
        "user_id AS x",
        "pseudonym",
    ] {
        let bad_principal_query = EvidenceQuery {
            id: "q.bad.principal".into(),
            version: "1.0.0".into(),
            capability: "cap.preexec.enforce".into(),
            reads: vec![FieldRead {
                field_path: "receipt.verdict".into(),
                data_class: EvidenceDataClass::Derived,
            }],
            max_class: EvidenceDataClass::Derived,
            group_by: vec![bad_dim.into()],
        };
        assert!(
            matches!(
                validate_evidence_query(&bad_principal_query),
                Err(ComplyError::InvalidEvidenceQuery { .. })
            ),
            "group_by `{bad_dim}` must be rejected"
        );
    }

    let bad_content_query = EvidenceQuery {
        id: "q.bad.content".into(),
        version: "1.0.0".into(),
        capability: "cap.preexec.enforce".into(),
        reads: vec![FieldRead {
            field_path: "attempt.target".into(),
            data_class: EvidenceDataClass::Content,
        }],
        max_class: EvidenceDataClass::Derived,
        group_by: vec!["capability".into()],
    };
    assert!(matches!(
        validate_evidence_query(&bad_content_query),
        Err(ComplyError::InvalidEvidenceQuery { .. })
    ));

    let valid_query = EvidenceQuery {
        id: "q.preexec".into(),
        version: "1.0.0".into(),
        capability: "cap.preexec.enforce".into(),
        reads: vec![FieldRead {
            field_path: "receipt.verdict".into(),
            data_class: EvidenceDataClass::Derived,
        }],
        max_class: EvidenceDataClass::Derived,
        group_by: vec!["capability".into()],
    };

    let bad_period = EvidencePipelineInput {
        organisation: "org_acme".into(),
        period_start: end,
        period_end: now,
        pipeline_lag_seconds: 10,
        max_lag_seconds: 120,
        total_observations: 10,
        covered_observations: 10,
        sample_ids: vec![],
        query_digest: "sha256:q1".into(),
        pack_digest: "sha256:p1".into(),
        schema_rev: "v1alpha1".into(),
    };
    assert!(matches!(
        evaluate_evidence_item(&valid_query, &bad_period, &reg, &kp),
        Err(ComplyError::InvalidEvidenceInput { .. })
    ));

    let bad_counts = EvidencePipelineInput {
        period_start: now,
        period_end: end,
        total_observations: 10,
        covered_observations: 11,
        ..bad_period.clone()
    };
    assert!(matches!(
        evaluate_evidence_item(&valid_query, &bad_counts, &reg, &kp),
        Err(ComplyError::InvalidEvidenceInput { .. })
    ));

    let overflow_counts = EvidencePipelineInput {
        period_start: now,
        period_end: end,
        total_observations: u64::MAX,
        covered_observations: 10,
        ..bad_period
    };
    assert!(matches!(
        evaluate_evidence_item(&valid_query, &overflow_counts, &reg, &kp),
        Err(ComplyError::InvalidEvidenceInput { .. })
    ));

    let lagged_input = EvidencePipelineInput {
        organisation: "org_acme".into(),
        period_start: now,
        period_end: end,
        pipeline_lag_seconds: 600,
        max_lag_seconds: 120,
        total_observations: 100,
        covered_observations: 100,
        sample_ids: vec!["rcp_1".into(), "rcp_2".into()],
        query_digest: "sha256:q1".into(),
        pack_digest: "sha256:p1".into(),
        schema_rev: "v1alpha1".into(),
    };
    let lagged_res = evaluate_evidence_item(&valid_query, &lagged_input, &reg, &kp);
    assert!(lagged_res.is_ok());
    if let Ok(lagged_item) = lagged_res {
        assert_eq!(lagged_item.result, EvidenceResult::NotEvaluable);
    }

    let ok_input = EvidencePipelineInput {
        pipeline_lag_seconds: 15,
        ..lagged_input
    };
    let ok_res = evaluate_evidence_item(&valid_query, &ok_input, &reg, &kp);
    assert!(ok_res.is_ok());
    if let Ok(ok_item) = ok_res {
        assert_eq!(ok_item.result, EvidenceResult::Met);
    }
}

#[test]
fn oscal_1_2_3_and_offline_auditor_bundle_verify_and_detect_forgery_and_injection() {
    let Ok(reg) = default_registry() else {
        return;
    };
    let kp_res = SigningKeypair::generate();
    assert!(kp_res.is_ok());
    let Ok(kp) = kp_res else {
        return;
    };
    let attacker_res = SigningKeypair::generate();
    assert!(attacker_res.is_ok());
    let Ok(attacker_kp) = attacker_res else {
        return;
    };
    let now = Timestamp::from_second(1_700_000_000).unwrap_or(Timestamp::UNIX_EPOCH);
    let end = Timestamp::from_second(1_700_086_400).unwrap_or(Timestamp::UNIX_EPOCH);

    let comp_def = export_component_definition(&reg, "Guardrails ADR", "0.1.0", now);
    let parsed_uuid = Uuid::parse_str(&comp_def.component_definition.uuid);
    assert!(parsed_uuid.is_ok());
    assert_eq!(parsed_uuid.map(|u| u.get_version_num()), Ok(5));
    let comp_json = serde_json::to_string_pretty(&comp_def).unwrap_or_default();
    assert!(comp_json.contains("\"oscal-version\": \"1.2.3\""));
    assert!(comp_json.contains("\"component-definition\""));

    let q = EvidenceQuery {
        id: "q.receipts".into(),
        version: "1.0.0".into(),
        capability: "cap.receipts.signed".into(),
        reads: vec![FieldRead {
            field_path: "receipt.receipt_digest".into(),
            data_class: EvidenceDataClass::Structural,
        }],
        max_class: EvidenceDataClass::Derived,
        group_by: vec!["capability".into()],
    };
    let item_res = evaluate_evidence_item(
        &q,
        &EvidencePipelineInput {
            organisation: "org_acme".into(),
            period_start: now,
            period_end: end,
            pipeline_lag_seconds: 5,
            max_lag_seconds: 60,
            total_observations: 42,
            covered_observations: 42,
            sample_ids: vec!["rcp_01".into()],
            query_digest: "sha256:q".into(),
            pack_digest: "sha256:p".into(),
            schema_rev: "v1alpha1".into(),
        },
        &reg,
        &kp,
    );
    assert!(item_res.is_ok());
    let Ok(item) = item_res else {
        return;
    };

    let mut csv_item = item.clone();
    csv_item.organisation = " =CMD()|\"org,acme\"".into();
    let csv = export_evidence_csv(&[csv_item.clone()]);
    assert!(csv.contains("\"' =CMD()|\"\"org,acme\"\"\""));
    let md = export_evidence_markdown("org|acme<script>", &[csv_item]);
    assert!(!md.contains("<script>"));
    assert!(md.contains("\\|"));

    let expected_fp = deployment_fingerprint(&kp.public_info());
    let bundle_res = export_offline_bundle(&kp, "org_acme", std::slice::from_ref(&item), now);
    assert!(bundle_res.is_ok());
    let Ok(bundle) = bundle_res else {
        return;
    };
    let report_res = verify_evidence_bundle(&bundle, &expected_fp);
    assert!(report_res.is_ok());
    if let Ok(report) = report_res {
        assert_eq!(report.verified_items, 1);
        assert_eq!(report.oscal_version, "1.2.3");
    }

    assert!(matches!(
        verify_evidence_bundle(&bundle, "fp_wrong"),
        Err(ComplyError::VerificationFailed { .. })
    ));

    let mut forged = export_offline_bundle(&attacker_kp, "org_acme", &[item], now)
        .unwrap_or_else(|_| bundle.clone());
    forged.deployment_fingerprint = expected_fp.clone();
    assert!(matches!(
        verify_evidence_bundle(&forged, &expected_fp),
        Err(ComplyError::VerificationFailed { .. })
    ));

    let mut ar_tampered = bundle.clone();
    if let Some(entry) = ar_tampered
        .assessment_results
        .assessment_results
        .results
        .first_mut()
        && let Some(obs) = entry.observations.first_mut()
    {
        obs.description = "forged narrative".into();
    }
    assert!(matches!(
        verify_evidence_bundle(&ar_tampered, &expected_fp),
        Err(ComplyError::VerificationFailed { .. })
    ));

    let mut item_tampered = bundle;
    if let Some(first) = item_tampered.items.first_mut() {
        first.result = EvidenceResult::NotMet;
    }
    assert!(matches!(
        verify_evidence_bundle(&item_tampered, &expected_fp),
        Err(ComplyError::VerificationFailed { .. })
    ));
}

#[test]
fn retention_rejects_floor_ceiling_conflicts_and_hot_overrides_and_enforces_holds() {
    let mut basis = BTreeMap::new();
    basis.insert(RetentionPreset::PciDss4, "Cardholder audit logging".into());

    let conflict = resolve_retention_policy(&RetentionProposal {
        organisation: "org_de".into(),
        presets: vec![RetentionPreset::PciDss4],
        ceiling_profile: PrivacyCeilingProfile::WorksCouncil,
        legal_basis: basis.clone(),
        override_legal_basis: None,
        content_days: None,
        activity_days: None,
        decision_days: None,
        audit_days: None,
        hot_days: None,
    });
    assert!(matches!(
        conflict,
        Err(ComplyError::RetentionConflict {
            ref floor_clause,
            ref ceiling_clause,
            ..
        }) if floor_clause.contains("pci-dss-4") && ceiling_clause.contains("works-council")
    ));

    let hot_below_floor = resolve_retention_policy(&RetentionProposal {
        organisation: "org_de".into(),
        presets: vec![RetentionPreset::PciDss4],
        ceiling_profile: PrivacyCeilingProfile::Standard,
        legal_basis: basis,
        override_legal_basis: None,
        content_days: None,
        activity_days: None,
        decision_days: None,
        audit_days: None,
        hot_days: Some(7),
    });
    assert!(matches!(
        hot_below_floor,
        Err(ComplyError::RetentionConflict { .. })
    ));

    let hot_above_wc_activity = resolve_retention_policy(&RetentionProposal {
        organisation: "org_de".into(),
        presets: vec![RetentionPreset::Default],
        ceiling_profile: PrivacyCeilingProfile::WorksCouncil,
        legal_basis: BTreeMap::new(),
        override_legal_basis: Some("Internal retention review".into()),
        content_days: None,
        activity_days: None,
        decision_days: None,
        audit_days: None,
        hot_days: Some(120),
    });
    assert!(matches!(
        hot_above_wc_activity,
        Err(ComplyError::RetentionConflict { .. })
    ));

    let missing_override_basis = resolve_retention_policy(&RetentionProposal {
        organisation: "org_de".into(),
        presets: vec![RetentionPreset::Default],
        ceiling_profile: PrivacyCeilingProfile::Standard,
        legal_basis: BTreeMap::new(),
        override_legal_basis: None,
        content_days: Some(90),
        activity_days: None,
        decision_days: None,
        audit_days: None,
        hot_days: None,
    });
    assert!(matches!(
        missing_override_basis,
        Err(ComplyError::MissingLegalBasis(_))
    ));

    let wc_default_res = resolve_retention_policy(&RetentionProposal {
        organisation: "org_de".into(),
        presets: vec![RetentionPreset::Default],
        ceiling_profile: PrivacyCeilingProfile::WorksCouncil,
        legal_basis: BTreeMap::new(),
        override_legal_basis: None,
        content_days: None,
        activity_days: None,
        decision_days: None,
        audit_days: None,
        hot_days: None,
    });
    assert!(wc_default_res.is_ok());
    if let Ok(wc_default) = wc_default_res {
        assert_eq!(wc_default.activity_days, 90);
        assert_eq!(wc_default.decision_days, 396);
    }

    let now = Timestamp::from_second(1_700_000_000).unwrap_or(Timestamp::UNIX_EPOCH);
    let review_at =
        Timestamp::from_second(1_700_000_000 + 30 * 86_400).unwrap_or(Timestamp::UNIX_EPOCH);
    let defer_until =
        Timestamp::from_second(1_700_000_000 + 14 * 86_400).unwrap_or(Timestamp::UNIX_EPOCH);

    let mut ledger = HoldsLedger::default();
    let dup_approver = ledger.place_hold(PlaceHoldInput {
        organisation: "org_de".into(),
        scope: HoldScope {
            pseudonyms: vec!["prn_alice".into()],
            session_ids: vec![],
            incident_id: None,
            classes: vec![],
            from: None,
            to: None,
        },
        matter_ref: "LIT-DUP".into(),
        reason: "Pending".into(),
        created_by: "dpo_bob".into(),
        approvers: vec!["dpo_bob".into(), "dpo_bob".into()],
        created_at: now,
        review_by: review_at,
        notice: HoldNotice::Immediate,
    });
    assert!(matches!(dup_approver, Err(ComplyError::InvalidHold { .. })));

    let hold_res = ledger.place_hold(PlaceHoldInput {
        organisation: "org_de".into(),
        scope: HoldScope {
            pseudonyms: vec!["prn_alice".into()],
            session_ids: vec!["ses_1".into()],
            incident_id: Some("inc_1".into()),
            classes: vec!["activity".into()],
            from: None,
            to: None,
        },
        matter_ref: "LIT-2026-01".into(),
        reason: "Pending litigation".into(),
        created_by: "dpo_bob".into(),
        approvers: vec!["dpo_bob".into(), "owner_carol".into()],
        created_at: now,
        review_by: review_at,
        notice: HoldNotice::Deferred {
            until: defer_until,
            renewals: 0,
        },
    });
    assert!(hold_res.is_ok());
    let Ok(hold) = hold_res else {
        return;
    };

    assert!(matches!(
        ledger.check(&HoldCheckQuery {
            organisation: "org_de",
            pseudonym: None,
            session_id: None,
            incident_id: Some("inc_1"),
            data_class: Some("activity"),
            record_at: Some(now),
        }),
        HoldCheckResult::Held { .. }
    ));
    assert!(matches!(
        ledger.check(&HoldCheckQuery {
            organisation: "org_other",
            pseudonym: Some("prn_alice"),
            session_id: None,
            incident_id: None,
            data_class: None,
            record_at: None,
        }),
        HoldCheckResult::Clear
    ));

    let pending_erasure = ledger.process_erasure("org_de", "prn_alice", now);
    assert!(matches!(
        pending_erasure,
        ErasureOutcome::PendingHeld {
            disclose_hold: false,
            ..
        }
    ));

    let overdue_ts =
        Timestamp::from_second(1_700_000_000 + 40 * 86_400).unwrap_or(Timestamp::UNIX_EPOCH);
    let overdue_findings = ledger.flag_expired_reviews(overdue_ts);
    assert_eq!(overdue_findings.len(), 1);

    let new_review =
        Timestamp::from_second(1_700_000_000 + 120 * 86_400).unwrap_or(Timestamp::UNIX_EPOCH);
    let renewed = ledger.renew_hold(
        "org_de",
        &hold.hold_id,
        &["dpo_bob".into(), "owner_carol".into()],
        new_review,
        None,
        overdue_ts,
    );
    assert!(renewed.is_ok());
    if let Ok(r) = renewed {
        assert_eq!(r.lifecycle, HoldLifecycle::Active);
        assert_eq!(r.renewals, 1);
    }

    assert!(
        ledger
            .release_hold(
                "org_de",
                &hold.hold_id,
                &["dpo_bob".into(), "owner_carol".into()],
                "Matter settled",
                overdue_ts,
            )
            .is_ok()
    );
    assert!(matches!(
        ledger.process_erasure("org_de", "prn_alice", overdue_ts),
        ErasureOutcome::Executed { .. }
    ));
}

#[test]
fn rfp_generator_covers_t1_to_t17_and_fails_closed_on_missing_or_red_gates() {
    let readiness = PlatformReadiness {
        release_version: "0.1.0-alpha".into(),
        os_assurance_summary: "Linux AL2/AL3, macOS AL2, Windows AL1".into(),
        topology: DeploymentTopology::ServerAvailable,
        broker: BrokerReadiness::Unavailable,
        connectors: ConnectorCoverage::ReadOnlyPair,
        certification: CertificationStatus::NoneHeld,
        acceptance_tests_green: full_green_acceptance_map(),
    };
    let report = generate_rfp_response(&readiness).expect("rfp response");
    assert_eq!(report.items.len(), 17);
    assert!(report.release_gate_passed);

    assert!(
        report
            .items
            .iter()
            .any(|i| i.id == "T6" && i.status == RfpItemStatus::PartiallyMet)
    );
    assert!(
        report
            .items
            .iter()
            .any(|i| i.id == "T12" && i.status == RfpItemStatus::PartiallyMet)
    );

    let md = render_rfp_markdown(&report);
    assert!(md.contains("T1"));
    assert!(md.contains("T17"));

    let empty_map_report = generate_rfp_response(&PlatformReadiness {
        acceptance_tests_green: BTreeMap::new(),
        ..readiness.clone()
    })
    .expect("rfp empty map");
    assert!(!empty_map_report.release_gate_passed);

    let mut failing_readiness = readiness;
    failing_readiness
        .acceptance_tests_green
        .insert("T2".into(), false);
    let gated = generate_rfp_response(&failing_readiness).expect("rfp failing");
    assert!(!gated.release_gate_passed);
    assert_eq!(gated.failing_gate_items, vec!["T2"]);
}
