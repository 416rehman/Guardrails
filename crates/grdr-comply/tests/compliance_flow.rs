// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Integration tests for grdr-comply (crosswalks, OSCAL, offline verify, retention, holds, RFP).

use std::collections::BTreeMap;

use grdr_comply::{
    BrokerReadiness, CertificationStatus, ComplyError, ConnectorCoverage, DeploymentTopology,
    ErasureOutcome, EvidenceDataClass, EvidencePipelineInput, EvidenceQuery, EvidenceResult,
    FieldRead, HoldCheckResult, HoldNotice, HoldScope, HoldsLedger, PlaceHoldInput,
    PlatformReadiness, PrivacyCeilingProfile, RetentionPreset, RetentionProposal, RfpItemStatus,
    default_registry, eo14434_display_label, evaluate_evidence_item, export_component_definition,
    export_evidence_csv, export_evidence_markdown, export_offline_bundle, generate_rfp_response,
    render_rfp_markdown, resolve_retention_policy, validate_evidence_query, verify_evidence_bundle,
};
use grdr_crypto::SigningKeypair;
use jiff::Timestamp;

#[test]
fn registry_covers_all_fifteen_capabilities_nine_frameworks_and_paraphrase_bounds() {
    let reg = default_registry();
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
fn evidence_query_enforces_derived_ceiling_no_principal_group_by_and_lag_not_evaluable() {
    let reg = default_registry();
    let kp_res = SigningKeypair::generate();
    assert!(kp_res.is_ok(), "generate keypair");
    let Ok(kp) = kp_res else {
        return;
    };
    let now = Timestamp::from_second(1_700_000_000).unwrap_or(Timestamp::UNIX_EPOCH);
    let end = Timestamp::from_second(1_700_086_400).unwrap_or(Timestamp::UNIX_EPOCH);

    let bad_principal_query = EvidenceQuery {
        id: "q.bad.principal".into(),
        version: "1.0.0".into(),
        capability: "cap.preexec.enforce".into(),
        reads: vec![FieldRead {
            field_path: "receipt.verdict".into(),
            data_class: EvidenceDataClass::Derived,
        }],
        max_class: EvidenceDataClass::Derived,
        group_by: vec!["user_id".into()],
    };
    assert!(matches!(
        validate_evidence_query(&bad_principal_query),
        Err(ComplyError::InvalidEvidenceQuery { .. })
    ));

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
fn oscal_1_2_3_and_offline_auditor_bundle_verify_and_detect_tampering() {
    let reg = default_registry();
    let kp_res = SigningKeypair::generate();
    assert!(kp_res.is_ok());
    let Ok(kp) = kp_res else {
        return;
    };
    let now = Timestamp::from_second(1_700_000_000).unwrap_or(Timestamp::UNIX_EPOCH);
    let end = Timestamp::from_second(1_700_086_400).unwrap_or(Timestamp::UNIX_EPOCH);

    let comp_def = export_component_definition(&reg, "Guardrails ADR", "0.1.0", now);
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

    let csv = export_evidence_csv(std::slice::from_ref(&item));
    assert!(csv.contains("cap.receipts.signed,met"));
    let md = export_evidence_markdown("org_acme", std::slice::from_ref(&item));
    assert!(md.contains("cap.receipts.signed"));

    let bundle_res = export_offline_bundle(&kp, "org_acme", "fp_root_abc123", &[item], now);
    assert!(bundle_res.is_ok());
    let Ok(mut bundle) = bundle_res else {
        return;
    };
    let report_res = verify_evidence_bundle(&bundle, "fp_root_abc123");
    assert!(report_res.is_ok());
    if let Ok(report) = report_res {
        assert_eq!(report.verified_items, 1);
        assert_eq!(report.oscal_version, "1.2.3");
    }

    assert!(matches!(
        verify_evidence_bundle(&bundle, "fp_wrong"),
        Err(ComplyError::VerificationFailed { .. })
    ));

    if let Some(first) = bundle.items.first_mut() {
        first.result = EvidenceResult::NotMet;
    }
    assert!(matches!(
        verify_evidence_bundle(&bundle, "fp_root_abc123"),
        Err(ComplyError::VerificationFailed { .. })
    ));
}

#[test]
fn retention_rejects_floor_ceiling_conflicts_naming_both_clauses_and_enforces_holds() {
    let mut basis = BTreeMap::new();
    basis.insert(RetentionPreset::PciDss4, "Cardholder audit logging".into());

    let conflict = resolve_retention_policy(&RetentionProposal {
        organisation: "org_de".into(),
        presets: vec![RetentionPreset::PciDss4],
        ceiling_profile: PrivacyCeilingProfile::WorksCouncil,
        legal_basis: basis,
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

    let wc_default_res = resolve_retention_policy(&RetentionProposal {
        organisation: "org_de".into(),
        presets: vec![RetentionPreset::Default],
        ceiling_profile: PrivacyCeilingProfile::WorksCouncil,
        legal_basis: BTreeMap::new(),
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

    let valid_eu_res = resolve_retention_policy(&RetentionProposal {
        organisation: "org_de".into(),
        presets: vec![RetentionPreset::EuAiActDeployer],
        ceiling_profile: PrivacyCeilingProfile::Standard,
        legal_basis: BTreeMap::from([(
            RetentionPreset::EuAiActDeployer,
            "Annex III log duty".into(),
        )]),
        content_days: None,
        activity_days: None,
        decision_days: None,
        audit_days: None,
        hot_days: None,
    });
    assert!(valid_eu_res.is_ok());
    if let Ok(valid_eu) = valid_eu_res {
        assert_eq!(valid_eu.activity_days, 184);
        assert_eq!(valid_eu.decision_days, 396);
    }

    let below_floor = resolve_retention_policy(&RetentionProposal {
        organisation: "org_de".into(),
        presets: vec![RetentionPreset::EuAiActDeployer],
        ceiling_profile: PrivacyCeilingProfile::Standard,
        legal_basis: BTreeMap::from([(
            RetentionPreset::EuAiActDeployer,
            "Annex III log duty".into(),
        )]),
        content_days: None,
        activity_days: Some(100),
        decision_days: None,
        audit_days: None,
        hot_days: None,
    });
    assert!(matches!(
        below_floor,
        Err(ComplyError::RetentionConflict { ref floor_clause, .. })
            if floor_clause.contains("eu-ai-act-deployer")
    ));

    let now = Timestamp::from_second(1_700_000_000).unwrap_or(Timestamp::UNIX_EPOCH);
    let review_at =
        Timestamp::from_second(1_700_000_000 + 30 * 86_400).unwrap_or(Timestamp::UNIX_EPOCH);
    let defer_until =
        Timestamp::from_second(1_700_000_000 + 14 * 86_400).unwrap_or(Timestamp::UNIX_EPOCH);

    let mut ledger = HoldsLedger::default();
    let hold_res = ledger.place_hold(PlaceHoldInput {
        organisation: "org_de".into(),
        scope: HoldScope {
            pseudonyms: vec!["prn_alice".into()],
            session_ids: vec!["ses_1".into()],
            incident_id: Some("inc_1".into()),
            classes: vec![],
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
        ledger.check("prn_alice", None, None),
        HoldCheckResult::Held { .. }
    ));

    let pending_erasure = ledger.process_erasure("prn_alice", now);
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

    assert!(ledger.release_hold(&hold.hold_id).is_ok());
    assert!(matches!(
        ledger.process_erasure("prn_alice", now),
        ErasureOutcome::Executed { .. }
    ));
}

#[test]
fn rfp_generator_covers_t1_to_t17_and_blocks_red_mandatory_release_gates() {
    let readiness = PlatformReadiness {
        release_version: "0.1.0-alpha".into(),
        os_assurance_summary: "Linux AL2/AL3, macOS AL2, Windows AL1".into(),
        topology: DeploymentTopology::ServerAvailable,
        broker: BrokerReadiness::Unavailable,
        connectors: ConnectorCoverage::ReadOnlyPair,
        certification: CertificationStatus::NoneHeld,
        acceptance_tests_green: BTreeMap::new(),
    };
    let report = generate_rfp_response(&readiness);
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

    let mut failing_readiness = readiness;
    failing_readiness
        .acceptance_tests_green
        .insert("T2".into(), false);
    let gated = generate_rfp_response(&failing_readiness);
    assert!(!gated.release_gate_passed);
    assert_eq!(gated.failing_gate_items, vec!["T2"]);
}
