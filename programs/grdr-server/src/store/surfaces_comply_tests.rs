// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use jiff::Timestamp;
use uuid::Uuid;

use grdr_comply::{
    HoldNotice, HoldScope, HoldsLedger, NoticeLocale, PlaceHoldInput, PrivacyCeilingProfile,
    SubjectRequestKind, SubjectRequestLifecycle as ComplySubjectLifecycle, format_utc_quarter,
    validate_oscal_assessment_json, validate_oscal_component_json,
};
use grdr_model::{
    ActionAttempt, ActionClass, ApprovalGrade, ApprovalRequest, ApprovalState, ControlPoint,
    DecisionReceipt, Device, Finding, FindingClass, FindingLifecycle, FindingSeverity, Grant,
    GrantScope, IdentityMode, InstallProfile, ProvenanceSource, SpanKind, Verdict,
};
use grdr_ports::LakeQueryIr;
use grdr_proto::api::operator::StageConfigRevisionRequest;
use grdr_proto::api::surfaces::{
    ApproveLegalHoldRequest, ApproveReidentificationRequest, CreateLegalHoldRequest,
    RequestReidentificationRequest, UpdateCompliancePolicyRequest,
};

use super::super::AppState;
use super::super::StorageBackend;
use super::super::surfaces_comply_seed::ensure_compliance_seeded;
use super::super::surfaces_types::{ReidLifecycle, ReidentificationRecord};
use super::super::users::DirectoryUserRecord;
use crate::auth::{AuthContext, AuthPlane, ConfirmAssertion};

fn test_auth(tenant_id: &str, principal_id: &str) -> AuthContext {
    AuthContext {
        principal_id: principal_id.to_owned(),
        tenant_id: tenant_id.to_owned(),
        plane: AuthPlane::Console,
        scopes: vec!["compliance:write".to_owned()],
        confirmation: ConfirmAssertion::StepUpVerified,
    }
}

fn test_scratch_dir(tag: &str) -> std::path::PathBuf {
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .or_else(|| std::env::var_os("HOME"))
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    base.join(format!("{tag}-{}", Uuid::now_v7().simple()))
}

#[tokio::test]
async fn compliance_honesty_lag_not_evaluable_and_works_council_drill_down() {
    let state = AppState::init(StorageBackend::Memory, false).unwrap();
    let ws = state.get_compliance_workspace("org-default").await;
    assert!(ws.legal_holds.is_empty());
    assert!(ws.subject_requests.is_empty());
    assert!(ws.reid_requests.is_empty());
    assert!(ws.disclosures.is_empty());
    assert!(ws.connectors.iter().all(|c| c.delivered_items == 0));
    assert!(ws.evidence_items.iter().all(|e| e.result == "not-met"));
    assert_eq!(
        ws.disclosure_metrics.as_ref().map(|m| m.quarter.as_str()),
        Some(format_utc_quarter(Timestamp::now()).as_str())
    );

    // Un-receipted attempt aged > 300s drives pipeline lag -> `not-evaluable`.
    let stale_ts =
        Timestamp::from_second(Timestamp::now().as_second().saturating_sub(600)).unwrap();
    {
        let mut g = state.inner.write().await;
        g.attempts.push(ActionAttempt {
            id: "att-lag-1".into(),
            session_id: "sess-lag".into(),
            device_id: "dev-lag".into(),
            device_name: "host-lag".into(),
            agent_name: "claude-code".into(),
            action_class: ActionClass::Exec,
            control_point: ControlPoint::Hook,
            target: "echo hi".into(),
            summary: "Lagging attempt".into(),
            timestamp: stale_ts,
            user_id: None,
            user_display: None,
            turn_index: 1,
            span_id: None,
            parent_span_id: None,
            span_kind: SpanKind::ExecuteTool,
            duration_ms: 10,
            provenance: ProvenanceSource::Observed,
            secondary_actions: vec![],
            skill_used: None,
            compaction: false,
        });
    }
    let lagged = state.get_compliance_workspace("org-default").await;
    assert!(
        lagged
            .evidence_items
            .iter()
            .all(|e| e.result == "not-evaluable")
    );

    // Works-council mode enforces purpose-bound drill-down with audit.access logging.
    let auth = test_auth("org-default", "responder@acme.example");
    state
        .update_compliance_policy(
            UpdateCompliancePolicyRequest {
                privacy_profile: "works-council".into(),
                presets: vec!["default".into()],
                override_legal_basis: None,
                capture_level: Some("metadata-and-signals".into()),
            },
            &auth,
        )
        .await
        .unwrap();
    assert!(
        state
            .validate_and_log_drill_down("prn_alice", None, None, "check", &auth)
            .await
            .is_err()
    );
    // Non-existent or resolved incident/finding IDs are rejected fail-closed.
    assert!(
        state
            .validate_and_log_drill_down(
                "prn_alice",
                Some("inc-42"),
                None,
                "Check fake incident",
                &auth,
            )
            .await
            .is_err()
    );

    let open_fnd_id = "fnd-drill-open".to_owned();
    let resolved_fnd_id = "fnd-drill-closed".to_owned();
    {
        let mut g = state.inner.write().await;
        let now = Timestamp::now();
        g.findings.push(Finding {
            id: open_fnd_id.clone(),
            session_id: "sess-drill-open".into(),
            device_id: "dev-drill".into(),
            device_name: "host-drill".into(),
            agent_name: "claude-code".into(),
            class: FindingClass::Threat,
            finding_class_other: None,
            severity: FindingSeverity::High,
            lifecycle: FindingLifecycle::Open,
            rule_id: None,
            title: "Active secret leak".into(),
            summary: "Open drill-down test finding".into(),
            target: ".env".into(),
            detected_at: now,
        });
        g.findings.push(Finding {
            id: resolved_fnd_id.clone(),
            session_id: "sess-drill-closed".into(),
            device_id: "dev-drill".into(),
            device_name: "host-drill".into(),
            agent_name: "claude-code".into(),
            class: FindingClass::Threat,
            finding_class_other: None,
            severity: FindingSeverity::Low,
            lifecycle: FindingLifecycle::Resolved,
            rule_id: None,
            title: "Resolved leak".into(),
            summary: "Closed finding".into(),
            target: ".env".into(),
            detected_at: now,
        });
    }
    let live_incidents = state.incidents().await;
    let open_inc = live_incidents
        .iter()
        .find(|inc| inc.session_id == "sess-drill-open")
        .expect("open incident");
    let closed_inc = live_incidents
        .iter()
        .find(|inc| inc.session_id == "sess-drill-closed")
        .expect("closed incident");
    assert!(
        state
            .validate_and_log_drill_down(
                "prn_alice",
                Some(&closed_inc.id),
                None,
                "Closed incident",
                &auth,
            )
            .await
            .is_err()
    );
    assert!(
        state
            .validate_and_log_drill_down(
                "prn_alice",
                None,
                Some(&resolved_fnd_id),
                "Closed finding",
                &auth,
            )
            .await
            .is_err()
    );

    let rec = state
        .validate_and_log_drill_down(
            "prn_alice",
            Some(&open_inc.id),
            None,
            "Contain leaked credential",
            &auth,
        )
        .await
        .unwrap();
    assert_eq!(rec.audit_kind, "audit.access");
    let rec_fnd = state
        .validate_and_log_drill_down(
            "prn_alice",
            None,
            Some(&open_fnd_id),
            "Triage open finding",
            &auth,
        )
        .await
        .unwrap();
    assert_eq!(rec_fnd.audit_kind, "audit.access");
}

#[tokio::test]
async fn server_dsar_hold_deferral_release_and_parquet_lake_erasure_cascade() {
    let dir = test_scratch_dir("grdr-comply-dsar-lake");
    let state = AppState::init(StorageBackend::Disk(dir.clone()), false).unwrap();
    let now = Timestamp::now();
    let now_ms = now.as_millisecond();
    let auth = test_auth("org-default", "dpo@acme.example");

    {
        let mut g = state.inner.write().await;
        ensure_compliance_seeded(&mut g, now);
        g.user_directory.push(DirectoryUserRecord {
            id: "usr-eva".into(),
            display_name: "Eva".into(),
            email: "eva@acme.example".into(),
            department: "Security".into(),
            idp_source: "scim".into(),
            pseudonym_id: "prn_eva_01".into(),
        });
        g.devices.push(Device {
            id: "dev-eva".into(),
            hostname: "eva-mbp".into(),
            os: "macOS".into(),
            arch: "arm64".into(),
            install_profile: InstallProfile::Protected,
            daemon_version: "0.1.0".into(),
            online: true,
            hook_effective: true,
            agents: vec![],
            mcp_servers: vec![],
            artifacts: vec![],
            user_id: Some("usr-eva".into()),
            user_display: Some("Eva".into()),
            last_seen: now,
            public_key: None,
        });
        g.attempts.push(ActionAttempt {
            id: "att-eva-1".into(),
            session_id: "sess-eva-01".into(),
            device_id: "dev-eva".into(),
            device_name: "eva-mbp".into(),
            agent_name: "claude-code".into(),
            action_class: ActionClass::FileRead,
            control_point: ControlPoint::Hook,
            target: "secret prompt payload".into(),
            summary: "Read secret file".into(),
            timestamp: now,
            user_id: Some("usr-eva".into()),
            user_display: Some("Eva".into()),
            turn_index: 1,
            span_id: None,
            parent_span_id: None,
            span_kind: SpanKind::ExecuteTool,
            duration_ms: 15,
            provenance: ProvenanceSource::Mediated,
            secondary_actions: vec![],
            skill_used: None,
            compaction: false,
        });
        g.receipts.push(DecisionReceipt {
            receipt_id: "rcp-eva-1".into(),
            attempt_id: "att-eva-1".into(),
            session_id: "sess-eva-01".into(),
            device_id: "dev-eva".into(),
            agent_name: "claude-code".into(),
            action_class: ActionClass::FileRead,
            control_point: ControlPoint::Hook,
            target: "secret prompt payload".into(),
            verdict: Verdict::Allow,
            would_be: None,
            rule_id: None,
            pack_id: None,
            mode_applied: None,
            grant_id: None,
            reason: "Allowed read of secret.txt".into(),
            next_step: "Open secret.txt".into(),
            receipt_digest: "dig-eva".into(),
            decided_at: now,
            key_id: None,
            signature: None,
            signature_verified: None,
        });
        g.approvals.push(ApprovalRequest {
            id: "apr-eva-1".into(),
            receipt_id: "rcp-eva-1".into(),
            session_id: "sess-eva-01".into(),
            device_id: "dev-eva".into(),
            device_name: "eva-mbp".into(),
            agent_name: "claude-code".into(),
            action_class: ActionClass::FileRead,
            target: "secret.txt".into(),
            rule_id: "r1".into(),
            rule_title: "Read secret".into(),
            required_grade: ApprovalGrade::G1,
            reason: "Eva needs secret.txt".into(),
            requested_at: now,
            state: ApprovalState::Approved {
                grant_id: "gr-eva-1".into(),
                scope: GrantScope::Once,
                decided_at: now,
                note: "Approved for Eva".into(),
            },
        });
        g.grants.push(Grant {
            grant_id: "gr-eva-1".into(),
            rule_id: "r1".into(),
            session_id: "sess-eva-01".into(),
            device_id: "dev-eva".into(),
            action_class: ActionClass::FileRead,
            target_pattern: "secret.txt".into(),
            scope: GrantScope::Once,
            grade: ApprovalGrade::G1,
            granted_at: now,
            expires_at: None,
            remaining_uses: Some(1),
            note: "Eva secret grant".into(),
            key_id: None,
            signature: None,
        });
        g.findings.push(Finding {
            id: "fnd-eva-1".into(),
            session_id: "sess-eva-01".into(),
            device_id: "dev-eva".into(),
            device_name: "eva-mbp".into(),
            agent_name: "claude-code".into(),
            class: FindingClass::Threat,
            finding_class_other: None,
            severity: FindingSeverity::Medium,
            lifecycle: FindingLifecycle::Open,
            rule_id: None,
            title: "Eva opened secret.txt".into(),
            summary: "Eva summary".into(),
            target: "secret.txt".into(),
            detected_at: now,
        });

        let mut ledger = HoldsLedger::default();
        let hold = ledger
            .place_hold(PlaceHoldInput {
                organisation: "org-default".into(),
                scope: HoldScope {
                    pseudonyms: vec!["prn_eva_01".into()],
                    session_ids: vec![],
                    incident_id: None,
                    classes: vec!["decision".into(), "audit".into()],
                    from: None,
                    to: None,
                },
                matter_ref: "MATTER-EVA-9".into(),
                reason: "Hold while preserving incident chain".into(),
                created_by: "dpo@acme.example".into(),
                approvers: vec!["dpo@acme.example".into(), "owner@acme.example".into()],
                created_at: now,
                review_by: Timestamp::from_second(now.as_second() + 30 * 86_400).unwrap(),
                notice: HoldNotice::Deferred {
                    until: Timestamp::from_second(now.as_second() + 14 * 86_400).unwrap(),
                    renewals: 0,
                },
            })
            .unwrap();
        if let Some(ref mut comp) = g.surfaces.compliance {
            comp.legal_holds.push(hold.clone());
            comp.reid_requests.push(ReidentificationRecord {
                request_id: "reid-iso-other".into(),
                organisation: "org-other".into(),
                pseudonym_id: "prn_eva_01".into(),
                requester: "other@other.example".into(),
                reason: "Other org".into(),
                legal_basis: "Art. 6(1)(f)".into(),
                status: ReidLifecycle::Approved,
                approvers: vec!["a@other.example".into(), "b@other.example".into()],
                resolved_identity: Some("Other Eva".into()),
                created_at: now.to_string(),
                resolved_at: Some(now.to_string()),
            });
            comp.reid_requests.push(ReidentificationRecord {
                request_id: "reid-same-org".into(),
                organisation: "org-default".into(),
                pseudonym_id: "prn_eva_01".into(),
                requester: "dpo@acme.example".into(),
                reason: "Same org".into(),
                legal_basis: "Art. 6(1)(f)".into(),
                status: ReidLifecycle::Approved,
                approvers: vec!["dpo@acme.example".into(), "owner@acme.example".into()],
                resolved_identity: Some("Eva <eva@acme.example>".into()),
                created_at: now.to_string(),
                resolved_at: Some(now.to_string()),
            });
        }
    }

    let payload = br#"{"receipt_id":"rcp_eva_1","session_id":"sess-eva-01","target":"secret prompt payload","content":"sensitive"}"#;
    state
        .storage
        .as_ref()
        .unwrap()
        .append_and_commit_event("dev-eva", payload)
        .unwrap();
    let flushed = state.flush_lake(now_ms.saturating_add(1_000)).unwrap();
    assert!(flushed.rows_flushed >= 1);

    // Held erasure stays PendingHeld and does not disclose deferred hold IDs.
    let held_exec = state
        .execute_server_subject_request(SubjectRequestKind::Erasure, "eva@acme.example", &auth)
        .await
        .unwrap();
    assert!(matches!(
        held_exec.record.lifecycle,
        ComplySubjectLifecycle::PendingHeld {
            disclose_hold: false,
            ..
        }
    ));

    // Releasing the legal hold via release_legal_hold triggers atomic post-hold DSAR cascade.
    let hid = {
        let g = state.inner.read().await;
        g.surfaces
            .compliance
            .as_ref()
            .unwrap()
            .legal_holds
            .first()
            .unwrap()
            .hold_id
            .clone()
    };
    let (released_entry, processed) = state
        .release_legal_hold(
            &hid,
            &["dpo@acme.example".into(), "owner@acme.example".into()],
            "Matter concluded",
            &auth,
        )
        .await
        .unwrap();
    assert_eq!(released_entry.lifecycle, "released");
    assert_eq!(processed, 1);

    let g = state.inner.read().await;
    assert!(g.user_directory.is_empty());
    assert_eq!(
        g.attempts.first().unwrap().target,
        "[erased under GDPR Art. 17]"
    );
    assert_eq!(
        g.receipts.first().unwrap().reason,
        "[erased under GDPR Art. 17]"
    );
    assert_eq!(
        g.approvals.first().unwrap().target,
        "[erased under GDPR Art. 17]"
    );
    assert_eq!(
        g.grants.first().unwrap().target_pattern,
        "[erased under GDPR Art. 17]"
    );
    assert_eq!(
        g.findings.first().unwrap().title,
        "[erased under GDPR Art. 17]"
    );
    let comp = g.surfaces.compliance.as_ref().unwrap();
    assert_eq!(
        comp.subject_requests.first().unwrap().subject_ref,
        "[erased]"
    );
    assert_eq!(
        comp.reid_requests
            .iter()
            .find(|r| r.request_id == "reid-same-org")
            .unwrap()
            .pseudonym_id,
        "[unlinked]"
    );
    // Cross-tenant re-identification records must remain untouched.
    assert_eq!(
        comp.reid_requests
            .iter()
            .find(|r| r.request_id == "reid-iso-other")
            .unwrap()
            .pseudonym_id,
        "prn_eva_01"
    );
    drop(g);

    let timeline = state
        .query_lake(&LakeQueryIr::Timeline {
            root_session_id: "sess-eva-01".into(),
            include_content: true,
            limit: 10,
        })
        .unwrap();
    assert!(
        timeline
            .rows
            .iter()
            .all(|r| r.content_redacted || !r.columns.contains_key("content"))
    );

    // P8 k-anonymity rejects oversight report when approvals exist and distinct reviewers < 5, even if user_directory >= 5.
    {
        let mut g = state.inner.write().await;
        for idx in 0..5 {
            g.user_directory.push(DirectoryUserRecord {
                id: format!("usr-cohort-{idx}"),
                display_name: format!("User {idx}"),
                email: format!("u{idx}@acme.example"),
                department: "Eng".into(),
                idp_source: "scim".into(),
                pseudonym_id: format!("prn_cohort_{idx}"),
            });
        }
    }
    assert!(
        state
            .build_server_oversight_report("org-default")
            .await
            .is_err()
    );
    {
        let mut g = state.inner.write().await;
        let comp = g.surfaces.compliance.as_mut().unwrap();
        for idx in 0..5 {
            comp.co_approver_group
                .push(format!("reviewer-{idx}@acme.example"));
        }
    }
    let oversight = state
        .build_server_oversight_report("org-default")
        .await
        .unwrap();
    assert_eq!(oversight.organisation, "org-default");

    let ropa = state
        .build_server_ropa("org-default", "Acme GmbH", "dpo@acme.example")
        .await
        .unwrap();
    assert_eq!(ropa.controller_name, "Acme GmbH");
    let restr = state
        .execute_server_subject_request(SubjectRequestKind::Restriction, "prn_cohort_1", &auth)
        .await
        .unwrap();
    assert!(!restr.exclusion_added.is_empty());
    let docs = state
        .build_server_privacy_docs("org-default", NoticeLocale::De)
        .await
        .unwrap();
    assert!(docs.worker_notice.title.contains("Datenschutzhinweis"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn policy_schedule_basis_works_council_quorum_and_lake_error_fail_closed() {
    let dir = test_scratch_dir("grdr-comply-quorum");
    let state = AppState::init(StorageBackend::Disk(dir.clone()), false).unwrap();
    let dpo_a = test_auth("org-default", "dpo-a@acme.example");
    let rep_b = test_auth("org-default", "council-rep@acme.example");
    let non_group = test_auth("org-default", "outsider@acme.example");

    // 1. Capture increase under Standard stays deferred until effective_at.
    state
        .update_compliance_policy(
            UpdateCompliancePolicyRequest {
                privacy_profile: "standard".into(),
                presets: vec!["default".into()],
                override_legal_basis: None,
                capture_level: Some("metadata-and-signals".into()),
            },
            &dpo_a,
        )
        .await
        .unwrap();
    {
        let mut g = state.inner.write().await;
        let comp = g.surfaces.compliance.as_mut().unwrap();
        assert_eq!(comp.capture_level, "metadata-only");
        let pending = comp.pending_capture_change.as_mut().unwrap();
        pending.effective_at =
            Timestamp::from_second(Timestamp::now().as_second().saturating_sub(60))
                .unwrap()
                .to_string();
    }
    let _ = state.get_compliance_workspace("org-default").await;
    {
        let g = state.inner.read().await;
        let comp = g.surfaces.compliance.as_ref().unwrap();
        assert_eq!(comp.capture_level, "metadata-and-signals");
        assert!(comp.pending_capture_change.is_none());
    }

    // 2. Regulated preset requiring recorded legal basis fails closed without explicit basis.
    assert!(
        state
            .update_compliance_policy(
                UpdateCompliancePolicyRequest {
                    privacy_profile: "standard".into(),
                    presets: vec!["eu-ai-act-deployer".into()],
                    override_legal_basis: None,
                    capture_level: None,
                },
                &dpo_a,
            )
            .await
            .is_err()
    );
    let mut reg_map = BTreeMap::new();
    reg_map.insert("preset", "eu-ai-act-deployer");
    assert!(!reg_map.is_empty());
    state
        .update_compliance_policy(
            UpdateCompliancePolicyRequest {
                privacy_profile: "standard".into(),
                presets: vec!["eu-ai-act-deployer".into()],
                override_legal_basis: Some("EU AI Act Art. 26 deployer mandate".into()),
                capture_level: None,
            },
            &dpo_a,
        )
        .await
        .unwrap();

    // 3. WorksCouncil quorum requires co_approver_group across holds, re-id, and downgrade.
    state
        .update_compliance_policy(
            UpdateCompliancePolicyRequest {
                privacy_profile: "works-council".into(),
                presets: vec!["default".into()],
                override_legal_basis: None,
                capture_level: Some("metadata-only".into()),
            },
            &dpo_a,
        )
        .await
        .unwrap();
    {
        let mut g = state.inner.write().await;
        g.surfaces
            .compliance
            .as_mut()
            .unwrap()
            .co_approver_group
            .push("council-rep@acme.example".into());
    }

    let pending_hold = state
        .create_legal_hold(
            CreateLegalHoldRequest {
                matter_ref: "M-WC-1".into(),
                reason: "WC hold".into(),
                pseudonym_or_session: "prn_wc_1".into(),
            },
            &dpo_a,
        )
        .await
        .unwrap();
    assert!(
        state
            .approve_legal_hold(
                ApproveLegalHoldRequest {
                    hold_id: pending_hold.hold_id.clone(),
                    note: None,
                },
                &non_group,
            )
            .await
            .is_err()
    );
    let active_hold = state
        .approve_legal_hold(
            ApproveLegalHoldRequest {
                hold_id: pending_hold.hold_id,
                note: None,
            },
            &rep_b,
        )
        .await
        .unwrap();
    assert_eq!(active_hold.lifecycle, "active");

    let reid_req = state
        .request_reidentification(
            RequestReidentificationRequest {
                pseudonym_id: "prn_wc_1".into(),
                reason: "Incident escalation".into(),
                legal_basis: "Art. 6(1)(f)".into(),
            },
            &dpo_a,
        )
        .await
        .unwrap();
    assert!(
        state
            .approve_reidentification(
                ApproveReidentificationRequest {
                    request_id: reid_req.request_id.clone(),
                    note: None,
                },
                &non_group,
            )
            .await
            .is_ok()
    );
    // Completing quorum requires at least one co_approver_group member.
    let outsider2 = test_auth("org-default", "outsider2@acme.example");
    assert!(
        state
            .approve_reidentification(
                ApproveReidentificationRequest {
                    request_id: reid_req.request_id.clone(),
                    note: None,
                },
                &outsider2,
            )
            .await
            .is_err()
    );
    let approved_reid = state
        .approve_reidentification(
            ApproveReidentificationRequest {
                request_id: reid_req.request_id,
                note: None,
            },
            &rep_b,
        )
        .await
        .unwrap();
    assert!(approved_reid.resolved_identity.is_some());

    // WorksCouncil -> Standard downgrade stages on 1st call, binds parameters strictly, and completes on matching co-approver 2nd call.
    state
        .update_compliance_policy(
            UpdateCompliancePolicyRequest {
                privacy_profile: "standard".into(),
                presets: vec!["default".into()],
                override_legal_basis: Some("DPO approved".into()),
                capture_level: None,
            },
            &dpo_a,
        )
        .await
        .unwrap();
    {
        let g = state.inner.read().await;
        assert_eq!(g.privacy.identity_mode, IdentityMode::Pseudonymous);
        assert_eq!(
            g.surfaces.compliance.as_ref().unwrap().privacy_profile,
            PrivacyCeilingProfile::WorksCouncil
        );
    }
    assert!(
        state
            .update_compliance_policy(
                UpdateCompliancePolicyRequest {
                    privacy_profile: "standard".into(),
                    presets: vec!["default".into()],
                    override_legal_basis: Some("Outsider attempt".into()),
                    capture_level: None,
                },
                &non_group,
            )
            .await
            .is_err()
    );
    // Mismatched parameters from co-approver must fail closed.
    assert!(
        state
            .update_compliance_policy(
                UpdateCompliancePolicyRequest {
                    privacy_profile: "standard".into(),
                    presets: vec!["default".into()],
                    override_legal_basis: Some("Substituted basis".into()),
                    capture_level: None,
                },
                &rep_b,
            )
            .await
            .is_err()
    );
    state
        .update_compliance_policy(
            UpdateCompliancePolicyRequest {
                privacy_profile: "standard".into(),
                presets: vec!["default".into()],
                override_legal_basis: Some("DPO approved".into()),
                capture_level: None,
            },
            &rep_b,
        )
        .await
        .unwrap();
    {
        let g = state.inner.read().await;
        assert_eq!(g.privacy.identity_mode, IdentityMode::Named);
    }

    // 4. Corrupt lake manifest on disk fails closed -> evidence becomes not-evaluable.
    let manifest_path = dir.join("lake").join("manifest.json");
    if manifest_path.exists() {
        std::fs::write(&manifest_path, b"{corrupt").unwrap();
        let ws = state.get_compliance_workspace("org-default").await;
        assert!(
            ws.evidence_items
                .iter()
                .all(|e| e.result == "not-evaluable")
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn session_hold_notice_extension_operator_parity_and_oscal_validation_work() {
    let dir = test_scratch_dir("grdr-comply-b2-b4");
    let state = AppState::init(StorageBackend::Disk(dir.clone()), false).unwrap();
    let now = Timestamp::now();
    let dpo_a = test_auth("org-default", "dpo-a@acme.example");
    let rep_b = test_auth("org-default", "council-rep@acme.example");

    // 1. Server legal hold targeting a session ID populates scope.session_ids and blocks DSAR erasure + lake DEKs.
    {
        let mut g = state.inner.write().await;
        ensure_compliance_seeded(&mut g, now);
        g.user_directory.push(DirectoryUserRecord {
            id: "usr-bob".into(),
            display_name: "Bob".into(),
            email: "bob@acme.example".into(),
            department: "Eng".into(),
            idp_source: "scim".into(),
            pseudonym_id: "prn_bob_01".into(),
        });
        g.devices.push(Device {
            id: "dev-bob".into(),
            hostname: "bob-mbp".into(),
            os: "macOS".into(),
            arch: "arm64".into(),
            install_profile: InstallProfile::Protected,
            daemon_version: "0.1.0".into(),
            online: true,
            hook_effective: true,
            agents: vec![],
            mcp_servers: vec![],
            artifacts: vec![],
            user_id: Some("usr-bob".into()),
            user_display: Some("Bob".into()),
            last_seen: now,
            public_key: None,
        });
        g.attempts.push(ActionAttempt {
            id: "att-bob-1".into(),
            session_id: "sess-bob-hold".into(),
            device_id: "dev-bob".into(),
            device_name: "bob-mbp".into(),
            agent_name: "claude-code".into(),
            action_class: ActionClass::FileRead,
            control_point: ControlPoint::Hook,
            target: "bob secret".into(),
            summary: "Bob summary".into(),
            timestamp: now,
            user_id: Some("usr-bob".into()),
            user_display: Some("Bob".into()),
            turn_index: 1,
            span_id: None,
            parent_span_id: None,
            span_kind: SpanKind::ExecuteTool,
            duration_ms: 10,
            provenance: ProvenanceSource::Mediated,
            secondary_actions: vec![],
            skill_used: None,
            compaction: false,
        });
    }
    let proposed = state
        .create_legal_hold(
            CreateLegalHoldRequest {
                matter_ref: "M-SESS-1".into(),
                reason: "Session hold".into(),
                pseudonym_or_session: "sess-bob-hold".into(),
            },
            &dpo_a,
        )
        .await
        .unwrap();
    let active = state
        .approve_legal_hold(
            ApproveLegalHoldRequest {
                hold_id: proposed.hold_id,
                note: None,
            },
            &rep_b,
        )
        .await
        .unwrap();
    assert_eq!(active.scope_summary, "sess-bob-hold");
    let held_dsar = state
        .execute_server_subject_request(SubjectRequestKind::Erasure, "bob@acme.example", &dpo_a)
        .await
        .unwrap();
    assert!(matches!(
        held_dsar.record.lifecycle,
        ComplySubjectLifecycle::PendingHeld { .. }
    ));

    // Also queue a second DSAR under the same hold to exercise per-request H6 checkpointing on release.
    let held_dsar2 = state
        .execute_server_subject_request(SubjectRequestKind::Erasure, "prn_bob_01", &dpo_a)
        .await
        .unwrap();
    assert!(matches!(
        held_dsar2.record.lifecycle,
        ComplySubjectLifecycle::PendingHeld { .. }
    ));
    let (_, reprocessed) = state
        .release_legal_hold(
            &active.hold_id,
            &[
                "dpo-a@acme.example".into(),
                "council-rep@acme.example".into(),
            ],
            "Hold cleared",
            &dpo_a,
        )
        .await
        .unwrap();
    assert_eq!(reprocessed, 2);

    // 2. B3: Transitioning to WorksCouncil with a 7d Standard PendingCaptureChange extends notice to 14d.
    state
        .update_compliance_policy(
            UpdateCompliancePolicyRequest {
                privacy_profile: "standard".into(),
                presets: vec!["default".into()],
                override_legal_basis: None,
                capture_level: Some("metadata-and-signals".into()),
            },
            &dpo_a,
        )
        .await
        .unwrap();
    let before_ext = {
        let g = state.inner.read().await;
        g.surfaces
            .compliance
            .as_ref()
            .unwrap()
            .pending_capture_change
            .as_ref()
            .unwrap()
            .effective_at
            .parse::<Timestamp>()
            .unwrap()
    };
    state
        .update_compliance_policy(
            UpdateCompliancePolicyRequest {
                privacy_profile: "works-council".into(),
                presets: vec!["default".into()],
                override_legal_basis: None,
                capture_level: None,
            },
            &dpo_a,
        )
        .await
        .unwrap();
    {
        let g = state.inner.read().await;
        let pending = g
            .surfaces
            .compliance
            .as_ref()
            .unwrap()
            .pending_capture_change
            .as_ref()
            .unwrap();
        let after_ext = pending.effective_at.parse::<Timestamp>().unwrap();
        assert!(after_ext > before_ext);
        assert!(pending.notice_rule.contains("14d"));
    }

    // Reset back to Standard cleanly to test B4 operator guards from Standard -> WorksCouncil -> Standard.
    {
        let mut g = state.inner.write().await;
        g.privacy.identity_mode = IdentityMode::Named;
        let comp = g.surfaces.compliance.as_mut().unwrap();
        comp.privacy_profile = PrivacyCeilingProfile::Standard;
        comp.pending_capture_change = None;
        comp.co_approver_group = vec!["council-rep@acme.example".into()];
    }

    // 3. B4: stage_config_revision rejects requires_recorded_basis preset without recorded Compliance basis.
    assert!(
        state
            .stage_config_revision(
                StageConfigRevisionRequest {
                    capture_level: "metadata-only".into(),
                    privacy_profile: "standard".into(),
                    retention_preset: "eu-ai-act-deployer".into(),
                    otlp_enabled: false,
                    release_channel: "stable".into(),
                    summary: "No basis".into(),
                },
                &dpo_a,
            )
            .await
            .is_err()
    );
    let std_rev = state
        .stage_config_revision(
            StageConfigRevisionRequest {
                capture_level: "metadata-only".into(),
                privacy_profile: "standard".into(),
                retention_preset: "default".into(),
                otlp_enabled: false,
                release_channel: "stable".into(),
                summary: "Baseline standard".into(),
            },
            &dpo_a,
        )
        .await
        .unwrap();
    state
        .apply_config_revision(&std_rev.revision_id, &dpo_a)
        .await
        .unwrap();
    let wc_rev = state
        .stage_config_revision(
            StageConfigRevisionRequest {
                capture_level: "metadata-only".into(),
                privacy_profile: "works-council".into(),
                retention_preset: "default".into(),
                otlp_enabled: false,
                release_channel: "stable".into(),
                summary: "Enable works council".into(),
            },
            &dpo_a,
        )
        .await
        .unwrap();
    state
        .apply_config_revision(&wc_rev.revision_id, &dpo_a)
        .await
        .unwrap();
    {
        let g = state.inner.read().await;
        assert_eq!(g.privacy.identity_mode, IdentityMode::Pseudonymous);
        assert_eq!(
            g.surfaces.compliance.as_ref().unwrap().privacy_profile,
            PrivacyCeilingProfile::WorksCouncil
        );
    }
    let std_rev2 = state
        .stage_config_revision(
            StageConfigRevisionRequest {
                capture_level: "metadata-only".into(),
                privacy_profile: "standard".into(),
                retention_preset: "default".into(),
                otlp_enabled: false,
                release_channel: "stable".into(),
                summary: "Attempt weaken".into(),
            },
            &dpo_a,
        )
        .await
        .unwrap();
    assert!(
        state
            .apply_config_revision(&std_rev2.revision_id, &dpo_a)
            .await
            .is_err()
    );
    assert!(
        state
            .rollback_config_revision(
                Some(&std_rev.revision_id),
                "Attempt rollback weaken",
                &dpo_a
            )
            .await
            .is_err()
    );
    {
        let g = state.inner.read().await;
        assert_eq!(g.privacy.identity_mode, IdentityMode::Pseudonymous);
    }

    // Complete Compliance co-approver quorum downgrade, then operator apply succeeds and stays synchronized.
    state
        .update_compliance_policy(
            UpdateCompliancePolicyRequest {
                privacy_profile: "standard".into(),
                presets: vec!["default".into()],
                override_legal_basis: Some("Quorum basis".into()),
                capture_level: None,
            },
            &dpo_a,
        )
        .await
        .unwrap();
    state
        .update_compliance_policy(
            UpdateCompliancePolicyRequest {
                privacy_profile: "standard".into(),
                presets: vec!["default".into()],
                override_legal_basis: Some("Quorum basis".into()),
                capture_level: None,
            },
            &rep_b,
        )
        .await
        .unwrap();
    state
        .apply_config_revision(&std_rev2.revision_id, &dpo_a)
        .await
        .unwrap();
    {
        let g = state.inner.read().await;
        assert_eq!(g.privacy.identity_mode, IdentityMode::Named);
        assert_eq!(
            g.surfaces.compliance.as_ref().unwrap().privacy_profile,
            PrivacyCeilingProfile::Standard
        );
    }

    // 4. H4: OSCAL exports validate against strict structural validator.
    let comp_export = state
        .export_compliance_artifact("oscal-component", &dpo_a)
        .await
        .unwrap();
    validate_oscal_component_json(&comp_export.payload).unwrap();
    let assess_export = state
        .export_compliance_artifact("oscal-assessment", &dpo_a)
        .await
        .unwrap();
    validate_oscal_assessment_json(&assess_export.payload).unwrap();

    let _ = std::fs::remove_dir_all(&dir);
}
