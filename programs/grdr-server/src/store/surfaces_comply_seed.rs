// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use jiff::Timestamp;

use grdr_comply::{
    HoldNotice, HoldScope, HoldsLedger, PlaceHoldInput, PrivacyCeilingProfile, RetentionPreset,
};
use grdr_model::IdentityMode;

use super::StoreData;
use super::surfaces_types::{
    ComplianceGovernanceState, ConnectorRuntimeRecord, DisclosureRecord, ReidLifecycle,
    ReidentificationRecord, SubjectReqRecord, SubjectRequestLifecycle,
};

const SECONDS_PER_DAY: i64 = 86_400;

pub(crate) fn ensure_compliance_seeded(data: &mut StoreData, now: Timestamp) {
    if data.surfaces.compliance.is_some() {
        return;
    }
    let created_hold =
        Timestamp::from_second(now.as_second().saturating_sub(2 * SECONDS_PER_DAY)).unwrap_or(now);
    let review_hold =
        Timestamp::from_second(now.as_second().saturating_add(60 * SECONDS_PER_DAY)).unwrap_or(now);
    let mut ledger = HoldsLedger::default();
    let _ = ledger.place_hold(PlaceHoldInput {
        organisation: "org-default".to_owned(),
        scope: HoldScope {
            pseudonyms: vec!["prn_8f4c21a9e041".to_owned()],
            session_ids: Vec::new(),
            incident_id: None,
            classes: vec!["decision".to_owned(), "audit".to_owned()],
            from: None,
            to: None,
        },
        matter_ref: "MATTER-2026-014".to_owned(),
        reason: "Preserving key-access trace pending security review".to_owned(),
        created_by: "dpo@acme-eng.example".to_owned(),
        approvers: vec![
            "legal-counsel@acme-eng.example".to_owned(),
            "sec-lead@acme-eng.example".to_owned(),
        ],
        created_at: created_hold,
        review_by: review_hold,
        notice: HoldNotice::Immediate,
    });

    let active_hold_ids: Vec<String> = ledger.holds.iter().map(|h| h.hold_id.clone()).collect();
    data.surfaces.compliance = Some(ComplianceGovernanceState {
        privacy_profile: if data.privacy.identity_mode == IdentityMode::Pseudonymous {
            PrivacyCeilingProfile::WorksCouncil
        } else {
            PrivacyCeilingProfile::Standard
        },
        presets: vec![RetentionPreset::Default, RetentionPreset::EuAiActDeployer],
        override_legal_basis: None,
        capture_level: "metadata-only".to_owned(),
        legal_holds: ledger.holds,
        pending_holds: Vec::new(),
        subject_requests: vec![
            SubjectReqRecord {
                request_id: "dsr-erasure-01".to_owned(),
                organisation: "org-default".to_owned(),
                kind: "erasure".to_owned(),
                subject_ref: "prn_8f4c21a9e041".to_owned(),
                status: SubjectRequestLifecycle::PendingHeld,
                hold_ids: active_hold_ids,
                requested_at: created_hold.to_string(),
                detail: "Erasure paused while active legal hold MATTER-2026-014 remains open"
                    .to_owned(),
            },
            SubjectReqRecord {
                request_id: "dsr-access-02".to_owned(),
                organisation: "org-default".to_owned(),
                kind: "access".to_owned(),
                subject_ref: "prn_92e04ab11f88".to_owned(),
                status: SubjectRequestLifecycle::Executed,
                hold_ids: Vec::new(),
                requested_at: now.to_string(),
                detail: "Signed metadata bundle delivered cleanly".to_owned(),
            },
        ],
        connectors: vec![
            ConnectorRuntimeRecord {
                id: "anthropic-compliance".to_owned(),
                name: "Anthropic Activity Feed".to_owned(),
                kind: "saas_compliance".to_owned(),
                stability: "preview".to_owned(),
                circuit_state: "closed".to_owned(),
                queued_items: 0,
                delivered_items: 18,
                capture_ceiling: "metadata-only".to_owned(),
                assurance_label: "Claimed · API pull".to_owned(),
                last_delivery_at: Some(now.to_string()),
                summary: "Ingests organization Claude usage without prompt payloads".to_owned(),
            },
            ConnectorRuntimeRecord {
                id: "openai-compliance".to_owned(),
                name: "OpenAI Compliance API".to_owned(),
                kind: "saas_compliance".to_owned(),
                stability: "preview".to_owned(),
                circuit_state: "closed".to_owned(),
                queued_items: 1,
                delivered_items: 12,
                capture_ceiling: "metadata-only".to_owned(),
                assurance_label: "Claimed · API pull".to_owned(),
                last_delivery_at: Some(now.to_string()),
                summary: "Reconciles workspace sessions with shared rate budget guard".to_owned(),
            },
            ConnectorRuntimeRecord {
                id: "ciso-assistant".to_owned(),
                name: "CISO Assistant GRC".to_owned(),
                kind: "grc_sink".to_owned(),
                stability: "stable".to_owned(),
                circuit_state: "closed".to_owned(),
                queued_items: 0,
                delivered_items: 6,
                capture_ceiling: "derived-only".to_owned(),
                assurance_label: "Verified · Ed25519".to_owned(),
                last_delivery_at: Some(now.to_string()),
                summary: "Publishes applied control states and SHA-256 evidence digests".to_owned(),
            },
            ConnectorRuntimeRecord {
                id: "probo".to_owned(),
                name: "Probo Compliance".to_owned(),
                kind: "grc_sink".to_owned(),
                stability: "stable".to_owned(),
                circuit_state: "closed".to_owned(),
                queued_items: 0,
                delivered_items: 4,
                capture_ceiling: "derived-only".to_owned(),
                assurance_label: "Verified · Ed25519".to_owned(),
                last_delivery_at: Some(now.to_string()),
                summary: "Pushes SOC 2 and ISO 27001 readiness bundles without prompt text"
                    .to_owned(),
            },
        ],
        reid_requests: vec![ReidentificationRecord {
            request_id: "reid-demo-01".to_owned(),
            organisation: "org-default".to_owned(),
            pseudonym_id: "prn_3b19d04c7a12".to_owned(),
            requester: "maya.chen@acme-eng.example".to_owned(),
            reason: "Verify authorized owner behind SSH key read finding".to_owned(),
            legal_basis: "Incident containment Art. 6(1)(f)".to_owned(),
            status: ReidLifecycle::PendingQuorum,
            approvers: vec!["legal-counsel@acme-eng.example".to_owned()],
            resolved_identity: None,
            created_at: created_hold.to_string(),
            resolved_at: None,
        }],
        disclosures: vec![DisclosureRecord {
            id: "disc-demo-01".to_owned(),
            organisation: "org-default".to_owned(),
            kind: "legal_hold".to_owned(),
            actor: "legal-counsel@acme-eng.example".to_owned(),
            target_ref: "prn_8f4c21a9e041".to_owned(),
            legal_basis: "MATTER-2026-014".to_owned(),
            timestamp: created_hold.to_string(),
            quarter: "2026-Q4".to_owned(),
            summary: "Dual-approved hold registered across decision and audit lanes".to_owned(),
        }],
    });
}
