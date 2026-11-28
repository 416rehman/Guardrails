// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use jiff::Timestamp;

use grdr_comply::{PrivacyCeilingProfile, RetentionPreset};
use grdr_model::{IdentityMode, IntegrationHealthState};

use super::StoreData;
use super::surfaces_types::{ComplianceGovernanceState, ConnectorRuntimeRecord};

pub(crate) fn ensure_compliance_seeded(data: &mut StoreData, _now: Timestamp) {
    if data.surfaces.compliance.is_some() {
        return;
    }

    let mut connectors: Vec<ConnectorRuntimeRecord> = data
        .integrations
        .iter()
        .map(|entry| ConnectorRuntimeRecord {
            id: entry.id.clone(),
            name: entry.name.clone(),
            kind: format!("{:?}", entry.category).to_ascii_lowercase(),
            stability: if entry.state == IntegrationHealthState::NotConfigured {
                "not_configured".to_owned()
            } else {
                "configured".to_owned()
            },
            circuit_state: "closed".to_owned(),
            queued_items: 0,
            delivered_items: 0,
            capture_ceiling: "metadata-only".to_owned(),
            assurance_label: "Claimed · API pull".to_owned(),
            last_delivery_at: entry.last_sync_at.clone(),
            summary: entry.detail.clone(),
        })
        .collect();

    for (id, name, summary) in [
        (
            "ciso-assistant",
            "CISO Assistant GRC",
            "Publishes applied control states and SHA-256 evidence digests",
        ),
        (
            "probo",
            "Probo Compliance",
            "Pushes SOC 2 and ISO 27001 readiness bundles without prompt text",
        ),
    ] {
        if !connectors.iter().any(|c| c.id == id) {
            connectors.push(ConnectorRuntimeRecord {
                id: id.to_owned(),
                name: name.to_owned(),
                kind: "grc_sink".to_owned(),
                stability: "not_configured".to_owned(),
                circuit_state: "closed".to_owned(),
                queued_items: 0,
                delivered_items: 0,
                capture_ceiling: "metadata-only".to_owned(),
                assurance_label: "Pending · local outbox".to_owned(),
                last_delivery_at: None,
                summary: summary.to_owned(),
            });
        }
    }

    data.surfaces.compliance = Some(ComplianceGovernanceState {
        privacy_profile: if data.privacy.identity_mode == IdentityMode::Pseudonymous {
            PrivacyCeilingProfile::WorksCouncil
        } else {
            PrivacyCeilingProfile::Standard
        },
        presets: vec![RetentionPreset::Default],
        override_legal_basis: None,
        capture_level: "metadata-only".to_owned(),
        legal_holds: Vec::new(),
        pending_holds: Vec::new(),
        subject_requests: Vec::new(),
        connectors,
        reid_requests: Vec::new(),
        disclosures: Vec::new(),
        co_approver_group: Vec::new(),
        recorded_legal_bases: BTreeMap::new(),
        exclusions: Vec::new(),
        pending_capture_change: None,
        pending_profile_downgrade: None,
    });
}
