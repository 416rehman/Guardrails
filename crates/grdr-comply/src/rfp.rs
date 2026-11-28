// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Buyer RFP generator covering parity checklist T1 to T17 loaded from YAML (`docs/design/01`, `29` s.3).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::pack_loader::{
    load_yaml_checked, yaml_req_bool, yaml_req_seq, yaml_req_str, yaml_req_str_list,
};
use crate::registry::CapabilityRegistry;
use crate::{ComplyError, markdown_safe};

const EMBEDDED_RFP_PARITY_YAML: &str = include_str!("../data/rfp-parity.yaml");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RfpItemStatus {
    Met,
    PartiallyMet,
    Unmet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentTopology {
    Standalone,
    ServerAvailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerReadiness {
    Unavailable,
    Ready,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorCoverage {
    ReadOnlyPair,
    Complete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificationStatus {
    NoneHeld,
    Held,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParityItemSpec {
    pub id: String,
    pub title: String,
    pub mandatory: bool,
    pub capabilities: Vec<String>,
    pub notes: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformReadiness {
    pub release_version: String,
    pub os_assurance_summary: String,
    pub topology: DeploymentTopology,
    pub broker: BrokerReadiness,
    pub connectors: ConnectorCoverage,
    pub certification: CertificationStatus,
    pub acceptance_tests_green: BTreeMap<String, bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RfpItemReport {
    pub id: String,
    pub title: String,
    pub mandatory: bool,
    pub status: RfpItemStatus,
    pub capabilities: Vec<String>,
    pub requires: Vec<String>,
    pub test_green: bool,
    pub gap_note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RfpParityReport {
    pub release_version: String,
    pub os_assurance_summary: String,
    pub release_gate_passed: bool,
    pub failing_gate_items: Vec<String>,
    pub items: Vec<RfpItemReport>,
}

pub fn load_parity_items_yaml(raw: &str) -> Result<Vec<ParityItemSpec>, ComplyError> {
    let doc = load_yaml_checked(raw, "rfp-parity.yaml")?;
    let seq = yaml_req_seq(&doc, "items", "rfp-parity.yaml")?;
    let mut items = Vec::with_capacity(seq.len());
    for node in seq {
        let id = yaml_req_str(node, "id", "rfp item")?.to_owned();
        items.push(ParityItemSpec {
            id: id.clone(),
            title: yaml_req_str(node, "title", &id)?.to_owned(),
            mandatory: yaml_req_bool(node, "mandatory", &id)?,
            capabilities: yaml_req_str_list(node, "capabilities", &id)?,
            notes: yaml_req_str(node, "notes", &id)?.to_owned(),
        });
    }
    if items.is_empty() {
        return Err(ComplyError::VerificationFailed {
            detail: "rfp-parity.yaml contains zero items".into(),
        });
    }
    Ok(items)
}

pub fn generate_rfp_response(
    readiness: &PlatformReadiness,
) -> Result<RfpParityReport, ComplyError> {
    let items = load_parity_items_yaml(EMBEDDED_RFP_PARITY_YAML)?;
    let registry = crate::registry::try_default_registry()?;
    Ok(generate_rfp_response_with_items(
        &registry, readiness, &items,
    ))
}

pub fn generate_rfp_response_with_registry(
    registry: &CapabilityRegistry,
    readiness: &PlatformReadiness,
    extra_partner_yaml: Option<&str>,
) -> Result<RfpParityReport, ComplyError> {
    let mut items = load_parity_items_yaml(EMBEDDED_RFP_PARITY_YAML)?;
    if let Some(extra) = extra_partner_yaml {
        items.extend(load_parity_items_yaml(extra)?);
    }
    Ok(generate_rfp_response_with_items(
        registry, readiness, &items,
    ))
}

pub fn render_rfp_markdown(report: &RfpParityReport) -> String {
    let mut out = format!(
        "# Guardrails ADR Buyer RFP Parity Report ({})\n\nAssurance reachability: {}\nRelease gate: {}\n\n| Item | Status | Mandatory | Requires | Test | Notes |\n|---|---|---|---|---|---|\n",
        markdown_safe(&report.release_version),
        markdown_safe(&report.os_assurance_summary),
        if report.release_gate_passed {
            "PASS"
        } else {
            "FAIL"
        }
    );
    for item in &report.items {
        let status = match item.status {
            RfpItemStatus::Met => "Met",
            RfpItemStatus::PartiallyMet => "Partially met",
            RfpItemStatus::Unmet => "Unmet",
        };
        let note = item.gap_note.as_deref().unwrap_or("Full parity");
        let reqs = if item.requires.is_empty() {
            "none".to_owned()
        } else {
            item.requires.join(", ")
        };
        out.push_str(&format!(
            "| {} ({}) | {} | {} | {} | {} | {} |\n",
            markdown_safe(&item.id),
            markdown_safe(&item.title),
            status,
            item.mandatory,
            markdown_safe(&reqs),
            if item.test_green { "green" } else { "red" },
            markdown_safe(note)
        ));
    }
    out
}

fn generate_rfp_response_with_items(
    registry: &CapabilityRegistry,
    readiness: &PlatformReadiness,
    specs: &[ParityItemSpec],
) -> RfpParityReport {
    if specs.is_empty() {
        return RfpParityReport {
            release_version: readiness.release_version.clone(),
            os_assurance_summary: readiness.os_assurance_summary.clone(),
            release_gate_passed: false,
            failing_gate_items: vec!["T1..T17".into()],
            items: Vec::new(),
        };
    }

    let mut items = Vec::with_capacity(specs.len());
    let mut failing_gate_items = Vec::new();

    for spec in specs {
        let test_green = readiness
            .acceptance_tests_green
            .get(&spec.id)
            .copied()
            .unwrap_or(false);

        let (status, gap_note) = evaluate_item_status(&spec.id, &spec.notes, readiness);
        let mut requires = Vec::new();
        for cap_id in &spec.capabilities {
            if let Some(cap) = registry.capabilities.get(cap_id) {
                for req in &cap.requires {
                    if !requires.contains(req) {
                        requires.push(req.clone());
                    }
                }
            }
        }

        if spec.mandatory && status == RfpItemStatus::Met && !test_green {
            failing_gate_items.push(spec.id.clone());
        }

        items.push(RfpItemReport {
            id: spec.id.clone(),
            title: spec.title.clone(),
            mandatory: spec.mandatory,
            status,
            capabilities: spec.capabilities.clone(),
            requires,
            test_green,
            gap_note,
        });
    }

    RfpParityReport {
        release_version: readiness.release_version.clone(),
        os_assurance_summary: readiness.os_assurance_summary.clone(),
        release_gate_passed: failing_gate_items.is_empty(),
        failing_gate_items,
        items,
    }
}

fn evaluate_item_status(
    id: &str,
    default_note: &str,
    readiness: &PlatformReadiness,
) -> (RfpItemStatus, Option<String>) {
    match id {
        "T6" if readiness.connectors == ConnectorCoverage::ReadOnlyPair => {
            (RfpItemStatus::PartiallyMet, Some(default_note.to_owned()))
        }
        "T9" if readiness.topology == DeploymentTopology::Standalone => (
            RfpItemStatus::Unmet,
            Some("Gateway verdict API requires server decide target".into()),
        ),
        "T12" | "T16" if readiness.broker == BrokerReadiness::Unavailable => {
            (RfpItemStatus::PartiallyMet, Some(default_note.to_owned()))
        }
        "T17" if readiness.certification == CertificationStatus::NoneHeld => {
            (RfpItemStatus::PartiallyMet, Some(default_note.to_owned()))
        }
        _ => (RfpItemStatus::Met, None),
    }
}
