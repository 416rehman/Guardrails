// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Buyer RFP generator covering parity checklist T1 to T17 (`docs/design/01`, `29` s.3).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::markdown_safe;

const PARITY_ITEMS: &[(&str, &str, bool, &[&str], &str)] = &[
    (
        "T1",
        "Inventory of named agents, MCP servers, and extensions without manual registration",
        true,
        &["cap.inventory.agents"],
        "Windows Tier 1 requires S-04; Linux and macOS inventory runs locally",
    ),
    (
        "T2",
        "Pre-execution hook verdicts for Claude Code, Codex, and Cursor",
        true,
        &["cap.preexec.enforce"],
        "Claude Code, Codex, and Cursor covered via grdr-hook",
    ),
    (
        "T3",
        "MCP control point with per-tool allow and block",
        true,
        &["cap.supplychain.provenance", "cap.preexec.enforce"],
        "MCP broker mediates stdio and HTTP tool calls with manifest pins",
    ),
    (
        "T4",
        "Allow, Ask, Block plus Watch detect-only mode",
        true,
        &["cap.preexec.enforce"],
        "Cedar 4.x evaluator derives all five AARM verdicts",
    ),
    (
        "T5",
        "Session-centred audit with run reconstruction",
        true,
        &["cap.receipts.signed", "cap.attribution.graded"],
        "Local chain standalone; fleet timeline with server",
    ),
    (
        "T6",
        "SaaS connectors for Copilot Studio, Agentforce, Bedrock AgentCore, Claude Enterprise",
        true,
        &["cap.inventory.agents", "cap.export.siem"],
        "Read-only Anthropic/OpenAI connectors only; remaining SaaS connectors unmet without API integration",
    ),
    (
        "T7",
        "Coexistence beside a third-party EDR",
        true,
        &["cap.preexec.enforce", "cap.containment"],
        "Targeted build avoids driver/hook collisions",
    ),
    (
        "T8",
        "MITRE ATLAS mapping of detection content",
        true,
        &["cap.detect.respond"],
        "Detection content carries MITRE ATLAS tags",
    ),
    (
        "T9",
        "Verdict API for gateways (LiteLLM, Kong, AuthZEN)",
        true,
        &["cap.preexec.enforce"],
        "Requires server decide target for remote gateway callers",
    ),
    (
        "T10",
        "Principal and agent attribution in every record with five verdicts",
        true,
        &["cap.attribution.graded", "cap.preexec.enforce"],
        "Attribution grade 0-4 and actor_kind recorded per envelope",
    ),
    (
        "T11",
        "Recorded human approval for high-impact actions",
        true,
        &["cap.approval.graded"],
        "Graded STEP_UP approvals bound to exact action digest",
    ),
    (
        "T12",
        "Suspend an agent or group and revoke credentials",
        true,
        &["cap.detect.respond", "cap.identity.brokered"],
        "Session freeze works locally; credential revocation requires broker and token service",
    ),
    (
        "T13",
        "SIEM, SOAR, and ticketing export with stable identifiers",
        true,
        &["cap.export.siem"],
        "OCSF 1.9 / 1.3 and JSONL export contracts",
    ),
    (
        "T14",
        "Policy versioning, counterfactual dry-run replay, and rollback",
        true,
        &["cap.policy.change"],
        "Signed packs with 7-day replay and last-known-good rollback",
    ),
    (
        "T15",
        "Tamper-evident audit log retained 12 months or more",
        true,
        &["cap.receipts.signed", "cap.retention.policy"],
        "13-month default decision/audit retention with checkpoint chains",
    ),
    (
        "T16",
        "Static-secret findings and short-lived brokered tokens",
        true,
        &["cap.detect.respond", "cap.identity.brokered"],
        "Static-secret inventory works locally; short-lived tokens require credential broker",
    ),
    (
        "T17",
        "Compliance assurance: OSCAL library, exit export/deletion, certifications",
        true,
        &["cap.retention.policy", "cap.privacy.floor"],
        "Control library and export/deletion included; paid SOC 2 / ISO 27001 require sponsor or revenue",
    ),
];

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

pub fn generate_rfp_response(readiness: &PlatformReadiness) -> RfpParityReport {
    let mut items = Vec::with_capacity(PARITY_ITEMS.len());
    let mut failing_gate_items = Vec::new();

    for (id, title, mandatory, caps, default_note) in PARITY_ITEMS {
        let test_green = readiness
            .acceptance_tests_green
            .get(*id)
            .copied()
            .unwrap_or(false);

        let (status, gap_note) = evaluate_item_status(id, default_note, readiness);

        if *mandatory && status == RfpItemStatus::Met && !test_green {
            failing_gate_items.push((*id).to_owned());
        }

        items.push(RfpItemReport {
            id: (*id).to_owned(),
            title: (*title).to_owned(),
            mandatory: *mandatory,
            status,
            capabilities: caps.iter().map(|c| (*c).to_owned()).collect(),
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

pub fn render_rfp_markdown(report: &RfpParityReport) -> String {
    let mut out = format!(
        "# Guardrails ADR Buyer RFP Parity Report ({})\n\nAssurance reachability: {}\nRelease gate: {}\n\n| Item | Status | Mandatory | Test | Notes |\n|---|---|---|---|---|\n",
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
        out.push_str(&format!(
            "| {} ({}) | {} | {} | {} | {} |\n",
            markdown_safe(&item.id),
            markdown_safe(&item.title),
            status,
            item.mandatory,
            if item.test_green { "green" } else { "red" },
            markdown_safe(note)
        ));
    }
    out
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
