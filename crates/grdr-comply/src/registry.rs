// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Compliance capability registry, framework catalogues, and crosswalks (`docs/design/29` s.1).

use std::collections::BTreeMap;

use grdr_model::AssuranceLevel;
use serde::{Deserialize, Serialize};

use crate::ComplyError;
use crate::catalog_capabilities::CAPABILITY_DEFS;
use crate::catalog_crosswalks_a::CROSSWALK_DEFS_CORE;
use crate::catalog_crosswalks_b::CROSSWALK_DEFS_GOVERNANCE;
use crate::catalog_frameworks::FRAMEWORK_SPECS;

pub type CapabilityId = String;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Responsibility {
    Product,
    Operator,
    Customer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CrosswalkRelation {
    Satisfies,
    Supports,
    EvidenceFor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ControlCoverageStatus {
    Addressed,
    NotAddressed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityRecord {
    pub id: CapabilityId,
    pub statement: String,
    pub decisions: Vec<String>,
    pub requires: Vec<String>,
    pub assurance_requirement: AssuranceLevel,
    pub evidence_query: String,
    pub responsibility: Responsibility,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlEntry {
    pub control_id: String,
    pub paraphrase: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameworkCatalogue {
    pub doc_id: String,
    pub title: String,
    pub version: String,
    pub controls: Vec<ControlEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrosswalkEntry {
    pub capability: CapabilityId,
    pub framework_id: String,
    pub control_id: String,
    pub relation: CrosswalkRelation,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlCoverageRow {
    pub control_id: String,
    pub paraphrase: String,
    pub coverage: ControlCoverageStatus,
    pub mapped_capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameworkCoverageReport {
    pub framework_id: String,
    pub display_title: String,
    pub total_controls: usize,
    pub addressed_controls: usize,
    pub rows: Vec<ControlCoverageRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityRegistry {
    pub capabilities: BTreeMap<String, CapabilityRecord>,
    pub frameworks: BTreeMap<String, FrameworkCatalogue>,
    pub crosswalks: Vec<CrosswalkEntry>,
}

pub fn default_registry() -> CapabilityRegistry {
    let mut capabilities = BTreeMap::new();
    for (id, stmt, decisions, requires, assurance, query, resp) in CAPABILITY_DEFS {
        capabilities.insert(
            (*id).to_owned(),
            CapabilityRecord {
                id: (*id).to_owned(),
                statement: (*stmt).to_owned(),
                decisions: decisions.iter().map(|d| (*d).to_owned()).collect(),
                requires: requires.iter().map(|r| (*r).to_owned()).collect(),
                assurance_requirement: *assurance,
                evidence_query: (*query).to_owned(),
                responsibility: *resp,
            },
        );
    }

    let mut frameworks = BTreeMap::new();
    for (doc_id, title, version, controls) in FRAMEWORK_SPECS {
        frameworks.insert(
            (*doc_id).to_owned(),
            FrameworkCatalogue {
                doc_id: (*doc_id).to_owned(),
                title: (*title).to_owned(),
                version: (*version).to_owned(),
                controls: controls
                    .iter()
                    .map(|(cid, para)| ControlEntry {
                        control_id: (*cid).to_owned(),
                        paraphrase: (*para).to_owned(),
                    })
                    .collect(),
            },
        );
    }

    let crosswalks = CROSSWALK_DEFS_CORE
        .iter()
        .chain(CROSSWALK_DEFS_GOVERNANCE.iter())
        .map(|(cap, fw, ctrl, rel, note)| CrosswalkEntry {
            capability: (*cap).to_owned(),
            framework_id: (*fw).to_owned(),
            control_id: (*ctrl).to_owned(),
            relation: *rel,
            note: (*note).to_owned(),
        })
        .collect();

    CapabilityRegistry {
        capabilities,
        frameworks,
        crosswalks,
    }
}

pub fn eo14434_display_label(raw_title: &str) -> String {
    raw_title.replace(" AI ", " SI ")
}

impl CapabilityRegistry {
    pub fn capability(&self, id: &str) -> Result<&CapabilityRecord, ComplyError> {
        self.capabilities
            .get(id)
            .ok_or_else(|| ComplyError::UnknownCapability(id.to_owned()))
    }

    pub fn controls_for_capability(&self, capability_id: &str) -> Vec<(String, String)> {
        self.crosswalks
            .iter()
            .filter(|c| c.capability == capability_id)
            .map(|c| (c.framework_id.clone(), c.control_id.clone()))
            .collect()
    }

    pub fn framework_coverage(
        &self,
        framework_id: &str,
    ) -> Result<FrameworkCoverageReport, ComplyError> {
        let fw = self
            .frameworks
            .get(framework_id)
            .ok_or_else(|| ComplyError::UnknownFramework(framework_id.to_owned()))?;

        let mut rows = Vec::with_capacity(fw.controls.len());
        let mut addressed_controls: usize = 0;

        for ctrl in &fw.controls {
            let mapped: Vec<String> = self
                .crosswalks
                .iter()
                .filter(|cw| cw.framework_id == framework_id && cw.control_id == ctrl.control_id)
                .map(|cw| cw.capability.clone())
                .collect();
            let coverage = if mapped.is_empty() {
                ControlCoverageStatus::NotAddressed
            } else {
                addressed_controls = addressed_controls.saturating_add(1);
                ControlCoverageStatus::Addressed
            };
            rows.push(ControlCoverageRow {
                control_id: ctrl.control_id.clone(),
                paraphrase: ctrl.paraphrase.clone(),
                coverage,
                mapped_capabilities: mapped,
            });
        }

        Ok(FrameworkCoverageReport {
            framework_id: fw.doc_id.clone(),
            display_title: eo14434_display_label(&fw.title),
            total_controls: fw.controls.len(),
            addressed_controls,
            rows,
        })
    }
}
