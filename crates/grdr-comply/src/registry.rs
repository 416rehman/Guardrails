// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Compliance capability registry, framework catalogues, and crosswalks (`docs/design/29` s.1).

use std::collections::BTreeMap;
use std::path::Path;

use grdr_model::AssuranceLevel;
use serde::{Deserialize, Serialize};

use crate::ComplyError;
use crate::evidence::EvidenceQuery;
use crate::pack_loader::{
    default_pack_digest_sha256, default_pack_evidence_queries, load_compliance_pack_from_dir,
    load_embedded_compliance_pack,
};

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

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityRegistry {
    pub capabilities: BTreeMap<String, CapabilityRecord>,
    pub frameworks: BTreeMap<String, FrameworkCatalogue>,
    pub crosswalks: Vec<CrosswalkEntry>,
}

pub fn try_default_registry() -> Result<CapabilityRegistry, ComplyError> {
    load_embedded_compliance_pack().map(|pack| pack.registry)
}

pub fn default_registry() -> Result<CapabilityRegistry, ComplyError> {
    try_default_registry()
}

pub fn load_registry_from_dir(
    pack_dir: &Path,
    trust_roots_path: Option<&Path>,
) -> Result<CapabilityRegistry, ComplyError> {
    load_compliance_pack_from_dir(pack_dir, trust_roots_path).map(|pack| pack.registry)
}

pub fn default_evidence_queries() -> Result<Vec<EvidenceQuery>, ComplyError> {
    default_pack_evidence_queries()
}

pub fn default_compliance_pack_digest() -> Result<String, ComplyError> {
    default_pack_digest_sha256()
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
