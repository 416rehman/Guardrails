// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! P7 pack manifest and compliance evidence query execution-safety linter.

use grdr_model::IdentityMode;
use serde::{Deserialize, Serialize};

use crate::{LintDomain, LintError, LintFinding, LintSeverity};

const PRINCIPAL_FIELDS: &[&str] = &[
    "user_id",
    "user_display",
    "principal",
    "pseudonym",
    "pseudonym_id",
    "actor",
    "subject",
    "subject_ref",
];

const FORBIDDEN_EXECUTION_PATTERNS: &[&str] = &[
    "curl ",
    "wget ",
    "http://",
    "https://",
    "bash -c",
    "sh -c",
    "powershell -enc",
    "invoke-webrequest",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackDataClass {
    Public,
    Structural,
    Derived,
    Identifier,
    Content,
    Secret,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackKind {
    Policy,
    Detection,
    Compliance,
    Intel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldReadDecl {
    pub path: String,
    pub data_class: PackDataClass,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceQueryDecl {
    pub id: String,
    pub reads: Vec<FieldReadDecl>,
    pub max_class: PackDataClass,
    pub group_by: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackManifest {
    pub id: String,
    pub version: String,
    pub kind: PackKind,
    pub reads: Vec<FieldReadDecl>,
    #[serde(default)]
    pub commands: Vec<String>,
    #[serde(default)]
    pub executables: Vec<String>,
    #[serde(default)]
    pub urls: Vec<String>,
    #[serde(default)]
    pub env_vars_to_set: Vec<String>,
    #[serde(default)]
    pub mcp_servers_to_start: Vec<String>,
    #[serde(default)]
    pub evidence_queries: Vec<EvidenceQueryDecl>,
    #[serde(default)]
    pub rule_snippets: Vec<String>,
    #[serde(default)]
    pub per_person_scoring: bool,
}

pub fn lint_pack_manifest(
    manifest: &PackManifest,
    identity_mode: IdentityMode,
) -> Result<Vec<LintFinding>, LintError> {
    let mut findings = Vec::new();
    let label = format!("pack:{}", manifest.id);

    if !manifest.commands.is_empty() {
        findings.push(p7_finding(
            &label,
            "P7 violation: packs cannot declare shell commands to execute",
        ));
    }
    if !manifest.executables.is_empty() {
        findings.push(p7_finding(
            &label,
            "P7 violation: packs cannot declare executable paths to run",
        ));
    }
    if !manifest.urls.is_empty() {
        findings.push(p7_finding(
            &label,
            "P7 violation: packs cannot declare URLs to fetch",
        ));
    }
    if !manifest.env_vars_to_set.is_empty() {
        findings.push(p7_finding(
            &label,
            "P7 violation: packs cannot declare environment variables to set",
        ));
    }
    if !manifest.mcp_servers_to_start.is_empty() {
        findings.push(p7_finding(
            &label,
            "P7 violation: packs cannot declare MCP servers to start",
        ));
    }

    for snippet in &manifest.rule_snippets {
        let lower = snippet.to_ascii_lowercase();
        for pat in FORBIDDEN_EXECUTION_PATTERNS {
            if lower.contains(pat) {
                findings.push(p7_finding(
                    &label,
                    &format!("P7 violation: embedded snippet contains `{}`", pat.trim()),
                ));
            }
        }
    }

    if manifest.kind == PackKind::Compliance {
        for read in &manifest.reads {
            if read.data_class > PackDataClass::Derived {
                findings.push(p7_finding(
                    &label,
                    &format!(
                        "compliance pack read `{}` exceeds `derived` data class",
                        read.path
                    ),
                ));
            }
        }

        for query in &manifest.evidence_queries {
            if query.max_class > PackDataClass::Derived {
                findings.push(p7_finding(
                    &label,
                    &format!("evidence query `{}` max_class exceeds `derived`", query.id),
                ));
            }
            for read in &query.reads {
                if read.data_class > query.max_class {
                    findings.push(p7_finding(
                        &label,
                        &format!(
                            "evidence query `{}` read `{}` exceeds declared max_class",
                            query.id, read.path
                        ),
                    ));
                }
            }
            for grp in &query.group_by {
                let norm = grp.trim().to_ascii_lowercase();
                if PRINCIPAL_FIELDS.iter().any(|p| norm == *p) {
                    findings.push(p7_finding(
                        &label,
                        &format!(
                            "evidence query `{}` forbids principal group_by `{grp}`",
                            query.id
                        ),
                    ));
                }
            }
        }
    }

    if identity_mode == IdentityMode::Pseudonymous && manifest.per_person_scoring {
        findings.push(p7_finding(
            &label,
            "per-person risk scoring is rejected under `works-council` pseudonymous mode",
        ));
    }

    if findings.iter().any(|f| f.severity == LintSeverity::Error) {
        let detail = findings
            .iter()
            .map(|f| f.message.as_str())
            .collect::<Vec<_>>()
            .join("; ");
        return Err(LintError::PackViolation {
            pack_id: manifest.id.clone(),
            detail,
        });
    }

    Ok(findings)
}

fn p7_finding(target: &str, message: &str) -> LintFinding {
    LintFinding {
        code: "GRDR-LINT-0005".into(),
        domain: LintDomain::PackManifest,
        severity: LintSeverity::Error,
        target: target.into(),
        message: message.into(),
    }
}
