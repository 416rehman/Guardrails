// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Cedar 4.x schema and policy-mode linter (`docs/design/12`, `D-08`, `D-51`).

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use cedar_policy::{Effect, PolicySet, Schema, ValidationMode, Validator};
use grdr_model::IdentityMode;
use grdr_schema::cedar::{CANONICAL_ACTIONS, CedarPlane, parse_schema};

use crate::{LintDomain, LintError, LintFinding, LintSeverity};

const REQUIRED_RUNTIME_ENTITIES: &[&str] = &[
    "Organisation",
    "Group",
    "User",
    "Device",
    "Agent",
    "AgentInstance",
    "Session",
    "Process",
    "Executable",
    "Path",
    "Endpoint",
    "ModelEndpoint",
    "McpServer",
    "McpTool",
    "Credential",
    "ConfigTarget",
    "ElevationRoute",
    "UiTarget",
    "Sink",
];

pub fn lint_cedar_dir(dir: &Path, findings: &mut Vec<LintFinding>) -> Result<usize, LintError> {
    if !dir.is_dir() {
        return Err(LintError::Io {
            path: dir.display().to_string(),
            detail: "schema/cedar directory not found".into(),
        });
    }

    let mut count: usize = 0;
    let entries = fs::read_dir(dir).map_err(|e| LintError::Io {
        path: dir.display().to_string(),
        detail: e.to_string(),
    })?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| LintError::Io {
            path: dir.display().to_string(),
            detail: e.to_string(),
        })?;
        let p = entry.path();
        if p.extension().and_then(|s| s.to_str()) == Some("cedarschema") {
            paths.push(p);
        }
    }
    paths.sort();

    for path in &paths {
        count = count.saturating_add(1);
        let file_name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown.cedarschema");
        let content = fs::read_to_string(path).map_err(|e| LintError::Io {
            path: path.display().to_string(),
            detail: e.to_string(),
        })?;
        lint_cedar_schema_file(file_name, &content, findings);
    }
    Ok(count)
}

pub fn lint_cedar_schema_file(file_label: &str, source: &str, findings: &mut Vec<LintFinding>) {
    let schema = match Schema::from_cedarschema_str(source) {
        Ok((schema, _warnings)) => schema,
        Err(err) => {
            findings.push(LintFinding {
                code: "GRDR-LINT-0003".into(),
                domain: LintDomain::Cedar,
                severity: LintSeverity::Error,
                target: file_label.into(),
                message: format!("failed to parse Cedar schema: {err}"),
            });
            return;
        }
    };

    if file_label == "v1alpha1.cedarschema" {
        let action_names: BTreeSet<String> = schema
            .actions()
            .map(|a| a.id().escaped().to_string())
            .collect();
        for canonical in CANONICAL_ACTIONS {
            if !action_names.contains(*canonical) {
                findings.push(LintFinding {
                    code: "GRDR-LINT-0003".into(),
                    domain: LintDomain::Cedar,
                    severity: LintSeverity::Error,
                    target: file_label.into(),
                    message: format!("runtime schema missing canonical action `{canonical}`"),
                });
            }
        }
        for group in ["any", "file", "net", "mcp"] {
            if !action_names.contains(group) {
                findings.push(LintFinding {
                    code: "GRDR-LINT-0003".into(),
                    domain: LintDomain::Cedar,
                    severity: LintSeverity::Error,
                    target: file_label.into(),
                    message: format!("runtime schema missing action group `{group}`"),
                });
            }
        }
        let entities: BTreeSet<String> = schema
            .entity_types()
            .map(|e| e.basename().to_string())
            .collect();
        for req_entity in REQUIRED_RUNTIME_ENTITIES {
            if !entities.contains(*req_entity) {
                findings.push(LintFinding {
                    code: "GRDR-LINT-0003".into(),
                    domain: LintDomain::Cedar,
                    severity: LintSeverity::Error,
                    target: file_label.into(),
                    message: format!("runtime schema missing required entity `{req_entity}`"),
                });
            }
        }
        if !source.contains("type ScheduleContext = {};") {
            findings.push(LintFinding {
                code: "GRDR-LINT-0003".into(),
                domain: LintDomain::Cedar,
                severity: LintSeverity::Error,
                target: file_label.into(),
                message: "v1alpha1 runtime schema must keep `type ScheduleContext = {};`".into(),
            });
        }
    }
}

pub fn lint_cedar_policy_in_mode(
    pack_id: &str,
    cedar_source: &str,
    identity_mode: IdentityMode,
) -> Result<(), LintError> {
    let schema = parse_schema(CedarPlane::Runtime).map_err(|e| LintError::CedarViolation {
        file: pack_id.into(),
        detail: e.to_string(),
    })?;
    let policy_set = cedar_source
        .parse::<PolicySet>()
        .map_err(|e| LintError::CedarViolation {
            file: pack_id.into(),
            detail: e.to_string(),
        })?;

    if pack_id != "grdr.base" && policy_set.policies().any(|p| p.effect() == Effect::Permit) {
        return Err(LintError::CedarViolation {
            file: pack_id.into(),
            detail: "permit policies are forbidden outside `grdr.base`".into(),
        });
    }

    if identity_mode == IdentityMode::Pseudonymous && cedar_source.contains("Grdr::User") {
        return Err(LintError::CedarViolation {
            file: pack_id.into(),
            detail: "policies targeting `Grdr::User` are rejected under `works-council` pseudonymous mode".into(),
        });
    }

    let validator = Validator::new(schema);
    let result = validator.validate(&policy_set, ValidationMode::Strict);
    if !result.validation_passed() {
        let detail = result
            .validation_errors()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ");
        return Err(LintError::CedarViolation {
            file: pack_id.into(),
            detail,
        });
    }
    Ok(())
}
