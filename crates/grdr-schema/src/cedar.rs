// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Cedar 4.x schemas (`Grdr`, `Grdr::Console`, `Grdr::Operator`).

use std::fmt;

use cedar_policy::{PolicySet, Schema, ValidationMode, Validator};

use crate::codes::{
    CODE_SCHEMA_CEDAR_POLICY_PARSE, CODE_SCHEMA_CEDAR_POLICY_VALIDATION,
    CODE_SCHEMA_CEDAR_SCHEMA_PARSE,
};

pub const SCHEMA_VERSION: &str = "v1alpha1";

pub const V1ALPHA1: &str = include_str!("../../../contracts/cedar/v1alpha1.cedarschema");
pub const CONSOLE_V1ALPHA1: &str =
    include_str!("../../../contracts/cedar/console_v1alpha1.cedarschema");
pub const OPERATOR_V1ALPHA1: &str =
    include_str!("../../../contracts/cedar/operator_v1alpha1.cedarschema");

pub const CANONICAL_ACTIONS: &[&str] = &[
    "exec",
    "file.read",
    "file.write",
    "file.delete",
    "net.connect",
    "net.request",
    "llm.request",
    "mcp.connect",
    "mcp.call",
    "cred.use",
    "agent.spawn",
    "config.change",
    "elevate",
    "ui.act",
    "data.flow",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CedarPlane {
    Runtime,
    Console,
    Operator,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CedarSchemaError {
    SchemaParse { plane: CedarPlane, detail: String },
    PolicyParse { detail: String },
    PolicyValidation { detail: String },
}

impl CedarSchemaError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::SchemaParse { .. } => CODE_SCHEMA_CEDAR_SCHEMA_PARSE,
            Self::PolicyParse { .. } => CODE_SCHEMA_CEDAR_POLICY_PARSE,
            Self::PolicyValidation { .. } => CODE_SCHEMA_CEDAR_POLICY_VALIDATION,
        }
    }
}

impl fmt::Display for CedarSchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SchemaParse { plane, detail } => write!(
                f,
                "{}: failed to load Cedar {plane:?} schema: {detail}",
                self.code()
            ),
            Self::PolicyParse { detail } => {
                write!(
                    f,
                    "{}: failed to parse Cedar policy set: {detail}",
                    self.code()
                )
            }
            Self::PolicyValidation { detail } => write!(
                f,
                "{}: Cedar policy failed strict schema validation: {detail}",
                self.code()
            ),
        }
    }
}

impl std::error::Error for CedarSchemaError {}

pub fn schema_source(plane: CedarPlane) -> &'static str {
    match plane {
        CedarPlane::Runtime => V1ALPHA1,
        CedarPlane::Console => CONSOLE_V1ALPHA1,
        CedarPlane::Operator => OPERATOR_V1ALPHA1,
    }
}

pub fn parse_schema(plane: CedarPlane) -> Result<Schema, CedarSchemaError> {
    let (schema, _warnings) =
        Schema::from_cedarschema_str(schema_source(plane)).map_err(|err| {
            CedarSchemaError::SchemaParse {
                plane,
                detail: err.to_string(),
            }
        })?;
    Ok(schema)
}

pub fn validate_policy_source(
    plane: CedarPlane,
    source: &str,
) -> Result<PolicySet, CedarSchemaError> {
    let schema = parse_schema(plane)?;
    let policy_set = source
        .parse::<PolicySet>()
        .map_err(|err| CedarSchemaError::PolicyParse {
            detail: err.to_string(),
        })?;
    let validator = Validator::new(schema);
    let result = validator.validate(&policy_set, ValidationMode::Strict);
    if !result.validation_passed() {
        let messages: Vec<String> = result
            .validation_errors()
            .map(ToString::to_string)
            .collect();
        return Err(CedarSchemaError::PolicyValidation {
            detail: messages.join("; "),
        });
    }
    Ok(policy_set)
}

pub fn resource_entity_type_for_action(action_name: &str) -> &'static str {
    match action_name {
        "exec" => "Grdr::Executable",
        "file.read" | "file.write" | "file.delete" => "Grdr::Path",
        "net.connect" | "net.request" => "Grdr::Endpoint",
        "llm.request" => "Grdr::ModelEndpoint",
        "mcp.connect" => "Grdr::McpServer",
        "mcp.call" => "Grdr::McpTool",
        "cred.use" => "Grdr::Credential",
        "agent.spawn" => "Grdr::Agent",
        "config.change" => "Grdr::ConfigTarget",
        "elevate" => "Grdr::ElevationRoute",
        "ui.act" => "Grdr::UiTarget",
        "data.flow" => "Grdr::Sink",
        _ => "Grdr::Executable",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_canonical_cedar_schemas_parse_cleanly() {
        for plane in [
            CedarPlane::Runtime,
            CedarPlane::Console,
            CedarPlane::Operator,
        ] {
            let schema = parse_schema(plane).expect("canonical Cedar schema must parse");
            if plane == CedarPlane::Runtime {
                let actions: Vec<String> = schema
                    .actions()
                    .map(|a| a.id().escaped().to_string())
                    .collect();
                for expected in CANONICAL_ACTIONS {
                    assert!(
                        actions.iter().any(|a| a == expected),
                        "missing canonical action {expected}"
                    );
                }
                for group in ["any", "file", "net", "mcp"] {
                    assert!(
                        actions.iter().any(|a| a == group),
                        "missing action group {group}"
                    );
                }
            }
        }
    }

    #[test]
    fn console_and_operator_policies_validate_strictly() {
        let console_policy = r#"
            permit (
                principal is Grdr::Console::User,
                action == Grdr::Console::Action::"policy.approve",
                resource is Grdr::Console::PolicyRule
            )
            when { context.roles.contains("policy-approver") && context.person_proof_age_s <= 300 };
        "#;
        assert!(validate_policy_source(CedarPlane::Console, console_policy).is_ok());

        let operator_policy = r#"
            permit (
                principal is Grdr::Operator::OperatorUser,
                action == Grdr::Operator::Action::"key.rotate",
                resource is Grdr::Operator::SigningKey
            )
            when { context.roles.contains("operator-admin") && context.person_proof_age_s <= 300 };
        "#;
        assert!(validate_policy_source(CedarPlane::Operator, operator_policy).is_ok());
    }
}
