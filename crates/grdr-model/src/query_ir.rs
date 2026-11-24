// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::query_catalog::catalog_entities;
use crate::{CodedError, IdentityMode};

pub const CODE_QUERY_RESTRICTED_COLUMN: &str = "GRDR-QUERY-0001";
pub const CODE_QUERY_UNKNOWN_ENTITY: &str = "GRDR-QUERY-0002";
pub const DEFAULT_SAMPLE_LIMIT: u32 = 10;
pub const MAX_SAMPLE_LIMIT: u32 = 25;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaDataClass {
    Metadata,
    NamedIdentity,
    Content,
    Secret,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColumnDef {
    pub name: String,
    pub data_class: SchemaDataClass,
    pub description: String,
    pub sensitive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntitySchema {
    pub name: String,
    pub description: String,
    pub columns: Vec<ColumnDef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntitySummaryInfo {
    pub name: String,
    pub description: String,
    pub visible_columns: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryScope {
    pub allow_content_grant: bool,
    pub identity_mode: IdentityMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryRequest {
    pub entity: String,
    #[serde(default)]
    pub columns: Vec<String>,
    pub limit: Option<u32>,
    pub filter_text: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryPlanResult {
    pub entity: String,
    pub selected_columns: Vec<String>,
    pub hidden_columns_stripped: usize,
    pub effective_limit: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserIntentDescriptor {
    pub identity_mode: IdentityMode,
    pub correlation_guidance: String,
    pub safe_join_keys: Vec<String>,
    pub schema_hidden_fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum QueryCellValue {
    Text(String),
    Number(u64),
    Bool(bool),
    List(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuerySampleResponse {
    pub plan: QueryPlanResult,
    pub rows: Vec<BTreeMap<String, QueryCellValue>>,
    pub untrusted_warning: String,
}

pub fn is_column_visible(column: &ColumnDef, scope: &QueryScope) -> bool {
    match column.data_class {
        SchemaDataClass::Metadata => !column.sensitive || scope.allow_content_grant,
        SchemaDataClass::NamedIdentity => scope.identity_mode == IdentityMode::Named,
        SchemaDataClass::Content => scope.allow_content_grant,
        SchemaDataClass::Secret => false,
    }
}

pub fn describe_schema(scope: &QueryScope) -> Vec<EntitySchema> {
    catalog_entities()
        .into_iter()
        .map(|entity| EntitySchema {
            name: entity.name,
            description: entity.description,
            columns: entity
                .columns
                .into_iter()
                .filter(|col| is_column_visible(col, scope))
                .collect(),
        })
        .collect()
}

pub fn describe_entities(scope: &QueryScope) -> Vec<EntitySummaryInfo> {
    describe_schema(scope)
        .into_iter()
        .map(|entity| EntitySummaryInfo {
            name: entity.name,
            description: entity.description,
            visible_columns: entity.columns.into_iter().map(|c| c.name).collect(),
        })
        .collect()
}

pub fn user_intent(scope: &QueryScope) -> UserIntentDescriptor {
    let mut hidden = vec!["raw_secret".to_string()];
    if !scope.allow_content_grant {
        hidden.push("prompt_body".into());
    }
    match scope.identity_mode {
        IdentityMode::Named => UserIntentDescriptor {
            identity_mode: IdentityMode::Named,
            correlation_guidance: "Standard security attribution is active. Correlate users via `user_id` and `user_display` alongside `session_id` and `device_id`.".into(),
            safe_join_keys: vec![
                "user_id".into(),
                "session_id".into(),
                "device_id".into(),
            ],
            schema_hidden_fields: hidden,
        },
        IdentityMode::Pseudonymous => {
            hidden.push("user_id".into());
            hidden.push("user_display".into());
            hidden.push("display_name".into());
            hidden.push("user_email".into());
            UserIntentDescriptor {
                identity_mode: IdentityMode::Pseudonymous,
                correlation_guidance: "Works-council pseudonymous mode is active. Correlate events via `pseudonym_id`, `session_id`, and `device_id`; personal identifiers are hidden from schema.".into(),
                safe_join_keys: vec![
                    "pseudonym_id".into(),
                    "session_id".into(),
                    "device_id".into(),
                ],
                schema_hidden_fields: hidden,
            }
        }
    }
}

pub fn plan_query(req: &QueryRequest, scope: &QueryScope) -> Result<QueryPlanResult, CodedError> {
    let entity = catalog_entities()
        .into_iter()
        .find(|e| e.name == req.entity)
        .ok_or_else(|| {
            CodedError::new(
                CODE_QUERY_UNKNOWN_ENTITY,
                format!("Unknown query entity `{}`.", req.entity),
                "Call describe_entities first to discover available entities.",
            )
        })?;

    let visible: Vec<&ColumnDef> = entity
        .columns
        .iter()
        .filter(|col| is_column_visible(col, scope))
        .collect();
    let hidden_count = entity.columns.len().saturating_sub(visible.len());

    let selected_columns = if req.columns.is_empty() {
        visible.into_iter().map(|c| c.name.clone()).collect()
    } else {
        let mut chosen = Vec::new();
        for name in &req.columns {
            if !visible.iter().any(|c| &c.name == name) {
                return Err(CodedError::new(
                    CODE_QUERY_RESTRICTED_COLUMN,
                    format!(
                        "Column `{name}` on entity `{}` is hidden or unknown under the active privacy/content scope.",
                        req.entity
                    ),
                    "Call describe_schema to inspect permitted columns.",
                ));
            }
            if !chosen.contains(name) {
                chosen.push(name.clone());
            }
        }
        chosen
    };

    let effective_limit = req
        .limit
        .unwrap_or(DEFAULT_SAMPLE_LIMIT)
        .clamp(1, MAX_SAMPLE_LIMIT);

    Ok(QueryPlanResult {
        entity: entity.name,
        selected_columns,
        hidden_columns_stripped: hidden_count,
        effective_limit,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_hides_content_and_secrets_by_default() {
        let scope = QueryScope {
            allow_content_grant: false,
            identity_mode: IdentityMode::Named,
        };
        let schema = describe_schema(&scope);
        let attempts = schema
            .iter()
            .find(|e| e.name == "attempts")
            .expect("attempts");
        assert!(attempts.columns.iter().any(|c| c.name == "user_display"));
        assert!(!attempts.columns.iter().any(|c| c.name == "prompt_body"));
        assert!(!attempts.columns.iter().any(|c| c.name == "raw_secret"));
    }

    #[test]
    fn works_council_mode_hides_named_identity_columns() {
        let scope = QueryScope {
            allow_content_grant: false,
            identity_mode: IdentityMode::Pseudonymous,
        };
        let schema = describe_schema(&scope);
        let users = schema.iter().find(|e| e.name == "users").expect("users");
        assert!(users.columns.iter().any(|c| c.name == "pseudonym_id"));
        assert!(!users.columns.iter().any(|c| c.name == "user_email"));
        assert!(!users.columns.iter().any(|c| c.name == "display_name"));

        let rejected = plan_query(
            &QueryRequest {
                entity: "users".into(),
                columns: vec!["user_email".into()],
                limit: Some(5),
                filter_text: None,
            },
            &scope,
        );
        let err = rejected.expect_err("restricted column rejected");
        assert_eq!(err.code, CODE_QUERY_RESTRICTED_COLUMN);
    }

    #[test]
    fn plan_strips_hidden_columns_and_clamps_limit() {
        let scope = QueryScope {
            allow_content_grant: false,
            identity_mode: IdentityMode::Named,
        };
        let plan = plan_query(
            &QueryRequest {
                entity: "sessions".into(),
                columns: Vec::new(),
                limit: Some(250),
                filter_text: None,
            },
            &scope,
        )
        .expect("default projection succeeds");
        assert_eq!(plan.effective_limit, MAX_SAMPLE_LIMIT);
        assert_eq!(plan.hidden_columns_stripped, 1);
        assert!(!plan.selected_columns.iter().any(|c| c == "prompt_body"));
    }
}
