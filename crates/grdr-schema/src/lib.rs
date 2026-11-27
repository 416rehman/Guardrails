// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

pub mod brand;
pub mod capture;
pub mod cedar;
pub mod limits;
mod limits_parse;
mod limits_types;
mod limits_validate;
pub mod registry;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub use brand::{
    AuditLane, BrandDisplayStrings, BrandIdentity, CommitmentClass, ContentKind, DataClass,
    FiveWayCommitments, brand_identity, is_valid_brand_domain, is_valid_brand_identity,
    is_valid_brand_namespace, load_embedded_brand_display, parse_brand_display_toml,
    parse_brand_identity_toml, schema_base_uri,
};

pub const DRAFT_2020_12: &str = "https://json-schema.org/draft/2020-12/schema";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaKind {
    PolicyPack,
    DecisionReceipt,
    ActionAttempt,
    OcsfEvent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JsonType {
    Object,
    Array,
    String,
    Integer,
    Boolean,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaProperty {
    pub name: String,
    pub kind: JsonType,
    pub required: bool,
    pub non_empty: bool,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaDocument {
    pub schema_uri: String,
    pub id: String,
    pub title: String,
    pub version: String,
    pub properties: Vec<SchemaProperty>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SchemaValidationError {
    #[error("GRDR-SCHEMA-0001: payload root must be a JSON object")]
    NotObject,
    #[error("GRDR-SCHEMA-0002: missing required field `{field}`")]
    MissingRequiredField { field: String },
    #[error("GRDR-SCHEMA-0003: field `{field}` must have JSON type {expected}")]
    TypeMismatch {
        field: String,
        expected: &'static str,
    },
    #[error("GRDR-SCHEMA-0004: field `{field}` cannot be an empty string")]
    EmptyRequiredString { field: String },
}

impl JsonType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Object => "object",
            Self::Array => "array",
            Self::String => "string",
            Self::Integer => "integer",
            Self::Boolean => "boolean",
        }
    }

    pub fn matches(self, val: &Value) -> bool {
        match self {
            Self::Object => val.is_object(),
            Self::Array => val.is_array(),
            Self::String => val.is_string(),
            Self::Integer => val.is_i64() || val.is_u64(),
            Self::Boolean => val.is_boolean(),
        }
    }
}

impl SchemaProperty {
    fn req(name: &str, kind: JsonType, non_empty: bool, description: &str) -> Self {
        Self {
            name: name.into(),
            kind,
            required: true,
            non_empty,
            description: description.into(),
        }
    }

    fn opt(name: &str, kind: JsonType, description: &str) -> Self {
        Self {
            name: name.into(),
            kind,
            required: false,
            non_empty: false,
            description: description.into(),
        }
    }
}

pub fn schema_for(kind: SchemaKind) -> SchemaDocument {
    match kind {
        SchemaKind::PolicyPack => policy_pack_schema(),
        SchemaKind::DecisionReceipt => decision_receipt_schema(),
        SchemaKind::ActionAttempt => action_attempt_schema(),
        SchemaKind::OcsfEvent => ocsf_event_schema(),
    }
}

fn schema_doc_id(filename: &str) -> String {
    format!("{}/{filename}", schema_base_uri())
}

pub fn policy_pack_schema() -> SchemaDocument {
    SchemaDocument {
        schema_uri: DRAFT_2020_12.into(),
        id: schema_doc_id("policy-pack.json"),
        title: "PolicyPack".into(),
        version: "1.0.0".into(),
        properties: vec![
            SchemaProperty::req("id", JsonType::String, true, "Unique pack identifier"),
            SchemaProperty::req("name", JsonType::String, true, "Human pack name"),
            SchemaProperty::req("description", JsonType::String, false, "Pack description"),
            SchemaProperty::req("version", JsonType::String, true, "Semantic pack version"),
            SchemaProperty::req("channel", JsonType::String, true, "Release channel"),
            SchemaProperty::req("rules", JsonType::Array, false, "Ordered policy rules"),
            SchemaProperty::opt("key_id", JsonType::String, "Signing key identifier"),
            SchemaProperty::opt("signature", JsonType::String, "Ed25519 signature"),
        ],
    }
}

pub fn decision_receipt_schema() -> SchemaDocument {
    SchemaDocument {
        schema_uri: DRAFT_2020_12.into(),
        id: schema_doc_id("decision-receipt.json"),
        title: "DecisionReceipt".into(),
        version: "1.0.0".into(),
        properties: vec![
            SchemaProperty::req("receipt_id", JsonType::String, true, "Unique receipt ID"),
            SchemaProperty::req("attempt_id", JsonType::String, true, "Evaluated attempt ID"),
            SchemaProperty::req("session_id", JsonType::String, true, "Agent session ID"),
            SchemaProperty::req("device_id", JsonType::String, true, "Endpoint device ID"),
            SchemaProperty::req("agent_name", JsonType::String, true, "Harness identifier"),
            SchemaProperty::req("action_class", JsonType::String, true, "Normalized action"),
            SchemaProperty::req("target", JsonType::String, false, "Attempt target resource"),
            SchemaProperty::req("verdict", JsonType::String, true, "Decision verdict"),
            SchemaProperty::req("receipt_digest", JsonType::String, true, "Integrity digest"),
            SchemaProperty::req("decided_at", JsonType::String, true, "RFC 3339 timestamp"),
        ],
    }
}

pub fn action_attempt_schema() -> SchemaDocument {
    SchemaDocument {
        schema_uri: DRAFT_2020_12.into(),
        id: schema_doc_id("action-attempt.json"),
        title: "ActionAttempt".into(),
        version: "1.0.0".into(),
        properties: vec![
            SchemaProperty::req("id", JsonType::String, true, "Attempt ID"),
            SchemaProperty::req("session_id", JsonType::String, true, "Session identifier"),
            SchemaProperty::req("device_id", JsonType::String, true, "Device identifier"),
            SchemaProperty::req("device_name", JsonType::String, true, "Device hostname"),
            SchemaProperty::req("agent_name", JsonType::String, true, "Agent harness name"),
            SchemaProperty::req("action_class", JsonType::String, true, "Action taxonomy"),
            SchemaProperty::req("control_point", JsonType::String, true, "Enforcement point"),
            SchemaProperty::req("target", JsonType::String, false, "Action target"),
            SchemaProperty::req("timestamp", JsonType::String, true, "RFC 3339 event time"),
        ],
    }
}

pub fn ocsf_event_schema() -> SchemaDocument {
    SchemaDocument {
        schema_uri: DRAFT_2020_12.into(),
        id: schema_doc_id("ocsf-1.9-event.json"),
        title: "OcsfEvent".into(),
        version: "1.9.0".into(),
        properties: vec![
            SchemaProperty::req("class_uid", JsonType::Integer, false, "OCSF class UID"),
            SchemaProperty::req(
                "category_uid",
                JsonType::Integer,
                false,
                "OCSF category UID",
            ),
            SchemaProperty::req("activity_id", JsonType::Integer, false, "OCSF activity ID"),
            SchemaProperty::req("type_uid", JsonType::Integer, false, "OCSF type UID"),
            SchemaProperty::req("time", JsonType::Integer, false, "Epoch milliseconds"),
            SchemaProperty::req("severity_id", JsonType::Integer, false, "OCSF severity ID"),
            SchemaProperty::req("metadata", JsonType::Object, false, "OCSF metadata object"),
            SchemaProperty::req("device", JsonType::Object, false, "OCSF device object"),
            SchemaProperty::req("resources", JsonType::Array, false, "Affected resources"),
        ],
    }
}

pub fn to_json_schema(doc: &SchemaDocument) -> Value {
    let mut required = Vec::new();
    let mut props: BTreeMap<String, Value> = BTreeMap::new();

    for prop in &doc.properties {
        if prop.required {
            required.push(Value::String(prop.name.clone()));
        }
        let mut field_obj = Map::new();
        field_obj.insert("type".into(), Value::String(prop.kind.as_str().into()));
        field_obj.insert(
            "description".into(),
            Value::String(prop.description.clone()),
        );
        if prop.kind == JsonType::String && prop.non_empty {
            field_obj.insert("minLength".into(), Value::from(1));
        }
        props.insert(prop.name.clone(), Value::Object(field_obj));
    }

    let props_map: Map<String, Value> = props.into_iter().collect();

    let mut root = Map::new();
    root.insert("$schema".into(), Value::String(doc.schema_uri.clone()));
    root.insert("$id".into(), Value::String(doc.id.clone()));
    root.insert("title".into(), Value::String(doc.title.clone()));
    root.insert("version".into(), Value::String(doc.version.clone()));
    root.insert("type".into(), Value::String("object".into()));
    root.insert("required".into(), Value::Array(required));
    root.insert("properties".into(), Value::Object(props_map));
    Value::Object(root)
}

pub fn validate_json(
    doc: &SchemaDocument,
    value: &Value,
) -> Result<(), Vec<SchemaValidationError>> {
    let Some(obj) = value.as_object() else {
        return Err(vec![SchemaValidationError::NotObject]);
    };

    let mut errors = Vec::new();
    for prop in &doc.properties {
        match obj.get(&prop.name) {
            None | Some(Value::Null) => {
                if prop.required {
                    errors.push(SchemaValidationError::MissingRequiredField {
                        field: prop.name.clone(),
                    });
                }
            }
            Some(field_val) => {
                if !prop.kind.matches(field_val) {
                    errors.push(SchemaValidationError::TypeMismatch {
                        field: prop.name.clone(),
                        expected: prop.kind.as_str(),
                    });
                } else if prop.non_empty
                    && let Some(raw) = field_val.as_str()
                    && raw.trim().is_empty()
                {
                    errors.push(SchemaValidationError::EmptyRequiredString {
                        field: prop.name.clone(),
                    });
                }
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn generates_deterministic_json_schemas_and_validates_ocsf_and_core_payloads() {
        let pack_schema = schema_for(SchemaKind::PolicyPack);
        let rendered_a = serde_json::to_string(&to_json_schema(&pack_schema)).unwrap();
        let rendered_b = serde_json::to_string(&to_json_schema(&pack_schema)).unwrap();
        assert_eq!(rendered_a, rendered_b);

        let valid_pack = json!({
            "id": "pack-essentials-slice0",
            "name": "Essentials",
            "description": "Baseline policy",
            "version": "1.0.0",
            "channel": "stable",
            "rules": [],
            "key_id": null
        });
        assert!(validate_json(&pack_schema, &valid_pack).is_ok());

        let ocsf_schema = schema_for(SchemaKind::OcsfEvent);
        let valid_ocsf = json!({
            "class_uid": 6003,
            "category_uid": 6,
            "activity_id": 1,
            "type_uid": 600301,
            "time": 1700000000000i64,
            "severity_id": 4,
            "metadata": { "version": "1.9.0" },
            "device": { "uid": "dev-1" },
            "resources": []
        });
        assert!(validate_json(&ocsf_schema, &valid_ocsf).is_ok());

        let bad_receipt = json!({
            "receipt_id": "  ",
            "verdict": 123
        });
        let errs =
            validate_json(&schema_for(SchemaKind::DecisionReceipt), &bad_receipt).unwrap_err();
        assert!(errs.iter().any(|e| matches!(
            e,
            SchemaValidationError::EmptyRequiredString { field } if field == "receipt_id"
        )));
        assert!(errs.iter().any(|e| matches!(
            e,
            SchemaValidationError::TypeMismatch { field, .. } if field == "verdict"
        )));
        assert!(errs.iter().any(|e| matches!(
            e,
            SchemaValidationError::MissingRequiredField { field } if field == "attempt_id"
        )));

        let brand = brand_identity();
        assert_eq!(brand.namespace, "grdr");
        assert_eq!(brand.domain, "guardrailshq.com");
        assert_eq!(
            pack_schema.id,
            "https://guardrailshq.com/schemas/v1/policy-pack.json"
        );
        assert!(default_capture_level_is_metadata());

        assert!(DataClass::Structural < DataClass::Derived);
        assert!(DataClass::Derived < DataClass::Identifier);
        assert!(DataClass::Identifier < DataClass::Content);
        assert!(CommitmentClass::Structural < CommitmentClass::Derived);
        assert!(CommitmentClass::Derived < CommitmentClass::Identifier);
        assert!(CommitmentClass::Identifier < CommitmentClass::ContentArgument);
        assert!(CommitmentClass::ContentArgument < CommitmentClass::ContentBody);

        assert_eq!(AuditLane::parse("spine"), Some(AuditLane::Spine));
        assert_eq!(AuditLane::parse("evidence"), Some(AuditLane::Evidence));
        assert_eq!(AuditLane::parse(" spine"), None);
        assert_eq!(AuditLane::parse("spine "), None);
        assert_eq!(AuditLane::parse("event\n"), None);
        assert_eq!(AuditLane::parse("\tevent"), None);
        assert_ne!(AuditLane::Spine, AuditLane::Evidence);
        assert!(
            serde_json::from_str::<FiveWayCommitments>(
                r#"{"d_identifier":"sha256:00","d_structural":"sha256:00","d_derived":"sha256:00","d_argument":"sha256:00","d_body":"sha256:00","extra":1}"#,
            )
            .is_err()
        );

        let quoted =
            "[identity]\nnamespace = \"acme\" # tail\ndomain = \"acme.example#frag\" # inline\n";
        let parsed = parse_brand_identity_toml(quoted);
        assert_eq!(parsed.namespace, "acme");
        assert!(!is_valid_brand_domain(&parsed.domain));
    }

    fn default_capture_level_is_metadata() -> bool {
        capture::default_capture_level().name == "metadata"
    }
}
