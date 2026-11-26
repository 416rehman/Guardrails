// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Tool descriptor pinning (`canonical_tool_digest`, `verify_tool_pin`) and poisoning detection.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use grdr_model::eval::sha256_hex;

use crate::McpProtoError;

const MAX_SCHEMA_RECURSION_DEPTH: usize = 64;

const OVERRIDE_PHRASES: &[&str] = &[
    "ignore previous instructions",
    "disregard prior instructions",
    "bypass policy",
    "do not inform the user",
    "do not tell the user",
    "system prompt override",
];
const EXFIL_PHRASES: &[&str] = &[
    "send ~/.ssh",
    "upload credentials",
    "exfiltrate",
    "pastebin",
    "webhook.site",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolDescriptor {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolPin {
    pub server_name: String,
    pub tool_name: String,
    pub digest_sha256: String,
    pub schema_version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PinVerification {
    Matched,
    Unpinned,
    Drifted { expected: String, actual: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolPoisoningSignal {
    HiddenUnicodeControl,
    PromptOverrideDirective,
    ExfiltrationInstruction,
    HiddenXmlTag,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolPoisoningFinding {
    pub tool_name: String,
    pub signals: Vec<ToolPoisoningSignal>,
    pub detail: String,
}

impl ToolPin {
    #[must_use]
    pub fn from_descriptor(server_name: impl Into<String>, desc: &ToolDescriptor) -> Self {
        Self {
            server_name: server_name.into(),
            tool_name: desc.name.clone(),
            digest_sha256: canonical_tool_digest(desc),
            schema_version: 1,
        }
    }
}

impl PinVerification {
    #[must_use]
    pub fn is_safe_to_execute(&self) -> bool {
        !matches!(self, Self::Drifted { .. })
    }
}

pub fn try_canonical_tool_digest(desc: &ToolDescriptor) -> Result<String, McpProtoError> {
    let canonical_schema = canonicalize_json(&desc.input_schema, 0)?;
    let doc = json!({
        "name": desc.name.trim(),
        "description": desc.description.trim(),
        "input_schema": canonical_schema,
    });
    let bytes = serde_json::to_vec(&doc).map_err(|e| {
        McpProtoError::InvalidFrame(format!("canonical schema serialize failed: {e}"))
    })?;
    Ok(sha256_hex(&bytes))
}

#[must_use]
pub fn canonical_tool_digest(desc: &ToolDescriptor) -> String {
    match try_canonical_tool_digest(desc) {
        Ok(hex) => hex,
        Err(_) => "err:schema-depth-or-serialization".to_owned(),
    }
}

#[must_use]
pub fn verify_tool_pin(desc: &ToolDescriptor, pin: Option<&ToolPin>) -> PinVerification {
    let Some(expected_pin) = pin else {
        return PinVerification::Unpinned;
    };
    let Ok(actual) = try_canonical_tool_digest(desc) else {
        return PinVerification::Drifted {
            expected: expected_pin.digest_sha256.clone(),
            actual: "err:schema-depth-or-serialization".to_owned(),
        };
    };
    if actual == expected_pin.digest_sha256 {
        PinVerification::Matched
    } else {
        PinVerification::Drifted {
            expected: expected_pin.digest_sha256.clone(),
            actual,
        }
    }
}

#[must_use]
pub fn detect_tool_poisoning(desc: &ToolDescriptor) -> Vec<ToolPoisoningFinding> {
    let mut texts = vec![desc.description.clone()];
    let depth_exceeded = collect_schema_strings(&desc.input_schema, 0, &mut texts).is_err();

    let mut signals = Vec::new();
    let mut details: Vec<&'static str> = Vec::new();

    if depth_exceeded {
        signals.push(ToolPoisoningSignal::HiddenXmlTag);
        details.push("input_schema exceeds maximum nesting depth bound");
    }

    for text in &texts {
        if has_hidden_unicode(text) && !signals.contains(&ToolPoisoningSignal::HiddenUnicodeControl)
        {
            signals.push(ToolPoisoningSignal::HiddenUnicodeControl);
            details.push("contains hidden zero-width or bidirectional control characters");
        }
        let lower = text.to_ascii_lowercase();
        if (lower.contains("<important>")
            || lower.contains("</important>")
            || lower.contains("<system>")
            || lower.contains("</system>"))
            && !signals.contains(&ToolPoisoningSignal::HiddenXmlTag)
        {
            signals.push(ToolPoisoningSignal::HiddenXmlTag);
            details.push("contains hidden prompt tag markup (<IMPORTANT> or <system>)");
        }
        if OVERRIDE_PHRASES.iter().any(|p| lower.contains(p))
            && !signals.contains(&ToolPoisoningSignal::PromptOverrideDirective)
        {
            signals.push(ToolPoisoningSignal::PromptOverrideDirective);
            details.push("contains instruction override directive");
        }
        if EXFIL_PHRASES.iter().any(|p| lower.contains(p))
            && !signals.contains(&ToolPoisoningSignal::ExfiltrationInstruction)
        {
            signals.push(ToolPoisoningSignal::ExfiltrationInstruction);
            details.push("contains suspicious credential or exfiltration instruction");
        }
    }

    if signals.is_empty() {
        Vec::new()
    } else {
        vec![ToolPoisoningFinding {
            tool_name: desc.name.clone(),
            signals,
            detail: details.join("; "),
        }]
    }
}

fn canonicalize_json(val: &Value, depth: usize) -> Result<Value, McpProtoError> {
    if depth > MAX_SCHEMA_RECURSION_DEPTH {
        return Err(McpProtoError::InvalidFrame(
            "MCP schema nesting exceeds maximum recursion depth".into(),
        ));
    }
    let next_depth = depth.saturating_add(1);
    match val {
        Value::Object(map) => {
            let mut sorted = BTreeMap::new();
            for (k, v) in map {
                sorted.insert(k.clone(), canonicalize_json(v, next_depth)?);
            }
            let out: serde_json::Map<String, Value> = sorted.into_iter().collect();
            Ok(Value::Object(out))
        }
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(canonicalize_json(item, next_depth)?);
            }
            Ok(Value::Array(out))
        }
        other => Ok(other.clone()),
    }
}

fn collect_schema_strings(
    val: &Value,
    depth: usize,
    out: &mut Vec<String>,
) -> Result<(), McpProtoError> {
    if depth > MAX_SCHEMA_RECURSION_DEPTH {
        return Err(McpProtoError::InvalidFrame(
            "MCP schema string traversal exceeded recursion bound".into(),
        ));
    }
    let next_depth = depth.saturating_add(1);
    match val {
        Value::String(s) => out.push(s.clone()),
        Value::Array(items) => {
            for item in items {
                collect_schema_strings(item, next_depth, out)?;
            }
        }
        Value::Object(map) => {
            for v in map.values() {
                collect_schema_strings(v, next_depth, out)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn has_hidden_unicode(s: &str) -> bool {
    s.chars().any(|ch| {
        matches!(
            ch,
            '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{206F}' | '\u{FEFF}'
        )
    })
}
