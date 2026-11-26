// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use serde::{Deserialize, Serialize};

use crate::error::ProtoError;
use crate::strict_json::{MAX_JSON_DEPTH, MAX_LLM_REQUEST_BYTES, parse_strict_json_str};

const DEFAULT_PROVIDERS_MANIFEST_JSON: &str = include_str!("../schemas/providers.json");
const MAX_MANIFEST_PROVIDERS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderFamily {
    AnthropicMessages,
    #[serde(rename = "openai_chat")]
    OpenAiChat,
    #[serde(rename = "openai_responses")]
    OpenAiResponses,
    GoogleGemini,
    AwsBedrock,
    #[serde(rename = "openai_realtime")]
    OpenAiRealtime,
    A2a,
    Generic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaLimitsSpec {
    pub max_request_bytes: usize,
    pub max_sse_event_bytes: usize,
    pub max_json_depth: usize,
    pub max_tool_calls: usize,
    pub max_decompression_ratio: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderSchemaSpec {
    pub id: String,
    pub family: ProviderFamily,
    pub host_patterns: Vec<String>,
    pub path_prefixes: Vec<String>,
    pub model_keys: Vec<String>,
    pub stream_keys: Vec<String>,
    pub system_keys: Vec<String>,
    pub message_array_keys: Vec<String>,
    pub tool_array_keys: Vec<String>,
    pub tool_name_paths: Vec<String>,
    pub response_stop_keys: Vec<String>,
    pub response_usage_keys: Vec<String>,
    pub requires_sigv4: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ProviderManifestFile {
    schema_version: u32,
    limits: SchemaLimitsSpec,
    providers: Vec<ProviderSchemaSpec>,
}

#[derive(Debug, Clone)]
pub struct ProviderSchemaRegistry {
    limits: SchemaLimitsSpec,
    providers: Vec<ProviderSchemaSpec>,
}

impl ProviderSchemaRegistry {
    pub fn default_embedded() -> Result<Self, ProtoError> {
        Self::from_manifest_json(DEFAULT_PROVIDERS_MANIFEST_JSON)
    }

    pub fn from_manifest_json(raw: &str) -> Result<Self, ProtoError> {
        let value = parse_strict_json_str(raw, MAX_LLM_REQUEST_BYTES, MAX_JSON_DEPTH)?;
        let parsed: ProviderManifestFile =
            serde_json::from_value(value).map_err(|e| ProtoError::Parse(e.to_string()))?;
        if parsed.schema_version != 1 {
            return Err(ProtoError::Parse(
                "unsupported provider schema_version".to_string(),
            ));
        }
        if parsed.providers.is_empty() || parsed.providers.len() > MAX_MANIFEST_PROVIDERS {
            return Err(ProtoError::Parse(
                "provider manifest count out of bounds".to_string(),
            ));
        }
        Ok(Self {
            limits: parsed.limits,
            providers: parsed.providers,
        })
    }

    #[must_use]
    pub fn limits(&self) -> &SchemaLimitsSpec {
        &self.limits
    }

    #[must_use]
    pub fn providers(&self) -> &[ProviderSchemaSpec] {
        &self.providers
    }

    #[must_use]
    pub fn find_by_family(&self, family: ProviderFamily) -> Option<&ProviderSchemaSpec> {
        self.providers.iter().find(|p| p.family == family)
    }

    #[must_use]
    pub fn match_request(
        &self,
        host: &str,
        path: &str,
        body_obj: Option<&serde_json::Map<String, serde_json::Value>>,
    ) -> Option<&ProviderSchemaSpec> {
        let lower_host = host.trim().to_ascii_lowercase();
        let clean_path = path.split('?').next().unwrap_or(path);
        for spec in &self.providers {
            if path_matches_spec(clean_path, spec)
                && (spec.host_patterns.is_empty() || host_matches_spec(&lower_host, spec))
            {
                return Some(spec);
            }
        }
        for spec in &self.providers {
            if !spec.host_patterns.is_empty() && host_matches_spec(&lower_host, spec) {
                return Some(spec);
            }
        }
        let obj = body_obj?;
        self.providers
            .iter()
            .find(|&spec| spec_body_matches(obj, spec))
    }
}

fn host_matches_spec(lower_host: &str, spec: &ProviderSchemaSpec) -> bool {
    let bare = lower_host.split(':').next().unwrap_or(lower_host);
    spec.host_patterns.iter().any(|pat| {
        let p = pat.to_ascii_lowercase();
        if p.starts_with('.') || p.starts_with('-') {
            bare.ends_with(&p)
        } else {
            bare == p
        }
    })
}

fn path_matches_spec(clean_path: &str, spec: &ProviderSchemaSpec) -> bool {
    spec.path_prefixes.iter().any(|prefix| {
        if prefix.starts_with("/v1/models/") {
            clean_path.contains(":generateContent") || clean_path.contains(":streamGenerateContent")
        } else {
            clean_path.starts_with(prefix)
        }
    })
}

fn spec_body_matches(
    obj: &serde_json::Map<String, serde_json::Value>,
    spec: &ProviderSchemaSpec,
) -> bool {
    match spec.family {
        ProviderFamily::OpenAiResponses => obj.contains_key("input") && obj.contains_key("model"),
        ProviderFamily::GoogleGemini => obj.contains_key("contents"),
        ProviderFamily::AwsBedrock => {
            obj.contains_key("toolConfig") || obj.contains_key("anthropic_version")
        }
        ProviderFamily::AnthropicMessages => {
            obj.contains_key("system") && obj.contains_key("messages")
        }
        ProviderFamily::OpenAiChat => obj.contains_key("messages"),
        ProviderFamily::OpenAiRealtime => obj.contains_key("session") || obj.contains_key("type"),
        ProviderFamily::A2a => obj.contains_key("jsonrpc") && obj.contains_key("method"),
        ProviderFamily::Generic => false,
    }
}
