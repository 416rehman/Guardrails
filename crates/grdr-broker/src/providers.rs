// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Declarative `providers.d/` manifest loader and strict transport/schema validation (`docs/design/07`).

use std::collections::BTreeSet;
use std::path::Path;

use serde::{Deserialize, Serialize};

use grdr_core::detect::yaml::{YamlValue, parse_yaml};
use grdr_model::CodedError;
use grdr_ports::{LocalFsPort, RegularEntryKind};

use crate::providers_parse::{
    brk_manifest_err, is_valid_provider_id, parse_capabilities_map, parse_provider_kind,
    parse_string_list, req_nonempty_str, validate_provider_transport,
};

pub const PROVIDER_MANIFEST_SCHEMA: &str = "grdr.hook-broker.provider/v1alpha1";
const MAX_PROVIDER_MANIFEST_BYTES: u64 = 262_144;
pub const DEFAULT_PROVIDER_DEADLINE_MS: u64 = 150;
pub const MAX_PROVIDER_DEADLINE_MS: u64 = 1000;
const ALLOWED_MANIFEST_KEYS: &[&str] = &[
    "schema",
    "id",
    "kind",
    "enabled",
    "endpoint",
    "command",
    "args",
    "capabilities",
];
const ALLOWED_CAPABILITY_KEYS: &[&str] = &[
    "provider_id",
    "action_classes",
    "max_capture_level",
    "on_failure",
    "trust_model",
    "may_modify",
    "timeout_ms",
    "priority",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderKind {
    #[default]
    Native,
    CommandHook,
    Acs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProviderOnFailure {
    #[default]
    FailClosed,
    StepUp,
    Ignore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProviderCaptureCeiling {
    #[default]
    MetadataOnly,
    ArgumentPreview,
    FullMinimised,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProviderTrustModel {
    #[default]
    DeterministicRule,
    ModelBacked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCapabilities {
    #[serde(default)]
    pub provider_id: String,
    #[serde(default)]
    pub action_classes: BTreeSet<String>,
    #[serde(default)]
    pub max_capture_level: ProviderCaptureCeiling,
    #[serde(default)]
    pub on_failure: ProviderOnFailure,
    #[serde(default)]
    pub trust_model: ProviderTrustModel,
    #[serde(default)]
    pub may_modify: bool,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_priority")]
    pub priority: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderManifest {
    pub schema: String,
    pub id: String,
    #[serde(default)]
    pub kind: ProviderKind,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    pub capabilities: ProviderCapabilities,
}

const fn default_enabled() -> bool {
    true
}

const fn default_timeout_ms() -> u64 {
    DEFAULT_PROVIDER_DEADLINE_MS
}

const fn default_priority() -> u16 {
    100
}

impl Default for ProviderCapabilities {
    fn default() -> Self {
        Self {
            provider_id: String::new(),
            action_classes: BTreeSet::new(),
            max_capture_level: ProviderCaptureCeiling::MetadataOnly,
            on_failure: ProviderOnFailure::FailClosed,
            trust_model: ProviderTrustModel::DeterministicRule,
            may_modify: false,
            timeout_ms: DEFAULT_PROVIDER_DEADLINE_MS,
            priority: 100,
        }
    }
}

impl ProviderManifest {
    pub fn from_yaml_str(raw: &str) -> Result<Self, CodedError> {
        let root = parse_yaml(raw).map_err(|e| brk_manifest_err(e.to_string()))?;
        let map = root
            .as_map()
            .ok_or_else(|| brk_manifest_err("provider manifest must be a YAML map"))?;
        for key in map.keys() {
            if !ALLOWED_MANIFEST_KEYS.contains(&key.as_str()) {
                return Err(brk_manifest_err(format!(
                    "unknown field `{key}` in provider manifest"
                )));
            }
        }
        let id = req_nonempty_str(map, "id")?;
        let schema = req_nonempty_str(map, "schema")?;
        let kind = parse_provider_kind(map)?;
        let enabled = match map.get("enabled") {
            None => true,
            Some(v) => v
                .as_bool()
                .ok_or_else(|| brk_manifest_err("`enabled` must be a boolean"))?,
        };
        let endpoint = match map.get("endpoint") {
            Some(v) => v
                .as_str()
                .ok_or_else(|| brk_manifest_err("`endpoint` must be a string"))?
                .to_owned(),
            None if kind == ProviderKind::CommandHook => String::new(),
            None => return Err(brk_manifest_err("provider manifest missing `endpoint`")),
        };
        let command = match map.get("command") {
            None => None,
            Some(v) => Some(
                v.as_str()
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| brk_manifest_err("`command` must be a non-empty string"))?
                    .to_owned(),
            ),
        };
        let args = parse_string_list(map, "args")?;
        let caps_map = map
            .get("capabilities")
            .and_then(YamlValue::as_map)
            .ok_or_else(|| brk_manifest_err("provider manifest missing `capabilities`"))?;
        for key in caps_map.keys() {
            if !ALLOWED_CAPABILITY_KEYS.contains(&key.as_str()) {
                return Err(brk_manifest_err(format!(
                    "unknown field `capabilities.{key}` in provider manifest"
                )));
            }
        }
        let capabilities = parse_capabilities_map(&id, caps_map)?;
        let mut manifest = Self {
            schema,
            id,
            kind,
            enabled,
            endpoint,
            command,
            args,
            capabilities,
        };
        manifest.validate_and_clamp()?;
        Ok(manifest)
    }

    pub fn from_json_str(raw: &str) -> Result<Self, CodedError> {
        let mut manifest: Self =
            serde_json::from_str(raw).map_err(|e| brk_manifest_err(e.to_string()))?;
        if manifest.capabilities.provider_id.is_empty() {
            manifest.capabilities.provider_id = manifest.id.clone();
        }
        manifest.validate_and_clamp()?;
        Ok(manifest)
    }

    pub fn validate_and_clamp(&mut self) -> Result<(), CodedError> {
        if self.schema != PROVIDER_MANIFEST_SCHEMA {
            return Err(brk_manifest_err(format!(
                "unsupported schema `{}`; expected `{PROVIDER_MANIFEST_SCHEMA}`",
                self.schema
            )));
        }
        if !is_valid_provider_id(&self.id) {
            return Err(brk_manifest_err(format!(
                "invalid provider id `{}` (expected [a-z0-9._-])",
                self.id
            )));
        }
        if self.capabilities.provider_id != self.id {
            return Err(brk_manifest_err(format!(
                "capabilities.provider_id `{}` does not match id `{}`",
                self.capabilities.provider_id, self.id
            )));
        }
        validate_provider_transport(
            self.kind,
            &self.endpoint,
            self.command.as_deref(),
            &self.args,
        )?;
        if self.capabilities.timeout_ms == 0
            || self.capabilities.timeout_ms > MAX_PROVIDER_DEADLINE_MS
        {
            return Err(brk_manifest_err(format!(
                "provider `{}` timeout_ms={} outside allowed 1..={MAX_PROVIDER_DEADLINE_MS}",
                self.id, self.capabilities.timeout_ms
            )));
        }
        if self.capabilities.trust_model == ProviderTrustModel::ModelBacked {
            if self.capabilities.may_modify {
                return Err(brk_manifest_err(format!(
                    "model_backed provider `{}` cannot hold may_modify=true",
                    self.id
                )));
            }
            // Doc 07: model_backed providers clamp on_failure=ignore to avoid outage deadlocks.
            self.capabilities.on_failure = ProviderOnFailure::Ignore;
        }
        Ok(())
    }
}

pub fn load_providers_dir(
    dir: &Path,
    fs: &dyn LocalFsPort,
) -> Result<Vec<ProviderManifest>, CodedError> {
    match fs.inspect_nofollow(dir).map_err(brk_manifest_err)? {
        RegularEntryKind::Missing => return Ok(Vec::new()),
        RegularEntryKind::Dir => {}
        RegularEntryKind::File | RegularEntryKind::UnsafeOrOther => {
            return Err(brk_manifest_err(format!(
                "providers.d must be a real directory without symlinks: {}",
                dir.display()
            )));
        }
    }

    let paths: Vec<_> = fs
        .read_dir_entries(dir)
        .map_err(brk_manifest_err)?
        .into_iter()
        .filter(|p| {
            p.extension()
                .and_then(|s| s.to_str())
                .is_some_and(|ext| matches!(ext, "yaml" | "yml" | "json"))
        })
        .collect();

    let mut manifests = Vec::with_capacity(paths.len());
    for path in paths {
        let raw = fs
            .read_bounded_regular_string(&path, MAX_PROVIDER_MANIFEST_BYTES)
            .map_err(brk_manifest_err)?;
        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
        let manifest = if ext == "json" {
            ProviderManifest::from_json_str(&raw)?
        } else {
            ProviderManifest::from_yaml_str(&raw)?
        };
        if manifest.enabled {
            manifests.push(manifest);
        }
    }

    validate_provider_set(&manifests)?;
    manifests.sort_by_key(|m| (m.capabilities.priority, m.id.clone()));
    Ok(manifests)
}

pub fn validate_provider_set(manifests: &[ProviderManifest]) -> Result<(), CodedError> {
    let mut seen_ids = BTreeSet::new();
    let mut modify_writers: Vec<&str> = Vec::new();
    for m in manifests {
        if !m.enabled {
            continue;
        }
        if !seen_ids.insert(m.id.as_str()) {
            return Err(brk_manifest_err(format!(
                "duplicate provider id `{}` in providers.d",
                m.id
            )));
        }
        if m.capabilities.may_modify {
            modify_writers.push(m.id.as_str());
        }
    }
    if modify_writers.len() > 1 {
        return Err(CodedError::new(
            "GRDR-BRK-0006",
            format!(
                "multiple active providers declare may_modify=true ({})",
                modify_writers.join(", ")
            ),
            "Configure at most one active single-writer may_modify provider in providers.d.",
        ));
    }
    Ok(())
}
