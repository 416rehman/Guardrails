// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Declarative `providers.d/` manifest loader and strict transport/schema validation (`docs/design/07`).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};

use grdr_core::detect::yaml::{YamlValue, parse_yaml};
use grdr_model::CodedError;
use grdr_ports::{LocalFsPort, RegularEntryKind};

pub const PROVIDER_MANIFEST_SCHEMA: &str = "grdr.hook-broker.provider/v1alpha1";
const MAX_PROVIDER_MANIFEST_BYTES: u64 = 262_144;
pub const DEFAULT_PROVIDER_DEADLINE_MS: u64 = 150;
pub const MAX_PROVIDER_DEADLINE_MS: u64 = 1000;
const ALLOWED_MANIFEST_KEYS: &[&str] = &["schema", "id", "enabled", "endpoint", "capabilities"];
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
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    pub endpoint: String,
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
        let enabled = match map.get("enabled") {
            None => true,
            Some(v) => v
                .as_bool()
                .ok_or_else(|| brk_manifest_err("`enabled` must be a boolean"))?,
        };
        let endpoint = req_nonempty_str(map, "endpoint")?;
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

        let provider_id = match caps_map.get("provider_id") {
            None => id.clone(),
            Some(v) => v
                .as_str()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| brk_manifest_err("`capabilities.provider_id` must be non-empty"))?
                .to_owned(),
        };
        let action_classes = parse_action_classes(caps_map)?;
        let max_capture_level = parse_capture_level(caps_map)?;
        let on_failure = parse_on_failure(caps_map)?;
        let trust_model = parse_trust_model(caps_map)?;
        let may_modify = match caps_map.get("may_modify") {
            None => false,
            Some(v) => v
                .as_bool()
                .ok_or_else(|| brk_manifest_err("`capabilities.may_modify` must be a boolean"))?,
        };
        let timeout_ms = parse_timeout_ms(caps_map)?;
        let priority = parse_priority(caps_map)?;

        let mut manifest = Self {
            schema,
            id,
            enabled,
            endpoint,
            capabilities: ProviderCapabilities {
                provider_id,
                action_classes,
                max_capture_level,
                on_failure,
                trust_model,
                may_modify,
                timeout_ms,
                priority,
            },
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
        validate_ipc_endpoint(&self.endpoint)?;
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

fn validate_ipc_endpoint(endpoint: &str) -> Result<(), CodedError> {
    if endpoint.is_empty()
        || endpoint
            .chars()
            .any(|c| c.is_control() || c.is_whitespace())
        || endpoint.contains(['@', '#', '?'])
    {
        return Err(brk_manifest_err(
            "endpoint contains forbidden control, whitespace, userinfo, query, or fragment characters",
        ));
    }
    if let Some(sock_path) = endpoint.strip_prefix("unix:///") {
        if sock_path.is_empty()
            || sock_path.contains('\\')
            || Path::new(sock_path)
                .components()
                .any(|c| matches!(c, Component::ParentDir))
        {
            return Err(brk_manifest_err("invalid unix:/// endpoint path"));
        }
        return Ok(());
    }
    if let Some(pipe_name) = endpoint.strip_prefix(r"\\.\pipe\") {
        if pipe_name.is_empty() || pipe_name.contains(['\\', '/']) || pipe_name.contains("..") {
            return Err(brk_manifest_err("invalid Windows named-pipe endpoint"));
        }
        return Ok(());
    }
    let stripped = endpoint
        .strip_prefix("http://")
        .or_else(|| endpoint.strip_prefix("https://"))
        .or_else(|| endpoint.strip_prefix("ipc://"))
        .unwrap_or(endpoint)
        .trim_end_matches('/');
    let port_str = stripped
        .strip_prefix("127.0.0.1:")
        .or_else(|| stripped.strip_prefix("[::1]:"))
        .ok_or_else(|| {
            brk_manifest_err(
                "endpoint must use unix:///, \\\\.\\pipe\\, or loopback IPC (127.0.0.1 / [::1])",
            )
        })?;
    let port: u16 = port_str
        .parse()
        .map_err(|_| brk_manifest_err("loopback IPC endpoint port must be 1..=65535"))?;
    if port == 0 {
        return Err(brk_manifest_err(
            "loopback IPC endpoint port must be non-zero",
        ));
    }
    Ok(())
}

fn is_valid_provider_id(id: &str) -> bool {
    !id.is_empty()
        && !id.contains("..")
        && id
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
}

fn req_nonempty_str(map: &BTreeMap<String, YamlValue>, key: &str) -> Result<String, CodedError> {
    map.get(key)
        .and_then(YamlValue::as_str)
        .map(str::to_owned)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| brk_manifest_err(format!("provider manifest missing `{key}`")))
}

fn parse_action_classes(
    caps: &BTreeMap<String, YamlValue>,
) -> Result<BTreeSet<String>, CodedError> {
    match caps.get("action_classes") {
        None => Ok(BTreeSet::new()),
        Some(YamlValue::Seq(seq)) => {
            let mut set = BTreeSet::new();
            for item in seq {
                let s = item
                    .as_str()
                    .ok_or_else(|| brk_manifest_err("`action_classes` entries must be strings"))?;
                set.insert(s.to_owned());
            }
            Ok(set)
        }
        Some(_) => Err(brk_manifest_err(
            "`capabilities.action_classes` must be a list",
        )),
    }
}

fn parse_capture_level(
    caps: &BTreeMap<String, YamlValue>,
) -> Result<ProviderCaptureCeiling, CodedError> {
    match caps.get("max_capture_level") {
        None => Ok(ProviderCaptureCeiling::MetadataOnly),
        Some(v) => match v.as_str() {
            Some("metadata_only") => Ok(ProviderCaptureCeiling::MetadataOnly),
            Some("argument_preview") => Ok(ProviderCaptureCeiling::ArgumentPreview),
            Some("full_minimised") => Ok(ProviderCaptureCeiling::FullMinimised),
            _ => Err(brk_manifest_err("unknown `capabilities.max_capture_level`")),
        },
    }
}

fn parse_on_failure(caps: &BTreeMap<String, YamlValue>) -> Result<ProviderOnFailure, CodedError> {
    match caps.get("on_failure") {
        None => Ok(ProviderOnFailure::FailClosed),
        Some(v) => match v.as_str() {
            Some("fail_closed") => Ok(ProviderOnFailure::FailClosed),
            Some("step_up") => Ok(ProviderOnFailure::StepUp),
            Some("ignore") => Ok(ProviderOnFailure::Ignore),
            _ => Err(brk_manifest_err("unknown `capabilities.on_failure`")),
        },
    }
}

fn parse_trust_model(caps: &BTreeMap<String, YamlValue>) -> Result<ProviderTrustModel, CodedError> {
    match caps.get("trust_model") {
        None => Ok(ProviderTrustModel::DeterministicRule),
        Some(v) => match v.as_str() {
            Some("deterministic_rule") => Ok(ProviderTrustModel::DeterministicRule),
            Some("model_backed") => Ok(ProviderTrustModel::ModelBacked),
            _ => Err(brk_manifest_err("unknown `capabilities.trust_model`")),
        },
    }
}

fn parse_timeout_ms(caps: &BTreeMap<String, YamlValue>) -> Result<u64, CodedError> {
    match caps.get("timeout_ms") {
        None => Ok(DEFAULT_PROVIDER_DEADLINE_MS),
        Some(v) => v
            .as_i64()
            .and_then(|n| u64::try_from(n).ok())
            .filter(|&ms| ms > 0 && ms <= MAX_PROVIDER_DEADLINE_MS)
            .ok_or_else(|| brk_manifest_err("`capabilities.timeout_ms` must be 1..=1000")),
    }
}

fn parse_priority(caps: &BTreeMap<String, YamlValue>) -> Result<u16, CodedError> {
    match caps.get("priority") {
        None => Ok(100),
        Some(v) => v
            .as_i64()
            .and_then(|n| u16::try_from(n).ok())
            .ok_or_else(|| brk_manifest_err("`capabilities.priority` must be 0..=65535")),
    }
}

fn brk_manifest_err(msg: impl Into<String>) -> CodedError {
    CodedError::new(
        "GRDR-BRK-0005",
        msg,
        "Validate providers.d manifest against spec/hook-broker/provider-manifest.schema.yaml.",
    )
}
