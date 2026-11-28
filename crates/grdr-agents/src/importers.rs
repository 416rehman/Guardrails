// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! P14 external catalogue importers (`ai-detection-spec`, Uber ADR, ACP registry) and P7 pack linter (`docs/design/05`).

use std::collections::BTreeSet;

use grdr_core::detect::yaml::{YamlValue, parse_yaml};
use grdr_model::CodedError;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::catalogue::{
    AdminConfigPaths, AgentArtifactRoutes, AgentManifest, AgentRoutes, HookSpec, validate_slug_id,
};

const MAX_IMPORT_BYTES: usize = 2 * 1024 * 1024;

const DISALLOWED_P7_KEYS: &[&str] = &[
    "commands",
    "command",
    "exec",
    "shell",
    "script",
    "args",
    "argv",
    "executables",
    "urls_to_contact",
    "webhook",
    "beacon_url",
    "callback_url",
    "env_vars_to_set",
    "set_env",
    "export_env",
];

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineList {
    pub ids: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportSummary {
    pub imported: Vec<AgentManifest>,
    pub skipped_quarantined: usize,
}

impl QuarantineList {
    pub fn from_json(raw: &str) -> Result<Self, CodedError> {
        check_import_size(raw, "quarantine.json")?;
        let val: Value = serde_json::from_str(raw)
            .map_err(|e| imp_err("GRDR-AGENTS-0004", format!("invalid quarantine.json: {e}")))?;
        let arr = if let Some(arr) = val.get("quarantined").and_then(Value::as_array) {
            arr
        } else if let Some(arr) = val.as_array() {
            arr
        } else {
            return Err(imp_err(
                "GRDR-AGENTS-0004",
                "quarantine.json must be a top-level array or object with `quarantined` array",
            ));
        };
        let mut ids = BTreeSet::new();
        for item in arr {
            let Some(id) = item
                .as_str()
                .or_else(|| item.get("id").and_then(Value::as_str))
            else {
                return Err(imp_err(
                    "GRDR-AGENTS-0004",
                    "quarantine.json entries must be non-empty ID strings or objects with `id`",
                ));
            };
            let trimmed = id.trim();
            if trimmed.is_empty() {
                return Err(imp_err(
                    "GRDR-AGENTS-0004",
                    "quarantine.json entries cannot be empty",
                ));
            }
            ids.insert(trimmed.to_ascii_lowercase());
        }
        Ok(Self { ids })
    }

    #[must_use]
    pub fn is_quarantined(&self, id: &str) -> bool {
        self.ids.contains(&id.to_ascii_lowercase())
    }
}

pub fn lint_catalogue_pack_yaml(raw_yaml: &str) -> Result<(), CodedError> {
    check_import_size(raw_yaml, "catalogue pack YAML")?;
    let root = parse_yaml(raw_yaml).map_err(|e| imp_err("GRDR-AGENTS-0004", e.to_string()))?;
    lint_yaml_value(&root)
}

pub fn lint_cedar_block_on_advisory(cedar_src: &str) -> Result<(), CodedError> {
    check_import_size(cedar_src, "Cedar policy")?;
    let stripped = strip_cedar_comments(cedar_src);
    for stmt in split_cedar_statements(&stripped) {
        let lower = stmt.to_ascii_lowercase();
        let is_forbid = lower.contains("forbid") || lower.contains("block");
        let reads_advisory = lower.contains("agent_suspected")
            || lower.contains("agent-suspected")
            || lower.contains("discovery_evidence")
            || lower.contains("discoveryevidence");
        if is_forbid && reads_advisory {
            return Err(imp_err(
                "GRDR-AGENTS-0004",
                "Cedar Block/forbid rule cannot reference advisory DiscoveryEvidence or agent_suspected (P2)",
            ));
        }
        if contains_forbidden_unless_basis(&lower) {
            return Err(imp_err(
                "GRDR-AGENTS-0004",
                "Doc 06 invariant: Cedar `unless` clause cannot depend on declared-only, traffic, timing, or influenced predicates",
            ));
        }
    }
    Ok(())
}

pub fn import_ai_detection_spec(
    raw_yaml: &str,
    quarantine: &QuarantineList,
) -> Result<ImportSummary, CodedError> {
    check_import_size(raw_yaml, "ai-detection-spec YAML")?;
    lint_catalogue_pack_yaml(raw_yaml)?;
    let root = parse_yaml(raw_yaml).map_err(|e| imp_err("GRDR-AGENTS-0004", e.to_string()))?;
    let map = root
        .as_map()
        .ok_or_else(|| imp_err("GRDR-AGENTS-0004", "ai-detection-spec root must be map"))?;
    let entries = map
        .get("agents")
        .or_else(|| map.get("detections"))
        .and_then(YamlValue::as_seq)
        .ok_or_else(|| imp_err("GRDR-AGENTS-0004", "missing agents/detections list"))?;

    let mut imported = Vec::new();
    let mut skipped = 0usize;
    for entry in entries {
        let Some(m) = entry.as_map() else {
            return Err(imp_err("GRDR-AGENTS-0004", "detection entry must be map"));
        };
        let raw_id = m
            .get("id")
            .and_then(YamlValue::as_str)
            .ok_or_else(|| imp_err("GRDR-AGENTS-0004", "missing detection id"))?;
        if quarantine.is_quarantined(raw_id) {
            skipped = skipped.saturating_add(1);
            continue;
        }
        let manifest = manifest_from_imported(
            raw_id,
            m.get("name").and_then(YamlValue::as_str).unwrap_or(raw_id),
            m.get("vendor")
                .and_then(YamlValue::as_str)
                .unwrap_or("community"),
            "hook-shim",
            yaml_str_list(m, "binaries"),
            yaml_str_list(m, "npm"),
            yaml_str_list(m, "pypi"),
            yaml_str_list(m, "env_markers"),
            yaml_str_list(m, "endpoints"),
        )?;
        imported.push(manifest);
    }
    Ok(ImportSummary {
        imported,
        skipped_quarantined: skipped,
    })
}

pub fn import_uber_adr_signatures(
    raw_json: &str,
    quarantine: &QuarantineList,
) -> Result<ImportSummary, CodedError> {
    check_import_size(raw_json, "Uber ADR JSON")?;
    let val: Value = serde_json::from_str(raw_json)
        .map_err(|e| imp_err("GRDR-AGENTS-0004", format!("invalid Uber ADR JSON: {e}")))?;
    let items = val
        .get("agents")
        .or_else(|| val.get("signatures"))
        .and_then(Value::as_array)
        .ok_or_else(|| imp_err("GRDR-AGENTS-0004", "Uber ADR payload missing agents array"))?;
    let mut imported = Vec::new();
    let mut skipped = 0usize;
    for item in items {
        let raw_id = item
            .get("id")
            .or_else(|| item.get("slug"))
            .and_then(Value::as_str)
            .ok_or_else(|| imp_err("GRDR-AGENTS-0004", "Uber ADR entry missing id/slug"))?;
        if quarantine.is_quarantined(raw_id) {
            skipped = skipped.saturating_add(1);
            continue;
        }
        let manifest = manifest_from_imported(
            raw_id,
            item.get("name").and_then(Value::as_str).unwrap_or(raw_id),
            item.get("vendor")
                .and_then(Value::as_str)
                .unwrap_or("uber-adr"),
            "sensor-only",
            json_str_list(item, "process_names"),
            json_str_list(item, "npm_packages"),
            json_str_list(item, "pypi_packages"),
            json_str_list(item, "env_vars"),
            json_str_list(item, "hosts"),
        )?;
        imported.push(manifest);
    }
    Ok(ImportSummary {
        imported,
        skipped_quarantined: skipped,
    })
}

pub fn import_acp_registry(
    raw_json: &str,
    quarantine: &QuarantineList,
) -> Result<ImportSummary, CodedError> {
    check_import_size(raw_json, "ACP registry JSON")?;
    let val: Value = serde_json::from_str(raw_json).map_err(|e| {
        imp_err(
            "GRDR-AGENTS-0004",
            format!("invalid ACP registry JSON: {e}"),
        )
    })?;
    let items = val
        .get("agents")
        .and_then(Value::as_array)
        .ok_or_else(|| imp_err("GRDR-AGENTS-0004", "ACP registry missing agents array"))?;
    let mut imported = Vec::new();
    let mut skipped = 0usize;
    for item in items {
        let raw_id = item
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| imp_err("GRDR-AGENTS-0004", "ACP agent entry missing id"))?;
        if quarantine.is_quarantined(raw_id) {
            skipped = skipped.saturating_add(1);
            continue;
        }
        let mut bins = json_str_list(item, "binaries");
        if let Some(cmd) = item.get("command").and_then(Value::as_str)
            && !cmd.is_empty()
        {
            bins.push(cmd.to_owned());
        }
        let manifest = manifest_from_imported(
            raw_id,
            item.get("name").and_then(Value::as_str).unwrap_or(raw_id),
            item.get("vendor").and_then(Value::as_str).unwrap_or("acp"),
            "acp",
            bins,
            json_str_list(item, "npm"),
            json_str_list(item, "pypi"),
            Vec::new(),
            Vec::new(),
        )?;
        imported.push(manifest);
    }
    Ok(ImportSummary {
        imported,
        skipped_quarantined: skipped,
    })
}

fn lint_yaml_value(val: &YamlValue) -> Result<(), CodedError> {
    match val {
        YamlValue::Map(map) => {
            for (k, v) in map {
                let kl = k.to_ascii_lowercase();
                if DISALLOWED_P7_KEYS.iter().any(|bad| *bad == kl) {
                    let non_empty = match v {
                        YamlValue::Seq(s) => !s.is_empty(),
                        YamlValue::Str(s) => !s.trim().is_empty(),
                        YamlValue::Map(m) => !m.is_empty(),
                        _ => true,
                    };
                    if non_empty {
                        return Err(imp_err(
                            "GRDR-AGENTS-0004",
                            format!("P7 violation: pack introduces disallowed field `{k}`"),
                        ));
                    }
                }
                lint_yaml_value(v)?;
            }
            Ok(())
        }
        YamlValue::Seq(seq) => {
            for item in seq {
                lint_yaml_value(item)?;
            }
            Ok(())
        }
        YamlValue::Str(s) => {
            if s.chars().any(char::is_control) {
                return Err(imp_err(
                    "GRDR-AGENTS-0004",
                    "P7 control character in pack string",
                ));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[allow(clippy::too_many_arguments)]
fn manifest_from_imported(
    raw_id: &str,
    name: &str,
    vendor: &str,
    adapter: &str,
    binaries: Vec<String>,
    npm: Vec<String>,
    pypi: Vec<String>,
    env_markers: Vec<String>,
    net: Vec<String>,
) -> Result<AgentManifest, CodedError> {
    let id = raw_id.trim().to_ascii_lowercase().replace('_', "-");
    validate_slug_id(&id, "GRDR-AGENTS-0004")?;
    for v in binaries
        .iter()
        .chain(npm.iter())
        .chain(pypi.iter())
        .chain(env_markers.iter())
        .chain(net.iter())
    {
        if v.is_empty() || v.chars().any(char::is_control) || v.contains("..") {
            return Err(imp_err(
                "GRDR-AGENTS-0004",
                format!("P7 unsafe imported route value `{v}` in `{id}`"),
            ));
        }
    }
    Ok(AgentManifest {
        id,
        aliases: Vec::new(),
        name: name.into(),
        vendor: vendor.into(),
        kind: "coding-agent".into(),
        catalogue_tier: "B".into(),
        surfaces: vec!["cli".into()],
        declared_action_classes: vec!["exec".into(), "file.read".into()],
        containment_default: "watch".into(),
        adapter: adapter.into(),
        routes: AgentRoutes {
            binaries,
            windows_exes: Vec::new(),
            wsl_harnesses: Vec::new(),
            cmdline_markers: Vec::new(),
            npm,
            pypi,
            vscode_extensions: Vec::new(),
            state_dirs: Vec::new(),
            config_paths: Vec::new(),
            admin_config_paths: AdminConfigPaths::default(),
            mcp_config_paths: Vec::new(),
            mcp_config_key: String::new(),
            env_markers,
            net,
            artifacts: AgentArtifactRoutes::default(),
            autonomy_flags: Vec::new(),
        },
        hook: HookSpec::default(),
    })
}

fn yaml_str_list(map: &std::collections::BTreeMap<String, YamlValue>, key: &str) -> Vec<String> {
    map.get(key)
        .and_then(YamlValue::as_seq)
        .map(|seq| {
            seq.iter()
                .filter_map(YamlValue::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn json_str_list(obj: &Value, key: &str) -> Vec<String> {
    obj.get(key)
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn check_import_size(raw: &str, label: &str) -> Result<(), CodedError> {
    if raw.len() > MAX_IMPORT_BYTES {
        return Err(imp_err(
            "GRDR-AGENTS-0004",
            format!("{label} exceeds bounded import limit ({MAX_IMPORT_BYTES} bytes)"),
        ));
    }
    Ok(())
}

fn strip_cedar_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let bytes = src.as_bytes();
    let mut i = 0usize;
    let mut in_str = false;
    let mut escaped = false;
    while let Some(&ch) = bytes.get(i) {
        if in_str {
            if let Some(s) = src.get(i..)
                && let Some(c) = s.chars().next()
            {
                out.push(c);
                i = i.saturating_add(c.len_utf8());
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == '"' {
                    in_str = false;
                }
                continue;
            }
            break;
        }
        if ch == b'"' {
            in_str = true;
            out.push('"');
            i = i.saturating_add(1);
            continue;
        }
        if bytes.get(i..i.saturating_add(2)) == Some(b"//") {
            while bytes.get(i).is_some_and(|&b| b != b'\n') {
                i = i.saturating_add(1);
            }
            continue;
        }
        if bytes.get(i..i.saturating_add(2)) == Some(b"/*") {
            i = i.saturating_add(2);
            while i < bytes.len() && bytes.get(i..i.saturating_add(2)) != Some(b"*/") {
                i = i.saturating_add(1);
            }
            i = i.saturating_add(2).min(bytes.len());
            out.push(' ');
            continue;
        }
        if let Some(s) = src.get(i..)
            && let Some(c) = s.chars().next()
        {
            out.push(c);
            i = i.saturating_add(c.len_utf8());
        } else {
            break;
        }
    }
    out
}

fn split_cedar_statements(src: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut in_str = false;
    let mut escaped = false;
    let mut start = 0usize;
    for (idx, ch) in src.char_indices() {
        if in_str {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_str = false;
            }
            continue;
        }
        if ch == '"' {
            in_str = true;
        } else if ch == ';' {
            if let Some(stmt) = src.get(start..idx) {
                out.push(stmt);
            }
            start = idx.saturating_add(1);
        }
    }
    if let Some(tail) = src.get(start..)
        && !tail.trim().is_empty()
    {
        out.push(tail);
    }
    out
}

fn contains_forbidden_unless_basis(lower_stmt: &str) -> bool {
    let Some(idx) = lower_stmt.find("unless") else {
        return false;
    };
    let tail = lower_stmt.get(idx..).unwrap_or("");
    [
        "declared-only",
        "declared_only",
        "traffic",
        "timing",
        "influenced",
    ]
    .iter()
    .any(|needle| tail.contains(needle))
}

fn imp_err(code: &'static str, msg: impl Into<String>) -> CodedError {
    CodedError::new(
        code,
        msg.into(),
        "Ensure imported packs satisfy P7 metadata-only schema rules.",
    )
}
