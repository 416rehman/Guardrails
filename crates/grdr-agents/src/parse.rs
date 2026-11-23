// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::fs;
use std::path::Path;

use serde_json::Value;

use grdr_model::McpServerEntry;

pub(crate) fn read_json(path: &Path) -> Result<Value, String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&raw).map_err(|e| format!("{}: {e}", path.display()))
}

pub(crate) fn json_contains_grdr_hook(val: &Value) -> bool {
    let Some(hooks) = val.get("hooks").and_then(Value::as_object) else {
        return false;
    };
    serde_json::to_string(hooks)
        .unwrap_or_default()
        .contains("grdr-hook")
}

pub(crate) fn extract_mcp_servers(
    val: &Value,
    source_agent: &str,
    config_path: &Path,
    out: &mut Vec<McpServerEntry>,
) {
    let servers = val
        .get("mcpServers")
        .or_else(|| val.get("servers"))
        .and_then(Value::as_object);
    let Some(map) = servers else {
        return;
    };

    for (name, cfg) in map {
        let transport = if cfg.get("url").is_some() {
            "http"
        } else {
            "stdio"
        };
        let command = cfg
            .get("command")
            .and_then(Value::as_str)
            .map(command_basename)
            .or_else(|| cfg.get("url").and_then(Value::as_str).map(strip_url_query))
            .unwrap_or_else(|| "unknown".into());

        out.push(McpServerEntry {
            name: name.clone(),
            transport: transport.into(),
            command,
            source_agent: source_agent.into(),
            config_path: display_path(config_path),
            pinned: cfg.get("digest").is_some() || cfg.get("sha256").is_some(),
        });
    }
}

pub(crate) fn extract_toml_mcp_headers(
    text: &str,
    source_agent: &str,
    config_path: &Path,
    out: &mut Vec<McpServerEntry>,
) {
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("[mcp_servers.")
            && let Some(name) = rest.strip_suffix(']')
            && !name.contains('.')
            && !name.is_empty()
        {
            out.push(McpServerEntry {
                name: name.to_string(),
                transport: "stdio".into(),
                command: "codex-mcp".into(),
                source_agent: source_agent.into(),
                config_path: display_path(config_path),
                pinned: false,
            });
        }
    }
}

pub(crate) fn command_basename(raw: &str) -> String {
    Path::new(raw)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(raw)
        .to_string()
}

pub(crate) fn strip_url_query(raw: &str) -> String {
    raw.split('?').next().unwrap_or(raw).to_string()
}

pub(crate) fn display_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}
