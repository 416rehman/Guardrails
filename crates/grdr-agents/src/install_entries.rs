// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Declarative hook JSON entry construction, diffing, and removal helpers for the hook installer.

use std::path::{Path, PathBuf};

use grdr_ports::{LocalFsPort, RegularEntryKind, validate_safe_rel_path};
use serde_json::{Map, Value, json};

use crate::catalogue::{AgentCatalogue, AgentFlagMode, AgentManifest, HookEntryStyle, TimeoutUnit};
use crate::json_edit::insert_array_entries_preserving_spans;
use crate::parse::json_value_contains_hook_command;

pub(crate) const MAX_CONFIG_BYTES: u64 = 1_048_576;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MergeOutcome {
    Added,
    AlreadyPresent,
}

pub(crate) fn validate_hook_command(cmd: &str) -> Result<(), String> {
    let trimmed = cmd.trim();
    if trimmed.is_empty() || trimmed.chars().any(char::is_control) {
        return Err(
            "GRDR-AGENTS-0001: hook_command is empty or contains control chars".to_string(),
        );
    }
    Ok(())
}

pub(crate) fn safe_join_home(home_dir: &Path, rel: &str) -> Result<PathBuf, String> {
    validate_safe_rel_path(rel, false, false, false)
        .map_err(|e| format!("GRDR-AGENTS-0001: unsafe config_rel `{rel}`: {e}"))?;
    Ok(home_dir.join(rel))
}

pub(crate) fn read_existing_regular_config(
    path: &Path,
    fs: &dyn LocalFsPort,
) -> Result<String, String> {
    match fs.inspect_nofollow(path)? {
        RegularEntryKind::Missing => {
            fs.check_no_ancestor_symlinks(path)?;
            Ok(String::new())
        }
        RegularEntryKind::File => fs.read_bounded_regular_string(path, MAX_CONFIG_BYTES),
        RegularEntryKind::Dir | RegularEntryKind::UnsafeOrOther => Err(format!(
            "GRDR-AGENTS-0002: refusing symlink or non-regular file at {}",
            path.display()
        )),
    }
}

pub(crate) fn resolve_hook_manifest<'a>(
    target_id: &str,
    catalogue: &'a AgentCatalogue,
) -> Result<&'a AgentManifest, String> {
    let manifest = catalogue.resolve(target_id).ok_or_else(|| {
        format!("GRDR-AGENTS-0001: unsupported hook install target `{target_id}`")
    })?;
    if !manifest.hook.supported
        || manifest.hook.config_rel.is_empty()
        || manifest.hook.events.is_empty()
    {
        return Err(format!(
            "GRDR-AGENTS-0001: manifest `{}` does not declare hook installation targets",
            manifest.id
        ));
    }
    validate_safe_rel_path(&manifest.hook.config_rel, false, false, false).map_err(|e| {
        format!(
            "GRDR-AGENTS-0001: unsafe hook config_rel in `{}`: {e}",
            manifest.id
        )
    })?;
    Ok(manifest)
}

pub(crate) fn compute_hook_preview(
    manifest: &AgentManifest,
    existing_raw: Option<&str>,
    config_path: &Path,
    hook_command: &str,
) -> Result<(MergeOutcome, String, Vec<String>), String> {
    let root_key = if manifest.hook.root_key.is_empty() {
        "hooks"
    } else {
        manifest.hook.root_key.as_str()
    };

    if let Some(raw) = existing_raw {
        let root: Value = serde_json::from_str(raw)
            .map_err(|e| format!("invalid JSON in {}: {e}", config_path.display()))?;
        let pending_owned = collect_pending_entries(&root, manifest, root_key, hook_command)?;
        if pending_owned.is_empty() {
            return Ok((MergeOutcome::AlreadyPresent, raw.to_owned(), Vec::new()));
        }
        let added_events: Vec<String> = pending_owned.iter().map(|(k, _)| k.clone()).collect();
        let refs: Vec<(&str, Value)> = pending_owned
            .iter()
            .map(|(k, v)| (k.as_str(), v.clone()))
            .collect();
        let updated = insert_array_entries_preserving_spans(raw, root_key, &refs)?;
        return Ok((MergeOutcome::Added, updated, added_events));
    }

    let mut root = Value::Object(Map::new());
    if let Some(ver) = manifest.hook.version_field
        && let Some(obj) = root.as_object_mut()
    {
        obj.insert("version".into(), json!(ver));
    }
    let added = merge_new_hook_entries(&mut root, manifest, root_key, hook_command)?;
    let serialized = serde_json::to_string_pretty(&root)
        .map_err(|e| format!("failed serializing merged hook config: {e}"))?;
    Ok((MergeOutcome::Added, format!("{serialized}\n"), added))
}

fn collect_pending_entries(
    root: &Value,
    manifest: &AgentManifest,
    root_key: &str,
    hook_command: &str,
) -> Result<Vec<(String, Value)>, String> {
    let root_obj = root
        .as_object()
        .ok_or_else(|| "root hook config must be a JSON object".to_string())?;
    let hooks_obj = match root_obj.get(root_key) {
        Some(v) => Some(
            v.as_object()
                .ok_or_else(|| format!("`{root_key}` field must be a JSON object"))?,
        ),
        None => None,
    };

    let mut pending = Vec::new();
    for event_key in &manifest.hook.events {
        if let Some(hooks) = hooks_obj
            && let Some(val) = hooks.get(event_key.as_str())
        {
            let arr = val
                .as_array()
                .ok_or_else(|| format!("`{root_key}.{event_key}` must be a JSON array"))?;
            if arr
                .iter()
                .any(|item| json_value_contains_hook_command(item, hook_command))
            {
                continue;
            }
        }
        pending.push((
            event_key.clone(),
            build_entry_for_manifest(manifest, hook_command),
        ));
    }
    Ok(pending)
}

fn merge_new_hook_entries(
    root: &mut Value,
    manifest: &AgentManifest,
    root_key: &str,
    hook_command: &str,
) -> Result<Vec<String>, String> {
    let root_obj = root
        .as_object_mut()
        .ok_or_else(|| "root hook config must be a JSON object".to_string())?;
    if !root_obj.contains_key(root_key) {
        root_obj.insert(root_key.into(), Value::Object(Map::new()));
    }
    let hooks_obj = root_obj
        .get_mut(root_key)
        .and_then(Value::as_object_mut)
        .ok_or_else(|| format!("`{root_key}` field must be a JSON object"))?;

    let mut added = Vec::new();
    for event_key in &manifest.hook.events {
        if !hooks_obj.contains_key(event_key.as_str()) {
            hooks_obj.insert(event_key.clone(), Value::Array(Vec::new()));
        }
        let arr = hooks_obj
            .get_mut(event_key.as_str())
            .and_then(Value::as_array_mut)
            .ok_or_else(|| format!("`{root_key}.{event_key}` must be a JSON array"))?;
        arr.push(build_entry_for_manifest(manifest, hook_command));
        added.push(event_key.clone());
    }
    Ok(added)
}

pub(crate) fn remove_grdr_entries(
    root: &mut Value,
    manifest: &AgentManifest,
    hook_command: &str,
) -> bool {
    let root_key = if manifest.hook.root_key.is_empty() {
        "hooks"
    } else {
        manifest.hook.root_key.as_str()
    };
    let Some(hooks_obj) = root.get_mut(root_key).and_then(Value::as_object_mut) else {
        return false;
    };
    let mut changed = false;
    for key in &manifest.hook.events {
        if let Some(arr) = hooks_obj
            .get_mut(key.as_str())
            .and_then(Value::as_array_mut)
        {
            let before = arr.len();
            arr.retain(|item| !json_value_contains_hook_command(item, hook_command));
            if arr.len() != before {
                changed = true;
            }
        }
    }
    changed
}

pub(crate) fn format_hook_command(manifest: &AgentManifest, hook_command: &str) -> String {
    match manifest.hook.agent_flag {
        AgentFlagMode::Append => format!("{hook_command} --agent {}", manifest.id),
        AgentFlagMode::Omit => hook_command.to_owned(),
    }
}

pub(crate) fn build_entry_for_manifest(manifest: &AgentManifest, hook_command: &str) -> Value {
    let command = format_hook_command(manifest, hook_command);
    match manifest.hook.entry_style {
        HookEntryStyle::CommandItem => json!({ "command": command }),
        HookEntryStyle::MatcherHooks | HookEntryStyle::TomlHook | HookEntryStyle::None => {
            let matcher = manifest.hook.matcher.as_deref().unwrap_or(".*");
            let timeout = match manifest.hook.timeout_unit {
                TimeoutUnit::Seconds => manifest.hook.timeout_ms.div_ceil(1000).max(1),
                TimeoutUnit::Milliseconds => manifest.hook.timeout_ms,
            };
            let mut inner = Map::new();
            if let Some(name) = &manifest.hook.entry_name {
                inner.insert("name".into(), json!(name));
            }
            inner.insert("type".into(), json!("command"));
            inner.insert("command".into(), json!(command));
            inner.insert("timeout".into(), json!(timeout));
            json!({
                "matcher": matcher,
                "hooks": [Value::Object(inner)],
            })
        }
    }
}
