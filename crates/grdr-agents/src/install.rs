// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::install_journal::{
    PriorFile, atomic_write, detect_state_dir, restore_from_journal, write_journal_if_absent,
};
use crate::json_edit::insert_array_entries_preserving_spans;
use crate::parse::{json_contains_grdr_hook, read_json};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookTargetKind {
    ClaudeCode,
    Cursor,
    Gemini,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallOutcome {
    Applied,
    AlreadyInstalled,
    DryRunPreview,
    Unchanged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HookInstallState {
    Effective,
    NotConfigured,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookStatusReport {
    pub agent: String,
    pub state: HookInstallState,
    pub installed: bool,
    pub config_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookInstallReport {
    pub agent: String,
    pub config_path: PathBuf,
    pub journal_path: PathBuf,
    pub outcome: InstallOutcome,
    pub preview_json: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MergeOutcome {
    Added,
    AlreadyPresent,
}

impl HookTargetKind {
    pub fn from_name(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "claude" | "claude-code" | "claude_code" => Ok(Self::ClaudeCode),
            "cursor" => Ok(Self::Cursor),
            "gemini" | "gemini-cli" | "antigravity" => Ok(Self::Gemini),
            other => Err(format!(
                "GRDR-AGENTS-0001: unsupported hook install target `{other}` (expected claude-code, cursor, or gemini)"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude-code",
            Self::Cursor => "cursor",
            Self::Gemini => "gemini",
        }
    }

    pub fn config_path(self, home_dir: &Path) -> PathBuf {
        match self {
            Self::ClaudeCode => home_dir.join(".claude").join("settings.json"),
            Self::Cursor => home_dir.join(".cursor").join("hooks.json"),
            Self::Gemini => home_dir.join(".gemini").join("settings.json"),
        }
    }

    pub fn journal_path(self, state_dir: &Path) -> PathBuf {
        state_dir.join(format!("hook-backup-{}.json", self.as_str()))
    }
}

pub fn hook_status(target: HookTargetKind, home_dir: &Path) -> Result<HookStatusReport, String> {
    let config_path = target.config_path(home_dir);
    let mut candidates = vec![config_path.clone()];
    if target == HookTargetKind::ClaudeCode {
        candidates.push(home_dir.join(".claude.json"));
    }

    let mut installed = false;
    for path in &candidates {
        if !path.is_file() {
            continue;
        }
        let val = read_json(path).map_err(|e| format!("GRDR-AGENTS-0002: {e}"))?;
        if json_contains_grdr_hook(&val) {
            installed = true;
            break;
        }
    }

    let state = if installed {
        HookInstallState::Effective
    } else {
        HookInstallState::NotConfigured
    };

    Ok(HookStatusReport {
        agent: target.as_str().into(),
        state,
        installed,
        config_path,
    })
}

pub fn install_hook(
    target: HookTargetKind,
    home_dir: &Path,
    hook_command: &str,
    dry_run: bool,
) -> Result<HookInstallReport, String> {
    let state_dir = detect_state_dir(home_dir);
    install_hook_in_state_dir(target, home_dir, &state_dir, hook_command, dry_run)
}

pub fn install_hook_in_state_dir(
    target: HookTargetKind,
    home_dir: &Path,
    state_dir: &Path,
    hook_command: &str,
    dry_run: bool,
) -> Result<HookInstallReport, String> {
    let config_path = target.config_path(home_dir);
    let journal_path = target.journal_path(state_dir);
    let prior = if config_path.is_file() {
        PriorFile::Present(
            fs::read_to_string(&config_path)
                .map_err(|e| format!("failed reading {}: {e}", config_path.display()))?,
        )
    } else {
        PriorFile::Absent
    };

    let (merge, preview_json) = match &prior {
        PriorFile::Present(raw) if !raw.trim().is_empty() => {
            let root: Value = serde_json::from_str(raw)
                .map_err(|e| format!("invalid JSON in {}: {e}", config_path.display()))?;
            let pending = collect_pending_entries(&root, target, hook_command)?;
            if pending.is_empty() {
                (MergeOutcome::AlreadyPresent, raw.clone())
            } else {
                let updated = insert_array_entries_preserving_spans(raw, &pending)?;
                (MergeOutcome::Added, updated)
            }
        }
        _ => {
            let mut root = Value::Object(Map::new());
            let merge = merge_hook_entry(&mut root, target, hook_command)?;
            let serialized = serde_json::to_string_pretty(&root)
                .map_err(|e| format!("failed serializing merged hook config: {e}"))?;
            (merge, format!("{serialized}\n"))
        }
    };

    let outcome = match (merge, dry_run) {
        (MergeOutcome::AlreadyPresent, _) => InstallOutcome::AlreadyInstalled,
        (MergeOutcome::Added, true) => InstallOutcome::DryRunPreview,
        (MergeOutcome::Added, false) => {
            write_journal_if_absent(&journal_path, prior)?;
            atomic_write(&config_path, preview_json.as_bytes())?;
            InstallOutcome::Applied
        }
    };

    Ok(HookInstallReport {
        agent: target.as_str().into(),
        config_path,
        journal_path,
        outcome,
        preview_json,
    })
}

pub fn uninstall_hook(
    target: HookTargetKind,
    home_dir: &Path,
) -> Result<HookInstallReport, String> {
    let state_dir = detect_state_dir(home_dir);
    uninstall_hook_in_state_dir(target, home_dir, &state_dir)
}

pub fn uninstall_hook_in_state_dir(
    target: HookTargetKind,
    home_dir: &Path,
    state_dir: &Path,
) -> Result<HookInstallReport, String> {
    let config_path = target.config_path(home_dir);
    let journal_path = target.journal_path(state_dir);

    if let Some(preview_json) = restore_from_journal(&journal_path, &config_path)? {
        return Ok(HookInstallReport {
            agent: target.as_str().into(),
            config_path,
            journal_path,
            outcome: InstallOutcome::Applied,
            preview_json,
        });
    }

    if !config_path.is_file() {
        return Ok(HookInstallReport {
            agent: target.as_str().into(),
            config_path,
            journal_path,
            outcome: InstallOutcome::Unchanged,
            preview_json: String::new(),
        });
    }

    let raw = fs::read_to_string(&config_path)
        .map_err(|e| format!("failed reading {}: {e}", config_path.display()))?;
    let mut root: Value = serde_json::from_str(&raw)
        .map_err(|e| format!("invalid JSON in {}: {e}", config_path.display()))?;
    let changed = remove_grdr_entries(&mut root, target);
    let preview_json = serde_json::to_string_pretty(&root)
        .map_err(|e| format!("failed serializing config: {e}"))?;
    if changed {
        atomic_write(&config_path, preview_json.as_bytes())?;
    }

    Ok(HookInstallReport {
        agent: target.as_str().into(),
        config_path,
        journal_path,
        outcome: if changed {
            InstallOutcome::Applied
        } else {
            InstallOutcome::Unchanged
        },
        preview_json,
    })
}

fn collect_pending_entries(
    root: &Value,
    target: HookTargetKind,
    hook_command: &str,
) -> Result<Vec<(&'static str, Value)>, String> {
    let root_obj = root
        .as_object()
        .ok_or_else(|| "root hook config must be a JSON object".to_string())?;
    let hooks_obj = match root_obj.get("hooks") {
        Some(v) => Some(
            v.as_object()
                .ok_or_else(|| "`hooks` field must be a JSON object".to_string())?,
        ),
        None => None,
    };

    let desired: Vec<(&'static str, Value)> = match target {
        HookTargetKind::ClaudeCode => vec![("PreToolUse", claude_hook_entry(hook_command))],
        HookTargetKind::Gemini => vec![("BeforeTool", gemini_hook_entry(hook_command))],
        HookTargetKind::Cursor => vec![
            ("beforeShellExecution", cursor_hook_entry(hook_command)),
            ("preToolUse", cursor_hook_entry(hook_command)),
        ],
    };

    let mut pending = Vec::new();
    for (event_key, entry) in desired {
        if let Some(hooks) = hooks_obj
            && let Some(val) = hooks.get(event_key)
        {
            let arr = val
                .as_array()
                .ok_or_else(|| format!("`hooks.{event_key}` must be a JSON array"))?;
            let already = arr.iter().any(|item| {
                serde_json::to_string(item)
                    .unwrap_or_default()
                    .contains("grdr-hook")
            });
            if already {
                continue;
            }
        }
        pending.push((event_key, entry));
    }
    Ok(pending)
}

fn merge_hook_entry(
    root: &mut Value,
    target: HookTargetKind,
    hook_command: &str,
) -> Result<MergeOutcome, String> {
    let root_obj = root
        .as_object_mut()
        .ok_or_else(|| "root hook config must be a JSON object".to_string())?;

    if !root_obj.contains_key("hooks") {
        root_obj.insert("hooks".into(), Value::Object(Map::new()));
    }
    let hooks_obj = root_obj
        .get_mut("hooks")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "`hooks` field must be a JSON object".to_string())?;

    match target {
        HookTargetKind::ClaudeCode => {
            ensure_array_contains(hooks_obj, "PreToolUse", claude_hook_entry(hook_command))
        }
        HookTargetKind::Gemini => {
            ensure_array_contains(hooks_obj, "BeforeTool", gemini_hook_entry(hook_command))
        }
        HookTargetKind::Cursor => {
            let first = ensure_array_contains(
                hooks_obj,
                "beforeShellExecution",
                cursor_hook_entry(hook_command),
            )?;
            let second =
                ensure_array_contains(hooks_obj, "preToolUse", cursor_hook_entry(hook_command))?;
            if first == MergeOutcome::Added || second == MergeOutcome::Added {
                Ok(MergeOutcome::Added)
            } else {
                Ok(MergeOutcome::AlreadyPresent)
            }
        }
    }
}

fn ensure_array_contains(
    hooks_obj: &mut Map<String, Value>,
    event_key: &str,
    entry: Value,
) -> Result<MergeOutcome, String> {
    if !hooks_obj.contains_key(event_key) {
        hooks_obj.insert(event_key.into(), Value::Array(Vec::new()));
    }
    let arr = hooks_obj
        .get_mut(event_key)
        .and_then(Value::as_array_mut)
        .ok_or_else(|| format!("`hooks.{event_key}` must be a JSON array"))?;

    let already = arr.iter().any(|item| {
        serde_json::to_string(item)
            .unwrap_or_default()
            .contains("grdr-hook")
    });
    if already {
        return Ok(MergeOutcome::AlreadyPresent);
    }
    arr.push(entry);
    Ok(MergeOutcome::Added)
}

fn remove_grdr_entries(root: &mut Value, target: HookTargetKind) -> bool {
    let Some(hooks_obj) = root.get_mut("hooks").and_then(Value::as_object_mut) else {
        return false;
    };
    let keys: &[&str] = match target {
        HookTargetKind::ClaudeCode => &["PreToolUse"],
        HookTargetKind::Gemini => &["BeforeTool"],
        HookTargetKind::Cursor => &["beforeShellExecution", "preToolUse"],
    };
    let mut changed = false;
    for key in keys {
        if let Some(arr) = hooks_obj.get_mut(*key).and_then(Value::as_array_mut) {
            let before = arr.len();
            arr.retain(|item| {
                !serde_json::to_string(item)
                    .unwrap_or_default()
                    .contains("grdr-hook")
            });
            if arr.len() != before {
                changed = true;
            }
        }
    }
    changed
}

fn claude_hook_entry(hook_command: &str) -> Value {
    json!({
        "matcher": "Bash|PowerShell|Read|Write|Edit|MultiEdit|WebFetch|mcp__.*",
        "hooks": [
            {
                "type": "command",
                "command": hook_command,
                "timeout": 2
            }
        ]
    })
}

fn gemini_hook_entry(hook_command: &str) -> Value {
    json!({
        "matcher": ".*",
        "hooks": [
            {
                "name": "guardrails-adr",
                "type": "command",
                "command": format!("{hook_command} --agent gemini"),
                "timeout": 2000
            }
        ]
    })
}

fn cursor_hook_entry(hook_command: &str) -> Value {
    json!({
        "command": format!("{hook_command} --agent cursor")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_merges_without_clobbering_and_uninstall_restores_byte_for_byte() {
        let home = std::env::temp_dir().join(format!("grdr-inst-{}", uuid::Uuid::now_v7()));
        let state_dir = home.join(".local").join("state").join("grdr");
        let claude_dir = home.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();

        let original_raw = "{\n  \"hooks\": {\n    \"PreToolUse\": [\n      {\n        \"matcher\": \"Bash\",\n        \"hooks\": [\n          {\n            \"type\": \"command\",\n            \"command\": \"/opt/other-vendor/bin/check-tool --mode safe\",\n            \"timeout\": 10\n          }\n        ]\n      }\n    ]\n  },\n  \"model\": \"example-model\"\n}\n";
        let settings_path = claude_dir.join("settings.json");
        fs::write(&settings_path, original_raw).unwrap();

        let before_status = hook_status(HookTargetKind::ClaudeCode, &home).unwrap();
        assert_eq!(before_status.state, HookInstallState::NotConfigured);
        assert!(!before_status.installed);

        let dry = install_hook_in_state_dir(
            HookTargetKind::ClaudeCode,
            &home,
            &state_dir,
            "grdr-hook",
            true,
        )
        .unwrap();
        assert_eq!(dry.outcome, InstallOutcome::DryRunPreview);
        assert_eq!(fs::read_to_string(&settings_path).unwrap(), original_raw);

        let applied = install_hook_in_state_dir(
            HookTargetKind::ClaudeCode,
            &home,
            &state_dir,
            "grdr-hook",
            false,
        )
        .unwrap();
        assert_eq!(applied.outcome, InstallOutcome::Applied);
        assert!(applied.journal_path.starts_with(&state_dir));
        assert!(applied.journal_path.is_file());
        assert!(!claude_dir.join(".grdr-backup.json").exists());
        assert!(!claude_dir.join("settings.json.grdr-backup.json").exists());

        let merged_text = fs::read_to_string(&settings_path).unwrap();
        assert!(merged_text.contains("\"/opt/other-vendor/bin/check-tool --mode safe\""));
        assert!(merged_text.contains("\"type\": \"command\""));
        assert!(merged_text.contains("\"model\": \"example-model\""));
        assert!(merged_text.contains("grdr-hook"));

        let after_status = hook_status(HookTargetKind::ClaudeCode, &home).unwrap();
        assert_eq!(after_status.state, HookInstallState::Effective);
        assert!(after_status.installed);

        let second = install_hook_in_state_dir(
            HookTargetKind::ClaudeCode,
            &home,
            &state_dir,
            "grdr-hook",
            false,
        )
        .unwrap();
        assert_eq!(second.outcome, InstallOutcome::AlreadyInstalled);
        assert_eq!(fs::read_to_string(&settings_path).unwrap(), merged_text);

        let removed =
            uninstall_hook_in_state_dir(HookTargetKind::ClaudeCode, &home, &state_dir).unwrap();
        assert_eq!(removed.outcome, InstallOutcome::Applied);
        assert_eq!(fs::read_to_string(&settings_path).unwrap(), original_raw);
        assert!(!applied.journal_path.exists());

        let final_status = hook_status(HookTargetKind::ClaudeCode, &home).unwrap();
        assert_eq!(final_status.state, HookInstallState::NotConfigured);
        assert!(!final_status.installed);

        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn cursor_install_creates_new_file_and_uninstall_cleans_up() {
        let home = std::env::temp_dir().join(format!("grdr-inst-cur-{}", uuid::Uuid::now_v7()));
        let state_dir = home.join(".local").join("state").join("grdr");
        let installed = install_hook_in_state_dir(
            HookTargetKind::Cursor,
            &home,
            &state_dir,
            "grdr-hook",
            false,
        )
        .unwrap();
        assert_eq!(installed.outcome, InstallOutcome::Applied);
        assert!(installed.config_path.is_file());
        assert!(installed.journal_path.starts_with(&state_dir));

        let removed =
            uninstall_hook_in_state_dir(HookTargetKind::Cursor, &home, &state_dir).unwrap();
        assert_eq!(removed.outcome, InstallOutcome::Applied);
        assert!(!installed.config_path.exists());
        assert!(!installed.journal_path.exists());

        let _ = fs::remove_dir_all(&home);
    }
}
