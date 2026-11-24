// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookInstallReport {
    pub agent: String,
    pub config_path: PathBuf,
    pub journal_path: PathBuf,
    pub outcome: InstallOutcome,
    pub preview_json: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "content", rename_all = "snake_case")]
enum PriorFile {
    Absent,
    Present(String),
}

#[derive(Debug, Serialize, Deserialize)]
struct HookBackupJournal {
    prior: PriorFile,
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

    pub fn journal_path(self, home_dir: &Path) -> PathBuf {
        let cfg = self.config_path(home_dir);
        let name = cfg
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("settings.json");
        cfg.with_file_name(format!("{name}.grdr-backup.json"))
    }
}

pub fn install_hook(
    target: HookTargetKind,
    home_dir: &Path,
    hook_command: &str,
    dry_run: bool,
) -> Result<HookInstallReport, String> {
    let config_path = target.config_path(home_dir);
    let journal_path = target.journal_path(home_dir);
    let prior = if config_path.is_file() {
        PriorFile::Present(
            fs::read_to_string(&config_path)
                .map_err(|e| format!("failed reading {}: {e}", config_path.display()))?,
        )
    } else {
        PriorFile::Absent
    };

    let mut root: Value = match &prior {
        PriorFile::Present(raw) if !raw.trim().is_empty() => serde_json::from_str(raw)
            .map_err(|e| format!("invalid JSON in {}: {e}", config_path.display()))?,
        _ => Value::Object(Map::new()),
    };

    let merge = merge_hook_entry(&mut root, target, hook_command)?;
    let preview_json = serde_json::to_string_pretty(&root)
        .map_err(|e| format!("failed serializing merged hook config: {e}"))?;

    let outcome = match (merge, dry_run) {
        (MergeOutcome::AlreadyPresent, _) => InstallOutcome::AlreadyInstalled,
        (MergeOutcome::Added, true) => InstallOutcome::DryRunPreview,
        (MergeOutcome::Added, false) => {
            if !journal_path.is_file() {
                let journal = HookBackupJournal { prior };
                let journal_bytes = serde_json::to_vec_pretty(&journal)
                    .map_err(|e| format!("failed serializing backup journal: {e}"))?;
                atomic_write(&journal_path, &journal_bytes)?;
            }
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
    let config_path = target.config_path(home_dir);
    let journal_path = target.journal_path(home_dir);

    if journal_path.is_file() {
        let raw_journal = fs::read_to_string(&journal_path)
            .map_err(|e| format!("failed reading journal {}: {e}", journal_path.display()))?;
        let journal: HookBackupJournal = serde_json::from_str(&raw_journal)
            .map_err(|e| format!("corrupt backup journal {}: {e}", journal_path.display()))?;

        let preview_json = match journal.prior {
            PriorFile::Present(original) => {
                atomic_write(&config_path, original.as_bytes())?;
                original
            }
            PriorFile::Absent => {
                if config_path.is_file() {
                    let _ = fs::remove_file(&config_path);
                }
                String::new()
            }
        };
        let _ = fs::remove_file(&journal_path);
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

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed creating {}: {e}", parent.display()))?;
    }
    let tmp = path.with_extension("grdr.tmp");
    fs::write(&tmp, bytes).map_err(|e| format!("failed writing {}: {e}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|e| format!("failed committing {}: {e}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_merges_without_clobbering_and_uninstall_restores_byte_for_byte() {
        let home = std::env::temp_dir().join(format!("grdr-inst-{}", uuid::Uuid::now_v7()));
        let claude_dir = home.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();

        let original_raw = "{\n  \"theme\": \"dark\",\n  \"hooks\": {\n    \"PreToolUse\": [\n      { \"matcher\": \"CustomTool\", \"hooks\": [{ \"type\": \"command\", \"command\": \"my-user-hook\" }] }\n    ]\n  }\n}\n";
        let settings_path = claude_dir.join("settings.json");
        fs::write(&settings_path, original_raw).unwrap();

        let dry = install_hook(HookTargetKind::ClaudeCode, &home, "grdr-hook", true).unwrap();
        assert_eq!(dry.outcome, InstallOutcome::DryRunPreview);
        assert_eq!(fs::read_to_string(&settings_path).unwrap(), original_raw);

        let applied = install_hook(HookTargetKind::ClaudeCode, &home, "grdr-hook", false).unwrap();
        assert_eq!(applied.outcome, InstallOutcome::Applied);

        let merged_text = fs::read_to_string(&settings_path).unwrap();
        assert!(merged_text.contains("my-user-hook"));
        assert!(merged_text.contains("grdr-hook"));
        assert!(merged_text.contains("\"theme\": \"dark\""));

        let second = install_hook(HookTargetKind::ClaudeCode, &home, "grdr-hook", false).unwrap();
        assert_eq!(second.outcome, InstallOutcome::AlreadyInstalled);

        let removed = uninstall_hook(HookTargetKind::ClaudeCode, &home).unwrap();
        assert_eq!(removed.outcome, InstallOutcome::Applied);
        assert_eq!(fs::read_to_string(&settings_path).unwrap(), original_raw);
        assert!(!applied.journal_path.exists());

        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn cursor_install_creates_new_file_and_uninstall_cleans_up() {
        let home = std::env::temp_dir().join(format!("grdr-inst-cur-{}", uuid::Uuid::now_v7()));
        let installed = install_hook(HookTargetKind::Cursor, &home, "grdr-hook", false).unwrap();
        assert_eq!(installed.outcome, InstallOutcome::Applied);
        assert!(installed.config_path.is_file());

        let removed = uninstall_hook(HookTargetKind::Cursor, &home).unwrap();
        assert_eq!(removed.outcome, InstallOutcome::Applied);
        assert!(!installed.config_path.exists());
        assert!(!installed.journal_path.exists());

        let _ = fs::remove_dir_all(&home);
    }
}
