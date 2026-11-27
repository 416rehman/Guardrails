// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Dynamic P14 multi-harness hook installer with dry-run diff and journal rollback (`docs/design/07`).

use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use grdr_ports::{LocalFsPort, RegularEntryKind, validate_safe_rel_path};

use crate::catalogue::{AgentCatalogue, AgentManifest};
use crate::install_entries::{
    MAX_CONFIG_BYTES, MergeOutcome, compute_hook_preview, read_existing_regular_config,
    remove_grdr_entries, resolve_hook_manifest, safe_join_home, validate_hook_command,
};
use crate::install_journal::{
    PriorFile, detect_state_dir, read_journal_hook_command, restore_from_journal,
    write_journal_if_absent,
};
use crate::parse::{json_contains_hook_command, read_json};

static EMBEDDED_HOOK_CATALOGUE: OnceLock<Option<AgentCatalogue>> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HookTargetKind(Cow<'static, str>);

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookDryRunDiff {
    pub agent: String,
    pub config_path: PathBuf,
    pub before_content: String,
    pub after_content: String,
    pub added_events: Vec<String>,
    pub changed: bool,
}

impl HookTargetKind {
    #[allow(
        non_upper_case_globals,
        reason = "preserves API compatibility for existing HookTargetKind::ClaudeCode callers while P14 manifests drive targets dynamically"
    )]
    pub const ClaudeCode: Self = Self(Cow::Borrowed("claude-code"));

    #[allow(
        non_upper_case_globals,
        reason = "preserves API compatibility for existing HookTargetKind::Cursor callers"
    )]
    pub const Cursor: Self = Self(Cow::Borrowed("cursor"));

    #[allow(
        non_upper_case_globals,
        reason = "preserves API compatibility for existing HookTargetKind::Gemini callers"
    )]
    pub const Gemini: Self = Self(Cow::Borrowed("gemini-cli"));

    pub fn from_name(raw: &str) -> Result<Self, String> {
        let cat = embedded_catalogue()?;
        Self::from_name_with_catalogue(raw, cat)
    }

    pub fn from_name_with_catalogue(raw: &str, catalogue: &AgentCatalogue) -> Result<Self, String> {
        let normalized = raw.trim().replace('_', "-");
        if let Some(manifest) = catalogue.resolve(&normalized) {
            if manifest.hook.supported {
                return Ok(Self(Cow::Owned(manifest.id.clone())));
            }
            return Err(format!(
                "GRDR-AGENTS-0001: agent `{}` uses adapter `{}` and has no native hook config target",
                manifest.id, manifest.adapter
            ));
        }
        Err(format!(
            "GRDR-AGENTS-0001: unsupported hook install target `{raw}`"
        ))
    }

    #[must_use]
    pub fn from_manifest(manifest: &AgentManifest) -> Self {
        Self(Cow::Owned(manifest.id.clone()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }

    #[must_use]
    pub fn config_path(&self, home_dir: &Path) -> PathBuf {
        if let Ok(cat) = embedded_catalogue()
            && let Some(manifest) = cat.resolve(self.as_str())
            && validate_safe_rel_path(&manifest.hook.config_rel, false, false, false).is_ok()
        {
            return home_dir.join(&manifest.hook.config_rel);
        }
        let slug: String = self
            .as_str()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
            .collect();
        let safe_slug = if slug.is_empty() { "agent" } else { &slug };
        home_dir.join(format!(".{safe_slug}/hooks.json"))
    }

    #[must_use]
    pub fn journal_path(&self, state_dir: &Path) -> PathBuf {
        let slug: String = self
            .as_str()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
            .collect();
        let safe_slug = if slug.is_empty() { "agent" } else { &slug };
        state_dir.join(format!("hook-backup-{safe_slug}.json"))
    }
}

pub fn recorded_hook_command(
    target: &HookTargetKind,
    state_dir: &Path,
    fs: &dyn LocalFsPort,
) -> Result<Option<String>, String> {
    read_journal_hook_command(&target.journal_path(state_dir), fs)
}

pub fn hook_status(
    target: HookTargetKind,
    home_dir: &Path,
    hook_command: &str,
    fs: &dyn LocalFsPort,
) -> Result<HookStatusReport, String> {
    let cat = embedded_catalogue()?;
    hook_status_with_catalogue(&target, home_dir, hook_command, cat, fs)
}

pub fn hook_status_with_catalogue(
    target: &HookTargetKind,
    home_dir: &Path,
    hook_command: &str,
    catalogue: &AgentCatalogue,
    fs: &dyn LocalFsPort,
) -> Result<HookStatusReport, String> {
    validate_hook_command(hook_command)?;
    let manifest = resolve_hook_manifest(target.as_str(), catalogue)?;
    let config_path = safe_join_home(home_dir, &manifest.hook.config_rel)?;
    let mut candidates = vec![config_path.clone()];
    for rel in &manifest.routes.config_paths {
        if !rel.starts_with('$') && rel != &manifest.hook.config_rel && rel.ends_with(".json") {
            candidates.push(safe_join_home(home_dir, rel)?);
        }
    }

    let mut installed = false;
    for path in &candidates {
        match fs.inspect_nofollow(path)? {
            RegularEntryKind::Missing => continue,
            RegularEntryKind::File => {
                let val = read_json(path, fs).map_err(|e| format!("GRDR-AGENTS-0002: {e}"))?;
                if json_contains_hook_command(&val, &manifest.hook.root_key, hook_command) {
                    installed = true;
                    break;
                }
            }
            RegularEntryKind::Dir | RegularEntryKind::UnsafeOrOther => {
                return Err(format!(
                    "GRDR-AGENTS-0002: refusing symlink or non-regular hook config at {}",
                    path.display()
                ));
            }
        }
    }

    let state = if installed {
        HookInstallState::Effective
    } else {
        HookInstallState::NotConfigured
    };

    Ok(HookStatusReport {
        agent: manifest.id.clone(),
        state,
        installed,
        config_path,
    })
}

pub fn dry_run_hook_diff(
    target: &HookTargetKind,
    home_dir: &Path,
    hook_command: &str,
    catalogue: &AgentCatalogue,
    fs: &dyn LocalFsPort,
) -> Result<HookDryRunDiff, String> {
    validate_hook_command(hook_command)?;
    let manifest = resolve_hook_manifest(target.as_str(), catalogue)?;
    let config_path = safe_join_home(home_dir, &manifest.hook.config_rel)?;
    let before_content = read_existing_regular_config(&config_path, fs)?;

    let (merge, after_content, added_events) = compute_hook_preview(
        manifest,
        if before_content.trim().is_empty() {
            None
        } else {
            Some(before_content.as_str())
        },
        &config_path,
        hook_command,
    )?;

    Ok(HookDryRunDiff {
        agent: manifest.id.clone(),
        config_path,
        before_content,
        after_content,
        added_events,
        changed: merge == MergeOutcome::Added,
    })
}

pub fn install_hook(
    target: HookTargetKind,
    home_dir: &Path,
    hook_command: &str,
    dry_run: bool,
    fs: &dyn LocalFsPort,
) -> Result<HookInstallReport, String> {
    let state_dir = detect_state_dir(home_dir);
    install_hook_in_state_dir(target, home_dir, &state_dir, hook_command, dry_run, fs)
}

pub fn install_hook_in_state_dir(
    target: HookTargetKind,
    home_dir: &Path,
    state_dir: &Path,
    hook_command: &str,
    dry_run: bool,
    fs: &dyn LocalFsPort,
) -> Result<HookInstallReport, String> {
    let cat = embedded_catalogue()?;
    install_hook_with_catalogue(&target, home_dir, state_dir, hook_command, dry_run, cat, fs)
}

pub fn install_hook_with_catalogue(
    target: &HookTargetKind,
    home_dir: &Path,
    state_dir: &Path,
    hook_command: &str,
    dry_run: bool,
    catalogue: &AgentCatalogue,
    fs: &dyn LocalFsPort,
) -> Result<HookInstallReport, String> {
    validate_hook_command(hook_command)?;
    let manifest = resolve_hook_manifest(target.as_str(), catalogue)?;
    let config_path = safe_join_home(home_dir, &manifest.hook.config_rel)?;
    let journal_path = HookTargetKind::from_manifest(manifest).journal_path(state_dir);

    let prior = match fs.inspect_nofollow(&config_path)? {
        RegularEntryKind::Missing => {
            fs.check_no_ancestor_symlinks(&config_path)?;
            PriorFile::Absent
        }
        RegularEntryKind::File => {
            PriorFile::Present(fs.read_bounded_regular_string(&config_path, MAX_CONFIG_BYTES)?)
        }
        RegularEntryKind::Dir | RegularEntryKind::UnsafeOrOther => {
            return Err(format!(
                "GRDR-AGENTS-0002: refusing symlink or non-regular file at {}",
                config_path.display()
            ));
        }
    };

    let existing_opt = match &prior {
        PriorFile::Present(raw) if !raw.trim().is_empty() => Some(raw.as_str()),
        _ => None,
    };
    let (merge, preview_json, _) =
        compute_hook_preview(manifest, existing_opt, &config_path, hook_command)?;

    let outcome = match (merge, dry_run) {
        (MergeOutcome::AlreadyPresent, _) => InstallOutcome::AlreadyInstalled,
        (MergeOutcome::Added, true) => InstallOutcome::DryRunPreview,
        (MergeOutcome::Added, false) => {
            let created_journal = write_journal_if_absent(
                &journal_path,
                prior,
                preview_json.as_bytes(),
                hook_command,
                fs,
            )?;
            if let Err(err) = fs.atomic_write_nofollow(&config_path, preview_json.as_bytes(), false)
            {
                if created_journal {
                    let _ = fs.remove_regular_file_nofollow(&journal_path);
                }
                return Err(err);
            }
            InstallOutcome::Applied
        }
    };

    Ok(HookInstallReport {
        agent: manifest.id.clone(),
        config_path,
        journal_path,
        outcome,
        preview_json,
    })
}

pub fn uninstall_hook(
    target: HookTargetKind,
    home_dir: &Path,
    hook_command: Option<&str>,
    fs: &dyn LocalFsPort,
) -> Result<HookInstallReport, String> {
    let state_dir = detect_state_dir(home_dir);
    uninstall_hook_in_state_dir(target, home_dir, &state_dir, hook_command, fs)
}

pub fn uninstall_hook_in_state_dir(
    target: HookTargetKind,
    home_dir: &Path,
    state_dir: &Path,
    hook_command: Option<&str>,
    fs: &dyn LocalFsPort,
) -> Result<HookInstallReport, String> {
    let cat = embedded_catalogue()?;
    uninstall_hook_with_catalogue(&target, home_dir, state_dir, hook_command, cat, fs)
}

pub fn uninstall_hook_with_catalogue(
    target: &HookTargetKind,
    home_dir: &Path,
    state_dir: &Path,
    hook_command: Option<&str>,
    catalogue: &AgentCatalogue,
    fs: &dyn LocalFsPort,
) -> Result<HookInstallReport, String> {
    let manifest = resolve_hook_manifest(target.as_str(), catalogue)?;
    let config_path = safe_join_home(home_dir, &manifest.hook.config_rel)?;
    let journal_path = HookTargetKind::from_manifest(manifest).journal_path(state_dir);

    let restore = restore_from_journal(&journal_path, &config_path, fs)?;
    if let Some(preview_json) = restore.restored_content {
        return Ok(HookInstallReport {
            agent: manifest.id.clone(),
            config_path,
            journal_path,
            outcome: InstallOutcome::Applied,
            preview_json,
        });
    }

    if fs.inspect_nofollow(&config_path)? == RegularEntryKind::Missing {
        return Ok(HookInstallReport {
            agent: manifest.id.clone(),
            config_path,
            journal_path,
            outcome: InstallOutcome::Unchanged,
            preview_json: String::new(),
        });
    }

    let cmd_to_strip = hook_command
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or(restore.recorded_hook_command.as_deref())
        .ok_or_else(|| {
            "GRDR-AGENTS-0001: uninstall requires hook_command when no backup journal records the installed command"
                .to_string()
        })?;
    validate_hook_command(cmd_to_strip)?;

    let raw = read_existing_regular_config(&config_path, fs)?;
    let mut root: Value = serde_json::from_str(&raw)
        .map_err(|e| format!("invalid JSON in {}: {e}", config_path.display()))?;
    let changed = remove_grdr_entries(&mut root, manifest, cmd_to_strip);
    let preview_json = serde_json::to_string_pretty(&root)
        .map_err(|e| format!("failed serializing config: {e}"))?;
    if changed {
        fs.atomic_write_nofollow(&config_path, preview_json.as_bytes(), false)?;
    }

    Ok(HookInstallReport {
        agent: manifest.id.clone(),
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

fn embedded_catalogue() -> Result<&'static AgentCatalogue, String> {
    EMBEDDED_HOOK_CATALOGUE
        .get_or_init(|| AgentCatalogue::embedded().ok())
        .as_ref()
        .ok_or_else(|| "GRDR-AGENTS-0004: embedded agent catalogue failed to parse".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fs::TestLocalFs;
    use std::fs;

    #[test]
    fn install_merges_without_clobbering_and_uninstall_restores_byte_for_byte() {
        let home = std::env::temp_dir().join(format!("grdr-inst-{}", uuid::Uuid::now_v7()));
        let state_dir = home.join(".local").join("state").join("grdr");
        let claude_dir = home.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();

        let original_raw = "{\n  \"hooks\": {\n    \"PreToolUse\": [\n      {\n        \"matcher\": \"Bash\",\n        \"hooks\": [\n          {\n            \"type\": \"command\",\n            \"command\": \"/opt/other-vendor/bin/check-tool --mode safe\",\n            \"timeout\": 10\n          }\n        ]\n      }\n    ]\n  },\n  \"model\": \"example-model\"\n}\n";
        let settings_path = claude_dir.join("settings.json");
        fs::write(&settings_path, original_raw).unwrap();

        let before_status =
            hook_status(HookTargetKind::ClaudeCode, &home, "grdr-hook", &TestLocalFs).unwrap();
        assert_eq!(before_status.state, HookInstallState::NotConfigured);
        assert!(!before_status.installed);

        let dry = install_hook_in_state_dir(
            HookTargetKind::ClaudeCode,
            &home,
            &state_dir,
            "grdr-hook",
            true,
            &TestLocalFs,
        )
        .unwrap();
        assert_eq!(dry.outcome, InstallOutcome::DryRunPreview);
        assert_eq!(fs::read_to_string(&settings_path).unwrap(), original_raw);
        assert!(!dry.journal_path.exists());

        let applied = install_hook_in_state_dir(
            HookTargetKind::ClaudeCode,
            &home,
            &state_dir,
            "grdr-hook",
            false,
            &TestLocalFs,
        )
        .unwrap();
        assert_eq!(applied.outcome, InstallOutcome::Applied);
        let merged = fs::read_to_string(&settings_path).unwrap();
        assert!(merged.contains("check-tool"));
        assert!(merged.contains("grdr-hook"));
        assert!(merged.contains("example-model"));
        assert!(applied.journal_path.starts_with(&state_dir));
        assert!(applied.journal_path.is_file());

        let after_status =
            hook_status(HookTargetKind::ClaudeCode, &home, "grdr-hook", &TestLocalFs).unwrap();
        assert_eq!(after_status.state, HookInstallState::Effective);
        assert!(after_status.installed);

        let again = install_hook_in_state_dir(
            HookTargetKind::ClaudeCode,
            &home,
            &state_dir,
            "grdr-hook",
            false,
            &TestLocalFs,
        )
        .unwrap();
        assert_eq!(again.outcome, InstallOutcome::AlreadyInstalled);

        let removed = uninstall_hook_in_state_dir(
            HookTargetKind::ClaudeCode,
            &home,
            &state_dir,
            None,
            &TestLocalFs,
        )
        .unwrap();
        assert_eq!(removed.outcome, InstallOutcome::Applied);
        assert_eq!(fs::read_to_string(&settings_path).unwrap(), original_raw);
        assert!(!applied.journal_path.exists());

        let final_status =
            hook_status(HookTargetKind::ClaudeCode, &home, "grdr-hook", &TestLocalFs).unwrap();
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
            &TestLocalFs,
        )
        .unwrap();
        assert_eq!(installed.outcome, InstallOutcome::Applied);
        assert!(installed.config_path.is_file());
        assert!(installed.journal_path.starts_with(&state_dir));

        let removed = uninstall_hook_in_state_dir(
            HookTargetKind::Cursor,
            &home,
            &state_dir,
            None,
            &TestLocalFs,
        )
        .unwrap();
        assert_eq!(removed.outcome, InstallOutcome::Applied);
        assert!(!installed.config_path.exists());
        assert!(!installed.journal_path.exists());

        let _ = fs::remove_dir_all(&home);
    }
}
