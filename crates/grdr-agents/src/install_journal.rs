// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "content", rename_all = "snake_case")]
pub(crate) enum PriorFile {
    Absent,
    Present(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct HookBackupJournal {
    pub(crate) prior: PriorFile,
}

pub fn detect_state_dir(home_dir: &Path) -> PathBuf {
    let local_app_data = std::env::var_os("LOCALAPPDATA");
    let xdg_state_home = std::env::var_os("XDG_STATE_HOME");
    resolve_state_dir(
        home_dir,
        cfg!(windows),
        local_app_data.as_deref(),
        xdg_state_home.as_deref(),
    )
}

pub(crate) fn resolve_state_dir(
    home_dir: &Path,
    is_windows: bool,
    local_app_data: Option<&OsStr>,
    xdg_state_home: Option<&OsStr>,
) -> PathBuf {
    if is_windows {
        if let Some(dir) = local_app_data
            && !dir.is_empty()
        {
            return PathBuf::from(dir).join("grdr").join("state");
        }
        return home_dir
            .join("AppData")
            .join("Local")
            .join("grdr")
            .join("state");
    }

    if let Some(dir) = xdg_state_home
        && !dir.is_empty()
    {
        return PathBuf::from(dir).join("grdr");
    }
    home_dir.join(".local").join("state").join("grdr")
}

pub(crate) fn write_journal_if_absent(journal_path: &Path, prior: PriorFile) -> Result<(), String> {
    if journal_path.is_file() {
        return Ok(());
    }
    let journal = HookBackupJournal { prior };
    let journal_bytes = serde_json::to_vec_pretty(&journal)
        .map_err(|e| format!("failed serializing backup journal: {e}"))?;
    atomic_write(journal_path, &journal_bytes)
}

pub(crate) fn restore_from_journal(
    journal_path: &Path,
    config_path: &Path,
) -> Result<Option<String>, String> {
    if !journal_path.is_file() {
        return Ok(None);
    }
    let raw_journal = fs::read_to_string(journal_path)
        .map_err(|e| format!("failed reading journal {}: {e}", journal_path.display()))?;
    let journal: HookBackupJournal = serde_json::from_str(&raw_journal)
        .map_err(|e| format!("corrupt backup journal {}: {e}", journal_path.display()))?;

    let preview_json = match journal.prior {
        PriorFile::Present(original) => {
            atomic_write(config_path, original.as_bytes())?;
            original
        }
        PriorFile::Absent => {
            if config_path.is_file() {
                let _ = fs::remove_file(config_path);
            }
            String::new()
        }
    };
    let _ = fs::remove_file(journal_path);
    Ok(Some(preview_json))
}

pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
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
    fn state_dir_resolution_respects_os_and_xdg_or_localappdata() {
        let home = PathBuf::from("/home/alice");
        assert_eq!(
            resolve_state_dir(&home, false, None, None),
            PathBuf::from("/home/alice/.local/state/grdr")
        );
        assert_eq!(
            resolve_state_dir(
                &home,
                false,
                None,
                Some(OsStr::new("/tmp/custom-xdg-state"))
            ),
            PathBuf::from("/tmp/custom-xdg-state/grdr")
        );

        let win_home = PathBuf::from("C:/Users/alice");
        assert_eq!(
            resolve_state_dir(
                &win_home,
                true,
                Some(OsStr::new("C:/Users/alice/AppData/Local")),
                Some(OsStr::new("C:/Users/alice/.local/state")),
            ),
            PathBuf::from("C:/Users/alice/AppData/Local/grdr/state")
        );
    }
}
