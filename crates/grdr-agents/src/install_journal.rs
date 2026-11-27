// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Hook configuration backup journal with tamper-checked non-destructive restore (`docs/design/07`).

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use grdr_crypto::{Sha256Hasher, encode_lower_hex};
use grdr_ports::{LocalFsPort, RegularEntryKind};
use serde::{Deserialize, Serialize};

const MAX_JOURNAL_BYTES: u64 = 1_048_576;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "content", rename_all = "snake_case")]
pub(crate) enum PriorFile {
    Absent,
    Present(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct HookBackupJournal {
    pub(crate) prior: PriorFile,
    #[serde(default)]
    pub(crate) post_install_sha256: Option<String>,
    #[serde(default)]
    pub(crate) hook_command: Option<String>,
}

pub(crate) struct JournalRestoreOutcome {
    pub(crate) restored_content: Option<String>,
    pub(crate) recorded_hook_command: Option<String>,
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

pub(crate) fn write_journal_if_absent(
    journal_path: &Path,
    prior: PriorFile,
    post_install_bytes: &[u8],
    hook_command: &str,
    fs: &dyn LocalFsPort,
) -> Result<bool, String> {
    fs.check_no_ancestor_symlinks(journal_path)?;
    match fs.inspect_nofollow(journal_path)? {
        RegularEntryKind::File => return Ok(false),
        RegularEntryKind::Missing => {}
        RegularEntryKind::Dir | RegularEntryKind::UnsafeOrOther => {
            return Err(format!(
                "refusing symlink or non-regular backup journal at {}",
                journal_path.display()
            ));
        }
    }
    let journal = HookBackupJournal {
        prior,
        post_install_sha256: Some(sha256_hex(post_install_bytes)),
        hook_command: Some(hook_command.to_owned()),
    };
    let journal_bytes = serde_json::to_vec_pretty(&journal)
        .map_err(|e| format!("failed serializing backup journal: {e}"))?;
    fs.atomic_write_nofollow(journal_path, &journal_bytes, true)?;
    Ok(true)
}

pub(crate) fn read_journal_hook_command(
    journal_path: &Path,
    fs: &dyn LocalFsPort,
) -> Result<Option<String>, String> {
    fs.check_no_ancestor_symlinks(journal_path)?;
    match fs.inspect_nofollow(journal_path)? {
        RegularEntryKind::Missing => return Ok(None),
        RegularEntryKind::File => {}
        RegularEntryKind::Dir | RegularEntryKind::UnsafeOrOther => {
            return Err(format!(
                "refusing symlink or non-regular backup journal at {}",
                journal_path.display()
            ));
        }
    }
    let raw_journal = fs.read_bounded_regular_string(journal_path, MAX_JOURNAL_BYTES)?;
    let journal: HookBackupJournal = serde_json::from_str(&raw_journal)
        .map_err(|e| format!("corrupt backup journal {}: {e}", journal_path.display()))?;
    Ok(journal.hook_command.filter(|s| !s.trim().is_empty()))
}

pub(crate) fn restore_from_journal(
    journal_path: &Path,
    config_path: &Path,
    fs: &dyn LocalFsPort,
) -> Result<JournalRestoreOutcome, String> {
    fs.check_no_ancestor_symlinks(journal_path)?;
    match fs.inspect_nofollow(journal_path)? {
        RegularEntryKind::Missing => {
            return Ok(JournalRestoreOutcome {
                restored_content: None,
                recorded_hook_command: None,
            });
        }
        RegularEntryKind::File => {}
        RegularEntryKind::Dir | RegularEntryKind::UnsafeOrOther => {
            return Err(format!(
                "refusing symlink or non-regular backup journal at {}",
                journal_path.display()
            ));
        }
    }
    let raw_journal = fs.read_bounded_regular_string(journal_path, MAX_JOURNAL_BYTES)?;
    let journal: HookBackupJournal = serde_json::from_str(&raw_journal)
        .map_err(|e| format!("corrupt backup journal {}: {e}", journal_path.display()))?;

    if let Some(expected_sha) = journal.post_install_sha256.as_deref() {
        let current_matches = match fs.inspect_nofollow(config_path)? {
            RegularEntryKind::File => {
                let current_bytes =
                    fs.read_bounded_regular_bytes(config_path, MAX_JOURNAL_BYTES)?;
                sha256_hex(&current_bytes) == expected_sha
            }
            RegularEntryKind::Missing => false,
            RegularEntryKind::Dir | RegularEntryKind::UnsafeOrOther => {
                return Err(format!(
                    "refusing symlink or non-regular config at {}",
                    config_path.display()
                ));
            }
        };
        if !current_matches {
            fs.remove_regular_file_nofollow(journal_path)?;
            return Ok(JournalRestoreOutcome {
                restored_content: None,
                recorded_hook_command: journal.hook_command.filter(|s| !s.trim().is_empty()),
            });
        }
    }

    let preview_json = match journal.prior {
        PriorFile::Present(original) => {
            fs.atomic_write_nofollow(config_path, original.as_bytes(), false)?;
            original
        }
        PriorFile::Absent => {
            fs.remove_regular_file_nofollow(config_path)?;
            String::new()
        }
    };
    fs.remove_regular_file_nofollow(journal_path)?;
    Ok(JournalRestoreOutcome {
        restored_content: Some(preview_json),
        recorded_hook_command: journal.hook_command.filter(|s| !s.trim().is_empty()),
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256Hasher::new();
    hasher.update(bytes);
    encode_lower_hex(&hasher.finalize_digest())
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
