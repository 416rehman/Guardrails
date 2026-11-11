//! Per-session state the hooks keep under `.agent/state/` (git-ignored): what `SessionStart` saw,
//! which the later handlers compare against, and the Stop gate's round counter. Agents cannot
//! write these files: `guard-path` and `guard-command` deny them.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::repo::{Repo, write_if_changed};

pub const STATE_DIR: &str = ".agent/state";
pub const SESSION_SCHEMA: &str = "hook-session.v1";
pub const SKILLS_SCHEMA: &str = "path-skills.v1";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionState {
    pub schema: String,
    pub session_id: String,
    pub started_at: String,
    pub agent: Option<String>,
    pub work_item: Option<u64>,
    /// The model SessionStart named, or the one the session was started on (`startup_model`).
    pub model: Option<String>,
    /// [`crate::git::tree_digest`] when the session started.
    pub start_tree: Option<String>,
    /// SHA-256 of each protected path that already differed from `HEAD` at session start.
    #[serde(default)]
    pub protected_baseline: BTreeMap<String, String>,
    /// SHA-256 of the hooks, permissions and sandbox keys of each settings file at session start.
    #[serde(default)]
    pub settings_baseline: BTreeMap<String, String>,
    /// The transcript's length when the session was last resumed or forked: assistant messages
    /// before it ran on the model the session had before, so `model` wins until a newer one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resumed_at_byte: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StopCounter {
    pub digest: String,
    pub blocks: u32,
}

/// The `.agents/kit/path-skills.toml` entries guard-path has named to a session, and the skills
/// stop-gate found the session loaded.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillsState {
    pub schema: String,
    #[serde(default)]
    pub announced: BTreeSet<String>,
    #[serde(default)]
    pub loaded: BTreeSet<String>,
}

impl SessionState {
    pub fn path(session_id: &str) -> String {
        format!("{STATE_DIR}/session-{}.json", safe_id(session_id))
    }

    pub fn load(repo: &Repo, session_id: &str) -> Result<Option<SessionState>> {
        read_json(repo, &SessionState::path(session_id))
    }

    pub fn save(&self, repo: &Repo) -> Result<()> {
        write_json(repo, &SessionState::path(&self.session_id), self)
    }
}

impl StopCounter {
    pub fn path(session_id: &str) -> String {
        format!("{STATE_DIR}/stop-{}.json", safe_id(session_id))
    }

    pub fn load(repo: &Repo, session_id: &str) -> StopCounter {
        read_json(repo, &StopCounter::path(session_id))
            .ok()
            .flatten()
            .unwrap_or_default()
    }

    pub fn save(&self, repo: &Repo, session_id: &str) -> Result<()> {
        write_json(repo, &StopCounter::path(session_id), self)
    }

    /// Blocks recorded on `digest` before this one.
    pub fn blocks_on(&self, digest: &str) -> u32 {
        if self.digest == digest {
            self.blocks
        } else {
            0
        }
    }
}

impl SkillsState {
    pub fn path(session_id: &str) -> String {
        format!("{STATE_DIR}/skills-{}.json", safe_id(session_id))
    }

    pub fn load(repo: &Repo, session_id: &str) -> Result<SkillsState> {
        Ok(
            read_json(repo, &SkillsState::path(session_id))?.unwrap_or_else(|| SkillsState {
                schema: SKILLS_SCHEMA.to_owned(),
                ..SkillsState::default()
            }),
        )
    }

    pub fn save(&self, repo: &Repo, session_id: &str) -> Result<()> {
        write_json(repo, &SkillsState::path(session_id), self)
    }
}

/// The state file of the pre-compact summary for a session.
pub fn summary_path(session_id: &str) -> String {
    format!("{STATE_DIR}/session-{}.md", safe_id(session_id))
}

/// A session id usable in a file name: letters, digits, `-` and `_` no longer than its digest,
/// else the digest.
pub fn safe_id(id: &str) -> String {
    let digest = sha256_hex(id.as_bytes());
    let plain = !id.is_empty()
        && id.len() <= digest.len()
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if plain { id.to_owned() } else { digest }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn read_json<T: for<'de> Deserialize<'de>>(repo: &Repo, relative: &str) -> Result<Option<T>> {
    let Some(text) = repo.read_optional(relative)? else {
        return Ok(None);
    };
    serde_json::from_str(&text)
        .with_context(|| format!("parsing {relative}"))
        .map(Some)
}

pub fn write_json<T: Serialize>(repo: &Repo, relative: &str, value: &T) -> Result<()> {
    let mut text = serde_json::to_string_pretty(value)?;
    text.push('\n');
    write_if_changed(&repo.path(relative), text.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_ids_become_safe_file_names() {
        assert_eq!(safe_id("6f1c-aa_9"), "6f1c-aa_9");
        let odd = safe_id("../../etc/passwd");
        assert_eq!(odd.len(), sha256_hex(b"").len());
        assert!(odd.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(safe_id(""), safe_id(""));
    }

    #[test]
    fn counter_counts_only_its_digest() {
        let counter = StopCounter {
            digest: "a".into(),
            blocks: 2,
        };
        assert_eq!(counter.blocks_on("a"), 2);
        assert_eq!(counter.blocks_on("b"), 0);
    }
}
