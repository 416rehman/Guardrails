//! The change `cargo xtask risk` classifies: every changed file against the base, with its added
//! and removed lines and both versions.

use std::collections::BTreeMap;

use anyhow::Result;

use crate::git::{self, Base};
use crate::repo::Repo;

/// One changed file and what the diff shows of it.
#[derive(Debug, Clone, Default)]
pub struct FileChange {
    pub path: String,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub before: Option<String>,
    pub after: Option<String>,
}

/// Every changed file against `base` with its added and removed lines and both versions.
pub fn changes(repo: &Repo, base: &Base) -> Result<Vec<FileChange>> {
    let paths = git::changed_files(repo, base)?;
    let mut lines = match base.commit() {
        Some(commit) => parse_diff(&git::output(
            repo,
            &[
                "-c",
                "core.quotepath=off",
                "diff",
                "-U0",
                "--no-color",
                "--no-ext-diff",
                "--no-renames",
                commit,
                "--",
            ],
        )?),
        None => BTreeMap::new(),
    };
    let mut changes = Vec::new();
    for path in paths {
        let path = path.as_str().to_owned();
        let before = match base.commit() {
            Some(commit) => git::show(repo, commit, &path)?,
            None => None,
        };
        let after = std::fs::read(repo.path(&path))
            .ok()
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned());
        let (added, removed) = match lines.remove(&path) {
            Some(found) => found,
            None => (
                after
                    .as_deref()
                    .map(|t| t.lines().map(str::to_owned).collect())
                    .unwrap_or_default(),
                Vec::new(),
            ),
        };
        changes.push(FileChange {
            path,
            added,
            removed,
            before,
            after,
        });
    }
    Ok(changes)
}

/// Added and removed lines per file from a zero-context diff.
pub fn parse_diff(diff: &str) -> BTreeMap<String, (Vec<String>, Vec<String>)> {
    let mut files: BTreeMap<String, (Vec<String>, Vec<String>)> = BTreeMap::new();
    let mut minus: Option<String> = None;
    let mut current: Option<String> = None;
    let mut header = false;
    for line in diff.lines() {
        if line.starts_with("diff --git ") {
            header = true;
            continue;
        }
        if line.starts_with("@@") {
            header = false;
            continue;
        }
        if header {
            if let Some(path) = line.strip_prefix("--- ") {
                minus = path.strip_prefix("a/").map(str::to_owned);
            } else if let Some(path) = line.strip_prefix("+++ ") {
                current = path
                    .strip_prefix("b/")
                    .map(str::to_owned)
                    .or_else(|| minus.clone());
            }
            continue;
        }
        let Some(path) = &current else { continue };
        let entry = files.entry(path.clone()).or_default();
        if let Some(text) = line.strip_prefix('+') {
            entry.0.push(text.to_owned());
        } else if let Some(text) = line.strip_prefix('-') {
            entry.1.push(text.to_owned());
        }
    }
    files
}
