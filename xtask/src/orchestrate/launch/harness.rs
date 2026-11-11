//! What `kit launch` reads from `.agents/harness.toml`: single values and lists of its tables,
//! and the Claude Code executable that `[launch] claude` and `claude_locations` lead to.

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

use anyhow::{Result, bail};

use super::CLAUDE_VARIABLE;
use crate::git::{self, Base};
use crate::process;
use crate::repo::Repo;

pub const HARNESS_FILE: &str = ".agents/harness.toml";

/// The Claude Code executable: the one `GRDR_CLAUDE` names, else `[launch] claude` found on
/// `PATH` by [`process::find_on_path`], else the first of `[launch] claude_locations` that exists.
/// An explicit `GRDR_CLAUDE` wins so a test's fake can never be passed over for a real install.
pub fn claude_program(repo: &Repo) -> Result<PathBuf> {
    let lookup = |name: &str| std::env::var_os(name).filter(|value| !value.is_empty());
    claude_from(repo, lookup)
}

pub fn claude_from(repo: &Repo, lookup: impl Fn(&str) -> Option<OsString>) -> Result<PathBuf> {
    if let Some(named) = lookup(CLAUDE_VARIABLE) {
        return Ok(PathBuf::from(named));
    }
    let Some(name) = harness_text(repo, "launch", "claude")? else {
        bail!("{HARNESS_FILE} [launch] claude names no executable");
    };
    let path = lookup("PATH");
    let extensions = lookup("PATHEXT");
    if let Some(found) = process::find_on_path(&name, path.as_deref(), extensions.as_deref()) {
        return Ok(found);
    }
    let home = lookup("HOME").or_else(|| lookup("USERPROFILE"));
    let located = harness_list(repo, "launch", "claude_locations")?
        .unwrap_or_default()
        .iter()
        .filter_map(|pattern| expand_location(pattern, home.as_deref()))
        .find(|candidate| candidate.is_file());
    Ok(located.unwrap_or_else(|| PathBuf::from(name)))
}

/// `{home}` and `{exe}` filled in; a pattern that needs a home directory there is none for is
/// skipped.
fn expand_location(pattern: &str, home: Option<&OsStr>) -> Option<PathBuf> {
    let with_home = if pattern.contains("{home}") {
        let home = home?.to_string_lossy().replace('\\', "/");
        pattern.replace("{home}", home.trim_end_matches('/'))
    } else {
        pattern.to_owned()
    };
    Some(PathBuf::from(
        with_home.replace("{exe}", std::env::consts::EXE_SUFFIX),
    ))
}

/// A string, or a boolean as `true` or `false`, from a table of `.agents/harness.toml`.
pub(super) fn harness_text(repo: &Repo, table: &str, key: &str) -> Result<Option<String>> {
    Ok(
        harness_value(repo, table, key)?.and_then(|value| match value {
            toml::Value::String(text) => Some(text),
            toml::Value::Boolean(flag) => Some(flag.to_string()),
            _ => None,
        }),
    )
}

/// A list of strings from a table of `.agents/harness.toml`, `None` when absent.
pub(super) fn harness_list(repo: &Repo, table: &str, key: &str) -> Result<Option<Vec<String>>> {
    Ok(harness_value(repo, table, key)?.and_then(strings))
}

/// [`harness_list`] from the copy at `base` ([`git::read_at`]), with the label of that copy.
pub(super) fn harness_list_at(
    repo: &Repo,
    base: &Base,
    table: &str,
    key: &str,
) -> Result<(Option<Vec<String>>, String)> {
    let (text, source) = git::read_at(repo, base, HARNESS_FILE)?;
    let list = match text {
        Some(text) => table_value(&text, &source, table, key)?.and_then(strings),
        None => None,
    };
    Ok((list, source))
}

fn harness_value(repo: &Repo, table: &str, key: &str) -> Result<Option<toml::Value>> {
    let Some(text) = repo.read_optional(HARNESS_FILE)? else {
        return Ok(None);
    };
    table_value(&text, HARNESS_FILE, table, key)
}

/// `key` of `table` in the harness file `text`, read from `source`.
fn table_value(text: &str, source: &str, table: &str, key: &str) -> Result<Option<toml::Value>> {
    let parsed: toml::Table = crate::config::parse_toml(text, source)?;
    Ok(parsed
        .get(table)
        .and_then(|section| section.get(key))
        .cloned())
}

fn strings(value: toml::Value) -> Option<Vec<String>> {
    value.as_array().map(|items| {
        items
            .iter()
            .filter_map(toml::Value::as_str)
            .map(str::to_owned)
            .collect()
    })
}
