//! `PreCompact`, `ConfigChange` and `SessionEnd` (team/03 section 4.1). PreCompact saves what the
//! session must not lose to `.agent/state/session-<id>.md` and returns compaction instructions.
//! ConfigChange blocks a mid-session change to hooks, permissions or sandbox settings, measured
//! against the digests SessionStart recorded. SessionEnd appends one line to
//! `.agent/learnings.jsonl`.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::PathBuf;

use anyhow::Result;
use serde_json::{Map, Value, json};

use super::context::Context;
use super::handoff;
use super::outcome::Outcome;
use super::state::{SessionState, sha256_hex, summary_path};
use super::transcript;
use crate::clock::Utc;
use crate::config::session::{
    AGENT_VARIABLE, LAUNCHER_MODEL_VARIABLE, SCOPE_VARIABLE, WORK_ITEM_VARIABLE,
};
use crate::gates::evidence::EVIDENCE_DIR;
use crate::kit::claude_config;
use crate::kit::install::LOCAL_SETTINGS;
use crate::kit::settings::SETTINGS_PATH;
use crate::repo::walk_files;

const LEARNINGS: &str = ".agent/learnings.jsonl";
/// The session identity variables the launcher sets for the hooks.
const IDENTITY_VARIABLES: &[&str] = &[
    AGENT_VARIABLE,
    WORK_ITEM_VARIABLE,
    SCOPE_VARIABLE,
    LAUNCHER_MODEL_VARIABLE,
];
/// The settings keys a session may not change under itself.
const GUARDED_KEYS: &[&str] = &[
    "hooks",
    "permissions",
    "sandbox",
    "disableAllHooks",
    "allowManagedHooksOnly",
    "enabledPlugins",
    "env",
    "model",
    "availableModels",
    "extraKnownMarketplaces",
    "apiKeyHelper",
    "statusLine",
];
const SOURCES: &[&str] = &["user_settings", "project_settings", "local_settings"];
const VERIFYING: &[&str] = &[
    "cargo xtask",
    "cargo test",
    "cargo nextest",
    "cargo clippy",
    "pnpm test",
    "pnpm run",
    "npm test",
    "pytest",
    "go test",
];

pub fn pre_compact(context: &Context) -> Result<Outcome> {
    let Some(session) = context.input.session_id() else {
        return Ok(Outcome::Allow);
    };
    let uses = context
        .input
        .path("transcript_path", &context.env)
        .filter(|path| path.is_file())
        .and_then(|path| transcript::tail(&path, context.limits.pre_compact.transcript_bytes).ok())
        .map(|entries| transcript::tool_uses(&entries))
        .unwrap_or_default();
    let listed = context.limits.pre_compact.listed;
    let touched =
        unique(transcript::edited_paths(&uses).iter().map(
            |raw| match context.locate_inside(raw) {
                Some(path) => path.to_string(),
                None => raw.clone(),
            },
        ));
    let commands = unique(
        transcript::shell_commands(&uses)
            .into_iter()
            .filter(|command| {
                VERIFYING
                    .iter()
                    .any(|runner| command.trim_start().starts_with(runner))
            }),
    );
    let plan = uses
        .iter()
        .rev()
        .find(|tool| tool.name == "TodoWrite")
        .and_then(|tool| tool.input.get("todos").and_then(Value::as_array).cloned())
        .unwrap_or_default();
    let item = context.env.get(WORK_ITEM_VARIABLE);
    let agent = context.env.get(AGENT_VARIABLE);
    let decisions = item
        .and_then(|raw| crate::config::session::parse_item_number(raw).ok())
        .zip(agent)
        .and_then(|(number, agent)| {
            context
                .repo
                .read_optional(&handoff::path(number, agent))
                .ok()
                .flatten()
        })
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .and_then(|value| value.get("decisions").and_then(Value::as_array).cloned())
        .unwrap_or_default();
    let evidence = recent_evidence_ids(context);
    let mut text = format!(
        "# Session {session} before compaction ({})\n\n",
        Utc::now().iso()
    );
    if let Some(item) = item {
        text.push_str(&format!("Work item: #{}\n\n", item.trim_start_matches('#')));
    }
    section(
        &mut text,
        "Plan",
        plan.iter().map(|todo| {
            let content = todo
                .get("content")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let status = todo
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or_default();
            format!("[{status}] {content}")
        }),
        listed,
    );
    section(
        &mut text,
        "Decisions",
        decisions.iter().map(|decision| {
            let at = decision
                .get("at")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let choice = decision
                .get("choice")
                .and_then(Value::as_str)
                .unwrap_or_default();
            format!("{at}: {choice}")
        }),
        listed,
    );
    section(&mut text, "Touched files", touched.into_iter(), listed);
    section(
        &mut text,
        "Verifying commands",
        commands.into_iter(),
        listed,
    );
    section(&mut text, "Evidence", evidence.iter().cloned(), listed);
    let path = summary_path(session);
    crate::repo::write_if_changed(&context.repo.path(&path), text.as_bytes())?;
    let ids = if evidence.is_empty() {
        "none yet".to_owned()
    } else {
        evidence.join(", ")
    };
    Ok(Outcome::Context(format!(
        "Keep in the summary: the failing tests and the commands that show them, the invariants and decisions with their reasons, the evidence ids ({ids}), the work item and its write set. The full pre-compaction state is in {path}."
    )))
}

pub fn config_change(context: &Context) -> Result<Outcome> {
    let source = context.input.str("source").unwrap_or_default();
    if !SOURCES.contains(&source) {
        context.note(format!(
            "config change from {source}: not a settings file this hook guards"
        ));
        return Ok(Outcome::Allow);
    }
    let file = context
        .input
        .path("file_path", &context.env)
        .or_else(|| settings_file(context, source));
    let now = digest(
        file.as_ref()
            .and_then(|path| std::fs::read_to_string(path).ok())
            .as_deref(),
    );
    let baseline = match context.input.session_id() {
        Some(session) => {
            SessionState::load(&context.repo, session)?.map(|state| state.settings_baseline)
        }
        None => None,
    };
    let unchanged = baseline.as_ref().and_then(|digests| digests.get(source)) == Some(&now);
    if unchanged {
        return Ok(Outcome::Allow);
    }
    let shown = file.map_or_else(|| source.to_owned(), |path| path.display().to_string());
    context.note(format!(
        "blocked a change to the hooks, permissions or sandbox of {shown}"
    ));
    Ok(Outcome::Block(format!(
        "{shown}: hooks, permissions and sandbox settings do not change mid-session; change the kit sources and run cargo xtask kit render outside the session"
    )))
}

pub fn session_end(context: &Context) -> Result<Outcome> {
    let line = json!({
        "at": Utc::now().iso(),
        "session": context.input.session_id(),
        "agent": context.env.get(AGENT_VARIABLE),
        "item": context.env.get(WORK_ITEM_VARIABLE),
        "reason": context.input.str("reason"),
    });
    let path = context.repo.path(LEARNINGS);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(file, "{line}")?;
    Ok(Outcome::Allow)
}

/// The digest of the guarded keys of each settings file, for SessionStart to record.
pub fn settings_baseline(context: &Context) -> BTreeMap<String, String> {
    SOURCES
        .iter()
        .map(|source| {
            let text =
                settings_file(context, source).and_then(|path| std::fs::read_to_string(path).ok());
            ((*source).to_owned(), digest(text.as_deref()))
        })
        .collect()
}

/// Settings files whose `env` sets a session identity variable: Claude Code applies it
/// to the session and its hooks, so the identity would no longer be the launcher's.
pub fn settings_identity(context: &Context) -> Vec<String> {
    SOURCES
        .iter()
        .filter_map(|source| {
            let path = settings_file(context, source)?;
            let text = std::fs::read_to_string(&path).ok()?;
            let value: Value = serde_json::from_str(&text).ok()?;
            let names: Vec<String> = value
                .get("env")?
                .as_object()?
                .keys()
                .filter(|name| IDENTITY_VARIABLES.contains(&name.to_ascii_uppercase().as_str()))
                .cloned()
                .collect();
            (!names.is_empty())
                .then(|| format!("{} sets {} in `env`", path.display(), names.join(", ")))
        })
        .collect()
}

fn settings_file(context: &Context, source: &str) -> Option<PathBuf> {
    match source {
        "user_settings" => claude_config::user_settings(context.env.lookup()),
        "project_settings" => Some(context.repo.path(SETTINGS_PATH)),
        "local_settings" => Some(context.repo.path(LOCAL_SETTINGS)),
        _ => None,
    }
}

/// SHA-256 of the guarded keys only, so a theme change does not count.
fn digest(text: Option<&str>) -> String {
    let guarded: Map<String, Value> = match text {
        None => Map::new(),
        Some(text) => match serde_json::from_str::<Value>(text) {
            Ok(Value::Object(object)) => object
                .into_iter()
                .filter(|(key, _)| GUARDED_KEYS.contains(&key.as_str()))
                .collect(),
            _ => return sha256_hex(text.as_bytes()),
        },
    };
    sha256_hex(Value::Object(guarded).to_string().as_bytes())
}

fn recent_evidence_ids(context: &Context) -> Vec<String> {
    let mut names: Vec<String> = walk_files(&context.repo.path(EVIDENCE_DIR))
        .unwrap_or_default()
        .into_iter()
        .filter_map(|path| {
            path.file_stem()
                .map(|stem| stem.to_string_lossy().into_owned())
        })
        .collect();
    names.sort();
    names
        .into_iter()
        .rev()
        .take(context.limits.pre_compact.evidence_files)
        .collect()
}

/// Each item once, where it first appears.
fn unique(items: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    for item in items {
        if !seen.contains(&item) {
            seen.push(item);
        }
    }
    seen
}

/// A titled list of the last `limit` lines.
fn section(text: &mut String, title: &str, lines: impl Iterator<Item = String>, limit: usize) {
    let lines: Vec<String> = lines.collect();
    text.push_str(&format!("## {title}\n\n"));
    if lines.is_empty() {
        text.push_str("(none)\n");
    }
    for line in lines.iter().rev().take(limit).rev() {
        text.push_str(&format!("- {line}\n"));
    }
    text.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_covers_only_the_guarded_keys() {
        let base = digest(Some(r#"{"hooks":{"Stop":[]},"theme":"dark"}"#));
        assert_eq!(
            base,
            digest(Some(r#"{"theme":"light","hooks":{"Stop":[]}}"#))
        );
        assert_ne!(base, digest(Some(r#"{"hooks":{}}"#)));
        assert_eq!(digest(None), digest(Some("{}")));
    }
}
