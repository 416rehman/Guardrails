//! `SubagentStart` and `SubagentStop` (team/03 section 4.1). Start injects the write set, the
//! protected paths and the `handoff.v1` contract. Stop checks the subagent's report against what
//! it did: files it says it wrote exist, and every test command it reports is in its transcript.

use std::sync::LazyLock;

use anyhow::{Context as _, Result};
use regex::Regex;
use serde_json::Value;

use super::context::{Context, expand_home};
use super::identity::{Identity, Who};
use super::outcome::Outcome;
use super::transcript;
use crate::config::protected::ProtectedPaths;
use crate::kit::{CHIEF_ARCHITECT, OWNERSHIP_SENTENCE};
use crate::paths::Located;

const HANDOFF_CONTRACT: &str = "End with one handoff.v1 JSON block (skill grdr-handoff): schema, item, agent, model (exact id), status, round, summary naming evidence ids, changed_paths, evidence [{cmd, exit, log, sha256}], decisions [{at, choice, spec_silent, confidence}], next. Claim nothing a command did not show.";
const TEST_RUNNERS: &[&str] = &[
    "cargo test",
    "cargo nextest",
    "cargo xtask",
    "cargo clippy",
    "pnpm test",
    "pnpm run test",
    "npm test",
    "npm run test",
    "yarn test",
    "pytest",
    "go test",
    "vitest",
    "npx vitest",
];

static PATTERNS: LazyLock<Option<Patterns>> = LazyLock::new(|| {
    Some(Patterns {
        claim_sentence: Regex::new(
            r"(?i)\b(created|wrote|written|added|updated|modified|changed|edited|implemented|fixed|new file)\b",
        )
        .ok()?,
        gone_sentence: Regex::new(r"(?i)\b(deleted|removed|renamed|moved)\b").ok()?,
        sentence_end: Regex::new(r"\.\s+|\n").ok()?,
        ticked: Regex::new(r"`([^`\n]+)`").ok()?,
        json_block: Regex::new(r"(?s)```(?:json)?\s*(\{.*?\})\s*```").ok()?,
    })
});

/// What a subagent's report is read with.
struct Patterns {
    claim_sentence: Regex,
    /// A sentence that also reports a deletion or a rename names paths that need not exist.
    gone_sentence: Regex,
    sentence_end: Regex,
    ticked: Regex,
    json_block: Regex,
}

pub fn start(context: &Context) -> Result<Outcome> {
    let mut lines = Vec::new();
    if context.input.agent_type() == Some(CHIEF_ARCHITECT) {
        lines.push(OWNERSHIP_SENTENCE.to_owned());
    }
    let identity = Identity::load(context)?;
    let write_set = match (identity.snapshot(), &identity.who) {
        (Some(snapshot), _) => Some(format!(
            "issue #{}: {}",
            snapshot.number,
            snapshot.write_set.join(", ")
        )),
        (None, Who::Agent { name, agent }) if !agent.write.is_empty() => {
            Some(format!("{name}: {}", agent.write.join(", ")))
        }
        _ => None,
    };
    lines.push(match write_set {
        Some(globs) => format!("Write set ({globs}); nothing else."),
        None => "Write set: none recorded; write only what the task names.".to_owned(),
    });
    let protected = ProtectedPaths::load(&context.repo)?;
    lines.push(format!(
        "Never write these protected paths: {}.",
        protected.paths.join(", ")
    ));
    lines.push(HANDOFF_CONTRACT.to_owned());
    Ok(Outcome::Context(lines.join("\n")))
}

pub fn stop(context: &Context) -> Result<Outcome> {
    let message = context
        .input
        .str("last_assistant_message")
        .unwrap_or_default();
    let ran = match context.input.str("agent_transcript_path") {
        Some(raw) => {
            let path = expand_home(raw, &context.env);
            transcript::tail(&path, context.limits.subagent.transcript_bytes)
                .map(|entries| transcript::shell_commands(&transcript::tool_uses(&entries)))?
        }
        None => Vec::new(),
    };
    let mut problems = Vec::new();
    let patterns = PATTERNS
        .as_ref()
        .context("subagent-stop's report patterns do not compile")?;
    let longest_extension = context.limits.subagent.path_extension_chars;
    for path in claimed_files(message, patterns, longest_extension) {
        let exists = match context.locate(&path) {
            Located::Inside(relative) => context.repo.path(relative.as_str()).exists(),
            Located::Outside(absolute) => std::path::Path::new(&absolute).exists(),
        };
        if !exists {
            problems.push(format!("you report writing `{path}`, which does not exist"));
        }
    }
    let squashed_ran: Vec<String> = ran.iter().map(|command| squash(command)).collect();
    for command in reported_commands(message, patterns) {
        let wanted = squash(&command);
        if !squashed_ran.iter().any(|ran| ran.contains(&wanted)) {
            problems.push(format!("you report running `{command}`, which your transcript does not show; run it or drop the claim"));
        }
    }
    Ok(Outcome::block_if(problems))
}

/// Paths in backticks in a sentence that says they were written.
fn claimed_files(message: &str, patterns: &Patterns, longest_extension: usize) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for sentence in patterns.sentence_end.split(message).filter(|sentence| {
        patterns.claim_sentence.is_match(sentence) && !patterns.gone_sentence.is_match(sentence)
    }) {
        for captures in patterns.ticked.captures_iter(sentence) {
            let Some(candidate) = captures.get(1).map(|found| found.as_str().trim()) else {
                continue;
            };
            if looks_like_path(candidate, longest_extension)
                && !found.iter().any(|known| known == candidate)
            {
                found.push(candidate.to_owned());
            }
        }
    }
    found
}

/// Test commands named in backticks or on their own line.
fn reported_commands(message: &str, patterns: &Patterns) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    let spans = patterns
        .ticked
        .captures_iter(message)
        .filter_map(|captures| captures.get(1).map(|span| span.as_str().to_owned()));
    let lines = message
        .lines()
        .map(|line| line.trim().trim_start_matches(['$', '>', ' ']).to_owned());
    for candidate in spans.chain(lines) {
        let candidate = candidate.trim().to_owned();
        let runs_tests = TEST_RUNNERS
            .iter()
            .any(|runner| candidate.starts_with(runner));
        if runs_tests && !found.contains(&candidate) {
            found.push(candidate);
        }
    }
    for block in patterns.json_block.captures_iter(message) {
        let Some(Ok(value)) = block
            .get(1)
            .map(|json| serde_json::from_str::<Value>(json.as_str()))
        else {
            continue;
        };
        let commands = value
            .get("evidence")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for command in commands
            .iter()
            .filter_map(|entry| entry.get("cmd").and_then(Value::as_str))
        {
            if !found.iter().any(|known| known == command) {
                found.push(command.to_owned());
            }
        }
    }
    found
}

fn looks_like_path(candidate: &str, longest_extension: usize) -> bool {
    let has_separator = candidate.contains('/') || candidate.contains('\\');
    let name = candidate.rsplit(['/', '\\']).next().unwrap_or(candidate);
    let has_extension = name.rsplit_once('.').is_some_and(|(stem, ext)| {
        !stem.is_empty() && !ext.is_empty() && ext.len() <= longest_extension
    });
    has_separator
        && has_extension
        && !candidate.contains(char::is_whitespace)
        && !candidate.contains("://")
}

/// Whitespace collapsed, so a reported command matches the one that ran.
fn squash(command: &str) -> String {
    command.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hook::limits::kit_limits;

    #[test]
    fn claims_and_commands_are_found() {
        let message = "I created `crates/a/src/lib.rs`. I read `docs/x.md`.\nRan `cargo test -p a`.\n$ cargo clippy -p a";
        let patterns = PATTERNS.as_ref().unwrap();
        let longest_extension = kit_limits().subagent.path_extension_chars;
        assert_eq!(
            claimed_files(message, patterns, longest_extension),
            vec!["crates/a/src/lib.rs"]
        );
        assert_eq!(
            reported_commands(message, patterns),
            vec!["cargo test -p a", "cargo clippy -p a"]
        );
        assert!(!looks_like_path("https://x.y/z.md", longest_extension));
    }
}
