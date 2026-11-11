//! `SessionStart` (team/03 section 4.1, owner instructions 1, 4 and 18). `session-start` (startup,
//! resume, clear, fork) rebuilds a stale kit binary, records the session's baseline, and prints at
//! most `[hook.outcome] context_lines` of context: the chief architect's ownership sentence first
//! on every source, the agent and its model rule, the work item and its issue, the write set, the
//! AGENTS.md files that govern it and the `.agents/kit/path-skills.toml` skills it touches, the
//! protected-path digest, the last failing gate, the sandbox state, and for writers the skills to
//! load before writing code. `session-restore` (compact) re-injects the pre-compact summary.

use std::collections::BTreeSet;
use std::io::Write as _;
use std::process::Command;

use anyhow::Result;

use super::context::Context;
use super::github::GithubSettings;
use super::identity::{self, Identity, Item, Who};
use super::lifecycle::settings_baseline;
use super::model::{self, Verdict};
use super::outcome::Outcome;
use super::path_skills::{self, PATH_SKILLS_FILE, PathSkills, fixed_prefix};
use super::post_bash::{baseline, protected_changes};
use super::startup_model;
use super::state::{SESSION_SCHEMA, SessionState, sha256_hex, summary_path};
use crate::clock::Utc;
use crate::config::protected::{PROTECTED_PATHS_FILE, ProtectedPaths};
use crate::config::session::Scope;
use crate::gates::evidence::{EVIDENCE_DIR, Evidence};
use crate::kit::OWNERSHIP_SENTENCE;
use crate::kit::install;
use crate::repo::{Repo, walk_files};

const ENV_FILE_VARIABLE: &str = "CLAUDE_ENV_FILE";
const AGENTS_FILE: &str = "AGENTS.md";
const TOOLCHAIN_FILE: &str = "rust-toolchain.toml";
const SKILLS_LINE: &str = "Before writing code, load the grdr-structure and cleanup skills (Skill tool: grdr-structure, then cleanup:cleanup).";
/// Parts of a variable name that mark a credential; only names are ever printed.
const CREDENTIAL_MARKS: &[&str] = &[
    "API_KEY",
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PRIVATE_KEY",
    "ACCESS_KEY",
];
/// Credential-looking names the kit itself sets or that carry no secret.
const NOT_CREDENTIALS: &[&str] = &["CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR"];

pub fn start(context: &Context) -> Result<Outcome> {
    let mut lines = Vec::new();
    if identity::is_chief_architect(context) {
        lines.push(OWNERSHIP_SENTENCE.to_owned());
    }
    let identity = match Identity::load(context) {
        Ok(identity) => identity,
        Err(error) => {
            lines.push(format!("Session identity is invalid: {error:#}. Guarded tools are blocked until the launcher fixes it."));
            return Ok(Outcome::Context(lines.join("\n")));
        }
    };
    lines.extend(rebuild(context, &identity));
    lines.extend(credential_warning(context, &identity));
    record(context, &identity);
    lines.extend(who(context, &identity)?);
    lines.extend(item(context, &identity));
    let globs = write_set_globs(&identity);
    lines.extend(write_set(context, globs.as_deref()));
    lines.extend(path_skill_lines(&context.repo, globs.as_deref()));
    lines.push(protected_digest(&context.repo));
    lines.extend(last_failing_gate(&context.repo));
    lines.push(sandbox().to_owned());
    if identity.writes() {
        lines.push(SKILLS_LINE.to_owned());
    }
    write_env_file(context);
    Ok(Outcome::Context(lines.join("\n")))
}

pub fn restore(context: &Context) -> Result<Outcome> {
    let mut lines = Vec::new();
    if identity::is_chief_architect(context) {
        lines.push(OWNERSHIP_SENTENCE.to_owned());
    }
    let summary = context.input.session_id().and_then(|session| {
        context
            .repo
            .read_optional(&summary_path(session))
            .ok()
            .flatten()
    });
    match summary {
        Some(text) => lines.extend(text.lines().take(context.limits.session_start.summary_lines).map(str::to_owned)),
        None => lines.push("No pre-compact summary was saved; rebuild context from the hand-off draft and the issue (skill grdr-start-item).".to_owned()),
    }
    Ok(Outcome::Context(lines.join("\n")))
}

/// Credential-looking variables in an agent session's environment, by name only: every Bash
/// and cargo subprocess of the session inherits them (AGENTS.md: "You hold no secrets").
fn credential_warning(context: &Context, identity: &Identity) -> Option<String> {
    if !identity.is_agent() {
        return None;
    }
    let names: Vec<&str> = context
        .env
        .names()
        .filter(|name| {
            let upper = name.to_ascii_uppercase();
            CREDENTIAL_MARKS.iter().any(|mark| upper.contains(mark))
                && !NOT_CREDENTIALS.contains(&upper.as_str())
        })
        .collect();
    (!names.is_empty()).then(|| {
        format!(
            "WARNING: this agent session's environment holds credential-looking variables ({}); never print or use them. cargo xtask kit launch starts agent sessions with them emptied (harness.toml [launch] scrub_user_env).",
            names.join(", ")
        )
    })
}

/// Rebuilds the kit binary when this is the installed one and its source moved on. An agent
/// session rebuilds only from a merge base: before one exists the source is `HEAD` or the
/// working tree, which hold the agent's own edits, so the hooks would become the agent's.
fn rebuild(context: &Context, identity: &Identity) -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    if !super::context::same_file(&exe, &install::binary_path(&context.repo))
        || install::is_current(&context.repo).unwrap_or(true)
    {
        return None;
    }
    let merge_base = matches!(
        install::source(&context.repo),
        Ok(install::KitSource::MergeBase { .. })
    );
    if identity.is_agent() && !merge_base {
        return Some("Kit: the hook binary is older than the tree, and with no merge base an agent session does not rebuild it; cargo xtask kit install runs outside agent sessions.".to_owned());
    }
    let mut command = Command::new(&exe);
    command
        .args(["kit", "install"])
        .current_dir(context.repo.root());
    let timeout = context
        .remaining()
        .saturating_sub(context.limits.session_start.rebuild_margin());
    let ran = crate::process::run(&mut command, None, timeout).ok()?;
    context.note(format!(
        "kit install: {}\n{}{}",
        ran.describe(),
        ran.stdout(),
        ran.stderr()
    ));
    Some(if ran.success() {
        "Kit: rebuilt the hook binary from the base branch.".to_owned()
    } else {
        format!(
            "Kit: the rebuild failed ({}); the hooks still run the old binary.",
            ran.describe()
        )
    })
}

/// Saves what later handlers compare against; a resumed session keeps its first baseline.
fn record(context: &Context, identity: &Identity) {
    let Some(session) = context.input.session_id() else {
        return;
    };
    let model = context
        .input
        .str("model")
        .map(str::to_owned)
        .or_else(|| startup_model::find(context));
    let existing = SessionState::load(&context.repo, session).ok().flatten();
    let resumed = matches!(context.input.str("source"), Some("resume" | "fork"));
    let transcript_length = context
        .input
        .path("transcript_path", &context.env)
        .and_then(|path| std::fs::metadata(path).ok())
        .map(|meta| meta.len());
    let state = match existing {
        Some(mut state) => {
            if model.is_some() {
                state.model = model;
            }
            if resumed {
                state.resumed_at_byte = transcript_length;
            }
            state
        }
        None => SessionState {
            schema: SESSION_SCHEMA.to_owned(),
            session_id: session.to_owned(),
            started_at: Utc::now().iso(),
            agent: identity.agent().map(str::to_owned),
            work_item: identity.item_number(),
            model,
            start_tree: crate::git::tree_digest(&context.repo).ok(),
            protected_baseline: protected_changes(&context.repo)
                .map(|changes| baseline(&changes))
                .unwrap_or_default(),
            settings_baseline: settings_baseline(context),
            resumed_at_byte: transcript_length.filter(|_| resumed),
        },
    };
    if let Err(error) = state.save(&context.repo) {
        context.note(format!("could not save the session state: {error:#}"));
    }
}

fn who(context: &Context, identity: &Identity) -> Result<Vec<String>> {
    let mut lines = vec![match &identity.who {
        Who::Person => "Session: no agent (a person's session).".to_owned(),
        Who::Agent { name, agent } => format!(
            "Agent: {name} ({:?}, effort {}, roster model {}).",
            agent.group,
            agent.effort.as_str(),
            agent.model
        )
        .to_lowercase(),
        Who::Unknown(name) => format!("Agent: {name}, which is not in the roster."),
    }];
    if let Verdict::Violation(message) = model::check(context, identity)? {
        lines.push(format!(
            "MODEL RULE VIOLATED, tools and prompts are blocked: {message}"
        ));
    }
    match identity.scope() {
        Some(Scope::Seed) => lines.push(
            "Scope: seed; this session may write .agents/kit/seed-scope.toml's paths.".to_owned(),
        ),
        Some(Scope::Protected) => lines.push(
            "Scope: a protected-change lease; the item's write set may include protected paths."
                .to_owned(),
        ),
        None => {}
    }
    Ok(lines)
}

fn item(context: &Context, identity: &Identity) -> Vec<String> {
    let issue = |number: u64| match GithubSettings::load(&context.repo) {
        Ok(github) => format!(
            "Issue: #{number} of {}; read it with gh issue view {number}.",
            github.repository
        ),
        Err(error) => format!("Issue: #{number}; the repository is unknown ({error:#})."),
    };
    match &identity.item {
        Item::None => vec!["Work item: none.".to_owned()],
        Item::Missing(number) => vec![
            format!(
                "Work item: #{number}, but .agent/state/item-{number}.json is missing, so only the protected-path and command rules apply; relaunch with cargo xtask kit launch --item {number}."
            ),
            issue(*number),
        ],
        Item::Snapshot(snapshot) => vec![
            format!(
                "Work item: #{} {} (kind {}, tier {:?}{}, attempt {}).",
                snapshot.number,
                snapshot.title,
                snapshot.kind,
                snapshot.risk_tier,
                if snapshot.trust_core {
                    ", trust core"
                } else {
                    ""
                },
                snapshot.attempt
            ),
            issue(snapshot.number),
            format!("Acceptance digest: sha256:{}", snapshot.acceptance_sha256),
        ],
    }
}

/// The item's write set, or the roster agent's `write` globs without an item.
fn write_set_globs(identity: &Identity) -> Option<Vec<String>> {
    match (identity.snapshot(), &identity.who) {
        (Some(snapshot), _) => Some(snapshot.write_set.clone()),
        (None, Who::Agent { agent, .. }) => Some(agent.write.clone()),
        _ => None,
    }
}

/// The write set, and the AGENTS.md files on the path to each of its directories.
fn write_set(context: &Context, globs: Option<&[String]>) -> Vec<String> {
    let Some(globs) = globs else {
        return Vec::new();
    };
    if globs.is_empty() {
        return vec!["Write set: none; this role writes no repository files.".to_owned()];
    }
    let shown = context.limits.session_start.write_set_lines;
    let mut lines = vec!["Write set:".to_owned()];
    lines.extend(globs.iter().take(shown).map(|glob| format!("  {glob}")));
    if globs.len() > shown {
        lines.push(format!("  ... and {} more", globs.len() - shown));
    }
    let governing = governing_agents_files(&context.repo, globs);
    if !governing.is_empty() {
        lines.push(format!(
            "Principles for this write set: {} (and docs/design/00-decisions.md section 2).",
            governing.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    lines
}

/// The AGENTS.md files in the directories each glob is fixed to, and in every directory above.
fn governing_agents_files(repo: &Repo, globs: &[String]) -> BTreeSet<String> {
    let mut governing = BTreeSet::new();
    for glob in globs {
        let prefix = fixed_prefix(glob);
        let segments: Vec<&str> = prefix.split('/').collect();
        for depth in 0..=segments.len() {
            let dir = segments.get(..depth).unwrap_or_default().join("/");
            let candidate = if dir.is_empty() {
                AGENTS_FILE.to_owned()
            } else {
                format!("{dir}/{AGENTS_FILE}")
            };
            if repo.path(&candidate).is_file() {
                governing.insert(candidate);
            }
        }
    }
    governing
}

/// The skills of every `.agents/kit/path-skills.toml` entry the write set touches, in order.
fn path_skill_lines(repo: &Repo, globs: Option<&[String]>) -> Option<String> {
    let globs = globs.filter(|globs| !globs.is_empty())?;
    let mapping = match PathSkills::load(repo) {
        Ok(mapping) => mapping,
        Err(error) => return Some(format!("{PATH_SKILLS_FILE} cannot be read: {error:#}")),
    };
    let touched = match mapping.touched_by(repo, globs) {
        Ok(touched) => touched,
        Err(error) => return Some(format!("{PATH_SKILLS_FILE} cannot be applied: {error:#}")),
    };
    if touched.is_empty() {
        return None;
    }
    let names: Vec<&str> = touched.iter().map(|entry| entry.name.as_str()).collect();
    Some(format!(
        "Skills for this write set, loaded in order before editing it: {} ({PATH_SKILLS_FILE}: {}).",
        path_skills::skills_of(&touched).join(", "),
        names.join(", ")
    ))
}

fn protected_digest(repo: &Repo) -> String {
    let text = repo
        .read_optional(PROTECTED_PATHS_FILE)
        .ok()
        .flatten()
        .unwrap_or_default();
    let count = ProtectedPaths::load(repo)
        .map(|paths| paths.paths.len())
        .unwrap_or(0);
    format!(
        "Protected paths: {count} globs, sha256:{} ({PROTECTED_PATHS_FILE}); never write them.",
        sha256_hex(text.as_bytes())
    )
}

fn last_failing_gate(repo: &Repo) -> Option<String> {
    let mut files: Vec<_> = walk_files(&repo.path(EVIDENCE_DIR))
        .ok()?
        .into_iter()
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("verify-"))
        })
        .collect();
    files.sort();
    let newest = files.last()?;
    let evidence: Evidence = serde_json::from_str(&std::fs::read_to_string(newest).ok()?).ok()?;
    if evidence.exit_code == 0 {
        return Some(format!("Last verify ({}): green.", evidence.id));
    }
    let failed: Vec<&str> = evidence
        .gates
        .iter()
        .filter(|gate| gate.outcome.failed())
        .map(|gate| gate.id.as_str())
        .collect();
    Some(format!(
        "Last verify ({}) failed: {}.",
        evidence.id,
        failed.join(", ")
    ))
}

fn sandbox() -> &'static str {
    if cfg!(windows) {
        "Sandbox: unavailable on native Windows: request level only."
    } else {
        "Sandbox: as .claude/settings.json configures it (macOS, Linux, WSL2)."
    }
}

/// Toolchain pins for the session's shell, as `export NAME=value` lines.
fn write_env_file(context: &Context) {
    let Some(path) = context.env.get(ENV_FILE_VARIABLE) else {
        return;
    };
    let channel = context
        .repo
        .read_optional(TOOLCHAIN_FILE)
        .ok()
        .flatten()
        .and_then(|text| toml::from_str::<toml::Table>(&text).ok())
        .and_then(|table| {
            table
                .get("toolchain")?
                .get("channel")?
                .as_str()
                .map(str::to_owned)
        });
    let mut text = String::from("export CARGO_TERM_COLOR=never\n");
    if let Some(channel) = channel {
        text.push_str(&format!("export RUSTUP_TOOLCHAIN={channel}\n"));
    }
    let written = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .and_then(|mut file| file.write_all(text.as_bytes()));
    if let Err(error) = written {
        context.note(format!("could not write {ENV_FILE_VARIABLE}: {error}"));
    }
}
