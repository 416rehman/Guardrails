//! What a worker's hand-off ships: the agent branch pushed to `origin`, and the pull request
//! opened or updated in the form of owner instruction 27: the title is the branch's first valid
//! Conventional Commit subject, and the body is the evidence template of team/01 section 3 with
//! the line that closes the issue and the writer's `meta.v1` block (harness, model id, attempt).

use std::process::{Command, ExitCode};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde_json::Value;

use crate::config::session::ItemSnapshot;
use crate::git;
use crate::github::{EXIT_OWNER_STEP, Identity, Mode};
use crate::hook::handoff::ARMS;
use crate::orchestrate::form::Form;
use crate::orchestrate::issue::{Issue, tier_name};
use crate::orchestrate::records;
use crate::orchestrate::tracker::{NewPullRequest, Tracker};
use crate::process;
use crate::repo::Repo;

const RISK_EVIDENCE: &str = ".agent/evidence/risk.json";
const NOT_RUN: &str = "not-run";

/// Who wrote the change, for the body's `meta.v1` block.
#[derive(Debug, Clone, Copy)]
pub struct Writer<'a> {
    pub model: &'a str,
    pub attempt: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ship {
    PushOnly,
    PullRequest,
}

/// The branch a hand-off ships.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Branch<'a> {
    /// The item's `agent/<n>/a<attempt>`.
    Item,
    /// One named branch: the seed session's.
    Named(&'a str),
}

/// One hand-off's shipment.
pub(super) struct Shipment<'a> {
    pub form: &'a Form,
    pub issue: &'a Issue,
    pub draft: &'a Value,
    pub writer: Writer<'a>,
    pub mode: Mode,
    pub ship: Ship,
    pub branch: Branch<'a>,
}

/// Pushes the agent branch and, for [`Ship::PullRequest`], opens or updates its pull request.
pub(super) fn ship(repo: &Repo, tracker: &dyn Tracker, shipment: &Shipment) -> Result<ExitCode> {
    let Shipment {
        form,
        issue,
        draft,
        writer,
        mode,
        ship,
        branch: expected,
    } = *shipment;
    let branch = git::current_branch(repo)?.unwrap_or_default();
    let prefix = format!("agent/{}/a", issue.number);
    let (shipped, wanted) = match expected {
        Branch::Item => (branch.starts_with(&prefix), format!("{prefix}<attempt>")),
        Branch::Named(name) => (branch == name, name.to_owned()),
    };
    if !shipped {
        bail!(
            "the hand-off is published, but HEAD is on `{branch}`, not {wanted}; nothing was pushed"
        );
    }
    let identity = Identity::load(repo)?;
    if !push(repo, &identity, &form.remote, &branch, mode)? {
        return Ok(ExitCode::from(EXIT_OWNER_STEP));
    }
    if ship == Ship::PushOnly {
        return Ok(ExitCode::SUCCESS);
    }
    let base = form.base.as_str();
    let open = tracker.open_pull_request(&branch)?;
    let number = open.as_ref().map_or(issue.number, |open| open.number);
    let title = title(repo, form, base, &branch, number)?;
    let body = pull_request_body(repo, form, issue, draft, writer)?;
    let foreign = form.foreign_closes(&body, issue.number);
    if !foreign.is_empty() {
        bail!(
            "the hand-off is published and {branch} is pushed, but no pull request was opened: {}; reword the hand-off's summary and decisions and run kit handoff again",
            foreign.join("; ")
        );
    }
    match open {
        Some(open) => {
            tracker.update_pull_request(open.number, &title, &body)?;
            println!(
                "kit handoff: updated pull request #{} for {branch}",
                open.number
            );
        }
        None => {
            tracker.create_pull_request(&NewPullRequest {
                branch: &branch,
                base,
                title: &title,
                body: &body,
            })?;
            println!("kit handoff: opened the pull request for {branch} against {base}");
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// `git push --set-upstream <remote> <branch>`; false, with the owner step printed, when there is
/// no such remote yet.
fn push(repo: &Repo, identity: &Identity, remote: &str, branch: &str, mode: Mode) -> Result<bool> {
    if git::try_output(repo, &["remote", "get-url", remote])?.is_none() {
        eprintln!("owner step needed: {}", identity.missing_remote(branch));
        return Ok(false);
    }
    if mode == Mode::DryRun {
        println!("dry run: git push --set-upstream {remote} {branch}");
        return Ok(true);
    }
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(repo.root())
        .args(["push", "--set-upstream", remote, branch]);
    let timeout = Duration::from_secs(identity.push_timeout_seconds);
    let ran = process::run(&mut command, None, timeout).context("starting git push")?;
    if !ran.success() {
        bail!("git push {remote} {branch} failed: {}", ran.stderr().trim());
    }
    Ok(true)
}

/// The subject of the branch's first commit that is a valid one-line Conventional Commit and
/// still is once the queue adds the pull request's number; the pull request is not opened without
/// one. A new pull request's number is not known yet, so the issue's, which is smaller, stands in
/// for it and the queue checks the subject that lands.
fn title(repo: &Repo, form: &Form, base: &str, branch: &str, number: u64) -> Result<String> {
    let range = format!("{}..HEAD", fetched_base(repo, form)?);
    let log =
        git::try_output(repo, &["log", "--reverse", "--format=%s", &range])?.unwrap_or_default();
    let subjects: Vec<&str> = log.lines().map(str::trim_end).collect();
    if let Some(valid) = subjects
        .iter()
        .find(|subject| form.landing_problems(subject, number).is_empty())
    {
        return Ok((*valid).to_owned());
    }
    let why = subjects
        .first()
        .map(|first| form.landing_problems(first, number).join("; "))
        .unwrap_or_else(|| format!("{branch} has no commit since {base}"));
    bail!(
        "the hand-off is published and {branch} is pushed, but no pull request was opened: the title must be a commit subject in Conventional Commit form ({why}); amend the commit to one valid line and run kit handoff again"
    )
}

/// The base as last fetched from the remote, else the local branch. Nothing moves a main checkout's
/// local base when changes land, so its range would add their subjects ahead of the branch's own.
fn fetched_base(repo: &Repo, form: &Form) -> Result<String> {
    let fetched = format!("refs/remotes/{}/{}", form.remote, form.base);
    let found = git::try_output(repo, &["rev-parse", "--verify", "--quiet", &fetched])?;
    Ok(found.map_or_else(|| form.base.clone(), |_| fetched))
}

/// The evidence template of team/01 section 3, filled from the draft, with the closing line and
/// the writer's `meta.v1` block.
pub fn pull_request_body(
    repo: &Repo,
    form: &Form,
    issue: &Issue,
    draft: &Value,
    writer: Writer,
) -> Result<String> {
    let snapshot = ItemSnapshot::load(repo, issue.number)?;
    let item = issue.work_item();
    let tier = snapshot
        .as_ref()
        .map(|s| tier_name(s.risk_tier).to_owned())
        .or_else(|| item.tier.map(|t| tier_name(t).to_owned()))
        .unwrap_or_else(|| "unknown".to_owned());
    let reason = risk_reason(repo)?.unwrap_or_else(|| "the issue's tier label".to_owned());
    let text = |key: &str| {
        draft
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let array = |key: &str| {
        draft
            .get(key)
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    };
    let evidence = array("evidence");
    let testing: Vec<String> = evidence.iter().map(evidence_line).collect();
    let three_arm = draft.get("three_arm").map_or_else(
        || "Not a bug fix.".to_owned(),
        |arms| {
            ARMS.iter()
                .map(|arm| {
                    let entry = arms
                        .get(*arm)
                        .and_then(Value::as_u64)
                        .and_then(|i| evidence.get(usize::try_from(i).ok()?));
                    format!(
                        "- {arm}: {}",
                        entry.map_or_else(|| "missing".to_owned(), evidence_line)
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")
        },
    );
    let decisions: Vec<String> = array("decisions").iter().map(decision_line).collect();
    let not_run: Vec<String> = array("acceptance")
        .iter()
        .filter(|entry| entry.get("result").and_then(Value::as_str) == Some(NOT_RUN))
        .filter_map(|entry| {
            entry
                .get("id")
                .and_then(Value::as_str)
                .map(|id| format!("- {id} was not run"))
        })
        .collect();
    let revert = draft.get("revert").and_then(Value::as_str).map_or_else(
        || "`git revert <the squash commit>`".to_owned(),
        |command| format!("`{command}`"),
    );
    let removal = if item.kind.as_deref() == Some("removal") {
        text("next")
    } else {
        "Not a removal.".to_owned()
    };
    let meta = records::meta_block(&form.meta(issue.number, writer.model, writer.attempt))?;
    Ok(format!(
        "Work item: #{n}   Risk tier: {tier} (reason: {reason})\n{closes}\n\n## What changed and why\n{summary}\n\n## Testing (commands and their output, not a claim)\n{testing}\n\n## Three-arm proof (bug fixes): fails on parent | passes on change | fails on revert\n{three_arm}\n\n## Survival tests (removals): test that fails if the removed code remains\n{removal}\n\n## Decisions where the spec was silent, least confident first (the hand-off's decisions list)\n{decisions}\n\n## What was not verified, and why\n{not_run}\n\n## How to revert\n{revert}\n\n{meta}",
        n = issue.number,
        closes = form.closes(issue.number),
        summary = text("summary"),
        testing = or_none(&testing),
        decisions = or_none(&decisions),
        not_run = if not_run.is_empty() {
            "Every acceptance criterion ran.".to_owned()
        } else {
            not_run.join("\n")
        },
    ))
}

fn risk_reason(repo: &Repo) -> Result<Option<String>> {
    let Some(text) = repo.read_optional(RISK_EVIDENCE)? else {
        return Ok(None);
    };
    let value: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    let reasons: Vec<&str> = value
        .get("reasons")
        .and_then(Value::as_array)
        .map(|list| list.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    Ok((!reasons.is_empty()).then(|| format!("cargo xtask risk: {}", reasons.join("; "))))
}

fn evidence_line(entry: &Value) -> String {
    format!(
        "- `{}`: exit {}, log `{}`, sha256 `{}`",
        field_text(entry, "cmd"),
        field_text(entry, "exit"),
        field_text(entry, "log"),
        field_text(entry, "sha256")
    )
}

fn decision_line(entry: &Value) -> String {
    format!(
        "- `{}`: {} (confidence {}, spec silent: {})",
        field_text(entry, "at"),
        field_text(entry, "choice"),
        field_text(entry, "confidence"),
        field_text(entry, "spec_silent")
    )
}

/// A string field as it is, any other value as JSON, a missing one empty.
fn field_text(entry: &Value, key: &str) -> String {
    entry
        .get(key)
        .map(|value| {
            value
                .as_str()
                .map_or_else(|| value.to_string(), str::to_owned)
        })
        .unwrap_or_default()
}

fn or_none(lines: &[String]) -> String {
    if lines.is_empty() {
        "None.".to_owned()
    } else {
        lines.join("\n")
    }
}
