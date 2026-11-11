//! `cargo xtask audit run <id> [--dry-run] [--diff <base>] [--commit <sha>] [--arm power|control]
//! [--trigger <name>]` (team/04 sections 2 and 3, `audits/README.md`): the read-only power-prompt
//! pipeline. The prompt is the shared preamble filled for the run plus the prompt's concept; the
//! find pass runs `claude -p` on the library's finder model in a fresh worktree of the commit with
//! read tools and one writable output; the runner checks the report and every evidence span; each
//! surviving result goes to a refuting verifier in a new session on the verifier model (Opus), and
//! a severity 1 result to a second one; the run record lands in `.agent/audits/<run>/run.json`.
//! `--diff <base>` limits the scope to the files changed since `base`, which the `review`
//! workflow uses for A01. The prove step and the ledger repositories come later (team/04 work items).

mod check;
mod job;
mod library;
mod runner;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

use self::job::{Job, Totals, report, with_skip};
use self::library::Entry;
pub use self::runner::Runner;
use super::ids;
use crate::cli::{self, Spec};
use crate::config::limits::Limits;
use crate::config::models::Models;
use crate::dispatch::worker::{Launcher, prepare_worktree};
use crate::git;
use crate::globs::{Case, GlobList};
use crate::repo::{Repo, write_if_changed};

const OUT_DIR: &str = ".agent/audit-out";
const RUNS_DIR: &str = ".agent/audits";
const SPEC: Spec = Spec {
    flags: &["--dry-run"],
    options: &["--diff", "--commit", "--arm", "--trigger"],
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditArm {
    Power,
    Control,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    Repo,
    Diff { base: String, files: Vec<String> },
}

/// What `audit run` was asked for.
#[derive(Debug, Clone)]
pub struct Request {
    pub id: String,
    pub diff: Option<String>,
    pub commit: Option<String>,
    pub arm: AuditArm,
    pub trigger: String,
}

impl Scope {
    /// The scope in words for the prompts, naming at most `named` changed files.
    fn describe(&self, named: usize) -> String {
        match self {
            Scope::Repo => "the whole repository".to_owned(),
            Scope::Diff { base, files } => {
                let shown: Vec<&str> = files.iter().take(named).map(String::as_str).collect();
                let more = files.len().saturating_sub(shown.len());
                let tail = if more > 0 {
                    format!(" and {more} more")
                } else {
                    String::new()
                };
                format!(
                    "the changes since {} in {}{tail}",
                    short(base),
                    shown.join(", ")
                )
            }
        }
    }

    fn record(&self) -> Value {
        match self {
            Scope::Repo => json!({"kind": "repo", "name": "repo"}),
            Scope::Diff { base, .. } => {
                json!({"kind": "diff", "name": format!("diff/{}", short(base)), "base": base})
            }
        }
    }
}

/// `audit`.
pub fn command(args: &[String]) -> Result<ExitCode> {
    let parsed = cli::parse(args, &SPEC)?;
    let (Some("run"), Some(id)) = (
        parsed.positional.first().map(String::as_str),
        parsed.positional.get(1),
    ) else {
        bail!(
            "usage: cargo xtask audit run <id> [--dry-run] [--diff <base>] [--commit <sha>] [--arm power|control] [--trigger <name>]"
        );
    };
    let arm = match parsed.value("--arm") {
        None | Some("power") => AuditArm::Power,
        Some("control") => AuditArm::Control,
        Some(other) => bail!("--arm {other}: power or control"),
    };
    let request = Request {
        id: id.clone(),
        diff: parsed.value("--diff").map(str::to_owned),
        commit: parsed.value("--commit").map(str::to_owned),
        arm,
        trigger: parsed.value("--trigger").unwrap_or("manual").to_owned(),
    };
    let repo = Repo::discover()?;
    let runner = Runner::from_kit(&repo)?;
    run(&repo, &runner, &request, parsed.has("--dry-run"))
}

pub fn run(repo: &Repo, runner: &Runner, request: &Request, dry_run: bool) -> Result<ExitCode> {
    let models = Models::load(repo)?;
    let library_base = git::resolve_base(repo)?;
    let entry = Entry::load(repo, &library_base, &models, &request.id)?;
    let commit = match &request.commit {
        Some(commit) => commit.clone(),
        None => git::head(repo)?.context("audit run needs a commit; commit the seed first")?,
    };
    let run_id = ids::run_id();
    let scope = scope(repo, &entry, request.diff.as_deref())?;
    let job = Job {
        repo,
        runner,
        entry: &entry,
        request,
        scope_text: scope.describe(Limits::built_with()?.orchestrate.audit.scope_files_named),
        scope,
        run_dir: repo.path(&format!("{RUNS_DIR}/{run_id}")),
        run_id,
        commit,
    };
    if let Scope::Diff { files, .. } = &job.scope
        && files.is_empty()
    {
        let record = with_skip(
            job.run_record(&Totals::default(), Vec::new(), &[]),
            &entry.id,
            "scope-absent",
            "no changed file matches the prompt's paths",
        );
        write_json(&job.run_dir.join("run.json"), &record)?;
        println!(
            "audit {}: skipped, no changed file matches its paths; record {RUNS_DIR}/{}/run.json",
            entry.id, job.run_id
        );
        return Ok(ExitCode::SUCCESS);
    }
    let finder_prompt = job.finder_prompt();
    if dry_run {
        println!(
            "audit {}: dry run of {} on {} at {}; finder {} for at most {} turns, verifier {}",
            entry.id,
            job.run_id,
            job.scope_text,
            job.commit,
            entry.finder_model,
            entry.finder_turns,
            entry.verifier_model
        );
        println!("{finder_prompt}");
        return Ok(ExitCode::SUCCESS);
    }
    let started = Instant::now();
    let worktree = audit_worktree(repo, &job.run_id, &job.commit, runner)?;
    let outcome = job.passes(&worktree, &finder_prompt);
    let _ = git::try_output(
        repo,
        &["worktree", "remove", "--force", &worktree.to_string_lossy()],
    );
    let (mut totals, records, sound) = outcome?;
    totals.duration = started.elapsed();
    let upheld = records.iter().filter(|r| r["state"] == "upheld").count();
    write_json(
        &job.run_dir.join("run.json"),
        &job.run_record(&totals, records.clone(), &sound),
    )?;
    report(&entry, &records);
    println!(
        "audit {}: {} returned, {} after the span check, {upheld} upheld; record {RUNS_DIR}/{}/run.json",
        entry.id, totals.returned, totals.after_spans, job.run_id
    );
    let blocks = matches!(job.scope, Scope::Diff { .. }) && entry.blocking.is_some() && upheld > 0;
    Ok(if blocks {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    })
}

fn scope(repo: &Repo, entry: &Entry, diff: Option<&str>) -> Result<Scope> {
    let Some(reference) = diff else {
        return Ok(Scope::Repo);
    };
    let base = git::base_for(repo, Some(reference))?;
    let Some(commit) = base.commit().map(str::to_owned) else {
        bail!("--diff {reference} does not name a commit");
    };
    let paths = GlobList::new(&entry.paths, Case::Sensitive)?;
    let files = git::changed_files(repo, &base)?
        .into_iter()
        .map(|path| path.as_str().to_owned())
        .filter(|path| paths.is_empty() || paths.is_match(path))
        .collect();
    Ok(Scope::Diff {
        base: commit,
        files,
    })
}

fn audit_worktree(repo: &Repo, run_id: &str, commit: &str, runner: &Runner) -> Result<PathBuf> {
    let dir = repo.path(&format!(".agent/worktrees/audit-{run_id}"));
    let target = dir.to_string_lossy().into_owned();
    git::output(
        repo,
        &["worktree", "add", "--quiet", "--detach", &target, commit],
    )
    .context("creating the audit worktree")?;
    let launcher = Launcher {
        program: std::env::current_exe()?,
        leading: Vec::new(),
        prepare: runner.prepare,
    };
    prepare_worktree(repo, &dir, &launcher)?;
    std::fs::create_dir_all(dir.join(OUT_DIR))?;
    Ok(dir)
}

fn write_json(path: &Path, value: &Value) -> Result<()> {
    let mut text = serde_json::to_string_pretty(value)?;
    text.push('\n');
    write_text(path, &text)
}

fn write_text(path: &Path, text: &str) -> Result<()> {
    write_if_changed(path, text.as_bytes())?;
    Ok(())
}

fn short(commit: &str) -> &str {
    commit.get(..12).unwrap_or(commit)
}

#[cfg(test)]
mod tests;
