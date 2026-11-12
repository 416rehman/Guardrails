//! Where and how a dispatched session runs: a git worktree under `.agent/worktrees/` on the lease's
//! branch, or for a planner or routine detached at the fetched base tip before each session, with
//! the kit binary and the machine's marketplace entry copied in so the hooks work there, and
//! `kit launch` in print mode as the process. Until the fleet container exists (WI-0006) the
//! worktree and the permission rules are the only isolation.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::config::limits::Limits;
use crate::config::session::IDENTITY_VARIABLES;
use crate::gates::evidence::EVIDENCE_DIR;
use crate::git;
use crate::kit::install::{self, LOCAL_SETTINGS, RECORD_FILE};
use crate::orchestrate::claude::{Running, Watch};
use crate::orchestrate::launch::{LaunchScope, SessionStart};
use crate::process;
use crate::repo::{Repo, walk_files};

const WORKTREES: &str = ".agent/worktrees";
const KIT_DIR: &str = ".agent/kit";
const PROJECT_DIR_VARIABLE: &str = "CLAUDE_PROJECT_DIR";

/// How a worktree gets its kit binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prepare {
    /// Copy the repository's installed kit, or run `kit install` in the worktree when there is none.
    CopyOrInstall,
    /// Copy only; for tests, where the current executable is not the kit.
    CopyOnly,
}

/// The program that starts a session: `xtask kit launch`, or a fake in tests.
#[derive(Debug, Clone)]
pub struct Launcher {
    pub program: PathBuf,
    pub leading: Vec<String>,
    pub prepare: Prepare,
}

/// What one session is for.
#[derive(Debug, Clone)]
pub struct Job<'a> {
    pub agent: &'a str,
    pub item: Option<u64>,
    pub prompt: &'a str,
    pub start: &'a SessionStart,
    pub log: &'a Path,
    /// A model the dispatcher asks for, such as opus for a cross-model review.
    pub model: Option<&'a str>,
    /// An effort the dispatcher asks for, such as low for the light review lane.
    pub effort: Option<&'a str>,
    pub scope: LaunchScope,
}

/// Where new branches start: the base branch on the remote, fetched first, so an item starts from
/// what has landed and not from the dispatcher checkout's own `HEAD`.
#[derive(Debug, Clone, Copy)]
pub struct Upstream<'a> {
    pub remote: &'a str,
    pub base: &'a str,
}

impl Launcher {
    /// This executable's `kit launch`.
    pub fn kit() -> Result<Launcher> {
        Ok(Launcher {
            program: std::env::current_exe().context("finding the kit executable")?,
            leading: vec!["kit".to_owned(), "launch".to_owned()],
            prepare: Prepare::CopyOrInstall,
        })
    }

    pub fn spawn(&self, worktree: &Path, job: &Job, watch: Watch) -> Result<Running> {
        let mut command = Command::new(&self.program);
        command.args(&self.leading).arg(job.agent);
        if let Some(item) = job.item {
            command.args(["--item", &item.to_string()]);
        }
        if job.scope == LaunchScope::Seed {
            command.arg("--seed");
        }
        if let Some(model) = job.model {
            command.args(["--model", model]);
        }
        if let Some(effort) = job.effort {
            command.args(["--effort", effort]);
        }
        command.args(["--print", job.prompt]);
        match job.start {
            SessionStart::New => {}
            SessionStart::Named(id) => {
                command.args(["--session-id", id]);
            }
            SessionStart::Resume(id) => {
                command.args(["--resume", id]);
            }
        }
        command
            .current_dir(worktree)
            .env(PROJECT_DIR_VARIABLE, worktree);
        for name in IDENTITY_VARIABLES {
            command.env_remove(name);
        }
        Running::spawn(command, None, Some(job.log), watch)
    }
}

/// The worktree name of one attempt at an item, which its worker and its evaluators share.
pub fn attempt_worktree(item: u64, attempt: u32) -> String {
    format!("{item}-a{attempt}")
}

/// `.agent/worktrees/<name>`, whether or not it exists yet.
pub fn worktree_dir(repo: &Repo, name: &str) -> PathBuf {
    repo.path(&format!("{WORKTREES}/{name}"))
}

/// `.agent/worktrees/<name>` on `branch`, created from the fetched base tip when the branch is
/// new. A worktree with no branch, a planner's or a routine's, moves to the fetched tip before
/// every session while it has no tracked change, so it never plans or scans an old tree.
pub fn worktree(
    repo: &Repo,
    name: &str,
    branch: Option<&str>,
    launcher: &Launcher,
    upstream: Upstream,
) -> Result<PathBuf> {
    let dir = worktree_dir(repo, name);
    if !dir.join(".git").exists() {
        let Some(base) = start_point(repo, upstream)? else {
            bail!("dispatch needs a commit to branch from; commit the seed first");
        };
        let target = dir.to_string_lossy().into_owned();
        let exists = branch.is_some_and(|b| {
            let reference = format!("refs/heads/{b}");
            git::try_output(repo, &["rev-parse", "--verify", "--quiet", &reference])
                .ok()
                .flatten()
                .is_some()
        });
        let args: Vec<&str> = match branch {
            Some(b) if exists => vec!["worktree", "add", "--quiet", &target, b],
            Some(b) => vec!["worktree", "add", "--quiet", "-b", b, &target, &base],
            None => vec!["worktree", "add", "--quiet", "--detach", &target, &base],
        };
        git::output(repo, &args).with_context(|| format!("creating the worktree {target}"))?;
    } else if branch.is_none() {
        refresh_detached(repo, &dir, upstream)?;
    }
    prepare_worktree(repo, &dir, launcher)?;
    Ok(dir)
}

/// Checks a detached worktree out at the fetched base tip, unless it holds a tracked change.
fn refresh_detached(repo: &Repo, dir: &Path, upstream: Upstream) -> Result<()> {
    let Some(tip) = start_point(repo, upstream)? else {
        return Ok(());
    };
    let worktree = Repo::at(dir);
    let changes = git::output(
        &worktree,
        &["status", "--porcelain", "--untracked-files=no"],
    )?;
    if !changes.trim().is_empty() {
        return Ok(());
    }
    git::output(&worktree, &["checkout", "--detach", "--quiet", &tip])
        .with_context(|| format!("moving {} to {tip}", dir.display()))?;
    Ok(())
}

/// The fetched tip of the base on the remote; the checkout's merge base while it has no remote.
fn start_point(repo: &Repo, upstream: Upstream) -> Result<Option<String>> {
    let Upstream { remote, base } = upstream;
    if git::try_output(repo, &["remote", "get-url", remote])?.is_none() {
        return Ok(git::resolve_base(repo)?.commit().map(str::to_owned));
    }
    git::output(repo, &["fetch", "--quiet", remote, base])
        .with_context(|| format!("fetching {base} from {remote}"))?;
    let tip = git::output(
        repo,
        &[
            "rev-parse",
            "--verify",
            &format!("refs/remotes/{remote}/{base}^{{commit}}"),
        ],
    )?;
    Ok(Some(tip.trim().to_owned()))
}

/// Copies the kit binary and the local settings into a worktree that has no kit yet, or installs
/// the kit there, and makes the evidence directory the evaluators' expectation logs go to. A
/// worktree's own kit is never overwritten: its SessionStart rebuilds it from the worktree's base
/// when it is stale, and the main checkout's copy may be older than that.
pub fn prepare_worktree(repo: &Repo, dir: &Path, launcher: &Launcher) -> Result<()> {
    let worktree = Repo::at(dir);
    let kit = repo.path(KIT_DIR);
    fs::create_dir_all(worktree.path(EVIDENCE_DIR))
        .with_context(|| format!("creating {EVIDENCE_DIR} in {}", dir.display()))?;
    if kit.is_dir() {
        if !has_kit(&worktree) {
            copy_tree(&kit, &worktree.path(KIT_DIR))?;
        }
    } else if launcher.prepare == Prepare::CopyOrInstall {
        let mut command = Command::new(&launcher.program);
        command
            .args(["kit", "install"])
            .current_dir(dir)
            .env(PROJECT_DIR_VARIABLE, dir);
        let timeout = Limits::built_with()?.dispatch.worker.install_timeout();
        let ran = process::run(&mut command, None, timeout)
            .context("running kit install in the worktree")?;
        if !ran.success() {
            bail!(
                "kit install in {} failed: {}",
                dir.display(),
                ran.stderr().trim()
            );
        }
    }
    let settings = repo.path(LOCAL_SETTINGS);
    if settings.is_file() {
        let target = worktree.path(LOCAL_SETTINGS);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(&settings, &target).with_context(|| format!("copying {LOCAL_SETTINGS}"))?;
    }
    Ok(())
}

fn has_kit(worktree: &Repo) -> bool {
    worktree.path(RECORD_FILE).is_file() && install::binary_path(worktree).is_file()
}

/// Each file is placed by rename, which Windows allows over a binary another session is running.
fn copy_tree(from: &Path, to: &Path) -> Result<()> {
    for file in walk_files(from)? {
        let Ok(relative) = file.strip_prefix(from) else {
            continue;
        };
        install::place(&file, &to.join(relative))
            .with_context(|| format!("copying {}", file.display()))?;
    }
    Ok(())
}
