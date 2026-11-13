//! The merge queue (owner instructions 7, 8 and 27; team/05 section 15): deterministic software
//! that lands a pull request with no person. The dispatcher's review pass hands it every pull
//! request whose lane's evaluators passed (none in the static lane); the queue lands it once the
//! title and body are valid, CI is green where it runs, the item used no more than its review
//! rounds, and the kit binary's full verify is green on the exact tree that lands: the pull
//! request squashed onto the current base tip in `.agent/worktrees/<[queue] worktree>`. It
//! squash-merges with the subject `<title> (#<pr>)` and an empty body, bound to the verified
//! head, and closes the issue. The kit binary is the one `kit install` built from the base, so a
//! change never verifies itself with its own gates. The verify runs as the lease's writer:
//! `GRDR_AGENT` and `GRDR_WORK_ITEM` name it, `GRDR_SCOPE` is the lease's scope (protected for a
//! protected-change lease, seed for the seed session's), and the item's snapshot is in the queue
//! worktree, so gate V05 judges the tree that lands as that agent's change (owner instruction 7).
//! `cargo xtask queue` runs these passes alone.

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use super::dispatcher::Dispatcher;
use super::policy::Policy;
use super::worker::{self, Launcher};
use crate::cli::{self, Spec};
use crate::clock::Utc;
use crate::config::session::{
    AGENT_VARIABLE, IDENTITY_VARIABLES, ItemSnapshot, SCOPE_VARIABLE, Scope, WORK_ITEM_VARIABLE,
};
use crate::git;
use crate::github::{Gh, Mode};
use crate::kit::install;
use crate::lock::Lock;
use crate::orchestrate::issue::Issue;
use crate::orchestrate::launch::{self, HARNESS_FILE, LaunchKit, LaunchScope, owner_step_or};
use crate::orchestrate::records::{self, Lease};
use crate::orchestrate::tracker::{CheckRollup, CheckState, GhTracker, PullRequest};
use crate::repo::Repo;

mod preparing;
pub use preparing::Preparing;

const SPEC: Spec = Spec {
    flags: &["--once", "--dry-run"],
    options: &[],
};

/// `.agents/harness.toml [queue]`.
#[derive(Debug, Clone, Deserialize)]
struct QueueFile {
    queue: QueueTable,
}

#[derive(Debug, Clone, Deserialize)]
struct QueueTable {
    worktree: String,
    verify_args: Vec<String>,
    verify_timeout_seconds: u64,
}

/// How the queue verifies: the program and arguments, where, and for how long.
#[derive(Debug, Clone)]
pub struct QueueConfig {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub worktree: String,
    pub timeout: Duration,
}

/// What CI says of a pull request's head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Checks {
    Green,
    Waiting(Vec<String>),
    Failed(Vec<String>),
}

/// The tree that would land: the pull request's head squashed onto the base tip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tree {
    pub pr: u64,
    pub item: u64,
    pub head: String,
    pub base: String,
    pub base_tip: String,
}

/// The lease whose change the queue verifies: its item's snapshot, and the scope it widens.
#[derive(Debug, Clone)]
pub struct Writer {
    pub snapshot: ItemSnapshot,
    pub scope: Option<Scope>,
}

/// A full verify of one tree, running in the queue's worktree.
pub struct Verifying {
    pub tree: Tree,
    pub log: PathBuf,
    child: Child,
    started: Instant,
    timeout: Duration,
}

pub enum Prepared {
    Started(Box<Verifying>),
    /// The pull request does not apply to the base tip; the detail is git's.
    Conflict(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verified {
    Running,
    Passed,
    Failed(String),
}

impl QueueConfig {
    pub fn load(repo: &Repo) -> Result<QueueConfig> {
        let text = repo
            .read_optional(HARNESS_FILE)?
            .with_context(|| format!("{HARNESS_FILE} is missing"))?;
        let file: QueueFile = crate::config::parse_toml(&text, HARNESS_FILE)
            .with_context(|| format!("reading [queue] in {HARNESS_FILE}"))?;
        Ok(QueueConfig {
            program: install::binary_path(repo),
            args: file.queue.verify_args,
            worktree: file.queue.worktree,
            timeout: Duration::from_secs(file.queue.verify_timeout_seconds),
        })
    }
}

impl Writer {
    /// The writer of `lease`'s change: its item's snapshot, with the seed scope for the seed
    /// session's lease and the protected scope for a protected-change lease whose write set is
    /// still the one it was readied with. An issue that names another agent than its lease is an
    /// error, so the change is never judged as a third identity.
    pub fn of(kit: &LaunchKit, issue: &Issue, lease: &Lease) -> Result<Writer> {
        let snapshot = launch::snapshot_of(issue, kit, &lease.agent)?;
        if snapshot.agent != lease.agent {
            bail!(
                "issue #{}'s agent changed since its lease: the lease names {}, the issue {}",
                issue.number,
                lease.agent,
                snapshot.agent
            );
        }
        let readied = records::write_set_readied(&records::records(issue), &issue.work_item());
        let scope = match kit.scope_of(lease) {
            LaunchScope::Seed => Some(Scope::Seed),
            LaunchScope::Ordinary if readied => kit
                .is_protected_change(&lease.agent, &snapshot.write_set)?
                .then_some(Scope::Protected),
            LaunchScope::Ordinary => None,
        };
        Ok(Writer { snapshot, scope })
    }
}

impl Verifying {
    /// Whether the verify ended; a run past its timeout is killed and fails.
    pub fn poll(&mut self) -> Verified {
        match self.child.try_wait() {
            Ok(Some(status)) if status.success() => Verified::Passed,
            Ok(Some(status)) => Verified::Failed(format!(
                "verify exited {}; its output is in {}",
                status
                    .code()
                    .map_or_else(|| "by signal".to_owned(), |code| code.to_string()),
                self.log.display()
            )),
            Ok(None) if self.started.elapsed() >= self.timeout => {
                self.stop();
                Verified::Failed(format!(
                    "verify ran past {} s; its output is in {}",
                    self.timeout.as_secs(),
                    self.log.display()
                ))
            }
            Ok(None) => Verified::Running,
            Err(error) => Verified::Failed(format!("waiting for verify: {error}")),
        }
    }

    pub fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// CI's view of the head: green when every check finished green, including when none runs.
pub fn rollup(checks: &[CheckRollup]) -> Checks {
    let named = |state: CheckState| -> Vec<String> {
        checks
            .iter()
            .filter(|check| check.state() == state)
            .map(|check| check.label().to_owned())
            .collect()
    };
    let failed = named(CheckState::Failed);
    if !failed.is_empty() {
        return Checks::Failed(failed);
    }
    let waiting = named(CheckState::Waiting);
    if waiting.is_empty() {
        Checks::Green
    } else {
        Checks::Waiting(waiting)
    }
}

/// Fetches the base and the pull request's branch from `remote` and returns the base tip.
pub fn fetch(repo: &Repo, remote: &str, base: &str, branch: &str) -> Result<String> {
    if git::try_output(repo, &["remote", "get-url", remote])?.is_none() {
        bail!("the checkout has no {remote} remote to land through");
    }
    git::output(repo, &["fetch", "--quiet", remote, base, branch])
        .with_context(|| format!("fetching {base} and {branch} from {remote}"))?;
    let tip = git::output(
        repo,
        &[
            "rev-parse",
            "--verify",
            &format!("refs/remotes/{remote}/{base}^{{commit}}"),
        ],
    )?;
    Ok(tip.trim().to_owned())
}

/// Squashes the head onto the base tip in the queue's worktree and starts the verify there, as
/// `writer`.
pub fn start(repo: &Repo, config: &QueueConfig, tree: &Tree, writer: &Writer) -> Result<Prepared> {
    if !config.program.is_file() {
        bail!(
            "{} is missing; run cargo xtask kit install so the queue verifies with the base's gates",
            config.program.display()
        );
    }
    let dir = worker::worktree_dir(repo, &config.worktree);
    if dir.join(".git").exists() {
        let worktree = Repo::at(&dir);
        git::output(&worktree, &["reset", "--hard", "--quiet", &tree.base_tip])?;
        git::output(&worktree, &["clean", "-d", "--force", "--quiet"])?;
    } else {
        let target = dir.to_string_lossy().into_owned();
        git::output(
            repo,
            &[
                "worktree",
                "add",
                "--quiet",
                "--detach",
                &target,
                &tree.base_tip,
            ],
        )
        .with_context(|| format!("creating the queue worktree {target}"))?;
    }
    let worktree = Repo::at(&dir);
    let merged = git::try_output(
        &worktree,
        &["merge", "--squash", "--no-commit", "--quiet", &tree.head],
    )?;
    if merged.is_none() {
        let conflicted = git::try_output(&worktree, &["diff", "--name-only", "--diff-filter=U"])?
            .unwrap_or_default();
        git::output(&worktree, &["reset", "--hard", "--quiet", &tree.base_tip])?;
        let files: Vec<&str> = conflicted.lines().collect();
        return Ok(Prepared::Conflict(format!(
            "squashing {} onto {} conflicts in {}",
            tree.head,
            tree.base_tip,
            if files.is_empty() {
                "the tree".to_owned()
            } else {
                files.join(", ")
            }
        )));
    }
    let log = repo.path(&format!(
        ".agent/logs/queue-{}-{}.log",
        tree.pr,
        Utc::now().compact()
    ));
    if let Some(parent) = log.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    let out = File::create(&log).with_context(|| format!("creating {}", log.display()))?;
    let err = out.try_clone()?;
    writer.snapshot.save(&worktree)?;
    let mut command = verify_command(config, &dir, tree, writer);
    command.stdout(out).stderr(err);
    let child = command
        .spawn()
        .with_context(|| format!("starting {}", config.program.display()))?;
    Ok(Prepared::Started(Box::new(Verifying {
        tree: tree.clone(),
        log,
        child,
        started: Instant::now(),
        timeout: config.timeout,
    })))
}

/// The verify of `tree` in `dir` as `writer`'s session: its agent and item, and the protected
/// scope for a protected-change lease; every other identity variable is removed.
fn verify_command(config: &QueueConfig, dir: &Path, tree: &Tree, writer: &Writer) -> Command {
    let mut command = Command::new(&config.program);
    command
        .args(&config.args)
        .args(["--base", &tree.base_tip])
        .current_dir(dir)
        .stdin(Stdio::null());
    for name in IDENTITY_VARIABLES {
        command.env_remove(name);
    }
    command
        .env(AGENT_VARIABLE, &writer.snapshot.agent)
        .env(WORK_ITEM_VARIABLE, writer.snapshot.number.to_string());
    if let Some(scope) = writer.scope {
        command.env(SCOPE_VARIABLE, scope.name());
    }
    command
}

/// The open pull request for `branch`, when it is the one the queue would land.
pub fn landable(request: &PullRequest) -> Option<&PullRequest> {
    (!request.draft && !request.head.is_empty()).then_some(request)
}

/// `cargo xtask queue [--once] [--dry-run]`: the review pass's landing alone, with no session
/// started, under the dispatch lock so it never runs beside a dispatcher.
pub fn command(args: &[String]) -> Result<ExitCode> {
    let parsed = cli::parse(args, &SPEC)?;
    let repo = Repo::discover()?;
    let mut policy = Policy::load(&repo, Some(0))?;
    policy.without_routines();
    let mode = if parsed.has("--dry-run") {
        Mode::DryRun
    } else {
        Mode::Live
    };
    let gh = Gh::for_repo(&repo, mode)?;
    if let Err(error) = gh.preflight() {
        return Ok(crate::github::report(&error));
    }
    let tracker = GhTracker::new(gh);
    let _lock = Lock::take(
        repo.path(super::LOCK_FILE),
        policy.poll / 2,
        "a dispatcher holds the dispatch lock; it runs the merge queue itself",
    )?;
    let result = Dispatcher::new(repo, policy, &tracker, Launcher::kit()?)
        .and_then(|mut dispatcher| dispatcher.run_queue(parsed.has("--once")));
    result.map(|()| ExitCode::SUCCESS).or_else(owner_step_or)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(name: &str, status: &str, conclusion: &str) -> CheckRollup {
        CheckRollup {
            name: name.into(),
            status: status.into(),
            conclusion: conclusion.into(),
            ..CheckRollup::default()
        }
    }

    #[test]
    fn ci_is_green_only_when_every_check_finished_green() {
        assert_eq!(rollup(&[]), Checks::Green);
        assert_eq!(
            rollup(&[check("verify", "COMPLETED", "SUCCESS")]),
            Checks::Green
        );
        assert_eq!(
            rollup(&[
                check("verify", "COMPLETED", "SUCCESS"),
                check("matrix", "IN_PROGRESS", "")
            ]),
            Checks::Waiting(vec!["matrix".into()])
        );
        assert_eq!(
            rollup(&[
                check("matrix", "IN_PROGRESS", ""),
                check("codeql", "COMPLETED", "FAILURE")
            ]),
            Checks::Failed(vec!["codeql".into()])
        );
    }

    #[test]
    fn the_verify_runs_as_the_leases_writer() {
        let config = QueueConfig {
            program: PathBuf::from("xtask"),
            args: vec!["verify".into()],
            worktree: "queue".into(),
            timeout: Duration::from_secs(1),
        };
        let tree = Tree {
            pr: 70,
            item: 7,
            head: "abc".into(),
            base: "main".into(),
            base_tip: "def".into(),
        };
        let snapshot: ItemSnapshot = serde_json::from_value(serde_json::json!({
            "schema": "item-snapshot.v1", "number": 7, "title": "[WI-0003] Gates",
            "agent": "lead-agent-kit", "kind": "gate", "squad": null, "size": null,
            "risk_tier": "high", "trust_core": true, "write_set": ["xtask/src/hook/**"],
            "status": "in-review", "acceptance_sha256": "ab", "attempt": 1,
            "fetched_at": "2026-11-11T10:00:00Z"
        }))
        .unwrap();
        let env = |scope: Option<Scope>| {
            let writer = Writer {
                snapshot: snapshot.clone(),
                scope,
            };
            let command = verify_command(&config, Path::new("."), &tree, &writer);
            command
                .get_envs()
                .map(|(name, value)| {
                    let shown = value.map(|v| v.to_string_lossy().into_owned());
                    (name.to_string_lossy().into_owned(), shown)
                })
                .collect::<std::collections::BTreeMap<_, _>>()
        };
        let ordinary = env(None);
        assert_eq!(ordinary[AGENT_VARIABLE].as_deref(), Some("lead-agent-kit"));
        assert_eq!(ordinary[WORK_ITEM_VARIABLE].as_deref(), Some("7"));
        assert_eq!(ordinary[SCOPE_VARIABLE], None);
        let protected = env(Some(Scope::Protected));
        assert_eq!(protected[SCOPE_VARIABLE].as_deref(), Some("protected"));
        assert_eq!(
            env(Some(Scope::Seed))[SCOPE_VARIABLE].as_deref(),
            Some("seed")
        );
    }

    #[test]
    fn drafts_and_unknown_heads_are_not_landable() {
        let request = PullRequest {
            number: 3,
            head: "abc".into(),
            ..PullRequest::default()
        };
        assert!(landable(&request).is_some());
        let draft = PullRequest {
            draft: true,
            ..request.clone()
        };
        assert!(landable(&draft).is_none());
        let unknown = PullRequest {
            head: String::new(),
            ..request
        };
        assert!(landable(&unknown).is_none());
    }
}
