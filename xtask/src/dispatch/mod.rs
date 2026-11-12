//! `cargo xtask dispatch [--once] [--max-writers N] [--dry-run] [--no-routines]`: the orchestrator
//! of owner instructions 5 to 8 and team/01 section 9. It leases `status:ready` issues of the
//! repository `.agents/harness.toml` names to their agents, runs each worker through `kit launch`
//! in print mode in its own worktree, enforces the turn cap, the stall timeout and the lease,
//! pauses everything at a usage limit without counting an attempt, moves items on by their pull
//! requests and attempts, runs the recurring agents of `.agents/kit/usage.toml`, starts the lead
//! that plans each proposed, escalated or blocked issue, starts the evaluators each issue in
//! review needs, and lands what passed through the merge queue (`merge`). On restart it rebuilds
//! its leases from the issues. `kit claim --next` leases one issue to a person's own session
//! instead; guard-command keeps agent sessions from running either.

pub mod ci_env;
pub mod dispatcher;
pub mod lease;
pub mod merge;
pub mod policy;
pub mod queue;
pub mod routines;
pub mod state;
pub mod worker;

use std::process::ExitCode;

use anyhow::{Context, Result, bail};

use self::dispatcher::Dispatcher;
use self::policy::Policy;
use self::worker::Launcher;
use crate::cli::{self, Spec};
use crate::config::session::{ItemSnapshot, ItemStatus, RiskTier};
use crate::github::{Gh, Mode};
use crate::lock::Lock;
use crate::orchestrate::launch::{self, LaunchKit, owner_step_or};
use crate::orchestrate::tracker::{GhTracker, Tracker};
use crate::repo::Repo;

const LOCK_FILE: &str = ".agent/state/dispatch.lock";
const GOOD_FIRST_ISSUE: &str = "good-first-issue";
const ISOLATION_NOTICE: &str = "dispatch: workers are not yet isolated in the fleet container (WI-0006); each runs on this host in a git worktree under .agent/worktrees/, fenced only by the permission rules and the hooks";
const SPEC: Spec = Spec {
    flags: &["--once", "--dry-run", "--no-routines"],
    options: &["--max-writers"],
};
const CLAIM_SPEC: Spec = Spec {
    flags: &["--next", "--any-tier", "--dry-run"],
    options: &[],
};

pub fn run(_command: &str, args: &[String]) -> Result<ExitCode> {
    let parsed = cli::parse(args, &SPEC)?;
    let max_writers = parsed
        .value("--max-writers")
        .map(|raw| {
            raw.parse::<u32>()
                .with_context(|| format!("--max-writers {raw} is not a number"))
        })
        .transpose()?;
    let repo = Repo::discover()?;
    let mut policy = Policy::load(&repo, max_writers)?;
    if parsed.has("--no-routines") {
        policy.without_routines();
    }
    println!("{ISOLATION_NOTICE}");
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
    let result = if parsed.has("--dry-run") {
        plan_only(repo, policy, &tracker)
    } else {
        let _lock = Lock::take(
            repo.path(LOCK_FILE),
            policy.poll / 2,
            "another dispatcher holds the dispatch lock and it is fresh, so this one stops",
        )?;
        println!(
            "dispatch: at most {} writers and {} routine sessions, stall after {} s",
            policy.max_writers,
            policy.max_gardeners,
            policy.session.stall.as_secs()
        );
        let mut dispatcher = Dispatcher::new(repo, policy, &tracker, Launcher::kit()?)?;
        dispatcher
            .run(parsed.has("--once"))
            .map(|()| ExitCode::SUCCESS)
    };
    result.or_else(owner_step_or)
}

/// `--dry-run`: what the next pass would lease, changing nothing.
fn plan_only(repo: Repo, policy: Policy, tracker: &dyn Tracker) -> Result<ExitCode> {
    let writers = usize::try_from(policy.max_writers).unwrap_or(0);
    let dispatcher = Dispatcher::new(repo, policy, tracker, Launcher::kit()?)?;
    if let Some(seed) = dispatcher.seed_not_handed_off()? {
        println!(
            "dispatch: issue #{seed} is the seed session's own and has no lease.v1 yet, so a live run would refuse to start until the seed hands it off"
        );
    }
    let candidates = dispatcher.candidates(false)?;
    if candidates.is_empty() {
        println!("dispatch: nothing is ready to lease");
    }
    for (index, candidate) in candidates.iter().enumerate() {
        let verb = if index < writers {
            "would lease"
        } else {
            "would wait for a slot:"
        };
        println!(
            "dispatch: {verb} #{} to {}, attempt {}",
            candidate.issue.number, candidate.agent, candidate.attempt
        );
    }
    Ok(ExitCode::SUCCESS)
}

/// `kit claim --next [--any-tier] [--dry-run]`: leases the next eligible issue to the calling
/// person's session (the loop overlay of team/03 section 2): `tier:low` unless `--any-tier`, never
/// `good-first-issue`, and never a trust-core or high-tier item, which needs the opus worker the
/// dispatcher launches. It writes the snapshot and prints the branch to work on; a claim nobody
/// finishes expires after the role's wall clock and goes back to ready.
pub fn claim_command(args: &[String]) -> Result<ExitCode> {
    let parsed = cli::parse(args, &CLAIM_SPEC)?;
    if !parsed.has("--next") {
        bail!("usage: cargo xtask kit claim --next [--any-tier] [--dry-run]");
    }
    let repo = Repo::discover()?;
    let mode = if parsed.has("--dry-run") {
        Mode::DryRun
    } else {
        Mode::Live
    };
    let tracker = GhTracker::new(Gh::for_repo(&repo, mode)?);
    claim(&repo, &tracker, parsed.has("--any-tier")).or_else(owner_step_or)
}

pub fn claim(repo: &Repo, tracker: &dyn Tracker, any_tier: bool) -> Result<ExitCode> {
    let policy = Policy::load(repo, None)?;
    let branch_pattern = policy.clone();
    let dispatcher = Dispatcher::new(repo.clone(), policy, tracker, Launcher::kit()?)?;
    let kit = LaunchKit::load(repo)?;
    let candidates = dispatcher.candidates(true)?;
    let mut chosen = None;
    for candidate in candidates {
        if candidate.issue.has_label(GOOD_FIRST_ISSUE) {
            continue;
        }
        let snapshot = launch::snapshot_of(&candidate.issue, &kit, &candidate.agent)?;
        let opus_only = snapshot.trust_core || snapshot.risk_tier == RiskTier::High;
        if !opus_only && (any_tier || snapshot.risk_tier == RiskTier::Low) {
            chosen = Some((candidate, snapshot));
            break;
        }
    }
    let Some((candidate, snapshot)) = chosen else {
        println!("kit claim: nothing eligible; stop");
        return Ok(ExitCode::SUCCESS);
    };
    let model = kit.choose_model(&candidate.agent, Some(&snapshot))?;
    let branch = branch_pattern.branch_for(candidate.issue.number, candidate.attempt);
    let record = lease::grant(tracker, &candidate, &model, &branch, None)?;
    let saved = ItemSnapshot {
        attempt: record.attempt,
        status: ItemStatus::Leased,
        ..snapshot
    };
    saved.save(repo)?;
    println!(
        "kit claim: leased #{} to {} on {}, attempt {}; work on branch {branch} (git switch -c {branch})",
        record.item, record.agent, record.model, record.attempt
    );
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod assist_tests;
#[cfg(test)]
mod landing_tests;
#[cfg(test)]
mod preflight_tests;
#[cfg(test)]
mod tests;
