//! `cargo xtask kit ci-env --pull-request <n> --snapshot-into <checkout>`: the session identity CI
//! runs a pull request's gates as, the one the merge queue's verify runs it as ([`Writer::of`]).
//! The newest `lease.v1` on an issue the pull request closes, when it names the pull request's
//! head branch, gives `GRDR_AGENT`, `GRDR_WORK_ITEM` and `GRDR_SCOPE`, printed one `NAME=value`
//! line each for `$GITHUB_ENV`, and the item's snapshot, saved into the change's checkout as the
//! queue saves it into its worktree, so gate V05 judges the lease's write set. A pull request from
//! another repository, a head branch no lease names, and a lease comment by anyone but the
//! repository's owner (the rule of `records`) print and save nothing, so the gates judge the change
//! as no agent's. An issue that names another agent than its lease, and a checkout whose `.agent`
//! path is a link, are errors, so CI never runs as a third identity or writes outside the change.
//! It only reads GitHub, through `GH_TOKEN` when set.

use std::path::Path;
use std::process::ExitCode;

use anyhow::{Result, bail};

use super::merge::Writer;
use crate::cli::{self, Spec};
use crate::config::session::{AGENT_VARIABLE, SCOPE_VARIABLE, Scope, WORK_ITEM_VARIABLE};
use crate::github::{Gh, Mode};
use crate::orchestrate::launch::{LaunchKit, owner_step_or};
use crate::orchestrate::records;
use crate::orchestrate::tracker::{GhTracker, Tracker};
use crate::repo::Repo;

const SPEC: Spec = Spec {
    flags: &[],
    options: &["--pull-request", "--snapshot-into"],
};
const USAGE: &str =
    "usage: cargo xtask kit ci-env --pull-request <number> --snapshot-into <change checkout>";

/// Whose change CI judges.
#[derive(Debug)]
enum Judged {
    /// The lease's writer.
    Leased(Box<Writer>),
    /// The head branch lives in another repository.
    Fork,
    /// No lease the kit trusts names the head branch.
    Unleased,
}

/// `kit ci-env`.
pub fn command(args: &[String]) -> Result<ExitCode> {
    let parsed = cli::parse(args, &SPEC)?;
    let (Some(raw), Some(checkout)) = (
        parsed.value("--pull-request"),
        parsed.value("--snapshot-into"),
    ) else {
        bail!("{USAGE}");
    };
    let Some(number) = raw.trim().parse::<u64>().ok().filter(|number| *number > 0) else {
        bail!("--pull-request {raw} is not a pull request number");
    };
    let repo = Repo::discover()?;
    let kit = LaunchKit::load(&repo)?;
    let tracker = GhTracker::new(Gh::for_repo(&repo, Mode::Live)?);
    let judged = match judge(&kit, &tracker, number) {
        Ok(judged) => judged,
        Err(error) => return owner_step_or(error),
    };
    match judged {
        Judged::Leased(writer) => {
            save_snapshot(&writer, Path::new(checkout))?;
            print!("{}", lines(&writer));
        }
        Judged::Fork => eprintln!(
            "kit ci-env: #{number} comes from another repository, so its gates run as no agent's"
        ),
        Judged::Unleased => eprintln!(
            "kit ci-env: no lease by the repository's owner names the head branch of #{number}, so its gates run as no agent's"
        ),
    }
    Ok(ExitCode::SUCCESS)
}

/// Whose change pull request `number` is.
fn judge(kit: &LaunchKit, tracker: &GhTracker, number: u64) -> Result<Judged> {
    let source = tracker.pull_request_source(number)?;
    let repository = tracker.gh().repository();
    if source.from_fork(repository) {
        return Ok(Judged::Fork);
    }
    for item in source.closed_issues(repository) {
        let issue = tracker.issue(item)?;
        let found = records::records(&issue);
        let Some(lease) =
            records::current_lease(&found, item).filter(|lease| lease.branch == source.head_branch)
        else {
            continue;
        };
        let writer = Writer::of(kit, &issue, lease)?;
        // The agent can come from the issue body, and a roster name never carries a second line.
        kit.agent(&writer.snapshot.agent)?;
        return Ok(Judged::Leased(Box::new(writer)));
    }
    Ok(Judged::Unleased)
}

/// The lease's item snapshot in the change's checkout, where gate V05 reads its write set. It
/// replaces any copy the change committed there, so the change never sets its own write set, and
/// refuses a committed link on the way, which would carry the write out of the checkout.
fn save_snapshot(writer: &Writer, checkout: &Path) -> Result<()> {
    writer.snapshot.save(&Repo::at(checkout))
}

/// The three `$GITHUB_ENV` lines; an ordinary lease has an empty scope.
fn lines(writer: &Writer) -> String {
    let scope = writer.scope.map_or("", Scope::name);
    format!(
        "{AGENT_VARIABLE}={}\n{WORK_ITEM_VARIABLE}={}\n{SCOPE_VARIABLE}={scope}\n",
        writer.snapshot.agent, writer.snapshot.number
    )
}

#[cfg(test)]
mod tests;
