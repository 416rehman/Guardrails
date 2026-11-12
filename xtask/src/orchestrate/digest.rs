//! `cargo xtask kit digest <n>` (owner instruction 5, skill grdr-evaluate section 1): the SHA-256
//! of the issue's current acceptance-criteria section beside the digests its newest `ready.v1` and
//! `lease.v1` comments name, so an evaluator compares them with one read-only call. An issue the
//! kit put in review without a `ready.v1`, the seed's, is judged against its lease's digest.
//! Exit 0 when the digests that exist agree, 2 when they differ or the section is missing.

use std::process::ExitCode;

use anyhow::{Result, bail};

use super::issue::Issue;
use super::launch::owner_step_or;
use super::records;
use super::tracker::{GhTracker, Tracker};
use crate::cli::{self, Spec};
use crate::config::session::parse_item_number;
use crate::github::{Gh, Mode};
use crate::repo::Repo;

const SPEC: Spec = Spec {
    flags: &[],
    options: &[],
};
const MISSING: &str = "none";

/// The digests one issue carries.
#[derive(Debug)]
struct Digests {
    current: Option<String>,
    /// The newest `ready.v1`'s digest and the agent that posted it.
    ready: Option<(String, String)>,
    lease: Option<String>,
}

impl Digests {
    fn of(issue: &Issue) -> Digests {
        let found = records::records(issue);
        Digests {
            current: issue.work_item().acceptance.map(|section| section.sha256),
            ready: records::latest_ready(&found, issue.number)
                .map(|(_, ready)| (ready.acceptance_sha256.clone(), ready.by.clone())),
            lease: records::current_lease(&found, issue.number)
                .map(|lease| lease.acceptance_sha256.clone()),
        }
    }

    /// Whether the current section has the digest every record that names one gives it.
    fn agree(&self) -> bool {
        let Some(current) = &self.current else {
            return false;
        };
        let named: Vec<&String> = [
            self.ready.as_ref().map(|(digest, _)| digest),
            self.lease.as_ref(),
        ]
        .into_iter()
        .flatten()
        .collect();
        !named.is_empty() && named.iter().all(|digest| *digest == current)
    }
}

pub fn command(args: &[String]) -> Result<ExitCode> {
    let parsed = cli::parse(args, &SPEC)?;
    let Some(raw) = parsed.positional.first() else {
        bail!("usage: cargo xtask kit digest <issue>");
    };
    let number = parse_item_number(raw)?;
    let repo = Repo::discover()?;
    let tracker = GhTracker::new(Gh::for_repo(&repo, Mode::Live)?);
    let issue = match tracker.issue(number) {
        Ok(issue) => issue,
        Err(error) => return owner_step_or(error),
    };
    let digests = Digests::of(&issue);
    println!("current: {}", digests.current.as_deref().unwrap_or(MISSING));
    match &digests.ready {
        Some((digest, by)) => println!("ready.v1: {digest} (by {by})"),
        None => println!("ready.v1: {MISSING}"),
    }
    println!("lease.v1: {}", digests.lease.as_deref().unwrap_or(MISSING));
    if digests.agree() {
        println!("kit digest: #{number}'s acceptance section matches every digest it was given");
        return Ok(ExitCode::SUCCESS);
    }
    println!(
        "kit digest: #{number}'s acceptance section does not match the digests above; it must be readied again"
    );
    Ok(ExitCode::from(2))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digests(current: Option<&str>, ready: Option<&str>, lease: Option<&str>) -> Digests {
        Digests {
            current: current.map(str::to_owned),
            ready: ready.map(|digest| (digest.to_owned(), "lead-core".to_owned())),
            lease: lease.map(str::to_owned),
        }
    }

    #[test]
    fn digests_agree_only_when_every_named_digest_is_the_current_one() {
        assert!(digests(Some("a"), Some("a"), Some("a")).agree());
        assert!(digests(Some("a"), None, Some("a")).agree());
        assert!(digests(Some("a"), Some("a"), None).agree());
        assert!(!digests(Some("a"), Some("b"), Some("a")).agree());
        assert!(!digests(Some("a"), None, Some("b")).agree());
        assert!(!digests(None, Some("a"), Some("a")).agree());
        assert!(!digests(Some("a"), None, None).agree());
    }
}
