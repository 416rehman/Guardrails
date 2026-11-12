//! `PostToolUse` on Bash and PowerShell (team/03 section 4.1): protected paths that differ from
//! what they were when the session started are fed back with the command that reverts them. The
//! session's baseline keeps files that were already changed out of the report, and so does the
//! session's own widened scope: the seed scope, or a protected-change lease's write set, whose
//! paths that session places with `cargo xtask kit place`.

use std::collections::BTreeMap;

use anyhow::Result;

use super::context::Context;
use super::identity::Identity;
use super::outcome::{Outcome, capped};
use super::state::{SESSION_SCHEMA, SessionState, sha256_hex};
use crate::clock::Utc;
use crate::config::protected::ProtectedPaths;
use crate::gates::protected::allowance;
use crate::git::{self, Base};
use crate::globs::GlobList;
use crate::paths::RepoPath;
use crate::repo::Repo;

const DELETED: &str = "deleted";
/// `XY ` before the path of each `git status --porcelain=v1` record.
const STATUS_PREFIX_BYTES: usize = 3;

/// A protected path that differs from `HEAD`, with its content hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Changed {
    pub path: RepoPath,
    pub hash: String,
    pub tracked: bool,
}

pub fn run(context: &Context) -> Result<Outcome> {
    let Some(session) = context.input.session_id() else {
        return Ok(Outcome::Allow);
    };
    let current = protected_changes(&context.repo)?;
    let Some(state) = SessionState::load(&context.repo, session)? else {
        let state = SessionState {
            schema: SESSION_SCHEMA.to_owned(),
            session_id: session.to_owned(),
            started_at: Utc::now().iso(),
            protected_baseline: baseline(&current),
            ..SessionState::default()
        };
        state.save(&context.repo)?;
        context.note("no session state: recorded the protected-path baseline now");
        return Ok(Outcome::Allow);
    };
    let widened = widened(context);
    let new: Vec<&Changed> = current
        .iter()
        .filter(|changed| {
            state.protected_baseline.get(changed.path.as_str()) != Some(&changed.hash)
        })
        .filter(|changed| {
            !widened
                .as_ref()
                .is_some_and(|globs| globs.is_match(changed.path.as_str()))
        })
        .collect();
    if new.is_empty() {
        return Ok(Outcome::Allow);
    }
    let reverts: Vec<String> = new
        .iter()
        .map(|changed| {
            let baselined = state.protected_baseline.contains_key(changed.path.as_str());
            revert_command(changed, baselined)
        })
        .collect();
    for revert in &reverts {
        context.note(revert.clone());
    }
    let mut lines = vec![format!(
        "{} protected path(s) changed during this session; protected paths change only through protected_change_requests. Revert with:",
        new.len()
    )];
    lines.extend(capped(&reverts, context.limits.post_bash.protected_listed));
    Ok(Outcome::Block(lines.join("\n")))
}

/// The protected globs this session's scope covers, as guard-path and guard-command read them.
/// An identity that does not load widens nothing, so every protected change is still reported.
fn widened(context: &Context) -> Option<GlobList> {
    let identity = Identity::load(context).ok()?;
    let agent = identity.agent()?;
    allowance(&context.repo, &Base::Unborn, &identity.session, agent)
        .ok()
        .flatten()
}

/// Protected paths that `git status` reports as changed, added or deleted.
pub fn protected_changes(repo: &Repo) -> Result<Vec<Changed>> {
    let protected = ProtectedPaths::load(repo)?.globs()?;
    let listing = git::output(
        repo,
        &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    )?;
    let mut records = listing.split('\0').filter(|record| !record.is_empty());
    let mut changed = Vec::new();
    while let Some(record) = records.next() {
        let (code, path) = record
            .split_at_checked(STATUS_PREFIX_BYTES)
            .unwrap_or((record, ""));
        if code.starts_with('R') || code.starts_with('C') {
            records.next();
        }
        let Some(path) = RepoPath::new(path) else {
            continue;
        };
        if !protected.is_match(path.as_str()) {
            continue;
        }
        let hash = std::fs::read(repo.path(path.as_str()))
            .map(|bytes| sha256_hex(&bytes))
            .unwrap_or_else(|_| DELETED.to_owned());
        changed.push(Changed {
            path,
            hash,
            tracked: !code.starts_with("??"),
        });
    }
    Ok(changed)
}

pub fn baseline(changes: &[Changed]) -> BTreeMap<String, String> {
    changes
        .iter()
        .map(|changed| (changed.path.to_string(), changed.hash.clone()))
        .collect()
}

/// The revert for one path: git restores a tracked one; a new untracked one is deleted; an
/// untracked one that already existed at session start has no copy in git, so it is restored by
/// hand to the content it had then.
fn revert_command(changed: &Changed, baselined: bool) -> String {
    match (changed.tracked, baselined) {
        (true, _) => format!("git checkout HEAD -- {}", changed.path),
        (false, false) => format!("rm -- {}", changed.path),
        (false, true) => format!(
            "{} is untracked and existed when the session started: undo your edit to it by hand; never delete it",
            changed.path
        ),
    }
}
