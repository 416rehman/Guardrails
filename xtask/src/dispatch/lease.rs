//! Leases on GitHub (team/01 sections 3 and 9): granting one swaps `status:ready` for
//! `status:leased`, assigns the issue and posts `lease.v1` with the attempt, agent, model, branch,
//! acceptance digest and session id; ending one swaps the status and posts `state.v1`. A failed or
//! stalled attempt returns to `status:ready`, and after the last attempt goes to
//! `status:escalated` with a team/01 section 6 packet. A usage limit posts nothing.

use std::path::PathBuf;

use anyhow::{Result, bail};

use super::queue::Candidate;
use crate::config::session::{ItemStatus, RiskTier};
use crate::orchestrate::issue::status_label;
use crate::orchestrate::launch::ModelChoice;
use crate::orchestrate::records::{
    self, LEASE_SCHEMA, Lease, Reason, STATE_SCHEMA, Transition, lease_comment, transition_comment,
};
use crate::orchestrate::tracker::{IssueEdit, Tracker};

/// A lease this dispatcher holds, with what it needs to run, pause and resume the worker.
#[derive(Debug, Clone)]
pub struct Held {
    pub record: Lease,
    pub worktree: PathBuf,
    pub size: Option<String>,
    pub tier: RiskTier,
    pub trust_core: bool,
    pub priority: Option<u8>,
    /// Sessions started in this attempt.
    pub sessions: u32,
    /// Time the worker has run in this attempt; paused time is not counted.
    pub worked: std::time::Duration,
}

/// One status change and why.
#[derive(Debug, Clone, Copy)]
pub struct Change {
    pub item: u64,
    pub attempt: u32,
    pub from: ItemStatus,
    pub to: ItemStatus,
    pub reason: Reason,
}

/// How an attempt that did not reach a pull request ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Retry,
    Escalate,
}

impl Held {
    pub fn item(&self) -> u64 {
        self.record.item
    }

    pub fn session(&self) -> Option<&str> {
        self.record.session.as_deref()
    }
}

/// Leases `candidate` with `model`, and checks that the newest lease is this one. `session` is
/// the Claude Code session the dispatcher starts; a lease taken by `kit claim` has none, so a
/// restarted dispatcher never takes it over.
pub fn grant(
    tracker: &dyn Tracker,
    candidate: &Candidate,
    model: &ModelChoice,
    branch: &str,
    session: Option<&str>,
) -> Result<Lease> {
    let number = candidate.issue.number;
    let record = Lease {
        schema: LEASE_SCHEMA.to_owned(),
        item: number,
        attempt: candidate.attempt,
        agent: candidate.agent.clone(),
        model: model.id.clone(),
        acceptance_sha256: candidate.digest.clone(),
        branch: branch.to_owned(),
        session: session.map(str::to_owned),
    };
    let edit = IssueEdit {
        add: status_label(ItemStatus::Leased).into_iter().collect(),
        remove: status_label(ItemStatus::Ready).into_iter().collect(),
        assign_self: true,
    };
    tracker.edit(number, &edit)?;
    tracker.comment(number, &lease_comment(&record)?)?;
    let after = tracker.issue(number)?;
    let found = records::records(&after);
    let newest = records::current_lease(&found, number);
    if newest != Some(&record) {
        bail!(
            "#{number}: another lease comment arrived after this one; leaving it to that dispatcher"
        );
    }
    Ok(record)
}

/// Swaps the status label and records why in a `state.v1` comment.
pub fn transition(
    tracker: &dyn Tracker,
    item: u64,
    attempt: u32,
    from: ItemStatus,
    to: ItemStatus,
    reason: Reason,
) -> Result<()> {
    let change = Change {
        item,
        attempt,
        from,
        to,
        reason,
    };
    transition_with(tracker, &change, None)
}

/// [`transition`] with the detail the next session needs, such as the checks that failed.
pub fn transition_with(tracker: &dyn Tracker, change: &Change, detail: Option<&str>) -> Result<()> {
    let Change {
        item,
        attempt,
        from,
        to,
        reason,
    } = *change;
    let edit = IssueEdit {
        add: status_label(to).into_iter().collect(),
        remove: status_label(from).into_iter().collect(),
        assign_self: false,
    };
    tracker.edit(item, &edit)?;
    let record = Transition {
        schema: STATE_SCHEMA.to_owned(),
        item,
        attempt,
        from,
        to,
        reason,
    };
    let mut line = format!(
        "Moved from {} to {}: {}.",
        status_label(from).unwrap_or_default(),
        status_label(to).unwrap_or_default(),
        reason.describe()
    );
    if let Some(detail) = detail {
        line.push(' ');
        line.push_str(detail);
    }
    tracker.comment(item, &transition_comment(&record, &line)?)
}

/// The pull request is open: the item is in review.
pub fn to_review(tracker: &dyn Tracker, held: &Lease) -> Result<()> {
    transition(
        tracker,
        held.item,
        held.attempt,
        ItemStatus::Leased,
        ItemStatus::InReview,
        Reason::PullRequestOpen,
    )
}

/// Ends an attempt that did not reach a pull request.
pub fn end_attempt(
    tracker: &dyn Tracker,
    lease: &Lease,
    reason: Reason,
    max_attempts: u32,
) -> Result<Outcome> {
    if lease.attempt < max_attempts {
        transition(
            tracker,
            lease.item,
            lease.attempt,
            ItemStatus::Leased,
            ItemStatus::Ready,
            reason,
        )?;
        return Ok(Outcome::Retry);
    }
    transition(
        tracker,
        lease.item,
        lease.attempt,
        ItemStatus::Leased,
        ItemStatus::Escalated,
        reason,
    )?;
    tracker.comment(lease.item, &packet(lease, reason))?;
    Ok(Outcome::Escalate)
}

/// The one-screen escalation packet of team/01 section 6; it goes to the item's lead, never to a
/// person (owner instruction 7).
fn packet(lease: &Lease, reason: Reason) -> String {
    format!(
        "### Escalation #{n}-E{a}\nQuestion: attempt {a} of #{n} ended without a pull request ({why}); how should the item change before it is readied again?\nOptions: A (recommended) the item's lead re-plans it from the hand-offs and readies it again / B split it into sub-issues.\nEvidence: the lease and hand-off comments above, branch `{branch}`, the dispatcher log .agent/logs/dispatch-{n}-a{a}.jsonl.\nCost of waiting: #{n} and the issues it blocks stay unworked.\nDefault if unanswered in 48 h: A.\n",
        n = lease.item,
        a = lease.attempt,
        why = reason.describe(),
        branch = lease.branch,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchestrate::records::Record;
    use crate::orchestrate::testkit::{MemoryTracker, issue};

    fn lease(attempt: u32) -> Lease {
        Lease {
            schema: LEASE_SCHEMA.into(),
            item: 3,
            attempt,
            agent: "impl-rust".into(),
            model: "claude-sonnet-5-5".into(),
            acceptance_sha256: "d".into(),
            branch: format!("agent/3/a{attempt}"),
            session: Some("s".into()),
        }
    }

    #[test]
    fn the_first_failure_retries_and_the_last_escalates() {
        let tracker = MemoryTracker::default();
        tracker.add(issue(3, &["status:leased"], ""));
        assert_eq!(
            end_attempt(&tracker, &lease(1), Reason::Stall, 2).unwrap(),
            Outcome::Retry
        );
        let after = tracker.snapshot(3);
        assert_eq!(after.status(), Some(ItemStatus::Ready));
        let found = records::records(&after);
        assert!(
            matches!(found.last(), Some(Record::Transition(t)) if t.reason == Reason::Stall && t.to == ItemStatus::Ready)
        );
        tracker
            .edit(
                3,
                &IssueEdit {
                    add: vec!["status:leased".into()],
                    remove: vec!["status:ready".into()],
                    assign_self: false,
                },
            )
            .unwrap();
        assert_eq!(
            end_attempt(&tracker, &lease(2), Reason::NoPullRequest, 2).unwrap(),
            Outcome::Escalate
        );
        let escalated = tracker.snapshot(3);
        assert_eq!(escalated.status(), Some(ItemStatus::Escalated));
        assert!(
            escalated
                .comments
                .last()
                .unwrap()
                .body
                .starts_with("### Escalation #3-E2")
        );
    }
}
