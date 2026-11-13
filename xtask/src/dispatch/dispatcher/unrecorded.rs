//! A `status:leased` label with no `lease.v1` behind it. A grant edits the label and then posts
//! the record, so an edit GitHub applied but answered after the timeout fails the grant between
//! the two: the issue is leased, nobody works on it, and a restart adopts only recorded leases.
//! A failed grant is undone at once, and each pass puts back any such issue no slot holds. An
//! issue whose lease is recorded is never touched here, and neither is one whose attempt already
//! has an open pull request.

use anyhow::Result;

use super::Dispatcher;
use super::journal::note;
use super::review::since_lease;
use crate::config::session::ItemStatus;
use crate::dispatch::lease;
use crate::dispatch::queue::Candidate;
use crate::orchestrate::issue::{Issue, status_label};
use crate::orchestrate::records::{self, Lease, Record};

impl Dispatcher<'_> {
    /// Puts `candidate`'s issue back where its failed grant found it, when the label edit landed
    /// and the `lease.v1` of the attempt did not. A failure here is printed and left to
    /// `put_back_unrecorded` on a later pass.
    pub(super) fn undo_unrecorded_grant(&self, candidate: &Candidate) {
        let number = candidate.issue.number;
        if let Err(error) = self.try_undo_grant(candidate) {
            eprintln!("dispatch: #{number}: its failed lease was not undone: {error:#}");
        }
    }

    fn try_undo_grant(&self, candidate: &Candidate) -> Result<()> {
        let number = candidate.issue.number;
        let Some(before) = candidate.issue.status() else {
            return Ok(());
        };
        let issue = self.tracker.issue(number)?;
        let recorded = records::current_lease(&records::records(&issue), number)
            .is_some_and(|lease| lease.attempt == candidate.attempt);
        if recorded || issue.status() != Some(ItemStatus::Leased) {
            return Ok(());
        }
        self.withdraw(number, before)
    }

    /// Puts `issue`, `status:leased` with no lease in force among `found` and held by no slot,
    /// back where its next lease starts from: ready, or proposed for the seed's issue, which
    /// nobody readies. It stays while the branch of that attempt has an open pull request.
    pub(super) fn put_back_unrecorded(&self, issue: &Issue, found: &[Record]) -> Result<()> {
        let attempt = records::current_lease(found, issue.number)
            .map_or(1, |lease| lease.attempt.saturating_add(1));
        let branch = self.branch_of(issue, attempt);
        if self.tracker.open_pull_request(&branch)?.is_some() {
            return Ok(());
        }
        let to = if self.is_seed_issue(issue) {
            ItemStatus::Proposed
        } else {
            ItemStatus::Ready
        };
        self.withdraw(issue.number, to)
    }

    fn withdraw(&self, number: u64, to: ItemStatus) -> Result<()> {
        lease::withdraw(self.tracker, number, to)?;
        let detail = format!(
            "#{number} was status:leased with no lease.v1; back to {}",
            status_label(to).unwrap_or_default()
        );
        note(&self.repo, "unrecorded-lease", None, &detail);
        println!("dispatch: {detail}");
        Ok(())
    }
}

/// The lease `item`'s `status:leased` label stands for: its current `lease.v1`, unless a later
/// `state.v1` ended that attempt back at ready, after which only a new `lease.v1` leases it.
pub(super) fn lease_in_force(found: &[Record], item: u64) -> Option<&Lease> {
    let lease = records::current_lease(found, item)?;
    let ended = since_lease(found, lease).iter().any(|record| {
        matches!(record, Record::Transition(t)
            if t.item == item && t.from == ItemStatus::Leased && t.to == ItemStatus::Ready)
    });
    (!ended).then_some(lease)
}
