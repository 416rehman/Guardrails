//! Taking work from the queue: rebuilding leases from the issues on restart, leasing ready issues
//! into free writer slots in lease order, sending back any item whose acceptance section changed
//! under its lease, expiring `kit claim` leases nobody finished, and moving leased issues on once
//! their pull request opens and no hand-off is owed.

use std::time::Duration;

use anyhow::Result;

use super::journal::note;
use super::sessions::fix_owed;
use super::{Dispatcher, Prompt, Slot};
use crate::config::session::ItemStatus;
use crate::dispatch::lease::{self, Change, Held};
use crate::dispatch::queue::{self, Candidate, Verdict};
use crate::dispatch::routines::{now_unix, unix_of};
use crate::dispatch::worker;
use crate::orchestrate::ids;
use crate::orchestrate::issue::{Issue, status_label};
use crate::orchestrate::launch::{self, Caps};
use crate::orchestrate::records::{self, Lease, Reason, Record};

impl Dispatcher<'_> {
    /// Rebuilds the leases from the issues: every `status:leased` issue whose latest `lease.v1`
    /// names a session, is the seed's (which names none), or came back from review unanswered (a
    /// `kit claim` lease the send-back took over) becomes a paused slot, resumed when the window
    /// and a slot allow, or started as a fix when its fix is owed. An issue whose slot cannot be
    /// rebuilt is left out. The evaluators the review rounds started and that no longer run are
    /// forgotten, so the next review pass starts them again; one the old process left running
    /// still holds its session lock, so the new launch waits until it ends.
    pub fn adopt(&mut self) -> Result<()> {
        for (item, round) in &mut self.assisted.reviewing {
            round.started.retain(|agent| {
                self.assists
                    .iter()
                    .any(|assist| assist.item == *item && assist.agent == *agent)
            });
        }
        self.assisted.save(&self.repo)?;
        let Some(label) = status_label(ItemStatus::Leased) else {
            return Ok(());
        };
        for summary in self.tracker.open_with_label(&label)? {
            if self.held().contains(&summary.number) {
                continue;
            }
            let issue = self.tracker.issue(summary.number)?;
            let found = records::records(&issue);
            let Some(lease) = records::current_lease(&found, issue.number)
                .filter(|l| l.session.is_some() || self.is_seed_lease(l) || fix_owed(&found, l))
                .cloned()
            else {
                continue;
            };
            let prompt = if fix_owed(&found, &lease) {
                Prompt::Fix
            } else {
                Prompt::Resume
            };
            let held = match self.held_for(&issue, lease) {
                Ok(held) => held,
                Err(error) => {
                    eprintln!("dispatch: #{} was not adopted: {error:#}", issue.number);
                    continue;
                }
            };
            note(
                &self.repo,
                "adopted",
                Some(&held.record),
                "rebuilt from the issue's lease comment",
            );
            self.slots.push(Slot::Paused { held, prompt });
        }
        Ok(())
    }

    /// Starts the seed session again when its issue is back at proposed, then leases ready issues
    /// into free slots. The ready queue is swept every pass, so a readying that is no longer valid
    /// goes back to proposed even while every slot is busy.
    pub(super) fn fill(&mut self) -> Result<()> {
        self.relaunch_seed()?;
        let free = usize::try_from(self.policy.max_writers)
            .unwrap_or(0)
            .saturating_sub(self.slots.len());
        let candidates = self.candidates(true)?;
        for candidate in candidates.into_iter().take(free) {
            let number = candidate.issue.number;
            if let Err(error) = self.lease_and_start(candidate) {
                println!("dispatch: #{number} was not leased: {error:#}");
            }
        }
        Ok(())
    }

    /// Starts the seed session again on the seed branch when its issue is back at
    /// `status:proposed` after its hand-off, where the chief architect's decision on an escalation
    /// moved it. Nobody readies it, so a new lease carries the current acceptance digest. It waits
    /// for a free writer slot and stops once `[item] max_attempts` is used; the previous attempt's
    /// worktree lets go of the branch first.
    fn relaunch_seed(&mut self) -> Result<()> {
        let Some(agent) = self.kit.seed.as_ref().map(|seed| seed.agent.clone()) else {
            return Ok(());
        };
        let Some(label) = status_label(ItemStatus::Proposed) else {
            return Ok(());
        };
        let writers = usize::try_from(self.policy.max_writers).unwrap_or(0);
        for summary in self.tracker.open_with_label(&label)? {
            let n = summary.number;
            if !self.is_seed_issue(&summary) || self.held().contains(&n) || self.assisting(n) {
                continue;
            }
            let issue = self.tracker.issue(n)?;
            let found = records::records(&issue);
            let Some(last) = records::current_lease(&found, n)
                .filter(|lease| self.is_seed_lease(lease))
                .cloned()
            else {
                continue;
            };
            let Some(attempt) = self.next_seed_attempt(&last) else {
                let used = self.policy.max_attempts;
                self.notice(
                    n,
                    &format!("is the seed's, back at status:proposed with its {used} attempts used, so the seed session does not start again"),
                );
                continue;
            };
            if self.slots.len() >= writers {
                continue;
            }
            worker::detach(&self.repo, &worker::attempt_worktree(n, last.attempt))?;
            let item = issue.work_item();
            let candidate = Candidate {
                digest: item
                    .acceptance
                    .as_ref()
                    .map(|acceptance| acceptance.sha256.clone())
                    .unwrap_or_default(),
                item,
                agent: agent.clone(),
                attempt,
                blocks_others: false,
                issue,
            };
            if let Err(error) = self.lease_and_start(candidate) {
                println!("dispatch: #{n}, the seed's, did not start again: {error:#}");
            }
        }
        Ok(())
    }

    /// The attempt of the seed session after `last`, the seed's current lease; none once `[item]
    /// max_attempts` is used.
    pub(super) fn next_seed_attempt(&self, last: &Lease) -> Option<u32> {
        let next = last.attempt.saturating_add(1);
        (next <= self.policy.max_attempts).then_some(next)
    }

    /// The eligible ready issues in lease order; with `apply`, invalid readyings go back to proposed.
    pub fn candidates(&self, apply: bool) -> Result<Vec<Candidate>> {
        let Some(label) = status_label(ItemStatus::Ready) else {
            return Ok(Vec::new());
        };
        let mut candidates = Vec::new();
        for summary in self.tracker.open_with_label(&label)? {
            if self.held().contains(&summary.number) {
                continue;
            }
            let issue = self.tracker.issue(summary.number)?;
            match queue::assess(&issue, &self.kit, &self.labels, &self.policy, self.tracker)? {
                Verdict::Eligible(candidate) => candidates.push(*candidate),
                Verdict::Wait(why) => println!("dispatch: #{} waits: {why}", issue.number),
                Verdict::Unready(reason) if apply => {
                    queue::unready(self.tracker, &issue, reason)?;
                    println!(
                        "dispatch: #{} back to status:proposed: {}",
                        issue.number,
                        reason.describe()
                    );
                }
                Verdict::Unready(reason) => {
                    println!(
                        "dispatch: #{} would go back to status:proposed: {}",
                        issue.number,
                        reason.describe()
                    );
                }
            }
        }
        queue::order(&mut candidates, &self.policy.lease_order);
        Ok(candidates)
    }

    pub(super) fn lease_and_start(&mut self, candidate: Candidate) -> Result<()> {
        let number = candidate.issue.number;
        let snapshot = launch::snapshot_of(&candidate.issue, &self.kit, &candidate.agent)?;
        let model = self.kit.choose_model(&candidate.agent, Some(&snapshot))?;
        let branch = match &self.kit.seed {
            Some(seed) if self.is_seed_issue(&candidate.issue) => seed.branch.clone(),
            _ => self.policy.branch_for(number, candidate.attempt),
        };
        let name = worker::attempt_worktree(number, candidate.attempt);
        let worktree = self.worktree(&name, Some(&branch))?;
        let session = ids::session_id();
        let record = lease::grant(self.tracker, &candidate, &model, &branch, Some(&session))?;
        println!(
            "dispatch: leased #{number} to {} on {}, attempt {}",
            record.agent, record.model, record.attempt
        );
        note(&self.repo, "leased", Some(&record), "");
        let held = Held {
            record,
            worktree,
            size: snapshot.size,
            tier: snapshot.risk_tier,
            trust_core: snapshot.trust_core,
            priority: candidate.item.priority,
            caps: self.kit.caps_for(&candidate.agent, &snapshot.write_set)?,
            sessions: 0,
            worked: Duration::ZERO,
            refused_at: None,
            left_session: false,
        };
        let failed_record = held.record.clone();
        match self.start(held, Prompt::Fresh) {
            Ok(slot) => {
                self.slots.extend(slot);
                Ok(())
            }
            Err(error) => {
                lease::end_attempt(
                    self.tracker,
                    &failed_record,
                    Reason::WorkerFailed,
                    self.attempts_for(&failed_record),
                )?;
                Err(error)
            }
        }
    }

    /// Leased issues this dispatcher does not hold: back to proposed, or the seed's to the chief
    /// architect, when the acceptance section changed; to review once their pull request opens
    /// unless a hand-off is owed, which its holder answers first; and a `kit claim` lease nobody
    /// finished ends as expired after the role's wall clock times the lease factor.
    pub(super) fn reconcile(&mut self) -> Result<()> {
        let Some(label) = status_label(ItemStatus::Leased) else {
            return Ok(());
        };
        for summary in self.tracker.open_with_label(&label)? {
            if self.held().contains(&summary.number) {
                continue;
            }
            let issue = self.tracker.issue(summary.number)?;
            let found = records::timed_records(&issue);
            let plain: Vec<Record> = found.iter().map(|(_, record)| record.clone()).collect();
            let Some(lease) = records::current_lease(&plain, issue.number).cloned() else {
                continue;
            };
            if acceptance_changed(&issue, &lease) {
                self.acceptance_moved(&lease, ItemStatus::Leased)?;
                continue;
            }
            if self.handoff_owed(&plain, &lease) {
                continue;
            }
            if self.tracker.open_pull_request(&lease.branch)?.is_some() {
                lease::to_review(self.tracker, &lease)?;
                println!("dispatch: #{} is in review", issue.number);
                continue;
            }
            if lease.session.is_none() && self.claim_expired(&found, &lease) {
                let outcome = lease::end_attempt(
                    self.tracker,
                    &lease,
                    Reason::LeaseExpired,
                    self.attempts_for(&lease),
                )?;
                println!(
                    "dispatch: #{}: the kit claim lease expired; {outcome:?}",
                    issue.number
                );
            }
        }
        Ok(())
    }

    /// Every held lease whose acceptance section changed since it was leased ends: the session
    /// stops and the item goes back to proposed for its lead to ready again, or the seed's to
    /// the chief architect.
    pub(super) fn check_acceptance(&mut self) -> Result<()> {
        for slot in std::mem::take(&mut self.slots) {
            let lease = slot.held().record.clone();
            let issue = match self.tracker.issue(lease.item) {
                Ok(issue) => issue,
                Err(error) => {
                    eprintln!("dispatch: #{}: {error:#}", lease.item);
                    self.slots.push(slot);
                    continue;
                }
            };
            if !acceptance_changed(&issue, &lease) || issue.status() != Some(ItemStatus::Leased) {
                self.slots.push(slot);
                continue;
            }
            if let Slot::Working { mut run, .. } = slot {
                run.stop();
            }
            self.acceptance_moved(&lease, ItemStatus::Leased)?;
        }
        Ok(())
    }

    /// The acceptance section changed under `lease`, so the evaluators would not judge the
    /// snapshot it was leased with: the item goes back to proposed for its lead to ready again,
    /// and the seed's issue, which nobody readies, to the chief architect.
    pub(super) fn acceptance_moved(&self, lease: &Lease, from: ItemStatus) -> Result<()> {
        let (to, detail) = if self.is_seed_lease(lease) {
            (
                ItemStatus::Escalated,
                Some(
                    "Nobody readies the seed's issue, so the chief architect decides how it continues.",
                ),
            )
        } else {
            (ItemStatus::Proposed, None)
        };
        let change = Change {
            item: lease.item,
            attempt: lease.attempt,
            from,
            to,
            reason: Reason::AcceptanceChanged,
        };
        lease::transition_with(self.tracker, &change, detail)?;
        note(
            &self.repo,
            "acceptance-changed",
            Some(lease),
            Reason::AcceptanceChanged.describe(),
        );
        println!(
            "dispatch: #{} to {}: {}",
            lease.item,
            status_label(to).unwrap_or_default(),
            Reason::AcceptanceChanged.describe()
        );
        Ok(())
    }

    /// A claim lease older than the role's wall clock times the lease factor.
    fn claim_expired(&self, found: &[(String, Record)], lease: &Lease) -> bool {
        let posted = found.iter().rev().find_map(|(at, record)| match record {
            Record::Lease(l) if l == lease => unix_of(at),
            _ => None,
        });
        let limit = self
            .kit
            .wall_clock(&lease.agent, None, Caps::Role)
            .map(|clock| clock.saturating_mul(self.policy.lease_factor));
        match (posted, limit) {
            (Some(at), Some(limit)) => now_unix().saturating_sub(at) > limit.as_secs(),
            _ => false,
        }
    }

    pub(super) fn held_for(&self, issue: &Issue, record: Lease) -> Result<Held> {
        let snapshot = launch::snapshot_of(issue, &self.kit, &record.agent)?;
        let name = worker::attempt_worktree(issue.number, record.attempt);
        let caps = self.kit.caps_for(&record.agent, &snapshot.write_set)?;
        Ok(Held {
            worktree: worker::worktree_dir(&self.repo, &name),
            record,
            size: snapshot.size,
            tier: snapshot.risk_tier,
            trust_core: snapshot.trust_core,
            priority: issue.work_item().priority,
            caps,
            sessions: 1,
            worked: Duration::ZERO,
            refused_at: None,
            left_session: false,
        })
    }
}

/// Whether the issue's acceptance section no longer has the digest its lease carries.
pub(super) fn acceptance_changed(issue: &Issue, lease: &Lease) -> bool {
    issue
        .work_item()
        .acceptance
        .is_none_or(|current| current.sha256 != lease.acceptance_sha256)
}
