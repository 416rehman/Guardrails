//! The merge queue inside the dispatcher (owner instruction 7, `dispatch::merge`): a pull request
//! whose lane's evaluators passed lands once its title and body are valid, CI is green, the
//! rounds were not exceeded, the acceptance section still has the digest its lease names (owner
//! instruction 5: evaluators judged that snapshot) and the full verify passed on the tree that
//! lands. One verify runs at
//! a time; a passed tree is kept by pull request, head and base tip, so a moved base or a new
//! push verifies again. A refusal sends the item back to its worker with the reason and uses one
//! of its review rounds, so a refusal the worker cannot answer ends with the rounds. The seed's
//! branch, which no session can rebase, goes to the chief architect on a conflict instead.

use anyhow::Result;

use super::journal::note;
use super::leasing::acceptance_changed;
use super::review::failed_rounds;
use super::{Dispatcher, LOCAL_POLL};
use crate::config::session::ItemStatus;
use crate::dispatch::lease::{self, Change};
use crate::dispatch::merge::{self, Checks, Prepared, Tree, Verified, Verifying, Writer};
use crate::dispatch::worker;
use crate::git;
use crate::orchestrate::form::Expected;
use crate::orchestrate::issue::Issue;
use crate::orchestrate::labels::{self, LABELS_FILE, LabelsFile};
use crate::orchestrate::launch::trust;
use crate::orchestrate::records::{self, Lease, Reason, Record};
use crate::orchestrate::tracker::{PullRequest, Squash};
use crate::repo::Repo;

/// The queue's one verify slot.
pub(super) enum Landing {
    Idle,
    Verifying(Box<Verifying>),
}

impl Dispatcher<'_> {
    /// Lands `request` for `issue`, or says why not yet.
    pub(super) fn land(
        &mut self,
        issue: &Issue,
        lease: &Lease,
        found: &[Record],
        request: &PullRequest,
    ) -> Result<()> {
        let n = issue.number;
        if acceptance_changed(issue, lease) {
            note(
                &self.repo,
                "acceptance-changed",
                Some(lease),
                Reason::AcceptanceChanged.describe(),
            );
            return lease::transition(
                self.tracker,
                n,
                lease.attempt,
                ItemStatus::InReview,
                ItemStatus::Proposed,
                Reason::AcceptanceChanged,
            );
        }
        let Some(request) = merge::landable(request) else {
            self.notice(
                n,
                "passed review; its pull request is a draft or has no head yet",
            );
            return Ok(());
        };
        let ids: Vec<&str> = self.kit.models.ids().collect();
        let expected = Expected {
            item: n,
            attempt: lease.attempt,
            model_ids: &ids,
        };
        let problems = self.form.pull_request_problems(request, expected);
        if !problems.is_empty() {
            let detail = format!("Fix and run kit handoff again: {}.", problems.join("; "));
            return self.queue_refused(issue, lease, found, Reason::PullRequestInvalid, &detail);
        }
        match merge::rollup(&request.checks) {
            Checks::Failed(names) => {
                let detail = format!("Failed: {}.", names.join(", "));
                return self.queue_refused(issue, lease, found, Reason::ChecksFailed, &detail);
            }
            Checks::Waiting(names) => {
                self.notice(
                    n,
                    &format!("passed review; waiting for {}", names.join(", ")),
                );
                return Ok(());
            }
            Checks::Green => {}
        }
        let used = u32::try_from(failed_rounds(found, lease))
            .unwrap_or(u32::MAX)
            .saturating_add(1);
        if used > self.max_rounds() {
            return self.rounds_used(issue, lease);
        }
        let fetched = merge::fetch(
            &self.repo,
            &self.form.remote,
            &self.form.base,
            &lease.branch,
        );
        let base_tip = match fetched {
            Ok(tip) => tip,
            Err(error) => {
                self.notice(
                    n,
                    &format!("passed review; the queue cannot fetch: {error:#}"),
                );
                return Ok(());
            }
        };
        let tree = Tree {
            pr: request.number,
            item: n,
            head: request.head.clone(),
            base: request.base.clone(),
            base_tip,
        };
        if self.verified.get(&request.number) == Some(&tree) {
            return self.merge(issue, request, &tree);
        }
        self.verify(issue, lease, found, tree)
    }

    fn verify(&mut self, issue: &Issue, lease: &Lease, found: &[Record], tree: Tree) -> Result<()> {
        if let Landing::Verifying(running) = &self.landing {
            let what = if running.tree == tree {
                "passed review; the merge queue is verifying it".to_owned()
            } else {
                format!(
                    "passed review; waits for the queue to verify #{}",
                    running.tree.item
                )
            };
            self.notice(issue.number, &what);
            return Ok(());
        }
        let writer = Writer::of(&self.kit, issue, lease);
        let prepared =
            match writer.and_then(|writer| merge::start(&self.repo, &self.queue, &tree, &writer)) {
                Ok(prepared) => prepared,
                Err(error) => {
                    self.notice(
                        issue.number,
                        &format!("passed review; the queue cannot verify: {error:#}"),
                    );
                    return Ok(());
                }
            };
        match prepared {
            Prepared::Started(running) => {
                println!(
                    "dispatch: #{} verifying {} on {} (log {})",
                    issue.number,
                    tree.head,
                    tree.base_tip,
                    running.log.display()
                );
                self.landing = Landing::Verifying(running);
                Ok(())
            }
            Prepared::Conflict(detail) if self.is_seed_lease(lease) => {
                let change = Change {
                    item: issue.number,
                    attempt: lease.attempt,
                    from: ItemStatus::InReview,
                    to: ItemStatus::Escalated,
                    reason: Reason::MergeConflict,
                };
                let detail = format!(
                    "The seed branch no longer merges onto {}: {detail}. No session can merge or rebase it, and the seed's issue has no second attempt, so the chief architect decides how it continues.",
                    tree.base
                );
                lease::transition_with(self.tracker, &change, Some(&detail))
            }
            Prepared::Conflict(detail) => {
                let detail = format!(
                    "The branch no longer merges onto {}: {detail}. A session cannot merge or rebase, so push nothing and stop; the attempt then ends and the next one starts from the current base.",
                    tree.base
                );
                self.queue_refused(issue, lease, found, Reason::MergeConflict, &detail)
            }
        }
    }

    fn merge(&mut self, issue: &Issue, request: &PullRequest, tree: &Tree) -> Result<()> {
        let labels_changed = git::try_output(
            &self.repo,
            &[
                "diff",
                "--quiet",
                &tree.base_tip,
                &tree.head,
                "--",
                LABELS_FILE,
            ],
        )?
        .is_none();
        let subject = self.form.squash_subject(&request.title, request.number);
        self.tracker.squash_merge(&Squash {
            number: request.number,
            subject: &subject,
            head: &tree.head,
        })?;
        self.verified.remove(&request.number);
        self.assisted.reviewing.remove(&issue.number);
        self.assisted.save(&self.repo)?;
        let after = self.tracker.issue(issue.number)?;
        if after.is_open() {
            self.tracker.close_issue(issue.number)?;
        }
        note(
            &self.repo,
            "landed",
            None,
            &format!("#{} as {subject}", issue.number),
        );
        println!("dispatch: #{} landed as `{subject}`", issue.number);
        if labels_changed {
            let landed = Repo::at(worker::worktree_dir(&self.repo, &self.queue.worktree));
            match LabelsFile::load(&landed) {
                Ok(file) => {
                    self.unsynced_labels = Some(file);
                    self.sync_labels();
                }
                Err(error) => {
                    println!("dispatch: the landed {LABELS_FILE} does not load: {error:#}");
                }
            }
        }
        Ok(())
    }

    /// Applies a landed `.github/labels.toml` to the repository (team/06 section 13 step 6), so
    /// its labels exist before an agent files one; a failed sync is tried again on the next
    /// review pass.
    pub(super) fn sync_labels(&mut self) {
        let Some(file) = self.unsynced_labels.take() else {
            return;
        };
        match labels::sync(self.tracker, &file, false) {
            Ok(_) => {
                note(&self.repo, "labels-synced", None, LABELS_FILE);
                self.labels = file;
            }
            Err(error) => {
                println!(
                    "dispatch: syncing the landed {LABELS_FILE} failed: {error:#}; it is tried again on the next pass"
                );
                self.unsynced_labels = Some(file);
            }
        }
    }

    /// Polls the running verify; a pass is kept for the next GitHub pass to land, a failure
    /// sends the item back to its worker.
    pub fn step_queue(&mut self) -> Result<()> {
        let Landing::Verifying(running) = &mut self.landing else {
            return Ok(());
        };
        let verdict = running.poll();
        if verdict == Verified::Running {
            return Ok(());
        }
        let tree = running.tree.clone();
        self.landing = Landing::Idle;
        match verdict {
            Verified::Passed => {
                println!(
                    "dispatch: #{} verified; it lands on the next pass",
                    tree.item
                );
                self.verified.insert(tree.pr, tree);
                Ok(())
            }
            Verified::Running => Ok(()),
            Verified::Failed(detail) => {
                let issue = self.tracker.issue(tree.item)?;
                let found = records::records(&issue);
                let Some(lease) = records::current_lease(&found, tree.item).cloned() else {
                    return Ok(());
                };
                let detail = format!("{detail}.");
                self.queue_refused(&issue, &lease, &found, Reason::VerifyFailed, &detail)
            }
        }
    }

    /// `cargo xtask queue`: review passes that only land. A pass that verified a tree is followed
    /// at once by the pass that lands it; with `once`, the first pass that verified nothing ends
    /// the run. The review pass starts evaluators and fix sessions, so it runs only while Claude
    /// Code trusts the repository folder.
    pub fn run_queue(&mut self, once: bool) -> Result<()> {
        trust::require(&self.repo)?;
        loop {
            if let Err(error) = trust::require(&self.repo).and_then(|()| self.review()) {
                eprintln!("queue: {error:#}; retrying on the next pass");
            }
            let before = self.verified.len();
            while matches!(self.landing, Landing::Verifying(_)) {
                self.step_queue()?;
                std::thread::sleep(LOCAL_POLL.min(self.policy.poll));
            }
            if self.verified.len() > before {
                continue;
            }
            if once {
                return Ok(());
            }
            std::thread::sleep(self.policy.poll);
        }
    }
}
