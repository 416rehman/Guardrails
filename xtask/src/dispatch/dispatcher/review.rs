//! The review pass (owner instructions 6 to 8, team/02 section 10, team/01 section 5): every
//! issue in review gets the evaluators its lane needs (`evaluators.rs`) without a person starting
//! them, `eval-tier` first. The verdicts are the evaluators' `handoff.v1` comments since the issue
//! last entered review; a pass counts only from the model it was asked on. A failed round sends
//! the item back to its worker until the rounds are used up, and a failed light round raises the
//! item to standard; a round with no verdict within the deadline is escalated. Every send-back,
//! the merge queue's included, uses one of the rounds, so no loop between the worker and the
//! queue is unbounded. A passed change goes to the merge queue (`landing.rs`).

use anyhow::Result;
use serde_json::Value;

use super::assist::{AssistJob, Purpose, Round};
use super::evaluators::{EVAL_DIFF, Needed, Plan};
use super::{Dispatcher, Prompt, Slot};
use crate::config::session::ItemStatus;
use crate::dispatch::lease::{self, Change};
use crate::dispatch::routines::{HOUR, now_unix, unix_of};
use crate::dispatch::worker;
use crate::github::Identity;
use crate::orchestrate::issue::{Issue, status_label};
use crate::orchestrate::records::{self, LANE_SCHEMA, LaneRaise, Lease, Reason, Record};
use crate::orchestrate::risk::Lane;

const EVAL_TIER: &str = "eval-tier";
const PASS: &str = "pass";
/// The name the dispatcher's own `lane.v1` comments carry, as `.github/labels.toml` names it.
const DISPATCHER: &str = "dispatcher";
/// The send-backs that use a review round: an evaluator's findings and every refusal by the
/// merge queue, which a worker answers with a new head that the evaluators judge again.
const ROUND_ENDS: &[Reason] = &[
    Reason::EvaluatorFindings,
    Reason::PullRequestInvalid,
    Reason::ChecksFailed,
    Reason::VerifyFailed,
    Reason::MergeConflict,
];

/// The review round the evaluators start in: its first record, the pull request head they judge
/// and the lane.
pub(super) struct RoundStart<'a> {
    since: usize,
    head: &'a str,
    lane: Lane,
}

/// What the verdicts of the current round say.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdicts {
    Missing(Vec<Needed>),
    Failed(String),
    Passed,
}

impl Dispatcher<'_> {
    pub(super) fn review(&mut self) -> Result<()> {
        self.sync_labels();
        let Some(label) = status_label(ItemStatus::InReview) else {
            return Ok(());
        };
        for summary in self.tracker.open_with_label(&label)? {
            if self.assisting(summary.number) || self.held().contains(&summary.number) {
                continue;
            }
            let issue = self.tracker.issue(summary.number)?;
            if let Err(error) = self.review_issue(&issue) {
                println!("dispatch: #{} review: {error:#}", issue.number);
            }
        }
        Ok(())
    }

    fn review_issue(&mut self, issue: &Issue) -> Result<()> {
        let found = records::timed_records(issue);
        let plain: Vec<Record> = found.iter().map(|(_, record)| record.clone()).collect();
        let Some(lease) = records::current_lease(&plain, issue.number).cloned() else {
            return Ok(());
        };
        let since = found
            .iter()
            .rposition(|(_, record)| {
                matches!(record, Record::Transition(t) if t.to == ItemStatus::InReview)
            })
            .or_else(|| {
                found
                    .iter()
                    .rposition(|(_, record)| matches!(record, Record::Lease(l) if *l == lease))
            })
            .unwrap_or(0);
        let entered = found.get(since).and_then(|(at, _)| unix_of(at));
        let overdue = entered.is_some_and(|at| {
            now_unix().saturating_sub(at) > self.policy.verdict_hours.saturating_mul(HOUR)
        });
        let Some(request) = self.tracker.open_pull_request(&lease.branch)? else {
            if overdue {
                return self.escalate(issue.number, &lease, Reason::NoVerdict);
            }
            self.notice(issue.number, "is in review with no open pull request");
            return Ok(());
        };
        let (lane, needed) = match self.plan_review(issue, &lease, &plain, &request)? {
            Plan::OneModel { required } => {
                println!(
                    "dispatch: #{} needs passing evaluators on {required} models, and its lane's evaluators run on one",
                    issue.number
                );
                return self.escalate(issue.number, &lease, Reason::EvaluatorsOnOneModel);
            }
            Plan::Unavailable(why) => {
                println!(
                    "dispatch: #{} cannot be reviewed: {}",
                    issue.number,
                    why.join("; ")
                );
                return self.escalate(issue.number, &lease, Reason::EvaluatorUnavailable);
            }
            Plan::Evaluate { lane, needed } => (lane, needed),
        };
        let round = found.get(since..).unwrap_or_default();
        match verdicts(round, issue.number, &needed) {
            Verdicts::Passed => self.land(issue, &lease, &plain, &request),
            Verdicts::Failed(by) => self.failed_round(issue, &lease, &plain, &by, lane),
            Verdicts::Missing(_) if overdue => {
                self.escalate(issue.number, &lease, Reason::NoVerdict)
            }
            Verdicts::Missing(missing) => {
                let start = RoundStart {
                    since,
                    head: &request.head,
                    lane,
                };
                self.start_evaluators(issue.number, &lease, &start, &missing)
            }
        }
    }

    fn start_evaluators(
        &mut self,
        item: u64,
        lease: &Lease,
        start: &RoundStart,
        missing: &[Needed],
    ) -> Result<()> {
        let capacity = usize::try_from(self.policy.max_evaluators).unwrap_or(0);
        let round = self.assisted.reviewing.entry(item).or_default();
        if round.since != start.since {
            *round = Round {
                since: start.since,
                ..Round::default()
            };
        }
        let started = round.started.clone();
        let first = missing.iter().find(|needed| needed.agent == EVAL_TIER);
        let wanted: Vec<&Needed> = match first {
            Some(tier) => vec![tier],
            None => missing.iter().collect(),
        };
        for needed in wanted {
            if started.contains(&needed.agent) || self.assists_for(Purpose::Review) >= capacity {
                continue;
            }
            let prompt = self.review_prompt(item, lease, &needed.agent, start)?;
            let worktree = worker::attempt_worktree(item, lease.attempt);
            let job = AssistJob {
                purpose: Purpose::Review,
                item,
                agent: &needed.agent,
                worktree: &worktree,
                branch: Some(&lease.branch),
                prompt: &prompt,
                model: needed.ask_model.then_some(needed.model.as_str()),
                effort: needed.effort.as_deref(),
            };
            match self.start_assist(&job) {
                Ok(()) => {
                    if let Some(round) = self.assisted.reviewing.get_mut(&item) {
                        round.started.push(needed.agent.clone());
                    }
                }
                Err(error) => println!(
                    "dispatch: #{item}: {} did not start: {error:#}",
                    needed.agent
                ),
            }
        }
        self.assisted.save(&self.repo)
    }

    /// `.agents/kit/prompts/dispatch-review.md` with `{item}`, `{agent}`, `{branch}`, `{lane}`,
    /// `{head}` and `{repository}` when present, otherwise one paragraph; the light lane's pass
    /// runs without the review workflow. The commit status is spelled out because only that form
    /// of `gh api` has a permission rule, and the verdict goes through a draft file because
    /// `dontAsk` refuses a here-document that carries JSON.
    fn review_prompt(
        &self,
        item: u64,
        lease: &Lease,
        agent: &str,
        start: &RoundStart,
    ) -> Result<String> {
        let (b, head, lane) = (&lease.branch, start.head, start.lane);
        let repository = Identity::load(&self.repo)?.repository;
        let how = match lane {
            Lane::Light => {
                "in one pass on the diff, without the review workflow and without audits (the light lane). This is owner instruction 8's single Sonnet pass, not the cross-model review, so grdr-evaluate's stop for a reviewer on the writer's model does not apply to it"
            }
            _ if agent == EVAL_DIFF => "with the review workflow",
            _ => "with the grdr-evaluate skill",
        };
        let line = format!(
            "Evaluate the pull request of issue #{item} on branch {b}, head {head}, as {agent} {how}. Judge it against the acceptance criteria the issue's ready.v1 digest names, or for an issue the kit put in review without a ready.v1 (the seed's) the lease.v1 digest the kit posted; cargo xtask kit digest {item} prints the digests. Post your verdict as the commit status gh api --method POST repos/{repository}/statuses/{head} -f state=<success, failure or error> -f context=grdr-evaluator/{agent} -f description='<one line>', then write the handoff.v1 JSON, whose status is pass, fail or cannot-evaluate, to .agent/state/handoff-{item}-{agent}.json with the Write tool and finish with cargo xtask kit handoff --item {item}."
        );
        let number = item.to_string();
        Ok(self
            .template(
                "review",
                &[
                    ("item", number.as_str()),
                    ("agent", agent),
                    ("branch", b.as_str()),
                    ("lane", lane.name()),
                    ("head", head),
                    ("repository", repository.as_str()),
                ],
            )?
            .unwrap_or(line))
    }

    /// A send-back from the merge queue, which uses a round as a failed review does.
    pub(super) fn queue_refused(
        &mut self,
        issue: &Issue,
        lease: &Lease,
        found: &[Record],
        reason: Reason,
        detail: &str,
    ) -> Result<()> {
        let round = u32::try_from(failed_rounds(found, lease))
            .unwrap_or(u32::MAX)
            .saturating_add(1);
        if round < self.max_rounds() {
            return self.send_back(issue, lease, reason, detail);
        }
        println!(
            "dispatch: #{} used its {} rounds: {}",
            issue.number,
            self.max_rounds(),
            reason.describe()
        );
        self.rounds_used(issue, lease)
    }

    /// A failed round: back to the worker on the same attempt while rounds remain; then the
    /// lead re-plans it, or after the last attempt it is escalated. A failed light round raises
    /// the item to standard, so the light lane gets one round.
    fn failed_round(
        &mut self,
        issue: &Issue,
        lease: &Lease,
        found: &[Record],
        by: &str,
        lane: Lane,
    ) -> Result<()> {
        let rounds = failed_rounds(found, lease);
        let limit = self.max_rounds();
        let round = u32::try_from(rounds).unwrap_or(u32::MAX).saturating_add(1);
        println!(
            "dispatch: #{} failed review round {round} ({by})",
            issue.number
        );
        if lane == Lane::Light {
            let raise = LaneRaise {
                schema: LANE_SCHEMA.to_owned(),
                item: issue.number,
                lane: Lane::Standard,
                by: DISPATCHER.to_owned(),
                reason: format!("the light review failed ({by})"),
            };
            self.tracker
                .comment(issue.number, &records::lane_comment(&raise)?)?;
        }
        if round < limit {
            return self.send_back(issue, lease, Reason::EvaluatorFindings, by);
        }
        self.rounds_used(issue, lease)
    }

    /// The rounds are used up: the lead re-plans the item, or after the last attempt (the seed's
    /// issue has one) it is escalated (`.github/labels.toml`'s in-review transitions for
    /// review-rounds-used).
    pub(super) fn rounds_used(&mut self, issue: &Issue, lease: &Lease) -> Result<()> {
        let to = if lease.attempt < self.attempts_for(lease) {
            ItemStatus::Proposed
        } else {
            ItemStatus::Escalated
        };
        lease::transition(
            self.tracker,
            issue.number,
            lease.attempt,
            ItemStatus::InReview,
            to,
            Reason::ReviewRoundsUsed,
        )
    }

    pub(super) fn max_rounds(&self) -> u32 {
        self.policy.max_review_rounds
    }

    /// Back to the worker on the same attempt, with why, and its fix session started when a
    /// writer slot is free.
    fn send_back(
        &mut self,
        issue: &Issue,
        lease: &Lease,
        reason: Reason,
        detail: &str,
    ) -> Result<()> {
        let change = Change {
            item: issue.number,
            attempt: lease.attempt,
            from: ItemStatus::InReview,
            to: ItemStatus::Leased,
            reason,
        };
        let held = self.held_for(issue, lease.clone())?;
        lease::transition_with(self.tracker, &change, Some(detail))?;
        let free = self.slots.len() < usize::try_from(self.policy.max_writers).unwrap_or(0);
        if free {
            let kept = held.clone();
            match self.start(held, Prompt::Fix) {
                Ok(slot) => self.slots.extend(slot),
                Err(_) => self.slots.push(Slot::Paused {
                    held: kept,
                    prompt: Prompt::Fix,
                }),
            }
        } else {
            self.slots.push(Slot::Paused {
                held,
                prompt: Prompt::Fix,
            });
        }
        Ok(())
    }

    pub(super) fn escalate(&mut self, item: u64, lease: &Lease, reason: Reason) -> Result<()> {
        lease::transition(
            self.tracker,
            item,
            lease.attempt,
            ItemStatus::InReview,
            ItemStatus::Escalated,
            reason,
        )
    }

    /// Prints `what` for `item` once, until the notice changes.
    pub(super) fn notice(&mut self, item: u64, what: &str) {
        if self.notices.get(&item).is_some_and(|last| last == what) {
            return;
        }
        println!("dispatch: #{item} {what}");
        self.notices.insert(item, what.to_owned());
    }
}

/// The rounds since the lease that ended in a send-back to the worker.
pub(super) fn failed_rounds(found: &[Record], lease: &Lease) -> usize {
    since_lease(found, lease)
        .iter()
        .filter(|record| matches!(record, Record::Transition(t) if ROUND_ENDS.contains(&t.reason)))
        .count()
}

/// The records from the newest posted copy of `lease` on; none when it was never posted. The
/// session is not compared: the dispatcher names a new one for each session after the first.
pub(super) fn since_lease<'r>(found: &'r [Record], lease: &Lease) -> &'r [Record] {
    found
        .iter()
        .rposition(|record| matches!(record, Record::Lease(posted) if same_lease(posted, lease)))
        .and_then(|index| found.get(index..))
        .unwrap_or_default()
}

fn same_lease(posted: &Lease, lease: &Lease) -> bool {
    posted.item == lease.item
        && posted.attempt == lease.attempt
        && posted.agent == lease.agent
        && posted.branch == lease.branch
}

/// The verdicts in `round` (records since the issue last entered review) for the needed
/// evaluators: a fail or cannot-evaluate from any of them fails the round, and a pass counts
/// only from the model the evaluator was needed on.
fn verdicts(round: &[(String, Record)], item: u64, needed: &[Needed]) -> Verdicts {
    let latest = |agent: &str| {
        round.iter().rev().find_map(|(_, record)| {
            let value = handoff_by(record, item, agent)?;
            let status = value.get("status").and_then(Value::as_str)?;
            let model = value
                .get("model")
                .and_then(Value::as_str)
                .unwrap_or_default();
            Some((status.to_owned(), model.to_owned()))
        })
    };
    let mut missing = Vec::new();
    for want in needed {
        match latest(&want.agent) {
            Some((status, model)) if status == PASS && model == want.model => {}
            Some((status, _)) if status == PASS => missing.push(want.clone()),
            Some((status, _)) => return Verdicts::Failed(format!("{}: {status}", want.agent)),
            None => missing.push(want.clone()),
        }
    }
    if missing.is_empty() {
        Verdicts::Passed
    } else {
        Verdicts::Missing(missing)
    }
}

/// `record` when it is a hand-off by `agent` on `item`.
pub(super) fn handoff_by<'r>(record: &'r Record, item: u64, agent: &str) -> Option<&'r Value> {
    match record {
        Record::Handoff(value)
            if value.get("item").and_then(Value::as_u64) == Some(item)
                && value.get("agent").and_then(Value::as_str) == Some(agent) =>
        {
            Some(value)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchestrate::records::{LEASE_SCHEMA, STATE_SCHEMA, Transition};

    fn back(reason: Reason) -> Record {
        Record::Transition(Transition {
            schema: STATE_SCHEMA.to_owned(),
            item: 7,
            attempt: 1,
            from: ItemStatus::InReview,
            to: ItemStatus::Leased,
            reason,
        })
    }

    #[test]
    fn every_send_back_uses_a_round_and_nothing_else_does() {
        let lease = Lease {
            schema: LEASE_SCHEMA.to_owned(),
            item: 7,
            attempt: 1,
            agent: "impl-rust".to_owned(),
            model: "claude-sonnet-5-5".to_owned(),
            acceptance_sha256: "ab".to_owned(),
            branch: "agent/7/a1".to_owned(),
            session: None,
        };
        let mut found = vec![Record::Lease(lease.clone())];
        found.extend(ROUND_ENDS.iter().map(|reason| back(*reason)));
        found.push(back(Reason::AcceptanceChanged));
        assert_eq!(failed_rounds(&found, &lease), ROUND_ENDS.len());
        assert!(ROUND_ENDS.contains(&Reason::ChecksFailed));
        assert!(ROUND_ENDS.contains(&Reason::VerifyFailed));
    }

    /// A slot's lease names the session it runs now, a later one than the posted copy names.
    #[test]
    fn the_records_since_a_lease_start_at_its_posted_copy_and_nowhere_else() {
        let posted = Lease {
            schema: LEASE_SCHEMA.to_owned(),
            item: 7,
            attempt: 2,
            agent: "impl-rust".to_owned(),
            model: "claude-sonnet-5-5".to_owned(),
            acceptance_sha256: "ab".to_owned(),
            branch: "agent/7/a2".to_owned(),
            session: Some("6b1c0f4e-1111-4222-8333-944455556607".to_owned()),
        };
        let found = vec![
            back(Reason::EvaluatorFindings),
            Record::Lease(posted.clone()),
            back(Reason::ChecksFailed),
        ];
        let running = Lease {
            session: Some("6b1c0f4e-1111-4222-8333-944455556617".to_owned()),
            ..posted.clone()
        };
        assert_eq!(since_lease(&found, &running).len(), 2);
        let never_posted = Lease {
            attempt: 3,
            ..posted
        };
        assert!(since_lease(&found, &never_posted).is_empty());
    }
}
