//! The planning pass (owner instructions 6 and 7, team/01 sections 3 and 6): every proposed,
//! escalated or blocked issue gets a planner session without a person starting it. The squad's
//! lead from `.agents/owners.toml` plans it, the product lead when the issue names no squad or
//! when the squad's lead is the issue's own agent, since the agent that readies an item never
//! implements it; an escalation the lead leaves unresolved goes to the chief architect, who
//! decides it, one fable session at a time and never on a cadence. An issue is planned again only
//! once its `updatedAt` moved since its last planner ended, so an unchanged issue costs no read
//! beyond the list. The seed session's own issue is not planned until the seed's hand-off posts
//! its lease; after that only the chief architect, whose seed scope it is, decides it, and only
//! when it is escalated, where every seed attempt that ends without landing goes. Nobody plans it
//! at proposed, where the dispatcher starts the seed session again instead (`leasing.rs`), or at
//! blocked, which the chief architect may not move it from.

use anyhow::Result;

use super::Dispatcher;
use super::assist::{AssistJob, Purpose};
use super::review::since_lease;
use crate::config::session::ItemStatus;
use crate::kit::CHIEF_ARCHITECT;
use crate::orchestrate::issue::{Issue, status_label};
use crate::orchestrate::records::{self, Reason, Record};

const PRODUCT_LEAD: &str = "product-lead";
const PLANNED: &[ItemStatus] = &[
    ItemStatus::Escalated,
    ItemStatus::Proposed,
    ItemStatus::Blocked,
];
const FINISH: &str = "Finish by writing the handoff.v1 JSON to .agent/state/handoff-{n}-{agent}.json with the Write tool and running cargo xtask kit handoff --item {n} (skill grdr-handoff).";

impl Dispatcher<'_> {
    pub(super) fn plan(&mut self) -> Result<()> {
        let capacity = usize::try_from(self.policy.max_planners).unwrap_or(0);
        for status in PLANNED {
            let Some(label) = status_label(*status) else {
                continue;
            };
            for summary in self.tracker.open_with_label(&label)? {
                if self.assists_for(Purpose::Plan) >= capacity {
                    return Ok(());
                }
                if self.assisting(summary.number)
                    || self.held().contains(&summary.number)
                    || self.awaits_seed_handoff(&summary)?
                {
                    continue;
                }
                let Some(agent) = self.planner_for(&summary, *status) else {
                    continue;
                };
                let busy = self.assists.iter().any(|assist| assist.agent == agent);
                let fable = self.is_fable(&agent) && self.fable_busy()?;
                if busy || fable {
                    continue;
                }
                let prompt = self.planning_prompt(&summary, *status, &agent)?;
                let worktree = format!("plan-{agent}");
                let job = AssistJob {
                    purpose: Purpose::Plan,
                    item: summary.number,
                    agent: &agent,
                    worktree: &worktree,
                    branch: None,
                    prompt: &prompt,
                    model: None,
                    effort: None,
                };
                if let Err(error) = self.start_assist(&job) {
                    println!("dispatch: #{} was not planned: {error:#}", summary.number);
                }
            }
        }
        Ok(())
    }

    /// The squad's lead, or the product lead when there is no squad lead or it is the issue's
    /// own agent; the seed scope's agent for the seed's issue, which is planned only when escalated;
    /// the chief architect for an escalation its lead already saw and left as it was; nobody for
    /// an issue unchanged since its last planner. `issue` is the list entry, whose labels and
    /// `updatedAt` are all this needs.
    fn planner_for(&self, issue: &Issue, status: ItemStatus) -> Option<String> {
        let item = issue.work_item();
        let seed = self
            .kit
            .seed
            .as_ref()
            .filter(|seed| seed.names_issue(&issue.title));
        let lead = match seed {
            Some(seed) if status == ItemStatus::Escalated => seed.agent.clone(),
            Some(_) => return None,
            None => item
                .squad
                .and_then(|squad| self.squad_leads.get(&squad).cloned())
                .filter(|lead| self.kit.roster.agent(lead).is_some())
                .filter(|lead| item.agent.as_ref() != Some(lead))
                .unwrap_or_else(|| PRODUCT_LEAD.to_owned()),
        };
        let chosen = match self.assisted.planned.get(&issue.number) {
            Some(last) if last.updated_at == issue.updated_at => {
                let escalate = status == ItemStatus::Escalated && last.agent != CHIEF_ARCHITECT;
                escalate.then(|| CHIEF_ARCHITECT.to_owned())?
            }
            _ => lead,
        };
        self.kit.roster.agent(&chosen).is_some().then_some(chosen)
    }

    /// The issue `.agents/kit/seed-scope.toml` reserves for the seed session.
    pub(super) fn is_seed_issue(&self, issue: &Issue) -> bool {
        self.kit
            .seed
            .as_ref()
            .is_some_and(|seed| seed.names_issue(&issue.title))
    }

    /// Whether `issue` is the seed's, still proposed with no `lease.v1`: the seed's hand-off posts
    /// one as it moves the issue into review. `issue` may be a list entry without comments.
    pub(super) fn awaits_seed_handoff(&self, issue: &Issue) -> Result<bool> {
        if !self.is_seed_issue(issue) || issue.status() != Some(ItemStatus::Proposed) {
            return Ok(false);
        }
        let full = self.tracker.issue(issue.number)?;
        Ok(records::current_lease(&records::records(&full), issue.number).is_none())
    }

    /// `.agents/kit/prompts/dispatch-plan-<status>.md` when present, otherwise one line. The
    /// chief architect gets its own escalation prompt: nobody stands above it, so it decides; and
    /// for the seed's issue, which nobody readies, the prompt names what moving it on does.
    fn planning_prompt(&self, issue: &Issue, status: ItemStatus, agent: &str) -> Result<String> {
        let n = issue.number;
        let (kind, line) = match status {
            ItemStatus::Escalated if self.is_seed_issue(issue) => {
                ("plan-escalated-seed", self.seed_decision(n, agent)?)
            }
            ItemStatus::Escalated if agent == CHIEF_ARCHITECT => (
                "plan-escalated-final",
                format!(
                    "Issue #{n} is status:escalated and its lead left it unresolved. As {agent}, decide it (team/01 section 6): there is no one above you and no person to hand it to. Record the decision as a comment, or as a decision record when it outlives the item, then move it on with gh issue edit {n} --remove-label status:escalated --add-label status:proposed, or close it as not planned with the reason."
                ),
            ),
            ItemStatus::Escalated => (
                "plan-escalated",
                format!(
                    "Issue #{n} is status:escalated. As {agent}, read its escalation packet and decide it (team/01 section 6): record the decision as a comment, then move it on with gh issue edit {n} --remove-label status:escalated --add-label status:proposed, or close it as not planned with the reason. If the decision is above your role, leave it escalated and say why in the hand-off; the chief architect decides it next."
                ),
            ),
            ItemStatus::Blocked => (
                "plan-blocked",
                format!(
                    "Issue #{n} is status:blocked. As {agent}, check whether what it waits on holds now: if it does, move it to status:proposed with gh issue edit {n} --remove-label status:blocked --add-label status:proposed and plan it; if not, leave it and name what it still waits on."
                ),
            ),
            _ => (
                "plan",
                format!(
                    "Plan issue #{n}, which is status:proposed, as {agent} with the grdr-write-spec skill: give it a spec, a write set, acceptance criteria with named oracles and its labels, split a large one into sub-issues and set its dependencies, then ready it with cargo xtask kit ready {n}. Close it as not planned with the reason if it should not be done. You never ready an issue you implement."
                ),
            ),
        };
        let number = n.to_string();
        let finish = FINISH.replace("{n}", &number).replace("{agent}", agent);
        let text = format!("{line} {finish}");
        Ok(self
            .template(kind, &[("item", number.as_str()), ("agent", agent)])?
            .unwrap_or(text))
    }

    /// The decision on the seed's escalated issue `n`: moving it back to proposed starts the seed
    /// session again while `[item] max_attempts` leaves an attempt, and only closing is left
    /// after that, or once its branch no longer merges, which no session can clear.
    fn seed_decision(&self, n: u64, agent: &str) -> Result<String> {
        let issue = self.tracker.issue(n)?;
        let found = records::records(&issue);
        let lease = records::current_lease(&found, n).filter(|lease| self.is_seed_lease(lease));
        let conflict = lease.is_some_and(|lease| {
            since_lease(&found, lease)
                .iter()
                .rev()
                .find_map(|record| match record {
                    Record::Transition(transition) => Some(transition.reason),
                    _ => None,
                })
                == Some(Reason::MergeConflict)
        });
        let next = lease.and_then(|lease| self.next_seed_attempt(lease));
        let max = self.policy.max_attempts;
        let branch = self
            .kit
            .seed
            .as_ref()
            .map(|seed| seed.branch.as_str())
            .unwrap_or_default();
        let close_only = "Record the decision as a comment and close it as not planned with the reason, or leave it escalated and say why in the hand-off.";
        let (why, exits) = match next.filter(|_| !conflict) {
            Some(attempt) => (
                format!(
                    "nobody readies it, and once it is moved to status:proposed with gh issue edit {n} --remove-label status:escalated --add-label status:proposed, the dispatcher starts the seed session again on {branch}, attempt {attempt} of {max}, to carry the decision out"
                ),
                "Record the decision as a comment, then either move it to status:proposed as above, or close it as not planned with the reason.",
            ),
            None if conflict => (
                format!(
                    "its pull request no longer merges onto the base, and no session can merge or rebase {branch}, so starting the seed session again cannot clear the conflict"
                ),
                close_only,
            ),
            None => (
                format!(
                    "its {max} attempts are used, so the dispatcher does not start the seed session again"
                ),
                close_only,
            ),
        };
        Ok(format!(
            "Issue #{n} is the seed's own and status:escalated: {why}. As {agent}, decide it (team/01 section 6): there is no one above you and no person to hand it to. {exits}"
        ))
    }
}
