//! The planning pass (owner instructions 6 and 7, team/01 sections 3 and 6): every proposed,
//! escalated or blocked issue gets a planner session without a person starting it. The squad's
//! lead from `.agents/owners.toml` plans it, the product lead when the issue names no squad; an
//! escalation the lead leaves unresolved goes to the chief architect, who decides it, one fable
//! session at a time and never on a cadence. An issue is planned again only once its `updatedAt`
//! moved since its last planner ended, so an unchanged issue costs no read beyond the list.

use anyhow::Result;

use super::Dispatcher;
use super::assist::{AssistJob, Purpose};
use crate::config::session::ItemStatus;
use crate::kit::CHIEF_ARCHITECT;
use crate::orchestrate::issue::{Issue, status_label};
use crate::orchestrate::launch;

const PRODUCT_LEAD: &str = "product-lead";
const PLANNED: &[ItemStatus] = &[
    ItemStatus::Escalated,
    ItemStatus::Proposed,
    ItemStatus::Blocked,
];
const FINISH: &str = "Finish with cargo xtask kit handoff --item {n} --draft '<handoff.v1 JSON>' (skill grdr-handoff).";

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
                if self.assisting(summary.number) || self.held().contains(&summary.number) {
                    continue;
                }
                let Some(agent) = self.planner_for(&summary, *status) else {
                    continue;
                };
                let busy = self.assists.iter().any(|assist| assist.agent == agent);
                let fable = agent == CHIEF_ARCHITECT && launch::fable_session_running()?;
                if busy || fable {
                    continue;
                }
                let prompt = self.planning_prompt(summary.number, *status, &agent)?;
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

    /// The squad's lead, or the product lead; the chief architect for an escalation its lead
    /// already saw and left as it was; nobody for an issue unchanged since its last planner.
    /// `issue` is the list entry, whose labels and `updatedAt` are all this needs.
    fn planner_for(&self, issue: &Issue, status: ItemStatus) -> Option<String> {
        let lead = issue
            .work_item()
            .squad
            .and_then(|squad| self.squad_leads.get(&squad).cloned())
            .filter(|lead| self.kit.roster.agent(lead).is_some())
            .unwrap_or_else(|| PRODUCT_LEAD.to_owned());
        let chosen = match self.assisted.planned.get(&issue.number) {
            Some(last) if last.updated_at == issue.updated_at => {
                let escalate = status == ItemStatus::Escalated && last.agent != CHIEF_ARCHITECT;
                escalate.then(|| CHIEF_ARCHITECT.to_owned())?
            }
            _ => lead,
        };
        self.kit.roster.agent(&chosen).is_some().then_some(chosen)
    }

    /// `.agents/kit/prompts/dispatch-plan-<status>.md` when present, otherwise one line. The
    /// chief architect gets its own escalation prompt: nobody stands above it, so it decides.
    fn planning_prompt(&self, n: u64, status: ItemStatus, agent: &str) -> Result<String> {
        let (kind, line) = match status {
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
        let text = format!("{line} {}", FINISH.replace("{n}", &number));
        Ok(self
            .template(kind, &[("item", number.as_str()), ("agent", agent)])?
            .unwrap_or(text))
    }
}
