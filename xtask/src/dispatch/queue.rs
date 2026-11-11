//! Which `status:ready` issues may be leased, and in what order (team/01 sections 3 and 7, owner
//! instruction 5): every blocker closed, the agent a roster agent the dispatcher may run, and the
//! latest `ready.v1` from an agent allowed to ready, never the item's implementer, carrying the
//! digests of the current acceptance section and write set. An issue whose section or write set
//! changed, or whose readying is not valid, goes back to `status:proposed`. An agent bound to fable, the chief architect, is
//! leased only its protected-change items (owner instruction 7, D-63), one fable session at a
//! time.

use anyhow::Result;

use super::policy::{OrderKey, Policy};
use crate::config::session::{ItemStatus, RiskTier};
use crate::orchestrate::issue::{Issue, IssueState, WorkItem};
use crate::orchestrate::labels::LabelsFile;
use crate::orchestrate::launch::{self, LaunchKit};
use crate::orchestrate::records::{self, Reason};
use crate::orchestrate::tracker::Tracker;

/// Sorts after `priority:p3`.
const NO_PRIORITY: u8 = 4;

/// An issue the dispatcher may lease now.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub issue: Issue,
    pub item: WorkItem,
    pub agent: String,
    pub digest: String,
    pub attempt: u32,
    pub blocks_others: bool,
}

#[derive(Debug, Clone)]
pub enum Verdict {
    Eligible(Box<Candidate>),
    /// Not now; the reason is printed and the issue stays ready.
    Wait(String),
    /// Back to `status:proposed` for a lead to ready again.
    Unready(Reason),
}

/// Judges one ready issue; `issue` carries its comments.
pub fn assess(
    issue: &Issue,
    kit: &LaunchKit,
    labels: &LabelsFile,
    policy: &Policy,
    tracker: &dyn Tracker,
) -> Result<Verdict> {
    let item = issue.work_item();
    let Some(agent) = item.agent.clone() else {
        return Ok(Verdict::Wait("no agent: label".to_owned()));
    };
    if kit.roster.agent(&agent).is_none() {
        return Ok(Verdict::Wait(format!(
            "agent `{agent}` is not in the roster"
        )));
    }
    if kit.models.rules.fable_agents.contains(&agent) {
        if !kit.is_protected_change(&agent, &item.write_set)? {
            return Ok(Verdict::Wait(format!(
                "{agent} runs on fable, which the dispatcher leases only protected-change items; a lead names another agent"
            )));
        }
        if launch::fable_session_running()? {
            return Ok(Verdict::Wait(
                "a fable session already runs; the chief architect runs one session at a time"
                    .to_owned(),
            ));
        }
    }
    let found = records::records(issue);
    let Some((_, ready)) = records::latest_ready(&found, issue.number) else {
        return Ok(Verdict::Unready(Reason::NoValidReady));
    };
    let readier_allowed =
        labels.may_ready(&ready.by, kit.acting_as(&ready.by))? && ready.by != agent;
    if !readier_allowed {
        return Ok(Verdict::Unready(Reason::NoValidReady));
    }
    let current = item.acceptance.as_ref().map(|a| a.sha256.as_str());
    if current != Some(ready.acceptance_sha256.as_str()) {
        return Ok(Verdict::Unready(Reason::AcceptanceChanged));
    }
    if !records::write_set_readied(&found, &item) {
        return Ok(Verdict::Unready(Reason::WriteSetChanged));
    }
    let open: Vec<u64> = tracker
        .blocked_by(issue.number)?
        .into_iter()
        .filter(|dependency| dependency.state == IssueState::Open)
        .map(|dependency| dependency.number)
        .collect();
    if let Some(first) = open.first() {
        return Ok(Verdict::Wait(format!("blocked by #{first}")));
    }
    let attempt = records::current_lease(&found, issue.number)
        .map_or(1, |lease| lease.attempt.saturating_add(1));
    if attempt > policy.max_attempts {
        return Ok(Verdict::Wait(format!(
            "its {} attempts are used; a lead readies it again",
            policy.max_attempts
        )));
    }
    let blocks_others = if policy.lease_order.contains(&OrderKey::BlocksOthers) {
        tracker
            .blocking(issue.number)?
            .iter()
            .any(|d| d.state == IssueState::Open)
    } else {
        false
    };
    Ok(Verdict::Eligible(Box::new(Candidate {
        issue: issue.clone(),
        item,
        agent,
        digest: ready.acceptance_sha256.clone(),
        attempt,
        blocks_others,
    })))
}

/// Orders candidates by the policy's lease order, issue number last.
pub fn order(candidates: &mut [Candidate], keys: &[OrderKey]) {
    candidates.sort_by(|a, b| {
        keys.iter()
            .map(|key| match key {
                OrderKey::BlocksOthers => b.blocks_others.cmp(&a.blocks_others),
                OrderKey::Priority => priority(a).cmp(&priority(b)),
                OrderKey::Age => a.issue.created_at.cmp(&b.issue.created_at),
            })
            .find(|ordering| ordering.is_ne())
            .unwrap_or_else(|| a.issue.number.cmp(&b.issue.number))
    });
}

/// Resume order after a pause: trust-core first, then high tier, then priority.
pub fn urgency(trust_core: bool, tier: RiskTier, priority: Option<u8>) -> (u8, u8, u8) {
    let tier = match tier {
        RiskTier::High => 0,
        RiskTier::Medium => 1,
        RiskTier::Low => 2,
    };
    (u8::from(!trust_core), tier, priority.unwrap_or(NO_PRIORITY))
}

/// Swaps `status:ready` for `status:proposed` with the reason as a `state.v1` comment.
pub fn unready(tracker: &dyn Tracker, issue: &Issue, reason: Reason) -> Result<()> {
    let attempt =
        records::current_lease(&records::records(issue), issue.number).map_or(0, |l| l.attempt);
    super::lease::transition(
        tracker,
        issue.number,
        attempt,
        ItemStatus::Ready,
        ItemStatus::Proposed,
        reason,
    )
}

fn priority(candidate: &Candidate) -> u8 {
    candidate.item.priority.unwrap_or(NO_PRIORITY)
}
