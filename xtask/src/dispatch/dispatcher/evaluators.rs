//! Which evaluators a review needs (owner instructions 7 and 8, team/02 section 10): the lane is
//! `cargo xtask risk` on the pull request's branch, raised by the issue's `lane.v1` comments and
//! never lowered, and [`RiskPolicy::lane_evaluators`] says what it needs, the change kind's and
//! the diff triggers' evaluators included. A trust-core change takes the full lane and a
//! protected-change item at least the standard one, whatever the diff, and both need passing
//! evaluators on two models. `eval-diff` runs on the model that did not write the change, as the
//! pull request's `meta.v1` block and the worker's hand-off comment name it. An evaluator the
//! policy names that cannot run (not in the roster, no model, or not allowed on the model asked)
//! stops the review instead of being dropped. The worker's tree is classified only while it is
//! clean at the pull request's head; otherwise the review takes at least the standard lane.
//!
//! [`RiskPolicy::lane_evaluators`]: crate::orchestrate::tiers::RiskPolicy::lane_evaluators

use std::collections::BTreeSet;

use anyhow::Result;
use serde_json::Value;

use super::Dispatcher;
use super::review::{handoff_by, since_lease};
use crate::dispatch::worker;
use crate::git;
use crate::orchestrate::issue::{Issue, parse_tier, raise};
use crate::orchestrate::launch;
use crate::orchestrate::records::{self, Lease, Record};
use crate::orchestrate::risk::{self, Floor, Lane};
use crate::orchestrate::tiers::{CROSS_MODEL, Change, LaneEvaluator};
use crate::orchestrate::tracker::PullRequest;
use crate::repo::Repo;

pub(super) const EVAL_DIFF: &str = "eval-diff";
const OPUS: &str = "opus";
const SONNET: &str = "sonnet";

/// One evaluator a lane needs, on the model its verdict must come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Needed {
    pub agent: String,
    pub model: String,
    /// Whether the dispatcher passes `--model`; otherwise the evaluator runs on its binding.
    pub ask_model: bool,
    pub effort: Option<String>,
}

/// What the review of one issue needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Plan {
    Evaluate {
        lane: Lane,
        needed: Vec<Needed>,
    },
    /// The evaluators would all run on one model, and the change needs `required`.
    OneModel {
        required: usize,
    },
    /// Evaluators the policy names that cannot run, each with why.
    Unavailable(Vec<String>),
}

impl Dispatcher<'_> {
    pub(super) fn plan_review(
        &self,
        issue: &Issue,
        lease: &Lease,
        found: &[Record],
        request: &PullRequest,
    ) -> Result<Plan> {
        let snapshot = launch::snapshot_of(issue, &self.kit, &lease.agent)?;
        let name = worker::attempt_worktree(issue.number, lease.attempt);
        let worktree = worker::worktree_dir(&self.repo, &name);
        let raised = records::lane_floor(found, issue.number);
        let floor = Floor {
            tier: Some(snapshot.risk_tier),
            lane: raised,
        };
        let tree = Repo::at(&worktree);
        let assessed = (worktree.join(".git").exists() && is_at(&tree, &request.head))
            .then(|| risk::assess_tree(&tree, floor).ok())
            .flatten();
        let (lane, tier, trust_core, triggers) = match &assessed {
            Some(found) => (
                found.lane,
                parse_tier(found.tier).map_or(snapshot.risk_tier, |t| raise(t, snapshot.risk_tier)),
                found.trust_core || snapshot.trust_core,
                found.triggers.clone(),
            ),
            None => (
                raised.map_or(Lane::Standard, |lane| lane.max(Lane::Standard)),
                snapshot.risk_tier,
                snapshot.trust_core,
                Vec::new(),
            ),
        };
        let protected = self
            .kit
            .is_protected_change(&lease.agent, &snapshot.write_set)?;
        let policy = &self.kit.risk;
        let lane = policy.review_lane(lane, trust_core, protected);
        let change = Change {
            tier,
            trust_core,
            protected,
            kind: Some(snapshot.kind.as_str()),
            triggers: &triggers,
        };
        let reviewer = self.reviewer_model(&writer_models(found, issue.number, lease, request));
        let mut needed: Vec<Needed> = Vec::new();
        let mut unavailable = Vec::new();
        for wanted in policy.lane_evaluators(lane, &change) {
            match self.needed(wanted, reviewer.as_deref()) {
                Ok(one) if needed.iter().all(|known| known.agent != one.agent) => needed.push(one),
                Ok(_) => {}
                Err(why) => unavailable.push(why),
            }
        }
        if !unavailable.is_empty() {
            return Ok(Plan::Unavailable(unavailable));
        }
        let required = policy.required_models(trust_core, protected);
        let models: BTreeSet<&str> = needed.iter().map(|n| n.model.as_str()).collect();
        if required > 1 && models.len() < required {
            return Ok(Plan::OneModel { required });
        }
        Ok(Plan::Evaluate { lane, needed })
    }

    /// The agent, model and effort `wanted` runs with, or why it cannot run.
    fn needed(&self, wanted: LaneEvaluator, reviewer: Option<&str>) -> Result<Needed, String> {
        let agent = if wanted.agent == CROSS_MODEL {
            EVAL_DIFF.to_owned()
        } else {
            wanted.agent
        };
        if self.kit.roster.agent(&agent).is_none() {
            return Err(format!("{agent} is not in .agents/roster.toml"));
        }
        let (model, ask_model) = match (wanted.model.as_deref(), agent == EVAL_DIFF) {
            (Some(name), _) => (self.kit.models.id(name).map(str::to_owned), true),
            (None, true) => (reviewer.map(str::to_owned), true),
            (None, false) => (self.binding(&agent), false),
        };
        let Some(model) = model else {
            return Err(format!("{agent} has no model in .agents/models.toml"));
        };
        if !self.kit.may_run_on(&agent, &model) {
            return Err(format!("{agent} may not run on {model}"));
        }
        Ok(Needed {
            agent,
            model,
            ask_model,
            effort: wanted.effort,
        })
    }

    /// The model that did not write the change: sonnet when only opus wrote it, otherwise opus.
    fn reviewer_model(&self, writers: &BTreeSet<String>) -> Option<String> {
        let sonnet = self.kit.models.id(SONNET)?;
        let opus = self.kit.models.id(OPUS)?;
        let only_opus = writers.len() == 1 && writers.contains(opus);
        Some(if only_opus { sonnet } else { opus }.to_owned())
    }

    fn binding(&self, agent: &str) -> Option<String> {
        let bound = &self.kit.roster.agent(agent)?.model;
        self.kit.models.id(bound).map(str::to_owned)
    }
}

/// Whether the worker's tree is clean at `head`, so its classification is the pull request's;
/// otherwise the review takes at least the standard lane.
fn is_at(tree: &Repo, head: &str) -> bool {
    let at_head = git::head(tree)
        .ok()
        .flatten()
        .is_some_and(|sha| sha == head);
    let clean = git::try_output(tree, &["status", "--porcelain"])
        .ok()
        .flatten()
        .is_some_and(|status| status.trim().is_empty());
    !head.is_empty() && at_head && clean
}

/// The models that wrote the change: the pull request's `meta.v1` block, and the worker's
/// hand-off comment (its `meta.v1` and the `model` of its `handoff.v1`); the lease's model when
/// neither names one.
fn writer_models(
    found: &[Record],
    item: u64,
    lease: &Lease,
    request: &PullRequest,
) -> BTreeSet<String> {
    let mut models = BTreeSet::new();
    if let Some(meta) = records::meta_in(&request.body).filter(|meta| meta.item == item) {
        models.insert(meta.model);
    }
    if let Some(meta) = records::latest_meta(found, item) {
        models.insert(meta.model.clone());
    }
    let worker = since_lease(found, lease).iter().rev().find_map(|record| {
        handoff_by(record, item, &lease.agent)?
            .get("model")
            .and_then(Value::as_str)
            .map(str::to_owned)
    });
    models.extend(worker);
    if models.is_empty() {
        models.insert(lease.model.clone());
    }
    models
}
