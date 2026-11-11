//! Sessions that work on an issue without holding its lease (owner instruction 6): a lead, the
//! product lead or the chief architect plans a proposed, escalated or blocked issue, and the
//! evaluators judge an issue in review. They run in their own slots beside the writers, under the
//! same usage window, and what the dispatcher must remember between passes is kept in
//! `.agent/state/dispatch-assists.json`.

use std::collections::BTreeMap;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::Dispatcher;
use crate::clock::Utc;
use crate::dispatch::state;
use crate::dispatch::worker::Job;
use crate::orchestrate::claude::{Ended, Running};
use crate::orchestrate::ids;
use crate::orchestrate::launch::{LaunchScope, SessionStart};
use crate::repo::Repo;

const STATE_FILE: &str = ".agent/state/dispatch-assists.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Purpose {
    Plan,
    Review,
}

/// One running planner or evaluator session.
pub(super) struct Assist {
    pub purpose: Purpose,
    pub item: u64,
    pub agent: String,
    pub run: Running,
}

/// What a planning session left: the issue's `updatedAt` when it ended, and who ran it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Planned {
    #[serde(default)]
    pub updated_at: String,
    pub agent: String,
}

/// The evaluators started in one review round, which begins at the record index `since`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Round {
    pub since: usize,
    pub started: Vec<String>,
    /// The verdict was reported, so the notice prints once.
    #[serde(default)]
    pub reported: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssistState {
    #[serde(default)]
    pub planned: BTreeMap<u64, Planned>,
    #[serde(default)]
    pub reviewing: BTreeMap<u64, Round>,
}

/// What one assist session is started with.
pub(super) struct AssistJob<'a> {
    pub purpose: Purpose,
    pub item: u64,
    pub agent: &'a str,
    /// The worktree name under `.agent/worktrees/` and, for a review, the branch to check out.
    pub worktree: &'a str,
    pub branch: Option<&'a str>,
    pub prompt: &'a str,
    pub model: Option<&'a str>,
    pub effort: Option<&'a str>,
}

impl AssistState {
    pub fn load(repo: &Repo) -> Result<AssistState> {
        state::load(repo, STATE_FILE)
    }

    pub fn save(&self, repo: &Repo) -> Result<()> {
        state::save(repo, STATE_FILE, self)
    }

    pub fn remove_started(&mut self, item: u64, agent: &str) {
        if let Some(round) = self.reviewing.get_mut(&item) {
            round.started.retain(|started| started != agent);
        }
    }
}

impl Dispatcher<'_> {
    pub(super) fn assisting(&self, item: u64) -> bool {
        self.assists.iter().any(|assist| assist.item == item)
    }

    pub(super) fn assists_for(&self, purpose: Purpose) -> usize {
        self.assists
            .iter()
            .filter(|assist| assist.purpose == purpose)
            .count()
    }

    pub(super) fn start_assist(&mut self, job: &AssistJob) -> Result<()> {
        let worktree = self.worktree(job.worktree, job.branch)?;
        let watch = self.policy.session.watch(
            Some(self.kit.turn_cap(job.agent, None)?),
            self.kit.wall_clock(job.agent, None),
        );
        let log = self.repo.path(&format!(
            ".agent/logs/dispatch-{}-{}-{}.jsonl",
            job.agent,
            job.item,
            Utc::now().compact()
        ));
        let start = SessionStart::Named(ids::session_id());
        let spawned = Job {
            agent: job.agent,
            item: Some(job.item),
            prompt: job.prompt,
            start: &start,
            log: &log,
            model: job.model,
            effort: job.effort,
            scope: LaunchScope::Ordinary,
        };
        let run = self.launcher.spawn(&worktree, &spawned, watch)?;
        println!(
            "dispatch: started {} on #{} to {}",
            job.agent,
            job.item,
            match job.purpose {
                Purpose::Plan => "plan it",
                Purpose::Review => "review it",
            }
        );
        self.assists.push(Assist {
            purpose: job.purpose,
            item: job.item,
            agent: job.agent.to_owned(),
            run,
        });
        Ok(())
    }

    /// A planner records the issue as it left it, so it is planned again only after a change. A
    /// session that ended at a usage limit records nothing and runs again after the window.
    pub(super) fn after_assist(&mut self, assist: &Assist, ended: &Ended) -> Result<()> {
        println!(
            "dispatch: {} on #{} {}",
            assist.agent,
            assist.item,
            ended.describe()
        );
        if matches!(ended, Ended::UsageLimited { .. }) {
            self.assisted.remove_started(assist.item, &assist.agent);
            return self.assisted.save(&self.repo);
        }
        if assist.purpose == Purpose::Plan {
            let issue = self.tracker.issue(assist.item)?;
            self.assisted.planned.insert(
                assist.item,
                Planned {
                    updated_at: issue.updated_at,
                    agent: assist.agent.clone(),
                },
            );
        }
        self.assisted.save(&self.repo)
    }
}
