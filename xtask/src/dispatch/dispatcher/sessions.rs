//! One worker session from start to end: which session to start (the lease's own, a resumed one
//! or a new one in the same attempt), its prompt and limits, and what its end means for the item:
//! review when the pull request is open, another session after a partial hand-off, or the end of
//! the attempt.

use anyhow::Result;

use super::journal::{log_session, note};
use super::{Dispatcher, Prompt, Slot};
use crate::config::session::ItemStatus;
use crate::dispatch::lease::{self, Held};
use crate::dispatch::worker::{self, Job};
use crate::orchestrate::claude::Ended;
use crate::orchestrate::ids;
use crate::orchestrate::launch::SessionStart;
use crate::orchestrate::records::{self, Lease, Reason};

const PARTIAL: &str = "partial";
/// The `result` subtype of a session that `--max-turns` stopped.
const MAX_TURNS_SUBTYPE: &str = "error_max_turns";

impl Dispatcher<'_> {
    pub(super) fn after_session(
        &mut self,
        mut held: Held,
        ended: Ended,
        prompt: Prompt,
    ) -> Result<Option<Slot>> {
        held.worked += ended.report().elapsed;
        log_session(&self.repo, &held.record, &ended);
        println!(
            "dispatch: #{} attempt {} {}",
            held.item(),
            held.record.attempt,
            ended.describe()
        );
        let reason = match &ended {
            Ended::UsageLimited { .. } => return Ok(Some(Slot::Paused { held })),
            Ended::Stalled { .. } => Some(Reason::Stall),
            Ended::OverTime { .. } => Some(Reason::LeaseExpired),
            Ended::OverTurns { .. } | Ended::Exited { .. } => None,
        };
        if let Some(reason) = reason {
            return self.fail(held, reason);
        }
        let issue = self.tracker.issue(held.item())?;
        if issue.status() != Some(ItemStatus::Leased) {
            note(
                &self.repo,
                "released",
                Some(&held.record),
                "the hand-off moved the issue",
            );
            return Ok(None);
        }
        if self
            .tracker
            .open_pull_request(&held.record.branch)?
            .is_some()
        {
            lease::to_review(self.tracker, &held.record)?;
            println!("dispatch: #{} is in review", held.item());
            return Ok(None);
        }
        if prompt == Prompt::Resume && ended.report().turns == 0 {
            return self.start(held, Prompt::Continue);
        }
        let partial = records::latest_handoff(&records::records(&issue), held.item())
            .and_then(|handoff| handoff.get("status").and_then(serde_json::Value::as_str))
            == Some(PARTIAL);
        let cap_role = self.kit.agent(&held.record.agent)?.cap_role.clone();
        if partial && held.sessions < self.policy.sessions_per_attempt(&cap_role)? {
            return self.start(held, Prompt::Continue);
        }
        let at_cap = ended
            .report()
            .result
            .as_ref()
            .is_some_and(|result| result.subtype == MAX_TURNS_SUBTYPE);
        let reason = match &ended {
            Ended::OverTurns { .. } => Reason::TurnCap,
            Ended::Exited { .. } if at_cap => Reason::TurnCap,
            Ended::Exited { code: Some(0), .. } => Reason::NoPullRequest,
            _ => Reason::WorkerFailed,
        };
        self.fail(held, reason)
    }

    pub(super) fn fail(&mut self, held: Held, reason: Reason) -> Result<Option<Slot>> {
        let outcome =
            lease::end_attempt(self.tracker, &held.record, reason, self.policy.max_attempts)?;
        let detail = format!("{}; {outcome:?}", reason.describe());
        note(&self.repo, "attempt-ended", Some(&held.record), &detail);
        println!(
            "dispatch: #{} attempt {} ended: {detail}",
            held.item(),
            held.record.attempt
        );
        Ok(None)
    }

    /// Starts a session for `held`: the lease's own session, a resumed one, or a new one. An
    /// expired lease ends its attempt instead, and no slot remains.
    pub(super) fn start(&mut self, mut held: Held, prompt: Prompt) -> Result<Option<Slot>> {
        let agent = held.record.agent.clone();
        let lease_limit = self
            .kit
            .wall_clock(&agent, held.size.as_deref())
            .map(|clock| clock.saturating_mul(self.policy.lease_factor));
        if lease_limit.is_some_and(|limit| held.worked >= limit) {
            return self.fail(held, Reason::LeaseExpired);
        }
        let start = match (prompt, held.session()) {
            (Prompt::Resume, Some(id)) => SessionStart::Resume(id.to_owned()),
            (Prompt::Fresh, Some(id)) => SessionStart::Named(id.to_owned()),
            _ => SessionStart::Named(ids::session_id()),
        };
        if prompt == Prompt::Fix {
            held.sessions = 0;
        }
        if let SessionStart::Named(id) = &start {
            held.record.session = Some(id.clone());
            held.sessions = held.sessions.saturating_add(1);
        }
        let name = worker::attempt_worktree(held.item(), held.record.attempt);
        held.worktree = self.worktree(&name, Some(&held.record.branch))?;
        let text = self.prompt_text(&held.record, prompt)?;
        let log = self.repo.path(&format!(
            ".agent/logs/dispatch-{name}-s{}.jsonl",
            held.sessions
        ));
        let scope = self.kit.scope_of(&held.record);
        let watch = self.policy.session.watch(
            Some(
                self.kit
                    .session_turns(&agent, held.size.as_deref(), scope)?,
            ),
            lease_limit.map(|limit| limit.saturating_sub(held.worked)),
        );
        let job = Job {
            agent: &agent,
            item: Some(held.item()),
            prompt: &text,
            start: &start,
            log: &log,
            model: None,
            effort: None,
            scope,
        };
        let run = self.launcher.spawn(&held.worktree, &job, watch)?;
        Ok(Some(Slot::Working {
            held,
            run: Box::new(run),
            prompt,
        }))
    }

    /// The prompt for a worker session: `.agents/kit/prompts/dispatch-<kind>.md` when present,
    /// otherwise one line naming the issue, the attempt and the branch.
    pub(super) fn prompt_text(&self, lease: &Lease, prompt: Prompt) -> Result<String> {
        let (n, a, b) = (lease.item, lease.attempt, &lease.branch);
        let (kind, fallback) = match prompt {
            Prompt::Fresh => (
                "worker",
                format!(
                    "Work issue #{n}, attempt {a} on branch {b}, with the grdr-start-item skill. Every commit message is one Conventional Commit line. Finish with cargo xtask kit handoff."
                ),
            ),
            Prompt::Continue => (
                "continue",
                format!(
                    "Continue issue #{n}, attempt {a} on branch {b}: read your last handoff.v1 comment on the issue and resume from its next field. Finish with cargo xtask kit handoff."
                ),
            ),
            Prompt::Resume => (
                "resume",
                format!("The usage window has reset. Continue issue #{n} where you stopped."),
            ),
            Prompt::Fix => (
                "fix",
                format!(
                    "The pull request of issue #{n}, attempt {a} on branch {b}, came back from review or the merge queue: read the newest state.v1 comment for why, the failed check runs and the evaluators' handoff.v1 comments on the issue, fix what they found in the design (never around the symptom), push, and finish with cargo xtask kit handoff."
                ),
            ),
        };
        let item = lease.item.to_string();
        let attempt = lease.attempt.to_string();
        let values = [
            ("item", item.as_str()),
            ("attempt", attempt.as_str()),
            ("branch", lease.branch.as_str()),
        ];
        Ok(self.template(kind, &values)?.unwrap_or(fallback))
    }

    pub(super) fn template(&self, kind: &str, values: &[(&str, &str)]) -> Result<Option<String>> {
        let path = format!(".agents/kit/prompts/dispatch-{kind}.md");
        Ok(self.repo.read_optional(&path)?.map(|text| {
            values
                .iter()
                .fold(text, |text, (key, value)| {
                    text.replace(&format!("{{{key}}}"), value)
                })
                .trim()
                .to_owned()
        }))
    }
}
