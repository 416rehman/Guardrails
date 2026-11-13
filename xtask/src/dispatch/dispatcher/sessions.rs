//! One worker session from start to end: which session to start (the lease's own, a resumed one
//! or a new one in the same attempt), its prompt and limits, and what its end means for the item:
//! another session after a partial hand-off while the attempt has sessions left, a fix session's
//! included although its pull request is open; review when the pull request is open; or the end
//! of the attempt. Once an item came back from review, its next session in the attempt, resumed
//! or new, goes back to review only after a new hand-off, so the evaluators never judge a head
//! left unanswered; so does the seed session started again, whose earlier attempt's pull request
//! is still open. A fable agent's session waits while another fable session runs, this
//! dispatcher's own or one holding the machine lock, and any launch a lock refused waits the same
//! way: for another fable session, or for the same session a stopped dispatcher left running,
//! which runs the item, so that wait counts against the lease. Once it uses the lease while that
//! session still runs, the item escalates instead of starting another attempt beside it.

use std::time::{Duration, Instant};

use anyhow::Result;

use super::journal::{log_session, note};
use super::review::{handoff_by, since_lease};
use super::{Dispatcher, Named, Prompt, Slot};
use crate::config::session::ItemStatus;
use crate::dispatch::lease::{self, Held, Outcome};
use crate::dispatch::worker::{self, Job};
use crate::orchestrate::claude::Ended;
use crate::orchestrate::ids;
use crate::orchestrate::launch::{self, SessionStart};
use crate::orchestrate::records::{self, Lease, Reason, Record};
use crate::repo::Repo;

const PARTIAL: &str = "partial";
/// The `result` subtype of a session that `--max-turns` stopped.
const MAX_TURNS_SUBTYPE: &str = "error_max_turns";

/// What a hand-off asks of its attempt once a session of it ended.
enum HandedOn {
    /// Another session: the hand-off is partial and the attempt has sessions left.
    Continue,
    /// Review: the pull request is open and no hand-off is owed.
    Review,
}

impl Dispatcher<'_> {
    pub(super) fn after_session(
        &mut self,
        mut held: Held,
        ended: Ended,
        prompt: Prompt,
        named: Option<Named>,
    ) -> Result<Option<Slot>> {
        log_session(&self.repo, &held.record, &ended);
        println!(
            "dispatch: #{} attempt {} {}",
            held.item(),
            held.record.attempt,
            ended.describe()
        );
        if self.lock_refused(&ended) {
            return self.after_refusal(held, prompt, named, &ended);
        }
        if self.fable_limited(&held.record.agent, &ended) {
            return self.after_refusal(held, prompt, named, &ended);
        }
        held.worked += ended.report().elapsed;
        held.refused_at = None;
        held.left_session = false;
        if let Ended::UsageLimited { .. } = &ended {
            return Ok(Some(Slot::Paused {
                held,
                prompt: Prompt::Resume,
            }));
        }
        // Read before a stopped session fails its attempt: a session that handed off and then sat
        // silent until it was stopped has already moved the issue or opened its pull request, and
        // its work stands.
        let issue = self.tracker.issue(held.item())?;
        if issue.status() != Some(ItemStatus::Leased) {
            return Ok(self.released(&held, "the hand-off moved the issue"));
        }
        let found = records::records(&issue);
        match self.handed_on(&held, &found)? {
            Some(HandedOn::Continue) => return self.start(held, Prompt::Continue),
            Some(HandedOn::Review) => return self.in_review(&held),
            None => {}
        }
        let stopped = match &ended {
            Ended::Stalled { .. } => Some(Reason::Stall),
            Ended::OverTime { .. } => Some(Reason::LeaseExpired),
            Ended::UsageLimited { .. } | Ended::OverTurns { .. } | Ended::Exited { .. } => None,
        };
        if let Some(reason) = stopped {
            return self.fail(held, reason);
        }
        let owes_fix = fix_owed(&found, &held.record);
        let owed = self.handoff_owed(&found, &held.record);
        if owes_fix {
            note(
                &self.repo,
                "fix-unanswered",
                Some(&held.record),
                "the session ended without a hand-off since the item came back from review",
            );
        } else if owed {
            note(
                &self.repo,
                "seed-unanswered",
                Some(&held.record),
                "the seed session started again and ended without a hand-off",
            );
        }
        if prompt == Prompt::Resume && ended.report().turns == 0 {
            if owes_fix {
                return self.start(held, Prompt::Fix);
            }
            if owed {
                // The seed started again owes its first hand-off: its own prompt, in a new session,
                // since the lease's session id is taken.
                held.record.session = None;
                return self.start(held, Prompt::Fresh);
            }
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

    /// A launch a lock refused started no session: what `start` did is undone, and the slot waits
    /// to start it again.
    fn after_refusal(
        &self,
        mut held: Held,
        prompt: Prompt,
        named: Option<Named>,
        ended: &Ended,
    ) -> Result<Option<Slot>> {
        if let Some(Named { before }) = named {
            held.record.session = before;
            held.sessions = held.sessions.saturating_sub(1);
        }
        self.count_lock_wait(&mut held, ended.report().elapsed)?;
        Ok(Some(Slot::Paused { held, prompt }))
    }

    /// Counts a wait of `held` that took `spent` against its lease while its own session lock is
    /// held, since the session holding it runs the item; `start` ends the lease once it is used. A
    /// wait for another fable session counts nothing.
    fn count_lock_wait(&self, held: &mut Held, spent: Duration) -> Result<()> {
        if self.session_left_running(held)? {
            held.count_wait(spent);
            held.left_session = true;
        } else {
            held.refused_at = None;
        }
        Ok(())
    }

    /// Whether a session of `held`'s attempt holds the slot's session lock while the slot has no
    /// session running, such as one a stopped dispatcher left running.
    fn session_left_running(&self, held: &Held) -> Result<bool> {
        launch::session_running(&Repo::at(&held.worktree), held.item(), &held.record.agent)
    }

    /// Starts paused `held` again. An issue that left `status:leased` while the slot waited lets
    /// go of the slot instead. Once the session a stopped dispatcher left running lets go of the
    /// slot's session lock, its hand-off decides what follows, as after the slot's own session.
    pub(super) fn resume(&mut self, mut held: Held, prompt: Prompt) -> Result<Option<Slot>> {
        let issue = self.tracker.issue(held.item())?;
        if issue.status() != Some(ItemStatus::Leased) {
            return Ok(self.released(&held, "the issue left status:leased while the slot waited"));
        }
        if held.left_session && !self.session_left_running(&held)? {
            held.left_session = false;
            match self.handed_on(&held, &records::records(&issue))? {
                Some(HandedOn::Continue) => return self.start(held, Prompt::Continue),
                Some(HandedOn::Review) => return self.in_review(&held),
                None => {}
            }
        }
        self.start(held, prompt)
    }

    /// What `found`'s last hand-off asks of `held`'s attempt, if anything.
    fn handed_on(&self, held: &Held, found: &[Record]) -> Result<Option<HandedOn>> {
        let partial = records::latest_handoff(found, held.item())
            .and_then(|handoff| handoff.get("status").and_then(serde_json::Value::as_str))
            == Some(PARTIAL);
        let cap_role = self.kit.cap_role(&held.record.agent, held.caps)?;
        if partial && held.sessions < self.policy.sessions_per_attempt(&cap_role)? {
            return Ok(Some(HandedOn::Continue));
        }
        let open = !self.handoff_owed(found, &held.record)
            && self
                .tracker
                .open_pull_request(&held.record.branch)?
                .is_some();
        Ok(open.then_some(HandedOn::Review))
    }

    /// Moves `held`'s item to review, its pull request open; no slot remains.
    fn in_review(&self, held: &Held) -> Result<Option<Slot>> {
        lease::to_review(self.tracker, &held.record)?;
        println!("dispatch: #{} is in review", held.item());
        Ok(None)
    }

    /// `held`'s lease is used, so its attempt ends. While a session of the attempt still holds
    /// the slot's session lock, the item escalates whatever attempts are left, so no other
    /// attempt starts beside it.
    fn lease_used(&mut self, held: Held) -> Result<Option<Slot>> {
        if !self.session_left_running(&held)? {
            return self.fail(held, Reason::LeaseExpired);
        }
        let checkout = Repo::at(&held.worktree);
        let lock = launch::session_lock_path(&checkout, held.item(), &held.record.agent);
        // The line is posted on a public issue, so it names the lock from the repository root.
        let shown = lock.strip_prefix(self.repo.root()).unwrap_or(&lock);
        let detail = format!(
            "A session of the attempt still holds {}, so no other attempt starts beside it.",
            shown.to_string_lossy().replace('\\', "/")
        );
        lease::escalate(
            self.tracker,
            &held.record,
            Reason::LeaseExpired,
            Some(&detail),
        )?;
        let outcome = format!(
            "{}; {:?}. {detail}",
            Reason::LeaseExpired.describe(),
            Outcome::Escalate
        );
        Ok(self.attempt_ended(&held, &outcome))
    }

    /// `held`'s issue moved on, `why`, so the slot lets go of it.
    fn released(&self, held: &Held, why: &str) -> Option<Slot> {
        note(&self.repo, "released", Some(&held.record), why);
        None
    }

    pub(super) fn fail(&mut self, held: Held, reason: Reason) -> Result<Option<Slot>> {
        let attempts = self.attempts_for(&held.record);
        let outcome = lease::end_attempt(self.tracker, &held.record, reason, attempts)?;
        Ok(self.attempt_ended(&held, &format!("{}; {outcome:?}", reason.describe())))
    }

    /// Records that `held`'s attempt ended, saying `detail`; no slot remains.
    fn attempt_ended(&self, held: &Held, detail: &str) -> Option<Slot> {
        note(&self.repo, "attempt-ended", Some(&held.record), detail);
        println!(
            "dispatch: #{} attempt {} ended: {detail}",
            held.item(),
            held.record.attempt
        );
        None
    }

    /// Starts a session for `held`: the lease's own session, a resumed one, or a new one. An
    /// expired lease ends its attempt instead, and no slot remains; a fable agent's session waits
    /// in a paused slot while another fable session runs.
    pub(super) fn start(&mut self, mut held: Held, prompt: Prompt) -> Result<Option<Slot>> {
        let agent = held.record.agent.clone();
        let fable_waits = self.is_fable(&agent) && self.fable_busy()?;
        if fable_waits {
            self.count_lock_wait(&mut held, Duration::ZERO)?;
        }
        let lease_limit = self
            .kit
            .wall_clock(&agent, held.size.as_deref(), held.caps)
            .map(|clock| clock.saturating_mul(self.policy.lease_factor));
        if lease_limit.is_some_and(|limit| held.worked >= limit) {
            return self.lease_used(held);
        }
        if fable_waits {
            return Ok(Some(Slot::Paused { held, prompt }));
        }
        let start = match (prompt, held.session()) {
            (Prompt::Resume, Some(id)) => SessionStart::Resume(id.to_owned()),
            (Prompt::Fresh, Some(id)) => SessionStart::Named(id.to_owned()),
            _ => SessionStart::Named(ids::session_id()),
        };
        if prompt == Prompt::Fix {
            held.sessions = 0;
        }
        let named = match &start {
            SessionStart::Named(id) => {
                let before = held.record.session.replace(id.clone());
                held.sessions = held.sessions.saturating_add(1);
                Some(Named { before })
            }
            SessionStart::New | SessionStart::Resume(_) => None,
        };
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
                    .session_turns(&agent, held.size.as_deref(), scope, held.caps)?,
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
            busy_exit: self.policy.busy_exit,
        };
        let run = self.launcher.spawn(&held.worktree, &job, watch)?;
        Ok(Some(Slot::Working {
            held,
            run: Box::new(run),
            prompt,
            named,
        }))
    }

    /// Whether `lease`'s open pull request holds a head its agent has not handed off since: the
    /// item came back from review unanswered, or the seed session started again under `lease`
    /// while the pull request of its earlier attempt stays open.
    pub(super) fn handoff_owed(&self, found: &[Record], lease: &Lease) -> bool {
        if fix_owed(found, lease) {
            return true;
        }
        let restarted_seed = self.is_seed_lease(lease) && lease.attempt > 1;
        restarted_seed
            && !since_lease(found, lease)
                .iter()
                .any(|record| handoff_by(record, lease.item, &lease.agent).is_some())
    }

    /// Whether `ended` is a launch a lock refused (`[launch] busy_exit`), so no session ran.
    pub(super) fn lock_refused(&self, ended: &Ended) -> bool {
        let busy = i32::from(self.policy.busy_exit);
        matches!(ended, Ended::Exited { code: Some(code), .. } if *code == busy)
    }

    /// Whether `agent` runs on fable (models.toml `rules.fable_agents`).
    pub(super) fn is_fable(&self, agent: &str) -> bool {
        self.kit
            .models
            .rules
            .fable_agents
            .iter()
            .any(|fable| fable == agent)
    }

    /// Whether a fable session runs: one this dispatcher started, whose `kit launch` may not
    /// hold the machine lock yet, or any session that holds it.
    /// Whether `ended` is a fable session `agent` ran that met a limit on its model alone; it ran
    /// no work, so no attempt counts, and fable work waits out the retry interval from now.
    pub(super) fn fable_limited(&mut self, agent: &str, ended: &Ended) -> bool {
        let text = ended
            .report()
            .result
            .as_ref()
            .map(|result| result.text.as_str());
        let met = self.is_fable(agent)
            && text.is_some_and(|text| {
                (self.policy.session.model_limit_strings.iter())
                    .any(|limit| text.contains(limit.as_str()))
            });
        if met {
            self.fable_limited_at = Some(Instant::now());
        }
        met
    }

    pub(super) fn fable_busy(&self) -> Result<bool> {
        let limited = self
            .fable_limited_at
            .is_some_and(|at| at.elapsed() < self.policy.session.retry_after_limit);
        if limited {
            return Ok(true);
        }
        let own = self.slots.iter().any(
            |slot| matches!(slot, Slot::Working { held, .. } if self.is_fable(&held.record.agent)),
        ) || self
            .assists
            .iter()
            .any(|assist| self.is_fable(&assist.agent));
        Ok(own || launch::fable_session_running()?)
    }

    /// The prompt for a worker session: `.agents/kit/prompts/dispatch-<kind>.md` when present,
    /// otherwise one line naming the issue, the attempt and the branch.
    pub(super) fn prompt_text(&self, lease: &Lease, prompt: Prompt) -> Result<String> {
        let (n, a, b) = (lease.item, lease.attempt, &lease.branch);
        let (kind, fallback) = match prompt {
            Prompt::Fresh if self.is_seed_lease(lease) => (
                "seed-again",
                format!(
                    "Issue #{n} is the seed's own. The decision on its escalation moved it back to status:proposed, so the seed session starts again on branch {b}, attempt {a}: read the decision comment and the state.v1 and handoff.v1 comments since the previous lease.v1, carry the decision out on {b}, commit, and finish with cargo xtask kit handoff."
                ),
            ),
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
                    "The pull request of issue #{n}, attempt {a} on branch {b}, came back from review or the merge queue: read the newest state.v1 comment for why, the failed checks (gh pr checks {b}) and the evaluators' handoff.v1 comments on the issue, fix what they found in the design (never around the symptom), push, and finish with cargo xtask kit handoff. If the state.v1 comment says there is nothing to fix in the branch, stop without a hand-off."
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

/// Whether the item came back from review in `lease`'s attempt and its agent has not handed off
/// since, so its pull request still holds the head the evaluators or the merge queue sent back.
pub(super) fn fix_owed(found: &[Record], lease: &Lease) -> bool {
    let attempt = since_lease(found, lease);
    let Some(returned) = attempt.iter().rposition(|record| {
        matches!(record, Record::Transition(t) if t.from == ItemStatus::InReview && t.to == ItemStatus::Leased)
    }) else {
        return false;
    };
    !attempt
        .get(returned + 1..)
        .unwrap_or_default()
        .iter()
        .any(|record| handoff_by(record, lease.item, &lease.agent).is_some())
}
