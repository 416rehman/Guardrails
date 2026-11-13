//! The dispatcher's loop (team/01 section 9, owner instructions 5 to 7): one slot per lease it
//! holds, each either working or paused; a usage window that is open or exhausted; the recurring
//! agents beside the writers; the planners and evaluators that move issues on without a person
//! (leads ready proposed issues and answer escalations, evaluators judge pull requests); and the
//! merge queue that lands what passed. Sessions and the queue's verify are polled every second;
//! GitHub is read when a session ends and otherwise on the policy's poll interval (`pacing.rs`).

mod assist;
mod evaluators;
mod journal;
mod landing;
mod leasing;
mod pacing;
mod planning;
mod recurring;
mod review;
mod sessions;
mod unrecorded;

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};

use self::assist::{Assist, AssistState};
use self::journal::note;
use self::landing::Landing;
use self::pacing::Pacing;
use super::lease::Held;
use super::merge::{QueueConfig, Tree};
use super::policy::Policy;
use super::queue;
use super::routines::{Routine, Schedule, now_unix};
use super::worker::{self, Launcher, Upstream};
use crate::config::session::ItemStatus;
use crate::orchestrate::claude::{Ended, Running};
use crate::orchestrate::form::Form;
use crate::orchestrate::issue::status_label;
use crate::orchestrate::labels::LabelsFile;
use crate::orchestrate::launch::{LaunchKit, trust};
use crate::orchestrate::records::Lease;
use crate::orchestrate::tracker::Tracker;
use crate::repo::Repo;

/// How often sessions and the queue's verify are polled; GitHub is read on the policy's interval.
const LOCAL_POLL: Duration = Duration::from_secs(1);

/// Which prompt a session gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Prompt {
    Fresh,
    /// A new session in the same attempt, after a partial hand-off.
    Continue,
    /// The same session, after a pause.
    Resume,
    /// A new session in the same attempt, after an evaluator or the merge queue sent it back.
    Fix,
}

/// A session `start` named and counted, and the session the lease named before it.
struct Named {
    before: Option<String>,
}

enum Slot {
    Working {
        held: Held,
        run: Box<Running>,
        prompt: Prompt,
        /// What a launch a lock refused puts back; `None` when `start` resumed a session.
        named: Option<Named>,
    },
    Paused {
        held: Held,
        /// The prompt it restarts with: `Fix` for a sent-back item whose fix has not started,
        /// `Resume` for a session stopped mid-work.
        prompt: Prompt,
    },
}

struct RoutineRun {
    routine: Routine,
    run: Running,
    previous: Option<u64>,
}

enum Window {
    Open,
    Exhausted { since: Instant },
}

pub struct Dispatcher<'a> {
    repo: Repo,
    kit: LaunchKit,
    labels: LabelsFile,
    policy: Policy,
    tracker: &'a dyn Tracker,
    launcher: Launcher,
    slots: Vec<Slot>,
    running_routines: Vec<RoutineRun>,
    routines: Vec<Routine>,
    schedule: Schedule,
    window: Window,
    assists: Vec<Assist>,
    assisted: AssistState,
    /// Each squad's lead from `.agents/owners.toml`.
    squad_leads: BTreeMap<String, String>,
    form: Form,
    queue: QueueConfig,
    landing: Landing,
    /// Trees whose full verify passed, by pull request.
    verified: BTreeMap<u64, Tree>,
    /// The last notice printed for an issue, so a waiting issue prints once.
    notices: BTreeMap<u64, String>,
    pacing: Pacing,
    /// Unix seconds when this dispatcher started; no deadline counts time before it.
    started: u64,
    /// A landed `.github/labels.toml` whose sync onto the repository has not succeeded yet.
    unsynced_labels: Option<LabelsFile>,
}

impl Slot {
    fn held(&self) -> &Held {
        match self {
            Slot::Working { held, .. } | Slot::Paused { held, .. } => held,
        }
    }
}

impl<'a> Dispatcher<'a> {
    pub fn new(
        repo: Repo,
        policy: Policy,
        tracker: &'a dyn Tracker,
        launcher: Launcher,
    ) -> Result<Dispatcher<'a>> {
        let kit = LaunchKit::load(&repo)?;
        let labels = LabelsFile::load(&repo)?;
        let routines = policy
            .routines()
            .iter()
            .map(|(name, table)| Routine::from_table(name, table))
            .filter(|routine| {
                routine
                    .agent
                    .as_deref()
                    .is_none_or(|agent| kit.roster.agent(agent).is_some())
            })
            .collect();
        let schedule = Schedule::load(&repo)?;
        let assisted = AssistState::load(&repo)?;
        let squad_leads = squad_leads(&repo)?;
        let form = Form::load(&repo)?;
        let queue = QueueConfig::load(&repo)?;
        Ok(Dispatcher {
            repo,
            kit,
            labels,
            policy,
            tracker,
            launcher,
            slots: Vec::new(),
            running_routines: Vec::new(),
            routines,
            schedule,
            window: Window::Open,
            assists: Vec::new(),
            assisted,
            squad_leads,
            form,
            queue,
            landing: Landing::Idle,
            verified: BTreeMap::new(),
            notices: BTreeMap::new(),
            pacing: Pacing::new(),
            started: now_unix(),
            unsynced_labels: None,
        })
    }

    /// The seed session's issue while it waits for the seed's hand-off.
    pub fn seed_not_handed_off(&self) -> Result<Option<u64>> {
        let Some(label) = status_label(ItemStatus::Proposed) else {
            return Ok(None);
        };
        for issue in self.tracker.open_with_label(&label)? {
            if self.awaits_seed_handoff(&issue)? {
                return Ok(Some(issue.number));
            }
        }
        Ok(None)
    }

    /// The attempts `lease`'s item gets before one that ends without landing is escalated: one
    /// for the seed's issue, which nobody readies again, so each of its attempts that ends goes to
    /// the chief architect, whose decision may start the next while `[item] max_attempts` allows
    /// (`relaunch_seed`).
    fn attempts_for(&self, lease: &Lease) -> u32 {
        if self.is_seed_lease(lease) {
            1
        } else {
            self.policy.max_attempts
        }
    }

    /// Whether `lease` is the one the seed's hand-off posted: it names the seed scope's branch.
    fn is_seed_lease(&self, lease: &Lease) -> bool {
        self.kit
            .seed
            .as_ref()
            .is_some_and(|seed| seed.branch == lease.branch)
    }

    /// Runs the queue's verify with `program` instead of the installed kit binary.
    #[cfg(test)]
    pub(crate) fn set_verifier(&mut self, program: std::path::PathBuf) {
        self.queue.program = program;
    }

    /// Runs until stopped, or with `once` until the sessions the first pass started have ended.
    /// It starts nothing while Claude Code does not trust the repository folder, or while the
    /// seed session's issue has not been handed off.
    pub fn run(&mut self, once: bool) -> Result<()> {
        trust::require(&self.repo)?;
        if let Some(seed) = self.seed_not_handed_off()? {
            bail!(
                "issue #{seed} is the seed session's own and has no lease.v1 yet; the seed hands it off with cargo xtask kit handoff (team/06 section 13 step 5) before the dispatcher starts"
            );
        }
        self.adopt()?;
        let mut passes = 0u32;
        loop {
            if let Err(error) = self.step_sessions() {
                eprintln!("dispatch: {error:#}");
            }
            if let Err(error) = self.step_queue() {
                eprintln!("dispatch: merge queue: {error:#}");
            }
            if self.pass_due() {
                let step = if !once || passes == 0 {
                    self.step_github()
                } else {
                    Ok(())
                };
                self.pace(step);
                passes = passes.saturating_add(1);
            }
            if once && passes > 0 && self.idle() {
                return Ok(());
            }
            std::thread::sleep(LOCAL_POLL.min(self.policy.poll));
        }
    }

    /// Whether the next GitHub pass is due: the poll interval ran out, or a session ended.
    pub(crate) fn pass_due(&self) -> bool {
        self.pacing.due()
    }

    /// Sets when the pass after one that ended as `step` is due.
    pub(crate) fn pace(&mut self, step: Result<()>) {
        match step {
            Ok(()) => self.pacing.passed(&self.policy),
            Err(error) => {
                let wait = self.pacing.failed(&self.policy);
                eprintln!("dispatch: {error:#}; retrying in {} s", wait.as_secs());
            }
        }
    }

    /// A session that ended as `ended` left its result on GitHub, so the next pass reads it now
    /// (owner instruction 30). A launch a lock refused started no session; its retry keeps to
    /// the poll interval.
    fn pass_after(&mut self, ended: &Ended) {
        if !self.lock_refused(ended) {
            self.pacing.session_ended();
        }
    }

    /// `.agent/worktrees/<name>`, a new branch starting from the fetched base tip.
    fn worktree(&self, name: &str, branch: Option<&str>) -> Result<std::path::PathBuf> {
        let upstream = Upstream {
            remote: &self.form.remote,
            base: &self.form.base,
        };
        worker::worktree(&self.repo, name, branch, &self.launcher, upstream)
    }

    pub fn idle(&self) -> bool {
        self.running_routines.is_empty()
            && self.assists.is_empty()
            && matches!(self.landing, Landing::Idle)
            && !self
                .slots
                .iter()
                .any(|slot| matches!(slot, Slot::Working { .. }))
    }

    pub fn held(&self) -> Vec<u64> {
        self.slots.iter().map(|slot| slot.held().item()).collect()
    }

    /// Polls every session and acts on the ones that ended.
    pub fn step_sessions(&mut self) -> Result<()> {
        let mut limited = false;
        for slot in std::mem::take(&mut self.slots) {
            let next = match slot {
                Slot::Working {
                    held,
                    mut run,
                    prompt,
                    named,
                } => match run.poll() {
                    None => Some(Slot::Working {
                        held,
                        run,
                        prompt,
                        named,
                    }),
                    Some(ended) => {
                        limited |= matches!(ended, Ended::UsageLimited { .. });
                        self.pass_after(&ended);
                        let kept = held.clone();
                        self.after_session(held, ended, prompt, named)
                            .unwrap_or_else(|error| {
                                eprintln!(
                                    "dispatch: #{}: {error:#}; the lease stays paused",
                                    kept.item()
                                );
                                Some(Slot::Paused {
                                    held: kept,
                                    prompt: Prompt::Resume,
                                })
                            })
                    }
                },
                paused @ Slot::Paused { .. } => Some(paused),
            };
            self.slots.extend(next);
        }
        for mut routine in std::mem::take(&mut self.running_routines) {
            match routine.run.poll() {
                None => self.running_routines.push(routine),
                Some(ended) => {
                    limited |= matches!(ended, Ended::UsageLimited { .. });
                    self.pass_after(&ended);
                    self.after_routine(routine, &ended)?;
                }
            }
        }
        for mut assist in std::mem::take(&mut self.assists) {
            match assist.run.poll() {
                None => self.assists.push(assist),
                Some(ended) => {
                    limited |= matches!(ended, Ended::UsageLimited { .. });
                    self.pass_after(&ended);
                    if let Err(error) = self.after_assist(&assist, &ended) {
                        eprintln!("dispatch: #{}: {error:#}", assist.item);
                    }
                }
            }
        }
        if limited {
            self.pause_all()?;
        }
        Ok(())
    }

    /// Reopens the window after the retry interval, resumes paused leases, leases ready issues
    /// into free slots, starts due routines, plans proposed, escalated and blocked issues,
    /// reviews issues in review, and moves leased issues with open pull requests on. A pass
    /// while Claude Code does not trust the repository folder fails before it leases or starts
    /// anything.
    pub fn step_github(&mut self) -> Result<()> {
        if let Window::Exhausted { since } = self.window
            && since.elapsed() >= self.policy.session.retry_after_limit
        {
            println!("dispatch: retrying the usage window");
            self.window = Window::Open;
        }
        if let Window::Exhausted { .. } = self.window {
            return Ok(());
        }
        trust::require(&self.repo)?;
        self.check_acceptance()?;
        self.resume_paused()?;
        self.fill()?;
        self.start_routines()?;
        self.plan()?;
        self.review()?;
        self.reconcile()
    }

    /// A usage limit: every session stops as a pause, nothing is posted, and no lease is granted
    /// until the window is retried. Its time counts against no lease, a writer's wait for its
    /// session lock included.
    fn pause_all(&mut self) -> Result<()> {
        self.window = Window::Exhausted {
            since: Instant::now(),
        };
        for slot in std::mem::take(&mut self.slots) {
            let (mut held, prompt) = match slot {
                Slot::Working {
                    mut held, mut run, ..
                } => {
                    held.worked += run.stop().report().elapsed;
                    // Its own session ran since, so its resume continues that session.
                    held.left_session = false;
                    (held, Prompt::Resume)
                }
                Slot::Paused { held, prompt } => (held, prompt),
            };
            held.refused_at = None;
            self.slots.push(Slot::Paused { held, prompt });
        }
        for mut routine in std::mem::take(&mut self.running_routines) {
            let ended = routine.run.stop();
            self.after_routine(routine, &ended)?;
        }
        for mut assist in std::mem::take(&mut self.assists) {
            let ended = assist.run.stop();
            println!(
                "dispatch: {} on #{} paused: {}",
                assist.agent,
                assist.item,
                ended.describe()
            );
            self.assisted.remove_started(assist.item, &assist.agent);
        }
        self.assisted.save(&self.repo)?;
        note(
            &self.repo,
            "paused",
            None,
            "usage limit: every session paused, no attempt counted",
        );
        println!("dispatch: usage limit reached; every session is paused and no attempt counts");
        Ok(())
    }

    fn resume_paused(&mut self) -> Result<()> {
        let mut paused: Vec<(Held, Prompt)> = Vec::new();
        let mut kept = Vec::new();
        for slot in std::mem::take(&mut self.slots) {
            match slot {
                Slot::Paused { held, prompt } => paused.push((held, prompt)),
                working => kept.push(working),
            }
        }
        self.slots = kept;
        paused.sort_by_key(|(held, _)| queue::urgency(held.trust_core, held.tier, held.priority));
        for (held, prompt) in paused {
            let kept = held.clone();
            match self.resume(held, prompt) {
                Ok(slot) => self.slots.extend(slot),
                Err(error) => {
                    eprintln!("dispatch: #{} could not resume: {error:#}", kept.item());
                    self.slots.push(Slot::Paused { held: kept, prompt });
                }
            }
        }
        Ok(())
    }
}

/// `[squad.<id>] lead` of `.agents/owners.toml`, by squad id.
fn squad_leads(repo: &Repo) -> Result<BTreeMap<String, String>> {
    let Some(text) = repo.read_optional(".agents/owners.toml")? else {
        return Ok(BTreeMap::new());
    };
    let table: toml::Table = crate::config::parse_toml(&text, ".agents/owners.toml")?;
    Ok(table
        .get("squad")
        .and_then(toml::Value::as_table)
        .map(|squads| {
            squads
                .iter()
                .filter_map(|(id, squad)| {
                    let lead = squad.get("lead")?.as_str()?;
                    Some((id.clone(), lead.to_owned()))
                })
                .collect()
        })
        .unwrap_or_default())
}

#[cfg(test)]
mod refusal_tests;
