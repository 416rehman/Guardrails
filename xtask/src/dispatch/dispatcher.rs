//! The dispatcher's loop (team/01 section 9, owner instructions 5 to 7): one slot per lease it
//! holds, each either working or paused; a usage window that is open or exhausted; the recurring
//! agents beside the writers; the planners and evaluators that move issues on without a person
//! (leads ready proposed issues and answer escalations, evaluators judge pull requests); and the
//! merge queue that lands what passed. Sessions and the queue's verify are polled every second;
//! GitHub is read on the policy's poll interval with jitter, so many dispatchers never call it in
//! step, and after a failed pass it backs off with full jitter (P15).

mod assist;
mod evaluators;
mod journal;
mod landing;
mod leasing;
mod planning;
mod recurring;
mod review;
mod sessions;

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};

use self::assist::{Assist, AssistState};
use self::journal::note;
use self::landing::Landing;
use super::lease::Held;
use super::merge::{QueueConfig, Tree};
use super::policy::Policy;
use super::queue;
use super::routines::{Routine, Schedule};
use super::worker::{self, Launcher, Upstream};
use crate::config::session::ItemStatus;
use crate::orchestrate::claude::{Ended, Running};
use crate::orchestrate::form::Form;
use crate::orchestrate::ids;
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

enum Slot {
    Working {
        held: Held,
        run: Box<Running>,
        prompt: Prompt,
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
    /// GitHub passes failed in a row, for the backoff.
    failed_passes: u32,
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
            failed_passes: 0,
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

    /// The attempts `lease`'s item gets: one for the seed's issue, which nobody readies again,
    /// so an attempt that ends without landing goes to the chief architect.
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
        let mut next_github = Instant::now();
        let mut passes = 0u32;
        loop {
            if let Err(error) = self.step_sessions() {
                eprintln!("dispatch: {error:#}");
            }
            if let Err(error) = self.step_queue() {
                eprintln!("dispatch: merge queue: {error:#}");
            }
            if Instant::now() >= next_github {
                let step = if !once || passes == 0 {
                    self.step_github()
                } else {
                    Ok(())
                };
                let wait = match step {
                    Ok(()) => {
                        self.failed_passes = 0;
                        jittered(self.policy.poll, self.policy.poll_jitter)
                    }
                    Err(error) => {
                        self.failed_passes = self.failed_passes.saturating_add(1);
                        let wait = backoff(
                            self.policy.backoff_base,
                            self.policy.backoff_cap,
                            self.failed_passes,
                        );
                        eprintln!("dispatch: {error:#}; retrying in {} s", wait.as_secs());
                        wait
                    }
                };
                passes = passes.saturating_add(1);
                next_github = Instant::now() + wait;
            }
            if once && passes > 0 && self.idle() {
                return Ok(());
            }
            std::thread::sleep(LOCAL_POLL.min(self.policy.poll));
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
                } => match run.poll() {
                    None => Some(Slot::Working { held, run, prompt }),
                    Some(ended) => {
                        limited |= matches!(ended, Ended::UsageLimited { .. });
                        let kept = held.clone();
                        self.after_session(held, ended, prompt)
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
                    self.after_routine(routine, &ended)?;
                }
            }
        }
        for mut assist in std::mem::take(&mut self.assists) {
            match assist.run.poll() {
                None => self.assists.push(assist),
                Some(ended) => {
                    limited |= matches!(ended, Ended::UsageLimited { .. });
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
    /// until the window is retried.
    fn pause_all(&mut self) -> Result<()> {
        self.window = Window::Exhausted {
            since: Instant::now(),
        };
        for slot in std::mem::take(&mut self.slots) {
            let paused = match slot {
                Slot::Working {
                    mut held, mut run, ..
                } => {
                    held.worked += run.stop().report().elapsed;
                    Slot::Paused {
                        held,
                        prompt: Prompt::Resume,
                    }
                }
                paused @ Slot::Paused { .. } => paused,
            };
            self.slots.push(paused);
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
            match self.start(held, prompt) {
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

/// `poll` plus or minus up to `jitter`, never more than `poll` itself, so dispatchers started
/// together spread their reads.
fn jittered(poll: Duration, jitter: Duration) -> Duration {
    let millis = u64::try_from(poll.as_millis()).unwrap_or(u64::MAX);
    let spread = u64::try_from(jitter.as_millis())
        .unwrap_or(u64::MAX)
        .min(millis);
    let offset = ids::below(spread.saturating_mul(2).saturating_add(1));
    Duration::from_millis(millis.saturating_sub(spread).saturating_add(offset))
}

/// Full-jitter exponential backoff after `failures` failed passes in a row: a uniform wait up to
/// `min(cap, base * 2^failures)`. The loop's one-second session poll keeps a zero wait from
/// spinning.
fn backoff(base: Duration, cap: Duration, failures: u32) -> Duration {
    let base = u64::try_from(base.as_millis()).unwrap_or(u64::MAX);
    let cap = u64::try_from(cap.as_millis()).unwrap_or(u64::MAX);
    let ceiling = base.saturating_mul(2u64.saturating_pow(failures)).min(cap);
    Duration::from_millis(ids::below(ceiling.saturating_add(1)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_backoff_grows_with_full_jitter_up_to_its_cap() {
        for failures in [1, 2, 5, 40, u32::MAX] {
            let wait = backoff(Duration::from_secs(30), Duration::from_secs(900), failures);
            let grown = 30u64.saturating_mul(2u64.saturating_pow(failures)).min(900);
            assert!(
                wait <= Duration::from_secs(grown),
                "{failures}: {wait:?} above {grown} s"
            );
        }
        let poll = jittered(Duration::from_secs(60), Duration::from_secs(6));
        assert!(poll >= Duration::from_secs(54) && poll <= Duration::from_secs(66));
        assert_eq!(
            jittered(Duration::from_secs(60), Duration::ZERO),
            Duration::from_secs(60)
        );
    }
}
