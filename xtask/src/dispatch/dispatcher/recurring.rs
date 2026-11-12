//! The recurring agents beside the writers: due routines start in their own worktrees within the
//! routine slots, and a routine that ends at a usage limit keeps its previous start, so it runs
//! again once the window is back.

use anyhow::Result;

use super::{Dispatcher, RoutineRun};
use crate::clock::Utc;
use crate::config::session::ItemStatus;
use crate::dispatch::routines::{Cadence, Routine, now_unix, unix_of};
use crate::dispatch::worker::Job;
use crate::orchestrate::claude::Ended;
use crate::orchestrate::ids;
use crate::orchestrate::issue::status_label;
use crate::orchestrate::launch::{Caps, LaunchScope, SessionStart};

impl Dispatcher<'_> {
    /// When the newest `status:proposed` issue was filed, for routines that run on new issues.
    fn newest_proposed(&self) -> Result<Option<u64>> {
        let watched = self
            .routines
            .iter()
            .any(|routine| routine.cadence == Cadence::NewIssue);
        let Some(label) = status_label(ItemStatus::Proposed).filter(|_| watched) else {
            return Ok(None);
        };
        Ok(self
            .tracker
            .open_with_label(&label)?
            .iter()
            .filter_map(|issue| unix_of(&issue.created_at))
            .max())
    }

    pub(super) fn after_routine(&mut self, routine: RoutineRun, ended: &Ended) -> Result<()> {
        println!(
            "dispatch: routine {} {}",
            routine.routine.name,
            ended.describe()
        );
        if let Ended::UsageLimited { .. } = ended {
            match routine.previous {
                Some(previous) => self.schedule.started(&routine.routine.name, previous),
                None => {
                    self.schedule.last_started.remove(&routine.routine.name);
                }
            }
            self.schedule.save(&self.repo)?;
        }
        Ok(())
    }

    pub(super) fn start_routines(&mut self) -> Result<()> {
        let capacity = usize::try_from(self.policy.max_gardeners).unwrap_or(0);
        let running: Vec<String> = self
            .running_routines
            .iter()
            .map(|r| r.routine.name.clone())
            .collect();
        let newest = self.newest_proposed()?;
        let due: Vec<Routine> = self
            .schedule
            .due(&self.routines, now_unix(), newest)
            .into_iter()
            .filter(|routine| !running.contains(&routine.name))
            .cloned()
            .collect();
        for routine in due
            .into_iter()
            .take(capacity.saturating_sub(self.running_routines.len()))
        {
            let Some(agent) = routine.agent.clone() else {
                continue;
            };
            let worktree = self.worktree(&format!("routine-{}", routine.name), None)?;
            let previous = self.schedule.last_started.get(&routine.name).copied();
            self.schedule.started(&routine.name, now_unix());
            self.schedule.save(&self.repo)?;
            let watch = self.policy.session.watch(
                Some(self.kit.turn_cap(&agent, None, Caps::Role)?),
                self.kit.wall_clock(&agent, None, Caps::Role),
            );
            let log = self.repo.path(&format!(
                ".agent/logs/dispatch-routine-{}-{}.jsonl",
                routine.name,
                Utc::now().compact()
            ));
            let prompt = self
                .template("routine", &[("routine", &routine.name)])?
                .unwrap_or_else(|| routine.prompt());
            let start = SessionStart::Named(ids::session_id());
            let job = Job {
                agent: &agent,
                item: None,
                prompt: &prompt,
                start: &start,
                log: &log,
                model: None,
                effort: None,
                scope: LaunchScope::Ordinary,
            };
            let run = self.launcher.spawn(&worktree, &job, watch)?;
            println!("dispatch: started routine {} ({agent})", routine.name);
            self.running_routines.push(RoutineRun {
                routine,
                run,
                previous,
            });
        }
        Ok(())
    }
}
