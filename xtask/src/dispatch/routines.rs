//! The recurring agents (owner instruction 6, team/03 section 7): every `[routine.<name>]` of
//! `.agents/kit/usage.toml` with an `agent` and a time cadence runs as one print-mode session when
//! it is due, within its usage cap, and files what it finds as `status:proposed` issues. Event
//! cadences (pull request, issue opened, release branch and the like) belong to the events that
//! fire them, and owner-scheduled tasks to the owner's machine, so the dispatcher skips both; the
//! one event it watches itself is `issue-opened`, by polling for `status:proposed` issues filed
//! after the routine last started. The last start of each routine is kept in
//! `.agent/state/dispatch-routines.json`.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::state;
use crate::repo::Repo;

const SCHEDULE_FILE: &str = ".agent/state/dispatch-routines.json";
const ISSUE_OPENED: &str = "issue-opened";
pub(super) const HOUR: u64 = 3600;
const DAY: u64 = 24 * HOUR;
const CADENCES: &[(&str, u64)] = &[
    ("hourly", HOUR),
    ("daily", DAY),
    ("nightly", DAY),
    ("weekly", 7 * DAY),
    ("monthly", 30 * DAY),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cadence {
    Every(Duration),
    /// When an issue is filed; the dispatcher polls for it.
    NewIssue,
    /// Run by an event outside the dispatcher.
    Event(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Routine {
    pub name: String,
    pub agent: Option<String>,
    pub workflow: Option<String>,
    pub cadence: Cadence,
    pub usage_cap: Option<f64>,
    /// Another runner owns it, such as the owner's scheduled task.
    pub runner: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Schedule {
    /// Unix seconds of each routine's last start that did not end at a usage limit.
    pub last_started: BTreeMap<String, u64>,
}

impl Routine {
    pub fn from_table(name: &str, table: &toml::Table) -> Routine {
        let text = |key: &str| {
            table
                .get(key)
                .and_then(toml::Value::as_str)
                .map(str::to_owned)
        };
        let cadence_name = text("cadence").unwrap_or_default();
        let cadence = match CADENCES.iter().find(|(known, _)| *known == cadence_name) {
            Some((_, seconds)) => Cadence::Every(Duration::from_secs(*seconds)),
            None if cadence_name == ISSUE_OPENED => Cadence::NewIssue,
            None => Cadence::Event(cadence_name.clone()),
        };
        Routine {
            name: name.to_owned(),
            agent: text("agent").filter(|agent| !agent.contains('*')),
            workflow: text("workflow"),
            cadence,
            usage_cap: table.get("usage_cap").and_then(toml::Value::as_float),
            runner: text("runner"),
        }
    }

    /// Whether it is due: an agent, no other runner, and its time or a newer filed issue, given
    /// its last start and the creation time of the newest `status:proposed` issue (Unix seconds).
    pub fn is_due(&self, now: u64, last: Option<u64>, newest_issue: Option<u64>) -> bool {
        if self.agent.is_none() || self.runner.is_some() {
            return false;
        }
        match &self.cadence {
            Cadence::Every(every) => {
                last.is_none_or(|last| now.saturating_sub(last) >= every.as_secs())
            }
            Cadence::NewIssue => {
                newest_issue.is_some_and(|newest| last.is_none_or(|last| newest > last))
            }
            Cadence::Event(_) => false,
        }
    }

    /// One line, so it passes through any launcher unchanged.
    pub fn prompt(&self) -> String {
        let workflow = self
            .workflow
            .as_ref()
            .map(|name| format!(" through the /{name} workflow"))
            .unwrap_or_default();
        let cap = self
            .usage_cap
            .map(|cap| format!(" Stop within {:.1}% of the usage window.", cap * 100.0))
            .unwrap_or_default();
        format!(
            "Scheduled run of routine {}{workflow}: do your role's recurring job on the current base. File each finding as a status:proposed issue with its evidence after searching for an existing one, and change nothing outside your role.{cap}",
            self.name
        )
    }
}

impl Schedule {
    pub fn load(repo: &Repo) -> Result<Schedule> {
        state::load(repo, SCHEDULE_FILE)
    }

    pub fn save(&self, repo: &Repo) -> Result<()> {
        state::save(repo, SCHEDULE_FILE, self)
    }

    /// The routines due at `now` (Unix seconds), oldest last start first.
    pub fn due<'a>(
        &self,
        routines: &'a [Routine],
        now: u64,
        newest_issue: Option<u64>,
    ) -> Vec<&'a Routine> {
        let mut due: Vec<(&Routine, u64)> = routines
            .iter()
            .filter_map(|routine| {
                let last = self.last_started.get(&routine.name).copied();
                routine
                    .is_due(now, last, newest_issue)
                    .then_some((routine, last.unwrap_or(0)))
            })
            .collect();
        due.sort_by_key(|(_, last)| *last);
        due.into_iter().map(|(routine, _)| routine).collect()
    }

    pub fn started(&mut self, name: &str, at: u64) {
        self.last_started.insert(name.to_owned(), at);
    }
}

/// Unix seconds of a GitHub timestamp such as `2026-11-11T10:00:00Z`.
pub fn unix_of(iso: &str) -> Option<u64> {
    let number = |from: usize, to: usize| iso.get(from..to)?.parse::<i64>().ok();
    let (year, month, day) = (number(0, 4)?, number(5, 7)?, number(8, 10)?);
    let (hour, minute, second) = (number(11, 13)?, number(14, 16)?, number(17, 19)?);
    let days = days_from_civil(year, month, day);
    u64::try_from(days * 86_400 + hour * 3600 + minute * 60 + second).ok()
}

/// Howard Hinnant's civil-to-days conversion, the inverse of the one in `crate::clock`.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let shifted = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * shifted + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Unix seconds now.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn routine(name: &str, table: &str) -> Routine {
        Routine::from_table(
            name,
            &crate::config::parse_toml(table, "usage.toml").unwrap(),
        )
    }

    #[test]
    fn only_agent_routines_on_times_or_new_issues_are_dispatched() {
        let docs = routine(
            "garden-docs",
            "agent = \"garden-docs\"\ncadence = \"weekly\"\nusage_cap = 0.02\n",
        );
        assert_eq!(docs.cadence, Cadence::Every(Duration::from_secs(7 * DAY)));
        assert!(docs.is_due(10 * DAY, None, None));
        assert!(
            docs.prompt()
                .contains("Stop within 2.0% of the usage window.")
        );
        assert!(!docs.prompt().contains('\n'));
        let review = routine(
            "review",
            "agent = \"eval-diff\"\nworkflow = \"review\"\ncadence = \"pull-request\"\n",
        );
        assert_eq!(review.cadence, Cadence::Event("pull-request".into()));
        assert!(!review.is_due(10 * DAY, None, Some(DAY)));
        assert!(
            !routine("by-kind", "agent = \"eval-*\"\ncadence = \"daily\"\n").is_due(
                10 * DAY,
                None,
                None
            )
        );
        assert!(
            !routine(
                "digest",
                "runner = \"owner-scheduled-task\"\ncadence = \"daily\"\n"
            )
            .is_due(10 * DAY, None, None)
        );
        let intake = routine(
            "garden-intake",
            "agent = \"garden-intake\"\ncadence = \"issue-opened\"\n",
        );
        assert_eq!(intake.cadence, Cadence::NewIssue);
        assert!(!intake.is_due(10 * DAY, None, None));
        assert!(intake.is_due(10 * DAY, Some(DAY), Some(2 * DAY)));
        assert!(!intake.is_due(10 * DAY, Some(3 * DAY), Some(2 * DAY)));
        let audit = routine(
            "audit-weekly",
            "agent = \"garden-architecture\"\nworkflow = \"audit\"\ncadence = \"weekly\"\n",
        );
        assert!(audit.prompt().contains("through the /audit workflow"));
    }

    #[test]
    fn due_routines_follow_their_last_start() {
        let routines = vec![
            routine(
                "garden-intel",
                "agent = \"garden-intel\"\ncadence = \"daily\"\n",
            ),
            routine(
                "garden-docs",
                "agent = \"garden-docs\"\ncadence = \"weekly\"\n",
            ),
        ];
        let mut schedule = Schedule::default();
        let now = 10 * DAY;
        assert_eq!(schedule.due(&routines, now, None).len(), 2);
        schedule.started("garden-intel", now - HOUR);
        schedule.started("garden-docs", now - 2 * DAY);
        assert!(schedule.due(&routines, now, None).is_empty());
        let names: Vec<&str> = schedule
            .due(&routines, now + DAY, None)
            .iter()
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(names, vec!["garden-intel"]);
    }

    #[test]
    fn github_timestamps_become_unix_seconds() {
        assert_eq!(unix_of("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(unix_of("2023-11-14T22:13:20Z"), Some(1_700_000_000));
        assert_eq!(unix_of("2000-02-29T00:00:00Z"), Some(951_782_400));
        assert_eq!(unix_of("not a time"), None);
    }
}
