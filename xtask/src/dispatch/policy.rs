//! The dispatcher's policy, all of it data (P14): `.agents/harness.toml [github]`, `[dispatch]`
//! and `[limits]`, and `.agents/kit/usage.toml [item]` and `[role.*]`. Every key the dispatcher
//! reads is required, so a missing one fails the first command instead of falling back to a
//! number in code.

use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::config;
use crate::config::limits::Limits;
use crate::orchestrate::claude::SessionRules;
use crate::repo::Repo;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OrderKey {
    BlocksOthers,
    Priority,
    Age,
}

#[derive(Debug, Clone)]
pub struct Policy {
    pub max_writers: u32,
    pub max_gardeners: u32,
    /// Planner sessions at once: leads, the product lead and the chief architect.
    pub max_planners: u32,
    /// Evaluator sessions at once.
    pub max_evaluators: u32,
    pub session: SessionRules,
    pub poll: Duration,
    pub max_attempts: u32,
    /// Review rounds an attempt may use (`[item] max_review_rounds`).
    pub max_review_rounds: u32,
    pub lease_order: Vec<OrderKey>,
    pub branch: String,
    /// A lease lasts this many times the role's wall clock (team/01 section 9).
    pub lease_factor: u32,
    /// Each GitHub pass starts up to this much before or after the poll interval.
    pub poll_jitter: Duration,
    /// Full-jitter backoff after a failed GitHub pass: base and cap (P15).
    pub backoff_base: Duration,
    pub backoff_cap: Duration,
    /// An issue in review with no verdict for this many hours escalates.
    pub verdict_hours: u64,
    usage: toml::Table,
}

#[derive(Deserialize)]
struct HarnessKeys {
    github: GithubKeys,
    dispatch: DispatchKeys,
}

#[derive(Deserialize)]
struct GithubKeys {
    branch: String,
}

#[derive(Deserialize)]
struct DispatchKeys {
    max_writers: u32,
    max_gardeners: u32,
    max_planners: u32,
    max_evaluators: u32,
    poll_seconds: u64,
    poll_jitter_seconds: u64,
    backoff_base_seconds: u64,
    backoff_cap_seconds: u64,
    lease_order: Vec<OrderKey>,
}

#[derive(Deserialize)]
struct UsageKeys {
    item: ItemKeys,
}

#[derive(Deserialize)]
struct ItemKeys {
    max_attempts: u32,
    max_review_rounds: u32,
    verdict_hours: u64,
}

impl Policy {
    /// The policy from the kit data, with `--max-writers` able only to lower the ceiling.
    pub fn load(repo: &Repo, max_writers: Option<u32>) -> Result<Policy> {
        let (harness_label, harness_path) = config::agents_file(repo, "harness.toml");
        let harness: HarnessKeys = config::read_toml(&harness_path, &harness_label)?;
        let (usage_label, usage_path) = config::agents_file(repo, "kit/usage.toml");
        let usage: toml::Table = config::read_toml(&usage_path, &usage_label)?;
        let item = toml::Value::Table(usage.clone())
            .try_into::<UsageKeys>()
            .with_context(|| format!("parsing {usage_label}"))?
            .item;
        let dispatch = harness.dispatch;
        let ceiling = dispatch.max_writers;
        Ok(Policy {
            max_writers: max_writers.map_or(ceiling, |asked| asked.min(ceiling)),
            max_gardeners: dispatch.max_gardeners,
            max_planners: dispatch.max_planners,
            max_evaluators: dispatch.max_evaluators,
            session: SessionRules::load(repo)?,
            poll: Duration::from_secs(dispatch.poll_seconds),
            max_attempts: item.max_attempts,
            max_review_rounds: item.max_review_rounds,
            lease_order: dispatch.lease_order,
            branch: harness.github.branch,
            lease_factor: Limits::built_with()?.dispatch.lease.lease_factor,
            poll_jitter: Duration::from_secs(dispatch.poll_jitter_seconds),
            backoff_base: Duration::from_secs(dispatch.backoff_base_seconds),
            backoff_cap: Duration::from_secs(dispatch.backoff_cap_seconds),
            verdict_hours: item.verdict_hours,
            usage,
        })
    }

    /// No gardener, planner or evaluator sessions.
    pub fn without_routines(&mut self) {
        self.max_gardeners = 0;
        self.max_planners = 0;
        self.max_evaluators = 0;
    }

    pub fn branch_for(&self, issue: u64, attempt: u32) -> String {
        self.branch
            .replace("{issue}", &issue.to_string())
            .replace("{attempt}", &attempt.to_string())
    }

    /// Sessions one attempt may use for a cap role (`[role.<cap role>] sessions_per_attempt`),
    /// which every role whose sessions continue an attempt names.
    pub fn sessions_per_attempt(&self, cap_role: &str) -> Result<u32> {
        self.usage
            .get("role")
            .and_then(|roles| roles.get(cap_role))
            .and_then(|role| role.get("sessions_per_attempt"))
            .and_then(toml::Value::as_integer)
            .and_then(|value| u32::try_from(value).ok())
            .with_context(|| {
                format!(".agents/kit/usage.toml [role.{cap_role}] has no sessions_per_attempt")
            })
    }

    /// The `[routine.<name>]` tables of usage.toml, in name order.
    pub fn routines(&self) -> Vec<(String, toml::Table)> {
        self.usage
            .get("routine")
            .and_then(toml::Value::as_table)
            .map(|table| {
                table
                    .iter()
                    .filter_map(|(name, value)| value.as_table().map(|t| (name.clone(), t.clone())))
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::testkit::TempRepo;

    /// Every key the dispatcher reads from `.agents/harness.toml`, for tests that start one.
    pub(crate) const HARNESS: &str = "[github]\nbranch = \"agent/{issue}/a{attempt}\"\n[dispatch]\nmax_writers = 3\nprotected_change_agents = [\"lead-agent-kit\", \"chief-architect\"]\nmax_gardeners = 1\nmax_planners = 1\nmax_evaluators = 2\nstall_seconds = 120\npoll_seconds = 60\npoll_jitter_seconds = 6\nbackoff_base_seconds = 30\nbackoff_cap_seconds = 900\nlease_order = [\"priority\", \"age\"]\n[limits]\nusage_limit_strings = [\"You've hit your session limit\"]\nretry_seconds = 60\n";

    #[test]
    fn reads_the_kit_data_and_only_lowers_the_writer_ceiling() {
        let temp = TempRepo::create();
        temp.write(".agents/harness.toml", HARNESS);
        temp.write(".agents/kit/usage.toml", "[item]\nmax_attempts = 2\nmax_review_rounds = 3\nverdict_hours = 24\n[role.worker]\nmax_turns = 80\nsessions_per_attempt = 2\n[routine.garden-docs]\nagent = \"garden-docs\"\ncadence = \"weekly\"\n");
        let policy = Policy::load(&temp.repo(), Some(8)).unwrap();
        assert_eq!(policy.max_writers, 3);
        assert_eq!(Policy::load(&temp.repo(), Some(1)).unwrap().max_writers, 1);
        assert_eq!(policy.session.stall, Duration::from_secs(120));
        assert_eq!(policy.session.retry_after_limit, Duration::from_secs(60));
        assert_eq!(policy.lease_order, vec![OrderKey::Priority, OrderKey::Age]);
        assert_eq!(policy.branch_for(142, 2), "agent/142/a2");
        assert_eq!(policy.sessions_per_attempt("worker").unwrap(), 2);
        assert!(policy.sessions_per_attempt("lead").is_err());
        assert_eq!(policy.routines()[0].0, "garden-docs");
        assert_eq!(policy.session.limit_strings.len(), 1);
    }

    #[test]
    fn a_missing_key_or_an_unknown_order_key_is_an_error() {
        let temp = TempRepo::create();
        temp.write(
            ".agents/kit/usage.toml",
            "[item]\nmax_attempts = 2\nmax_review_rounds = 3\nverdict_hours = 24\n",
        );
        temp.write(
            ".agents/harness.toml",
            &HARNESS.replace("poll_seconds = 60\n", ""),
        );
        let error = Policy::load(&temp.repo(), None).unwrap_err();
        assert!(format!("{error:#}").contains("poll_seconds"), "{error:#}");
        temp.write(
            ".agents/harness.toml",
            &HARNESS.replace("\"age\"", "\"oldest\""),
        );
        assert!(Policy::load(&temp.repo(), None).is_err());
        temp.write(".agents/harness.toml", HARNESS);
        temp.write(
            ".agents/kit/usage.toml",
            "[item]\nmax_attempts = 2\nverdict_hours = 24\n",
        );
        let error = Policy::load(&temp.repo(), None).unwrap_err();
        assert!(
            format!("{error:#}").contains("max_review_rounds"),
            "{error:#}"
        );
    }
}
