//! `cargo xtask kit ready <n> [--dry-run]` (team/01 section 3, owner instruction 6): the readying
//! agent, a lead, the product lead or the programme manager and never the item's implementer,
//! turns a `status:proposed` issue into a ready one. The kit checks the form, applies the field
//! labels from the sections, raises the tier to what the write set reaches, posts `ready.v1` with
//! the digests of the acceptance section and the write set, then swaps `status:proposed` for
//! `status:ready`.

use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use serde_json::Value;

use super::issue::{Issue, TRUST_CORE_LABEL, globs_in, raise, section, status_label, tier_name};
use super::labels::LabelsFile;
use super::launch::{LaunchKit, owner_step_or};
use super::overlap::overlaps;
use super::records::{READY_SCHEMA, Ready, json_blocks, ready_comment};
use super::tracker::{GhTracker, IssueEdit, Tracker};
use crate::cli::{self, Spec};
use crate::config::limits::Limits;
use crate::config::session::{ItemStatus, RiskTier, Scope, Session, parse_item_number};
use crate::github::{Gh, Mode};
use crate::repo::Repo;

const SPEC: Spec = Spec {
    flags: &["--dry-run"],
    options: &[],
};
const REQUIRED_SECTIONS: &[&str] = &["Spec", "Write set", "Acceptance criteria"];
const CRITERION_FIELDS: &[&str] = &["id", "check", "expect", "oracle"];
const LINE_FIELDS: usize = 4;
const ORACLE_MARK: &str = "oracle";
const TIER_PREFIX: &str = "tier:";

/// The labels and digest a valid readying produces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Readying {
    pub ready: Ready,
    pub edit: IssueEdit,
    pub tier: RiskTier,
}

/// `kit ready <n>`.
pub fn command(args: &[String]) -> Result<ExitCode> {
    let parsed = cli::parse(args, &SPEC)?;
    let Some(raw) = parsed.positional.first() else {
        bail!("usage: cargo xtask kit ready <issue> [--dry-run]");
    };
    let number = parse_item_number(raw)?;
    let repo = Repo::discover()?;
    let session = Session::from_env()?;
    let readier = session
        .agent
        .clone()
        .context("GRDR_AGENT is unset: kit ready runs inside a lead, product-lead or programme-manager session")?;
    let mode = if parsed.has("--dry-run") {
        Mode::DryRun
    } else {
        Mode::Live
    };
    let tracker = GhTracker::new(Gh::for_repo(&repo, mode)?);
    let seed = seed_session(&repo, &session, &readier)?;
    match ready(&repo, &tracker, number, &readier, seed) {
        Ok(code) => Ok(code),
        Err(error) => owner_step_or(error),
    }
}

pub fn ready(
    repo: &Repo,
    tracker: &dyn Tracker,
    number: u64,
    readier: &str,
    seed: bool,
) -> Result<ExitCode> {
    let kit = LaunchKit::load(repo)?;
    let labels = LabelsFile::load(repo)?;
    let issue = tracker.issue(number)?;
    let readying = match plan(&kit, &labels, &issue, readier, seed) {
        Ok(readying) => readying,
        Err(problems) => {
            let printed = Limits::built_with()?.orchestrate.ready.printed_problems;
            for problem in problems.iter().take(printed) {
                eprintln!("ERROR kit ready #{number}: {problem}");
            }
            return Ok(ExitCode::from(2));
        }
    };
    tracker.comment(number, &ready_comment(&readying.ready)?)?;
    tracker.edit(number, &readying.edit)?;
    println!(
        "kit ready: #{number} is status:ready at {} tier, acceptance sha256 {}, readied by {readier}",
        tier_name(readying.tier),
        readying.ready.acceptance_sha256
    );
    Ok(ExitCode::SUCCESS)
}

/// The readying, or every reason the issue cannot be readied yet.
pub fn plan(
    kit: &LaunchKit,
    labels: &LabelsFile,
    issue: &Issue,
    readier: &str,
    seed: bool,
) -> Result<Readying, Vec<String>> {
    let mut problems = Vec::new();
    let item = issue.work_item();
    let acting_as = if seed { kit.acting_as(readier) } else { &[] };
    let allowed = labels.may_ready(readier, acting_as).unwrap_or(false);
    if !allowed {
        problems.push(format!(
            "{readier} may not ready items; .github/labels.toml names who may"
        ));
    }
    if item.status != Some(ItemStatus::Proposed) {
        problems.push("only a status:proposed issue is readied".to_owned());
    }
    match &item.agent {
        Some(agent) if agent == readier => problems.push(format!(
            "{readier} is the item's agent; the agent that readies an item never implements it"
        )),
        Some(agent) if kit.roster.agent(agent).is_none() => {
            problems.push(format!("agent `{agent}` is not in the roster"))
        }
        Some(_) => {}
        None => problems.push("the issue names no agent".to_owned()),
    }
    for heading in REQUIRED_SECTIONS {
        let empty = section(&issue.body, heading).is_none_or(|text| globs_in(&text).is_empty());
        if empty {
            problems.push(format!("the `### {heading}` section is empty"));
        }
    }
    if let Some(found) = &item.acceptance {
        problems.extend(criteria_problems(&found.text));
    }
    let write_set = &item.write_set;
    let protected = overlaps(write_set, &kit.protected.paths).unwrap_or(true);
    let protected_agent = item
        .agent
        .as_deref()
        .is_some_and(|agent| kit.is_protected_change(agent, write_set).unwrap_or(false));
    if protected && !protected_agent {
        problems.push("the write set reaches a protected path; a protected change is its own item for lead-agent-kit or the chief architect".to_owned());
    }
    let floor = kit
        .risk
        .tier_of_write_set(write_set)
        .ok()
        .flatten()
        .unwrap_or(RiskTier::Medium);
    let tier = item.tier.map_or(floor, |tier| raise(tier, floor));
    let trust_core = item.trust_core || kit.risk.touches_trust_core(write_set).unwrap_or(true);
    let mut add: Vec<String> = Vec::new();
    for (prefix, value) in [
        ("kind:", item.kind.as_deref()),
        ("squad:", item.squad.as_deref()),
        ("size:", item.size.as_deref()),
        ("agent:", item.agent.as_deref()),
        (TIER_PREFIX, Some(tier_name(tier))),
    ] {
        match value {
            Some(value) => add.push(format!("{prefix}{value}")),
            None => problems.push(format!("no {prefix} value in the labels or the form")),
        }
    }
    if trust_core {
        add.push(TRUST_CORE_LABEL.to_owned());
    }
    for name in &add {
        if !labels.knows(name) {
            problems.push(format!("`{name}` is not a label in .github/labels.toml"));
        }
    }
    for prefix in labels.required_when_ready() {
        if !add.iter().any(|name| name.starts_with(prefix)) {
            problems.push(format!("no {prefix} label"));
        }
    }
    let write_set_sha256 = item.write_set_sha256();
    let Some(acceptance) = item.acceptance.filter(|_| problems.is_empty()) else {
        if problems.is_empty() {
            problems.push("the issue has no `### Acceptance criteria` section".to_owned());
        }
        return Err(problems);
    };
    let mut remove: Vec<String> = issue
        .label_names()
        .filter(|name| name.starts_with(TIER_PREFIX) && !add.iter().any(|added| added == name))
        .map(str::to_owned)
        .collect();
    remove.extend(status_label(ItemStatus::Proposed));
    add.extend(status_label(ItemStatus::Ready));
    add.retain(|name| !issue.has_label(name));
    Ok(Readying {
        ready: Ready {
            schema: READY_SCHEMA.to_owned(),
            item: issue.number,
            by: readier.to_owned(),
            acceptance_sha256: acceptance.sha256,
            write_set_sha256,
        },
        edit: IssueEdit {
            add,
            remove,
            assign_self: false,
        },
        tier,
    })
}

/// Every criterion names a command and an oracle: the JSON block of team/06 section 6.4, or one
/// `id | check | expect | oracle: ...` line per criterion.
pub fn criteria_problems(text: &str) -> Vec<String> {
    let blocks = json_blocks(text);
    if let Some(block) = blocks.first() {
        let Ok(value) = serde_json::from_str::<Value>(block) else {
            return vec!["the acceptance criteria block is not JSON".to_owned()];
        };
        let criteria = value
            .get("criteria")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if criteria.is_empty() {
            return vec!["the acceptance criteria block lists no criteria".to_owned()];
        }
        return criteria
            .iter()
            .enumerate()
            .flat_map(|(index, criterion)| {
                CRITERION_FIELDS.iter().filter_map(move |field| {
                    let present = criterion
                        .get(*field)
                        .and_then(Value::as_str)
                        .is_some_and(|v| !v.trim().is_empty());
                    (!present)
                        .then(|| format!("acceptance criterion {} has no `{field}`", index + 1))
                })
            })
            .collect();
    }
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    if lines.is_empty() {
        return vec!["the acceptance criteria section is empty".to_owned()];
    }
    lines
        .iter()
        .filter(|line| {
            let fields: Vec<&str> = line.split('|').map(str::trim).collect();
            fields.len() < LINE_FIELDS
                || !fields
                    .last()
                    .is_some_and(|last| last.starts_with(ORACLE_MARK))
        })
        .map(|line| {
            format!("criterion `{line}` needs id | check | expect | oracle: <named oracle>")
        })
        .collect()
}

/// The chief architect's seed session plays the planner role (team/06 section 14).
fn seed_session(repo: &Repo, session: &Session, agent: &str) -> Result<bool> {
    if session.scope != Some(Scope::Seed) {
        return Ok(false);
    }
    let Some(scope) = crate::config::protected::SeedScope::load(repo)? else {
        return Ok(false);
    };
    Ok(scope.agent == agent)
}

#[cfg(test)]
mod tests;
