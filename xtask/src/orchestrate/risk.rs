//! `cargo xtask risk [--base <ref>] [--item <n>] [--floor <tier>] [--lane <lane>] [--raise <lane>
//! --reason <text>] [--json <path>]` (team/01 section 5, owner instruction 8): the deterministic
//! tier and review lane of the change against its base. Paths give the tier through
//! `.agents/risk-tiers.toml` and the trust-core list (read from the base), triggers found in the
//! diff raise it, and the issue's tier label or `--floor` is a floor, so a tier is only ever
//! raised. The lane decides how much review the change costs: `static` for changes proven
//! equivalent or checkable without a model, `light` for small changes away from every sensitive
//! surface, `full` for high tier or trust core, `standard` otherwise. A lane is raised, never
//! lowered: by `--lane`, by the issue's `lane.v1` comments, and by `--raise`, which posts one for
//! the item. The result goes to `.agent/evidence/risk.json`.

mod diff;
mod equivalence;
mod item;
mod manifest;

use std::process::ExitCode;
use std::sync::LazyLock;

use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::{Deserialize, Serialize};

use super::issue::{parse_tier, raise, tier_name};
use super::launch::owner_step_or;
use super::tiers::{Change, LaneLimits, RUNTIME_TRUST_CORE, RiskPolicy};
use super::tracker::GhTracker;
use crate::cli::{self, Spec};
use crate::clock::Utc;
use crate::config::limits::Limits;
use crate::config::protected::{PROTECTED_PATHS_FILE, ProtectedPaths};
use crate::config::session::{RiskTier, parse_item_number};
use crate::git::{self, Base, read_at};
use crate::github::{Gh, Mode};
use crate::globs::{Case, GlobList};
use crate::repo::{Repo, write_if_changed};

pub use self::diff::{FileChange, changes, parse_diff};
use self::item::{item_facts, lane_option, post_raise};

pub const EVIDENCE: &str = ".agent/evidence/risk.json";
const SCHEMA: &str = "risk.v1";
const PROSE_EXTENSIONS: &[&str] = &["md", "mdx", "txt"];
const LIMITS_FILE: &str = "limits.toml";
const NOT_CHECKED: &[&str] = &[
    "public_api_change (cargo semver-checks arrives with the gates)",
    "fail_mode_change",
    "security_test_weakened",
    "essentials_or_failsafe_change",
    "additive_behind_flag",
];
const SPEC: Spec = Spec {
    flags: &[],
    options: &[
        "--base", "--item", "--floor", "--lane", "--raise", "--reason", "--json",
    ],
};
const LANES: &[(&str, Lane)] = &[
    ("static", Lane::Static),
    ("light", Lane::Light),
    ("standard", Lane::Standard),
    ("full", Lane::Full),
];
static UNSAFE: LazyLock<Option<Regex>> = LazyLock::new(|| Regex::new(r"\bunsafe\b").ok());
static ERROR_CODE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"GRDR-[A-Z]+-\d{4}").ok());
static PUBLIC_ITEM: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"^\s*pub\s+(async\s+|unsafe\s+|const\s+)*(fn|struct|enum|trait|type|const|static|mod|use|union)\b").ok()
});
static TEST_PATH: LazyLock<Option<GlobList>> = LazyLock::new(|| {
    GlobList::new(
        &[
            "**/tests/**",
            "**/benches/**",
            "fuzz/**",
            "**/*_test.rs",
            "**/*.test.ts",
            "**/*.test.tsx",
            "**/*.spec.ts",
            "**/*.spec.tsx",
        ],
        Case::Sensitive,
    )
    .ok()
});

/// Ordered by the review a lane costs, so raising a lane is taking the maximum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Lane {
    Static,
    Light,
    Standard,
    Full,
}

/// What a classification may not go below: the tier and the lane.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Floor {
    pub tier: Option<RiskTier>,
    pub lane: Option<Lane>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Assessment {
    pub schema: &'static str,
    pub id: String,
    pub tier: &'static str,
    pub trust_core: bool,
    pub lane: Lane,
    pub reasons: Vec<String>,
    /// The `.agents/risk-tiers.toml` triggers found in the diff, by name.
    pub triggers: Vec<String>,
    pub evidence_required: Vec<String>,
    pub not_checked: Vec<&'static str>,
    pub changed_files: Vec<String>,
    pub changed_lines: usize,
    pub base: String,
    pub policy: String,
}

impl Lane {
    pub fn name(self) -> &'static str {
        match self {
            Lane::Static => "static",
            Lane::Light => "light",
            Lane::Standard => "standard",
            Lane::Full => "full",
        }
    }

    pub fn parse(name: &str) -> Option<Lane> {
        LANES
            .iter()
            .find(|(known, _)| *known == name)
            .map(|(_, lane)| *lane)
    }
}

/// `risk`.
pub fn command(args: &[String]) -> Result<ExitCode> {
    let parsed = cli::parse(args, &SPEC)?;
    let repo = Repo::discover()?;
    let base = git::base_for(&repo, parsed.value("--base"))?;
    let mut floor = Floor {
        tier: parsed.value("--floor").and_then(parse_tier),
        lane: lane_option(parsed.value("--lane"), "--lane")?,
    };
    let raised = lane_option(parsed.value("--raise"), "--raise")?;
    let mut reasons = Vec::new();
    let item = parsed.value("--item").map(parse_item_number).transpose()?;
    if raised.is_some() && item.is_none() {
        bail!("--raise needs --item <n>: the raise is posted on the issue");
    }
    if let Some(number) = item {
        let tracker = GhTracker::new(Gh::for_repo(&repo, Mode::Live)?);
        if let Some(lane) = raised {
            let reason = parsed
                .value("--reason")
                .context("--raise needs --reason <text>: why the lane goes up")?;
            if let Err(error) = post_raise(&tracker, number, lane, reason) {
                return owner_step_or(error);
            }
        }
        let facts = match item_facts(&tracker, number) {
            Ok(facts) => facts,
            Err(error) => return owner_step_or(error),
        };
        floor.tier = match (floor.tier, facts.tier) {
            (Some(a), Some(b)) => Some(raise(a, b)),
            (a, b) => a.or(b),
        };
        floor.lane = floor.lane.max(facts.lane);
        if facts.acceptance_changed {
            reasons.push("acceptance_changed_after_lease: the acceptance digest differs from the lease comment".to_owned());
        }
    }
    let assessment = assess_at(&repo, &base, floor, reasons)?;
    let mut json = serde_json::to_string_pretty(&assessment)?;
    json.push('\n');
    write_if_changed(&repo.path(EVIDENCE), json.as_bytes())?;
    write_if_changed(
        &repo.path(&format!(".agent/evidence/{}.json", assessment.id)),
        json.as_bytes(),
    )?;
    if let Some(path) = parsed.value("--json") {
        write_if_changed(&std::env::current_dir()?.join(path), json.as_bytes())?;
    }
    println!(
        "risk: tier {}, lane {}, trust core {}, {} files and {} lines against {}",
        assessment.tier,
        assessment.lane.name(),
        if assessment.trust_core { "yes" } else { "no" },
        assessment.changed_files.len(),
        assessment.changed_lines,
        assessment.base
    );
    let printed = Limits::built_with()?.orchestrate.risk.printed_reasons;
    for reason in assessment.reasons.iter().take(printed) {
        println!("  {reason}");
    }
    println!("risk: evidence {} ({EVIDENCE})", assessment.id);
    Ok(ExitCode::SUCCESS)
}

/// The assessment of `repo`'s working tree against its base, as `cargo xtask risk` makes it.
pub fn assess_tree(repo: &Repo, floor: Floor) -> Result<Assessment> {
    let base = git::resolve_base(repo)?;
    assess_at(repo, &base, floor, Vec::new())
}

fn assess_at(repo: &Repo, base: &Base, floor: Floor, reasons: Vec<String>) -> Result<Assessment> {
    let changes = changes(repo, base)?;
    let policy = RiskPolicy::load_at(repo, base)?;
    let protected = protected_globs(repo, base)?;
    Ok(assess(&policy, &protected, &changes, floor, reasons, base))
}

/// Classifies `changes`; a floor can only raise the tier and the lane.
pub fn assess(
    policy: &RiskPolicy,
    protected: &GlobList,
    changes: &[FileChange],
    floor: Floor,
    mut reasons: Vec<String>,
    base: &Base,
) -> Assessment {
    let mut tier = RiskTier::Low;
    let mut trust_core = false;
    for change in changes {
        let path_tier = policy.tier_of(&change.path);
        if path_tier != RiskTier::Low {
            reasons.push(format!("{}: {} tier", change.path, tier_name(path_tier)));
        }
        tier = raise(tier, path_tier);
        if policy.is_trust_core(&change.path) {
            trust_core = true;
            reasons.push(format!("{}: trust core", change.path));
        }
    }
    let mut triggers = triggers(changes);
    triggers.extend(
        changes
            .iter()
            .filter(|change| policy.is_runtime_trust_core(&change.path))
            .map(|change| format!("{RUNTIME_TRUST_CORE}: {}", change.path)),
    );
    let tests_only = !changes.is_empty()
        && changes
            .iter()
            .all(|c| is_test(&c.path) && c.removed.is_empty() && c.before.is_none());
    if tests_only
        && !trust_core
        && policy
            .triggers(RiskTier::Low)
            .iter()
            .any(|t| t == "tests_only_addition")
    {
        tier = RiskTier::Low;
        reasons.push("tests_only_addition: low tier".to_owned());
    }
    for trigger in &triggers {
        if policy
            .triggers(RiskTier::High)
            .iter()
            .any(|known| trigger.starts_with(known.as_str()))
        {
            tier = RiskTier::High;
        }
        reasons.push(trigger.clone());
    }
    if reasons
        .iter()
        .any(|r| r.starts_with("acceptance_changed_after_lease"))
    {
        tier = RiskTier::High;
    }
    if let Some(floor) = floor.tier {
        tier = raise(tier, floor);
    }
    let changed_lines: usize = changes
        .iter()
        .map(|c| c.added.len() + c.removed.len())
        .sum();
    let classified = lane(
        policy,
        protected,
        changes,
        tier,
        trust_core,
        &triggers,
        changed_lines,
    );
    let lane = floor
        .lane
        .map_or(classified, |raised| classified.max(raised));
    if lane != classified {
        reasons.push(format!(
            "lane raised from {} to {}",
            classified.name(),
            lane.name()
        ));
    }
    let mut trigger_names: Vec<String> = triggers
        .iter()
        .map(|trigger| {
            trigger
                .split_once(':')
                .map_or(trigger.as_str(), |(name, _)| name)
        })
        .map(str::to_owned)
        .collect();
    trigger_names.sort();
    trigger_names.dedup();
    let change = Change {
        tier,
        trust_core,
        protected: false,
        kind: None,
        triggers: &trigger_names,
    };
    let evidence_required = match lane {
        Lane::Static => vec!["verify, the equivalence check and the prose lint".to_owned()],
        _ => policy
            .lane_evaluators(lane, &change)
            .into_iter()
            .map(|evaluator| match (evaluator.model, evaluator.effort) {
                (Some(model), Some(effort)) => {
                    format!(
                        "{} on {model} at {effort} effort, one round",
                        evaluator.agent
                    )
                }
                _ => evaluator.agent,
            })
            .collect(),
    };
    let id = format!("risk-{}", Utc::now().compact());
    Assessment {
        schema: SCHEMA,
        id,
        tier: tier_name(tier),
        trust_core,
        lane,
        reasons,
        triggers: trigger_names,
        evidence_required,
        not_checked: NOT_CHECKED.to_vec(),
        changed_files: changes.iter().map(|c| c.path.clone()).collect(),
        changed_lines,
        base: base.describe(),
        policy: policy.source.clone(),
    }
}

fn lane(
    policy: &RiskPolicy,
    protected: &GlobList,
    changes: &[FileChange],
    tier: RiskTier,
    trust_core: bool,
    triggers: &[String],
    changed_lines: usize,
) -> Lane {
    let all_static = !changes.is_empty()
        && changes
            .iter()
            .all(|c| is_static(c, protected, &policy.lanes));
    // D-63: on a trust-core path only a lockfile inside the supply-chain policy stays static.
    let trust_core_only_lockfiles = changes
        .iter()
        .filter(|c| policy.is_trust_core(&c.path))
        .all(|c| is_lockfile(&c.path, &policy.lanes));
    if all_static && trust_core_only_lockfiles {
        return Lane::Static;
    }
    if trust_core {
        return Lane::Full;
    }
    if tier == RiskTier::High {
        return Lane::Full;
    }
    let small = changed_lines <= policy.lanes.light_max_lines
        && changes.len() <= policy.lanes.light_max_files;
    let sensitive = changes.iter().any(|c| {
        protected.is_match(&c.path)
            || c.path.ends_with(LIMITS_FILE)
            || c.path.ends_with(".proto")
            || manifest::is_manifest(&c.path)
            || c.added
                .iter()
                .chain(&c.removed)
                .any(|line| matches(&ERROR_CODE, line) || matches(&PUBLIC_ITEM, line))
    });
    if small && !sensitive && triggers.is_empty() {
        Lane::Light
    } else {
        Lane::Standard
    }
}

/// Proven equivalent Rust, prose or a generated file outside the protected paths, or a lockfile
/// whose packages stay within their majors.
fn is_static(change: &FileChange, protected: &GlobList, lanes: &LaneLimits) -> bool {
    let extension = change
        .path
        .rsplit_once('.')
        .map(|(_, e)| e)
        .unwrap_or_default();
    if is_lockfile(&change.path, lanes) {
        return manifest::lockfile_within_majors(
            &change.path,
            change.before.as_deref(),
            change.after.as_deref(),
        );
    }
    let outside_protected = change.after.is_some() && !protected.is_match(&change.path);
    if PROSE_EXTENSIONS.contains(&extension) {
        return outside_protected;
    }
    let generated = GlobList::new(&lanes.generated, Case::Sensitive)
        .is_ok_and(|globs| globs.is_match(&change.path));
    if generated {
        return outside_protected;
    }
    match (extension, &change.before, &change.after) {
        ("rs", Some(before), Some(after)) => {
            let tokens = (
                equivalence::rust_tokens(before),
                equivalence::rust_tokens(after),
            );
            matches!(tokens, (Some(a), Some(b)) if a == b)
        }
        _ => false,
    }
}

fn is_lockfile(path: &str, lanes: &LaneLimits) -> bool {
    let file_name = path.rsplit_once('/').map_or(path, |(_, name)| name);
    lanes.lockfiles.iter().any(|name| name == file_name)
}

fn triggers(changes: &[FileChange]) -> Vec<String> {
    let mut found = Vec::new();
    for change in changes {
        if change.path.ends_with(".rs") && change.added.iter().any(|line| matches(&UNSAFE, line)) {
            found.push(format!("unsafe_added: {}", change.path));
        }
        if manifest::is_manifest(&change.path) {
            let deps = manifest::compare(
                &change.path,
                change.before.as_deref(),
                change.after.as_deref(),
            );
            found.extend(
                deps.added
                    .iter()
                    .map(|d| format!("new_dependency: {} in {}", d, change.path)),
            );
            found.extend(
                deps.major_bumps
                    .iter()
                    .map(|d| format!("major_bump: {} in {}", d, change.path)),
            );
        }
        if change.path.ends_with(".proto") {
            found.push(format!("wire_or_pack_format_change: {}", change.path));
        }
    }
    found
}

fn matches(pattern: &LazyLock<Option<Regex>>, line: &str) -> bool {
    pattern.as_ref().is_some_and(|regex| regex.is_match(line))
}

fn is_test(path: &str) -> bool {
    TEST_PATH.as_ref().is_some_and(|globs| globs.is_match(path))
}

fn protected_globs(repo: &Repo, base: &Base) -> Result<GlobList> {
    let (text, _) = read_at(repo, base, PROTECTED_PATHS_FILE)?;
    let paths: Vec<String> = match text {
        Some(text) => {
            crate::config::parse_toml::<ProtectedPaths>(&text, PROTECTED_PATHS_FILE)?.paths
        }
        None => Vec::new(),
    };
    GlobList::new(&paths, Case::Insensitive)
}

#[cfg(test)]
mod tests;
