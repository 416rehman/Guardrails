//! `.agents/kit/usage.toml` (session and routine caps, team/01 section 9) and `.agents/harness.toml`
//! (dispatcher policy and the Claude Code facts the kit relies on). Keys these types do not name are
//! left for the dispatcher to read.

use std::collections::BTreeMap;

use anyhow::Result;
use serde::Deserialize;

use crate::repo::Repo;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Usage {
    #[serde(default)]
    pub item: ItemCaps,
    #[serde(default)]
    pub role: BTreeMap<String, RoleCaps>,
    #[serde(default)]
    pub routine: BTreeMap<String, Routine>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ItemCaps {
    pub max_attempts: Option<u32>,
    pub max_review_rounds: Option<u32>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RoleCaps {
    pub max_turns: Option<u32>,
    pub wall_clock_minutes: Option<u32>,
    pub usage_cap: Option<f64>,
    /// `low` for `XS` and `S` items (owner instruction 8); absent means the roster's effort.
    pub effort: Option<String>,
    #[serde(default)]
    pub size: BTreeMap<String, RoleCaps>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Routine {
    pub cadence: Option<String>,
    pub cap_role: Option<String>,
    pub usage_cap: Option<f64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Harness {
    #[serde(default)]
    pub github: GitHub,
    #[serde(default)]
    pub dispatch: Dispatch,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub skills: HarnessSkills,
}

/// The one repository that holds the work items (owner instruction 5), which every `gh` call and
/// the rendered `GH_REPO` name, and the branch pattern of an item's attempts.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct GitHub {
    /// `owner/name`.
    pub repository: Option<String>,
    /// The item branch, such as `agent/{issue}/a{attempt}`.
    pub branch: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Dispatch {
    pub max_writers: Option<u32>,
    pub max_evaluators: Option<u32>,
    pub stall_seconds: Option<u64>,
    pub claude_pin: Option<String>,
}

/// A subscription usage limit pauses work and never fails it (D-47); these strings detect one.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Limits {
    #[serde(default)]
    pub usage_limit_strings: Vec<String>,
    pub on_limit: Option<String>,
    pub resume: Option<String>,
}

/// Skills that exist outside `.agents/skills/` and the marketplace: those built into the pinned
/// Claude Code, and the owner's user-scope skills on interactive machines.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct HarnessSkills {
    #[serde(default)]
    pub builtin: Vec<String>,
    #[serde(default)]
    pub user: Vec<String>,
    /// The owner's claude.ai skills, named `anthropic-skills:<name>` in Claude Code.
    #[serde(default)]
    pub account: Vec<String>,
    /// Plugins the owner's user settings enable, whose skills are `<plugin>:<skill>`.
    #[serde(default)]
    pub user_plugins: Vec<String>,
}

impl Usage {
    pub fn load(repo: &Repo) -> Result<Usage> {
        let (label, path) = super::agents_file(repo, "kit/usage.toml");
        super::read_toml(&path, &label)
    }
}

impl Harness {
    pub fn load(repo: &Repo) -> Result<Harness> {
        let (label, path) = super::agents_file(repo, "harness.toml");
        super::read_toml(&path, &label)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_and_harness_tolerate_extra_keys() {
        let usage: Usage = crate::config::parse_toml(
            "[item]\nmax_attempts = 2\nescalate_above = 1.5\n[role.worker]\nmax_turns = 80\n[role.worker.size.M]\nmax_turns = 150\n[routine.garden-docs]\ncadence = \"weekly\"\ncap_role = \"gardener\"\n",
            "usage.toml",
        )
        .unwrap();
        assert_eq!(usage.role["worker"].size["M"].max_turns, Some(150));
        assert_eq!(
            usage.routine["garden-docs"].cadence.as_deref(),
            Some("weekly")
        );
        let harness: Harness = crate::config::parse_toml(
            "[github]\nrepository = \"owner/name\"\nbranch = \"agent/{issue}\"\n[dispatch]\nmax_writers = 3\n[limits]\nusage_limit_strings = [\"You've hit your session limit\"]\ncounts_as_attempt = false\n",
            "harness.toml",
        )
        .unwrap();
        assert_eq!(harness.dispatch.max_writers, Some(3));
        assert_eq!(harness.github.repository.as_deref(), Some("owner/name"));
        assert_eq!(harness.github.branch.as_deref(), Some("agent/{issue}"));
        assert!(harness.skills.builtin.is_empty());
    }
}
