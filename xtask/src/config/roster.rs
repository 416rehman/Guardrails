//! The agent roster (team/02 section 1.2): `.agents/roster.toml`. Unknown keys are errors, because
//! Claude Code silently ignores unknown front matter.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::globs::{Case, GlobList};
use crate::repo::Repo;

const ROSTER_FILE: &str = "roster.toml";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Group {
    Direction,
    Lead,
    Implementer,
    Evaluator,
    Gardener,
    Council,
    Operations,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Effort {
    Low,
    Medium,
    High,
    Xhigh,
    Max,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum Net {
    A,
    B,
    #[serde(rename = "forge-read")]
    ForgeRead,
    #[serde(rename = "intel")]
    Intel,
    #[serde(rename = "none")]
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Trigger {
    Dispatch,
    Event,
    Schedule,
    Manual,
}

/// `deny_write` has one legal value, which expands to `.agents/kit/protected-paths.toml`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum DenyWrite {
    #[serde(rename = "@protected")]
    Protected,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Agent {
    pub group: Group,
    pub description: String,
    pub model: String,
    pub effort: Effort,
    pub cap_role: String,
    pub max_turns: u32,
    pub tools: Vec<String>,
    #[serde(default)]
    pub disallowed_tools: Vec<String>,
    #[serde(default)]
    pub write: Vec<String>,
    pub deny_write: DenyWrite,
    pub net: Net,
    #[serde(default)]
    pub skills: Vec<String>,
    pub trigger: Trigger,
    pub usage_cap: Option<f64>,
    pub body: String,
}

#[derive(Debug, Clone, Default)]
pub struct Roster {
    /// `[defaults]`: values every role shares (hand-off form, issue snapshot and branch
    /// patterns). They render into no front matter, so their keys are open.
    pub defaults: toml::Table,
    pub agents: BTreeMap<String, Agent>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RosterFile {
    defaults: Option<toml::Table>,
    #[serde(default)]
    agent: BTreeMap<String, Agent>,
}

impl Group {
    pub const ALL: [Group; 7] = [
        Group::Direction,
        Group::Lead,
        Group::Implementer,
        Group::Evaluator,
        Group::Gardener,
        Group::Council,
        Group::Operations,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Group::Direction => "direction",
            Group::Lead => "lead",
            Group::Implementer => "implementer",
            Group::Evaluator => "evaluator",
            Group::Gardener => "gardener",
            Group::Council => "council",
            Group::Operations => "operations",
        }
    }
}

impl Net {
    /// The `[list.<name>]` of `.agents/kit/egress.toml` this value names.
    pub fn list_name(self) -> &'static str {
        match self {
            Net::A => "A",
            Net::B => "B",
            Net::ForgeRead => "forge-read",
            Net::Intel => "intel",
            Net::None => "none",
        }
    }
}

impl Effort {
    pub fn as_str(self) -> &'static str {
        match self {
            Effort::Low => "low",
            Effort::Medium => "medium",
            Effort::High => "high",
            Effort::Xhigh => "xhigh",
            Effort::Max => "max",
        }
    }
}

impl Agent {
    /// The globs this role may write, before protected paths are taken away.
    pub fn write_globs(&self) -> Result<GlobList> {
        GlobList::new(&self.write, Case::Sensitive)
    }

    pub fn is_read_only(&self) -> bool {
        ["Edit", "Write"]
            .iter()
            .all(|tool| self.disallowed_tools.iter().any(|t| t == tool))
    }

    pub fn loads(&self, skill: &str) -> bool {
        self.skills.iter().any(|loaded| loaded == skill)
    }
}

impl Roster {
    pub fn load(repo: &Repo) -> Result<Roster> {
        let (label, path) = super::agents_file(repo, ROSTER_FILE);
        let file: RosterFile = super::read_toml(&path, &label)?;
        Roster::from_file(file, &label)
    }

    pub fn agent(&self, name: &str) -> Option<&Agent> {
        self.agents.get(name)
    }

    /// A string from `[defaults]`, such as `branch`.
    pub fn default_str(&self, key: &str) -> Option<&str> {
        self.defaults.get(key).and_then(toml::Value::as_str)
    }

    fn from_file(file: RosterFile, label: &str) -> Result<Roster> {
        for name in file.agent.keys() {
            validate_name(name).with_context(|| label.to_owned())?;
        }
        Ok(Roster {
            defaults: file.defaults.unwrap_or_default(),
            agents: file.agent,
        })
    }
}

/// Agent names become file names and front matter: lowercase letters, digits and dashes.
pub fn validate_name(name: &str) -> Result<()> {
    let valid = !name.is_empty()
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !valid {
        bail!("agent name `{name}` must be lowercase letters, digits and dashes");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const AGENT: &str = r#"
[agent.impl-rust]
group = "implementer"
description = "Implements one item."
model = "sonnet"
effort = "high"
cap_role = "worker"
max_turns = 80
tools = ["Read", "Edit"]
write = ["crates/**"]
deny_write = "@protected"
net = "A"
skills = ["grdr-verify"]
trigger = "dispatch"
body = "templates/agents/impl-rust.md"
"#;

    #[test]
    fn parses_an_agent() {
        let file: RosterFile = crate::config::parse_toml(AGENT, "roster").unwrap();
        let agent = &file.agent["impl-rust"];
        assert_eq!(agent.group, Group::Implementer);
        assert_eq!(agent.effort.as_str(), "high");
        assert!(
            agent
                .write_globs()
                .unwrap()
                .is_match("crates/grdr-core/src/lib.rs")
        );
        assert!(!agent.is_read_only());
    }

    #[test]
    fn rejects_unknown_fields_and_bad_values() {
        let unknown = format!("{AGENT}memory = \"project\"\n");
        assert!(crate::config::parse_toml::<RosterFile>(&unknown, "roster").is_err());
        let bad_effort = AGENT.replace("effort = \"high\"", "effort = \"extreme\"");
        assert!(crate::config::parse_toml::<RosterFile>(&bad_effort, "roster").is_err());
        let bad_deny = AGENT.replace("\"@protected\"", "\"nothing\"");
        assert!(crate::config::parse_toml::<RosterFile>(&bad_deny, "roster").is_err());
    }

    #[test]
    fn agent_names_are_validated_on_load() {
        let bad = AGENT.replace("[agent.impl-rust]", "[agent.Impl]");
        let file = crate::config::parse_toml(&bad, "roster").unwrap();
        assert!(Roster::from_file(file, "roster").is_err());
    }

    #[test]
    fn names_are_kebab_case() {
        assert!(validate_name("eval-a11y").is_ok());
        assert!(validate_name("Eval").is_err());
        assert!(validate_name("../x").is_err());
    }
}
