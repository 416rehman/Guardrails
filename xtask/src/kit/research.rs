//! The research grant of owner instruction 14. A role whose roster skills include the skill
//! `.agents/kit/vendors.toml` names gets `WebFetch` and `WebSearch`, a fetch rule for every
//! domain the file lists, and those domains on its egress; every other role keeps `WebSearch`
//! out of its tools.

use anyhow::{Result, bail};

use crate::config::Kit;
use crate::config::roster::Agent;
use crate::config::vendors::Vendors;
use crate::gates::skills;
use crate::repo::Repo;

pub const FETCH_TOOL: &str = "WebFetch";
pub const SEARCH_TOOL: &str = "WebSearch";
/// The tools the grant adds to a role's definition.
pub const GRANTED_TOOLS: [&str; 2] = [FETCH_TOOL, SEARCH_TOOL];

/// The tool lists a rendered definition carries once the grant is applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolLists {
    pub tools: Vec<String>,
    pub disallowed: Vec<String>,
}

/// The grant `vendors.toml` defines; absent when the file is.
#[derive(Debug, Clone, Copy)]
pub struct Grant<'a> {
    vendors: &'a Vendors,
}

impl<'a> Grant<'a> {
    pub fn of(kit: &'a Kit) -> Option<Grant<'a>> {
        kit.vendors.as_ref().map(|vendors| Grant { vendors })
    }

    pub fn skill(&self) -> &'a str {
        &self.vendors.research.skill
    }

    pub fn covers(&self, agent: &Agent) -> bool {
        agent.loads(self.skill())
    }

    /// Whether any roster role of `group` gets the grant.
    pub fn covers_group(&self, kit: &Kit, group: &str) -> bool {
        kit.roster
            .agents
            .values()
            .any(|agent| agent.group.as_str() == group && self.covers(agent))
    }

    pub fn domains(&self) -> Vec<&'a str> {
        self.vendors.domains()
    }

    pub fn egress_lists(&self) -> &'a [String] {
        &self.vendors.research.egress_lists
    }

    /// One fetch rule per domain, then the search rule.
    pub fn allow_rules(&self) -> Vec<String> {
        self.domains()
            .into_iter()
            .map(|domain| format!("{FETCH_TOOL}(domain:{domain})"))
            .chain(std::iter::once(SEARCH_TOOL.to_owned()))
            .collect()
    }
}

/// The tools and disallowed tools `name` renders with: the grant's tools added for a role that
/// loads the skill; a role that does not may not list `WebSearch`.
pub fn tool_lists(kit: &Kit, name: &str, agent: &Agent) -> Result<ToolLists> {
    let mut lists = ToolLists {
        tools: agent.tools.clone(),
        disallowed: agent.disallowed_tools.clone(),
    };
    let grant = Grant::of(kit);
    match grant.filter(|grant| grant.covers(agent)) {
        Some(grant) => {
            for tool in GRANTED_TOOLS {
                if lists.disallowed.iter().any(|listed| listed == tool) {
                    bail!(
                        "agent `{name}` loads `{}`, which grants {tool}, but its roster entry disallows {tool}; remove it from disallowed_tools",
                        grant.skill()
                    );
                }
                if !lists.tools.iter().any(|listed| listed == tool) {
                    lists.tools.push(tool.to_owned());
                }
            }
        }
        None if lists.tools.iter().any(|tool| tool == SEARCH_TOOL) => {
            let skill = grant.map_or("the research skill of .agents/kit/vendors.toml", |grant| {
                grant.skill()
            });
            bail!(
                "agent `{name}` lists {SEARCH_TOOL} but does not load {skill}; only the roles that load it may search (owner instruction 14)"
            );
        }
        None => {}
    }
    Ok(lists)
}

/// A rule in `rules` that names a granted tool bare, which would deny or prompt for every call
/// the grant's rules allow.
pub fn shadowing_rule(rules: &[String]) -> Option<&str> {
    rules
        .iter()
        .map(String::as_str)
        .find(|rule| GRANTED_TOOLS.contains(rule))
}

/// What `kit check` reports about `vendors.toml` beyond its format: every brief exists, the skill
/// is a project skill, and some role loads it.
pub fn problems(repo: &Repo, kit: &Kit) -> Result<Vec<String>> {
    let Some(grant) = Grant::of(kit) else {
        return Ok(Vec::new());
    };
    let mut problems = Vec::new();
    for (id, vendor) in &grant.vendors.vendor {
        if !repo.path(&vendor.brief).is_file() {
            problems.push(format!(
                ".agents/kit/vendors.toml [vendor.{id}] names brief {}, which does not exist",
                vendor.brief
            ));
        }
    }
    let skill = grant.skill();
    let known = skills::skill_files(repo)?
        .iter()
        .any(|file| file.name() == skill);
    if !known {
        problems.push(format!(
            ".agents/kit/vendors.toml [research] skill `{skill}` has no .agents/skills/{skill}/SKILL.md"
        ));
    }
    if !kit.roster.agents.values().any(|agent| grant.covers(agent)) {
        problems.push(format!(
            ".agents/kit/vendors.toml: no roster role loads `{skill}`, so no role gets its fetch rules"
        ));
    }
    Ok(problems)
}
