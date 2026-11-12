//! The kit data one launch reads, and the rules it applies to it: the model a session runs on
//! (team/01 section 9, design/_review/03), its turn and wall-clock caps by cap role and size class
//! (`.agents/kit/usage.toml`), whether an item is a protected change (owner instruction 7), and
//! the allow rules of the plugins' own commands (`[launch] plugin_allow`).

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use super::LaunchScope;
use super::harness::{harness_list_at, harness_strings};
use crate::config::marketplace::{InstalledPlugins, Marketplace};
use crate::config::models::Models;
use crate::config::protected::{ProtectedPaths, SeedScope};
use crate::config::roster::{Agent, Group, Roster};
use crate::config::runtime::{Harness, Usage};
use crate::config::session::{ItemSnapshot, RiskTier};
use crate::git::Base;
use crate::orchestrate::overlap::overlaps;
use crate::orchestrate::records::Lease;
use crate::orchestrate::tiers::RiskPolicy;
use crate::repo::Repo;

const OPUS: &str = "opus";
const SONNET: &str = "sonnet";
const FABLE: &str = "fable";
/// The roles that write code for an item, whose sonnet binding the launcher raises to opus on a
/// trust-core or high-tier item (team/02 section 2, design/_review/03).
const RAISABLE: &[Group] = &[Group::Implementer, Group::Gardener, Group::Operations];
/// Evaluators the dispatcher may start on opus, the model that did not write the change.
const REVIEW_RAISABLE: &[Group] = &[Group::Evaluator];
const MODEL_RANK: &[&str] = &[SONNET, OPUS, FABLE];
const SECONDS_PER_MINUTE: u64 = 60;
/// Stands for a plugin's install directory in a `[launch] plugin_allow` rule.
const PLUGIN_ROOT: &str = "{root}";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelChoice {
    pub name: String,
    pub id: String,
    /// Why the binding was raised, when it was.
    pub raised_for: Option<String>,
}

/// The kit data a launch reads.
pub struct LaunchKit {
    pub models: Models,
    pub roster: Roster,
    pub usage: Usage,
    pub harness: Harness,
    pub protected: ProtectedPaths,
    pub seed: Option<SeedScope>,
    pub risk: RiskPolicy,
    /// `--allowedTools` rules every session gets for a plugin's own commands.
    pub plugin_rules: Vec<String>,
    protected_agents: Vec<String>,
}

impl LaunchKit {
    pub fn load(repo: &Repo) -> Result<LaunchKit> {
        let harness = Harness::load(repo)?;
        let protected_agents = protected_change_agents(repo, &Base::Unborn)?;
        let templates = harness_strings(repo, "launch", "plugin_allow")?;
        let plugin_rules = if templates.is_empty() {
            Vec::new()
        } else {
            plugin_rules(
                &templates,
                &Marketplace::load(repo)?,
                &crate::kit::install::read_installed()?,
            )
        };
        Ok(LaunchKit {
            models: Models::load(repo)?,
            roster: Roster::load(repo)?,
            usage: Usage::load(repo)?,
            harness,
            protected: ProtectedPaths::load(repo)?,
            seed: SeedScope::load(repo)?,
            risk: RiskPolicy::load(repo)?,
            plugin_rules,
            protected_agents,
        })
    }

    pub fn agent(&self, name: &str) -> Result<&Agent> {
        self.roster
            .agent(name)
            .with_context(|| format!("`{name}` is not an agent in .agents/roster.toml"))
    }

    /// The model a session runs on: the roster binding, raised to opus for a worker on a
    /// high-tier or trust-core item. Fable is only for the agents models.toml names.
    pub fn choose_model(&self, name: &str, item: Option<&ItemSnapshot>) -> Result<ModelChoice> {
        let agent = self.agent(name)?;
        if agent.model == FABLE && !self.models.rules.fable_agents.iter().any(|a| a == name) {
            bail!(
                "model rule: {name} is bound to fable, which only {} may use",
                self.models.rules.fable_agents.join(", ")
            );
        }
        let raised_for = item
            .filter(|_| RAISABLE.contains(&agent.group) && agent.model != OPUS)
            .and_then(|item| {
                if item.trust_core {
                    Some(format!("#{} touches the trust core", item.number))
                } else if item.risk_tier == RiskTier::High {
                    Some(format!("#{} is high tier", item.number))
                } else {
                    None
                }
            });
        let name = if raised_for.is_some() {
            OPUS
        } else {
            agent.model.as_str()
        };
        let id = self
            .models
            .id(name)
            .with_context(|| format!(".agents/models.toml binds no `{name}`"))?;
        Ok(ModelChoice {
            name: name.to_owned(),
            id: id.to_owned(),
            raised_for,
        })
    }

    /// Whether `id` is a model this agent may run on: its binding, or opus raised from sonnet for
    /// the roles the launcher may raise (writers, and evaluators for a cross-model review).
    pub fn may_run_on(&self, name: &str, id: &str) -> bool {
        let Ok(agent) = self.agent(name) else {
            return false;
        };
        let binding = self.models.id(&agent.model);
        let raised = agent.model == SONNET
            && (RAISABLE.contains(&agent.group) || REVIEW_RAISABLE.contains(&agent.group))
            && self.models.id(OPUS) == Some(id);
        binding == Some(id) || raised
    }

    /// Whether model `a` ranks above `b` in sonnet, opus, fable order.
    pub fn ranks_above(&self, a: &str, b: &str) -> bool {
        let rank = |id: &str| {
            MODEL_RANK
                .iter()
                .position(|name| self.models.id(name) == Some(id))
        };
        matches!((rank(a), rank(b)), (Some(a), Some(b)) if a > b)
    }

    /// The effort the item's size row names (owner instruction 8), else none and the roster's.
    pub fn effort(&self, name: &str, size: Option<&str>) -> Option<String> {
        let agent = self.agent(name).ok()?;
        let role = self.usage.role.get(&agent.cap_role)?;
        size.and_then(|size| role.size.get(size))
            .and_then(|caps| caps.effort.clone())
            .or_else(|| role.effort.clone())
    }

    /// The per-session turn cap: the size class row of the agent's cap role, else the role, else
    /// the roster figure (team/01 section 9).
    pub fn turn_cap(&self, name: &str, size: Option<&str>) -> Result<u32> {
        let agent = self.agent(name)?;
        let role = self.usage.role.get(&agent.cap_role);
        let by_size = size
            .and_then(|size| role.and_then(|role| role.size.get(size)))
            .and_then(|caps| caps.max_turns);
        Ok(by_size
            .or_else(|| role.and_then(|role| role.max_turns))
            .unwrap_or(agent.max_turns))
    }

    /// The turn cap of one session in `scope`: the seed scope's own for the seed session, else
    /// [`LaunchKit::turn_cap`].
    pub fn session_turns(&self, name: &str, size: Option<&str>, scope: LaunchScope) -> Result<u32> {
        match (scope, &self.seed) {
            (LaunchScope::Seed, Some(seed)) => {
                Ok(seed.max_turns.unwrap_or(self.agent(name)?.max_turns))
            }
            _ => self.turn_cap(name, size),
        }
    }

    /// The scope a session on `lease` starts in: the seed scope for the seed session's lease, its
    /// agent on its branch, so a fix session works where the seed session did.
    pub fn scope_of(&self, lease: &Lease) -> LaunchScope {
        match &self.seed {
            Some(seed) if seed.is_session(&lease.agent, &lease.branch) => LaunchScope::Seed,
            _ => LaunchScope::Ordinary,
        }
    }

    /// The wall clock one session may take, from the same rows' `wall_clock_minutes`.
    pub fn wall_clock(&self, name: &str, size: Option<&str>) -> Option<Duration> {
        let agent = self.agent(name).ok()?;
        let role = self.usage.role.get(&agent.cap_role)?;
        let minutes = size
            .and_then(|size| role.size.get(size))
            .and_then(|caps| caps.wall_clock_minutes)
            .or(role.wall_clock_minutes)?;
        Some(Duration::from_secs(u64::from(minutes) * SECONDS_PER_MINUTE))
    }

    /// The roles `agent` plays in the seed session (team/06 section 14), empty otherwise.
    pub fn acting_as(&self, agent: &str) -> &[String] {
        self.seed.as_ref().map_or(&[], |seed| seed.roles_of(agent))
    }

    /// Whether `name` implements protected changes (owner instruction 7).
    pub fn is_protected_agent(&self, name: &str) -> bool {
        self.protected_agents.iter().any(|agent| agent == name)
    }

    /// Owner instruction 7: a protected-change lease, whose own write set may hold protected paths.
    pub fn is_protected_change(&self, name: &str, write_set: &[String]) -> Result<bool> {
        if !self.is_protected_agent(name) {
            return Ok(false);
        }
        overlaps(write_set, &self.protected.paths)
    }
}

/// The rules of `templates`, plugin entry name to rule, for each entry Claude Code records as
/// installed from `marketplace`: `{root}` becomes its install directory with forward slashes, the
/// form a plugin prints its own commands in. A plugin not installed yet gets no rule, and its
/// hooks do not run either.
pub fn plugin_rules(
    templates: &BTreeMap<String, String>,
    marketplace: &Marketplace,
    installed: &InstalledPlugins,
) -> Vec<String> {
    templates
        .iter()
        .filter_map(|(entry, rule)| {
            let root = installed
                .plugins
                .get(&marketplace.id(entry))?
                .iter()
                .find_map(|record| record.install_path.as_deref())?;
            Some(rule.replace(PLUGIN_ROOT, &root.replace('\\', "/")))
        })
        .collect()
}

/// The agents that implement protected changes (owner instruction 7): `[dispatch]
/// protected_change_agents` in the harness file at `base`, which is required.
pub fn protected_change_agents(repo: &Repo, base: &Base) -> Result<Vec<String>> {
    let (agents, source) = harness_list_at(repo, base, "dispatch", "protected_change_agents")?;
    agents.with_context(|| format!("{source} [dispatch] has no protected_change_agents"))
}

pub(super) fn model_name(models: &Models, id: &str) -> Option<String> {
    models
        .models
        .iter()
        .find(|(_, known)| known.as_str() == id)
        .map(|(name, _)| name.clone())
}
