//! `PreToolUse` on Bash and PowerShell (team/03 section 4.1). The token scanner reduces the
//! command to invocations; each is judged against the deny list, the commit form (owner
//! instruction 27) and the role's `gh` calls (owner instruction 6). An invocation the
//! scanner cannot read in a denied class is denied. K12 swaps the scanner for the product's shell
//! canonicaliser.

mod gh;
mod git;
mod rules;
mod writes;

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::Result;

use super::context::Context;
use super::github::GithubSettings;
use super::guard_path::KitState;
use super::identity::{Identity, Role};
use super::model;
use super::outcome::Outcome;
use super::shell::{self, Dialect, Invocation, Program};
use crate::config::protected::{ProtectedPaths, SeedScope};
use crate::config::session::Scope;
use crate::gates::protected::allowance;
use crate::git::Base;
use crate::globs::GlobList;
use crate::repo::Repo;

/// The chief architect's whole shell (team/01 section 4, team/02 section 3, owner instruction 7),
/// when no seed scope names its own list: file, label, answer and close issues, read pull
/// requests and history, run verify, and ready and hand off through the kit.
const ARCHITECT_COMMANDS: &[&str] = &[
    "gh issue create",
    "gh issue edit",
    "gh issue view",
    "gh issue list",
    "gh issue comment",
    "gh issue close",
    "gh pr view",
    "gh pr diff",
    "gh pr list",
    "gh pr checks",
    "git status",
    "git log",
    "git diff",
    "git show",
    "cargo xtask verify",
    "cargo xtask kit ready",
    "cargo xtask kit handoff",
];
const CHANGE_DIRECTORY: &[&str] = &["cd", "pushd", "set-location", "sl", "chdir"];

/// What every rule may read about the session and the repository.
pub struct Rules<'a> {
    pub context: &'a Context,
    pub identity: &'a Identity,
    pub role: Role,
    pub protected: GlobList,
    /// The protected globs as written, for the directory checks of deletions.
    pub protected_paths: Vec<String>,
    pub widened: Option<GlobList>,
    pub kit_state: KitState,
    pub github: GithubSettings,
    architect_commands: Vec<String>,
    branches: RefCell<BTreeMap<PathBuf, Option<String>>>,
}

impl<'a> Rules<'a> {
    pub fn new(context: &'a Context, identity: &'a Identity) -> Result<Rules<'a>> {
        let protected_file = ProtectedPaths::load(&context.repo)?;
        let protected = protected_file.globs()?;
        let widened = match identity.agent() {
            Some(agent) => allowance(&context.repo, &Base::Unborn, &identity.session, agent)?,
            None => None,
        };
        Ok(Rules {
            context,
            identity,
            role: identity.role(),
            protected,
            protected_paths: protected_file.paths,
            widened,
            kit_state: KitState::compile()?,
            github: GithubSettings::load(&context.repo)?,
            architect_commands: architect_commands(&context.repo, identity)?,
            branches: RefCell::default(),
        })
    }

    /// Every reason to deny `source`; empty when it may run.
    pub fn judge(&self, source: &str, dialect: Dialect) -> Result<Vec<String>> {
        let resolve = |name: &str| self.context.env.resolvable(name);
        let reading = shell::Reading {
            resolve: &resolve,
            nested_shells: self.context.limits.shell.nested_shells,
            substitutions: self.context.limits.shell.substitutions,
        };
        let invocations = shell::parse(source, dialect, reading);
        let mut cwd = Some(self.context.cwd());
        let mut reasons: Vec<String> = Vec::new();
        for invocation in &invocations {
            for reason in self.check(invocation, cwd.as_deref())? {
                if !reasons.contains(&reason) {
                    reasons.push(reason);
                }
            }
            if let Some(name) = invocation.name()
                && CHANGE_DIRECTORY.contains(&name)
            {
                cwd = changed_directory(cwd.as_deref(), invocation);
            }
        }
        Ok(reasons)
    }

    fn check(&self, invocation: &Invocation, cwd: Option<&Path>) -> Result<Vec<String>> {
        if let Program::Opaque(raw) = &invocation.program {
            return Ok(vec![format!(
                "`{raw}` hides the command it runs; write the command out literally"
            )]);
        }
        let mut reasons = writes::writes(self, invocation, cwd);
        reasons.extend(rules::environment(self, invocation));
        if self.role == Role::Architect
            && let Some(refused) = self.architect(invocation)
        {
            reasons.push(refused);
            return Ok(reasons);
        }
        match invocation.name() {
            Some("git") => reasons.extend(git::check(self, invocation, cwd)?),
            Some("gh") => reasons.extend(gh::check(self, invocation, cwd)),
            Some(_) => reasons.extend(rules::programs(self, invocation)),
            None => {}
        }
        Ok(reasons)
    }

    fn architect(&self, invocation: &Invocation) -> Option<String> {
        let name = invocation.name()?;
        let allowed = self.architect_commands.iter().any(|command| {
            let mut words = command.split_whitespace();
            let program = words.next().unwrap_or_default();
            let rest: Vec<&str> = words.collect();
            let direct = name == program
                && invocation.leading(rest.len()).as_deref() == Some(rest.as_slice());
            let kit_binary = program == "cargo"
                && name == "xtask"
                && rest.first() == Some(&"xtask")
                && invocation.leading(rest.len().saturating_sub(1)).as_deref() == rest.get(1..);
            direct || kit_binary
        });
        (!allowed).then(|| {
            format!(
                "chief-architect runs only {} on the shell",
                self.architect_commands.join(", ")
            )
        })
    }

    /// The branch checked out in `dir`'s repository, looked up once per directory.
    pub fn branch(&self, dir: &Path) -> Option<String> {
        if let Some(known) = self.branches.borrow().get(dir) {
            return known.clone();
        }
        let branch = crate::git::current_branch(&Repo::at(dir)).ok().flatten();
        self.branches
            .borrow_mut()
            .insert(dir.to_path_buf(), branch.clone());
        branch
    }

    pub fn is_agent(&self) -> bool {
        self.identity.is_agent()
    }

    /// The session's agent, or `this agent` when it has none.
    pub fn agent_name(&self) -> &str {
        self.identity.agent().unwrap_or("this agent")
    }

    /// The branch this session pushes and opens its pull request from: its item's branch from
    /// harness.toml `[github] branch` (any attempt before the snapshot exists), and for a gardener
    /// or an operations agent without an item `<namespace><agent>/<topic>`, which no lease uses.
    pub fn is_own_branch(&self, branch: &str) -> bool {
        if self.role == Role::Person {
            return true;
        }
        if !matches!(self.role, Role::Implementer | Role::Gardener) {
            return false;
        }
        match (self.identity.snapshot(), self.identity.item_number()) {
            (Some(snapshot), _) => {
                branch == self.github.item_branch(snapshot.number, snapshot.attempt)
            }
            (None, Some(number)) => self.github.is_item_branch(branch, number),
            (None, None) if self.role == Role::Gardener => {
                self.identity.agent().is_some_and(|agent| {
                    branch
                        .strip_prefix(&format!("{}{agent}/", self.github.namespace()))
                        .is_some_and(|topic| !topic.is_empty())
                })
            }
            (None, None) => false,
        }
    }

    /// What `is_own_branch` accepts, for messages.
    pub fn own_branch_pattern(&self) -> String {
        match (self.identity.snapshot(), self.identity.item_number()) {
            (Some(snapshot), _) => self.github.item_branch(snapshot.number, snapshot.attempt),
            (None, Some(number)) => self.github.item_branch_pattern(number),
            (None, None) if self.role == Role::Gardener => format!(
                "{}{}/<topic>",
                self.github.namespace(),
                self.identity.agent().unwrap_or("<agent>")
            ),
            (None, None) => "no branch (this session has no leased item)".to_owned(),
        }
    }
}

pub fn run(context: &Context) -> Result<Outcome> {
    let identity = Identity::load(context)?;
    if let Some(message) = model::violation(context, &identity)? {
        return Ok(Outcome::Block(message));
    }
    let Some(source) = context.input.text_at("/tool_input/command") else {
        return Ok(Outcome::Allow);
    };
    let dialect = match context.input.tool_name() {
        Some("PowerShell") => Dialect::PowerShell,
        _ => Dialect::Bash,
    };
    let rules = Rules::new(context, &identity)?;
    Ok(Outcome::block_if(rules.judge(source, dialect)?))
}

fn architect_commands(repo: &Repo, identity: &Identity) -> Result<Vec<String>> {
    if identity.scope() == Some(Scope::Seed)
        && let Some(seed) = SeedScope::load(repo)?
        && Some(seed.agent.as_str()) == identity.agent()
        && !seed.commands.is_empty()
    {
        return Ok(seed.commands);
    }
    Ok(ARCHITECT_COMMANDS
        .iter()
        .map(|command| (*command).to_owned())
        .collect())
}

/// `relative` inside `base`, or as written when it is absolute or there is no base.
fn join(base: Option<&Path>, relative: &str) -> PathBuf {
    let path = Path::new(relative);
    match base {
        Some(base) if !path.is_absolute() => base.join(path),
        _ => path.to_path_buf(),
    }
}

/// The directory after `cd <dir>`; unknown when the argument is an expansion.
fn changed_directory(cwd: Option<&Path>, invocation: &Invocation) -> Option<PathBuf> {
    let target = invocation.positionals().next()?;
    if target.opaque {
        return None;
    }
    let path = Path::new(&target.value);
    if path.is_absolute() || target.value.starts_with('/') {
        return Some(path.to_path_buf());
    }
    cwd.map(|cwd| cwd.join(path))
}
