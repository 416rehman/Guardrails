//! Who a session is and what it holds: the roster agent named by `GRDR_AGENT`, or by `agent_type`
//! for a session started with `--agent` and for a roster subagent; its role on GitHub (team/01
//! section 4, owner instruction 6); and the work item snapshot the launcher wrote. Bad identity
//! values are errors, so the guards fail closed.

use anyhow::{Result, bail};

use super::context::Context;
use crate::config::roster::{Agent, Group, Roster};
use crate::config::session::{ItemSnapshot, Scope, Session};
use crate::gates::protected::protected_lease;
use crate::git::Base;
use crate::kit::CHIEF_ARCHITECT;

#[derive(Debug, Clone)]
pub enum Who {
    /// A person's session: no `GRDR_AGENT` and no roster `agent_type`.
    Person,
    Agent {
        name: String,
        agent: Box<Agent>,
    },
    /// `GRDR_AGENT` names no roster agent.
    Unknown(String),
}

/// What a session may do through `gh` and the shell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Person,
    /// Files, labels, answers and closes issues, and runs only its own command list on the shell.
    Architect,
    /// Leads, the product lead and the programme manager: create and edit issues and labels.
    Planner,
    /// Comment, push its item branch, open its pull request, file `status:proposed` issues.
    Implementer,
    /// Like an implementer, on any `agent/*` branch: gardeners and the operations agents.
    Gardener,
    /// Comment, post check runs, file `status:proposed` issues.
    Evaluator,
    /// Comment and file `status:proposed` issues: council seats.
    Commenter,
}

#[derive(Debug, Clone)]
pub enum Item {
    None,
    /// `GRDR_WORK_ITEM` is set but `kit launch` wrote no snapshot: only protected-path and
    /// command rules apply.
    Missing(u64),
    Snapshot(Box<ItemSnapshot>),
}

#[derive(Debug, Clone)]
pub struct Identity {
    pub who: Who,
    pub session: Session,
    pub item: Item,
    /// Whether the session holds a protected-change lease (`gates::protected::protected_lease`).
    pub protected_lease: bool,
    /// Whether a subagent's `agent_type` is no roster agent: a workflow or plugin agent, which
    /// takes its caller's role but not its caller's model binding.
    pub workflow_subagent: bool,
}

impl Who {
    pub fn name(&self) -> Option<&str> {
        match self {
            Who::Person => None,
            Who::Agent { name, .. } | Who::Unknown(name) => Some(name),
        }
    }
}

impl Identity {
    pub fn load(context: &Context) -> Result<Identity> {
        let forged = super::lifecycle::settings_identity(context);
        if !forged.is_empty() {
            bail!(
                "{}; the session identity comes from the launcher only, so remove it there",
                forged.join("; ")
            );
        }
        let session = Session::from_lookup(context.env.lookup())?;
        let roster = Roster::load(&context.repo)?;
        let who = resolve(&session, &roster, context);
        let item = match session.work_item {
            None => Item::None,
            Some(number) => match ItemSnapshot::load(&context.repo, number)? {
                Some(snapshot) => Item::Snapshot(Box::new(snapshot)),
                None => Item::Missing(number),
            },
        };
        let protected_lease = match who.name() {
            Some(name) => protected_lease(&context.repo, &Base::Unborn, &session, name)?.is_some(),
            None => false,
        };
        let workflow_subagent = context.input.agent_id().is_some()
            && context
                .input
                .agent_type()
                .is_none_or(|name| roster.agent(name).is_none());
        Ok(Identity {
            who,
            session,
            item,
            protected_lease,
            workflow_subagent,
        })
    }

    pub fn agent(&self) -> Option<&str> {
        self.who.name()
    }

    pub fn is_agent(&self) -> bool {
        !matches!(self.who, Who::Person)
    }

    /// A protected-change lease makes its lead or the chief architect the item's implementer
    /// (owner instruction 7); guard-path still holds it to the item's write set.
    pub fn role(&self) -> Role {
        match &self.who {
            Who::Person => Role::Person,
            Who::Unknown(_) => Role::Commenter,
            Who::Agent { .. } if self.protected_lease => Role::Implementer,
            Who::Agent { name, .. } if name == CHIEF_ARCHITECT => Role::Architect,
            Who::Agent { agent, .. } => match agent.group {
                Group::Direction | Group::Lead => Role::Planner,
                Group::Implementer => Role::Implementer,
                Group::Gardener | Group::Operations => Role::Gardener,
                Group::Evaluator => Role::Evaluator,
                Group::Council => Role::Commenter,
            },
        }
    }

    /// Sessions whose work is code or documents in this repository, so the code checks apply.
    pub fn writes(&self) -> bool {
        matches!(
            self.role(),
            Role::Person | Role::Architect | Role::Implementer | Role::Gardener
        )
    }

    pub fn snapshot(&self) -> Option<&ItemSnapshot> {
        match &self.item {
            Item::Snapshot(snapshot) => Some(snapshot),
            _ => None,
        }
    }

    pub fn item_number(&self) -> Option<u64> {
        match &self.item {
            Item::None => None,
            Item::Missing(number) => Some(*number),
            Item::Snapshot(snapshot) => Some(snapshot.number),
        }
    }

    pub fn scope(&self) -> Option<Scope> {
        self.session.scope
    }
}

/// The chief architect by `GRDR_AGENT` or by `agent_type` (owner instruction 1).
pub fn is_chief_architect(context: &Context) -> bool {
    context.env.get(crate::config::session::AGENT_VARIABLE) == Some(CHIEF_ARCHITECT)
        || context.input.agent_type() == Some(CHIEF_ARCHITECT)
}

fn resolve(session: &Session, roster: &Roster, context: &Context) -> Who {
    let agent_type = context.input.agent_type();
    let subagent = context.input.agent_id().is_some();
    let roster_type = agent_type.filter(|name| roster.agent(name).is_some());
    let name = match (subagent, roster_type, session.agent.as_deref()) {
        (true, Some(name), _) => name,
        (_, _, Some(name)) => name,
        (_, Some(name), None) => name,
        (_, None, None) => return Who::Person,
    };
    match roster.agent(name) {
        Some(agent) => Who::Agent {
            name: name.to_owned(),
            agent: Box::new(agent.clone()),
        },
        None => Who::Unknown(name.to_owned()),
    }
}
