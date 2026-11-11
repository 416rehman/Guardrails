//! The model rule (design/_review/03) on every prompt, guarded tool call and model switch. A
//! session may run on its roster binding; the launcher may start a sonnet-bound worker,
//! evaluator, gardener or operations agent on opus and says so in `GRDR_MODEL`, which binds only
//! the launched agent and never its subagents; a roster subagent runs on its own binding; a
//! workflow or plugin subagent and a session with no agent may use opus or sonnet; fable is only
//! for the agents `models.toml` lists; any other id is refused.

use anyhow::Result;

use super::context::Context;
use super::identity::{Identity, Who};
use super::outcome::Outcome;
use super::state::SessionState;
use super::transcript;
use crate::config::models::Models;
use crate::config::roster::Group;
use crate::config::session::LAUNCHER_MODEL_VARIABLE;

/// The roster's own notes: the dispatcher starts a worker on opus for a trust-core path or a high
/// tier, eval-diff on the model that did not write the change, and every refuting pass on opus.
const LAUNCHER_OPUS_GROUPS: &[Group] = &[
    Group::Implementer,
    Group::Evaluator,
    Group::Gardener,
    Group::Operations,
];
/// Field prefixes that name the model a switch leaves, never its target.
const SWITCH_SOURCES: &[&str] = &["from", "previous", "current", "old"];
/// Fields a `PreModelSwitch` payload may name the target model in.
const SWITCH_FIELDS: &[&str] = &[
    "to_model",
    "requested_model",
    "new_model",
    "target_model",
    "model",
];
const OPUS: &str = "opus";
const SONNET: &str = "sonnet";
const FABLE: &str = "fable";
const DATE_SUFFIX_DIGITS: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allowed,
    /// No model is known yet, as before the first assistant message.
    Unknown,
    Violation(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub allowed: Vec<String>,
    holder: String,
}

/// `UserPromptSubmit`: a violating session's prompts are blocked.
pub fn gate(context: &Context) -> Result<Outcome> {
    let identity = Identity::load(context)?;
    Ok(match check(context, &identity)? {
        Verdict::Violation(message) => Outcome::Block(message),
        _ => Outcome::Allow,
    })
}

/// `PreModelSwitch`: a switch to a model the session may not use is refused.
pub fn switch(context: &Context) -> Result<Outcome> {
    let identity = Identity::load(context)?;
    let models = Models::load(&context.repo)?;
    let rule = match rule_for(&models, &identity, context.env.get(LAUNCHER_MODEL_VARIABLE)) {
        Ok(rule) => rule,
        Err(message) => return Ok(Outcome::Block(message)),
    };
    let Some(target) = switch_target(context, &models) else {
        return Ok(Outcome::Block(
            "model switch refused: the payload names no target model the kit can read; the switch is refused until it does".to_owned(),
        ));
    };
    Ok(match judge(&models, &rule, &target) {
        Verdict::Violation(message) => Outcome::Block(format!("model switch refused: {message}")),
        _ => Outcome::Allow,
    })
}

/// The target of a model switch: a known field, else any top-level string that names a model of
/// models.toml.
fn switch_target(context: &Context, models: &Models) -> Option<String> {
    SWITCH_FIELDS
        .iter()
        .find_map(|field| context.input.str(field))
        .map(str::to_owned)
        .or_else(|| {
            context
                .input
                .at("")
                .and_then(serde_json::Value::as_object)?
                .iter()
                .filter(|(key, _)| !SWITCH_SOURCES.iter().any(|source| key.starts_with(source)))
                .filter_map(|(_, value)| value.as_str())
                .find(|value| models.is_id(&normalise(models, value)))
                .map(str::to_owned)
        })
}

/// Whether the session's current model obeys the rule.
pub fn check(context: &Context, identity: &Identity) -> Result<Verdict> {
    let models = Models::load(&context.repo)?;
    let rule = match rule_for(&models, identity, context.env.get(LAUNCHER_MODEL_VARIABLE)) {
        Ok(rule) => rule,
        Err(message) => return Ok(Verdict::Violation(message)),
    };
    let Some(model) = current_model(context)? else {
        return Ok(Verdict::Unknown);
    };
    Ok(judge(&models, &rule, &model))
}

/// The violation line a guard prints, if the session violates the rule.
pub fn violation(context: &Context, identity: &Identity) -> Result<Option<String>> {
    Ok(match check(context, identity)? {
        Verdict::Violation(message) => Some(message),
        _ => None,
    })
}

pub fn judge(models: &Models, rule: &Rule, raw: &str) -> Verdict {
    let id = normalise(models, raw);
    let first = rule.allowed.first().map(String::as_str).unwrap_or(SONNET);
    if !models.is_id(&id) {
        return Verdict::Violation(format!(
            "model rule: this session runs on `{raw}`, which .agents/models.toml does not bind; fix: /model {first}, or relaunch with cargo xtask kit launch"
        ));
    }
    if !rule.allowed.contains(&id) {
        return Verdict::Violation(format!(
            "model rule: {} may run on {}; this session runs on {id}; fix: /model {first}, or relaunch with cargo xtask kit launch",
            rule.holder,
            rule.allowed.join(" or ")
        ));
    }
    Verdict::Allowed
}

/// `fable[1m]`, `claude-fable-5-2[1m]` and `claude-fable-5-2-20261101` are all `claude-fable-5-2`.
pub fn normalise(models: &Models, raw: &str) -> String {
    let trimmed = raw
        .split('[')
        .next()
        .unwrap_or(raw)
        .trim()
        .to_ascii_lowercase();
    if let Some(id) = models.resolve(&trimmed) {
        return id.to_owned();
    }
    if let Some((stem, suffix)) = trimmed.rsplit_once('-')
        && suffix.len() == DATE_SUFFIX_DIGITS
        && suffix.chars().all(|c| c.is_ascii_digit())
        && models.is_id(stem)
    {
        return stem.to_owned();
    }
    trimmed
}

/// The models this session may run on, or the violation that its identity already is.
pub fn rule_for(
    models: &Models,
    identity: &Identity,
    launcher: Option<&str>,
) -> Result<Rule, String> {
    let id = |name: &str| {
        models
            .id(name)
            .map(str::to_owned)
            .ok_or_else(|| format!("model rule: .agents/models.toml binds no `{name}`"))
    };
    let (name, agent) = match &identity.who {
        Who::Person => {
            return Ok(Rule {
                allowed: vec![id(SONNET)?, id(OPUS)?],
                holder: "a session with no agent".to_owned(),
            });
        }
        Who::Unknown(name) => {
            return Err(format!(
                "GRDR_AGENT={name} is not a roster agent; fix: start the session with cargo xtask kit launch"
            ));
        }
        Who::Agent { name, agent } => (name, agent),
    };
    if identity.workflow_subagent {
        return Ok(Rule {
            allowed: vec![id(SONNET)?, id(OPUS)?],
            holder: format!("a workflow or plugin agent of {name}"),
        });
    }
    let launcher = launcher.filter(|_| identity.session.agent.as_deref() == Some(name.as_str()));
    let binding = id(&agent.model)?;
    if agent.model == FABLE && !models.rules.fable_agents.contains(name) {
        return Err(format!(
            "model rule: {name} is bound to fable, which only {} may use; fix the roster",
            models.rules.fable_agents.join(", ")
        ));
    }
    let mut allowed = vec![binding.clone()];
    if let Some(launcher) = launcher {
        let chosen = normalise(models, launcher);
        let raised = chosen == id(OPUS)?
            && agent.model == SONNET
            && LAUNCHER_OPUS_GROUPS.contains(&agent.group);
        if raised {
            allowed.push(chosen);
        } else if chosen != binding {
            return Err(format!(
                "model rule: {LAUNCHER_MODEL_VARIABLE}={launcher} is not a model {name} may run on; fix: relaunch with cargo xtask kit launch"
            ));
        }
    }
    Ok(Rule {
        allowed,
        holder: name.clone(),
    })
}

/// SessionStart's `model`, else the last assistant message of the (sub)agent's transcript, else
/// the model the session started on.
pub fn current_model(context: &Context) -> Result<Option<String>> {
    if let Some(model) = context.input.str("model") {
        return Ok(Some(model.to_owned()));
    }
    let transcript = context.input.path("transcript_path", &context.env);
    if let Some(agent_id) = context.input.agent_id() {
        let own = transcript.and_then(|main| transcript::subagent_transcript(&main, agent_id));
        return match own {
            Some(path) => transcript::last_model(&path, &context.limits.transcript),
            None => Ok(None),
        };
    }
    let state = match context.input.session_id() {
        Some(session) => SessionState::load(&context.repo, session)?,
        None => None,
    };
    let transcript = transcript.filter(|path| path.is_file());
    if let (Some(path), Some(state)) = (&transcript, &state)
        && let Some(from) = state.resumed_at_byte
    {
        return Ok(match transcript::last_model_since(path, from)? {
            Some(model) => Some(model),
            None => state.model.clone(),
        });
    }
    if let Some(path) = &transcript
        && let Some(model) = transcript::last_model(path, &context.limits.transcript)?
    {
        return Ok(Some(model));
    }
    Ok(state.and_then(|state| state.model))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::roster::Roster;
    use crate::config::session::Session;
    use crate::hook::identity::Item;

    const MODELS: &str = "[models]\nfable = \"claude-fable-5-2\"\nopus = \"claude-opus-5-5\"\nsonnet = \"claude-sonnet-5-5\"\n[rules]\nfable_agents = [\"chief-architect\"]\n";
    const ROSTER: &str = r#"
[agent.chief-architect]
group = "direction"
description = "d"
model = "fable"
effort = "xhigh"
cap_role = "direction"
max_turns = 1
tools = []
deny_write = "@protected"
net = "B"
trigger = "manual"
body = "b"

[agent.impl-rust]
group = "implementer"
description = "d"
model = "sonnet"
effort = "high"
cap_role = "worker"
max_turns = 1
tools = []
deny_write = "@protected"
net = "A"
trigger = "dispatch"
body = "b"

[agent.lead-core]
group = "lead"
description = "d"
model = "opus"
effort = "high"
cap_role = "lead"
max_turns = 1
tools = []
deny_write = "@protected"
net = "A"
trigger = "dispatch"
body = "b"
"#;

    fn models() -> Models {
        crate::config::parse_toml(MODELS, "models").unwrap()
    }

    fn identity(name: Option<&str>) -> Identity {
        #[derive(serde::Deserialize)]
        struct File {
            agent: std::collections::BTreeMap<String, crate::config::roster::Agent>,
        }
        let file: File = crate::config::parse_toml(ROSTER, "roster").unwrap();
        let roster = Roster {
            defaults: toml::Table::new(),
            agents: file.agent,
        };
        let who = match name {
            None => Who::Person,
            Some(name) => match roster.agent(name) {
                Some(agent) => Who::Agent {
                    name: name.to_owned(),
                    agent: Box::new(agent.clone()),
                },
                None => Who::Unknown(name.to_owned()),
            },
        };
        Identity {
            who,
            session: Session {
                agent: name.map(str::to_owned),
                ..Session::default()
            },
            item: Item::None,
            protected_lease: false,
            workflow_subagent: false,
        }
    }

    fn verdict(name: Option<&str>, launcher: Option<&str>, model: &str) -> Verdict {
        let models = models();
        match rule_for(&models, &identity(name), launcher) {
            Ok(rule) => judge(&models, &rule, model),
            Err(message) => Verdict::Violation(message),
        }
    }

    #[test]
    fn fable_only_for_the_chief_architect() {
        assert_eq!(
            verdict(Some("chief-architect"), None, "claude-fable-5-2[1m]"),
            Verdict::Allowed
        );
        assert!(matches!(
            verdict(Some("impl-rust"), None, "claude-fable-5-2"),
            Verdict::Violation(_)
        ));
        assert!(matches!(
            verdict(None, None, "fable[1m]"),
            Verdict::Violation(_)
        ));
        assert!(matches!(
            verdict(Some("chief-architect"), None, "claude-opus-5-5"),
            Verdict::Violation(_)
        ));
    }

    #[test]
    fn bindings_launcher_opus_and_people() {
        assert_eq!(
            verdict(Some("impl-rust"), None, "claude-sonnet-5-5"),
            Verdict::Allowed
        );
        assert!(matches!(
            verdict(Some("impl-rust"), None, "claude-opus-5-5"),
            Verdict::Violation(_)
        ));
        assert_eq!(
            verdict(Some("impl-rust"), Some("opus"), "claude-opus-5-5"),
            Verdict::Allowed
        );
        assert!(matches!(
            verdict(Some("impl-rust"), Some("fable"), "claude-sonnet-5-5"),
            Verdict::Violation(_)
        ));
        assert!(matches!(
            verdict(Some("lead-core"), None, "claude-sonnet-5-5"),
            Verdict::Violation(_)
        ));
        assert_eq!(verdict(None, None, "opus"), Verdict::Allowed);
        assert_eq!(
            verdict(None, None, "claude-sonnet-5-5-20261101"),
            Verdict::Allowed
        );
        assert!(matches!(
            verdict(None, None, "claude-haiku-4-5"),
            Verdict::Violation(_)
        ));
        assert!(matches!(
            verdict(Some("impl-ghost"), None, "claude-sonnet-5-5"),
            Verdict::Violation(_)
        ));
    }

    #[test]
    fn subagents_are_judged_by_their_own_rule_not_the_launchers() {
        let models = models();
        let mut roster_subagent = identity(Some("lead-core"));
        roster_subagent.session.agent = Some("chief-architect".into());
        let rule = rule_for(&models, &roster_subagent, Some("claude-fable-5-2")).unwrap();
        assert_eq!(judge(&models, &rule, "claude-opus-5-5"), Verdict::Allowed);
        let mut workflow = identity(Some("chief-architect"));
        workflow.workflow_subagent = true;
        let rule = rule_for(&models, &workflow, Some("claude-fable-5-2")).unwrap();
        assert_eq!(judge(&models, &rule, "claude-sonnet-5-5"), Verdict::Allowed);
        assert_eq!(judge(&models, &rule, "claude-opus-5-5"), Verdict::Allowed);
        assert!(matches!(
            judge(&models, &rule, "claude-fable-5-2"),
            Verdict::Violation(_)
        ));
    }
}
