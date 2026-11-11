//! Gate V22, the model rule of design/_review/03: models.toml binds exactly `fable`, `opus`
//! and `sonnet` to the three ids that rule pins; only `chief-architect` runs on Fable; every model
//! a role, hook, skill, setting or rendered definition names is a name or id from models.toml;
//! and every model a kit workflow step or the audit library names is opus or sonnet, never fable,
//! Haiku or another vendor's.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::LazyLock;

use anyhow::Result;

use super::skills;
use super::structure::patterns::{Compiled, compile};
use crate::config::Kit;
use crate::config::hooks::Action;
use crate::frontmatter;
use crate::kit::CHIEF_ARCHITECT;
use crate::repo::{Repo, walk_files};

pub const MODEL_NAMES: [&str; 3] = ["fable", "opus", "sonnet"];
/// The ids design/_review/03 binds; a change to them is a change to that rule first.
const PINNED_IDS: [(&str, &str); 3] = [
    ("fable", "claude-fable-5-2"),
    ("opus", "claude-opus-5-5"),
    ("sonnet", "claude-sonnet-5-5"),
];
/// The models a workflow step or an audit pass may name.
const WORKER_MODELS: [&str; 2] = ["opus", "sonnet"];
const RENDERED_AGENTS: &str = ".claude/agents";
const WORKFLOWS: &str = ".agents/kit/workflows";
const AUDIT_LIBRARY: &str = "audits/library.toml";

static MODEL_LITERAL: Compiled = LazyLock::new(|| compile(r#"\bmodel\s*:\s*['"]([^'"]+)['"]"#));
static ALLOWED_LIST: Compiled = LazyLock::new(|| compile(r"ALLOWED_MODELS\s*=\s*\[([^\]]*)\]"));

pub fn problems(repo: &Repo) -> Result<Vec<String>> {
    let kit = match Kit::load(repo) {
        Ok(kit) => kit,
        Err(error) => return Ok(vec![format!("kit sources: {error:#}")]),
    };
    let mut problems = rule_problems(&kit);
    problems.extend(file_problems(repo, &kit)?);
    problems.extend(workflow_problems(repo)?);
    problems.extend(audit_problems(repo)?);
    Ok(problems)
}

/// `model:` literals and `ALLOWED_MODELS` in the kit workflows: opus or sonnet only.
fn workflow_problems(repo: &Repo) -> Result<Vec<String>> {
    let (Some(literal), Some(allowed_list)) = (MODEL_LITERAL.as_ref(), ALLOWED_LIST.as_ref())
    else {
        anyhow::bail!("the workflow model patterns do not compile");
    };
    let mut problems = Vec::new();
    for file in walk_files(&repo.path(WORKFLOWS))? {
        if file.extension().is_none_or(|ext| ext != "js") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        let shown = display_path(repo, &file);
        let named = literal
            .captures_iter(&text)
            .filter_map(|found| found.get(1))
            .map(|model| model.as_str().to_owned());
        let allowed = allowed_list
            .captures_iter(&text)
            .filter_map(|found| found.get(1))
            .flat_map(|list| {
                list.as_str()
                    .split(',')
                    .map(|item| item.trim().trim_matches(['\'', '"']).to_owned())
                    .filter(|item| !item.is_empty())
            });
        for model in named.chain(allowed) {
            if !WORKER_MODELS.contains(&model.as_str()) {
                problems.push(format!(
                    "{shown}: names model `{model}`; workflow steps run on opus or sonnet only"
                ));
            }
        }
    }
    Ok(problems)
}

/// Every `*_model` key and `allowed_models` list of the audit library: opus or sonnet only.
fn audit_problems(repo: &Repo) -> Result<Vec<String>> {
    let Some(text) = repo.read_optional(AUDIT_LIBRARY)? else {
        return Ok(Vec::new());
    };
    let table: toml::Table = match crate::config::parse_toml(&text, AUDIT_LIBRARY) {
        Ok(table) => table,
        Err(error) => return Ok(vec![format!("{error:#}")]),
    };
    let mut problems = Vec::new();
    audit_models(&toml::Value::Table(table), "", &mut problems);
    Ok(problems)
}

fn audit_models(value: &toml::Value, at: &str, problems: &mut Vec<String>) {
    let toml::Value::Table(table) = value else {
        if let toml::Value::Array(items) = value {
            for (index, item) in items.iter().enumerate() {
                audit_models(item, &format!("{at}[{index}]"), problems);
            }
        }
        return;
    };
    for (key, entry) in table {
        let path = if at.is_empty() {
            key.clone()
        } else {
            format!("{at}.{key}")
        };
        let named: Vec<&str> = match (key.as_str(), entry) {
            ("allowed_models", toml::Value::Array(items)) => {
                items.iter().filter_map(toml::Value::as_str).collect()
            }
            (key, toml::Value::String(model)) if key.ends_with("_model") => vec![model.as_str()],
            _ => {
                audit_models(entry, &path, problems);
                continue;
            }
        };
        for model in named {
            if !WORKER_MODELS.contains(&model) {
                problems.push(format!(
                    "{AUDIT_LIBRARY} {path} names model `{model}`; audit passes run on opus or sonnet only"
                ));
            }
        }
    }
}

/// The rule applied to the kit sources alone.
pub fn rule_problems(kit: &Kit) -> Vec<String> {
    let models = &kit.models;
    let mut problems = Vec::new();
    let names: BTreeSet<&str> = models.models.keys().map(String::as_str).collect();
    if names != MODEL_NAMES.into_iter().collect() {
        problems.push(format!(
            "models.toml must bind exactly fable, opus and sonnet; it binds {}",
            list(&names)
        ));
    }
    for (name, id) in &models.models {
        let pinned = PINNED_IDS
            .iter()
            .find(|(known, _)| known == name)
            .map(|(_, pinned)| *pinned);
        if let Some(pinned) = pinned
            && pinned != id
        {
            problems.push(format!(
                "models.toml binds `{name}` to `{id}`; design/_review/03 binds it to `{pinned}`"
            ));
        }
    }
    if models.rules.fable_agents != [CHIEF_ARCHITECT] {
        problems.push(format!(
            "models.toml rules.fable_agents must be [\"{CHIEF_ARCHITECT}\"]"
        ));
    }
    let mut on_fable = Vec::new();
    for (agent, role) in &kit.roster.agents {
        if !names.contains(role.model.as_str()) {
            problems.push(format!(
                "agent `{agent}` names model `{}`, which models.toml does not bind",
                role.model
            ));
        }
        if role.model == "fable" {
            on_fable.push(agent.as_str());
        }
    }
    if on_fable != [CHIEF_ARCHITECT] {
        problems.push(format!(
            "exactly one agent, {CHIEF_ARCHITECT}, may run on fable; on fable now: {}",
            list(&on_fable)
        ));
    }
    for hook in &kit.hooks.hooks {
        if let Action::Prompt { model, .. } = &hook.action
            && models.resolve(model).is_none()
        {
            problems.push(format!(
                "{} prompt hook names model `{model}`, which models.toml does not bind",
                hook.event
            ));
        }
    }
    let settings = &kit.permissions.settings;
    if models.id("sonnet") != Some(settings.model.as_str()) {
        problems.push(format!(
            "permissions.toml settings.model must be the sonnet id, not `{}`",
            settings.model
        ));
    }
    let available: BTreeSet<&str> = settings
        .available_models
        .iter()
        .map(String::as_str)
        .collect();
    if available != names {
        problems.push(format!(
            "permissions.toml settings.available_models must list {}",
            list(&names)
        ));
    }
    for (variable, value) in &settings.env {
        if variable.contains("MODEL") && !models.is_id(value) {
            problems.push(format!(
                "settings.env {variable} = `{value}` is not a model id from models.toml"
            ));
        }
    }
    problems
}

/// Model fields in skills and in the rendered agent definitions on disk.
fn file_problems(repo: &Repo, kit: &Kit) -> Result<Vec<String>> {
    let mut problems = Vec::new();
    for skill in skills::skill_files(repo)? {
        let model = skill
            .front_matter()
            .and_then(|front| front.value("model").map(str::to_owned));
        if let Some(model) = model.filter(|model| kit.models.resolve(model).is_none()) {
            problems.push(format!(
                "{}: model `{model}` is not a name or id from models.toml",
                skill.path
            ));
        }
    }
    for file in walk_files(&repo.path(RENDERED_AGENTS))? {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        let Ok(Some(front)) = frontmatter::parse(&text) else {
            continue;
        };
        let Some(model) = front.value("model") else {
            continue;
        };
        if !kit.models.is_id(model) {
            problems.push(format!(
                "{}: model `{model}` is not an id from models.toml",
                display_path(repo, &file)
            ));
        }
    }
    Ok(problems)
}

/// `file` relative to the root, or as given when it is outside it.
fn display_path(repo: &Repo, file: &Path) -> String {
    repo.relative(file)
        .map_or_else(|| file.display().to_string(), |path| path.to_string())
}

fn list<S: AsRef<str>>(items: impl IntoIterator<Item = S>) -> String {
    let items: Vec<String> = items
        .into_iter()
        .map(|item| item.as_ref().to_owned())
        .collect();
    if items.is_empty() {
        "none".to_owned()
    } else {
        items.join(", ")
    }
}
