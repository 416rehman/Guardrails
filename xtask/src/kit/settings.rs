//! `.claude/settings.json` from `permissions.toml`, `protected-paths.toml`, `hooks.toml`,
//! `marketplace.toml` and `vendors.toml`, and the fleet's managed settings from
//! `[managed.<group>]` (team/03 sections 4 and 8). Only project-scope keys go into the project
//! file. `GH_REPO` comes from harness.toml `[github] repository` and each folded model alias from
//! models.toml, so neither is written twice.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value, json};

use super::research::{self, Grant};
use crate::config::Kit;
use crate::config::hooks::{Action, OnFailure};
use crate::config::permissions::FORBIDDEN_PROJECT_MODES;
use crate::config::roster::Group;
use crate::repo::Repo;

pub const SETTINGS_PATH: &str = ".claude/settings.json";
/// Shell form with the quoted path: Git Bash on Windows resolves `xtask` to `xtask.exe`.
pub const KIT_BINARY_COMMAND: &str = "\"${CLAUDE_PROJECT_DIR}/.agent/kit/bin/xtask\"";
/// Honoured only from managed or user settings; never written to the project file.
pub const MANAGED_ONLY_KEYS: &[&str] = &[
    "strictKnownMarketplaces",
    "allowManagedPermissionRulesOnly",
    "allowManagedHooksOnly",
];
/// team/03 section 8: it would stop the project hooks.
pub const NEVER_MANAGED_KEYS: &[&str] = &["allowManagedHooksOnly"];
pub const MANAGED_DIR: &str = "deploy/fleet";
/// The group whose managed document is `managed-settings.json` itself.
const DEFAULT_GROUP: Group = Group::Implementer;
const REPOSITORY_VARIABLE: &str = "GH_REPO";

/// The entries of one event that share a matcher.
struct MatcherGroup<'a> {
    matcher: Option<&'a str>,
    entries: Vec<Value>,
}

/// The command a hook entry runs for `handler`.
pub fn hook_command(handler: &str) -> String {
    format!("{KIT_BINARY_COMMAND} hook {handler}")
}

/// `deploy/fleet/managed-settings.json` for implementers, `managed-settings.<group>.json` for the rest.
pub fn managed_path(group: &str) -> String {
    if group == DEFAULT_GROUP.as_str() {
        format!("{MANAGED_DIR}/managed-settings.json")
    } else {
        format!("{MANAGED_DIR}/managed-settings.{group}.json")
    }
}

pub fn project(repo: &Repo, kit: &Kit) -> Result<Value> {
    let settings = &kit.permissions.settings;
    let mut root = Map::new();
    if let Some(schema) = &settings.schema {
        root.insert("$schema".into(), json!(schema));
    }
    let mut env = Map::new();
    for (name, value) in &settings.env {
        env.insert(name.clone(), json!(value));
    }
    add_env(&mut env, derived_env(kit)?, "permissions.toml settings.env")?;
    if !env.is_empty() {
        root.insert("env".into(), Value::Object(env));
    }
    if !kit.models.is_id(&settings.model) {
        bail!(
            "permissions.toml settings.model `{}` is not a model id from models.toml",
            settings.model
        );
    }
    root.insert("model".into(), json!(settings.model));
    let available = settings
        .available_models
        .iter()
        .map(|name| {
            kit.models.id(name).with_context(|| {
                format!("settings.available_models: `{name}` is not bound in models.toml")
            })
        })
        .collect::<Result<Vec<&str>>>()?;
    root.insert("availableModels".into(), json!(available));
    root.insert("autoMemoryEnabled".into(), json!(settings.auto_memory));
    root.insert(
        "attribution".into(),
        json!({ "commit": settings.attribution_commit, "pr": settings.attribution_pr }),
    );
    if let Some(mode) = &settings.disable_auto_mode {
        root.insert("disableAutoMode".into(), json!(mode));
    }
    if settings.disable_workflows {
        bail!(
            "permissions.toml settings.disable_workflows: no verified Claude Code setting renders it; keep it false"
        );
    }
    root.insert("permissions".into(), permissions(kit)?);
    root.insert("sandbox".into(), sandbox(kit));
    let plugins: Map<String, Value> = kit
        .marketplace
        .plugins
        .enabled
        .iter()
        .map(|id| (id.clone(), json!(true)))
        .collect();
    if !plugins.is_empty() {
        root.insert("enabledPlugins".into(), Value::Object(plugins));
    }
    if let Some(known) = kit.marketplace.extra_known_marketplaces() {
        root.insert("extraKnownMarketplaces".into(), known);
    }
    root.insert("hooks".into(), hooks(repo, kit)?);
    Ok(Value::Object(root))
}

/// One managed settings document, with the protected-path deny rules merged in.
pub fn managed(kit: &Kit, group: &str, document: &toml::Table) -> Result<Value> {
    if !Group::ALL.iter().any(|known| known.as_str() == group) {
        bail!(
            "permissions.toml [managed.{group}]: `{group}` is not a roster group ({})",
            Group::ALL.map(Group::as_str).join(", ")
        );
    }
    let mut value =
        serde_json::to_value(document).context("converting managed settings to JSON")?;
    let Some(root) = value.as_object_mut() else {
        bail!("permissions.toml [managed.{group}] is not a table");
    };
    if let Some(key) = NEVER_MANAGED_KEYS
        .iter()
        .find(|key| root.contains_key(**key))
    {
        bail!(
            "permissions.toml [managed.{group}] sets `{key}`, which would stop the project hooks"
        );
    }
    let permissions = root.entry("permissions").or_insert_with(|| json!({}));
    let Some(permissions) = permissions.as_object_mut() else {
        bail!("permissions.toml [managed.{group}].permissions is not a table");
    };
    let listed = rule_list(permissions, "deny", group)?;
    let asked = rule_list(permissions, "ask", group)?;
    let grant = Grant::of(kit).filter(|grant| grant.covers_group(kit, group));
    if let Some(rule) =
        research::shadowing_rule(&listed).or_else(|| research::shadowing_rule(&asked))
        && grant.is_some()
    {
        bail!(
            "permissions.toml [managed.{group}].permissions lists `{rule}`, which would refuse the fetch rules vendors.toml grants to this group's roles"
        );
    }
    permissions.insert(
        "deny".into(),
        json!(dedupe(kit.protected.edit_rules().into_iter().chain(listed))),
    );
    if let Some(grant) = grant {
        let allowed = rule_list(permissions, "allow", group)?;
        permissions.insert(
            "allow".into(),
            json!(dedupe(allowed.into_iter().chain(grant.allow_rules()))),
        );
    }
    let derived = derived_env(kit)?;
    if !derived.is_empty() {
        let env = root.entry("env").or_insert_with(|| json!({}));
        let Some(env) = env.as_object_mut() else {
            bail!("permissions.toml [managed.{group}].env is not a table");
        };
        add_env(
            env,
            derived,
            &format!("permissions.toml [managed.{group}].env"),
        )?;
    }
    Ok(value)
}

/// Pretty JSON with a final newline, the form every rendered JSON file takes.
pub fn to_bytes(value: &Value) -> Result<Vec<u8>> {
    let mut text = serde_json::to_string_pretty(value)?;
    text.push('\n');
    Ok(text.into_bytes())
}

fn permissions(kit: &Kit) -> Result<Value> {
    let source = &kit.permissions.permissions;
    if FORBIDDEN_PROJECT_MODES.contains(&source.default_mode.as_str()) {
        bail!(
            "permissions.toml default_mode `{}` cannot be set from a project file",
            source.default_mode
        );
    }
    let mut out = Map::new();
    out.insert("defaultMode".into(), json!(source.default_mode));
    if let Some(value) = &source.disable_bypass {
        out.insert("disableBypassPermissionsMode".into(), json!(value));
    }
    let deny = dedupe(
        kit.protected
            .edit_rules()
            .into_iter()
            .chain(source.deny.iter().cloned()),
    );
    let grant =
        Grant::of(kit).filter(|grant| kit.roster.agents.values().any(|agent| grant.covers(agent)));
    let mut allow = source.allow.clone();
    if let Some(grant) = grant {
        for (list, rules) in [("deny", &source.deny), ("ask", &source.ask)] {
            if let Some(rule) = research::shadowing_rule(rules) {
                bail!(
                    "permissions.toml {list} lists `{rule}`, which would override the fetch rules vendors.toml grants; the roles without the grant do not have the tool"
                );
            }
        }
        allow = dedupe(allow.into_iter().chain(grant.allow_rules()));
    }
    out.insert("deny".into(), json!(deny));
    out.insert("ask".into(), json!(source.ask));
    out.insert("allow".into(), json!(allow));
    Ok(Value::Object(out))
}

fn sandbox(kit: &Kit) -> Value {
    let source = &kit.permissions.sandbox;
    let mut out = Map::new();
    out.insert("enabled".into(), json!(source.enabled));
    out.insert(
        "allowUnsandboxedCommands".into(),
        json!(source.allow_unsandboxed_commands),
    );
    if let Some(fail) = source.fail_if_unavailable {
        out.insert("failIfUnavailable".into(), json!(fail));
    }
    if !source.deny_read.is_empty() {
        out.insert("filesystem".into(), json!({ "denyRead": source.deny_read }));
    }
    if !source.allowed_domains.is_empty() {
        out.insert(
            "network".into(),
            json!({ "allowedDomains": source.allowed_domains }),
        );
    }
    Value::Object(out)
}

/// Entries for one event and matcher keep their file order; matcher groups keep first appearance.
fn hooks(repo: &Repo, kit: &Kit) -> Result<Value> {
    let mut events: BTreeMap<&str, Vec<MatcherGroup>> = BTreeMap::new();
    for hook in &kit.hooks.hooks {
        let mut entry = Map::new();
        match &hook.action {
            Action::Command {
                handler,
                on_failure,
            } => {
                entry.insert("type".into(), json!("command"));
                entry.insert("command".into(), json!(hook_command(handler)));
                if let Some(on_failure) = on_failure {
                    let word = if *on_failure == OnFailure::Block {
                        "block"
                    } else {
                        "continue"
                    };
                    entry.insert("onFailure".into(), json!(word));
                }
            }
            Action::Prompt { model, prompt_file } => {
                let id = kit.models.resolve(model).with_context(|| {
                    format!(
                        "{} prompt hook: model `{model}` is not bound in models.toml",
                        hook.event
                    )
                })?;
                let prompt = repo.read(&format!("{}/{prompt_file}", crate::config::AGENTS_DIR))?;
                entry.insert("type".into(), json!("prompt"));
                entry.insert("prompt".into(), json!(prompt.trim_end()));
                entry.insert("model".into(), json!(id));
            }
        }
        if let Some(timeout) = hook.timeout {
            entry.insert("timeout".into(), json!(timeout));
        }
        if let Some(message) = &hook.status_message {
            entry.insert("statusMessage".into(), json!(message));
        }
        let groups = events.entry(hook.event.as_str()).or_default();
        let matcher = hook.matcher.as_deref();
        match groups.iter_mut().find(|group| group.matcher == matcher) {
            Some(group) => group.entries.push(Value::Object(entry)),
            None => groups.push(MatcherGroup {
                matcher,
                entries: vec![Value::Object(entry)],
            }),
        }
    }
    let rendered: Map<String, Value> = events
        .into_iter()
        .map(|(event, groups)| {
            let groups: Vec<Value> = groups
                .into_iter()
                .map(|group| match group.matcher {
                    Some(matcher) => json!({ "matcher": matcher, "hooks": group.entries }),
                    None => json!({ "hooks": group.entries }),
                })
                .collect();
            (event.to_owned(), Value::Array(groups))
        })
        .collect();
    Ok(Value::Object(rendered))
}

/// `GH_REPO` and the folded model aliases: values other kit data already holds.
fn derived_env(kit: &Kit) -> Result<Vec<(String, String)>> {
    let mut derived = kit.models.folded_env()?;
    if let Some(repository) = &kit.harness.github.repository {
        derived.push((REPOSITORY_VARIABLE.to_owned(), repository.clone()));
    }
    Ok(derived)
}

/// Adds derived variables to `env`; `source` setting one itself is an error, so each value has
/// one home.
fn add_env(
    env: &mut Map<String, Value>,
    derived: Vec<(String, String)>,
    source: &str,
) -> Result<()> {
    for (name, value) in derived {
        if env.contains_key(&name) {
            bail!(
                "{source} sets `{name}`, which kit render derives from harness.toml [github] or models.toml folded_aliases; remove it"
            );
        }
        env.insert(name, json!(value));
    }
    Ok(())
}

fn rule_list(permissions: &Map<String, Value>, key: &str, group: &str) -> Result<Vec<String>> {
    match permissions.get(key) {
        Some(Value::Array(items)) => Ok(items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_owned))
            .collect()),
        Some(_) => bail!("permissions.toml [managed.{group}].permissions.{key} is not a list"),
        None => Ok(Vec::new()),
    }
}

fn dedupe(items: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    items
        .into_iter()
        .filter(|item| seen.insert(item.clone()))
        .collect()
}
