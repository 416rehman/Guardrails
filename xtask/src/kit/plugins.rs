//! The agents that enabled marketplace plugins ship, read from the marketplace's local checkout
//! and from Claude Code's plugin cache. Plugin agents run on the model the rule gives their caller
//! (team/03 section 5): `kit check` refuses one that names a model the render cannot fold and the
//! hooks would refuse, so the problem shows before a session meets it.

use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::config::Kit;
use crate::config::models::FABLE;
use crate::frontmatter;
use crate::repo::{Repo, walk_files};

const MARKETPLACE_MANIFEST: &str = ".claude-plugin/marketplace.json";
const PLUGIN_CACHE: &str = "plugins/cache";
const AGENTS_DIR: &str = "agents";
const INHERIT: &str = "inherit";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginAgent {
    pub plugin: String,
    pub path: PathBuf,
    pub model: Option<String>,
}

/// Every agent definition of an enabled plugin found on this machine.
pub fn plugin_agents(
    repo: &Repo,
    kit: &Kit,
    config_dir: Option<&Path>,
) -> Result<Vec<PluginAgent>> {
    let enabled: Vec<&str> = kit.marketplace.enabled_plugins().collect();
    let mut roots: Vec<(String, PathBuf)> = Vec::new();
    if let Some(local) = &kit.marketplace.marketplace.local_path {
        let checkout = repo.root().join(local);
        roots.extend(
            local_sources(&checkout)
                .into_iter()
                .filter(|(plugin, _)| enabled.contains(&plugin.as_str())),
        );
    }
    if let Some(config) = config_dir {
        let cache = config
            .join(PLUGIN_CACHE)
            .join(&kit.marketplace.marketplace.name);
        roots.extend(
            enabled
                .iter()
                .map(|plugin| ((*plugin).to_owned(), cache.join(plugin))),
        );
    }
    let mut agents = Vec::new();
    for (plugin, root) in roots {
        for file in walk_files(&root)? {
            let in_agents_dir = file
                .parent()
                .and_then(Path::file_name)
                .is_some_and(|name| name == AGENTS_DIR);
            if !in_agents_dir || file.extension().is_none_or(|ext| ext != "md") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&file) else {
                continue;
            };
            let model = match frontmatter::parse(&text) {
                Ok(Some(front)) => front.value("model").map(str::to_owned),
                _ => continue,
            };
            agents.push(PluginAgent {
                plugin: plugin.clone(),
                path: file,
                model,
            });
        }
    }
    Ok(agents)
}

/// A plugin agent may name no model, `inherit`, an alias the render folds, or opus or sonnet by
/// name or id; anything else, fable included, is refused.
pub fn model_problems(kit: &Kit, agents: &[PluginAgent]) -> Vec<String> {
    let models = &kit.models;
    let fable_id = models.id(FABLE);
    agents
        .iter()
        .filter_map(|agent| {
            let model = agent.model.as_deref()?.trim();
            let resolved = models.resolve(model);
            let allowed = model == INHERIT
                || models.is_folded(model)
                || resolved.is_some_and(|id| Some(id) != fable_id);
            (!allowed).then(|| {
                format!(
                    "plugin agent {} of `{}` names model `{model}`; plugin agents run on their caller's model, so it must be absent, `{INHERIT}`, an alias models.toml folds, or a non-{FABLE} name or id from models.toml",
                    agent.path.display(),
                    agent.plugin
                )
            })
        })
        .collect()
}

/// `(plugin, directory)` for each plugin whose marketplace entry has a local `source` path.
fn local_sources(checkout: &Path) -> Vec<(String, PathBuf)> {
    let manifest = checkout.join(MARKETPLACE_MANIFEST);
    let Some(value) = std::fs::read_to_string(&manifest)
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
    else {
        return Vec::new();
    };
    let Some(plugins) = value.get("plugins").and_then(serde_json::Value::as_array) else {
        return Vec::new();
    };
    plugins
        .iter()
        .filter_map(|entry| {
            let name = entry.get("name")?.as_str()?;
            let source = entry.get("source")?.as_str()?;
            let path = source
                .split('/')
                .filter(|segment| !segment.is_empty() && *segment != ".")
                .fold(checkout.to_path_buf(), |path, segment| path.join(segment));
            Some((name.to_owned(), path))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::TempRepo;

    const MANIFEST: &str = r#"{"name": "grdr-agent-marketplace", "plugins": [
        {"name": "cleanup", "source": "./plugins/cleanup"},
        {"name": "other", "source": "./plugins/other"},
        {"name": "remote", "source": {"source": "github", "repo": "o/r", "sha": "abc"}}
    ]}"#;

    fn agent(model: &str) -> String {
        format!("---\nname: a\ndescription: d\nmodel: {model}\n---\n\nBody.\n")
    }

    #[test]
    fn enabled_plugin_agents_are_read_from_the_checkout_and_the_cache() {
        let temp = TempRepo::create();
        let market = "market/";
        temp.write(
            &format!("{market}.claude-plugin/marketplace.json"),
            MANIFEST,
        );
        temp.write(
            &format!("{market}plugins/cleanup/agents/tidy.md"),
            &agent("haiku"),
        );
        temp.write(
            &format!("{market}plugins/other/agents/x.md"),
            &agent("gpt-5"),
        );
        temp.write(
            "cfg/plugins/cache/grdr-agent-marketplace/cleanup/0.1.0/agents/judge.md",
            &agent("fable"),
        );
        temp.write(
            "cfg/plugins/cache/grdr-agent-marketplace/cleanup/0.1.0/skills/s/SKILL.md",
            &agent("x"),
        );
        let repo = temp.repo();
        let mut kit = Kit::load(&repo).unwrap();
        kit.marketplace.marketplace.local_path = Some("market".into());
        kit.models
            .rules
            .folded_aliases
            .insert("haiku".into(), "sonnet".into());
        let config = temp.root().join("cfg");
        let found = plugin_agents(&repo, &kit, Some(config.as_path())).unwrap();
        let models: Vec<Option<&str>> = found.iter().map(|a| a.model.as_deref()).collect();
        assert_eq!(models, vec![Some("haiku"), Some("fable")], "{found:#?}");
        let problems = model_problems(&kit, &found);
        assert_eq!(problems.len(), 1, "{problems:#?}");
        assert!(problems[0].contains("names model `fable`"));
    }

    #[test]
    fn allowed_plugin_models() {
        let kit = Kit::load(&TempRepo::create().repo()).unwrap();
        let agents: Vec<PluginAgent> = [
            None,
            Some("inherit"),
            Some("opus"),
            Some("claude-sonnet-5-5"),
            Some("claude-haiku-4-5"),
        ]
        .into_iter()
        .map(|model| PluginAgent {
            plugin: "p".into(),
            path: PathBuf::from("a.md"),
            model: model.map(str::to_owned),
        })
        .collect();
        let problems = model_problems(&kit, &agents);
        assert_eq!(problems.len(), 1, "{problems:#?}");
        assert!(problems[0].contains("`claude-haiku-4-5`"));
    }
}
