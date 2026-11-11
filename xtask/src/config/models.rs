//! `.agents/models.toml`: the binding of model names to exact ids (design/_review/03).

use std::collections::BTreeMap;

use anyhow::{Result, bail};
use serde::Deserialize;

use crate::repo::Repo;

/// The model only the agents in `rules.fable_agents` may run on.
pub const FABLE: &str = "fable";
/// Claude Code reads the model an alias stands for from `ANTHROPIC_DEFAULT_<ALIAS>_MODEL`.
const ALIAS_VARIABLE_PREFIX: &str = "ANTHROPIC_DEFAULT_";
const ALIAS_VARIABLE_SUFFIX: &str = "_MODEL";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Models {
    pub models: BTreeMap<String, String>,
    pub rules: ModelRules,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelRules {
    pub fable_agents: Vec<String>,
    /// Claude Code aliases outside the rule (a plugin agent's `model: haiku`, Claude Code's own
    /// background calls) and the bound name each resolves to instead; `kit render` sets the
    /// alias's `ANTHROPIC_DEFAULT_<ALIAS>_MODEL` to that name's id.
    #[serde(default)]
    pub folded_aliases: BTreeMap<String, String>,
}

impl Models {
    pub fn load(repo: &Repo) -> Result<Models> {
        let (label, path) = super::agents_file(repo, "models.toml");
        super::read_toml(&path, &label)
    }

    pub fn id(&self, name: &str) -> Option<&str> {
        self.models.get(name).map(String::as_str)
    }

    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.models.values().map(String::as_str)
    }

    pub fn is_id(&self, id: &str) -> bool {
        self.ids().any(|known| known == id)
    }

    /// A name from models.toml or one of its ids, resolved to the id.
    pub fn resolve(&self, name_or_id: &str) -> Option<&str> {
        self.id(name_or_id)
            .or_else(|| self.ids().find(|id| *id == name_or_id))
    }

    pub fn is_folded(&self, alias: &str) -> bool {
        self.rules.folded_aliases.contains_key(alias)
    }

    /// The environment variables that send each folded alias to its bound model's id.
    pub fn folded_env(&self) -> Result<Vec<(String, String)>> {
        let mut env = Vec::new();
        for (alias, name) in &self.rules.folded_aliases {
            if alias.is_empty() || !alias.chars().all(|c| c.is_ascii_lowercase()) {
                bail!("models.toml folded_aliases: `{alias}` is not a lower-case alias");
            }
            if self.models.contains_key(alias) {
                bail!("models.toml folds `{alias}`, which it also binds");
            }
            if name == FABLE {
                bail!(
                    "models.toml folds `{alias}` onto {FABLE}, which only {} may run on",
                    self.rules.fable_agents.join(", ")
                );
            }
            let Some(id) = self.id(name) else {
                bail!("models.toml folds `{alias}` onto `{name}`, which it does not bind");
            };
            let variable = format!(
                "{ALIAS_VARIABLE_PREFIX}{}{ALIAS_VARIABLE_SUFFIX}",
                alias.to_ascii_uppercase()
            );
            env.push((variable, id.to_owned()));
        }
        Ok(env)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_names_and_ids() {
        let models: Models = crate::config::parse_toml(
            "[models]\nfable = \"claude-fable-5-2\"\nsonnet = \"claude-sonnet-5-5\"\n[rules]\nfable_agents = [\"chief-architect\"]\n",
            "models.toml",
        )
        .unwrap();
        assert_eq!(models.resolve("sonnet"), Some("claude-sonnet-5-5"));
        assert_eq!(models.resolve("claude-fable-5-2"), Some("claude-fable-5-2"));
        assert_eq!(models.resolve("haiku"), None);
    }

    #[test]
    fn folded_aliases_render_to_their_bound_id() {
        let text = "[models]
fable = \"claude-fable-5-2\"
sonnet = \"claude-sonnet-5-5\"
[rules]
fable_agents = [\"chief-architect\"]
folded_aliases = { haiku = \"sonnet\" }
";
        let models: Models = crate::config::parse_toml(text, "models.toml").unwrap();
        assert!(models.is_folded("haiku"));
        assert_eq!(
            models.folded_env().unwrap(),
            vec![(
                "ANTHROPIC_DEFAULT_HAIKU_MODEL".to_owned(),
                "claude-sonnet-5-5".to_owned()
            )]
        );
        for bad in [
            "haiku = \"fable\"",
            "haiku = \"opus\"",
            "sonnet = \"sonnet\"",
        ] {
            let models: Models =
                crate::config::parse_toml(&text.replace("haiku = \"sonnet\"", bad), "models.toml")
                    .unwrap();
            assert!(models.folded_env().is_err(), "{bad}");
        }
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let parsed: Result<Models> = crate::config::parse_toml(
            "[models]\nopus = \"claude-opus-5-5\"\n[rules]\nfable_agents = []\ndefault = \"opus\"\n",
            "models.toml",
        );
        assert!(parsed.is_err());
    }
}
