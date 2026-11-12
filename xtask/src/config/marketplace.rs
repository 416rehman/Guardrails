//! `.agents/kit/marketplace.toml` and the catalogue it names: the plugin marketplace kept in this
//! repository, every git entry pinned by commit and every entry enabled (team/03 sections 5 and
//! 9, owner instructions 2 and 5).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::repo::Repo;

pub const CATALOGUE_FILE: &str = ".claude-plugin/marketplace.json";
pub const PINS_FILE: &str = "PINS.md";
pub const PROVENANCE_FILE: &str = "PROVENANCE.md";
const COMMIT_HEX_DIGITS: usize = 40;
const VENDORED_PREFIX: &str = "./";
const ENABLED_PLUGINS: &str = "enabledPlugins";

#[derive(Debug, Clone, Deserialize)]
pub struct Marketplace {
    pub marketplace: MarketplaceSource,
    #[serde(default)]
    pub plugins: Plugins,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MarketplaceSource {
    pub name: String,
    /// The catalogue's root, relative to the repository root. [`Marketplace::load`] requires it.
    pub local_path: Option<String>,
    /// Refused by [`Marketplace::load`]: the catalogue lives in this repository.
    pub github: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Plugins {
    #[serde(default)]
    pub enabled: Vec<String>,
    /// The manifest name of an entry whose own name differs: its skills are `<manifest>:<skill>`.
    #[serde(default)]
    pub namespaces: BTreeMap<String, String>,
}

/// `.claude-plugin/marketplace.json` under the marketplace directory.
#[derive(Debug, Clone, Deserialize)]
pub struct Catalogue {
    pub name: String,
    pub plugins: Vec<Entry>,
    /// The catalogue directory it was read from, relative to the repository root.
    #[serde(skip)]
    pub root: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Entry {
    pub name: String,
    pub source: Source,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Source {
    /// A plugin directory inside the catalogue, written `./<path>` from its root.
    Vendored(String),
    Git(GitSource),
}

/// A source Claude Code clones and checks out at `sha`, whatever `ref` names by then.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "source", rename_all = "kebab-case")]
pub enum GitSource {
    Github {
        repo: String,
        #[serde(rename = "ref")]
        reference: String,
        sha: String,
    },
    Url {
        url: String,
        #[serde(rename = "ref")]
        reference: String,
        sha: String,
    },
    GitSubdir {
        url: String,
        path: String,
        #[serde(rename = "ref")]
        reference: String,
        sha: String,
    },
}

/// One pinned plugin's installed commit against its pin (team/03 section 9 rule 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinState {
    NotFetched,
    AtPin,
    /// Installed without a recorded commit, so the pin cannot be compared.
    Unrecorded,
    Moved {
        installed: String,
        scope: String,
    },
}

/// `installed_plugins.json` in Claude Code's plugin root.
#[derive(Debug, Default, Deserialize)]
pub struct InstalledPlugins {
    #[serde(default)]
    pub plugins: BTreeMap<String, Vec<InstalledRecord>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstalledRecord {
    #[serde(default)]
    pub scope: String,
    pub git_commit_sha: Option<String>,
    /// The directory the plugin runs from, `CLAUDE_PLUGIN_ROOT` in its hooks.
    #[serde(default)]
    pub install_path: Option<String>,
}

impl Marketplace {
    pub fn load(repo: &Repo) -> Result<Marketplace> {
        let (label, path) = super::agents_file(repo, "kit/marketplace.toml");
        let marketplace: Marketplace = super::read_toml(&path, &label)?;
        marketplace.validate(&label)?;
        Ok(marketplace)
    }

    pub fn id(&self, entry: &str) -> String {
        format!("{entry}@{}", self.marketplace.name)
    }

    /// Entry names of the enabled plugins: `cleanup` for `cleanup@grdr-agent-marketplace`. Claude
    /// Code names an installed plugin's cache directory after it.
    pub fn enabled_plugins(&self) -> impl Iterator<Item = &str> {
        self.plugins
            .enabled
            .iter()
            .filter_map(|id| id.split_once('@').map(|(plugin, _)| plugin))
    }

    /// What the enabled plugins' skills and agents carry before the colon: the entry name, or the
    /// manifest name `[plugins.namespaces]` gives the entry.
    pub fn skill_namespaces(&self) -> impl Iterator<Item = &str> {
        self.enabled_plugins().map(|entry| {
            self.plugins
                .namespaces
                .get(entry)
                .map_or(entry, String::as_str)
        })
    }

    /// The catalogue directory relative to the repository root, without `./` or a trailing `/`.
    pub fn directory(&self) -> Option<&str> {
        let directory = self
            .marketplace
            .local_path
            .as_deref()?
            .trim_end_matches('/');
        Some(directory.strip_prefix(VENDORED_PREFIX).unwrap_or(directory))
    }

    /// The catalogue's `source` as the tracked settings name it. Claude Code resolves a relative
    /// directory against the main checkout, so every worktree loads the same catalogue.
    pub fn directory_source(&self) -> Option<Value> {
        let directory = self.directory()?;
        Some(json!({ "source": "directory", "path": format!("{VENDORED_PREFIX}{directory}") }))
    }

    /// The `extraKnownMarketplaces` value of `.claude/settings.json`.
    pub fn extra_known_marketplaces(&self) -> Option<Value> {
        let source = self.directory_source()?;
        Some(json!({ self.marketplace.name.clone(): { "source": source } }))
    }

    /// User-scope plugins, enabled in the user's settings, that load under a skill namespace an
    /// entry here uses. Claude Code registers one copy's hooks per name, so the user copy goes.
    pub fn shadowed_by(&self, user_settings: &Value) -> Vec<String> {
        let namespaces: BTreeSet<&str> = self.skill_namespaces().collect();
        let Some(enabled) = user_settings
            .get(ENABLED_PLUGINS)
            .and_then(Value::as_object)
        else {
            return Vec::new();
        };
        enabled
            .iter()
            .filter(|(_, on)| on.as_bool() == Some(true))
            .filter_map(|(id, _)| {
                let (plugin, origin) = id.split_once('@')?;
                (origin != self.marketplace.name && namespaces.contains(plugin)).then(|| id.clone())
            })
            .collect()
    }

    fn validate(&self, label: &str) -> Result<()> {
        if let Some(repository) = &self.marketplace.github {
            bail!(
                "{label}: `github = \"{repository}\"`: the catalogue lives in this repository at `local_path`"
            );
        }
        if self.marketplace.local_path.is_none() {
            bail!("{label}: [marketplace] names no `local_path`, the catalogue's directory");
        }
        for id in &self.plugins.enabled {
            let from_here = id.split_once('@').is_some_and(|(plugin, source)| {
                !plugin.is_empty() && source == self.marketplace.name
            });
            if !from_here {
                bail!(
                    "{label}: `{id}` must be `<plugin>@{}`: plugins come only from the private marketplace",
                    self.marketplace.name
                );
            }
        }
        let enabled: BTreeSet<&str> = self.enabled_plugins().collect();
        if let Some(entry) = self
            .plugins
            .namespaces
            .keys()
            .find(|entry| !enabled.contains(entry.as_str()))
        {
            bail!("{label}: [plugins.namespaces] names `{entry}`, which `enabled` does not list");
        }
        Ok(())
    }
}

impl Catalogue {
    pub fn load(repo: &Repo, marketplace: &Marketplace) -> Result<Catalogue> {
        let Some(root) = marketplace.directory().filter(|root| stays_inside(root)) else {
            bail!(
                ".agents/kit/marketplace.toml: local_path `{}` must be a relative path inside the repository",
                marketplace
                    .marketplace
                    .local_path
                    .as_deref()
                    .unwrap_or_default()
            );
        };
        let label = format!("{root}/{CATALOGUE_FILE}");
        let text = repo.read(&label)?;
        let catalogue: Catalogue =
            serde_json::from_str(&text).with_context(|| format!("parsing {label}"))?;
        Ok(Catalogue {
            root: root.to_owned(),
            ..catalogue
        })
    }

    /// Entries Claude Code fetches from a git host, by plugin id.
    pub fn git_entries<'a>(
        &'a self,
        marketplace: &'a Marketplace,
    ) -> impl Iterator<Item = (String, &'a GitSource)> {
        self.plugins.iter().filter_map(|entry| match &entry.source {
            Source::Git(source) => Some((marketplace.id(&entry.name), source)),
            Source::Vendored(_) => None,
        })
    }

    /// What breaks team/03 section 9 or owner instruction 2: a name that differs from
    /// marketplace.toml's, an entry not enabled or an enabled one not listed, a git source without
    /// a full commit, a vendored plugin outside the catalogue or without provenance, and an entry
    /// that PINS.md does not record with its commit.
    pub fn problems(&self, repo: &Repo, marketplace: &Marketplace) -> Result<Vec<String>> {
        let directory = self.root.as_str();
        let label = format!("{directory}/{CATALOGUE_FILE}");
        let mut problems = Vec::new();
        if self.name != marketplace.marketplace.name {
            problems.push(format!(
                "{label}: name `{}` differs from `{}` in .agents/kit/marketplace.toml",
                self.name, marketplace.marketplace.name
            ));
        }
        let enabled: BTreeSet<&str> = marketplace.enabled_plugins().collect();
        let mut listed = BTreeSet::new();
        for entry in &self.plugins {
            if !listed.insert(entry.name.as_str()) {
                problems.push(format!("{label}: `{}` is listed twice", entry.name));
            }
            if !enabled.contains(entry.name.as_str()) {
                problems.push(format!(
                    "{label}: `{}` is not enabled in .agents/kit/marketplace.toml (owner instruction 2)",
                    marketplace.id(&entry.name)
                ));
            }
            problems.extend(entry.source_problems(repo, directory, &label));
        }
        problems.extend(enabled.difference(&listed).map(|entry| {
            format!(
                ".agents/kit/marketplace.toml enables `{}`, which {label} does not list",
                marketplace.id(entry)
            )
        }));
        problems.extend(self.pin_record_problems(repo, directory)?);
        Ok(problems)
    }

    fn pin_record_problems(&self, repo: &Repo, directory: &str) -> Result<Vec<String>> {
        let label = format!("{directory}/{PINS_FILE}");
        let Some(pins) = repo.read_optional(&label)? else {
            return Ok(vec![format!("{label} is missing")]);
        };
        Ok(self
            .plugins
            .iter()
            .filter_map(|entry| {
                let named = pins.contains(&format!("`{}`", entry.name));
                let pinned = match &entry.source {
                    Source::Git(source) => pins.contains(source.sha()),
                    Source::Vendored(_) => true,
                };
                (!named || !pinned)
                    .then(|| format!("{label} does not record `{}` with its commit", entry.name))
            })
            .collect())
    }
}

impl Entry {
    fn source_problems(&self, repo: &Repo, directory: &str, label: &str) -> Vec<String> {
        let name = &self.name;
        match &self.source {
            Source::Git(source) => {
                let mut problems = Vec::new();
                if !is_full_commit(source.sha()) {
                    problems.push(format!(
                        "{label}: `{name}` sha `{}` is not a full lowercase commit id",
                        source.sha()
                    ));
                }
                if source.reference().trim().is_empty() {
                    problems.push(format!("{label}: `{name}` has an empty `ref`"));
                }
                problems
            }
            Source::Vendored(path) => {
                let Some(relative) = path.strip_prefix(VENDORED_PREFIX) else {
                    return vec![format!(
                        "{label}: `{name}` source `{path}` must start with `./`"
                    )];
                };
                if !stays_inside(relative) {
                    return vec![format!(
                        "{label}: `{name}` source `{path}` leaves the catalogue"
                    )];
                }
                let plugin = format!("{directory}/{}", relative.trim_end_matches('/'));
                if !repo.path(&plugin).is_dir() {
                    return vec![format!("{label}: `{name}`: {plugin} does not exist")];
                }
                let provenance = format!("{plugin}/{PROVENANCE_FILE}");
                if repo.path(&provenance).is_file() {
                    Vec::new()
                } else {
                    vec![format!(
                        "{label}: `{name}` is vendored without {provenance}"
                    )]
                }
            }
        }
    }
}

impl GitSource {
    pub fn sha(&self) -> &str {
        match self {
            GitSource::Github { sha, .. }
            | GitSource::Url { sha, .. }
            | GitSource::GitSubdir { sha, .. } => sha,
        }
    }

    pub fn reference(&self) -> &str {
        match self {
            GitSource::Github { reference, .. }
            | GitSource::Url { reference, .. }
            | GitSource::GitSubdir { reference, .. } => reference,
        }
    }
}

impl InstalledPlugins {
    /// A plugin is at its pin when every record of it that names a commit names the pin.
    pub fn pin_state(&self, id: &str, pin: &str) -> PinState {
        let Some(records) = self.plugins.get(id).filter(|records| !records.is_empty()) else {
            return PinState::NotFetched;
        };
        let moved = records.iter().find_map(|record| {
            let sha = record.git_commit_sha.as_deref()?;
            (sha != pin).then(|| (sha.to_owned(), record.scope.clone()))
        });
        match moved {
            Some((installed, scope)) => PinState::Moved { installed, scope },
            None if records
                .iter()
                .any(|record| record.git_commit_sha.as_deref() == Some(pin)) =>
            {
                PinState::AtPin
            }
            None => PinState::Unrecorded,
        }
    }
}

fn is_full_commit(sha: &str) -> bool {
    sha.len() == COMMIT_HEX_DIGITS
        && sha
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

/// A relative path whose every part is a name: no root, no drive and no `..`.
fn stays_inside(relative: &str) -> bool {
    !relative.is_empty()
        && Path::new(relative)
            .components()
            .all(|part| matches!(part, Component::Normal(_) | Component::CurDir))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "489dd5a409814c9db337a4d53bce440aba75d21f";

    fn marketplace(enabled: &[&str]) -> Marketplace {
        let ids: Vec<String> = enabled
            .iter()
            .map(|entry| format!("\"{entry}@grdr-agent-marketplace\""))
            .collect();
        let text = format!(
            "[marketplace]\nname = \"grdr-agent-marketplace\"\nlocal_path = \"./.agents/marketplace/\"\n\n[plugins]\nenabled = [{}]\n\n[plugins.namespaces]\nsecurity-scan = \"claude-security\"\n",
            ids.join(", ")
        );
        crate::config::parse_toml(&text, "marketplace.toml").unwrap()
    }

    fn write(root: &Path, relative: &str, text: &str) {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn fixture(name: &str, catalogue: &str, pins: &str) -> (Repo, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!("xtask-market-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        write(
            &root,
            &format!(".agents/marketplace/{CATALOGUE_FILE}"),
            catalogue,
        );
        write(&root, ".agents/marketplace/PINS.md", pins);
        write(
            &root,
            ".agents/marketplace/plugins/unslop/PROVENANCE.md",
            "# Provenance\n",
        );
        (Repo::at(&root), root)
    }

    fn catalogue(cleanup_sha: &str) -> String {
        format!(
            r#"{{"name": "grdr-agent-marketplace", "owner": {{"name": "x"}}, "plugins": [
  {{"name": "cleanup", "source": {{"source": "git-subdir", "url": "https://example.com/mods.git", "path": "cleanup", "ref": "main", "sha": "{cleanup_sha}"}}}},
  {{"name": "security-scan", "source": {{"source": "github", "repo": "example/security", "ref": "main", "sha": "{SHA}"}}}},
  {{"name": "unslop", "source": "./plugins/unslop"}}
]}}"#
        )
    }

    #[test]
    fn namespaces_rename_skills_only_and_ids_must_come_from_here() {
        let market = marketplace(&["cleanup", "security-scan"]);
        let entries: Vec<&str> = market.enabled_plugins().collect();
        assert_eq!(entries, vec!["cleanup", "security-scan"]);
        let namespaces: Vec<&str> = market.skill_namespaces().collect();
        assert_eq!(namespaces, vec!["cleanup", "claude-security"]);
        let mut broken = market.clone();
        broken.plugins.enabled.push("cleanup@claude-mods".into());
        assert!(broken.validate("m").is_err());
        let mut stray = market.clone();
        stray
            .plugins
            .namespaces
            .insert("hookify".into(), "x".into());
        assert!(stray.validate("m").is_err());
        let mut github = market.clone();
        github.marketplace.github = Some("example/market".into());
        assert!(github.validate("m").is_err());
        let mut nowhere = market;
        nowhere.marketplace.local_path = None;
        assert!(nowhere.validate("m").is_err());
    }

    #[test]
    fn the_directory_source_is_relative_to_the_main_checkout() {
        let market = marketplace(&["cleanup"]);
        assert_eq!(
            market.extra_known_marketplaces(),
            Some(
                json!({"grdr-agent-marketplace": {"source": {"source": "directory", "path": "./.agents/marketplace"}}})
            )
        );
    }

    #[test]
    fn a_complete_catalogue_has_no_problems() {
        let pins = format!("`cleanup` {SHA}\n`security-scan` {SHA}\n`unslop`\n");
        let (repo, root) = fixture("ok", &catalogue(SHA), &pins);
        let market = marketplace(&["cleanup", "security-scan", "unslop"]);
        let loaded = Catalogue::load(&repo, &market).unwrap();
        assert_eq!(
            loaded.problems(&repo, &market).unwrap(),
            Vec::<String>::new()
        );
        let fetched: Vec<String> = loaded.git_entries(&market).map(|(id, _)| id).collect();
        assert_eq!(
            fetched,
            vec![
                "cleanup@grdr-agent-marketplace",
                "security-scan@grdr-agent-marketplace"
            ]
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn short_pins_missing_records_and_unlisted_entries_are_problems() {
        let (repo, root) = fixture("bad", &catalogue("489dd5a"), "`cleanup` 489dd5a\n");
        let market = marketplace(&["cleanup", "security-scan", "hookify"]);
        let problems = Catalogue::load(&repo, &market)
            .unwrap()
            .problems(&repo, &market)
            .unwrap();
        let has = |text: &str| problems.iter().any(|problem| problem.contains(text));
        assert!(has("`cleanup` sha `489dd5a` is not a full"));
        assert!(has("`unslop@grdr-agent-marketplace` is not enabled"));
        assert!(has("enables `hookify@grdr-agent-marketplace`"));
        assert!(has("does not record `security-scan`"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_catalogue_outside_the_repository_is_refused() {
        let mut market = marketplace(&["cleanup"]);
        market.marketplace.local_path = Some("../grdr-agent-marketplace".into());
        assert!(Catalogue::load(&Repo::at(std::env::temp_dir()), &market).is_err());
        assert!(stays_inside("plugins/unslop"));
        assert!(!stays_inside("../x") && !stays_inside("/x") && !stays_inside(""));
    }

    #[test]
    fn user_copies_under_a_pinned_name_are_shadowed() {
        let user = json!({ "enabledPlugins": {
            "cleanup@claude-mods": true,
            "claude-security@claude-plugins-official": true,
            "spinlings@spinlings": true,
            "hookify@claude-plugins-official": false,
            "cleanup@grdr-agent-marketplace": true
        }});
        let market = marketplace(&["cleanup", "security-scan", "hookify"]);
        assert_eq!(
            market.shadowed_by(&user),
            vec![
                "claude-security@claude-plugins-official",
                "cleanup@claude-mods"
            ]
        );
        assert!(market.shadowed_by(&json!({})).is_empty());
    }

    #[test]
    fn pins_compare_every_installed_record() {
        const OTHER: &str = "e4db79059ef469b72ccdc408b2cb2fb9b3b20ec7";
        let record = |sha: Option<&str>| InstalledRecord {
            scope: "local".into(),
            git_commit_sha: sha.map(str::to_owned),
            install_path: None,
        };
        let installed = InstalledPlugins {
            plugins: BTreeMap::from([
                ("at".to_owned(), vec![record(Some(SHA))]),
                ("bare".to_owned(), vec![record(None)]),
                (
                    "moved".to_owned(),
                    vec![record(Some(SHA)), record(Some(OTHER))],
                ),
            ]),
        };
        assert_eq!(installed.pin_state("absent", SHA), PinState::NotFetched);
        assert_eq!(installed.pin_state("at", SHA), PinState::AtPin);
        assert_eq!(installed.pin_state("bare", SHA), PinState::Unrecorded);
        assert_eq!(
            installed.pin_state("moved", SHA),
            PinState::Moved {
                installed: OTHER.into(),
                scope: "local".into()
            }
        );
    }
}
