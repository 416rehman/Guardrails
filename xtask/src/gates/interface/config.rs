//! The interface checks' configuration: `quality/interface.toml`, the interface paths of
//! `.agents/kit/path-skills.toml`, the exception registry of `ui` and the pattern registry, all
//! read from the comparison base. Without the configuration or the path-skill entries the
//! interface checks cannot place a file, and V26 fails saying which is missing.

use std::collections::BTreeSet;

use anyhow::Result;
use serde::Deserialize;

use crate::config::parse_toml;
use crate::gates::structure::policy_read as read;
use crate::git::Base;
use crate::globs::{Case, GlobList};
use crate::paths::RepoPath;
use crate::repo::Repo;

pub const CONFIG_PATH: &str = "quality/interface.toml";
pub const PATH_SKILLS_PATH: &str = ".agents/kit/path-skills.toml";
const PATTERN_TABLES: &[&str] = &["pattern", "patterns"];
const ID_KEYS: &[&str] = &["id", "name"];
const FILE_KEYS: &[&str] = &["files", "file", "paths", "path"];
const PACKAGE_KEYS: &[&str] = &["packages", "package"];
const SCOPE_KEYS: &[&str] = &["paths", "globs"];
const SKILL_KEY: &str = "skills";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    scope_skill: String,
    exclude: Vec<String>,
    apps: Vec<String>,
    ui: Vec<String>,
    kit: Vec<String>,
    i18n: Vec<String>,
    ui_only_imports: Vec<String>,
    exception_imports: Vec<String>,
    exceptions: String,
    kit_imports: Vec<String>,
    icon_imports: Vec<String>,
    patterns: String,
    accessor: String,
    mutation_hooks: Vec<String>,
    shortcut_hooks: Vec<String>,
    confirmation_elements: Vec<String>,
}

/// One entry of the exception registry: the files that may import the packages it names; an
/// entry that names none may import every governed package.
#[derive(Debug, Clone)]
pub struct Exception {
    pub packages: Vec<String>,
    pub files: GlobList,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub scope: GlobList,
    pub exclude: GlobList,
    pub apps: GlobList,
    pub ui: GlobList,
    pub kit: GlobList,
    pub i18n: GlobList,
    pub ui_only_imports: Vec<String>,
    /// Every package the registry governs: the configured ones and those its entries name.
    pub governed_imports: Vec<String>,
    pub exceptions_path: String,
    pub exceptions: Vec<Exception>,
    pub kit_imports: Vec<String>,
    pub icon_imports: Vec<String>,
    pub patterns_path: String,
    /// Registered pattern ids, normalised by [`normalise`]; `None` while the registry is absent.
    pub patterns: Option<BTreeSet<String>>,
    pub accessor: String,
    pub mutation_hooks: Vec<String>,
    pub shortcut_hooks: Vec<String>,
    pub confirmation_elements: Vec<String>,
}

/// Whether the interface checks can place files, and why not.
#[derive(Debug, Clone)]
pub enum Interface {
    Configured(Box<Config>),
    Unconfigured(String),
}

impl Interface {
    pub fn load(repo: &Repo, base: &Base) -> Result<Interface> {
        let Some(text) = read(repo, base, CONFIG_PATH)? else {
            return Ok(Interface::Unconfigured(format!(
                "{CONFIG_PATH} does not exist"
            )));
        };
        let file: ConfigFile = parse_toml(&text, CONFIG_PATH)?;
        let Some(skills) = read(repo, base, PATH_SKILLS_PATH)? else {
            return Ok(Interface::Unconfigured(format!(
                "{PATH_SKILLS_PATH} does not exist, so no path is an interface path"
            )));
        };
        let scope = scope_globs(
            &parse_toml::<toml::Table>(&skills, PATH_SKILLS_PATH)?,
            &file.scope_skill,
        );
        if scope.is_empty() {
            return Ok(Interface::Unconfigured(format!(
                "no entry of {PATH_SKILLS_PATH} loads `{}`, so no path is an interface path",
                file.scope_skill
            )));
        }
        let exceptions = match read(repo, base, &file.exceptions)? {
            Some(text) => exception_entries(&parse_toml::<toml::Table>(&text, &file.exceptions)?)?,
            None => Vec::new(),
        };
        let patterns = read(repo, base, &file.patterns)?
            .map(|text| parse_toml::<toml::Table>(&text, &file.patterns))
            .transpose()?
            .map(|table| pattern_ids(&table));
        Ok(Interface::Configured(Box::new(Config::new(
            file, &scope, exceptions, patterns,
        )?)))
    }

    /// Whether the interface checks judge `path`.
    pub fn covers(&self, path: &RepoPath) -> bool {
        self.config().is_some_and(|config| config.covers(path))
    }

    pub fn config(&self) -> Option<&Config> {
        match self {
            Interface::Configured(config) => Some(config),
            Interface::Unconfigured(_) => None,
        }
    }
}

impl Config {
    fn new(
        file: ConfigFile,
        scope: &[String],
        exceptions: Vec<Exception>,
        patterns: Option<BTreeSet<String>>,
    ) -> Result<Config> {
        let globs = |patterns: &[String]| GlobList::new(patterns, Case::Sensitive);
        let mut governed_imports = file.exception_imports;
        governed_imports.extend(
            exceptions
                .iter()
                .flat_map(|entry| entry.packages.iter().cloned()),
        );
        governed_imports.sort();
        governed_imports.dedup();
        Ok(Config {
            scope: globs(scope)?,
            exclude: globs(&file.exclude)?,
            apps: globs(&file.apps)?,
            ui: globs(&file.ui)?,
            kit: globs(&file.kit)?,
            i18n: globs(&file.i18n)?,
            ui_only_imports: file.ui_only_imports,
            governed_imports,
            exceptions_path: file.exceptions,
            exceptions,
            kit_imports: file.kit_imports,
            icon_imports: file.icon_imports,
            patterns_path: file.patterns,
            patterns,
            accessor: file.accessor,
            mutation_hooks: file.mutation_hooks,
            shortcut_hooks: file.shortcut_hooks,
            confirmation_elements: file.confirmation_elements,
        })
    }

    pub fn covers(&self, path: &RepoPath) -> bool {
        self.scope.is_match(path.as_str()) && !self.exclude.is_match(path.as_str())
    }

    /// Whether the registry lets `path` import `package`.
    pub fn excepted(&self, path: &RepoPath, package: &str) -> bool {
        self.exceptions.iter().any(|entry| {
            entry.files.is_match(path.as_str())
                && (entry.packages.is_empty()
                    || entry.packages.iter().any(|named| named == package))
        })
    }
}

/// Whether `specifier` imports `package` or a subpath of it; `@scope/*` names a whole scope.
pub fn imports_package(specifier: &str, package: &str) -> bool {
    match package.strip_suffix("/*") {
        Some(scope) => specifier.starts_with(&format!("{scope}/")),
        None => specifier == package || specifier.starts_with(&format!("{package}/")),
    }
}

/// A pattern id or an export name in one comparable form: `approval-card`, `approval_card` and
/// `ApprovalCard` are the same.
pub fn normalise(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

/// The paths of every entry, at any depth, whose `skills` list `skill`.
fn scope_globs(table: &toml::Table, skill: &str) -> Vec<String> {
    let mut found = Vec::new();
    for entry in entries(table) {
        let loads = strings(entry, &[SKILL_KEY])
            .iter()
            .any(|name| name == skill);
        if loads {
            found.extend(strings(entry, SCOPE_KEYS));
        }
    }
    found
}

fn exception_entries(table: &toml::Table) -> Result<Vec<Exception>> {
    entries(table)
        .into_iter()
        .filter_map(|entry| {
            let files = strings(entry, FILE_KEYS);
            (!files.is_empty()).then(|| (strings(entry, PACKAGE_KEYS), files))
        })
        .map(|(packages, files)| {
            Ok(Exception {
                packages,
                files: GlobList::new(&files, Case::Sensitive)?,
            })
        })
        .collect()
}

fn pattern_ids(table: &toml::Table) -> BTreeSet<String> {
    let registry = PATTERN_TABLES.iter().find_map(|key| table.get(*key));
    let mut ids = BTreeSet::new();
    match registry {
        Some(toml::Value::Table(patterns)) => ids.extend(patterns.keys().map(|key| normalise(key))),
        Some(toml::Value::Array(items)) => {
            for item in items.iter().filter_map(toml::Value::as_table) {
                ids.extend(strings(item, ID_KEYS).iter().map(|id| normalise(id)));
            }
        }
        _ => ids.extend(table.keys().map(|key| normalise(key))),
    }
    ids
}

/// Every table in `table`, itself included, at any depth.
fn entries(table: &toml::Table) -> Vec<&toml::Table> {
    let mut found = vec![table];
    let mut stack: Vec<&toml::Value> = table.values().collect();
    while let Some(value) = stack.pop() {
        match value {
            toml::Value::Table(inner) => {
                found.push(inner);
                stack.extend(inner.values());
            }
            toml::Value::Array(items) => stack.extend(items.iter()),
            _ => {}
        }
    }
    found
}

/// The strings under the first of `keys` that `table` has, as one string or an array of them.
fn strings(table: &toml::Table, keys: &[&str]) -> Vec<String> {
    let Some(value) = keys.iter().find_map(|key| table.get(*key)) else {
        return Vec::new();
    };
    match value {
        toml::Value::String(one) => vec![one.clone()],
        toml::Value::Array(items) => items
            .iter()
            .filter_map(toml::Value::as_str)
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;

    pub(crate) const PATH_SKILLS: &str = "[[entry]]\nname = \"interface\"\nskills = [\"ui-architect\", \"frontend-design\"]\npaths = [\"web/**\", \"site/**\"]\n\n[[entry]]\nname = \"code\"\nskills = [\"grdr-structure\"]\npaths = [\"**/*.rs\"]\n";
    pub(crate) const EXCEPTIONS: &str = "[[exception]]\nneed = \"a combobox with async loading\"\nexit = \"replace when the component library ships one\"\nowner = \"lead-interfaces\"\npackages = [\"react-aria-components\"]\nfiles = [\"web/packages/ui/src/combo/Combo.tsx\"]\n";
    pub(crate) const PATTERNS: &str = "[pattern.approval-card]\nstates = [\"ready\"]\n";

    /// The shipped `quality/interface.toml` over the fixture registries.
    pub(crate) fn config() -> Config {
        let file: ConfigFile = parse_toml(
            include_str!("../../../../quality/interface.toml"),
            CONFIG_PATH,
        )
        .unwrap();
        let skills: toml::Table = toml::from_str(PATH_SKILLS).unwrap();
        let scope = scope_globs(&skills, &file.scope_skill);
        let exceptions = exception_entries(&toml::from_str(EXCEPTIONS).unwrap()).unwrap();
        let patterns = Some(pattern_ids(&toml::from_str(PATTERNS).unwrap()));
        Config::new(file, &scope, exceptions, patterns).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::config;
    use super::*;

    fn path(p: &str) -> RepoPath {
        RepoPath::new(p).unwrap()
    }

    #[test]
    fn scope_registries_and_package_matching() {
        let config = config();
        assert!(config.covers(&path("web/apps/console/src/Home.tsx")));
        assert!(config.covers(&path("site/src/theme/Footer.tsx")));
        assert!(!config.covers(&path("web/packages/i18n/src/generated/messages.ts")));
        assert!(!config.covers(&path("web/apps/console/src/Home.stories.tsx")));
        assert!(!config.covers(&path("crates/a/src/lib.rs")));
        assert_eq!(
            config.governed_imports,
            vec!["react-aria", "react-aria-components"]
        );
        assert!(config.excepted(
            &path("web/packages/ui/src/combo/Combo.tsx"),
            "react-aria-components"
        ));
        assert!(!config.excepted(&path("web/packages/ui/src/combo/Combo.tsx"), "react-aria"));
        assert!(
            config
                .patterns
                .as_ref()
                .unwrap()
                .contains(&normalise("ApprovalCard"))
        );
        assert!(imports_package(
            "@astryxdesign/react/button",
            "@astryxdesign/*"
        ));
        assert!(imports_package(
            "react-aria-components",
            "react-aria-components"
        ));
        assert!(!imports_package("react-aria-components", "react-aria"));
    }
}
