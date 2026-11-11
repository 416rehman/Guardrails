//! Dependency changes in a manifest, for the `new_dependency` and `major_bump` triggers: the
//! dependency tables of `Cargo.toml` (`[dependencies]`, `[dev-dependencies]`,
//! `[build-dependencies]`, `[workspace.dependencies]` and their `[target.*]` forms) and of
//! `package.json`, before and after. A lockfile (`Cargo.lock`, `pnpm-lock.yaml`) is compared by
//! its packages: the `static` lane takes one whose packages gain no new name and no new major.

use std::collections::{BTreeMap, BTreeSet};

const CARGO_TABLES: &[&str] = &["dependencies", "dev-dependencies", "build-dependencies"];
const NPM_TABLES: &[&str] = &[
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DependencyChange {
    pub added: Vec<String>,
    pub major_bumps: Vec<String>,
}

/// What changed between two versions of the manifest at `path`; an unreadable one changes all.
pub fn compare(path: &str, before: Option<&str>, after: Option<&str>) -> DependencyChange {
    let read = |text: Option<&str>| match text {
        None => Some(BTreeMap::new()),
        Some(text) if path.ends_with("package.json") => npm(text),
        Some(text) => cargo(text),
    };
    let (Some(before), Some(after)) = (read(before), read(after)) else {
        return DependencyChange {
            added: vec![format!("{path} (unreadable)")],
            major_bumps: Vec::new(),
        };
    };
    let mut change = DependencyChange::default();
    for (name, version) in &after {
        match before.get(name) {
            None => change.added.push(name.clone()),
            Some(old) if major(old) != major(version) => change.major_bumps.push(name.clone()),
            Some(_) => {}
        }
    }
    change
}

/// Whether a lockfile change only moves packages it already had within their majors. A file that
/// does not parse, a new package name or a new major for a known one is not.
pub fn lockfile_within_majors(path: &str, before: Option<&str>, after: Option<&str>) -> bool {
    let read = |text: &str| {
        if path.ends_with(".yaml") || path.ends_with(".yml") {
            Some(pnpm_packages(text))
        } else {
            cargo_lock_packages(text)
        }
    };
    let (Some(before), Some(after)) = (before.and_then(read), after.and_then(read)) else {
        return false;
    };
    let known: BTreeSet<(&str, (String, String))> = before
        .iter()
        .map(|(name, version)| (name.as_str(), major(version)))
        .collect();
    !after.is_empty()
        && after
            .iter()
            .all(|(name, version)| known.contains(&(name.as_str(), major(version))))
}

pub fn is_manifest(path: &str) -> bool {
    path == "Cargo.toml"
        || path.ends_with("/Cargo.toml")
        || path == "package.json"
        || path.ends_with("/package.json")
}

fn cargo(text: &str) -> Option<BTreeMap<String, String>> {
    let table: toml::Table = toml::from_str(text).ok()?;
    let mut found = BTreeMap::new();
    collect_cargo(&table, "", &mut found);
    if let Some(workspace) = table.get("workspace").and_then(toml::Value::as_table) {
        collect_cargo(workspace, "workspace.", &mut found);
    }
    if let Some(targets) = table.get("target").and_then(toml::Value::as_table) {
        for (cfg, target) in targets {
            if let Some(target) = target.as_table() {
                collect_cargo(target, &format!("target.{cfg}."), &mut found);
            }
        }
    }
    Some(found)
}

fn collect_cargo(table: &toml::Table, scope: &str, found: &mut BTreeMap<String, String>) {
    for kind in CARGO_TABLES {
        let Some(dependencies) = table.get(*kind).and_then(toml::Value::as_table) else {
            continue;
        };
        for (name, spec) in dependencies {
            let version = match spec {
                toml::Value::String(version) => version.clone(),
                toml::Value::Table(spec) => spec
                    .get("version")
                    .and_then(toml::Value::as_str)
                    .map_or_else(|| spec.to_string(), str::to_owned),
                other => other.to_string(),
            };
            found.insert(format!("{scope}{kind}.{name}"), version);
        }
    }
}

fn npm(text: &str) -> Option<BTreeMap<String, String>> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let mut found = BTreeMap::new();
    for kind in NPM_TABLES {
        if let Some(dependencies) = value.get(*kind).and_then(serde_json::Value::as_object) {
            for (name, version) in dependencies {
                found.insert(
                    format!("{kind}.{name}"),
                    version.as_str().unwrap_or_default().to_owned(),
                );
            }
        }
    }
    Some(found)
}

/// `[[package]]` names and versions of a `Cargo.lock`.
fn cargo_lock_packages(text: &str) -> Option<Vec<(String, String)>> {
    let table: toml::Table = toml::from_str(text).ok()?;
    let packages = table.get("package")?.as_array()?;
    packages
        .iter()
        .map(|package| {
            let name = package.get("name")?.as_str()?;
            let version = package.get("version")?.as_str()?;
            Some((name.to_owned(), version.to_owned()))
        })
        .collect()
}

/// The package keys of a `pnpm-lock.yaml`'s `packages:` and `snapshots:` sections, such as
/// `'@scope/name@1.2.3':` or `name@1.2.3(peer@4.5.6):`, split into name and version.
fn pnpm_packages(text: &str) -> Vec<(String, String)> {
    let mut found = Vec::new();
    let mut inside = false;
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        if !line.starts_with(' ') {
            inside = matches!(line.trim_end(), "packages:" | "snapshots:");
            continue;
        }
        let Some(key) = line
            .strip_prefix("  ")
            .filter(|rest| !rest.starts_with(' '))
        else {
            continue;
        };
        if !inside {
            continue;
        }
        let key = key
            .split(": ")
            .next()
            .unwrap_or(key)
            .trim_end()
            .trim_end_matches(':')
            .trim_matches(['\'', '"']);
        let key = key.trim_start_matches('/');
        let plain = key.split('(').next().unwrap_or(key);
        let split = plain
            .char_indices()
            .filter(|(at, c)| *c == '@' && *at > 0)
            .map(|(at, _)| at)
            .next_back();
        if let Some(at) = split {
            let (name, version) = plain.split_at(at);
            found.push((name.to_owned(), version.trim_start_matches('@').to_owned()));
        }
    }
    found
}

/// The part of a version requirement a major bump changes: the first number, or the first two
/// while the first is zero.
fn major(requirement: &str) -> (String, String) {
    let numbers: Vec<&str> = requirement
        .trim_start_matches(|c: char| !c.is_ascii_digit())
        .split(|c: char| !c.is_ascii_digit())
        .take(2)
        .collect();
    let first = numbers.first().copied().unwrap_or_default().to_owned();
    let second = if first == "0" {
        numbers.get(1).copied().unwrap_or_default().to_owned()
    } else {
        String::new()
    };
    (first, second)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cargo_and_npm_dependencies() {
        let before = "[dependencies]\nserde = \"1.0\"\ntoml = { version = \"0.8\" }\n";
        let after = "[dependencies]\nserde = \"1.2\"\ntoml = { version = \"0.9\" }\nregex = \"1\"\n[target.'cfg(unix)'.dependencies]\nlibc = \"0.2\"\n";
        let change = compare("crates/a/Cargo.toml", Some(before), Some(after));
        assert_eq!(
            change.added,
            vec!["dependencies.regex", "target.cfg(unix).dependencies.libc"]
        );
        assert_eq!(change.major_bumps, vec!["dependencies.toml"]);
        let npm = compare(
            "web/package.json",
            Some("{\"dependencies\": {\"react\": \"^18.3.1\"}}"),
            Some(
                "{\"dependencies\": {\"react\": \"^19.0.0\"}, \"devDependencies\": {\"vitest\": \"3\"}}",
            ),
        );
        assert_eq!(npm.added, vec!["devDependencies.vitest"]);
        assert_eq!(npm.major_bumps, vec!["dependencies.react"]);
        assert_eq!(compare("Cargo.toml", Some("[x"), None).added.len(), 1);
        assert!(is_manifest("xtask/Cargo.toml"));
        assert!(!is_manifest("Cargo.lock"));
    }

    #[test]
    fn lockfiles_stay_static_only_within_known_majors() {
        let lock = |packages: &[(&str, &str)]| {
            packages
                .iter()
                .map(|(name, version)| {
                    format!("[[package]]\nname = \"{name}\"\nversion = \"{version}\"\n")
                })
                .collect::<String>()
        };
        let before = lock(&[("serde", "1.0.200"), ("toml", "0.8.1")]);
        let patch = lock(&[("serde", "1.0.228"), ("toml", "0.8.9")]);
        let minor_zero = lock(&[("serde", "1.0.228"), ("toml", "0.9.0")]);
        let added = lock(&[("serde", "1.0.228"), ("toml", "0.8.9"), ("regex", "1.0.0")]);
        assert!(lockfile_within_majors(
            "Cargo.lock",
            Some(&before),
            Some(&patch)
        ));
        assert!(!lockfile_within_majors(
            "Cargo.lock",
            Some(&before),
            Some(&minor_zero)
        ));
        assert!(!lockfile_within_majors(
            "Cargo.lock",
            Some(&before),
            Some(&added)
        ));
        assert!(!lockfile_within_majors(
            "Cargo.lock",
            Some("[x"),
            Some(&patch)
        ));
        assert!(!lockfile_within_majors("Cargo.lock", None, Some(&patch)));
        let pnpm = |react: &str| {
            format!(
                "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      react:\n        specifier: ^19\n\npackages:\n\n  '@types/node@22.1.0':\n    resolution: {{integrity: x}}\n\n  react@{react}:\n    resolution: {{integrity: y}}\n\nsnapshots:\n\n  react@{react}(scheduler@0.25.0): {{}}\n"
            )
        };
        assert!(lockfile_within_majors(
            "pnpm-lock.yaml",
            Some(&pnpm("19.0.0")),
            Some(&pnpm("19.1.0"))
        ));
        assert!(!lockfile_within_majors(
            "pnpm-lock.yaml",
            Some(&pnpm("19.0.0")),
            Some(&pnpm("20.0.0"))
        ));
        assert_eq!(
            pnpm_packages(&pnpm("19.0.0")),
            vec![
                ("@types/node".to_owned(), "22.1.0".to_owned()),
                ("react".to_owned(), "19.0.0".to_owned()),
                ("react".to_owned(), "19.0.0".to_owned()),
            ]
        );
    }
}
