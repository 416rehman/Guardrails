//! `.agents/kit/path-skills.toml` (owner instruction 18, P14): which skills an agent loads, in
//! order, before it edits a matching path. `guard-path` names an entry's skills the first time a
//! session edits one of its paths, `SessionStart` lists the entries an item's write set touches,
//! and `stop-gate` records which skills the session loaded. A missing file means no entries.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context as _, Result};
use serde::Deserialize;

use crate::globs::{Case, GlobList};
use crate::repo::Repo;

pub const PATH_SKILLS_FILE: &str = ".agents/kit/path-skills.toml";
const MANIFEST: &str = "Cargo.toml";

#[derive(Debug, Clone, Default)]
pub struct PathSkills {
    entries: Vec<Entry>,
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub name: String,
    pub skills: Vec<String>,
    paths: Vec<String>,
    globs: GlobList,
    /// Crates whose `[package.metadata.grdr] renders` is one of these match wherever they live.
    renders: Vec<String>,
}

/// One glob of a write set, compiled, with the `renders` of the crate it is rooted in.
struct WriteGlob<'a> {
    text: &'a str,
    globs: GlobList,
    renders: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PathSkillsFile {
    #[serde(default)]
    entry: Vec<EntryFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryFile {
    name: String,
    skills: Vec<String>,
    #[serde(default)]
    paths: Vec<String>,
    crates_with: Option<CratesWith>,
    /// The same entry's paths in the content repository, whose kit reads them.
    #[serde(default)]
    content_repository_paths: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CratesWith {
    renders: Vec<String>,
}

impl PathSkills {
    pub fn load(repo: &Repo) -> Result<PathSkills> {
        match repo.read_optional(PATH_SKILLS_FILE)? {
            Some(text) => PathSkills::parse(&text),
            None => Ok(PathSkills::default()),
        }
    }

    pub fn parse(text: &str) -> Result<PathSkills> {
        let file: PathSkillsFile = crate::config::parse_toml(text, PATH_SKILLS_FILE)?;
        let entries = file
            .entry
            .into_iter()
            .map(|entry| {
                GlobList::new(&entry.content_repository_paths, Case::Sensitive)
                    .with_context(|| format!("{PATH_SKILLS_FILE}: entry `{}`", entry.name))?;
                let globs = GlobList::new(&entry.paths, Case::Sensitive)
                    .with_context(|| format!("{PATH_SKILLS_FILE}: entry `{}`", entry.name))?;
                Ok(Entry {
                    name: entry.name,
                    skills: entry.skills,
                    paths: entry.paths,
                    globs,
                    renders: entry
                        .crates_with
                        .map(|with| with.renders)
                        .unwrap_or_default(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(PathSkills { entries })
    }

    /// The entries whose paths or crates include `path`, in file order.
    pub fn matching(&self, repo: &Repo, path: &str) -> Vec<&Entry> {
        let parent = Path::new(path).parent().unwrap_or(Path::new(""));
        let renders = renders_at(repo, parent);
        self.entries
            .iter()
            .filter(|entry| {
                entry.globs.is_match(path)
                    || renders
                        .as_deref()
                        .is_some_and(|renders| entry.renders_include(renders))
            })
            .collect()
    }

    /// Every skill the file names, each once, in file order.
    pub fn skill_names(&self) -> Vec<String> {
        skills_of(&self.entries.iter().collect::<Vec<_>>())
    }

    /// The entries whose names are in `names`, in file order.
    pub fn named(&self, names: &BTreeSet<String>) -> Vec<&Entry> {
        self.entries
            .iter()
            .filter(|entry| names.contains(&entry.name))
            .collect()
    }

    /// The entries a write set may touch: a write-set glob inside an entry's paths, an entry path
    /// inside a write-set glob, or a glob rooted in a crate the entry names by `renders`.
    pub fn touched_by(&self, repo: &Repo, write_set: &[String]) -> Result<Vec<&Entry>> {
        let globs = write_set
            .iter()
            .map(|glob| {
                Ok(WriteGlob {
                    text: glob,
                    globs: GlobList::new(std::slice::from_ref(glob), Case::Sensitive)?,
                    renders: renders_at(repo, Path::new(&fixed_prefix(glob))),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(self
            .entries
            .iter()
            .filter(|entry| globs.iter().any(|glob| entry.touches(glob)))
            .collect())
    }
}

impl Entry {
    fn touches(&self, glob: &WriteGlob) -> bool {
        self.globs.is_match(glob.text)
            || self.paths.iter().any(|path| glob.globs.is_match(path))
            || glob
                .renders
                .as_deref()
                .is_some_and(|renders| self.renders_include(renders))
    }

    fn renders_include(&self, renders: &str) -> bool {
        self.renders.iter().any(|named| named == renders)
    }
}

/// Each skill of `entries` once, in entry order.
pub fn skills_of(entries: &[&Entry]) -> Vec<String> {
    let mut seen = BTreeSet::new();
    entries
        .iter()
        .flat_map(|entry| entry.skills.iter())
        .filter(|skill| seen.insert(skill.as_str()))
        .cloned()
        .collect()
}

/// The directories of `glob` before its first wildcard.
pub(super) fn fixed_prefix(glob: &str) -> String {
    glob.split('/')
        .take_while(|segment| !segment.contains(['*', '?', '[', '{']))
        .collect::<Vec<_>>()
        .join("/")
}

/// `[package.metadata.grdr] renders` of the nearest package manifest at or above `dir`.
fn renders_at(repo: &Repo, dir: &Path) -> Option<String> {
    dir.ancestors()
        .filter(|ancestor| !ancestor.as_os_str().is_empty())
        .map(|ancestor| repo.root().join(ancestor).join(MANIFEST))
        .find(|manifest| manifest.is_file())
        .and_then(|manifest| std::fs::read_to_string(manifest).ok())
        .and_then(|text| text.parse::<toml::Table>().ok())
        .and_then(|table| {
            table
                .get("package")?
                .get("metadata")?
                .get("grdr")?
                .get("renders")?
                .as_str()
                .map(str::to_owned)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = r#"
[[entry]]
name = "web"
skills = ["ui-architect", "frontend-design:frontend-design", "grdr-interface"]
paths = ["web/**", "site/**"]

[[entry]]
name = "interface"
skills = ["ui-architect", "grdr-interface"]
paths = ["interface/**"]
crates_with = { renders = ["person", "agent"] }

[[entry]]
name = "translation"
skills = ["ui-architect"]
paths = ["docs/i18n/**"]
content_repository_paths = ["packs/*/messages/**"]

[[entry]]
name = "code"
skills = ["grdr-structure", "cleanup:cleanup"]
paths = ["crates/**", "**/*.ts", "**/*.tsx"]
"#;

    #[test]
    fn paths_and_crates_match_in_order() {
        let temp = crate::testkit::TempRepo::create();
        temp.write(
            "crates/grdr-term/Cargo.toml",
            "[package]\nname = \"grdr-term\"\n[package.metadata.grdr]\nrenders = \"person\"\n",
        );
        let repo = temp.repo();
        let skills = PathSkills::parse(FILE).unwrap();
        let names = |path: &str| {
            skills
                .matching(&repo, path)
                .iter()
                .map(|entry| entry.name.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(names("web/apps/console/src/App.tsx"), ["web", "code"]);
        assert_eq!(names("crates/grdr-term/src/lib.rs"), ["interface", "code"]);
        assert_eq!(names("crates/grdr-core/src/lib.rs"), ["code"]);
        assert!(names("README.md").is_empty());
        let web = skills.matching(&repo, "web/apps/console/src/App.tsx");
        assert_eq!(
            skills_of(&web),
            [
                "ui-architect",
                "frontend-design:frontend-design",
                "grdr-interface",
                "grdr-structure",
                "cleanup:cleanup"
            ]
        );
    }

    #[test]
    fn write_sets_touch_entries() {
        let temp = crate::testkit::TempRepo::create();
        let repo = temp.repo();
        let skills = PathSkills::parse(FILE).unwrap();
        let touched = |globs: &[&str]| {
            let globs: Vec<String> = globs.iter().map(|glob| (*glob).to_owned()).collect();
            skills
                .touched_by(&repo, &globs)
                .unwrap()
                .iter()
                .map(|entry| entry.name.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(touched(&["web/packages/ui/**"]), ["web"]);
        assert_eq!(touched(&["crates/grdr-core/**"]), ["code"]);
        assert_eq!(touched(&["**"]).len(), 4);
        assert!(touched(&["docs/design/**"]).is_empty());
    }

    #[test]
    fn the_kit_file_maps_the_owner_paths() {
        let temp = crate::testkit::TempRepo::create();
        let repo = temp.repo();
        let kit = PathSkills::parse(include_str!("../../../.agents/kit/path-skills.toml")).unwrap();
        let skills = |path: &str| skills_of(&kit.matching(&repo, path));
        let web = skills("web/apps/console/src/main.tsx");
        assert_eq!(web.first().map(String::as_str), Some("ui-architect"));
        assert!(web.contains(&"frontend-design:frontend-design".to_owned()));
        assert!(
            skills("web/extension/manifest.json")
                .contains(&"modern-web-guidance:chrome-extensions".to_owned())
        );
        for path in [
            "crates/grdr-core/src/lib.rs",
            "programs/grdr/Cargo.toml",
            "xtask/verify.toml",
        ] {
            assert!(
                skills(path).contains(&"cleanup:cleanup".to_owned()),
                "{path}"
            );
        }
        assert_eq!(
            skills("docs/team/03-skills-hooks-and-plugins.md"),
            ["anthropic-skills:write-like-a-normal-staff-senior-developer"]
        );
        assert!(
            kit.skill_names()
                .contains(&"modern-web-guidance:modern-web-guidance".to_owned())
        );
    }

    #[test]
    fn bad_files_fail_and_a_missing_one_is_empty() {
        assert!(PathSkills::parse("[[entry]]\nname = \"x\"\nskills = []\nglobs = []\n").is_err());
        assert!(
            PathSkills::parse("[[entry]]\nname = \"x\"\nskills = []\npaths = [\"a/[\"]\n").is_err()
        );
        let temp = crate::testkit::TempRepo::create();
        assert!(PathSkills::load(&temp.repo()).unwrap().entries.is_empty());
    }
}
