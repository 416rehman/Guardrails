//! Gate V23: every `SKILL.md` under `.agents/skills/` has valid front matter with only the
//! fields Claude Code reads, a name equal to its directory, and fewer lines than
//! `[gates.skills] max_lines`; project skills (`grdr-*`) also carry the licence and metadata of
//! team/03 section 3.

use anyhow::Result;

use crate::config::limits::SkillsLimits;
use crate::frontmatter::{self, FrontMatter};
use crate::paths::RepoPath;
use crate::repo::{Repo, walk_files};

pub const SKILLS_DIR: &str = ".agents/skills";
pub const ALLOWED_FIELDS: &[&str] = &[
    "name",
    "description",
    "license",
    "metadata",
    "allowed-tools",
    "disallowed-tools",
    "model",
    "effort",
    "context",
    "agent",
    "disable-model-invocation",
    "user-invocable",
    "hooks",
    "paths",
    "when_to_use",
];
const PROJECT_PREFIX: &str = "grdr-";
const PROJECT_METADATA: &[&str] = &["version", "owner", "requires", "closes-by"];

#[derive(Debug, Clone)]
pub struct SkillFile {
    pub path: RepoPath,
    pub directory: String,
    pub text: String,
}

impl SkillFile {
    /// The front-matter name, or the directory name when the front matter has none.
    pub fn name(&self) -> String {
        self.front_matter()
            .and_then(|front| front.value("name").map(str::to_owned))
            .unwrap_or_else(|| self.directory.clone())
    }

    pub fn front_matter(&self) -> Option<FrontMatter> {
        frontmatter::parse(&self.text).ok().flatten()
    }
}

/// Every `SKILL.md` below `.agents/skills/`, in path order.
pub fn skill_files(repo: &Repo) -> Result<Vec<SkillFile>> {
    let mut skills = Vec::new();
    for file in walk_files(&repo.path(SKILLS_DIR))? {
        if file.file_name().is_none_or(|name| name != "SKILL.md") {
            continue;
        }
        let Some(path) = repo.relative(&file) else {
            continue;
        };
        let directory = file
            .parent()
            .and_then(|dir| dir.file_name())
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let text = std::fs::read_to_string(&file)?;
        skills.push(SkillFile {
            path,
            directory,
            text,
        });
    }
    Ok(skills)
}

pub fn problems(repo: &Repo, limits: &SkillsLimits) -> Result<Vec<String>> {
    Ok(skill_files(repo)?
        .iter()
        .flat_map(|skill| lint(skill, limits))
        .collect())
}

pub fn lint(skill: &SkillFile, limits: &SkillsLimits) -> Vec<String> {
    let path = &skill.path;
    let mut problems = Vec::new();
    let lines = skill.text.lines().count();
    if lines >= limits.max_lines {
        problems.push(format!(
            "{path}: {lines} lines; keep a skill under {} and move detail to references/",
            limits.max_lines
        ));
    }
    let front = match frontmatter::parse(&skill.text) {
        Ok(Some(front)) => front,
        Ok(None) => {
            problems.push(format!("{path}: no front matter"));
            return problems;
        }
        Err(error) => {
            problems.push(format!("{path}: front matter: {error}"));
            return problems;
        }
    };
    for field in &front.fields {
        if !ALLOWED_FIELDS.contains(&field.key.as_str()) {
            problems.push(format!(
                "{path}:{}: unknown front-matter field `{}`",
                field.line, field.key
            ));
        }
    }
    match front.value("name") {
        Some(name) if name == skill.directory => {}
        Some(name) => problems.push(format!(
            "{path}: name `{name}` differs from its directory `{}`",
            skill.directory
        )),
        None => problems.push(format!("{path}: front matter has no `name`")),
    }
    problems.extend(description_problem(&front, path));
    if skill.directory.starts_with(PROJECT_PREFIX) {
        problems.extend(project_problems(&front, path));
    }
    problems
}

fn description_problem(front: &FrontMatter, path: &RepoPath) -> Option<String> {
    let Some(field) = front.get("description") else {
        return Some(format!("{path}: front matter has no `description`"));
    };
    if field.value.trim().is_empty() && field.block.is_empty() {
        return Some(format!("{path}: `description` is empty"));
    }
    let quoted = field.raw.starts_with(['"', '\'']);
    (!quoted && field.raw.contains(": ")).then(|| {
        format!(
            "{path}:{}: quote `description`; YAML reads `: ` inside it as a mapping",
            field.line
        )
    })
}

fn project_problems(front: &FrontMatter, path: &RepoPath) -> Vec<String> {
    let mut problems = Vec::new();
    if front.get("license").is_none() {
        problems.push(format!(
            "{path}: project skills carry `license: Apache-2.0`"
        ));
    }
    let keys = front
        .get("metadata")
        .map(|field| field.nested_keys())
        .unwrap_or_default();
    for key in PROJECT_METADATA
        .iter()
        .filter(|key| !keys.iter().any(|k| k == *key))
    {
        problems.push(format!(
            "{path}: `metadata` lacks `{key}` (team/03 section 3)"
        ));
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::limits::Limits;

    const GOOD: &str = "---
name: grdr-verify
description: Run the gates. Use before a hand-off.
license: Apache-2.0
metadata:
  version: \"1\"
  owner: agent-kit
  requires: K4
  closes-by: evidence
---

# Verify
";

    fn limits() -> &'static SkillsLimits {
        &Limits::built_with().unwrap().gates.skills
    }

    fn skill(directory: &str, text: &str) -> SkillFile {
        SkillFile {
            path: RepoPath::new(&format!(".agents/skills/{directory}/SKILL.md")).unwrap(),
            directory: directory.into(),
            text: text.into(),
        }
    }

    #[test]
    fn a_valid_project_skill_passes() {
        assert!(lint(&skill("grdr-verify", GOOD), limits()).is_empty());
        assert_eq!(skill("grdr-verify", GOOD).name(), "grdr-verify");
    }

    #[test]
    fn reports_each_problem() {
        let bad = "---
name: verify
description: Run: the gates
memory: project
---
";
        let problems = lint(&skill("grdr-verify", bad), limits());
        let joined = problems.join("\n");
        assert!(
            joined.contains("unknown front-matter field `memory`"),
            "{joined}"
        );
        assert!(joined.contains("differs from its directory"), "{joined}");
        assert!(joined.contains("quote `description`"), "{joined}");
        assert!(joined.contains("license"), "{joined}");
        assert!(joined.contains("`metadata` lacks `version`"), "{joined}");
    }

    #[test]
    fn long_skills_and_missing_front_matter_fail() {
        let long = format!("{GOOD}{}", "line\n".repeat(limits().max_lines));
        let expected = format!("lines; keep a skill under {}", limits().max_lines);
        assert!(lint(&skill("grdr-verify", &long), limits())[0].contains(&expected));
        assert_eq!(
            lint(&skill("vendor-skill", "# no front matter\n"), limits()).len(),
            1
        );
    }
}
