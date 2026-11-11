//! `.agents/harness.toml [github]` and `[pull_request]`, as the hooks read them: the one
//! repository `gh` calls may name, the item branch pattern, the base branch the merge queue lands
//! on and the release branch prefixes no session pushes to (owner instructions 5, 7 and 26). All
//! are data; the hooks hold none of them.

use anyhow::{Result, bail};
use serde::Deserialize;

use crate::repo::Repo;

const HARNESS_FILE: &str = "harness.toml";
const ISSUE_PLACEHOLDER: &str = "{issue}";
const ATTEMPT_PLACEHOLDER: &str = "{attempt}";
const ISSUE_SHOWN: &str = "<issue>";
const ATTEMPT_SHOWN: &str = "<attempt>";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubSettings {
    /// `owner/name`.
    pub repository: String,
    /// The item branch, such as `agent/{issue}/a{attempt}`.
    pub branch: String,
    /// The branch pull requests target and the merge queue lands on.
    pub base: String,
    /// Prefixes of the release branches, which only release-please and the queue write.
    pub protected_prefixes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct GithubTable {
    repository: String,
    branch: String,
}

#[derive(Debug, Deserialize)]
struct PullRequestTable {
    base: String,
    protected_prefixes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct HarnessGithub {
    github: Option<GithubTable>,
    pull_request: Option<PullRequestTable>,
}

impl GithubSettings {
    pub fn load(repo: &Repo) -> Result<GithubSettings> {
        let (label, path) = crate::config::agents_file(repo, HARNESS_FILE);
        let file: HarnessGithub = crate::config::read_toml(&path, &label)?;
        let Some(github) = file.github else {
            bail!("{label} has no [github] table with `repository` and `branch`");
        };
        let Some(pull_request) = file.pull_request else {
            bail!("{label} has no [pull_request] table with `base` and `protected_prefixes`");
        };
        if !github.branch.contains(ISSUE_PLACEHOLDER)
            || !github.branch.contains(ATTEMPT_PLACEHOLDER)
        {
            bail!(
                "{label} [github] branch must name {ISSUE_PLACEHOLDER} and {ATTEMPT_PLACEHOLDER}"
            );
        }
        Ok(GithubSettings {
            repository: github.repository,
            branch: github.branch,
            base: pull_request.base,
            protected_prefixes: pull_request.protected_prefixes,
        })
    }

    /// The base and the release branches: only the merge queue and release-please write them.
    pub fn is_protected_branch(&self, branch: &str) -> bool {
        branch == self.base
            || self
                .protected_prefixes
                .iter()
                .any(|prefix| branch.starts_with(prefix.as_str()))
    }

    pub fn item_branch(&self, number: u64, attempt: u32) -> String {
        self.fill(&number.to_string(), &attempt.to_string())
    }

    /// The pattern with the issue filled in and `<attempt>` for the attempt, for messages.
    pub fn item_branch_pattern(&self, number: u64) -> String {
        self.fill(&number.to_string(), ATTEMPT_SHOWN)
    }

    /// The pattern with `<issue>` and `<attempt>`, for messages.
    pub fn any_item_branch(&self) -> String {
        self.fill(ISSUE_SHOWN, ATTEMPT_SHOWN)
    }

    /// Whether `branch` is issue `number`'s branch at any attempt.
    pub fn is_item_branch(&self, branch: &str, number: u64) -> bool {
        let filled = self.branch.replace(ISSUE_PLACEHOLDER, &number.to_string());
        let Some((prefix, suffix)) = filled.split_once(ATTEMPT_PLACEHOLDER) else {
            return false;
        };
        branch
            .strip_prefix(prefix)
            .and_then(|rest| rest.strip_suffix(suffix))
            .is_some_and(|attempt| {
                !attempt.is_empty() && attempt.chars().all(|c| c.is_ascii_digit())
            })
    }

    /// The fixed start of every agent branch, `agent/` for `agent/{issue}/a{attempt}`; a gardener
    /// without an item pushes `<namespace><agent>/<topic>`.
    pub fn namespace(&self) -> &str {
        self.branch
            .split_once('{')
            .map_or(self.branch.as_str(), |(namespace, _)| namespace)
    }

    fn fill(&self, issue: &str, attempt: &str) -> String {
        self.branch
            .replace(ISSUE_PLACEHOLDER, issue)
            .replace(ATTEMPT_PLACEHOLDER, attempt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn item_branches_follow_the_pattern() {
        let settings = GithubSettings {
            repository: "owner/name".into(),
            branch: "agent/{issue}/a{attempt}".into(),
            base: "trunk".into(),
            protected_prefixes: vec!["release/".into()],
        };
        assert!(settings.is_protected_branch("trunk"));
        assert!(settings.is_protected_branch("release/1.0"));
        assert!(!settings.is_protected_branch("main"));
        assert_eq!(settings.item_branch(7, 2), "agent/7/a2");
        assert!(settings.is_item_branch("agent/7/a12", 7));
        assert!(!settings.is_item_branch("agent/7/a", 7));
        assert!(!settings.is_item_branch("agent/8/a1", 7));
        assert!(!settings.is_item_branch("agent/7/a1x", 7));
        assert_eq!(settings.namespace(), "agent/");
        assert_eq!(settings.item_branch_pattern(7), "agent/7/a<attempt>");
        assert_eq!(settings.any_item_branch(), "agent/<issue>/a<attempt>");
    }

    #[test]
    fn the_table_is_required() {
        let temp = crate::testkit::TempRepo::create();
        temp.write(".agents/harness.toml", "[dispatch]\nmax_writers = 3\n");
        assert!(GithubSettings::load(&temp.repo()).is_err());
        temp.write(
            ".agents/harness.toml",
            "[github]\nrepository = \"owner/name\"\nbranch = \"agent/{issue}/a{attempt}\"\nissue_form = \"x\"\n",
        );
        assert!(GithubSettings::load(&temp.repo()).is_err());
        temp.write(
            ".agents/harness.toml",
            "[github]\nrepository = \"owner/name\"\nbranch = \"agent/{issue}/a{attempt}\"\nissue_form = \"x\"\n[pull_request]\nbase = \"main\"\nprotected_prefixes = []\n",
        );
        assert_eq!(
            GithubSettings::load(&temp.repo()).unwrap().repository,
            "owner/name"
        );
    }
}
