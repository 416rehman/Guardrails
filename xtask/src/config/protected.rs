//! `.agents/kit/protected-paths.toml` (team/05 section 5) and `.agents/kit/seed-scope.toml`, the
//! write scope of the chief architect's first session (team/06 section 14).

use anyhow::{Context, Result};
use serde::Deserialize;

use super::parse_toml;
use crate::git::{self, Base};
use crate::globs::{Case, GlobList};
use crate::repo::Repo;

pub const PROTECTED_PATHS_FILE: &str = ".agents/kit/protected-paths.toml";
pub const SEED_SCOPE_FILE: &str = ".agents/kit/seed-scope.toml";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedPaths {
    pub paths: Vec<String>,
}

/// The keys the gates need; the session launcher reads the rest (prompt, roles, commands).
#[derive(Debug, Clone, Deserialize)]
pub struct SeedScope {
    pub agent: String,
    pub scope: String,
    /// The branch the seed session commits on and hands off, which `kit launch --seed` checks
    /// out and `kit handoff` pushes.
    pub branch: String,
    pub max_turns: Option<u32>,
    pub prompt: Option<String>,
    pub paths: Vec<String>,
    #[serde(default)]
    pub commands: Vec<String>,
    /// The roles the seed session plays, whose readyings the dispatcher accepts from it.
    #[serde(default)]
    pub acts_as: Vec<String>,
}

impl ProtectedPaths {
    pub fn load(repo: &Repo) -> Result<ProtectedPaths> {
        ProtectedPaths::at(repo, &Base::Unborn)
    }

    /// The copy at `base` ([`git::read_at`]), so gate V05 never judges a change by paths the
    /// change itself set.
    pub fn at(repo: &Repo, base: &Base) -> Result<ProtectedPaths> {
        let (text, source) = git::read_at(repo, base, PROTECTED_PATHS_FILE)?;
        let text = text.with_context(|| format!("{source} is missing"))?;
        parse_toml(&text, &source)
    }

    /// Case-insensitive, so `cargo.toml` on Windows is still `Cargo.toml`.
    pub fn globs(&self) -> Result<GlobList> {
        GlobList::new(&self.paths, Case::Insensitive)
    }

    /// The permission rule that denies edits to one protected glob: `./` anchors a root path,
    /// a `**/` glob stays bare (team/03 section 4).
    pub fn edit_rules(&self) -> Vec<String> {
        self.paths
            .iter()
            .map(|path| {
                if path.starts_with("**/") {
                    format!("Edit({path})")
                } else {
                    format!("Edit(./{path})")
                }
            })
            .collect()
    }
}

impl SeedScope {
    pub fn load(repo: &Repo) -> Result<Option<SeedScope>> {
        SeedScope::at(repo, &Base::Unborn)
    }

    /// The copy at `base`, as [`ProtectedPaths::at`] reads its file.
    pub fn at(repo: &Repo, base: &Base) -> Result<Option<SeedScope>> {
        let (text, source) = git::read_at(repo, base, SEED_SCOPE_FILE)?;
        text.map(|text| parse_toml(&text, &source)).transpose()
    }

    pub fn globs(&self) -> Result<GlobList> {
        GlobList::new(&self.paths, Case::Sensitive)
    }

    /// Whether `agent` on `branch` is the seed session, as its lease names it.
    pub fn is_session(&self, agent: &str, branch: &str) -> bool {
        self.agent == agent && self.branch == branch
    }

    /// The roles `agent` plays in the seed session; none when it is not the seed's agent.
    pub fn roles_of(&self, agent: &str) -> &[String] {
        if self.agent == agent {
            &self.acts_as
        } else {
            &[]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edit_rules_anchor_root_paths() {
        let protected = ProtectedPaths {
            paths: vec!["Cargo.toml".into(), "**/*.snap".into(), ".claude/**".into()],
        };
        assert_eq!(
            protected.edit_rules(),
            vec![
                "Edit(./Cargo.toml)",
                "Edit(**/*.snap)",
                "Edit(./.claude/**)"
            ]
        );
        assert!(protected.globs().unwrap().is_match("CARGO.toml"));
    }
}
