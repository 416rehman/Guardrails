//! `governance/governance.toml`: the required files and sections, the maintainer list's bot rules
//! and the human gates owner instruction 7 removed.

use anyhow::{Result, bail};
use serde::Deserialize;

use crate::git::{self, Base};
use crate::repo::Repo;

pub const RULES_PATH: &str = "governance/governance.toml";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rules {
    #[serde(rename = "file")]
    pub files: Vec<RequiredFile>,
    pub maintainers: MaintainerRules,
    #[serde(default, rename = "removed_gate")]
    pub removed_gates: Vec<RemovedGate>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredFile {
    pub path: String,
    /// The `## ` headings the file must hold.
    pub sections: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaintainerRules {
    pub path: String,
    /// The info string of the fenced block that holds the `[[maintainer]]` entries.
    pub language: String,
    pub bot_prefixes: Vec<String>,
    pub bot_suffixes: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemovedGate {
    pub phrase: String,
    /// What replaced the gate, quoted in the failure.
    pub removed: String,
}

impl Rules {
    /// The rules as the base commit has them, or the working tree's while the base has none.
    pub fn at(repo: &Repo, base: &Base) -> Result<Rules> {
        let (text, label) = git::read_at(repo, base, RULES_PATH)?;
        let Some(text) = text else {
            bail!(
                "{RULES_PATH} is missing; it lists the governance files governance-check requires"
            );
        };
        crate::config::parse_toml(&text, &label)
    }
}
