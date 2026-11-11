//! Loaders for the kit sources under `.agents/` (team/03 section 1) and the per-session state the
//! launcher writes under `.agent/state/`. Each source has its own module; [`Kit`] loads them all.

pub mod egress;
pub mod hooks;
pub mod limits;
pub mod marketplace;
pub mod models;
pub mod permissions;
pub mod protected;
pub mod roster;
pub mod runtime;
pub mod session;
pub mod vendors;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::de::DeserializeOwned;

use crate::repo::Repo;

pub const AGENTS_DIR: &str = ".agents";

/// Every kit source, loaded and validated against its own format.
#[derive(Debug, Clone)]
pub struct Kit {
    pub models: models::Models,
    pub roster: roster::Roster,
    pub hooks: hooks::Hooks,
    pub permissions: permissions::PermissionsFile,
    pub protected: protected::ProtectedPaths,
    pub marketplace: marketplace::Marketplace,
    pub usage: runtime::Usage,
    pub harness: runtime::Harness,
    pub seed_scope: Option<protected::SeedScope>,
    pub vendors: Option<vendors::Vendors>,
    pub egress: Option<egress::Egress>,
}

impl Kit {
    pub fn load(repo: &Repo) -> Result<Kit> {
        Ok(Kit {
            models: models::Models::load(repo)?,
            roster: roster::Roster::load(repo)?,
            hooks: hooks::Hooks::load(repo)?,
            permissions: permissions::PermissionsFile::load(repo)?,
            protected: protected::ProtectedPaths::load(repo)?,
            marketplace: marketplace::Marketplace::load(repo)?,
            usage: runtime::Usage::load(repo)?,
            harness: runtime::Harness::load(repo)?,
            seed_scope: protected::SeedScope::load(repo)?,
            vendors: vendors::Vendors::load(repo)?,
            egress: egress::Egress::load(repo)?,
        })
    }
}

/// Parses a TOML file; the error names the file and the offending key.
pub fn read_toml<T: DeserializeOwned>(path: &Path, label: &str) -> Result<T> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {label}"))?;
    parse_toml(&text, label)
}

pub fn parse_toml<T: DeserializeOwned>(text: &str, label: &str) -> Result<T> {
    toml::from_str(text).with_context(|| format!("parsing {label}"))
}

/// `.agents/<relative>` as a root-relative label and a file system path.
pub fn agents_file(repo: &Repo, relative: &str) -> (String, PathBuf) {
    let label = format!("{AGENTS_DIR}/{relative}");
    let path = repo.path(&label);
    (label, path)
}
