//! `.agents/kit/permissions.toml`: project-scope permissions, sandbox and settings for
//! `.claude/settings.json`, and the managed settings documents for the fleet (team/03 sections 4
//! and 8). Every key here is rendered, so an unknown key is an error rather than a silent drop.

use std::collections::BTreeMap;

use anyhow::Result;
use serde::Deserialize;

use crate::repo::Repo;

/// Modes Claude Code refuses from a project settings file.
pub const FORBIDDEN_PROJECT_MODES: &[&str] = &["auto", "bypassPermissions"];

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionsFile {
    pub permissions: Permissions,
    pub sandbox: Sandbox,
    pub settings: Settings,
    /// `[managed.<group>]`: one managed settings document per roster group, written in TOML with
    /// Claude Code's own key names. `kit render` adds the protected-path deny rules.
    #[serde(default)]
    pub managed: BTreeMap<String, toml::Table>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Permissions {
    pub default_mode: String,
    pub disable_bypass: Option<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub ask: Vec<String>,
    #[serde(default)]
    pub allow: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sandbox {
    pub enabled: bool,
    pub allow_unsandboxed_commands: bool,
    pub fail_if_unavailable: Option<bool>,
    #[serde(default)]
    pub deny_read: Vec<String>,
    #[serde(default)]
    pub allowed_domains: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// The JSON schema the rendered settings name in `$schema`.
    pub schema: Option<String>,
    /// The default model id for sessions in this repository.
    pub model: String,
    /// Names from models.toml.
    pub available_models: Vec<String>,
    pub auto_memory: bool,
    pub attribution_commit: String,
    pub attribution_pr: String,
    #[serde(default)]
    pub disable_workflows: bool,
    pub disable_auto_mode: Option<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

impl PermissionsFile {
    pub fn load(repo: &Repo) -> Result<PermissionsFile> {
        let (label, path) = super::agents_file(repo, "kit/permissions.toml");
        super::read_toml(&path, &label)
    }
}
