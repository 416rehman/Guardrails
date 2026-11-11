//! Who a session is and what it works on. The launcher sets `GRDR_AGENT`, `GRDR_WORK_ITEM` and
//! `GRDR_SCOPE` in the environment of the `claude` process; an agent cannot change its own hook
//! environment. `kit launch --item <n>` writes the issue's snapshot to `.agent/state/item-<n>.json`
//! (owner instruction 5); a missing snapshot means no item, so only protected-path and command
//! rules apply.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::globs::{Case, GlobList};
use crate::repo::{Repo, write_if_changed};

pub const SNAPSHOT_SCHEMA: &str = "item-snapshot.v1";
pub const AGENT_VARIABLE: &str = "GRDR_AGENT";
pub const WORK_ITEM_VARIABLE: &str = "GRDR_WORK_ITEM";
pub const SCOPE_VARIABLE: &str = "GRDR_SCOPE";
/// The model id the launcher chose, which may be opus for a sonnet-bound worker (team/01 section 9).
pub const LAUNCHER_MODEL_VARIABLE: &str = "GRDR_MODEL";
/// Every variable the launcher sets.
pub const IDENTITY_VARIABLES: [&str; 4] = [
    AGENT_VARIABLE,
    WORK_ITEM_VARIABLE,
    SCOPE_VARIABLE,
    LAUNCHER_MODEL_VARIABLE,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// The chief architect's first session: `.agents/kit/seed-scope.toml` widens its write scope.
    Seed,
    /// A protected-change lease (owner instruction 7): the item's write set may include protected paths.
    Protected,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Session {
    pub agent: Option<String>,
    pub work_item: Option<u64>,
    pub scope: Option<Scope>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RiskTier {
    Low,
    Medium,
    High,
}

/// The issue's `status:` label, or `closed` once the merged pull request closed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ItemStatus {
    Proposed,
    Ready,
    Leased,
    InReview,
    Blocked,
    Escalated,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemSnapshot {
    pub schema: String,
    /// The issue number, which is also the work-item id.
    pub number: u64,
    pub title: String,
    /// The roster name from the issue's `agent:` label.
    pub agent: String,
    pub kind: String,
    pub squad: Option<String>,
    pub size: Option<String>,
    pub risk_tier: RiskTier,
    pub trust_core: bool,
    pub write_set: Vec<String>,
    pub status: ItemStatus,
    /// SHA-256 of the acceptance-criteria section that the `ready.v1` comment named.
    pub acceptance_sha256: String,
    pub attempt: u32,
    pub fetched_at: String,
}

impl Scope {
    /// The `GRDR_SCOPE` value.
    pub fn name(self) -> &'static str {
        match self {
            Scope::Seed => "seed",
            Scope::Protected => "protected",
        }
    }
}

impl Session {
    pub fn from_env() -> Result<Session> {
        Session::from_lookup(|name| std::env::var(name).ok())
    }

    /// Unknown values are errors, so a hook fails closed instead of guessing a scope.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Session> {
        let present = |name: &str| {
            lookup(name)
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
        };
        let work_item = present(WORK_ITEM_VARIABLE)
            .map(|raw| parse_item_number(&raw))
            .transpose()?;
        let scope = match present(SCOPE_VARIABLE).as_deref() {
            None => None,
            Some("seed") => Some(Scope::Seed),
            Some("protected") => Some(Scope::Protected),
            Some(other) => bail!("{SCOPE_VARIABLE}={other} is not a scope (seed or protected)"),
        };
        Ok(Session {
            agent: present(AGENT_VARIABLE),
            work_item,
            scope,
        })
    }

    /// The snapshot of this session's item, when it has one and the launcher wrote it.
    pub fn item(&self, repo: &Repo) -> Result<Option<ItemSnapshot>> {
        match self.work_item {
            Some(number) => ItemSnapshot::load(repo, number),
            None => Ok(None),
        }
    }
}

impl ItemSnapshot {
    pub fn path(repo: &Repo, number: u64) -> PathBuf {
        repo.path(&ItemSnapshot::relative(number))
    }

    fn relative(number: u64) -> String {
        format!(".agent/state/item-{number}.json")
    }

    pub fn load(repo: &Repo, number: u64) -> Result<Option<ItemSnapshot>> {
        let path = ItemSnapshot::path(repo, number);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
        };
        let snapshot: ItemSnapshot =
            serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        if snapshot.schema != SNAPSHOT_SCHEMA || snapshot.number != number {
            bail!(
                "{} is not an {SNAPSHOT_SCHEMA} snapshot of issue #{number}",
                path.display()
            );
        }
        Ok(Some(snapshot))
    }

    /// Writes the snapshot into `repo`, never through a link out of it.
    pub fn save(&self, repo: &Repo) -> Result<()> {
        let mut json = serde_json::to_string_pretty(self)?;
        json.push('\n');
        repo.refuse_links(&ItemSnapshot::relative(self.number))?;
        write_if_changed(&ItemSnapshot::path(repo, self.number), json.as_bytes())?;
        Ok(())
    }

    pub fn write_set_globs(&self) -> Result<GlobList> {
        GlobList::new(&self.write_set, Case::Sensitive)
    }
}

/// `12` or `#12`.
pub fn parse_item_number(raw: &str) -> Result<u64> {
    let digits = raw.trim().strip_prefix('#').unwrap_or(raw.trim());
    match digits.parse::<u64>() {
        Ok(number) if number > 0 => Ok(number),
        _ => bail!("{WORK_ITEM_VARIABLE}={raw} is not an issue number"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let pairs: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |name| {
            pairs
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        }
    }

    #[test]
    fn session_from_environment() {
        let session = Session::from_lookup(env(&[
            ("GRDR_AGENT", "impl-rust"),
            ("GRDR_WORK_ITEM", "#42"),
        ]))
        .unwrap();
        assert_eq!(session.agent.as_deref(), Some("impl-rust"));
        assert_eq!(session.work_item, Some(42));
        assert_eq!(session.scope, None);
        let seed = Session::from_lookup(env(&[("GRDR_SCOPE", "seed")])).unwrap();
        assert_eq!(seed.scope, Some(Scope::Seed));
        assert_eq!(Session::from_lookup(env(&[])).unwrap(), Session::default());
    }

    #[test]
    fn bad_identity_values_fail_closed() {
        assert!(Session::from_lookup(env(&[("GRDR_SCOPE", "everything")])).is_err());
        assert!(Session::from_lookup(env(&[("GRDR_WORK_ITEM", "WI-0001")])).is_err());
        assert!(Session::from_lookup(env(&[("GRDR_WORK_ITEM", "0")])).is_err());
    }

    #[test]
    fn snapshot_round_trip() {
        let dir = std::env::temp_dir().join(format!("xtask-snapshot-{}", std::process::id()));
        let repo = Repo::at(&dir);
        let snapshot = ItemSnapshot {
            schema: SNAPSHOT_SCHEMA.into(),
            number: 7,
            title: "[WI-0001] Workspace".into(),
            agent: "impl-rust".into(),
            kind: "feature".into(),
            squad: Some("core".into()),
            size: Some("S".into()),
            risk_tier: RiskTier::High,
            trust_core: true,
            write_set: vec!["crates/**".into()],
            status: ItemStatus::Leased,
            acceptance_sha256: "ab".repeat(32),
            attempt: 1,
            fetched_at: "2026-11-11T10:00:00Z".into(),
        };
        assert_eq!(ItemSnapshot::load(&repo, 7).unwrap(), None);
        snapshot.save(&repo).unwrap();
        assert_eq!(
            ItemSnapshot::load(&repo, 7).unwrap(),
            Some(snapshot.clone())
        );
        assert!(
            snapshot
                .write_set_globs()
                .unwrap()
                .is_match("crates/grdr-core/src/lib.rs")
        );
        let text = std::fs::read_to_string(ItemSnapshot::path(&repo, 7)).unwrap();
        assert!(text.contains("\"status\": \"leased\""));
        assert!(ItemSnapshot::load(&repo, 8).unwrap().is_none());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
