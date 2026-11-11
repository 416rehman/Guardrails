//! `.github/labels.toml` (owner instruction 5): the labels of the configured repository, their
//! groups and the status transitions. `cargo xtask labels sync [--dry-run]` creates and updates the
//! labels; `labels check` (or `sync --check`) exits 2 when GitHub differs. Labels GitHub has and the
//! file does not are reported and left alone.

use std::process::ExitCode;

use anyhow::{Context as _, Result, bail};
use serde::Deserialize;

use super::launch::owner_step_or;
use super::tracker::{GhTracker, RemoteLabel, Tracker};
use crate::cli::{self, Spec};
use crate::git::{self, Base};
use crate::github::{Gh, Mode};
use crate::globs::{Case, GlobList};
use crate::repo::Repo;

pub const LABELS_FILE: &str = ".github/labels.toml";
/// The `set_by` entry for whoever creates an issue, at creation only.
const FILER: &str = "filer";
const STATUS_PREFIX: &str = "status:";
const SPEC: Spec = Spec {
    flags: &["--check", "--dry-run"],
    options: &[],
};

#[derive(Debug, Clone, Default, Deserialize)]
pub struct LabelsFile {
    #[serde(default)]
    pub group: Vec<LabelGroup>,
    #[serde(default)]
    pub transition: Vec<LabelTransition>,
    #[serde(default)]
    pub label: Vec<LabelSpec>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct LabelGroup {
    pub prefix: Option<String>,
    #[serde(default)]
    pub names: Vec<String>,
    pub count: Option<String>,
    #[serde(default)]
    pub set_by: Vec<String>,
    /// The only label of the group a new issue may carry.
    pub filed_as: Option<String>,
    /// A label of the group may be raised, never removed or lowered.
    #[serde(default)]
    pub raise_only: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct LabelTransition {
    pub from: String,
    pub to: String,
    #[serde(default)]
    pub by: Vec<String>,
    #[serde(default)]
    pub run_by: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct LabelSpec {
    pub name: String,
    #[serde(default)]
    pub color: String,
    #[serde(default)]
    pub description: String,
}

/// How GitHub's labels differ from the file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Drift {
    pub missing: Vec<RemoteLabel>,
    pub changed: Vec<RemoteLabel>,
    pub extra: Vec<String>,
}

impl LabelsFile {
    pub fn load(repo: &Repo) -> Result<LabelsFile> {
        LabelsFile::at(repo, &Base::Unborn)
    }

    /// The copy at `base` ([`git::read_at`]), so gate Q01 never judges a readying by rules the
    /// change itself set.
    pub fn at(repo: &Repo, base: &Base) -> Result<LabelsFile> {
        let (text, source) = git::read_at(repo, base, LABELS_FILE)?;
        let text = text.with_context(|| format!("{source} is missing"))?;
        crate::config::parse_toml(&text, &source)
    }

    pub fn knows(&self, name: &str) -> bool {
        self.label.iter().any(|label| label.name == name)
    }

    /// The prefixes whose label an issue must carry once it is ready (`count = "one-when-ready"`).
    pub fn required_when_ready(&self) -> Vec<&str> {
        self.group
            .iter()
            .filter(|group| group.count.as_deref() == Some("one-when-ready"))
            .filter_map(|group| group.prefix.as_deref())
            .collect()
    }

    /// The group a label belongs to: a group naming it, else the group of its prefix.
    pub fn group_of(&self, name: &str) -> Option<&LabelGroup> {
        self.group
            .iter()
            .find(|group| group.names.iter().any(|known| known == name))
            .or_else(|| {
                self.group.iter().find(|group| {
                    group
                        .prefix
                        .as_deref()
                        .is_some_and(|prefix| name.starts_with(prefix))
                })
            })
    }

    /// Whether `agent` may move an issue from status `from` to `to` itself (its `by` roster
    /// globs); `kit` and `dispatcher` transitions run only through those commands.
    pub fn may_move(&self, from: &str, to: &str, agent: &str) -> Result<bool> {
        let strip = |name: &'_ str| name.strip_prefix(STATUS_PREFIX).unwrap_or(name).to_owned();
        let (from, to) = (strip(from), strip(to));
        let Some(transition) = self.find_transition(&from, &to) else {
            return Ok(false);
        };
        Ok(GlobList::new(&transition.by, Case::Sensitive)?.is_match(agent))
    }

    /// The agents that ready an item: the `run_by` of proposed to ready, plus the agent of a seed
    /// scope that acts as one of them (team/06 section 14). `kit ready` and the dispatcher's
    /// queue both use it, so a readying the kit posted is one the dispatcher accepts.
    pub fn may_ready(&self, agent: &str, acting_as: &[String]) -> Result<bool> {
        for role in std::iter::once(agent).chain(acting_as.iter().map(String::as_str)) {
            if self.may_run("proposed", "ready", role)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Whether `agent` may run the transition `from` to `to` (its `run_by` roster globs).
    pub fn may_run(&self, from: &str, to: &str, agent: &str) -> Result<bool> {
        let Some(transition) = self.find_transition(from, to) else {
            return Ok(false);
        };
        let allowed = GlobList::new(&transition.run_by, Case::Sensitive)?;
        Ok(allowed.is_match(agent))
    }

    fn find_transition(&self, from: &str, to: &str) -> Option<&LabelTransition> {
        self.transition
            .iter()
            .find(|transition| transition.from == from && transition.to == to)
    }
}

impl LabelGroup {
    /// Whether `agent` may add or remove a label of this group; `creating` admits the filer.
    pub fn may_set(&self, agent: &str, creating: bool) -> Result<bool> {
        if creating && self.set_by.iter().any(|entry| entry == FILER) {
            return Ok(true);
        }
        let agents: Vec<&String> = self.set_by.iter().filter(|entry| *entry != FILER).collect();
        Ok(GlobList::new(&agents, Case::Sensitive)?.is_match(agent))
    }

    pub fn is_status(&self) -> bool {
        self.prefix.as_deref() == Some(STATUS_PREFIX)
    }
}

impl Drift {
    pub fn is_empty(&self) -> bool {
        self.missing.is_empty() && self.changed.is_empty()
    }
}

/// `labels sync | check`.
pub fn command(args: &[String]) -> Result<ExitCode> {
    let parsed = cli::parse(args, &SPEC)?;
    let check = match parsed.positional.first().map(String::as_str) {
        Some("sync") => parsed.has("--check"),
        Some("check") => true,
        _ => bail!("usage: cargo xtask labels sync [--check] [--dry-run] | labels check"),
    };
    let repo = Repo::discover()?;
    let file = LabelsFile::load(&repo)?;
    let mode = if parsed.has("--dry-run") {
        Mode::DryRun
    } else {
        Mode::Live
    };
    let tracker = GhTracker::new(Gh::for_repo(&repo, mode)?);
    match sync(&tracker, &file, check) {
        Ok(code) => Ok(code),
        Err(error) => owner_step_or(error),
    }
}

pub fn sync(tracker: &dyn Tracker, file: &LabelsFile, check: bool) -> Result<ExitCode> {
    let drift = drift(file, &tracker.labels()?);
    for name in &drift.extra {
        println!("labels: {name} is on GitHub but not in {LABELS_FILE}; left alone");
    }
    if check {
        for label in &drift.missing {
            println!("ERROR labels: {} is missing on GitHub", label.name);
        }
        for label in &drift.changed {
            println!("ERROR labels: {} differs from {LABELS_FILE}", label.name);
        }
        return Ok(if drift.is_empty() {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(2)
        });
    }
    for label in &drift.missing {
        tracker.save_label(label, false)?;
    }
    for label in &drift.changed {
        tracker.save_label(label, true)?;
    }
    println!(
        "labels: {} created, {} updated, {} already right",
        drift.missing.len(),
        drift.changed.len(),
        file.label
            .len()
            .saturating_sub(drift.missing.len() + drift.changed.len())
    );
    Ok(ExitCode::SUCCESS)
}

pub fn drift(file: &LabelsFile, remote: &[RemoteLabel]) -> Drift {
    let mut drift = Drift::default();
    for wanted in &file.label {
        let label = RemoteLabel {
            name: wanted.name.clone(),
            color: wanted.color.trim_start_matches('#').to_ascii_lowercase(),
            description: wanted.description.clone(),
        };
        match remote.iter().find(|have| have.name == wanted.name) {
            None => drift.missing.push(label),
            Some(have)
                if have.color.to_ascii_lowercase() != label.color
                    || have.description != label.description =>
            {
                drift.changed.push(label);
            }
            Some(_) => {}
        }
    }
    drift.extra = remote
        .iter()
        .filter(|have| !file.knows(&have.name))
        .map(|have| have.name.clone())
        .collect();
    drift
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchestrate::testkit::MemoryTracker;

    const FILE: &str = "[[group]]\nprefix = \"tier:\"\ncount = \"one-when-ready\"\n\n[[group]]\nprefix = \"status:\"\ncount = \"one\"\n\n[[transition]]\nfrom = \"proposed\"\nto = \"ready\"\nby = [\"kit\"]\nrun_by = [\"lead-*\", \"programme-manager\"]\n\n[[label]]\nname = \"status:ready\"\ncolor = \"0e8a16\"\ndescription = \"Ready\"\n\n[[label]]\nname = \"tier:low\"\ncolor = \"C2E0C6\"\ndescription = \"Low\"\n";

    fn file() -> LabelsFile {
        crate::config::parse_toml(FILE, "labels.toml").unwrap()
    }

    #[test]
    fn transitions_and_groups_come_from_the_file() {
        let file = file();
        assert!(file.may_run("proposed", "ready", "lead-core").unwrap());
        assert!(
            file.may_run("proposed", "ready", "programme-manager")
                .unwrap()
        );
        assert!(!file.may_run("proposed", "ready", "impl-rust").unwrap());
        assert!(!file.may_run("ready", "leased", "lead-core").unwrap());
        assert_eq!(file.required_when_ready(), vec!["tier:"]);
    }

    #[test]
    fn sync_creates_missing_labels_and_updates_changed_ones() {
        let tracker = MemoryTracker::default();
        tracker.set_labels(vec![
            RemoteLabel {
                name: "tier:low".into(),
                color: "c2e0c6".into(),
                description: "Old".into(),
            },
            RemoteLabel {
                name: "bug".into(),
                color: "d73a4a".into(),
                description: String::new(),
            },
        ]);
        assert_eq!(sync(&tracker, &file(), true).unwrap(), ExitCode::from(2));
        assert!(tracker.calls().is_empty());
        assert_eq!(sync(&tracker, &file(), false).unwrap(), ExitCode::SUCCESS);
        assert_eq!(
            tracker.calls(),
            vec!["label create status:ready", "label edit tier:low"]
        );
        let drift = drift(&file(), &tracker.labels().unwrap());
        assert_eq!(drift.extra, vec!["bug"]);
    }
}
