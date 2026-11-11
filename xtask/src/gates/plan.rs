//! `xtask/verify.toml`: one `[[step]]` per gate with its id, name, forms, trigger paths, timeout
//! and failing fixture (team/05 sections 2 and 3). A step runs a command or a builtin gate.

use std::collections::BTreeSet;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

use super::Form;
use crate::git::{self, Base};
use crate::globs::{Case, GlobList};
use crate::repo::Repo;

pub const VERIFY_TOML: &str = "xtask/verify.toml";

/// Gates implemented in this binary rather than by an external command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Builtin {
    KitCheck,
    ModelRule,
    SkillsLint,
    Structure,
    ProtectedPaths,
    Commits,
    Prose,
    HooksSelftest,
    AcceptanceDigest,
    Interface,
    PackageManager,
}

#[derive(Debug, Clone)]
pub enum Action {
    /// An argv; `{packages}` expands to the fast form's packages or `--workspace`, `{base}` to
    /// the base commit.
    Command(Vec<String>),
    Builtin(Builtin),
}

#[derive(Debug, Clone)]
pub struct Step {
    pub id: String,
    pub name: String,
    pub forms: Vec<Form>,
    pub changed: Option<GlobList>,
    pub timeout: Duration,
    pub action: Action,
    /// The fixture that proves the gate fails (team/05 section 2).
    pub fixture: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanFile {
    step: Vec<toml::Table>,
}

/// The keys every step has; `run` or `builtin` is taken out of the table first.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    id: String,
    name: String,
    forms: Vec<Form>,
    when: Option<When>,
    timeout_s: u64,
    fixture: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct When {
    changed: Vec<String>,
}

impl Step {
    fn from_table(mut table: toml::Table, index: usize) -> Result<Step> {
        let context = || format!("{VERIFY_TOML}: [[step]] {}", index + 1);
        let action = match (table.remove("run"), table.remove("builtin")) {
            (Some(run), None) => {
                let argv: Vec<String> = run.try_into().with_context(context)?;
                if argv.is_empty() {
                    bail!("{}: `run` is empty", context());
                }
                Action::Command(argv)
            }
            (None, Some(builtin)) => Action::Builtin(builtin.try_into().with_context(context)?),
            (Some(_), Some(_)) => bail!("{}: give `run` or `builtin`, not both", context()),
            (None, None) => bail!("{}: needs `run` or `builtin`", context()),
        };
        let header: Header = toml::Value::Table(table).try_into().with_context(context)?;
        let changed = header
            .when
            .map(|when| GlobList::new(&when.changed, Case::Sensitive))
            .transpose()
            .with_context(context)?;
        Ok(Step {
            id: header.id,
            name: header.name,
            forms: header.forms,
            changed,
            timeout: Duration::from_secs(header.timeout_s),
            action,
            fixture: header.fixture,
        })
    }
}

/// The steps as the base commit has them, or the working tree's copy while the base has none.
pub fn load_plan(repo: &Repo, base: &Base) -> Result<Vec<Step>> {
    let from_base = match base.commit() {
        Some(commit) => git::show(repo, commit, VERIFY_TOML)?,
        None => None,
    };
    let text = match from_base {
        Some(text) => text,
        None => repo.read(VERIFY_TOML)?,
    };
    parse_plan(&text)
}

pub fn parse_plan(text: &str) -> Result<Vec<Step>> {
    let file: PlanFile = crate::config::parse_toml(text, VERIFY_TOML)?;
    let steps: Vec<Step> = file
        .step
        .into_iter()
        .enumerate()
        .map(|(index, table)| Step::from_table(table, index))
        .collect::<Result<_>>()?;
    let mut ids = BTreeSet::new();
    for step in &steps {
        if !ids.insert(step.id.as_str()) {
            bail!("{VERIFY_TOML}: step id {} appears twice", step.id);
        }
    }
    Ok(steps)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_parses_command_and_builtin_steps() {
        let plan = parse_plan(
            "[[step]]\nid = \"V01\"\nname = \"format\"\nforms = [\"fast\", \"full\"]\nrun = [\"cargo\", \"fmt\"]\ntimeout_s = 60\n\n[[step]]\nid = \"V-structure\"\nname = \"structure\"\nforms = [\"fast\"]\nbuiltin = \"structure\"\nwhen = { changed = [\"**/*.rs\"] }\ntimeout_s = 60\n",
        )
        .unwrap();
        assert!(matches!(plan[0].action, Action::Command(_)));
        assert!(matches!(
            plan[1].action,
            Action::Builtin(Builtin::Structure)
        ));
        assert!(
            plan[1]
                .changed
                .as_ref()
                .unwrap()
                .is_match("xtask/src/main.rs")
        );
    }

    #[test]
    fn plan_rejects_unknown_keys_duplicates_and_missing_actions() {
        let step = "[[step]]\nid = \"V01\"\nname = \"f\"\nforms = [\"fast\"]\nrun = [\"x\"]\ntimeout_s = 1\n";
        assert!(parse_plan(&format!("{step}{step}")).is_err());
        assert!(parse_plan(&format!("{step}optional = true\n")).is_err());
        let unknown_builtin = "[[step]]\nid = \"V9\"\nname = \"b\"\nforms = [\"fast\"]\nbuiltin = \"nothing\"\ntimeout_s = 1\n";
        assert!(parse_plan(unknown_builtin).is_err());
        let neither = "[[step]]\nid = \"V9\"\nname = \"b\"\nforms = [\"fast\"]\ntimeout_s = 1\n";
        assert!(parse_plan(neither).is_err());
    }

    #[test]
    fn the_repository_plan_parses() {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/verify.toml")).unwrap();
        let plan = parse_plan(&text).unwrap();
        assert!(plan.iter().any(|step| step.id == "V20"));
        assert!(plan.iter().any(|step| step.id == "V18"));
        assert!(
            plan.iter()
                .any(|step| step.id == "Q01" && step.forms == vec![Form::Ci])
        );
    }
}
