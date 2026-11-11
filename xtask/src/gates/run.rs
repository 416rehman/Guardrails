//! Running one step: its trigger, its builtin or command, and the packages the fast form builds.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};

use super::evidence::{GateResult, GateRun};
use super::plan::{Action, Builtin, Step};
use super::{
    Context, Form, Outcome, acceptance, commits, interface, models, pnpm, prose, protected, skills,
    structure,
};
use crate::config::limits::RunLimits;
use crate::globs::{Case, GlobList};
use crate::process::{self, Finished};
use crate::repo::Repo;

const WORKSPACE_FILES: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "rustfmt.toml",
    "clippy.toml",
    ".cargo/**",
];
const PACKAGES_PLACEHOLDER: &str = "{packages}";
const BASE_PLACEHOLDER: &str = "{base}";
const FAILURE_MARKERS: &[&str] = &["error", "Diff in", "FAILED", "panicked at", "warning:"];

enum Packages {
    Workspace,
    Touched(Vec<String>),
    Untouched,
}

pub fn step(step: &Step, context: &Context) -> GateRun {
    let started = Instant::now();
    let triggered = step.changed.as_ref().is_none_or(|globs| {
        context
            .changed
            .iter()
            .any(|path| globs.is_match(path.as_str()))
    });
    let (outcome, log) = match &step.action {
        _ if !triggered => (
            Outcome::skip("no changed path matches the step's trigger"),
            String::new(),
        ),
        Action::Builtin(builtin) => {
            let outcome = builtin_gate(*builtin, context).unwrap_or_else(|error| Outcome::Error {
                reason: format!("{error:#}"),
            });
            (outcome, String::new())
        }
        Action::Command(argv) => external(argv, step.timeout, context),
    };
    let result = GateResult {
        id: step.id.clone(),
        name: step.name.clone(),
        duration_ms: started.elapsed().as_millis(),
        outcome,
    };
    GateRun { result, log }
}

fn builtin_gate(builtin: Builtin, context: &Context) -> Result<Outcome> {
    match builtin {
        Builtin::KitCheck => Ok(Outcome::from_problems(crate::kit::check::kit_problems(
            &context.repo,
        )?)),
        Builtin::ModelRule => Ok(Outcome::from_problems(models::problems(&context.repo)?)),
        Builtin::SkillsLint => Ok(Outcome::from_problems(skills::problems(
            &context.repo,
            &context.limits.gates.skills,
        )?)),
        Builtin::Structure => {
            let report = structure::check_changed(
                &context.repo,
                &context.base,
                structure::Family::Structure,
            )?;
            let notes = report
                .warnings()
                .map(|finding| format!("warning {finding}"))
                .collect();
            let mut problems: Vec<String> = report.blocking().map(ToString::to_string).collect();
            if problems.is_empty() {
                return Ok(Outcome::Pass { notes });
            }
            problems.push(structure::SKILL_HINT.to_owned());
            Ok(Outcome::Fail { problems })
        }
        Builtin::ProtectedPaths => protected::gate(context),
        Builtin::Commits => commits::gate(context),
        Builtin::Prose => prose::gate(context),
        Builtin::HooksSelftest => Ok(Outcome::from_problems(crate::hook::selftest_problems()?)),
        Builtin::AcceptanceDigest => acceptance::gate(context),
        Builtin::Interface => interface::gate(context),
        Builtin::PackageManager => pnpm::gate(context),
    }
}

fn external(argv: &[String], timeout: Duration, context: &Context) -> (Outcome, String) {
    match expand(argv, context) {
        Ok(Some(expanded)) => command(
            &expanded,
            timeout,
            context.repo.root(),
            &context.limits.gates.run,
        ),
        Ok(None) => (Outcome::skip("no Rust package changed"), String::new()),
        Err(error) => (
            Outcome::Error {
                reason: format!("{error:#}"),
            },
            String::new(),
        ),
    }
}

/// The argv with its placeholders filled; `None` when the fast form has no package to build.
fn expand(argv: &[String], context: &Context) -> Result<Option<Vec<String>>> {
    let packages = if argv.iter().any(|arg| arg == PACKAGES_PLACEHOLDER) {
        Some(packages(context)?)
    } else {
        None
    };
    if let Some(Packages::Untouched) = packages {
        return Ok(None);
    }
    let mut expanded = Vec::new();
    for arg in argv {
        match (arg.as_str(), &packages) {
            (PACKAGES_PLACEHOLDER, Some(Packages::Touched(names))) => names
                .iter()
                .for_each(|name| expanded.extend(["-p".to_owned(), name.clone()])),
            (PACKAGES_PLACEHOLDER, _) => expanded.push("--workspace".to_owned()),
            (BASE_PLACEHOLDER, _) => match context.base.commit() {
                Some(commit) => expanded.push(commit.to_owned()),
                None => bail!("`{BASE_PLACEHOLDER}` needs a base commit and nothing is committed"),
            },
            (other, _) => expanded.push(other.to_owned()),
        }
    }
    Ok(Some(expanded))
}

fn command(
    argv: &[String],
    timeout: Duration,
    root: &Path,
    limits: &RunLimits,
) -> (Outcome, String) {
    let Some((program, args)) = argv.split_first() else {
        return (
            Outcome::Error {
                reason: "the step's command is empty".to_owned(),
            },
            String::new(),
        );
    };
    let mut command = Command::new(process::program(program));
    command
        .args(args)
        .current_dir(root)
        .env("CARGO_TERM_COLOR", "never");
    let ran = match process::run(&mut command, None, timeout) {
        Ok(ran) => ran,
        Err(error) => {
            return (
                Outcome::Error {
                    reason: format!("cannot start `{program}`: {error}"),
                },
                String::new(),
            );
        }
    };
    let output = format!("$ {}\n{}{}", argv.join(" "), ran.stdout(), ran.stderr());
    let outcome = match &ran.finished {
        Finished::Exited { code: Some(0), .. } => Outcome::Pass { notes: Vec::new() },
        Finished::Exited { .. } => Outcome::Fail {
            problems: vec![
                summarise(&output, limits.summary_chars).unwrap_or_else(|| ran.describe()),
            ],
        },
        Finished::TimedOut { .. } => Outcome::Fail {
            problems: vec![ran.describe()],
        },
    };
    (outcome, output)
}

/// Touched packages and their direct dependents, or the whole workspace when the full form runs
/// or a workspace-level file changed.
fn packages(context: &Context) -> Result<Packages> {
    if context.form == Form::Full {
        return Ok(Packages::Workspace);
    }
    let workspace_files = GlobList::new(WORKSPACE_FILES, Case::Sensitive)?;
    if context
        .changed
        .iter()
        .any(|path| workspace_files.is_match(path.as_str()))
    {
        return Ok(Packages::Workspace);
    }
    let metadata = cargo_metadata(&context.repo, context.limits.gates.run.metadata_timeout())?;
    let packages: Vec<&serde_json::Value> = metadata
        .get("packages")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .collect();
    let members: Vec<(&str, String)> = packages
        .iter()
        .filter_map(|package| {
            let manifest = Path::new(package.get("manifest_path")?.as_str()?);
            let dir = context.repo.relative(manifest.parent()?)?;
            Some((package.get("name")?.as_str()?, dir.to_string()))
        })
        .collect();
    let touched: BTreeSet<&str> = context
        .changed
        .iter()
        .filter_map(|path| {
            members
                .iter()
                .filter(|(_, dir)| dir.is_empty() || path.as_str().starts_with(&format!("{dir}/")))
                .max_by_key(|(_, dir)| dir.len())
                .map(|(name, _)| *name)
        })
        .collect();
    if touched.is_empty() {
        return Ok(Packages::Untouched);
    }
    let dependents = packages.iter().filter_map(|package| {
        let dependencies = package.get("dependencies")?.as_array()?;
        let local = |dependency: &serde_json::Value| dependency.get("path").is_some();
        let on_touched = dependencies.iter().any(|dependency| {
            local(dependency)
                && dependency
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|name| touched.contains(name))
        });
        on_touched
            .then(|| package.get("name").and_then(serde_json::Value::as_str))
            .flatten()
    });
    let selected: BTreeSet<&str> = touched.iter().copied().chain(dependents).collect();
    Ok(Packages::Touched(
        selected.into_iter().map(str::to_owned).collect(),
    ))
}

fn cargo_metadata(repo: &Repo, timeout: Duration) -> Result<serde_json::Value> {
    let mut command = Command::new(process::cargo());
    command
        .args([
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--locked",
            "--offline",
        ])
        .current_dir(repo.root());
    let ran = process::run(&mut command, None, timeout).context("starting cargo metadata")?;
    if !ran.success() {
        bail!("cargo metadata failed: {}", ran.stderr().trim());
    }
    serde_json::from_str(&ran.stdout()).context("parsing cargo metadata")
}

/// The first line of tool output that names the failure.
fn summarise(output: &str, width: usize) -> Option<String> {
    let line = output.lines().skip(1).map(str::trim).find(|line| {
        FAILURE_MARKERS
            .iter()
            .any(|marker| line.starts_with(marker))
    })?;
    Some(line.chars().take(width).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarise_finds_the_failure_line() {
        let width = crate::config::limits::Limits::built_with()
            .unwrap()
            .gates
            .run
            .summary_chars;
        let output = "$ cargo clippy\n   Compiling x\nerror: unused variable: `a`\n";
        assert_eq!(
            summarise(output, width).as_deref(),
            Some("error: unused variable: `a`")
        );
        assert_eq!(summarise("$ cargo fmt\nok\n", width), None);
    }
}
