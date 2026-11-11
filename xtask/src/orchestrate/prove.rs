//! `cargo xtask prove --arm before|after|revert [--test <filter>] [--base <ref>]` (skill
//! `grdr-fix-bug`, D-47): the three-arm proof of a bug fix. `before` runs the new test on the
//! working tree before the fix and must fail; `after` runs it on the fixed tree and must pass;
//! `revert` checks the base commit out in a scratch worktree, brings over only the changed test
//! files, and must fail. Every arm lands in `.agent/evidence/prove.json` with its exit code, the
//! tests it ran, its log and the tree digest; the Stop gate reads that file. The test command is
//! `.agents/harness.toml [prove] command`, with the test paths and the test-count pattern beside
//! it; the code holds none of them.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::{Deserialize, Serialize};

use super::issue::sha256_hex;
use super::launch::HARNESS_FILE;
use crate::cli::{self, Spec};
use crate::clock::Utc;
use crate::config::limits::Limits;
use crate::config::session::Session;
use crate::git::{self, Base};
use crate::globs::{Case, GlobList};
use crate::process::{self, Finished};
use crate::repo::{Repo, write_if_changed};

pub const EVIDENCE: &str = ".agent/evidence/prove.json";
const SCHEMA: &str = "prove.v1";
const TEST_PLACEHOLDER: &str = "{test}";
const SPEC: Spec = Spec {
    flags: &[],
    options: &["--arm", "--test", "--base"],
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arm {
    Before,
    After,
    Revert,
}

/// `[prove]` in harness.toml; every key is required.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProveConfig {
    pub command: Vec<String>,
    pub count_regex: String,
    pub test_paths: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ProveFile {
    prove: ProveConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArmResult {
    pub cmd: String,
    pub exit: i64,
    /// Tests the run reported, when its output says.
    pub tests: Option<u64>,
    pub holds: bool,
    pub tree_digest: String,
    pub log: String,
    pub sha256: String,
    pub at: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Arms {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fails_before: Option<ArmResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passes_after: Option<ArmResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fails_on_revert: Option<ArmResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    pub schema: String,
    pub id: String,
    pub item: Option<u64>,
    pub test: String,
    pub base: Option<String>,
    pub tree_digest: String,
    pub arms: Arms,
    pub holds: bool,
}

impl Arm {
    fn parse(text: &str) -> Result<Arm> {
        match text {
            "before" => Ok(Arm::Before),
            "after" => Ok(Arm::After),
            "revert" => Ok(Arm::Revert),
            other => bail!("--arm {other}: the arms are before, after and revert"),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Arm::Before => "before",
            Arm::After => "after",
            Arm::Revert => "revert",
        }
    }

    /// Before and revert must fail; after must pass; and the test must have run.
    fn holds(self, exit: i64, tests: Option<u64>) -> bool {
        let ran = tests != Some(0);
        match self {
            Arm::Before | Arm::Revert => exit != 0 && ran,
            Arm::After => exit == 0 && ran,
        }
    }
}

impl ProveConfig {
    pub fn load(repo: &Repo) -> Result<ProveConfig> {
        let text = repo
            .read_optional(HARNESS_FILE)?
            .with_context(|| format!("{HARNESS_FILE} is missing"))?;
        let file: ProveFile = crate::config::parse_toml(&text, HARNESS_FILE)
            .with_context(|| format!("reading [prove] in {HARNESS_FILE}"))?;
        Ok(file.prove)
    }
}

impl Arms {
    fn set(&mut self, arm: Arm, result: ArmResult) {
        let digest = result.tree_digest.clone();
        let stale =
            |slot: &Option<ArmResult>| slot.as_ref().is_some_and(|r| r.tree_digest != digest);
        if arm != Arm::Before {
            if stale(&self.passes_after) {
                self.passes_after = None;
            }
            if stale(&self.fails_on_revert) {
                self.fails_on_revert = None;
            }
        }
        match arm {
            Arm::Before => self.fails_before = Some(result),
            Arm::After => self.passes_after = Some(result),
            Arm::Revert => self.fails_on_revert = Some(result),
        }
    }

    fn all_hold(&self) -> bool {
        [
            &self.fails_before,
            &self.passes_after,
            &self.fails_on_revert,
        ]
        .iter()
        .all(|arm| arm.as_ref().is_some_and(|result| result.holds))
    }
}

/// `prove`.
pub fn command(args: &[String]) -> Result<ExitCode> {
    let parsed = cli::parse(args, &SPEC)?;
    let arm = Arm::parse(
        parsed
            .value("--arm")
            .context("usage: cargo xtask prove --arm before|after|revert [--test <filter>]")?,
    )?;
    let repo = Repo::discover()?;
    let base = git::base_for(&repo, parsed.value("--base"))?;
    let item = Session::from_env()?.work_item;
    let proof = prove(
        &repo,
        &ProveConfig::load(&repo)?,
        arm,
        parsed.value("--test"),
        &base,
        item,
    )?;
    let result = match arm {
        Arm::Before => proof.arms.fails_before.as_ref(),
        Arm::After => proof.arms.passes_after.as_ref(),
        Arm::Revert => proof.arms.fails_on_revert.as_ref(),
    };
    let holds = result.is_some_and(|r| r.holds);
    if let Some(result) = result {
        println!(
            "prove {}: exit {}, {} tests, {}; log {}",
            arm.name(),
            result.exit,
            result
                .tests
                .map_or_else(|| "unknown".to_owned(), |n| n.to_string()),
            if holds { "holds" } else { "does not hold" },
            result.log
        );
    }
    println!(
        "prove: three arms {}; evidence {} ({EVIDENCE})",
        if proof.holds { "hold" } else { "incomplete" },
        proof.id
    );
    Ok(if holds {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}

/// Runs one arm and records it.
pub fn prove(
    repo: &Repo,
    config: &ProveConfig,
    arm: Arm,
    test: Option<&str>,
    base: &Base,
    item: Option<u64>,
) -> Result<Proof> {
    let revert_commit = match arm {
        Arm::Revert => Some(
            base.commit()
                .context("the revert arm needs a base commit; commit the seed first")?,
        ),
        Arm::Before | Arm::After => None,
    };
    let previous: Option<Proof> = repo
        .read_optional(EVIDENCE)?
        .and_then(|text| serde_json::from_str(&text).ok());
    let test = match (test, &previous) {
        (Some(test), _) => test.to_owned(),
        (None, Some(proof)) => proof.test.clone(),
        (None, None) => bail!("--test <filter> names the test on the first arm"),
    };
    let mut proof = match previous.filter(|p| p.test == test && p.item == item) {
        Some(proof) => proof,
        None => Proof {
            schema: SCHEMA.to_owned(),
            id: String::new(),
            item,
            test: test.clone(),
            base: base.commit().map(str::to_owned),
            tree_digest: String::new(),
            arms: Arms::default(),
            holds: false,
        },
    };
    let digest = git::tree_digest(repo)?;
    let stamp = Utc::now();
    let result = match revert_commit {
        Some(commit) => {
            let scratch = std::env::temp_dir().join(format!(
                "xtask-prove-{}-{}",
                std::process::id(),
                stamp.compact()
            ));
            let ran = with_reverted(repo, config, commit, &scratch, |dir| {
                run_arm(repo, config, arm, &test, dir, &digest, &stamp)
            });
            remove_worktree(repo, &scratch);
            ran?
        }
        None => run_arm(repo, config, arm, &test, repo.root(), &digest, &stamp)?,
    };
    proof.arms.set(arm, result);
    proof.tree_digest = digest;
    proof.holds = proof.arms.all_hold();
    proof.id = format!("prove-{}", stamp.compact());
    let mut json = serde_json::to_string_pretty(&proof)?;
    json.push('\n');
    write_if_changed(&repo.path(EVIDENCE), json.as_bytes())?;
    write_if_changed(
        &repo.path(&format!(".agent/evidence/{}.json", proof.id)),
        json.as_bytes(),
    )?;
    Ok(proof)
}

fn run_arm(
    repo: &Repo,
    config: &ProveConfig,
    arm: Arm,
    test: &str,
    dir: &Path,
    digest: &str,
    stamp: &Utc,
) -> Result<ArmResult> {
    let words: Vec<String> = config
        .command
        .iter()
        .map(|word| word.replace(TEST_PLACEHOLDER, test))
        .collect();
    let Some((program, args)) = words.split_first() else {
        bail!("[prove] command is empty");
    };
    let mut command = Command::new(process::program(program));
    command
        .args(args)
        .current_dir(dir)
        .env("CARGO_TARGET_DIR", repo.path("target"))
        .env("CARGO_TERM_COLOR", "never");
    let timeout = Limits::built_with()?.orchestrate.prove.run_timeout();
    let ran =
        process::run(&mut command, None, timeout).with_context(|| format!("starting {program}"))?;
    let output = format!("{}{}", ran.stdout(), ran.stderr());
    let exit = match ran.finished {
        Finished::Exited {
            code: Some(code), ..
        } => i64::from(code),
        Finished::Exited { code: None, .. } | Finished::TimedOut { .. } => -1,
    };
    let tests = count_tests(&config.count_regex, &output);
    let log = format!(".agent/logs/prove-{}-{}.log", arm.name(), stamp.compact());
    write_if_changed(&repo.path(&log), output.as_bytes())?;
    Ok(ArmResult {
        cmd: words.join(" "),
        exit,
        tests,
        holds: arm.holds(exit, tests),
        tree_digest: digest.to_owned(),
        log,
        sha256: sha256_hex(output.as_bytes()),
        at: stamp.iso(),
    })
}

/// Runs `body` in a worktree of `commit` that carries the working tree's changed test files.
fn with_reverted<T>(
    repo: &Repo,
    config: &ProveConfig,
    commit: &str,
    scratch: &Path,
    body: impl FnOnce(&Path) -> Result<T>,
) -> Result<T> {
    let target = scratch.to_string_lossy().into_owned();
    git::output(
        repo,
        &["worktree", "add", "--quiet", "--detach", &target, commit],
    )
    .context("creating the revert worktree")?;
    let tests = GlobList::new(&config.test_paths, Case::Sensitive)?;
    let base = Base::Commit {
        commit: commit.to_owned(),
        origin: git::BaseOrigin::Given(commit.to_owned()),
    };
    for path in git::changed_files(repo, &base)? {
        if !tests.is_match(path.as_str()) {
            continue;
        }
        let source = repo.path(path.as_str());
        let destination = path
            .as_str()
            .split('/')
            .fold(PathBuf::from(scratch), |dir, part| dir.join(part));
        if source.is_file() {
            if let Some(parent) = destination.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(&source, &destination).with_context(|| format!("copying {path}"))?;
        } else {
            let _ = std::fs::remove_file(&destination);
        }
    }
    body(scratch)
}

fn remove_worktree(repo: &Repo, scratch: &Path) {
    let target = scratch.to_string_lossy().into_owned();
    let _ = git::try_output(repo, &["worktree", "remove", "--force", &target]);
    let _ = std::fs::remove_dir_all(scratch);
    let _ = git::try_output(repo, &["worktree", "prune"]);
}

/// The sum of every count the output reports, or `None` when it reports none.
pub fn count_tests(pattern: &str, output: &str) -> Option<u64> {
    let regex = Regex::new(pattern).ok()?;
    let counts: Vec<u64> = regex
        .captures_iter(output)
        .filter_map(|captures| captures.get(1)?.as_str().parse().ok())
        .collect();
    (!counts.is_empty()).then(|| counts.iter().sum())
}

#[cfg(test)]
mod tests;
