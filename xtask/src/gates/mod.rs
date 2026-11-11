//! `cargo xtask verify [--fast | --ci] [--base <ref>] [--json <path>]` (team/05 section 3). The
//! steps come from `xtask/verify.toml` at the comparison base, so a change cannot relax the gate
//! that judges it. `--ci` runs only the CI-form steps, the ones that read GitHub (Q01). Output is
//! at most ten lines with one `ERROR <gate-id>` line per failed gate and the log path; the
//! evidence file records the command, exit code, duration and tree digest (team/03 section 1).
//! Exit 0 when every gate passed, 2 when one failed, 1 on an infrastructure error.

pub mod acceptance;
pub mod commits;
pub mod evidence;
pub mod interface;
pub mod models;
pub mod plan;
pub mod pnpm;
pub mod prose;
pub mod protected;
pub mod run;
pub mod skills;
pub mod structure;

pub use evidence::{EVIDENCE_DIR, EVIDENCE_SCHEMA, Evidence, GateResult, LOG_DIR};
pub use plan::{Action, Builtin, Step, VERIFY_TOML, load_plan, parse_plan};

use std::process::ExitCode;
use std::time::Instant;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::cli::{self, Spec};
use crate::clock::Utc;
use crate::config::limits::Limits;
use crate::config::session::Session;
use crate::git::{self, Base};
use crate::paths::{Located, RepoPath};
use crate::repo::Repo;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Form {
    Fast,
    Full,
    /// Steps that read GitHub, run in CI and the merge queue only.
    Ci,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum Outcome {
    Pass { notes: Vec<String> },
    Fail { problems: Vec<String> },
    Skip { reason: String },
    Error { reason: String },
}

/// What every gate may read: the repository, the form, the base, the branch diff and the kit's
/// limits as the base has them.
pub struct Context {
    pub repo: Repo,
    pub form: Form,
    pub base: Base,
    pub changed: Vec<RepoPath>,
    pub session: Session,
    pub limits: Limits,
}

impl Form {
    fn label(self) -> &'static str {
        match self {
            Form::Fast => "--fast",
            Form::Full => "full",
            Form::Ci => "--ci",
        }
    }
}

impl Outcome {
    pub fn from_problems(problems: Vec<String>) -> Outcome {
        if problems.is_empty() {
            Outcome::Pass { notes: Vec::new() }
        } else {
            Outcome::Fail { problems }
        }
    }

    pub fn skip(reason: impl Into<String>) -> Outcome {
        Outcome::Skip {
            reason: reason.into(),
        }
    }

    pub fn failed(&self) -> bool {
        matches!(self, Outcome::Fail { .. } | Outcome::Error { .. })
    }
}

pub fn verify_command(args: &[String]) -> Result<ExitCode> {
    let parsed = cli::parse(
        args,
        &Spec {
            flags: &["--fast", "--ci"],
            options: &["--base", "--json"],
        },
    )?;
    let form = match (parsed.has("--fast"), parsed.has("--ci")) {
        (true, true) => anyhow::bail!("--fast and --ci exclude each other"),
        (true, false) => Form::Fast,
        (false, true) => Form::Ci,
        (false, false) => Form::Full,
    };
    let repo = Repo::discover()?;
    if let Some(raw) = parsed.value("--json") {
        let cwd = std::env::current_dir()?;
        let inside = match repo.locate(raw, Some(&cwd)) {
            Located::Inside(path) => path.as_str().starts_with(".agent/"),
            Located::Outside(_) => false,
        };
        if !inside {
            anyhow::bail!(
                "--json {raw}: the copy goes under .agent/, never over a repository file"
            );
        }
    }
    let started = Instant::now();
    let stamp = Utc::now();
    let base = git::base_for(&repo, parsed.value("--base"))?;
    let tree_digest = git::tree_digest(&repo)?;
    let plan = load_plan(&repo, &base)?;
    let changed = git::changed_files(&repo, &base)?;
    let session = Session::from_env()?;
    let limits = Limits::load(&repo, &base)?;
    let context = Context {
        repo,
        form,
        base,
        changed,
        session,
        limits,
    };
    let runs: Vec<_> = plan
        .iter()
        .filter(|step| step.forms.contains(&form))
        .map(|step| run::step(step, &context))
        .collect();
    let id = format!("verify-{}-{}", stamp.compact(), std::process::id());
    let evidence = Evidence {
        schema: EVIDENCE_SCHEMA.to_owned(),
        log: format!("{LOG_DIR}/{id}.log"),
        id,
        command: format!("cargo xtask verify {}", args.join(" "))
            .trim_end()
            .to_owned(),
        exit_code: evidence::exit_code(&runs),
        duration_ms: started.elapsed().as_millis(),
        tree_digest,
        base: context.base.commit().map(str::to_owned),
        base_description: context.base.describe(),
        form,
        started_at: stamp.iso(),
        gates: runs.iter().map(|run| run.result.clone()).collect(),
    };
    evidence::write(&context.repo, &evidence, &runs, parsed.value("--json"))?;
    for line in evidence::summary_lines(&evidence) {
        println!("{line}");
    }
    Ok(ExitCode::from(evidence.exit_code))
}
