//! `cargo xtask kit render | check | install` (team/03 section 1, K1 and K2). Other `kit`
//! subcommands belong to the orchestration module.

pub mod agents;
pub mod check;
pub mod claude_config;
pub mod egress;
pub mod gh_config;
pub mod install;
pub mod plugins;
pub mod render;
pub mod research;
pub mod settings;

use std::path::Path;
use std::process::ExitCode;

use anyhow::Result;

use crate::cli::{self, Spec};
use crate::clock::Utc;
use crate::config::Kit;
use crate::config::limits::Limits;
use crate::git;
use crate::repo::{Repo, write_if_changed};

pub const CHIEF_ARCHITECT: &str = "chief-architect";
/// Owner instruction 1, verbatim: the first line of the chief architect's body, its SessionStart
/// context on every source, and the first prompt of team/06 section 14.
pub const OWNERSHIP_SENTENCE: &str = "This codebase is yours: what it's for and how it's built are your call, and you'll keep building on it.";
const NO_ARGUMENTS: Spec = Spec {
    flags: &[],
    options: &[],
};

/// `kit render [--out <dir>]`: write the rendered tree into the repository, or into `dir` to inspect it.
pub fn render_command(args: &[String]) -> Result<ExitCode> {
    let parsed = cli::parse(
        args,
        &Spec {
            flags: &[],
            options: &["--out"],
        },
    )?;
    let repo = Repo::discover()?;
    let kit = Kit::load(&repo)?;
    let rendered = render::render(&repo, &kit)?;
    let summary = match parsed.value("--out") {
        Some(dir) => rendered.write_to(Path::new(dir))?,
        None => rendered.write(&repo)?,
    };
    println!(
        "kit render: {} written, {} unchanged, {} removed ({} files)",
        summary.written,
        summary.unchanged,
        summary.removed,
        rendered.files.len()
    );
    Ok(ExitCode::SUCCESS)
}

/// `kit check`: exit 2 with the problems when the rendered tree or the kit data is wrong.
pub fn check_command(args: &[String]) -> Result<ExitCode> {
    cli::parse(args, &NO_ARGUMENTS)?;
    let repo = Repo::discover()?;
    let limits = Limits::load(&repo, &git::resolve_base(&repo)?)?;
    let problems = check::all_problems(&repo, &limits)?;
    if problems.is_empty() {
        println!("kit check: the rendered tree matches the kit sources and the kit rules hold");
        return Ok(ExitCode::SUCCESS);
    }
    let log = format!(
        "{}/kit-check-{}.log",
        crate::gates::LOG_DIR,
        Utc::now().compact()
    );
    let mut text = problems.join("\n");
    text.push('\n');
    write_if_changed(&repo.path(&log), text.as_bytes())?;
    for problem in problems.iter().take(limits.kit.check.printed_problems) {
        let first_line = problem.lines().next().unwrap_or_default();
        println!("ERROR kit check: {first_line}");
    }
    println!("kit check: {} problems; full list in {log}", problems.len());
    Ok(ExitCode::from(2))
}

pub fn install_command(args: &[String]) -> Result<ExitCode> {
    cli::parse(args, &NO_ARGUMENTS)?;
    install::run(&Repo::discover()?)
}
