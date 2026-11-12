//! `cargo xtask kit place [--stage] <path>...` (owner instruction 7): how a widened session, the
//! chief architect's seed session or a protected-change lease, writes the protected paths its
//! scope covers. kit render denies every protected path to the file tools in
//! `.claude/settings.json`, and no hook decision overrides a deny rule, so the session writes its
//! copy at `.agent/state/place/<path>` and this command puts it in place. It holds the session to
//! what guard-path holds it to: an agent identity, a scope that widens ([`allowance`]) and covers
//! the path, never the kit's own state, never through a link. `--stage` copies the current file
//! to the staging path first, so it can be edited there.

use std::fs;
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};

use crate::cli::{self, Spec};
use crate::config::session::Session;
use crate::gates::protected::allowance;
use crate::git::Base;
use crate::globs::GlobList;
use crate::hook::guard_path::{KitState, PLACE_DIR};
use crate::paths::{Located, RepoPath};
use crate::repo::Repo;

const SPEC: Spec = Spec {
    flags: &["--stage"],
    options: &[],
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// Copy the current file to its staging path.
    Stage,
    /// Move the staged copy into place.
    Place,
}

/// `kit place`.
pub fn command(args: &[String]) -> Result<ExitCode> {
    let parsed = cli::parse(args, &SPEC)?;
    if parsed.positional.is_empty() {
        bail!("usage: cargo xtask kit place [--stage] <path>...");
    }
    let step = if parsed.has("--stage") {
        Step::Stage
    } else {
        Step::Place
    };
    let repo = Repo::discover()?;
    let cwd = std::env::current_dir().context("reading the working directory")?;
    let scope = widened_scope(&repo, &Session::from_env()?)?;
    let targets = targets(&repo, &scope, &parsed.positional, &cwd)?;
    for target in &targets {
        println!("{}", run(&repo, step, target)?);
    }
    Ok(ExitCode::SUCCESS)
}

/// The globs this session may place: its seed or protected-change scope.
fn widened_scope(repo: &Repo, session: &Session) -> Result<GlobList> {
    let Some(agent) = session.agent.as_deref() else {
        bail!(
            "kit place is for an agent session whose scope widens what it writes; GRDR_AGENT is unset, so edit the file directly"
        );
    };
    match allowance(repo, &Base::Unborn, session, agent)? {
        Some(globs) => Ok(globs),
        None => bail!(
            "{agent}'s session has no seed scope and no protected-change lease, so it places nothing; ask for the change in the hand-off's protected_change_requests"
        ),
    }
}

/// Every path in `raw` as a repository path the scope covers; any other path refuses them all.
fn targets(repo: &Repo, scope: &GlobList, raw: &[String], cwd: &Path) -> Result<Vec<RepoPath>> {
    let kit_state = KitState::compile()?;
    let mut found = Vec::new();
    let mut refused = Vec::new();
    for written in raw {
        match repo.locate_through_links(written, Some(cwd)) {
            Ok(Located::Inside(path))
                if kit_state.is_kit_written(path.as_str()) || kit_state.is_draft(path.as_str()) =>
            {
                refused.push(format!("{path} is the kit's state or a draft under .agent/, which kit place never writes"));
            }
            Ok(Located::Inside(path)) if !scope.is_match(path.as_str()) => {
                refused.push(format!("{path} is outside this session's scope"));
            }
            Ok(Located::Inside(path)) => found.push(path),
            Ok(Located::Outside(absolute)) => {
                refused.push(format!("{absolute} is outside the repository"));
            }
            Err(error) => refused.push(format!("{written}: {error:#}")),
        }
    }
    if !refused.is_empty() {
        bail!("kit place placed nothing:\n{}", refused.join("\n"));
    }
    Ok(found)
}

/// One step for one path, and the line that reports it.
fn run(repo: &Repo, step: Step, target: &RepoPath) -> Result<String> {
    let staged_relative = format!("{PLACE_DIR}/{target}");
    let staged = repo.path(&staged_relative);
    let destination = repo.path(target.as_str());
    repo.refuse_links(target.as_str())?;
    repo.refuse_links(&staged_relative)?;
    match step {
        Step::Stage if !destination.is_file() => Ok(format!(
            "kit place: {target} does not exist yet; write it at {staged_relative}"
        )),
        Step::Stage => {
            copy(&destination, &staged)?;
            Ok(format!("kit place: staged {target} at {staged_relative}"))
        }
        Step::Place if !staged.is_file() => bail!(
            "{staged_relative} does not exist; write the new {target} there first (`kit place --stage {target}` copies the current one)"
        ),
        Step::Place => {
            copy(&staged, &destination)?;
            fs::remove_file(&staged).with_context(|| format!("removing {staged_relative}"))?;
            Ok(format!("kit place: placed {target}"))
        }
    }
}

fn copy(from: &Path, to: &Path) -> Result<()> {
    if let Some(parent) = to.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    fs::copy(from, to)
        .with_context(|| format!("copying {} to {}", from.display(), to.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::globs::Case;
    use crate::testkit::TempRepo;

    fn scope(globs: &[&str]) -> GlobList {
        GlobList::new(
            &globs.iter().map(|g| (*g).to_owned()).collect::<Vec<_>>(),
            Case::Sensitive,
        )
        .unwrap()
    }

    fn paths(temp: &TempRepo, written: &[&str]) -> Result<Vec<RepoPath>> {
        let raw: Vec<String> = written.iter().map(|p| (*p).to_owned()).collect();
        targets(
            &temp.repo(),
            &scope(&["AGENTS.md", "docs/decisions/ADR-0001-*.md"]),
            &raw,
            temp.root(),
        )
    }

    #[test]
    fn only_paths_the_scope_covers_are_placed() {
        let temp = TempRepo::create();
        let found = paths(&temp, &["AGENTS.md", "docs/decisions/ADR-0001-spine.md"]).unwrap();
        assert_eq!(found.len(), 2);
        let refused = paths(&temp, &["AGENTS.md", "limits.toml", "../elsewhere.md"])
            .unwrap_err()
            .to_string();
        assert!(
            refused.contains("limits.toml is outside this session's scope"),
            "{refused}"
        );
        assert!(refused.contains("outside the repository"), "{refused}");
        let state = targets(
            &temp.repo(),
            &scope(&[".agent/**"]),
            &[
                ".agent/state/item-7.json".to_owned(),
                ".agent/state/place/x".to_owned(),
            ],
            temp.root(),
        )
        .unwrap_err()
        .to_string();
        assert_eq!(
            state.matches("which kit place never writes").count(),
            2,
            "{state}"
        );
    }

    #[test]
    fn staging_copies_the_file_and_placing_moves_the_copy_back() {
        let temp = TempRepo::create();
        temp.write("AGENTS.md", "# old\n");
        let target = RepoPath::new("AGENTS.md").unwrap();
        let repo = temp.repo();
        assert!(
            run(&repo, Step::Stage, &target)
                .unwrap()
                .contains("staged AGENTS.md")
        );
        let staged = repo.path(".agent/state/place/AGENTS.md");
        assert_eq!(fs::read_to_string(&staged).unwrap(), "# old\n");
        fs::write(&staged, "# new\n").unwrap();
        assert_eq!(
            run(&repo, Step::Place, &target).unwrap(),
            "kit place: placed AGENTS.md"
        );
        assert_eq!(temp.repo().read("AGENTS.md").unwrap(), "# new\n");
        assert!(!staged.exists());
        let again = run(&repo, Step::Place, &target).unwrap_err().to_string();
        assert!(again.contains("does not exist"), "{again}");
        let fresh = RepoPath::new("docs/decisions/ADR-0001-spine.md").unwrap();
        assert!(
            run(&repo, Step::Stage, &fresh)
                .unwrap()
                .contains("does not exist yet")
        );
    }

    #[test]
    fn a_session_without_a_widened_scope_places_nothing() {
        let temp = TempRepo::create();
        let person = Session::default();
        assert!(
            widened_scope(&temp.repo(), &person)
                .unwrap_err()
                .to_string()
                .contains("GRDR_AGENT is unset")
        );
        let ordinary = Session {
            agent: Some("chief-architect".into()),
            work_item: None,
            scope: None,
        };
        let refused = widened_scope(&temp.repo(), &ordinary)
            .unwrap_err()
            .to_string();
        assert!(refused.contains("no seed scope"), "{refused}");
        temp.write(
            ".agents/kit/seed-scope.toml",
            "agent = \"chief-architect\"\nscope = \"seed\"\nbranch = \"agent/seed\"\npaths = [\"AGENTS.md\"]\n",
        );
        let seed = Session {
            scope: Some(crate::config::session::Scope::Seed),
            ..ordinary
        };
        assert!(
            widened_scope(&temp.repo(), &seed)
                .unwrap()
                .is_match("AGENTS.md")
        );
    }
}
