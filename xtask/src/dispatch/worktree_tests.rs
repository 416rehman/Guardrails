//! A branchless worktree that cannot move to the fetched tip, a planner's or a routine's, is made
//! again there, and a routine whose worktree cannot be made does not stop the GitHub pass, so
//! planning, review and landing go on.

use std::path::PathBuf;

use super::assist_tests::{LEAD, OWNERS};
use super::landing_tests::with_origin;
use super::tests::{DONE, GARDEN_ROUTINE, Setup, settle};
use super::worker::{self, Launcher, Prepare, Upstream};
use crate::orchestrate::testkit::{git, issue};
use crate::testkit::TempRepo;

/// A lead for squad core and the base pushed to a bare `origin`, with `routines` in usage.toml.
fn planned_setup(routines: &str) -> (Setup, TempRepo) {
    let setup = Setup::new(routines);
    setup.temp.add_agents(LEAD);
    setup.temp.write(".agents/owners.toml", OWNERS);
    git(setup.temp.root(), &["add", "-A"]);
    git(
        setup.temp.root(),
        &["commit", "--quiet", "-m", "chore: owners"],
    );
    let origin = with_origin(&setup);
    (setup, origin)
}

/// The worktree `name` at the current tip, with `notes.md` left untracked in it; then a clone
/// lands its own `notes.md` on `main`. Returns the worktree and the new tip.
fn untracked_in_the_way(setup: &Setup, origin: &TempRepo, name: &str) -> (PathBuf, String) {
    let launcher = Launcher {
        program: setup.fake.program().to_path_buf(),
        leading: Vec::new(),
        prepare: Prepare::CopyOnly,
    };
    let upstream = Upstream {
        remote: "origin",
        base: "main",
    };
    let dir = worker::worktree(&setup.temp.repo(), name, None, &launcher, upstream).unwrap();
    std::fs::write(dir.join("notes.md"), "A draft the last run left.\n").unwrap();
    let other = TempRepo::create();
    let url = origin.root().to_string_lossy().into_owned();
    git(other.root(), &["clone", "--quiet", &url, "clone"]);
    let clone = other.root().join("clone");
    std::fs::write(clone.join("notes.md"), "Landed notes.\n").unwrap();
    git(&clone, &["add", "-A"]);
    git(&clone, &["commit", "--quiet", "-m", "docs: land the notes"]);
    git(&clone, &["push", "--quiet", "origin", "HEAD:main"]);
    let tip = git(&clone, &["rev-parse", "HEAD"]).trim().to_owned();
    (dir, tip)
}

#[test]
fn a_routine_worktree_in_the_way_of_the_tip_is_made_again_there() {
    let (setup, origin) = planned_setup(GARDEN_ROUTINE);
    let (dir, tip) = untracked_in_the_way(&setup, &origin, "routine-garden-docs");
    setup.tracker.add(issue(
        95,
        &["status:proposed", "squad:core"],
        "A gap a gardener filed.",
    ));
    setup.fake.respond(1, DONE, 0).respond(2, DONE, 0);
    let mut dispatcher = setup.dispatcher();
    let pass = dispatcher
        .step_github()
        .map_err(|error| format!("{error:#}"));
    settle(&mut dispatcher);
    let calls = setup.fake.calls();
    assert!(
        pass.is_ok()
            && calls.iter().any(|call| call.starts_with("garden-docs"))
            && calls
                .iter()
                .any(|call| call.contains("lead-core --item 95")),
        "pass: {pass:?}; calls: {calls:?}"
    );
    assert_eq!(git(&dir, &["rev-parse", "HEAD"]).trim(), tip);
    // Git checks the file out with the line ending its `core.autocrlf` asks for.
    assert_eq!(
        std::fs::read_to_string(dir.join("notes.md"))
            .unwrap()
            .trim_end(),
        "Landed notes."
    );
}

#[test]
fn a_planner_worktree_in_the_way_of_the_tip_is_made_again_there() {
    let (setup, origin) = planned_setup("");
    let (dir, tip) = untracked_in_the_way(&setup, &origin, "plan-lead-core");
    setup.tracker.add(issue(
        96,
        &["status:proposed", "squad:core"],
        "A gap a gardener filed.",
    ));
    setup.fake.respond(1, DONE, 0);
    let mut dispatcher = setup.dispatcher();
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    let calls = setup.fake.calls();
    assert!(
        calls
            .iter()
            .any(|call| call.contains("lead-core --item 96")),
        "{calls:?}"
    );
    assert_eq!(git(&dir, &["rev-parse", "HEAD"]).trim(), tip);
}

#[test]
fn a_routine_whose_worktree_cannot_be_made_does_not_stop_the_pass() {
    let (setup, _origin) = planned_setup(GARDEN_ROUTINE);
    let blocked = setup
        .temp
        .root()
        .join(".agent/worktrees/routine-garden-docs");
    std::fs::create_dir_all(blocked.parent().unwrap()).unwrap();
    std::fs::write(&blocked, "a file where the worktree goes\n").unwrap();
    setup.tracker.add(issue(
        97,
        &["status:proposed", "squad:core"],
        "A gap a gardener filed.",
    ));
    setup.fake.respond(1, DONE, 0);
    let mut dispatcher = setup.dispatcher();
    let pass = dispatcher
        .step_github()
        .map_err(|error| format!("{error:#}"));
    settle(&mut dispatcher);
    let calls = setup.fake.calls();
    assert!(
        pass.is_ok()
            && calls
                .iter()
                .any(|call| call.contains("lead-core --item 97")),
        "pass: {pass:?}; calls: {calls:?}"
    );
}
