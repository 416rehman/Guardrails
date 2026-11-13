//! Every session the dispatcher starts is given the dispatcher's busy code, which `kit launch`
//! exits with when a lock refuses it. A session the dispatcher stops, at a stall for one, is
//! killed with its process tree, and the `kit launch` in it never lets go of its session lock;
//! the dispatcher empties that lock, so the session it starts again on the next pass is not
//! refused.

use std::process::ExitCode;
use std::time::Duration;

use super::assist_tests::{EVALUATORS, handoff};
use super::dispatcher::Dispatcher;
use super::landing_tests::to_review;
use super::policy::Policy;
use super::restart_tests::wait_for_calls;
use super::tests::{BUSY_EXIT, GARDEN_ROUTINE, Setup, settle, transitions};
use super::worker::{self, Launcher, Prepare};
use crate::config::session::ItemStatus;
use crate::orchestrate::launch::{ModelChoice, Plan, session_lock_path, start};
use crate::orchestrate::tracker::Tracker;
use crate::repo::Repo;

/// The test name of `kit_launch_stand_in`, which a launcher runs alone with `--exact`.
const STAND_IN: &str = "dispatch::kill_tests::kit_launch_stand_in";
/// Marks the arguments after it as the stand-in's: the fake program, then `kit launch`'s own.
const STAND_IN_ARGS: &str = "--kit-launch-stand-in";

/// Stands in for `kit launch` when a launcher runs this test binary alone with `STAND_IN_ARGS`,
/// the fake program and `kit launch`'s arguments after `--`: it runs the fake with those
/// arguments under the session lock the real launch takes, and fails when that lock refuses it.
/// Run any other way, it does nothing.
#[test]
fn kit_launch_stand_in() {
    let args: Vec<String> = std::env::args().collect();
    let Some(at) = args.iter().position(|arg| arg == STAND_IN_ARGS) else {
        return;
    };
    let fake = &args[at + 1];
    let launch = args[at + 2..].to_vec();
    let item = launch
        .iter()
        .position(|arg| arg == "--item")
        .map(|index| launch[index + 1].parse::<u64>().unwrap())
        .unwrap();
    let checkout = Repo::at(std::env::current_dir().unwrap());
    let session_lock = session_lock_path(&checkout, item, &launch[0]);
    let plan = Plan {
        program: fake.into(),
        args: launch,
        stdin: None,
        env: Vec::new(),
        unset: Vec::new(),
        model: ModelChoice {
            name: "sonnet".into(),
            id: "claude-sonnet-5-5".into(),
            raised_for: None,
        },
        turns: 0,
        effort: None,
        snapshot: None,
        busy_exit: None,
        session_lock: Some(session_lock),
    };
    assert_eq!(start(&plan).unwrap(), ExitCode::SUCCESS);
}

/// A writer, its evaluators and a routine, launched by a dispatcher whose busy code is not
/// harness.toml's: each launch is given the dispatcher's, the code `kit launch` exits with in a
/// worktree whose harness.toml has no `[launch] busy_exit`.
#[test]
fn every_launch_is_given_the_dispatchers_busy_code() {
    let setup = Setup::new(GARDEN_ROUTINE);
    setup.temp.add_agents(EVALUATORS);
    let path = setup.temp.repo().path(".agents/harness.toml");
    let harness = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, harness.replace(BUSY_EXIT, "busy_exit = 76\n")).unwrap();
    let mut dispatcher = to_review(&setup, 7, "lib.rs");
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    let calls = setup.fake.calls();
    for launch in [
        "impl-rust --item 7",
        "eval-tier --item 7",
        "garden-docs --print",
    ] {
        assert!(
            calls.iter().any(|call| call.starts_with(launch)),
            "{launch}: {calls:?}"
        );
    }
    assert!(
        calls.iter().all(|call| call.ends_with("--busy-exit 76")),
        "{calls:?}"
    );
}

/// A dispatcher whose sessions run under the stand-in and stall after a second without output.
fn stalling_under_the_stand_in(setup: &Setup) -> Dispatcher<'_> {
    let fake = setup.fake.program().to_string_lossy().into_owned();
    let launcher = Launcher {
        program: std::env::current_exe().unwrap(),
        leading: ["--exact", STAND_IN, "--", STAND_IN_ARGS, fake.as_str()]
            .map(str::to_owned)
            .to_vec(),
        prepare: Prepare::CopyOnly,
    };
    let mut policy = Policy::load(&setup.temp.repo(), None).unwrap();
    policy.session.stall = Duration::from_secs(1);
    Dispatcher::new(setup.temp.repo(), policy, &setup.tracker, launcher).unwrap()
}

#[test]
fn a_stalled_evaluator_is_started_again_on_the_next_pass() {
    let setup = Setup::new("");
    setup.temp.add_agents(EVALUATORS);
    drop(to_review(&setup, 97, "lib.rs"));
    setup.fake.sleep(2, 20);
    let mut dispatcher = stalling_under_the_stand_in(&setup);
    dispatcher.step_github().unwrap();
    // Polling starts once the fake runs, so the stall kills the stand-in after it took the lock.
    wait_for_calls(&setup.fake, 2);
    settle(&mut dispatcher);
    let worktree = Repo::at(worker::worktree_dir(&setup.temp.repo(), "97-a1"));
    let lock = session_lock_path(&worktree, 97, "eval-tier");
    assert_eq!(
        std::fs::read_to_string(&lock).unwrap(),
        "",
        "the killed session's lock still names it"
    );
    dispatcher.step_github().unwrap();
    wait_for_calls(&setup.fake, 3);
    setup
        .tracker
        .comment(97, &handoff(97, "eval-tier", "pass", "claude-sonnet-5-5"))
        .unwrap();
    settle(&mut dispatcher);
    let calls = setup.fake.calls();
    assert!(
        calls.len() == 3 && calls[2].contains("eval-tier --item 97"),
        "{calls:?}"
    );
    assert_eq!(
        setup.status(97),
        Some(ItemStatus::InReview),
        "{:?}",
        transitions(&setup.found(97))
    );
}
