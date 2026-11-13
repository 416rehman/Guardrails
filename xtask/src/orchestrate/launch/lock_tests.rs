//! The locks `kit launch` holds while a session runs: one fable session on the machine, and one
//! printed session of an agent on an item in a checkout. A launch a lock refuses exits with
//! `--busy-exit`, else `[launch] busy_exit`.

use super::locks::{FABLE_BUSY, busy_exit};
use super::tests::{plan_for, repo, tracker_with};
use super::*;
use crate::lock::{Busy, Lock};
use crate::orchestrate::testkit::FakeProgram;
use crate::testkit::TempRepo;

#[test]
fn a_printed_session_already_running_on_the_item_here_exits_with_the_busy_code() {
    let temp = repo();
    temp.write(
        ".agents/harness.toml",
        "[dispatch]\nprotected_change_agents = [\"lead-agent-kit\"]\n[launch]\nbusy_exit = 75\n",
    );
    let tracker = tracker_with(
        16,
        &["status:leased", "agent:impl-rust"],
        &["crates/grdr-core/**"],
    );
    let fake = FakeProgram::new("launch-busy-claude");
    let mut plan = plan_for(&temp, &tracker, "impl-rust", 16);
    plan.program = fake.program().to_path_buf();
    let beat = std::time::Duration::from_secs(30);
    let running = temp.repo().path(".agent/state/session-16-impl-rust.lock");
    let _running = Lock::take(running, beat, "the first session").unwrap();
    assert_eq!(start(&plan).unwrap(), ExitCode::from(75));
    assert!(fake.calls().is_empty(), "{:?}", fake.calls());
}

#[test]
fn a_launch_the_fable_lock_refuses_exits_with_the_busy_code() {
    let path = std::env::temp_dir().join(format!("xtask-fable-busy-{}.lock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let beat = std::time::Duration::from_secs(30);
    let held = Lock::take(path.clone(), beat, FABLE_BUSY).unwrap();
    let refused = Lock::take(path.clone(), beat, FABLE_BUSY).unwrap_err();
    drop(held);
    let _ = std::fs::remove_file(&path);
    let code = 75;
    assert_eq!(
        busy_exit(refused, Some(code)).unwrap(),
        ExitCode::from(code)
    );
    assert!(busy_exit(anyhow::anyhow!("claude is missing"), Some(code)).is_err());
    let temp = TempRepo::create();
    temp.write(".agents/harness.toml", "[launch]\nbusy_exit = 75\n");
    assert_eq!(
        harness_code(&temp.repo(), "launch", "busy_exit").unwrap(),
        Some(code)
    );
    temp.write(".agents/harness.toml", "[launch]\nbusy_exit = 300\n");
    assert!(harness_code(&temp.repo(), "launch", "busy_exit").is_err());
}

/// What `kit launch` with `args` asks for.
fn requested(args: &[&str]) -> Result<Request> {
    let args: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
    request_of(&cli::parse(&args, &SPEC)?)
}

/// The dispatcher's worktree is on the item's branch, whose harness.toml may predate
/// `[launch] busy_exit`; the code the dispatcher passes on the command line still comes back, and
/// a person's own launch there reports the refusal.
#[test]
fn a_launch_exits_with_the_busy_code_it_was_given_where_harness_toml_has_none() {
    let temp = repo();
    temp.write(
        ".agents/harness.toml",
        "[dispatch]\nprotected_change_agents = [\"lead-agent-kit\"]\n[launch]\n",
    );
    let tracker = tracker_with(
        17,
        &["status:leased", "agent:impl-rust"],
        &["crates/grdr-core/**"],
    );
    let fake = FakeProgram::new("launch-given-busy-claude");
    let kit = LaunchKit::load(&temp.repo()).unwrap();
    let launch = ["impl-rust", "--item", "17", "--print", "Work issue #17."];
    let given = requested(&[&launch[..], &["--busy-exit", "75"]].concat()).unwrap();
    let program = fake.program().to_path_buf();
    let plan_given = plan(&temp.repo(), &kit, &tracker, program.clone(), &given).unwrap();
    let own = requested(&launch).unwrap();
    let plan_own = plan(&temp.repo(), &kit, &tracker, program, &own).unwrap();
    let beat = std::time::Duration::from_secs(30);
    let running = session_lock_path(&temp.repo(), 17, "impl-rust");
    let _running = Lock::take(running, beat, "the first session").unwrap();
    assert_eq!(start(&plan_given).unwrap(), ExitCode::from(75));
    let refused = start(&plan_own).unwrap_err();
    assert!(refused.is::<Busy>(), "{refused:#}");
    assert!(fake.calls().is_empty(), "{:?}", fake.calls());
    assert!(requested(&[&launch[..], &["--busy-exit", "300"]].concat()).is_err());
}
