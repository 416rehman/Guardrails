//! A writer's launch that its own session lock keeps refusing waits for the session that holds
//! the lock, which runs the item, so the wait counts against the lease. Once the wait uses the
//! lease while that session runs, the item escalates instead of starting another attempt beside
//! it. Once that session lets go, its hand-off decides what follows: review for a done hand-off
//! with its pull request open, and nothing for one that moved the issue. A refusal by another
//! lock, and a usage-limit pause between refusals, count nothing. A fable writer waiting while its
//! own session holds the lock counts that wait the same way.

use std::time::{Duration, Instant};

use super::{Dispatcher, Slot};
use crate::config::session::ItemStatus;
use crate::dispatch::assist_tests::{EVALUATORS, handoff};
use crate::dispatch::fable_tests::{failed_in_review, refused, two_writers};
use crate::dispatch::restart_tests::wait_for_calls;
use crate::dispatch::tests::{DONE, Setup, settle, transitions};
use crate::dispatch::worker;
use crate::lock::Lock;
use crate::orchestrate::launch::session_lock_path;
use crate::orchestrate::records::Reason;
use crate::orchestrate::tracker::{IssueEdit, Tracker};
use crate::repo::Repo;

/// Takes the session lock of `agent` on `item` in the item's attempt 1 worktree, as a session a
/// stopped dispatcher left running holds it.
fn left_running(setup: &Setup, item: u64, agent: &str) -> Lock {
    let name = worker::attempt_worktree(item, 1);
    let checkout = Repo::at(worker::worktree_dir(&setup.temp.repo(), &name));
    let path = session_lock_path(&checkout, item, agent);
    Lock::take(path, Duration::from_secs(30), "the session left running").unwrap()
}

/// Leaves two minutes on the lease of each paused slot and sets its first wait five minutes back.
fn nearly_used(dispatcher: &mut Dispatcher) {
    let (kit, factor) = (&dispatcher.kit, dispatcher.policy.lease_factor);
    for slot in &mut dispatcher.slots {
        if let Slot::Paused { held, .. } = slot {
            let clock = kit.wall_clock(&held.record.agent, held.size.as_deref(), held.caps);
            held.worked = clock.unwrap() * factor - Duration::from_secs(120);
            held.refused_at = Instant::now().checked_sub(Duration::from_secs(300));
        }
    }
}

/// Issue 70 leased, its launches all refused; after the first, its lease is nearly used. With
/// `hold_the_lock` the slot's session lock is held from before that refusal.
fn refused_once(setup: &Setup, hold_the_lock: bool) -> (Dispatcher<'_>, Option<Lock>) {
    setup.ready_issue(70, &[], "lead-core");
    for call in 1..=3 {
        refused(setup, call);
    }
    let mut dispatcher = setup.dispatcher();
    dispatcher.step_github().unwrap();
    let lock = hold_the_lock.then(|| left_running(setup, 70, "impl-rust"));
    settle(&mut dispatcher);
    nearly_used(&mut dispatcher);
    (dispatcher, lock)
}

fn pass(dispatcher: &mut Dispatcher) {
    dispatcher.step_github().unwrap();
    settle(dispatcher);
}

#[test]
fn a_launch_its_own_session_lock_keeps_refusing_escalates_once_the_wait_uses_the_lease() {
    let setup = Setup::new("");
    let (mut dispatcher, lock) = refused_once(&setup, true);
    pass(&mut dispatcher);
    pass(&mut dispatcher);
    drop(lock);
    assert_eq!(
        transitions(&setup.found(70)),
        vec![(ItemStatus::Escalated, Reason::LeaseExpired)]
    );
    let comments = setup.tracker.snapshot(70).comments;
    let [.., moved, packet] = comments.as_slice() else {
        panic!("{comments:?}");
    };
    let named = "still holds .agent/worktrees/70-a1/.agent/state/session-70-impl-rust.lock, so";
    assert!(moved.body.contains(named), "{}", moved.body);
    let root = setup.temp.root().to_string_lossy().into_owned();
    assert!(!moved.body.contains(&root), "{}", moved.body);
    assert!(
        packet.body.starts_with("### Escalation #70-E1"),
        "{}",
        packet.body
    );
    assert_eq!(setup.fake.calls().len(), 2, "{:?}", setup.fake.calls());
}

/// The session left running hands off done: its hand-off comment and an open pull request, with
/// issue 70 still leased, as `kit handoff` leaves it.
fn hand_off_done(setup: &Setup) {
    let done = handoff(70, "impl-rust", "done", "claude-sonnet-5-5");
    setup.tracker.comment(70, &done).unwrap();
    setup.tracker.open_pull_request_for("agent/70/a1", 700);
}

/// The session left running hands off blocked, which moves issue 70 to `status:blocked`.
fn hand_off_blocked(setup: &Setup) {
    let blocked = handoff(70, "impl-rust", "blocked", "claude-sonnet-5-5");
    setup.tracker.comment(70, &blocked).unwrap();
    let to_blocked = IssueEdit {
        add: vec!["status:blocked".into()],
        remove: vec!["status:leased".into()],
        assign_self: false,
    };
    setup.tracker.edit(70, &to_blocked).unwrap();
}

/// Launches of issue 70's worker, the evaluators' left out.
fn worker_calls(setup: &Setup) -> Vec<String> {
    let calls = setup.fake.calls();
    calls
        .into_iter()
        .filter(|call| call.starts_with("impl-rust --item 70"))
        .collect()
}

#[test]
fn a_done_hand_off_by_the_left_session_sends_the_item_to_review() {
    let setup = Setup::new("");
    setup.ready_issue(70, &[], "lead-core");
    refused(&setup, 1);
    setup.fake.respond(2, DONE, 0);
    let mut dispatcher = setup.dispatcher();
    dispatcher.step_github().unwrap();
    let lock = left_running(&setup, 70, "impl-rust");
    settle(&mut dispatcher);
    hand_off_done(&setup);
    drop(lock);
    dispatcher.resume_paused().unwrap();
    settle(&mut dispatcher);
    assert!(dispatcher.held().is_empty());
    assert_eq!(worker_calls(&setup).len(), 1, "{:?}", setup.fake.calls());
    assert_eq!(
        transitions(&setup.found(70)),
        vec![(ItemStatus::InReview, Reason::PullRequestOpen)]
    );
}

#[test]
fn a_done_hand_off_as_the_wait_uses_the_lease_sends_the_item_to_review() {
    let setup = Setup::new("");
    let (mut dispatcher, lock) = refused_once(&setup, true);
    pass(&mut dispatcher);
    hand_off_done(&setup);
    drop(lock);
    pass(&mut dispatcher);
    assert!(dispatcher.held().is_empty());
    assert_eq!(worker_calls(&setup).len(), 2, "{:?}", setup.fake.calls());
    // The same pass then reviews it, and this setup has no evaluators in its roster.
    let moved = transitions(&setup.found(70));
    assert_eq!(
        moved.first(),
        Some(&(ItemStatus::InReview, Reason::PullRequestOpen)),
        "{moved:?}"
    );
}

/// The left session lets go just as the slot's launch goes through, so the slot's own session
/// runs while the left one's hand-off is unjudged. After a usage-limit pause the slot continues
/// its own session, and that earlier hand-off sends nothing to review.
#[test]
fn a_usage_limit_pause_continues_the_slots_own_session_after_a_left_one() {
    let setup = Setup::new("");
    setup.ready_issue(70, &[], "lead-core");
    refused(&setup, 1);
    setup.fake.sleep(2, 60);
    let mut dispatcher = setup.dispatcher();
    dispatcher.step_github().unwrap();
    let lock = left_running(&setup, 70, "impl-rust");
    settle(&mut dispatcher);
    hand_off_done(&setup);
    // The fake takes no lock, as a launch that follows the left session's release does not wait.
    dispatcher.resume_paused().unwrap();
    drop(lock);
    wait_for_calls(&setup.fake, 2);
    dispatcher.pause_all().unwrap();
    dispatcher.resume_paused().unwrap();
    assert_eq!(dispatcher.held(), vec![70]);
    assert_eq!(transitions(&setup.found(70)), Vec::new());
}

#[test]
fn a_lease_used_after_the_left_session_handed_off_leaves_the_issue_where_the_hand_off_put_it() {
    let setup = Setup::new("");
    let (mut dispatcher, lock) = refused_once(&setup, true);
    pass(&mut dispatcher);
    hand_off_blocked(&setup);
    drop(lock);
    dispatcher.resume_paused().unwrap();
    assert!(dispatcher.held().is_empty());
    assert_eq!(transitions(&setup.found(70)), Vec::new());
    assert_eq!(setup.status(70), Some(ItemStatus::Blocked));
}

#[test]
fn a_refusal_by_another_lock_counts_nothing_against_the_lease() {
    let setup = Setup::new("");
    let (mut dispatcher, _) = refused_once(&setup, false);
    pass(&mut dispatcher);
    pass(&mut dispatcher);
    assert_eq!(transitions(&setup.found(70)), Vec::new());
}

#[test]
fn a_usage_limit_pause_between_refusals_counts_nothing_against_the_lease() {
    let setup = Setup::new("");
    let (mut dispatcher, lock) = refused_once(&setup, true);
    dispatcher.pause_all().unwrap();
    pass(&mut dispatcher);
    pass(&mut dispatcher);
    drop(lock);
    assert_eq!(transitions(&setup.found(70)), Vec::new());
}

/// Two chief-architect send-backs: 80's fix session runs, and 81's waits for it, while a session
/// left running holds 81's own session lock. That wait counts, and once it uses the lease 81
/// escalates.
#[test]
fn a_fable_writer_waiting_while_its_own_session_runs_escalates_once_the_wait_uses_the_lease() {
    let setup = Setup::new("[role.direction]\nmax_turns = 60\nwall_clock_minutes = 60\n");
    setup.temp.add_agents(EVALUATORS);
    two_writers(&setup);
    failed_in_review(&setup, 80);
    failed_in_review(&setup, 81);
    setup.fake.sleep(1, 60);
    let mut dispatcher = setup.dispatcher();
    let lock = left_running(&setup, 81, "chief-architect");
    dispatcher.step_github().unwrap();
    assert_eq!(dispatcher.held(), vec![80, 81]);
    nearly_used(&mut dispatcher);
    dispatcher.resume_paused().unwrap();
    assert_eq!(dispatcher.held(), vec![80]);
    // 80's fake records its call only once it starts, and dropping the dispatcher kills it.
    wait_for_calls(&setup.fake, 1);
    drop(dispatcher);
    drop(lock);
    assert_eq!(
        transitions(&setup.found(81)).last(),
        Some(&(ItemStatus::Escalated, Reason::LeaseExpired))
    );
    let calls = setup.fake.calls();
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert!(!calls[0].contains("--item 81"), "{calls:?}");
}
