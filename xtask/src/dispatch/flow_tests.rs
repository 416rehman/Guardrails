//! What keeps work moving past a fault or a wait: a session stopped as stalled after its hand-off
//! leaves the issue where the hand-off put it; a `status:leased` label with no `lease.v1` goes
//! back to where its lease starts, at once when the dispatcher's own grant failed and on a pass
//! otherwise; no deadline counts the time before the dispatcher started; and the pass after a
//! session's end is due at once.

use super::assist_tests::{EVALUATORS, LEAD, OWNERS};
use super::dispatcher::Dispatcher;
use super::fable_tests::refused;
use super::landing_tests::{CRITERIA, to_review};
use super::routines::{HOUR, now_unix};
use super::tests::{DONE, GARDEN_ROUTINE, Setup, leases, settle, transitions};
use crate::clock::Utc;
use crate::config::session::ItemStatus;
use crate::orchestrate::issue::{Comment, acceptance, status_label};
use crate::orchestrate::records::{
    LEASE_SCHEMA, Lease, Reason, STATE_SCHEMA, Transition, lease_comment, ready_comment,
    transition_comment,
};
use crate::orchestrate::testkit::{body, issue, ready_for};
use crate::orchestrate::tracker::{IssueEdit, Tracker};

/// Long before any test's dispatcher starts.
const LONG_AGO: &str = "2020-01-01T00:00:00Z";
const JOURNAL: &str = ".agent/logs/dispatch-usage.jsonl";

/// An issue with its status, the session its lease names, the records after the lease, and the
/// time every comment was posted.
struct Recorded<'a> {
    item: u64,
    status: ItemStatus,
    session: Option<&'a str>,
    history: &'a [String],
    at: &'a str,
}

fn statuses(setup: &Setup, item: u64) -> Vec<String> {
    setup
        .tracker
        .snapshot(item)
        .labels
        .iter()
        .map(|label| label.name.clone())
        .filter(|name| name.starts_with("status:"))
        .collect()
}

fn relabel(setup: &Setup, item: u64, from: &str, to: &str) {
    let edit = IssueEdit {
        add: vec![to.to_owned()],
        remove: vec![from.to_owned()],
        assign_self: false,
    };
    setup.tracker.edit(item, &edit).unwrap();
}

fn moved(item: u64, from: ItemStatus, to: ItemStatus, reason: Reason) -> String {
    let record = Transition {
        schema: STATE_SCHEMA.into(),
        item,
        attempt: 1,
        from,
        to,
        reason,
    };
    transition_comment(&record, "Moved.").unwrap()
}

/// Adds `recorded`'s issue, readied and leased to impl-rust on attempt 1.
fn add(setup: &Setup, recorded: &Recorded) {
    let item = recorded.item;
    let text = body("impl-rust", &["crates/grdr-core/**"], CRITERIA);
    let lease = Lease {
        schema: LEASE_SCHEMA.into(),
        item,
        attempt: 1,
        agent: "impl-rust".into(),
        model: "claude-sonnet-5-5".into(),
        acceptance_sha256: acceptance(&text).unwrap().sha256,
        branch: format!("agent/{item}/a1"),
        session: recorded.session.map(str::to_owned),
    };
    let mut bodies = vec![
        ready_comment(&ready_for(item, "lead-core", &text)).unwrap(),
        lease_comment(&lease).unwrap(),
    ];
    bodies.extend_from_slice(recorded.history);
    let status = status_label(recorded.status).unwrap();
    let mut found = issue(item, &[&status, "agent:impl-rust"], &text);
    found.comments = bodies
        .into_iter()
        .map(|body| Comment {
            body,
            created_at: recorded.at.to_owned(),
            ..Comment::default()
        })
        .collect();
    setup.tracker.add(found);
}

fn in_review_since(setup: &Setup, item: u64, at: &str) {
    let entered = moved(
        item,
        ItemStatus::Leased,
        ItemStatus::InReview,
        Reason::PullRequestOpen,
    );
    let recorded = Recorded {
        item,
        status: ItemStatus::InReview,
        session: Some("6b1c0f4e-1111-4222-8333-944455556600"),
        history: &[entered],
        at,
    };
    add(setup, &recorded);
}

/// An hour between passes, so only a session's end makes one due within a test.
fn poll_hourly(setup: &Setup) {
    let path = setup.temp.repo().path(".agents/harness.toml");
    let harness = std::fs::read_to_string(&path).unwrap();
    std::fs::write(
        &path,
        harness.replace("poll_seconds = 1\n", "poll_seconds = 3600\n"),
    )
    .unwrap();
}

/// Makes a pass as the run loop does, then says whether the next is due once the sessions that
/// pass started have ended.
fn due_after_its_sessions(dispatcher: &mut Dispatcher) -> bool {
    let step = dispatcher.step_github();
    dispatcher.pace(step);
    assert!(
        !dispatcher.pass_due(),
        "the next pass is due before any session ended"
    );
    settle(dispatcher);
    dispatcher.pass_due()
}

#[test]
fn an_issue_with_a_skip_label_is_left_to_the_setup_session() {
    let setup = Setup::new("");
    let path = setup.temp.repo().path(".agents/harness.toml");
    let harness = std::fs::read_to_string(&path).unwrap().replace(
        "[dispatch]
",
        "[dispatch]
skip_labels = [\"meta\"]
",
    );
    std::fs::write(&path, harness).unwrap();
    setup.ready_issue(71, &["meta"], "lead-core");
    setup.fake.respond(1, DONE, 0);
    let mut dispatcher = setup.dispatcher();
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    assert_eq!(dispatcher.held(), Vec::<u64>::new());
    assert!(setup.fake.calls().is_empty(), "{:?}", setup.fake.calls());
    assert_eq!(statuses(&setup, 71), vec!["status:ready".to_owned()]);
}

#[test]
fn a_session_stopped_as_stalled_after_it_handed_off_blocked_posts_nothing() {
    let setup = Setup::new("");
    setup.ready_issue(40, &[], "lead-core");
    setup.fake.sleep(1, 4);
    let mut dispatcher = setup.stalling_dispatcher();
    dispatcher.step_github().unwrap();
    relabel(&setup, 40, "status:leased", "status:blocked");
    settle(&mut dispatcher);
    assert_eq!(statuses(&setup, 40), vec!["status:blocked".to_owned()]);
    assert_eq!(transitions(&setup.found(40)), vec![]);
    assert_eq!(dispatcher.held(), Vec::<u64>::new());
    dispatcher.step_github().unwrap();
    assert_eq!(
        leases(&setup.found(40)).len(),
        1,
        "a second attempt was leased beside the hand-off"
    );
}

#[test]
fn a_session_stopped_as_stalled_after_it_handed_off_done_goes_to_review() {
    let setup = Setup::new("");
    setup.ready_issue(39, &[], "lead-core");
    setup.fake.sleep(1, 4);
    let mut dispatcher = setup.stalling_dispatcher();
    dispatcher.step_github().unwrap();
    setup.tracker.open_pull_request_for("agent/39/a1", 739);
    settle(&mut dispatcher);
    assert_eq!(
        transitions(&setup.found(39)),
        vec![(ItemStatus::InReview, Reason::PullRequestOpen)]
    );
    assert_eq!(leases(&setup.found(39)).len(), 1);
}

#[test]
fn a_grant_whose_label_edit_was_answered_late_is_undone_before_the_pass_goes_on() {
    let setup = Setup::new("");
    setup.ready_issue(41, &[], "lead-core");
    setup.tracker.answer_edits_late(1);
    setup.fake.respond(1, DONE, 0);
    let mut dispatcher = setup.dispatcher();
    dispatcher.step_github().unwrap();
    let calls = setup.tracker.calls();
    let late = calls
        .iter()
        .position(|call| call == "edit 41 +status:leased -status:ready")
        .unwrap();
    assert_eq!(
        calls[late + 1..late + 3],
        ["issue 41", "edit 41 +status:ready -status:leased"],
        "{calls:?}"
    );
    assert_eq!(statuses(&setup, 41), vec!["status:ready".to_owned()]);
    assert_eq!(dispatcher.held(), Vec::<u64>::new());
    dispatcher.step_github().unwrap();
    assert_eq!(dispatcher.held(), vec![41]);
    let found = setup.found(41);
    let attempts: Vec<u32> = leases(&found).iter().map(|lease| lease.attempt).collect();
    assert_eq!(attempts, vec![1]);
    settle(&mut dispatcher);
}

#[test]
fn a_leased_issue_with_no_lease_record_goes_back_to_ready_with_one_journal_note() {
    let setup = Setup::new("");
    setup.ready_issue(42, &[], "lead-core");
    relabel(&setup, 42, "status:ready", "status:leased");
    let mut dispatcher = setup.dispatcher();
    dispatcher.adopt().unwrap();
    assert_eq!(dispatcher.held(), Vec::<u64>::new());
    dispatcher.step_github().unwrap();
    assert_eq!(statuses(&setup, 42), vec!["status:ready".to_owned()]);
    assert_eq!(transitions(&setup.found(42)), vec![]);
    let journal = std::fs::read_to_string(setup.temp.repo().path(JOURNAL)).unwrap();
    assert_eq!(journal.matches("unrecorded-lease").count(), 1, "{journal}");
    setup.fake.respond(1, DONE, 0);
    dispatcher.step_github().unwrap();
    assert_eq!(dispatcher.held(), vec![42]);
    settle(&mut dispatcher);
}

#[test]
fn a_leased_issue_whose_last_attempt_ended_goes_back_to_ready_for_the_next_attempt() {
    let setup = Setup::new("");
    let ended = moved(43, ItemStatus::Leased, ItemStatus::Ready, Reason::Stall);
    let recorded = Recorded {
        item: 43,
        status: ItemStatus::Leased,
        session: None,
        history: &[ended],
        at: "",
    };
    add(&setup, &recorded);
    setup.fake.respond(1, DONE, 0);
    let mut dispatcher = setup.dispatcher();
    dispatcher.step_github().unwrap();
    assert_eq!(statuses(&setup, 43), vec!["status:ready".to_owned()]);
    dispatcher.step_github().unwrap();
    let found = setup.found(43);
    let branches: Vec<&str> = leases(&found)
        .iter()
        .map(|lease| lease.branch.as_str())
        .collect();
    assert_eq!(branches, vec!["agent/43/a1", "agent/43/a2"]);
    settle(&mut dispatcher);
}

#[test]
fn a_recorded_lease_and_an_attempt_with_an_open_pull_request_stay_leased() {
    let setup = Setup::new("");
    let recorded = Recorded {
        item: 44,
        status: ItemStatus::Leased,
        session: Some("6b1c0f4e-1111-4222-8333-944455556644"),
        history: &[],
        at: "",
    };
    add(&setup, &recorded);
    setup.ready_issue(45, &[], "lead-core");
    relabel(&setup, 45, "status:ready", "status:leased");
    setup.tracker.open_pull_request_for("agent/45/a1", 450);
    let mut dispatcher = setup.dispatcher();
    dispatcher.step_github().unwrap();
    assert_eq!(statuses(&setup, 44), vec!["status:leased".to_owned()]);
    assert_eq!(statuses(&setup, 45), vec!["status:leased".to_owned()]);
    assert!(
        !setup.temp.repo().path(JOURNAL).exists(),
        "a journal note was written"
    );
}

#[test]
fn a_verdict_deadline_that_ran_out_before_the_dispatcher_started_escalates_nothing() {
    let setup = Setup::new("");
    setup.temp.add_agents(EVALUATORS);
    in_review_since(&setup, 46, LONG_AGO);
    setup.tracker.open_pull_request_for("agent/46/a1", 460);
    setup.fake.respond(1, DONE, 0);
    let mut dispatcher = setup.dispatcher();
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    assert_eq!(
        setup.status(46),
        Some(ItemStatus::InReview),
        "{:?}",
        transitions(&setup.found(46))
    );
    let calls = setup.fake.calls();
    assert!(
        calls.len() == 1 && calls[0].contains("eval-tier --item 46"),
        "{calls:?}"
    );
}

#[test]
fn the_verdict_deadline_runs_from_the_later_of_the_round_and_the_dispatchers_start() {
    let setup = Setup::new("");
    in_review_since(&setup, 47, LONG_AGO);
    in_review_since(&setup, 48, &Utc::now().iso());
    let mut dispatcher = setup.dispatcher();
    dispatcher.started_at(now_unix() - 25 * HOUR);
    dispatcher.step_github().unwrap();
    assert_eq!(
        transitions(&setup.found(47)).last(),
        Some(&(ItemStatus::Escalated, Reason::NoVerdict))
    );
    assert_eq!(setup.status(48), Some(ItemStatus::InReview));
}

#[test]
fn a_claim_lease_expires_by_the_time_since_the_dispatcher_started() {
    let setup = Setup::new("");
    let recorded = Recorded {
        item: 49,
        status: ItemStatus::Leased,
        session: None,
        history: &[],
        at: LONG_AGO,
    };
    add(&setup, &recorded);
    let mut dispatcher = setup.dispatcher();
    dispatcher.step_github().unwrap();
    assert_eq!(statuses(&setup, 49), vec!["status:leased".to_owned()]);
    dispatcher.started_at(now_unix() - 25 * HOUR);
    dispatcher.step_github().unwrap();
    assert_eq!(
        transitions(&setup.found(49)),
        vec![(ItemStatus::Ready, Reason::LeaseExpired)]
    );
}

#[test]
fn the_pass_after_a_writer_ends_is_due_at_once() {
    let setup = Setup::new("");
    poll_hourly(&setup);
    setup.ready_issue(50, &[], "lead-core");
    setup.fake.respond(1, DONE, 0);
    let mut dispatcher = setup.dispatcher();
    assert!(due_after_its_sessions(&mut dispatcher));
    assert_eq!(setup.fake.calls().len(), 1);
}

#[test]
fn the_pass_after_a_planner_ends_is_due_at_once() {
    let setup = Setup::new("");
    poll_hourly(&setup);
    setup.temp.add_agents(LEAD);
    setup.temp.write(".agents/owners.toml", OWNERS);
    let proposed = issue(51, &["status:proposed", "squad:core"], "A gap.");
    setup.tracker.add(proposed);
    setup.fake.respond(1, DONE, 0);
    let mut dispatcher = setup.dispatcher();
    assert!(due_after_its_sessions(&mut dispatcher));
    assert_eq!(setup.fake.calls().len(), 1);
}

#[test]
fn the_pass_after_an_evaluator_ends_is_due_at_once() {
    let setup = Setup::new("");
    poll_hourly(&setup);
    setup.temp.add_agents(EVALUATORS);
    let mut dispatcher = to_review(&setup, 52, "lib.rs");
    setup.fake.respond(2, DONE, 0);
    assert!(due_after_its_sessions(&mut dispatcher));
    let calls = setup.fake.calls();
    assert!(
        calls.len() == 2 && calls[1].contains("eval-tier --item 52"),
        "{calls:?}"
    );
}

#[test]
fn the_pass_after_a_routine_ends_is_due_at_once() {
    let setup = Setup::new(GARDEN_ROUTINE);
    poll_hourly(&setup);
    setup.fake.respond(1, DONE, 0);
    let mut dispatcher = setup.dispatcher();
    assert!(due_after_its_sessions(&mut dispatcher));
    assert_eq!(setup.fake.calls().len(), 1);
}

#[test]
fn a_launch_a_lock_refused_leaves_the_next_pass_to_the_poll_interval() {
    let setup = Setup::new("");
    poll_hourly(&setup);
    setup.ready_issue(53, &[], "lead-core");
    refused(&setup, 1);
    let mut dispatcher = setup.dispatcher();
    assert!(!due_after_its_sessions(&mut dispatcher));
    assert_eq!(dispatcher.held(), vec![53]);
}
