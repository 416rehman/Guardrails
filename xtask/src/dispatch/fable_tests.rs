//! One fable session at a time inside one dispatcher: a second chief-architect session in the
//! same pass waits in a paused slot even though the first one's `kit launch` has not taken the
//! machine lock yet, and a launch that another fable session refused stays paused instead of
//! ending its attempt.

use super::assist_tests::{EVALUATORS, SEED_SCOPE, handoff};
use super::landing_tests::CRITERIA;
use super::policy::Policy;
use super::tests::{DONE, Setup, settle, transitions};
use crate::config::session::ItemStatus;
use crate::orchestrate::issue::acceptance;
use crate::orchestrate::records::{
    LEASE_SCHEMA, Lease, Reason, STATE_SCHEMA, Transition, lease_comment, ready_comment,
    transition_comment,
};
use crate::orchestrate::testkit::{FakeProgram, body, issue, ready_for};
use crate::orchestrate::tracker::Tracker;

/// What Claude Code prints when the account's Fable allowance is used up.
const FABLE_LIMITED: &str = "{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":true,\"num_turns\":1,\"result\":\"You've reached your Fable limit. Switch to another model, or manage usage credits, to continue.\"}\n";

pub(super) fn two_writers(setup: &Setup) {
    let path = setup.temp.repo().path(".agents/harness.toml");
    let harness = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, harness.replace("max_writers = 1", "max_writers = 2")).unwrap();
}

/// Issue `item` in review for the chief architect on a protected path, its eval-diff failed.
pub(super) fn failed_in_review(setup: &Setup, item: u64) {
    let text = body("chief-architect", &["Cargo.toml"], CRITERIA);
    setup.tracker.add(issue(
        item,
        &["status:in-review", "agent:chief-architect"],
        &text,
    ));
    let lease = Lease {
        schema: LEASE_SCHEMA.into(),
        item,
        attempt: 1,
        agent: "chief-architect".into(),
        model: "claude-fable-5-2".into(),
        acceptance_sha256: acceptance(&text).unwrap().sha256,
        branch: format!("agent/{item}/a1"),
        session: Some(format!("6b1c0f4e-1111-4222-8333-9444555566{item}")),
    };
    let entered = Transition {
        schema: STATE_SCHEMA.into(),
        item,
        attempt: 1,
        from: ItemStatus::Leased,
        to: ItemStatus::InReview,
        reason: Reason::PullRequestOpen,
    };
    for comment in [
        ready_comment(&ready_for(item, "lead-core", &text)).unwrap(),
        lease_comment(&lease).unwrap(),
        transition_comment(&entered, "In review.").unwrap(),
        handoff(item, "eval-diff", "fail", "claude-opus-5-5"),
    ] {
        setup.tracker.comment(item, &comment).unwrap();
    }
    setup
        .tracker
        .open_pull_request_for(&format!("agent/{item}/a1"), item * 10);
}

fn fable_calls(fake: &FakeProgram) -> usize {
    fake.calls()
        .iter()
        .filter(|call| call.starts_with("chief-architect"))
        .count()
}

#[test]
fn two_fable_send_backs_in_one_pass_start_one_session() {
    let setup = Setup::new("");
    setup.temp.add_agents(EVALUATORS);
    two_writers(&setup);
    failed_in_review(&setup, 80);
    failed_in_review(&setup, 81);
    let mut dispatcher = setup.dispatcher();
    dispatcher.step_github().unwrap();
    assert_eq!(dispatcher.held(), vec![80, 81]);
    settle(&mut dispatcher);
    assert_eq!(fable_calls(&setup.fake), 1, "{:?}", setup.fake.calls());
}

/// The seed's issue 33, escalated after its hand-off, waiting for the chief architect's decision.
fn escalated_seed(setup: &Setup) {
    setup.temp.write(".agents/kit/seed-scope.toml", SEED_SCOPE);
    let mut seed = issue(
        33,
        &["status:escalated", "agent:chief-architect"],
        "The seed.",
    );
    seed.title = "[WI-0000] Seed the agent team".to_owned();
    setup.tracker.add(seed);
    let lease = Lease {
        schema: LEASE_SCHEMA.into(),
        item: 33,
        attempt: 1,
        agent: "chief-architect".into(),
        model: "claude-fable-5-2".into(),
        acceptance_sha256: String::new(),
        branch: "agent/seed".into(),
        session: None,
    };
    setup
        .tracker
        .comment(33, &lease_comment(&lease).unwrap())
        .unwrap();
}

/// The fake's `call` exits as `kit launch` does when a lock refuses it.
pub(super) fn refused(setup: &Setup, call: usize) {
    let busy = Policy::load(&setup.temp.repo(), None).unwrap().busy_exit;
    setup
        .fake
        .respond_err(call, "kit launch: a lock refused it", i32::from(busy));
}

#[test]
fn a_fable_planner_and_a_fable_fix_in_one_pass_start_one_session() {
    let setup = Setup::new("");
    setup.temp.add_agents(EVALUATORS);
    escalated_seed(&setup);
    failed_in_review(&setup, 80);
    let mut dispatcher = setup.dispatcher();
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    assert_eq!(fable_calls(&setup.fake), 1, "{:?}", setup.fake.calls());
}

#[test]
fn a_fable_decision_the_lock_refused_is_started_again() {
    let setup = Setup::new("");
    escalated_seed(&setup);
    refused(&setup, 1);
    setup.fake.respond(2, DONE, 0);
    let mut dispatcher = setup.dispatcher();
    for _ in 0..3 {
        dispatcher.step_github().unwrap();
        settle(&mut dispatcher);
    }
    let calls = setup.fake.calls();
    assert_eq!(calls.len(), 2, "{calls:?}");
    assert!(
        calls[1].contains("chief-architect --item 33 --print"),
        "{}",
        calls[1]
    );
}

#[test]
fn a_fable_session_its_model_limit_refused_counts_no_attempt_and_waits() {
    let setup = Setup::new("");
    setup.temp.add_agents(EVALUATORS);
    failed_in_review(&setup, 80);
    let path = setup.temp.repo().path(".agents/harness.toml");
    let harness = std::fs::read_to_string(&path).unwrap().replace(
        "retry_seconds = 0
",
        "retry_seconds = 3600
model_limit_strings = [\"You've reached your Fable limit\"]
",
    );
    std::fs::write(&path, harness).unwrap();
    setup.fake.respond(1, FABLE_LIMITED, 1);
    let mut dispatcher = setup.dispatcher();
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    assert_eq!(setup.status(80), Some(ItemStatus::Leased));
    assert_eq!(dispatcher.held(), vec![80]);
    assert_eq!(
        transitions(&setup.found(80)),
        vec![
            (ItemStatus::InReview, Reason::PullRequestOpen),
            (ItemStatus::Leased, Reason::EvaluatorFindings)
        ]
    );
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    assert_eq!(setup.fake.calls().len(), 1, "{:?}", setup.fake.calls());
}

#[test]
fn a_launch_another_fable_session_refused_stays_paused() {
    let setup = Setup::new("");
    setup.temp.add_agents(EVALUATORS);
    failed_in_review(&setup, 80);
    refused(&setup, 1);
    setup.fake.respond(2, DONE, 0);
    let mut dispatcher = setup.dispatcher();
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    assert_eq!(setup.status(80), Some(ItemStatus::Leased));
    assert_eq!(dispatcher.held(), vec![80]);
    assert_eq!(
        transitions(&setup.found(80)),
        vec![
            (ItemStatus::InReview, Reason::PullRequestOpen),
            (ItemStatus::Leased, Reason::EvaluatorFindings)
        ]
    );
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    let calls = setup.fake.calls();
    assert_eq!(calls.len(), 2, "{calls:?}");
    assert!(
        calls[1].contains("chief-architect --item 80")
            && calls[1].contains("came back from review"),
        "{}",
        calls[1]
    );
}
