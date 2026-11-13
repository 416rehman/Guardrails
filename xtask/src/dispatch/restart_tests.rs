//! What a dispatcher restart rebuilds: a send-back nobody answered yet, a `kit claim` lease's
//! included, is adopted and started as a fix instead of going back to review on the head the
//! evaluators failed; an issue whose lease cannot be rebuilt is left out instead of stopping the
//! start; and an evaluator that died with the old process runs again, while one that outlived it
//! is waited for instead of started beside it. A send-back whose slot cannot be rebuilt posts
//! nothing.

use std::time::{Duration, Instant};

use super::assist_tests::EVALUATORS;
use super::fable_tests::refused;
use super::landing_tests::{CRITERIA, push_and_open, to_review, valid_body, with_origin};
use super::tests::{DONE, Setup, settle, transitions};
use crate::config::session::ItemStatus;
use crate::orchestrate::issue::acceptance;
use crate::orchestrate::records::{
    LEASE_SCHEMA, Lease, Reason, STATE_SCHEMA, Transition, lease_comment, ready_comment,
    transition_comment,
};
use crate::orchestrate::testkit::{FakeProgram, body, issue, ready_for};
use crate::orchestrate::tracker::{IssueEdit, Tracker};

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

/// Issue `item`, `status:leased` for `agent` (its label), readied, with a lease for impl-rust
/// naming `session` and the transitions `history`.
fn leased(setup: &Setup, item: u64, agent: &str, session: Option<&str>, history: &[String]) {
    let text = body(agent, &["crates/grdr-core/**"], CRITERIA);
    let label = format!("agent:{agent}");
    setup
        .tracker
        .add(issue(item, &["status:leased", &label], &text));
    let lease = Lease {
        schema: LEASE_SCHEMA.into(),
        item,
        attempt: 1,
        agent: "impl-rust".into(),
        model: "claude-sonnet-5-5".into(),
        acceptance_sha256: acceptance(&text).unwrap().sha256,
        branch: format!("agent/{item}/a1"),
        session: session.map(str::to_owned),
    };
    let mut comments = vec![
        ready_comment(&ready_for(item, "lead-core", &text)).unwrap(),
        lease_comment(&lease).unwrap(),
    ];
    comments.extend_from_slice(history);
    for comment in comments {
        setup.tracker.comment(item, &comment).unwrap();
    }
}

pub(super) fn wait_for_calls(fake: &FakeProgram, count: usize) {
    let started = Instant::now();
    while fake.calls().len() < count && started.elapsed() < Duration::from_secs(30) {
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn a_restart_adopts_an_unanswered_claim_send_back_and_starts_its_fix() {
    let setup = Setup::new("");
    let history = [
        moved(
            90,
            ItemStatus::Leased,
            ItemStatus::InReview,
            Reason::PullRequestOpen,
        ),
        moved(
            90,
            ItemStatus::InReview,
            ItemStatus::Leased,
            Reason::EvaluatorFindings,
        ),
    ];
    leased(&setup, 90, "impl-rust", None, &history);
    setup.tracker.open_pull_request_for("agent/90/a1", 900);
    setup.fake.respond(1, DONE, 0);
    let mut dispatcher = setup.dispatcher();
    dispatcher.adopt().unwrap();
    assert_eq!(dispatcher.held(), vec![90]);
    dispatcher.step_github().unwrap();
    assert_eq!(
        setup.status(90),
        Some(ItemStatus::Leased),
        "the unanswered send-back went back to review: {:?}",
        transitions(&setup.found(90))
    );
    settle(&mut dispatcher);
    let calls = setup.fake.calls();
    assert!(
        calls[0].contains("impl-rust --item 90") && calls[0].contains("came back from review"),
        "{calls:?}"
    );
}

#[test]
fn a_send_back_nobody_holds_waits_for_its_fix() {
    let setup = Setup::new("");
    let history = [
        moved(
            91,
            ItemStatus::Leased,
            ItemStatus::InReview,
            Reason::PullRequestOpen,
        ),
        moved(
            91,
            ItemStatus::InReview,
            ItemStatus::Leased,
            Reason::EvaluatorFindings,
        ),
    ];
    leased(
        &setup,
        91,
        "impl-rust",
        Some("6b1c0f4e-1111-4222-8333-944455556691"),
        &history,
    );
    setup.tracker.open_pull_request_for("agent/91/a1", 910);
    let mut dispatcher = setup.dispatcher();
    dispatcher.step_github().unwrap();
    assert_eq!(
        transitions(&setup.found(91)),
        vec![
            (ItemStatus::InReview, Reason::PullRequestOpen),
            (ItemStatus::Leased, Reason::EvaluatorFindings)
        ]
    );
}

#[test]
fn a_lease_that_cannot_be_rebuilt_does_not_stop_the_restart() {
    let setup = Setup::new("");
    leased(
        &setup,
        92,
        "impl-ts",
        Some("6b1c0f4e-1111-4222-8333-944455556692"),
        &[],
    );
    leased(
        &setup,
        93,
        "impl-rust",
        Some("6b1c0f4e-1111-4222-8333-944455556693"),
        &[],
    );
    let mut dispatcher = setup.dispatcher();
    dispatcher.adopt().unwrap();
    assert_eq!(dispatcher.held(), vec![93]);
}

#[test]
fn a_restart_starts_the_evaluator_that_died_with_the_old_process() {
    let setup = Setup::new("");
    setup.temp.add_agents(EVALUATORS);
    let mut dispatcher = to_review(&setup, 94, "lib.rs");
    setup.fake.respond(2, DONE, 0).sleep(2, 5);
    dispatcher.step_github().unwrap();
    wait_for_calls(&setup.fake, 2);
    assert!(
        setup.fake.calls()[1].contains("eval-tier --item 94"),
        "{:?}",
        setup.fake.calls()
    );
    drop(dispatcher);
    setup.fake.respond(3, DONE, 0);
    let mut restarted = setup.dispatcher();
    restarted.adopt().unwrap();
    restarted.step_github().unwrap();
    settle(&mut restarted);
    let calls = setup.fake.calls();
    assert!(
        calls.len() == 3 && calls[2].contains("eval-tier --item 94"),
        "after the restart no evaluator runs for #94: {calls:?}"
    );
}

#[test]
fn an_evaluator_the_old_process_left_running_is_started_again_once_it_ends() {
    let setup = Setup::new("");
    setup.temp.add_agents(EVALUATORS);
    let mut dispatcher = to_review(&setup, 96, "lib.rs");
    setup.fake.respond(2, DONE, 0).sleep(2, 5);
    dispatcher.step_github().unwrap();
    wait_for_calls(&setup.fake, 2);
    drop(dispatcher);
    refused(&setup, 3);
    setup
        .fake
        .respond(4, DONE, 0)
        .respond(5, DONE, 0)
        .sleep(5, 5);
    let mut restarted = setup.dispatcher();
    restarted.adopt().unwrap();
    for _ in 0..2 {
        restarted.step_github().unwrap();
        settle(&mut restarted);
    }
    restarted.step_github().unwrap();
    wait_for_calls(&setup.fake, 5);
    let evaluated = setup
        .fake
        .calls()
        .iter()
        .filter(|call| call.contains("eval-tier --item 96"))
        .count();
    assert_eq!(
        (evaluated, setup.status(96)),
        (4, Some(ItemStatus::InReview)),
        "the refused launch is not an end without a verdict: {:?}",
        transitions(&setup.found(96))
    );
}

#[test]
fn a_send_back_whose_slot_cannot_be_rebuilt_posts_nothing() {
    let setup = Setup::new("");
    let _origin = with_origin(&setup);
    let verify = FakeProgram::new("refused-verify");
    verify.sleep(1, 3).respond(1, "verify: red\n", 1);
    let mut dispatcher = to_review(&setup, 95, "guide.md");
    dispatcher.set_verifier(verify.program().to_path_buf());
    push_and_open(&setup, 95, "docs: add the guide", &valid_body(95));
    dispatcher.step_github().unwrap();
    wait_for_calls(&verify, 1);
    let relabel = IssueEdit {
        add: vec!["agent:impl-ts".into()],
        remove: vec!["agent:impl-rust".into()],
        assign_self: false,
    };
    setup.tracker.edit(95, &relabel).unwrap();
    let started = Instant::now();
    while !dispatcher.idle() && started.elapsed() < Duration::from_secs(20) {
        let _ = dispatcher.step_queue();
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(
        setup.status(95),
        Some(ItemStatus::InReview),
        "{:?}",
        transitions(&setup.found(95))
    );
    assert_eq!(dispatcher.held(), Vec::<u64>::new());
}
