//! After a send-back and while the merge queue verifies: a fix session that hands off partial
//! gets another session in the attempt instead of review, until the attempt's sessions are used;
//! an acceptance edit during the verify stops it; and a verify that fails after the item left
//! review sends nothing back.

use super::assist_tests::handoff;
use super::dispatcher::Dispatcher;
use super::landing_tests::{push_and_open, to_review, until_verified, valid_body, with_origin};
use super::restart_tests::wait_for_calls;
use super::tests::{DONE, Setup, settle, transitions};
use crate::config::session::ItemStatus;
use crate::orchestrate::records::Reason;
use crate::orchestrate::testkit::{FakeProgram, body};
use crate::orchestrate::tracker::{IssueEdit, Tracker};

/// The `status:` labels of issue `item`.
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

fn verifying(setup: &Setup, item: u64) -> (Dispatcher<'_>, FakeProgram) {
    let verify = FakeProgram::new("late-verify");
    verify.sleep(1, 4).respond(1, "verify: red\n", 1);
    let mut dispatcher = to_review(setup, item, "guide.md");
    dispatcher.set_verifier(verify.program().to_path_buf());
    push_and_open(setup, item, "docs: add the guide", &valid_body(item));
    dispatcher.step_github().unwrap();
    wait_for_calls(&verify, 1);
    (dispatcher, verify)
}

#[test]
fn an_acceptance_edit_during_the_verify_stops_it() {
    let setup = Setup::new("");
    let _origin = with_origin(&setup);
    let (mut dispatcher, _verify) = verifying(&setup, 67);
    let mut edited = setup.tracker.snapshot(67);
    edited.body = body(
        "impl-rust",
        &["crates/grdr-core/**"],
        "AC-1 | cargo test | exit 1 | oracle: sh",
    );
    setup.tracker.add(edited);
    setup.fake.respond(2, DONE, 0);
    dispatcher.step_github().unwrap();
    assert!(dispatcher.idle(), "the verify of #67 still runs");
    until_verified(&mut dispatcher);
    settle(&mut dispatcher);
    assert_eq!(statuses(&setup, 67), vec!["status:proposed".to_owned()]);
    assert_eq!(setup.fake.calls().len(), 1, "{:?}", setup.fake.calls());
}

#[test]
fn a_verify_that_fails_after_the_item_left_review_sends_nothing_back() {
    let setup = Setup::new("");
    let _origin = with_origin(&setup);
    let (mut dispatcher, _verify) = verifying(&setup, 68);
    let escalated = IssueEdit {
        add: vec!["status:escalated".into()],
        remove: vec!["status:in-review".into()],
        assign_self: false,
    };
    setup.tracker.edit(68, &escalated).unwrap();
    setup.fake.respond(2, DONE, 0);
    until_verified(&mut dispatcher);
    settle(&mut dispatcher);
    assert_eq!(statuses(&setup, 68), vec!["status:escalated".to_owned()]);
    assert!(
        !transitions(&setup.found(68)).contains(&(ItemStatus::Leased, Reason::VerifyFailed)),
        "{:?}",
        transitions(&setup.found(68))
    );
    assert_eq!(setup.fake.calls().len(), 1, "{:?}", setup.fake.calls());
}

/// Issue `item` sent back for an invalid title, its fix session running for three seconds.
fn sent_back(setup: &Setup, item: u64) -> Dispatcher<'_> {
    let mut dispatcher = to_review(setup, item, "notes.md");
    push_and_open(setup, item, "Add the notes", &format!("Work item: #{item}"));
    setup.fake.sleep(2, 3).respond(2, DONE, 0);
    dispatcher.step_github().unwrap();
    assert!(
        transitions(&setup.found(item)).contains(&(ItemStatus::Leased, Reason::PullRequestInvalid))
    );
    dispatcher
}

#[test]
fn a_partial_fix_gets_another_session_instead_of_review() {
    let setup = Setup::new("");
    let _origin = with_origin(&setup);
    let mut dispatcher = sent_back(&setup, 69);
    setup
        .tracker
        .comment(
            69,
            &handoff(69, "impl-rust", "partial", "claude-sonnet-5-5"),
        )
        .unwrap();
    setup.fake.respond(3, DONE, 0);
    settle(&mut dispatcher);
    let calls = setup.fake.calls();
    assert!(
        calls
            .get(2)
            .is_some_and(|call| call.contains("Continue issue #69")),
        "the partial fix went to review ({:?}): {calls:?}",
        transitions(&setup.found(69))
    );
    assert_eq!(calls.len(), 3, "{calls:?}");
    assert_eq!(
        setup.status(69),
        Some(ItemStatus::InReview),
        "at the session cap the partial head with its open pull request goes to review: {:?}",
        transitions(&setup.found(69))
    );
}
