//! The seed's own issue after its hand-off: nobody readies it, so when the chief architect's
//! decision moves it back to proposed the dispatcher starts the seed session again on the seed
//! branch under a new lease, until `[item] max_attempts` is used, and that session goes to review
//! only after its own hand-off, whichever session of the attempt ends; the decision prompt names
//! that exit, or its absence; and an acceptance edit under its lease escalates it instead of
//! returning it to proposed.

use super::assist_tests::handoff;
use super::fable_tests::refused;
use super::landing_tests::{CRITERIA, valid_body, with_origin};
use super::tests::{DONE, Setup, leases, settle, transitions};
use crate::config::session::ItemStatus;
use crate::orchestrate::issue::acceptance;
use crate::orchestrate::records::{self, LEASE_SCHEMA, Lease, Reason, lease_comment};
use crate::orchestrate::testkit::{FakeProgram, body, git, issue};
use crate::orchestrate::tracker::{PullRequest, Tracker};

const SEED_SCOPE: &str = "agent = \"chief-architect\"\nscope = \"seed\"\nbranch = \"agent/seed\"\nmax_turns = 200\npaths = [\"docs/plan.md\"]\nwork_item = \"WI-0000\"\n";
const SEED: u64 = 62;
const FABLE: &str = "claude-fable-5-2";
const SESSION: &str = "6b1c0f4e-1111-4222-8333-944455556662";

/// Issue 62, the seed's, at `status` with the lease the seed's hand-off posted at `attempt`, and
/// the seed branch checked out in the attempt's worktree, pushed, with its pull request open.
fn handed_off_seed(setup: &Setup, status: &str, attempt: u32) {
    seed_issue(setup, status);
    post_seed_lease(setup, attempt, None);
    seed_branch(setup, attempt);
}

/// The seed's issue leased again after attempt 1 handed off blocked: lease 2 names `SESSION`.
fn restarted_seed(setup: &Setup) {
    seed_issue(setup, "status:leased");
    post_seed_lease(setup, 1, None);
    setup
        .tracker
        .comment(SEED, &handoff(SEED, "chief-architect", "blocked", FABLE))
        .unwrap();
    post_seed_lease(setup, 2, Some(SESSION));
    seed_branch(setup, 2);
}

fn seed_issue(setup: &Setup, status: &str) {
    setup.temp.write(".agents/kit/seed-scope.toml", SEED_SCOPE);
    let text = body("chief-architect", &["docs/plan.md"], CRITERIA);
    let mut seed = issue(SEED, &[status, "agent:chief-architect"], &text);
    seed.title = "[WI-0000] Seed the agent team".into();
    setup.tracker.add(seed);
}

fn post_seed_lease(setup: &Setup, attempt: u32, session: Option<&str>) {
    let text = setup.tracker.snapshot(SEED).body;
    let lease = Lease {
        schema: LEASE_SCHEMA.into(),
        item: SEED,
        attempt,
        agent: "chief-architect".into(),
        model: FABLE.into(),
        acceptance_sha256: acceptance(&text).unwrap().sha256,
        branch: "agent/seed".into(),
        session: session.map(str::to_owned),
    };
    setup
        .tracker
        .comment(SEED, &lease_comment(&lease).unwrap())
        .unwrap();
}

fn seed_branch(setup: &Setup, attempt: u32) {
    let worktree = setup
        .temp
        .root()
        .join(format!(".agent/worktrees/{SEED}-a{attempt}"));
    let target = worktree.to_string_lossy().into_owned();
    git(
        setup.temp.root(),
        &[
            "worktree",
            "add",
            "--quiet",
            "-b",
            "agent/seed",
            &target,
            "main",
        ],
    );
    std::fs::create_dir_all(worktree.join("docs")).unwrap();
    std::fs::write(worktree.join("docs/plan.md"), "The plan.\n").unwrap();
    git(&worktree, &["add", "-A"]);
    git(
        &worktree,
        &["commit", "--quiet", "-m", "docs: seed the team"],
    );
    git(&worktree, &["push", "--quiet", "origin", "agent/seed"]);
    let head = git(&worktree, &["rev-parse", "HEAD"]).trim().to_owned();
    setup.tracker.set_pull_request(
        "agent/seed",
        PullRequest {
            number: 620,
            title: "docs: seed the team".into(),
            body: valid_body(SEED),
            head,
            base: "main".into(),
            ..PullRequest::default()
        },
    );
}

fn newest_lease(setup: &Setup) -> Lease {
    records::current_lease(&setup.found(SEED), SEED)
        .cloned()
        .unwrap()
}

fn edit_acceptance(setup: &Setup) {
    let mut edited = setup.tracker.snapshot(SEED);
    edited.body = body(
        "chief-architect",
        &["docs/plan.md"],
        "AC-1 | cargo test | exit 1 | oracle: sh",
    );
    setup.tracker.add(edited);
}

#[test]
fn a_decided_seed_issue_back_at_proposed_starts_the_seed_session_again() {
    let setup = Setup::new("");
    let _origin = with_origin(&setup);
    handed_off_seed(&setup, "status:proposed", 1);
    setup.fake.respond(1, DONE, 0).sleep(1, 2);
    let mut dispatcher = setup.dispatcher();
    assert_eq!(
        dispatcher.seed_not_handed_off().unwrap(),
        None,
        "the seed's lease lets the dispatcher start"
    );
    dispatcher.step_github().unwrap();
    assert_eq!(
        setup.status(SEED),
        Some(ItemStatus::Leased),
        "calls {:?}",
        setup.fake.calls()
    );
    let lease = newest_lease(&setup);
    let digest = acceptance(&setup.tracker.snapshot(SEED).body)
        .unwrap()
        .sha256;
    assert_eq!(
        (lease.attempt, lease.branch.as_str(), lease.agent.as_str()),
        (2, "agent/seed", "chief-architect")
    );
    assert_eq!(lease.acceptance_sha256, digest);
    setup
        .tracker
        .comment(SEED, &handoff(SEED, "chief-architect", "done", FABLE))
        .unwrap();
    settle(&mut dispatcher);
    let calls = setup.fake.calls();
    assert_eq!(calls.len(), 1, "no planner runs beside it: {calls:?}");
    assert!(
        calls[0].contains("chief-architect --item 62 --seed --print")
            && calls[0].contains(&format!("--session-id {}", lease.session.unwrap()))
            && calls[0].contains("starts again on branch agent/seed, attempt 2"),
        "{}",
        calls[0]
    );
    let worktree = setup.temp.root().join(".agent/worktrees/62-a2");
    assert_eq!(
        git(&worktree, &["symbolic-ref", "--short", "HEAD"]).trim(),
        "agent/seed"
    );
    assert_eq!(
        setup.status(SEED),
        Some(ItemStatus::InReview),
        "it handed off with its pull request open, so the seed goes back to review: {:?}",
        transitions(&setup.found(SEED))
    );
}

#[test]
fn a_restarted_seed_session_that_hands_nothing_off_goes_to_the_chief_architect() {
    let setup = Setup::new("");
    let _origin = with_origin(&setup);
    handed_off_seed(&setup, "status:proposed", 1);
    setup.fake.respond(1, DONE, 0);
    let mut dispatcher = setup.dispatcher();
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    assert_eq!(
        transitions(&setup.found(SEED)),
        vec![(ItemStatus::Escalated, Reason::NoPullRequest)],
        "the earlier attempt's open pull request is not this session's hand-off"
    );
}

#[test]
fn a_blocked_seed_issue_spends_no_fable_session() {
    let setup = Setup::new("");
    let _origin = with_origin(&setup);
    handed_off_seed(&setup, "status:blocked", 1);
    setup.fake.respond(1, DONE, 0);
    let mut dispatcher = setup.dispatcher();
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    let calls = setup.fake.calls();
    assert!(
        calls.is_empty(),
        "the chief architect may not move it from blocked: {calls:?}"
    );
}

#[test]
fn the_decision_on_a_seed_branch_that_no_longer_merges_offers_no_new_session() {
    let setup = Setup::new("");
    let _origin = with_origin(&setup);
    handed_off_seed(&setup, "status:in-review", 1);
    setup.temp.write("docs/plan.md", "Another plan.\n");
    git(setup.temp.root(), &["add", "-A"]);
    git(
        setup.temp.root(),
        &["commit", "--quiet", "-m", "docs: another plan"],
    );
    git(setup.temp.root(), &["push", "--quiet", "origin", "main"]);
    setup.fake.respond(1, DONE, 0);
    let verify = FakeProgram::new("seed-conflict-verify");
    let mut dispatcher = setup.dispatcher();
    dispatcher.set_verifier(verify.program().to_path_buf());
    dispatcher.step_github().unwrap();
    assert_eq!(
        transitions(&setup.found(SEED)),
        vec![(ItemStatus::Escalated, Reason::MergeConflict)]
    );
    let detail = setup
        .tracker
        .snapshot(SEED)
        .comments
        .last()
        .unwrap()
        .body
        .clone();
    assert!(
        detail.contains("No session can merge or rebase the seed branch, so the chief architect"),
        "{detail}"
    );
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    let calls = setup.fake.calls();
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert!(
        calls[0].contains("cannot clear the conflict")
            && !calls[0].contains("--add-label status:proposed"),
        "{}",
        calls[0]
    );
}

#[test]
fn the_seed_session_starts_again_only_while_its_attempts_last() {
    let setup = Setup::new("");
    let _origin = with_origin(&setup);
    handed_off_seed(&setup, "status:proposed", 2);
    setup.fake.respond(1, DONE, 0);
    let mut dispatcher = setup.dispatcher();
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    assert!(setup.fake.calls().is_empty(), "{:?}", setup.fake.calls());
    assert_eq!(setup.status(SEED), Some(ItemStatus::Proposed));
    assert_eq!(leases(&setup.found(SEED)).len(), 1);
}

#[test]
fn the_decision_on_the_escalated_seed_names_its_exit() {
    let setup = Setup::new("");
    let _origin = with_origin(&setup);
    handed_off_seed(&setup, "status:escalated", 1);
    setup.fake.respond(1, DONE, 0);
    let mut dispatcher = setup.dispatcher();
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    let calls = setup.fake.calls();
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert!(
        calls[0].contains("chief-architect --item 62 --print")
            && calls[0].contains("the dispatcher starts the seed session again on agent/seed"),
        "{}",
        calls[0]
    );
}

#[test]
fn the_decision_on_a_seed_with_no_attempt_left_offers_no_new_session() {
    let setup = Setup::new("");
    let _origin = with_origin(&setup);
    handed_off_seed(&setup, "status:escalated", 2);
    setup.fake.respond(1, DONE, 0);
    let mut dispatcher = setup.dispatcher();
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    let calls = setup.fake.calls();
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert!(
        calls[0].contains("does not start the seed session again")
            && !calls[0].contains("--add-label status:proposed"),
        "{}",
        calls[0]
    );
}

#[test]
fn the_seeds_acceptance_edit_in_review_escalates_it() {
    let setup = Setup::new("");
    let _origin = with_origin(&setup);
    handed_off_seed(&setup, "status:in-review", 1);
    edit_acceptance(&setup);
    let mut dispatcher = setup.dispatcher();
    dispatcher.step_github().unwrap();
    assert_eq!(
        transitions(&setup.found(SEED)),
        vec![(ItemStatus::Escalated, Reason::AcceptanceChanged)]
    );
}

#[test]
fn the_seeds_acceptance_edit_under_a_held_lease_escalates_it() {
    let setup = Setup::new("");
    let _origin = with_origin(&setup);
    handed_off_seed(&setup, "status:leased", 1);
    let mut dispatcher = setup.dispatcher();
    dispatcher.adopt().unwrap();
    assert_eq!(dispatcher.held(), vec![SEED]);
    edit_acceptance(&setup);
    dispatcher.step_github().unwrap();
    assert_eq!(
        transitions(&setup.found(SEED)),
        vec![(ItemStatus::Escalated, Reason::AcceptanceChanged)]
    );
    assert!(setup.fake.calls().is_empty(), "{:?}", setup.fake.calls());
}

#[test]
fn the_seeds_acceptance_edit_under_a_lease_nobody_holds_escalates_it() {
    let setup = Setup::new("");
    let _origin = with_origin(&setup);
    handed_off_seed(&setup, "status:leased", 1);
    edit_acceptance(&setup);
    let mut dispatcher = setup.dispatcher();
    dispatcher.step_github().unwrap();
    assert_eq!(
        transitions(&setup.found(SEED)),
        vec![(ItemStatus::Escalated, Reason::AcceptanceChanged)]
    );
}

#[test]
fn another_items_acceptance_edit_still_returns_it_to_proposed() {
    let setup = Setup::new("");
    setup.ready_issue(63, &[], "lead-core");
    setup.fake.respond(1, DONE, 0).sleep(1, 3);
    let mut dispatcher = setup.dispatcher();
    dispatcher.step_github().unwrap();
    let mut edited = setup.tracker.snapshot(63);
    edited.body = body(
        "impl-rust",
        &["crates/grdr-core/**"],
        "AC-1 | cargo test | exit 1 | oracle: sh",
    );
    setup.tracker.add(edited);
    dispatcher.step_github().unwrap();
    assert_eq!(
        transitions(&setup.found(63)),
        vec![(ItemStatus::Proposed, Reason::AcceptanceChanged)]
    );
}

/// A restart adopts the seed started again, and resuming its session does nothing: the next
/// session gets the seed's own prompt again under a new id, and when it ends without a hand-off
/// the seed escalates, attempt 1's hand-off notwithstanding.
#[test]
fn a_restarted_seed_whose_resume_did_nothing_gets_its_own_prompt_again() {
    let setup = Setup::new("");
    let _origin = with_origin(&setup);
    restarted_seed(&setup);
    setup
        .fake
        .respond_err(1, "No conversation found with session ID", 1)
        .respond(2, DONE, 0);
    let mut dispatcher = setup.dispatcher();
    dispatcher.adopt().unwrap();
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    let calls = setup.fake.calls();
    assert_eq!(calls.len(), 2, "{calls:?}");
    assert!(
        calls[0].contains(&format!("--resume {SESSION}")),
        "{}",
        calls[0]
    );
    assert!(
        calls[1].contains("starts again on branch agent/seed, attempt 2")
            && calls[1].contains("--session-id")
            && !calls[1].contains(SESSION),
        "{}",
        calls[1]
    );
    assert_eq!(
        transitions(&setup.found(SEED)),
        vec![(ItemStatus::Escalated, Reason::NoPullRequest)]
    );
}

/// The seed's lease names no session, as its hand-off posts it, so a restart starts a new one; a
/// lock refuses that launch, and the retry starts a new session again instead of resuming one
/// that never ran.
#[test]
fn a_refused_launch_of_the_seeds_own_lease_is_retried_as_a_new_session() {
    let setup = Setup::new("");
    let _origin = with_origin(&setup);
    handed_off_seed(&setup, "status:leased", 1);
    refused(&setup, 1);
    setup.fake.respond(2, DONE, 0);
    let mut dispatcher = setup.dispatcher();
    dispatcher.adopt().unwrap();
    for _ in 0..2 {
        dispatcher.step_github().unwrap();
        settle(&mut dispatcher);
    }
    let calls = setup.fake.calls();
    assert_eq!(calls.len(), 2, "{calls:?}");
    assert!(
        calls[1].contains("--session-id") && !calls[1].contains("--resume"),
        "{}",
        calls[1]
    );
}
