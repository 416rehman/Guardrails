//! The merge queue in the dispatcher: a static-lane change lands as `<title> (#<pr>)` once the
//! full verify passed on the squashed tree, an invalid pull request goes back to its worker, and
//! a failed light round raises the item to standard.

use std::path::Path;
use std::time::{Duration, Instant};

use super::assist_tests::handoff;
use super::dispatcher::Dispatcher;
use super::tests::{DONE, Setup, settle, transitions};
use crate::config::session::ItemStatus;
use crate::orchestrate::form::tests::form;
use crate::orchestrate::issue::acceptance;
use crate::orchestrate::records::{
    self, LEASE_SCHEMA, Lease, Reason, Record, lease_comment, meta_block, ready_comment,
};
use crate::orchestrate::risk::Lane;
use crate::orchestrate::testkit::{FakeProgram, body, git, issue, ready_for};
use crate::orchestrate::tracker::{PullRequest, Tracker};
use crate::testkit::{TempRepo, risk_tiers, tier};

const SEED: &str = "agent = \"chief-architect\"\nscope = \"seed\"\nbranch = \"agent/seed\"\nmax_turns = 200\npaths = [\"docs/plan.md\"]\n";
const CRITERIA: &str = "AC-1 | cargo test | exit 0 | oracle: sh";
const EVAL_DIFF: &str = "[agent.eval-diff]\ngroup = \"evaluator\"\ndescription = \"Diff.\"\nmodel = \"sonnet\"\neffort = \"high\"\ncap_role = \"evaluator-review\"\nmax_turns = 40\ntools = [\"Read\"]\ndisallowed_tools = [\"Edit\", \"Write\"]\ndeny_write = \"@protected\"\nnet = \"none\"\ntrigger = \"event\"\nbody = \"templates/agents/eval-diff.md\"\n";

/// A bare `origin` with `main` pushed, so the queue can fetch and the worker can push.
fn with_origin(setup: &Setup) -> TempRepo {
    let origin = TempRepo::create();
    git(origin.root(), &["init", "--quiet", "--bare"]);
    let url = origin.root().to_string_lossy().into_owned();
    git(setup.temp.root(), &["remote", "add", "origin", &url]);
    git(setup.temp.root(), &["push", "--quiet", "origin", "main"]);
    origin
}

/// Commits the worker's tree on its branch, pushes it, and opens its pull request.
fn push_and_open(setup: &Setup, item: u64, title: &str, body: &str) -> String {
    let worktree = setup
        .temp
        .root()
        .join(format!(".agent/worktrees/{item}-a1"));
    let branch = format!("agent/{item}/a1");
    git(&worktree, &["add", "-A"]);
    git(&worktree, &["commit", "--quiet", "-m", title]);
    git(&worktree, &["push", "--quiet", "origin", &branch]);
    let head = git(&worktree, &["rev-parse", "HEAD"]).trim().to_owned();
    setup.tracker.set_pull_request(
        &branch,
        PullRequest {
            number: item * 10,
            title: title.to_owned(),
            body: body.to_owned(),
            head: head.clone(),
            base: "main".into(),
            ..PullRequest::default()
        },
    );
    head
}

fn valid_body(item: u64) -> String {
    let block = meta_block(&form().meta(item, "claude-sonnet-5-5", 1)).unwrap();
    format!("Work item: #{item}\nCloses #{item}\n\n{block}")
}

fn until_verified(dispatcher: &mut Dispatcher) {
    let started = Instant::now();
    while !dispatcher.idle() {
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "the verify did not end"
        );
        std::thread::sleep(Duration::from_millis(50));
        dispatcher.step_queue().unwrap();
    }
}

fn to_review<'a>(setup: &'a Setup, item: u64, file: &str) -> Dispatcher<'a> {
    setup.ready_issue(item, &[], "lead-core");
    setup.fake.respond(1, DONE, 0).writes(1, file, "Words.\n");
    setup
        .tracker
        .open_pull_request_for(&format!("agent/{item}/a1"), item * 10);
    let mut dispatcher = setup.dispatcher();
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    assert_eq!(setup.status(item), Some(ItemStatus::InReview));
    dispatcher
}

#[test]
fn a_static_change_lands_after_the_full_verify_of_the_squashed_tree() {
    let setup = Setup::new("");
    let _origin = with_origin(&setup);
    let verify = FakeProgram::new("queue-verify");
    verify.respond(1, "verify: green\n", 0);
    let mut dispatcher = to_review(&setup, 60, "guide.md");
    dispatcher.set_verifier(verify.program().to_path_buf());
    let head = push_and_open(&setup, 60, "docs: add the guide", &valid_body(60));
    dispatcher.step_github().unwrap();
    until_verified(&mut dispatcher);
    let calls = verify.calls();
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert!(calls[0].starts_with("verify --base "), "{}", calls[0]);
    let squashed = setup.temp.root().join(".agent/worktrees/queue/guide.md");
    assert!(
        Path::new(&squashed).is_file(),
        "the verify ran on the squashed tree"
    );
    dispatcher.step_github().unwrap();
    let merged = format!("merge 600 docs: add the guide (#600) at {head}");
    assert!(
        setup.tracker.calls().contains(&merged),
        "{:?}",
        setup.tracker.calls()
    );
    assert!(!setup.tracker.snapshot(60).is_open());
}

#[test]
fn an_invalid_title_goes_back_to_the_worker_with_the_reason() {
    let setup = Setup::new("");
    let _origin = with_origin(&setup);
    let mut dispatcher = to_review(&setup, 61, "notes.md");
    push_and_open(&setup, 61, "Add the notes", "Work item: #61");
    setup.fake.respond(2, DONE, 0);
    dispatcher.step_github().unwrap();
    let found = setup.found(61);
    assert!(
        transitions(&found).contains(&(ItemStatus::Leased, Reason::PullRequestInvalid)),
        "{:?}",
        transitions(&found)
    );
    let after = setup.tracker.snapshot(61);
    let line = &after.comments.last().unwrap().body;
    assert!(line.contains("title: `Add the notes` is not"), "{line}");
    assert!(line.contains("no `Closes #61` line"), "{line}");
    settle(&mut dispatcher);
    let fix = &setup.fake.calls()[1];
    assert!(fix.contains("impl-rust --item 61"), "{fix}");
    assert!(!fix.contains("--seed"), "{fix}");
}

#[test]
fn a_failed_light_round_raises_the_item_to_standard() {
    let setup = Setup::new("");
    setup.temp.add_agents(EVAL_DIFF);
    let diff = "[\"eval-diff\"]";
    let tiers = [
        tier("high", "[]", "[]", diff),
        tier("medium", "[\"crates/**\"]", "[]", diff),
        tier("low", "[\"docs/**\"]", "[]", diff),
    ]
    .concat();
    setup
        .temp
        .write(".agents/risk-tiers.toml", &risk_tiers(&tiers, diff));
    git(setup.temp.root(), &["add", "-A"]);
    git(
        setup.temp.root(),
        &["commit", "--quiet", "-m", "chore: lanes"],
    );
    let _origin = with_origin(&setup);
    let mut dispatcher = to_review(&setup, 62, "a.rs");
    push_and_open(&setup, 62, "feat(core): add a", &valid_body(62));
    setup.fake.respond(2, DONE, 0);
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    let calls = setup.fake.calls();
    assert!(
        calls[1].contains("eval-diff --item 62 --model claude-sonnet-5-5 --effort low"),
        "{}",
        calls[1]
    );
    assert!(
        calls[1].contains("without the review workflow"),
        "{}",
        calls[1]
    );
    setup
        .tracker
        .comment(62, &handoff(62, "eval-diff", "fail", "claude-sonnet-5-5"))
        .unwrap();
    setup.fake.respond(3, DONE, 0);
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    let found: Vec<Record> = setup.found(62);
    assert_eq!(records::lane_floor(&found, 62), Some(Lane::Standard));
    assert!(transitions(&found).contains(&(ItemStatus::Leased, Reason::EvaluatorFindings)));
}

#[test]
fn a_pull_request_against_another_base_is_refused() {
    let setup = Setup::new("");
    let _origin = with_origin(&setup);
    git(
        setup.temp.root(),
        &["push", "--quiet", "origin", "main:release/1.0"],
    );
    let mut dispatcher = to_review(&setup, 64, "notes.md");
    push_and_open(&setup, 64, "docs: add the notes", &valid_body(64));
    let mut request = setup
        .tracker
        .open_pull_request("agent/64/a1")
        .unwrap()
        .unwrap();
    request.base = "release/1.0".into();
    setup.tracker.set_pull_request("agent/64/a1", request);
    setup.fake.respond(2, DONE, 0);
    dispatcher.step_github().unwrap();
    let found = setup.found(64);
    assert!(
        transitions(&found).contains(&(ItemStatus::Leased, Reason::PullRequestInvalid)),
        "{:?}",
        transitions(&found)
    );
    assert!(
        !setup
            .tracker
            .calls()
            .iter()
            .any(|call| call.starts_with("merge 640"))
    );
}

#[test]
fn a_squash_subject_over_the_limit_is_refused() {
    let setup = Setup::new("");
    let _origin = with_origin(&setup);
    let mut dispatcher = to_review(&setup, 63, "guide.md");
    let title = format!("docs: {}", "x".repeat(66));
    push_and_open(&setup, 63, &title, &valid_body(63));
    setup.fake.respond(2, DONE, 0);
    dispatcher.step_github().unwrap();
    let found = setup.found(63);
    assert!(
        transitions(&found).contains(&(ItemStatus::Leased, Reason::PullRequestInvalid)),
        "{:?}",
        transitions(&found)
    );
    let after = setup.tracker.snapshot(63);
    let line = &after.comments.last().unwrap().body;
    assert!(line.contains("(#630)"), "{line}");
    assert!(
        !setup
            .tracker
            .calls()
            .iter()
            .any(|call| call.starts_with("merge 630"))
    );
}

#[test]
fn an_acceptance_edit_in_review_returns_the_item_to_proposed() {
    let setup = Setup::new("");
    let _origin = with_origin(&setup);
    let mut dispatcher = to_review(&setup, 65, "guide.md");
    push_and_open(&setup, 65, "docs: add the guide", &valid_body(65));
    let mut edited = setup.tracker.snapshot(65);
    edited.body = crate::orchestrate::testkit::body(
        "impl-rust",
        &["crates/grdr-core/**"],
        "AC-1 | cargo test | exit 1 | oracle: sh",
    );
    setup.tracker.add(edited);
    dispatcher.step_github().unwrap();
    assert_eq!(setup.status(65), Some(ItemStatus::Proposed));
    assert!(
        transitions(&setup.found(65)).contains(&(ItemStatus::Proposed, Reason::AcceptanceChanged))
    );
    assert!(
        !setup
            .tracker
            .calls()
            .iter()
            .any(|call| call.starts_with("merge 650"))
    );
}

#[test]
fn a_landed_labels_change_is_synced_onto_the_repository() {
    let setup = Setup::new("");
    let plain = crate::testkit::plain_tiers("[]", "[\"crates/**\"]", "[\"docs/**\"]");
    setup
        .temp
        .write(".agents/risk-tiers.toml", &risk_tiers(&plain, "[]"));
    git(setup.temp.root(), &["add", "-A"]);
    git(
        setup.temp.root(),
        &["commit", "--quiet", "-m", "chore: tiers"],
    );
    let _origin = with_origin(&setup);
    let verify = FakeProgram::new("labels-verify");
    verify.respond(1, "verify: green\n", 0);
    setup.ready_issue(66, &[], "lead-core");
    let labels = std::fs::read_to_string(setup.temp.repo().path(".github/labels.toml")).unwrap();
    let added = format!(
        "{labels}\n[[label]]\nname = \"kind:example\"\ncolor = \"ededed\"\ndescription = \"An example\"\n"
    );
    setup
        .fake
        .respond(1, DONE, 0)
        .writes(1, ".github/labels.toml", &added);
    setup.tracker.open_pull_request_for("agent/66/a1", 660);
    let mut dispatcher = setup.dispatcher();
    dispatcher.set_verifier(verify.program().to_path_buf());
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    push_and_open(
        &setup,
        66,
        "chore(labels): add kind:example",
        &valid_body(66),
    );
    dispatcher.step_github().unwrap();
    until_verified(&mut dispatcher);
    dispatcher.step_github().unwrap();
    let calls = setup.tracker.calls();
    assert!(
        calls.iter().any(|call| call.starts_with("merge 660")),
        "{calls:?}"
    );
    assert!(
        calls.iter().any(|call| call == "label create kind:example"),
        "{calls:?}"
    );
}

#[test]
fn the_seed_pull_request_sent_back_by_the_queue_is_fixed_in_the_seed_scope() {
    let setup = Setup::new("");
    let _origin = with_origin(&setup);
    setup.temp.write(".agents/kit/seed-scope.toml", SEED);
    let text = body("chief-architect", &["docs/plan.md"], CRITERIA);
    let digest = acceptance(&text).unwrap().sha256;
    setup.tracker.add(issue(
        62,
        &["status:in-review", "agent:chief-architect"],
        &text,
    ));
    let ready = ready_for(62, "programme-manager", &text);
    let lease = Lease {
        schema: LEASE_SCHEMA.into(),
        item: 62,
        attempt: 1,
        agent: "chief-architect".into(),
        model: "claude-fable-5-2".into(),
        acceptance_sha256: digest,
        branch: "agent/seed".into(),
        session: None,
    };
    for comment in [
        ready_comment(&ready).unwrap(),
        lease_comment(&lease).unwrap(),
    ] {
        setup.tracker.comment(62, &comment).unwrap();
    }
    let worktree = setup.temp.root().join(".agent/worktrees/62-a1");
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
    git(&worktree, &["commit", "--quiet", "-m", "Seed the team"]);
    git(&worktree, &["push", "--quiet", "origin", "agent/seed"]);
    let head = git(&worktree, &["rev-parse", "HEAD"]).trim().to_owned();
    setup.tracker.set_pull_request(
        "agent/seed",
        PullRequest {
            number: 620,
            title: "Seed the team".into(),
            body: "Work item: #62".into(),
            head,
            base: "main".into(),
            ..PullRequest::default()
        },
    );
    setup.fake.respond(1, DONE, 0);
    let mut dispatcher = setup.dispatcher();
    dispatcher.step_github().unwrap();
    assert!(
        transitions(&setup.found(62)).contains(&(ItemStatus::Leased, Reason::PullRequestInvalid)),
        "{:?}",
        transitions(&setup.found(62))
    );
    settle(&mut dispatcher);
    let calls = setup.fake.calls();
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert!(
        calls[0].contains("chief-architect --item 62 --seed --print"),
        "{}",
        calls[0]
    );
}
