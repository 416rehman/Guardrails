use serde_json::json;

use super::*;
use crate::config::session::Scope;
use crate::github::EXIT_OWNER_STEP;
use crate::orchestrate::form::tests::{FORM, form};
use crate::orchestrate::records::{LEASE_SCHEMA, Lease, Record, lease_comment, meta_in, records};
use crate::orchestrate::testkit::{MemoryTracker, body, git, init_git, issue};
use crate::testkit::TempRepo;

/// A temporary repository whose harness carries the GitHub identity and the commit form.
fn temp_repo() -> TempRepo {
    let temp = TempRepo::create();
    temp.write(
        ".agents/harness.toml",
        &format!(
            "{}{FORM}[dispatch]\nprotected_change_agents = [\"lead-agent-kit\", \"chief-architect\"]\n",
            crate::github::tests::GITHUB
        ),
    );
    temp
}

fn draft(status: &str) -> Value {
    json!({
        "schema": "handoff.v1", "item": 7, "agent": "impl-rust", "model": "claude-sonnet-5-5",
        "status": status, "round": 1, "summary": "Fixed the parser. Evidence verify-20261111T100200Z.",
        "changed_paths": ["crates/a/src/lib.rs"],
        "evidence": [{"cmd": "cargo xtask verify --fast", "exit": 0, "log": ".agent/logs/v.log", "sha256": "ab"}],
        "acceptance": [{"id": "AC-1", "result": "pass", "evidence": 0}, {"id": "AC-2", "result": "not-run", "evidence": 0}],
        "decisions": [{"at": "crates/a/src/lib.rs:3", "choice": "kept the old name", "spec_silent": true, "confidence": "low"}],
        "revert": "git revert abc123",
        "next": "Evaluators run AC-1."
    })
}

fn leased_tracker() -> MemoryTracker {
    let tracker = MemoryTracker::default();
    tracker.add(issue(
        7,
        &["status:leased", "agent:impl-rust", "kind:feature"],
        &body("impl-rust", &["crates/a/**"], "AC-1"),
    ));
    let lease = Lease {
        schema: LEASE_SCHEMA.into(),
        item: 7,
        attempt: 1,
        agent: "impl-rust".into(),
        model: "claude-sonnet-5-5".into(),
        acceptance_sha256: "x".into(),
        branch: "agent/7/a1".into(),
        session: None,
    };
    tracker.comment(7, &lease_comment(&lease).unwrap()).unwrap();
    tracker
}

fn caller(agent: &str) -> Caller {
    Caller {
        session: Session {
            agent: Some(agent.to_owned()),
            ..Session::default()
        },
        model: None,
    }
}

fn write_draft(temp: &TempRepo, value: &Value) {
    temp.write(".agent/state/handoff-7-impl-rust.json", &value.to_string());
}

fn check(value: &Value, group: Group, bug: bool, launched: Option<&str>) -> Vec<String> {
    let ids = vec!["claude-sonnet-5-5".to_owned(), "claude-opus-5-5".to_owned()];
    let expect = Expectation {
        item: 7,
        agent: "impl-rust",
        model_ids: &ids,
        launcher_model: launched,
        kind: kind(group, bug),
    };
    crate::hook::handoff::validate(value, &expect)
}

#[test]
fn drafts_are_checked_against_handoff_v1() {
    assert_eq!(
        check(&draft("done"), Group::Implementer, false, None),
        Vec::<String>::new()
    );
    let problems = check(&draft("done"), Group::Implementer, true, None);
    assert_eq!(problems.len(), 1, "{problems:?}");
    let mut bad = draft("finished");
    bad["item"] = json!(8);
    bad["extra"] = json!(true);
    bad["evidence"] = json!([{"cmd": "x"}]);
    let problems = check(&bad, Group::Implementer, false, None);
    assert!(problems.iter().any(|p| p.contains("`item` is not 7")));
    assert!(problems.iter().any(|p| p.contains("unknown key `extra`")));
    assert!(
        problems
            .iter()
            .any(|p| p.contains("`status` is not one of"))
    );
    assert!(problems.iter().any(|p| p.contains("evidence[0].exit")));
    assert!(check(&draft("pass"), Group::Evaluator, false, None).is_empty());
}

#[test]
fn the_model_is_the_sessions() {
    let mut opus = draft("pass");
    opus["model"] = json!("claude-opus-5-5");
    let problems = check(&opus, Group::Evaluator, false, Some("claude-sonnet-5-5"));
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(problems[0].contains("claude-sonnet-5-5"), "{problems:?}");
    assert!(check(&opus, Group::Evaluator, false, Some("claude-opus-5-5")).is_empty());
    let temp = temp_repo();
    let tracker = leased_tracker();
    let mut done = draft("done");
    done["model"] = json!("claude-opus-5-5");
    write_draft(&temp, &done);
    let comments = tracker.snapshot(7).comments.len();
    let launched = Caller {
        model: Some("claude-sonnet-5-5".to_owned()),
        ..caller("impl-rust")
    };
    let code = publish(&temp.repo(), &tracker, 7, &launched, Mode::Live).unwrap();
    assert_eq!(code, ExitCode::from(2));
    assert_eq!(tracker.snapshot(7).comments.len(), comments);
}

#[test]
fn the_status_decides_what_follows_the_comment() {
    assert_eq!(follow("done", Output::Code, false), Follow::PullRequest);
    assert_eq!(follow("done", Output::Comments, false), Follow::Nothing);
    assert_eq!(follow("partial", Output::Code, false), Follow::PushOnly);
    assert_eq!(
        follow("blocked", Output::Code, true),
        Follow::Status(ItemStatus::Escalated)
    );
    assert_eq!(
        follow("blocked", Output::Code, false),
        Follow::Status(ItemStatus::Blocked)
    );
    assert_eq!(
        follow("impossible", Output::Code, false),
        Follow::Status(ItemStatus::Proposed)
    );
    assert_eq!(follow("pass", Output::Comments, false), Follow::Nothing);
}

#[test]
fn a_protected_change_lease_ships_its_code() {
    let temp = temp_repo();
    let snapshot = ItemSnapshot {
        schema: crate::config::session::SNAPSHOT_SCHEMA.to_owned(),
        number: 7,
        title: "[WI-0003] Gate configuration".to_owned(),
        agent: "chief-architect".to_owned(),
        kind: "feature".to_owned(),
        squad: None,
        size: None,
        risk_tier: crate::config::session::RiskTier::High,
        trust_core: true,
        write_set: vec!["docs/decisions/**".to_owned()],
        status: ItemStatus::Leased,
        acceptance_sha256: "x".to_owned(),
        attempt: 1,
        fetched_at: "2026-11-11T10:00:00Z".to_owned(),
    };
    snapshot.save(&temp.repo()).unwrap();
    let protected = Session {
        agent: Some("chief-architect".to_owned()),
        work_item: Some(7),
        scope: Some(Scope::Protected),
    };
    let shipped = output(
        &temp.repo(),
        &protected,
        "chief-architect",
        Group::Direction,
    );
    assert_eq!(shipped.unwrap(), Output::Code);
    let ordinary = Session {
        scope: None,
        ..protected
    };
    let commented = output(&temp.repo(), &ordinary, "chief-architect", Group::Direction);
    assert_eq!(commented.unwrap(), Output::Comments);
    let implementer = output(
        &temp.repo(),
        &Session::default(),
        "impl-rust",
        Group::Implementer,
    );
    assert_eq!(implementer.unwrap(), Output::Code);
}

#[test]
fn a_blocked_handoff_with_a_packet_escalates() {
    let temp = temp_repo();
    let tracker = leased_tracker();
    write_draft(&temp, &draft("blocked"));
    temp.write(
        ".agent/state/escalation-7.md",
        "### Escalation #7-E1\nQuestion: new dependency?\n",
    );
    let code = publish(&temp.repo(), &tracker, 7, &caller("impl-rust"), Mode::Live).unwrap();
    assert_eq!(code, ExitCode::SUCCESS);
    let after = tracker.snapshot(7);
    assert_eq!(after.status(), Some(ItemStatus::Escalated));
    let posted = &after.comments.last().unwrap().body;
    assert!(posted.starts_with("Hand-off from impl-rust, attempt 1, round 1: **blocked**."));
    assert!(posted.contains("### Escalation #7-E1"));
    assert_eq!(meta_in(posted), None);
    assert!(matches!(records(&after).last(), Some(Record::Handoff(_))));
}

#[test]
fn an_impossible_handoff_returns_to_proposed_and_bad_drafts_post_nothing() {
    let temp = temp_repo();
    let tracker = leased_tracker();
    write_draft(&temp, &draft("impossible"));
    publish(&temp.repo(), &tracker, 7, &caller("impl-rust"), Mode::Live).unwrap();
    assert_eq!(tracker.snapshot(7).status(), Some(ItemStatus::Proposed));
    let comments = tracker.snapshot(7).comments.len();
    let mut bad = draft("done");
    bad["agent"] = json!("impl-web");
    write_draft(&temp, &bad);
    let code = publish(&temp.repo(), &tracker, 7, &caller("impl-rust"), Mode::Live).unwrap();
    assert_eq!(code, ExitCode::from(2));
    assert_eq!(tracker.snapshot(7).comments.len(), comments);
}

#[test]
fn a_done_handoff_pushes_and_opens_the_pull_request() {
    let temp = temp_repo();
    temp.write(".gitignore", ".agent/\n");
    init_git(temp.root());
    git(temp.root(), &["checkout", "--quiet", "-b", "agent/7/a1"]);
    temp.write("crates/a/src/lib.rs", "pub fn a() {}\n");
    git(temp.root(), &["add", "-A"]);
    git(temp.root(), &["commit", "--quiet", "-m", "Add a"]);
    temp.write("crates/a/src/b.rs", "pub fn b() {}\n");
    git(temp.root(), &["add", "-A"]);
    git(temp.root(), &["commit", "--quiet", "-m", "feat(a): add a"]);
    let tracker = leased_tracker();
    write_draft(&temp, &draft("done"));
    let code = publish(&temp.repo(), &tracker, 7, &caller("impl-rust"), Mode::Live).unwrap();
    assert_eq!(code, ExitCode::from(EXIT_OWNER_STEP));
    let origin = TempRepo::create();
    git(origin.root(), &["init", "--quiet", "--bare"]);
    let url = origin.root().to_string_lossy().into_owned();
    git(temp.root(), &["remote", "add", "origin", &url]);
    let code = publish(&temp.repo(), &tracker, 7, &caller("impl-rust"), Mode::Live).unwrap();
    assert_eq!(code, ExitCode::SUCCESS);
    assert!(
        tracker
            .calls()
            .iter()
            .any(|call| call == "pr create agent/7/a1 feat(a): add a")
    );
    assert!(git(origin.root(), &["branch", "--list"]).contains("agent/7/a1"));
    let commented = tracker.snapshot(7);
    let repeated = meta_in(&commented.comments.last().unwrap().body).unwrap();
    assert_eq!(
        (repeated.model.as_str(), repeated.attempt),
        ("claude-sonnet-5-5", 1)
    );
    let issue = tracker.snapshot(7);
    let writer = PullRequestWriter {
        model: "claude-sonnet-5-5",
        attempt: 1,
    };
    let body = pull_request_body(&temp.repo(), &form(), &issue, &draft("done"), writer).unwrap();
    assert!(body.starts_with("Work item: #7   Risk tier: medium"));
    assert!(body.contains("\nCloses #7\n"));
    assert_eq!(meta_in(&body), Some(form().meta(7, "claude-sonnet-5-5", 1)));
    let ids = ["claude-sonnet-5-5"];
    let expected = crate::orchestrate::form::Expected {
        item: 7,
        attempt: 1,
        model_ids: &ids,
    };
    let request = crate::orchestrate::tracker::PullRequest {
        number: 1000,
        title: "feat(a): add a".to_owned(),
        body: body.clone(),
        base: "main".to_owned(),
        ..Default::default()
    };
    assert!(form().pull_request_problems(&request, expected).is_empty());
    assert!(body.contains("- AC-2 was not run"));
    assert!(body.contains("`crates/a/src/lib.rs:3`: kept the old name"));
    assert!(body.contains("`git revert abc123`"));
    publish(&temp.repo(), &tracker, 7, &caller("impl-rust"), Mode::Live).unwrap();
    assert!(
        tracker
            .calls()
            .iter()
            .any(|call| call == "pr edit 1000 feat(a): add a")
    );
}

#[test]
fn no_pull_request_opens_without_a_valid_subject() {
    let temp = temp_repo();
    temp.write(".gitignore", ".agent/\n");
    init_git(temp.root());
    let origin = TempRepo::create();
    git(origin.root(), &["init", "--quiet", "--bare"]);
    let url = origin.root().to_string_lossy().into_owned();
    git(temp.root(), &["remote", "add", "origin", &url]);
    git(temp.root(), &["checkout", "--quiet", "-b", "agent/7/a1"]);
    temp.write("crates/a/src/lib.rs", "pub fn a() {}\n");
    git(temp.root(), &["add", "-A"]);
    git(temp.root(), &["commit", "--quiet", "-m", "Add a"]);
    let tracker = leased_tracker();
    write_draft(&temp, &draft("done"));
    let error = publish(&temp.repo(), &tracker, 7, &caller("impl-rust"), Mode::Live).unwrap_err();
    assert!(format!("{error:#}").contains("no pull request was opened"));
    assert!(
        !tracker
            .calls()
            .iter()
            .any(|call| call.starts_with("pr create"))
    );
}

#[test]
fn the_seed_session_ships_agent_seed_into_review() {
    let temp = temp_repo();
    temp.write(".gitignore", ".agent/\n");
    temp.write(
        ".agents/kit/seed-scope.toml",
        "agent = \"chief-architect\"\nscope = \"seed\"\nbranch = \"agent/seed\"\npaths = [\"AGENTS.md\"]\n",
    );
    init_git(temp.root());
    let origin = TempRepo::create();
    git(origin.root(), &["init", "--quiet", "--bare"]);
    let url = origin.root().to_string_lossy().into_owned();
    git(temp.root(), &["remote", "add", "origin", &url]);
    git(temp.root(), &["push", "--quiet", "origin", "main"]);
    let form = Form::load(&temp.repo()).unwrap();
    crate::orchestrate::launch::check_out_seed_branch(&temp.repo(), &form, "agent/seed").unwrap();
    temp.write("AGENTS.md", "# Agents\n");
    git(temp.root(), &["add", "-A"]);
    git(
        temp.root(),
        &["commit", "--quiet", "-m", "docs(plan): seed the agent team"],
    );
    let tracker = MemoryTracker::default();
    tracker.add(issue(
        7,
        &["status:proposed", "agent:chief-architect"],
        &body("chief-architect", &["AGENTS.md"], "AC-1"),
    ));
    let mut seed = draft("done");
    seed["agent"] = json!("chief-architect");
    temp.write(
        ".agent/state/handoff-7-chief-architect.json",
        &seed.to_string(),
    );
    let ordinary = caller("chief-architect");
    let seeding = Caller {
        session: Session {
            scope: Some(Scope::Seed),
            ..ordinary.session.clone()
        },
        ..ordinary
    };
    let code = publish(&temp.repo(), &tracker, 7, &seeding, Mode::Live).unwrap();
    assert_eq!(code, ExitCode::SUCCESS);
    let calls = tracker.calls();
    assert!(
        calls
            .iter()
            .any(|call| call == "pr create agent/seed docs(plan): seed the agent team"),
        "{calls:?}"
    );
    assert!(git(origin.root(), &["branch", "--list"]).contains("agent/seed"));
    let after = tracker.snapshot(7);
    assert_eq!(after.status(), Some(ItemStatus::InReview));
    let found = records(&after);
    let lease = crate::orchestrate::records::current_lease(&found, 7).unwrap();
    assert_eq!(lease.branch, "agent/seed");
    assert_eq!(
        crate::orchestrate::records::lane_floor(&found, 7),
        Some(crate::orchestrate::risk::Lane::Full)
    );
    assert_eq!(crate::git::current_branch(&temp.repo()).unwrap(), None);
    let worktree = temp.root().join(".agent/worktrees/7-a1");
    git(
        temp.root(),
        &[
            "worktree",
            "add",
            "--quiet",
            &worktree.to_string_lossy(),
            "agent/seed",
        ],
    );
    let fix = Repo::at(&worktree);
    assert_eq!(
        crate::git::current_branch(&fix).unwrap().as_deref(),
        Some("agent/seed")
    );
    release_seed_branch(&fix, "agent/seed").unwrap();
    assert_eq!(
        crate::git::current_branch(&fix).unwrap().as_deref(),
        Some("agent/seed")
    );
}

#[test]
fn the_seed_branch_is_checked_out_from_the_base() {
    let temp = temp_repo();
    temp.write(".gitignore", ".agent/\n");
    init_git(temp.root());
    let repo = temp.repo();
    let form = Form::load(&repo).unwrap();
    crate::orchestrate::launch::check_out_seed_branch(&repo, &form, "agent/seed").unwrap();
    assert_eq!(
        crate::git::current_branch(&repo).unwrap().as_deref(),
        Some("agent/seed")
    );
    crate::orchestrate::launch::check_out_seed_branch(&repo, &form, "agent/seed").unwrap();
    git(temp.root(), &["checkout", "--quiet", "main"]);
    temp.write(".gitignore", ".agent/\ntarget/\n");
    let error =
        crate::orchestrate::launch::check_out_seed_branch(&repo, &form, "agent/seed").unwrap_err();
    assert!(
        format!("{error:#}").contains("uncommitted changes"),
        "{error:#}"
    );
}
