//! `kit ci-env` against a scripted `gh`: a leased pull request prints its writer's three lines,
//! the seed session's prints the seed scope, a protected-change lease prints the protected scope
//! and leaves its snapshot in the change's checkout, never through a link, and a fork, an unleased
//! branch or a lease by someone other than the owner prints nothing. A write set edited after
//! readying widens nothing, and an issue whose agent is not its lease's, or a failed GitHub read,
//! is an error.

use serde_json::json;

use super::*;
use crate::config::session::ItemSnapshot;
use crate::github::tests::identity;
use crate::orchestrate::issue::acceptance;
use crate::orchestrate::records::{LEASE_SCHEMA, Lease, lease_comment, ready_comment};
use crate::orchestrate::testkit::{FakeProgram, body, ready_for};
use crate::testkit::{TempRepo, link_dir};

const CRITERIA: &str = "AC-1 | cargo test | exit 0 | oracle: sh";
const SEED: &str = "agent = \"chief-architect\"\nscope = \"seed\"\nbranch = \"agent/seed\"\npaths = [\"AGENTS.md\"]\n";

fn tracker(fake: &FakeProgram) -> GhTracker {
    GhTracker::new(Gh::new(
        fake.program().to_path_buf(),
        identity(),
        Mode::Live,
    ))
}

fn pull_request(head: &str, owner: &str, closes: u64) -> String {
    json!({
        "headRefName": head,
        "headRepository": {"name": "Guardrails", "nameWithOwner": format!("{owner}/Guardrails")},
        "isCrossRepository": owner != "416rehman",
        "closingIssuesReferences": [
            {"number": closes, "repository": {"name": "Guardrails", "owner": {"login": "416rehman"}}}
        ]
    })
    .to_string()
}

fn leased_issue(number: u64, agent: &str, branch: &str, association: &str) -> String {
    issue_leased_for(number, agent, &["crates/grdr-core/**"], branch, association)
}

/// A readied issue whose current lease names `agent` on `branch`, posted with `association`.
fn issue_leased_for(
    number: u64,
    agent: &str,
    write_set: &[&str],
    branch: &str,
    association: &str,
) -> String {
    let text = body(agent, write_set, CRITERIA);
    let ready = ready_comment(&ready_for(number, "lead-core", &text)).unwrap();
    let comments = [ready, lease(number, agent, &text, branch)];
    issue_json(number, &text, &comments, association)
}

fn lease(number: u64, agent: &str, text: &str, branch: &str) -> String {
    let lease = Lease {
        schema: LEASE_SCHEMA.into(),
        item: number,
        attempt: 1,
        agent: agent.into(),
        model: "claude-sonnet-5-5".into(),
        acceptance_sha256: acceptance(text).unwrap().sha256,
        branch: branch.into(),
        session: None,
    };
    lease_comment(&lease).unwrap()
}

fn issue_json(number: u64, text: &str, comments: &[String], association: &str) -> String {
    let comments: Vec<serde_json::Value> = comments
        .iter()
        .map(|comment| {
            json!({
                "author": {"login": "416rehman"},
                "authorAssociation": association,
                "body": comment,
                "createdAt": "2026-11-11T10:00:00Z"
            })
        })
        .collect();
    json!({
        "number": number,
        "title": "An item",
        "body": text,
        "labels": [{"name": "status:in-review"}],
        "state": "OPEN",
        "comments": comments
    })
    .to_string()
}

fn judged(temp: &TempRepo, fake: &FakeProgram) -> Result<Judged> {
    let kit = LaunchKit::load(&temp.repo()).unwrap();
    judge(&kit, &tracker(fake), 70)
}

#[test]
fn a_leased_pull_request_prints_its_writer() {
    let temp = TempRepo::create();
    let fake = FakeProgram::new("ci-env-leased");
    fake.respond(1, &pull_request("agent/7/a1", "416rehman", 7), 0)
        .respond(2, &leased_issue(7, "impl-rust", "agent/7/a1", "OWNER"), 0);
    let Judged::Leased(writer) = judged(&temp, &fake).unwrap() else {
        panic!("a leased branch has a writer");
    };
    assert_eq!(
        lines(&writer),
        "GRDR_AGENT=impl-rust\nGRDR_WORK_ITEM=7\nGRDR_SCOPE=\n"
    );
    let calls = fake.calls();
    assert!(
        calls[0].starts_with("pr view 70 --json headRefName"),
        "{calls:?}"
    );
    assert!(calls[1].starts_with("issue view 7 --json"), "{calls:?}");
}

#[test]
fn the_seed_pull_request_runs_in_the_seed_scope() {
    let temp = TempRepo::create();
    temp.write(".agents/kit/seed-scope.toml", SEED);
    let fake = FakeProgram::new("ci-env-seed");
    let text = body("chief-architect", &["AGENTS.md"], CRITERIA);
    let only_lease = [lease(1, "chief-architect", &text, "agent/seed")];
    fake.respond(1, &pull_request("agent/seed", "416rehman", 1), 0)
        .respond(2, &issue_json(1, &text, &only_lease, "OWNER"), 0);
    let Judged::Leased(writer) = judged(&temp, &fake).unwrap() else {
        panic!("the seed branch has a writer");
    };
    assert_eq!(
        lines(&writer),
        "GRDR_AGENT=chief-architect\nGRDR_WORK_ITEM=1\nGRDR_SCOPE=seed\n"
    );
}

#[test]
fn a_protected_change_runs_in_the_protected_scope_with_its_snapshot_in_the_checkout() {
    let temp = TempRepo::create();
    let fake = FakeProgram::new("ci-env-protected");
    fake.respond(1, &pull_request("agent/9/a1", "416rehman", 9), 0)
        .respond(
            2,
            &issue_leased_for(9, "chief-architect", &[".claude/**"], "agent/9/a1", "OWNER"),
            0,
        );
    let Judged::Leased(writer) = judged(&temp, &fake).unwrap() else {
        panic!("a leased branch has a writer");
    };
    assert_eq!(
        lines(&writer),
        "GRDR_AGENT=chief-architect\nGRDR_WORK_ITEM=9\nGRDR_SCOPE=protected\n"
    );
    let change = TempRepo::create();
    change.write(
        ".agent/state/item-9.json",
        "{\"schema\": \"committed by the change\"}",
    );
    save_snapshot(&writer, change.root()).unwrap();
    let saved = ItemSnapshot::load(&change.repo(), 9).unwrap().unwrap();
    assert_eq!(saved.agent, "chief-architect");
    assert_eq!(saved.write_set, vec![".claude/**"]);
}

#[test]
fn a_write_set_edited_after_readying_widens_nothing() {
    let temp = TempRepo::create();
    let readied = body("chief-architect", &[".claude/**"], CRITERIA);
    let widened = body("chief-architect", &[".claude/**", ".github/**"], CRITERIA);
    let comments = [
        ready_comment(&ready_for(9, "lead-core", &readied)).unwrap(),
        lease(9, "chief-architect", &widened, "agent/9/a1"),
    ];
    let fake = FakeProgram::new("ci-env-widened");
    fake.respond(1, &pull_request("agent/9/a1", "416rehman", 9), 0)
        .respond(2, &issue_json(9, &widened, &comments, "OWNER"), 0);
    let Judged::Leased(writer) = judged(&temp, &fake).unwrap() else {
        panic!("a leased branch has a writer");
    };
    assert_eq!(
        lines(&writer),
        "GRDR_AGENT=chief-architect\nGRDR_WORK_ITEM=9\nGRDR_SCOPE=\n"
    );
}

#[test]
fn an_issue_whose_agent_is_not_its_leases_is_an_error() {
    let temp = TempRepo::create();
    let text = body("chief-architect", &[".claude/**"], CRITERIA);
    let relabelled = text.replace("### Agent\n\nchief-architect", "### Agent\n\nimpl-rust");
    let comments = [
        ready_comment(&ready_for(9, "lead-core", &text)).unwrap(),
        lease(9, "chief-architect", &text, "agent/9/a1"),
    ];
    let fake = FakeProgram::new("ci-env-relabelled");
    fake.respond(1, &pull_request("agent/9/a1", "416rehman", 9), 0)
        .respond(2, &issue_json(9, &relabelled, &comments, "OWNER"), 0);
    let error = judged(&temp, &fake).unwrap_err();
    assert!(
        format!("{error:#}").contains("issue #9's agent changed since its lease"),
        "{error:#}"
    );
}

#[test]
fn the_snapshot_is_never_saved_through_a_link() {
    let temp = TempRepo::create();
    let fake = FakeProgram::new("ci-env-link");
    fake.respond(1, &pull_request("agent/7/a1", "416rehman", 7), 0)
        .respond(2, &leased_issue(7, "impl-rust", "agent/7/a1", "OWNER"), 0);
    let Judged::Leased(writer) = judged(&temp, &fake).unwrap() else {
        panic!("a leased branch has a writer");
    };
    let change = TempRepo::create();
    let outside = TempRepo::create();
    link_dir(&change.root().join(".agent"), outside.root());
    let error = save_snapshot(&writer, change.root()).unwrap_err();
    assert!(format!("{error:#}").contains("is a link"), "{error:#}");
    assert!(!outside.root().join("state").exists());
}

#[test]
fn a_fork_reads_no_issue() {
    let temp = TempRepo::create();
    let fake = FakeProgram::new("ci-env-fork");
    fake.respond(1, &pull_request("agent/7/a1", "someone", 7), 0);
    assert!(matches!(judged(&temp, &fake).unwrap(), Judged::Fork));
    assert_eq!(fake.calls().len(), 1);
}

#[test]
fn a_lease_by_another_author_or_for_another_branch_is_no_lease() {
    let temp = TempRepo::create();
    let fake = FakeProgram::new("ci-env-untrusted");
    fake.respond(1, &pull_request("agent/7/a1", "416rehman", 7), 0)
        .respond(
            2,
            &leased_issue(7, "impl-rust", "agent/7/a1", "CONTRIBUTOR"),
            0,
        );
    assert!(matches!(judged(&temp, &fake).unwrap(), Judged::Unleased));
    let other = FakeProgram::new("ci-env-other-branch");
    other
        .respond(1, &pull_request("agent/7/a2", "416rehman", 7), 0)
        .respond(2, &leased_issue(7, "impl-rust", "agent/7/a1", "OWNER"), 0);
    assert!(matches!(judged(&temp, &other).unwrap(), Judged::Unleased));
}

#[test]
fn a_failed_read_is_an_error() {
    let temp = TempRepo::create();
    let fake = FakeProgram::new("ci-env-failed");
    fake.respond_err(1, "gh: Bad credentials (HTTP 401)\n", 1);
    let error = judged(&temp, &fake).unwrap_err();
    assert!(
        format!("{error:#}").contains("owner step needed"),
        "{error:#}"
    );
    let unknown = FakeProgram::new("ci-env-unknown");
    unknown.respond_err(1, "gh: Not Found (HTTP 404)\n", 1);
    assert!(judged(&temp, &unknown).is_err());
}
