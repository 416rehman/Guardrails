//! The dispatcher's planning and review passes: proposed issues reach their squad's lead and are
//! planned again only after a change, issues in review get `eval-tier` first and `eval-diff` on
//! the other model, a failed round goes back to the worker, and a held lease whose acceptance
//! section changed goes back to proposed.

use super::tests::{DONE, Setup, settle, transitions};
use crate::config::session::ItemStatus;
use crate::orchestrate::records::Reason;
use crate::orchestrate::testkit::{body, git, issue};
use crate::orchestrate::tracker::Tracker;
use crate::testkit::{risk_tiers, tier};

const LEAD: &str = "[agent.lead-core]\ngroup = \"lead\"\ndescription = \"Core lead.\"\nmodel = \"opus\"\neffort = \"high\"\ncap_role = \"lead\"\nmax_turns = 40\ntools = [\"Read\"]\ndisallowed_tools = [\"Edit\", \"Write\"]\ndeny_write = \"@protected\"\nnet = \"A\"\ntrigger = \"dispatch\"\nbody = \"templates/agents/lead-core.md\"\n";
const EVALUATORS: &str = "[agent.eval-tier]\ngroup = \"evaluator\"\ndescription = \"Tier.\"\nmodel = \"sonnet\"\neffort = \"low\"\ncap_role = \"evaluator-light\"\nmax_turns = 30\ntools = [\"Read\"]\ndisallowed_tools = [\"Edit\", \"Write\"]\ndeny_write = \"@protected\"\nnet = \"none\"\ntrigger = \"event\"\nbody = \"templates/agents/eval-tier.md\"\n\n[agent.eval-diff]\ngroup = \"evaluator\"\ndescription = \"Diff.\"\nmodel = \"sonnet\"\neffort = \"high\"\ncap_role = \"evaluator-review\"\nmax_turns = 40\ntools = [\"Read\"]\ndisallowed_tools = [\"Edit\", \"Write\"]\ndeny_write = \"@protected\"\nnet = \"none\"\ntrigger = \"event\"\nbody = \"templates/agents/eval-diff.md\"\n";
const OWNERS: &str = "[squad.core]\nlead = \"lead-core\"\npaths = [\"crates/**\"]\n";

pub(super) fn handoff(item: u64, agent: &str, status: &str, model: &str) -> String {
    format!(
        "Hand-off.\n\n<details><summary>handoff.v1</summary>\n\n```json\n{{\"schema\": \"handoff.v1\", \"item\": {item}, \"agent\": \"{agent}\", \"model\": \"{model}\", \"status\": \"{status}\"}}\n```\n\n</details>\n"
    )
}

#[test]
fn a_proposed_issue_gets_its_squads_lead_and_is_not_planned_twice() {
    let setup = Setup::new("");
    setup.temp.add_agents(LEAD);
    setup.temp.write(".agents/owners.toml", OWNERS);
    setup.tracker.add(issue(
        30,
        &["status:proposed", "squad:core"],
        "A gap a gardener filed.",
    ));
    setup.fake.respond(1, DONE, 0);
    let mut dispatcher = setup.dispatcher();
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    let calls = setup.fake.calls();
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert!(calls[0].contains("lead-core --item 30"), "{}", calls[0]);
    assert!(
        calls[0].contains("cargo xtask kit ready 30"),
        "{}",
        calls[0]
    );
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    assert_eq!(
        setup.fake.calls().len(),
        1,
        "an unchanged issue is not planned again"
    );
    setup
        .tracker
        .comment(30, "More detail from the filer.")
        .unwrap();
    setup.fake.respond(2, DONE, 0);
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    assert_eq!(
        setup.fake.calls().len(),
        2,
        "a changed issue is planned again"
    );
}

#[test]
fn an_issue_in_review_gets_eval_tier_first_and_a_failed_round_goes_back_to_its_worker() {
    let setup = Setup::new("");
    setup.temp.add_agents(EVALUATORS);
    setup.ready_issue(40, &[], "lead-core");
    let code: String = (0..60)
        .map(|i| format!("pub const C{i}: u8 = {i};\n"))
        .collect();
    setup.fake.respond(1, DONE, 0).writes(1, "lib60.rs", &code);
    setup.tracker.open_pull_request_for("agent/40/a1", 400);
    let mut dispatcher = setup.dispatcher();
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    assert_eq!(setup.status(40), Some(ItemStatus::InReview));
    setup.fake.respond(2, DONE, 0);
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    let calls = setup.fake.calls();
    assert!(calls[1].contains("eval-tier --item 40"), "{}", calls[1]);
    setup
        .tracker
        .comment(40, &handoff(40, "eval-tier", "pass", "claude-sonnet-5-5"))
        .unwrap();
    setup.fake.respond(3, DONE, 0);
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    let calls = setup.fake.calls();
    assert!(calls[2].contains("eval-diff --item 40"), "{}", calls[2]);
    assert!(
        calls[2].contains("--model claude-opus-5-5"),
        "eval-diff runs on the model that did not write the change: {}",
        calls[2]
    );
    setup
        .tracker
        .comment(40, &handoff(40, "eval-diff", "fail", "claude-opus-5-5"))
        .unwrap();
    setup.fake.respond(4, DONE, 0);
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    assert!(
        transitions(&setup.found(40)).contains(&(ItemStatus::Leased, Reason::EvaluatorFindings)),
        "{:?}",
        transitions(&setup.found(40))
    );
    assert!(
        setup.fake.calls()[3].contains("impl-rust --item 40"),
        "the worker fixes the findings: {}",
        setup.fake.calls()[3]
    );
}

#[test]
fn a_held_lease_whose_acceptance_changed_goes_back_to_proposed() {
    let setup = Setup::new("");
    setup.ready_issue(50, &[], "lead-core");
    setup.fake.respond(1, DONE, 0);
    let mut dispatcher = setup.dispatcher();
    dispatcher.step_github().unwrap();
    let mut changed = setup.tracker.snapshot(50);
    changed.body = body(
        "impl-rust",
        &["crates/grdr-core/**"],
        "AC-1 | cargo test | exit 1 | oracle: sh",
    );
    setup.tracker.add(changed);
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    assert_eq!(setup.status(50), Some(ItemStatus::Proposed));
    assert!(
        transitions(&setup.found(50)).contains(&(ItemStatus::Proposed, Reason::AcceptanceChanged))
    );
}

/// Commits `.agents/risk-tiers.toml` with `medium` as the medium tier's evaluators and `kinds` as
/// its `[kinds]` entries, so the dispatcher reads them from the base.
fn commit_tiers(setup: &Setup, medium: &str, kinds: &str) {
    let tiers = [
        tier("high", "[]", "[]", medium),
        tier("medium", "[\"crates/**\"]", "[]", medium),
        tier("low", "[\"docs/**\"]", "[]", medium),
    ]
    .concat();
    let text = risk_tiers(&tiers, "[]").replace("[kinds]\n", &format!("[kinds]\n{kinds}"));
    setup.temp.write(".agents/risk-tiers.toml", &text);
    git(setup.temp.root(), &["add", "-A"]);
    git(
        setup.temp.root(),
        &["commit", "--quiet", "-m", "chore: tiers"],
    );
}

/// Leases `number`, runs its worker to a 60-line change and moves it to review.
fn in_review<'a>(
    setup: &'a Setup,
    number: u64,
    labels: &[&str],
) -> super::dispatcher::Dispatcher<'a> {
    setup.ready_issue(number, labels, "lead-core");
    let code: String = (0..60)
        .map(|i| format!("pub const C{i}: u8 = {i};\n"))
        .collect();
    setup.fake.respond(1, DONE, 0).writes(1, "lib60.rs", &code);
    setup
        .tracker
        .open_pull_request_for(&format!("agent/{number}/a1"), number * 10);
    let mut dispatcher = setup.dispatcher();
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    assert_eq!(setup.status(number), Some(ItemStatus::InReview));
    dispatcher
}

#[test]
fn a_ui_change_gets_the_ux_and_accessibility_evaluators() {
    let setup = Setup::new("");
    setup.temp.add_agents(EVALUATORS);
    setup.temp.add_agents(
        &EVALUATORS
            .replace("eval-tier", "eval-ux")
            .replace("eval-diff", "eval-a11y"),
    );
    commit_tiers(
        &setup,
        "[\"eval-tier\"]",
        "ui = [\"eval-ux\", \"eval-a11y\"]\n",
    );
    let mut dispatcher = in_review(&setup, 43, &["kind:ui"]);
    setup.fake.respond(2, DONE, 0);
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    setup
        .tracker
        .comment(43, &handoff(43, "eval-tier", "pass", "claude-sonnet-5-5"))
        .unwrap();
    setup.fake.respond(3, DONE, 0).respond(4, DONE, 0);
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    let calls = setup.fake.calls();
    assert!(
        calls.iter().any(|call| call.contains("eval-ux --item 43")),
        "{calls:?}"
    );
    assert!(
        calls
            .iter()
            .any(|call| call.contains("eval-a11y --item 43")),
        "{calls:?}"
    );
}

#[test]
fn an_unknown_evaluator_stops_the_review() {
    let setup = Setup::new("");
    setup.temp.add_agents(EVALUATORS);
    commit_tiers(&setup, "[\"eval-tier\", \"eval-renamed\"]", "");
    let mut dispatcher = in_review(&setup, 44, &[]);
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    let found = setup.found(44);
    assert!(
        transitions(&found).contains(&(ItemStatus::Escalated, Reason::EvaluatorUnavailable)),
        "{:?}",
        transitions(&found)
    );
    assert_eq!(setup.fake.calls().len(), 1, "no evaluator started");
    assert!(
        !setup
            .tracker
            .calls()
            .iter()
            .any(|call| call.starts_with("merge"))
    );
}
