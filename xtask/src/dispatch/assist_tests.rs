//! The dispatcher's planning and review passes: proposed issues reach their squad's lead and are
//! planned again only after a change, an item its squad's lead implements goes to the product
//! lead, the seed's own issue waits for the seed's hand-off and its escalation then goes to the
//! chief architect, issues in review get `eval-tier` first and `eval-diff` on the other model, a
//! failed round goes back to the worker with the fix prompt even when it waited for a slot, and a
//! held lease whose acceptance section changed goes back to proposed. Planners go to blocked
//! issues before proposed ones and by priority within a status; a lead plans several issues at
//! once up to its cap, each in a worktree of its own that is removed once no session runs in it,
//! while the chief architect still decides one escalation at a time.

use std::path::PathBuf;
use std::time::Duration;

use super::tests::{DONE, Setup, settle, transitions};
use super::worker::{self, Launcher, Prepare, Upstream};
use crate::config::session::ItemStatus;
use crate::lock::Lock;
use crate::orchestrate::launch::session_lock_path;
use crate::orchestrate::records::{LEASE_SCHEMA, Lease, Reason, lease_comment};
use crate::orchestrate::testkit::{body, git, issue};
use crate::orchestrate::tracker::Tracker;
use crate::repo::Repo;
use crate::testkit::{risk_tiers, tier};

pub(super) const LEAD: &str = "[agent.lead-core]\ngroup = \"lead\"\ndescription = \"Core lead.\"\nmodel = \"opus\"\neffort = \"high\"\ncap_role = \"lead\"\nmax_turns = 40\ntools = [\"Read\"]\ndisallowed_tools = [\"Edit\", \"Write\"]\ndeny_write = \"@protected\"\nnet = \"A\"\ntrigger = \"dispatch\"\nbody = \"templates/agents/lead-core.md\"\n";
pub(super) const EVALUATORS: &str = "[agent.eval-tier]\ngroup = \"evaluator\"\ndescription = \"Tier.\"\nmodel = \"sonnet\"\neffort = \"low\"\ncap_role = \"evaluator-light\"\nmax_turns = 30\ntools = [\"Read\"]\ndisallowed_tools = [\"Edit\", \"Write\"]\ndeny_write = \"@protected\"\nnet = \"none\"\ntrigger = \"event\"\nbody = \"templates/agents/eval-tier.md\"\n\n[agent.eval-diff]\ngroup = \"evaluator\"\ndescription = \"Diff.\"\nmodel = \"sonnet\"\neffort = \"high\"\ncap_role = \"evaluator-review\"\nmax_turns = 40\ntools = [\"Read\"]\ndisallowed_tools = [\"Edit\", \"Write\"]\ndeny_write = \"@protected\"\nnet = \"none\"\ntrigger = \"event\"\nbody = \"templates/agents/eval-diff.md\"\n";
pub(super) const OWNERS: &str = "[squad.core]\nlead = \"lead-core\"\npaths = [\"crates/**\"]\n";
pub(super) const SEED_SCOPE: &str = "agent = \"chief-architect\"\nscope = \"seed\"\nbranch = \"agent/seed\"\npaths = [\"docs/plan.md\"]\nwork_item = \"WI-0000\"\n";

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
        calls[0].contains("cargo xtask kit ready 30")
            && calls[0].contains(".agent/state/handoff-30-lead-core.json"),
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
fn an_item_its_squad_lead_implements_goes_to_the_product_lead_and_the_seed_issue_to_nobody() {
    let setup = Setup::new("");
    setup.temp.add_agents(LEAD);
    setup.temp.add_agents(
        &LEAD
            .replace("lead-core", "product-lead")
            .replace("\"lead\"", "\"direction\""),
    );
    setup.temp.write(".agents/owners.toml", OWNERS);
    setup.temp.write(".agents/kit/seed-scope.toml", SEED_SCOPE);
    setup.tracker.add(issue(
        31,
        &["status:proposed", "squad:core", "agent:lead-core"],
        "A protected item the core lead implements.",
    ));
    let mut seed = issue(32, &["status:proposed", "squad:core"], "The seed.");
    seed.title = "[WI-0000] Seed the agent team".to_owned();
    setup.tracker.add(seed);
    setup.fake.respond(1, DONE, 0);
    let mut dispatcher = setup.dispatcher();
    assert_eq!(dispatcher.seed_not_handed_off().unwrap(), Some(32));
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    let calls = setup.fake.calls();
    assert_eq!(
        calls.len(),
        1,
        "the seed's issue is never planned: {calls:?}"
    );
    assert!(calls[0].contains("product-lead --item 31"), "{}", calls[0]);
}

#[test]
fn a_handed_off_seed_issue_lets_the_dispatcher_start_and_its_escalation_goes_to_the_chief_architect()
 {
    let setup = Setup::new("");
    setup.temp.write(".agents/owners.toml", OWNERS);
    setup.temp.write(".agents/kit/seed-scope.toml", SEED_SCOPE);
    let mut seed = issue(
        33,
        &["status:escalated", "squad:core", "agent:chief-architect"],
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
    setup.fake.respond(1, DONE, 0);
    let mut dispatcher = setup.dispatcher();
    assert_eq!(
        dispatcher.seed_not_handed_off().unwrap(),
        None,
        "the seed's hand-off posted its lease, so the dispatcher may start"
    );
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    let calls = setup.fake.calls();
    assert_eq!(
        calls.len(),
        1,
        "an unchanged escalation is decided once: {calls:?}"
    );
    assert!(
        calls[0].contains("chief-architect --item 33") && calls[0].contains("decide it"),
        "{}",
        calls[0]
    );
}

#[test]
fn a_fix_that_waited_for_a_writer_slot_starts_with_the_fix_prompt() {
    let setup = Setup::new("");
    setup.temp.add_agents(EVALUATORS);
    let mut dispatcher = in_review(&setup, 46, &[]);
    setup.fake.respond(2, DONE, 0);
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    setup
        .tracker
        .comment(46, &handoff(46, "eval-tier", "pass", "claude-sonnet-5-5"))
        .unwrap();
    setup.fake.respond(3, DONE, 0);
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    setup
        .tracker
        .comment(46, &handoff(46, "eval-diff", "fail", "claude-opus-5-5"))
        .unwrap();
    setup.ready_issue(47, &[], "lead-core");
    setup.fake.respond(4, DONE, 0).respond(5, DONE, 0);
    dispatcher.step_github().unwrap();
    assert_eq!(
        dispatcher.held(),
        vec![47, 46],
        "#47 took the only writer slot, so #46's fix waits"
    );
    settle(&mut dispatcher);
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    let calls = setup.fake.calls();
    assert!(calls[3].contains("impl-rust --item 47"), "{calls:?}");
    assert!(calls[4].contains("impl-rust --item 46"), "{calls:?}");
    assert!(
        calls[4].contains("came back from review") && !calls[4].contains("--resume"),
        "{}",
        calls[4]
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
    assert!(
        calls[1].contains("to .agent/state/handoff-40-eval-tier.json with the Write tool"),
        "the verdict goes through a draft file: {}",
        calls[1]
    );
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

/// Lets `planners` planner sessions run at once; the harness lets one agent run two of them.
fn allow_planners(setup: &Setup, planners: u32) {
    let path = setup.temp.repo().path(".agents/harness.toml");
    let harness = std::fs::read_to_string(&path).unwrap();
    let raised = harness.replace("max_planners = 1", &format!("max_planners = {planners}"));
    std::fs::write(&path, raised).unwrap();
}

/// A lead for squad core, and `issues` filed for that squad with their labels.
fn core_issues(issues: &[(u64, &[&str])]) -> Setup {
    let setup = Setup::new("");
    setup.temp.add_agents(LEAD);
    setup.temp.write(".agents/owners.toml", OWNERS);
    for (number, labels) in issues {
        let all = [&["squad:core"][..], *labels].concat();
        setup
            .tracker
            .add(issue(*number, &all, "A gap a gardener filed."));
    }
    setup
}

/// The issue each session was started on, in start order.
fn items(setup: &Setup) -> Vec<u64> {
    let item = |call: &String| {
        call.split(" --item ")
            .nth(1)?
            .split(' ')
            .next()?
            .parse()
            .ok()
    };
    setup.fake.calls().iter().filter_map(item).collect()
}

fn planning_worktree(setup: &Setup, item: u64) -> PathBuf {
    worker::worktree_dir(&setup.temp.repo(), &format!("plan-lead-core-{item}"))
}

#[test]
fn planners_go_to_blocked_issues_before_proposed_ones_and_by_priority_within_a_status() {
    let setup = core_issues(&[
        (71, &["status:proposed"]),
        (72, &["status:proposed", "priority:p2"]),
        (73, &["status:proposed", "priority:p0"]),
        (74, &["status:blocked"]),
        (75, &["status:blocked", "priority:p1"]),
    ]);
    let mut dispatcher = setup.dispatcher();
    for call in 1..=5 {
        setup.fake.respond(call, DONE, 0);
        dispatcher.step_github().unwrap();
        settle(&mut dispatcher);
    }
    assert_eq!(
        items(&setup),
        vec![75, 74, 73, 72, 71],
        "{:?}",
        setup.fake.calls()
    );
}

#[test]
fn a_lead_plans_several_issues_at_once_up_to_its_cap_each_in_its_own_worktree() {
    let proposed: &[&str] = &["status:proposed"];
    let setup = core_issues(&[(81, proposed), (82, proposed), (83, proposed)]);
    allow_planners(&setup, 4);
    for call in 1..=3 {
        setup.fake.respond(call, DONE, 0);
    }
    let mut dispatcher = setup.dispatcher();
    dispatcher.step_github().unwrap();
    assert!(
        planning_worktree(&setup, 81).join(".git").exists()
            && planning_worktree(&setup, 82).join(".git").exists(),
        "each session has its own checkout"
    );
    assert!(
        !planning_worktree(&setup, 83).exists(),
        "the third issue waits for one of the lead's two sessions"
    );
    settle(&mut dispatcher);
    let mut together = items(&setup);
    together.sort_unstable();
    assert_eq!(together, vec![81, 82], "{:?}", setup.fake.calls());
    assert!(
        !planning_worktree(&setup, 81).exists() && !planning_worktree(&setup, 82).exists(),
        "a planning worktree is removed once its session ended"
    );
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    assert_eq!(items(&setup).last(), Some(&83), "{:?}", setup.fake.calls());
}

#[test]
fn the_chief_architect_decides_one_escalation_at_a_time_whatever_the_agent_cap() {
    let escalated: &[&str] = &["status:escalated"];
    let setup = core_issues(&[(85, escalated), (86, escalated)]);
    allow_planners(&setup, 4);
    for call in 1..=4 {
        setup.fake.respond(call, DONE, 0);
    }
    let mut dispatcher = setup.dispatcher();
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    assert_eq!(
        setup.fake.calls().len(),
        2,
        "the lead reads both escalations at once: {:?}",
        setup.fake.calls()
    );
    for (decided, sessions) in [(85, 3), (86, 4)] {
        dispatcher.step_github().unwrap();
        settle(&mut dispatcher);
        let calls = setup.fake.calls();
        let expected = format!("chief-architect --item {decided}");
        assert!(
            calls.len() == sessions && calls.last().is_some_and(|call| call.starts_with(&expected)),
            "{calls:?}"
        );
    }
}

#[test]
fn a_planning_worktree_left_behind_is_removed_once_no_session_runs_in_it() {
    let setup = core_issues(&[]);
    let launcher = Launcher {
        program: setup.fake.program().to_path_buf(),
        leading: Vec::new(),
        prepare: Prepare::CopyOnly,
    };
    let upstream = Upstream {
        remote: "origin",
        base: "main",
    };
    let left =
        |name: &str| worker::worktree(&setup.temp.repo(), name, None, &launcher, upstream).unwrap();
    let (ended, running) = (left("plan-lead-core-90"), left("plan-lead-core-91"));
    let attempt = left("92-a1");
    let lock = Lock::take(
        session_lock_path(&Repo::at(&running), 91, "lead-core"),
        Duration::from_secs(30),
        "the session a stopped dispatcher left running",
    )
    .unwrap();
    let mut dispatcher = setup.dispatcher();
    dispatcher.step_github().unwrap();
    assert!(!ended.exists(), "no session runs in it");
    assert!(running.exists(), "a session still runs in it");
    drop(lock);
    dispatcher.step_github().unwrap();
    assert!(!running.exists(), "its session ended");
    assert!(attempt.exists(), "an attempt's worktree is not a planner's");
}
