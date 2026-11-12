use std::time::{Duration, Instant};

use super::dispatcher::Dispatcher;
use super::policy::{OrderKey, Policy};
use super::queue::{self, Candidate};
use super::worker::{Launcher, Prepare};
use super::*;
use crate::config::session::ItemStatus;
use crate::orchestrate::issue::{IssueState, acceptance};
use crate::orchestrate::records::{
    self, LEASE_SCHEMA, Lease, Reason, Record, lease_comment, ready_comment,
};
use crate::orchestrate::testkit::{FakeProgram, MemoryTracker, body, init_git, issue, ready_for};
use crate::testkit::{TempRepo, risk_tiers, tier};

/// A fake session can take seconds to print on a loaded runner, so no session here stalls unless
/// its test asks for `Setup::stalling_dispatcher`.
const HARNESS: &str = "[dispatch]\nprotected_change_agents = [\"lead-agent-kit\", \"chief-architect\"]\nmax_writers = 1\nmax_gardeners = 1\nmax_planners = 1\nmax_evaluators = 2\nstall_seconds = 60\npoll_seconds = 1\npoll_jitter_seconds = 0\nbackoff_base_seconds = 1\nbackoff_cap_seconds = 1\nlease_order = [\"blocks-others\", \"priority\", \"age\"]\n[limits]\nusage_limit_strings = [\"You've hit your session limit\"]\nretry_seconds = 0\n[queue]\nworktree = \"queue\"\nverify_args = [\"verify\"]\nverify_timeout_seconds = 60\n[workspace_trust]\ncheck = \"managed\"\n";
/// Written right after `GITHUB`, so it joins that `[github]` table, which has no branch pattern.
const BRANCH: &str = "branch = \"agent/{issue}/a{attempt}\"\n";
const USAGE: &str = "[item]\nmax_attempts = 2\nmax_review_rounds = 3\nverdict_hours = 24\n[role.worker]\nmax_turns = 80\nwall_clock_minutes = 60\nsessions_per_attempt = 2\n";
const LABELS: &str = "[[transition]]\nfrom = \"proposed\"\nto = \"ready\"\nby = [\"kit\"]\nrun_by = [\"lead-*\", \"programme-manager\"]\n";
const GARDENER: &str = "[agent.garden-docs]\ngroup = \"gardener\"\ndescription = \"Docs.\"\nmodel = \"sonnet\"\neffort = \"medium\"\ncap_role = \"gardener\"\nmax_turns = 60\ntools = [\"Read\"]\ndeny_write = \"@protected\"\nnet = \"none\"\ntrigger = \"schedule\"\nbody = \"templates/agents/garden-docs.md\"\n";
pub(super) const DONE: &str = "{\"type\":\"assistant\",\"message\":{\"id\":\"m1\",\"content\":[]}}\n{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":false,\"num_turns\":1,\"result\":\"handed off\"}\n";
const LIMITED: &str = "{\"type\":\"result\",\"subtype\":\"error_during_execution\",\"is_error\":true,\"result\":\"You've hit your session limit - resets 3pm\"}\n";
const CRITERIA: &str = "AC-1 | cargo test | exit 0 | oracle: sh";

pub(super) struct Setup {
    pub(super) temp: TempRepo,
    pub(super) fake: FakeProgram,
    pub(super) tracker: MemoryTracker,
}

impl Setup {
    pub(super) fn new(usage_extra: &str) -> Setup {
        let temp = TempRepo::create();
        temp.write(".gitignore", ".agent/\n");
        temp.write(
            ".agents/harness.toml",
            &format!(
                "{HARNESS}{}{BRANCH}{}",
                crate::github::tests::GITHUB,
                crate::orchestrate::form::tests::FORM
            ),
        );
        temp.write(".agents/kit/usage.toml", &format!("{USAGE}{usage_extra}"));
        temp.write(".github/labels.toml", LABELS);
        temp.add_agents(GARDENER);
        let evaluators = "[\"eval-tier\", \"eval-diff\"]";
        let tiers = [
            ("high", "[]"),
            ("medium", "[\"crates/**\"]"),
            ("low", "[\"docs/**\"]"),
        ]
        .map(|(name, paths)| tier(name, paths, "[]", evaluators))
        .concat();
        temp.write(".agents/risk-tiers.toml", &risk_tiers(&tiers, "[]"));
        temp.write("security/trust-core.paths", "crates/grdr-crypto/**\n");
        init_git(temp.root());
        Setup {
            temp,
            fake: FakeProgram::new("dispatch-worker"),
            tracker: MemoryTracker::default(),
        }
    }

    pub(super) fn ready_issue(&self, number: u64, labels: &[&str], by: &str) {
        let text = body("impl-rust", &["crates/grdr-core/**"], CRITERIA);
        let mut all = vec!["status:ready", "agent:impl-rust"];
        all.extend_from_slice(labels);
        self.tracker.add(issue(number, &all, &text));
        self.tracker
            .comment(
                number,
                &ready_comment(&ready_for(number, by, &text)).unwrap(),
            )
            .unwrap();
    }

    pub(super) fn dispatcher(&self) -> Dispatcher<'_> {
        self.try_dispatcher().unwrap()
    }

    pub(super) fn try_dispatcher(&self) -> Result<Dispatcher<'_>> {
        self.dispatcher_under(Policy::load(&self.temp.repo(), None).unwrap())
    }

    /// A dispatcher that takes one second without output as a stall.
    fn stalling_dispatcher(&self) -> Dispatcher<'_> {
        let mut policy = Policy::load(&self.temp.repo(), None).unwrap();
        policy.session.stall = Duration::from_secs(1);
        self.dispatcher_under(policy).unwrap()
    }

    fn dispatcher_under(&self, policy: Policy) -> Result<Dispatcher<'_>> {
        let launcher = Launcher {
            program: self.fake.program().to_path_buf(),
            leading: Vec::new(),
            prepare: Prepare::CopyOnly,
        };
        Dispatcher::new(self.temp.repo(), policy, &self.tracker, launcher)
    }

    pub(super) fn found(&self, number: u64) -> Vec<Record> {
        records::records(&self.tracker.snapshot(number))
    }

    pub(super) fn status(&self, number: u64) -> Option<ItemStatus> {
        self.tracker.snapshot(number).status()
    }
}

pub(super) fn settle(dispatcher: &mut Dispatcher) {
    let started = Instant::now();
    dispatcher.step_sessions().unwrap();
    while !dispatcher.idle() {
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "sessions did not end"
        );
        std::thread::sleep(Duration::from_millis(50));
        dispatcher.step_sessions().unwrap();
    }
}

fn leases(found: &[Record]) -> Vec<&Lease> {
    found
        .iter()
        .filter_map(|record| match record {
            Record::Lease(lease) => Some(lease),
            _ => None,
        })
        .collect()
}

pub(super) fn transitions(found: &[Record]) -> Vec<(ItemStatus, Reason)> {
    found
        .iter()
        .filter_map(|record| match record {
            Record::Transition(t) => Some((t.to, t.reason)),
            _ => None,
        })
        .collect()
}

#[test]
fn a_ready_issue_is_leased_run_and_moved_to_review() {
    let setup = Setup::new("");
    setup.ready_issue(7, &[], "lead-core");
    setup.fake.respond(1, DONE, 0);
    setup.tracker.open_pull_request_for("agent/7/a1", 70);
    let mut dispatcher = setup.dispatcher();
    dispatcher.step_github().unwrap();
    assert_eq!(setup.status(7), Some(ItemStatus::Leased));
    let found = setup.found(7);
    let lease = leases(&found)[0];
    assert_eq!(
        (lease.attempt, lease.branch.as_str(), lease.model.as_str()),
        (1, "agent/7/a1", "claude-sonnet-5-5")
    );
    assert!(
        setup
            .tracker
            .snapshot(7)
            .assignees
            .iter()
            .any(|a| a.login == "416rehman")
    );
    settle(&mut dispatcher);
    assert_eq!(setup.status(7), Some(ItemStatus::InReview));
    assert_eq!(
        transitions(&setup.found(7)),
        vec![(ItemStatus::InReview, Reason::PullRequestOpen)]
    );
    let call = &setup.fake.calls()[0];
    assert!(
        call.starts_with("impl-rust --item 7 --print Work issue #7"),
        "{call}"
    );
    assert!(call.contains(&format!("--session-id {}", lease.session.clone().unwrap())));
    assert!(
        setup
            .temp
            .root()
            .join(".agent/worktrees/7-a1/.git")
            .exists()
    );
}

#[test]
fn stalls_return_the_item_to_ready_and_the_second_escalates() {
    let setup = Setup::new("");
    setup.ready_issue(8, &[], "lead-core");
    setup.fake.sleep(1, 4).sleep(2, 4);
    let mut dispatcher = setup.stalling_dispatcher();
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    assert_eq!(setup.status(8), Some(ItemStatus::Ready));
    dispatcher.step_github().unwrap();
    let found = setup.found(8);
    assert_eq!(
        leases(&found).iter().map(|l| l.attempt).collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert_eq!(leases(&found)[1].branch, "agent/8/a2");
    settle(&mut dispatcher);
    assert_eq!(setup.status(8), Some(ItemStatus::Escalated));
    let escalated = setup.found(8);
    assert_eq!(
        transitions(&escalated),
        vec![
            (ItemStatus::Ready, Reason::Stall),
            (ItemStatus::Escalated, Reason::Stall)
        ]
    );
    assert!(
        setup
            .tracker
            .snapshot(8)
            .comments
            .last()
            .unwrap()
            .body
            .starts_with("### Escalation #8-E2")
    );
}

#[test]
fn a_usage_limit_pauses_without_an_attempt_and_the_session_resumes() {
    let setup = Setup::new("");
    setup.ready_issue(9, &[], "lead-core");
    setup.fake.respond(1, LIMITED, 1).respond(2, DONE, 0);
    let mut dispatcher = setup.dispatcher();
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    assert_eq!(setup.status(9), Some(ItemStatus::Leased));
    assert!(transitions(&setup.found(9)).is_empty());
    assert_eq!(dispatcher.held(), vec![9]);
    setup.tracker.open_pull_request_for("agent/9/a1", 90);
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    let session = leases(&setup.found(9))[0].session.clone().unwrap();
    assert!(
        setup.fake.calls()[1].contains(&format!("--resume {session}")),
        "{:?}",
        setup.fake.calls()
    );
    assert_eq!(setup.status(9), Some(ItemStatus::InReview));
    assert_eq!(leases(&setup.found(9)).len(), 1);
}

#[test]
fn readyings_that_no_longer_hold_go_back_to_proposed() {
    let setup = Setup::new("");
    setup.ready_issue(10, &[], "lead-core");
    let mut edited = setup.tracker.snapshot(10);
    edited.body = edited.body.replace("exit 0", "exit 1");
    setup.tracker.add(edited);
    setup.ready_issue(11, &[], "impl-rust");
    setup.ready_issue(12, &[], "lead-core");
    setup.tracker.block(12, 3, IssueState::Open);
    setup.ready_issue(13, &[], "lead-core");
    let mut widened = setup.tracker.snapshot(13);
    widened.body = widened
        .body
        .replace("crates/grdr-core/**\n", "crates/grdr-core/**\n.github/**\n");
    setup.tracker.add(widened);
    let mut dispatcher = setup.dispatcher();
    dispatcher.step_github().unwrap();
    assert_eq!(setup.status(10), Some(ItemStatus::Proposed));
    assert_eq!(
        transitions(&setup.found(10)),
        vec![(ItemStatus::Proposed, Reason::AcceptanceChanged)]
    );
    assert_eq!(setup.status(13), Some(ItemStatus::Proposed));
    assert_eq!(
        transitions(&setup.found(13)),
        vec![(ItemStatus::Proposed, Reason::WriteSetChanged)]
    );
    assert_eq!(setup.status(11), Some(ItemStatus::Proposed));
    assert_eq!(
        transitions(&setup.found(11)),
        vec![(ItemStatus::Proposed, Reason::NoValidReady)]
    );
    assert_eq!(setup.status(12), Some(ItemStatus::Ready));
    assert!(setup.fake.calls().is_empty());
}

#[test]
fn the_writer_ceiling_and_the_lease_order_hold() {
    let setup = Setup::new("");
    setup.ready_issue(20, &["priority:p2"], "lead-core");
    setup.ready_issue(21, &["priority:p0"], "lead-core");
    setup.ready_issue(22, &["priority:p3"], "lead-core");
    setup.tracker.blocks(22, 30);
    setup.fake.respond(1, DONE, 0);
    let mut dispatcher = setup.dispatcher();
    let order: Vec<u64> = dispatcher
        .candidates(false)
        .unwrap()
        .iter()
        .map(|c| c.issue.number)
        .collect();
    assert_eq!(order, vec![22, 21, 20]);
    dispatcher.step_github().unwrap();
    assert_eq!(dispatcher.held(), vec![22]);
    assert_eq!(setup.status(21), Some(ItemStatus::Ready));
    settle(&mut dispatcher);
}

#[test]
fn a_restart_adopts_leases_and_resumes_their_sessions() {
    let setup = Setup::new("");
    setup.ready_issue(14, &[], "lead-core");
    let mut leased = setup.tracker.snapshot(14);
    leased.labels.retain(|label| label.name != "status:ready");
    leased.labels.push(crate::orchestrate::issue::Named {
        name: "status:leased".into(),
    });
    let digest = acceptance(&leased.body).unwrap().sha256;
    setup.tracker.add(leased);
    let lease = Lease {
        schema: LEASE_SCHEMA.into(),
        item: 14,
        attempt: 1,
        agent: "impl-rust".into(),
        model: "claude-sonnet-5-5".into(),
        acceptance_sha256: digest,
        branch: "agent/14/a1".into(),
        session: Some("6b1c0f4e-1111-4222-8333-944455556666".into()),
    };
    setup
        .tracker
        .comment(14, &lease_comment(&lease).unwrap())
        .unwrap();
    setup.fake.respond(1, DONE, 0);
    let mut dispatcher = setup.dispatcher();
    dispatcher.adopt().unwrap();
    assert_eq!(dispatcher.held(), vec![14]);
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    assert!(setup.fake.calls()[0].contains("--resume 6b1c0f4e-1111-4222-8333-944455556666"));
    assert_eq!(setup.status(14), Some(ItemStatus::Ready));
    assert_eq!(
        transitions(&setup.found(14)),
        vec![(ItemStatus::Ready, Reason::NoPullRequest)]
    );
}

#[test]
fn due_routines_run_their_agent_without_an_item() {
    let setup = Setup::new(
        "[role.gardener]\nmax_turns = 60\nwall_clock_minutes = 45\n[routine.garden-docs]\nagent = \"garden-docs\"\ncadence = \"weekly\"\nusage_cap = 0.02\n[routine.review]\nagent = \"eval-diff\"\ncadence = \"pull-request\"\n",
    );
    setup.fake.respond(1, DONE, 0);
    let mut dispatcher = setup.dispatcher();
    dispatcher.step_github().unwrap();
    settle(&mut dispatcher);
    let calls = setup.fake.calls();
    assert_eq!(calls.len(), 1);
    assert!(
        calls[0].starts_with("garden-docs --print Scheduled run of routine garden-docs"),
        "{}",
        calls[0]
    );
    assert!(!calls[0].contains("--item"));
    let schedule = super::routines::Schedule::load(&setup.temp.repo()).unwrap();
    assert!(schedule.last_started.contains_key("garden-docs"));
    dispatcher.step_github().unwrap();
    assert!(dispatcher.idle());
}

#[test]
fn claim_leases_the_next_low_tier_issue() {
    let setup = Setup::new("");
    let text = body("impl-rust", &["docs/guide/**"], CRITERIA);
    setup.tracker.add(issue(
        31,
        &["status:ready", "agent:impl-rust", "tier:low"],
        &text,
    ));
    setup
        .tracker
        .comment(
            31,
            &ready_comment(&ready_for(31, "lead-core", &text)).unwrap(),
        )
        .unwrap();
    setup.ready_issue(32, &[], "lead-core");
    assert_eq!(
        claim(&setup.temp.repo(), &setup.tracker, false).unwrap(),
        ExitCode::SUCCESS
    );
    assert_eq!(setup.status(31), Some(ItemStatus::Leased));
    assert_eq!(setup.status(32), Some(ItemStatus::Ready));
    let snapshot = ItemSnapshot::load(&setup.temp.repo(), 31).unwrap().unwrap();
    assert_eq!(snapshot.risk_tier, RiskTier::Low);
    assert_eq!(snapshot.status, ItemStatus::Leased);
    assert_eq!(leases(&setup.found(31))[0].session, None);
    let mut dispatcher = setup.dispatcher();
    dispatcher.adopt().unwrap();
    assert!(dispatcher.held().is_empty());
}

#[test]
fn order_puts_blockers_first_then_priority_then_age() {
    let candidate = |number: u64, priority: Option<u8>, blocks: bool| {
        let issue = issue(number, &[], "");
        let mut item = issue.work_item();
        item.priority = priority;
        Candidate {
            item,
            agent: "impl-rust".into(),
            digest: String::new(),
            attempt: 1,
            blocks_others: blocks,
            issue,
        }
    };
    let mut list = vec![
        candidate(3, Some(1), false),
        candidate(1, None, false),
        candidate(2, Some(1), false),
        candidate(4, Some(3), true),
    ];
    queue::order(
        &mut list,
        &[OrderKey::BlocksOthers, OrderKey::Priority, OrderKey::Age],
    );
    let numbers: Vec<u64> = list.iter().map(|c| c.issue.number).collect();
    assert_eq!(numbers, vec![4, 2, 3, 1]);
    assert!(
        queue::urgency(true, RiskTier::Low, None) < queue::urgency(false, RiskTier::High, Some(0))
    );
}

#[test]
fn the_chief_architect_is_leased_only_its_protected_changes() {
    let setup = Setup::new("");
    let repo = setup.temp.repo();
    let kit = crate::orchestrate::launch::LaunchKit::load(&repo).unwrap();
    let labels = crate::orchestrate::labels::LabelsFile::load(&repo).unwrap();
    let policy = Policy::load(&repo, None).unwrap();
    let ready = |number: u64, write_set: &[&str]| {
        let text = body("chief-architect", write_set, CRITERIA);
        setup.tracker.add(issue(
            number,
            &["status:ready", "agent:chief-architect"],
            &text,
        ));
        setup
            .tracker
            .comment(
                number,
                &ready_comment(&ready_for(number, "lead-core", &text)).unwrap(),
            )
            .unwrap();
        setup.tracker.issue(number).unwrap()
    };
    let protected = ready(70, &["Cargo.toml"]);
    let verdict = queue::assess(&protected, &kit, &labels, &policy, &setup.tracker).unwrap();
    match verdict {
        queue::Verdict::Eligible(candidate) => assert_eq!(candidate.agent, "chief-architect"),
        queue::Verdict::Wait(why) => assert!(why.contains("a fable session already runs"), "{why}"),
        queue::Verdict::Unready(reason) => panic!("unready: {reason:?}"),
    }
    let ordinary = ready(71, &["docs/notes/guide.md"]);
    let verdict = queue::assess(&ordinary, &kit, &labels, &policy, &setup.tracker).unwrap();
    assert!(
        matches!(&verdict, queue::Verdict::Wait(why) if why.contains("only protected-change items")),
        "{verdict:?}"
    );
}

#[test]
fn a_new_item_branch_starts_from_the_fetched_base_tip() {
    let setup = Setup::new("");
    let origin = TempRepo::create();
    crate::orchestrate::testkit::git(
        origin.root(),
        &["init", "--quiet", "--bare", "--initial-branch=main"],
    );
    let url = origin.root().to_string_lossy().into_owned();
    let run = |root: &std::path::Path, args: &[&str]| crate::orchestrate::testkit::git(root, args);
    run(setup.temp.root(), &["remote", "add", "origin", &url]);
    run(setup.temp.root(), &["push", "--quiet", "origin", "main"]);
    let other = TempRepo::create();
    run(other.root(), &["clone", "--quiet", &url, "clone"]);
    let clone = other.root().join("clone");
    std::fs::write(clone.join("landed.md"), "Landed.\n").unwrap();
    run(&clone, &["add", "-A"]);
    run(&clone, &["commit", "--quiet", "-m", "docs: land a change"]);
    run(&clone, &["push", "--quiet", "origin", "HEAD:main"]);
    let tip = run(&clone, &["rev-parse", "HEAD"]).trim().to_owned();
    let launcher = Launcher {
        program: setup.fake.program().to_path_buf(),
        leading: Vec::new(),
        prepare: Prepare::CopyOnly,
    };
    let upstream = super::worker::Upstream {
        remote: "origin",
        base: "main",
    };
    let dir = super::worker::worktree(
        &setup.temp.repo(),
        "99-a1",
        Some("agent/99/a1"),
        &launcher,
        upstream,
    )
    .unwrap();
    assert_eq!(run(&dir, &["rev-parse", "HEAD"]).trim(), tip);
}
