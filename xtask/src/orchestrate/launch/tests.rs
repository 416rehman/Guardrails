use super::*;
use crate::config::session::{ItemStatus, RiskTier};
use crate::orchestrate::records::{LEASE_SCHEMA, Lease, lease_comment};
use crate::orchestrate::testkit::{FakeProgram, MemoryTracker, body, issue};
use crate::testkit::{TempRepo, plain_tiers, risk_tiers};

const EXTRA_ROSTER: &str = r#"
[agent.impl-kernel]
group = "implementer"
description = "Kernel work."
model = "opus"
effort = "xhigh"
cap_role = "worker"
max_turns = 80
tools = ["Read", "Edit"]
write = ["bpf/**"]
deny_write = "@protected"
net = "A"
trigger = "dispatch"
body = "templates/agents/impl-kernel.md"

[agent.eval-diff]
group = "evaluator"
description = "Reviews diffs."
model = "sonnet"
effort = "high"
cap_role = "evaluator-review"
max_turns = 40
tools = ["Read"]
disallowed_tools = ["Edit", "Write", "NotebookEdit"]
deny_write = "@protected"
net = "none"
trigger = "event"
body = "templates/agents/eval-diff.md"

[agent.lead-agent-kit]
group = "lead"
description = "Leads the agent kit."
model = "opus"
effort = "high"
cap_role = "lead"
max_turns = 40
tools = ["Read", "Edit"]
write = [".agents/**"]
deny_write = "@protected"
net = "A"
trigger = "dispatch"
body = "templates/agents/lead-agent-kit.md"
"#;
const SEED: &str = "agent = \"chief-architect\"\nscope = \"seed\"\nbranch = \"agent/seed\"\nmax_turns = 200\nprompt = \"kit/prompts/seed.md\"\npaths = [\"AGENTS.md\"]\n";
const USAGE: &str = "[role.worker]\nmax_turns = 80\nwall_clock_minutes = 60\n[role.worker.size.S]\neffort = \"low\"\n[role.worker.size.M]\nmax_turns = 150\nwall_clock_minutes = 120\n[role.lead]\nmax_turns = 40\nprotected_change_cap_role = \"worker\"\n";

pub(super) fn repo() -> TempRepo {
    let temp = TempRepo::create();
    temp.add_agents(EXTRA_ROSTER);
    let tiers = plain_tiers("[\"proto/**\"]", "[\"crates/**\"]", "[\"docs/**\"]");
    temp.write(".agents/risk-tiers.toml", &risk_tiers(&tiers, "[]"));
    temp.write("security/trust-core.paths", "crates/grdr-crypto/**\n");
    temp.write(".agents/kit/seed-scope.toml", SEED);
    temp.write(
        ".agents/kit/prompts/seed.md",
        "You are the chief architect.\nStart the team.\n",
    );
    temp.write(".agents/kit/usage.toml", USAGE);
    temp
}

pub(super) fn request(agent: &str, item: Option<u64>, prompting: Prompting) -> Request {
    Request {
        agent: agent.into(),
        item,
        scope: LaunchScope::Ordinary,
        prompting,
        session: SessionStart::New,
        model: None,
        effort: None,
        busy_exit: None,
    }
}

pub(super) fn tracker_with(number: u64, labels: &[&str], write_set: &[&str]) -> MemoryTracker {
    let tracker = MemoryTracker::default();
    tracker.add(issue(
        number,
        labels,
        &body("impl-rust", write_set, "AC-1 | true | exit 0 | oracle: sh"),
    ));
    tracker
}

pub(super) fn env_value<'a>(plan: &'a Plan, name: &str) -> Option<&'a str> {
    plan.env
        .iter()
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.as_str())
}

#[test]
fn the_model_rule_raises_workers_only_for_high_tier_or_trust_core() {
    let temp = repo();
    let kit = LaunchKit::load(&temp.repo()).unwrap();
    let print = || Prompting::Print("Work the issue.".into());
    let medium = tracker_with(
        7,
        &["status:leased", "tier:medium", "agent:impl-rust"],
        &["crates/grdr-core/**"],
    );
    let plan_medium = plan(
        &temp.repo(),
        &kit,
        &medium,
        "claude".into(),
        &request("impl-rust", Some(7), print()),
    )
    .unwrap();
    assert_eq!(plan_medium.model.id, "claude-sonnet-5-5");
    let high = tracker_with(
        7,
        &["status:leased", "tier:high", "agent:impl-rust"],
        &["crates/grdr-core/**"],
    );
    let plan_high = plan(
        &temp.repo(),
        &kit,
        &high,
        "claude".into(),
        &request("impl-rust", Some(7), print()),
    )
    .unwrap();
    assert_eq!(plan_high.model.id, "claude-opus-5-5");
    let trust = tracker_with(
        7,
        &["status:leased", "agent:impl-rust"],
        &["crates/grdr-crypto/src/**"],
    );
    let plan_trust = plan(
        &temp.repo(),
        &kit,
        &trust,
        "claude".into(),
        &request("impl-rust", Some(7), print()),
    )
    .unwrap();
    assert_eq!(plan_trust.model.id, "claude-opus-5-5");
    assert!(plan_trust.snapshot.as_ref().unwrap().trust_core);
    let kernel = kit.choose_model("impl-kernel", None).unwrap();
    assert_eq!(kernel.id, "claude-opus-5-5");
    let snapshot = plan_high.snapshot.clone().unwrap();
    assert_eq!(
        kit.choose_model("eval-diff", Some(&snapshot)).unwrap().id,
        "claude-sonnet-5-5"
    );
    assert_eq!(
        kit.choose_model("chief-architect", None).unwrap().id,
        "claude-fable-5-2"
    );
}

#[test]
fn print_mode_sets_identity_caps_and_the_snapshot() {
    let temp = repo();
    let kit = LaunchKit::load(&temp.repo()).unwrap();
    let tracker = tracker_with(
        12,
        &["status:leased", "agent:impl-rust", "size:M"],
        &["crates/grdr-core/src/**"],
    );
    let request = Request {
        session: SessionStart::Named("0f6c1e2a-7d2b-4c11-9a4e-5b0c1d2e3f42".into()),
        ..request(
            "impl-rust",
            Some(12),
            Prompting::Print("Work issue #12.".into()),
        )
    };
    let plan = plan(&temp.repo(), &kit, &tracker, "claude".into(), &request).unwrap();
    assert_eq!(env_value(&plan, "GRDR_AGENT"), Some("impl-rust"));
    assert_eq!(env_value(&plan, "GRDR_WORK_ITEM"), Some("12"));
    assert_eq!(env_value(&plan, "GRDR_MODEL"), Some("claude-sonnet-5-5"));
    assert!(plan.unset.contains(&"GRDR_SCOPE"));
    assert_eq!(plan.turns, 150);
    let line = plan.args.join(" ");
    assert!(
        line.starts_with("-p --agent impl-rust --model claude-sonnet-5-5 --session-id 0f6c1e2a"),
        "{line}"
    );
    assert!(line.contains(
        "--max-turns 150 --permission-mode dontAsk --output-format stream-json --verbose"
    ));
    assert_eq!(plan.stdin.as_deref(), Some("Work issue #12."));
    let saved = ItemSnapshot::load(&temp.repo(), 12).unwrap().unwrap();
    assert_eq!(saved.write_set, vec!["crates/grdr-core/src/**"]);
    assert_eq!(saved.risk_tier, RiskTier::Medium);
    assert_eq!(saved.status, ItemStatus::Leased);
    let acceptance = std::fs::read_to_string(acceptance_path(&temp.repo(), 12)).unwrap();
    assert!(acceptance.contains("AC-1 | true"));
    assert_eq!(
        saved.acceptance_sha256,
        crate::orchestrate::issue::sha256_hex(b"AC-1 | true | exit 0 | oracle: sh")
    );
}

#[test]
fn a_lease_keeps_its_model_and_a_wrong_agent_is_refused() {
    let temp = repo();
    let kit = LaunchKit::load(&temp.repo()).unwrap();
    let tracker = tracker_with(
        5,
        &["status:leased", "agent:impl-rust"],
        &["crates/grdr-core/**"],
    );
    let lease = Lease {
        schema: LEASE_SCHEMA.into(),
        item: 5,
        attempt: 2,
        agent: "impl-rust".into(),
        model: "claude-opus-5-5".into(),
        acceptance_sha256: "x".into(),
        branch: "agent/5/a2".into(),
        session: None,
    };
    tracker.comment(5, &lease_comment(&lease).unwrap()).unwrap();
    let print = Prompting::Print("Go.".into());
    let plan = plan(
        &temp.repo(),
        &kit,
        &tracker,
        "claude".into(),
        &request("impl-rust", Some(5), print.clone()),
    )
    .unwrap();
    assert_eq!(plan.model.id, "claude-opus-5-5");
    assert_eq!(plan.snapshot.unwrap().attempt, 2);
    let wrong = super::plan(
        &temp.repo(),
        &kit,
        &tracker,
        "claude".into(),
        &request("impl-kernel", Some(5), print),
    );
    assert!(wrong.unwrap_err().to_string().contains("is for impl-rust"));
    let reviewer = super::plan(
        &temp.repo(),
        &kit,
        &tracker,
        "claude".into(),
        &request("eval-diff", Some(5), Prompting::Print("Review #5.".into())),
    )
    .unwrap();
    assert_eq!(reviewer.snapshot.unwrap().agent, "impl-rust");
}

#[test]
fn protected_changes_get_the_protected_scope() {
    let temp = repo();
    let kit = LaunchKit::load(&temp.repo()).unwrap();
    let tracker = MemoryTracker::default();
    tracker.add(issue(
        9,
        &["status:leased", "agent:lead-agent-kit"],
        &body("lead-agent-kit", &[".claude/**"], "AC-1"),
    ));
    let request = request(
        "lead-agent-kit",
        Some(9),
        Prompting::Print("Change the gate.".into()),
    );
    let unleased = plan(&temp.repo(), &kit, &tracker, "claude".into(), &request).unwrap();
    assert_eq!(
        env_value(&unleased, "GRDR_SCOPE"),
        None,
        "no lease.v1 names lead-agent-kit, so nothing widens"
    );
    assert_eq!(unleased.turns, 40, "an unleased lead runs on the lead caps");
    let lease = Lease {
        schema: LEASE_SCHEMA.into(),
        item: 9,
        attempt: 1,
        agent: "lead-agent-kit".into(),
        model: "claude-opus-5-5".into(),
        acceptance_sha256: "x".into(),
        branch: "agent/9/a1".into(),
        session: None,
    };
    tracker.comment(9, &lease_comment(&lease).unwrap()).unwrap();
    let plan = plan(&temp.repo(), &kit, &tracker, "claude".into(), &request).unwrap();
    assert_eq!(env_value(&plan, "GRDR_SCOPE"), Some("protected"));
    assert_eq!(
        plan.turns, 80,
        "a protected-change lease runs on the worker caps its role names"
    );
    assert!(
        !kit.is_protected_change("impl-rust", &[".claude/**".into()])
            .unwrap()
    );
}

#[test]
fn start_passes_identity_and_the_prompt_to_claude() {
    let temp = repo();
    let kit = LaunchKit::load(&temp.repo()).unwrap();
    let fake = FakeProgram::new("launch-claude");
    fake.respond(1, "{\"type\":\"result\",\"subtype\":\"success\"}\n", 3);
    let tracker = tracker_with(
        4,
        &["status:leased", "agent:impl-rust"],
        &["crates/grdr-core/**"],
    );
    let request = request(
        "impl-rust",
        Some(4),
        Prompting::Print("Work issue #4.".into()),
    );
    let plan = plan(
        &temp.repo(),
        &kit,
        &tracker,
        fake.program().to_path_buf(),
        &request,
    )
    .unwrap();
    let code = start(&plan).unwrap();
    assert_eq!(code, ExitCode::from(3));
    assert!(
        fake.env(1)
            .contains("agent=impl-rust item=4 model=claude-sonnet-5-5"),
        "{}",
        fake.env(1)
    );
    assert!(fake.stdin(1).contains("Work issue #4."));
    assert!(fake.calls()[0].contains("--output-format stream-json"));
}

#[test]
fn small_items_run_at_low_effort_and_the_setting_sources_are_data() {
    let temp = repo();
    let kit = LaunchKit::load(&temp.repo()).unwrap();
    let tracker = tracker_with(
        14,
        &["status:leased", "agent:impl-rust", "size:S"],
        &["crates/grdr-core/src/**"],
    );
    let plan = plan(
        &temp.repo(),
        &kit,
        &tracker,
        "claude".into(),
        &request("impl-rust", Some(14), Prompting::Print("Go.".into())),
    )
    .unwrap();
    let line = command_line(&plan);
    assert!(line.contains("-p --effort low --agent impl-rust"), "{line}");
    assert_eq!(plan.effort.as_deref(), Some("low"));
    temp.write(
        ".agents/harness.toml",
        "[dispatch]\nmax_writers = 3\nprotected_change_agents = [\"lead-agent-kit\"]\n[launch]\nsetting_sources = \"project,local\"\n",
    );
    let narrowed = plan_for(&temp, &tracker, "impl-rust", 14);
    assert!(
        command_line(&narrowed).contains("-p --setting-sources project,local --effort low"),
        "{}",
        command_line(&narrowed)
    );
}

pub(super) fn plan_for(temp: &TempRepo, tracker: &MemoryTracker, agent: &str, item: u64) -> Plan {
    let kit = LaunchKit::load(&temp.repo()).unwrap();
    plan(
        &temp.repo(),
        &kit,
        tracker,
        "claude".into(),
        &request(agent, Some(item), Prompting::Print("Go.".into())),
    )
    .unwrap()
}

#[test]
fn user_settings_env_is_blanked_by_name_only() {
    let temp = TempRepo::create();
    temp.write(
        "user/settings.json",
        "{\"env\": {\"STRIPE_SECRET_KEY\": \"sk-live\", \"GH_REPO\": \"x\"}, \"model\": \"fable[1m]\"}",
    );
    temp.write(
        ".claude/settings.json",
        "{\"env\": {\"GH_REPO\": \"416rehman/Guardrails\"}}",
    );
    let scrubbed = scrubbed_env(
        &temp.repo().path("user/settings.json"),
        &temp.repo().path(".claude/settings.json"),
    )
    .unwrap();
    assert_eq!(scrubbed, "{\"env\":{\"STRIPE_SECRET_KEY\":\"\"}}");
    assert!(!scrubbed.contains("sk-live"));
    assert!(
        scrubbed_env(
            &temp.repo().path("missing.json"),
            &temp.repo().path("none.json")
        )
        .is_none()
    );
}

#[test]
fn a_lease_never_lowers_the_model_and_a_review_may_raise_it() {
    let temp = repo();
    let kit = LaunchKit::load(&temp.repo()).unwrap();
    let tracker = tracker_with(
        15,
        &["status:leased", "agent:impl-rust", "trust-core"],
        &["crates/grdr-crypto/src/**"],
    );
    let lease = Lease {
        schema: LEASE_SCHEMA.into(),
        item: 15,
        attempt: 1,
        agent: "impl-rust".into(),
        model: "claude-sonnet-5-5".into(),
        acceptance_sha256: "x".into(),
        branch: "agent/15/a1".into(),
        session: None,
    };
    tracker
        .comment(15, &lease_comment(&lease).unwrap())
        .unwrap();
    let worker = plan(
        &temp.repo(),
        &kit,
        &tracker,
        "claude".into(),
        &request("impl-rust", Some(15), Prompting::Print("Go.".into())),
    )
    .unwrap();
    assert_eq!(worker.model.id, "claude-opus-5-5");
    let review = Request {
        model: Some("opus".into()),
        ..request("eval-diff", Some(15), Prompting::Print("Review.".into()))
    };
    let reviewer = plan(&temp.repo(), &kit, &tracker, "claude".into(), &review).unwrap();
    assert_eq!(reviewer.model.id, "claude-opus-5-5");
    let fable = Request {
        model: Some("fable".into()),
        ..request("eval-diff", Some(15), Prompting::Print("Review.".into()))
    };
    assert!(plan(&temp.repo(), &kit, &tracker, "claude".into(), &fable).is_err());
}

#[test]
fn the_claude_executable_is_named_found_on_path_or_at_an_install_location() {
    let temp = TempRepo::create();
    let home = temp.root().join("home");
    let installed = home
        .join(".local")
        .join("bin")
        .join(format!("claude{}", std::env::consts::EXE_SUFFIX));
    std::fs::create_dir_all(installed.parent().unwrap()).unwrap();
    std::fs::write(&installed, "").unwrap();
    temp.write(
        ".agents/harness.toml",
        "[launch]\nclaude = \"claude\"\nclaude_locations = [\"{home}/.local/bin/claude{exe}\"]\n",
    );
    let repo = temp.repo();
    let quoted = std::ffi::OsString::from(format!("\"{}\"", temp.root().join("empty").display()));
    let home_value = home.clone().into_os_string();
    let lookup = |named: Option<&str>| {
        let quoted = quoted.clone();
        let home_value = home_value.clone();
        let named = named.map(std::ffi::OsString::from);
        move |name: &str| match name {
            CLAUDE_VARIABLE => named.clone(),
            "PATH" => Some(quoted.clone()),
            "HOME" => Some(home_value.clone()),
            _ => None,
        }
    };
    assert_eq!(
        claude_from(&repo, lookup(Some("/opt/fake-claude"))).unwrap(),
        PathBuf::from("/opt/fake-claude")
    );
    let found = claude_from(&repo, lookup(None)).unwrap();
    assert_eq!(
        found.to_string_lossy().replace('\\', "/"),
        installed.to_string_lossy().replace('\\', "/")
    );
    temp.write(".agents/harness.toml", "[launch]\nclaude_locations = []\n");
    assert!(claude_from(&temp.repo(), lookup(None)).is_err());
}
