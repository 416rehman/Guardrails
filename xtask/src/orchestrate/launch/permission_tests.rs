//! How a launched session runs with no one to answer a prompt: `dontAsk` on every launch, the
//! seed session in print mode with its prompt on stdin, and the plugin rules `[launch]
//! plugin_allow` names.

use super::kit::plugin_rules;
use super::tests::{env_value, repo, request};
use super::*;
use crate::config::marketplace::{InstalledPlugins, Marketplace};
use crate::orchestrate::testkit::MemoryTracker;

#[test]
fn the_seed_session_is_only_for_the_chief_architect() {
    let temp = repo();
    let kit = LaunchKit::load(&temp.repo()).unwrap();
    let tracker = MemoryTracker::default();
    let seed = Request {
        scope: LaunchScope::Seed,
        ..request("chief-architect", None, Prompting::Interactive)
    };
    let plan = plan(&temp.repo(), &kit, &tracker, "claude".into(), &seed).unwrap();
    assert_eq!(env_value(&plan, "GRDR_SCOPE"), Some("seed"));
    assert_eq!(plan.turns, 200);
    assert_eq!(plan.model.id, "claude-fable-5-2");
    let line = plan.args.join(" ");
    assert!(
        line.starts_with("-p --agent chief-architect --model claude-fable-5-2"),
        "{line}"
    );
    assert!(
        line.ends_with(
            "--max-turns 200 --permission-mode dontAsk --output-format stream-json --verbose"
        ),
        "{line}"
    );
    let prompt = plan.stdin.as_deref().unwrap();
    assert!(prompt.starts_with(OWNERSHIP_SENTENCE), "{prompt}");
    assert!(prompt.contains("Start the team."));
    assert!(!line.contains("Start the team."), "{line}");
    let other = Request {
        scope: LaunchScope::Seed,
        ..request("impl-rust", None, Prompting::Interactive)
    };
    assert!(super::plan(&temp.repo(), &kit, &tracker, "claude".into(), &other).is_err());
}

#[test]
fn every_session_runs_in_dont_ask_and_gets_the_plugin_rules() {
    let temp = repo();
    let mut kit = LaunchKit::load(&temp.repo()).unwrap();
    assert!(kit.plugin_rules.is_empty(), "{:?}", kit.plugin_rules);
    kit.plugin_rules =
        vec!["Bash(node \"C:/p/cleanup/0.1.0/hooks/cleanup-gate.js\" --mark *)".into()];
    let tracker = MemoryTracker::default();
    let interactive = plan(
        &temp.repo(),
        &kit,
        &tracker,
        "claude".into(),
        &request("impl-rust", None, Prompting::Interactive),
    )
    .unwrap();
    assert_eq!(
        interactive.args,
        [
            "--agent",
            "impl-rust",
            "--model",
            "claude-sonnet-5-5",
            "--permission-mode",
            "dontAsk",
            "--allowedTools",
            "Bash(node \"C:/p/cleanup/0.1.0/hooks/cleanup-gate.js\" --mark *)",
        ]
    );
    assert!(interactive.stdin.is_none());
    let seed = Request {
        scope: LaunchScope::Seed,
        ..request(
            "chief-architect",
            None,
            Prompting::Print("Only step 1.".into()),
        )
    };
    let asked = plan(&temp.repo(), &kit, &tracker, "claude".into(), &seed).unwrap();
    let prompt = asked.stdin.unwrap();
    assert!(prompt.starts_with(OWNERSHIP_SENTENCE), "{prompt}");
    assert!(prompt.ends_with("Only step 1."), "{prompt}");
    assert_eq!(
        asked.args.last().map(String::as_str),
        Some(kit.plugin_rules[0].as_str())
    );
}

#[test]
fn plugin_rules_name_the_installed_directory_with_forward_slashes() {
    let temp = repo();
    let marketplace = Marketplace::load(&temp.repo()).unwrap();
    let installed: InstalledPlugins = serde_json::from_str(
        r#"{"plugins": {"cleanup@grdr-agent-marketplace": [{"scope": "local", "installPath": "C:\\Users\\dev\\.claude\\plugins\\cache\\grdr-agent-marketplace\\cleanup\\0.1.0"}]}}"#,
    )
    .unwrap();
    let templates = std::collections::BTreeMap::from([
        (
            "cleanup".to_owned(),
            "Bash(node \"{root}/hooks/cleanup-gate.js\" --mark *)".to_owned(),
        ),
        ("absent".to_owned(), "Bash(node \"{root}/x.js\")".to_owned()),
    ]);
    assert_eq!(
        plugin_rules(&templates, &marketplace, &installed),
        [
            "Bash(node \"C:/Users/dev/.claude/plugins/cache/grdr-agent-marketplace/cleanup/0.1.0/hooks/cleanup-gate.js\" --mark *)"
        ]
    );
    temp.write(
        ".agents/harness.toml",
        "[dispatch]\nprotected_change_agents = [\"lead-agent-kit\"]\n[launch]\nplugin_allow = { cleanup = 7 }\n",
    );
    let error = LaunchKit::load(&temp.repo()).err().unwrap().to_string();
    assert!(
        error.contains("plugin_allow.cleanup is not a string"),
        "{error}"
    );
}
