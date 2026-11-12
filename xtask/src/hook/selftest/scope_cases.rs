//! Cases built in code for the widened scopes and the item snapshot: post-bash reports no protected
//! path a seed or protected-change session placed inside its own scope and still reports every
//! other one, and guard-path holds a session to a snapshot's write set only when the snapshot is
//! the session's own item, so a planner launched on another agent's item writes only its drafts.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::harness::{Case, Expect};
use crate::hook::Handler;
use crate::hook::state::SESSION_SCHEMA;

const SESSION: &str = "s-scope";

pub fn cases() -> Vec<(Handler, String, Case)> {
    let lease = [
        ("GRDR_AGENT", "lead-agent-kit"),
        ("GRDR_WORK_ITEM", "7"),
        ("GRDR_SCOPE", "protected"),
    ];
    let seed = [("GRDR_AGENT", "chief-architect"), ("GRDR_SCOPE", "seed")];
    let writer = [("GRDR_AGENT", "impl-rust"), ("GRDR_WORK_ITEM", "7")];
    let planner = [("GRDR_AGENT", "lead-core"), ("GRDR_WORK_ITEM", "7")];
    let post_bash =
        |preset: &str, name: &str, env: &[(&str, &str)], path: &str, expect, contains| {
            let (input, files) = placed(path);
            let case = case(name, env, input, files, expect, contains);
            (Handler::PostBash, preset.to_owned(), case)
        };
    let guard_path = |name: &str, env: &[(&str, &str)], path: &str, expect, contains| {
        let input =
            json!({"tool_name": "Write", "tool_input": {"file_path": path, "content": "x\n"}});
        let case = case(name, env, input, BTreeMap::new(), expect, contains);
        (Handler::GuardPath, "worker".to_owned(), case)
    };
    vec![
        post_bash(
            "protected",
            "placed-inside-the-lease-write-set",
            &lease,
            ".agents/kit/hooks.toml",
            Expect::Allow,
            "",
        ),
        post_bash(
            "protected",
            "protected-path-outside-the-lease-write-set",
            &lease,
            "AGENTS.md",
            Expect::Block,
            "AGENTS.md",
        ),
        post_bash(
            "architect-seed",
            "placed-inside-the-seed-scope",
            &seed,
            "AGENTS.md",
            Expect::Allow,
            "",
        ),
        post_bash(
            "architect-seed",
            "protected-path-outside-the-seed-scope",
            &seed,
            "security/policy.md",
            Expect::Block,
            "security/policy.md",
        ),
        post_bash(
            "worker",
            "ordinary-session-reports-a-protected-path",
            &writer,
            "AGENTS.md",
            Expect::Block,
            "git checkout HEAD -- AGENTS.md",
        ),
        guard_path(
            "planner-gets-no-write-set-from-another-agents-item",
            &planner,
            "crates/a/src/planned.rs",
            Expect::Block,
            "outside what lead-core writes",
        ),
        guard_path(
            "planner-writes-its-issue-body-draft",
            &planner,
            ".agent/state/proposed-split.md",
            Expect::Approve,
            "",
        ),
        guard_path(
            "writer-keeps-its-own-items-write-set",
            &writer,
            "crates/a/src/owned.rs",
            Expect::Approve,
            "",
        ),
    ]
}

/// A Bash call after the session changed `path`, with a session baseline from before the change.
fn placed(path: &str) -> (Value, BTreeMap<String, String>) {
    let state = json!({
        "schema": SESSION_SCHEMA,
        "session_id": SESSION,
        "started_at": "2026-11-11T00:00:00Z",
        "agent": null,
        "work_item": null,
        "model": null,
        "start_tree": null,
    });
    let files = BTreeMap::from([
        (
            format!(".agent/state/session-{SESSION}.json"),
            state.to_string(),
        ),
        (path.to_owned(), "changed by the session\n".to_owned()),
    ]);
    let command = format!("cargo xtask kit place {path}");
    let input =
        json!({"session_id": SESSION, "tool_name": "Bash", "tool_input": {"command": command}});
    (input, files)
}

fn case(
    name: &str,
    env: &[(&str, &str)],
    input: Value,
    files: BTreeMap<String, String>,
    expect: Expect,
    contains: &str,
) -> Case {
    Case {
        name: name.to_owned(),
        preset: None,
        env: env
            .iter()
            .map(|(variable, value)| ((*variable).to_owned(), (*value).to_owned()))
            .collect(),
        input,
        expect,
        contains: (!contains.is_empty()).then(|| contains.to_owned()),
        files,
        sign_off: false,
    }
}
