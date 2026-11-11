//! The throwaway-repository presets the fixtures run against, and the heavy cases built in code
//! rather than committed as large files: the 501-line source file, the 1 MiB command payload and
//! the deep call nesting. Each preset writes a minimal but valid kit tree.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Result, bail};
use serde_json::json;

use super::harness::{Case, Expect};
use crate::hook::Handler;

const MODELS: &str = "[models]\nfable = \"claude-fable-5-2\"\nopus = \"claude-opus-5-5\"\nsonnet = \"claude-sonnet-5-5\"\n\n[rules]\nfable_agents = [\"chief-architect\"]\n";
const PROTECTED: &str = r#"paths = [
  "Cargo.toml",
  "Cargo.lock",
  "limits.toml",
  "rustfmt.toml",
  "quality/**",
  "security/**",
  ".agents/**",
  ".claude/**",
  ".github/**",
  "docs/design/**",
  "docs/team/**",
  "AGENTS.md",
  "**/AGENTS.md",
  "CLAUDE.md",
  "xtask/src/gates/**",
  "xtask/verify.toml",
]
"#;
const VERIFY: &str = "[[step]]\nid = \"V22\"\nname = \"model-rule\"\nforms = [\"fast\", \"full\"]\nbuiltin = \"model-rule\"\ntimeout_s = 30\n";
const LABELS: &str = r#"[[group]]
prefix = "status:"
count = "one"
filed_as = "status:proposed"

[[group]]
prefix = "tier:"
set_by = ["lead-*", "eval-tier"]
raise_only = true

[[group]]
names = ["trust-core"]
set_by = ["lead-*", "eval-tier"]
raise_only = true

[[group]]
prefix = "agent:"
set_by = ["filer", "lead-*"]

[[group]]
prefix = "squad:"
set_by = ["filer", "lead-*"]

[[transition]]
from = "proposed"
to = "ready"
by = ["kit"]
run_by = ["lead-*"]

[[transition]]
from = "proposed"
to = "blocked"
by = ["lead-*"]

[[label]]
name = "status:proposed"
[[label]]
name = "status:ready"
[[label]]
name = "status:blocked"
[[label]]
name = "tier:low"
[[label]]
name = "tier:high"
[[label]]
name = "trust-core"
[[label]]
name = "agent:impl-rust"
[[label]]
name = "squad:core"
"#;
/// The harness tables the hooks read: the repository and branch, the commit form of owner
/// instruction 27 and the usage-limit strings.
const HARNESS: &str = r#"[github]
repository = "selftest/repository"
branch = "agent/{issue}/a{attempt}"

[pull_request]
base = "main"
protected_prefixes = ["release/", "release-", "releases/"]

[dispatch]
protected_change_agents = ["lead-agent-kit", "chief-architect"]

[commit]
types = ["feat", "fix", "docs", "style", "refactor", "perf", "test", "build", "ci", "chore", "revert"]
max_subject_chars = 72

[limits]
usage_limit_strings = ["You've hit your session limit"]
"#;
/// The path-skill entries the guard-path and session-start cases add.
const PATH_SKILLS: &str = r#"[[entry]]
name = "code"
skills = ["grdr-structure", "cleanup:cleanup"]
paths = ["crates/**", "**/*.rs"]

[[entry]]
name = "prose"
skills = ["anthropic-skills:write-like-a-normal-staff-senior-developer"]
paths = ["docs/**"]
"#;
const SEED_SCOPE: &str = r#"agent = "chief-architect"
scope = "seed"
branch = "agent/seed"
paths = ["AGENTS.md", "CLAUDE.md", "docs/decisions/ADR-0001-*.md", ".github/ISSUE_TEMPLATE/*"]
commands = ["gh issue create", "gh issue edit", "gh issue view", "gh issue list", "cargo xtask kit ready", "cargo xtask kit handoff"]
"#;

fn roster() -> String {
    let agent = |name: &str, group: &str, model: &str, write: &str| {
        format!(
            "[agent.{name}]\ngroup = \"{group}\"\ndescription = \"{name}\"\nmodel = \"{model}\"\neffort = \"high\"\ncap_role = \"{group}\"\nmax_turns = 40\ntools = [\"Read\", \"Edit\", \"Write\", \"Bash\"]\nwrite = [{write}]\ndeny_write = \"@protected\"\nnet = \"A\"\ntrigger = \"dispatch\"\nbody = \"templates/agents/{name}.md\"\n\n"
        )
    };
    let mut text = String::from("[defaults]\nhandoff = \"issue-comment\"\n\n");
    text.push_str(&agent(
        "chief-architect",
        "direction",
        "fable",
        "\"docs/decisions/**\"",
    ));
    text.push_str(&agent("lead-core", "lead", "opus", ""));
    text.push_str(&agent(
        "lead-agent-kit",
        "lead",
        "opus",
        "\".agents/**\", \".claude/**\"",
    ));
    text.push_str(&agent(
        "impl-rust",
        "implementer",
        "sonnet",
        "\"crates/**\"",
    ));
    text.push_str(&agent("eval-security", "evaluator", "opus", ""));
    text.push_str(&agent("eval-architecture", "evaluator", "opus", ""));
    text.push_str(&agent(
        "garden-deslop",
        "gardener",
        "sonnet",
        "\"crates/**\", \"xtask/src/**\"",
    ));
    text.push_str(&agent("persona-solo-dev", "council", "sonnet", ""));
    text
}

fn snapshot(kind: &str) -> String {
    snapshot_for("impl-rust", kind, &["crates/**"])
}

fn snapshot_for(agent: &str, kind: &str, write_set: &[&str]) -> String {
    json!({
        "schema": "item-snapshot.v1",
        "number": 7,
        "title": "[WI-0007] A worked item",
        "agent": agent,
        "kind": kind,
        "squad": "core",
        "size": "S",
        "risk_tier": "high",
        "trust_core": false,
        "write_set": write_set,
        "status": "leased",
        "acceptance_sha256": "ab".repeat(32),
        "attempt": 1,
        "fetched_at": "2026-11-11T10:00:00Z"
    })
    .to_string()
}

/// Writes a minimal, valid kit tree for `preset` into `root`.
pub fn write_preset(root: &Path, preset: &str) -> Result<()> {
    let mut files: BTreeMap<&str, String> = BTreeMap::new();
    files.insert(".agents/models.toml", MODELS.to_owned());
    files.insert(".agents/roster.toml", roster());
    files.insert(".agents/kit/protected-paths.toml", PROTECTED.to_owned());
    files.insert(".github/labels.toml", LABELS.to_owned());
    files.insert(".agents/harness.toml", HARNESS.to_owned());
    files.insert("xtask/verify.toml", VERIFY.to_owned());
    files.insert(
        "xtask/Cargo.toml",
        "[package]\nname = \"xtask\"\n".to_owned(),
    );
    files.insert("AGENTS.md", "# Agent rules\n".to_owned());
    files.insert("crates/a/AGENTS.md", "# Crate rules\n".to_owned());
    files.insert("crates/a/src/lib.rs", "pub fn a() {}\n".to_owned());
    match preset {
        "worker" => {
            files.insert(".agent/state/item-7.json", snapshot("feature"));
        }
        "worker-bug" => {
            files.insert(".agent/state/item-7.json", snapshot("bug"));
        }
        "protected" => {
            files.insert(
                ".agent/state/item-7.json",
                snapshot_for("lead-agent-kit", "gate", &[".agents/kit/**"]),
            );
        }
        "no-snapshot" | "person" | "evaluator" | "planner" => {}
        "architect-seed" => {
            files.insert(".agents/kit/seed-scope.toml", SEED_SCOPE.to_owned());
        }
        other => bail!("unknown preset `{other}`"),
    }
    for (path, text) in files {
        let target = root.join(path.replace('/', std::path::MAIN_SEPARATOR_STR));
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&target, text)?;
    }
    Ok(())
}

/// Heavy cases built in code: the 501-line file (S1), a type after an impl (S2), a three-bool
/// struct (S4), deep nesting (S5), a panic path (S6), and the 1 MiB command payload.
pub fn programmatic() -> Vec<(Handler, String, Case)> {
    let oversized: String = (0..501)
        .map(|i| format!("pub const C{i}: u8 = {};\n", i % 256))
        .collect();
    let after_impl =
        "pub struct A;\nimpl A {\n    pub fn new() -> A { A }\n}\npub const LATE: u8 = 1;\n";
    let three_bools = "pub struct Flags {\n    pub started: bool,\n    pub ready: bool,\n    pub done: bool,\n}\n";
    let panics = "pub fn f(v: Option<u8>) -> u8 {\n    v.unwrap()\n}\n";
    let deep = "pub fn f(a: bool, b: bool, c: bool, d: bool, e: bool) {\n    if a {\n        if b {\n            if c {\n                if d {\n                    if e {\n                        g();\n                    }\n                }\n            }\n        }\n    }\n}\n";
    let large_command = format!(
        "echo start\n{}echo end",
        "git status --short\n".repeat(60_000)
    );
    let edit = |path: &str| json!({"tool_name": "Edit", "tool_input": {"file_path": path}});
    let mut cases = vec![
        (
            Handler::PostEdit,
            "worker".into(),
            edit_case(
                "s1-oversized-file",
                "crates/a/src/big.rs",
                oversized,
                Expect::Block,
                Some("code lines"),
            ),
        ),
        (
            Handler::PostEdit,
            "worker".into(),
            edit_case(
                "s2-type-after-impl",
                "crates/a/src/order.rs",
                after_impl.into(),
                Expect::Block,
                Some("before impls"),
            ),
        ),
        (
            Handler::PostEdit,
            "worker".into(),
            edit_case(
                "s4-three-bools",
                "crates/a/src/flags.rs",
                three_bools.into(),
                Expect::Block,
                Some("bool fields"),
            ),
        ),
        (
            Handler::PostEdit,
            "worker".into(),
            edit_case(
                "s5-deep-nesting",
                "crates/a/src/deep.rs",
                deep.into(),
                Expect::Context,
                Some("nesting"),
            ),
        ),
        (
            Handler::PostEdit,
            "worker".into(),
            edit_case(
                "s6-panic-path",
                "crates/a/src/panics.rs",
                panics.into(),
                Expect::Block,
                Some("panic path"),
            ),
        ),
        (
            Handler::PostEdit,
            "worker".into(),
            Case {
                name: "broken-member-manifest".into(),
                preset: None,
                env: worker_env(),
                input: json!({"tool_name": "Edit", "tool_input": {"file_path": "crates/a/src/lib.rs"}}),
                expect: Expect::Allow,
                contains: None,
                files: BTreeMap::from([
                    (
                        "crates/a/Cargo.toml".to_owned(),
                        "[package\nname = ".to_owned(),
                    ),
                    (
                        "crates/a/src/lib.rs".to_owned(),
                        "pub fn a() {}\n".to_owned(),
                    ),
                ]),
                sign_off: false,
            },
        ),
        (
            Handler::GuardCommand,
            "worker".into(),
            Case {
                name: "one-mib-payload".into(),
                preset: None,
                env: worker_env(),
                input: json!({"tool_name": "Bash", "tool_input": {"command": large_command}}),
                expect: Expect::Allow,
                contains: None,
                files: BTreeMap::new(),
                sign_off: false,
            },
        ),
        (
            Handler::GuardPath,
            "worker".into(),
            Case {
                name: "inside-write-set".into(),
                preset: None,
                env: worker_env(),
                input: edit("crates/a/src/added.rs"),
                expect: Expect::Allow,
                contains: None,
                files: BTreeMap::new(),
                sign_off: false,
            },
        ),
        (
            Handler::GuardPath,
            "worker".into(),
            Case {
                name: "backslash-protected-path".into(),
                preset: None,
                env: worker_env(),
                input: edit("crates\\a\\src\\..\\..\\..\\Cargo.toml"),
                expect: Expect::Block,
                contains: Some("protected".into()),
                files: BTreeMap::new(),
                sign_off: false,
            },
        ),
    ];
    cases.extend(super::rule_cases::cases(PATH_SKILLS));
    cases
}

fn edit_case(
    name: &str,
    path: &str,
    content: String,
    expect: Expect,
    contains: Option<&str>,
) -> Case {
    let mut files = BTreeMap::new();
    files.insert(path.to_owned(), content);
    Case {
        name: name.to_owned(),
        preset: None,
        env: worker_env(),
        input: json!({"tool_name": "Edit", "tool_input": {"file_path": path}}),
        expect,
        contains: contains.map(str::to_owned),
        files,
        sign_off: false,
    }
}

fn worker_env() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("GRDR_AGENT".to_owned(), "impl-rust".to_owned()),
        ("GRDR_WORK_ITEM".to_owned(), "7".to_owned()),
    ])
}
