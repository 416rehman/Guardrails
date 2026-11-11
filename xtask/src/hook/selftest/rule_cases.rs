//! Cases built in code for the owner's kit rules (instructions 1, 18, 24 and 27): the one-line
//! commit form, pnpm as the only package manager, `eval-architecture` as an evaluator, the
//! ownership sentence on every `SessionStart` source, path skills at session start and on a first
//! edit, and the `StopFailure` record.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::harness::{Case, Expect};
use crate::hook::Handler;

/// guard-command cases: name, preset, agent (empty for a person), command, expectation, and a
/// word the answer contains (empty for none).
const COMMANDS: &[(&str, &str, &str, &str, Expect, &str)] = &[
    (
        "one-line-commit",
        "worker",
        "impl-rust",
        r#"git commit -m "fix(kit): handle the empty case""#,
        Expect::Allow,
        "",
    ),
    (
        "second-message-is-a-body",
        "worker",
        "impl-rust",
        r#"git commit -m "fix: x" -m "more detail""#,
        Expect::Block,
        "second -m",
    ),
    (
        "message-file-refused",
        "worker",
        "impl-rust",
        "git commit -F message.txt",
        Expect::Block,
        "-F",
    ),
    (
        "template-refused",
        "worker",
        "impl-rust",
        r#"git commit -t template.txt -m "fix: x""#,
        Expect::Block,
        "--template",
    ),
    (
        "trailer-refused",
        "worker",
        "impl-rust",
        r#"git commit -m "fix: x" --trailer "Work-Item: #7""#,
        Expect::Block,
        "no trailers",
    ),
    (
        "here-document-body",
        "worker",
        "impl-rust",
        "git commit -m \"$(cat <<'EOF'\nfix: x\n\nAssisted-by: claude-code:claude-sonnet-5-5\nEOF\n)\"",
        Expect::Block,
        "more than one line",
    ),
    (
        "type-not-allowed",
        "worker",
        "impl-rust",
        r#"git commit -m "update: x""#,
        Expect::Block,
        "conventional commit",
    ),
    (
        "subject-too-long",
        "worker",
        "impl-rust",
        r#"git commit -m "fix: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx""#,
        Expect::Block,
        "over the limit",
    ),
    (
        "sign-off-refused",
        "worker",
        "impl-rust",
        r#"git commit -s -m "fix: x""#,
        Expect::Block,
        "signed-off-by",
    ),
    (
        "person-commit-left-to-v24",
        "person",
        "",
        r#"git commit -m "wip" -m "body""#,
        Expect::Allow,
        "",
    ),
    (
        "npm-ci",
        "worker",
        "impl-rust",
        "npm ci",
        Expect::Block,
        "pnpm",
    ),
    (
        "npm-i",
        "worker",
        "impl-rust",
        "npm i left-pad",
        Expect::Block,
        "pnpm",
    ),
    (
        "npm-exec",
        "worker",
        "impl-rust",
        "npm exec vitest",
        Expect::Block,
        "pnpm",
    ),
    (
        "yarn-install",
        "worker",
        "impl-rust",
        "yarn install",
        Expect::Block,
        "pnpm",
    ),
    (
        "bun-install",
        "worker",
        "impl-rust",
        "bun install",
        Expect::Block,
        "pnpm",
    ),
    (
        "bunx",
        "worker",
        "impl-rust",
        "bunx vite",
        Expect::Block,
        "pnpm",
    ),
    (
        "npx-person",
        "person",
        "",
        "npx create-vite",
        Expect::Block,
        "pnpm",
    ),
    (
        "modern-web-guidance-cli",
        "worker",
        "impl-rust",
        "pnpm dlx modern-web-guidance@latest search dialog",
        Expect::Block,
        "installed modern-web-guidance plugin",
    ),
    (
        "modern-web-guidance-through-npx",
        "worker",
        "impl-rust",
        "npx -y modern-web-guidance@latest",
        Expect::Block,
        "is not run in this repository",
    ),
    (
        "pnpm-frozen-install",
        "worker",
        "impl-rust",
        "pnpm install --frozen-lockfile",
        Expect::Allow,
        "",
    ),
    (
        "eval-architecture-posts-a-check-run",
        "evaluator",
        "eval-architecture",
        "gh api -X POST repos/selftest/repository/check-runs -f name=eval-architecture -f conclusion=success",
        Expect::Allow,
        "",
    ),
    (
        "eval-architecture-edits-no-body",
        "evaluator",
        "eval-architecture",
        "gh issue edit 7 --body replaced",
        Expect::Block,
        "labels only",
    ),
    (
        "check-run-on-another-repository",
        "evaluator",
        "eval-architecture",
        "gh api -X POST repos/someone/else/check-runs -f name=x",
        Expect::Block,
        "may not run",
    ),
    (
        "evaluator-posts-commit-status",
        "evaluator",
        "eval-architecture",
        "gh api -X POST repos/selftest/repository/statuses/0123abcd -f state=success -f context=grdr-evaluator/eval-architecture",
        Expect::Allow,
        "",
    ),
    (
        "commit-status-under-another-context",
        "evaluator",
        "eval-architecture",
        "gh api -X POST repos/selftest/repository/statuses/0123abcd -f state=success -f context=grdr-evaluator/eval-security",
        Expect::Block,
        "context=grdr-evaluator/eval-architecture",
    ),
    (
        "commit-status-on-another-repository",
        "evaluator",
        "eval-architecture",
        "gh api -X POST repos/someone/else/statuses/0123abcd -f context=grdr-evaluator/eval-architecture",
        Expect::Block,
        "may not run",
    ),
    (
        "abbreviated-trailer",
        "worker",
        "impl-rust",
        r#"git commit -m "fix: x" --trai "Reviewed-by: someone""#,
        Expect::Block,
        "no trailers",
    ),
    (
        "abbreviated-signoff",
        "worker",
        "impl-rust",
        r#"git commit -m "fix: x" --sign"#,
        Expect::Block,
        "Signed-off-by",
    ),
    (
        "abbreviated-no-verify",
        "worker",
        "impl-rust",
        r#"git commit --no-veri -m "fix: x""#,
        Expect::Block,
        "--no-verify",
    ),
    (
        "unknown-commit-option",
        "worker",
        "impl-rust",
        r#"git commit --nonsense -m "fix: x""#,
        Expect::Block,
        "write the option out in full",
    ),
    (
        "gh-repo-from-environment",
        "evaluator",
        "eval-architecture",
        "GH_REPO=someone/else gh issue comment 5 --body hi",
        Expect::Block,
        "selftest/repository",
    ),
    (
        "agent-runs-the-queue",
        "worker",
        "impl-rust",
        "cargo xtask queue --once",
        Expect::Block,
        "merge queue",
    ),
    (
        "tier-added-without-a-swap",
        "worker",
        "lead-core",
        "gh issue edit 7 --add-label tier:low",
        Expect::Block,
        "swap",
    ),
    (
        "pull-request-against-another-base",
        "worker",
        "impl-rust",
        r#"gh pr create --head agent/7/a1 --base release/1.0 --title "fix: x" --body "y""#,
        Expect::Block,
        "release/1.0",
    ),
    (
        "push-to-a-release-branch",
        "worker",
        "impl-rust",
        "git push origin HEAD:release/1.0",
        Expect::Block,
        "merge queue",
    ),
];

/// The SessionStart sources besides `startup` and `compact`, which the fixtures cover.
const ARCHITECT_SOURCES: &[&str] = &["resume", "clear", "fork"];

pub fn cases(path_skills: &str) -> Vec<(Handler, String, Case)> {
    let mut cases: Vec<(Handler, String, Case)> = COMMANDS
        .iter()
        .map(|(name, preset, agent, command, expect, contains)| {
            let input = json!({"tool_name": "Bash", "tool_input": {"command": command}});
            let case = case(name, env(agent), input, *expect, contains, BTreeMap::new());
            (Handler::GuardCommand, (*preset).to_owned(), case)
        })
        .collect();
    cases.extend(ARCHITECT_SOURCES.iter().map(|source| {
        let input = json!({"source": source, "agent_type": "chief-architect"});
        let case = case(
            &format!("chief-architect-{source}"),
            env("chief-architect"),
            input,
            Expect::Context,
            "This codebase is yours",
            BTreeMap::new(),
        );
        (Handler::SessionStart, "no-snapshot".to_owned(), case)
    }));
    let skills = || {
        BTreeMap::from([(
            ".agents/kit/path-skills.toml".to_owned(),
            path_skills.to_owned(),
        )])
    };
    let mut announced = skills();
    announced.insert(
        ".agent/state/skills-s-skills.json".to_owned(),
        r#"{"schema": "path-skills.v1", "announced": ["code"]}"#.to_owned(),
    );
    let edit = |path: &str| json!({"tool_name": "Edit", "tool_input": {"file_path": path}});
    let worker = |handler, case| (handler, "worker".to_owned(), case);
    cases.extend([
        worker(
            Handler::SessionStart,
            case("write-set-path-skills", env("impl-rust"), json!({"source": "startup"}), Expect::Context, "Skills for this write set", skills()),
        ),
        worker(
            Handler::GuardPath,
            case("first-edit-names-path-skills", env("impl-rust"), edit("crates/a/src/added.rs"), Expect::Context, "grdr-structure", skills()),
        ),
        worker(
            Handler::GuardPath,
            case(
                "named-path-skills-are-not-repeated",
                env("impl-rust"),
                json!({"session_id": "s-skills", "tool_name": "Edit", "tool_input": {"file_path": "crates/a/src/added.rs"}}),
                Expect::Allow,
                "",
                announced,
            ),
        ),
        worker(
            Handler::GuardPath,
            case("blocked-edit-names-no-skills", env("impl-rust"), edit("programs/grdr/src/main.rs"), Expect::Block, "write set", skills()),
        ),
        worker(
            Handler::StopFailure,
            case(
                "usage-limit-recorded",
                env("impl-rust"),
                json!({"error": "rate_limit", "last_assistant_message": "You've hit your session limit"}),
                Expect::Allow,
                "",
                BTreeMap::new(),
            ),
        ),
    ]);
    cases
}

fn case(
    name: &str,
    env: BTreeMap<String, String>,
    input: Value,
    expect: Expect,
    contains: &str,
    files: BTreeMap<String, String>,
) -> Case {
    Case {
        name: name.to_owned(),
        preset: None,
        env,
        input,
        expect,
        contains: (!contains.is_empty()).then(|| contains.to_owned()),
        files,
        sign_off: false,
    }
}

/// The launcher's variables for `agent`, with item 7 for the writers; none for a person.
fn env(agent: &str) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    if agent.is_empty() {
        return env;
    }
    env.insert("GRDR_AGENT".to_owned(), agent.to_owned());
    if agent.starts_with("impl-") {
        env.insert("GRDR_WORK_ITEM".to_owned(), "7".to_owned());
    }
    env
}
