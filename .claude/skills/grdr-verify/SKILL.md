---
name: grdr-verify
description: Run the repository gates before claiming anything works. Use before reporting a change done, after any batch of edits, and whenever CI reports a failure.
license: Apache-2.0
metadata:
  version: "2"
  owner: agent-kit
---

# Run the gates and read the result

The gates are plain tools. CI (`.github/workflows/verify.yml`) runs the same commands on every pull request and decides; run them yourself first.

| Gate | Command |
|---|---|
| Format | `cargo fmt --all -- --check` |
| Lints, warnings denied | `cargo clippy --workspace --locked --all-targets -- -D warnings` |
| Tests | `cargo test --workspace --locked` |
| Dependencies, licences, advisories | `cargo deny check` |

CI also runs CodeQL, gitleaks, zizmor, osv-scanner and Semgrep (`.github/workflows/`). A crate or package `AGENTS.md` may name more commands for its own code; run those too.

While no crate exists under `crates/` or `programs/`, the workspace has no members and Cargo refuses every command above. Say so in your report and run nothing; CI skips the Rust jobs until the first crate lands.

## Read the output

1. Run the commands in the order above; stop at the first red one and fix it before going on.
2. Quote the lines that matter, not the whole log. Keep long output in a file under `target/` and give its path.
3. Fix the cause inside your write set, then run the same command again. A lint that names `unwrap`, `expect`, `panic!` or indexing is fixed with a typed error carrying its `GRDR-<AREA>-<NNNN>` code, never with an `#[allow]`.
4. When all are green, report each command with its exit code. A result no command produced counts for nothing.

## What review checks instead of a tool

No tool runs these; you check them on your own diff before you report, and `eval-diff` checks them again:

- the structure rules S1 to S7 of skill `grdr-structure` (files of at most 500 code lines, declarations first, no narration comments, explicit state types, nesting, no panic paths, no hard-coded values);
- on interface paths, the checks UX1 to UX8 of skill `grdr-interface`;
- commits: one line each, a Conventional Commit subject of at most 72 characters, no body, no trailers;
- prose: no em dash; plain words (`write-like-a-normal-staff-senior-developer`).

## Rules

1. Never edit a gate to make it pass: lint configuration (`clippy.toml`, `rustfmt.toml`, `deny.toml`), `.github/workflows/`, snapshots and golden files. A gate you believe is wrong becomes an issue with the evidence (skill `grdr-handoff`, "New work").
2. Never weaken, skip, ignore or delete a test or an assertion to get green. No new `#[allow`, `#[ignore]`, `@ts-ignore`, `todo!` or `unimplemented!` without a stated reason.
3. Never accept snapshots: no `cargo insta accept`, `cargo insta review`, `INSTA_UPDATE=always` or `vitest -u`.
4. If a gate is red before you change anything, stop and report `blocked` with the output. Your change must not be mixed with a failure you did not cause.
5. A failure is never "pre-existing", "flaky" or "out of scope" without the command output that shows it, or an issue you filed.
6. Do not rerun hoping for a different answer. A test that fails and then passes on retry is flaky: report the test, its seed and the output.
7. A usage limit is never a reason to skip a check.

## When the gates and the specification disagree

If the only way to make a gate pass would contradict the spec or the issue's acceptance criteria, change neither. Report `impossible` with a one-line reason that names the clause and the gate or test. That is a correct outcome, not a failure.
