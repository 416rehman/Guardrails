# Gates of `cargo xtask verify`

Source: team/05 section 3, the kit's gates V18, V20 to V28 and Q01 included. `xtask/verify.toml` encodes the table and is authoritative; read it when this file and the command disagree. Gate ids are a letter and two digits and are not severities. The structure checks S1 to S7 inside V20 are not the audit prompts of team/04, whose security prompts are M01 to M05. Gate Q01 `acceptance-digest` reads the issue, so it runs only in `verify --ci`, on pull requests and in the merge queue.

| Id | Step | Fast form | What a failure means, and where the fix usually is |
|---|---|---|---|
| V01 | Format check (rustfmt, Biome, `buf format`) | Changed files | Run the formatter on the files you changed. The post-edit hook normally formats them already |
| V02 | Compile and Clippy, warnings denied | Touched crates and direct dependents | Fix the warning. `unwrap`, `expect`, `panic!`, `todo!`, `unimplemented!`, `unreachable!`, indexing that can panic and `process::exit` are denied in all non-test code (owner instruction 15), and unchecked arithmetic in layers 0 to 2 and privileged crates; return an error with a `GRDR-<AREA>-<NNNN>` code instead |
| V03 | Tests (nextest; doctests in the full form) | Touched crates and dependents | A test you changed or a test your change broke. Never edit an assertion to match new output without the spec saying the output changed |
| V04 | Architecture lint ARCH-001 to ARCH-026 (design/03) and the interface rules ARCH-101 to ARCH-106 (team/05 section 8) | Graph rules only | The message states the fix. Never edit `architecture.toml`; a wrong layer assignment is an RFC |
| V05 | Protected-path and identity check | Yes | You touched a path in `.agents/kit/protected-paths.toml`. Revert it (`git checkout -- <path>`) and put the change in `protected_change_requests` |
| V06 | Ratchets: suppressions, ignored tests, stubs, file size | Those four | Remove the new suppression or `#[ignore]`, or give it a reason; split an oversized file by responsibility (`grdr-structure`). Ratchets only tighten |
| V07 | Schema: `buf lint`, `buf breaking`, `grdr-schema-lint` | If `proto/` or `schema/` changed | A breaking wire or schema change needs an accepted RFC (D-61); stop and escalate |
| V08 | Policy packs under the production interpreter; golden vectors native and `wasm32` | If packs or `grdr-core` changed | Behaviour of the evaluator changed. Golden vectors are protected; a deliberate change goes through `protected_change_requests` |
| V09 | Property tests; deterministic simulation short seed set | Touched crates | The failing seed is printed. Fix the code; record the seed in the hand-off |
| V10 | Diff-scoped mutation testing | No | A mutant in your diff survived: a test does not check what the code does. Strengthen the test |
| V11 | Diff coverage | No | Changed lines without a test |
| V12 | Dependency gates (cargo-deny, cargo-vet, cargo-machete) | If a manifest or lockfile changed | Implementers never add dependencies; a new one is a separate high-tier item |
| V13 | Public API: semver and surface diff | If a public crate changed | A public surface changed. Layers 0 to 2 change only by RFC |
| V14 | Static security rules, secrets, workflow audit | Changed files | Semgrep, ast-grep, gitleaks or zizmor rule. A secret in the diff: remove it and say so in the hand-off |
| V15 | Security register | No | A due SR has no passing test id, or a threat has no SR or residual (design/02) |
| V16 | Web: typecheck, lint, unused code, tests | Changed packages | Under `web/` or `desktop/`. Pseudo-locale runs are gate U04 and string literals check UX3 |
| V17 | Documentation checks F1 to F14, Vale with the `ai-tells` styles, `cargo doc` warnings denied, typos | Changed docs | Broken internal link, Vale rule or doc warning. Fix the sentence; never disable a rule to clear one |
| V18 | Hook self-test | If `.agents/` or `.claude/` changed | A hook does not block or a matcher does not fire. Kit work items only |
| V19 | Instruction-count benchmarks | No | A hot path got slower |
| V20 | V-structure: structure checks S1 to S7 of skill `grdr-structure`, printed as `ERROR V20 S4: ...`: file size against `quality/file-size.toml`, declaration order, comments on the diff, implicit state machines, nesting, panic paths, hard-coded values | Changed files | S5 warns; the rest fail the gate. The fix is a design change: split by responsibility, move declarations up, delete the comment, introduce a state type, return a typed error, move the value to its data source. Exemptions and ratchet entries change only through their own protected-change item, which `lead-agent-kit` implements and `eval-architecture` must agree to (owner instruction 7) |
| V21 | `kit check`: the rendered `.claude/` equals a fresh render of `.agents/`, and the kit rules hold | Yes | Run `cargo xtask kit render` in a kit work item; never edit `.claude/` by hand |
| V22 | Model rule: `.agents/models.toml` binds the three ids and only `chief-architect` runs on Fable | Yes | A roster or prompt hook names a model outside the rule |
| V23 | Skills lint: front matter, name equal to its directory, under 200 lines, project skill metadata | Yes | Move detail to `references/`; fix the front matter |
| V24 | Commit form (owner instruction 27): every commit on the branch is one line, a Conventional Commit subject of at most 72 characters, with no body and no trailers | Commits since the base | Reword your own unpushed commit (`git commit --amend -m '<subject>'`) to the form skill `grdr-handoff` gives |
| V25 | Prose: no em dash in changed Markdown | Changed Markdown | Use a comma, a colon, parentheses or a new sentence |
| V26 | Interface cohesion (P17): checks UX1 to UX8 and `cargo xtask interface check` (skill `grdr-interface`) | Changed files under interface paths | Use the token, pattern, accessor or route the message names; there is no exemption and no inline suppression |
| V27 | Duplicate code: no new clone of 60 tokens or 8 lines against `quality/clones-baseline.json` | Changed files | Reuse the existing implementation; a deliberate pair is recorded in `architecture.toml` and its baseline entry needs `eval-architecture` |
| V28 | Package manager (owner instruction 24): no npm, Yarn or Bun lockfile, no `packageManager` other than pnpm, no npm or npx call in a `package.json` script or a workflow step | Yes | Delete the other lockfile and use pnpm: `pnpm install --frozen-lockfile`, `pnpm exec`, `pnpm dlx <package>@<version>` |
| V29 | Release diff: a release-please pull request changes only versions, changelogs and the release manifest; an agent commit changes no `package.version` | If a member manifest, `Cargo.lock` or release file changed | Revert the version line; release-please sets versions |
| V30 | Contract compatibility (D-71): every declared `provides` and `requires` range resolves, and a breaking change to a contract bumps its major | If a contract or a build manifest changed | Keep the contract compatible, or bump its major with the overlap its stability class requires |

## Output contract

- At most ten lines on stdout, then a log path. The first failing line is `ERROR <gate-id>: <reason>`.
- V05 prints `ERROR V05: <path> is protected; stop with status blocked and a protected_change_requests entry`.
- Exit `0` all green, `2` a gate failed, anything else an infrastructure error (counts as failure).
- The evidence file `.agent/evidence/<id>.json` records the command, exit code, duration and tree digest. Its id is what the hand-off and the Stop hook's checker look for.

## Time targets

Fast form: under 90 seconds warm for a one-crate change, under 3 minutes worst case. Full form: under 15 minutes on a clean hosted runner. A gate that is slow is still the gate; report the time in the hand-off rather than skipping it.
