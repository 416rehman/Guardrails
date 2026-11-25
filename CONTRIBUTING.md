# Contributing to Guardrails ADR

Thank you for helping. This file covers both ways to contribute: content
(rules, fingerprints, policy packs and other data) and code. AI_POLICY.md
applies to every contribution, whoever or whatever wrote it.

## How the project works

Guardrails ADR is built agent-first, with plain Claude Code. The team is the
subagents in `.claude/agents/`; a session told to work an issue follows the
skill `.claude/skills/grdr-work-issue/` and spawns them:

- Every work item is a GitHub issue in this repository. Labels carry its
  fields; the agent that writes an issue's spec never implements it.
- An implementer works on one issue in its own worktree and branch
  `issue/<n>`. Evaluator agents that did not write the change review it in
  clean contexts, as many as its risk tier calls for.
- When they pass and CI is green, the session opens a pull request with
  `Closes #<n>` and squash-merges it as one commit.
- release-please opens the release pull requests and creates the tags and
  GitHub releases; artefacts are signed keylessly with Sigstore.

You contribute through the same issues, pull requests and gates as the
agents.

## Before you start

- Licence: code and content are Apache-2.0. Kernel programs in bpf/ are
  GPL-2.0-only OR BSD-2-Clause. Documentation is Apache-2.0 OR CC-BY-4.0.
  There is no CLA and no sign-off. You keep your copyright. By opening a
  pull request you submit your contribution under the project's licence
  (Apache-2.0 section 5); see AI_POLICY.md.
- Commit messages are one line: a Conventional Commit subject such as
  `fix(grdr-core): return unresolved for here-doc bodies`, at most 72
  characters, with no body and no trailers.
- JavaScript and TypeScript use pnpm only, at the version `packageManager`
  pins in `package.json`: `pnpm install --frozen-lockfile`, `pnpm add`,
  `pnpm exec` and `pnpm dlx <package>@<version>`. npm, npx, yarn and bun
  commands and their lockfiles are refused in review. The npm registry is only where packages are fetched from and
  published to.
- Do not copy, translate or paraphrase code or rule logic from sources
  listed in security/supply-chain/do-not-read.toml (for example Elastic detection
  rules under the Elastic License, SigmaHQ rules under the DRL, AGPL or GPL
  engines). Reading them to understand a technique is fine; reproducing
  them is not.
- Security problems go to SECURITY.md, never to a public issue.

## Content: the open lane

Repository: the content repository. Anyone may contribute.

1. Pick a template: add-rule, add-agent (fingerprint and adapter manifest),
   add-pack, report-false-positive, report-malicious-artifact.
2. Write the item as a declarative file. A content item can never introduce
   anything to execute, contact or set: a command, an executable path, a
   URL to fetch, an environment variable to set or an MCP server to start;
   the verifier rejects it. Host patterns, environment variable names and
   path templates are allowed as typed match fields.
3. Add fixtures: at least one sample that must match and one that must
   not. Samples must be inert.
4. Run `grdr content test`. It loads your item in every supported engine
   and replays the public benign session corpus. Fix any benign hit or
   record it in known-fps.yaml with a reason.
5. Open a pull request with the evidence template filled in.

Review: the acceptance, adversarial and licence reviews must pass the
item, beside the fixtures and the benign replay, each from two review
agents on different models for a community rule. A rule whose response
ceiling is `contain` or above also needs the security review.
A content reviewer's review adds evidence. While `grdr content test` does
not yet exist, pull requests wait with the label "queued" rather than in
silence.
Every new rule starts as experimental and in Watch mode. It is promoted by
data (time in rings, benign hits, analyst verdicts), never by request, and
no community rule goes beyond Watch without its two passing reviews.

## Code

Repositories: the main repository and the contrib repository (community
adapters).

1. Every code change links an accepted work item: an issue with a spec,
   a write set and acceptance criteria. Look for issues labelled
   "open-to-contributors", or open an issue describing the problem and wait
   for a lead to specify it. Pull requests that link no accepted item are
   closed automatically unless you are on the vouch list
   (governance/vouched.txt); if you are, they stay open but cannot merge
   until an accepted item is linked. You get on the list with one merged
   content contribution, an accepted issue with a reproducer, or a
   maintainer's vouch.
2. "good-first-issue" items are kept for people making their first code
   contribution. The project's own agents never take them.
3. Build: install stable Rust (the minimum version is `rust-version` in
   the workspace Cargo.toml and is checked by CI) and run the gates:
   `cargo fmt --all -- --check`,
   `cargo clippy --workspace --locked --all-targets -- -D warnings`,
   `cargo test --workspace --locked` and `cargo deny --config security/deny.toml check`. CI runs the same
   commands. A clean clone should be green in under 15 minutes
   on Windows, macOS or Linux, with no kernel, Swift, Node or GPU
   toolchain. If it is not, that is a bug; please report it.
4. Keep to the layer rules of `architecture.toml`; review checks them until
   the architecture lint (WI-0003) lands.
5. Changes to public crates, wire formats, the pack format, the Cedar
   schema or anything else listed in GOVERNANCE.md need an accepted RFC
   first.
6. Changes to trust-core paths (security/trust-core.paths) need the
   security and adversarial reviews, two independent passing reviews on
   different models, and extra evidence (a reference model, differential
   tests, matrix and soak runs); a trust-core maintainer's review adds
   evidence. Talk to a maintainer before starting.
7. New dependencies need a licence on the allow-list in
   security/supply-chain/licences.toml and pass the licence review. Adding a
   licence to that list changes security/supply-chain/, a trust-core path, and is a
   change of its own.

### Contrib adapters

A storage, bus, blob, sandbox or sensor adapter outside the two core
adapters per port goes in the contrib repository. It needs a named owner
and must pass grdr-ports-testkit. It never gates a release and is removed
after two releases with a failing kit.

## Every pull request

Fill in the template:

- Work item: `Closes #<n>`.
- Metadata: the tool and model that wrote the change, or `none` (see
  AI_POLICY.md).
- Testing: the commands you ran and their output.
- Risk: what could break, and where.
- How to revert.
- Not verified: what you could not build, run or test.
- Bug fixes: a test that fails before the fix, passes after, and fails
  again if the fix is reverted.
- Removals: a test that fails if the removed code is still there.

Commit messages are one line, for example:

    fix(grdr-core): return unresolved for here-doc bodies

The pull request, not the commit, names the work item and the tools used.
It lands as one squash commit whose message is the pull request title, so
the title follows the same form.

## Tests you cannot see

Pull requests are gated only by the public gates and reviews. The project also runs
a held-out test suite before releases and every night on the main branch.
Its tests are published two releases after use. If a held-out test fails
because of your change, a maintainer posts a public reproducer. You may ask
a maintainer to run the held-out suite on your pull request before merge;
you get the same category counts the project's own agents get.

## Response times

Every issue and pull request gets a response, from a maintainer or from the
project's triage agent marked as one, and every content pull request a
decision. community/health.md publishes the median times, by
affiliation, so anyone can check that outside contributions are not
handled more slowly.
