# AI-Assisted Contributions Policy

Guardrails ADR is built with AI coding agents, which plan, write, review, and release changes
under transparent public rules. This policy applies identically to human contributors and to the
project's own steward agents. It may be changed only by public RFC.

## 1. The Rules

1. Every contribution has a responsible author: a human contributor or the project agent named in
   the pull request. Changes land solely via squash merge of a pull request whose CI gates and
   required reviews have passed. No individual approval acts as a manual gatekeeper, no evaluator
   reviews a change it wrote, and AI agents hold no `CODEOWNERS` entry or steering vote.
2. Every code change links an accepted work item (`Closes #<n>`). Agents do not open unsolicited
   pull requests against external projects or this repository without a tracked issue.
3. Every pull request declares in its metadata block whether AI was used: specify `<tool>:<model>`
   (for example `claude-code:claude-sonnet-4-6` or `antigravity:gemini-3.1-pro`) or `none` if
   no AI tool authored any part of the diff, commit message, or PR description.
4. Every pull request includes the verification evidence block from `PULL_REQUEST_TEMPLATE.md`
   with real observed command outputs (and explicit notation of anything not executed locally).
5. There is no DCO and no commit trailer (`Signed-off-by`, `Co-Authored-By`, or generated badges).
   Every commit is a single Conventional Commit line (maximum 72 characters).

## 2. What Opening a Pull Request Means

By opening a pull request you submit the contribution under `Apache-2.0` Section 5 (or
`GPL-2.0-only OR BSD-2-Clause` under `bpf/`) and confirm that:
- Any tool's terms of service allow you to contribute its output under `Apache-2.0`.
- You did not feed it, and it did not fetch, restricted material listed in
  `security/supply-chain/do-not-read.toml` or incompatible source code.
- The output does not, to your knowledge, reproduce third-party code or rules under an
  incompatible licence.

Review depth follows the risk tier recorded on the pull request: low-risk changes require one
independent review; medium-risk changes follow their tier evaluation; high-risk and trust-core
(`security/trust-core.paths`) changes require dual independent security/adversarial passes across
distinct models (`docs/design/02`, `docs/design/35`, `ADR-0043`).

## 3. Quality Bar & Same Gate for Everyone

Public CI gates (`cargo fmt`, `cargo clippy`, `cargo test`, `cargo deny`, `check-architecture`,
`licence-lint`, Web typecheck/tests/build, and fuzz/CodeQL checks) apply uniformly to all authors.
Contributions costing more to review than their value (unlinked diffs, non-failing tests,
compatibility shims violating pre-release rules, or missing verification output) are closed with a
clear reason (`extractive`).

## 4. Security Reports

AI-assisted vulnerability discoveries are welcome via `SECURITY.md` private reporting channels
provided they include a minimal deterministic reproducer and exact scope tested. Reports without
reproducers are closed.
