# ADR-0025: The repository is public from the first push, after the pre-push public gate on the seed

- Status: proposed
- Date: 2026-11-11
- Decided by: chief architect
- Spine: D-02, D-62, D-64
- Requires: nothing
- RFC: not required: restates owner instruction 28
- Work items: [WI-0004]; the gate itself ran at setup (`team/06` section 11 items 6 and 9)

## Context
The owner ruled that the repository stays public (owner instruction 28). A public history cannot be recalled, and free hosted runners, CodeQL and Scorecard are available only to a public repository.

## Decision
The main repository is public from its first push. Before that push a public gate runs on the seed commit: a secret scan of the whole tree and history, no `research/_sources/` path and no personal data beyond what the project publishes. A finding is fixed by amending the unpushed commit. The covenant, the governance files and the D-66 search are work items, not conditions of being public.

## Enforced by
The pre-push public gate of `team/06` section 11 item 9 (gitleaks with `supply-chain/gitleaks.toml` and the path check), run by the setup session before the first push. GitHub secret scanning with push protection on every later push, a repository setting `cargo xtask github check` reads. gitleaks in `verify` and `scan.yml` ([WI-0004]).

## Consequences
Everything committed is published at once, so a secret that lands is rotated at its issuer immediately. CI runs its full public form from the first commit.

## Alternatives rejected
- A private period until governance files exist: owner instruction 28 replaced it.
- Relying on push protection alone: it recognises only known token formats.

## Revisit when
The repository is ever made private; the workflows then fall back to their Linux-only form (D-64).
