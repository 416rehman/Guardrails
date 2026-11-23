---
name: grdr-write-spec
description: Lean spec helper for complex non-trivial issues only. Skip completely for fast-track tasks or issues that already state goal, paths, and acceptance checks.
license: Apache-2.0
metadata:
  version: "4"
  owner: agent-kit
---

# Write a short, actionable specification

## 1. When to skip (default for routine work)
Do **not** spawn a spec-writer or write formal R-numbered specs for:
- `fast_track` issues (dependency/tool pins, docs, tests, lint/config tweaks, small bug fixes under 50 lines);
- any issue whose description already names the goal, target files, and how to test it.

Proceed straight to implementation (or direct orchestrator edit for fast-track).

## 2. Complex features & RFCs only
When a medium/high feature truly lacks clarity or needs an ADR/RFC:
1. Keep the spec short and direct (Problem, target Write set, Behaviour, 2 to 5 simple Acceptance Criteria JSON entries).
2. **Cap acceptance criteria at 2 to 5 concrete checks** (never bloat an issue into 10+ ACs, custom mutation-testing drivers, cross-squad sign-off chains, or persona-council reviews).
3. Reserve threat models and reference models strictly for **runtime** `trust-core` components (`security/trust-core.paths` code paths), never for config files, dependency pins, or agent markdown.
4. Set labels (`squad:`, `kind:`, `tier:`, `agent:`, `trust-core` only if `security/trust-core.paths` matches) and write via `gh issue edit <n> --body-file target/proposed-<slug>.md`.
5. Use spine vocabulary (`Mode`, no case object), British English, and no em dashes.
