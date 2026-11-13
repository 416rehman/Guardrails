# ADR-0017: The public gate is `verify`; the held-out suite gates releases and agent work items

- Status: proposed
- Date: 2026-11-11
- Decided by: chief architect
- Spine: D-45
- Requires: the efficacy harness and the replay model endpoint
- RFC: not required: restates D-45 as repository mechanism
- Work items: [WI-0027], [WI-0028], [WI-0012]

## Context
A team that can read its own test set fits to it (brief g08; reviews c8, c9, l09). An outside contributor must still be able to run every gate their pull request faces.

## Decision
The pull-request gate is the public `cargo xtask verify` and nothing else. A held-out scenario suite, in a private repository behind an evaluator service, gates releases and gated agent work items. Agents receive category counts only. Each held-out set is published two releases after use, and the scorecard reports the margin between the tuning set and the held-out set.

## Enforced by
The evaluator service of [WI-0028], which returns counts to agents and full results to maintainers. The release workflow gate, which blocks a release when the held-out margin is above 5 points (spine section 9). Keeping the held-out repository out of worker sessions is part of [WI-0028]'s acceptance: agents receive category counts only.

## Consequences
Outsiders see the same gate as agents. The project keeps one private repository, which P11 lists as a stated exception.

## Alternatives rejected
- All scenarios public: efficacy numbers would measure fitting.
- The held-out suite on every pull request: every run leaks signal about its content.

## Revisit when
The held-out margin stays under 1 point for three releases; the set size or the rotation is then reviewed.
