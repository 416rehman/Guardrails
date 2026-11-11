# Provenance: ce-simplify-code

| Field | Value |
|---|---|
| Upstream | `EveryInc/compound-engineering-plugin`, directory `skills/ce-simplify-code/` |
| Commit | `dd9b7921c9c80498eba84994ff1b8e1e81dbc1db`, tag `compound-engineering-v3.37.1`, 2026-11-09 |
| Licence | MIT, Copyright (c) 2025 Every. `LICENSE` here is the upstream root `LICENSE` (blob `959dd283c510cfac6fd912555f99b14613ee9018`), unchanged |
| Copied | 2026-11-11, file by file through the GitHub API at the commit above |
| Why vendored | The skill needs edits before it fits this repository (de-slop research, section 1.1) |

The de-slop research reviewed the skill at `406b85c4562de3d415927fccc5e614c6554aab00`. Owner instruction 22 pins the newest stable release instead, so this copy comes from v3.37.1 with the research's edits applied to it. That release also added a structural pass; it is removed here, because judging structure belongs to audit A01 and the thermo-nuclear review seat (research section 1.2).

## Files

| File | Upstream blob | Blob here | State |
|---|---|---|---|
| `skills/ce-simplify-code/SKILL.md` | `945ae2a9503ea5604b20505bf62b25d46dcaf09f` | `30f856e4b0415f74fee2b4991f890a017a50532e` | Edited |
| `skills/ce-simplify-code/references/standalone-report.md` | `f8911c145750bf1abaafd48afed128b8f514263b` | `10379ce4a51b35c5ddcbd49ea7d4ef5c5268ad41` | Edited |
| `skills/ce-simplify-code/references/personas/code-quality-reviewer.md` | `05b09f1a92353b72d3b29945e25b3fd636bec243` | `a214b77f767e76b9a1749a446258bc3b29b8889b` | Edited |
| `skills/ce-simplify-code/references/personas/code-reuse-reviewer.md` | `1189e4e1670bab44863195c79ac22060a40ca394` | Same | Unchanged |
| `skills/ce-simplify-code/references/personas/test-value-reviewer.md` | `86fa8ce2bb58af2991ed90b3b46583836fe49351` | Same | Unchanged |
| `skills/ce-simplify-code/references/reviewer-dispatch.md` | `f74593fcdff0ff2fdc2246997f117d651e8955a7` | Same | Unchanged |
| `skills/ce-simplify-code/references/single-pass.md` | `2179e18e6900c749108622827ebc0bc71aa51877` | Same | Unchanged |
| `LICENSE` | `959dd283c510cfac6fd912555f99b14613ee9018` | Same | Unchanged |

`.claude-plugin/plugin.json` and this file are ours. Check a checkout with `git hash-object <file>` against the third column.

Not copied:

- `references/personas/comment-reviewer.md` and `references/personas/efficiency-reviewer.md`: `cleanup` owns comments and efficiency within the diff.
- `references/personas/structure-reviewer.md`, `references/structural-pass.md` and `scripts/structure-evidence.py`: the structural pass.

## Edits

1. `SKILL.md` front matter: `disable-model-invocation: true`, so the skill runs only when `garden-deslop` invokes it, and a description that says so. Upstream lets the agent start it at a completion boundary.
2. `SKILL.md` Step 2 dispatches the reuse, quality and test-value reviewers only.
3. Test-value findings are reported and never applied (`SKILL.md` Steps 1, 3, 4 and 5; `standalone-report.md`). They become issues for the agent that owns the tests.
4. `SKILL.md` Step 4 runs `cargo xtask verify --fast` in place of "typecheck, lint, tests".
5. `standalone-report.md` no longer points at the structural pass or reports comment findings, and its one em dash is a semicolon (gate V25).
6. `code-quality-reviewer.md` item 8 leaves comments to `cleanup`.
7. The em dash in the opening paragraph of `SKILL.md` became two sentences.

## Moving the pin

A pin move is a protected change (owner instruction 7). Fetch `skills/ce-simplify-code/` at the new commit, compare it with the upstream blobs above to see what changed, apply the edits again, and update this file, the table in `../../PINS.md` and nothing else in the same change.
