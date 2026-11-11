# Provenance: unslop

| Field | Value |
|---|---|
| Upstream | `cursor/plugins`, file `pstack/skills/unslop/SKILL.md` |
| Commit | `5866df557357d005b3c0c9d3da0d9e739b4bdde3`, 2026-11-11. The file is unchanged since `bc697d0a5a163cec979e362b601e36f5616083fd` and has the same blob at the research's `c742dd61706fbacc1b95f1a20b7b988cf096ce6c` |
| Licence | MIT, Copyright (c) 2026 Lauren Tan. `LICENSE` here is upstream `pstack/LICENSE` (blob `6b5400237fdf6545be0b8fae370d6f2fcff8fb25`), unchanged |
| Copied | 2026-11-11, through the GitHub API at the commit above |
| Why vendored | Two rules conflict with how this repository writes specifications (de-slop research, section 1.1) |

Only the skill is taken. The pstack plugin itself stays out: it sends subagents to another vendor's model.

## Files

| File | Upstream blob | Blob here | State |
|---|---|---|---|
| `skills/unslop/SKILL.md` | `97f5b6412148fa5b2a2fe478836fe8923ffa5cbb` | `5c2fd4b6c7f7dfc89d8a608af5cf2930b0fda394` | Edited |
| `LICENSE` | `6b5400237fdf6545be0b8fae370d6f2fcff8fb25` | Same | Unchanged |

`.claude-plugin/plugin.json` and this file are ours.

## Edits

1. Rule 13 allows parentheses, which gate V25 offers in place of an em dash.
2. The opening paragraph keeps "must", "never" and "should" as requirement words, which rules 24 (hedging) and 30 (adverbs) would otherwise cut from a specification.

Upstream already sets `disable-model-invocation: true`, so `impl-docs` runs it as `/unslop:unslop` once over the prose its item changed.

## Moving the pin

A pin move is a protected change (owner instruction 7). Fetch the file at the new commit, compare it with the upstream blob above, apply the two edits again, and update this file and `../../PINS.md` in the same change.
