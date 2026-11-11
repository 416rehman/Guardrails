# Provenance: vale-ai-tells styles

| Field | Value |
|---|---|
| Upstream | https://github.com/tbhb/vale-ai-tells |
| Commit | `51f646e366ba7c9dcb078ebeae345b7ff353eb3b` (2026-10-11) |
| Licence | MIT, "Copyright (c) 2025-2026 Tony Burns" (`LICENSE`, copied unchanged) |
| Copied on | 2026-11-11, through the GitHub API at the commit above |
| Changes | None. This file is the only addition |
| Why vendored | `verify` runs Vale with these styles in CI and outsiders run the same command, so the rules must be in the tree at a fixed commit (de-slop research, 2026-11-11; design/24 section 12) |

## What was copied

Upstream paths keep their place under this directory, so Vale's `StylesPath` is
`third_party/vale/ai-tells/styles`. Each git object id below equals the upstream object at the
commit, so `git ls-tree` on a checkout proves the copy:

| Path | Git object | Content |
|---|---|---|
| `styles/ai-tells/` | tree `799afec480ef8e136376c9416aae738a338ff806` | 137 rules for prose |
| `styles/ai-tells-commits/` | tree `406bec4412fd8ed347c06bf1fd0eb66f6fc3ee02` | 15 rules for commit messages and pull request titles |
| `styles/config/vocabularies/vale-ai-tells/` | tree `b451f2fc08788d900736612e352784ee03cc24e6` | The upstream accept list |
| `LICENSE` | blob `b77a7e63d80bed7e3eefa6f8d26b8bda614e31b7` | MIT licence |

## What was not copied

- `styles/ai-tells-experimental/` and the Tengo scripts under `styles/config/scripts/`: only the
  experimental rules load the scripts, and no rule in the two copied styles extends `script`.
- The upstream catalog name, the release archive, the test fixtures and the repository's own
  agent tooling (`.claude/`), which sets another vendor's model.

## Updating

A new commit is a dependency change of its own: copy the same paths at the new commit, update this
file's commit and object ids, and run the Vale gates. Rules are tuned through our Vale
configuration, never by editing files here.
