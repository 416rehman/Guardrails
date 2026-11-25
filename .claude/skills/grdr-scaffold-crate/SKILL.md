---
name: grdr-scaffold-crate
description: Create a new crate in the workspace. Use when an item adds a crate or splits a module out of `grdr-core`.
license: Apache-2.0
metadata:
  version: "2"
  owner: agent-kit
  closes-by: lint
---

# Add a crate to the workspace

A crate is a unit of the architecture: its layer, privilege and surface are gate data that the architecture lint, the risk tiers and the trust-core list read. Get those three right first; everything else follows from them.

## 1. Decide that it should be a crate

- The item names the crate, and the crate is in the item's write set.
- A module of `grdr-core` becomes a crate only when it gains a second consumer or needs a different licence (design/03 section 2). Otherwise it stays a module: ARCH-013 holds the module import table, and a later split is a file move. If the item asks for a split and neither condition holds, report `blocked` with that reason, for the lead to decide.
- The name starts with `grdr-` and matches the crate table in design/03 section 2 when the crate is listed there.

## 2. Decide its metadata

| Key | Values | Source |
|---|---|---|
| `layer` | `0` to `4`, or `tool` | design/03 section 2. A crate may depend only on lower layers plus listed same-layer edges; `tool` crates (`grdr-policy-ref`, `grdr-conformance`) may depend on any layer and are never linked into a layer 4 program |
| `privilege` | `privileged`, `sandboxed`, `untrusted`, `none` | The process it runs in (design/03 section 4). A privileged crate must be on `security/trust-core.paths` |
| `surface` | `public`, `internal` | Layers 0 to 2 are public: published, semver-checked, and changed only by RFC (D-61) |

Layer 4 programs live in `programs/<name>/`; every other crate in `crates/<name>/`.

## 3. Create it

Follow `references/manual-scaffold.md`: `cargo new`, then the manifest, source and tests by hand. The
result has:

- `Cargo.toml` with `[package.metadata.grdr]` holding `layer`, `privilege` and `surface`, and `[lints] workspace = true`.
- `src/lib.rs` (or `src/main.rs` for a program) with `#![forbid(unsafe_code)]`, unless the crate is an OS adapter crate or `grdr-ffi` (SD-01).
- `tests/` for integration tests; unit tests beside the code.
- The crate `AGENTS.md` from the template of team/06 section 5, under 60 lines, its front block matching `[package.metadata.grdr]`. See step 5: agents may not edit this file.

The root manifest's `members = ["crates/*", "programs/*"]` already picks up the new directory, so `Cargo.toml` at the root needs no edit unless the crate changes `default-members`, `exclude` or workspace dependencies.

## 4. Follow the conventions from the first line

- One error enum with stable codes `GRDR-<AREA>-<NNNN>`, each registered in `grdr-schema`, each with a class: `input`, `policy`, `retryable`, `fatal`, `internal`. No dynamic error type below layer 4.
- Layers 0 and 1: no I/O, async runtime, clock or randomness. Take `now` and `entropy` as arguments, or return an `Effect`. Layer 1 builds for `wasm32-unknown-unknown`.
- Layers 0 to 2 and privileged crates: no `unwrap`, `expect`, unchecked indexing or unchecked arithmetic.
- Every queue, map, cache, body size and recursion depth has a named bound in `contracts/limits.toml`.
- Log macros take `LogSafe` values only. No brand string outside `contracts/interface/brand/`.
- No new dependency in this item. A dependency is its own high-tier item, and an implementer never runs `cargo add`.
- Every file follows skill `grdr-structure` from its first line: declaration order, the 500-line limit, state types instead of flags.

## 5. Request the entries agents may not write

The crate needs entries in files an ordinary issue may not change (`team/05` section 5). File them as one issue for `lead-agent-kit` with the reason for each, name it in your report, and post the exact text to add as one comment on the item's issue, headed with the target path (`gh issue comment <n> --body-file <file>`):

| File | Entry |
|---|---|
| `architecture.toml` | The crate and its layer. A same-layer edge is an RFC, never part of this item |
| `contracts/limits.toml` | One key per bound from step 4 |
| `crates/<name>/AGENTS.md` (no ordinary issue writes `**/AGENTS.md`) | The whole file, from the template of team/06 section 5 |
| `.claude/owners.toml` | The owning squad, so every path has one owner |
| `security/trust-core.paths` | Only for a privileged crate or another D-63 class; a privileged crate outside it is a review blocker |
| `audits/library.toml` | The nightly rotation and the path filters of the prompts that apply (team/04 work item 10) |
| `surfaces.toml` | Only for a public crate, with its stability class |
| `**/clippy.toml` | Only if the layer needs disallowed-method rules the existing file lacks |

If the `architecture.toml` entry is not on `main`, the architecture lint fails on the new crate once it exists. Then report `blocked` with that issue; it lands before this item is worked again. Never edit the files to get green.

The error-code registration in `grdr-schema` is a high-tier path. If `crates/grdr-schema/**` is not in your write set, put the codes in your report's `Next` field.

## 6. Verify and report

Run the gates of `grdr-verify`. Say in your report that the crate `AGENTS.md` waits on the issue from step 5. Finish with `grdr-handoff`.
