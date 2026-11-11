---
name: grdr-scaffold-crate
description: Create a new crate in the workspace. Use when an item adds a crate or splits a module out of `grdr-core`.
license: Apache-2.0
metadata:
  version: "1"
  owner: agent-kit
  requires: cargo xtask new-crate
  closes-by: lint
---

# Add a crate to the workspace

A crate is a unit of the architecture: its layer, privilege and surface are gate data that `archlint`, the risk classifier and the trust-core list read. Get those three right first; everything else follows from them.

## 1. Decide that it should be a crate

- The item names the crate, and the crate is in the item's write set.
- A module of `grdr-core` becomes a crate only when it gains a second consumer or needs a different licence (design/03 section 2). Otherwise it stays a module: ARCH-013 holds the module import table, and a later split is a file move. If the item asks for a split and neither condition holds, hand off with status `blocked` and that reason in `next`, for the lead to decide.
- The name starts with `grdr-` and matches the crate table in design/03 section 2 when the crate is listed there.

## 2. Decide its metadata

| Key | Values | Source |
|---|---|---|
| `layer` | `0` to `4`, or `tool` | design/03 section 2. A crate may depend only on lower layers plus listed same-layer edges; `tool` crates (`xtask`, `grdr-policy-ref`, `grdr-conformance`) may depend on any layer and are never linked into a layer 4 program |
| `privilege` | `privileged`, `sandboxed`, `untrusted`, `none` | The process it runs in (design/03 section 4). A privileged crate must be on `security/trust-core.paths` |
| `surface` | `public`, `internal` | Layers 0 to 2 are public: published, semver-checked, and changed only by RFC (D-61) |

Layer 4 programs live in `programs/<name>/`; every other crate in `crates/<name>/`.

## 3. Create it

```sh
cargo xtask new-crate <name> --layer <N> --privilege <P> --surface <S>
```

Then check what it wrote:

- `Cargo.toml` with `[package.metadata.grdr]` holding `layer`, `privilege` and `surface`, and `[lints] workspace = true`.
- `src/lib.rs` (or `src/main.rs` for a program) with `#![forbid(unsafe_code)]`, unless the crate is an OS adapter crate or `grdr-ffi` (SD-01).
- `tests/` for integration tests; unit tests beside the code.
- The crate `AGENTS.md` from the template of team/06 section 5, under 60 lines, its front block matching `[package.metadata.grdr]`. See step 5: this file is protected.

The root manifest's `members = ["crates/*", "programs/*", "xtask"]` already picks up the new directory, so `Cargo.toml` at the root needs no edit unless the crate changes `default-members`, `exclude` or workspace dependencies.

## 4. Follow the conventions from the first line

- One error enum with stable codes `GRDR-<AREA>-<NNNN>`, each registered in `grdr-schema`, each with a class: `input`, `policy`, `retryable`, `fatal`, `internal`. No dynamic error type below layer 4.
- Layers 0 and 1: no I/O, async runtime, clock or randomness. Take `now` and `entropy` as arguments, or return an `Effect`. Layer 1 builds for `wasm32-unknown-unknown`.
- Layers 0 to 2 and privileged crates: no `unwrap`, `expect`, unchecked indexing or unchecked arithmetic.
- Every queue, map, cache, body size and recursion depth has a named bound in `limits.toml`.
- Log macros take `LogSafe` values only. No brand string outside `brand/`.
- No new dependency in this item. A dependency is its own high-tier item; `cargo add` is denied for implementers.
- Every file follows skill `grdr-structure` from its first line: declaration order, the 500-line limit, state types instead of flags. A new crate starts with nothing in `quality/file-size.toml` and should never need an entry.

## 5. Request the protected entries

The crate needs entries in files no agent may write. Put each in the hand-off's `protected_change_requests` with the reason, and post the exact text to add as one comment on the item's issue, headed with the target path (`gh issue comment <n> --body-file <file>`):

| File | Entry |
|---|---|
| `architecture.toml` | The crate and its layer. A same-layer edge is an RFC, never part of this item |
| `limits.toml` | One key per bound from step 4 |
| `crates/<name>/AGENTS.md` (`**/AGENTS.md` is protected) | The whole file, from the template of team/06 section 5 |
| `.agents/owners.toml` | The owning squad, so `verify` finds no unowned path |
| `security/trust-core.paths` | Only for a privileged crate or another D-63 class; `verify` fails while a privileged crate is outside it |
| `audits/library.toml` | The nightly rotation and the path filters of the prompts that apply (team/04 work item 10) |
| `surfaces.toml` | Only for a public crate, with its stability class |
| `**/clippy.toml` | Only if the layer needs disallowed-method rules the existing file lacks |

If the `architecture.toml` entry is not on the base branch, `archlint` (V04) fails on the new crate. Then hand off with status `blocked` and these requests; the lead files them as a protected-change item for `lead-agent-kit` before the item is ready again. Never edit the files to get green.

The error-code registration in `grdr-schema` is a high-tier path. If `crates/grdr-schema/**` is not in your write set, put the codes in the hand-off's `next` field.

## 6. Verify and hand off

Run `cargo xtask verify --fast` (skill `grdr-verify`). `archlint` checks the layering; `kit check` fails a crate without an `AGENTS.md` or with one over 60 lines, which is expected until its protected-change item lands: say so in the hand-off. Finish with `grdr-handoff`.

## Before `cargo xtask new-crate` exists

No work item in team/06 section 10 reserves `new-crate`; it is one of the kit items leads file from WI-0054 onward. If `xtask` reports an unknown subcommand, check for an open issue that adds it (`gh issue list --state open --search "new-crate in:title"`) and, if there is none, file one with `status:proposed` (skill `grdr-handoff`, "File new work"). Then create the crate by hand as WI-0001 creates the initial crates, following `references/manual-scaffold.md`, and say in the hand-off that the scaffold was written by hand.
