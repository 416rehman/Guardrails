# Scaffold a crate by hand

Use this only while `cargo xtask new-crate` does not exist (cargo reports no `xtask` command, or `xtask` reports an unknown subcommand). It produces what the command will produce, so the result passes the same checks.

## 1. Create the package

```sh
cargo new --lib --vcs none crates/<name>        # layers 0 to 3 and tool crates
cargo new --bin --vcs none programs/<name>      # layer 4 programs
```

These are the commands WI-0001 uses for the initial crates (team/06 section 13 step 7).

## 2. Edit the package manifest

`crates/<name>/Cargo.toml` is not protected (only the root `Cargo.toml` is). Add:

```toml
[package.metadata.grdr]
layer = 1                # 0 to 4, or "tool"
privilege = "none"       # privileged | sandboxed | untrusted | none
surface = "internal"     # public | internal

[lints]
workspace = true
```

Keep `edition`, `version` and `license` consistent with the sibling crates; read one before you write. Add no `[dependencies]` beyond workspace crates the layer rules allow. A third-party dependency is its own item.

## 3. Source and tests

- `src/lib.rs` starts with `#![forbid(unsafe_code)]` unless the crate is an OS adapter crate or `grdr-ffi`.
- The error enum, with codes `GRDR-<AREA>-<NNNN>`. The codes are registered in `grdr-schema` (step 5 of `SKILL.md`).
- `tests/` for integration tests. One real test that exercises the crate's first behaviour; no placeholder test that asserts nothing.

## 4. Draft the crate `AGENTS.md`

`crates/<name>/AGENTS.md` matches the protected glob `**/AGENTS.md`, so write the draft in `.agent/state/<name>.AGENTS.draft.md` and post it as a comment on the item's issue headed `Proposed crates/<name>/AGENTS.md`. Follow the template of team/06 section 5: the front block (layer, privilege, surface, squad, trust core, stability for public crates, design reference), then Purpose, Invariants (each with the test, lint or type that holds it), Allowed dependencies, How to test (command, oracle, fuzz and differential targets), Data classes, Limits, Do not. At most 60 lines.

## 5. Check before the hand-off

```sh
cargo metadata --format-version 1 --no-deps > /dev/null    # the workspace sees the crate
cargo build -p <name>
cargo test -p <name>
```

Then `grdr-verify`. Record each command as an evidence entry. List every protected entry from step 5 of `SKILL.md` in `protected_change_requests`.
