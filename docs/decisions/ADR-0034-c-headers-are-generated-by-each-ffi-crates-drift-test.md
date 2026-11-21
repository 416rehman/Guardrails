# ADR-0034: Each FFI crate generates its C header in its own drift test, held to the Rust, the contract, the status registry and a C compiler

- Status: proposed
- Date: 2026-11-21
- Decided by: chief architect
- Spine: D-02, D-60, D-61, D-63, D-71, P8, P9, P14
- Requires: #2 (the FFI crates in the workspace); the items of the Enforced by section
- RFC: 0004 (`rfcs/0004-c-header-generation-and-drift-check.md`), accepted on #474
- Work items: #474, #1776, #1777, #1778, #1779, #1780, #1781; #418, #388, #247 apply it

## Context
EM-2 (#418) needs `grdr_fastpath.h` produced from the `grdr_fp_*` exports, with a CI check that fails on drift. #388 needs the same for `grdr.h`, and #247 for `grdr_macos.h`. Design/26 EM-2 says the header is "generated and diffed in CI", design/03 section 7 gates the C ABI on "Generated header diffed", and `spec/host-contract/c-abi.md` says the generated headers are diffed against its text.

The constraints:
- The fast-path closure may hold only `grdr-fastpath` and `grdr-fastpath-ffi` (design/26 section 2).
- cbindgen is MPL-2.0, which `supply-chain/licences.toml` keeps out of layers 0 to 2, `grdr-ffi` and the embedded closure.
- ADR-0029 removed `xtask`.

RFC 0004 went through three rounds of the persona council and `eval-architecture`. The last round passed with no major finding (#474, comment 7057386447).

## Decision
Each FFI crate keeps a descriptor of its header in `tests/header_drift.rs`. The descriptor lists every export, struct, enum, typedef and constant, each field's data class and byte encoding, and the header's content: SPDX identifier, contract section, optional status block and optional version scheme. Macros make the compiler hold it to the Rust items.

The `tool` crate `grdr-cabi-testkit` (unpublished, std only, no dependency) runs the whole test behind an `Env` trait. It renders the header and a layout-assert source and requires the committed files to match byte for byte. It also checks:
- types and layout against rustc (`HDR-1`);
- the committed text (`HDR-2`);
- declarations and stated offsets against the protected contract (`HDR-3`);
- status constants and the version function against the registry (`HDR-4`);
- every export, written out at the top level of `src/lib.rs` (`HDR-5`).

Every failure names its next step, and a bless always fails its run. A `c-headers` CI job compiles every committed header and layout source as C and C++ on the systems `verify.yml`'s `plan` job selects. Rust enums cross the boundary only as return values.

No third-party dependency, licence change, public crate or same-layer edge is added. The `grdr_status` block of `grdr.h` and `grdr_fastpath.h` is one piece of default content, so the two blocks are identical.

## Enforced by
- The drift test of each FFI crate, run by `cargo test --workspace` in `verify.yml`'s `rust` job, with `HDR-1` to `HDR-5` and the testkit's seeded unit tests: #1778.
- Compile-time checks of the descriptor (signatures, fields, field types, enum variants) and their `compile_fail` doctests: #1778, and #418 for `grdr_fp_arena_size`.
- The `c-headers` job on `plan`'s systems. gcc and clang run on every pull request. MSVC (`/std:c11`, `/std:c++14`) and Apple clang are read from the dispatched run on the head: #1779.
- The high-tier row for `crates/grdr-cabi-testkit/**` in `.claude/risk-tiers.toml`: #1777.
- `HDR-3` against `c-abi.md` section 2.4, which #246 carries.
- ARCH-001 over the testkit's `layer = "tool"`, and `cargo tree -e normal,build` on `grdr-fastpath-ffi` (#418 AC-6).
- #473's check of the archive's defined symbols, independent of the textual export scan.
- #1771, the cross-release compatibility check, as a gate of the first release that ships a header and of any move out of experimental.

## Consequences
- Changing an exported function takes three hand edits and a bless: the contract (an issue first, since it is protected), the Rust, and the descriptor.
- Exports live at the top level of `src/lib.rs`, so #418's modules hold implementations only.
- The test reads `spec/` from the crate directory, so a published FFI crate excludes `tests/header_drift.rs` from its package.
- Embedders get a committed header and a layout source they can compile without Rust, with the data class and encoding beside each field.
- A private copy of the repository compiles its headers with gcc and clang only.

## Alternatives rejected
- A hand-written header parsed against the crate's source: two parsers, a new dependency, and no layout check (RFC 0004, Alternative a).
- cbindgen as a dependency or in `build.rs`: the licence class and the fast-path closure forbid it (b1, b2). As a pinned tool it stays the fallback (b3).
- An `xtask` tool: removed by ADR-0029 (b4).
- The testkit as a public layer 1 crate: design/03's `tool` layer already covers it (i).
- A C compile inside `cargo test`, or a CI job with its own system list: it would need a compiler on every contributor's machine, or a second planner beside `plan` (j, m).

## Revisit when
- The testkit's drift tests and `c-headers` together give a false failure that the stated rules cannot remove.
- Or a header needs a C construct the descriptor cannot express.
- Either way, the fallback is cbindgen as a pinned tool (RFC 0004, Alternative b3), through a new RFC.
