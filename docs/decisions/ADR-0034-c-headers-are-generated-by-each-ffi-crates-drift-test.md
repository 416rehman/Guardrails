# ADR-0034: Each FFI crate generates its C header in its own drift test, with layout and signature checks compiled into every build of the library

- Status: proposed
- Date: 2026-11-21
- Decided by: chief architect
- Spine: D-02, D-60, D-61, D-63, D-71, P8, P9, P14
- Requires: #2 (the FFI crates in the workspace); the items of the Enforced by section; #1668 and #1741 for the CI part of the protection of the contract and the header list
- RFC: 0004 (`rfcs/0004-c-header-generation-and-drift-check.md`), accepted on #474 as revision 6
- Work items: #474, #1776, #1777, #1778, #1779, #1780, #1781, #1784, #1817; #418, #388 and #247 apply it; #1588 adds the `embedded` profile to the header list

## Context
EM-2 (#418) needs `grdr_fastpath.h` produced from the `grdr_fp_*` exports, with a CI check that fails on drift. #388 needs the same for `grdr.h`, and #247 for `grdr_macos.h`. Design/26 EM-2 says the header is "generated and diffed in CI", design/03 section 7 gates the C ABI on "Generated header diffed", and `spec/host-contract/c-abi.md` says the generated headers are diffed against its text.

The constraints:
- The fast-path closure may hold only `grdr-fastpath` and `grdr-fastpath-ffi` (design/26 section 2).
- cbindgen is MPL-2.0, which `supply-chain/licences.toml` keeps out of the libraries and closures it names.
- ADR-0029 removed `xtask`.
- The shipped libraries are built in configurations the test build differs from: the `embedded` profile's `panic = "abort"` (design/03 section 8), which Cargo ignores for tests; features a dev-dependency turns on in the test build but not in the shipped one; and aarch64 targets where `c_char` is unsigned.

RFC 0004 went through four review rounds: the persona council, `eval-architecture`, `eval-diff`, `eval-acceptance`, `eval-security` and `eval-adversarial`. After the third, the owner narrowed its promise to accidental drift, because a test that runs code its writer controls cannot defend against that writer. Round 4 found that the shipped configuration was never checked. Revision 6 closes that for layout and signatures in the library itself, and the session holding the owner's delegation ruled that it is decided without a further round. `eval-security` passed revision 6 on the second model (#474, comment 7069562494); its minor findings are must-fail cases of #1778 and #1779.

## Decision
Each FFI crate keeps a descriptor of its header in `tests/header_drift.rs`. It lists every export, struct, enum, typedef and constant, and each field's data class and byte encoding. It also gives the header's content: SPDX identifier, summary, optional status block and optional version scheme. Macros make the compiler hold the descriptor to the Rust items, and every declared export is declared again by its C name, so the test does not link if the library lacks it.

The `tool` crate `grdr-cabi-testkit` (unpublished, std only, no dependency, no `unsafe`) renders three files from the descriptor:
- the header, with its structs between `#pragma pack(push, 8)` and `#pragma pack(pop)`;
- a layout-assert source beside it, for embedders and for the C compilers;
- `src/<file>_abi.rs`, size, alignment and offset asserts and a coercion of every export to its described signature, which the library compiles in every build.

The library includes the third file behind `#[cfg(not(grdr_bless))]`, so a bless can build it while the checks are stale. So every profile, feature set and target that builds the library checks the layout and signatures the header states.

The test requires the committed files to match their rendering, and checks:
- `HDR-1`: types and layout against rustc, a C type built for the Rust type at its position, and a `c_char` only as `as "char"`;
- `HDR-2`: the committed text of all three files;
- `HDR-3`: declarations, stated offsets and each field's data class and encoding against the contract that the header's `surfaces.toml` row names, read from every `c` and `h` fence;
- `HDR-4`: status constants and the version function against the registry;
- `HDR-5`: each linked symbol is the Rust item described, the crate's manifest, the `mod` line of the generated checks, and an early-warning scan of exports at the top level of `src/lib.rs`.

Every failure names its next step, and a bless always fails its run. Rust enums cross the boundary only as return values.

The header list is the `[[c_header]]` rows of `surfaces.toml`. Each row gives the header's file, crate, contract, section and stability class. It also gives what the header ships in, `profiles`, `features` and `targets`, as data (P14).

A `c-headers` CI job runs on the systems `verify.yml`'s `plan` job selects. Its five steps:
1. Holds the files and manifests to the header list.
2. Runs each drift test by name as `cargo test` and `cargo test --release`, with a negative control in a fresh copy with its own build directory.
3. Compiles every header and layout source as C and C++, including under 1-byte packing.
4. Compares the release export tables with the headers.
5. Checks each library in each listed profile, and each drift test, for each listed target.

The promise is accidental drift. A hostile writer of the descriptor, the crate's sources or its manifest is held by controls that do not run that writer's code:
- review of every pull request that changes a descriptor, an FFI crate's source or manifest, or a generated file. For `crates/grdr-fastpath-ffi/**` and `crates/grdr-ffi/**`, which are trust core, that is `eval-security`, `eval-adversarial` and two passing evaluators on different models (D-63). For the testkit and the header paths of other crates, it is the high-tier evaluators of `.claude/risk-tiers.toml` (#1777);
- the export tables of the release artefacts (#1784);
- for the contract and the header list, review alone today: the protected-path list of `team/06` section 2.1 and the evaluators' write-set check (ADR-0035). CI adds #1668's write-set job and `rfc-required` (#1741) when they land; both are open.

What remains is accepted for an experimental surface (D-60), and is not claimed as closed: a hostile change to the ABI behind the same exported symbol, by a writer who also passes that review.

No third-party dependency, licence change, public crate or same-layer edge is added. The `grdr_status` block of `grdr.h` and `grdr_fastpath.h` is one piece of default content, so the two blocks are identical.

## Enforced by
- The drift test of each FFI crate, `HDR-1` to `HDR-5`, the generated `src/<file>_abi.rs`, the pack pragmas, the fence rule and the testkit's seeded unit tests: #1778. From `eval-security`'s revision 6 findings, #1778 also asserts constant and status values in the generated file, requires the generated module's two lines exactly, reads contract fences by default deny, and applies the `c_char` rule to types, not lines. Its acceptance includes eval-adversarial round 4's P1, P1e, F1 to F3, X4 and D1 and eval-security round 4's packing case as must-fail cases.
- Compile-time checks of the descriptor and their `compile_fail` doctests: #1778, and #418 for `grdr_fp_arena_size`.
- `c-headers` steps 1, 2, 3 and 5: #1779. Its acceptance includes eval-adversarial round 4's P1 and P1e, eval-security round 4's F1 and packing case, and the sketch's T1 as must-fail cases. Step 4, the export tables: #1784.
- Review of every change to a descriptor, an FFI crate's source or manifest, or a generated file, by the evaluators the Decision names, on each pull request: `security/trust-core.paths` and the high-tier rows of #1777.
- The protection of `spec/host-contract/**` and `surfaces.toml`: review today, under ADR-0035; #1668's write-set job and `rfc-required` (#1741), both pending while open.
- The `[[c_header]]` rows with their profiles, features and targets: #1817. #1588 adds `embedded` to the C ABI rows when it defines `[profile.embedded]`.
- High tier for `crates/grdr-cabi-testkit/**`, `crates/*/tests/header_drift.rs`, `crates/*/include/**` and `crates/*/src/*_abi.rs`, and the testkit's owner: #1777.
- `c-abi.md` section 2.4, its packing sentence and the data-class brackets of its field comments, which `HDR-3` reads: #246.
- The design/03 amendments: #1780. The embedder page: #1781.
- ARCH-001 over the testkit's `layer = "tool"`, and `cargo tree -e normal,build` on `grdr-fastpath-ffi` (#418 AC-6).
- #1771, the cross-release compatibility check, as a gate of the first release that ships a header and of any move out of experimental.

## Consequences
- Changing an exported function takes three hand edits and a bless: the contract (an issue first, since it is protected), the Rust, and the descriptor. The bless sets `RUSTFLAGS="--cfg grdr_bless"`, which rebuilds the crate's dependencies once.
- Exports live at the top level of `src/lib.rs`, so #418's modules hold implementations only.
- The FFI libraries do not build for a 32-bit target until that target has its checks and its compiler leg.
- The test reads `spec/` and `surfaces.toml` from the crate directory, so a published FFI crate excludes `tests/header_drift.rs` from its package.
- Embedders get a committed header and a layout source they can compile without Rust, with the data class and encoding beside each field and a layout that survives their packing.
- Not covered, as RFC 0004 section 10 states:
  - a hostile change to the ABI behind the same exported symbol, by a writer who also passes trust-core review. It is accepted while the surface is experimental (D-60);
  - a target or profile the header's row does not list. Only the library's own layout and signature checks run there, not the drift test;
  - whether a field's data class is right. The contract states it and `HDR-3` holds the descriptor to it, but its correctness is review of the protected contract;
  - behaviour, which is #418's and #388's tests;
  - compilers off Linux on a pull request. A pull request compiles the headers with gcc and clang only. MSVC and Apple clang run in the dispatched run on the head, on pushes to `main` and nightly, and never in a private copy.

## Alternatives rejected
- A hand-written header parsed against the crate's source: two parsers, a new dependency, and no layout check (RFC 0004, Alternative a).
- cbindgen as a dependency or in `build.rs`: dev graph cost, no layout or contract check, and the fast-path closure (b1, b2). As a pinned tool it stays the fallback (b3).
- An `xtask` tool: removed by ADR-0029 (b4).
- The testkit as a public layer 1 crate: design/03's `tool` layer already covers it (i).
- A C compile inside `cargo test`, or a CI job with its own system list (j, m).
- A line-based scan of `src/lib.rs` as the export check, or rustdoc JSON as the compiler's view: broken from several directions, or unstable on the pinned toolchain (o, p).
- A drift test that defends against a hostile descriptor writer: the test runs that writer's code, so each closed route opened another (s).

## Revisit when
- A C header is to leave experimental (D-60). The hostile-writer residual was accepted for an experimental surface only, so it is decided again before the header's `class` changes.
- #1668 or #1741 is closed without landing, which leaves the contract and the header list protected by review alone.
- The drift tests and `c-headers` together give a false failure that the stated rules cannot remove.
- A header needs a C construct the descriptor cannot express.
- For the last two, the fallback is cbindgen as a pinned tool (RFC 0004, Alternative b3), through a new RFC.
