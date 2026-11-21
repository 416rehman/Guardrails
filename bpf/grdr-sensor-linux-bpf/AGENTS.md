# grdr-sensor-linux-bpf

layer: 3   privilege: privileged   renders: none
surface: internal   squad: linux   trust core: yes
stability: not applicable (internal crate)
design: docs/design/10-sensor-linux-containers-ci.md sections 2 and 3; notes: none (internal crate)

## Purpose
The Linux kernel programs, licensed `GPL-2.0-only OR BSD-2-Clause` (ADR-0004), outside the workspace and built to an object the back end loads, never a Cargo dependency (design/10 section 3).

## Invariants
- Dependency edges: none yet. Every edge goes to a lower layer or is a same-layer edge of `architecture.toml` (`cargo metadata`; ARCH-001 once #1580 lands).
- Checked or saturating arithmetic: `#![deny(clippy::arithmetic_side_effects)]` at the crate root (ADR-0022).
- No panic path in non-test code: the clippy deny lints of its own `[lints]` table, a copy of the root's.
- `unsafe_code` is `deny` in its own `[lints]` table; aya-ebpf helper calls will take a reasoned `#[allow(unsafe_code)]` and a `// SAFETY:` comment. It has none yet.
- Formats no text a person or an agent reads (`renders = "none"`).
- Trust core: `bpf/**` in security/trust-core.paths (D-63).
- Not a workspace member: the root `exclude` and its own empty `[workspace]` table.
- Line 1 of `src/lib.rs` is `// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause` and line 2 is `// SPDX-FileCopyrightText: <holder>`, the `[legal] copyright_holder` of `brand/brand.toml`; the object's licence string is `Dual BSD/GPL`.
- Programs are written in Rust with aya-ebpf; a program aya cannot express is written in C in its own directory of this crate. Its toolchain, target and dependencies are #406's.
- CI builds the signed `.o` the back end loads (ARCH-011).

## Allowed dependencies
None: it has no dependencies and no crate depends on it (design/10 R2).

## How to test
- `cargo fmt --manifest-path bpf/grdr-sensor-linux-bpf/Cargo.toml -- --check`
- `cargo clippy --locked --manifest-path bpf/grdr-sensor-linux-bpf/Cargo.toml -- -D warnings`
- Oracle: the kernel verifier on the design/10 section 14 matrix, and the reference model of #107.
- Fuzz and differential targets: none yet: no code reads input (first content #26).

## Data classes
Reads: none yet. Writes: none yet (first content #26). Logs: LogSafe only.

## Limits
Bounds in limits.toml: none yet (limits.toml arrives with #279).

## Do not
- Enable kernel enforcement before S-12 and the D-62 review.
