# grdr-wasm

layer: 1   privilege: none   renders: none
surface: public   squad: core   trust core: yes
stability: unstable (contracts/surfaces.toml, contracts/architecture.toml)
design: docs/design/03-system-architecture-and-modularity.md section 2; docs/design/23-apis-webhooks-and-sdks.md

## Purpose
Zero-import `wasm32` C-ABI and pure-Rust policy/floor evaluator (`cdylib`, `rlib`). Does no I/O, clock, or randomness reads.

## Invariants
- Dependency edges: `grdr-fastpath`, `jiff`, `serde`, `serde_json` (`grdr-core` / `grdr-model` strictly in `[dev-dependencies]` for parity tests).
- No I/O, async runtime, clock or randomness (`getrandom` absent from non-dev `wasm32` graph).
- Builds as a zero-import `cdylib` for `wasm32-unknown-unknown` (`cargo build -p grdr-wasm --target wasm32-unknown-unknown --locked`).
- Checked or saturating arithmetic: `#![deny(clippy::arithmetic_side_effects)]` at the crate root (ADR-0022).
- No panic path in non-test code: `#![deny(clippy::unwrap_used, ...)]` plus `catch_unwind` at every C-ABI export.
- `unsafe_code = "deny"`: isolated strictly to C-ABI memory exports in `src/abi.rs`, documented with `// SAFETY:` and registered in `security/unsafe-register.toml`.
- Formats no text a person or an agent reads (`renders = "none"`).

## Allowed dependencies
Layer 0 plus Layer 1 same-layer edge `grdr-fastpath` (in `contracts/architecture.toml`).

## How to test
- `cargo test --locked -p grdr-wasm`
- `cargo build -p grdr-wasm --target wasm32-unknown-unknown --locked`

## Data classes
Evaluates caller-supplied attempts/packs in memory only; emits no logs or persisted state.

## Limits
- Input/allocation ceiling (`MAX_WASM_ABI_BYTES = 1 MiB`) and step budget (`DEFAULT_WASM_STEP_BUDGET`) enforced in `src/abi.rs` and `src/types.rs`.

## Do not
- Do not pull `grdr-core`, `grdr-model`, `getrandom`, clock, or filesystem/network imports into runtime dependencies.
