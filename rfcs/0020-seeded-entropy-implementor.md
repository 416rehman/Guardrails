RFC: 0020
Title: Shared 32-byte seeded Entropy implementor amending RFC 0008 and RFC 0009
Author: chief-architect
Harness: antigravity
Model: Gemini 4 Neon
State: Review
Design issue: #2083
Spine: [docs/design/00-decisions.md](../docs/design/00-decisions.md) at `a80859235e7a2a4444648d6fa8d389d78dde6be9` (`D-05`, `D-06`, `D-61`, `D-63`, `P5`, `P8`, `P9`, `P14`, `P17`)
Surfaces: `grdr_model::SeededChaCha20` (`grdr-model`, `experimental` per RFC 0009), `grdr_core::engine::boundary::step_bytes_seeded` (`grdr-core`, `experimental` in [`surfaces.toml`](../surfaces.toml)), `grdr_ports_testkit::SeededEntropy::from_seed_bytes` (`grdr-ports-testkit`, `experimental` in [`surfaces.toml`](../surfaces.toml)). As proposals for follow-up items: [`architecture.toml`](../architecture.toml) (`ARCH-003` implementor and caller entries), [`security/trust-core.paths`](../security/trust-core.paths), `crates/grdr-core/tests/vectors/engine/` (`#384`), `#281`, `#383`, `#388`, `#19`, `#1582`, `#1988` R5 / `#2084`, and [`spec/host-contract/c-abi.md`](../spec/host-contract/c-abi.md). No wire format, Cedar schema, same-layer dependency edge, third-party crate, `Cargo.lock` or [`surfaces.toml`](../surfaces.toml) stability class changes.
Decision record: none yet

## Summary

This RFC amends [RFC 0008](./0008-clock-entropy-and-the-retry-executor.md) and [RFC 0009](./0009-grdr-model-slice-0-surface.md) to supply the governed product `Entropy` implementor deferred by [RFC 0014](./0014-engine-boundary-c-abi.md) section 3.3 and [ADR-0041](../docs/decisions/ADR-0041-the-grdr-model-slice-0-surface-adopted-by-rfc-0009.md) constraint 2e (`#2083`):

1. **R1 (Algorithm, hosting crate, fallibility and seed equivalence).** Defines one pure checked-Rust **RFC 8439 ChaCha20** keystream generator (`grdr_model::SeededChaCha20`) shared by `grdr_core::engine::boundary`'s module-private `SeededBoundaryEntropy` (constructed strictly per call inside `step_bytes_seeded(..., entropy: [u8; 32])`) and `grdr_ports_testkit::SeededEntropy::from_seed_bytes(seed: [u8; 32])`. `grdr_ports_testkit::SeededEntropy::from_seed(u64)` stays on SplitMix64 (`#281` AC-3); `u64` and `[u8; 32]` seeds stay distinct and non-equivalent, while parity holds identically over `[u8; 32]` seeds.
2. **R2 (256-bit expansion strength, allowed `IdKind` surface and `ARCH-003` confinement).** Proves full 256-bit seed expansion without collapsing `[u8; 32]` to 64 bits and counter-wrap protection (`Err(EntropyError::Unavailable)` past `2^38` bytes), enumerates all 29 `IdKind` variants to constrain `step_bytes_seeded` strictly to non-secret execution trace identifiers (`StepId` `stp_` in slice 0; barred from cryptographic keys, secrets and all `Random128` tenancy/delegation/approval kinds), and updates `ARCH-003` in [`architecture.toml`](../architecture.toml) so `step_bytes_seeded` is callable outside tests only from `grdr-ffi` and `grdr-wasm` and no other product crate can implement `Entropy`, reach `SeededChaCha20` or touch `grdr-crypto`'s system generator.
3. **R3 (Caller seed-reuse policy, consumer guarantees, cross-target determinism and follow-ups).** Confirms no product consumer keys cross-call state on `StepId`, fixes seed uniqueness as a host duty with zero engine reuse detection (so replay stays exact), sets the exact exception text for [`docs/design/02-threat-model.md`](../docs/design/02-threat-model.md) (`#1988` R5) and [`docs/design/26-embedding-oem-and-white-label.md`](../docs/design/26-embedding-oem-and-white-label.md) section 3 (`#2084`), confirms bit-identical outputs across `x86_64`, `aarch64` and `wasm32`, and lists the follow-up items.

## Motivation

[RFC 0014](./0014-engine-boundary-c-abi.md) establishes the embedded engine ABI in `grdr_core::engine::boundary`, `grdr-ffi` (`#388`) and `grdr-wasm` (`#19`). Whereas the pure Rust `boundary::step_bytes` entrypoint takes `&mut dyn Entropy` (allowing `#384` to pass a deterministic test fixture without shipping a product `Entropy` implementor), the host-facing C ABI (`grdr_engine_step` taking `const uint8_t entropy[32]`) and Wasm export (`grdr_engine_step` taking `(ent_ptr, ent_len)` with `ent_len == 32`) cross a language boundary that cannot accept a Rust trait object (`&mut dyn Entropy`). Instead, the host passes 32 raw bytes per call to seed an ephemeral deterministic generator inside `grdr_core::engine::boundary::step_bytes_seeded`.

Two earlier decisions require an explicit amendment of both [RFC 0008](./0008-clock-entropy-and-the-retry-executor.md) and [RFC 0009](./0009-grdr-model-slice-0-surface.md) before `#388`, `#19` or `#1988` R5 can proceed:

- **[ADR-0040](../docs/decisions/ADR-0040-clock-entropy-and-the-retry-executor-adopted-by-rfc-0008.md) (RFC 0008):** Restricts non-test `Entropy` implementations in `ARCH-003` to `grdr-crypto`'s `random` module (`OsRandom`) and `grdr-ports-testkit`'s `SeededEntropy::from_seed(u64)` (SplitMix64 matching `splitmix64.c`), and bars `grdr-ports-testkit` from normal closures of `grdr-ffi`, `grdr-wasm` and Layer 4 programs.
- **[ADR-0041](../docs/decisions/ADR-0041-the-grdr-model-slice-0-surface-adopted-by-rfc-0009.md), constraint 2e and constraint 4:** States that any product `Entropy` implementation constructed inside `engine::boundary` from caller-supplied `[u8; 32]` bytes must land via an amending RFC naming RFC 0008 and RFC 0009 that fixes:
  1. which crate hosts the product `Entropy` implementor and when, if ever, its `fill` returns `Err`;
  2. the one deterministic seeded algorithm shared with `grdr-ports-testkit::SeededEntropy` in a crate both depend on, with a parity test and either proof of 256-bit expansion strength or a complete proof that no minted id kind is a secret;
  3. whether `SeededEntropy::from_seed(u64)` retains SplitMix64 (`#281` AC-3) and what equal seeds mean across `u64` and `[u8; 32]`;
  4. whether any consumer keys on minted ids across calls, whether reused `[u8; 32]` seeds are detected by the engine, and the resulting `docs/design/02` and `docs/design/26` text.

Using SplitMix64 directly for `[u8; 32]` would collapse 256 bits of caller seed down to 64 bits of state, making the generator trivially invertible from a single 10-byte `StepId` draw. Conversely, importing a third-party cryptography crate in Layer 1 (`grdr-model` or `grdr-core`) violates `ARCH-006` (`"Cryptography crates appear only under grdr-crypto"`), and placing shared PRNG logic in `grdr-core` would pull `cedar-policy` and `grdr-proto` into `grdr-ports-testkit`. This RFC resolves all three constraints cleanly inside existing Layer 1 dependency edges.

## Design

### R1. Shared algorithm, hosting crate, fallibility and seed equivalence

1. **Shared deterministic algorithm (RFC 8439 ChaCha20).** Both `grdr_core::engine::boundary` and `grdr-ports-testkit` use **RFC 8439 ChaCha20** (`20` rounds, `64`-byte little-endian keystream blocks) with:
   - 256-bit key: the caller's `seed: [u8; 32]` parsed into 8 words via `u32::from_le_bytes` (full 256-bit state input, zero truncation or XOR folding);
   - 96-bit nonce: fixed zero nonce `[0u32; 3]` (`[0u8; 12]`);
   - 32-bit block counter: `u32` starting at `0` for the first block and incrementing by `1` per subsequent `64`-byte block up to `u32::MAX` (`2^32` blocks = `2^38` bytes = `256 GiB` maximum stream length per seed);
   - RFC 8439 constants (`[0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]`), standard 10 double-round column/diagonal quarter-rounds (`wrapping_add`, bitwise `^`, `rotate_left`), word-wise `wrapping_add` feed-forward of the initial state, and `u32::to_le_bytes` output serialisation;
   - sequential byte consumption across `fill` calls via a `[u8; 64]` block buffer and byte offset (`0..=64`), so splitting draws across multiple calls produces the exact same bytes as one combined draw (`fill([u8; 10])` followed by `fill([u8; 16])` equals `fill([u8; 26])`).
   Implementation uses pure checked Rust only (`#![forbid(unsafe_code)]`, `#![deny(clippy::arithmetic_side_effects)]`, `#![deny(clippy::indexing_slicing)]`, zero allocations, zero floating-point operations, zero OS calls, zero third-party crates). Unit tests verify the internal block function against RFC 8439 section 2.3.2 (`key = 0x00..0x1f`, `counter = 1`, `nonce = 000000090000004a00000000` -> first 16 bytes `10f1e7e4d13b5915500fdd1fa32071c4`), RFC 8439 section 2.4.2, and the zero-seed block-0 prefix (`76b8e0ada0f13d90405d6ae55386bd28`).

2. **Crate hosting the shared primitive (`grdr-model`).** The shared stream primitive lives in `crates/grdr-model/src/seeded_entropy.rs` (private module under [RFC 0009](./0009-grdr-model-slice-0-surface.md) section 1's crate-root export rule, re-exported at root as `pub struct SeededChaCha20`), already in the Layer 1 dependency closure of both `grdr-core` (`#2080`) and `grdr-ports-testkit` (`#281`). This requires zero new workspace dependency edges, keeps `cedar-policy` out of `grdr-ports-testkit`, keeps `grdr-model` free of third-party crates and Cargo features (`RFC 0009` section 1), and compiles identically for native targets and `wasm32-unknown-unknown` (`#281` AC-6).
   - `grdr-model` exposes:
     - `pub const fn new(seed: [u8; 32]) -> Self`
     - `pub fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), EntropyError>`
   - **`grdr-model` still implements `Entropy` for no type (`RFC 0009` section 3 invariant preserved).** `SeededChaCha20` deliberately does not implement `grdr_model::Entropy`, does not implement `LogSafe`, derives `Clone` (required by `SeededEntropy`), omits `Copy`, `Default`, `Serialize` and `Deserialize`, and implements a redacted `fmt::Debug` (`SeededChaCha20 { .. }`) so seed words and buffered keystream bytes never appear in debug formatting (`P8`).

3. **Crate hosting the product `Entropy` implementor and `fill` fallibility (`grdr-core`).**
   - Inside `crates/grdr-core/src/engine/boundary.rs` (or a private submodule of `engine::boundary`), a module-private type `struct SeededBoundaryEntropy(grdr_model::SeededChaCha20);` implements `grdr_model::Entropy` by delegating `fill` to `self.0.fill_bytes(out)`. `SeededBoundaryEntropy` is private to `engine::boundary` and derives neither `Clone` nor `Copy`.
   - `grdr_core::engine::boundary` exposes one entrypoint per [RFC 0014](./0014-engine-boundary-c-abi.md) section 3.3:
     ```rust
     pub fn step_bytes_seeded(
         engine: &mut Engine,
         input: &[u8],
         now: Timestamp,
         entropy: [u8; 32],
     ) -> Result<Vec<u8>, BoundaryError>
     ```
     which constructs `SeededBoundaryEntropy(SeededChaCha20::new(entropy))` for that call alone, passes `&mut seeded` to `step_bytes`, and drops it before returning. Neither `grdr-ffi` nor `grdr-wasm` implements `Entropy`; both call `step_bytes_seeded` solely.
   - **When `fill` returns `Err`:** `SeededChaCha20::fill_bytes` checks the remaining stream capacity before writing to `out`. Calling with `out.is_empty()` returns `Ok(())` without advancing state. If `u64::try_from(out.len())` overflows or `out.len()` exceeds the remaining unread bytes through block `counter = u32::MAX` (`2^38` bytes total from counter `0`), `fill_bytes` returns `Err(EntropyError::Unavailable)` (`GRDR-MODEL-0003`) without mutating `out` or wrapping the 32-bit block counter back to `0`. Under every normal step call (slice 0 draws 10 bytes for one `StepId`; step work is bounded by the step budget), `fill` is total and returns `Ok(())`. If an unexpected future bug ever triggered `EntropyError::Unavailable`, `Engine::step` returns `Output::Failed` with `IdError::Entropy` (`GRDR-MODEL-0003`) leaving engine state and `step_seq` unchanged (`RFC 0014` sections 3.2, 3.3 and 9; `ADR-0041` constraint 1d), and `boundary::step_bytes_seeded` (delegating to `boundary::step_bytes`) encodes that `Output::Failed` into `Ok(Vec<u8>)` (`step_seq = 0`, `step_id = ""`, empty `events`/`effects`, and error `Diagnostic` carrying `GRDR-MODEL-0003`; C ABI / Wasm status `GRDR_OK`), returning `Err(BoundaryError::Encode)` (`GRDR-CORE-0009`) only if protobuf encoding itself fails.

4. **Testkit `SeededEntropy` and seed equivalence (`grdr-ports-testkit`).**
   - Amending [RFC 0008](./0008-clock-entropy-and-the-retry-executor.md) sections 3 and 5:
     - `SeededEntropy::from_seed(seed: u64) -> SeededEntropy` **stays on SplitMix64**, unchanged, so `#281` AC-3 (`seed = 0` yields `0xe220a8397b1dcdaf` first, matching `splitmix64.c`) and conformance runner reports (`Suite::run` seeded by `u64`) require zero rework.
     - `SeededEntropy::from_seed_bytes(seed: [u8; 32]) -> SeededEntropy` is added, wrapping `grdr_model::SeededChaCha20::new(seed)` inside `SeededEntropy`'s private state (`#[derive(Clone, Debug)]`).
   - **Rule on "equal seeds" across `u64` and `[u8; 32]`:** `u64` (`SplitMix64`) and `[u8; 32]` (`ChaCha20`) are disjoint seed domains with no automatic conversion. Collapsing `[u8; 32]` to `u64`, zero-padding `u64` to `[u8; 32]`, or treating `from_seed(s)` as equivalent to `step_bytes_seeded(..., expand(s))` is forbidden. Parity ("equal seeds give equal draws") is defined strictly over `seed: [u8; 32]`: `grdr_ports_testkit::SeededEntropy::from_seed_bytes(seed)` and `grdr_core::engine::boundary`'s `SeededBoundaryEntropy` call the same `grdr_model::SeededChaCha20::new(seed)` implementation and emit byte-identical draws across every call sequence, verified by a workspace test comparing `SeededEntropy::from_seed_bytes(seed)` draws (including `StepId::mint`) directly against `step_bytes_seeded(..., seed)` outputs.

### R2. 256-bit expansion strength, allowed id kinds and `ARCH-003` confinement

This RFC satisfies **both** requirements of [ADR-0041](../docs/decisions/ADR-0041-the-grdr-model-slice-0-surface-adopted-by-rfc-0009.md) constraint 2e (`Seat 5`) together: full 256-bit cryptographic seed expansion **and** explicit confinement to non-secret identifiers.

1. **256-bit expansion strength.** RFC 8439 ChaCha20 absorbs the full `[u8; 32]` seed as a 256-bit key (`8` distinct `u32` words) into a `512`-bit permutation state without folding or narrowing, prevents counter wraparound at `2^38` bytes (`Err(EntropyError::Unavailable)`), and preserves `256`-bit key-recovery and next-block unpredictability security against an observer who sees any bounded sequence of outputs from one fresh seed.
2. **Complete `IdKind` surface classification under `step_bytes_seeded`.** Every `IdKind` defined across [RFC 0009](./0009-grdr-model-slice-0-surface.md) section 4 (28 kinds) and [RFC 0014](./0014-engine-boundary-c-abi.md) section 3.1 (`Step`) sits in one of three buckets:

| Bucket | Mint route | Bytes drawn | Registered kinds | Permitted in `step_bytes_seeded`? | Reason |
|---|---|---|---|---|---|
| Deterministic hash-derived | `Derived128` | `0` | `Device` (`dev_`), `HumanPrincipal` (`prn_`), `ServicePrincipal` (`svc_`), `AgentIdentity` (`aid_`), `AgentInstance` (`agi_`), `McpServer` (`mcp_`), `McpTool` (`mct_`), `Skill` (`skl_`), `Plugin` (`plg_`), `ModelEndpoint` (`mdl_`), `CredentialRef` (`crd_`), `Process` (`prc_`), `Flow` (`flw_`), `Finding` (`fnd_`) | Calls no `Entropy` | Content/descriptor hash; does not read `entropy` |
| Allowed trace and evaluation ids | `Uuid7` | `10` per id | **Slice 0:** `Step` (`stp_`). **Future engine slices (if minted inside `Engine::step`):** `Event` (`evt_`), `Action` (`act_`), `Decision` (`dec_`), `Session` (`ses_`), `ToolCall` (`tc_`) | **Allowed** (`Step` alone in slice 0) | Non-secret timestamped (`48`-bit unix ms + `74`-bit disambiguation) audit/trace identifiers; never bearer credentials, capability tokens, tenancy roots or cryptographic keys |
| Barred control-plane, capability and random-128 ids | `Uuid7` / `Random128` | `10` / `16` | `Uuid7`: `OperatorAccount` (`opa_`), `Grant` (`grt_`), `DelegationSnapshot` (`dls_`), `Incident` (`inc_`). `Random128`: `Org` (`org_`), `RetryToken` (`rty_`), `Provider` (`prv_`), `Delegation` (`dlg_`), `Holder` (`hld_`) | **Forbidden** | Tenancy/delegation/grant/daemon-token identifiers (`docs/design/12` section 6 binds `rty_` to daemon pending-approval state) must never derive from caller-reusable boundary seeds without dedicated host/OS randomness (`OsRandom`) and a separate RFC |

   Cryptographic keys, HMAC pseudonym keys, cipher nonces, bearer secrets and raw non-`IdKind` secret material are likewise **forbidden** from drawing from `step_bytes_seeded` or `SeededChaCha20`.

3. **Non-caller guarantees and `ARCH-003` product allow-list.** Amending [RFC 0008](./0008-clock-entropy-and-the-retry-executor.md) section 8 and [RFC 0009](./0009-grdr-model-slice-0-surface.md) section 3:
   - [`architecture.toml`](../architecture.toml) `ARCH-003` admits strictly three `Entropy` implementor locations outside test code:
     1. `grdr-crypto::random` (`OsRandom`, system randomness source);
     2. `grdr_core::engine::boundary` (`SeededBoundaryEntropy`, module-private, reachable only via `step_bytes_seeded`);
     3. `grdr-ports-testkit::SeededEntropy` (development/conformance kit only, forbidden by `architecture.toml` per-target closure rules from every Layer 4 program, `grdr-ffi` and `grdr-wasm`).
   - [`architecture.toml`](../architecture.toml) `ARCH-003` adds two companion caller allow-lists outside test code:
     - `grdr_model::SeededChaCha20`: callable/constructible only from `grdr_core::engine::boundary` and `grdr-ports-testkit`;
     - `grdr_core::engine::boundary::step_bytes_seeded`: callable only from `grdr-ffi` and `grdr-wasm`.
   - `grdr-ffi` and `grdr-wasm` are the sole non-test workspace callers of `grdr_core::engine::boundary::step_bytes_seeded`; neither implements `Entropy`, constructs `SeededChaCha20`, depends on `grdr-ports-testkit`, or reaches `grdr-crypto::random` (`#1582` `grdr-archlint` fixtures verify each restriction, including through `use` aliases and re-exports).
   - All Layer 4 programs, adapters, `grdr-core` modules outside `engine::boundary`, and all other non-test crates remain strictly barred from implementing `Entropy`, invoking `SeededChaCha20`, or calling `step_bytes_seeded` (including via aliases or re-exports).
   - Both file and subtree globs (`crates/grdr-core/src/engine/boundary.rs`, `crates/grdr-core/src/engine/boundary/**`, `crates/grdr-model/src/seeded_entropy.rs` and `crates/grdr-model/src/seeded_entropy/**`) are added to [`security/trust-core.paths`](../security/trust-core.paths) (where `*` does not match `/`) so any change to either module or its submodules triggers high-tier two-model `eval-review` + `eval-security`.

### R3. Seed-reuse policy, consumer guarantees, cross-target determinism and follow-ups

1. **Consumer keying guarantee.** No consumer inside `Engine`, `grdr-core`, `grdr-ffi`, `grdr-wasm` or the daemon keys persistent state, verdict caches, quotas, grants, idempotency tables or deduplication stores across calls on `StepId` (`stp_`, `loggable = false`) or any `Uuid7` trace identifier minted inside `step_bytes_seeded`. Envelope ordering and deduplication key on `(device_id, epoch, lane, seq)` ([`docs/design/04-event-model-and-schemas.md`](../docs/design/04-event-model-and-schemas.md) section 2), findings key on deterministic derived hashes (`FindingId`), and policy caches key on bundle digest and rule inputs ([`spec/host-contract/c-abi.md`](../spec/host-contract/c-abi.md)). Because `Random128` identifiers (`org_`, `prv_`, `dlg_`, `hld_`, `rty_`) are barred from `step_bytes_seeded`, host seed reuse cannot create duplicate `Random128` control-plane keys inside the engine. External log/telemetry sinks correlating `Output.step_id` still expect distinct steps in live operation to receive distinct `step_id` values, which rests on the host supplying unique fresh `[u8; 32]` bytes per live step call.

2. **Seed-reuse non-detection and exact replay.** `Engine`, `grdr_core::engine::boundary`, `grdr-ffi` and `grdr-wasm` retain zero prior `[u8; 32]` seeds and perform zero reuse detection. Detecting reuse across calls would require unbounded cross-call seed storage (violating `Engine`'s bounded memory and sans-IO snapshot isolation), would retain sensitive host CSPRNG outputs in engine heap, and would break deterministic replay (`restore` plus a recorded `(input, now_unix_ns, entropy[32])` tuple must repeat bit-identical `Output` including `step_id` per [`docs/design/26-embedding-oem-and-white-label.md`](../docs/design/26-embedding-oem-and-white-label.md) section 3 and [`spec/host-contract/c-abi.md`](../spec/host-contract/c-abi.md) section 7). Uniqueness of `[u8; 32]` in production calls is therefore strictly the host caller's duty; repeated seeds repeat deterministic draws identically.

3. **Authoritative text for `docs/design/02` (`#1988` R5) and `docs/design/26` section 3 (`#1988`, `#2084`).**
   - For [`docs/design/02-threat-model.md`](../docs/design/02-threat-model.md) (extending RFC 0008's randomness rule in `#1988` R5):
     > Product code draws randomness only from the system generator (`ARCH-003`). The single governed exception is `grdr_core::engine::boundary::step_bytes_seeded` (serving `grdr-ffi`'s `grdr_engine_step` and `grdr-wasm`'s `grdr_engine_step`), which expands caller-supplied `[u8; 32]` bytes per call through `grdr_model::SeededChaCha20` (RFC 8439 ChaCha20) strictly for non-secret execution identifiers (`StepId` `stp_` in slice 0; `Random128` kinds and keys barred); seed reuse is not detected by the library, so production hosts supply fresh system CSPRNG bytes per call and record seeds only for replay.
   - For [`docs/design/26-embedding-oem-and-white-label.md`](../docs/design/26-embedding-oem-and-white-label.md) section 3 (coordinating `#1988` R5 and `#2084`): name `grdr_model::SeededChaCha20` as the shared RFC 8439 ChaCha20 algorithm and `grdr_core::engine::boundary::step_bytes_seeded` as the sole product `Entropy` implementor behind `grdr_engine_step`'s `entropy[32]` (`grdr-ffi`) and `(ent_ptr, ent_len)` (`grdr-wasm`), state non-secret `StepId`/trace id restriction (with `Random128` kinds barred), state non-detection of seed reuse and host uniqueness responsibility, confirm exact replay for recorded seeds, and point embedders to [ADR-0041](../docs/decisions/ADR-0041-the-grdr-model-slice-0-surface-adopted-by-rfc-0009.md) for API stability rules and `Native_*` fields for partner extensions (`docs/design/26` section 9).

4. **Cross-target byte determinism (`x86_64`, `aarch64`, `wasm32`).** Because `SeededChaCha20` explicitly converts `[u8; 32]` using `u32::from_le_bytes`, runs fixed 20-round `u32` integer/rotation operations, uses fixed `u32` block indexing (never `usize`-width-dependent counters or pointer-size branches), serialises blocks with `u32::to_le_bytes`, and maps bytes into `StepId` via RFC 9562 big-endian timestamp + byte masking (`RFC 0009` section 4), `grdr_core::engine::boundary::step_bytes_seeded` emits bit-identical `Output` protobuf payloads and `step_id` strings across `x86_64`, `aarch64` and `wasm32-unknown-unknown` for `#384`'s committed `crates/grdr-core/tests/vectors/engine/` golden corpus, `#388`'s `ffi_vectors` / `c_harness.c`, and `#19`'s `wasm_vectors`.

5. **Follow-up items and updates on acceptance.**
   - **New protected gate/trust-core item (to be filed on acceptance, `squad:core`, `lead-agent-kit` / `chief-architect`, blocking `#384` vector finalisation, `#388`, `#19`, `#1582`):** update `ARCH-003` in [`architecture.toml`](../architecture.toml) (`grdr_core::engine::boundary` `Entropy` implementor, `grdr_model::SeededChaCha20` caller allow-list `{grdr_core::engine::boundary, grdr-ports-testkit}`, and `grdr_core::engine::boundary::step_bytes_seeded` caller allow-list `{grdr-ffi, grdr-wasm}`) and add `crates/grdr-core/src/engine/boundary.rs`, `crates/grdr-core/src/engine/boundary/**`, `crates/grdr-model/src/seeded_entropy.rs` and `crates/grdr-model/src/seeded_entropy/**` to [`security/trust-core.paths`](../security/trust-core.paths).
   - **`#383` (or `#384` if coordinated):** add `SeededChaCha20` in `crates/grdr-model/src/seeded_entropy.rs` (re-exported at `grdr_model` root) with RFC 8439 sections 2.3.2 and 2.4.2 vectors and `2^38`-byte counter-exhaustion test (`EntropyError::Unavailable` without wrap).
   - **`#281` (`grdr-ports-testkit`):** keep `SeededEntropy::from_seed(u64)` on SplitMix64 (`AC-3`), add `SeededEntropy::from_seed_bytes([u8; 32])` wrapping `grdr_model::SeededChaCha20`, and document the non-equivalence with `u64`.
   - **`#384` (`Engine` and `boundary`):** implement `step_bytes_seeded(..., entropy: [u8; 32])` in `crates/grdr-core/src/engine/boundary.rs` using module-private `SeededBoundaryEntropy`, verify parity with `grdr_ports_testkit::SeededEntropy::from_seed_bytes`, and freeze `crates/grdr-core/tests/vectors/engine/` expected `step_id` bytes using `SeededChaCha20`.
   - **`#388` (`grdr-ffi`) and `#19` (`grdr-wasm`):** unblock both once RFC 0020 and the `ARCH-003` protected change land; delegate step calls strictly to `step_bytes_seeded`.
   - **`#1988` R5 and `#2084`:** apply the exact `docs/design/02` exception and `docs/design/26` section 3 / `docs/design/03` section 10 updates; also file/fold a small `spec/host-contract/c-abi.md` doc clarification (updating `#246`'s legacy `"yields repeated Random128 identifiers"` lines in sections 3 and 7 to `"yields repeated step identifiers (`StepId` `stp_`) while `Random128` kinds remain barred from `step_bytes_seeded`"`).
   - **`#1582` (`grdr-archlint` Part b):** add `ARCH-003` negative test fixtures (including resolved `use` aliases and re-exports) ensuring `Entropy` implementors outside `{grdr-crypto::random, grdr_core::engine::boundary, grdr-ports-testkit}`, non-test `SeededChaCha20` callers outside `{grdr_core::engine::boundary, grdr-ports-testkit}`, and non-test `step_bytes_seeded` callers outside `{grdr-ffi, grdr-wasm}` fail `grdr-archlint`.

## Surfaces changed
- `grdr-model` (`experimental` per [RFC 0009](./0009-grdr-model-slice-0-surface.md) section 12): adds `pub struct SeededChaCha20` at crate root (`new([u8; 32])`, `fill_bytes(&mut [u8]) -> Result<(), EntropyError>`, `Clone`, redacted `Debug`, no `impl Entropy`).
- `grdr-core` (`experimental` in [`surfaces.toml`](../surfaces.toml)): exports `pub fn step_bytes_seeded(engine: &mut Engine, input: &[u8], now: Timestamp, entropy: [u8; 32]) -> Result<Vec<u8>, BoundaryError>` in `grdr_core::engine::boundary` with module-private `SeededBoundaryEntropy`.
- `grdr-ports-testkit` (`experimental` in [`surfaces.toml`](../surfaces.toml)): adds `pub fn SeededEntropy::from_seed_bytes(seed: [u8; 32]) -> SeededEntropy` while retaining `SeededEntropy::from_seed(u64)` on SplitMix64.
- Follow-up protected/design paths (not modified in this RFC commit): [`architecture.toml`](../architecture.toml) (`ARCH-003`), [`security/trust-core.paths`](../security/trust-core.paths), [`docs/design/02-threat-model.md`](../docs/design/02-threat-model.md), [`docs/design/03-system-architecture-and-modularity.md`](../docs/design/03-system-architecture-and-modularity.md), [`docs/design/26-embedding-oem-and-white-label.md`](../docs/design/26-embedding-oem-and-white-label.md) and [`spec/host-contract/c-abi.md`](../spec/host-contract/c-abi.md).

## Alternatives

- **Use SplitMix64 directly by folding `[u8; 32]` into one `u64` seed (rejected).** Folding 256 bits into 64 bits destroys 192 bits of caller seed entropy, makes collisions feasible at `2^32` seeds and allows state recovery from a single 10-byte `StepId` output. Splitting `SeededEntropy::from_seed(u64)` (SplitMix64, `#281` AC-3) from `from_seed_bytes([u8; 32])` (ChaCha20) keeps `#281` stable while eliminating entropy collapse.
- **Use SipHash-2-4 over `[u8; 32]` (rejected).** SipHash-2-4 takes a 128-bit key (`[u8; 16]`), still truncating or folding half of the `[u8; 32]` caller seed and producing 64-bit tags rather than a standard continuous byte stream with published stream-cipher test vectors.
- **Add a third-party CSPRNG crate such as `rand_chacha` or `chacha20` in `grdr-model` or `grdr-core` (rejected).** Violates `ARCH-006` (`"Cryptography crates appear only under grdr-crypto"`), violates [RFC 0009](./0009-grdr-model-slice-0-surface.md) section 1 (`grdr-model` has no third-party dependencies), and introduces supply-chain/admission churn in `Cargo.lock` for ~60 lines of standard checked Rust.
- **Host the shared ChaCha20 generator in `grdr-core` or `grdr-schema` (rejected).** Hosting in `grdr-core` forces `grdr-ports-testkit` to depend on `grdr-core` (pulling `cedar-policy` and `grdr-proto` into every adapter test harness and requiring a new edge in `Cargo.lock` and [`architecture.toml`](../architecture.toml)). Hosting in `grdr-schema` violates RFC 0007's strict `{lib, cedar, codes*, limits*, health*}` source layout check. `grdr-model` is already a dependency of both `grdr-core` and `grdr-ports-testkit`.
- **Make `SeededBoundaryEntropy` `pub` or implement `Entropy` directly on `grdr_model::SeededChaCha20` (rejected).** Exposing an `Entropy` implementation publicly in Layer 1 invites arbitrary adapters or engine modules to replace `OsRandom` with hardcoded seeds. Keeping `impl Entropy` private to `grdr_core::engine::boundary` and dev-only in `grdr-ports-testkit`, paired with `ARCH-003` caller allow-lists on both `SeededChaCha20` (`engine::boundary`, `grdr-ports-testkit`) and `step_bytes_seeded` (`grdr-ffi`, `grdr-wasm`), closes that bypass at both Rust visibility and archlint levels.
- **Wrap the `u32` block counter silently after `2^38` bytes or detect seed reuse across `Engine::step` calls (rejected).** Silent counter wraparound repeats keystream blocks under one seed (`EntropyError::Unavailable` cleanly prevents wraparound without changing runtime behaviour on bounded steps); detecting seed reuse across calls breaks exact snapshot+seed replay and forces unbounded heap state onto `Engine`.

## Drawbacks

- Pure checked-Rust ChaCha20 adds roughly 70 lines of trust-core integer permutation code in `crates/grdr-model/src/seeded_entropy.rs` that must be reviewed under `security/trust-core.paths` and tested against RFC 8439 vectors.
- `SeededEntropy` in `grdr-ports-testkit` supports two distinct algorithms (`from_seed(u64)` SplitMix64 vs `from_seed_bytes([u8; 32])` ChaCha20) so `#281` AC-3 stays intact; clear naming and tests prevent mixing the two seed domains.
- Permitting `Random128` or key generation under `step_bytes_seeded` in a future slice cannot reuse this exemption automatically; it must return via an RFC proving fresh-seed enforcement or host-layer `OsRandom` minting.

## Unresolved questions

None for this RFC's decision. Coordinated downstream work (`#281`, `#383`, `#384`, `#388`, `#19`, `#1582`, `#1988` R5, `#2084`, and the protected `architecture.toml` / `security/trust-core.paths` follow-up) executes the decisions recorded above once accepted.

## Review

How review binds the decision ([RFC 0001](./0001-adopt-the-spine.md), "Review binds the decision"; [ADR-0036](../docs/decisions/ADR-0036-the-amended-spine-is-the-baseline-adopted-by-rfc-0001.md); [ADR-0043](../docs/decisions/ADR-0043-lean-token-optimised-agent-team.md)):
- RFC 0020 decides no pinned path of [`rfcs/pins.toml`](./pins.toml), so its decision adds no decision line and no file under `rfcs/evidence/`, and `rfcs/pins.toml` stays unchanged.
- Design issue: `#2083` (`tier:high`, `kind:rfc`, amending RFC 0008 and RFC 0009 under ADR-0041 constraint 2e). Under [ADR-0043](../docs/decisions/ADR-0043-lean-token-optimised-agent-team.md) and [`.claude/risk-tiers.toml`](../.claude/risk-tiers.toml) (`[high]` and `[checklist_addons].rfc`), which supersede pre-ADR-0043 persona-council fan-out wording in ADR-0040 and ADR-0041, the review set is `eval-review` and `eval-security` on two distinct models/providers (`distinct_models = 2`, at least one distinct from `antigravity` / `Gemini 4 Neon` per [`.agents/models.toml`](../.agents/models.toml), explicitly verifying ADR-0041 constraint 2e Seat 5 criteria), capped at two rounds.
- Consulted baseline blobs at `origin/main` (`a83e9ea`):
  - [`docs/design/00-decisions.md`](../docs/design/00-decisions.md): `a80859235e7a2a4444648d6fa8d389d78dde6be9` (base pin in [`rfcs/pins.toml`](./pins.toml), SHA-256 `8f6ea876777c0121ecec068c0bc4cef45932be45c1c2aff4140712db1e06628d`)
  - [`rfcs/0008-clock-entropy-and-the-retry-executor.md`](./0008-clock-entropy-and-the-retry-executor.md): `b4af2b007041e3abdf6f7439824662ea6f08c52d`
  - [`rfcs/0009-grdr-model-slice-0-surface.md`](./0009-grdr-model-slice-0-surface.md): `4f36df6f0b2ce122d3b09d8109e83fb4720b1c68`
  - [`rfcs/0014-engine-boundary-c-abi.md`](./0014-engine-boundary-c-abi.md): `2519dae95887355b050965098d9c7c5fcac84ab1`
  - [`docs/decisions/ADR-0040-clock-entropy-and-the-retry-executor-adopted-by-rfc-0008.md`](../docs/decisions/ADR-0040-clock-entropy-and-the-retry-executor-adopted-by-rfc-0008.md): `41d28625f46393d48ef28ac1b5c3c2aa4a31f7af`
  - [`docs/decisions/ADR-0041-the-grdr-model-slice-0-surface-adopted-by-rfc-0009.md`](../docs/decisions/ADR-0041-the-grdr-model-slice-0-surface-adopted-by-rfc-0009.md): `9d2e12ae11c6986d3513418f941df8a0484846de`
  - [`docs/decisions/ADR-0054-engine-boundary-c-abi-adopted-by-rfc-0014.md`](../docs/decisions/ADR-0054-engine-boundary-c-abi-adopted-by-rfc-0014.md): `7af3cc9059295acb5d01cfedb60a3583a09fb1f7`
  - [`docs/design/02-threat-model.md`](../docs/design/02-threat-model.md): `bc869f61d9f0eaf431f0129aecdd50a620fb8d80`
  - [`docs/design/26-embedding-oem-and-white-label.md`](../docs/design/26-embedding-oem-and-white-label.md): `8d9327dce0ca530e065f06a8ed287dec664e1f5b`
  - [`spec/host-contract/c-abi.md`](../spec/host-contract/c-abi.md): `331f923dbcc8878148598c0450c14598131c9cdc`
  - [`architecture.toml`](../architecture.toml): `60743ee6b3f532190237a499b236784bf3587e04`
  - [`surfaces.toml`](../surfaces.toml): `2c000f6b76e08117a3551251c28f3081f8991b1e`
  - [`rfcs/pins.toml`](./pins.toml): `993f808476d52888e4a3673da9ad685e1ce55989`
- Each verdict on `#2083` names:
  - `Provider:` and `Model:`;
  - `RFC file:` exact 40-character blob id of `rfcs/0020-seeded-entropy-implementor.md` and commit;
  - `Proposed text: none`;
  - `Base:` `a80859235e7a2a4444648d6fa8d389d78dde6be9` (SHA-256 `8f6ea876777c0121ecec068c0bc4cef45932be45c1c2aff4140712db1e06628d`).

Verdicts on `#2083` will be linked below once review finishes, one per line.
(Pending evaluation.)

## Decision

Pending acceptance. Once the required verdicts pass on `#2083`, the acceptance commit updates `State:`, `Decision record:`, the verdict link lines above and this `Decision` section, keeping all reviewed body sections byte-identical, and records the decision in `docs/decisions/ADR-NNNN-*.md`.
