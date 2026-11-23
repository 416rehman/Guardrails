RFC: 0014
Title: Engine boundary: `grdr.embed.v1alpha1` skeleton, `grdr_core::engine`, C ABI 0.1 and `wasm32` exports
Author: chief-architect
Harness: antigravity
Model: Gemini 4 Neon
State: Accepted
Design issue: #378
Spine: D-05, D-06, D-09, D-15, D-41, D-60, D-61, D-63, P5, P8, P9, P14, P17 (no spine text changes)
Surfaces: the new protobuf package `grdr.embed.v1alpha1` (`proto/grdr/embed/v1alpha1/engine.proto`); public layer 1 module `grdr_core::engine` (including `grdr_core::engine::boundary` and `bundle_sha256`) and `grdr_model::VerifiedBundle` (plus `StepId` as content under RFC 0009); C ABI 0.1 (`grdr.h` in `grdr-ffi`, including the shared 12-value `grdr_status` block); `wasm32` exports (`grdr-wasm`); and the conformance vector layout (`crates/grdr-core/tests/vectors/engine/`). As proposals to land through their own follow-up or existing items: `surfaces.toml` entries (`[[proto_package]]` for `embed.v1alpha1` and `[[crate]]` rows for `grdr-ffi` and `grdr-wasm`); `security/trust-core.paths` entries (`crates/grdr-wasm/**`, `crates/grdr-core/src/engine/bundle_sha256.rs`, `crates/grdr-core/src/engine/bundle_sha256/**`); `limits.toml` ceiling row for `grdr-wasm` maximum linear memory; `wasmi` `2.0.2` dev-dependency admission in `supply-chain/admissions.toml`; workspace edges in `Cargo.toml` / `Cargo.lock` (including `grdr-ffi` and `grdr-wasm` -> `grdr-model`) and `ARCH-012` (`#1582`) / `ARCH-013` / `ARCH-027` (`#1751`) metadata and AST checks in `architecture.toml` / `grdr-archlint`; C harness step in `.github/workflows/verify.yml` inside `c-headers`; `CORE` area error codes in `schema/codes/`; coordination with `spec/host-contract/c-abi.md` and `status-codes.toml` (#246); write-backs on `#381`, `#384`, `#388`, `#19`, `#246`, `#1751` and `#1779`; and the separate ADR-0041 constraint 2e amendment of RFC 0008 and RFC 0009 before `#388` is readied.
Decision record: docs/decisions/ADR-0054-engine-boundary-c-abi-adopted-by-rfc-0014.md

To comment, write on issue #378 of this repository; you need no account on any service other than the code host. A security fix under embargo (D-62) may change a public surface without an RFC; open a retroactive RFC when the fix is disclosed.

## Summary
This RFC defines the slice-0 engine boundary across four artefacts so `#381`, `#384`, `#388` and `#19` (WI-0016) can be readied and built against one shared contract:

1. **`grdr.embed.v1alpha1` (`proto/grdr/embed/v1alpha1/engine.proto`, R1).** Declares the skeleton messages `Input`, `Tick`, `Output`, `Effect`, `Diagnostic` (with nested `Severity`), `LoadReport` (with nested `NotEvaluable`), `EngineState` and minimal `HostProfile`. `Input.event` and `Output.events` use `grdr.event.v1alpha1.Event` rather than bare `Envelope` so future payload variants arrive additively without a breaking wire retype. Every field carries an RFC 0006 `DataClass` option and every non-zero enum value carries a `wire_name`. `Output.step_id` uses a new typed WI-0015 identifier `StepId` (`stp_`, UUIDv7).
2. **`grdr_core::engine` (`crates/grdr-core/src/engine.rs` and `engine/boundary.rs`, R2).** Exposes the five core operations of `docs/design/03` section 3 (`load`, `step`, `interest`, `snapshot`, `restore`) over `grdr_model::VerifiedBundle` and typed engine structs. `Engine::step` returns an explicit typed enum `Output` (`Completed` or `Failed`) so a failed identifier draw (`GRDR-MODEL-0003`, `GRDR-MODEL-0005`) or `step_seq` overflow (`GRDR-CORE-0001`) can never be misread as an allowed or no-op step (ADR-0041 constraint 1d). `engine::boundary` provides the single decode, step, unkeyed `bundle_sha256` digest (`crates/grdr-core/src/engine/bundle_sha256.rs`, proposed as trust core) and encode path over `&VerifiedBundle`, while `VerifiedBundle::assume_verified` sits outside `grdr-core` solely at the `grdr-ffi` and `grdr-wasm` ingress (`ARCH-006`, `ARCH-012`). `Engine::interest` serialises the four fixed-format tables (`tables.md` section 3.5) in a fixed `GRDI` v1 binary frame.
3. **C ABI 0.1 (`grdr.h` in `grdr-ffi`, R3).** Exports 13 functions (`docs/design/26` section 3 minus `grdr_engine_compile_fastpath`, which moves to a later minor under `#1918`). `grdr_engine_config` carries `uint32_t struct_size` only (base size 4), accepting the departure from `docs/design/26` section 3 and aligning with `c-abi.md` (`#246`); allocator callbacks, `memory_cap` and `step_budget` arrive behind `struct_size` with EM-6. The shared `grdr_status` block behind `GRDR_STATUS_DEFINED` includes `GRDR_OK` (`0`) through `GRDR_E_INTERNAL` (`10`) plus RFC 0005's `GRDR_E_CHANGED` (`11`), though no engine function returns `11` in 0.1. Handle states follow the explicit `Created`, `Loaded`, `Poisoned` machine; `catch_unwind` maps any unwind to `GRDR_E_INTERNAL` and poisons the handle.
4. **`wasm32` exports (`grdr-wasm`, R4).** Compiles one `wasm32-unknown-unknown` core module with an empty import section, declaring a maximum memory read from `limits.toml` (`64 MiB`, `1,024` 64 KiB pages) and exposing the 13 engine entry points over linear-memory buffers alongside `grdr_alloc`, `grdr_free`, `grdr_result_ptr` and `grdr_result_len`. Implementation lives inside a `#![forbid(unsafe_code)]` inner module under one-call `#[unsafe(no_mangle)]` wrappers verified by `#1751`'s `ARCH-027` AST check; stateful exports pre-poison `InstanceSlot` to `TrapPoisoned` on entry across `panic = "abort"` traps and enforce bounded `try_reserve_exact` allocations (`GRDR_E_RESOURCE` preserving `last-known-good`).
5. **Dependencies and gates (R5, R6).** Admits `wasmi = "=2.0.2"` (`MIT OR Apache-2.0`) strictly as a `dev-dependency` of `grdr-wasm` after its protected admission record lands; cites accepted RFC 0004 (`ADR-0034`) for `grdr.h` generation and drift checks with zero new dependencies; runs EM-4's C harness as a plain command step inside `.github/workflows/verify.yml`'s `c-headers` job (`#1779`) rather than adding the `cc` crate; and registers every new public surface as `experimental` in `surfaces.toml` plus `grdr-wasm` and `bundle_sha256` in `security/trust-core.paths` through protected trust-core follow-up issues after acceptance (`D-60`, `D-63`, `ADR-0020`).

## Motivation
WI-0016 (`#19`) splits into four linked work items: `#381` (`grdr.embed.v1alpha1`), `#384` (`grdr_core::engine` and vectors), `#388` (`grdr-ffi` C ABI 0.1) and `#19` (`grdr-wasm` `wasm32` binding). Under D-61, every public crate (`grdr-core`, `grdr-ffi`, `grdr-wasm`, `grdr-proto`, `grdr-model`) and wire package (`grdr.embed.v1alpha1`) changes only by RFC.

Inspecting those four issues alongside recently decided RFCs and open contracts revealed seven mismatches that must be resolved before `#381`, `#384`, `#388` or `#19` can be readied:
1. **Protobuf envelope wrapper vs bare envelope.** `#381` R2 writes `<WI-0015 envelope message> event = 1` and R4 writes `repeated envelope events = 3`, while `#394` separates `Envelope` (`envelope.proto`) from `Event { Envelope envelope = 1; }` (`event.proto`) and reserves payload tags `2..15` on `Event`. Picking `Envelope` now would force a breaking message-field retype once payloads arrive.
2. **Missing `DataClass` precision and `step_id` type.** `#381` R10 writes "are metadata" for several fields, whereas accepted SP-1 / RFC 0006 (`proto/grdr/common/v1alpha1/options.proto`) defines `DATA_CLASS_IDENTIFIER`, `DATA_CLASS_STRUCTURAL`, `DATA_CLASS_DERIVED` and `DATA_CLASS_CONTENT` (`metadata` is a capture level, not a `DataClass` enum variant). Meanwhile `#381` R4 asks for a WI-0015 `step_id` while `#383` R5 (`ADR-0041` constraint 3a) lists no `Step` id kind yet.
3. **`Output` safety after a failed entropy draw.** `ADR-0041` constraint 1d requires that a failed `Entropy::fill` draw in `Engine::step` returns a typed failure on every input and never leaves an undrawn id or empty decision that could be read as "no decision needed". `docs/design/03` section 3 keeps signature `-> Output`.
4. **`VerifiedBundle` digest on the FFI and Wasm boundaries.** `#384` R1 requires `VerifiedBundle::assume_verified(bytes, digest)`, `#384` AC-1 / `#388` AC-2 / `#19` AC-3 require identical `LoadReport.bundle_digest` and `EngineState.bundle_digest` bytes across all three targets, yet `grdr_engine_load` and `grdr_engine_restore` take `(bundle, bundle_len)` with no `digest` argument and Layer 1 cannot depend on Layer 2 `grdr-crypto` (nor may `grdr-core` expose a bypass calling `assume_verified` for arbitrary Rust callers under `ARCH-012`).
5. **`InterestSet` wire format.** `grdr_engine_interest` writes `grdr_buf *out`, `#381` defines no `InterestSet` protobuf message, and `spec/host-contract/tables.md` section 3.5 defines the four record layouts without a standalone container header.
6. **C ABI alignment across RFC 0004, RFC 0005, `#246` and `#388`.** `#388` R3 specifies `{ size_t struct_size; }` and `R2` lists 11 status codes (`0..10`), whereas `#246` (`spec/host-contract/c-abi.md`) requires `uint32_t struct_size` (base size `4`) and RFC 0005 (`ADR-0037`) section 13 already adds `GRDR_E_CHANGED = 11` to the shared status block `grdr.h` renders.
7. **Edition 2024 lint conflict on `grdr-wasm` and `grdr_alloc` error reporting.** `crates/grdr-wasm/Cargo.toml` inherits `unsafe_code = "forbid"`, which in Rust Edition 2024 rejects `#[unsafe(no_mangle)]` (`exit 101`), requiring a crate-level `unsafe_code = "deny"` exception around one-line stubs over a `#![forbid(unsafe_code)]` inner module enforced by `#1751` (`ARCH-027`), while `#19` Failure modes specifies `grdr_alloc` returning status `GRDR_E_RESOURCE`.

## Design

### 1. Scope and non-goals
This RFC covers slice 0 of the engine boundary (`#378` R1 to R6):
- **In scope:** the slice-0 `grdr.embed.v1alpha1` skeleton in `proto/grdr/embed/v1alpha1/engine.proto`; the `grdr_model::VerifiedBundle` handle and `StepId` addition; the five `grdr_core::engine::Engine` methods and `engine::boundary` codec in `grdr-core`; C ABI 0.1 (13 functions, `grdr.h`) in `grdr-ffi`; `wasm32` core exports in `grdr-wasm`; test dependencies and CI harness routing; the shared conformance vector schema; and `experimental` stability classes.
- **Explicit non-goals (preserved from `#378`, `#381`, `#384`, `#388`, `#19`):**
  - `Input::ActionRequest`, `Grant`, `ResponseCommand`, `Output.decision` and the policy evaluation pipeline (`#1861`, `#1600`, `#1900`).
  - `compile_fastpath` and `grdr_engine_compile_fastpath` (RFC 0005; `#1918` in a later C ABI minor).
  - Per-handle allocator callbacks (`alloc`, `realloc`, `free`, `alloc_ctx`), `memory_cap` and `step_budget` on `grdr_engine_config` (EM-6).
  - Sidecar transport and `EngineService` (`EM-7`), full `HostProfile` fields (`EM-8`) and the TypeScript loader (`EM-5` second half).
  - The form of `grdr.h`, `grdr_cabi_testkit` macros and `HDR-1`..`HDR-5` drift checks, already decided by [RFC 0004](0004-c-header-generation-and-drift-check.md) (`ADR-0034`).
  - The 32-byte seeded product `Entropy` implementor and its `ARCH-003` entry, which require a dedicated amendment naming RFC 0008 and RFC 0009 before `#388` is readied (ADR-0041 constraint 2e; section 3 below).

### 2. Wire skeleton: `grdr.embed.v1alpha1` (R1)
`proto/grdr/embed/v1alpha1/engine.proto` declares `syntax = "proto3";` and `package grdr.embed.v1alpha1;`. Its namespace prefix `grdr` follows `brand/brand.toml` (`D-66`) and RFC 0006 R1-R3.

It imports only `"grdr/common/v1alpha1/options.proto"` (for `(grdr.common.v1alpha1.data_class)` and `(grdr.common.v1alpha1.wire_name)`) and `"grdr/event/v1alpha1/event.proto"` (for `grdr.event.v1alpha1.Event`, `#394`), with no foreign imports beyond RFC 0006 R14a.

```proto
syntax = "proto3";

package grdr.embed.v1alpha1;

import "grdr/common/v1alpha1/options.proto";
import "grdr/event/v1alpha1/event.proto";

message Input {
  oneof kind {
    grdr.event.v1alpha1.Event event = 1
        [(grdr.common.v1alpha1.data_class) = DATA_CLASS_STRUCTURAL];
    Tick tick = 2
        [(grdr.common.v1alpha1.data_class) = DATA_CLASS_STRUCTURAL];
  }
  reserved 3, 4, 5;
  reserved "action_request", "grant", "response_command";
}

message Tick {}

message Output {
  uint64 step_seq = 1
      [(grdr.common.v1alpha1.data_class) = DATA_CLASS_STRUCTURAL];
  string step_id = 2
      [(grdr.common.v1alpha1.data_class) = DATA_CLASS_IDENTIFIER];
  repeated grdr.event.v1alpha1.Event events = 3
      [(grdr.common.v1alpha1.data_class) = DATA_CLASS_STRUCTURAL];
  repeated Effect effects = 4
      [(grdr.common.v1alpha1.data_class) = DATA_CLASS_STRUCTURAL];
  repeated Diagnostic diagnostics = 5
      [(grdr.common.v1alpha1.data_class) = DATA_CLASS_STRUCTURAL];
  reserved 6;
  reserved "decision";
}

message Effect {
  oneof kind {
    // Reserved for expectation, actuator_request, label_projection, interest_change.
  }
  reserved 1, 2, 3, 4;
  reserved "expectation", "actuator_request", "label_projection", "interest_change";
}

message Diagnostic {
  enum Severity {
    SEVERITY_UNSPECIFIED = 0;
    SEVERITY_INFO = 1 [(grdr.common.v1alpha1.wire_name) = "info"];
    SEVERITY_WARNING = 2 [(grdr.common.v1alpha1.wire_name) = "warning"];
    SEVERITY_ERROR = 3 [(grdr.common.v1alpha1.wire_name) = "error"];
  }

  string code = 1
      [(grdr.common.v1alpha1.data_class) = DATA_CLASS_STRUCTURAL];
  Severity severity = 2
      [(grdr.common.v1alpha1.data_class) = DATA_CLASS_STRUCTURAL];
  string rule_id = 3
      [(grdr.common.v1alpha1.data_class) = DATA_CLASS_STRUCTURAL];
}

message LoadReport {
  message NotEvaluable {
    string rule_id = 1
        [(grdr.common.v1alpha1.data_class) = DATA_CLASS_STRUCTURAL];
    string reason = 2
        [(grdr.common.v1alpha1.data_class) = DATA_CLASS_STRUCTURAL];
  }

  bytes bundle_digest = 1
      [(grdr.common.v1alpha1.data_class) = DATA_CLASS_IDENTIFIER];
  repeated NotEvaluable not_evaluable = 2
      [(grdr.common.v1alpha1.data_class) = DATA_CLASS_STRUCTURAL];
}

message EngineState {
  uint32 format_version = 1
      [(grdr.common.v1alpha1.data_class) = DATA_CLASS_STRUCTURAL];
  bytes bundle_digest = 2
      [(grdr.common.v1alpha1.data_class) = DATA_CLASS_IDENTIFIER];
  uint64 step_seq = 3
      [(grdr.common.v1alpha1.data_class) = DATA_CLASS_STRUCTURAL];
}

message HostProfile {
  string host_id = 1
      [(grdr.common.v1alpha1.data_class) = DATA_CLASS_IDENTIFIER];
  string host_version = 2
      [(grdr.common.v1alpha1.data_class) = DATA_CLASS_STRUCTURAL];
  reserved 3, 4, 5, 6, 7, 8;
  reserved "event_classes", "session_mechanism", "attribution_bases", "actuators", "tamper", "limits";
}
```

Normative rules for `grdr.embed.v1alpha1`:
- **R1.1 (`Event` over `Envelope`).** `Input.event` and `Output.events` use `grdr.event.v1alpha1.Event` (`#394` R6). On slice 0, `Event` contains `Envelope envelope = 1` and keeps `2..15` for event payloads; `#381` and `#384` are updated to name `grdr.event.v1alpha1.Event`. Re-checking `buf lint` (`STANDARD`) confirms `Severity` uses enum value prefix `SEVERITY_`, passing `ENUM_VALUE_PREFIX` and `ENUM_ZERO_VALUE_SUFFIX`. If `buf` or protobuf syntax rejects an empty `oneof kind {}` inside `Effect`, `Effect` omits the empty `oneof kind {}` while keeping `reserved 1, 2, 3, 4;` and `reserved "expectation", "actuator_request", "label_projection", "interest_change";` (wire-compatible, because adding a `oneof` around future fields 1..4 is backward-compatible in proto3).
- **R1.2 (`DataClass` assignments).** Replacing `#381` R10's informal word "metadata", every field carries an explicit `DataClass`:
  - `DATA_CLASS_IDENTIFIER`: `Output.step_id` (every id is `identifier` per RFC 0009), `LoadReport.bundle_digest` and `EngineState.bundle_digest` (artefact digests per `docs/design/04` section 11), `HostProfile.host_id` (vendor domain id).
  - `DATA_CLASS_STRUCTURAL`: `Input.event`, `Input.tick`, `Output.step_seq`, `Output.events`, `Output.effects`, `Output.diagnostics`, `Diagnostic.code`, `Diagnostic.severity`, `Diagnostic.rule_id`, `LoadReport.not_evaluable`, `NotEvaluable.rule_id`, `NotEvaluable.reason`, `EngineState.format_version`, `EngineState.step_seq`, `HostProfile.host_version`. Notice `bundle_digest`, `step_seq`, `step_id`, `code`, `severity`, `rule_id`, `format_version`, `host_id`, `host_version` and `reason` are all `identifier` or `structural`, so all pass at the default `metadata` capture level and zero embed-wrapper field carries `content` (P8). Leaf fields nested inside `grdr.event.v1alpha1.Event` carry their own leaf classes in `grdr.event.v1alpha1`. `NotEvaluable.reason` carries machine tokens (such as missing capability names), never free-form user content or host input bytes.
- **R1.3 (`step_id` definition and minting).** `step_id` is a `grdr_model::StepId` (`IdKind::Step`, prefix `stp`, mint route `MintRoute::Uuid7`, `loggable = false`), matching `^[a-z]{2,3}_[0-7][0-9a-hjkmnp-tv-z]{25}$` (`stp_<26 lowercase Crockford base32>`). On normal completion of `Engine::step`, the engine increments `step_seq` via checked addition and mints `step_id` once from `(now, entropy)` via `StepId::mint(now, entropy)`. On a step failure (section 3), `Output` returns `step_seq = 0`, `step_id = ""`, empty `events` and `effects`, and at least one error `Diagnostic` (`SEVERITY_ERROR`, registered `GRDR-CORE` or `GRDR-MODEL` code), leaving the engine's `step_seq` unchanged.
- **R1.4 (`Diagnostic.code` and `Diagnostic` constraints).** `Diagnostic.code` is always a registered `GRDR-<AREA>-<NNNN>` identifier (from `grdr_schema::Code::as_str()`). `Diagnostic` carries no human prose string in slice 0 (`P8`, `D-69`).
- **R1.5 (Deterministic encoding and unknown-field policy).** With SP-1 (`RFC 0006` section 6): encoding any message in `grdr.embed.v1alpha1` is deterministic (`encode(msg) == encode(msg)` bit for bit across native `x86_64`/`aarch64` and `wasm32`). Note `Engine::step` and `boundary` hold no `map` fields (`docs/design/04` section 1 rule 4) and order repeated `diagnostics`, `effects`, `events` and `not_evaluable` deterministically. At the engine boundary in slice 0, unknown fields in `HostProfile` or `Input` do not fail decoding silently if ignored: unknown `Input` variants (for instance an `Input` whose `oneof kind` is unset or an unrecognised field with empty `kind`) are rejected by `boundary` with `BoundaryError::DecodeInput` (`GRDR_E_DECODE`), leaving engine state unchanged; unknown wire fields alongside known `HostProfile` fields are ignored only in `slice:0` until EM-8 maps unknown capabilities to `NotEvaluable` (matching RFC 0009 answer 5 / `docs/design/26` section 4). Unknown-field preservation on `grdr-proto` types stays verified by SP-1 (`#381`).

### 3. Rust core boundary: `grdr_core::engine` and `grdr_model::VerifiedBundle` (R2)

#### 3.1 Additions to `grdr-model`
1. **`grdr_model::VerifiedBundle` (`crates/grdr-model/src/bundle.rs`, re-exported at crate root):**
   ```rust
   #[derive(Clone, Debug, PartialEq, Eq)]
   pub struct VerifiedBundle {
       bytes: Vec<u8>,
       digest: [u8; 32],
   }

   impl VerifiedBundle {
       /// Wraps bundle bytes and their SHA-256 digest after caller verification.
       ///
       /// `grdr-core` performs no cryptographic signature verification.
       pub fn assume_verified(bytes: Vec<u8>, digest: [u8; 32]) -> Self;
       pub fn bytes(&self) -> &[u8];
       pub fn digest(&self) -> &[u8; 32];
   }
   ```
   `ARCH-012` confines `VerifiedBundle::assume_verified` outside tests strictly to `grdr-crypto`, `grdr-update`, `crates/grdr-ffi` (`grdr_engine_load` and `grdr_engine_restore`) and `crates/grdr-wasm` (`grdr_engine_load` and `grdr_engine_restore`). `grdr-core` never calls `VerifiedBundle::assume_verified` outside tests and exports no function constructing a `VerifiedBundle` from raw `&[u8]` bundle bytes.
2. **`grdr_model::StepId` (`IdKind::Step`):** Added as one entry in the `grdr-model` id macro list under RFC 0009 section 4 and `crates/grdr-model/AGENTS.md`'s one-row recipe (`IdKind::Step`, prefix `"stp"`, `MintRoute::Uuid7`, type `StepId`, `loggable = false`). `stp` is `[a-z]{3}`, distinct from `agt` and every prefix in RFC 0009 section 4 and `#383` R5. Because `IdKind` is `#[non_exhaustive]` and `loggable` is `false`, adding `Step` is content under RFC 0009 (`ADR-0041` amendment table row 1, checked by `eval-api` when `#384` lands with `crates/grdr-model/src/id*` added to `#384`'s write set and citing RFC 0009 alongside RFC 0014).

#### 3.2 `grdr_core::engine` public API
`crates/grdr-core/src/lib.rs` exports `pub mod engine;` (implemented across small modules under `crates/grdr-core/src/engine/`). `Engine` holds the active `bundle_digest: [u8; 32]`, `host_profile: HostProfile`, `step_seq: u64` (starts at `0` on `load`, restored on `restore`), and zero I/O, clock, randomness or interior-mutable global state (`Send + Sync`). An `Engine` value exists only after a successful `load` or `restore` (`#384` R3).

```rust
// crates/grdr-core/src/engine.rs
use grdr_fastpath::layout;
use grdr_model::{Entropy, IdError, SessionId, StepId, Timestamp, VerifiedBundle};
use grdr_proto::grdr::event::v1alpha1::Event;
use grdr_schema::{Code, Coded};

pub mod boundary;

pub struct Engine { /* private fields */ }

impl Engine {
    pub fn load(
        bundle: &VerifiedBundle,
        host: &HostProfile,
    ) -> Result<(Engine, LoadReport), LoadError>;

    pub fn step(
        &mut self,
        input: Input<'_>,
        now: Timestamp,
        entropy: &mut dyn Entropy,
    ) -> Output;

    pub fn interest(&self, session: Option<SessionId>) -> InterestSet;

    pub fn snapshot(&self) -> StateSnapshot;

    pub fn restore(
        bundle: &VerifiedBundle,
        host: &HostProfile,
        s: &StateSnapshot,
    ) -> Result<Engine, LoadError>;
}
```

Supporting types in `grdr_core::engine`:
- `HostProfile` (`#[non_exhaustive]`, `Clone`, `Debug`, `PartialEq`, `Eq`): constructed via `HostProfile::new(host_id: impl Into<String>, host_version: impl Into<String>) -> Result<HostProfile, LoadError>`, rejecting an empty `host_id` (`host_id.trim().is_empty()` or `is_empty()` -> wait: `host_id.is_empty()` returns `LoadError::Profile`, and `Load`/`Restore` re-validate; note `host_id` reverse-DNS non-empty validation stays simple in slice 0: empty `host_id` is `LoadError::Profile`). Exposes `pub fn host_id(&self) -> &str` and `pub fn host_version(&self) -> &str`.
- `LoadReport` & `NotEvaluable` (`#[non_exhaustive]`, `Clone`, `Debug`, `PartialEq`, `Eq`): `pub bundle_digest: [u8; 32]`, `pub not_evaluable: Vec<NotEvaluable>` (empty in slice 0); `NotEvaluable { pub rule_id: String, pub reason: String }`.
- `Input<'a>` (`#[non_exhaustive]`, `Clone`, `Debug`): `Event(&'a Event)`, `Tick`.
- `Output` (`#[non_exhaustive]`, `Clone`, `Debug`, `PartialEq`, `Eq`):
  ```rust
  #[non_exhaustive]
  #[derive(Clone, Debug, PartialEq, Eq)]
  pub enum Output {
      Completed(StepOutput),
      Failed(StepFailure),
  }

  #[non_exhaustive]
  #[derive(Clone, Debug, PartialEq, Eq)]
  pub struct StepOutput {
      pub step_seq: u64,
      pub step_id: StepId,
      pub events: Vec<Event>,
      pub effects: Vec<Effect>,
      pub diagnostics: Vec<Diagnostic>,
  }

  #[non_exhaustive]
  #[derive(Clone, Debug, PartialEq, Eq)]
  pub struct StepFailure {
      pub error: StepError,
      pub diagnostics: Vec<Diagnostic>,
  }
  ```
  Making `Output` an enum satisfies `docs/design/03` section 3 (`-> Output`), `#384` R5 (`step_seq` overflow diagnostic with state unchanged), and `ADR-0041` constraint 1d (`#1537`): a failed `Entropy::fill` (`IdError::Entropy` -> `GRDR-MODEL-0003`), pre-1970 `now` (`IdError::TimeOutOfRange` -> `GRDR-MODEL-0005`) or `step_seq` overflow (`GRDR-CORE-0001`) produces `Output::Failed(StepFailure)`, never exposes an un-drawn `StepId` or empty `StepOutput`, and leaves `self.step_seq` untouched.
- `Effect` (`#[non_exhaustive]`, `Clone`, `Debug`, `PartialEq`, `Eq`): enum with zero slice-0 variants (`#[non_exhaustive]` permits EM and `#1861` extensions).
- `Diagnostic` & `Severity` (`#[non_exhaustive]`, `Clone`, `Debug`, `PartialEq`, `Eq`): `pub code: Code`, `pub severity: Severity`, `pub rule_id: String`; `Severity` has `Info`, `Warning`, `Error`.
- `InterestSet` (`#[non_exhaustive]`, `Clone`, `Debug`, `PartialEq`, `Eq`): `pub process_scope: Vec<layout::ProcessScopeEntry>`, `pub paths: Vec<layout::PathEntry>`, `pub hosts: Vec<layout::HostEntry>`, `pub ports: Vec<layout::PortEntry>`, `pub strings: Vec<u8>`. Uses `grdr_fastpath::layout` structs across the existing `grdr-core -> grdr-fastpath` edge in `architecture.toml`. Slice 0 returns four empty tables and empty `strings`.
- `StateSnapshot` (`#[non_exhaustive]`, `Clone`, `Debug`, `PartialEq`, `Eq`): `pub const FORMAT_VERSION_V1: u32 = 1;`, `pub format_version: u32`, `pub bundle_digest: [u8; 32]`, `pub step_seq: u64`.
- **Error enums and registered `CORE` codes (`Coded`, RFC 0007, `ARCH-017`):**
  Every enum below implements `Clone`, `Copy` (except `LoadError` if needed; keeping all three `Clone, Copy, Debug, PartialEq, Eq, core::fmt::Display, core::error::Error` makes them cheap and `LogSafe`), `Display` and `grdr_schema::Coded` with exhaustive `match` and no wildcard arm, bound to area `CORE` (`schema/codes/areas.toml`, `schema/codes/core.toml`):

  | Code | Reason | Class | Connect | Bound variant |
  |---|---|---|---|---|
  | `GRDR-CORE-0001` | `STEP_SEQ_OVERFLOW` | `fatal` | `failed_precondition` | `StepError::StepSeqOverflow` |
  | `GRDR-CORE-0002` | `HOST_PROFILE_INVALID` | `input` | `invalid_argument` | `LoadError::Profile` |
  | `GRDR-CORE-0003` | `SNAPSHOT_BUNDLE_MISMATCH` | `input` | `failed_precondition` | `LoadError::SnapshotBundle` |
  | `GRDR-CORE-0004` | `SNAPSHOT_FORMAT_UNSUPPORTED` | `input` | `invalid_argument` | `LoadError::SnapshotFormat` |
  | `GRDR-CORE-0005` | `BOUNDARY_ARGUMENT_INVALID` | `input` | `invalid_argument` | `BoundaryError::Arg` |
  | `GRDR-CORE-0006` | `BOUNDARY_DECODE_INPUT` | `input` | `invalid_argument` | `BoundaryError::DecodeInput` |
  | `GRDR-CORE-0007` | `BOUNDARY_DECODE_STATE` | `input` | `invalid_argument` | `BoundaryError::DecodeState` |
  | `GRDR-CORE-0008` | `BOUNDARY_DECODE_PROFILE` | `input` | `invalid_argument` | `BoundaryError::DecodeProfile` |
  | `GRDR-CORE-0009` | `BOUNDARY_ENCODE_FAILED` | `internal` | `internal` | `BoundaryError::Encode` |

  (`StepError::Id(IdError)` delegates to `IdError::code()`, returning `GRDR-MODEL-0003` or `GRDR-MODEL-0005`; `BoundaryError::Load(LoadError)` delegates to `LoadError::code()`).

#### 3.3 `grdr_core::engine::boundary` and shared codec path
Both `grdr-ffi` and `grdr-wasm` depend on `grdr-core` (for `engine::boundary`) and `grdr-model` (to construct `VerifiedBundle` exclusively at their FFI and Wasm `load` / `restore` boundaries under `ARCH-012`), and never import `grdr-proto` directly or re-implement protobuf decoding or encoding. `engine::boundary` takes `&VerifiedBundle` and never constructs `VerifiedBundle` from raw bytes, eliminating any unchecked `grdr-core` wrapper around `VerifiedBundle::assume_verified`. It exposes:
- `pub fn bundle_sha256(bytes: &[u8]) -> [u8; 32]` (implemented in `crates/grdr-core/src/engine/bundle_sha256.rs`, proposed for `security/trust-core.paths`):
  Computes an unkeyed FIPS 180-4 SHA-256 content digest in pure checked Rust (zero `unsafe`, zero third-party crypto crates, keeping `ARCH-006` intact). It performs no signature check and returns `[u8; 32]` only (with no `VerifiedBundle` access) so `grdr-ffi` and `grdr-wasm` supply identical `bundle_digest` bytes to `VerifiedBundle::assume_verified`. Verified both by NIST FIPS 180-4 / SHAVS CAVP byte vectors in `crates/grdr-core/tests/` (`#384`) and by differential property testing against `grdr-crypto`'s AWS-LC SHA-256 (`#337`) inside `crates/grdr-crypto/tests/` (Layer 2 -> Layer 1, obeying `ARCH-001`).
- `pub fn load(bundle: &VerifiedBundle, host_profile: &[u8]) -> Result<(Engine, Vec<u8>), BoundaryError>`:
  Decodes `grdr.embed.v1alpha1.HostProfile` (`DecodeProfile`), calls `Engine::load(bundle, &profile)`, and encodes `grdr.embed.v1alpha1.LoadReport`.
- `pub fn step_bytes(engine: &mut Engine, input: &[u8], now: Timestamp, entropy: &mut dyn Entropy) -> Result<Vec<u8>, BoundaryError>`:
  Decodes `grdr.embed.v1alpha1.Input` (`DecodeInput`), verifies `kind` is `Some` (empty `oneof kind` returns `DecodeInput` with state unchanged), maps `Input`, calls `engine.step(mapped, now, entropy)`, and encodes `grdr.embed.v1alpha1.Output`:
  - `Output::Completed(s)` encodes `step_seq`, `step_id`, `events`, `effects`, `diagnostics`.
  - `Output::Failed(f)` encodes `step_seq = 0`, `step_id = ""`, empty `events`/`effects` and `f.diagnostics` (preserving parity with `#384` R5 on `step_seq` overflow and `IdError` across native, C ABI and `wasm32`). Note: adding an explicit `StepFailure` field (`7`) onto `grdr.embed.v1alpha1.Output` for `ActionRequest` deployments is left to the later wire RFC that unreserves `Output.decision` (`rfcs/0009` section 13 / constraint 2e).
- `pub fn timestamp_from_unix_ns(now_unix_ns: i64) -> Result<Timestamp, BoundaryError>`:
  Converts signed Unix nanoseconds to `Timestamp`, returning `BoundaryError::Arg` if `now_unix_ns` overflows `Timestamp::MIN..=Timestamp::MAX` (with `now_unix_ns < 0` flowing through `Engine::step` -> `IdError::TimeOutOfRange` / `Output::Failed` with `GRDR-MODEL-0005` so negative `now` behaves identically across native, C ABI and `wasm32`!).
- `pub fn interest_bytes(engine: &Engine, session_id: &[u8]) -> Result<Vec<u8>, BoundaryError>`:
  If `session_id.is_empty()`, calls `engine.interest(None)`; otherwise converts UTF-8 and validates `SessionId::from_wire` (`GRDR-CORE-0005` -> `GRDR_E_ARG` on invalid UTF-8 or malformed id, obeying `ARCH-020`), calls `engine.interest(Some(sid))`, and encodes `InterestSet` in the fixed `GRDI` v1 wire frame below.
- `pub fn snapshot_bytes(engine: &Engine) -> Result<Vec<u8>, BoundaryError>`:
  Calls `engine.snapshot()` and encodes `grdr.embed.v1alpha1.EngineState`.
- `pub fn restore_bytes(bundle: &VerifiedBundle, host_profile: &[u8], state: &[u8]) -> Result<Engine, BoundaryError>`:
  Decodes `HostProfile` (`DecodeProfile`) and `EngineState` (`DecodeState`), and calls `Engine::restore(bundle, &profile, &snapshot)`.
- `pub fn encode_diagnostic(code: Code, severity: Severity, rule_id: &str) -> Result<Vec<u8>, BoundaryError>`:
  Encodes `grdr.embed.v1alpha1.Diagnostic` for `grdr_engine_last_error`.
- Explicit codec helpers for tests and internal callers: `encode_host_profile`, `decode_host_profile`, `encode_load_report`, `decode_load_report`, `encode_engine_state`, `decode_engine_state`, `decode_interest_bytes`.

**Fixed `InterestSet` binary format (`GRDI` v1):**
Fixed little-endian layout matching `spec/host-contract/tables.md` section 3.5 record sizes (`ProcessScopeEntry` 48 B, `PathEntry` 16 B, `HostEntry` 40 B, `PortEntry` 4 B):
- Bytes `0..4`: ASCII magic `"GRDI"`
- Bytes `4..6`: `format_version: u16` (`1`)
- Bytes `6..8`: `flags: u16` (`0`)
- Bytes `8..12`: `process_scope_count: u32`
- Bytes `12..16`: `paths_count: u32`
- Bytes `16..20`: `hosts_count: u32`
- Bytes `20..24`: `ports_count: u32`
- Bytes `24..28`: `strings_len: u32`
- Followed immediately in exact order by `process_scope` (`count * 48` bytes), `paths` (`count * 16` bytes), `hosts` (`count * 40` bytes), `ports` (`count * 4` bytes) and `strings` (`strings_len` bytes). On slice 0, `grdr_engine_interest` emits the exact 28-byte little-endian header with all counts `0`.

**Seeded `[u8; 32]` `Entropy` prerequisite (ADR-0041 constraint 2e):**
`boundary::step_bytes` takes `entropy: &mut dyn Entropy`, keeping `#384` free of any product `Entropy` implementor and unblocked for native unit and property testing. Under ADR-0041 constraint 2e, converting `grdr_engine_step`'s `entropy: [u8; 32]` argument (and `wasm32`'s `(entropy_ptr, entropy_len)`) into a per-call deterministic `Entropy` generator in product code is an amendment of RFC 0008 and RFC 0009 (adding an `ARCH-003` implementor shared with `grdr-ports-testkit::SeededEntropy`, stating its 256-bit expansion strength or non-secret id-kind list, `from_seed(u64)` vs `[u8; 32]` equivalence and seed-reuse policy). Therefore:
- `#384` (`Engine` and `boundary`) builds with `step_bytes(..., entropy: &mut dyn Entropy)`.
- Before `#388` and `#19` are readied, `#388` brings that amendment RFC naming RFC 0008 and RFC 0009, adding the one `step_bytes_seeded(..., entropy: [u8; 32])` constructor/entry in `engine::boundary` and `ARCH-003` row in `architecture.toml`; `#384`'s committed vector files under `crates/grdr-core/tests/vectors/engine/` must compute expected `step_id` bytes using that exact same deterministic `[u8; 32]` generator once decided so `#384`, `#388` and `#19` agree byte for byte.

**Workspace dependency edges for `grdr-core`, `grdr-ffi` and `grdr-wasm`:**
`crates/grdr-core/Cargo.toml` gains workspace path dependencies on `grdr-proto`, `grdr-schema`, `grdr-model` and `grdr-fastpath`; `crates/grdr-ffi/Cargo.toml` and `crates/grdr-wasm/Cargo.toml` each gain workspace path dependencies on `grdr-core` and `grdr-model` (all permitted by `architecture.toml` under `ARCH-001` and existing Layer-1 `same_layer_rule` for `grdr-model` and `same_layer_edge` entries, with zero new third-party dependencies). Because editing crate manifests updates `Cargo.lock` (a trust-core path), those workspace edges land through a dedicated `lead-agent-kit` edge issue (`#1984` pattern) before `#384` runs. `architecture.toml` updates `ARCH-013` and `ARCH-012` metadata entries via `#1582` (confining `VerifiedBundle::assume_verified` outside tests to `grdr-crypto`, `grdr-update`, `grdr-ffi` and `grdr-wasm`, forbidding calls in `grdr-core`), while `#1751` enforces `ARCH-027` AST rules on `grdr-wasm`.

### 4. C ABI 0.1: `grdr.h` and `grdr-ffi` (R3)

#### 4.1 Function list and `grdr_engine_config` departure ruling
C ABI version `0.1` (`grdr_abi_version()` returns `(0u32 << 16) | 1u32` = `0x0000_0001`) exports **13 functions**, omitting `grdr_engine_compile_fastpath` (deferred to C ABI `0.2` via `#1918` / RFC 0005 R4.5):

```c
/* Behind #ifndef GRDR_STATUS_DEFINED (shared with grdr_fastpath.h per RFC 0004) */
typedef uint32_t grdr_status;

typedef struct grdr_engine grdr_engine; /* opaque */

typedef struct grdr_buf {
    uint8_t *ptr; /* [structural, pointer] */
    size_t   len; /* [structural, scalar] */
} grdr_buf;

typedef struct grdr_engine_config {
    uint32_t struct_size; /* [structural, scalar] base size 4 in ABI 0.1 */
} grdr_engine_config;

uint32_t    grdr_abi_version(void);
const char *grdr_engine_version(void);
grdr_status grdr_abi_check(uint16_t major, uint16_t min_minor);
grdr_status grdr_engine_new(const grdr_engine_config *cfg, grdr_engine **out);
grdr_status grdr_engine_load(grdr_engine *e, const uint8_t *bundle, size_t bundle_len,
                             const uint8_t *host_profile, size_t host_profile_len,
                             grdr_buf *report);
grdr_status grdr_engine_step(grdr_engine *e, const uint8_t *input, size_t input_len,
                             int64_t now_unix_ns, const uint8_t entropy[32],
                             grdr_buf *output);
grdr_status grdr_engine_interest(grdr_engine *e, const uint8_t *session_id,
                                 size_t session_id_len, grdr_buf *out);
grdr_status grdr_engine_snapshot(grdr_engine *e, grdr_buf *state);
grdr_status grdr_engine_restore(grdr_engine *e, const uint8_t *bundle, size_t bundle_len,
                                const uint8_t *host_profile, size_t host_profile_len,
                                const uint8_t *state, size_t state_len);
void        grdr_buf_free(grdr_buf *buf);
void        grdr_engine_free(grdr_engine *e);
const char *grdr_status_str(grdr_status s);
grdr_status grdr_engine_last_error(grdr_engine *e, grdr_buf *diagnostic);
```

**Explicit ruling on `grdr_engine_config` (`#378` R3):**
This RFC **accepts the departure** from `docs/design/26` section 3 and fixes `grdr_engine_config` in ABI 0.1 to `{ uint32_t struct_size; }` (base size `4` bytes), aligned with `spec/host-contract/c-abi.md` (`#246` on `origin/issue/246`, blob `b147c9d`):
1. **Type is `uint32_t`, not `size_t`.** `#388` R3's `{ size_t struct_size; }` is corrected to `{ uint32_t struct_size; }` (`#388` comment `2026-11-20`), matching `c-abi.md` section 1 and `grdr_fp_input`.
2. **Why EM-6 fields wait behind `struct_size`.** Neither per-handle allocators (which cannot be implemented without global/thread-local `#[global_allocator]` state or allocator-generic core collections), `memory_cap`, nor `step_budget` exist in slice 0. Accepting non-functional fields in 0.1 would silently ignore host resource limits (`P9`). Instead, `alloc`, `realloc`, `free`, `alloc_ctx`, `memory_cap` and `step_budget` append as trailing fields at offsets `8..48` (`56` bytes on 64-bit) when EM-6 lands and bumps C ABI minor.
3. **Version-size validation.** In `grdr_engine_new`, `cfg == NULL` or `out == NULL` returns `GRDR_E_ARG`. A `struct_size < 4` returns `GRDR_E_ARG`. A `struct_size >= 4` is accepted and any bytes beyond offset `4` are ignored in `0.1` (`c-abi.md` section 1); a caller that depends on EM-6's trailing fields calls `grdr_abi_check(0, em6_minor)` first, which returns `GRDR_E_ABI` against `0.1`.

#### 4.2 Status codes (`grdr_status`)
Per accepted RFC 0004 section 15 and RFC 0005 section 13 (`#388` constraint, `ADR-0037`), `grdr.h` declares the shared `grdr_status` constants through `c_status!` and `grdr-cabi-testkit`'s `content::grdr_status` behind `#ifndef GRDR_STATUS_DEFINED`:
- `GRDR_OK = 0` (`usable`)
- `GRDR_E_ARG = 1` (`usable`)
- `GRDR_E_ABI = 2` (`no-handle`)
- `GRDR_E_DECODE = 3` (`usable-state-unchanged`)
- `GRDR_E_BUNDLE = 4` (`last-known-good`)
- `GRDR_E_PROFILE = 5` (`previous-profile`)
- `GRDR_E_RESOURCE = 6` (`usable-state-unchanged`)
- `GRDR_E_BUDGET = 7` (`usable-state-unchanged`)
- `GRDR_E_STATE = 8` (`usable`)
- `GRDR_E_POISONED = 9` (`recreate-from-snapshot`)
- `GRDR_E_INTERNAL = 10` (`poisoned`)
- `GRDR_E_CHANGED = 11` (`reload-required`, RFC 0005; never returned by `grdr-ffi` engine calls, defined for shared `#ifndef GRDR_STATUS_DEFINED` `HDR-4` parity; `grdr_status_str(11)` returns `"GRDR_E_CHANGED"`, and any unrecognised value returns `"GRDR_E_UNKNOWN"`).

#### 4.3 Handle state machine, memory ownership, panics and RFC 0004 integration
- **Explicit handle state (`grdr-ffi`, structure S4):**
  ```rust
  pub enum HandleState {
      Created,
      Loaded(Engine),
      Poisoned,
  }
  ```
  - `Created` allows `load`, `restore`, `last_error`, `free`. Calls to `step`, `interest` and `snapshot` return `GRDR_E_STATE`.
  - `Loaded(Engine)` allows every function. A failing `load` or `restore` keeps the previous `Loaded(Engine)` intact (`last-known-good` / `previous-profile`). On a `DecodeInput`, `DecodeState`, `SnapshotBundle`, `Arg` or `Output::Failed` condition, `Loaded(Engine)` remains unchanged.
  - `Poisoned` (entered on any caught unwind or internal invariant failure `GRDR_E_INTERNAL`) allows only `last_error` and `free`; every other call returns `GRDR_E_POISONED`.
- **Memory, `VerifiedBundle` ingress, threading and panics:**
  - All input buffers (`bundle`, `host_profile`, `input`, `session_id`, `state`, `entropy[32]`) are borrowed only for the duration of the call; a null pointer with `len == 0` is treated as `&[]`, while a null pointer with `len > 0` or a null required out-pointer (`out`, `report`, `output`, `state`) returns `GRDR_E_ARG`. No output argument is written on any non-`GRDR_OK` return (`c-abi.md` section 1).
  - At `grdr_engine_load` and `grdr_engine_restore`, `crates/grdr-ffi` (covered by `security/trust-core.paths` `crates/grdr-ffi/**`) reserves the bundle copy with `Vec::try_reserve_exact(bundle_len)` (returning `GRDR_E_RESOURCE` with `Created` or `last-known-good` intact on allocation failure), computes `digest = grdr_core::engine::boundary::bundle_sha256(&buf)`, constructs `VerifiedBundle::assume_verified(buf, digest)` (`ARCH-012`), and passes `&VerifiedBundle` to `engine::boundary::{load, restore_bytes}`.
  - Returned `grdr_buf { ptr, len }` buffers are owned by the library and freed by `grdr_buf_free` (callable from any thread; no-op on null or `{ NULL, 0 }`).
  - `grdr_engine_last_error` returns `{ NULL, 0 }` (`GRDR_OK`) when no call on that handle has failed yet (`c-abi.md` empty buffer); any call returning a status other than `GRDR_OK` updates `last_error`, whereas `GRDR_OK` transport returns (including `Output` carrying an error `Diagnostic` in `Output.diagnostics`) do not clear `last_error`.
  - `grdr_engine` is `Send` and not `Sync`; the library holds zero global or thread-local mutable state (`#388` R11).
  - Every `extern "C"` function runs inside `std::panic::catch_unwind(std::panic::AssertUnwindSafe(...))` (`grdr-ffi` carries no `panic = "abort"` requirement during normal dev/test, while under the `embedded` `panic = "abort"` build profile any panic aborts immediately rather than unwinding across C, `c-abi.md` section 8). In `unwind` builds, catching a panic transitions the handle to `Poisoned`, records an internal `Diagnostic` (`GRDR-CORE-0009` `Encode` / internal `GRDR-CORE` code in `last_error`), and returns `GRDR_E_INTERNAL`.
  - Every `unsafe` block inside `crates/grdr-ffi` carries a `// SAFETY:` comment stating the pointer/alignment/lifetime invariant; no `unsafe` block exists outside `crates/grdr-ffi` and `crates/grdr-fastpath-ffi` at Layer 1 (and note `wasm32` crate lint structure below).
- **RFC 0004 (`grdr-cabi-testkit`) alignment:**
  `crates/grdr-ffi/src/lib.rs` places all 13 `extern "C"` exports at crate root above `#[cfg(not(grdr_bless))] mod grdr_abi;`, uses `c_fn!`, `c_struct!`, `c_status!`, `*const c_char as "char"`, `#pragma pack(push, 8)` / `#pragma pack(pop)` and `tests/header_drift.rs` (`header_drift`) generated via `grdr-cabi-testkit`. `crates/grdr-ffi/Cargo.toml` sets `[lib] crate-type = ["rlib", "staticlib"]` so `cargo test` links `rlib` while `c-headers` compiles and links the C harness cleanly against `staticlib` with no runtime shared-library loader configuration.

### 5. WebAssembly core exports: `grdr-wasm` (R4)

`crates/grdr-wasm` builds one `wasm32-unknown-unknown` `cdylib` (with `[lib] crate-type = ["cdylib", "rlib"]`) containing an **empty WebAssembly import section** (`module.imports().next().is_none()`): zero WASI, zero JS imports and zero host callbacks (`#19` R1).

#### 5.1 Linear-memory ABI exports
One Wasm module instance owns one single-threaded handle slot (`enum InstanceSlot { Uninit, Active(HandleState), TrapPoisoned }`, matching `c-abi.md` section 3 and `#19` R5). Because linear memory uses 32-bit `u32` addresses and core Wasm avoids pointer-to-pointer out-parameters, all binary outputs and static strings use the single result slot `(grdr_result_ptr(), grdr_result_len())`. Every stateful or allocating export pre-poisons `InstanceSlot` to `TrapPoisoned` on entry before running work (restoring or committing only on normal return), and every input `(ptr, len)` span with `len == 0` (notably `grdr_engine_interest(0, 0)`) resolves to `&[]` without consulting the allocation slot table while `len > 0` requires an active `grdr_alloc` slot (`GRDR_E_ARG` otherwise):

| Export | Wasm signature (`extern "C"`) | Semantics and status |
|---|---|---|
| `memory` | Core linear memory | Declared maximum pages matching `limits.toml` (64 MiB = `1,024` 64 KiB pages) |
| `grdr_alloc` | `(len: u32) -> u32` (`grdr_status`) | Returns `GRDR_E_POISONED` if `TrapPoisoned`; otherwise pre-poisons during allocation, reserves `len` bytes (`(0, 0)` for `len == 0`) via `Vec::try_reserve_exact` if live memory + allocation + reserve headroom stay within `limits.toml` max, writes offset/length to result slot, restores slot and returns `GRDR_OK` or `GRDR_E_RESOURCE` |
| `grdr_free` | `(ptr: u32, len: u32) -> ()` | Releases a buffer allocated by `grdr_alloc`; no-op on `(0, 0)`, stale or unowned `(ptr, len)` spans, leaving `TrapPoisoned` sticky if poisoned |
| `grdr_buf_free` | `() -> ()` | Clears the last result buffer (`result_ptr = 0, result_len = 0`) and frees backing bytes, preserving `TrapPoisoned` if set |
| `grdr_result_ptr` | `() -> u32` | Linear-memory offset of the last result (`0` when cleared/empty) |
| `grdr_result_len` | `() -> u32` | Byte length of the last result (`0` when cleared/empty) |
| `grdr_abi_version` | `() -> u32` | Returns `0x0000_0001` (`0.1`) |
| `grdr_engine_version` | `() -> u32` (`grdr_status`) | Writes static UTF-8 SemVer slice into `(result_ptr, result_len)`; returns `GRDR_OK` |
| `grdr_abi_check` | `(major: u32, min_minor: u32) -> u32` | Returns `GRDR_OK` (`major == 0 && min_minor <= 1`) or `GRDR_E_ABI` |
| `grdr_status_str` | `(s: u32) -> u32` (`grdr_status`) | Writes static ASCII code name (or `"GRDR_E_UNKNOWN"`) into `(result_ptr, result_len)`; returns `GRDR_OK` |
| `grdr_engine_new` | `(cfg_ptr: u32, cfg_len: u32) -> u32` | Pre-poisons on entry; validates `cfg` (`cfg_len >= 4`, active slot, little-endian `struct_size >= 4`) and creates `HandleState::Created` if `Uninit` (`GRDR_E_STATE` if already `Active`; `GRDR_E_POISONED` if `TrapPoisoned`) |
| `grdr_engine_load` | `(b_ptr: u32, b_len: u32, p_ptr: u32, p_len: u32) -> u32` | Pre-poisons on entry; checks `EMBED_WASM_MEMORY_MAX` + headroom and reserves bundle copy via `try_reserve_exact` (`GRDR_E_RESOURCE` preserving `prev`), computes `bundle_sha256` and `VerifiedBundle::assume_verified` (`ARCH-012`), calls `engine::boundary::load` and writes bounded `LoadReport` |
| `grdr_engine_step` | `(in_ptr: u32, in_len: u32, now_unix_ns: i64, ent_ptr: u32, ent_len: u32) -> u32` | Pre-poisons on entry; requires `ent_len == 32` (`GRDR_E_ARG`); converts `now_unix_ns`, calls `engine::boundary::step_bytes` (seeded via section 3 once Constraint 2e lands); writes bounded encoded `Output` to result slot |
| `grdr_engine_interest` | `(sid_ptr: u32, sid_len: u32) -> u32` | Pre-poisons on entry; treats `sid_len == 0` (including `(0, 0)`) as `&[]`, validates non-empty span against slot table, calls `engine::boundary::interest_bytes`; writes bounded `GRDI` v1 bytes to result slot |
| `grdr_engine_snapshot` | `() -> u32` | Pre-poisons on entry; calls `engine::boundary::snapshot_bytes`; writes bounded encoded `EngineState` to result slot |
| `grdr_engine_restore` | `(b_ptr: u32, b_len: u32, p_ptr: u32, p_len: u32, s_ptr: u32, s_len: u32) -> u32` | Pre-poisons on entry; checks `EMBED_WASM_MEMORY_MAX` + headroom and reserves bundle copy via `try_reserve_exact`, calls `VerifiedBundle::assume_verified` and `engine::boundary::restore_bytes`; transitions `Created`/`Loaded` to `Loaded` on success while restoring `prev` on failure |
| `grdr_engine_free` | `() -> ()` | Drops `Active(HandleState)` back to `Uninit` and frees live arena buffers while keeping `TrapPoisoned` sticky |
| `grdr_engine_last_error` | `() -> u32` | Returns `GRDR_E_POISONED` if `TrapPoisoned`; otherwise pre-poisons around bounded write of encoded `Diagnostic` of last failure (`(0, 0)` if none) into `(result_ptr, result_len)` |

#### 5.2 Key Wasm safety, memory limit and lint rules
- **Why `grdr_alloc(len) -> grdr_status` instead of returning `ptr` directly:** Returning `grdr_status` (`GRDR_OK` / `GRDR_E_RESOURCE` / `GRDR_E_POISONED`) and publishing the offset in `grdr_result_ptr()` matches `#19` R2 ("return the same `grdr_status` numbers") and `#19` Failure modes ("`grdr_alloc` fails with `GRDR_E_RESOURCE` | return code") verbatim, and keeps zero-length or error disambiguation type-clean (`grdr_alloc(0)` returns `GRDR_OK` with `(0, 0)`). `grdr_free(ptr, len)` silently ignores `(0, 0)` and validates any non-zero `(ptr, len)` against the live safe slot table (no UB if passed stale/mismatched values; invalid non-zero spans do nothing and return safely). Across all input-taking exports, `len == 0` (explicitly including `grdr_engine_interest(0, 0)` for full interest queries) resolves to `&[]` without requiring a slot entry, whereas `len > 0` demands `ptr != 0` inside an active `grdr_alloc` slot (`GRDR_E_ARG` otherwise).
- **Zero `unsafe` logic via `#![forbid(unsafe_code)]` inner module and `#1751` AST enforcement (`#19`, `ARCH-027`):**
  Running `cargo clippy --target wasm32-unknown-unknown -- -D warnings` on Rust `1.99.1` (`edition = "2024"`) confirms that `-F unsafe-code` (`unsafe_code = "forbid"` in root `Cargo.toml`) rejects `#[unsafe(no_mangle)]` itself (`error: usage of the unsafe no_mangle attribute`, exit `101`). At the same time, permitting crate-wide `unsafe_code = "deny"` + `#[allow(unsafe_code)]` on 18 multi-line export functions would disable `unsafe` checking inside their bodies unless constrained structurally. Therefore `grdr-wasm` isolates **100% of its implementation** inside a private inner module annotated `#![forbid(unsafe_code)]` (`mod safe_impl { #![forbid(unsafe_code)] ... }`): slot table, linear-memory offset calculation (`slice.as_ptr().addr() as u32`, stable Rust 1.84+), span checks, memory-cap arithmetic, `Vec::try_reserve_exact`, `VerifiedBundle::assume_verified` construction, and `engine::boundary` calls all compile under `rustc`'s `forbid(unsafe_code)`. The crate root (`crates/grdr-wasm/Cargo.toml`) sets `[lints.rust] unsafe_code = "deny"`, and each of the 18 top-level `#[unsafe(no_mangle)] pub extern "C" fn` items in `crates/grdr-wasm/src/lib.rs` carries `#[allow(unsafe_code, reason = "wasm32 export symbol")]` with **only a single delegation call expression** into `safe_impl` (zero local statements, zero `unsafe {}` blocks). `#1751` (`ARCH-027` in `grdr-archlint`) admits `grdr-wasm` alongside a `syn`-based AST check verifying `#![forbid(unsafe_code)]` on `safe_impl`, zero `unsafe {}` blocks, `unsafe fn`, `unsafe impl`, or `unsafe trait` across `crates/grdr-wasm/src/**/*.rs`, and `#[allow(unsafe_code)]` solely on single-call `#[unsafe(no_mangle)] pub extern "C" fn` delegation stubs, backed by a seeded failing fixture. In addition, `crates/grdr-wasm/**` is proposed for `security/trust-core.paths` so `.claude/risk-tiers.toml` `[trust_core]` applies two-model `eval-review` + `eval-security` review.
- **64 MiB maximum memory from `limits.toml`, headroom checks and `try_reserve_exact` (`#19` R4):**
  A dedicated `limits.toml` row `[bound.embed] wasm-memory-max` (`value = 67108864`, `unit = "bytes"`, `owner = "docs/design/26"`, i.e., `64 MiB` = `1,024` 64 KiB Wasm pages) generates `grdr_schema::limits::EMBED_WASM_MEMORY_MAX` (`Bytes`) via `#279`. `grdr-wasm` enforces `EMBED_WASM_MEMORY_MAX` on BOTH `grdr_alloc` and internal copy/output buffers (`grdr_engine_load`, `grdr_engine_restore`, `grdr_engine_step`, `grdr_engine_interest`, `grdr_engine_snapshot`, `grdr_engine_last_error`) by computing `live_wasm_bytes = (core::arch::wasm32::memory_size::<0>() as u64).saturating_mul(65_536)` (safe under `#![forbid(unsafe_code)]` in Rust `1.99.1`), rejecting any allocation where `live_wasm_bytes` + pending bytes + copy/decode/output headroom would exceed `EMBED_WASM_MEMORY_MAX`, AND allocating heap buffers fallibly with `Vec::try_reserve_exact`. On either budget rejection or `TryReserveError`, the export restores `prev` `InstanceSlot` and returns `GRDR_E_RESOURCE` without trapping. In particular, calling `grdr_alloc` for a `33 MiB` bundle succeeds (`< 64 MiB`), after which `grdr_engine_load` or `grdr_engine_restore` accounts for the `33 MiB` `VerifiedBundle` copy plus live linear pages and decode headroom exceeding `EMBED_WASM_MEMORY_MAX`, fails cleanly with `GRDR_E_RESOURCE`, leaves the `last-known-good` `Engine` intact, and never triggers `--max-memory` OOM abort (tested explicitly by a hostile `33 MiB` vector in `#19`). The compiled `.wasm` module's linear memory maximum is also checked in `crates/grdr-wasm/tests/` against `EMBED_WASM_MEMORY_MAX / 65_536` (`-Clink-arg=--max-memory=67108864` and `wasmi::StoreLimits`).
- **Pre-poisoned traps and poisoning (`#19` R5):**
  In `wasm32-unknown-unknown` with `panic = "abort"`, any Wasm trap aborts execution immediately without unwinding or running Rust destructors or post-trap assignments, so setting a poison flag after a trap is unreachable. Instead, `grdr-wasm` enforces **pre-poison-on-entry**: every stateful or allocating export first checks `matches!(slot, InstanceSlot::TrapPoisoned)` (returning `GRDR_E_POISONED` and clearing `(result_ptr, result_len)` on `u32` exports, or dropping arena buffers with `TrapPoisoned` left sticky on `grdr_engine_free`), swaps `slot` to `InstanceSlot::TrapPoisoned` in linear memory via `core::mem::replace` BEFORE any allocation or `boundary` call, and restores `prev` (for handled errors such as `GRDR_E_RESOURCE`, `GRDR_E_PROFILE`, `GRDR_E_DECODE`, `GRDR_E_STATE`, `GRDR_E_ARG`, preserving `last-known-good`) or commits `next` (`Active(next)` / `Uninit`) only on clean return. Consequently, if any panic or `--max-memory` trap aborts mid-call, `InstanceSlot::TrapPoisoned` is already persisted in linear memory: both the `wasmi` host wrapper (`trap_poisoned`) and any direct raw `.wasm` consumer (such as EM-5 TypeScript or external embedders) see `GRDR_E_POISONED` (`9`) on every subsequent call, never reading partial state. Re-instantiating a clean Wasm module and calling `grdr_engine_restore` resumes from the last snapshot, while `grdr_engine_free` on an unpoisoned handle returns `InstanceSlot` to `Uninit` for reuse.

### 6. Dependencies and build gates (R5)

#### R5 (a). WebAssembly runtime dev-dependency for `grdr-wasm`
**Decision:** Admit `wasmi = "=2.0.2"` (`default-features = false, features = ["stable", "std", "validate", "auto-dispatch"]`) strictly as a `[dev-dependencies]` entry of `crates/grdr-wasm/Cargo.toml` through its protected `supply-chain/admissions.toml` / `Cargo.lock` item. Never add `wasmi` to `[dependencies]` of any workspace crate (`ARCH-001`, verified by `cargo metadata` / `grdr-archlint`).

Verified evidence gathered against `crates.io`, `osv.dev` and the repository's `deny.toml` / `rust-toolchain.toml` (`1.99.1`):

| Criterion | Verified `wasmi = "=2.0.2"` fact | Note / mitigation |
|---|---|---|
| Licence | `MIT OR Apache-2.0` (`MIT/Apache-2.0` on crates.io) | Already in `supply-chain/licences.toml` permissive class and `deny.toml`; zero policy change |
| Pin and checksum | `2.0.2` (published `2026-11-19T14:25:11Z`) | SHA-256 `8762bb61dfbcfdbe0ab1a783a73d26d5149809cf7d882c9c9b76b7c0fb9417de`, MSRV `1.86` |
| Yank / OSV advisories | Not yanked; 0 OSV advisories (`api.osv.dev/v1/query`) | `2.0.0` and `2.0.1` are yanked; `2.0.2` is the current non-yanked release |
| `cargo deny` probe | Exited `0` (`advisories ok, bans ok, licenses ok, sources ok`) | Tested against repository `deny.toml` on toolchain `1.99.1` with `hash-collections` off |
| Closure size | 21 total packages (`wasmi`, `wasmi_core`, `wasmi_ir`, `wasmi_collections`, `wasmparser 0.228.0`, `spin 0.9.9`, `string-interner 0.19.0`, `foldhash`, `bitflags`, `libm`, `indexmap`, `hashbrown`, `equivalent`, `serde*`, `syn`, `proc-macro2`, `quote`, `unicode-ident`) | `wat` is disabled (`wat = optional`); `wasmparser` is `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` (satisfied by `Apache-2.0`/`MIT`). Zero `libc`, `rustix`, `windows-sys`, `cranelift` or JIT allocation crates |
| Maintainers & `unsafe` | `crates.io` owner: `Robbepop`; `build.rs` reads `OPT_LEVEL` / `CARGO_CFG_*` only; `wasmi` contains `unsafe` dispatch/VM code (dev-only test host) | Single-maintainer risk (`docs/design/35` section 2.6) is mitigated because `wasmi` runs only in `crates/grdr-wasm/tests/` and never enters any shipped product binary |
| Cooldown (`docs/design/35` §2.6, S04) | `wasmi 2.0.2` published `2026-11-19T14:25:11Z`; `hashbrown 0.17.2` published `2026-11-22T01:08:02Z` | Under the 7-day major cooldown (`docs/team/05` S04), `wasmi 2.0.2` carries `not_before = "2026-11-26T14:25:11Z"`; `hashbrown 0.17.1` already in `admissions.toml` satisfies `indexmap ^2.14.2` (or `0.17.2` carries `not_before = "2026-11-25T01:08:02Z"`). The consumer (`#19`) adds to `Cargo.lock` only after `not_before` clears |

Why `wasmi` over `wasmtime` (`51.0.0`, `Apache-2.0 WITH LLVM-exception`, `wasmtime-publish` / `github:bytecodealliance:wasmtime-publish`):
Although a `cargo-deny` probe showed `Apache-2.0 WITH LLVM-exception` satisfies `deny.toml`'s `Apache-2.0` allow-list entry, `wasmtime` pulls **104** transitive crates (`cranelift`, `pulley-interpreter`, `object`, `gimli`, `target-lexicon`, `libc`, `rustix`, `memfd`, `mach2`, `windows-sys`), allocates JIT executable pages in host tests, and brings native ISA backends irrelevant to checking core Wasm exports, empty imports via `Module::imports()` and byte-identical execution. Pure-Rust interpreter `wasmi` is 5x smaller (`21` vs `104` crates), portable across all three matrix OSes, and inspects empty imports cleanly in `wasm_imports`.

#### R5 (b). Header generation for `grdr.h`
No header generator crate or external tool is added. As decided by [RFC 0004](0004-c-header-generation-and-drift-check.md) (accepted on `#474`, recorded in [ADR-0034](../docs/decisions/ADR-0034-c-headers-are-generated-by-each-ffi-crates-drift-test.md)), `crates/grdr-ffi/tests/header_drift.rs` generates and checks `crates/grdr-ffi/include/grdr.h`, the layout source and `crates/grdr-ffi/src/grdr_abi.rs` using the internal workspace tool crate `grdr-cabi-testkit` (`#1778`), with zero third-party dependencies and zero licence changes.

#### R5 (c). C compiler for EM-4's C harness
**Decision:** Do **not** add the `cc` crate (`1.11.3`, `MIT OR Apache-2.0`) as a `dev-dependency` of `grdr-ffi`. Compile and execute EM-4's C harness as a **plain command step inside `.github/workflows/verify.yml`'s `c-headers` job** (`#1779`), following `ADR-0029` (no wrapper binary around Cargo or CI commands) and RFC 0004 Alternative (j):

- **Systems and compilers (matching `verify.yml` `plan` outputs and `#1779` R1):**
  - `ubuntu-26.04` (every PR, push to `main`, nightly schedule, `workflow_dispatch`): **`gcc`** and **`clang`**, with `-Wall -Wextra -Wpedantic -Werror -std=c99`.
  - `macos-26` (push to `main`, nightly schedule, `workflow_dispatch`): **Apple `clang`**, with `-Wall -Wextra -Wpedantic -Werror -std=c99`.
  - `windows-2025` (push to `main`, nightly schedule, `workflow_dispatch`): **`MSVC`** (`cl.exe`, located via `vswhere` and initialised via `vcvars64.bat`), with `/W4 /WX /std:c11`.
- **Execution mechanism:** Once `crates/grdr-ffi/include/grdr.h` and `crates/grdr-ffi/tests/c_harness.c` exist, the `c-headers` step builds `cargo build --locked --release -p grdr-ffi` (producing the `staticlib`), compiles `crates/grdr-ffi/tests/c_harness.c` with `-I crates/grdr-ffi/include` linking `grdr_ffi` (`staticlib`) for each system's compiler(s) above, and runs the harness binary against every vector under `crates/grdr-core/tests/vectors/engine/`.
- **Why not `cc` as a `dev-dependency`:**
  1. `#1779` Step 1 (`RFC 0004` section 7) explicitly forbids `custom-build` (`build.rs`) targets on `grdr-ffi`, so `cc` cannot run in its intended `build.rs` environment without inventing non-standard Cargo environment variables inside integration tests.
  2. Running C compilation inside `cargo test --locked -p grdr-ffi` forces every workstation running `cargo test --workspace --locked` to have a working C toolchain installed (`vcvars64.bat` / SDK on Windows, Xcode tools on macOS, `cc` on Linux) and compiles with only a single arbitrary compiler instead of both `gcc` and `clang` on Linux.
  3. Keeping `cargo test --locked -p grdr-ffi ffi_vectors` pure Rust (calling the exported `#[unsafe(no_mangle)] extern "C" fn grdr_*` ABI entry points directly) while running the real C source harness in `c-headers` tests the genuine C header across all four compilers cleanly with zero added `Cargo.lock` or `supply-chain/admissions.toml` crates (`cc`, `find-msvc-tools`, `shlex`, optional `jobserver`/`libc`). `#388` AC-1 and Plan step 4 are updated accordingly.

### 7. Conformance vector layout and cross-target determinism
All three targets (`engine_vectors` in `grdr-core`, `ffi_vectors` + `c_harness.c` in `grdr-ffi`, `wasm_vectors` in `grdr-wasm`) consume shared immutable fixtures committed under `crates/grdr-core/tests/vectors/engine/`:

```text
crates/grdr-core/tests/vectors/engine/
  README.md
  01-event-step/
    vector.toml
    host_profile.json
    host_profile.binpb
    load_report.binpb
    step_01_input.json
    step_01_input.binpb
    step_01_output.binpb
    interest.binpb
  02-tick-step/
    ...
  03-snapshot-restore/
    ...
  04-malformed-and-errors/
    ...
```

Rules for the vector directory (`#384` R10-R11, `#388` AC-1, `#19` AC-1):
1. **`README.md`** documents the `vector.toml` schema and the exact offline regeneration command using the pinned `buf` binary (`supply-chain/build-tools.toml`): `buf convert proto --type grdr.embed.v1alpha1.<Msg> --from <msg>.json --to <msg>.binpb`.
2. **`vector.toml` fields** (parsed with the already-admitted `toml` + `serde` dev-dependencies, requiring zero new JSON crates in shipped code and zero shelling out to `buf` inside `cargo test --workspace --locked` per RFC 0006 W1):
   - `bundle_hex` (hex-encoded bundle bytes) and `bundle_sha256` (64 lowercase hex chars; tests verify `bundle_sha256 == SHA-256(bundle)`).
   - `host_profile_bin = "host_profile.binpb"` and `expected_load_status = "GRDR_OK" | ...`, `load_report_bin` (when `GRDR_OK`).
   - Ordered `[[step]]` entries: `seq`, `op = "step" | "interest" | "snapshot" | "restore"`, `input_bin`, `session_id` (for `interest`), `now_unix_ns` (`i64`), `entropy_hex` (64 hex chars = `[u8; 32]`), optional `initial_step_seq` / `state_bin` (for `snapshot`/`restore`/overflow vectors), `expected_status` (`GRDR_OK` or status name), and `expected_out_bin` (`Output`, `InterestSet` `GRDI` binary, or `EngineState`).
3. **Minimum vectors (`#384` R10):** at least one vector exercising (a) an `Event` `Input` + `interest`, (b) a `Tick` `Input`, (c) mid-sequence `snapshot` and `restore` onto a fresh `Engine` instance followed by continued `step` plus wrong-bundle `restore` failure, and (d) malformed `Input` bytes (`GRDR_E_DECODE`, snapshot unchanged after error), empty `host_id` (`GRDR_E_PROFILE`), and `step_seq` overflow (`GRDR-CORE-0001`).
4. **Oracle independence:** Expected `.binpb` files are built from hand-written `proto3` JSON via pinned `buf convert`; expected `Output` payloads match `step_id` computed by calling `grdr_model::StepId::mint(now, entropy)` directly with the step's deterministic seeded `Entropy` (`section 3`). `grdr-ffi` and `grdr-wasm` read `crates/grdr-core/tests/vectors/engine/` read-only and never write there.

### 8. Stability classes and `surfaces.toml` (R6)
Every new public surface introduced or governed by this RFC starts **`experimental`** (`D-60`, `docs/design/03` section 7, `ADR-0020`). Nothing moves to `beta` or `stable` before an external embed pilot completes (`D-60`).

Because `surfaces.toml` is a protected trust-core path (`security/trust-core.paths`, `D-63`, `ADR-0020`), **no change is made to `surfaces.toml` in this RFC's pull request**. Upon acceptance of RFC 0014, a dedicated `surfaces.toml` trust-core follow-up issue (`#378` AC-3, modelled on `#1817` and `#1985`) adds:
- One `[[proto_package]]` row (following RFC 0006 R15):
  ```toml
  [[proto_package]]
  package = "embed.v1alpha1"
  class = "experimental"
  ```
- Two `[[crate]]` rows (following RFC 0005 R6.1):
  ```toml
  [[crate]]
  name = "grdr-ffi"
  class = "experimental"
  rfc = "0014"

  [[crate]]
  name = "grdr-wasm"
  class = "experimental"
  rfc = "0014"
  ```
Note that `grdr.h`'s `[[c_header]]` row (added by `#1817`) and `grdr-core`'s `[[crate]]` row (`class = "experimental"`, added by `#1915`) are already on `main`; `grdr-model`'s `[[crate]]` row is tracked by `#1985`. Per RFC 0005 R6.2 and RFC 0009 R3, stability classes are per crate, never per module, so `grdr_core::engine` and `grdr_model::VerifiedBundle` inherit `experimental` from their crates.

In addition, `security/trust-core.paths` currently lists `crates/grdr-ffi/**` under FFI boundaries while omitting `crates/grdr-wasm/**` and `crates/grdr-core/**`, which leaves `grdr-wasm` and Layer-1 `bundle_sha256` outside `.claude/risk-tiers.toml`'s `[trust_core]` rule (defaulting edits to `[medium]` without `eval-security`). Because `security/trust-core.paths` is a protected gate path (`AGENTS.md`), a dedicated follow-up issue worked by `lead-agent-kit` or the chief architect proposes adding `crates/grdr-wasm/**`, `crates/grdr-core/src/engine/bundle_sha256.rs` and `crates/grdr-core/src/engine/bundle_sha256/**` to `security/trust-core.paths` before `#384` and `#19` execute.

### 9. Failure modes and cross-cutting guarantees

| Condition | Core (`grdr-core`) outcome | C ABI (`grdr-ffi`) / Wasm (`grdr-wasm`) status | Engine / handle state after |
|---|---|---|---|
| Empty `host_id` or bad `HostProfile` bytes | `LoadError::Profile` (`GRDR-CORE-0002`) / `BoundaryError::DecodeProfile` (`GRDR-CORE-0008`) | `GRDR_E_PROFILE` (`5`) | Previous engine/profile unchanged; `Created` stays `Created` |
| Truncated / malformed `Input` or unset `Input.kind` | `BoundaryError::DecodeInput` (`GRDR-CORE-0006`) | `GRDR_E_DECODE` (`3`) | State and `step_seq` unchanged |
| Malformed `EngineState` or unknown `format_version` | `BoundaryError::DecodeState` (`0007`) / `LoadError::SnapshotFormat` (`0004`) | `GRDR_E_DECODE` (`3`) | Previous engine unchanged; `Created` stays `Created` |
| Snapshot from a different bundle (`bundle_digest` mismatch) | `LoadError::SnapshotBundle` (`GRDR-CORE-0003`) | `GRDR_E_STATE` (`8`) | Previous engine unchanged; `Created` stays `Created` |
| Out-of-order call on `Created` handle | Unconstructable in `grdr-core`; state check in bindings | `GRDR_E_STATE` (`8`) | Handle stays `Created` |
| Null pointer, short `struct_size`, non-32B entropy, invalid UTF-8 / `SessionId`, unowned non-empty Wasm span | `BoundaryError::Arg` (`GRDR-CORE-0005`) | `GRDR_E_ARG` (`1`) | Handle usable, state unchanged |
| `step_seq` overflow (`u64::MAX`) | `Output::Failed(StepFailure { error: StepSeqOverflow, .. })` (`GRDR-CORE-0001`) | `GRDR_OK` (`0`) returning encoded `Output` with `diagnostics` (`GRDR-CORE-0001`), `step_seq = 0`, `step_id = ""` | `Loaded` engine `step_seq` stays at `u64::MAX` |
| Failed `Entropy::fill` or pre-1970 `Timestamp` | `Output::Failed(StepFailure { error: Id(..), .. })` (`GRDR-MODEL-0003` / `0005`) | `GRDR_OK` (`0`) returning encoded `Output` with error `Diagnostic`, `step_seq = 0`, `step_id = ""` | Engine state and `step_seq` unchanged |
| Wasm `grdr_alloc`, copy headroom or `try_reserve_exact` exceeds `limits.toml` 64 MiB max (or FFI `try_reserve_exact` OOM) | n/a | `GRDR_E_RESOURCE` (`6`) (`grdr_alloc`, `grdr_engine_load`, `grdr_engine_restore`, result writes) | Instance remains usable; `last-known-good` / `Created` preserved without trapping |
| Internal bug / panic unwind across FFI or Wasm `panic = "abort"` / `--max-memory` trap | Checked error only (no panic path in `grdr-core`) | `GRDR_E_INTERNAL` (`10`) (FFI `catch_unwind`) or trap (`wasm32`) | Handle/instance stays `Poisoned` / `TrapPoisoned` (pre-poisoned on Wasm entry; later calls return `GRDR_E_POISONED` `9`) |

**Data classes (P8) and Assurance effect (P1):**
- No skeleton message or boundary function emits or logs content (`Output`, `LoadReport`, `EngineState`, `Diagnostic` and `HostProfile` hold only `identifier` and `structural` fields; `last_error` carries `Diagnostic` code/severity/rule id only and never echoes input bytes).
- Assurance effect: none in slice 0 (enforced verdict evaluation arrives in `#1861`).

### 10. Follow-up changes and issue write-backs
Upon decision of RFC 0014:
- **New follow-up issues to file on acceptance (not filed while in `State: Review`):**
  1. **`surfaces.toml` trust-core issue (`#378` AC-3):** Add `[[proto_package]] package = "embed.v1alpha1"` and `[[crate]]` rows for `grdr-ffi` and `grdr-wasm` (`experimental`, `rfc = "0014"`), blocked on RFC 0006 establishing `[[proto_package]]` (or split cleanly if RFC 0006 has not merged first).
  2. **Protected `security/trust-core.paths` item (`lead-agent-kit` / `chief-architect`, prerequisite for `#384` and `#19`):** Add `crates/grdr-wasm/**`, `crates/grdr-core/src/engine/bundle_sha256.rs` and `crates/grdr-core/src/engine/bundle_sha256/**` to `security/trust-core.paths` so `.claude/risk-tiers.toml` `[trust_core]` gates all FFI/Wasm `assume_verified` boundaries and Layer-1 FIPS 180-4 SHA-256.
  3. **Protected dependency & edge item (`lead-agent-kit`):** Add `[dependencies]` in `crates/grdr-core/Cargo.toml` (`grdr-proto`, `grdr-schema`, `grdr-model`, `grdr-fastpath`), `grdr-ffi` -> `{ grdr-core, grdr-model }`, `grdr-wasm` -> `{ grdr-core, grdr-model }`, and admit `wasmi = "=2.0.2"` in `supply-chain/admissions.toml` (honouring `not_before = "2026-11-26T14:25:11Z"`) and `crates/grdr-wasm/Cargo.toml` `[dev-dependencies]` + `Cargo.lock` (modelled on `#1984`).
  4. **Protected `limits.toml` item (`lead-agent-kit`, extending `#279`):** Add `[bound.embed] wasm-memory-max` = `67108864` bytes (`64 MiB`, owner `docs/design/26`), generating `grdr_schema::limits::EMBED_WASM_MEMORY_MAX`.
  5. **ADR-0041 Constraint 2e amendment RFC (`#388` prerequisite):** New RFC naming RFC 0008 and RFC 0009 defining the shared 32-byte seeded `Entropy` implementor (`ARCH-003` in `architecture.toml`) consumed by `engine::boundary` and `#384`'s vector seed harness before `#388` and `#19` are readied.
- **Required write-backs on existing issues before readying:**
  - **`#381`:** Specify `grdr.event.v1alpha1.Event` (not `Envelope`) for `Input.event` and `Output.events`; specify explicit RFC 0006 `DataClass` options on every field (section 2), `(wire_name)` on `Diagnostic.Severity` (`SEVERITY_INFO..ERROR`) and `StepId` (`stp_`) format for `step_id`.
  - **`#384`:** Expand write set to include `crates/grdr-model/src/id*` + `crates/grdr-model/tests/id_*` (or add `StepId` `stp_` ahead of `#384`) under RFC 0009 `ADR-0041` content rule; set `Trust core: yes` once `bundle_sha256.rs` enters `security/trust-core.paths`; keep `engine::boundary::{load, restore_bytes}` taking `&VerifiedBundle` with zero `assume_verified` calls in `grdr-core`; change `Input::Event(&Envelope)` / `Output.events` to `grdr.event.v1alpha1.Event`; adopt `Output::{Completed, Failed}` enum (ADR-0041 constraint 1d); add `InterestSet` `GRDI` v1 codec and pure FIPS 180-4 `bundle_sha256` (`crates/grdr-core/src/engine/bundle_sha256.rs`) verified against NIST FIPS 180-4 / SHAVS CAVP vectors in `crates/grdr-core/tests/` plus differential testing against `grdr-crypto`'s AWS-LC SHA-256 (`#337`) in `crates/grdr-crypto/tests/`; coordinate vector step `[u8; 32]` seeding with Constraint 2e.
  - **`#388`:** Update R2 to list the shared 12-row `grdr_status` block (`0..11`, including RFC 0005's `GRDR_E_CHANGED = 11`); keep R3 as `uint32_t struct_size` (base size `4`); perform bounded `Vec::try_reserve_exact` bundle copy + `engine::boundary::bundle_sha256` + `VerifiedBundle::assume_verified` at `grdr_engine_load` and `grdr_engine_restore` (`ARCH-012`), passing `&VerifiedBundle` to `engine::boundary` and returning `GRDR_E_RESOURCE` preserving `Loaded` / `Created` on OOM; integrate RFC 0004 section 15 (`grdr_abi.rs`, `header_drift`, `c_status!`, `as "char"`); add `[lib] crate-type = ["rlib", "staticlib"]` and `tests/c_harness.c`; update AC-1 / Plan step 4 so `cargo test --locked -p grdr-ffi ffi_vectors` calls exported `extern "C"` symbols in Rust while the C harness compiles and runs in `verify.yml` `c-headers`; keep ADR-0041 constraint 2e blocker. Also update `#1582` `ARCH-012` to admit `VerifiedBundle::assume_verified` outside tests strictly in `grdr-crypto`, `grdr-update`, `grdr-ffi` and `grdr-wasm` (forbidding calls in `grdr-core`).
  - **`#19`:** Confirm `grdr_alloc(len: u32) -> grdr_status` + `grdr_result_ptr()`/`grdr_result_len()` and signature table of section 5; isolate all implementation inside `mod safe_impl { #![forbid(unsafe_code)] ... }` under single-call `#[unsafe(no_mangle)]` wrappers gated by `#1751`'s `ARCH-027` AST enforcement (replacing the prior `#1582` citation); call `VerifiedBundle::assume_verified` solely at `grdr_engine_load` and `grdr_engine_restore` (`crates/grdr-wasm/**` covered by `security/trust-core.paths`); require pre-poison-on-entry `InstanceSlot::TrapPoisoned` across stateful exports; enforce `EMBED_WASM_MEMORY_MAX` + copy/decode headroom + `Vec::try_reserve_exact` on all copies/buffers with a hostile `33 MiB` `grdr_alloc` -> `grdr_engine_load` test asserting clean `GRDR_E_RESOURCE` preserving `last-known-good`; test `grdr_engine_interest(0, 0)` zero-length span acceptance explicitly; cite `wasmi = "=2.0.2"` as the WebAssembly runtime and `[bound.embed] wasm-memory-max` in `limits.toml`.
  - **`#1751` (`ARCH-027` in `grdr-archlint`):** Expand specification and tests so admitting `crates/grdr-wasm` under `[lints.rust] unsafe_code = "deny"` requires a `syn` AST check verifying `#![forbid(unsafe_code)]` on the inner implementation module (`mod safe_impl`), zero `unsafe {}` blocks, `unsafe fn`, `unsafe impl`, or `unsafe trait` anywhere in `crates/grdr-wasm/src/**/*.rs`, and `#[allow(unsafe_code)]` strictly on one-call `#[unsafe(no_mangle)] pub extern "C" fn` delegation wrappers, paired with a seeded failing fixture.
  - **`#246` (`spec/host-contract/c-abi.md` & `status-codes.toml`):** Note that `0.1` exports 13 functions (`compile_fastpath` arrives in `0.2` via `#1918`) and `grdr_engine_config` `0.1` base size `4` (`uint32_t struct_size`) ignores trailing bytes until EM-6; coordinate `GRDR_E_CHANGED = 11` (already specified by RFC 0005 section 13) and document `grdr_engine_interest`'s `GRDI` v1 wire format.
  - **`#1779` (`.github/workflows/verify.yml`):** Add the C harness step inside `c-headers` compiling `crates/grdr-ffi/tests/c_harness.c` against `include/grdr.h` and `grdr-ffi` `staticlib` across `gcc`, `clang` (`ubuntu-26.04`), Apple `clang` (`macos-26`) and `MSVC` (`windows-2025`), gated on `crates/grdr-ffi/include/grdr.h` and `tests/c_harness.c` existing so `#1779` does not fail before `#388` lands.

## Surfaces changed
- **`grdr.embed.v1alpha1` (new protobuf package, `experimental`, `proto/grdr/embed/v1alpha1/engine.proto`):** `Input`, `Tick`, `Output`, `Effect`, `Diagnostic` (`Severity`), `LoadReport` (`NotEvaluable`), `EngineState`, `HostProfile`.
- **`grdr-model` (`experimental`, public crate):** `VerifiedBundle` and `StepId` (`IdKind::Step`, `stp_`, `Uuid7`).
- **`grdr-core` (`experimental`, public crate):** `grdr_core::engine` (`Engine::{load, step, interest, snapshot, restore}`, `HostProfile`, `LoadReport`, `NotEvaluable`, `Input`, `Output`, `StepOutput`, `StepFailure`, `Effect`, `Diagnostic`, `Severity`, `InterestSet`, `StateSnapshot`, `LoadError`, `StepError`, `BoundaryError`) and `grdr_core::engine::boundary` (`&VerifiedBundle` entry points, `GRDI` v1 `InterestSet` wire frame, and `bundle_sha256` in `crates/grdr-core/src/engine/bundle_sha256.rs` proposed for `security/trust-core.paths`), plus `CORE` codes `GRDR-CORE-0001`..`0009`.
- **`grdr-ffi` (`experimental`, public crate, trust core):** 13 exported C ABI 0.1 functions and `grdr.h` (`grdr_engine_config` base size `4`, shared 12-code `grdr_status`), `HandleState::{Created, Loaded, Poisoned}`, bounded `VerifiedBundle::assume_verified` ingress, staticlib target and `tests/c_harness.c`.
- **`grdr-wasm` (`experimental`, public crate, proposed trust core):** 18 `wasm32-unknown-unknown` linear-memory exports wrapping a `#![forbid(unsafe_code)]` inner module (`#1751` `ARCH-027` AST enforcement), empty import section, pre-poisoned `InstanceSlot::TrapPoisoned`, bounded `VerifiedBundle::assume_verified` ingress, `limits.toml` 64 MiB maximum memory, `wasmi = "=2.0.2"` `dev-dependency`.
- **Gate / configuration / doc proposals (via their own follow-up items):** `surfaces.toml`, `security/trust-core.paths`, `limits.toml`, `architecture.toml`, `Cargo.toml` / `Cargo.lock`, `supply-chain/admissions.toml`, `schema/codes/`, `.github/workflows/verify.yml`, `spec/host-contract/c-abi.md` and `docs/design/26` section 3 (`#1988`).

## Alternatives
1. **Use `Envelope` directly instead of `Event` in `Input.event` and `Output.events` (rejected).** While `#381` and `#384` originally sketched `Envelope`, `#394` places all event payloads inside `Event { Envelope envelope = 1; }` (`2..15` payload `oneof`). Using `Envelope` on `grdr.embed.v1alpha1` would force a breaking retype (`RFC 0006` SL12) as soon as `#399` or detection needs payloads in `Engine::step`.
2. **Use `EventId` (`evt_`) for `step_id` instead of adding `StepId` (`stp_`) (rejected).** Reusing `EventId` conflates a step execution trace with emitted telemetry records (`D-06`, typed-id separation). Adding `Step` (`stp_`) via RFC 0009's one-row macro recipe gives `step_id` an unmistakable distinct prefix without changing `EventId`.
3. **Keep `alloc`, `realloc`, `free`, `alloc_ctx`, `memory_cap` and `step_budget` on `grdr_engine_config` in 0.1 (`docs/design/26` §3, rejected).** Without EM-6's allocator plumbing and rule evaluation counter, those fields would be silent no-ops (`P9`). Trailing extension behind `uint32_t struct_size` gives binary forward compatibility once EM-6 implements them.
4. **Represent `InterestSet` as a new `grdr.embed.v1alpha1` protobuf message instead of `GRDI` v1 binary tables (deferred / not chosen).** `docs/design/03` section 3 and `spec/host-contract/tables.md` section 3.5 treat interest sets as fixed-layout C/kernel-ready binary tables (`48/16/40/4` bytes), and `#378` R1 / `#381` exclude `InterestSet` from `engine.proto`. A fixed `GRDI` v1 header reuses `grdr_fastpath::layout` directly; if EM-7 later needs JSON/gRPC inspection of `InterestSet`, `EngineService` can wrap raw `bytes` or add an additive message then.
5. **Compute `bundle_digest` in `grdr-ffi` / `grdr-wasm` by passing `digest[32]` as a new C parameter, calling `assume_verified` inside `grdr-core`, or linking a SHA-256 crate (`rejected`).** Adding a parameter breaks `docs/design/26` section 3 and `c-abi.md`; placing `VerifiedBundle::assume_verified` inside `grdr-core` would let arbitrary Layer-4 callers bypass `grdr-crypto` verification (`ARCH-012`); linking a third-party hash crate in Layer 1 violates `ARCH-006` (`"Cryptography crates appear only under grdr-crypto"`). Exposing one unkeyed pure-Rust FIPS 180-4 content-digest helper (`engine::boundary::bundle_sha256` in `crates/grdr-core/src/engine/bundle_sha256.rs`, proposed as trust core and tested differentially against `grdr-crypto`) while keeping `VerifiedBundle::assume_verified` strictly inside `grdr-ffi` and `grdr-wasm` avoids any external crate, preserves `ARCH-012`, and yields byte-identical digests across native, C ABI and `wasm32`.
6. **Choose `wasmtime` (`51.0.0`) instead of `wasmi` (`2.0.2`) for `R5 (a)` (rejected).** `wasmtime` brings 104 transitive packages and JIT executable allocation vs `wasmi`'s 21 pure-Rust interpreter crates (`MIT OR Apache-2.0`).
7. **Choose the `cc` crate (`1.11.3`) as a `dev-dependency` of `grdr-ffi` for `R5 (c)` (rejected).** Conflicts with `#1779`'s ban on `custom-build` targets in `grdr-ffi`, forces every workstation running `cargo test --workspace` to configure a C compiler, and misses multi-compiler matrix coverage (`gcc` + `clang` on Linux, Apple `clang`, `MSVC`) that `verify.yml`'s `c-headers` job already runs.
8. **Solve ADR-0041 Constraint 2e inside this RFC (deferred).** `#378` does not charter amending RFC 0008 and RFC 0009; Constraint 2e explicitly binds `#388` to bring that dedicated amendment naming both RFCs and supplying its `ARCH-003` security analysis (`eval-security`, `eval-adversarial`, persona council) before `#388` is readied.

## Drawbacks
- **Pure-Rust FIPS 180-4 SHA-256 helper in Layer 1 (`crates/grdr-core/src/engine/bundle_sha256.rs`):** Although it links no crypto crate, never constructs `VerifiedBundle`, performs unkeyed content addressing only (never signature verification), and is gated as trust core (`security/trust-core.paths`) with CAVP vectors plus `grdr-crypto` differential tests, security review on `#384` and FIPS build review (`docs/design/03` section 8) must confirm whether unkeyed bundle hashing at the C/`wasm32` ingress is acceptable alongside `grdr-crypto` AWS-LC FIPS.
- **Edition 2024 `#[unsafe(no_mangle)]` attribute exception on `grdr-wasm`:** Requires narrowing `crates/grdr-wasm/Cargo.toml` from `unsafe_code = "forbid"` to `unsafe_code = "deny"` (`ARCH-027`), offset by placing all crate logic inside a `#![forbid(unsafe_code)]` inner module (`safe_impl`), enforcing AST checks in `#1751`, and bringing `crates/grdr-wasm/**` under `security/trust-core.paths`.
- **Two-part coordination before `#388` / `#19` execute:** `#388` and `#19` (and `#384`'s final `[u8; 32]` vector digests) must wait for the ADR-0041 constraint 2e amendment RFC (`RFC 0008` + `RFC 0009`), the `security/trust-core.paths` / `#1751` gate additions, and `wasmi 2.0.2` cooldown clearance (`2026-11-26T14:25:11Z`).
- **Two test steps for C ABI:** Running the real C harness in `verify.yml` `c-headers` rather than inside `cargo test -p grdr-ffi` keeps local contributor runs compiler-free, at the cost that C compiler warnings/linkage failures appear in `c-headers` (still run on Linux `gcc` and `clang` on every PR) rather than offline `cargo test`.

## Unresolved questions
1. **FIPS mode (`docs/design/03` section 8) vs Layer-1 SHA-256 content hash:** Does an `embedded` + `fips` build permit `grdr-ffi` and `grdr-wasm` to derive the unkeyed `VerifiedBundle` content digest via `engine::boundary::bundle_sha256`, or should FIPS-mode `grdr_engine_load` require an updated minor `grdr_engine_load_with_digest` taking the host's FIPS-computed 32-byte digest? (Tracked for `#384` / `#246` security review; does not block slice 0.)
2. **Constraint 2e algorithm choice (`SplitMix64` vs 256-bit PRNG):** Left cleanly to `#388`'s dedicated Constraint 2e RFC amending RFC 0008 and RFC 0009 so `eval-security` and seat 5 evaluate the id list (`StepId`, slice-0/1 `Random128` kinds) directly there.
3. **`grdr-core::engine` sidecar / allocator error codes for EM-6 and EM-7:** EM-6 (`GRDR_E_RESOURCE` / `GRDR_E_BUDGET` triggers in `Engine`) and EM-7 (`EngineService`) will add their variants/codes cleanly behind `#[non_exhaustive]` in later items without altering 0.1 signatures.

## Review
Reviewed under ADR-0043 and `#378` AC-1 / AC-2 (`State: Review`) across Round 1 and Round 2 evaluation. Evaluators comment on `#378` opening with:
- `RFC file: <blob of rfcs/0014-engine-boundary-c-abi.md at the commit reviewed>`;
- `Proposed text: none`;
- `Base: a80859235e7a2a4444648d6fa8d389d78dde6be9`, the spine pin (`rfcs/pins.toml`);
- `read=<path>@<blob>` for every consulted file.

The decided file may differ from the reviewed blob only where [RFC 0001](0001-adopt-the-spine.md) ("Review binds the decision") permits (`State:`, `Decision record:`, review link lines and `## Decision`). Upon acceptance, the orchestrating session files the `surfaces.toml` trust-core follow-up issue under `#378` AC-3.

This text rests on these blobs at `origin/main` (`f83ea0f`) unless noted otherwise:
- `docs/design/00-decisions.md`: `a80859235e7a2a4444648d6fa8d389d78dde6be9` (SHA-256 `8f6ea876777c0121ecec068c0bc4cef45932be45c1c2aff4140712db1e06628d`);
- `docs/design/03-system-architecture-and-modularity.md`: `2f9e920f0ace798592876d5009909eb096e7e952`;
- `docs/design/04-event-model-and-schemas.md`: `e77880a12d2f42e715836a6da9598b86f33b20b0`;
- `docs/design/12-policy-engine.md`: `b432904799251eca1d931378a6094ca6ea8b08db`;
- `docs/design/24-deployment-and-packaging.md`: `8403bec8717c6ad5fbb42fd173d5bde1b176bb23`;
- `docs/design/26-embedding-oem-and-white-label.md`: `8d9327dce0ca530e065f06a8ed287dec664e1f5b`;
- `docs/design/30-open-source-governance-and-community.md`: `91f909de5f9ed9aaf6db0bbeb4641db16976adda`;
- `docs/design/35-product-security-programme.md`: `dbc3874d96f51415db2e91c340747dac77043c2d`;
- `docs/team/05-quality-gates-and-ci.md`: `661c45625ea6541fea6fd988c38d3a5bb3327c27`;
- `rfcs/0001-adopt-the-spine.md`: `353436cd2f9cff08037783ca66678c52cd7d6be4`;
- `rfcs/0004-c-header-generation-and-drift-check.md`: `1f998f42db6c6ea6640c55df0a655e450759340f`;
- `rfcs/0005-fastpath-rust-surface.md`: `4ad52380450ff611f274b4813a19a7f8e412eb7f`;
- `rfcs/0007-grdr-model-and-grdr-schema-slice-0-surface.md`: `0c0a6745f04888bec8ef2e718352549f47181201`;
- `rfcs/0008-clock-entropy-and-the-retry-executor.md`: `b4af2b007041e3abdf6f7439824662ea6f08c52d`;
- `rfcs/0009-grdr-model-slice-0-surface.md`: `4f36df6f0b2ce122d3b09d8109e83fb4720b1c68`;
- `rfcs/0010-code-tokens-before-the-token-check.md`: `43cbdb3c08933783ce089f4e768f55771f1e9607`;
- `surfaces.toml`: `2fa94d4fecd4cdb355bfdcaf8ebce42f5bacb57a`;
- `architecture.toml`: `60743ee6b3f532190237a499b236784bf3587e04`;
- `security/trust-core.paths`: `1577f6c967b91ce762681f61eca5bd9afbcd5538`;
- `.claude/risk-tiers.toml`: `596539ddb6dbe01a23102f8a73c17a26aafc066e`;
- `deny.toml`: `2d0457ff71ea5c9bba91de0a580cd80f650d1479`;
- `supply-chain/licences.toml`: `65338a382a81c1ac500c533e22fa6ee22397928d`;
- `supply-chain/admissions.toml`: `1b25c164ade9d313e80bd6286444e289062d7f1f`;
- `rust-toolchain.toml`: `0db1e4dbd35927dacbd08830b13d074ef1977f39`;
- `.github/workflows/verify.yml`: `04ab24c3610fe03156f9e52f8ef3536dbc114675`;
- `origin/issue/246` (`#246`, open): `spec/host-contract/c-abi.md` (`b147c9dbd81068cd0d95cad4813bfee5e702fe30`) and `spec/host-contract/status-codes.toml` (`abcaa9704974359cdf7fac76712263b7b6f6f74b`);
- `origin/issue/1848` (`#1848`, open RFC 0006): `rfcs/0006-grdr-common-v1alpha1-options-and-sp1-crates.md` (`b14eab1663615bbf8d6cbbebf86b027f6b08536a`).

Verdicts on `#378` are linked below, one per line.
- `eval-review` (`Google`, `Gemini 4 Carbon`, round 2 pass, 0 blockers / 0 majors, on `7672ed44b1ffbc0248ec75d5540fff5e39c4171c` at `8179245e5da4b5afcaa50285cb2a98cf1bc60e33`, `Proposed text: none`, base `a80859235e7a2a4444648d6fa8d389d78dde6be9`): https://github.com/416rehman/Guardrails/issues/378#issuecomment-7100039824
- `eval-security` (`Google`, `Gemini 4 Neon`, round 2 pass, 0 findings, on `7672ed44b1ffbc0248ec75d5540fff5e39c4171c` at `8179245e5da4b5afcaa50285cb2a98cf1bc60e33`, `Proposed text: none`, base `a80859235e7a2a4444648d6fa8d389d78dde6be9`): https://github.com/416rehman/Guardrails/issues/378#issuecomment-7100040484

## Decision
Accepted by the chief architect under D-61 on pre-acceptance reviewed RFC file blob `7672ed44b1ffbc0248ec75d5540fff5e39c4171c` (SHA-256 `e383c44034f22e644fefdd6c9752ba026c09681f021f5a59475aae023aad1c77`, PR #2049 revision 2 `8179245e5da4b5afcaa50285cb2a98cf1bc60e33` merged on `main` at `c4ea11666a4bcd47e6cb631bc8fdf77cc4d7b064`), against spine pin `a80859235e7a2a4444648d6fa8d389d78dde6be9` (SHA-256 `8f6ea876777c0121ecec068c0bc4cef45932be45c1c2aff4140712db1e06628d`). [ADR-0054](../docs/decisions/ADR-0054-engine-boundary-c-abi-adopted-by-rfc-0014.md) records the decision.

This RFC decides no pinned path of [`rfcs/pins.toml`](./pins.toml), so this section holds no decision line, `rfcs/pins.toml` stays unchanged, and no file enters `rfcs/evidence/` ([RFC 0001](./0001-adopt-the-spine.md), "RFC states"; [ADR-0036](../docs/decisions/ADR-0036-the-amended-spine-is-the-baseline-adopted-by-rfc-0001.md)). The accepted file differs from `7672ed44b1ffbc0248ec75d5540fff5e39c4171c` only in `State:`, `Decision record:`, the review link lines above and this `Decision` section.

### Reasons
1. **Fixes the `grdr.embed.v1alpha1` wire skeleton with strict `DataClass` and `StepId` rules (R1).** Adopts `grdr.event.v1alpha1.Event` (`#394`) in `Input.event` and `Output.events` so future payloads land additively without wire retypes, declares explicit `DataClass` (`IDENTIFIER` / `STRUCTURAL`, zero `content` embed-wrapper fields) and `(wire_name)` options across every field and `Diagnostic.Severity` variant, registers typed `StepId` (`stp_`) as content under RFC 0009, and rejects unset `Input.kind` at the boundary.
2. **Establishes the layer-1 `grdr_core::engine` boundary and confines `VerifiedBundle::assume_verified` (`ARCH-012`, R2).** Fixes the five `Engine` operations over `&VerifiedBundle`, types `Engine::step -> Output::{Completed, Failed}` under ADR-0041 constraint 1d so failed draws and `step_seq` overflow return typed failures preserving engine state, frames `InterestSet` in deterministic 28-byte-header `GRDI` v1 layout, registers `GRDR-CORE-0001`..`0009`, isolates pure checked-Rust FIPS 180-4 `bundle_sha256` in `crates/grdr-core/src/engine/bundle_sha256.rs` (proposed trust core, tested against NIST CAVP and `#337` AWS-LC), and keeps zero `assume_verified` calls inside `grdr-core` while gating the 32-byte seeded `Entropy` implementor behind a dedicated RFC (`#2083`, ADR-0041 constraint 2e).
3. **Aligns C ABI `0.1` (`grdr-ffi` / `grdr.h`) with RFC 0004, RFC 0005 and `#246` (R3).** Exports 13 functions (`compile_fastpath` moving to `0.2` via `#1918`), accepts departing from `docs/design/26` section 3 so `grdr_engine_config` carries `{ uint32_t struct_size; }` (base size `4`, deferring EM-6 fields behind `struct_size`), renders the shared 12-code `grdr_status` block (`0..11` including `GRDR_E_CHANGED = 11`) through `grdr-cabi-testkit`, and enforces explicit `HandleState::{Created, Loaded, Poisoned}`, bounded `try_reserve_exact`, `catch_unwind` poisoning and `staticlib` C harness linkage.
4. **Secures `wasm32` exports (`grdr-wasm`) behind `#![forbid(unsafe_code)]`, pre-poisoning and bounded memory (R4).** Exposes 18 exports with an empty import section, uses `grdr_alloc(len) -> grdr_status` + `grdr_result_ptr()`/`grdr_result_len()` and `(0, 0)` / `len == 0` span semantics (`grdr_engine_interest(0, 0)`), pre-poisons `InstanceSlot::TrapPoisoned` on entry across `panic = "abort"` / `--max-memory` traps, enforces `EMBED_WASM_MEMORY_MAX` (`64 MiB` from `limits.toml`, `#2082`) + headroom + `Vec::try_reserve_exact` (verified by a hostile `33 MiB` `GRDR_E_RESOURCE` test), and isolates 100% of logic in `mod safe_impl { #![forbid(unsafe_code)] ... }` enforced by `#1751`'s `ARCH-027` AST gate and `security/trust-core.paths` (`#2079`).
5. **Applies least-privilege dependency and CI choices with two-model review passing (R5, R6).** Admits pure-Rust `wasmi = "=2.0.2"` strictly in `grdr-wasm` `[dev-dependencies]` subject to its `not_before = "2026-11-26T14:25:11Z"` cooldown (`#2080`), reuses RFC 0004 (`grdr-cabi-testkit`) for `grdr.h` with zero added crates, runs the C harness inside `verify.yml` `c-headers` (`#1779`) across `gcc`, `clang`, Apple `clang` and `MSVC` instead of adding `cc`, routes `experimental` `surfaces.toml` entries through `#2078` (`#378` AC-3) and `security/trust-core.paths` through `#2079`, and rests on passing round-2 two-model verdicts under [ADR-0043](../docs/decisions/ADR-0043-lean-token-optimised-agent-team.md) and [`.claude/risk-tiers.toml`](../.claude/risk-tiers.toml) (`eval-review` on `Google` / `Gemini 4 Carbon`, `issuecomment-7100039824`, 0 blockers/0 majors; `eval-security` on `Google` / `Gemini 4 Neon`, `issuecomment-7100040484`, 0 findings) alongside all 17 green CI checks on `8179245e5da4b5afcaa50285cb2a98cf1bc60e33`.

### Follow-up items and write-backs
- **Filed on acceptance:** `#2078` (`surfaces.toml` trust-core `[[proto_package]]` `embed.v1alpha1` and `[[crate]]` `grdr-ffi` / `grdr-wasm` `experimental` rows, `#378` AC-3), `#2079` (`security/trust-core.paths` entries for `crates/grdr-wasm/**` and `crates/grdr-core/src/engine/bundle_sha256*`), `#2080` (workspace path edges and `wasmi = "=2.0.2"` admission strictly after `not_before = "2026-11-26T14:25:11Z"` clears), `#2082` (`limits.toml` `[bound.embed.wasm-memory-max]` = `67_108_864` bytes via `#279`), `#2083` (ADR-0041 constraint 2e amendment RFC naming RFC 0008 and RFC 0009 before `#388` and `#19`), and `#2084` (`docs/design/26` section 3 and `docs/design/03` sections 3 and 7 sync coordinated with `#1988`).
- **Downstream write-backs (to post on merge):** `#381`, `#384`, `#388`, `#19`, `#1751`, `#1582`, `#1779`, `#246`, `#337`, `#278`, `#279`, `#1853`, `#1985`, `#1988`, `#1861` and `#1918` as listed in [ADR-0054](../docs/decisions/ADR-0054-engine-boundary-c-abi-adopted-by-rfc-0014.md#follow-up-items-and-downstream-write-backs).
