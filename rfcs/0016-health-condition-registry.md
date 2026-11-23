RFC: 0016
Title: Health condition registry, generated grdr-schema health module, first-run codes and #675 reconciliation
Author: chief-architect
Harness: Antigravity
Model: Gemini 4 Neon (pro)
State: Accepted
Design issue: #668
Spine: P1, P8, P9, P14, P17, D-15, D-37, D-48, D-52, D-59, D-60, D-61, D-63, D-68, D-69 (no spine text changes)
Surfaces: schema/health.toml; public crate `grdr-schema` (layer 0) module `health` (`HealthCode`, `HealthEntry`, `HealthSeverity`, `HealthScope`, `HealthSurface`, `ConditionStatus`, `ConditionState`, `Retirement`, `ALL`, `ACTIVE`, `find`, and active `HealthCode` constants); language-token ids `health.<code>.{meaning,cause,fix}` (`interface/strings/src/health.mf2.toml`) and docs anchor `codes/<code>`. As amendments: RFC 0007 sections 2 R10, 4 and 8 (source file layout, `layout` test, `trust-core` lines and base-build `history`). As proposals: docs/design/11 section 11, Interfaces table and Extension points; docs/design/34 reference labels; `#675`/`#1687` health lane boundary (`health.sensor` vs condition registry). No dependency, wire format, Cedar schema or same-layer edge changes
Decision record: docs/decisions/ADR-0050-health-condition-registry-adopted-by-rfc-0016.md

## Summary

This RFC establishes the single authoritative health condition registry at `schema/health.toml`, the generated layer-0 Rust module `grdr_schema::health` in [`crates/grdr-schema`](../crates/grdr-schema/Cargo.toml), the eleven initial first-run condition entries (from [design/11](../docs/design/11-endpoint-engineering.md) section 11, `#427`, `#1538`, and `#1673`), the "Content, not surface" rule for adding later conditions, and the boundary reconciling this registry with `#675` (`EN-DOC04`, moving `health.sensor` to `decision, A` emitted on change only).

Once this RFC is accepted and its lead-core item (`Item 1`) lands, `#147` (`HealthSet`), `#149`, `#421`, `#427`, `#1538`, `#1673`, `#1636` (`/codes/<code>` pages, paired with source tokens from `Item 2`), `#1644` (endpoint runbooks), and `#476` (`spool-unwritable` in its own RFC) consume one typed registry with zero ad-hoc condition strings.

## Motivation

[Design/11](../docs/design/11-endpoint-engineering.md) section 11 states that daemon health is a set of named conditions mapped to device surface states (`Protected`, `Degraded`, `Safe mode`) plus the independent flag `Stale`, and names `grdr-schema/health.toml` as the registry holding codes, severities, surface mappings, `stale` flags, and `health.<code>.*` language tokens. Without a formal specification for that registry and its generated Rust surface:

1. `#147` cannot make an unregistered health condition a compile error (`HealthSet::raise`) or enforce fixed severity, scope kinds, surface mapping, and `stale` flags from registry data rather than call-site parameters.
2. First-run path items (`#149`, `#421`, `#427`, `#1538`, and `#1673`) lack frozen canonical names and severities, including the three key-custody and fail-safe publish conditions `#1673` R3 and R6 raise.
3. `#1636` (`grdr-docgen codes`), `#1644` (runbooks for `degraded` and `critical` conditions), and `#1629` (`docs-check` checks `F2` and `F7`) have no schema path, grammar, or token convention to read.
4. `design/11` places the registry path at `grdr-schema/health.toml` and requires a fresh RFC per code, conflicting with the `schema/` repository layout and "Content, not surface" model established by [RFC 0007](./0007-grdr-model-and-grdr-schema-slice-0-surface.md). Meanwhile `#675` (`EN-DOC04`) clarified how `health.sensor` moves onto the `decision` lane alongside periodic heartbeat reporting (`design/22`) and `bulk` roll-ups, requiring an explicit boundary so telemetry events and condition codes never collide or duplicate vocabulary (P17).

## Design

### 1. Design reconciliation with `#675` (`EN-DOC04`) and telemetry lanes

This RFC freezes the architectural split between runtime daemon conditions (`schema/health.toml` / `grdr_schema::health`) and lane event records ([design/04](../docs/design/04-event-model-and-schemas.md) section 4, as ruled under `#675` and edited in `#1687`):

| Concept | Authoritative mechanism | Lane / store | Purpose |
|---|---|---|---|
| Condition codes (`HealthCode`) | `schema/health.toml` -> `grdr_schema::health` | Daemon `HealthSet` (`#147`), `status.pb`, `grdr doctor`, control-plane `Heartbeat` (`D-36`, [design/22](../docs/design/22-transport-fleet-and-updates.md)), `/codes/<code>`, `docs/runbooks/` | Fixed vocabulary of active and retired health conditions with compile-time checking, `severity`, `scopes`, `surface`, and `stale` |
| Sensor state transitions (`health.sensor`) | [design/04](../docs/design/04-event-model-and-schemas.md) §4 (`decision, A`) | `decision` lane, hash-chained, never sampled, never shed by the device | Emitted **on change only**: enforcement state change per action class, capability probe result, crash-loop ladder rung transition, slot-broker choice, going-down record, and resume. Never emitted on a timer |
| Periodic counters & health roll-ups | Control-plane `Heartbeat` (`design/22`) & `bulk` roll-ups | Control-plane uplink + `bulk` lane | Periodic condition summaries, queue depths, and loss counters without flooding `decision` |
| Sequence holes (`health.gap`) | [design/04](../docs/design/04-event-model-and-schemas.md) §4 (`decision, A`) | `decision` lane | Lane sequence gaps (`spool-drop`, `spool-full`, `recorder-expired`, `quota`, `crash`) |
| Could-not-look ledger (`health.coverage`) | [design/04](../docs/design/04-event-model-and-schemas.md) §4 (`bulk, A`) | `bulk` lane | Sensor omissions (`excluded`, `engine-overload`, `no-permission`, etc.) |

Rules following from this reconciliation:

1. `schema/health.toml` never registers telemetry event class names (`health.sensor`, `health.gap`, `health.coverage`) as condition codes, and `design/04` never defines duplicate condition registries outside `schema/health.toml` (P17).
2. A condition transition recorded by `#147`'s `HealthSet` (such as entering `engine-down`, `child-unresponsive`, `safe-mode`, `engine-sandbox-partial`, or `sandbox-violation`) updates device health state and, where design/11 sections 6 and 7 prescribe an auditable lane transition (ladder transitions, confinement changes, going-down/resume), emits `health.sensor` onto `decision, A` only on the state change itself (`#675`, `#1687` R3).
3. Timer-driven emission of `health.sensor` is prohibited; periodic health reporting remains in `design/22` heartbeats and `bulk` roll-ups.

### 2. Location, crate layout, and relationship to RFC 0007

#### Registry and generated module paths (R2)

- **Registry path:** `schema/health.toml` (directly beside `schema/codes/`, inside `schema/**` owned by `squad:core`).
- **Facade module:** `crates/grdr-schema/src/health.rs` (exported from `crates/grdr-schema/src/lib.rs` as `pub mod health;`).
- **Registry definition module:** `crates/grdr-schema/src/health/registry.rs`.
- **Generated module:** `crates/grdr-schema/src/health/generated.rs`.
- **Generator module:** `crates/grdr-schema/tests/gen/health.rs` (sharing the `crates/grdr-schema/tests/gen/` harness introduced by `#278`).
- **Generator integration test target:** `crates/grdr-schema/tests/health_gen.rs`, declared explicitly as `[[test]]` in `crates/grdr-schema/Cargo.toml` (`autotests = false` remains in force per RFC 0007 section 2 R10).
- **Fixture directory:** `crates/grdr-schema/tests/fixtures/health/**`.
- **Token source file (R8):** `interface/strings/src/health.mf2.toml`.

#### Why `schema/health.toml` instead of `grdr-schema/health.toml`

[Design/11](../docs/design/11-endpoint-engineering.md) wrote `grdr-schema/health.toml` before [RFC 0007](./0007-grdr-model-and-grdr-schema-slice-0-surface.md) placed error registries under `schema/codes/`. Keeping all registry inputs under `schema/` aligns path ownership in `.claude/owners.toml` (`schema/**` belongs to `squad:core`, [design/03](../docs/design/03-system-architecture-and-modularity.md) section 11), keeps generated Rust separate from declarative TOML data (`crates/grdr-schema/src/health/generated.rs` vs `schema/health.toml`), and puts every registry read by `grdr-docgen codes` and `docs-check` (`F2`, `F7`) under `schema/`.

#### Proposed amendments to `docs/design/11` and `docs/design/34`

Because `#668` R2 requires listing exact `design/11` text to amend when adopting `schema/health.toml`:

1. **[Design/11](../docs/design/11-endpoint-engineering.md) section 11 (`**Health.**` paragraph):** change `"Codes live in grdr-schema/health.toml, each with its health.<code>.* language tokens (D-69)..."` to `"Codes live in schema/health.toml (and are exposed as grdr_schema::health), each with its health.<code>.* language tokens (D-69)..."`.
2. **[Design/11](../docs/design/11-endpoint-engineering.md) Interfaces table (`grdr-schema/health.toml` row):** change the `Interface` cell from `` `grdr-schema/health.toml` `` to `` `schema/health.toml` (`grdr_schema::health`) ``.
3. **[Design/11](../docs/design/11-endpoint-engineering.md) Extension points section:** change `"- **Health conditions** are added by RFC to health.toml with a code, severity rule and doctor text as language tokens (D-69)."` as specified in Section 6 below (`schema/health.toml` and "Content, not surface").
4. **[Design/11](../docs/design/11-endpoint-engineering.md) Work breakdown table (`EN-F1` row):** clarify `` `health.toml` `` as `` `schema/health.toml` ``.
5. **[Design/34](../docs/design/34-documentation-support-and-lifecycle.md) section 2 and Appendices tables:** clarify `` `health.toml` `` as `` `schema/health.toml` `` where appropriate.
6. **Consumer issue updates (tracked on acceptance):** `#147` (Spec, R2, R3, Mechanism, AC-2), `#476` (Problem, D1, Prerequisites), and `#1636` AC-2 (`--health crates/grdr-schema/health.toml` -> `--health schema/health.toml`) update their text to name `schema/health.toml`.

#### Amendments to RFC 0007

This RFC names [RFC 0007](./0007-grdr-model-and-grdr-schema-slice-0-surface.md) (decided by [ADR-0038](../docs/decisions/ADR-0038-the-grdr-model-and-grdr-schema-slice-0-surface-adopted-by-rfc-0007.md)) and amends three points to integrate `health` cleanly alongside `codes` and `limits`:

1. **RFC 0007 section 2 R10 (`crates/grdr-schema/src/` layout and `tests/construction.rs` `layout` test):**
   RFC 0007 fixed `crates/grdr-schema/src/` at seven files (`lib.rs`, `codes/*`, `limits/*`) and ADR-0038 Constraint 5 staged `#278` before `#279`. With `health` added, the complete source tree under `crates/grdr-schema/src/` becomes **ten files**:
   - `lib.rs`
   - `codes.rs`, `codes/registry.rs`, `codes/generated.rs`
   - `limits.rs`, `limits/registry.rs`, `limits/generated.rs`
   - `health.rs`, `health/registry.rs`, `health/generated.rs`
   The `layout` test in `crates/grdr-schema/tests/construction.rs` permits `lib.rs` plus the exact 3-file triplet (`<m>.rs`, `<m>/registry.rs`, `<m>/generated.rs`) for each registered module (`codes`, `limits`, `health`) whose `generated.rs` exists in the checkout, refusing any unexpected or extra source file. That lets `health` and `limits` land in either order without breaking `layout` in between.
2. **RFC 0007 section 8 (`security/trust-core.paths`):**
   Add the four hand-authored `health` mechanism and fixture paths alongside RFC 0007's twelve lines (leaving `crates/grdr-schema/src/health/generated.rs` **off** `security/trust-core.paths`, for the same reason `codes/generated.rs` and `limits/generated.rs` stay off it, while `Cargo.toml`, `src/lib.rs`, `tests/gen/**`, and `tests/construction.rs` are already listed):
   - `crates/grdr-schema/src/health.rs`
   - `crates/grdr-schema/src/health/registry.rs`
   - `crates/grdr-schema/tests/health_gen.rs`
   - `crates/grdr-schema/tests/fixtures/health/**`
3. **CI drift and base-build history (`#1943` alignment):**
   `#1943` R2 already discovers every `<module>` whose `src/<module>/generated.rs` exists and runs `cargo test --locked -p grdr-schema --test <module>_gen -- --exact drift`, so naming the test target `crates/grdr-schema/tests/health_gen.rs` with `drift()` integrates with `#1943` automatically. A companion hardened `pull_request_target` workflow (`.github/workflows/schema-health-history.yml`) runs base's `cargo test --locked -p grdr-schema --test health_gen -- --ignored history` on any PR changing `schema/health.toml` or `crates/grdr-schema/Cargo.toml`, reading base `crates/grdr-schema/Cargo.toml` for the crate `version` and head's `schema/health.toml` strictly as data under `#1943` R5's hardening rules.

### 3. Layer-0 and generator rules (RFC 0007 alignment)

Every constraint from RFC 0007 section 2 R1 to R11 applies identically to `grdr_schema::health`:

1. **Zero normal dependencies and `#![no_std]` purity:** `crates/grdr-schema` takes zero `[dependencies]`. `health` uses only `core` primitives (`#![no_std]`-compatible, no `alloc`, no I/O, no `std::time`, no `std::env`, no panic paths, and checked/saturating arithmetic under `#![deny(clippy::arithmetic_side_effects)]`).
2. **No `Display` implementation (R4):** No type in `grdr_schema::health` implements `core::fmt::Display`. `grdr-schema` has `renders = "none"`. Person-facing text resolves via `meaning_token()`, `cause_token()`, and `fix_token()`; structured machine/log names use `as_str()`.
3. **`wasm32` target readiness:** `health` compiles for `wasm32-unknown-unknown` with no target-specific `cfg`.
4. **Sealed construction (`Seal` pattern):** `crates/grdr-schema/src/health/generated.rs` defines `pub(super) struct Seal(());` with private inner field. Constructors in `registry.rs` (`HealthCode::new_sealed`, `HealthEntry::new_active`, `HealthEntry::new_retired`, `Retirement::new_sealed`) take `_seal: super::generated::Seal` and have `pub(super)` visibility. Consequently:
   - External crates cannot construct `HealthCode`, `HealthEntry`, `Retirement`, `ConditionState::Retired`, or any condition code value from a `&str`.
   - Even modules outside `health::generated` inside `grdr-schema` cannot instantiate `Seal(())`.
   - Active codes are obtained strictly via the generated `pub const` bindings (or `ACTIVE`). Raising an unregistered condition in `#147` fails to compile.
5. **Deterministic generation (`drift` and `regenerate`):**
   - `cargo test --locked -p grdr-schema --test health_gen -- --exact drift` parses `schema/health.toml`, generates bytes in memory, normalises CRLF input line endings identically to LF, and asserts exact byte equality with `crates/grdr-schema/src/health/generated.rs`. On mismatch it prints the first differing line number (1-based) and the regenerate instruction, never modifying any file.
   - `GRDR_SCHEMA_REGENERATE=1 cargo test --locked -p grdr-schema --test health_gen -- --ignored regenerate` writes `crates/grdr-schema/src/health/generated.rs` using LF line endings only, deterministic ASCII string escaping, entries sorted lexicographically by `code`, zero timestamps, and zero local checkout paths.
   - `line_endings` test verifies that CRLF-rewritten copies of `schema/health.toml` generate identical LF-only bytes and contain no `\r`.
6. **By-value parity and compile-fail tests (`tests/construction.rs`):**
   - `cases` verifies every `active` `HealthEntry` in `ALL` matches its named `pub const` `HealthCode` across every accessor (`as_str`, `severity`, `scopes`, `surface`, `stale`, `owner`, `meaning_token`, `cause_token`, `fix_token`, `anchor`), verifies `ALL` is sorted strictly by `code` bytes, verifies `ACTIVE` equals the active subset of `ALL`, verifies `HealthSeverity::VARIANTS` ordering matches `Info < Warn < Degraded < Critical`, and verifies via doctests in `src/health.rs` (`compile_fail`) that external crates cannot construct `HealthCode`, `HealthEntry`, `Retirement`, `Seal`, or resolve a string directly into a `HealthCode`.
   - No reader crate outside `crates/grdr-schema` (`#147`, `grdr-interface-gen`, etc.) needs to parse `schema/health.toml` to enumerate codes at runtime (`ALL` exposes every metadata field); build-time documentation/gate tooling (`#1636` `grdr-docgen codes`, `#1629` `docs-check`) reads `schema/health.toml` directly as specified by those items.

### 4. The `grdr_schema::health` Rust surface (R4)

#### `crates/grdr-schema/src/health.rs` (facade)

```rust
pub mod registry;
mod generated;

pub use generated::*;
pub use registry::{
    ConditionState, ConditionStatus, HealthCode, HealthEntry, HealthScope,
    HealthSeverity, HealthSurface, Retirement, find,
};
```

#### `crates/grdr-schema/src/health/registry.rs`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HealthSeverity {
    Info,
    Warn,
    Degraded,
    Critical,
}

impl HealthSeverity {
    pub const VARIANTS: &[Self] = &[Self::Info, Self::Warn, Self::Degraded, Self::Critical];

    pub const fn as_str(self) -> &'static str;
    pub const fn rank(self) -> u8;
    pub const fn requires_runbook(self) -> bool; // true for Degraded and Critical
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HealthScope {
    Device,
    Component,
    Collector,
    AgentInstance,
    ActionClass,
}

impl HealthScope {
    pub const VARIANTS: &[Self] = &[
        Self::Device,
        Self::Component,
        Self::Collector,
        Self::AgentInstance,
        Self::ActionClass,
    ];

    pub const fn as_str(self) -> &'static str;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HealthSurface {
    None,
    SafeMode,
}

impl HealthSurface {
    pub const VARIANTS: &[Self] = &[Self::None, Self::SafeMode];

    pub const fn as_str(self) -> &'static str;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConditionStatus {
    Active,
    Retired,
}

impl ConditionStatus {
    pub const VARIANTS: &[Self] = &[Self::Active, Self::Retired];

    pub const fn as_str(self) -> &'static str;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Retirement {
    retired_in: &'static str,
    replaced_by: Option<&'static str>,
}

impl Retirement {
    pub(super) const fn new_sealed(
        retired_in: &'static str,
        replaced_by: Option<&'static str>,
        _seal: super::generated::Seal,
    ) -> Self;

    pub const fn retired_in(self) -> &'static str;
    pub const fn replaced_by(self) -> Option<&'static str>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConditionState {
    Active,
    Retired(Retirement),
}

impl ConditionState {
    pub const fn status(self) -> ConditionStatus;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HealthCode {
    code: &'static str,
    severity: HealthSeverity,
    scopes: &'static [HealthScope],
    surface: HealthSurface,
    stale: bool,
    owner: &'static str,
    meaning_token: &'static str,
    cause_token: &'static str,
    fix_token: &'static str,
    anchor: &'static str,
}

impl HealthCode {
    #[allow(clippy::too_many_arguments)]
    pub(super) const fn new_sealed(
        code: &'static str,
        severity: HealthSeverity,
        scopes: &'static [HealthScope],
        surface: HealthSurface,
        stale: bool,
        owner: &'static str,
        meaning_token: &'static str,
        cause_token: &'static str,
        fix_token: &'static str,
        anchor: &'static str,
        _seal: super::generated::Seal,
    ) -> Self;

    pub const fn as_str(self) -> &'static str;
    pub const fn severity(self) -> HealthSeverity;
    pub const fn scopes(self) -> &'static [HealthScope];
    pub const fn allows_scope(self, scope: HealthScope) -> bool;
    pub const fn surface(self) -> HealthSurface;
    pub const fn stale(self) -> bool;
    pub const fn owner(self) -> &'static str;
    pub const fn meaning_token(self) -> &'static str;
    pub const fn cause_token(self) -> &'static str;
    pub const fn fix_token(self) -> &'static str;
    pub const fn anchor(self) -> &'static str;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HealthEntry {
    code: &'static str,
    severity: HealthSeverity,
    scopes: &'static [HealthScope],
    surface: HealthSurface,
    stale: bool,
    state: ConditionState,
    owner: &'static str,
    meaning_token: &'static str,
    cause_token: &'static str,
    fix_token: &'static str,
    anchor: &'static str,
}

impl HealthEntry {
    // Same private seal constructor split (`new_active`, `new_retired`) taking `super::generated::Seal`
    pub const fn as_str(&self) -> &'static str;
    pub const fn severity(&self) -> HealthSeverity;
    pub const fn scopes(&self) -> &'static [HealthScope];
    pub const fn allows_scope(&self, scope: HealthScope) -> bool;
    pub const fn surface(&self) -> HealthSurface;
    pub const fn stale(&self) -> bool;
    pub const fn status(&self) -> ConditionStatus;
    pub const fn state(&self) -> ConditionState;
    pub const fn owner(&self) -> &'static str;
    pub const fn meaning_token(&self) -> &'static str;
    pub const fn cause_token(&self) -> &'static str;
    pub const fn fix_token(&self) -> &'static str;
    pub const fn anchor(&self) -> &'static str;
}

/// Looks up metadata for any active or retired entry by wire code string.
/// Returns `&HealthEntry`, never a `HealthCode`, so callers cannot bypass
/// compile-time code constants to raise conditions.
pub const fn find(code: &str) -> Option<&'static HealthEntry>;
```

#### Derived string formats per entry `<code>`

- `meaning_token()`: `health.<code>.meaning` (example: `health.engine-down.meaning`)
- `cause_token()`: `health.<code>.cause` (example: `health.engine-down.cause`)
- `fix_token()`: `health.<code>.fix` (example: `health.engine-down.fix`)
- `anchor()`: `codes/<code>` (example: `codes/engine-down`, matching [design/34](../docs/design/34-documentation-support-and-lifecycle.md) section 6 and `#668` R4)

#### `crates/grdr-schema/src/health/generated.rs` shape

```rust
// Generated by `grdr-schema` health generator from `schema/health.toml`. Do not edit by hand.
// Regenerate: `GRDR_SCHEMA_REGENERATE=1 cargo test --locked -p grdr-schema --test health_gen -- --ignored regenerate`

use super::registry::{
    ConditionState, HealthCode, HealthEntry, HealthScope, HealthSeverity, HealthSurface,
};

pub(super) struct Seal(());

pub const CHILD_UNRESPONSIVE: HealthCode = HealthCode::new_sealed(
    "child-unresponsive",
    HealthSeverity::Degraded,
    &[HealthScope::Component],
    HealthSurface::None,
    false,
    "design/11",
    "health.child-unresponsive.meaning",
    "health.child-unresponsive.cause",
    "health.child-unresponsive.fix",
    "codes/child-unresponsive",
    Seal(()),
);
// ... one pub const per active entry ...

pub const ACTIVE: &[HealthCode] = &[
    CHILD_UNRESPONSIVE,
    // ... sorted by `code`
];

pub const ALL: &[HealthEntry] = &[
    // every active and retired entry, sorted by `code`
];
```

Notice two safety properties of separating `HealthCode` constants (`ACTIVE`) from `HealthEntry` (`ALL`):

1. Retired entries exist in `ALL` so historical logs, `status.pb` readers, `grdr-docgen codes`, and `find()` still decode their severity, retirement version, replacement code, tokens, and `/codes/<code>` link, yet no `pub const` `HealthCode` exists for a retired condition and `find()` never returns a `HealthCode`, preventing new daemon call sites from raising retired conditions.
2. `HealthCode` is `Copy`, `Eq`, `Ord`, `Hash`, and small (`&'static` fields + enums/bool), allowing `#147`'s `HealthSet` to key maps directly on `(HealthCode, Scope)` without allocating. `#147` validates `code.allows_scope(scope.kind())` using `allows_scope` (`#[cfg(test)]` / debug / explicit contract) and reads `code.severity()`, `code.surface()`, and `code.stale()` solely from `HealthCode`.

Note on enum ordering in `HealthScope`: `generated.rs` emits `scopes` slices in canonical enum order (`Device`, `Component`, `Collector`, `AgentInstance`, `ActionClass`) regardless of key order inside `schema/health.toml`, guaranteeing deterministic output while still accepting human-ordered arrays without duplicate values.

### 5. Registry format, entry keys, refusals, and history check (R3, R5)

#### `schema/health.toml` structure and entry keys (R3)

The file `schema/health.toml` is a UTF-8 TOML table containing only the `[[condition]]` array of tables (any unknown top-level key or non-table root is refused). Each `[[condition]]` table accepts strictly the following keys:

| Key | Type | Required | Grammar / allowed values |
|---|---|---|---|
| `code` | string | yes | Regex `^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$`, length 1 to 63 ASCII bytes inclusive (`<= 63`), globally unique across all entries (active and retired). Rust `const` name is `code` with `-` mapped to `_` and ASCII uppercased (`[A-Z][A-Z0-9_]*`), verified unique |
| `severity` | string | yes | One of `"info"`, `"warn"`, `"degraded"`, `"critical"` |
| `scopes` | array of strings | yes | Non-empty (`len >= 1`), duplicate-free set; each element in `"device"`, `"component"`, `"collector"`, `"agent-instance"`, `"action-class"` |
| `surface` | string | yes | One of `"none"`, `"safe-mode"`. If `"safe-mode"`, `severity` must be `"critical"` |
| `stale` | bool | yes | TOML boolean `true` or `false` |
| `status` | string | yes | One of `"active"`, `"retired"` |
| `owner` | string | yes | Regex `^design/[0-9]{2}$`, resolving to **exactly one** file matching `docs/design/<NN>-*.md` |
| `retired_in` | string | if `status = "retired"`; forbidden if `"active"` | Semver `MAJOR.MINOR.PATCH` (`0` or `[1-9][0-9]*` per component, no `v` prefix, no pre-release/build tag) |
| `replaced_by` | string | optional if `status = "retired"`; forbidden if `"active"` | Valid `code` differing from this entry's own `code`, resolving to an existing entry in `schema/health.toml` with no cycle across replacement links (a newly added link on retirement must target an `active` entry) |

#### Generator refusals (R3)

On any validation error, generation stops before opening or modifying `crates/grdr-schema/src/health/generated.rs`, exits non-zero, and prints a message naming:
1. the file (`schema/health.toml`),
2. the offending entry (`code` if present and string, else 1-based entry index `condition[i]` or `"top-level"`), and
3. the broken rule name and reason.

Every one of the following must be refused (each tested by an explicit fixture under `crates/grdr-schema/tests/fixtures/health/`):

1. Missing file, invalid UTF-8, or TOML syntax error.
2. Top-level value not a table, unknown top-level key, missing `condition`, `condition` not an array of tables, zero `[[condition]]` entries, or zero `status = "active"` entries.
3. Unknown key inside a `[[condition]]` entry.
4. Missing required key (`code`, `severity`, `scopes`, `surface`, `stale`, `status`, `owner`).
5. Wrong TOML type on any key (for example integer or boolean for `code`/`severity`/`surface`/`status`/`owner`/`retired_in`/`replaced_by`, string `"true"` for `stale`, string instead of array for `scopes`, non-string element inside `scopes`).
6. `code` breaks `^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$` (empty, leading digit, uppercase letter, underscore, leading/trailing/double hyphen), exceeds 63 bytes, or collides in Rust `SCREAMING_SNAKE_CASE`.
7. Duplicate `code` across any two entries (including active vs retired).
8. `severity` outside `{"info", "warn", "degraded", "critical"}`.
9. `scopes` empty (`[]`), contains an element outside `{"device", "component", "collector", "agent-instance", "action-class"}`, or contains duplicate scope elements.
10. `surface` outside `{"none", "safe-mode"}`, or `surface = "safe-mode"` combined with `severity != "critical"`.
11. `status` outside `{"active", "retired"}`.
12. Retirement rule errors:
    - `retired_in` or `replaced_by` present when `status = "active"`;
    - `retired_in` missing or failing `MAJOR.MINOR.PATCH` semver grammar when `status = "retired"`;
    - `replaced_by` malformed, equal to the entry's own `code`, missing from `schema/health.toml`, or forming a replacement cycle (`A -> ... -> A`). Static generation permits an existing retired entry's unchanged `replaced_by` to point to an entry that retired later so multi-step chains (`A -> B -> C`) stay valid.
13. `owner` breaks `^design/[0-9]{2}$`, resolves to zero `docs/design/<NN>-*.md` files, or resolves to more than one file.

#### Never-change rules and `history` check (R5)

Once an entry in `schema/health.toml` lands on `main`:

1. **No deletion:** Every `code` present in the base `schema/health.toml` must remain present in the head `schema/health.toml`.
2. **Immutable semantics:** `code`, `severity`, `scopes`, `surface`, and `stale` may never change on an existing entry (`scopes` compares as a mathematical set, independent of TOML array element ordering).
3. **One-way lifecycle:** `status` may move only from `"active"` to `"retired"`, never from `"retired"` back to `"active"`.
4. **Immutable retirement metadata and transition checks:** Once `status = "retired"`, neither `retired_in` nor `replaced_by` may change. On the transition from `"active"` to `"retired"`, `retired_in` must equal the `version` of `crates/grdr-schema/Cargo.toml` on the PR **base** (matching RFC 0007 section 4), and any `replaced_by` set on that transition must resolve to an entry whose status is `"active"` in the head `schema/health.toml` (preventing simultaneous `A <-> B` retirement cycles while preserving multi-step `A -> B -> C` chains).

Enforcement: `crates/grdr-schema/tests/health_gen.rs` provides `#[ignore] fn history()`, parallel to `codes_gen::history` of RFC 0007 section 4. In CI (`pull_request_target` on `.github/workflows/schema-health-history.yml`), CI checks out and builds **only** the base branch, reads `retired_in`'s expected `version` from base's `crates/grdr-schema/Cargo.toml`, reads head's `schema/health.toml` strictly as a bounded regular-file git blob (no symlinks, no submodules, capped count/byte budget), runs base's `history` test, and fails closed naming the offending entry `code` and broken R5 rule (or failing with `"could not look"` if either side cannot be read).

### 6. Rule for adding a later health condition (R6)

**Decision:** Adopt [RFC 0007](./0007-grdr-model-and-grdr-schema-slice-0-surface.md) section 4's **"Content, not surface"** rule rather than requiring a fresh RFC per condition code.

#### Rationale

- Adding an entry to `schema/health.toml` changes **no** public Rust type signature (`HealthCode`, `HealthEntry`, `HealthSeverity`, `HealthScope`, `HealthSurface`, `ALL`, `ACTIVE`), **no** wire encoding, **no** Cedar schema, and **no** never-change contract.
- Every downstream consumer (`HealthSet`, `grdr-docgen codes`, `grdr-interface-gen`, `docs-check` `F2`/`F7`) operates generically over the generated types and registry TOML. Requiring 25+ individual RFCs for remaining `design/11` §11 and `design/07` conditions would create empty ceremony without increasing design safety, while `schema/**` and `crates/grdr-schema/**` already undergo `tier:high` two-model evaluation (`eval-review` + `eval-security`), `drift`, `history`, token checks, and runbook checks (`F7`).
- Note that `#476` (`spool-unwritable`) still properly remains an RFC of its own because `#476` D2 to D4 also alter `design/11` section 3 receipt-ring guarantees and `health.gap` accounting (`spool-drop` / torn-tail sequencing), not merely because it adds a health code.

#### Requirements on any future item adding a health condition

1. **Registry & generation:** The item that first raises the condition adds its `[[condition]]` entry to `schema/health.toml`, regenerates `crates/grdr-schema/src/health/generated.rs`, updates consumer doc/code pages as required, and names `RFC: 0016` for `rfc-required`.
2. **Language tokens:** Once the `grdr-interface-gen` health token check is on `main` (Section 8, matching [RFC 0010](./0010-code-tokens-before-the-token-check.md) R1), the item either writes `health.<code>.meaning`, `health.<code>.cause`, and `health.<code>.fix` in `interface/strings/src/health.mf2.toml` itself (when its write set includes it) or is blocked by the `squad:interfaces` token item that writes them before merging. Before that check lands on `main`, the token item writes the tokens for every registered health condition on its merge base without holding up registry items.
3. **Reference page & runbook:** Every condition regenerates `/codes/<code>` via `grdr-docgen codes` (`docs-check` `F2`), and every `degraded` or `critical` condition adds its runbook under `docs/runbooks/` (`docs-check` `F7`) in the same pull request (or is gated by it).
4. **Risk lane:** Because `schema/**` and `crates/grdr-schema/**` are `high` in `.claude/risk-tiers.toml`, every such PR runs `eval-review` and `eval-security` on two distinct models/providers, plus CI `drift` and `history`.

#### Exact `design/11` extension-point amendment (R6)

Amend [docs/design/11-endpoint-engineering.md](../docs/design/11-endpoint-engineering.md) Extension points (bullet `"Health conditions"`):

- **Before:** `"- **Health conditions** are added by RFC to health.toml with a code, severity rule and doctor text as language tokens (D-69)."`
- **After:** `"- **Health conditions** are added to schema/health.toml under RFC 0016's \"Content, not surface\" rule by the item that first raises them, with their severity, allowed scopes, surface mapping, stale flag, three health.<code>.* language tokens (D-69), generated /codes/<code> page, and a runbook under docs/runbooks/ when severity is degraded or critical (design/34 F2, F7)."`

### 7. Initial slice-0 entries (R7, AC-3)

The initial `schema/health.toml` contains **exactly eleven active entries** raised by the first runnable path (`#149`, `#421`, `#427`, `#1538`, `#1673`), sorted by `code`:

| `code` | `severity` | `scopes` | `surface` | `stale` | `status` | `owner` | Source / consumer items |
|---|---|---|---|---|---|---|---|
| `child-unresponsive` | `degraded` | `["component"]` | `none` | `false` | `active` | `design/11` | [design/11](../docs/design/11-endpoint-engineering.md) §1, §11; `#149` R6, R10 (missed heartbeats; names child component) |
| `engine-down` | `degraded` | `["component"]` | `none` | `false` | `active` | `design/11` | [design/11](../docs/design/11-endpoint-engineering.md) §11; `#427` R5/R6; `#149` R3, R10 (engine exited or failed `Ready` deadline; floor answers) |
| `engine-restarting` | `degraded` | `["component"]` | `none` | `false` | `active` | `design/11` | [design/11](../docs/design/11-endpoint-engineering.md) §11; `#149` R7, R10 (child in backoff / restart cycle) |
| `engine-sandbox-partial` | `degraded` | `["component"]` | `none` | `false` | `active` | `design/11` | [design/11](../docs/design/11-endpoint-engineering.md) §2, §11; `#421` R6 (confinement report marks element missing or unverified) |
| `failsafe-publish-failed` | `degraded` | `["device"]` | `none` | `false` | `active` | `design/11` | `#1673` R6, R7 (fail-safe table sign, self-verify, or atomic publish failed; previous table retained) |
| `floor-missing` | `critical` | `["device"]` | `none` | `false` | `active` | `design/11` | `#427` R8; `#1538` R3 (no valid floor table available at start; every class fails closed `DENY`) |
| `persistent-key-corrupt` | `degraded` | `["device", "component"]` | `none` | `false` | `active` | `design/21` | `#1673` R1, R3 (device or local artefact key seed corrupt; never overwritten; signs/publishes nothing) |
| `persistent-key-unreadable` | `degraded` | `["device", "component"]` | `none` | `false` | `active` | `design/21` | `#1673` R1, R3, R4 (device or local artefact key seed unreadable or fails owner/mode/symlink check) |
| `safe-mode` | `critical` | `["device"]` | `safe-mode` | `false` | `active` | `design/11` | [design/11](../docs/design/11-endpoint-engineering.md) §6, §11; `#147` R5 (crash-loop ladder reached `Safe mode`; engine not started) |
| `sandbox-violation` | `critical` | `["component"]` | `none` | `false` | `active` | `design/11` | [design/11](../docs/design/11-endpoint-engineering.md) §2, §11; `#421` R7 (child killed by seccomp `SIGSYS` or job limit; tamper-class boundary breach) |
| `stale-bundle` | `warn` | `["device"]` | `none` | `true` | `active` | `design/11` | [design/11](../docs/design/11-endpoint-engineering.md) §8, §11; `#1538` Failure modes; `#147` R5 (compile/validation failed while previous valid table stays active) |

#### Critical design invariants verified by this seed set

1. **Surface-state orthogonality (`#147` R5 and AC-2):**
   - `safe-mode` is the **only** entry with `surface = "safe-mode"`, so raising it sets device surface state `Safe mode`.
   - `floor-missing` and `sandbox-violation` have `severity = "critical"` and `surface = "none"`, proving in `#147` AC-2 that `severity = "critical"` without `surface = "safe-mode"` produces `Degraded`, never `Safe mode`.
   - `stale-bundle` is the **only** entry with `stale = true` and uses `severity = "warn"`, `surface = "none"`, proving in `#147` AC-2 that raising `stale-bundle` alone yields surface state `Protected` with `Stale = true`.
   - All seven `degraded` entries yield `Degraded` with `Stale = false`.
2. **Explicit exclusions (non-goals of `#668`):**
   - `spool-unwritable` is **excluded** here; `#476` D1 adds it through its own RFC (alongside `#476` D2 to D4) once RFC 0016's lead-core item lands.
   - All non-first-run codes from `design/11` §11 (`engine-overload`, `deadline-misses`, `minimal-core`, `input-quarantined`, `stale-metadata`, `spool-shedding`, `disk-cap`, `recorder-short`, `collector-loss`, `collector-detached`, `slot-unavailable`, `dev-drive-uncovered`, `egress-blocked`, `uplink-offline`, `uplink-downgraded`, `clock-jump`, `clock-skew`, `egress-unlisted`, `authenticode-chain-untrusted`, `host-class-unpopulated`, `pack-store-full`, `update-pending`, `handover`, `budget-exceeded`) and `design/07` hook health states stay out of the slice-0 seed and enter later under Section 6 (`"Content, not surface"`).
3. **Key-custody error naming (`#1673` R3 & R6):**
   - `persistent-key-corrupt` and `persistent-key-unreadable` cover both persistent seeds (`device` key and `local-artefact` key) using `["device", "component"]` so `#1673` can qualify which persistent key component failed without overwriting the other key's condition in `HealthSet`, while allowing device folding under `#147` R6. Notice `owner = "design/21"`, which resolves to [docs/design/21-tenancy-keys-and-access.md](../docs/design/21-tenancy-keys-and-access.md).
   - `failsafe-publish-failed` covers both self-verification mismatch (`#1673` R7) and publish write/rename failure (`#1673` R6) on the fail-safe table set, retaining the previously published table.

### 8. Language tokens, generated docs, data classes, assurance effect, stability

#### Source-locale language tokens (R8)

- Each entry `<code>` maps deterministically to three tokens in **`interface/strings/src/health.mf2.toml`** (confirming `#668` R8 beside [RFC 0007](./0007-grdr-model-and-grdr-schema-slice-0-surface.md) section 4's `interface/strings/src/code.mf2.toml`):
  - `health.<code>.meaning`
  - `health.<code>.cause`
  - `health.<code>.fix`
- Every token obeys `grdr-interface-gen` rules (`#1613` R2): `desc`, `max` graphemes, `risk` (`normal` or `safety`), typed arguments (`product` from `brand/brand.toml` rather than hard-coded product literals), and explicit indication inside `health.<code>.fix` when no user command applies (`#1636` R3).
- **Sequencing and single-writer ownership (following [RFC 0010](./0010-code-tokens-before-the-token-check.md) R1 to R5):** `interface/strings/src/health.mf2.toml` belongs to `squad:interfaces` in `.claude/owners.toml`, so the `lead-core` registry item (`Item 1`) never writes it. Because `#1613`, `#1853`, and the health-condition token check sit behind `#448`, blocking `Item 1` on the `squad:interfaces` token item (`Item 2`) before the check exists on `main` would deadlock (`Item 2` compiles its check against `grdr_schema::health::ALL` from `Item 1`) and stall `priority:p0` first-run path items (`#147`, `#149`, `#427`, `#1538`, `#1673`). Applying RFC 0010's rule directly:
  - **Before the health token check is on `main`:** `Item 1` (`lead-core`) is blocked only by `#278`, never by `Item 2`. No check exists on `main` yet that fails for missing `health.mf2.toml` entries.
  - **When `Item 2` (`lead-interfaces`) lands:** `Item 2` is blocked by `Item 1` (and `#1613` / `#1853`), authors `health.<code>.{meaning,cause,fix}` in `interface/strings/src/health.mf2.toml` for every condition present in `grdr_schema::health::ALL` at its merge base with `main`, and adds the token coverage check (`Item 2` R2/R3). Both `Item 2` and any open PR adding to `schema/health.toml` enforce RFC 0010 R5 at merge time (`git fetch origin main` and `git merge-base --is-ancestor origin/main <head>` must exit 0) so no unregistered-token condition lands across the merge window.
  - **Once the health token check is on `main`:** Any later PR adding a condition to `schema/health.toml` either adds its three tokens inside the PR (with `.claude/owners.toml` write-set coordination) or is blocked by the `squad:interfaces` item that writes them first, so `grdr-interface-gen` never fails on `main` (`#668` R8).
- **Token check extension:** `Item 2` extends `grdr-interface-gen` (parallel to `#1853` R2) to iterate `grdr_schema::health::ALL` (every `active` entry, and every `retired` entry so `/codes/<code>` pages stay complete) and fail with `GRDR-IFG-*` naming the code when `meaning_token()`, `cause_token()`, or `fix_token()` is missing from `interface/strings/src/health.mf2.toml`.
- **Docgen & runbooks (`#1636`, `#1644`, `#1629`):**
  - `grdr-docgen codes --errors schema/codes --health schema/health.toml --out docs/product/reference/_generated/codes` reads `schema/codes`, `schema/health.toml`, and the source tokens to emit `/codes/<code>` pages (`F2`).
  - **Resolving `owner_squad` and `stability` cleanly (`#1636` R2):** `.claude/owners.toml` maps repository file globs (`schema/**` -> `squad.core`, while `docs/design/**` maps to `direction.chief-architect` rather than a squad, and design document headers carry free prose such as `Endpoint platform` or `platform`), not `design/NN` strings. Accordingly, if `#1636` assigns `owner_squad` from the registry file's `.claude/owners.toml` owner, all entries take `core` (`squad.core`). If instead `#1636` assigns semantic `owner_squad` per `owner` (`design/11`, `design/21`), it reads a declarative `design/NN -> squad.<id>` mapping table supplied as data (for example a `schema/design-owners.toml` table or docs-generator configuration mapping `design/11 -> endpoint`, `design/21 -> core` matching `.claude/owners.toml` `[squad.<id>]` names, with `#1636` R1/AC-2 adjusted if another input flag is passed), and reads `surfaces.toml` for `stability` (`experimental` for `grdr-schema`, with deprecation notice for `retired` conditions), never hard-coding `design/NN -> squad` rules in `grdr-docgen` source (P14, D-69).
  - `docs-check.mjs --check F7` (`#1629`) reads `schema/health.toml` and verifies every active `degraded` or `critical` condition (10 of the 11 seed entries; `stale-bundle` has `severity = "warn"`) has a matching runbook in `docs/runbooks/endpoint/<code>.md` (`#1644`).

#### Data classes (R9, P8)

- Every key in `schema/health.toml` and every field/return value in `grdr_schema::health` is `structural` public product metadata.
- Condition instance scope identifiers at runtime (such as an `agent-instance` id, or component/collector label stored inside `#147`'s `HealthSet`) never appear in `schema/health.toml` or `crates/grdr-schema`. Inside `#147` (`programs/grdr-daemon`), `agent-instance` scope IDs carry `data_class = identifier`, and `LogSafe` log lines emit scope kind (`HealthScope`) and condition `code` only (`#147` R7). Higher-layer `LogSafe` trait implementations (`grdr-model`, [RFC 0009](./0009-grdr-model-slice-0-surface.md)) may wrap `HealthCode`, `HealthSeverity`, `HealthScope`, `HealthSurface`, and `ConditionStatus` in `grdr-model` without modifying `grdr-schema`.

#### Assurance effect (R10, P1)

- None. `schema/health.toml` and `grdr_schema::health` provide condition metadata and compile-time code safety only; they change no `visibility`, `control`, `on_failure`, or `tamper` classification.

#### Stability class (`surfaces.toml`, [ADR-0020](../docs/decisions/ADR-0020-stability-classes-live-in-surfaces-toml.md))

- Following RFC 0007 section 11:
  - **Rust module API (`grdr_schema::health`):** sits under `[[crate]] name = "grdr-schema"` in [`surfaces.toml`](../surfaces.toml), whose crate stability class is **`experimental`** (`since = "0.1.0"`).
  - **Wire / registry semantics (`code` string, fixed `severity`, allowed `scopes`, `surface`, `stale`, and never-delete rule R5):** **`stable`** across releases from the moment a condition enters a released registry, enforced continuously by R5 and `history`.

### 9. Mechanisms and failure modes

- **Mechanism (P14):** Typed enum and sealed constant generation from declarative TOML (`schema/health.toml`) in a dev-only test harness (`crates/grdr-schema/tests/gen/health.rs` -> `crates/grdr-schema/src/health/generated.rs`), zero runtime parsing in `grdr-schema` or `grdr-daemon`, paired with `grdr-interface-gen` for text tokens and `grdr-docgen` / `docs-check` for reference pages and runbooks. No hard-coded condition lists or severities in consumer crates.
- **Failure modes:**

| Failure | Declared outcome | Visible as |
|---|---|---|
| Registry TOML fails any rule of Section 5 (`R3`) | Generator exits non-zero and writes nothing to `generated.rs` | Error naming `schema/health.toml`, entry (`code` or `condition[i]`), and broken rule |
| Committed `generated.rs` diverges from fresh generation | `cargo test --workspace --locked` and required `drift` CI step fail | First differing line number (1-based) and regenerate command |
| PR deletes an entry or mutates an immutable field (`R5`) | `pull_request_target` `history` job fails the PR | Error naming the offending `code` and R5 invariant |
| Base `history` workflow cannot read base or head blob | Job fails closed (never passes) | Output `"could not look"` naming the unreadable path or ref |
| Unregistered health condition referenced in `grdr-daemon` | Crate build fails | Rust compile error (`HealthCode` sealed; `#147` R2) |
| Missing `health.<code>.*` token in `interface/strings/src/health.mf2.toml` (once health token check is on `main`) | `grdr-interface-gen` fails before merge (or before that, written by `Item 2` across all codes on `main`) | `GRDR-IFG-*` finding naming condition `code` and missing token id |
| Missing runbook for `degraded` or `critical` code | `docs-check` `F7` fails docs CI | `F7` finding naming `code` and missing `docs/runbooks/` coverage |

### 10. Items filed on acceptance (R11)

When RFC 0016 transitions to `Accepted` with its `ADR-*` record:

1. **File `lead-core` implementation item (`Item 1`):**
   - **Write set:** `schema/health.toml`, `crates/grdr-schema/Cargo.toml`, `crates/grdr-schema/AGENTS.md`, `crates/grdr-schema/src/lib.rs`, `crates/grdr-schema/src/health.rs`, `crates/grdr-schema/src/health/**`, `crates/grdr-schema/tests/gen/health.rs`, `crates/grdr-schema/tests/gen/health/**`, `crates/grdr-schema/tests/health_gen.rs`, `crates/grdr-schema/tests/construction.rs`, `crates/grdr-schema/tests/fixtures/health/**`.
   - **Cites:** `RFC: 0016`.
   - **Blocked by:** `#278` (shared generator harness and `construction.rs` scaffold). Per [RFC 0010](./0010-code-tokens-before-the-token-check.md) R1 to R3, `Item 1` is **not** blocked by `Item 2` while the health token check is absent from `main`, so first-run path items proceed without waiting on the `#1613 -> #449/#1612 -> #448` chain.
2. **File `lead-interfaces` token item (`Item 2`, `R8`):**
   - **Write set:** `interface/strings/src/health.mf2.toml` and `grdr-interface-gen` coverage extension (`crates/grdr-interface-gen/**`).
   - **Blocked by:** `Item 1` (`grdr_schema::health::ALL` must exist to iterate and check), `#1613`, and `#1853`.
   - **Scope:** Author `health.<code>.{meaning,cause,fix}` for every registered health condition present at its merge base (starting with all 11 slice-0 entries, 33 source-locale tokens) with `Brand`/product parametrisation and explicit fix tokens, and wire `grdr-interface-gen` validation over `grdr_schema::health::ALL`. Enforces [RFC 0010](./0010-code-tokens-before-the-token-check.md) R5 (`git merge-base --is-ancestor origin/main <head>`) at merge time on `Item 2` and any concurrent `schema/health.toml` PR.
3. **File `lead-agent-kit` gate item (`Item 3`):**
   - **Write set:** `security/trust-core.paths`, `.github/workflows/schema-health-history.yml` (and `.github/workflows/verify.yml` if needed beyond `#1943`'s dynamic loop).
   - **Blocked by:** `Item 1` (so `main`'s base commit holds `schema/health.toml` and `health_gen` before the `pull_request_target` workflow executes) and `#1943`. Once landed, blocks subsequent PRs that add or retire conditions in `schema/health.toml`.
   - **Scope:** Add the 4 `health` mechanism/fixture lines to `security/trust-core.paths` (keeping `src/health/generated.rs` out) and add the hardened base-build `pull_request_target` `history` workflow.
4. **Update consumer issues and design documents:**
   - Apply [design/11](../docs/design/11-endpoint-engineering.md) amendments (`schema/health.toml`, extension point `"Content, not surface"`, `EN-F1` clarification) and check [design/34](../docs/design/34-documentation-support-and-lifecycle.md) path alignment (`#1687` carries `#675`'s `design/04` edit).
   - Re-point `blockedBy` on `#147`, `#476`, `#1636`, and `#1644` from `#668` to `Item 1` (`#668` R11 / AC-4), and request lead updates in `#147`, `#476`, and `#1636` AC-2 so every path reads `schema/health.toml` (and any `design/NN -> owner_squad` data table `#1636` reads).

## Surfaces changed

- **New data format & file:** `schema/health.toml` (`[[condition]]` keys `code`, `severity`, `scopes`, `surface`, `stale`, `status`, `owner`, `retired_in`, `replaced_by`) with 11 active slice-0 entries.
- **Public crate [`grdr-schema`](../crates/grdr-schema/Cargo.toml) (layer 0, `experimental`):** new public module `health` (`HealthCode`, `HealthEntry`, `HealthSeverity`, `HealthScope`, `HealthSurface`, `ConditionStatus`, `ConditionState`, `Retirement`, `ACTIVE`, `ALL`, `find`, and 11 `HealthCode` constants).
- **Language-token schema id contract:** `health.<code>.{meaning,cause,fix}` under `interface/strings/src/health.mf2.toml` (source text landed separately by `squad:interfaces`).
- **Docs anchor pattern:** `codes/<code>` (`/codes/<code>` pages emitted by `grdr-docgen codes`, `#1636`).
- **Amendments to RFC 0007:** source file count in `crates/grdr-schema/src/` expanded cleanly from 7 to 10 (`lib.rs` + `codes/*` + `limits/*` + `health/*`), incremental `layout` test check in `tests/construction.rs`, 4 additional lines in `security/trust-core.paths`, and `schema-health-history` workflow.
- **Proposed design edits (filed / updated on acceptance):** `docs/design/11-endpoint-engineering.md` (section 11, Interfaces table, Extension points, `EN-F1` row) and optional clarity in `docs/design/34-documentation-support-and-lifecycle.md`; `#675` boundary documented across `schema/health.toml` and `docs/design/04` (`#1687`).
- **Unchanged:** `docs/design/00-decisions.md` spine text, protobuf schemas (`proto/**`), Cedar schema, `Cargo.toml` normal dependencies, and `architecture.toml` crate edges.

## Alternatives

1. **Registry inside `crates/grdr-schema/health.toml` (literal reading of `design/11`):**
   Rejected. Mixing declarative TOML registries into Rust crate roots splits schema ownership away from `schema/` (`schema/codes/`), blurs `owners.toml` rules between crate code and schema data, and forces doc/CI tooling (`docs-check`, `grdr-docgen`) to scan inside `crates/` alongside generated outputs. `schema/health.toml` keeps all registries together under `schema/`.
2. **Require a fresh RFC for every health condition (literal reading of `design/11` Extension points):**
   Rejected. [RFC 0007](./0007-grdr-model-and-grdr-schema-slice-0-surface.md) already proved `"Content, not surface"` works better for stable registry schemas: once RFC 0016 locks the TOML grammar, generated Rust signatures, immutability rules, token checks, and `F2`/`F7` docs gates, adding a new condition code touches zero API surface while still going through `tier:high` review, `history`, `drift`, `grdr-interface-gen`, and runbook checks. RFCs remain reserved for behaviour/model changes such as `#476`.
3. **Allow `HealthCode::from_str(&str)` or keep string constants (`&str`):**
   Rejected. Runtime string resolution would fail `#147` R2's requirement that calling a condition outside the registry is a compile error, while allowing arbitrary `&'static str` literals fails both compile safety and registry authority (`#147` R3). Separating sealed `HealthCode` constants (`ACTIVE`) from metadata lookup (`ALL` and `find() -> Option<&'static HealthEntry>`) gives compile safety at raise sites and lossless reading for docs and retired status inspection.
4. **Emit periodic `health.sensor` heartbeats on `decision` instead of separating `health.toml` / `Heartbeat` / on-change `health.sensor` (`#675`):**
   Rejected per `#675` / `#1687`. Timer-based `health.sensor` traffic would bloat the un-shed hash-chained `decision` reserve, whereas keeping `health.sensor` on `bulk` risks shedding going-down and ladder transitions during disk pressure. Keeping `health.sensor` on `decision, A` strictly on change and moving periodic condition summaries / loss counters to `Heartbeat` (`design/22`) and `bulk` roll-ups satisfies D-22, D-36, D-37, D-52, D-68, and P17 cleanly.

## Drawbacks

1. Adding a third generated module to `crates/grdr-schema` requires updating RFC 0007's fixed 7-file `layout` assumption and extending `security/trust-core.paths` and base-build `history` workflows through `lead-agent-kit`. Making `layout` modular over whichever of `{codes, limits, health}` exist limits churn while preserving strict rejection of stray source files.
2. Requiring all 3 `health.<code>.*` language tokens (`interface/strings/src/health.mf2.toml`) and a runbook (`docs/runbooks/`) for `degraded`/`critical` codes once the checks land on `main` binds subsequent registry merges to coordination across `squad:core`, `squad:interfaces`, and docs/runbook owners (`#147`, `#1636`, `#1644`, `#1629`), and requires RFC 0010 R5 merge-base currency across the bootstrap window before `Item 2` lands.
3. Fixed `severity`, `scopes`, `surface`, and `stale` immutability under R5 means an overly narrow `scopes` slice or misclassified severity cannot be edited on a released `code`; changing it requires retiring that `code` (`replaced_by = "<new-code>"`) and introducing a clean replacement. Care in initial entries (especially `["device", "component"]` on persistent keys and non-safe-mode `critical` on `floor-missing` and `sandbox-violation`) mitigates this.

## Unresolved questions

None. Open operational policy choices from `#668` (registry path `schema/health.toml`, `"Content, not surface"` rule vs per-code RFCs, `#1673`'s three condition names, and the `#675` boundary) are proposed directly by this RFC for review and decision.

## Review

- **Spine check:** Verified against pinned [`docs/design/00-decisions.md`](../docs/design/00-decisions.md) in [`rfcs/pins.toml`](./pins.toml) (git blob `a80859235e7a2a4444648d6fa8d389d78dde6be9`, sha256 `8f6ea876777c0121ecec068c0bc4cef45932be45c1c2aff4140712db1e06628d`). Zero spine text changes are proposed (`State` vocabulary uses `Mode`, surface states `Protected`, `Degraded`, `Safe mode` + `Stale`, and no `case` object).
- **Route ([design/30](../docs/design/30-open-source-governance-and-community.md) section 3, [ADR-0043](../docs/decisions/ADR-0043-lean-token-optimised-agent-team.md), `#668` R1):** Persona council seats on `#668`, `eval-architecture` / `eval-review`, and a second evaluator (`eval-security`) on a distinct model/provider (`Provider:` and `Model:` recorded in every verdict), followed by chief architect decision with written reasons and no waiting period (owner instruction 7).
- **Review record links (populated on acceptance):**
  - `eval-review` (`Google`, `Gemini 4 Carbon`, Round 2, `pass`): https://github.com/416rehman/Guardrails/issues/668#issuecomment-7099935189
  - `eval-security` (`Google`, `Gemini 4 Neon`, Round 2, `pass`): https://github.com/416rehman/Guardrails/issues/668#issuecomment-7099935784

## Decision

Accepted by the chief architect on 2026-11-23 under `#1828` owner delegation (`D-61`, [ADR-0043](../docs/decisions/ADR-0043-lean-token-optimised-agent-team.md)), on reviewed RFC file blob `90aec1dd91c95a528302ebde29cfd1e77b62e48b` (SHA-256 `76e4364b46856def1fcd7244aaaa9730a815721dd70ac38a9852898bda89e7e0`, PR `#2041` head commit `29b5d444a953160440c9ef12d6f2bb0aa88405d1`, merged to `main` at `1771fa281fb1c55c51b961070e089e58095e5a88`), with the spine pin in force ([`rfcs/pins.toml`](./pins.toml)), blob `a80859235e7a2a4444648d6fa8d389d78dde6be9` (SHA-256 `8f6ea876777c0121ecec068c0bc4cef45932be45c1c2aff4140712db1e06628d`), as its base. [ADR-0050](../docs/decisions/ADR-0050-health-condition-registry-adopted-by-rfc-0016.md) records the decision.

This RFC decides no pinned path of [`rfcs/pins.toml`](./pins.toml), so this section holds no decision line, `rfcs/pins.toml` does not change, and no file is added under `rfcs/evidence/` ([RFC 0001](./0001-adopt-the-spine.md#design); [ADR-0036](../docs/decisions/ADR-0036-the-amended-spine-is-the-baseline-adopted-by-rfc-0001.md)). [RFC 0007](./0007-grdr-model-and-grdr-schema-slice-0-surface.md) is not edited directly; sections 2, 5 and 6 of this RFC state its amendments (RFC 0007 section 2 `R10` ten-file modular `layout`, section 4 `"Content, not surface"`, and section 8 four `health` lines on `security/trust-core.paths` and `schema-health-history.yml`). The accepted file differs from `90aec1dd` only in `State:`, `Decision record:`, the review link lines above and this `Decision` section.

### Reasons
1. **Single authoritative registry and layer-0 sealed surface (sections 2 to 5).** Placing the registry at `schema/health.toml` (`squad:core` in `.claude/owners.toml`) beside `schema/codes/` and generating `crates/grdr-schema/src/health/generated.rs` behind `generated::Seal(())` guarantees that external crates can construct `HealthCode` values only from active generated constants, read `severity`, `scopes`, `surface`, and `stale` solely from the registry (`#147` R2, R3), and keep `grdr-schema` `#![no_std]`, dependency-free, `Display`-free, panic-free, and `wasm32`-ready (`P8`, `P9`, `P14`, `P17`, `D-69`).
2. **Acyclic retirement, immutable semantics, and hardened base-build `history` (section 5).** Static generation enforces all 13 refusal classes and acyclic `replaced_by` chains while preserving multi-step `A -> B -> C` history; base-built `history()` reads expected `retired_in` from base `crates/grdr-schema/Cargo.toml` and head `schema/health.toml` as bounded regular-file data under `#1943` R5 (`contents: read`, fail-closed `"could not look"`).
3. **`"Content, not surface"` and RFC 0010 token sequencing (sections 6 and 8).** Following RFC 0007 section 4 lets future conditions join as `tier:high` content with `drift`, `history`, `grdr-interface-gen` tokens, `/codes/<code>` pages (`F2`), and `docs/runbooks/` coverage (`F7`), while applying [RFC 0010](./0010-code-tokens-before-the-token-check.md) R1 to R5 unblocks `#2056` (`Item 1`) ahead of `#2057` (`Item 2`, `#1613`, `#1853`).
4. **Eleven slice-0 seed conditions and `#675` telemetry boundary (sections 1 and 7).** Freezing the eleven initial entries verifies all surface-state branches (`safe-mode` alone sets `Safe mode`; `floor-missing` and `sandbox-violation` are `critical` with `surface = "none"`; `stale-bundle` is `warn` with `stale = true`; `#1673`'s three key-custody/publish codes are frozen; `spool-unwritable` stays `#476`'s RFC), while cleanly separating `schema/health.toml` conditions from on-change `health.sensor` (`decision, A`) and periodic `Heartbeat` / `bulk` roll-ups (`#675`, `#1687`).

### Review it rests on
On PR `#2041` (`29b5d444a953160440c9ef12d6f2bb0aa88405d1`, merged at `1771fa281fb1c55c51b961070e089e58095e5a88`), on reviewed RFC file blob `90aec1dd91c95a528302ebde29cfd1e77b62e48b` (`Proposed text: none`, against spine pin `a80859235e7a2a4444648d6fa8d389d78dde6be9` under [ADR-0043](../docs/decisions/ADR-0043-lean-token-optimised-agent-team.md) and [`.claude/risk-tiers.toml`](../.claude/risk-tiers.toml) `[checklist_addons].rfc`):
- `eval-review` (`Google`, `Gemini 4 Carbon`, Round 2, `pass`): https://github.com/416rehman/Guardrails/issues/668#issuecomment-7099935189
- `eval-security` (`Google`, `Gemini 4 Neon`, Round 2, `pass`): https://github.com/416rehman/Guardrails/issues/668#issuecomment-7099935784
- CI checks on PR `#2041` (`29b5d444a953160440c9ef12d6f2bb0aa88405d1`) and merge commit (`1771fa281fb1c55c51b961070e089e58095e5a88`): `verify`, `docs`, `scan`, `codeql`, and `fuzz` passed (`ClusterFuzzLite` skipped until fuzz targets exist).

Under `#1828` owner delegation (`issuecomment-7074036273`) and [ADR-0043](../docs/decisions/ADR-0043-lean-token-optimised-agent-team.md), the RFC is accepted on the first round in which both required distinct-model evaluators pass with no blocker or major, with no 9-seat persona council fan-out.

### Filed on acceptance
- `#2056` (`Item 1`, `lead-core`, `tier:high`, `trust-core`, `priority:p0`): `schema/health.toml` (11 slice-0 entries), `grdr_schema::health`, `health_gen`, modular `tests/construction.rs` `layout` & `cases`, refusal fixtures, and `crates/grdr-schema/AGENTS.md` steps (blocked by `#668` and `#278`; not blocked by `#2057` per RFC 0010).
- `#2057` (`Item 2`, `lead-interfaces`, `tier:medium`, `priority:p1`): `interface/strings/src/health.mf2.toml` (33 slice-0 tokens and all `ALL` entries at merge base) and `grdr-interface-gen` health token check with RFC 0010 R5 merge-base verification (blocked by `#2056`, `#1613`, `#1853`).
- `#2058` (`Item 3`, `lead-agent-kit`, `tier:high`, `trust-core`, `priority:p0`): four hand-authored `health` lines on `security/trust-core.paths`, `.github/workflows/schema-health-history.yml`, and `#1943` R2 `drift` integration (blocked by `#2056` and `#1943`).
- `#2059` (`chief-architect`, `kind:design`, `tier:low`, `priority:p2`): text amendments to `docs/design/11-endpoint-engineering.md` and `docs/design/34-documentation-support-and-lifecycle.md` (blocked by `#668`; `#1687` R3 already holds the `#675` `docs/design/04` edit).

### Downstream write-backs and dependency re-pointing
- Re-pointed `blockedBy` on `#147`, `#476`, `#1636`, and `#1644` from `#668` to `#2056` (`R11`, `AC-4`).
- Posted explicit RFC 0016 write-back and amendment notes on `#147` (`issuecomment-7099995415`), `#476` (`issuecomment-7099992578`), `#1636` (`issuecomment-7099990167`), `#1644` (`issuecomment-7099998608`), `#149` (`issuecomment-7099989642`), `#421` (`issuecomment-7099996006`), `#427` (`issuecomment-7099996519`), `#1538` (`issuecomment-7099997529`), `#1673` (`issuecomment-7099994630`), `#675` (`issuecomment-7099998096`), `#1687` (`issuecomment-7099992036`), `#278` (`issuecomment-7099991305`), `#1943` (`issuecomment-7099993303`), `#1629` (`issuecomment-7099990645`), and `#1853` (`issuecomment-7099994014`), recorded in [ADR-0050](../docs/decisions/ADR-0050-health-condition-registry-adopted-by-rfc-0016.md).
