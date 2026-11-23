RFC: 0012
Title: RFC 0008 amendment 1: a wall-clock time on ClassReading
Author: chief-architect
Harness: Antigravity
Model: Gemini 4 Neon
State: Accepted
Design issue: #1963
Spine: D-05, D-60, D-61, D-69, P8, P9, P17 (no spine text changes)
Surfaces: the public crate `grdr-ports` (layer 2), through `ClassReading` (`pub taken: Timestamp`), `RetryState::reading()` and `Clock::now()` (documented UTC semantics) in modules `retry` and `clock`, and the relative-duration rendering rule for `Breaker::Open`'s `until` across UI, CLI and console surfaces. No new crate, dependency, same-layer edge, protobuf wire format, error code, limit row or Cedar schema changes
Decision record: [docs/decisions/ADR-0047-clock-reading-timestamp-adopted-by-rfc-0012.md](../docs/decisions/ADR-0047-clock-reading-timestamp-adopted-by-rfc-0012.md)

To comment, write on issue #1963 of this repository; you need no account on any service other than the code host. A security fix under embargo (D-62) may change a public surface without an RFC; open a retroactive RFC when the fix is disclosed.

This RFC amends [RFC 0008](0008-clock-entropy-and-the-retry-executor.md) (accepted at reviewed blob `b338780823870d0f81c92e1a6f9cd2a5ec472eb8`, [ADR-0040](../docs/decisions/ADR-0040-clock-entropy-and-the-retry-executor-adopted-by-rfc-0008.md)). Because an accepted RFC never returns to `Review` and the decided RFC 0008 file is never edited back to `Review` ([RFC 0001](0001-adopt-the-spine.md), "RFC states"; RFC 0008 section 8 and constraint `4d`), this amendment is a new RFC (`RFC 0008 amendment 1`). [RFC 0009](0009-grdr-model-slice-0-surface.md) section 16 ([ADR-0041](../docs/decisions/ADR-0041-the-grdr-model-slice-0-surface-adopted-by-rfc-0009.md)) also amended RFC 0008 as part of its own subject (wrapping `Breaker`'s open and half-open fields inside `OpenBreaker` and `HalfOpenBreaker`) and carries no amendment number; `#1966` (amendment 2) waits on this amendment (`ADR-0040` constraint `4b`, `#1963` comment `1e`).

## Summary
`ClassReading`, `HealthReading` and `Breaker::Open` (`OpenBreaker::until()`) carry only process-local `Monotonic` instants, which are never sent across processes or shown as dates. This amendment adds `pub taken: Timestamp` (UTC) to `ClassReading`, read from `Clock::now()` inside the same mutex lock hold as `at: Monotonic` in `RetryState::reading()`; specifies explicitly that `Clock::now()` returns a UTC `Timestamp`; defines how downstream callers convert `ClassReading` instants for `HealthReading`, IPC/wire messages (`grdr-wire` callers, `grdr.local.v1alpha1`, `grdr.fleet.v1alpha1`) and exports without emitting `Monotonic`; and requires UI, CLI and console surfaces to render `Breaker::Open`'s `until` as a relative duration from `taken` rather than a wall-clock timestamp.

## Motivation
During RFC 0008's review on `#1924`, Seat 3 (`persona-soc-analyst`, comment `7081910895`, Journey 4) and Seat 9 (`persona-intl`, comment `7081901532`, Journey 2) identified a representation gap in `grdr_ports::retry::ClassReading`:

1. `ClassReading.at`, `HealthReading.at` and `OpenBreaker::until()` (written in RFC 0008 as `Breaker::Open { until }` before RFC 0009 section 16 introduced `OpenBreaker`) are `Monotonic` values, which are `u64` nanoseconds from an arbitrary per-process origin (RFC 0008 section 3). A `Monotonic` instant cannot be converted to a calendar date, cannot be compared across processes, and is never sent over the wire.
2. Without a UTC wall-clock anchor paired atomically with `at`, the uplink (`#1238`), `grdr doctor` (`#1289`), server device coverage-gap rows (`#1972`), OCSF/SIEM exports and adapter set-up readings (`#1688` storage suites) cannot show when a reading or health failure happened ("since 14:02") or convert `until` across process boundaries into a locale-formatted wait duration.
3. RFC 0008 section 3 describes `Clock::now()` only as wall time that may jump, without stating UTC explicitly on `Clock`. Under D-69 and RFC 0009 constraint `2h`, every stored and wire `Timestamp` must be UTC and formatted on surfaces in the viewer's time zone.
4. Converting `Breaker::Open`'s `until` into a wall-clock deadline ("until 14:05") would break on wall-clock steps (NTP adjustments, VM clock jumps or time-zone edits) and mislead on cached or set-up snapshots, whereas showing `until` as a relative duration from `taken` stays accurate and process-independent.

Because `#283` and `#1238` are blocked by `#1963` before they are readied (`ADR-0040` constraint `4a`), and `#1966` builds on the resulting `ClassReading` layout (`#1963` comment `1e`), this amendment settles the signature, clock contract, wire/export conversion and rendering rules before implementation begins.

## Design
This amendment changes RFC 0008 sections 3, 4, 6, 7 and 8 in the rules below. Everything else in RFC 0008, as amended by RFC 0009 section 16 and the constraints of ADR-0040, stands unchanged.

- R1. **`ClassReading` gains `pub taken: Timestamp`.** In `grdr_ports::retry` (amending RFC 0008 section 4), `ClassReading` becomes:

  ```rust
  #[derive(Clone, Copy, Debug, PartialEq, Eq)]
  pub struct ClassReading {
      pub at: Monotonic,
      pub taken: Timestamp,
      pub breaker: Breaker,
      pub health: Option<HealthReading>,
      pub attempt_counter: AttemptCounter,
      pub last_code: Option<Code>,
  }
  ```

  `ClassReading` has these exact six fields and no others (`#1963` comment `1e`; RFC 0008 constraint `1e`). It retains `#[derive(Clone, Copy, Debug, PartialEq, Eq)]` (since `grdr_model::Timestamp` implements those traits) and `data_class = structural` (RFC 0008 R7; constraint `2f`: no peer address, header or error body). It still does not carry `failure_share()`, `at_cap()` or `abandoned()`. Note that `Breaker` is RFC 0009 section 6's four-variant enum where `Breaker::Open(OpenBreaker)` exposes `until(&self) -> Monotonic` and `phase(&self) -> OpenPhase` (amending RFC 0008 section 8 change 5 via RFC 0009 section 16).

- R2. **Atomic snapshot inside one mutex hold in `RetryState::reading()`.** In `impl<C: Clock, R, H> RetryState<C, R, H>`, `reading(&self) -> ClassReading` acquires the state's `std::sync::Mutex` once (reclaiming a poisoned lock with `PoisonError::into_inner` per RFC 0008 section 4) and, **inside that same lock hold**, reads:
  1. `at = self.clock.monotonic()`
  2. `taken = self.clock.now()`
  together with copying the class's `breaker`, `health`, `attempt_counter` and `last_code`.

  Both `Clock::monotonic()` and `Clock::now()` are synchronous, non-blocking methods; neither `.await`s, allocates, runs caller callbacks or acquires any `RetryState` lock (the lock order is strictly `RetryState` mutex to `Clock`), so reading both under the mutex introduces no lock inversion and keeps the `Send` guarantees of `RetryState`, `run` and `run_until` (RFC 0008 R2 and section 4). Reading `at` and `taken` in the same critical section as the copied fields prevents concurrent `run` transitions from interleaving between `at` and the copied state and prevents thread preemption across lock acquisition from skewing `taken` relative to `at`.

  `run` and `run_until` keep reading `Clock::monotonic()` only on their retry hot paths (RFC 0008 section 1 and section 4); they do not read `Clock::now()`. `HealthReading` keeps its exact three fields (`at: Monotonic`, `answer: HealthAnswer`, `refuted: u32`) unchanged.

- R3. **`Clock::now()` returns UTC `Timestamp`.** Amending RFC 0008 section 3 (`Clock, Entropy and Monotonic (#281)`):
  - `grdr_ports::clock::Clock::now(&self) -> Timestamp` returns the wall-clock instant in **UTC** (seconds and nanoseconds from `1970-01-01T00:00:00Z`, within `Timestamp::MIN..=Timestamp::MAX` per RFC 0009 section 2), never a local time-zone offset or a formatted string.
  - `now()` may jump forwards or backwards; no `Clock` implementation derives `monotonic()` from `now()` or `now()` from `monotonic()`.
  - `#281` documents this UTC contract in `Clock::now`'s doc comment on `grdr_ports::clock::Clock`. `#1927` (`OsClock`) meets it by converting `std::time::SystemTime::now()` to UTC `Timestamp` (clamping out-of-range readings to `Timestamp::MIN` or `Timestamp::MAX` and incrementing `wall_out_of_range`). `ManualClock` meets it by taking a UTC `Timestamp` in `ManualClock::new` and shifting it via `jump_wall`.
  - `clock::suite()` in `grdr-ports-testkit` keeps its existing three cases in `crates/grdr-ports-testkit/src/clock/params.rs` unchanged (`grdr-ports-testkit` sits in layer 2 and reads no system clock under R4 and ARCH-003; `OsClock::now()` is verified against `SystemTime::now()` by `#1927` AC-5).

- R4. **Downstream conversion for `HealthReading`, `grdr-wire` / IPC / fleet wire and exports.** Under RFC 0008 section 3 and RFC 0009 section 14, `Monotonic` instants (`ClassReading.at`, `HealthReading.at`, `OpenBreaker::until()`, `HalfOpenBreaker::probe_until()`, `RetryError::BreakerOpen { until, .. }`) never leave the owning process, cross a wire boundary, enter a persisted file or appear in an export. Before crossing process boundaries or constructing a `MessageRef`, callers convert `ClassReading` through `(reading.at, reading.taken)`:
  - **Past instants (`HealthReading.at` or an earlier `Monotonic` instant from the same process):**

    ```rust
    let elapsed = reading.at.saturating_duration_since(instant);
    let wall_time: Option<Timestamp> = reading.taken.checked_sub(elapsed);
    ```

    Because `OsClock::monotonic()` counts suspended time (`CLOCK_BOOTTIME`, `mach_continuous_time`, `QueryInterruptTimePrecise`), `elapsed` includes host sleep time; subtracting `elapsed` from `taken` assumes no wall-clock step occurred between `instant` and `reading.at`. If `checked_sub` returns `None` (the result would precede `Timestamp::MIN`), callers never unwrap or wrap: they omit the derived timestamp or treat it as unavailable without failing the health read.
  - **`grdr-wire` and protobuf schemas:** `grdr-wire` (`#1757`) owns local IPC framing, transports and peer authentication in layer 2 and carries no retry or health types; its Rust surface does not change. Any IPC or fleet message derived from `ClassReading` (such as `grdr.local.v1alpha1` status/doctor responses in `#1902` and `#1540`, `status.pb` snapshots, or `CheckInRequest.health` extensions in `#1238` and `#1972`, each governed by its own protobuf RFC per D-61 and ADR-0040 constraint `5b`) carries `taken` and any converted `since` / health-check instant as `google.protobuf.Timestamp` (UTC, `data_class = structural`), and any open-breaker remaining wait as a duration (`structural`), never `ClassReading` verbatim and never `Monotonic`.
  - **Persisted counter files:** Under RFC 0008 constraint `2f`, the uplink's persisted attempt-counter file continues to store attempt counters only: no `taken`, no `Timestamp`, no `Monotonic`, no origin and no code.
  - **Exports and logs:** Health records, OCSF `Sensor Health` (`docs/design/04` section 10), `grdr doctor --json` and SIEM/lake exports carry `taken` and converted UTC `Timestamp`s (with relative durations for open-breaker wait), `data_class = structural`, in one stable shape, never `ClassReading.at` or `HealthReading.at` (`Monotonic`). Any log site recording `reading.taken` uses `LogSafe` (`LogValue::Timestamp`) and follows RFC 0009 constraint `1a`'s log-gate rule (`#1989`, `#1990`).

- R5. **UI, CLI and console rendering of `taken` and `Breaker::Open`'s `until`.**
  - **Rendering `taken` and converted wall-clock instants:** On every person-facing surface (web console, desktop Rune, tray, CLI human output including `grdr doctor`), `taken` and any converted `HealthReading` / coverage-gap `since` `Timestamp` travel in `MessageRef`s or typed view-models as `Timestamp` arguments (D-69, RFC 0008 constraint `2h`) and render through `:datetime` in the viewer's configured time zone with UTC one step away (`docs/design/27` section 11, `docs/design/34` section 17), never as a raw `Monotonic` count and never concatenated in code. Machine-readable `--json` outputs keep UTC `Timestamp` values and English identifiers.
  - **Rendering `Breaker::Open`'s `until` as a relative duration:** On every UI, CLI and console surface (and in `MessageRef`s built by `grdr-uplink`, `grdr-daemon`, `grdr doctor` or storage-adapter diagnostics), `Breaker::Open`'s `until` (`OpenBreaker::until()`, written in RFC 0008 as `Breaker::Open { until }`) MUST be converted to a non-negative `Duration` from `taken` via `ClassReading`:

    ```rust
    let open_for: Duration = open.until().saturating_duration_since(reading.at);
    ```

    (Where `grdr-uplink` builds a `MessageRef` directly from `RetryError::BreakerOpen { until, .. }`, it uses `until.saturating_duration_since(clock.monotonic())`.) That duration travels in `MessageRef` as a typed duration argument (`Millis` or `Duration`) and renders through `:grdr:duration` ([RFC 0007](0007-grdr-model-and-grdr-schema-slice-0-surface.md) section 5; Seat 9) in the viewer's locale units and digits. Surfaces **never** convert `until` to a wall-clock `Timestamp` (never render "open until 14:05") and **never** display a raw `Monotonic` nanosecond count. When `until <= reading.at`, `saturating_duration_since` yields `Duration::ZERO` (probe due now). Any other future `Monotonic` bound shown in Advanced diagnostics (such as `HalfOpenBreaker::probe_until()`, `CheckingBreaker::check_until()` or `OpenPhase::CallTurn` `until`) follows the same relative-duration rule (`instant.saturating_duration_since(reading.at)` via `:grdr:duration`).
  - **Simple vs Advanced view boundary:** Under RFC 0008 constraint `3` (Seat 8 cut 1) and RFC 0009 constraint `2b`, the Simple view and default CLI output still show only `Degraded`, its code's token and the one next step. `Breaker::Open`, relative `until` durations, `abandoned()`, `refuted` and adapter set-up readings appear only in the Advanced view, `grdr doctor` and diagnostics output.
  - **Cached and set-up readings:** When displaying a cached snapshot (such as `grdr doctor` reading `status.pb` while the daemon is down) or an adapter's kept set-up `ClassReading` (RFC 0008 R9, [RFC 0002](0002-grdr-ports-slice-0-surface.md) section 5), `taken` renders via `:datetime` as when the snapshot was taken (labelled as set-up for an adapter, or showing reading age in `grdr doctor`), and `until` renders as the relative duration from `taken` (`open.until().saturating_duration_since(reading.at)` via `:grdr:duration`).

- R6. **Constraints and write-back for downstream items.**
  - **`#283` (`retry::run` in `grdr-ports`):**
    - Implement `ClassReading` with the exact six fields of R1 (`at`, `taken`, `breaker`, `health`, `attempt_counter`, `last_code`), `#[derive(Clone, Copy, Debug, PartialEq, Eq)]`, holding only `structural` fields (`2f`).
    - Implement `RetryState::reading(&self) -> ClassReading` so `at = self.clock.monotonic()` and `taken = self.clock.now()` are read inside the same `Mutex` lock hold alongside copying `breaker`, `health`, `attempt_counter` and `last_code` (`R2`). Keep `run` and `run_until` free of `Clock::now()`.
    - Add tests in `crates/grdr-ports-testkit/tests/` (specifically `crates/grdr-ports-testkit/tests/retry*.rs`) proving: (1) `reading().taken` and `reading().at` match the state's clock at the snapshot without mutating state; (2) `ManualClock::jump_wall` shifts `reading().taken` while leaving `reading().at`, `health.at` and `open.until().saturating_duration_since(reading.at)` unchanged; (3) `reading().taken.checked_sub(reading().at.saturating_duration_since(health.at))` recovers the health check's UTC time after `ManualClock::advance`, and returns `None` without panicking when the subtraction precedes `Timestamp::MIN`; (4) `reading()` reclaims a poisoned mutex via `PoisonError::into_inner`.
  - **`#1238` (`22-5`, `uplink-reconnect`):**
    - Never send `Monotonic` (`at`, `health.at`, raw `until`) over `grdr.fleet.v1alpha1`, `grdr.local.v1alpha1` or `MessageRef`, and keep the persisted counter file counters-only (`2f`: no `taken`, no `Timestamp`, no `Monotonic`).
    - Convert `HealthReading.at` via `reading.taken.checked_sub(reading.at.saturating_duration_since(health.at))` (omitting / marking unavailable on `None`) when populating `CheckIn`'s `Health` metadata (`2c`, `2d`, `5b` for `#1972`) and exported `Health` / OCSF `Sensor Health` records (`Timestamp`, UTC, `structural`).
    - Convert `OpenBreaker::until()` to `open.until().saturating_duration_since(reading.at)` (`Duration` / `Millis`, `structural`) for `MessageRef`s and diagnostics (`2h`); never render or transmit `until` as a wall-clock timestamp, never format text in `grdr-ports` or `grdr-uplink`, and keep `Breaker::Open`, `until`, `abandoned()` and `refuted` out of the Simple view (`constraint 3`).
    - Test that `ManualClock::jump_wall` leaves the relative `until` duration unchanged while updating `taken`, and that emitted `CheckIn` health metadata, exports and `MessageRef`s carry UTC `Timestamp` and relative duration with zero `Monotonic`.
  - **`#281` and `#1927` (`Clock`):** `#281` documents UTC semantics on `grdr_ports::clock::Clock::now` (`R3`); `clock::suite()` stays three cases. `#1927` (`OsClock::now()`) already returns UTC from `SystemTime::now()` clamped to `Timestamp::MIN..=Timestamp::MAX`; no change to `#1927`.
  - **`#1966` (`RFC 0008 amendment 2`):** Remains blocked by `#1963` until RFC 0012 is decided (`#1963` comment `1e`); its scoped `set_up` entry point returns `ClassReading` with all six fields of R1 (`taken` read in the same lock hold as `at`), and its R6 prose correction for `reading()` names `at` and `taken` alongside `breaker`, `health`, `attempt_counter` and `last_code`.
  - **`#1289` (`grdr doctor`), `#30`, `#1540` and `#1972` (server coverage-gap row):** `#1289` (and `#30` / `#1540` where class readings are shown) reads `ClassReading.taken` (UTC) for snapshot timestamp/age (`:datetime` in human output, UTC `Timestamp` in `--json`) and renders `OpenBreaker::until()` as a relative duration from `taken` (`:grdr:duration`), without mutating state (`constraint 2b`); `#1289` still brings `state_word` by its own amendment of RFC 0009 (`ADR-0041`). `#1972` uses the UTC `Timestamp` (`taken` / converted `since`) from `#1238`'s `CheckIn` health metadata for its coverage-gap `since` column, rendered via `:datetime`.
  - **`#1967` (`architecture.toml`) and `#1970` (`docs/design/*`):**
    - `#1967`: No change to `architecture.toml`. `grdr-ports` already depends on `grdr-model` (`Timestamp`), `RetryState::reading()` calls `Clock::now()` through the `Clock` trait rather than a system clock (`ARCH-003`), and `ARCH-018` restricts `RetryState::{new, for_class}` and `retry::{run, run_until}`, not `reading()`.
    - `#1970`: No change required to `#1970`'s write-back texts from RFC 0008 (`docs/design/03` section 10 Time is already updated for UTC `Timestamp` by `#1988`, and none of `#1970`'s target sections defines `ClassReading` or its UI duration rendering).
  - **RFC 0002 (`#1688` and storage adapter items):** Storage adapters' kept set-up `ClassReading` (`Fixture::setup_reading` and `FixtureError::Open`) gains `taken: Timestamp` automatically from `ClassReading` without changing RFC 0002's signatures; diagnostics surfaces show set-up `taken` via `:datetime` (labelled as set-up) and any `Breaker::Open` `until` as a duration from `taken` via `:grdr:duration`.

**What holds it.**
- Compiler and API checks (`#283`, `#1741`): `ClassReading` exposes `pub taken: Timestamp` alongside the existing five fields; `RetryState::reading(&self)` requires `C: Clock`.
- `#283` test suite under `ManualClock`: verifies same-hold read of `at` and `taken`, `jump_wall` invariance of `at` and relative `until`, `checked_sub` conversion of `health.at`, `Timestamp::MIN` boundary handling (`None`, no panic) and poisoned-mutex recovery.
- `#1238` tests: verify `CheckIn` health metadata, exports and `MessageRef` payloads contain UTC `Timestamp` and relative `Duration` / `Millis` with no `Monotonic`, and verify persisted counter files contain counters only.
- `#1927` AC-5: `OsClock::now()` agrees with `SystemTime::now()` in UTC within 1 s and clamps out-of-range times cleanly.
- `eval-ux` and interface checks (D-69, UX3 to UX6) on `#1853`, `#1289` and `#1972`: `taken` and `since` formatted via `:datetime`, and `until` formatted via `:grdr:duration` from `taken` in Advanced/diagnostics views only.
- Code review on `#283` (`eval-review`, `eval-security`): confirms `self.clock.monotonic()` and `self.clock.now()` are read inside the same `Mutex` hold in `RetryState::reading()`.

**Failure modes.**

| Failure | Declared outcome | Visible as |
|---|---|---|
| Wall clock jumps forwards or backwards between `HealthReading.at` and `reading()` | `taken` reflects the new UTC wall time, shifting `taken.checked_sub(at.saturating_duration_since(health.at))` by the jump; `until.saturating_duration_since(at)`, retry delays and breaker transitions are unaffected because they use `Monotonic` | `ManualClock::jump_wall` test in `#283` and `#1238` |
| Host suspends between `HealthReading.at` and `reading()` | `OsClock::monotonic()` includes suspended time, so `at.saturating_duration_since(health.at)` tracks real elapsed time and converted `health.at` stays accurate once wall clock is synced | `ManualClock::advance` test; `#1927` / `#1936` boot-time clock |
| `taken.checked_sub(at.saturating_duration_since(health.at))` precedes `Timestamp::MIN` | Returns `None`; callers treat derived wall time as unavailable and never panic or wrap | Boundary test near `Timestamp::MIN` in `#283` |
| System wall clock falls outside `Timestamp::MIN..=Timestamp::MAX` | `OsClock::now()` clamps to the nearest bound and increments `wall_out_of_range` (`#1927` R5) | `wall_range` test and `ClockCounters` in `#1927` |
| `reading()` runs after `OpenBreaker::until()` has passed before the next permit | `until <= reading.at`, so `until.saturating_duration_since(reading.at)` returns `Duration::ZERO` (probe due now), with no underflow or panic | Relative duration calculation in `#283` / `#1238` |
| `RetryState`'s mutex is poisoned when `reading()` is called | Reclaimed via `PoisonError::into_inner` (RFC 0008 section 4) and returns a consistent `(at, taken)` snapshot | Poisoned-lock test in `#283` |

Data classes: `taken: Timestamp` and derived relative durations are `structural` (P8; RFC 0008 R7). Assurance effect: none; no action class changes `visibility`, `control`, `on_failure` or `tamper` (P1).

## Surfaces changed
- `grdr-ports` (layer 2, public, stability class `experimental`): `grdr_ports::retry::ClassReading` gains `pub taken: Timestamp`, `RetryState::reading()` reads `Clock::now()` beside `Clock::monotonic()` under one mutex hold, and `grdr_ports::clock::Clock::now` is specified to return UTC `Timestamp`. Adding a public field to `ClassReading` is a breaking Rust API change under `experimental` (D-60; ADR-0020) for any code constructing or exhaustively pattern-matching `ClassReading`; within this workspace `#283` and all consumers of `ClassReading` wait on `#1963` and have not landed yet.
- UI, CLI and console rendering rule: `taken` and converted `Timestamp`s render through `:datetime` (viewer's zone with UTC one step away), and `Breaker::Open`'s `until` renders as a relative duration from `taken` through `:grdr:duration` (never as a wall-clock timestamp or raw `Monotonic`) in Advanced and diagnostics views only.
- Unchanged: `HealthReading`, `RetryError`, `RetryState` method signatures, `grdr-ports-testkit` (`clock::suite()`), `grdr-model`, `grdr-wire`, `rfcs/0008-clock-entropy-and-the-retry-executor.md`, spine text, `architecture.toml`, `limits.toml`, protobuf packages, Cedar schema, dependencies and same-layer edges.

## Alternatives
- **Add `taken: Timestamp` to `HealthReading` instead of (or in addition to) `ClassReading`.** Reading `Clock::now()` on every health check adds a wall-clock read to the retry loop (RFC 0008 section 1 keeps attempt/call clock reads to `monotonic()`), leaves `ClassReading` without a wall-clock timestamp whenever `health` is `None` (before the first check or on a healthy initial set-up), and leaves `OpenBreaker::until()` without an anchor on `ClassReading`. Rejected.
- **Convert `Breaker::Open`'s `until` to a wall-clock `Timestamp` (`taken + remaining`) and display it as a clock time ("until 14:05").** A wall-clock jump (NTP correction, VM clock step, time-zone change) invalidates a wall-clock deadline while the monotonic breaker remains unchanged, and a precomputed wall-clock deadline ages falsely inside cached `status.pb` or set-up readings. Rendering `until` as a relative duration from `taken` (`until.saturating_duration_since(reading.at)` via `:grdr:duration`) avoids clock-jump falsehoods and works uniformly across snapshots. Rejected.
- **Read `Clock::now()` outside `RetryState`'s mutex lock (before or after reading `at`).** Thread preemption or concurrent `run` transitions between reading `now()` and reading `at` inside the lock could skew `taken` against `at` and against the copied `breaker` and `health` fields. Reading both synchronous clock methods inside the same mutex hold keeps the snapshot atomic. Rejected.
- **Replace `at: Monotonic` on `ClassReading` with `taken: Timestamp`.** Without `at: Monotonic` from the same lock hold, callers cannot compute `at.saturating_duration_since(health.at)` or `open.until().saturating_duration_since(at)`, because `HealthReading.at` and `OpenBreaker::until()` stay `Monotonic`. Rejected.
- **Add an `Amendments` section inside `rfcs/0008-clock-entropy-and-the-retry-executor.md`.** RFC 0001 ("RFC states") and RFC 0008 constraint `4d` forbid editing an accepted RFC back to `Review` or altering its decided file. Rejected for a new RFC naming RFC 0008.
- **Add a UTC check case to `clock::suite()`.** `grdr-ports-testkit` sits in layer 2 and cannot read the system clock (R4, ARCH-003), `Timestamp` already enforces UTC `MIN..=MAX` by type, and `#1927` AC-5 already verifies `OsClock::now()` against `SystemTime::now()`. Rejected.

## Drawbacks
- Adding `pub taken: Timestamp` to `ClassReading` breaks any caller constructing or matching `ClassReading` without `..` (allowed under `experimental`, and zero workspace callers have landed yet).
- `RetryState::reading()` performs two synchronous clock reads (`monotonic()` and `now()`) inside its mutex hold rather than one (`monotonic()`). Both are fast, non-blocking reads, and `reading()` is called on inspection/check-in boundaries rather than inside `run`'s retry loop.
- Recovering `HealthReading.at` as `taken.checked_sub(at.saturating_duration_since(health.at))` assumes no wall-clock step occurred between `health.at` and `reading()`. A wall-clock jump in that interval shifts the derived `Timestamp` by the step, and a synthetic `ManualClock` near `Timestamp::MIN` can cause `checked_sub` to return `None`.
- Readers of RFC 0008 must read this amendment alongside RFC 0008 (and `#1966` once decided) to see the sixth field of `ClassReading` and the explicit UTC contract on `Clock::now()`.

## Unresolved questions
None.

## Review
How review binds the decision ([RFC 0001](0001-adopt-the-spine.md), "Review binds the decision"; [ADR-0036](../docs/decisions/ADR-0036-the-amended-spine-is-the-baseline-adopted-by-rfc-0001.md)):
- RFC 0012 decides no pinned path of `rfcs/pins.toml`, so its decision adds no decision line and no file under `rfcs/evidence/`, and `rfcs/pins.toml` does not change.
- Under [ADR-0040](../docs/decisions/ADR-0040-clock-entropy-and-the-retry-executor-adopted-by-rfc-0008.md) ("Lanes for later changes", row 5: changing a `grdr_ports::retry` struct and `Clock` semantic) and [ADR-0043](../docs/decisions/ADR-0043-lean-token-optimised-agent-team.md) (`.claude/risk-tiers.toml` `[high]` for `crates/grdr-ports/**` / `public_api_change` and `[checklist_addons].rfc`), this RFC changes a public API of `grdr-ports` (`high` tier) and is reviewed by `eval-review` and `eval-security` on two distinct models or providers (`D-63`; `.agents/models.toml`), capped at 2 rounds, without a 9-seat persona council fan-out (Seats 3 and 9 already originated this change during RFC 0008's review on `#1924`).
- Each evaluator verdict on `#1963` names `Provider:`, `Model:`, `Commit:` and the three role lines of RFC 0001 (`#1798`), as full 40-character ids:
  - `RFC file:` the blob of this file it read (`git rev-parse <commit>:rfcs/0012-clock-amendment-1-class-reading-timestamp.md`), with the commit;
  - `Proposed text: none`, because no pinned path changes;
  - `Base:` the spine pin in force in `rfcs/pins.toml`, `a80859235e7a2a4444648d6fa8d389d78dde6be9`, SHA-256 `8f6ea876777c0121ecec068c0bc4cef45932be45c1c2aff4140712db1e06628d`.
- The file the decision commits differs from the reviewed blob only in `State:`, `Decision record:`, review link lines added below and the `Decision` section, and reaches `main` in `State: Review` before the decision record (`docs/decisions/ADR-*`) is added.

Verdicts are linked below once posted on `#1963`.

## Decision
Accepted by the chief architect on 2026-11-23 under `#1828` owner delegation (`D-61`, [ADR-0043](../docs/decisions/ADR-0043-lean-token-optimised-agent-team.md)), on reviewed RFC file blob `950d69b0682d010924537d47a75f4718754fe787` (SHA-256 `db954f08c1858d3b5a4a200e0cf171f353f50a8e5275dc993262210b3e336c34`, PR `#2037` head commit `0ea031e1ba602ecbd0117a3d9134570f33983f54`, merged to `main` at `a0d9d0b423f420752f5aab735f43f65af867d6af`), with the spine pin in force (`rfcs/pins.toml`), blob `a80859235e7a2a4444648d6fa8d389d78dde6be9` (SHA-256 `8f6ea876777c0121ecec068c0bc4cef45932be45c1c2aff4140712db1e06628d`), as its base. [ADR-0047](../docs/decisions/ADR-0047-clock-reading-timestamp-adopted-by-rfc-0012.md) records the decision.

This RFC decides no pinned path of `rfcs/pins.toml`, so this section holds no decision line, `rfcs/pins.toml` does not change, and no file is added under `rfcs/evidence/` ([RFC 0001](0001-adopt-the-spine.md), "RFC states"; [ADR-0036](../docs/decisions/ADR-0036-the-amended-spine-is-the-baseline-adopted-by-rfc-0001.md), "Evidence added in route"). [`rfcs/0008-clock-entropy-and-the-retry-executor.md`](0008-clock-entropy-and-the-retry-executor.md) remains untouched (RFC 0008 stays accepted at reviewed blob `b338780823870d0f81c92e1a6f9cd2a5ec472eb8` and accepted blob `b4af2b007041e3abdf6f7439824662ea6f08c52d` by [ADR-0040](../docs/decisions/ADR-0040-clock-entropy-and-the-retry-executor-adopted-by-rfc-0008.md)). The accepted file differs from `950d69b` only in `State:`, `Decision record:` and this `Decision` section.

### Reasons
1. **Atomic UTC snapshot on `ClassReading` (R1, R2).** Adding `pub taken: Timestamp` (UTC, `data_class = structural`) to `grdr_ports::retry::ClassReading` and reading `self.clock.monotonic()` and `self.clock.now()` inside the same `std::sync::Mutex` lock hold in `RetryState::reading()` pairs `taken` atomically with `at` and the copied retry state without altering `run` or `run_until`, without lock inversion and while preserving `Send` guarantees.
2. **Explicit UTC semantics on `Clock::now()` (R3).** Specifying UTC on `grdr_ports::clock::Clock::now` satisfies `D-69` and RFC 0009 constraint `2h`, keeps `monotonic()` and `now()` independent, leaves `clock::suite()` in `grdr-ports-testkit` unchanged in layer 2 (`ARCH-003`), and matches `OsClock::now()` in `#1927`.
3. **Process-local `Monotonic` boundary and relative-duration `until` rendering (R4, R5).** Converting past `HealthReading.at` instants through `reading.taken.checked_sub(reading.at.saturating_duration_since(instant))` (treating `None` as unavailable without panicking or wrapping) and rendering `Breaker::Open`'s `until` (`OpenBreaker::until()`) as `open.until().saturating_duration_since(reading.at)` through `:grdr:duration` (never as a wall-clock deadline and only in Advanced/diagnostics views) keeps `Monotonic` off wire messages, persisted counter files and exports while avoiding clock-jump falsehoods.
4. **Immutability of RFC 0008 and unblocking downstream work (R6).** Leaving `rfcs/0008-clock-entropy-and-the-retry-executor.md` untouched preserves RFC 0001 ("RFC states") and RFC 0008 constraint `4d`, while satisfying `ADR-0040` constraints `4a` and `1e` for `#283`, `#1238`, `#281`, `#1927`, `#1966`, `#1289` and `#1972`.

### Review it rests on
On PR `#2037` (`0ea031e1ba602ecbd0117a3d9134570f33983f54`, merged to `main` at `a0d9d0b423f420752f5aab735f43f65af867d6af`), on reviewed RFC file blob `950d69b0682d010924537d47a75f4718754fe787` (`Proposed text: none`, against spine pin `a80859235e7a2a4444648d6fa8d389d78dde6be9` under [ADR-0043](../docs/decisions/ADR-0043-lean-token-optimised-agent-team.md) and [ADR-0040](../docs/decisions/ADR-0040-clock-entropy-and-the-retry-executor-adopted-by-rfc-0008.md) "Lanes for later changes" row 5):
- Round 2 `eval-review` (`Google`, `Gemini 4 Carbon`): `pass`
- Round 2 `eval-security` (`Google`, `Gemini 4 Neon`): `pass`
- CI checks on PR `#2037` (`0ea031e1ba602ecbd0117a3d9134570f33983f54`): `verify`, `docs`, `scan`, `codeql`, `fuzz` and `branch-check` all passed.

Under `#1828` owner delegation (`https://github.com/416rehman/Guardrails/issues/1828#issuecomment-7074036273`) and [ADR-0043](../docs/decisions/ADR-0043-lean-token-optimised-agent-team.md), the RFC is accepted on the first round in which both required distinct-model evaluators pass with no blocker or major, with no separate 9-seat persona council fan-out (Seats 3 and 9 originated this amendment during RFC 0008's review on `#1924`).

### Constraints
Each constraint below from R1 to R6 binds the named downstream issues upon acceptance:

1. **`#283` (`retry::run` in `grdr-ports`):**
   - Implement `ClassReading` with the exact six fields of R1 (`at: Monotonic`, `taken: Timestamp`, `breaker: Breaker`, `health: Option<HealthReading>`, `attempt_counter: AttemptCounter`, `last_code: Option<Code>`), `#[derive(Clone, Copy, Debug, PartialEq, Eq)]`, holding only `structural` fields (`2f`: no peer address, header or error body; still no `failure_share()`, `at_cap()` or `abandoned()`).
   - Implement `RetryState::reading(&self) -> ClassReading` so `at = self.clock.monotonic()` and `taken = self.clock.now()` are read inside the same `std::sync::Mutex` lock hold (reclaiming a poisoned lock with `PoisonError::into_inner`) alongside copying `breaker`, `health`, `attempt_counter` and `last_code` (`R2`). Keep `run` and `run_until` free of `Clock::now()`, and keep `HealthReading`'s three fields unchanged.
   - Add tests in `crates/grdr-ports-testkit/tests/` (`crates/grdr-ports-testkit/tests/retry*.rs`) proving: (1) `reading().taken` and `reading().at` match the state's clock at the snapshot without mutating state; (2) `ManualClock::jump_wall` shifts `reading().taken` while leaving `reading().at`, `health.at` and `open.until().saturating_duration_since(reading.at)` unchanged; (3) `reading().taken.checked_sub(reading().at.saturating_duration_since(health.at))` recovers the health check's UTC time after `ManualClock::advance` and returns `None` without panicking or wrapping when the subtraction precedes `Timestamp::MIN`; (4) `reading()` reclaims a poisoned mutex via `PoisonError::into_inner`.
2. **`#1238` (`22-5`, `uplink-reconnect`):**
   - Never send `Monotonic` (`ClassReading.at`, `HealthReading.at`, `OpenBreaker::until()`, `HalfOpenBreaker::probe_until()`, `RetryError::BreakerOpen { until, .. }`) over `grdr.fleet.v1alpha1`, `grdr.local.v1alpha1` or `MessageRef`, and keep the persisted attempt-counter file counters-only (`2f`: no `taken`, no `Timestamp`, no `Monotonic`, no origin, no code).
   - Convert `HealthReading.at` via `reading.taken.checked_sub(reading.at.saturating_duration_since(health.at))` (omitting or treating as unavailable on `None`, never unwrapping or wrapping, without failing the health read) when populating `CheckIn`'s `Health` metadata (`2c`, `2d`, `5b` for `#1972` under a separate wire RFC per `D-61`) and exported `Health` / OCSF `Sensor Health` records (`Timestamp`, UTC, `structural`). Any log site recording `reading.taken` uses `LogSafe` (`LogValue::Timestamp`) and follows RFC 0009 constraint `1a`.
   - Convert `OpenBreaker::until()` to `open.until().saturating_duration_since(reading.at)` (`Duration` / `Millis`, `structural`) for `MessageRef`s and diagnostics (`2h`, rendered via `:grdr:duration`; or `until.saturating_duration_since(clock.monotonic())` when building directly from `RetryError::BreakerOpen { until, .. }`; `Duration::ZERO` when `until <= reading.at`); never render or transmit `until` as a wall-clock timestamp or raw `Monotonic` count, never format text in `grdr-ports` or `grdr-uplink`, and keep `Breaker::Open`, `until`, `abandoned()` and `refuted` out of the Simple view (RFC 0008 constraint `3`).
   - Test that `ManualClock::jump_wall` leaves the relative `until` duration unchanged while updating `taken`, and that emitted `CheckIn` health metadata, exports and `MessageRef`s carry UTC `Timestamp` and relative duration with zero `Monotonic`.
3. **`#281` (`Clock` and `clock::suite()`):**
   - Document the explicit UTC contract in `Clock::now`'s doc comment on `grdr_ports::clock::Clock` (`R3`): returns wall-clock instant in UTC (`1970-01-01T00:00:00Z`, `Timestamp::MIN..=Timestamp::MAX`), never a local time-zone offset or formatted string; `now()` may jump forwards or backwards; and no `Clock` implementation derives `monotonic()` from `now()` or `now()` from `monotonic()`. `ManualClock` meets it via UTC `Timestamp` in `ManualClock::new` and `jump_wall`. `clock::suite()` in `crates/grdr-ports-testkit/src/clock/params.rs` keeps its three tests unchanged.
4. **`#1927` (`OsClock`):**
   - `OsClock::now()` already meets `R3` by converting `std::time::SystemTime::now()` to UTC `Timestamp` (clamping out-of-range values to `Timestamp::MIN` or `Timestamp::MAX` and incrementing `wall_out_of_range`, verified by `#1927` AC-5); no spec change to `#1927`.
5. **`#1966` (`RFC 0008 amendment 2`):**
   - Remains blocked by `#1963` until `#1963`'s decision PR merges (`#1963` comment `1e`); its scoped `set_up` entry point returns `ClassReading` with all six fields of `R1` (`taken` read in the same lock hold as `at`), and its R6 prose correction for `reading()` names `at` and `taken` alongside `breaker`, `health`, `attempt_counter` and `last_code`.
6. **`#1289` (`grdr doctor`, plus `#30` and `#1540`):**
   - Reads `ClassReading.taken` (UTC) for snapshot timestamp and age (`:datetime` in the viewer's configured time zone with UTC one step away in human output; UTC `Timestamp` in `--json`) and renders `OpenBreaker::until()` (and any cached `status.pb` or adapter set-up `ClassReading`) as a relative duration from `taken` (`open.until().saturating_duration_since(reading.at)` via `:grdr:duration`), never as a wall-clock deadline, without mutating state (RFC 0008 constraint `2b`) and keeping `Breaker::Open` and `until` out of the Simple view / default CLI output (RFC 0008 constraint `3`). `#1289` still brings `state_word` by its own amendment of RFC 0009 (`ADR-0041`).
7. **`#1972` (server coverage-gap row):**
   - Uses the UTC `Timestamp` (`taken` / converted `since`) from `#1238`'s `CheckIn` health metadata (`structural`, never receiving `Monotonic`) for its coverage-gap `since` column, rendered via `:datetime` in UI and console views.
8. **Unchanged items and storage suites (`#1967`, `#1970`, RFC 0002 / `#1688`):**
   - `#1967` (`architecture.toml`) and `#1970` (`docs/design/*`) require no change for RFC 0012 (`R6`).
   - Storage adapters' kept set-up `ClassReading` (`Fixture::setup_reading` and `FixtureError::Open`) gains `taken: Timestamp` automatically from `ClassReading` without changing RFC 0002 signatures, and diagnostics surfaces render set-up `taken` via `:datetime` (labelled as set-up) and any `Breaker::Open` `until` via `:grdr:duration` from `taken`.
