RFC: 0015
Title: The grdr-core::analyze public surface for the shell canonicaliser
Author: chief-architect
Harness: antigravity
Model: Gemini 4 Neon
State: Accepted
Design issue: #413
Spine: D-05, D-10, D-15, D-60, D-61, D-63, D-69, P1, P5, P8, P9, P14, P17 (no spine text changes)
Surfaces: the public crate `grdr-core` (layer 1, stability `experimental`), module `analyze`: `Resolution<T>`, `UnresolvedReason`, `UnresolvedKind`, `MalformedReason`, `LimitKind`, `Span`, and module `analyze::shell` (`ShellDialect`, `ShellInput`, `ShellLimits`, `ShellLimitsError`, `CommandTree`, `ListItem`, `ListConnector`, `Pipeline`, `Command`, `SimpleCommand`, `Assignment`, `Redirect`, `RedirectOp`, `canonicalise`); the error-code area `ANALYZE` with six codes (`GRDR-ANALYZE-0001` to `GRDR-ANALYZE-0006`) under `schema/codes/areas.toml` and `schema/codes/analyze.toml`. As proposals: `pub mod analyze;` in `crates/grdr-core/src/lib.rs`, dependencies `grdr-schema`, `grdr-model` and `brush-parser` (default features off) in `crates/grdr-core/Cargo.toml`, `[bound.analyze.shell.*]` rows in `limits.toml`, `libfuzzer-sys` in `fuzz/Cargo.toml`, and `fuzz/Cargo.toml` plus `fuzz/fuzz_targets/shell_*.rs` in `.claude/owners.toml`. No spine text, wire format, Cedar schema, same-layer edge or `surfaces.toml` stability class changes
Decision record: docs/decisions/ADR-0049-analyze-shell-surface-adopted-by-rfc-0015.md

To comment, write on issue #413 of this repository; you need no account on any service other than the code host. A security fix under embargo (D-62) may change a public surface without an RFC; open a retroactive RFC when the fix is disclosed.

This is revision 2. It answers the round 1 `eval-security` findings on #413 (PR #2039, commit `ca684fd`): state-mutating and POSIX special built-ins plus `command`/`builtin` wrappers, Billion-Laughs / `ShellInput.env` byte bounds (`EnvBytes`, `ExpandedBytes`), subshell redirects on `Command::Subshell`, and unquoted globs in `argv[0]` and `Redirect.target`. The text below is normative on its own. Where it differs from the items it covers (#22, #415, #422 to #426), this RFC wins, and section 10 tells each lead what to write back.

## Summary
WI-0019 (#22) adds the first normaliser in `grdr-core`, the POSIX shell canonicaliser of [docs/design/13](../docs/design/13-detection-engine-and-content.md) section 8, together with integration tests and the differential fuzz target required by D-10 and [ADR-0009](../docs/decisions/ADR-0009-normalisers-are-tri-state-with-differential-targets.md). Because `grdr-core` is a layer 1 public crate, its public API changes only by RFC (D-61). This RFC states the `grdr_core::analyze` and `grdr_core::analyze::shell` surface (R1 to R4 of #413) and settles the escalation `#22-E1`:

- **Tri-state resolution and shell AST (R1).** `grdr_core::analyze` exposes `Resolution<T>` with exactly `Resolved(T)`, `Unresolved(Vec<UnresolvedReason>)` (non-empty on every analyser return) and `Malformed(MalformedReason)`, with no `Default` and no conversion between variants. `grdr_core::analyze::shell` exposes `ShellDialect`, `ShellInput`, `ShellLimits`, `ShellLimitsError`, `CommandTree`, `ListItem`, `ListConnector`, `Pipeline`, `Command`, `SimpleCommand`, `Assignment`, `Redirect`, `RedirectOp` and `canonicalise(&ShellInput, &ShellLimits) -> Resolution<CommandTree>`. All items carry `grdr-core`'s existing `experimental` stability class in [`surfaces.toml`](../surfaces.toml).
- **Module placement (R2).** `Resolution<T>`, `UnresolvedReason` and `MalformedReason` stay in `grdr_core::analyze` for slice 0. Path and host/URL analysers also live inside `grdr_core::analyze`, and moving or generalising `Resolution` for external layer 1 crates follows [docs/design/03](../docs/design/03-system-architecture-and-modularity.md) section 2's module-split rule through a future RFC.
- **Error codes (R3).** Area `ANALYZE` (`owner = "design/13"`) registers `GRDR-ANALYZE-0001` to `0004` for `MalformedReason` and `0005` to `0006` for `ShellLimitsError` in `schema/codes/analyze.toml` under [RFC 0007](./0007-grdr-model-and-grdr-schema-slice-0-surface.md).
- **Parser isolation (R4).** `brush-parser` (MIT, default features off) is a private normal dependency of `grdr-core`. Zero `brush_parser` types, traits, errors or `From`/`TryFrom` conversions cross the public boundary (`ARCH-007`), so the parser can be replaced without an RFC.
- **Layer 1, privacy and bounds.** All `content` fields (`ShellInput.command`, `ShellInput.env`, `argv`, assignment fields, redirect targets) redact to byte lengths in `Debug` and are never `LogSafe` (P8). Reason enums, `LimitKind`, `ShellDialect` and codes carry structural data and byte offsets only and implement `LogSafe` (P8, [RFC 0009](./0009-grdr-model-slice-0-surface.md)). Bounds come from `grdr_schema::limits` generated from `limits.toml` (D-69, P14, `ARCH-019`).

## Motivation
Agent shell guards that inspect raw command strings or unlowered syntax trees are bypassed by quote insertion, escape sequences, `$IFS` manipulation, variable expansion and command substitution (GuardFall, [research/09](../docs/references/research/09-oss-detectors.md) section 6). D-10 and ADR-0009 require every normaliser to return one of `resolved`, `unresolved` or `malformed`, backed by a real consumer oracle and a differential fuzz target, never returning a best guess.

Without this RFC:
- Integration tests (`tests/shell_tree.rs`, `shell_lower.rs`, `shell_ref.rs`, `shell_exec_oracle.rs`) and the out-of-workspace fuzz crate (`fuzz/fuzz_targets/shell_canon.rs`) cannot call `grdr_core::analyze`, because [`crates/grdr-core/src/lib.rs`](../crates/grdr-core/src/lib.rs) declares `mod analyze;` privately and `grdr-core` has no public `analyze` surface.
- Parallel implementers on `#422` (types), `#423` (canonicaliser) and `#424` (reference model) would diverge on `ListConnector` trailing items, `Redirect.fd` defaults, straight-line assignment scoping, `PowerShell`/`Cmd` wrong-dialect handling (`#1705` Windows spike), `Debug` redaction of content bytes, and `ShellLimits` integration with accepted RFC 0007's `[bound.<name>]` schema.
- Escalation `#22-E1` blocks `#415` (`brush-parser` and `libfuzzer-sys` dependencies) and `#422` to `#426`.

## Design

### 1. Crate metadata, stability and dependencies
- **Stability.** `grdr-core` already holds a `[[crate]]` row in [`surfaces.toml`](../surfaces.toml) (`name = "grdr-core"`, `class = "experimental"`, `rfc = "0005"`). Per `surfaces.toml`, stability class is crate-wide, so `grdr_core::analyze` and `grdr_core::analyze::shell` inherit `experimental` (D-60; design/03 section 7 and R8). No change to `surfaces.toml` is required.
- **Visibility and module layout.** [`crates/grdr-core/src/lib.rs`](../crates/grdr-core/src/lib.rs) changes `mod analyze;` to `pub mod analyze;`. Submodules of `analyze` (such as `resolution`, and `shell`'s internal `tree`, `limits`, `canonicalise`, `lower`) stay private implementation modules and are re-exported at `grdr_core::analyze` and `grdr_core::analyze::shell` so each public item has one canonical path (P17).
- **Dependencies (`architecture.toml` and `#22-E1`).**
  - `grdr-schema` (layer 0): normal dependency of `grdr-core`, permitted by layer order (`1 -> 0`), for `Code`, `Coded`, `Bytes`, `Count` and generated `ANALYZE_*` constants.
  - `grdr-model` (layer 1): normal dependency of `grdr-core`, already permitted by `[[same_layer_rule]]` (`layer = 1`, `to = "grdr-model"`) in [`architecture.toml`](../architecture.toml), for `LogSafe`, `LogValue`, `WireName` and `wire_enum!`.
  - `brush-parser` (MIT, permissive under [`supply-chain/licences.toml`](../supply-chain/licences.toml)): private normal dependency of `grdr-core` with `default-features = false`, admitted via `#415` into `Cargo.lock` and `supply-chain/admissions.toml` subject to `cargo deny check` and `wasm32-unknown-unknown` compilation (`#415` AC-2).
  - `libfuzzer-sys` (MIT OR Apache-2.0): dependency of the standalone `fuzz/` workspace (`#426`), admitted via `#415` subject to `supply-chain/licences.toml` and `cargo deny check`.
- **Internal import rule (`ARCH-013`).** `grdr_core::analyze` imports no sibling module of `grdr-core` (`session`, `policy`, `detect`, `discover`, `compile`) (`ARCH-013`, design/03 section 2). Reading `grdr-schema` (layer 0) and `grdr-model` (layer 1) preserves `ARCH-013` and `ARCH-001`.
- **Layer 1 and `ARCH-003` invariants.** `analyze` performs no I/O, reads no filesystem, environment variable, clock or randomness source, uses no async runtime or thread, forbids `unsafe_code` (inherited from workspace lints), denies `clippy::arithmetic_side_effects`, `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `string_slice`, `todo`, `unimplemented`, `unreachable` and `exit` in non-test code, and compiles for `wasm32-unknown-unknown` (D-05). Maps inside `analyze` use `BTreeMap` / `BTreeSet` (never `HashMap` / `HashSet` with `RandomState`) so execution is deterministic across native and `wasm32`.

### 2. Public surface of `grdr_core::analyze` (R1)

```rust
// Re-exported at `grdr_core::analyze`

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Span {
    /* private: start: u32, end: u32, invariant start <= end */
}

impl Span {
    pub const fn new(start: u32, end: u32) -> Option<Span>;
    pub const fn point(offset: u32) -> Span;
    pub const fn start(self) -> u32;
    pub const fn end(self) -> u32;
    pub const fn len(self) -> u32;
    pub const fn is_empty(self) -> bool;
}

wire_enum! {
    pub enum LimitKind {
        InputBytes => "input_bytes",
        EnvBytes => "env_bytes",
        ExpandedBytes => "expanded_bytes",
        NestingDepth => "nesting_depth",
        Words => "words",
    }
}

wire_enum! {
    pub enum UnresolvedKind {
        UnknownVariable => "unknown_variable",
        IfsExpansion => "ifs_expansion",
        SubstitutionInCommandPosition => "substitution_in_command_position",
        ArithmeticInCommandPosition => "arithmetic_in_command_position",
        SubstitutionInWord => "substitution_in_word",
        ArithmeticInWord => "arithmetic_in_word",
        ProcessSubstitution => "process_substitution",
        DynamicEval => "dynamic_eval",
        DynamicSource => "dynamic_source",
        UndefinedAlias => "undefined_alias",
        LimitExceeded => "limit_exceeded",
        UnsupportedConstruct => "unsupported_construct",
        UnsupportedDialect => "unsupported_dialect",
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UnresolvedReason {
    UnknownVariable { span: Span },
    IfsExpansion { span: Span },
    SubstitutionInCommandPosition { span: Span },
    ArithmeticInCommandPosition { span: Span },
    SubstitutionInWord { span: Span },
    ArithmeticInWord { span: Span },
    ProcessSubstitution { span: Span },
    DynamicEval { span: Span },
    DynamicSource { span: Span },
    UndefinedAlias { span: Span },
    LimitExceeded { kind: LimitKind, span: Span },
    UnsupportedConstruct { span: Span },
    UnsupportedDialect { dialect: shell::ShellDialect, span: Span },
}

impl UnresolvedReason {
    pub const fn kind(&self) -> UnresolvedKind;
    pub const fn span(&self) -> Span;
}
// Implements `grdr_model::LogSafe`: returns `self.kind().log_value()` (`LogValue::Enum`).

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MalformedReason {
    UnterminatedQuote { offset: u32 },
    UnmatchedDelimiter { offset: u32 },
    UnexpectedEof { offset: u32 },
    SyntaxError { offset: u32 },
}

impl MalformedReason {
    pub const fn offset(&self) -> u32;
}
// Implements `grdr_schema::codes::Coded` (exhaustive match to `&ANALYZE_*`)
// and `grdr_model::LogSafe` (`LogValue::Code(*self.code())`).

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolution<T> {
    Resolved(T),
    Unresolved(Vec<UnresolvedReason>),
    Malformed(MalformedReason),
}

impl<T> Resolution<T> {
    pub const fn is_resolved(&self) -> bool;
    pub const fn is_unresolved(&self) -> bool;
    pub const fn is_malformed(&self) -> bool;
}
// Does NOT implement `Default` or `Display`.
// Provides NO method or trait conversion mapping between `Resolved`, `Unresolved` and `Malformed`.
```

Rules for `grdr_core::analyze`:
1. **`Resolution<T>` variants and non-emptiness.** `Resolution<T>` has exactly three variants: `Resolved(T)`, `Unresolved(Vec<UnresolvedReason>)` and `Malformed(MalformedReason)` (`#413` R1). Every analyser function in `grdr-core::analyze` that returns `Resolution::Unresolved(reasons)` must return `!reasons.is_empty()`. Callers must never rely on `Default` or variant coercions (`#422` R1).
2. **`Span` and offsets.** Offsets are `u32` byte indices into `ShellInput.command` so representations are identical on 64-bit hosts and 32-bit `wasm32` targets (D-05). `Span::new` checks `start <= end`; `Span::len` uses `saturating_sub` (`arithmetic_side_effects = "deny"`).
3. **Exhaustiveness while `experimental`.** `LimitKind`, `UnresolvedKind` and `UnresolvedReason` are exhaustive while `grdr-core` is `experimental` (matching RFC 0009 section 13), so internal policy/detection consumers and reference models fail to compile if a variant is added without handling. `MalformedReason` is `#[non_exhaustive]` as a coded error enum (RFC 0009 R6), so callers act on `code()` and `offset()`.
4. **No rendering.** `grdr-core` declares `renders = "none"`. None of `Resolution`, `UnresolvedReason`, `MalformedReason` or `ShellLimitsError` implements `Display` (D-69, UX6).

### 3. Public surface of `grdr_core::analyze::shell` (R1)

```rust
// Re-exported at `grdr_core::analyze::shell`

wire_enum! {
    pub enum ShellDialect {
        Posix => "posix",
        PowerShell => "powershell",
        Cmd => "cmd",
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ShellInput {
    pub command: Vec<u8>,
    pub dialect: ShellDialect,
    pub env: BTreeMap<Vec<u8>, Vec<u8>>,
}
// Manual `fmt::Debug`: prints `dialect`, `command_len` and `env_count` only.

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ShellLimits {
    /* private: max_input_bytes: Bytes, max_env_bytes: Bytes, max_expanded_bytes: Bytes,
       max_nesting_depth: Count, max_words: Count */
}

impl ShellLimits {
    pub const fn from_schema() -> ShellLimits;
    pub fn new(
        max_input_bytes: Bytes,
        max_env_bytes: Bytes,
        max_expanded_bytes: Bytes,
        max_nesting_depth: Count,
        max_words: Count,
    ) -> Result<ShellLimits, ShellLimitsError>;
    pub const fn max_input_bytes(self) -> Bytes;
    pub const fn max_env_bytes(self) -> Bytes;
    pub const fn max_expanded_bytes(self) -> Bytes;
    pub const fn max_nesting_depth(self) -> Count;
    pub const fn max_words(self) -> Count;
}
// Does NOT implement `Default`.

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ShellLimitsError {
    ZeroLimit { kind: LimitKind },
    OutOfRange { kind: LimitKind },
}
// Implements `grdr_schema::codes::Coded` and `grdr_model::LogSafe`.

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ListConnector {
    Sequence,
    And,
    Or,
    Background,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandTree {
    pub items: Vec<ListItem>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListItem {
    pub pipeline: Pipeline,
    pub connector: ListConnector,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pipeline {
    /* private: non-empty `Vec<Command>` */
}

impl Pipeline {
    pub fn new(commands: Vec<Command>) -> Option<Pipeline>;
    pub fn single(command: Command) -> Pipeline;
    pub fn commands(&self) -> &[Command];
    pub fn into_commands(self) -> Vec<Command>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    Simple(SimpleCommand),
    Subshell {
        tree: CommandTree,
        redirects: Vec<Redirect>,
    },
}

#[derive(Clone, PartialEq, Eq)]
pub struct SimpleCommand {
    pub assignments: Vec<Assignment>,
    pub argv: Vec<Vec<u8>>,
    pub redirects: Vec<Redirect>,
}
// Manual `fmt::Debug`: prints `assignments` (each `Assignment` prints `name_len` and `value_len`), `argv` word byte lengths only, and `redirects` (each `Redirect` prints `fd`, `op` and `target_len`).

#[derive(Clone, PartialEq, Eq)]
pub struct Assignment {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}
// Manual `fmt::Debug`: prints `name_len` and `value_len` only.

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RedirectOp {
    Input,     // <
    Output,    // >
    Append,    // >>
    Clobber,   // >|
    ReadWrite, // <>
    DupInput,  // <&
    DupOutput, // >&
    HereDoc,   // << and <<-
}

#[derive(Clone, PartialEq, Eq)]
pub struct Redirect {
    pub fd: u32,
    pub op: RedirectOp,
    pub target: Vec<u8>,
}
// Manual `fmt::Debug`: prints `fd`, `op` and `target_len` only.

pub fn canonicalise(input: &ShellInput, limits: &ShellLimits) -> Resolution<CommandTree>;
```

Notes on these types:
- **`ShellDialect` includes `PowerShell` and `Cmd` from slice 0.** Following the Windows spike (`#1705`) comments on `#22`, `grdr-agents` (`#376` R10) passes Claude Code `PowerShell` tool calls with `ShellDialect::PowerShell`. Including all three variants now lets `canonicalise` reject `PowerShell` and `Cmd` deterministically with `Resolution::Unresolved(vec![UnresolvedReason::UnsupportedDialect { dialect, span }])` before `#894` (E2.2) implements them, preventing any fail-open routing through the POSIX parser.
- **`Pipeline` non-emptiness by construction.** `Pipeline` holds its `Vec<Command>` privately and exposes `new`, `single`, `commands` and `into_commands`, making an empty pipeline unrepresentable (structure rule S4) without panicking indexing (`indexing_slicing = "deny"`).
- **`ShellLimits` and `limits.toml` under RFC 0007 (ADR-0038).** `limits.toml` was not yet created when `#416` and `#422` were drafted, and accepted RFC 0007 (`ADR-0038`) standardises `limits.toml` on `[bound.<name>]` rows read solely by `grdr_schema::limits` (P17, `ARCH-004`, `ARCH-019`). The five bounds enter `limits.toml` as:
  - `[bound.analyze.shell.input-max]` (`bytes = 1048576`, `min = 1`, `max = 1048576`, `scope = "fixed"`, `effect = "none"`, `owner = "design/13"`) -> `grdr_schema::limits::ANALYZE_SHELL_INPUT_MAX`;
  - `[bound.analyze.shell.env-max]` (`bytes = 1048576`, `min = 1`, `max = 1048576`, `scope = "fixed"`, `effect = "none"`, `owner = "design/13"`) -> `grdr_schema::limits::ANALYZE_SHELL_ENV_MAX`;
  - `[bound.analyze.shell.expanded-max]` (`bytes = 1048576`, `min = 1`, `max = 1048576`, `scope = "fixed"`, `effect = "none"`, `owner = "design/13"`) -> `grdr_schema::limits::ANALYZE_SHELL_EXPANDED_MAX`;
  - `[bound.analyze.shell.nesting-depth-max]` (`count = 8`, `min = 1`, `max = 8`, `scope = "fixed"`, `effect = "none"`, `owner = "design/13"`) -> `grdr_schema::limits::ANALYZE_SHELL_NESTING_DEPTH_MAX`;
  - `[bound.analyze.shell.words-max]` (`count = 65536`, `min = 1`, `max = 65536`, `scope = "fixed"`, `effect = "none"`, `owner = "design/13"`) -> `grdr_schema::limits::ANALYZE_SHELL_WORDS_MAX`.
  `ShellLimits::from_schema()` reads those five generated constants directly (with compile-time `const` assertions checking `>= 1` and `<= u32::MAX as u64`). `ShellLimits::new` validates non-zero and `u32`-representable bounds so test code can construct smaller limits while `ARCH-019` blocks literal `Bytes::new(...)` / `Count::new(...)` in product code.

### 4. Canonicalisation contract for `canonicalise`
To keep `#423` (canonicaliser), `#424` (reference model), `#425` (bash exec-tracing oracle) and `#426` (fuzz target) aligned:
1. **Dialect check first.** Any dialect other than `ShellDialect::Posix` immediately returns `Resolution::Unresolved(vec![UnresolvedReason::UnsupportedDialect { dialect: input.dialect, span: Span::point(0) }])` without running the parser.
2. **Input-size and environment-size bounds before parsing.**
   - If `u64::try_from(input.command.len())` overflows or exceeds `limits.max_input_bytes().get()`, return `Resolution::Unresolved(vec![UnresolvedReason::LimitExceeded { kind: LimitKind::InputBytes, span }])` covering `0` to `min(input.command.len(), u32::MAX)` (computed without `unwrap` or `panic`) before calling `brush-parser`.
   - Sum `k.len() + v.len()` across `input.env` using `checked_add`; if addition overflows `u64` or exceeds `limits.max_env_bytes().get()`, immediately return `Resolution::Unresolved(vec![UnresolvedReason::LimitExceeded { kind: LimitKind::EnvBytes, span: Span::point(0) }])` before copying or lowering any environment entries.
3. **Nesting-depth safety.** Both AST lowering and the parser input path enforce `limits.max_nesting_depth()` so adversarial inputs (such as deeply nested `((((...` within 1 MiB) return `Resolution::Unresolved(vec![UnresolvedReason::LimitExceeded { kind: LimitKind::NestingDepth, span }])` before unbounded stack recursion can occur. Top-level commands sit at depth 0; each subshell or compound nesting increments depth; depth strictly above `max_nesting_depth` fails to `LimitExceeded`.
4. **Word count and incremental expanded-bytes bounds.**
   - Raw words parsed and lowered words emitted (summed across `argv`, `assignments` and `redirects`, including nested subshells) must each stay at or below `limits.max_words()`. Exceeding `max_words` returns `Resolution::Unresolved(vec![UnresolvedReason::LimitExceeded { kind: LimitKind::Words, span }])`, never a truncated `CommandTree` (`#423` R2).
   - Lowering maintains a running `expanded_bytes` counter across all lowered `Assignment` names and values (including straight-line environment updates), `SimpleCommand.argv` words, and `Redirect.target` bytes (both simple commands and subshells). Before appending any literal slice or parameter expansion slice into a buffer or straight-line map, lowering computes `expanded_bytes.checked_add(chunk.len())` against `limits.max_expanded_bytes().get()`. If addition overflows or exceeds `max_expanded_bytes`, lowering halts immediately without allocating the expanded payload and returns `Resolution::Unresolved(vec![UnresolvedReason::LimitExceeded { kind: LimitKind::ExpandedBytes, span }])`, preventing Billion-Laughs exponential parameter expansion (`a=...; b=$a$a...; ...`) and large-`env` expansion OOM.
5. **UTF-8 and NUL bytes.** If `input.command` contains invalid UTF-8 or a `0x00` NUL byte, `canonicalise` returns `Resolution::Unresolved` (`UnsupportedConstruct`), never `Resolved` and never `Malformed` where `bash -n` accepts raw bytes (`#425` R4).
6. **Syntax errors.** Input rejected by POSIX.1-2024 XCU section 2 / `brush-parser` returns `Resolution::Malformed(MalformedReason)` with the matching `GRDR-ANALYZE-*` code and saturating `u32` byte offset (`UnterminatedQuote`, `UnmatchedDelimiter`, `UnexpectedEof`, `SyntaxError`).
7. **Canonical tree shape.**
   - Empty, whitespace-only or comment-only input returns `Resolved(CommandTree { items: Vec::new() })`.
   - The final `ListItem` in a sequential list (or a list terminated by `;` or newline) carries `ListConnector::Sequence`; `&&`, `||` and `&` set `And`, `Or` and `Background` on their preceding `ListItem`.
   - `Command::Subshell { tree, redirects }` lowers the `( ... )` body at `depth + 1` in a child variable scope (never leaking assignments outward) and lowers any trailing subshell redirects (for example `(echo ... ) > /etc/cron.d/pwn`) in the enclosing scope into `redirects`, enforcing the same word, expanded-bytes and redirect-target glob rules so subshell redirects are never dropped.
   - `Redirect.fd` stores the explicit fd if specified (fitting `u32`, else `Malformed`/`UnsupportedConstruct`), or the POSIX.1-2024 §2.7 default (`0` for `Input`, `ReadWrite`, `DupInput`, `HereDoc`; `1` for `Output`, `Append`, `Clobber`, `DupOutput`).
8. **Lowering, state-mutating built-ins, globs and unresolved triggers (`#423` R4, R5).**
   - Words expand single quotes, double quotes, ANSI-C `$'...'`, backslash escapes, and simple `$NAME` / `${NAME}` parameter expansions present in `input.env` or assigned earlier on the same straight-line `Sequence` path.
   - Dynamic shell variables (`RANDOM`, `SRANDOM`, `SECONDS`, `LINENO`, `EPOCHSECONDS`, `EPOCHREALTIME`, `BASHPID`, `PPID`, `PWD`, `OLDPWD`) return `UnknownVariable` unless deterministically fixed in the active environment; `cd`, `pushd` and `popd` clear `PWD` and `OLDPWD` from the active straight-line environment so subsequent `$PWD` / `$OLDPWD` expansions return `UnknownVariable`.
   - Prefix assignments (`FOO=bar cmd $FOO`) expand `cmd` arguments and redirects against the environment prior to `FOO=bar` and do not leak `FOO` to later commands; bare assignments (`FOO=bar` with empty `argv`) update the straight-line environment for subsequent `Sequence` items; subshells `( ... )`, multi-stage pipelines `|`, background `&`, and conditional `&&` / `||` branches never leak assignments outward (variables modified inside conditional branches become unknown afterward).
   - Default `IFS` (ASCII space, tab, newline) splitting applies only to unquoted expanded parameter values; quoted expansions produce one word; `~` / `~/...` expands only when `HOME` is known in the active environment (`UnknownVariable` if absent, `UnsupportedConstruct` for `~user`).
   - **Unquoted globs in command position or redirect targets.** Any unquoted and unescaped glob metacharacter (`*`, `?`, `[` or bash extglob `@(`, `!(`, `+(`, `*(`, `?(`), whether present literally or introduced by unquoted parameter or tilde expansion, in `argv[0]` (command position) or in `Redirect.target` returns `Resolution::Unresolved(vec![UnresolvedReason::UnsupportedConstruct { span }])`. Quoted glob characters (such as `"/bin/r[m]"`) remain literal. Non-command arguments `argv[1..]` keep literal `*`, `?`, `[` (no filesystem globbing in layer 1; extglob AST nodes anywhere return `UnsupportedConstruct`).
   - **Built-in and dynamic execution matching on lowered `argv[0]`.** Matching runs on the final lowered `argv[0]` (after quote removal, escape processing, parameter expansion, default-`IFS` word splitting and empty-word elision), catching `\eval`, `'eval'`, `""eval`, `E=eval; $E ...` and `E="eval rm"; $E`:
     - `eval` returns `DynamicEval`; `source` or `.` returns `DynamicSource`; `alias` returns `UndefinedAlias`.
     - `command` and `builtin` return `Unresolved` (mapping wrapped `eval` to `DynamicEval`, `source`/`.` to `DynamicSource`, `alias` to `UndefinedAlias`, and any other `command` / `builtin` invocation to `UnsupportedConstruct`), preventing wrapper bypasses such as `command eval ...` or `builtin export ...`.
     - State-mutating built-ins (`export`, `unset`, `readonly`, `declare`, `typeset`, `local`, `read`, `mapfile`, `readarray`, `getopts`, `set`, `shift`, `trap`, `unalias`, `shopt`, `enable`, `let`, `exec`, `times`, and `printf` whenever any argument before `--` starts with `-v`, covering both `-v name` and `-vname`, or conservatively if flag parsing is ambiguous) return `UnsupportedConstruct`, so straight-line variable state and `IFS` never go stale.
     - Any POSIX.1-2024 XCU §2.14 special built-in (`:`, `.`, `break`, `continue`, `eval`, `exec`, `exit`, `export`, `readonly`, `return`, `set`, `shift`, `times`, `trap`, `unset`) invoked with non-empty prefix `assignments` (such as `CMD=rm :`) returns `Unresolved` (`DynamicEval` / `DynamicSource` / `UnsupportedConstruct`), because prefix assignments on POSIX special built-ins persist in the current shell.
   - Any expansion of `IFS` or assignment to `IFS` (bare or prefix) returns `IfsExpansion`.
   - Unknown variables or special/positional parameters (`$1`, `$@`, `$*`, `$?`, `$$`, `$!`) return `UnknownVariable`.
   - Command substitution (`$(...)`, `` `...` ``) and arithmetic expansion (`$((...))`) return `SubstitutionInCommandPosition` / `ArithmeticInCommandPosition` in command-word position and `SubstitutionInWord` / `ArithmeticInWord` elsewhere; `<(...)` / `>(...)` returns `ProcessSubstitution`; unlowered control flow, functions, complex `${...}` parameter modifiers, brace expansion, unquoted heredoc expansions, pipeline negation `!` and bash-only redirects (`<<<`, `&>`, `&>>`) return `UnsupportedConstruct`.

### 5. Decision on `Resolution<T>` placement (R2)
**Decision.** `Resolution<T>`, `UnresolvedReason` and `MalformedReason` stay in `grdr_core::analyze` for slice 0.

Reasons against moving `Resolution<T>` to `grdr-model` now:
1. **`grdr-core` contains the other design/13 analysers.** [docs/design/13](../docs/design/13-detection-engine-and-content.md) section 8 places the shell canonicaliser (E2.1, E2.2), path canonicaliser (E2.3), host/URL classifier (E2.4), MCP differ (E2.5) and PII normaliser inside `grdr-core::analyze`. All of them live in the same module and share `grdr_core::analyze::Resolution<T>` directly without moving anything to `grdr-model`.
2. **Layer cohesion and single-parameter signature.** `grdr-model` holds cross-system domain primitives (`Timestamp`, `Entropy`, ids, `Lane`, `LogSafe`, `RetryPolicy`, `InstallProfile`, `Tamper`, [RFC 0009](./0009-grdr-model-slice-0-surface.md)) and carries no parser or analyser failure taxonomy. Moving `Resolution<T>` to `grdr-model` now would either pull shell-specific `UnresolvedReason` / `MalformedReason` and `GRDR-ANALYZE-*` codes into `grdr-model`, or replace `#413` R1's `Resolution<T>` with a three-parameter `Resolution<T, U, M>`.
3. **`grdr-fastpath` stays distinct.** `grdr_fastpath::Resolution<T> { Absent, Unresolved, Resolved(T) }` ([RFC 0005](./0005-fastpath-rust-surface.md)) is `#![no_std]` with no `alloc`, no `Vec`, no `grdr-model` dependency (`architecture.toml`) and a distinct `Absent` state for precompiled lookup inputs. It is not merged with `grdr_core::analyze::Resolution<T>`.

**Module-split and cross-crate rule (design/03 section 2).**
- When E2.3 (path canonicaliser) or E2.4 (host/URL classifier) is added inside `grdr-core::analyze`, `UnresolvedReason` / `MalformedReason` are extended (or `Resolution<T, U = UnresolvedReason, M = MalformedReason>` is introduced by a follow-up RFC while `grdr-core` is `experimental`) inside `grdr-core::analyze`.
- If a separate layer 1 crate (`grdr-llm-proto`, `grdr-mcp-proto`) later needs the tri-state normaliser type, or if `analyze` splits into its own `grdr-analyze` crate under design/03 section 2 ("gains a second consumer or a different licence"), a new RFC at that trigger either promotes a generic `Resolution<T, U, M>` to `grdr-model` (using the existing `same_layer_rule` to `grdr-model`) or splits `grdr-analyze` as its own crate, without adding a same-layer edge from `grdr-llm-proto` or `grdr-mcp-proto` to `grdr-core`.

### 6. Error codes and schema registry (R3)
Under [RFC 0007](./0007-grdr-model-and-grdr-schema-slice-0-surface.md) sections 3 and 4 (as amended by [RFC 0010](./0010-code-tokens-before-the-token-check.md)), `schema/codes/areas.toml` defines area `ANALYZE`:

```toml
[area.ANALYZE]
subsystem = "normalisers and analysers"
owner = "design/13"
```

`schema/codes/analyze.toml` defines the six entries bound by `MalformedReason` and `ShellLimitsError`:

| Code | Reason | Class | Connect | Bound by | Registered by | Next step (`code.<code>.fix`) |
|---|---|---|---|---|---|---|
| `GRDR-ANALYZE-0001` | `SHELL_UNTERMINATED_QUOTE` | `input` | `invalid_argument` | `MalformedReason::UnterminatedQuote` | `#422` | The shell command has an unclosed quote and was denied. Close the quote in the command and retry. |
| `GRDR-ANALYZE-0002` | `SHELL_UNMATCHED_DELIMITER` | `input` | `invalid_argument` | `MalformedReason::UnmatchedDelimiter` | `#422` | The shell command has an unmatched delimiter and was denied. Balance the parentheses, braces or keywords and retry. |
| `GRDR-ANALYZE-0003` | `SHELL_UNEXPECTED_EOF` | `input` | `invalid_argument` | `MalformedReason::UnexpectedEof` | `#422` | The shell command ended before a construct completed and was denied. Complete the command syntax and retry. |
| `GRDR-ANALYZE-0004` | `SHELL_SYNTAX_ERROR` | `input` | `invalid_argument` | `MalformedReason::SyntaxError` | `#422` | The shell command is not valid POSIX shell syntax and was denied. Correct the syntax and retry. |
| `GRDR-ANALYZE-0005` | `SHELL_LIMIT_ZERO` | `input` | `invalid_argument` | `ShellLimitsError::ZeroLimit` | `#422` | A shell canonicaliser bound is zero. Set a positive value in `limits.toml` and rebuild or reload. |
| `GRDR-ANALYZE-0006` | `SHELL_LIMIT_OUT_OF_RANGE` | `input` | `invalid_argument` | `ShellLimitsError::OutOfRange` | `#422` | A shell canonicaliser bound exceeds the 32-bit byte-offset limit. Lower the bound in `limits.toml` within `u32` range. |

Rules:
- `MalformedReason` and `ShellLimitsError` implement `grdr_schema::codes::Coded` with exhaustive `match` arms returning `&grdr_schema::codes::ANALYZE_*` generated constants; no `"GRDR-"` literal appears in `grdr-core` (`ARCH-017`).
- Token ids (`code.analyze_0001.message` / `.fix` through `0006`) and anchors (`codes/GRDR-ANALYZE-0001` through `0006`) derive automatically from `schema/codes/analyze.toml` per RFC 0007 section 3.
- Token registration follows RFC 0010 (`ADR-0044`): `#422` writes the tokens in `interface/strings/src/code.mf2.toml` if `#1853` R2 is already on `main`, or leaves them for `#1853` R1 before then.
- Later additions to `schema/codes/analyze.toml` (for example E2.2 PowerShell/cmd or E2.3 path malformed reasons) follow RFC 0007 section 4 ("Content, not surface") without amending this RFC.

### 7. Encapsulation of `brush-parser` (`ARCH-007`, R4)
`brush-parser` is strictly an implementation detail of `grdr_core::analyze::shell`:
1. No `brush_parser` type, AST node, token, error, trait or function appears in any `pub` item, field, variant, function signature, generic bound or `pub use` of `grdr-core`.
2. Neither `MalformedReason` nor any public type in `grdr-core` may implement `From<brush_parser::...>` or `TryFrom<brush_parser::...>`, because trait implementations referencing `brush_parser` appear in `cargo public-api` output and fail `ARCH-007`. All AST and error mapping lives in private `pub(super)` / `pub(crate)` functions inside `analyze/shell/`.
3. No `brush-parser` type is listed in `surfaces.toml`.
4. Replacing `brush-parser` (for example, if `#415` AC-2 shows `wasm32` incompatibility or a new parser is chosen later) requires zero RFC and zero public API change, provided `canonicalise` continues to pass the reference model differential tests (`#424`), the real `bash` exec-tracing oracle (`#425`) and the fuzz target (`#426`).

### 8. Data classes, `LogSafe` and assurance (P8, P1)
| Item | `data_class` | `Debug` rule | `LogSafe` rule |
|---|---|---|---|
| `ShellInput.command`, `ShellInput.env` (keys & values), `SimpleCommand.argv`, `Assignment.name`, `Assignment.value`, `Redirect.target` | `content` | Manual `fmt::Debug` prints byte length or entry count only; never raw bytes or lossy strings | Never `LogSafe`; never passed to log macros |
| `ShellDialect`, `LimitKind`, `UnresolvedKind`, `ListConnector`, `RedirectOp`, `Span` | `structural` | Standard `Debug` | `ShellDialect`, `LimitKind`, `UnresolvedKind` implement `LogSafe` via `wire_enum!` (`LogValue::Enum`); `Span` offsets log via `Count` |
| `UnresolvedReason` | `structural` | Standard `Debug` (variant, `LimitKind`/`ShellDialect`, `Span`) | `LogSafe` via `self.kind().log_value()` (`LogValue::Enum`); never holds command text or variable names |
| `MalformedReason`, `ShellLimitsError` | `structural` | Standard `Debug` (variant, `offset`/`kind`) | `LogSafe` via `LogValue::Code(*self.code())` |

- **Assurance effect (P1).** Defining this surface changes no assurance record by itself. Once policy wires `canonicalise` in `Engine::step`, `Malformed` denies at request level (`on_failure` closed for malformed input, D-10; design/12 section 4 row 1) and `Unresolved` emits `exec.opaque`, which steps up at request level in fail-closed classes and defers to OS control points where a boundary covers `exec`.
- **Scale (P15).** Canonicalisation is pure, per-call CPU work bounded by `ANALYZE_SHELL_INPUT_MAX` (1 MiB), `ANALYZE_SHELL_ENV_MAX` (1 MiB), `ANALYZE_SHELL_EXPANDED_MAX` (1 MiB), `ANALYZE_SHELL_NESTING_DEPTH_MAX` (8) and `ANALYZE_SHELL_WORDS_MAX` (65,536). It keeps no cross-call state, cache, queue or store call, and bounds allocation against Billion-Laughs parameter expansion in `O(max_expanded_bytes)` time and memory.

### 9. Mechanisms
| Decision | Mechanism | Built by |
|---|---|---|
| Exact public API and private internals | `cargo public-api -p grdr-core` and `cargo semver-checks` over [`surfaces.toml`](../surfaces.toml) (`experimental`) | `#422`, `#1741` |
| No `brush_parser` type on public surface (`ARCH-007`) | `cargo public-api -p grdr-core \| grep brush_parser` empty; private `lower`/`map_error` helpers; `ARCH-007` check | `#423`, `#1582` |
| Layer 1 purity and determinism (`D-05`, `ARCH-003`) | `cargo build -p grdr-core --locked --target wasm32-unknown-unknown`; workspace lints (`unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `unsafe_code = "forbid"`, `arithmetic_side_effects = "deny"`); `ARCH-003` | `#415`, `#422`, `#423`, `#1582` |
| Content-class `Debug` redaction and `LogSafe` boundary (`P8`) | Unit tests asserting `format!("{:?}", ...)` for `ShellInput`, `SimpleCommand`, `Assignment`, `Redirect` contains no raw payload bytes; compile-fail doctests rejecting `log_record!` on `ShellInput`/`CommandTree`/`SimpleCommand` | `#422`, `#284` |
| Bounds sourced from `limits.toml` (`D-69`, `ARCH-019`) | Five `[bound.analyze.shell.*]` rows in `limits.toml`, `const` assertions in `ShellLimits::from_schema()`, `ARCH-019` refusing literal `Bytes::new`/`Count::new` in non-test code | `#279`, follow-up `limits.toml` item, `#422`, `#1582` |
| Registered error codes (`ARCH-017`) | `schema/codes/analyze.toml`, `grdr_schema::codes` drift test, `Coded` exhaustive match, `ARCH-017` | `#278`, `#422`, `#1582` |
| Non-empty `Unresolved`, limit compliance, wrong dialect, DoS and built-in evasion | Property/unit tests (`shell_tree`, `shell_lower`): `ShellDialect::PowerShell` returns `Unresolved`; Billion-Laughs exponential expansion and oversized `ShellInput.env` fail fast at `ExpandedBytes`/`EnvBytes`; state-mutating built-ins, prefixed special built-ins, `command`/`builtin` wrappers, subshell redirects and unquoted `argv[0]`/`Redirect.target` globs are tested | `#422`, `#423` |
| Semantic parity and zero best guesses (`D-10`, `ADR-0009`) | Independent reference model (`#424`), real `bash` `strace -f -e trace=execve` oracle (`#425`), differential fuzz target `shell_canon` (`#426`) | `#424`, `#425`, `#426` |

### 10. What each item changes and prerequisites
Because `crates/grdr-schema` (`#278`, `#279`), `crates/grdr-model` (`#284`) and `limits.toml` (`#279`, `#416` closed without merging) have not yet landed on `main`, this RFC records the exact prerequisites and updates:

- **New protected-change item (to be filed on acceptance, `squad:core`, `trust-core`):** blocked by `#279`; adds `[bound.analyze.shell.input-max]`, `[bound.analyze.shell.env-max]`, `[bound.analyze.shell.expanded-max]`, `[bound.analyze.shell.nesting-depth-max]` and `[bound.analyze.shell.words-max]` to `limits.toml`, and adds `fuzz/Cargo.toml` and `fuzz/fuzz_targets/shell_*.rs` under `[squad.core]` in [`.claude/owners.toml`](../.claude/owners.toml) (replacing closed `#416`'s pre-ADR-0029 `.agents/owners.toml` reference).
- **`#415` (`brush-parser` and `libfuzzer-sys`):** carries `#22-E1`'s Option A admission into `Cargo.lock` and `supply-chain/admissions.toml`, and adds `grdr-schema` and `grdr-model` (already permitted by `architecture.toml`) to `crates/grdr-core/Cargo.toml` if not added in `#422`'s dependency edge item. If `#415` AC-2 finds `brush-parser` fails `wasm32-unknown-unknown`, `grdr_core::analyze`'s public API stays unchanged (`ARCH-007`) and `#415` routes to the fallback pure-Rust parser.
- **`#422` (WI-0019a):**
  - Blocked by `#278` (`grdr_schema::codes`), `#279` + the `[bound.analyze.shell.*]` `limits.toml` item (`grdr_schema::limits`), and `#284` (`grdr_model::LogSafe`, `wire_enum!`).
  - Write set gains [`crates/grdr-core/src/lib.rs`](../crates/grdr-core/src/lib.rs) (to change `mod analyze;` to `pub mod analyze;`), `crates/grdr-core/Cargo.toml`, `schema/codes/areas.toml`, `schema/codes/analyze.toml`, `crates/grdr-schema/src/codes/generated.rs`, and (if `#1853` R2 is on `main`) `interface/strings/src/code.mf2.toml` per RFC 0010.
  - Updates R2 to include `SubstitutionInWord`, `ArithmeticInWord`, `ProcessSubstitution`, `UnsupportedConstruct`, `UnsupportedDialect`, `UnresolvedKind`, `Span` and `LimitKind` (`InputBytes`, `EnvBytes`, `ExpandedBytes`, `NestingDepth`, `Words`); updates R3 for `MalformedReason` variants (`GRDR-ANALYZE-0001`..`0004`); updates R4 for `Pipeline` private non-empty methods, `ListConnector` final-item rule, `Command::Subshell { tree, redirects }` and `RedirectOp`/`fd: u32`; updates R5 for `ShellDialect { Posix, PowerShell, Cmd }`, `ShellLimits::from_schema()`/`new` (five bounds), `ShellLimitsError` (`GRDR-ANALYZE-0005`..`0006`), and reading `[bound.analyze.shell.*]` through `grdr_schema::limits` rather than raw `[analyze.shell]` TOML.
- **`#423` (WI-0019b):** implements section 4's dialect dispatch (`PowerShell`/`Cmd` -> `UnsupportedDialect`), pre-parse input and env bounds (`InputBytes`, `EnvBytes`), incremental expanded-bytes bound (`ExpandedBytes`), depth and word bounds (`NestingDepth`, `Words`), NUL/non-UTF-8 -> `UnsupportedConstruct`, subshell redirects on `Command::Subshell`, lowered-`argv[0]` matching for state-mutating built-ins / prefixed POSIX special built-ins / `command` & `builtin` wrappers, unquoted glob checks on `argv[0]` and `Redirect.target`, `brush-parser` lowering with private mappers (no `From<brush_parser::...>`), and tests covering `ShellDialect::PowerShell`, Billion-Laughs expansion, prefixed special built-ins (`CMD=rm :`), wrapped `command eval`, redirected subshells and `argv[0]`/`Redirect.target` globs (`#22` Windows spike).
- **`#424` (WI-0019c) and `#426` (WI-0019e):** read `ShellLimits::from_schema()` (from `limits.toml` via `grdr_schema::limits`) instead of parsing an `[analyze.shell]` TOML table directly; `#424` implements section 4's exact `CommandTree` representation (`Command::Subshell { tree, redirects }`), byte bounds and built-in/glob rules.
- **Design docs follow-up (filed on acceptance, `chief-architect`):** updates `docs/design/13` section 8 (`UnsupportedDialect`, `env-max`, `expanded-max`, `words-max`, `ShellLimits` via `grdr-schema`, built-in and command/redirect glob rules) and `docs/design/03` section 2 wording where needed once this RFC is accepted.

## Surfaces changed
- `grdr-core` (layer 1, public, stability `experimental` in [`surfaces.toml`](../surfaces.toml)): `pub mod analyze;` exposing `Resolution<T>`, `Span`, `LimitKind`, `UnresolvedKind`, `UnresolvedReason`, `MalformedReason`, and `pub mod shell` exposing `ShellDialect`, `ShellInput`, `ShellLimits`, `ShellLimitsError`, `CommandTree`, `ListItem`, `ListConnector`, `Pipeline`, `Command`, `SimpleCommand`, `Assignment`, `Redirect`, `RedirectOp`, `canonicalise`.
- Error-code registry (`schema/codes/areas.toml`, `schema/codes/analyze.toml`): area `ANALYZE`, codes `GRDR-ANALYZE-0001` to `GRDR-ANALYZE-0006`.
- Proposals for follow-up items: `crates/grdr-core/Cargo.toml` (`grdr-schema`, `grdr-model`, `brush-parser` with default features off), `Cargo.lock`, `supply-chain/admissions.toml`, `limits.toml` (`[bound.analyze.shell.*]`), `fuzz/Cargo.toml` (`libfuzzer-sys`), and `.claude/owners.toml` (`fuzz/Cargo.toml` and `fuzz/fuzz_targets/shell_*.rs` under `[squad.core]`).
- No spine text, protobuf package, Cedar schema, same-layer edge or `surfaces.toml` stability class changes.

## Alternatives
- **Keep `grdr_core::analyze` `pub(crate)` (Option B of `#22-E1`).** Integration tests and the external `fuzz/` crate could not invoke `canonicalise` without a public surface or moving fuzzing into `grdr-core`. That violates `ADR-0009` and `D-61`. Rejected.
- **Move `Resolution<T>` into `grdr-model` now.** Forces shell-specific `UnresolvedReason`, `MalformedReason` and `GRDR-ANALYZE-*` codes into `grdr-model`, or breaks `#413` R1's single-parameter `Resolution<T>` signature before any crate outside `grdr-core` needs it. Rejected (section 5); a later cross-crate need promotes a generic type via RFC.
- **Reuse `grdr_fastpath::Resolution<T>`.** `grdr-fastpath`'s type has `{ Absent, Unresolved, Resolved(T) }` with no reason lists, is `#![no_std]` without `alloc`, and models precompiled table lookups (`RFC 0005`). Rejected.
- **Keep `ShellDialect` POSIX-only (`Posix` variant alone) until `#894`.** Blocks `#376` R10 and `#1705` Windows `PowerShell` handling or forces `grdr-agents` to guess/skip calling the canonicaliser on Windows. Rejected for including `PowerShell` and `Cmd` now and returning `UnsupportedDialect` (`Unresolved`) until `#894`.
- **Expose `From<brush_parser::Error>` on `MalformedReason` or leak AST enums.** Exposes `brush-parser` in `cargo public-api`, violating `ARCH-007` and requiring an RFC to replace the parser. Rejected (section 7).
- **Parse `[analyze.shell]` directly from `limits.toml` inside `grdr-core` (pre-RFC-0007 `#416` / `#422`).** Duplicates TOML parsing outside `grdr-schema`, violates `ARCH-004` (`toml` is banned in normal runtime closures) and contradicts RFC 0007's `[bound.<name>]` schema (`ADR-0038`, P17). Rejected for `[bound.analyze.shell.*]` read through `grdr_schema::limits`.
- **Write a bespoke POSIX parser instead of admitting `brush-parser` (Option C of `#22-E1`).** Costs extra parser implementation while `docs/design/13` section 8 already selects `brush-parser` (MIT). Rejected as primary plan; preserved as `#415`'s zero-API-change fallback if `wasm32` fails.
- **Return `Malformed` on invalid UTF-8 or NUL bytes.** Causes mismatches against `bash -n` where `bash -n` accepts raw byte arguments (`#425` R4). Rejected in favour of `Unresolved(UnsupportedConstruct)`.
- **Ignore state-mutating built-ins or reject all subshells with redirects as `UnsupportedConstruct`.** Ignoring `export`/`unset`/`read`/prefixed special built-ins leaves stale `$VAR` and `IFS` values; rejecting redirected subshells `(cmd) > path` makes benign subshell logging opaque instead of preserving `redirects` for policy. Carrying `redirects` on `Command::Subshell` and returning `Unresolved` on state-mutating built-ins, prefixed special built-ins, wrappers and command/redirect globs handles both cleanly.

## Drawbacks
- `grdr-core` gains three dependencies (`grdr-schema`, `grdr-model`, `brush-parser`); if `#415` AC-2 reveals a `wasm32` blocker in `brush-parser`, `#415` must pivot to an internal POSIX parser without changing this RFC's public API.
- `#422` cannot land until `#278`, `#279`, `#284` and the `[bound.analyze.shell.*]` `limits.toml` item land, because `Code`, `Coded`, `Bytes`, `Count`, `LogSafe` and `ANALYZE_SHELL_*` live in those lower-layer items.
- Adding `UnresolvedReason` variants for E2.2 (`InvokeExpression`), E2.3 (path resolver) or E2.4 (host classifier) while `grdr-core` is `experimental` will break exhaustive matches inside `grdr-core` and `tests/shell_ref/` (intentional under RFC 0009 section 13 until beta freeze).
- Redacting `content` fields in `Debug` requires test failures on `#424` / `#425` to inspect slice fields directly in test helpers rather than relying on `{:?}` of `CommandTree`.

## Unresolved questions
None for this RFC's decision. Tracked in downstream items:
1. Whether `brush-parser` compiles cleanly for `wasm32-unknown-unknown` with `default-features = false` (`#415` AC-2).
2. Whether `brush-parser`'s POSIX mode accepts `$'...'` or bashisms (`[[`, `<<<`) in `#425`'s `bash -n` parity corpus (`#423` Open questions).
3. Which Linux isolation mechanism passes `#425` AC-2 without root on hosted CI runners (`#425` Open questions).
4. PowerShell and `cmd` canonicalisation rules and `InvokeExpression` handling (`#894`, design/13 E2.2).

## Review
How review binds the decision ([RFC 0001](./0001-adopt-the-spine.md), "Review binds the decision"; [ADR-0036](../docs/decisions/ADR-0036-the-amended-spine-is-the-baseline-adopted-by-rfc-0001.md); [ADR-0043](../docs/decisions/ADR-0043-lean-token-optimised-agent-team.md)):
- RFC 0015 decides no pinned path, so its decision adds no decision line and no file under `rfcs/evidence/`, and [`rfcs/pins.toml`](./pins.toml) does not change.
- Design issue: `#413` (`tier:high`, `public_api_change`). Under [ADR-0043](../docs/decisions/ADR-0043-lean-token-optimised-agent-team.md) and [`.claude/risk-tiers.toml`](../.claude/risk-tiers.toml) (`[high]` and `[checklist_addons].rfc`), the review set is `eval-review` and `eval-security` on two distinct models/providers (`distinct_models = 2`, at least one distinct from `antigravity` / `Gemini 4 Neon` per [`.agents/models.toml`](../.agents/models.toml)), capped at two rounds, with no persona council fan-out (note `#413` AC-3 predates ADR-0043 and still checks the `State:` line and written `## Decision` reasons).
- Each verdict on `#413` names:
  - `RFC file:` the exact 40-character blob id of `rfcs/0015-analyze-shell-surface.md` and commit;
  - `Proposed text: none`, because no pinned path changes;
  - `Base:` the spine pin in force in [`rfcs/pins.toml`](./pins.toml), `a80859235e7a2a4444648d6fa8d389d78dde6be9`, SHA-256 `8f6ea876777c0121ecec068c0bc4cef45932be45c1c2aff4140712db1e06628d`.
- This RFC lands on `main` in `State: Review` before the commit that decides it (RFC 0001, "RFC states"). Once both required evaluators pass on `#413`, the decision commit changes only `State:`, `Decision record:`, review link lines below and `## Decision`, and records the decision in `docs/decisions/ADR-NNNN-*.md`.

Verdicts on `#413` are linked below, one per line.
- `eval-review` (`Google`, `Gemini 4 Carbon`, round 2 pass, 0 blockers / 0 majors, on `c97afd1ad243faf9f9a05755e630aad54a0b3137` at `bd341e454242c8643256dda8c21594d28586edba`, `Proposed text: none`, base `a80859235e7a2a4444648d6fa8d389d78dde6be9`): https://github.com/416rehman/Guardrails/issues/413#issuecomment-7099934036
- `eval-security` (`Google`, `Gemini 4 Neon`, round 2 pass, 0 findings, on `c97afd1ad243faf9f9a05755e630aad54a0b3137` at `bd341e454242c8643256dda8c21594d28586edba`, `Proposed text: none`, base `a80859235e7a2a4444648d6fa8d389d78dde6be9`): https://github.com/416rehman/Guardrails/issues/413#issuecomment-7099934593

## Decision
Accepted by the chief architect under D-61 on pre-acceptance reviewed RFC file blob `c97afd1ad243faf9f9a05755e630aad54a0b3137` (SHA-256 `6bbf15ae532229e5de81dd5aa500783cff87fc60982e0a2a4a4b13a4d7354973`, PR #2039 revision 2 `bd341e454242c8643256dda8c21594d28586edba` merged on `main` at `bd00bb94bd2d1f19a93b91d9b7a9faf003421bc0`), against spine pin `a80859235e7a2a4444648d6fa8d389d78dde6be9` (SHA-256 `8f6ea876777c0121ecec068c0bc4cef45932be45c1c2aff4140712db1e06628d`). [ADR-0049](../docs/decisions/ADR-0049-analyze-shell-surface-adopted-by-rfc-0015.md) records the decision.

This RFC decides no pinned path of [`rfcs/pins.toml`](./pins.toml), so this section holds no decision line, `rfcs/pins.toml` stays unchanged, and no file enters `rfcs/evidence/` ([RFC 0001](./0001-adopt-the-spine.md), "RFC states"; [ADR-0036](../docs/decisions/ADR-0036-the-amended-spine-is-the-baseline-adopted-by-rfc-0001.md)). The accepted file differs from `c97afd1ad243faf9f9a05755e630aad54a0b3137` only in `State:`, `Decision record:`, the two verdict link lines above and this `Decision` section.

### Reasons
1. **Fixes the `grdr_core::analyze` and `grdr_core::analyze::shell` slice-0 surface (R1).** Exports `pub mod analyze;` on `grdr-core` (keeping `experimental` in `surfaces.toml`, RFC 0005), with `Resolution<T>` (`Resolved`, non-empty `Unresolved(Vec<UnresolvedReason>)`, `Malformed`, no `Default`/`Display`/variant coercion), `Span` (`u32` byte offsets), `ShellDialect` (`Posix`, `PowerShell`, `Cmd` rejecting non-POSIX dialects to `UnsupportedDialect` until `#894`), non-empty `Pipeline`, `Command::Subshell { tree, redirects }`, `ShellLimits::from_schema()` reading `[bound.analyze.shell.*]` from `grdr_schema::limits`, and `canonicalise(&ShellInput, &ShellLimits) -> Resolution<CommandTree>`.
2. **Preserves layer cohesion and `ARCH-013` (R2).** Keeping `Resolution<T>`, `UnresolvedReason` and `MalformedReason` in `grdr_core::analyze` avoids pulling shell error taxonomies into `grdr-model` or breaking the single-parameter signature before E2.3/E2.4 or an external layer 1 crate needs promotion or a `grdr-analyze` split via future RFC, while keeping `grdr_fastpath::Resolution<T>` (`#![no_std]`) independent.
3. **Binds `GRDR-ANALYZE-*` codes and `limits.toml` bounds to the slice-0 schema mechanisms (R3).** Registers area `ANALYZE` and `GRDR-ANALYZE-0001`..`0006` in `schema/codes/analyze.toml` (`Coded` exhaustive match, no `"GRDR-"` literal per `ARCH-017`, language tokens routed per RFC 0010 / ADR-0044), and reads the five `[bound.analyze.shell.*]` rows from `limits.toml` via `grdr_schema::limits` (`ARCH-019`, D-69, P14), closing pre-RFC-0007 `#416` drift.
4. **Encapsulates `brush-parser` and resolves `#22-E1` fail-closed (R4).** Admits `brush-parser` (MIT, `default-features = false`) privately in `grdr-core` and `libfuzzer-sys` in `fuzz/` via `#415` (Option A of `#22-E1`) with zero `brush_parser` types or `From`/`TryFrom` impls on the public surface (`ARCH-007`), preserving zero-API-change replacement if `#415` AC-2 finds a `wasm32` blocker.
5. **Two-model review passed with all round-1 security findings closed.** On blob `c97afd1ad243faf9f9a05755e630aad54a0b3137` (`bd341e454242c8643256dda8c21594d28586edba`), both required evaluators under [ADR-0043](../docs/decisions/ADR-0043-lean-token-optimised-agent-team.md) and [`.claude/risk-tiers.toml`](../.claude/risk-tiers.toml) passed in round 2 on two distinct models (`eval-review` on `Google` / `Gemini 4 Carbon`, `issuecomment-7099934036`, 0 blockers/0 majors; `eval-security` on `Google` / `Gemini 4 Neon`, `issuecomment-7099934593`, 0 findings, confirming closure of round 1's two blockers and two majors on state-mutating/prefixed POSIX special built-ins, `command`/`builtin` wrappers, Billion-Laughs / `ShellInput.env` bounds, subshell redirects and unquoted `argv[0]`/`Redirect.target` globs), with all 17 active CI checks passing before PR #2039 merged.

### Follow-up items and write-backs
- **Filed on acceptance:** `#2053` (protected change in `limits.toml` + `grdr_schema::limits` + `.claude/owners.toml`, replacing closed `#416`, blocked by `#413` merge and `#279`) and `#2054` (`docs/design/13` section 8 and `docs/design/03` section 2 updates, blocked by `#413` merge).
- **Downstream write-backs (to post on merge):** `#22`, `#415`, `#422` to `#426`, `#278`, `#279`, `#284`, `#1853`, `#894`, `#1582` and `#1741` as listed in [ADR-0049](../docs/decisions/ADR-0049-analyze-shell-surface-adopted-by-rfc-0015.md#follow-up-items-and-downstream-write-backs).
