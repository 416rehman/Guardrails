RFC: 0005
Title: The fast-path Rust surface: grdr-fastpath types, load and eval, compile_fastpath, its errors and the per-call cap
Author: chief-architect
Harness: Claude Code
Model: claude-opus-5-5
State: Accepted
Design issue: #405
Spine: D-05, D-10, D-15, D-20, D-22, D-41, D-60, D-61, D-71, P5, P8, P9, P14, P17 (no spine text changes)
Surfaces: the public crates `grdr-fastpath` (its first surface), `grdr-fastpath-ffi` (where its `#[repr(C)]` structs live) and `grdr-core` (module `compile::fastpath`); a new `[[crate]]` row kind in `surfaces.toml`, with three rows, all `experimental`; proposed changes to the host contract (`c-abi.md` and `status-codes.toml`, including a new status, a new input field, the cache key, the `GRDR_E_BUNDLE` row, the answer when the floor cannot answer, and arena and input custody; `tables.md`, including a new header field), carried by #246 and #245; proposals for `architecture.toml`, `limits.toml`, design/03, design/12 and design/26; one bundle manifest field, left to its own RFC. No wire format, Cedar schema or same-layer edge changes
Decision record: docs/decisions/ADR-0037-the-fast-path-rust-surface-adopted-by-rfc-0005.md

To comment, write on issue #405 of this repository; you need no account on any service other than the code host. A security fix under embargo (D-62) may change a public surface without an RFC; open a retroactive RFC when the fix is disclosed.

## Summary
This RFC fixes the Rust surface of the fast path: the types and functions of `grdr-fastpath`, the table layout module that `grdr-core` writes through, and `compile_fastpath` in `grdr-core`. It answers R1 to R7 of #405.
- The library takes a safe, borrowed input and returns a verdict enum whose variants carry their own data, scope included. A value the host could not resolve, or cannot pass in the library's form, has a form of its own, apart from an absent one. It never gets a cacheable `pass` and never meets a cached verdict.
- The `#[repr(C)]` mirrors of `grdr_fastpath.h` live in `grdr-fastpath-ffi`, because only that crate may read raw pointers.
- The tables handle is generic over who owns the blob and the arena, so the daemon can own them in safe Rust and the C library can borrow them. Custody of both, the arena included, and of each input for the length of its call, is a host obligation. What a call re-checks of that storage is a closed list, applied at the first read of what each check guards, and a change that keeps the list true is not detected.
- A blob or arena that fails a re-check gets a new status, `GRDR_E_CHANGED`, and that handle never answers again. The host retires the handle with its cache generation and reloads within a bound, with stated exits.
- The blob names the action classes that have a floor row or a rule declaring `@on_loss("block")`. The host copies that set at load, and whenever the floor cannot answer, those classes deny for processes inside session containers.
- Error variants are exempt from ARCH-017 one variant at a time. Each is bound to a status row through the FFI crate, and to a registered code through the daemon's floor module (#427).
- The per-call cap and three other bounds travel in the blob header, written by the compiler from `limits.toml`, as #245 rules. A host checks them against its own ceilings. Only the signed bundle can lengthen verdict reuse to the end of its scope; a setting can only shorten it.
- All three crates enter `surfaces.toml` as `experimental`, through a new `[[crate]]` row kind. No dependency or edge is added.

## Motivation
WI-0017 (#20) and its sub-issues #409, #410, #412 and #414, and EM-2 (#418), all build against a Rust surface no document states. #245 fixes the blob bytes and #246 the C functions. Design/26 section 2 says "Our daemon links `grdr-fastpath` directly from Rust", and #378 leaves `compile_fastpath` out of scope. `grdr-fastpath` and `grdr-core` are public crates in layer 1, so their surfaces change only by RFC (D-61; design/30 section 3).

Read together, the items already disagree:
- #405 R3 has `compile_fastpath` return a blob, while #414 R1 returns a blob and a floor report.
- #412 R2 makes an action class outside the table's vocabulary an argument error, while `tables.md` section 6 answers `pass` with scope `none` for a class within the ABI.
- #409 R2 asks for "the layout types of the RFC", which do not exist.

Nothing says where the `#[repr(C)]` structs live, how the daemon holds tables it loaded, how an error variant gets a code when the crate has no dependency, or where the cap comes from. Each item would otherwise answer on its own.

## Design

### 0. What this RFC fixes, and what it reads
It fixes the Rust items, their placement, their signatures, and which error or value each case gives. The bytes of the blob, the numbered TV rules, the evaluation semantics, the cost model and the cache-scope rules are `spec/host-contract/tables.md` (#245). The C functions and structs are `spec/host-contract/c-abi.md` (#246), and the header's generated form is RFC 0004. This RFC refers to those texts. Where it needs them changed, it lists the change for the item that owns the text (section 12).

It was written against, and its decision rests on, exactly these blobs:
- `tables.md` blob `8339bea85bb2ee563dd0dfe38befee871a5b7d12`, on `issue/245` at `115ec8b`;
- `c-abi.md` blob `b147c9dbd81068cd0d95cad4813bfee5e702fe30` and `status-codes.toml` blob `abcaa9704974359cdf7fac76712263b7b6f6f74b`, on `issue/246` at `ca039ed`;
- the spine pin in force, blob `a80859235e7a2a4444648d6fa8d389d78dde6be9`, on `main` at `4e46c2c`.

The names, units and keys of its `limits.toml` rows follow RFC 0007 revision 2 (blob `39616803a8292a6a19a40aa1cfefb98a1930a552`, on `issue/1710` at `b3774f0`) and the session's rulings 7 and 9 for that RFC's revision 3 (Unresolved question 3).

Where `c-abi.md` at `ca039ed` and `tables.md` at `115ec8b` disagree, this RFC follows `tables.md` (Unresolved question 2). #245 is not merged, so this text may need an amendment when it lands (Unresolved question 1).

Out of scope, as #405 says: the blob layout (#245), the C functions (#246), the shim's fail-safe table (#71) and the bounded hook-field scanner of design/07. The last two join `grdr-fastpath` later, each by an amendment of this RFC, with their own error enums (R4.6).

### 1. The `grdr-fastpath` surface (R1, R2)

```rust
// grdr_fastpath: #![no_std], #![forbid(unsafe_code)], #![deny(clippy::arithmetic_side_effects,
// clippy::as_conversions)], no dependency, no alloc.
pub mod layout;                                    // section 3

pub struct Tables<B, A> { /* private: blob B, arena A, their validated lengths, a copy of the header, the changed flag */ }

pub fn arena_size(blob: &[u8]) -> Result<usize, Error>;
pub fn load<B, A>(blob: B, arena: A) -> Result<Tables<B, A>, Error>
where B: AsRef<[u8]>, A: AsRef<[u8]> + AsMut<[u8]>;
pub fn eval<B, A>(tables: &Tables<B, A>, input: &Input<'_>) -> Result<Verdict, Error>
where B: AsRef<[u8]>, A: AsRef<[u8]>;
pub fn classify<B, A>(tables: &Tables<B, A>, input: &Input<'_>) -> Result<Option<ClassBits>, Error>
where B: AsRef<[u8]>, A: AsRef<[u8]>;
pub fn interest<B, A>(tables: &Tables<B, A>) -> Result<Interest<'_>, Error>
where B: AsRef<[u8]>, A: AsRef<[u8]>;

impl<B, A> Tables<B, A> {
    pub fn header(&self) -> &layout::Header;                  // the copy every call reads
    pub fn storage(&self) -> (&B, &A);                        // R1.12
    pub fn check_pairing(&self, labels: &Labels) -> Result<(), Error>   // R2.3 step 1
    where B: AsRef<[u8]>, A: AsRef<[u8]>;
    pub fn reason(&self, index: u32) -> Result<Reason<'_>, Error> where B: AsRef<[u8]>, A: AsRef<[u8]>;
    pub fn into_parts(self) -> (B, A);
}

pub struct Input<'a> {
    pub action_class: u16,            // tables.md section 1 numbers
    pub principal_kind: u16,          // Session 1, Process 2
    pub exe_digest: Resolution<Digest>,
    pub path: Resolution<Path<'a>>,   // resolved by the host (tables.md section 11)
    pub dest: Resolution<Dest<'a>>,
    pub labels: Labels,
    pub grant_digest: Option<Digest>,
}
pub enum Resolution<T> { Absent, Unresolved, Resolved(T) }   // R2.3b
pub struct Digest(/* private: [u8; 32], never all zero */);
impl Digest { pub fn new(bytes: [u8; 32]) -> Option<Digest>; pub fn as_bytes(&self) -> &[u8; 32]; }
pub enum Path<'a> { Utf8(&'a [u8]), Utf16Le(&'a [u8]) }    // bytes at any alignment
pub struct Dest<'a> { pub host: Host<'a>, pub port: u16 }
pub enum Host<'a> { Name(&'a [u8]), Ipv4([u8; 4]), Ipv6([u8; 16]) }
pub struct Labels { pub bits: u64, pub bundle_tag: u64 }

pub enum Verdict {
    Pass { scope: CacheScope },
    Deny { hit: Hit, scope: CacheScope },
    StepUp { hit: Hit },              // always scope none (tables.md section 6, rule 1)
}
pub struct Hit { pub rule_index: u32, pub reason: u32 }
pub enum CacheScope { None, Call, Session(layout::Expiry), Bundle(layout::Expiry) }
pub struct ClassBits(/* private: u64 */);
impl ClassBits { pub fn bits(self) -> u64; }
pub struct Reason<'a> { pub code: &'a str, pub rule_id: &'a str }

pub struct Interest<'a> {
    pub process_scope: Records<'a, layout::ProcessScopeEntry>,
    pub paths: Records<'a, layout::PathEntry>,
    pub hosts: Records<'a, layout::HostEntry>,
    pub ports: Records<'a, layout::PortRange>,
    pub strings: &'a [u8],
}
pub struct Records<'a, R> { /* private: the section's bytes and count */ }
impl<'a, R: layout::Record> Records<'a, R> {
    pub fn as_bytes(&self) -> &'a [u8];
    pub fn count(&self) -> u32;
    pub fn iter(&self) -> impl Iterator<Item = R> + 'a;
}

pub enum Error { Arg(ArgFault), Abi, Bundle(BundleFault), State, Changed }
pub enum ArgFault { Arena, ActionClass, PrincipalKind, Path, Destination, Reason }
pub enum BundleFault { Rule(TvRule), EvalCap }
pub struct TvRule(/* private: a rule number of tables.md section 5 other than 3 */);
impl TvRule { pub fn number(self) -> u8; }
impl Error { pub fn rule(&self) -> Option<u8>; }          // 3 for Abi, n for Bundle(Rule(n))
impl core::fmt::Display for Error;
impl core::error::Error for Error;
```

Types (R1):
- R1.1. The crate is `#![no_std]` with no `alloc`, no dependency and `#![forbid(unsafe_code)]`. It denies `clippy::arithmetic_side_effects` and `clippy::as_conversions` at its root, so no cast can truncate silently. It builds for `wasm32-unknown-unknown` and every host triple (design/26 section 2, ARCH-003).
- R1.2. `Input` is the safe form of `grdr_fp_input`. Its fields keep the meanings and numbers of `c-abi.md` section 2.1, grouped where Rust groups them: `labels` holds `label_bits` and `labels_bundle_tag`, and `dest` holds the `dest_*` fields. The other differences:
  - `struct_size` is a C concern, and `process_key` is read by no row, so neither is here;
  - each pointer and length pair is a slice, and `path_encoding` and `dest_kind` become the variants of `Path` and `Host`;
  - each of the three resource inputs is a `Resolution`: `Absent` when the action has none, `Unresolved` when it has one the host could not resolve, and `Resolved` otherwise (R2.3b). In C, absence keeps its form (`path_len` 0, `dest_kind` 0, an all-zero digest), and a new field, `unresolved`, marks the second case (section 12). An all-zero C grant digest is `grant_digest: None`;
  - a `Resolved` path with an empty slice is `Arg(Path)`, and so is a `Path::Utf16Le` slice of odd length. That slice holds the little-endian code units as bytes, so the FFI never builds an aligned `u16` slice from a host pointer.
- R1.3. `Verdict` holds each pairing `tables.md` section 6 allows, and no other. `Pass` names no row. `Deny` and `StepUp` carry the winning row's index and its reason index (#412 R8). `StepUp` carries no scope, because its scope is always `none`, and a verdict over an `Unresolved` input has scope `None` whatever its outcome (R2.3b). `Pass` is not `ALLOW` (design/26 section 2).
- R1.4. `CacheScope` carries the expiry inside the two scopes that have one, so the two meanings of `tables.md` section 6 never meet. `Call` and `None` are never reused. `Session` and `Bundle` carry `layout::Expiry`. The C numbers of scopes are the FFI's (section 5).
- R1.5. `Error` has one variant per fast-path status: `Arg` is `GRDR_E_ARG`, `Abi` is `GRDR_E_ABI`, `Bundle` is `GRDR_E_BUNDLE`, `State` is `GRDR_E_STATE` and `Changed` is the new `GRDR_E_CHANGED` (section 12).
  - `TvRule` names the failing rule, so a test can tell which rule failed (#409 R5). It never holds 3. The crate builds a rule failure in one place, which gives `Abi` for TV-3 and `Bundle(Rule(n))` for every other rule `n` (`tables.md` section 5), so TV-3 has one representation. `Error::rule` returns the number for both.
  - `BundleFault::EvalCap` is an input whose cost exceeds `eval_cap`.
  - `ArgFault::Reason` is a reason index that names no entry.
  - `Changed` is a failed re-check of section 2, or any later call on a handle that failed one (R2.12a).
- R1.6. Every public enum is exhaustive, so a new variant fails the FFI crate's build until it maps to a status (section 5). `#[non_exhaustive]` would force a wildcard arm there.
- R1.7. Derives and formatting. Every public type of both crates takes exactly the derives of this table. None derives `Hash`, `Default`, `PartialOrd` or `Ord`; adding a derive later is additive, so leaving one out costs nothing now. A redacting `Debug` prints field names and lengths or counts only, so an assertion or a wrapped error cannot carry a `content` or `identifier` value into a log.

  | Crate | Types | Derives | `Debug` |
  |---|---|---|---|
  | `grdr-fastpath` | `Error`, `ArgFault`, `BundleFault`, `TvRule` | `Clone`, `Copy`, `PartialEq`, `Eq` | Derived |
  | `grdr-fastpath` | `Verdict`, `Hit`, `CacheScope`, `ClassBits`, `Reason`; in `layout`, `Expiry`, `Nanos`, `Section`, `SectionEntry`, `PathEntry`, `PortRange`, `ReasonEntry` | `Clone`, `Copy`, `PartialEq`, `Eq` | Derived; every field is `structural` |
  | `grdr-fastpath` | `Input`, `Resolution`, `Path`, `Dest`, `Host`, `Digest`, `Labels`; in `layout`, `Header`, `FloorRow`, `HostEntry`, `ExeEntry`, `ProcessScopeEntry` | `Clone`, `Copy`, `PartialEq`, `Eq` | Redacting; `Resolution` derives it over its value's redacting one |
  | `grdr-fastpath` | `Interest`, `Records` | `Clone`, `Copy` | Redacting: counts only |
  | `grdr-fastpath` | `Tables` | None | Redacting: counts only |
  | `grdr-core` | `FastpathLimits`, `Narrowing`, `LimitRow`, `CaseRule` | `Clone`, `Copy`, `PartialEq`, `Eq` | Derived |
  | `grdr-core` | `FloorReport`, `FloorEntry`, `FloorOutcome`, `FastpathCompileError` | `Clone`, `PartialEq`, `Eq` | Derived; every field is `structural` |
  | `grdr-core` | `Facts`, `DeviceFacts`, `Volume` | `Clone`, `Copy` | Redacting |
  | `grdr-core` | `FastpathOutput`, `Blob` | None | Redacting: lengths only |

  - The types other items define and these types hold (`RuleId`, `Ineligible`, `EffectiveCompileError`, `PathContext`) take, in those items, the derives the rows above need, and the same `Debug` rule.
  - `Error` and `FastpathCompileError` carry structural values only, never input bytes. The `Display` of each writes the same text as its `Debug`: the variant path and its numbers, which are identifiers, not prose. With `Display`, each implements `core::error::Error`, and the `source` of `FastpathCompileError::Effective` is the error it wraps. In `grdr-fastpath` no other type implements `Display`, and neither crate formats text a person reads (`renders = "none"`; D-69). A host that reports a fast-path failure to a person does so under its own registered code (R4.3).
- R1.8. The `#[repr(C)]` structs of `grdr_fastpath.h` live in `grdr-fastpath-ffi`, not here (section 5). A struct holding raw pointers can be read only through `unsafe`, which this crate forbids. Keeping the structs in the FFI crate also keeps the C ABI's minor-version rule (trailing fields behind `struct_size`) apart from this crate's SemVer line (D-71). That answers RFC 0004's unresolved question 2 and its D10.
- R1.9. `Tables<B, A>` is generic over who owns the blob and the arena.
  - The FFI crate uses a raw view type of its own (R1.12). The daemon, the first consumer, can own both, for example as `Box<[u8]>`, and keep the handle in safe Rust with no self-referential helper.
  - Whatever the owner, the handle holds both for as long as it lives. While it lives, its arena cannot be passed to another `load` (#409 R7; `tables.md` section 10).
  - The host keeps both in custody, the arena as much as the blob (R2.14), and each input for the length of its call (R1.11a). What a call re-checks of that storage is section 2's.

Functions (R2):
- R2.1. `arena_size` applies TV-1 to TV-14 of `tables.md` section 5 in number order, then returns the arena size, computed from the header alone (`tables.md` section 7). The length TV-6 compares is `blob.len()`, compared in 64-bit arithmetic, so a blob longer than `u32::MAX` bytes fails TV-6 on every target. The size depends on `action_class_count` alone and is at most `8 * (action_class_count + 1)` bytes, so it is below 1 MiB for any header and fits `isize` on every target the crate builds for. It has no error of its own.
- R2.2. `load` checks in this order:
  1. it applies TV-1 to TV-14;
  2. it checks the arena, and an arena shorter than `arena_size` is `Arg(Arena)`;
  3. it applies TV-15 to TV-33;
  4. it builds its indices in the arena and returns the handle, with the two storage lengths, a copy of the header and a clear changed flag.

  It is never lazy. It writes only the arena, never copies the blob and allocates nothing. On any error the caller keeps the tables it had. `load` takes the blob and the arena by value, so an owning caller's new buffers are dropped on an error; `into_parts` returns them from a live handle.
- R2.3. `eval` checks in this order and stops at the first failure:
  0. a handle whose changed flag is set returns `Changed` (R2.12a);
  1. the pairing checks: RC1 of section 2 on the views this call took, which is `Changed`; then a `labels.bundle_tag` that differs from the first eight bytes of the handle's `bundle_digest`, both read as little-endian `u64` (`tables.md` section 8), which is `State`;
  2. the argument checks, each before any read of the blob or the arena:
     - an action class of 0 or above the ABI's highest is `Arg(ActionClass)`;
     - a principal kind of 0 or above `principal_kind_count` is `Arg(PrincipalKind)`;
     - a `Resolved` path whose code units exceed `path_max_units` is `Arg(Path)`, checked before the path is decoded; so is one that fails the form of R2.3a;
     - a `Resolved` destination name that is empty, longer than `layout::NAME_MAX_BYTES` or not in the canonical form of `tables.md` section 3.3 is `Arg(Destination)`.

     A host passes such a path or name as `Unresolved` (R2.3b), so these two errors mean a host fault. A host that gets one calls again with the value `Unresolved` (R2.17), so a value an agent chose never ends in an argument error;
  3. an action class within the ABI but above `action_class_count`, which returns `Pass { scope: None }` with no cost check, no class bits and no read of the blob or the arena;
  4. the cost, which reads the class's run from the arena and each path pattern's length from the pool, and counts an `Unresolved` input as R2.3b says; a cost above `eval_cap` is `Bundle(EvalCap)`, before any matching;
  5. evaluation by `tables.md` section 6 and R2.3b.

  Step 1 is one private function that takes the two views. `eval` and `classify` take their one view of each storage and pass those views to it, so they make RC1 on the views they read (R2.10). `check_pairing` is that function's public form: it takes its own views and calls it. The FFI calls `check_pairing` before its own field and length checks and then `eval` (R1.11), which is two library calls, each with one view of each storage. So C and Rust give one answer for one input.

  Steps 4 and 5 read storage. Each re-check of section 2 applies at the first read of what it guards, in whichever step that read happens (R2.12). So a run index or a pattern that fails its re-check gives `Changed` at step 4, never `Bundle(EvalCap)`. An input gets the same `Arg` answer whatever the vocabulary of the tables. `eval` reads only the tables and the input. It writes nothing but its return value and, when it returns `Changed`, the handle's changed flag, and it never returns a verdict on a failure.
- R2.3a. The path form the library checks. The one scan of R5.4 checks these, after the length check and before any match, and a `Resolved` path that fails one is `Arg(Path)`:
  - it is well formed in its encoding: UTF-8 with no overlong form, no surrogate code point and nothing above U+10FFFF, or UTF-16LE with no unpaired surrogate;
  - it holds no U+0000;
  - it is `/` alone, or `/` followed by segments joined by single `/` characters, with no trailing `/`, where no segment is empty, `.` or `..`.

  That is the whole of the form the library checks, in `eval`, `classify` and the FFI alike. The rest of `tables.md` section 11's path form (link resolution, the Windows forms, normalisation form C and the volume's case mapping) is the host's alone. The library cannot see it, and answers a path given in another form as given. `fastpath_path_form` (#412) holds one table of vectors, each in both encodings, and #418's differential runs the same table through `grdr_fp_eval`. Accepted vectors include `/`, `/a/b`, `/a.b/..c`, `/A`, a path not in normalisation form C and `/a\b`. Refused ones include `a`, `//`, `/a/`, `/a//b`, `/./a`, `/a/.`, `/a/..`, `/a/../b`, a U+0000 anywhere, an overlong or surrogate UTF-8 sequence and an unpaired UTF-16 surrogate.
- R2.3b. Absent and unresolved (D-10, P9). The two are different facts, and the second is never a cacheable `pass`.
  - `Absent` means the action has no such value: no target path, no destination, or no executable digest the host supplies. It contributes no class bits, as `tables.md` section 6 says today.
  - `Unresolved` means the action has the value and the host could not resolve it, which is D-10's `unresolved`, or cannot pass it in the form the library takes. The host passes as `Unresolved`, never as `Absent`: a path it could not resolve, or that fails R2.3a or has more code units than `path_max_units`; a destination it could not resolve, or a name that is empty, longer than `layout::NAME_MAX_BYTES` or outside the form of `tables.md` section 3.3; an executable digest it could not compute. That is a host obligation (section 12).
  - An `Unresolved` value contributes every class bit its classifier can set: `1 << class_bit` of every path entry, or the `class_mask` of every host entry, or of every executable entry. Rows then match as `tables.md` section 6 says, so a `deny` row the value could meet denies and a `step_up` row steps up. The floor never answers weaker than its rows for a value the host could not see.
  - A verdict over any `Unresolved` input has scope `none`, whatever its outcome, so it is never inserted into a cache. A host's cache key holds each input's `Resolution` variant, in C the `unresolved` bits, beside the values `c-abi.md` section 2.2 names, so an input with an `Unresolved` value never meets a verdict cached for an `Absent` one (section 12).
  - The cost counts one step per entry of each classifier an `Unresolved` input reads, in place of that classifier's term in `tables.md` section 7. An `Unresolved` path is not scanned.
  - `classify` returns the bits this rule gives.
  - A host's own `malformed` result is neither form. The host denies it before it calls, as D-10 says.
- R2.4. `classify` makes steps 0 to 4 of R2.3, then returns the class bits of `tables.md` section 6 and R2.3b. For the class of step 3 it returns `Ok(None)`, since no class bits are computed for it. Its step 4 reads the run as `eval`'s does, so it makes RC2. It never returns partial bits. #20 AC-2 holds it against `grdr-core`'s classifiers, so it is public.
- R2.5. `interest` returns the four interest tables and the string pool as views into the blob (`tables.md` section 3.5). Their places come from the handle's header copy, so only the changed flag and RC1 can fail it, as `Changed`.
- R2.6. `eval`, `classify`, `interest`, `reason` and `check_pairing` take `&Tables`. `Tables<B, A>`, `Interest` and `Records` are `Send` and `Sync` whenever `B` and `A` are. The handle's one piece of interior mutability is its changed flag (R2.12a), a `core::sync::atomic::AtomicU8` that only ever goes from clear to set, stored with `Release` and read with `Acquire` ordering. The crate holds no other interior mutability and no global or thread-local state. So any number of threads may evaluate the same tables at once (design/26 section 2), and every function is deterministic while the storage is unchanged.
- R2.7. `reason` returns the reason code and the instantiated rule id of one entry of the reason-code table. An index at or above the table's count is `Arg(Reason)`, and a set changed flag or a failed RC1, RC5 or RC6 is `Changed`. A Rust host takes the rule id it records from here, so it never reads the blob's layout itself (P17).
- R2.8. Every value a call reads from the header (counts, offsets, `eval_cap`, the vocabulary sizes, the expiries and `bundle_digest`) comes from the copy `load` kept, never from the blob again.

### 2. What a call re-checks (R2)
The storage the handle holds can change after `load`. In safe Rust a type with interior mutability can return other bytes from `as_ref()`. Through the FFI, host memory is behind raw pointers. Re-running the TV rules per call is not open: each rule is linear in the blob's length (`tables.md` section 5), and a call is bounded by the rows it touches (`tables.md` section 7). So the property is this:
- R2.9. For any bytes the storage returns, at any time, every function is free of panics, reads only inside the views of R2.10, and does no more work than the cost bound of `tables.md` section 7 plus one scan of the input path. In C this holds for every call whose copy of the handle record (R1.12) passes its check, or fails it and gives `Changed`. A rewrite of the record that keeps its check true is outside this property (R2.13).
- R2.10. Each function takes one view of each storage per call, one `as_ref()` of the blob and one of the arena, and reads only those views; `eval` and `classify` pass theirs to the pairing checks (R2.3). RC1 holds for exactly those views. A read that would fall outside a view is `Changed`, never a default value such as an empty run.
- R2.11. The arena holds the per-action-class run index and nothing else, besides the FFI's handle record (R1.12). An index added to the arena later is an amendment that adds its re-check here.
- R2.12. A function returns `Changed` when one of these re-checks fails. Each re-check applies at the first read of what it guards, in every step of every entry point, and never after a result computed from what it guards:
  - **RC1, storage lengths.** The blob view's length equals the length `load` validated, and the arena view's length is at least the size `load` used. Every function makes this check first, inside the pairing checks for `eval` and `classify`. In C the views come only from the call's checked copy of the handle record `grdr_fp_load` wrote at validation (R1.12). They never come from any other value the host passes.
  - **RC2, run index.** At the first read of an action class's run, in the cost step and in evaluation, the run lies inside the floor-row section. Where they exist, the row just before the run has a lower action class, and the row just after it a higher one. The run's first and last rows have the run's class. `load` writes a class with no rows as an empty run at the position its rows would sit. TV-27 sorts rows by class, so with an unchanged blob any change to a run entry, an emptied run included, fails this check. It costs at most four row reads per call. `eval` and `classify` make this check.
  - **RC3, rows touched.** Each row of the run has the run's action class, an outcome of 2 or 3, a principal kind at most `principal_kind_count`, and a reason below the reason table's count (TV-26 and TV-28 to TV-30, on those rows). `eval` makes this check.
  - **RC4, entries touched.** Each host entry read has a kind of 1 to 5 (TV-16), and a `prefix_len` of at most 32 for kind 3 and at most 128 for kind 4 (TV-22's bound), before the prefix indexes the address. Each path entry read has a class bit of at most 63 (TV-24). `eval` and `classify` make this check.
  - **RC5, pool references.** Each pool reference a call follows, including each pattern whose length the cost step counts, lies inside the pool. `eval`, `classify` and `reason` make this check.
  - **RC6, strings.** Each string a call decodes, including each pattern whose characters the cost step counts, is what TV-19 allows for it: valid UTF-8, UTF-16LE that decodes, or visible ASCII for a reason code or rule id. `eval`, `classify` and `reason` make this check.
- R2.12a. `Changed` is sticky. The first time a function returns `Changed` on a handle, it sets the handle's changed flag. From then on, every call on that handle that starts after that one returned, on any thread, returns `Changed` from every function, `check_pairing` included, before any other check, even when the storage reads valid again. The flag is never cleared, and only a new `load` gives a handle that answers. A call already running when the flag is set may return its own result, which section 2a has the host discard. The flag reads as set for any non-zero value, so a corrupted flag errs toward `Changed`. In C the sticky flag is the handle record's, with one exception, a record whose stored address differs from `t` (R1.12).
- R2.13. A change that keeps every re-check true is not detected, and the call answers from the changed bytes. With RC2 as stated, such changes are blob changes: a row's outcome moved from 2 to 3, a label or class bit, a grant digest, an entry moved inside its section, and an order that TV-25 or TV-33 held. In C, a rewrite of the handle record that changes two or more of its fields and keeps its check true can point the views at any memory, so the library reads bytes no TV rule has checked. That is outside R2.9: the result can be a wrong verdict or a fault in the host process. Custody is the only defence against both. The re-checks and the record's check catch accident, not intent.
- R2.14. Custody covers the blob and the whole arena. The host keeps both, the handle record included, in memory no less privileged process can write, and keeps the arena writable by its own process. They stay unchanged from `load` until the host's quiescence point after it retires the tables, except for the FFI's one flag store (R1.12). Today `tables.md` section 11 states custody for the blob only, and `c-abi.md` says only that the blob and arena "must outlive the tables". Section 12 gives #245 and #246 the text that widens both, and the text that gives the host the same duty for each input during its call (R1.11a). In the FFI the slices rest on that promise, which is the safety invariant of R1.12. A host that breaks it gets no claim beyond accident.

A sealed storage trait cannot make this a type:
- a trait can promise unchanged bytes to the compiler only as an `unsafe trait`, which `forbid(unsafe_code)` refuses;
- a safe sealed trait can be implemented only for types this crate can name, and with no `alloc` that excludes `Box<[u8]>` and `Vec<u8>`, the daemon's owners. A `std` feature that names them would make a public trait's implementations depend on a build feature;
- no trait reaches the host memory behind the FFI's raw pointers.

So the property stays with custody, and the re-checks are a closed list that tests hold (R2.15).
- R2.15. The tests, each over a test storage type whose bytes change after `load`:
  - one per re-check, `fastpath_changed_rc1` to `fastpath_changed_rc6`, each breaking exactly that re-check and expecting `Changed` from every function that makes it;
  - for RC2, `fastpath_changed_rc2_cost`, where the altered run would also exceed `eval_cap` and the answer is `Changed`, not `Bundle(EvalCap)`, from `eval` and `classify`; and `fastpath_changed_rc2_empty`, which empties a run that has rows;
  - for RC4, an entry whose `prefix_len` is above its kind's bound;
  - `fastpath_one_view`, with a storage that counts its `as_ref()` calls and returns a shorter slice on the second, expecting one call per storage per function call, `eval` and `classify` included;
  - `fastpath_changed_sticky`, with a storage that reads changed on one call and valid on every later one, expecting `Changed` from every function on every later call;
  - `fastpath_changed_undetected`, which moves a row's outcome from 2 to 3 and expects the new verdict and no error, so R2.13 is a tested fact;
  - `fastpath_no_false_changed`: for every blob `load` accepts in #409's and #412's fixture and generated sets, and every input drawn for it, no function gives `Changed` on unchanged storage. Seeded inputs sit at each boundary: `prefix_len` 32 and 128, `class_bit` 63, the first and last row of every run, empty runs, and the first and last class of the vocabulary.

### 2a. The host after `Changed`, and when the floor cannot answer (R2)
`Changed` means the tables the handle reads are no longer the ones `load` validated, and the handle never answers again (R2.12a). The status's `handle_after`, `reload-required`, names the host state this section sets out, and R2.17 also answers every other fast-path error. A host's floor state is an explicit state type (design/03 section 10). Our daemon's is #427's, and a partner host's follows the same rules through the contract text of section 12.
- R2.16. On `Changed` the host retires the handle at once:
  - no further call takes it;
  - its cache generation stops being current, and the host reads no verdict cached under it again. While the floor is missing the host reads no floor generation at all;
  - a call on that handle that was already running returns into a state that no longer serves it. The host discards its result, inserts nothing into the cache, and answers that action as R2.17 says;
  - a reload's handle gets a new generation, and a generation number is never reused, so no entry of the retired one can become current again (`tables.md` section 10).

  The host keeps the old interest filters installed, so selection never shrinks (`tables.md` section 10). It frees the old blob and arena only after its quiescence point, when no call on them can still be running.
- R2.17. When the floor cannot answer. `State`, `Arg(Path)` and `Arg(Destination)` from `eval` are answered by calling `eval` again on the same handle, by the two rules below, each applied at most once for an action. Each call made again keeps the changes of the one before it, the last call's verdict answers the action, and the host caches nothing from a call made again:
  - on `State`, the host calls again with label bits 0 and, as the tag, the first eight bytes of the handle's `bundle_digest`, read as R2.3 step 1 reads them. The engine supplies the labels and their tag, and it could already force this verdict by withholding every label. So a projection tagged with another bundle never stops a row that reads no label from answering, for any process (`tables.md` section 8);
  - on `Arg(Path)` or `Arg(Destination)`, the host calls again with the input's path and destination each `Unresolved` where it was `Resolved`. In C, where `GRDR_E_ARG` names no field, it does the same on any `GRDR_E_ARG` for an input that holds a path or a destination. So the library is the one checker of the forms of R2.3a and `tables.md` section 3.3, and a value the host and the library judge differently meets every row it could meet (R2.3b).

  The floor cannot answer an action while the host has no tables, when `eval` still returns an error after these calls, and when the host discards a call's result (R2.16). The host then answers from its copy of the header's `loss_closed_classes` (R3.11), taken when it adopted the tables it holds or last held, and never from the tables' storage:
  - an action whose class has its bit set, by a process inside a session container (D-15), is denied at once, without asking the content engine. D-20 gives these classes to the floor so that they never wait on anything else, and the engine, which parses untrusted content, is not the evaluator of their rows;
  - every other action goes on as after a floor `pass` (`tables.md` section 6). A class whose bit is clear has no floor row (TV-26, section 12), so this is the answer a serving floor gives it. A person's own shell is never denied because the floor is missing (design/07 section 10).

  A class's bit is set when the bundle has a floor row of that class, or an enforced rule of that class that declares `@on_loss("block")` (design/12 section 3). The answer is per class because the rows that would say which actions a rule covers are what the host can no longer read. Adding a pack can only set bits. Clearing one means removing a rule or lowering its Mode or its loss-of-sensor setting, each a widening by design/12 section 7.
  - An error of `eval` other than `Changed` answers that one action and changes no state: the host keeps serving the handle and asks it about the next action. Only `Changed` retires a handle (R2.16).
  - While the host has no tables, from its start and from a `Changed` until a load succeeds, the floor counts as missing, the device is Degraded, and each answer carries `degraded_reason` `floor-missing`. Our daemon gives the answers that go on as after a floor `pass` through #427 R5's path, so "the floor cannot answer" has one answer path (P17).
  - A host that holds no copy, because it has adopted no tables since it started, denies every floor lookup. That is #427 R8's deny-all.
  - No answer comes from the retired handle or its generation (R2.16).
- R2.18. The host reloads from a fresh copy that it verifies again from its source. That is the signed envelope it accepted, or for our daemon a fresh compile instance (#1538), and never the private copy that changed. The first attempt starts at once on entering floor-missing. Between attempts the host follows a named retry policy, `[retry.fastpath-reload]` in `limits.toml`, whose call timeout ends an attempt whose source does not answer, such as a compile instance that hangs, and whose give-up and breaker bound the rest (design/03 section 10). Design/26 owns the policy and sets its kind and values, which are `limits.toml` rows (section 12).
- R2.19. Episodes and exits.
  - Every `Changed` from a handle the host is serving raises a finding of class tamper (D-22) beside its code. Its cause is a defect in `load` or the library, an accident, or a write to the host's memory, and the host cannot tell which. The finding names the bundle by `bundle_digest`. A `Changed` from a handle the host already retired changes no state and raises nothing, since it comes from a call that was running at retirement (R2.16).
  - An episode opens when a handle that is serving with no episode open returns `Changed`. While it is open, every handle the host adopts, by a reload, an activation or a recompile on new device facts, is on probation until it has served for `fastpath.reload-settle`, a `limits.toml` row in `ms`. When a handle passes probation, the episode closes and the policy refills.
  - A `Changed` from a handle on probation is a repeat, and a repeat ends reloading. A fresh copy from the same source would hold the same bytes, since the compile is deterministic (R3.3) and an envelope does not change. A defect that an input triggers ends reloading the same way, and the device then stays floor-missing, answered as R2.17 says.

  | State | Event | Next state |
  |---|---|---|
  | No tables since start | A load succeeds and passes the host's ceilings and binding checks | Serving, no episode |
  | No tables since start | A load fails or is refused | Unchanged; every floor lookup still denies (#427 R8) |
  | Serving, no episode | An activation or a recompile on new device facts (#1538) | Adopted, by the swap of `tables.md` section 10: serving, no episode. Refused: unchanged |
  | Serving, on probation | An activation or a recompile on new device facts | Adopted: serving, on probation, which restarts with the new handle. Refused: unchanged |
  | Serving, no episode | `Changed` | Floor-missing, reload pending, a new episode; the first attempt starts at once |
  | Serving, on probation | `Changed` (a repeat) | Floor-missing, reloading ended |
  | Serving, on probation | The handle has served `fastpath.reload-settle` | Serving, no episode; the policy refills |
  | Floor-missing, reload pending | An attempt loads, and the load passes the checks | Serving, on probation |
  | Floor-missing, reload pending | An attempt fails or times out, for any reason: a failed or hung compile, a refused envelope, any status from `load`, or a host check | Floor-missing, reload pending; the next attempt follows the policy. Never the retired handle: tables that returned `Changed` are never last-known-good |
  | Floor-missing, reload pending | The policy gives up | Floor-missing, reloading ended |
  | Floor-missing, pending or ended | An activation or a recompile on new device facts | Its tables are tried at once, before any further attempt. Adopted: serving, on probation, and the remaining attempts are cancelled. Refused: as it was before the activation |
  | Any | `Changed` from a retired handle | Unchanged |
  | Any | A restart of the host | No tables since start, until #1538 adopts tables |

  The daemon reports a code on entering floor-missing, on a repeat and when the policy gives up (R4.3), and each keeps the device Degraded.
- R2.20. `fastpath_reload` (#427) tests each transition of R2.19 with an injected clock and a storage that changes. For each it asserts the answers, the Degraded state, the codes and findings reported, that the retired handle is never called again, and that no verdict cached under its generation, or returned by a call that was running at the transition, answers an action (R2.16).
  - The cases include a successful reload; an attempt that fails a TV rule, one whose compile fails, and one that times out; a repeat, which ends reloading; a reloaded handle that passes probation and later gives `Changed`, which opens a new episode with a full policy; an exhausted policy; an activation and a recompile on new facts in each state, adopted and refused, with the adopted handle on probation while an episode is open; a late `Changed` from the retired handle, which changes nothing; and a tamper finding for every `Changed` from a served handle.
  - The answers are checked for a process inside a session container and for a person's own shell, over a bundle whose `cred.use` class holds the honeytoken rule (Essentials Block, `@on_loss("block")`) beside `secret` rules that allow on loss, and again after a pack of such `secret` rules is added. The same answers are checked for an `Arg` of a field other than the path and the destination and a `Bundle(EvalCap)` from a served handle, and for a discarded result. A `State` from a projection tagged with another bundle is answered by the call R2.17 makes again, so a session outside any session container, such as a shared-host agent's (D-25), that uses a honeytoken is denied by the honeytoken rule, which reads no label. An `Arg(Path)` or an `Arg(Destination)` is answered by the call made again with the value `Unresolved`, which gets the verdict of the rows the value could meet. After each of these per-call errors, the next action is answered by the serving handle.
  - `fastpath_reload_cache` caches a `pass` of scope `bundle` and starts a call that returns after `Changed`, and expects neither to answer while the floor is missing. `fastpath_reload_loop_stops` uses a storage that fails the same way on every copy and expects reloading to end at the first repeat.

### 3. The table layout (R1, R3)
`grdr_fastpath::layout` is the one definition of the blob's layout that the writer and the reader share. It holds:
- the numbers `tables.md` fixes, as `pub const`: the magic, `table_format` 1, the 232-byte header (section 12 adds a field) and the 20-byte stable prefix, the ten sections, each record size, the kind values, the row outcomes and verdict numbers, the 253-byte name maximum of section 3.3 (`NAME_MAX_BYTES`), and the fast-path ABI version (`ABI_MAJOR`, `ABI_MINOR`, `abi_version()`) with the highest action class it carries (15 at 0.1). These are the format, like a protobuf field number, not tunable bounds, so they are not `limits.toml` entries (ARCH-019 targets bounds);
- `Header`, with one public field per field of `tables.md` section 2, of the same name and width, and `SectionEntry`;
- `Section`, the ten sections in directory order with their record sizes;
- one record type per record of `tables.md` section 3: `FloorRow`, `PathEntry`, `HostEntry`, `ExeEntry`, `ProcessScopeEntry`, `PortRange` and `ReasonEntry`, each with public fields of the document's names and widths;
- `Record`, a sealed `Copy + 'static` trait implemented by each record type, which gives the record size and decodes one record. It is sealed by a private supertrait, so no other crate can claim a type is a table record;
- `encode` and `decode` for the header and every record, over byte arrays of the exact size, with no validation, which is `load`'s;
- `Expiry`, which is `ScopeEnd` or `After(Nanos)`, where `Nanos` refuses 0 and the all-ones value, with the header mapping of `tables.md` sections 2 and 6;
- the cost function of `tables.md` section 7, with the terms of R2.3b for `Unresolved` inputs, which `eval` applies to the input and the compiler to its worst case (R3.7), so the formula exists once.

Rules:
- R3.1. Of `grdr-core`, only module `compile::fastpath` imports `grdr-fastpath`, and only `layout`: its types, its constants, `encode` and `decode`, and the cost function. That is what "table layout only" on the `grdr-core` to `grdr-fastpath` edge means (design/03 section 2), and the edge text names the cost function (section 12). Tests of `grdr-core` (#20, #414) may also call `load`, `eval` and `classify`, the blob's real consumer. The other edges into `grdr-fastpath` are unchanged:
  - `grdr-fastpath-ffi` uses the whole surface;
  - `grdr-ffi` and `grdr-wasm` keep their listed edges, and this RFC adds no use through them, since `grdr_engine_compile_fastpath` reaches the blob through `grdr-core`;
  - the daemon, a layer 4 program, uses the evaluator surface.
- R3.2. Sharing `layout` makes a layout fault symmetric, so it is not its own oracle. The oracles are independent of it:
  - #409's reference validator under `tests/`, which shares no code with `src/`;
  - #412's hand-encoded fixture blobs;
  - #414's golden rows, written by hand from the Cedar text;
  - #20's differential against `cedar-policy`.

  The shared cost function's independent oracle is the comparison-count vectors of `tables.md` section 7.

### 4. `compile_fastpath` (R3)

```rust
// grdr_core::compile::fastpath
use grdr_fastpath::layout::Nanos;

pub fn compile_fastpath(
    bundle: &VerifiedBundle,
    facts: &Facts<'_>,
    limits: &FastpathLimits,
) -> Result<FastpathOutput, FastpathCompileError>;

pub struct FastpathOutput { pub blob: Blob, pub report: FloorReport }
pub struct Blob { /* private: Vec<u8> */ }
impl Blob { pub fn as_bytes(&self) -> &[u8]; pub fn into_vec(self) -> Vec<u8>; }

pub enum Facts<'a> { Device(DeviceFacts<'a>), Relay }
pub struct DeviceFacts<'a> { pub templates: &'a PathContext, pub volumes: &'a [Volume<'a>] }
pub struct Volume<'a> { pub mount: &'a [u8], pub case: CaseRule }
pub enum CaseRule { Sensitive, Insensitive, Unknown }

pub struct FastpathLimits { /* private: the cap, the path bound, each scope's expiry bound and whether `narrow` set it */ }
impl FastpathLimits {
    pub fn from_limits() -> Result<FastpathLimits, FastpathCompileError>;
    pub fn narrow(self, to: Narrowing) -> Result<FastpathLimits, FastpathCompileError>;
}
pub struct Narrowing {
    pub eval_cap: Option<u32>,
    pub path_max_units: Option<u32>,
    pub expiry_bundle: Option<Nanos>,
    pub expiry_session: Option<Nanos>,
}

pub struct FloorReport { /* private: entries in rule-id order */ }
impl FloorReport { pub fn entries(&self) -> &[FloorEntry]; }
pub struct FloorEntry { pub rule: RuleId, pub outcome: FloorOutcome }
pub enum FloorOutcome {
    InFloor { rows: u32 },
    ModeWithoutRow,          // enforced Mode is Watch or Off
    Ineligible(Ineligible),  // #216's first failing atom
    TooManyClasses,
    TooManyLabels,
    NoDeviceValue,           // a template with no device-wide value, or any template under Relay
    Unmappable,              // a path or host entry the format cannot hold
    CannotMatch,             // contradictory labels, or a class no entry sets (TV-31, TV-32)
    FoldNonAscii,            // a fold-class entry with a non-ASCII literal
}

pub enum FastpathCompileError {
    Effective(EffectiveCompileError),  // steps 1 to 7 of design/12 section 7, with their own codes
    CostAboveCap { action_class: u16, cost: u64, cap: u32 },
    TooLarge,                          // the blob or a section would pass 4,294,967,295 bytes
    Limit(LimitRow),                   // a built-in row out of range
    NarrowingRefused(LimitRow),        // a narrowing above the current value, or out of range
}
pub enum LimitRow { EvalCap, PathMax, ExpiryBundle, ExpirySession }
impl core::fmt::Display for FastpathCompileError;
impl core::error::Error for FastpathCompileError;
```

- R3.3. `compile_fastpath` runs steps 1 to 7 of design/12 section 7 on the verified bundle. It then writes step 8's fast-path blob in the canonical form of `tables.md` section 4, through `grdr_fastpath::layout` only. It is pure and deterministic: one bundle, one set of facts and one set of limits give the same bytes on every target for one compiler version (D-05; R6.6). The effective-policy compiler of #71 writes its step 8 blob by calling this function, so the blob has one writer.
- R3.4. It returns the floor report beside the blob. The report has one entry per rule of a fail-closed class, in rule-id order, so nothing is dropped silently (#414 R6). Its outcomes are #414's and those `tables.md` section 13 adds.
  - `RuleId` is the instantiated rule id of design/12 section 7 step 4, the policy module's type.
  - `Ineligible` and `EffectiveCompileError` are the types #216 and #71 define.
- R3.5. `Facts::Device` carries the device-wide template values and each volume's mount point and case rule:
  - the templates are #221's `PathContext`, whose `$WORKSPACE` and `$SESSION_TMP` the fast path never reads;
  - the case rules decide `path_fold_classes` (`tables.md` section 13);
  - `CaseRule::Unknown` folds, and so does any volume a pattern can reach that `volumes` does not list, because folding errs toward `deny` (`tables.md` section 13);
  - a change of the device's volumes is a change of its facts, and the host compiles again (#1538).

  `Facts::Relay` is a partner relay compile with no per-device facts. It sets every bit of `path_fold_classes` and compiles no rule whose pattern holds a template (`tables.md` section 9). `DeviceFacts` is the device-facts input of design/12's `compile(layers, packs, device_facts)`, so #71 takes the same type (P17).
- R3.6. `FastpathLimits` carries the four header values the compiler writes, and for each expiry whether `narrow` set it, under the source rules of R5.2a.
  - `from_limits` reads the four `limits.toml` rows of #1768 through `grdr-schema`'s generated limits module (#279), converting the two `ms` rows to nanoseconds with checked arithmetic (R5.1). A row whose value `tables.md` TV-8 would refuse, or whose conversion overflows, is `Limit`, naming the row: a defect in the shipped file. A test holds `from_limits` to `Ok` on the committed `limits.toml`.
  - `narrow` returns limits that are each at most what they were. A lower cap or path bound is how a host compiles to its own ceiling (R5.3) and how a test meets the cap. A shorter expiry is the only way a setting reaches an expiry (R5.2a), and an expiry `narrow` set is recorded as set even when it equals the current amount. A value above the current one, or one TV-8 would refuse, is `NarrowingRefused`, naming the row: a fault of the caller.
- R3.7. It refuses with `CostAboveCap` a bundle whose worst-case cost for any action class exceeds the cap. The worst case takes each of the three resource inputs in whichever of its `Absent`, `Resolved` and `Unresolved` forms costs most, with a `Resolved` path of `path_max_units` code units. For an executable classifier the `Unresolved` term, one step per entry, is the larger. So a blob it wrote never reaches the cap at run time, whatever the host could resolve (`tables.md` section 13).
- R3.8. It writes an interest set that selects every action a floor row can match (`tables.md` section 13). `load` cannot check that property, since no TV rule reads interest coverage, so a compiler test holds it (R3.9). An interest set that selects too little is silent: the floor is never asked about the actions it misses.
- R3.9. `fastpath_compile_interest` (#414) compiles the bundles of #414 AC-4, and AC-5's generated bundles in its soak run. Its inputs are actions in the form a sensor sees them, not only fixed-layout inputs: each carries the fixed-layout fields, plus the acting process's executable path, signing identity, package identity and its lineage to a selected ancestor, which a process-scope entry reads (`tables.md` section 3.5). A catalogue fixture lists the sessions the bundle's catalogue opens, so rows naming `Session` can be judged (`tables.md` section 13). The generated actions include ones whose path, destination or executable digest is unresolved.
  - For every action that an unindexed reference matcher in the test finds a floor row of the blob to match, a reference interest selector, written from `tables.md` section 3.5 as section 12 amends it for unresolved values, must select that action.
  - Every floor row of every compiled blob must have at least one matching action in the generated set, so no row passes for lack of a witness. That covers rows naming `Session`, rows covered only through process scope, and rows of classes whose actions carry no target path or destination, such as `elevate`.
  - The class vocabularies are enumerated exhaustively up to 20 class bits and sampled above.
- R3.10. `compiler_version` is the crate's own package version, and no caller can set it. `bundle_digest` and `effective_hash` come from the bundle. The `Blob` makes no alignment promise. A host copies it into private memory before it loads (`tables.md` section 11, custody), and a C host aligns that copy to 8.
- R3.11. It writes the header field `loss_closed_classes` (section 12): bit `n` for every action class `n` that has a floor row in the blob, or an enforced rule of the bundle that declares `@on_loss("block")`. Such a rule sets its class's bit whether or not the floor can hold it, under `Facts::Relay` included. `load` checks the field against the rows (TV-8 and TV-26 as section 12 amends them). `fastpath_loss_classes` (#414) holds it, for every bundle of #414 AC-4, to the classes of the rules the floor report lists as `InFloor` and of the bundle's enforced `@on_loss("block")` rules, and to no other class.

### 5. What `grdr-fastpath-ffi` holds (R1)
- R1.10. It defines `grdr_fp_input`, `grdr_fp_verdict`, `grdr_fp_span` and `grdr_fp_interest_view` as `#[repr(C)]` structs and `grdr_fp_tables` as an opaque type, under the names `c-abi.md` section 2 gives. RFC 0004's descriptor describes them there, so its D10 re-export case does not arise. The crate root denies `clippy::as_conversions` as `grdr-fastpath` does. It uses `<*const T>::addr` only to compare addresses and to compute the check word, and never builds a pointer from an integer (R1.12).
- R1.11. Each entry point checks its arguments in this order, so that C and Rust give one answer for one input:
  1. a null pointer where the contract needs one, `GRDR_E_ARG`;
  2. for `grdr_fp_eval` and `grdr_fp_interest`, the handle record of R1.12: its flag is clear; then one copy of the rest of the record into a local, whose stored address equals `t` and whose check word recomputes to the stored one. A failure is `GRDR_E_CHANGED`. Nothing is read through an address the record holds until the copy passes, and from then on the call reads the record only through the copy;
  3. address checks, each `GRDR_E_ARG`, against the blob and arena ranges, taken from the arguments of `grdr_fp_arena_size` and `grdr_fp_load` and from the record's checked copy otherwise:
     - an output range that meets the blob or the arena: the `out` of `grdr_fp_arena_size`, `grdr_fp_load`, `grdr_fp_eval` and `grdr_fp_interest`. Writing through one would change validated bytes while the handle reads them;
     - an input struct whose base-size range meets the arena, since reading it would alias the arena the handle holds;
  4. a `struct_size` below the base size, or a struct whose `struct_size` range meets the arena, `GRDR_E_ARG`;
  5. one copy of the input struct's fields (R1.11a);
  6. for `grdr_fp_eval`, `check_pairing` on the copy's `Tables` value with the input's labels, so RC1 is `GRDR_E_CHANGED` and a label mismatch `GRDR_E_STATE`, as in Rust;
  7. the checks only C has, each `GRDR_E_ARG`, with every length checked before any slice is built:
     - a blob or arena not 8-aligned; a `path_encoding` or `dest_kind` value outside its set; an `unresolved` value with a bit outside its three, or with a bit set for a value the struct holds (a `path_len` above 0, a `dest_kind` above 0 or a non-zero `exe_digest`);
     - `path_len` above the handle's `path_max_units`, compared as code units, before the slice exists;
     - a UTF-16LE byte length, `path_len` times 2, computed with `checked_mul`;
     - any byte length above `isize::MAX`, the precondition of `core::slice::from_raw_parts`, for the path, the destination name, the blob or the arena;
     - `dest_name_len` above `layout::NAME_MAX_BYTES`;
     - a blob and arena whose address ranges overlap, which would let `load` write its index into the blob it validated;
     - a path or destination name whose range meets the arena.

  Steps 1, 3 and 4, and the alignment, value-set, `unresolved`, overlap and range checks of step 7, have no Rust counterpart, because a Rust caller cannot pass a null, a short struct, an unknown encoding, a contradictory resolution or aliasing slices. Step 2 is the C form of R2.12a and RC1. The length checks of step 7 come after step 6, as Rust's `Arg(Path)` and `Arg(Destination)` come after its pairing checks. For every input both can express, the answers are equal, which #418's differential checks. An all-zero digest with its `unresolved` bit clear becomes `Absent`, and `path_len` 0 with its bit clear becomes `path: Absent`. The Rust surface reads bytes at any alignment.
- R1.11a. Inputs during a call. The host owns each input struct, and the memory its pointers reach, for the whole call: it keeps them in memory no less privileged process can write, unchanged until the call returns (section 12, `c-abi.md` section 4). The FFI reads `struct_size` once and then copies the fields it covers once, by value, into a local before any further check, so no check and no use read a field twice. Its conversion function takes the struct by value, so a second read of host memory for a field cannot be written. The bytes the path and the destination name point to are read where evaluation needs them, which can be more than once. Their stability for the call is the host obligation above, which the `SAFETY` comment of each slice cites. In Rust the borrow of `Input` already gives both.
- R1.12. Its arena holds the handle record first, then the arena `grdr-fastpath` uses.
  - The record holds its own address, the `Tables` value over the FFI's raw view type, a check word and the record's changed flag. The two raw views hold the blob's and the arena's base pointers, with the provenance `grdr_fp_load` received from the host, and their lengths as it validated them, and build their slices from those pointers in `as_ref()`. `Tables` holds, beside its two views, only integers, the header copy and its own flag. A raw pointer, like an integer, is a valid value for any initialised bytes, so any bytes in the record are a valid value, and reading a changed record is defined behaviour.
  - Each call that takes `t` reads the record's flag, with `Acquire`, then copies the rest of the record once into a local, checks the copy, and builds every view and reads the header copy from it alone (R1.11 step 2). A write to the record after that copy does not reach the call, and the next call's check sees it.
  - The check word is 32 bytes, as wide as the widest field it covers. It is computed from field values, never from the record's bytes, so no padding is read: the record's own address, the two views' addresses (through `addr`) and lengths (through `Tables::storage`), and each field of the header copy (through `Tables::header`). Neither flag is in it. It folds the fields one at a time, each widened to 32 bytes, by an exclusive or into the running value followed by a fixed bijection of that value, so any change confined to one field changes the word. A change to two or more fields can keep it, which is R2.13's residual. The fold costs about a hundred word operations per call.
  - Any `GRDR_E_CHANGED`, from the record check or from the library, sets the record's flag by one atomic store with `Release`. The library's own flag inside the record's `Tables` value is never written after load, since the library runs on the copy. The FFI writes nothing when the copy's stored address differs from `t`, because it cannot tell that a record lies there. That one case is not sticky, and only the host's retirement of the handle (R2.16) stops further answers from it.
  - `grdr_fp_arena_size` is the record's size rounded up to 8 plus `arena_size(blob)`, in saturating arithmetic. R2.1's bound keeps it far below `PTRDIFF_MAX`, so it has no size error, and a saturated sum could only make `grdr_fp_load` refuse the arena.
  - `grdr_fp_load` splits the arena, calls `load` with the blob and the second part through the raw view type, and writes the record into the first part. That is an `unsafe` block with a `// SAFETY:` comment citing the custody text of section 12: the host keeps the blob and the whole arena, record included, alive, unchanged and out of reach of any less privileged process, from `grdr_fp_load` until its quiescence point after it retires the tables (R2.14). The copy of step 2 is a second `unsafe` block, a read by value of each record field but the flag, which another thread may store to at the same time. Its comment cites the same text and the validity of any bytes as a record.
  - After `grdr_fp_load`, the only arena byte the library writes is the record's flag, by one atomic store (section 12).
- R1.13. It maps a `Verdict` to `grdr_fp_verdict`:
  - the verdict numbers come from `layout`;
  - `rule_index` and `reason_code` are `UINT32_MAX` for `Pass`;
  - `StepUp` has scope `NONE`;
  - the scope number is `c-abi.md`'s;
  - `expiry_ns` follows `tables.md` section 6: the header value for `Session` and `Bundle`, where all ones means until the scope ends, and 0 for `Call` and `None`.

  It maps `Interest` to `grdr_fp_interest_view`. Each span's `ptr` is the address of its first record in the blob, or null when its `count` is 0. `count` is `Records::count`, and `record_size` is the `Record` implementation's size. `strings` and `strings_len` are the pool's address and length, with `strings` null when the pool is empty. A test in #418 holds the empty case for each span and for the pool.
- R1.14. It maps `Error` to `grdr_status` in one nested `match` that names every leaf variant, with no wildcard at any depth (R4.2). The constants `GRDR_FP_ABI_MAJOR`, `GRDR_FP_ABI_MINOR` and `GRDR_FP_ABI_VERSION` (RFC 0004 section 9), and the value `grdr_fp_abi_version()` returns, come from `layout`. The cache-scope, path-encoding, destination-kind, `unresolved` and status values, which only `c-abi.md` fixes, are its own constants. RFC 0004's `HDR-3` and `HDR-4` hold them to the contract and the registry.

### 6. Error codes (R4)
ARCH-017 binds every error variant to an entry in `schema/codes/<area>.toml`. `grdr-fastpath` has no dependency, so it cannot name `grdr-schema`'s generated codes. Three bindings were weighed:
- **(a) Entries in `schema/codes/fastpath.toml`, with the mapping in `grdr-core`.** The orphan rule keeps `grdr-core` from implementing a `grdr-model` trait for a `grdr-fastpath` type, so the binding would be a function in `grdr-core`. The daemon is the fast path's one Rust consumer, and ARCH-004 keeps `grdr-core` out of its closure, so the mapping would never reach the code that meets the errors.
- **(c) A test-only binding through a `grdr-schema` dev-dependency of `grdr-fastpath`.** A test could hold every variant to a code, but non-test code that constructs those codes would need its own copy of the mapping, which the test cannot see (P17). The test would bind codes nobody raises, or check a copy.
- **(b) Bound in two places, each whole.** Each leaf variant maps to one row of `spec/host-contract/status-codes.toml` through the FFI crate's match, which `HDR-4` holds to the registry. Each leaf also maps to one registered code through the daemon's floor module, where ARCH-017 applies in full.

**Decision: (b), exempted one variant at a time.** The leaves are the eleven variants that carry no fault type: the six of `ArgFault`, `Abi`, the two of `BundleFault`, `State` and `Changed`.
- R4.1. Each leaf has its own entry in the ARCH-017 entry list of `architecture.toml`, in the list form RFC 0002 section 14 proposes, with typed fields, not prose:
  - `type` and `variant`, such as `grdr_fastpath::ArgFault` and `Arena`;
  - `registry`, `spec/host-contract/status-codes.toml`, and `status`, the row's name;
  - `bound_in`, `grdr-fastpath-ffi`;
  - `coded_by`, `grdr-daemon`, and `code`, the reason of the code R4.3 registers.

  The entries are the one copy of both mappings, leaf to status and leaf to code. The two `match` expressions that implement them are checked against the entries, so neither is a second source:
  - ARCH-017 checks that the registry exists and holds a row named `status`, that `code` is a reason registered in area `FASTPATH` (R4.3), that `bound_in` and `coded_by` depend on the type's crate, and that every variant of a listed type has its own entry, unless it is a wrapper. So a variant added later fails the lint until it has an entry of its own.
  - A wrapper is a tuple variant whose only field is an enum that has entries of its own, here `Error::Arg(ArgFault)` and `Error::Bundle(BundleFault)`. ARCH-017 resolves a wrapper to the entries of its field's type and gives it no entry. Any other variant, a tuple variant over a type with no entries included, needs its own entry. In `grdr-core`, `FastpathCompileError::Effective` is a wrapper over a type bound in the ordinary way (R4.4).
  - An entry with `coded_by` and `code` is an exemption: its type has no code of its own. An entry without them binds a status only, for a type whose codes are bound in the ordinary way, and exempts nothing (R4.5). ARCH-017 checks both kinds the same way for `registry`, `status` and `bound_in`.
- R4.2. The FFI crate's mapping is one nested `match` naming every leaf, with no wildcard at any depth.
  - A test, `status_per_variant`, reads the entries from `architecture.toml` with `grdr-cabi-testkit`'s row reader (RFC 0004), the FFI crate's existing dev-dependency, and checks the crate's mapping against each entry's `status`.
  - The test's own nested `match`, again with no wildcard, lists the leaves by name only, so a new leaf fails the test's build. A leaf the mapping sends to a status other than its entry's fails the test's run.
  - The test holds the five parent pairs of R1.5 (`Arg` and `GRDR_E_ARG`, `Abi` and `GRDR_E_ABI`, `Bundle` and `GRDR_E_BUNDLE`, `State` and `GRDR_E_STATE`, `Changed` and `GRDR_E_CHANGED`) in a second `match` of its own, and checks every entry's `status` against its parent's. An entry change that swaps two parents' statuses then fails, even when both mappings follow it. The five pairs are the parent level R1.5 states, not a copy of the leaves.
  - The same test shows that each fast-path status row is produced by at least one leaf, which is ARCH-017's "every registered code is constructed somewhere" for those rows.
- R4.3. The daemon's floor module (#427, `programs/grdr-daemon/src/floor`) maps every leaf, by a nested `match` with no wildcard, to its own variant of the daemon's error, bound by ARCH-017 to one code each.
  - The codes are in area `FASTPATH` (subsystem: the fast-path evaluator; owner: docs/design/26), with their `/codes` pages and runbooks.
  - `Bundle(Rule(n))` is one code, with the TV number as a structural field.
  - Section 2a adds three codes of the daemon's own: entering floor-missing on `Changed`; a repeat, which ends reloading; and a reload policy that gave up. Each is named for what the daemon observed, never for a cause, because a `Changed` can come from a defect or from a write (R2.19). Every `Changed` from a served handle also raises a tamper finding (D-22).
  - #427 registers the codes, and its acceptance gains "every `grdr_fastpath` leaf variant has one registered code". Its test `code_per_variant` reads the entries as `status_per_variant` does and checks the daemon's mapping against each entry's `code`.
  - #1538's `Refused { code }` uses the load-side codes.
  - A person never meets a fast-path error as such. The host answers as R2.17 says and reports under these codes.
- R4.4. `FastpathCompileError` is in `grdr-core`, which has `grdr-schema`, so ordinary ARCH-017 applies.
  - `CostAboveCap`, `TooLarge`, `Limit` and `NarrowingRefused` bind to four entries of area `COMPILE` (subsystem: the effective-policy compiler; owner: docs/design/12), with the reasons `FASTPATH_COST_ABOVE_CAP`, `FASTPATH_TOO_LARGE`, `FASTPATH_LIMIT_OUT_OF_RANGE` and `FASTPATH_NARROWING_REFUSED`.
  - `Effective` carries the code of the error it wraps and has no entry of its own (R4.6).
  - Whichever of #71 and #414 lands first creates area `COMPILE` through #278's registry, and #414 adds its four entries.
  - `TooLarge` needs a blob above 4 GiB, so #414 reaches it through the compiler's size check, called with section counts at the bound, without building the blob.
- R4.5. `grdr_engine_compile_fastpath`, which #388 and #378 R3 leave to a later C ABI minor, calls `compile_fastpath` with `Facts::Relay` and `FastpathLimits::from_limits()`, narrowed by any input the item that adds it decides to take. It maps each leaf of `FastpathCompileError` to a status in one nested `match` with no wildcard:
  - `CostAboveCap` and `TooLarge` are `GRDR_E_BUNDLE`, and the loaded bundle stays;
  - `Limit` is `GRDR_E_INTERNAL`, a defect in the shipped `limits.toml`, which R3.6's test keeps unreachable;
  - `NarrowingRefused` is `GRDR_E_ARG`, the caller's own value, reachable only once the function takes a limits input;
  - `Effective` is a wrapper. Each leaf of `EffectiveCompileError` maps to the status #71 states for it: a fault of the bundle to `GRDR_E_BUNDLE`, a memory cap to `GRDR_E_RESOURCE`, and a failed consistency check to `GRDR_E_INTERNAL`.

  Each of these leaves, #71's included, has a status entry of R4.1's form with `bound_in` `grdr-ffi` and no `coded_by` or `code`. The item's `compile_status_per_variant` checks `grdr-ffi`'s mapping against them as `status_per_variant` does. A host whose ceiling is below our cap needs a limits input on that function, which the item that adds it decides (section 13).
- R4.6. Design/03 section 10 says "One enum per crate". This RFC settles it as follows, and proposes the wording to design/03 (section 12):
  - In `grdr-fastpath`, `Error` is the floor tables' enum, and it mirrors the statuses of `grdr_fastpath.h`. The fail-safe table and the field scanner get their own enums in their own modules when they arrive, because their failures never cross that header, and putting them in `Error` would force C statuses for errors that never reach C.
  - In `grdr-core`, `FastpathCompileError` sits beside #71's error. `grdr-core`'s modules are its future crates (design/03 section 2), and RFC 0002, in review, gives each port module of `grdr-ports` one enum in the same way.
  - A variant that only wraps another bound error takes that error's code, as `Effective` does, and ARCH-017 recognises it by R4.1's wrapper rule.

### 7. The per-call cap and the other header bounds (R5)
The cap could be a header field written by the compiler from a `limits.toml` row, or a row generated into `grdr-fastpath` as a constant. A constant would put our default inside every partner's library, needing a rebuild to change. A blob from a partner's relay could not state its own cap. A host would have nothing in the blob to compare with its ceiling.

**Decision: the header, as #245 rules** (`tables.md` sections 2, 7, 11 and 13; the chief architect's comment on #405 recording it):
- R5.1. `eval_cap`, `path_max_units`, `expiry_bundle_ns` and `expiry_session_ns` are header fields. The compiler writes them through `FastpathLimits` (R3.6) from four `limits.toml` rows, named as RFC 0007 section 6 requires: `fastpath.eval-cap` and `fastpath.path-max` in `count`, and `fastpath.expiry-bundle` and `fastpath.expiry-session` in `ms`. `from_limits` converts each `ms` value to nanoseconds with checked arithmetic, and a value that overflows or gives 0 is `Limit`, naming the row. `grdr-fastpath` holds none of them.
- R5.2. In the header, an expiry of all ones is `Expiry::ScopeEnd`, until the scope ends, and TV-8 refuses 0, so 0 only ever means "never reused" (`tables.md` section 6). No `limits.toml` row holds either number: a row is an amount, and RFC 0007 section 6 gives the format no value for "unbounded".
- R5.2a. Who may lengthen reuse (ruling 9 on #1710). Reusing a verdict for longer is a widening, as SR-26 (design/02 section 3.8) counts a longer timeout, so the sources of each scope's expiry are ordered:
  - by default the expiry is `After` the row's amount;
  - only the signed bundle the compiler reads may choose `ScopeEnd` for a scope, through a field of its manifest. That choice is a widening, so SR-26's signature rule applies to it as to any other widening, and an artefact signed by an operator alone cannot make it. The field is a bundle format change that needs its own RFC, filed on acceptance (section 13). Until it exists, no blob our compiler writes carries `ScopeEnd`;
  - `FastpathLimits::narrow` can only shorten. A `grdr.config` key that sets a fast-path expiry, if one is ever added, reaches the compiler only through `narrow`, so it can shorten an expiry, the bundle's `ScopeEnd` included, and never lengthen one or choose `ScopeEnd`. In RFC 0007 revision 3's terms such a key is a `setting` whose ceiling is the expiry's row;
  - the header's expiry for a scope is the shorter of what the bundle chose (`ScopeEnd`, or `After` the row's amount when it chose nothing) and the amount `narrow` set, when it set one. `FastpathLimits` records that it set one (R3.6), so a narrowing to the row's own amount still bounds a bundle's `ScopeEnd`.

  `fastpath_expiry_source` (#414) holds this. With no bundle choice the header carries the row's amount. `narrow` to a shorter amount writes that amount. `narrow` to an amount above the current one is `NarrowingRefused`. `from_limits()` and `from_limits()` narrowed to the row's own amount are unequal values. No input but the bundle writes all ones. The item that adds the manifest field adds the cases of a bundle that chooses `ScopeEnd`, with and without a shorter `narrow`.
- R5.3. Three parties hold the bounds:
  - the compiler refuses a bundle whose worst case exceeds the cap (R3.7);
  - `eval` refuses an input whose cost exceeds it (R2.3);
  - a host refuses a blob whose `eval_cap` or `path_max_units` exceeds its own ceilings, taken from its configuration, so a blob cannot raise the work a host accepts per call.

  A Rust host reads both values from `Tables::header()` after `load` and before it publishes the handle, and at the same point copies `loss_closed_classes` into its floor state (R2.17). That header copy is what every call reads (R2.8), so the check and the use read one value. A C host reads all three from its private copy before `grdr_fp_load`, and keeps them only if the load succeeds (`tables.md` section 11). Today `tables.md` section 11's cap obligation covers `eval_cap` only. Adding `path_max_units` is a change for #245 (section 12), and the daemon's tests of both are #1769's.

  Our daemon's ceilings are two `limits.toml` rows, `fastpath.host-eval-cap-ceiling` and `fastpath.host-path-max-ceiling`. Each is a `[bound.*]` row in `count` with the `min`, `max`, `scope` and `effect` keys RFC 0007 revision 3 makes required: `scope = "fixed"`, because they bound what a blob may ask for, no setting reads them and they change only by release, and `effect = "none"`. They are read through `grdr-schema`'s generated module, which is constants only and so admitted in a privileged closure. They are bounds, not operator settings, so they are not `grdr.config` keys (`grdr-structure`'s values table); an operator setting would need a stated use first. A test in #1538 holds `fastpath.eval-cap` and `fastpath.path-max` at or below them, so our own compiler's blobs always load on our daemon. The rows land with `[retry.fastpath-reload]` (R2.18) and `fastpath.reload-settle` (R2.19), also `fixed` and `none`, through one protected `limits.toml` item, filed on acceptance (section 13). #1768's four rows take the same keys, `fixed` and `none`.
- R5.4. The argument checks of R2.3 step 2 scan the input path once, linearly in its length, before the cost check. An `Unresolved` path is not scanned. `eval_cap` does not count that scan; `tables.md` section 7's cost model counts steps per row and per entry. So `path_max_units` bounds the scan, and for a blob from elsewhere only the host's ceiling bounds `path_max_units`.
- R5.5. RFC 0007 section 7 settles the units: the expiry rows are whole milliseconds, which `from_limits` converts (R5.1). R5.2a settles which source may choose `ScopeEnd`. `Expiry`, its mapping to the header and the order of R5.2a are this RFC's. #1768's lead writes the rows' values and their `min` and `max` within R5.2a, and the library never sees a row.

### 8. Stability (R6)
- R6.1. `surfaces.toml` gains a row kind for a public crate: `[[crate]]`, with the keys `name`, `class` and `rfc`. Each value is one double-quoted string on its own `key = "value"` line, the subset #1817's rows use.
  - Three rows, all `experimental`: `grdr-fastpath`, `grdr-fastpath-ffi`, and `grdr-core` unless another accepted RFC has added it.
  - A protected-change item adds the row kind and the rows once this RFC is accepted and #1817 has created the file.
  - ADR-0020's gate reads these rows for `cargo public-api` and `cargo semver-checks`.
- R6.2. A class is per crate. `compile::fastpath` has `grdr-core`'s class, and no row classes a module. A crate's class is at most the class of every crate whose public types its own public API exposes. `grdr-core` exposes `grdr_fastpath::layout::Nanos` (in `Narrowing`), so it cannot move above `grdr-fastpath`. `cargo public-api` lists the exposed types, and the stability gate checks the rule.
- R6.3. The blob format, `table_format` 1, is experimental by `tables.md` section 12, and the C header's class is its `[[c_header]]` row (#1817). This RFC sets neither.
- R6.4. An experimental crate may break, but a break bumps its major, with no overlap (ADR-0020, D-71). Under SemVer 0.y, `cargo semver-checks` treats the next 0.y as that major. A break is an amendment that names this RFC.
- R6.5. Moving any of the three crates to `beta` needs:
  - an RFC that changes its `surfaces.toml` row (design/30 section 3);
  - the external embed pilot of D-60, since `grdr-fastpath` mirrors `table_format` 1 and the C ABI, which stay experimental until it completes;
  - `#[non_exhaustive]` or constructors on `Input`, `Narrowing` and every `layout` record, so that a field added later is not a break;
  - a decision on which enums stay exhaustive (`Error` does, for R4.2);
  - `layout` versioned with `table_format`;
  - design/03 F3's freeze, and #1771's header compatibility gate.
- R6.6. Determinism holds within one compiler version, since `compiler_version` changes with each release (R3.10). Golden blob tests compare blobs with the six `compiler_version` bytes masked by one test helper, so a release bump changes no golden vector. A caller-set version was rejected (Alternatives).

### 9. Dependencies (R7)
- R7.1. `grdr-fastpath`: no normal or build dependency (design/26 section 2; #409 AC-5). Its tests may take `proptest` as a dev-dependency once #432 admits it to the workspace. That adds no package to `Cargo.lock` and never enters the normal or build graph.
- R7.2. `grdr-fastpath-ffi`: `grdr-fastpath` only, plus `grdr-cabi-testkit` as a dev-dependency (RFC 0004).
- R7.3. `grdr-core`: `grdr-model` and `grdr-fastpath`, its listed same-layer edges, and `grdr-schema` in layer 0 for codes and limits. `cedar-policy` and `proptest` reach it through #431's ruling and #432's admission. #414 is blocked by #432, and #20 by #21 and #414.
- R7.4. The fuzz target of SD-04 (section 11) uses the libFuzzer harness #415 admits, in the item that builds it. This RFC adds no third-party dependency and no edge. A ruling here would make two RFCs answer for one dependency set.

### 10. Failure modes, data classes and assurance effect
| Failure | Outcome | Visible as |
|---|---|---|
| A TV rule fails at `arena_size` or `load` | `Abi` for TV-3, `Bundle(Rule(n))` otherwise; no handle; the host keeps the tables it was using, or stays without tables if it had none or only retired ones | The returned error; the host reports under its `FASTPATH` code (R4.3) |
| The arena is too short | `Arg(Arena)`; no handle | As above |
| A C argument or length is invalid; blob and arena overlap; an output meets the blob or arena, or an input lies in the arena; an `unresolved` bit is unknown or contradicts a value the struct holds | `GRDR_E_ARG`; nothing written | The status; the host answers as R2.17 says |
| Label bits from another bundle | `State` on every call until labels and tables agree | The returned error; the host answers as R2.17 says and reports |
| An input field out of range, or a `Resolved` path or name outside the library's form | `Arg`, naming the field. A host passes a path or name it cannot put in that form as `Unresolved` (R2.3b), so this is a host fault | As above |
| An input value the host could not resolve, or cannot pass in the library's form | The rows it could meet give their own outcome, with scope `none`; never a cacheable `pass`, and never a cached verdict (R2.3b) | The verdict; nothing cached |
| An input whose cost exceeds `eval_cap` | `Bundle(EvalCap)`, never a verdict; unreachable for a blob our compiler wrote (R3.7) | As above |
| A re-check of section 2 fails, in any step, the cost step included | `Changed`, never a verdict and never `EvalCap`; the changed flag is set; the host retires the handle and its generation at once (R2.16) | The returned error or `GRDR_E_CHANGED`; the host reports under its code, raises a tamper finding and is Degraded (R2.19) |
| A call on a handle that returned `Changed` before, though its storage reads valid again | `Changed` (R2.12a) | As above |
| In C, the handle record changed in a way its check sees, or moved | `GRDR_E_CHANGED`; nothing read through its addresses (R1.11 step 2); sticky unless the stored address differs from `t` (R1.12) | As above |
| In C, the record written after the call's copy was checked | The call answers from its copy; the next call's check sees the write (R1.12) | As above, from the next call |
| A run entry in the arena is rewritten, an emptied run included | `Changed` from RC2's boundary rows | As above |
| A `Changed` from a handle already retired | No state change and no new finding (R2.19) | Nothing new |
| A verdict cached under the retired generation, or returned by a call running at the transition | Never read and never inserted; the action is answered as R2.17 says (R2.16) | The answer carries `floor-missing` |
| Between retiring the handle and a successful reload | Floor-missing: an action of a class in the host's copy of `loss_closed_classes`, by a process inside a session container, is denied at once; every other action goes on as after a floor `pass`; the old interest filters stay (R2.17) | `degraded_reason` `floor-missing`; the device is Degraded |
| A start before any tables were adopted | Every floor lookup denies (#427 R8) | `degraded_reason` `floor-missing` |
| A reload attempt fails or times out, for any reason | Floor-missing stays, never the retired tables; the next attempt follows `[retry.fastpath-reload]` (R2.19) | The daemon's code for the failure |
| `Changed` again from a handle on probation | A tamper finding; floor-missing; reloading ends (R2.19) | The repeat code and the finding |
| The reload policy gives up | Reloading ends; floor-missing until an activation is adopted or the host restarts (R2.19) | The daemon's code |
| A new activation, or a recompile on new device facts, while the floor is missing | Its tables are tried at once; adopted, the host serves them on probation; refused, floor-missing stays as it was (R2.19) | The activation's report (#1538) |
| Storage changes in a way no re-check sees: valid blob bytes, or in C a record rewritten in two or more fields with its check | A verdict from the changed bytes (R2.13); in C outside R2.9, so also a read of memory no TV rule checked, or a fault | Not visible to the library; custody (R2.14) prevents it |
| An input the host changes during the call | Outside the contract (R1.11a): the FFI reads each field once, and a changed path or name byte is answered as read | Not visible to the library; the host obligation prevents it |
| A host's ceiling is below the blob's `eval_cap` or `path_max_units` | The host refuses the blob and keeps the tables it was using | The host's report (#1769) |
| No floor row objects | `Pass`, which is not `ALLOW` | The verdict; the host goes on to the engine, or, when the engine cannot answer, to its loss-of-sensor outcome |
| A bundle whose worst case exceeds the cap, or a blob too large | `CostAboveCap` or `TooLarge`; no blob | The `COMPILE` code; the caller keeps the tables it was using, never tables that returned `Changed` (R2.19) |
| A built-in limit row out of range | `Limit(row)` | The `COMPILE` code, naming the row |
| A narrowing above the current value, or out of range | `NarrowingRefused(row)` | The `COMPILE` code, naming the row |
| A fail-closed rule the floor cannot hold | Its `FloorReport` outcome; the rule keeps its class's loss-of-sensor outcome, and its class's bit when it declares `@on_loss("block")` (R3.11) | The floor report, which #71 and #41 read |
| An interest set that selects too little | Not detectable at `load`; held at compile time by R3.9 | `fastpath_compile_interest` fails |
| A volume of unknown case | Its classes fold, which errs toward `deny` | The compiled `path_fold_classes` |

Data classes (P8):
- `action_class`, `principal_kind`, `dest.port`, the verdict, the rule and reason indices, the scope and the expiry are `structural`;
- `Digest` values, `bundle_tag`, and a destination name and address are `identifier`;
- `labels.bits` and `ClassBits` are `derived`;
- the target path is `content` (`content_kind` argument);
- the `Resolution` variant and the C `unresolved` bits are `structural`;
- header and records take the classes of `tables.md` section 14, and so does the `Blob`, which is `content` when it holds a resolved template and then never leaves the device;
- `loss_closed_classes`, and the host's copy of it, are `structural`;
- a volume mount point is `identifier`;
- the record's addresses and check word are `structural` and never leave the process;
- errors and the floor report are `structural`, and the tamper finding of R2.19 carries only its code and `bundle_digest`.

`grdr-fastpath` logs nothing, and R1.7 keeps content and identifiers out of `Debug`.

Assurance effect (P1): none of its own. The surface carries the floor rows that answer fail-closed classes while the engine is gone (D-15, D-20), and its items' tests are the evidence for `control` of those classes. While the floor cannot answer, section 2a keeps every class that holds a fail-closed floor row closed for processes inside session containers, so `on_failure` for those classes stays what the assurance record states, and no record value changes.

### 11. Mechanisms
| Decision | Mechanism | Built by |
|---|---|---|
| No raw pointer, `unsafe`, `alloc` or dependency in `grdr-fastpath` | `#![forbid(unsafe_code)]`, `#![no_std]`; `cargo tree -e normal,build` shows the crate alone; ARCH-001 | #409 (AC-5); #1580 |
| No truncating cast in either crate | `#![deny(clippy::as_conversions)]` at both crate roots, beside `arithmetic_side_effects` | #409; #418 |
| Builds for `wasm32-unknown-unknown` | `cargo build --target wasm32-unknown-unknown -p grdr-fastpath` | #409 (AC-6) |
| 32-bit arithmetic is executed, not only compiled; the FFI's `unsafe` runs under Miri (SD-01) | The nightly Miri job runs `grdr-fastpath`'s tests for `i686-unknown-linux-gnu`, which Miri interprets without a 32-bit libc, and `grdr-fastpath-ffi`'s tests on the host target, `ffi_record_changed` included | #1475 |
| `load`, the path decoder and the name check are fuzzed (SD-04) | A fuzz target over `load`, `eval` and `classify`, differential against #409's reference validator and #412's unindexed evaluator; a spurious `Changed` on unchanged storage fails it | The fuzz item filed on acceptance, blocked by #415 and #409 |
| Of `grdr-core`, only `compile::fastpath` imports `grdr-fastpath`, and only `layout` | ARCH-013's import table reads the edge's `importers` and `paths` in `architecture.toml` (section 12). Until #1582 lands, `eval-architecture` checks every change to `crates/grdr-core/src/**` | #1582; the `architecture.toml` item filed on acceptance |
| One layout definition, independent oracles | `layout` shared; #409's reference validator; #412's fixtures; #414's golden rows; #20's differential; the comparison-count vectors | #409, #412, #414, #20 |
| TV-3 has one representation | `TvRule` cannot hold 3; `fastpath_rule_variant`: a blob that fails exactly one rule gives the variant `tables.md` section 5 names, for every rule | #409 |
| Rust and C give the same answers | #418's behaviour: on any blob, `grdr_fp_load` then `grdr_fp_eval` equal `load` then `eval` | #418 |
| The FFI's argument, length, overlap, range and `unresolved` rules, in R1.11's order | One seeded test per R1.11 rule, each expecting its status with nothing written; one with a mismatched label tag and an over-long path, expecting `GRDR_E_STATE` from C as `State` from Rust | #418 |
| The C views come only from the checked copy of the record | `ffi_record_changed`: for each field the check word covers, a changed value gives `GRDR_E_CHANGED` from `grdr_fp_eval` and `grdr_fp_interest`, and so does a record copied to another address; a write to the record after the copy is checked leaves that call's answer as the copy gives it, and the next call gives `GRDR_E_CHANGED`; under Miri no read goes through a changed address, and every view keeps the provenance the host passed | #418; #1475 |
| Each input field is read once | The conversion function takes `grdr_fp_input` by value (R1.11a); `eval-security` checks it on #418's pull request | #418 |
| The library's path form | `fastpath_path_form`'s vector table, run by #412's tests and by #418's differential | #412; #418 |
| An unresolved value never gives a cacheable `pass` and never meets a cached verdict | `fastpath_unresolved`: for each classifier, an `Unresolved` value against rows that require its classes gives their outcome with scope `none`, a `pass` over one has scope `none`, and the cost counts its classifier's entries. #1769's lookup case: an input with an unresolved value misses the verdict cached for its absent twin | #412; #410 for `classify`; #418 for the C field; #1769 |
| A value an agent chooses never reaches an argument error | The host obligation of `tables.md` section 11 and `c-abi.md` section 2.1 (section 12); #1769's tests that an over-long path, a refused name and an executable the host cannot hash are each passed as unresolved | #245; #246; #1769 |
| While the floor cannot answer, the classes of its fail-closed rows stay closed | `loss_closed_classes`, written by the compiler (R3.11) and checked by TV-8 and TV-26; the host's copy taken at adoption (R2.17); `fastpath_loss_classes`; `fastpath_reload`'s answer cases, the honeytoken rule and an added pack among them (R2.20) | #414; #409; #427; #245 |
| The label tag is read little-endian | A #412 vector whose first eight digest bytes are not a palindrome | #412 |
| Each re-check gives `Changed` at its first read, none fires on unchanged storage, and an undetected change is recorded | The tests of R2.15, `fastpath_changed_rc2_cost`, `fastpath_changed_rc2_empty`, `fastpath_one_view` and `fastpath_no_false_changed` among them | #412, with #410 for RC2 and RC4 to RC6 in `classify` |
| `Changed` is sticky | `fastpath_changed_sticky`; in C, `ffi_changed_sticky` for the record's flag, set by a failed record check and by the library's `Changed`, and a case whose stored address differs from `t`, which writes nothing | #412; #410; #418 |
| `reload-required` is a state with bounded exits, the retired generation never answers, and every `Changed` is reported as tamper | `fastpath_reload`, `fastpath_reload_cache` and `fastpath_reload_loop_stops` (R2.20) | #427 |
| The host keeps blob, arena and inputs in custody | The contract text of section 12; for our daemon, #1769's custody race test extended to the arena, where a write to the arena after `load` must give `Changed` through RC2, and to the cache, where a verdict cached before `Changed` is never read while the floor is missing | #246; #245; #1769 |
| Every leaf variant maps to its status, every fast-path status is produced, and each leaf's status is its parent's | The nested no-wildcard mapping (R1.14), checked against the entries' `status` and the five parent pairs by `status_per_variant` (R4.2); `HDR-4` against `status-codes.toml` | #418; #1778 |
| The ARCH-017 exemption is per variant, typed, and the one copy of both mappings | The entries of R4.1, whose `status`, `code`, `bound_in` and `coded_by` ARCH-017 checks; the wrapper rule; status-only entries for compile errors | The `architecture.toml` item; #1582 |
| Every leaf variant has a registered code where the errors are met | The daemon's nested no-wildcard mapping, checked against the entries' `code` by `code_per_variant`; ARCH-017 on the daemon's enum; area `FASTPATH` | #427; #278 |
| Our daemon's ceilings, settle bound and reload policy are data | The `limits.toml` rows of R5.3, R2.18 and R2.19; a test that the compiler's defaults sit at or below the ceilings | The `limits.toml` item filed on acceptance; #1538 |
| `FastpathCompileError` codes and C statuses | Area `COMPILE`; ARCH-017; #278's drift test; the no-wildcard status match of R4.5, checked against its entries by `compile_status_per_variant`; `TooLarge` through the size check at the bound (R4.4) | #414; #71; #278; #1582; the `grdr_engine_compile_fastpath` item |
| No bound in `grdr-fastpath` | The four header fields; TV-8; `FastpathLimits` from the generated module; ARCH-019 | #1768; #414; #409; #1582 |
| Only the signed bundle lengthens reuse; a setting only shortens it | `narrow` refuses a longer value and records what it set; `fastpath_expiry_source` (R5.2a) | #414; the manifest field's item |
| A blob from our compiler never reaches the cap, whatever the host resolves, and the built-in limits are valid | `CostAboveCap` with a seeded bundle above a small cap through `FastpathLimits::narrow`, and with a large executable classifier whose `Unresolved` term sets the worst case, after which no input, an unresolved digest included, gives `Bundle(EvalCap)`; `from_limits` is `Ok` on the committed file | #414 |
| A host's ceilings bound `eval_cap` and `path_max_units` | The host obligation of `tables.md` section 11, widened to `path_max_units`; the daemon's negative tests | #245; #1769 |
| The interest set covers every floor row, unresolved paths, destinations and digests included | `fastpath_compile_interest` (R3.9) | #414 |
| Unknown or missing volume facts fold | A test with `CaseRule::Unknown`, an empty `volumes` and a partial one, each expecting the class's fold bit set | #414 |
| Concurrent evaluation is safe | A type-level test that `Tables`, `Interest` and `Records` are `Send + Sync`, for borrowed and boxed storage; #412's determinism property | #412 |
| Derives are those of R1.7, and no content or identifier reaches `Debug` | `cargo public-api` lists every derived trait, so ADR-0020's gate shows a change; a test per redacting type of R1.7, `Records` included, that its `Debug` output holds no byte of the value it was built from | #409, #410, #412, #414 for their types; ADR-0020's gate item |
| The interest view maps empty sections to null | A #418 test per span and for the pool (R1.13) | #418 |
| The ABI's highest action class equals the spine's | A test in `grdr-core` that `layout`'s ceiling equals the highest `grdr.common.v1alpha1.ActionClass` number, so a new class fails until a new minor raises it | #414 |
| The fast path is a deliberate second implementation (P17) | An `architecture.toml` record of the pair `grdr-fastpath` and `grdr-core`, held equal by the B2 differential | The `architecture.toml` item; #20 |
| Each crate has a class, and no crate outranks what it exposes | `[[crate]]` rows; `cargo public-api` and `cargo semver-checks` | The `surfaces.toml` item filed on acceptance; ADR-0020's gate item |
| Golden blobs survive a release | The masking helper of R6.6 | #414 |

### 12. Proposed changes to contracts, design documents and gate files
Each lands through the item named, or an issue whose write set names its file, after acceptance. The texts under "Required amendments" are exact, and are posted as comments on their items.

**`c-abi.md` and `status-codes.toml`** (#246, while it is open; otherwise a protected-change item):
1. A new status, `GRDR_E_CHANGED`, value 11, the next free one. Its `meaning` is "Fast path only: the tables' blob, arena or handle no longer reads as `grdr_fp_load` validated it, now or on an earlier call on the same handle." Its `handle_after` is `reload-required`, a new value whose text, in the registry's header comment and in `c-abi.md` section 7, is section 2a's state:
   - retire the handle at once and never call it again; its cache generation stops being current, no verdict cached under it is read, and the result of a call that was running on it is discarded;
   - until a load from a freshly verified copy succeeds, the floor is missing: answer as `tables.md` section 11 says when the floor cannot answer, keep the interest filters, and report Degraded;
   - free the old blob and arena only after the quiescence point;
   - start the first reload at once and bound the rest with a retry policy. Report every `GRDR_E_CHANGED` from a handle in use as tamper, and end reloading when a reloaded handle returns it before it has served a settle period.

   Section 6 says the fast path uses five statuses, not four.
2. The `grdr_fp_eval` and `grdr_fp_interest` rows list `GRDR_E_CHANGED`.
3. The `grdr_fp_eval` check order of R1.11 and R2.3:
   1. a null pointer, `GRDR_E_ARG`;
   2. the handle record's flag, then one checked copy of the record, `GRDR_E_CHANGED`;
   3. the address checks against the copy's ranges, then `struct_size`, `GRDR_E_ARG`;
   4. one copy of the input's fields;
   5. a failed RC1, `GRDR_E_CHANGED`; then a label mismatch, `GRDR_E_STATE`;
   6. the remaining argument and length checks, with the path form of R2.3a in place of "the canonical form of #221 R4", `GRDR_E_ARG`;
   7. the class above `action_class_count`, which gives `pass` with scope `none`;
   8. the cost, where a failed re-check of what the cost reads is `GRDR_E_CHANGED` and a cost that exceeds `eval_cap` is `GRDR_E_BUNDLE`;
   9. evaluation, where a failed re-check is `GRDR_E_CHANGED`.

   So `GRDR_E_CHANGED` can come before the cost result.
4. The argument rules of R1.11 in the rows of all four fast-path functions: address checks before any read, the record check before any read through its addresses, lengths checked before any slice, `PTRDIFF_MAX` as the largest byte length, the name maximum, blob and arena overlap, outputs that meet the blob or arena, inputs inside the arena, and the `unresolved` rules.
5. The `grdr_fp_verdict` text: a `step_up` verdict, and any verdict over an unresolved value, has `cache_scope` `NONE`. Its cache paragraph takes the exact text under "Required amendments".
6. The `grdr_engine_compile_fastpath` row: `GRDR_E_BUNDLE` also when the worst-case cost exceeds the cap, `GRDR_E_INTERNAL` for invalid built-in limits, `GRDR_E_ARG` for a refused narrowing once the function takes a limits input, and the statuses of #71's leaves (R4.5).
7. Arena custody, in section 2 and the `grdr_fp_load` row, replacing "The blob and arena must outlive the tables": "The host keeps the blob and the whole arena, the tables handle included, in memory no less privileged process can write and its own process can, unchanged from `grdr_fp_load` until its quiescence point after it retires the tables, except for the fast path's own flag store (item 10)" (R2.14).
8. Input custody, in section 4, replacing "Inputs are borrowed for the duration of the call and never retained": "Inputs are borrowed for the duration of the call and never retained. The host keeps each input, and the memory its pointers reach, in memory no less privileged process can write, unchanged until the call returns. The fast path reads each field of an input struct once, before any check" (R1.11a).
9. A new field of `grdr_fp_input`, `uint32_t unresolved`, declared after `dest_port` (R2.3b). On 64-bit targets it sits at offset 108, in what is padding today, so the base size stays 160, and on `wasm32` the base size stays 144. Another 32-bit target lays it out under its own C ABI; on i386 System V, where `uint64_t` aligns to 4 inside a struct, it moves the later fields and the base size becomes 144. ABI 0.1 is unpublished until #246 merges, so the field is part of 0.1's base size, and no host built to 0.1 lacks it; after publication the same change would need a major (ADR-0020).
   - Bit value 1 is the path, 2 the destination and 4 the executable digest. A set bit requires its value to be absent in the struct (`path_len` 0, `dest_kind` 0, an all-zero `exe_digest`); any other bit, or a bit set beside a value, is `GRDR_E_ARG`.
   - The `exe_digest` comment becomes "all zero: none supplied, unless `unresolved` says it could not be resolved".
   - Section 2.1 gains: "A host that has a path, destination or executable digest it could not resolve, or cannot pass in the form this section states, sets its bit in `unresolved` and never passes the value as absent (`tables.md` section 11)."
10. The fast path's writes, in sections 2, 4 and 5: it writes the arena in `grdr_fp_load`, and afterwards only the handle's changed flag, by one atomic store, in `grdr_fp_eval` and `grdr_fp_interest`. The section 2 rows' and section 5's "pure" becomes "deterministic while the blob and arena are unchanged", both stay callable concurrently on the same tables, and the comment on `grdr_fp_tables` says that the arena it lives in stays writable by the host's process.
11. The `GRDR_E_BUNDLE` row and the definition of `last-known-good`, with the exact text under "Required amendments".
12. Section 7's fast-path failure rule, with the exact text under "Required amendments".
13. The alignments of Unresolved question 2.

**`tables.md`** (#245):
1. Section 11, Cap: the host's ceiling also bounds `path_max_units` (R5.3).
2. Section 13: a class folds when a volume it can reach has an unknown case or is missing from the facts, and a change of the device's volumes is a recompile (R3.5).
3. Section 13: the compiler test that proves interest coverage is #414's `fastpath_compile_interest`.
4. Section 6: the order of the vocabulary case against the argument checks and the cost (R2.3).
5. Section 11, Custody: the arena joins the blob, with the text of `c-abi.md` item 7 above (R2.14), and inputs follow `c-abi.md` section 4 (item 8).
6. Sections 10 and 11: the host's state after `GRDR_E_CHANGED`, as section 2a states it. Section 10's cache paragraph gains: "A handle that returned `GRDR_E_CHANGED` is retired with its generation. The host reads no entry of that generation again, discards the result of a call that was running on it, reads no generation while it has no tables, and never reuses a generation number. A cache key holds the input's `unresolved` bits (`c-abi.md` section 2.2)."
7. Section 5, the sentence after the table, with the exact text under "Required amendments".
8. Section 6, Target path: the form the library checks is R2.3a's, and the rest of section 11's path form is the host's alone.
9. Sections 3.5, 6 and 7, unresolved values (R2.3b):
   - section 6's "An empty path, an absent destination or an all-zero executable digest contributes no bits" becomes "An absent path, destination or executable digest contributes no bits. An unresolved one contributes every class bit its classifier can set, and the verdict's scope is `none`";
   - section 6's cache rule 1 adds "when any input value is unresolved";
   - section 7 adds "with an unresolved value: one step per entry of its classifier, in place of that classifier's term";
   - section 3.5 adds that an action whose path or destination the host could not resolve is of interest whenever the interest set holds any path or host entry, and that a process whose executable digest the host could not compute is in scope whenever the interest set holds any kind 1 entry, since the host cannot tell which entry it would meet.
10. Section 7: after `grdr_fp_load`, the library writes only the handle's changed flag (`c-abi.md` item 10).
11. Sections 2 and 13: the row names of R5.1, and in section 2's source table, that each expiry is the shorter of the bundle's choice and any narrowing (R5.2a).
12. Sections 2, 4, 5 and 13, the header field `loss_closed_classes` (R2.17, R3.11):
    - section 2 gains the row "224 | 8 | `loss_closed_classes` | u64 | Bit `n` set when the bundle has a floor row of action class `n`, or an enforced rule of class `n` that declares `@on_loss("block")`; such a class answers closed while the floor cannot answer (section 11)", so the header is 232 bytes. Its source table gains "`loss_closed_classes` | The action classes of the floor rows, and of the bundle's enforced rules that declare `@on_loss("block")`";
    - 224 becomes 232 in section 4 item 3, in section 5's opening paragraph, and in TV-5, TV-11 and TV-14;
    - TV-8 also refuses a `loss_closed_classes` with bit 0 or a bit above `action_class_count` set;
    - TV-26 also refuses a floor row whose `action_class` has its bit clear in `loss_closed_classes`;
    - section 13: the compiler writes the field as R3.11 says.
13. Section 11, two new host obligations, with the exact text under "Required amendments": when the floor cannot answer, and unresolved values.
14. Section 13, Cap: the worst case takes each resource input in whichever of its absent, resolved and unresolved forms costs most (R3.7).

**Required amendments** (each posted on its item as a comment headed "Required amendment from RFC 0005 revision N", where N is the revision that last changed it: 6 for #246 and #245, 5 for #1538; the decision waits until all are posted):

- **#246, `spec/host-contract/status-codes.toml`.** The `GRDR_E_BUNDLE` row becomes:

  ```toml
  [[status]]
  name = "GRDR_E_BUNDLE"
  value = 4
  meaning = "Bundle rejected. For the fast path, a table blob that fails a TV rule, or an evaluation whose cost exceeds the blob's eval_cap. The host keeps the tables it was using before the call, unless those tables returned GRDR_E_CHANGED: such tables are never used again, so a host that held only those, or none, has no tables until a load succeeds."
  handle_after = "last-known-good"
  ```

  The header comment gains, after its list of `handle_after` values: "last-known-good means the host keeps the handle or tables it was using before the call; tables that returned GRDR_E_CHANGED are never last-known-good."
- **#246, `spec/host-contract/c-abi.md` section 2.2.** The paragraph after the `grdr_fp_verdict` struct becomes:

  > No verdict is 0, so a host that reads a verdict it never received sees an invalid value, not `pass`. Scope `none` is 0, so the same mistake never caches. The scope and expiry rules are those of `tables.md` section 6. A host caches a floor verdict only under its scope, keyed by the generation of the tables that gave it (`tables.md` section 10) and the input's resource identity: action class, path, destination, executable digest and the `unresolved` bits, plus the principal kind and session for `session`. A verdict over an unresolved value has scope `none` and is never inserted, so an input with an `unresolved` bit set never meets a cached verdict.
- **#246, `spec/host-contract/c-abi.md` section 7.** The bullet "On any error for an `ActionRequest`, and on any fast-path error, the host applies the action class's declared `on_failure` (D-15) and reports it as an event." becomes:

  > On any error for an `ActionRequest`, the host applies the action class's declared `on_failure` (D-15) and reports it as an event. On any status but `GRDR_OK` from `grdr_fp_eval`, and while it has no tables, the host answers the action as `tables.md` section 11 says when the floor cannot answer, and reports it as an event. A status from `grdr_fp_eval` other than `GRDR_E_CHANGED` answers that one action and changes no state.
- **#245, `spec/host-contract/tables.md` lines 386 and 387.** The sentence "A rule that fails leaves the host with no new table handle; the tables it loaded before stay in use, and the host applies the class's declared `on_failure` (D-15) and reports the status." becomes:

  > A rule that fails leaves the host with no new table handle. The host keeps the tables it was using, unless those tables returned `GRDR_E_CHANGED`: tables that did are retired with their cache generation and never used again (section 10), so a host that held only them has no tables until a load succeeds. Until then the floor cannot answer, and the host answers as section 11 says. Either way the host reports the status.
- **#245, `spec/host-contract/tables.md` section 11.** Two bullets join the host obligations, after Path form and Destination form:

  > - **Unresolved values.** An input value the action has, but the host cannot pass in the form the fast path takes, is unresolved, never absent: a target path the host could not resolve, or that fails the form of section 6 or has more code units than `path_max_units`; a destination the host could not resolve, or a name that is not in the form of section 3.3; an executable digest the host could not compute. The host sets its bit in `unresolved` (`c-abi.md` section 2.1), so no value an agent chooses gives an argument error.
  > - **When the floor cannot answer.** When the host adopts tables, it copies `loss_closed_classes` from its private copy of the blob into its own state, outside the blob and the arena. Two statuses of `grdr_fp_eval` are answered by calling it again, at most once each for an action, and the last call's verdict answers the action. On `GRDR_E_STATE`, the host calls again with `label_bits` 0 and the tag of the tables it loaded, the first eight bytes of their `bundle_digest` (section 8), so a row that reads no label answers for every process. On `GRDR_E_ARG` for an input that holds a path or a destination, it calls again with whichever of the two the input holds unresolved, so the library is the one checker of their form. Each call made again keeps the changes of the one before it, and the host caches nothing from it. The floor cannot answer an action while the host has no tables, when `grdr_fp_eval` still returns a status other than `GRDR_OK`, and when the host discards a call's result (section 10). The host then answers from that copy, never from the tables: an action whose class has its bit set, by a process inside a session container (D-15), is denied at once, without waiting for the content engine; every other action goes on as after a `pass` (section 6). A status from `grdr_fp_eval` other than `GRDR_E_CHANGED` answers that one action and changes no state. A host that has adopted no tables since it started holds no copy, and denies every floor lookup.
- **#1538, R3 and the soak line.** R3 becomes:

  > R3. The daemon validates the floor blob with #409's validator before use, and after `load`, before it adopts the handle, checks the header against its ceilings and copies its `loss_closed_classes` into its floor state (RFC 0005 R5.3, R2.17). A valid blob within the ceilings replaces the current `FloorSource` between decisions. A blob that fails validation or a ceiling, a failed compile or a failed self-test is refused, and the daemon's floor state stays as it was (RFC 0005 section 2a): serving tables stay in use; in floor-missing after `Changed` it stays floor-missing and never returns to the retired tables, since tables that returned `Changed` are never last-known-good; on first start, before any tables are adopted, #427's `floor-missing` holds and every floor lookup denies. The compile instance of R2 is also the reload source of RFC 0005 R2.18: a reload after `Changed` compiles the active bundle again in a fresh instance. A change of the device's volumes is a recompile, adopted as an activation is (RFC 0005 R2.19).

  The soak line becomes:

  > Trust core: soak evidence is `cargo test -p grdr-daemon --test bundle_adopt -- --ignored soak`, 1,000 activations under a 50-per-second Decide load with zero unanswered calls. While the daemon holds tables, every answer comes from either the old or the new table, never neither. The soak also changes the serving storage at seeded points so that the serving handle returns `Changed`. From that call until a reload or an activation is adopted, every answer is floor-missing (RFC 0005 R2.17: an action of a class in the copied `loss_closed_classes`, by a process inside a session container, is denied, every other action goes on as after a floor `pass`, and each carries `degraded_reason` `floor-missing`). None comes from the retired table or from a verdict cached under its generation, every `Changed` raises a tamper finding, and an activation refused in that state leaves the daemon floor-missing.

**Design documents** (the chief architect, through one issue):
- **design/26 section 2.** The sentence that fast-path functions return `GRDR_E_ARG`, `GRDR_E_ABI`, `GRDR_E_BUNDLE` and `GRDR_E_STATE` gains `GRDR_E_CHANGED` for a blob, arena or handle that no longer reads as loaded. The sentence after it becomes "On an error from `grdr_fp_eval`, and while it has no tables, the host answers as `tables.md` section 11 says when the floor cannot answer, and reports it". The label-pairing row of its test and evaluation table expects "`GRDR_E_STATE` on every call; the host calls again with label bits 0 and the tables' own tag, so a floor row that reads no label, such as honeytoken use, denies a session outside any session container as it denies one inside".
- **design/26 section 3, error model.** The status table gains the row `GRDR_E_CHANGED` (11), "Retire the handle and its generation, reload from a freshly verified copy, and until then answer as the floor cannot". The `GRDR_E_BUNDLE` (4) row's "Last-known-good stays active" becomes "The tables in use before the call stay active, unless they returned `GRDR_E_CHANGED`".
- **design/26 section 3, retries.** It owns `fastpath-reload`: `kind = "exponential"` with no `honour_hint`, the first attempt at once, a call timeout that ends a hung attempt, a breaker and a give-up. It also owns `fastpath.reload-settle`. The values are `limits.toml` rows that name design/26 as their owner.
- **design/03 section 2, crate table.** `grdr-fastpath`: "`no_std` table evaluator over fixed-layout inputs, the table layout `grdr-core` writes through, and the bounded field scanner; no dependencies". `grdr-fastpath-ffi`: "`extern "C"` entry points and the `#[repr(C)]` structs of `grdr_fastpath.h`, so `libgrdr_fastpath` carries no engine code (26); core squad".
- **design/03 section 2, same-layer edges.** "`grdr-core` to `grdr-fastpath` (table layout only: module `compile::fastpath` imports `grdr_fastpath::layout`, its types, constants, codecs and the cost function of the table format)".
- **design/03 section 10, Errors.** "One error enum per crate, or per module where the module is a future crate or serves its own interface. A variant that only wraps another bound error takes that error's code" (R4.6).
- **design/03 section 10, Retries.** The list of named policies gains `fastpath-reload` (26).
- **design/12 section 16.** A property row: "Interest set covers the floor rows | the compiled interest set | exhaustive up to 20 class bits, random above" (R3.9).

**Gate and registry files** (protected changes):
- **`architecture.toml`.** On the `grdr-core` to `grdr-fastpath` edge, `importers = ["compile::fastpath"]` and `paths = ["grdr_fastpath::layout"]` beside the existing `scope`, whose text gains "and the cost function". The eleven per-variant ARCH-017 entries of R4.1, and the status-only entries of R4.5 for `FastpathCompileError`'s leaves. One record of the independent pair `grdr-fastpath` and `grdr-core`, whose reason names the `no_std` fast path of P17 and the B2 differential (#20) that holds them equal.
- **`surfaces.toml`.** The `[[crate]]` row kind and its three rows (R6.1).
- **`schema/codes/`.** Area `COMPILE` and its four entries (R4.4); area `FASTPATH` with one entry per leaf variant and the three state codes (R4.3).
- **`security/requirements.yaml`.** The requirements SR-new-A to SR-new-R that eval-security's threat-model deltas on #405 propose, filed for the security squad. They cover the re-checks and their status, the FFI's rules and record, custody of the blob, arena and inputs, the floor-missing state and its reload, unresolved values and the cache key, the answer while the floor cannot answer, and verdict reuse that only the signed bundle can lengthen.
- **`limits.toml`.** The four rows of #1768, with RFC 0007's names and keys (R5.1, R5.3). A new protected item adds `fastpath.host-eval-cap-ceiling`, `fastpath.host-path-max-ceiling`, `fastpath.reload-settle` and `[retry.fastpath-reload]` (R5.3, R2.18, R2.19).

### 13. What each item changes
This RFC is normative. Each lead writes these changes back into its item before readying it.
- **#409.**
  - R2's layout types are `grdr_fastpath::layout` (section 3), with `Record` sealed and the header of 232 bytes with `loss_closed_classes`.
  - R3 and R4 are `arena_size` and `load` as R2.1 and R2.2 state, over `Tables<B, A>`, keeping the storage lengths, the header copy and a clear changed flag. The arena size has R2.1's bound and no error of its own.
  - R5's errors are `Abi`, `Bundle(Rule(n))` and `Arg(Arena)`, with `TvRule` unable to hold 3 and the number from `Error::rule`. It adds `fastpath_rule_variant`, whose blobs include one failing TV-8 and one failing TV-26 through `loss_closed_classes`.
  - It adds `clippy::as_conversions` to the crate root, and the derives and redacting `Debug` of R1.7 for its types.
  - Its write set gains `crates/grdr-fastpath/src/layout.rs`, `crates/grdr-fastpath/src/layout/**` and `crates/grdr-fastpath/AGENTS.md`, whose purpose line no longer says the inputs are `#[repr(C)]`.
  - `proptest` may be its dev-dependency (R7.1).
- **#410.** `classify` is public and returns `Option<ClassBits>` as R2.4 states, with the bits of R2.3b for `Unresolved` inputs, executable digests included. It fails with `Bundle(EvalCap)` or `Changed`, never partial bits. It checks the changed flag first, makes RC2 in its cost step and RC4 to RC6, `prefix_len` included, at the first read of what each guards, passes its views to the pairing checks, and adds the tests of those checks and of the sticky flag. The cost is the shared function of `layout`.
- **#412.**
  - `eval` returns `Verdict` with the scopes of R1.3 and R1.4, in the order of R2.3.
  - R2's vocabulary case follows `tables.md` section 6: a class within the ABI but above `action_class_count` is `Pass { scope: None }`, not `Arg`.
  - `Input` carries `Resolution` for its three resource inputs, evaluated as R2.3b says, and the path form is R2.3a's. It adds `fastpath_unresolved`, the `fastpath_path_form` vector table, and a label-tag vector whose first eight digest bytes are not a palindrome.
  - It makes RC1 to RC3, RC5 and RC6 at the first read of what each guards, the cost step included, over one view of each storage per call, with the views passed to the pairing checks (R2.10). RC2 checks the boundary rows. The changed flag is sticky, stored with `Release` and read with `Acquire` (R2.6, R2.12a). It adds the tests of R2.15 and the type-level test of R2.6.
  - `check_pairing` is public (R2.3), and `reason` returns `Result` (R2.7). R7's `interest` is R2.5's. `Tables::storage` is public (R1.12), and `Tables` holds, beside its views, only integers, the header copy and its flag.
  - Its arena holds the run index and nothing else (R2.11).
- **#414.**
  - R1 is `compile_fastpath` as section 4 states, with `Facts`, `CaseRule::Unknown`, `FastpathLimits` and `Narrowing`. R6's report gains the outcomes of `tables.md` section 13.
  - R8 reads its bounds through `FastpathLimits`, under the source rules of R5.2a, with `Limit` for a built-in row and `NarrowingRefused` for a narrowing (R3.6). R9 binds to area `COMPILE` with four entries (R4.4), which it creates if #71 has not.
  - It writes `loss_closed_classes` (R3.11) and adds `fastpath_loss_classes`.
  - It adds `fastpath_compile_interest` with its process-scope inputs, catalogue fixture, unresolved paths, destinations and digests, and one witness per row (R3.9), the fold test, the cost-refusal test with a large executable classifier (R3.7), the `TooLarge` size-check test (R4.4), the `from_limits`, `fastpath_expiry_source` and action-class-ceiling tests, and the masking helper (R6.6).
  - Its `grdr-core` types follow R1.7's derives and `Debug` rule, and `FastpathCompileError` implements `Display` and `core::error::Error`.
- **#418.**
  - It defines the C structs (R1.10), with the `unresolved` field and its 64-bit and `wasm32` layout asserts, and converts and checks in R1.11's order, calling `check_pairing` before its own field and length checks, with one test per rule. Its conversion takes the input struct by value (R1.11a).
  - It lays out its arena as R1.12 says: the handle record with its address, the raw views as pointers with provenance, the 32-byte check word and the record's flag, with the custody text in its `SAFETY` comments. Each call takes one checked copy of the record. It adds `ffi_record_changed` and `ffi_changed_sticky`.
  - It maps verdicts, interest views and errors as R1.13 and R1.14 say, with the empty-section test, adds `status_per_variant` reading the `architecture.toml` entries and the five parent pairs (R4.2), runs the `fastpath_path_form` table through its differential, and adds `clippy::as_conversions` to its root.
- **#388.** `grdr.h` takes the shared status block, so `grdr-ffi` defines `GRDR_E_CHANGED` with `c_status!` to pass `HDR-4`, though no engine function returns it. Its `grdr_status_str` returns the new row's name, and its handle-state tests list the `reload-required` value.
- **#1778.** `content::grdr_status` renders row 11 in both C ABI headers. Its row reader also reads the ARCH-017 entries of `architecture.toml`, which use the same one-string-per-line subset, for `status_per_variant`, `code_per_variant` and `compile_status_per_variant`.
- **#20.** No change beyond the names: R2 calls `compile_fastpath`, `load` and `eval`, and R5 calls `classify`, whose `None` case it skips. Its differential draws `Resolved` and `Absent` inputs only, since the engine has no worst-case bits for an unresolved value.
- **#71.** Its step 8 writes the fast-path blob by calling `compile_fastpath` (R3.3), and its `compile` takes `DeviceFacts` (R3.5). Its error is the one `Effective` wraps, and it may create area `COMPILE` for it (R4.4). It states the C status of each leaf of `EffectiveCompileError` and adds their status entries (R4.5).
- **#427.**
  - Its floor module maps every `grdr_fastpath` leaf variant to its own coded error, registers area `FASTPATH` with the three state codes, raises a tamper finding on every `Changed` from a served handle, and adds `code_per_variant` (R4.3).
  - Its floor state is an explicit type with section 2a's states, events and exits: no tables since start, serving with no episode, serving on probation, and floor-missing with its reload pending or ended. `fastpath_reload`, `fastpath_reload_cache` and `fastpath_reload_loop_stops` test them (R2.20).
  - On adopting tables it copies their `loss_closed_classes`. On `Changed` it retires the handle and its generation (R2.16). On `State`, `Arg(Path)` or `Arg(Destination)` it calls again as R2.17 says. Whenever the floor cannot answer, for another `Arg`, a `Bundle(EvalCap)` or an error of a call made again from a served handle, as well as in floor-missing, it answers as R2.17 says: the copied set's classes deny for processes inside session containers, and every other action takes R5's path as after a floor `pass`. An error other than `Changed` changes no state. R8's deny-all stays for a start before any tables were adopted.
- **#1538.**
  - R3 and the soak line take the exact text under "Required amendments".
  - Its `Refused { code }` uses the load-side `FASTPATH` codes.
  - It tests that the compiler's defaults sit at or below the ceiling rows of R5.3.
  - It recompiles when the device's volumes change, and the daemon adopts the result as an activation (R3.5, R2.19).
- **#1769.** It gains the daemon's negative tests for both ceilings (R5.3), and its custody race test covers the arena (R2.14) and a verdict cached before `Changed`, which is never read while the floor is missing (R2.16). It also tests the host obligation for unresolved values: an over-long path, a destination name outside `tables.md` section 3.3 and an executable the host cannot hash are each passed as unresolved, and an input with an unresolved value misses the verdict cached for its absent twin (R2.3b).
- **#1768.** Its rows take RFC 0007's names and keys (R5.1, R5.3). They are what `FastpathLimits::from_limits` reads, and the expiry rows hold amounts in `ms`, never a value for "until the scope ends" (R5.2, R5.2a).
- **#1582.** ARCH-013 reads the edge's `importers` and `paths`. ARCH-017 reads the per-variant entries, exemptions and status-only entries alike, checks their `status`, `code`, `bound_in` and `coded_by`, applies the wrapper rule, and fails a variant without an entry (R4.1).
- **#1475.** Its Miri job covers the two fast-path crates as section 11 states.
- **#246 and #245.** The deltas of section 12, its required amendments, and the alignments of Unresolved question 2.

Filed on acceptance, each linked as it blocks:
- the `architecture.toml` change of section 12, a protected change for lead-agent-kit, blocking #414, #418 and #427;
- the `surfaces.toml` row kind and rows of R6.1, a protected trust-core change, blocked by #1817;
- the design/03, design/12 and design/26 amendments of section 12, for the chief architect;
- the `limits.toml` item for the two ceiling rows, `fastpath.reload-settle` and `[retry.fastpath-reload]` (R5.3, R2.18, R2.19), a protected change for lead-agent-kit, blocking #1538 and #427;
- the `grdr-ffi` item that adds `grdr_engine_compile_fastpath` in a later C ABI minor (R4.5), which decides whether it takes a limits input and adds `compile_status_per_variant`;
- the bundle manifest field that chooses `ScopeEnd` per scope (R5.2a), with the RFC a bundle format change needs, for squad core;
- the fuzz item of section 11, blocked by #415 and #409;
- the `security/requirements.yaml` item of section 12, for the security squad.

## Surfaces changed
- `grdr-fastpath` (public crate, layer 1, `experimental`): its first surface, the items of section 1 and the module `layout` of section 3.
- `grdr-fastpath-ffi` (public crate, layer 1, `experimental`): the `#[repr(C)]` structs of section 5 beside the `extern "C"` items of `c-abi.md`.
- `grdr-core` (public crate, layer 1, `experimental`): module `compile::fastpath`, with the items of section 4.
- The host contract, as changes for #246 and #245: a new status `GRDR_E_CHANGED` and its `handle_after` value with the host state it names, new statuses on two fast-path rows, the `grdr_fp_eval` order, the argument, length, range and record rules, the `unresolved` input field, the cache key, arena and input custody, the fast path's flag write, the `GRDR_E_BUNDLE` row and `last-known-good`, the answer when the floor cannot answer, the header field `loss_closed_classes` with its TV checks, and the `tables.md` obligations of section 12.
- As proposals: the `[[crate]]` row kind and three rows of `surfaces.toml`; the `architecture.toml` edge keys, per-variant and status-only ARCH-017 entries and independent-pair record; the design/03, design/12 and design/26 text of section 12; areas `COMPILE` and `FASTPATH` in `schema/codes/`; two ceiling rows, a settle row and a retry policy in `limits.toml`; a bundle manifest field, left to its own RFC.
- No change to a protobuf package, the Cedar schema, a same-layer edge, the spine or the licence policy.

## Alternatives
- **The `#[repr(C)]` input and verdict in `grdr-fastpath`, re-exported by the FFI crate** (#405 R1 as written; RFC 0004 D10). The Rust API would carry raw pointers and `struct_size` that safe Rust cannot read, a second input type beside the safe one, and the C ABI's minor rule inside the crate's SemVer line. Rejected for R1.8.
- **A borrowed handle only, `Tables<'a>`.** It matches C, but the daemon owns its buffers, and safe Rust cannot store a handle beside the buffers it borrows. The daemon would need `unsafe`, a leaked buffer per swap, or a self-referential dependency. Rejected for R1.9.
- **A sealed storage trait.** Not viable, for the reasons of section 2. Rejected.
- **Re-running every TV rule on each call.** Each rule is linear in the blob, against a per-call bound of rows touched. Rejected for the closed re-check list.
- **Re-checks after the cost step.** The cost reads the run index and the pattern lengths, so a changed index would come back as `EvalCap`, whose `handle_after` keeps the tables. Rejected for re-checks at first read (R2.12).
- **RC2 as a bounds check alone.** An emptied run passes it, and the call returns a cacheable `Pass`. Rejected for the boundary rows, which TV-27's order makes exact.
- **A pure handle that answers again once its storage reads valid.** A flaky page, or a writer that restores the byte after the call that tripped, would resume answers from tables known to have changed. Rejected for the sticky flag (R2.12a), which costs one atomic load per call.
- **Comparing the C views with the handle's own fields alone.** RC1 then compares the handle with itself, and one pointer-sized write redirects the blob. Rejected for the record's stored address and check word (R1.12).
- **Reading the C record in place at each use.** A write that lands between the check and a view escapes the check. Rejected for one checked copy per call (R1.12).
- **Views stored as integers, or a 64-bit check word.** A pointer rebuilt from an integer has no provenance, and reading through it is undefined behaviour. A 64-bit word cannot see every change to a 32-byte field. Rejected for pointer views and a 32-byte word (R1.12).
- **A record the host cannot reach, such as a static table of handles, or a keyed check word.** The library holds no global state, has no memory a same-privilege writer cannot change, and has no secret to key a check with. Rejected; intent stays with custody (R2.13).
- **Keeping the dropped tables until a reload succeeds.** Every answer in between would come from bytes known not to be the ones validated. Rejected for floor-missing (R2.17).
- **Keeping the retired generation's cache entries.** A `pass` cached at scope `bundle` would answer for the whole outage, and a call in flight would add more. Rejected for R2.16.
- **Each action class's declared `on_failure` while the floor cannot answer.** The bundle declares failure per rule, not per class, so a class that holds a fail-closed row has no single declared answer, and a host could resolve it to `open` from one pack or from the assurance record. Rejected for `loss_closed_classes` (R2.17).
- **The set derived by each host, from its own bundle or from the tables.** A host that embeds only the fast path holds no bundle, two hosts would derive it two ways (P17), and after `Changed` the tables are what changed. Rejected for a header field that the compiler writes, TV-26 checks and the host copies at adoption.
- **The closed answer only when the engine cannot answer in time.** D-20 keeps these classes off the engine's answer, and the engine parses untrusted content. Rejected for an answer at once (R2.17).
- **Deny-all while the floor is missing.** It would deny a person's own shell and every class with no fail-closed rule, against D-15 and design/07 section 10, while the host still holds the bundle's set. Rejected for R2.17; deny-all stays only where the host holds no copy.
- **An over-long path or a refused name as an argument error.** An error is answered without the rows, so an agent that chooses one would avoid them. Rejected for `Unresolved`, which meets them (R2.3b).
- **A cache key without the resolution form.** An unresolved value has the fields of an absent one, so it would meet the verdict cached for it. Rejected (R2.3b).
- **Unbounded reloading.** A defect in `load` gives `Changed` on every fresh copy, so the host would loop. Rejected for the retry policy and the repeat rule (R2.18, R2.19).
- **A reload stop with no time scope.** Two unrelated accidents far apart would end reloading until a restart. Rejected for probation (R2.19).
- **A reload stop keyed by the blob's SHA-256.** A repeat always comes from the newest handle adopted, a fresh copy from the same source holds the same bytes, and a new blob arrives only by an activation or a recompile, which the table tries at once. The key would decide nothing. Rejected for "a repeat ends reloading" (R2.19).
- **A probation counted in calls.** A device with little traffic would hold an episode open indefinitely. Rejected for `ms`.
- **Calling a `Changed` a library defect, or raising a tamper finding only on a repeat.** A write would be filed as a bug, or, spaced past probation, would raise no finding at all. Rejected for neutral codes and a finding on every `Changed` (R2.19, R4.3).
- **Host ceilings as `grdr.config` keys.** They are bounds with no stated operator use, so they are `limits.toml` rows (R5.3). An operator setting can be added when a use is stated.
- **The leaf-to-status mapping in the test as well as the entries and the FFI.** Three copies, two of them unchecked against each other. Rejected for entries as the one copy, with both `match` expressions checked against them (R4.1, R4.2).
- **The handle inside the arena in Rust too.** Writing a typed value into caller bytes needs `unsafe`. Rejected; the FFI crate does it (R1.12).
- **`Changed` as `GRDR_E_BUNDLE` with a wider meaning.** Its `handle_after`, `last-known-good`, tells the host to keep the tables it has, which are the altered ones. Rejected for `GRDR_E_CHANGED`, and the `GRDR_E_BUNDLE` row says tables that returned it are never kept.
- **`Changed` as `GRDR_E_INTERNAL`.** Its meaning is a bug in the library and its `handle_after` is `poisoned`, which the library, holding no state, cannot enforce. A custody fault is not a library bug. Rejected.
- **`#[non_exhaustive]` error enums.** The FFI match would need a wildcard, and a new variant would map silently. Rejected for R1.6.
- **An ARCH-017 exemption by type.** A variant added later would be exempt with no decision, and a match on `Arg(_)` would let a new `ArgFault` inherit a status. Rejected for R4.1 and R4.2.
- **Codes bound in `grdr-core`, or through a test-only `grdr-schema` dev-dependency** (options (a) and (c)). Rejected for section 6.
- **One error variant per TV rule.** It is 33 variants that #245 can still renumber. `TvRule` carries the number. Rejected.
- **`TvRule` able to hold 3.** TV-3 would have two representations, and `Bundle(Rule(3))` would tell a host to keep tables a library cannot read. Rejected for R1.5.
- **`TooLarge` for the arena.** R2.1's bound makes it unreachable, so its variant, entry, status sentence and test could never be exercised. Rejected.
- **One `Limit` variant for a bad built-in row and a refused narrowing.** A caller's own value would read as a library defect. Rejected for `NarrowingRefused` (R3.6, R4.5).
- **An unresolved value as `Arg(Path)` for the classes that carry a path.** It mixes a host fact with a host bug, and the library would need a list of which classes carry a path, which is vocabulary written into code (P14). Rejected for `Resolution` (R2.3b).
- **An unresolved value as `pass` with scope `none`.** The floor would defer to the engine, which `tables.md` section 8 does not trust for these rows, and an agent that can make the host fail to resolve a path would reach the engine's answer. Rejected for worst-case class bits.
- **`step_up` for every row an unresolved value could meet,** D-10's request-level answer. An agent that can make a path unresolvable would turn Block rows into Ask. Rejected for each row's own outcome.
- **`unresolved` as a trailing field behind `struct_size`.** ABI 0.1 is unpublished, so no host built to it lacks the field, and a stray value in it gives `GRDR_E_ARG`, which R2.17 answers. Rejected; the field sits beside the values it qualifies.
- **A wider path-form check in the library,** such as normalisation form C or a link-free path. The library cannot see links or volumes, and a normalisation check needs data tables a `no_std` library with no dependency does not carry. Rejected for R2.3a's syntactic subset.
- **Copying the input path once into the library.** The library allocates nothing, and a path bounded only by `path_max_units` has no stack bound. Rejected: fields are copied once, and the bytes are the host's to keep stable (R1.11a).
- **The cap as a generated constant in `grdr-fastpath`.** Rejected for section 7.
- **Host ceilings as parameters of the Rust `load`.** The Rust and C entry points would differ, and `Tables::header()` already gives the host the one copy every call reads. Rejected for R5.3.
- **`FastpathLimits::new` with free values.** A caller could raise a bound above its row, or choose `ScopeEnd`. Rejected for `narrow` (R3.6).
- **`ScopeEnd` chosen by a `grdr.config` key, or by an argument of `from_limits`** (RFC 0007's open options). A setting could lengthen reuse with no organisation signature, which SR-26 counts as widening. Rejected for R5.2a.
- **`compile_fastpath(bundle) -> Blob`** (#405 R3 as written). It drops the floor report #414 and #71 read, and the device facts and limits `tables.md` sections 2 and 13 need. Rejected.
- **`compile_fastpath` over an effective bundle.** That type does not exist yet (#71), and the verified bundle is the only input a host can vouch for (design/03 section 3). Rejected for now. When #71 lands, both call one emitter (R3.3).
- **A caller-set `compiler_version`.** It would let a caller write a false version into the field that says which compiler wrote the blob. Rejected for the masking helper of R6.6.
- **A load-time TV rule for interest coverage.** Rows naming `Session` are covered through catalogue data the blob does not hold, and an inclusion check over sorted sections is not linear in the blob. Rejected for the compiler test of R3.9; a new rule would be #245's.
- **A per-module class in `surfaces.toml`.** `cargo public-api` and `cargo semver-checks` work per crate. Rejected for R6.2.
- **A separate layout crate.** It adds a crate and two edges, and gives `grdr-fastpath` a dependency against design/26 section 2. Rejected.
- **The layout defined in `grdr-core` and read again by `grdr-fastpath`.** Two definitions of one format (P17), and the edge runs from `grdr-core` to `grdr-fastpath`, not back. Rejected.
- **`classify` behind a `test-util` feature.** ARCH-008 allows the feature, but a build-dependent public surface is harder to reason about than a small public function. Rejected.
- **No `Display` on `Error`.** The daemon could not use `?` into a boxed error. A `Display` that writes identifiers is not person-facing text. Rejected, and `FastpathCompileError` takes the same rule.

## Drawbacks
- Two input types, `Input` and `grdr_fp_input`, with a conversion that #418's differential has to hold.
- Every function carries the storage parameters `B` and `A`.
- The re-checks detect only changes that break one of six invariants. An in-place change to valid blob bytes, or in C a record rewritten in two or more fields with its check, is answered, and in C that falls outside R2.9. Only custody prevents it (R2.13).
- RC2's boundary rows add up to four row reads to every call, and in C the record copy and its 32-byte check add about a hundred word operations.
- The changed flag gives the handle one atomic, and the FFI writes one byte of the arena after `load`, the record's flag. In C, a record whose stored address changed is not sticky, and only the host's retirement stops it.
- Every host carries a floor-missing state with episodes, probation, a bounded reload and its exits (section 2a). Our daemon carries three more codes, and a tamper finding on every `Changed`, a hardware fault's included.
- While the floor cannot answer, a class in `loss_closed_classes` denies every action of a process inside a session container, with the engine healthy too, until a load succeeds. A repeat or an exhausted policy keeps it so until an activation or a restart.
- An undetermined process (D-25) is outside session containers, so while the floor cannot answer, the `Process` rows of a closed class, which design/12 caps at Ask, give way to the engine's and the pack's answers.
- The same holds for every request from a session outside a session container, such as an agent in a shared host (D-25), its hook requests included, and for the rows that leave the principal unscoped, such as honeytoken use (design/12 section 3), for any process outside one. R2.17 keeps D-15's container scope at every control point, as the spine and SR-15 state it, not only at the OS control point design/12 section 3 names. So when the tables are gone and the engine cannot answer in time, a shared-host agent's hook request for honeytoken use takes #427 R5's path, where fail-closed applies only inside session containers (D-15), and is allowed. With no daemon at all, the shim's fail-safe table denies it (design/07 section 10).
- The header grows by 8 bytes for `loss_closed_classes`, and TV-8 and TV-26 each check one more condition.
- An unresolved value meets every row of its classes, so a host that often fails to resolve paths sees more denials, each with its rule and reason.
- Until the bundle manifest field exists, no blob reuses a verdict to the end of its scope, so bundle and session reuse are the rows' amounts.
- A new status, `GRDR_E_CHANGED`, a new `handle_after` value and a new input field for every C host to handle.
- Eleven exemption entries in `architecture.toml`, one per leaf, status-only entries for the compile errors, and a daemon wrapper that repeats the leaves to bind their codes.
- Exhaustive enums make every new variant a breaking change, which `experimental` allows and a later class will price.
- The FFI crate needs two more `unsafe` blocks, to place the record in the arena and to copy it on each call.
- Golden blob tests need a masking helper for `compiler_version`.

## Unresolved questions
1. **#245 is not merged.** If #245 lands with different text, this RFC needs an amendment when any of these change:
   - an error class, a status, or which rule gives `GRDR_E_ABI`;
   - the numbering or grouping of the TV rules, which R1.5, R2.1 and R2.2 bind (TV-3, TV-1 to TV-14, TV-15 to TV-33) and sections 2 and 12 cite (TV-8, TV-16, TV-19, TV-24, TV-26, TV-28 to TV-30);
   - an input field, such as `grant_digest` if #1770 changes how grants reach the host;
   - the section list or a record's fields, which `layout` mirrors;
   - a function, or a header field the compiler writes, `loss_closed_classes` included;
   - which argument checks belong to the library, which R2.3 step 2 and R2.3a fix.

   A change to a rule's content inside one of these, or to the cost model, changes no item here. Accepting this RFC does not wait on #245, and #409, #410, #412 and #414 each already require it.
2. **`c-abi.md` at `ca039ed` differs from `tables.md` at `115ec8b`.** This RFC follows `tables.md`, #246 aligns these with `tables.md` as merged, and #418 is blocked by #246. The differences:
   - the `grdr_fp_load` row applies "TV-15 to TV-31", where `tables.md` has 33 rules;
   - `grdr_fp_eval` check 3 makes an action class above `action_class_count` an argument error, where `tables.md` section 6 gives `pass` with scope `none` within the ABI;
   - the `grdr_fp_eval` row, check 4 and the `GRDR_E_BUNDLE` meaning in `status-codes.toml` say an evaluation "reaches" `eval_cap`, where `tables.md` section 7 says a cost that "exceeds" it, so a cost equal to the cap gets a verdict from one and an error from the other. The required amendment of section 12 settles the registry row;
   - the `expiry_ns` comment says "0: no bound beyond the scope", where `tables.md` section 6 makes 0 "never reused" and all ones "until the scope ends";
   - check 3 points the name form at TV-20, the path grammar, rather than section 3.3 and TV-21, and the path form at #221 R4 rather than R2.3a;
   - the `grdr_fp_eval` row and the `grdr_fp_verdict` text cite `tables.md` section 5 for evaluation, scope and expiry, which are section 6, and section 5 cites `tables.md` section 9 for the arena rule, which is section 10;
   - the `grdr_fp_verdict` text has a host clear its cache on a swap, where `tables.md` section 10 keys entries by a generation and needs no clearing.

   The required amendment of the cache paragraph settles the last item and that paragraph's section reference.
3. **RFC 0007 is in review.** The row names of R5.1 and R5.3 follow its revision 2, and the `min`, `max`, `scope` and `effect` keys of R5.3 follow the session's ruling 7 for its revision 3. If RFC 0007 is accepted with other names or keys, the `limits.toml` items use them, which changes no rule here.
4. **The ARCH-017 exemption list.** RFC 0002 (#1688, in review) proposes its form. If neither RFC is accepted with it, the `architecture.toml` item of section 12 creates the list with the typed fields of R4.1.
5. **Types other items define.** `PathContext` (#221), `Ineligible` (#216), `EffectiveCompileError` (#71) and `RuleId` (the policy module, #212) are named here and defined by their items. If one of them lands with another name, the item that lands it renames the use here, which changes no rule of this RFC.

## Review
Review happens on #405. The review calls for:
- the nine persona council seats;
- `eval-architecture`, the `[kinds] rfc` row of `.claude/risk-tiers.toml` on `main` at `4e46c2c`;
- `eval-security` and `eval-adversarial`, the row #1821 makes data, and `eval-api`, the `public_api_change` trigger's row. This RFC states the public API of two trust-core paths (`crates/grdr-fastpath/**` and `crates/grdr-core/src/compile/fastpath*`), and #405 is high tier with `public_api_change`.

At least one evaluator runs on the other model from the one in the metadata block (owner instruction 7).

Every seat comment and every evaluator verdict on this RFC names the blobs it read, as full 40-character ids, on fixed lines (RFC 0001, "Review binds the decision"; #1798):
- **RFC file:** `git rev-parse <commit>:rfcs/0005-fastpath-rust-surface.md`, with the commit it read.
- **Proposed text:** none. This RFC decides no pinned path of `rfcs/pins.toml`, so it adds no decision line and commits no evidence.
- **Base:** the spine pin in force, `a80859235e7a2a4444648d6fa8d389d78dde6be9`.
- **Contracts read:** the three contract blobs of section 0. A verdict that read other contract blobs names them, and the decision then waits for a revision that names the blobs it rests on.

A comment that cannot compute an id says so on that line and is not a pass. The decision rests on an `eval-architecture` pass that names the RFC file blob it decides. No verdict by an evaluator of this review may fail that blob. The file the decision commits may differ from that blob only in `State:`, `Decision record:`, link lines under this section and the `Decision` section, as RFC 0001 allows.

The verdicts, the session's rulings and the required amendments are linked from the revision comments on #405. The required amendments of section 12 are posted on #246, #245 and #1538 before the decision.

## Decision
Accepted by the chief architect under D-61, on RFC file blob `f6f1eadbff5d189d9966cea2dd3b044f901df7cb`, with the three contract blobs of section 0 and the spine pin in force, blob `a80859235e7a2a4444648d6fa8d389d78dde6be9`, as its base. The orchestrating session decided the outcome under the owner's delegation (#1828), and this section records it with the constraints that session made binding. [ADR-0037](../docs/decisions/ADR-0037-the-fast-path-rust-surface-adopted-by-rfc-0005.md) records the decision.

This RFC decides no pinned path of `rfcs/pins.toml`, so this section holds no decision line, `rfcs/pins.toml` does not change, and no file is added under `rfcs/evidence/`. The move from `Review` to `Accepted` is the one RFC 0001's "RFC states" allows for an RFC that decides no pinned path and holds no line, and an evidence file added without a decision line would be out of route (ADR-0036, "Evidence added in route").

### Review it rests on
On blob `f6f1ead`, on #405, each verdict naming that RFC file blob, the base above and the three contract blobs:
- `eval-architecture` (Sonnet), pass, minors 1 and 2, the delta `git diff 1d591bb f6f1ead` and the whole blob: https://github.com/416rehman/Guardrails/issues/405#issuecomment-7075428051
- `eval-api` (Sonnet), pass, minor O1, the same delta: https://github.com/416rehman/Guardrails/issues/405#issuecomment-7075407504
- `eval-security` round 6 (Opus), pass, minors MN13 and MN14: https://github.com/416rehman/Guardrails/issues/405#issuecomment-7075013043
- `eval-adversarial` round 6 (Sonnet), pass, minors m1 to m3: https://github.com/416rehman/Guardrails/issues/405#issuecomment-7074929458
- the nine seats, each supporting with changes and none reporting a broken spine floor: seat 1 https://github.com/416rehman/Guardrails/issues/405#issuecomment-7075042299, seat 2 https://github.com/416rehman/Guardrails/issues/405#issuecomment-7075067469, seat 3 https://github.com/416rehman/Guardrails/issues/405#issuecomment-7075044503, seat 4 https://github.com/416rehman/Guardrails/issues/405#issuecomment-7075055850, seat 5 https://github.com/416rehman/Guardrails/issues/405#issuecomment-7075081611, seat 6 https://github.com/416rehman/Guardrails/issues/405#issuecomment-7075059961, seat 7 https://github.com/416rehman/Guardrails/issues/405#issuecomment-7075052413, seat 8 https://github.com/416rehman/Guardrails/issues/405#issuecomment-7075062397, seat 9 https://github.com/416rehman/Guardrails/issues/405#issuecomment-7075085892

The decision rests on the `eval-architecture` pass above, as the Review section asks. Every evaluator the review calls for passed `f6f1ead`, with `eval-architecture`, `eval-api` and `eval-adversarial` on the other model from the metadata block, and no verdict on #405 fails it, as the exit rule on #1828 asks (ruling 1 below).

The required amendments of section 12 were posted before the decision: #246 https://github.com/416rehman/Guardrails/issues/246#issuecomment-7074820310, #245 https://github.com/416rehman/Guardrails/issues/245#issuecomment-7074820702 and #1538 https://github.com/416rehman/Guardrails/issues/1538#issuecomment-7074357164.

### Session rulings it relies on
1. The exit rule, https://github.com/416rehman/Guardrails/issues/1828#issuecomment-7074036273:
   > An RFC is decided after the first round in which no evaluator reports a blocker or a major. Minor findings from that round, and changes asked by seats that support with changes, do not open another round. They are written into the decision as constraints, each tied to the issue that builds the surface, which must meet it. Every gate stays: each required evaluator must pass on the decided blob, and trust core still needs two models.
2. The deciding round after round 4, https://github.com/416rehman/Guardrails/issues/405#issuecomment-7074036733:
   > Round 5 is the deciding round under the new exit rule on #1828. It runs eval-security (Opus) and eval-adversarial (Sonnet), the two lanes that failed, as delta reviews. If neither reports a blocker or a major, the nine seats review once and the RFC is decided.
3. Revision 6 and its constraints after round 5, https://github.com/416rehman/Guardrails/issues/405#issuecomment-7074638064:
   > Nothing else changes. Round 6 is a delta review limited to these changes: eval-security on Opus and eval-adversarial on Sonnet. If neither reports a blocker or a major, the nine seats review once and the RFC is decided.
4. The decision, https://github.com/416rehman/Guardrails/issues/405#issuecomment-7075095292:
   > Orchestrating session decision (owner delegated all decisions, #1828): **RFC 0005 is decided as Accepted** on blob `f6f1eadbff5d189d9966cea2dd3b044f901df7cb`, under the exit rule on #1828.

   > The decision record carries the following as binding constraints, each on the issue that builds it. They are not RFC text.
5. The correction to the decision, which withdrew its "Earlier passes, still standing" basis, https://github.com/416rehman/Guardrails/issues/405#issuecomment-7075382924:
   > Session correction (#1828): my decision comment 7075095292 treated the round 4 passes of eval-architecture and eval-api as still standing. They passed blob `1d591bb`, not the decided `f6f1ead`. Revisions 5 and 6 add public items, such as `loss_closed_classes` and `NarrowingRefused`, which neither evaluator has read. The exit rule requires every required evaluator to pass on the decided blob. Both now review `git diff 1d591bb f6f1ead`. #1913's pull request does not merge until both pass. If either fails, the RFC goes to revision 7 and the decision waits.

   Both passed (Review it rests on), so the decision rests on passes on `f6f1ead` and on no earlier pass.
6. Constraint 9 of the decision, as ruled for seat 8:
   > Accepted: the C handle record, its check word and the C compile entry wait for the embedding slice. The slice-0 host is the Rust daemon, so #418's C work moves after slice 0. Compiler options with no first user (the `ScopeEnd` source ordering, `narrow` on expiries, `Facts::Relay`) are not built in slice 0. The three error mappings come down to `coded_by` and `code`.

   > Declined: cutting RC2 to RC6, the reload state machine, or the `Arg` retry. Each closes an attack found in review, and a one-shot reload would worsen constraints 1 and 2.
7. Constraint 11 of the decision, on the round 6 `eval-adversarial` m1:
   > Round 6 adversarial m1 is taken in its strict reading: a `Pass` from the retry, for a contained process in a closed class, is answered as the closed answer (D-20). On #427 and #414.
8. The session's round 3 rulings for this decision record, on `eval-architecture`'s review of it (https://github.com/416rehman/Guardrails/issues/1913#issuecomment-7075512044), https://github.com/416rehman/Guardrails/issues/1913#issuecomment-7075601428. They narrow constraint 9's last sentence, move 4b out of the decision and rebind constraints 2c, 3, 4d, 5a and 5b:
   > - 2c binds #641, #727, #575 and #1734.
   > - #1538 keeps only 2b, the slow background re-adoption, from group 2's coexistence part.
   > - **2a stays bound to both #427 and #1538**, as eval-architecture judged correct.
   > - 3 binds #1384, #1537 and #1853, plus a new item for the `FASTPATH` tokens.
   > - 5a binds #706 and #1302.
   > - 5b binds #760 and #1357.
   > - 4d uses the existing `class` key and binds #278 and #427.
   > - 4b is removed and becomes an amendment item.
   > - 9c is narrowed: `status` stays the single copy, and only the five-pair match goes.
   > - 1a also lists line 776.

   The new item for the `FASTPATH` tokens is #1925, and the amendment item is #1926. Line 776 is #427's section 13 entry.

### Constraints
Each constraint binds the issues named after it. The lead of each issue writes it into the item before readying it, as section 13 asks, and it was posted on each issue under the heading "Constraint from RFC 0005 (decided, #1913)". Where a constraint and the text above differ, the constraint wins for the issues it binds. Where a constraint changes what a host does, the contract text of #245 or #246 takes the same rule, so that a partner host and our daemon answer one way (P17). That is why #245 appears beside #427 under 1a and 11-m1. The new items filed on acceptance are #1914 to #1921, listed after the constraints.

1. Cold start (seats 1, 2 and 4).
   - 1a. With no tables since start, deny-all applies only to processes inside session containers, and a person's own shell is never denied (D-15; design/07 section 10). This replaces "denies every floor lookup" in R2.17, in the R2.19 row for a load that fails with no tables since start, in section 10's row for a start before any tables were adopted, and in each of these places that say the same:
     - #427's section 13 entry, "R8's deny-all stays for a start before any tables were adopted";
     - the Alternatives line "deny-all stays only where the host holds no copy";
     - the last sentence of the #245 amendment "When the floor cannot answer" (section 12), "A host that has adopted no tables since it started holds no copy, and denies every floor lookup";
     - the #1538 amendment of R3 (section 12), "on first start, before any tables are adopted, #427's `floor-missing` holds and every floor lookup denies";
     - #1538's AC-2, "on first start every class denies with floor-missing", which #1538's lead rewrites.

     Binds #427, #1538 and #245, and #1921 for SR-new-W.
   - 1b. The daemon persists the last bundle it adopted and verifies it again at start. Until the signature check of slice 7 exists, "verifies it again" means the adoption checks on the persisted bundle, the generation floor of D-37 included, and a compile in a fresh instance (#1538 R2). It never means a compiled blob kept from before. A persisted bundle that fails any check leaves no tables. Binds #1538, and #1921 for SR-new-Y.
   - 1c. Hooks are enabled only after the first adoption. A hook request before the first adoption, from a harness that already holds a registered hook, is answered by the shim's fail-safe table (D-14), never by the daemon. Binds #1538 and #427.
   - 1d. A `limits.toml` row bounds the window from start to the first adoption. When the bound elapses with no tables adopted, the device stays in the no-tables state of 1a. It is Degraded and reports a code of area `FASTPATH` that #427 registers beside the three of R4.3. It enables nothing, neither hooks nor endpoints, and changes no answer. Binds #1917 for the row, #1538 and #427, which read it, and #1925 for the code's tokens.
2. Recovery (seats 1, 2 and 4).
   - 2a. An audited re-adoption request, from the owner or an operator, is treated as an activation. A solo user has one unelevated command for it. The request names no bundle, path or table. The daemon authenticates its peer as it does every other privileged-side request (design/02, SR-01 and SR-04): it refuses the request from agent lineage inside a session and, where an operator is enrolled, from anyone but the operator. Requests count against a `limits.toml` rate row (#1917). #1930 owns the command and its handler. Binds #1930, #427 and #1538, and #1921 for SR-new-X.
   - 2b. After a repeat `Changed` ends reloading, a slow, bounded background re-adoption from a freshly verified source follows a cooldown. A repeat still ends that cycle, and each attempt raises a finding. The cooldown also covers the requests of 2a, so a loop of requests gives at most the bounded number of adoptions. This adds rows to R2.19's table. Binds #427 and #1538, and #1917 for its retry policy and cooldown.
   - 2c. An incumbent-EDR coexistence case is added to the coexistence pack, with a runbook naming the peer product as first suspect. Binds the coexistence-pack items #641, #727, #575 and #1734.
3. Person-facing reasons (seats 1, 3, 6 and 9). The floor-missing denial, the daemon's state codes (the three of R4.3 and the one of 1d) and a deny over an `Unresolved` input each have a registered presentation row and language tokens. Each carries rule, reason and route (D-44), an LTR isolate for identifiers, and `risk = safety` on the denial text. Binds #1384 and #1537 for the block message, #1853, and #1925, which writes the `FASTPATH` code tokens, the presentation rows and the floor-missing block-message kinds and blocks #427.
4. Evidence (seat 3).
   - 4a. Every answer carries a stable `basis` (closed, open or served), the action class and an episode id. Binds #427, and #429, the receipt item that stamps every answer.
   - 4b. Not a constraint. Seat 3's request that `Changed` carry the failed re-check number contradicts R1.5 and R4, where `Changed` is a leaf that carries no fault type. It is #1926, an amendment item for recording which re-check fired without changing `Error::Changed` (ruling 8 above).
   - 4c. Inputs carry a resolution state, and a deny over an `Unresolved` input is filed as a coverage gap. Binds #427 and #429.
   - 4d. Tamper findings are grouped by bundle digest and compiler version. A code's routing class is its `class` key in the registry (RFC 0007; #278 R2: `input`, `policy`, `retryable`, `fatal` or `internal`), so no new registry field is added. The `FASTPATH` codes take these values (`eval-architecture` M1, https://github.com/416rehman/Guardrails/issues/1913#issuecomment-7075660462):
     - `retryable`: `Arg(Path)`, `Arg(Destination)` and `State`, which the call made again of R2.17 answers; entering floor-missing on `Changed`, where a reload starts at once; and a repeat, which 2b's background re-adoption follows;
     - `fatal`: `Changed`, whose handle never answers again; a reload policy that gave up; and the 1d bound elapsing;
     - `internal`: `Arg(Arena)`, `Arg(ActionClass)`, `Arg(PrincipalKind)`, `Arg(Reason)`, `Abi`, `Bundle(Rule(n))` and `Bundle(EvalCap)`. Our daemon loads only blobs its own compile instance writes (R3.7), so each is a defect in our daemon or compiler;
     - no `FASTPATH` code is `input` or `policy`.

     Binds #278 for the registry, and #427, which fills the key and groups the findings.
5. Fleet (seat 4).
   - 5a. Floor state, tamper findings and per-rule outcome counts go up as metadata. Binds #706, the heartbeat enforcement state and loss counters, and #1302, the device-side delivery.
   - 5b. A pack promotion preview shows the classes added to the closed set for each organisation. Binds #760, the Watch promotion gate, and #1357, its console panel.
6. Privacy (seat 6).
   - 6a. An unresolved executable digest is passed only for processes attributed to a session or left `undetermined`, with a test. Binds #427 and #1769.
   - 6b. `Blob` and `DeviceFacts` have no serialiser or `LogSafe` implementation, and a canary test checks this. Binds #414, and #412 for `Input`, `Path`, `Dest` and `Digest`.
   - 6c. The verdict cache is memory-only, bounded by a row of #1917, and cleared on retirement. Binds #427, and #1769 as a default a partner host is told.
   - 6d. A tamper finding names the device and the bundle only, never a principal, and reads "cause not determined". Binds #427.
7. International (seat 9).
   - 7a. A non-ASCII literal whose characters have no case mapping is compiled on case-insensitive volumes. `FoldNonAscii` stays for cased scripts. Binds #414.
   - 7b. NFD and mark-order vectors go in `fastpath_path_form`, and a name that cannot be normalised becomes `Unresolved`. Binds #412 for the vectors and #418 for its differential, and #427 and #1769 for the host rule.
   - 7c. The accepted vectors include U+200C, U+200F, U+061C, U+3000 and U+FF0F. Binds #412 and #418.
8. Contributors (seat 7).
   - 8a. Whichever of #245 and #246 lands first carries, in its pull request body, a table of every section 12 change: the change, the item that lands it, the file and section of the text it produces, and whether it has landed. Each later item that lands one updates its row in its own pull request body. Binds #245 and #246.
   - 8b. Each item of section 13 has the review lane the table below gives. Binds every item it lists.
   - 8c. Each oracle and named test of this RFC sits at a fixed path: `<crate or program root>/tests/<name>.rs`, or `tests/<name>/` when it needs more than one file. Each item writes the path into its plan. Binds #409, #410, #412, #414, #418 and #427.
   - 8d. The `AGENTS.md` of `grdr-fastpath` gains a "Where things are" table. Binds #409.
   - 8e. The decision record quotes the session rulings it relies on as text. Met by this section and ADR-0037 (#1913).
9. Slice-0 build order (seat 8, ruled; ruling 6 above).
   - 9a. The C handle record (R1.12), its check word and the C compile entry are built in the embedding slice. The slice-0 host is the Rust daemon, so #418's C work moves after slice 0. Binds #418 and #1918.
   - 9b. The `ScopeEnd` source ordering, `narrow` on expiries and `Facts::Relay` are not built in slice 0. Binds #414, #1918 for `Facts::Relay` and #1919 for `ScopeEnd`.
   - 9c. The ARCH-017 entries keep the fields of R4.1, `status` included, as the one copy of the leaf-to-status mapping (P17), and #418's `status_per_variant` reads it (ruling 8 above). No other copy of that mapping is built. The parent-swap check of R4.2 stays as a test in #418 (`eval-architecture` M2, https://github.com/416rehman/Guardrails/issues/1913#issuecomment-7075660462): it holds each entry's `status` to its parent's among the five parent statuses of R1.5, so an entry change that swaps two parents' statuses fails even when both mappings follow it. The five parent pairs are the parent level, not a copy of the leaves, so keeping them adds no copy. The session's instructions for this record's third round kept this check, which replaces "only the five-pair match goes" in ruling 8. Binds #1914 and #418.
   - 9d. RC2 to RC6, the reload state machine of R2.19 and the `Arg` call made again of R2.17 are kept. Binds #410, #412 and #427.
10. C interface for the embedding slice (seat 5).
    - 10a. Arena writability is stated, or the flag moves to a word the host supplies. Binds #246 and #418.
    - 10b. Static layout asserts for every supported target, with a zeroing initialiser, and later fields go only at the end. Binds #418 and #246.
    - 10c. `grdr_fp_blob_info` exposes the header values. Binds #246 and #418.
    - 10d. A host conformance kit covers path-form vectors, a fake library and cache-key vectors. Binds #1769.
    - 10e. The host's MUSTs and defaults are stated. Binds #246 and #1769.
11. Evaluator minors, each on the issues its verdict names.
    - MN9 (round 5 `eval-security`, https://github.com/416rehman/Guardrails/issues/405#issuecomment-7074632321). A recompile on new device facts can clear a class's bit when it drops a fail-closed rule from the floor, so R2.17's "Adding a pack can only set bits" leaves that case out. #414's fold test adds an `Unknown` volume with a cased non-ASCII literal, such as `Données`, and expects `FoldNonAscii` in the floor report; 7a's uncased literal stays its own vector (`eval-security` F5, https://github.com/416rehman/Guardrails/issues/1913#issuecomment-7075853473). #1538 raises a finding when a recompile on new device facts moves an enforced rule from `InFloor` to `NoDeviceValue`, `Unmappable` or `FoldNonAscii`, naming the rule and the outcome, with a test. Binds #414 and #1538, and #1921 for SR-new-U.
    - MN10 (same verdict). While the floor is missing, #1538's soak sends a hook request from a shared-host session for honeytoken use and expects the answer Drawbacks states, with `degraded_reason` `floor-missing`. Binds #1538.
    - MN11 (same verdict). The check word folds the section directory as the `count` and `offset` of each of its ten entries, each widened to 32 bytes, and `ffi_record_changed` changes each entry on its own. Binds #418.
    - MN12 (same verdict). Closed in the text by revision 6: R2.17's call made again on `Arg(Path)` or `Arg(Destination)`. Binds #427, which builds it and its R2.20 case.
    - MN13 (round 6 `eval-security`). R2.20 adds one case with a mis-tagged projection and a refused path in one action, which expects three calls and the verdict at label bits 0 with the path `Unresolved`. #1769's kit tests a C host for the `State` call, for the `Arg` call with the value in its absent form and its bit set, for both in one action, and for nothing cached. The #245 bullet "When the floor cannot answer" says each call made again is on the same tables, with their tag. Binds #427, #1769 and #245, and #1921 for SR-new-V.
    - MN14 (round 6 `eval-security`). A `State` now stops every floor row that reads a label from objecting, for every process, contained ones included, and for an honest engine whose projection comes from the other bundle during an activation as much as for a compromised one. This is a stated cost of the decision, beside the Drawbacks line on shared-host sessions. #427 marks the device Degraded and reports a code (R4.3) while calls keep returning `State` past a bound, a row of #1917. #1538's soak counts the `State` answers per activation. Binds #427, #1538 and #1917.
    - F9 (round 5 `eval-adversarial`, https://github.com/416rehman/Guardrails/issues/405#issuecomment-7074554760). Closed in the text by revision 6: the contract sentences cover `grdr_fp_eval` only, a per-call error changes no state, and R2.20 holds the next action to the serving handle. Binds #427, #245 and #246, which build those texts and the case.
    - C2 (same verdict). `fastpath_loss_classes` takes R3.11 as its one oracle: a floor row, or an enforced `@on_loss("block")` rule, sets a class's bit. It includes a rule made fail-closed by class default and one made fail-closed by a pack's `on-sensor-loss: block`, neither held by the floor, and expects their class's bit clear unless another rule sets it. Binds #414.
    - C3 (same verdict). The check word's fixed bijection diffuses across its four 64-bit lanes, so a difference confined to one lane is not absorbed by an eight-byte field, and the `SAFETY` comment says so. Binds #418.
    - C4 (same verdict). Step 2 of R1.11 reads the record by unaligned reads, and the record's flag is one byte, so a misaligned `t` is never undefined behaviour. The copy then fails the stored-address comparison or the check word and gives `GRDR_E_CHANGED`. The `ffi_record_changed` case "a record copied to another address" includes a misaligned address under Miri. Binds #418.
    - m1 (round 6 `eval-adversarial`, strict reading; ruling 7 above). On the call made again on `State`, a `Deny` or `StepUp` answers the action, and a `Pass`, for a process inside a session container in a class whose bit is set in `loss_closed_classes`, is answered as the closed answer (D-20). #427 builds it with a `fastpath_reload` case: a `State` from an honest but stale projection with a taint row, the engine down, expects the closed answer. #414's `fastpath_loss_classes` covers a class closed through a row that requires a label. Binds #427, #414 and #245.
    - m2 (same verdict). A C host that calls again with a value `Unresolved` sets the bit and clears the value. The #245 bullet says so, and #427's retry test gains a C case that expects a verdict, not `GRDR_E_ARG`, added when #418's FFI exists (9a). Binds #245 and #427.
    - m3 (same verdict). The first status is reported even when the call made again answers. The #246 section 7 bullet gains that sentence, and #427 adds a `fastpath_reload` case for it. Binds #246 and #427.
    - `eval-architecture` minor 1 (https://github.com/416rehman/Guardrails/issues/405#issuecomment-7075428051). The host's pre-check of a path or a destination name is limited to what the library cannot see. A host passes as `Unresolved` a value it could not resolve or cannot hold in the library's types: a path it could not resolve, an executable it could not hash, a path above `path_max_units`, a name it cannot normalise (7b). For the forms of R2.3a and `tables.md` section 3.3 it may pass the value as `Resolved` and rely on the call made again of R2.17, so the library stays the one checker of those forms. R2.3b's host duty and the #245 bullet "Unresolved values" say so. Binds #245 and #427.
    - `eval-architecture` minor 2 (same verdict). The host's copy of `loss_closed_classes` is a field of the serving and floor-missing variants of #427's floor state type, never an `Option` beside it. The no-tables-since-start variant holds none, so its deny-all (1a) is a variant and not an absent value. Binds #427.
    - `eval-api` O1 (https://github.com/416rehman/Guardrails/issues/405#issuecomment-7075407504). `tables.md` line 49, "The header is 224 bytes." in section 2, is among the sites where 224 becomes 232, beside section 4 item 3, section 5's opening paragraph, TV-5, TV-11 and TV-14 (section 12, `tables.md` item 12). Binds #245.
    - `eval-security` F3 on this decision (https://github.com/416rehman/Guardrails/issues/1913#issuecomment-7075853473). Three requirements join #1921's scope beside SR-new-A to SR-new-V, in that verdict's wording:
      - SR-new-W, cold-start scope. With no tables since start the host denies every action of a process inside a session container and nothing outside one; each answer carries `floor-missing`; the 1d bound changes no answer. Component: `tables.md` section 11 and #427's no-tables variant. Test: R2.20 no-tables cases for a contained process, the person's shell, a shared-host hook request and an undetermined process, with the bound elapsed.
      - SR-new-X, re-adoption request. It names no bundle, path or table; it is accepted only from a peer authenticated by kernel handle, refused from agent lineage inside a session and, where an operator is enrolled, from anyone else; it is audited without content and bounded by a `limits.toml` row. Component: the daemon's request handler and the CLI row (#1930). Test: a negative test from an agent-lineage process and from a second uid, and a loop of requests that gives at most the bounded number of adoptions.
      - SR-new-Y, persisted bundle. The daemon re-reads at start only the bundle, from the state directory its profile owns, through the adoption checks including the generation floor; any failure leaves no tables. Component: #1538. Test: a persisted copy with a lower generation and one failing a TV rule, each leaving no tables.

      The requirements on the FFI's rules and handle record are oracled in the embedding slice, not slice 0 (9a): `ffi_record_changed`, `ffi_changed_sticky`, #418's C differential and seeded rule tests, `status_per_variant`, the Miri run of `grdr-fastpath-ffi` (#1475) and #1769's C host cases (MN13, m2). #1921 marks each such row with the slice its oracle runs in, so the register claims no control whose test cannot run yet (P9). Binds #1921.

Review lanes (8b). Each lane is the `.claude/risk-tiers.toml` set for the item's tier, kind and diff, as `grdr-work-issue` reads it:

| Items | Lane |
|---|---|
| #20, #71, #409, #410, #412, #414, #418, #1778 | High and trust core: the `[high]` set, `eval-api` for `public_api_change`, and two passing evaluators on different models |
| #427, #1538, #1930 | As above, plus `eval-platform` and `eval-performance` for `runtime_trust_core` |
| #388, #1918 | High and trust core (`crates/grdr-ffi/**`), with `eval-api` |
| #1582, #1768, #1914, #1915, #1917 | High and trust core where the file is listed (`architecture.toml`, `surfaces.toml`, `limits.toml`), plus `eval-architecture` for `kind:gate` |
| #1475 | High and trust core (`.github/**`), worked by lead-agent-kit |
| #245, #246, #1769 | High (`spec/**`) |
| #1916, #1921 | High |
| #1920 | High and trust core (`crates/grdr-fastpath/**`) |
| #1925 | Medium, plus `eval-ux` and `eval-a11y` for `interface/**` |
| #1919, #1926 | The RFC route: the persona council, `eval-architecture`, `eval-security` and `eval-adversarial` |

Filed on acceptance, as section 13 lists them, each blocked by #1913:
- #1914, the `architecture.toml` change, blocking #414, #418 and #427;
- #1915, the `surfaces.toml` row kind and rows, blocked by #1817;
- #1916, the design/03, design/12 and design/26 amendments;
- #1917, the `limits.toml` rows, blocked by #1768 and blocking #1538 and #427, with the rows of constraints 1d, 2a, 2b, 6c and MN14;
- #1918, `grdr_engine_compile_fastpath`, blocked by #388 and #414;
- #1919, the RFC for the bundle manifest field;
- #1920, the fuzz item, blocked by #415, #409 and #412;
- #1921, the security requirements SR-new-A to SR-new-Y, blocked by #1859.

Filed in the decision's review, each blocked by #1913:
- #1925, the `FASTPATH` code tokens, presentation rows and block-message kinds of constraint 3, blocked by #1853 and blocking #427;
- #1926, the amendment item that takes seat 3's re-check number out of constraint 4b;
- #1930, the re-adoption command and its daemon handler of constraint 2a, blocked by #427, #1538 and #1917.
