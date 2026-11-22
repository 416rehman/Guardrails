RFC: 0009
Title: The slice-0 public surface of grdr-model: time, Entropy, ids, lanes, logging, the retry state types, InstallProfile and Tamper
Author: chief-architect
Harness: Claude Code
Model: claude-opus-5-5
State: Review
Design issue: #1850
Spine: D-05, D-06, D-15, D-36, D-48, D-51, D-60, D-61, P1, P5, P8, P9, P14, P15, P17 (no spine text changes)
Surfaces: the public crate `grdr-model` (layer 1): `Timestamp`, `TimeError`, `Entropy`, `EntropyError`, `IdKind`, `MintRoute`, `IdError`, the typed ids, `Lane`, `UploadedLane`, `Epoch`, `Seq`, `OrderError`, `RetryPolicy`, `RetryPolicyError`, `PeerAccess`, `RetryStep`, `GiveUp`, `AttemptCounter`, `RetryBudget`, `AttemptOutcome`, `Breaker`, `ClosedBreaker`, `CheckingBreaker`, `OpenBreaker`, `HalfOpenBreaker`, `OpenPhase`, `HalfOpenPhase`, `ProbeKind`, `Permit`, `CheckOutcome`, `LogSafe`, `LogValue`, `IdRef`, `LiteralText`, `WireName`, `EventName`, `FieldName`, `LogLevel`, `LogRecord`, the macros `wire_enum!`, `wire_name!`, `event_name!`, `field_name!` and `log_record!`, `InstallProfile` and `Tamper`; the error-code area `MODEL` with eleven codes. As amendments (section 16): of RFC 0007, the retry-table key `budget_share_attempts` with its `BudgetLimits` field, `RetryField` variant, three `RetryRule` variants, two `RetryBounds` fields and the rows `retry-bounds.share-attempts-ceiling` and `retry-bounds.share-multiple-floor`; of RFC 0008, the shape of change 5's breaker states and the form of change 4's failure count, with RFC 0008's timing unchanged. As proposals: one `[[crate]]` row of `surfaces.toml`, the `grdr-model` edges in `Cargo.toml` and `Cargo.lock`, sentences of design/02 section 3.8, design/03 sections 3 and 10, design/04 sections 1, 2, 3 and 11, design/20 section 6 and design/21 sections 2 and 5. No wire format, Cedar schema or third-party dependency changes
Decision record: none yet

To comment, write on issue #1850 of this repository; you need no account on any service other than the code host. A security fix under embargo (D-62) may change a public surface without an RFC; open a retroactive RFC when the fix is disclosed.

This is revision 3. It answers round 2 on blob `3af43ca` and the session's rulings R7 to R13, after revision 2 answered round 1 and rulings R1 to R6; the comments "RFC 0009 revision 2" and "RFC 0009 revision 3" on #1850 answer every finding by its id. The text below is normative on its own. Where it differs from the items it covers (#383, #18, #282, #284), this RFC wins, and section 14 tells each lead what to write back (#1850 R4). It is also an amendment of RFC 0007 and of RFC 0008 for the parts section 16 names, as AC-3's "settled by an amendment that names both RFCs" allows.

## Summary
Slice 0 adds the first public items to `grdr-model`: the wall-clock instant `Timestamp`, the `Entropy` trait, the typed ids and their one registry `IdKind`, the envelope's lane, epoch and sequence types, the retry state types that RFC 0008's executor drives, the `LogSafe` gate with its record and macros, and the install profile and tamper grade that `grdr-wire` reads. This RFC states every signature, error, code and stability class, answers the eight questions of #1850 and the three its comments add, and lists what each item and document changes.

The decisions that matter most:
- `Entropy::fill` returns a `Result`. A failed source is an error with a code, never bytes nobody drew, and it never counts against a peer. Minting returns the error, and `RetryPolicy::next` gives up with its own reason, so RFC 0008's `RetryError` does not change.
- A lane is `Lane::Uploaded(UploadedLane)` or `Lane::Local`. The server and the device's upload path take only `UploadedLane`, so neither can name `local`. A test holds `Lane` and the protobuf enum to one definition.
- `RetryPolicy::from_limits(table, access)` is the one constructor. `PeerAccess::retry_peer` is the one function that calls a back end local, only an in-process back end or a file on a local disk, and every connection is remote; a consistency check refuses a table of the other peer kind.
- The breaker's call-probe sub-lifecycle is an `OpenPhase` in `Open` and a `HalfOpenPhase` in `HalfOpen`, so every value the type can hold is one a transition produces, with RFC 0008's turn timing unchanged. The state structs have private fields.
- The failure share counts over `budget_share_attempts`, a registered retry-table key that `narrow` keeps and that `check` holds at or above a registered multiple of `breaker_failures`, so a budget is built from its policy alone.
- Nothing reaches a log but typed values: names are fixed at build time, bare integers are not `LogSafe`, and only the organisation id and the delegation snapshot id can be logged. A raw number wrapped in a unit type at a call site is the stated residual, listed by a scan and read in review.
- Every public item has one path, at the crate root. The crate enters `surfaces.toml` as `experimental`.

## Motivation
#383, #18, #282 and #284 add these types, and RFC 0002 (#1688), RFC 0003 (#1757), RFC 0007 and RFC 0008 already use them. No RFC states their signatures. `grdr-model` is a public crate, so its surface changes only by RFC (D-61; the ruling on #1535), and RFC 0001 adopts the spine text and no crate surface. RFC 0007 section 1 gave this half of #1710's scope to #1850.

The texts disagree where a builder would turn the gap into a defect:
- RFC 0002 gives `Lane` four variants and design/04 section 2 five, with `local` among them.
- RFC 0002 mints `HolderId` "through grdr-model's id constructor" while the type lives in `grdr-ports`, and uses `DelegationSnapshotId`, `DelegationId` and `ProviderId`, which #383's table lacks.
- #282 calls the give-up reason `GiveUpReason` and RFC 0008 calls it `GiveUp`.
- #383's `Entropy::fill` cannot report a failure, and #334 must report one (lead-core, https://github.com/416rehman/Guardrails/issues/1850#issuecomment-7075943583).
- #284 makes every minted id and every integer loggable, and design/21 section 2 lets server logs carry the organisation id and the request id only.
- RFC 0007 lets a remote call read a `local` retry table and skip the remote floors (https://github.com/416rehman/Guardrails/issues/1850#issuecomment-7075275383).
- RFC 0008 section 8 lists nine changes it needs of these types (https://github.com/416rehman/Guardrails/issues/1850#issuecomment-7082237522).

#1850 blocks #18, and #18 blocks the Clock port (#281) on the path to the first runnable target (#645). If nothing changes, four implementers build against conflicting signatures and three RFCs keep pointing at types nobody has stated.

## Design

### 1. Scope and rules for every item
| Section | Items | Built by |
|---|---|---|
| 2 | `Timestamp`, `TimeError` | #383 |
| 3 | `Entropy`, `EntropyError` | #383 |
| 4 | `IdKind`, `MintRoute`, `IdError`, the typed ids | #383 |
| 5 | `Lane`, `UploadedLane`, `Epoch`, `Seq`, `OrderError` | the order item: a #18 sub-issue filed on acceptance (section 15) |
| 6 | `RetryPolicy`, `RetryPolicyError`, `PeerAccess`, `RetryStep`, `GiveUp`, `AttemptCounter`, `RetryBudget`, `AttemptOutcome`, `Breaker`, `ClosedBreaker`, `CheckingBreaker`, `OpenBreaker`, `HalfOpenBreaker`, `OpenPhase`, `HalfOpenPhase`, `ProbeKind`, `Permit`, `CheckOutcome` | #282 |
| 7 | `LogSafe`, `LogValue`, `IdRef`, `LiteralText`, `WireName`, `EventName`, `FieldName`, `LogLevel`, `LogRecord`, the macros, and `LogSafe` for RFC 0007's `Code` and unit types | #284 |
| 8 | `InstallProfile`, `Tamper` | the install profile item, filed on acceptance (section 15) |

`Monotonic` is RFC 0008's (section 3 there) and is not restated. It takes this crate's stability class.

- R1. **Dependencies.** `grdr-model` depends on `grdr-schema` and on nothing else, for `Code`, `Coded`, `ErrorClass`, `ConnectCode`, `RetryLimits`, `RetryPeer`, `BudgetLimits`, the unit types and `RETRY_BOUNDS` (RFC 0007 sections 3 and 5). `grdr-proto` is a dev-dependency only, for the parity tests of section 5. No third-party dependency and no Cargo feature. Both edges go to layer 0 (design/03 section 2), and each changes `Cargo.lock`, a protected path, so they land as one protected change before #383 (section 15).
- R2. **Layer 1.** No I/O, async runtime, clock or randomness source: every instant and every draw is an argument (D-05, ARCH-003). The crate builds for `wasm32-unknown-unknown`. Arithmetic is checked or saturating (`#![deny(clippy::arithmetic_side_effects)]`), no non-test code has a panic path, and `unsafe` is forbidden.
- R3. **One path per item.** Every public type, trait and function is at the crate root, such as `grdr_model::Timestamp`, and the module that holds its source is private. The macros are `#[macro_export]`, so they are at the root too. RFC 0002, RFC 0003 and RFC 0008 already name root paths (`grdr_model::Monotonic`, `pub use grdr_model::Entropy`, `pub use grdr_model::{DelegationId, DelegationSnapshotId, OrgId, ProviderId}`), and a module path beside each would be a second way to name it (P17).
- R4. **No rendering.** The crate is `renders = "none"`. No type implements `Display`. Ids, lanes and enum words are read with `as_str`, and a person sees them only through a label of the presentation registry or as an argument of a language token (D-69, UX5, UX6), as RFC 0007 R4 has it for codes.
- R5. **One word list per enum.** Every closed enum whose values have wire words is declared with `wire_enum!` (section 7), which gives its variants, their words, `VARIANTS` and its `LogSafe` impl from one list. The words are wire identifiers, never display words. `grdr-schema` keeps its own private macro lists for its enums (RFC 0007 R6), because a layer 0 crate cannot use a layer 1 macro and `wire_enum!` emits a `LogSafe` impl, a layer 1 trait. Both follow one rule, variants, words and `VARIANTS` from one list, and the words of both fit `WireName`'s grammar (section 7).
- R6. **Errors.** Each error enum is `#[non_exhaustive]`, because callers act on the code's class and never on the variant (RFC 0002 Rule 8). Each implements RFC 0007's `Coded` with one exhaustive `match` and no wildcard arm, and a variant that wraps another coded error returns that error's code (RFC 0007 section 3). Each implements `LogSafe` as `LogValue::Code` of its code. The codes are section 9's.
- R7. **Format constants.** The numbers that define a format are not tunables (RFC 0007 R7): the range of `google.protobuf.Timestamp`, the 26-character id form and its prefix grammar, the 64-byte bound on names and words, and the first epoch and sequence number, 1. Every retry bound, the failure share's window included, comes from the policy, which comes from a `limits.toml` table through `RetryLimits` (P14). No type here holds a tunable bound (ARCH-019).
- R8. **Data classes and assurance.** The ids are `identifier` (design/04 section 11). Every other type here is `structural`. Entropy output is never stored or logged except as the bits it gives an id. Assurance effect: none. No action class changes `visibility`, `control`, `on_failure` or `tamper` (P1); `Tamper` declares the grade's type and sets no grade.
- R9. **Scale.** No type makes a call or holds a queue (P15). An id holds its text, at most 30 bytes, allocated once when it is built. A `RetryBudget` holds `budget_slots` counters and `budget_share_attempts` outcomes, fixed at construction and bounded by the `retry-bounds.slots-ceiling` and `retry-bounds.share-attempts-ceiling` rows. A log record borrows the fields its call site writes.
- R10. **Derives.** Every public type implements `Debug` and derives what its block below writes. None has interior mutability, so every type is `Send + Sync`, as RFC 0008 change 7 needs.

### 2. Time (#383)
```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp { /* private: seconds from 1970-01-01T00:00:00Z and nanoseconds, UTC */ }
impl Timestamp {
    pub const MIN: Timestamp; // 0001-01-01T00:00:00Z
    pub const MAX: Timestamp; // 9999-12-31T23:59:59.999999999Z
    pub const fn new(secs: i64, nanos: u32) -> Result<Timestamp, TimeError>;
    pub const fn secs(self) -> i64;
    pub const fn nanos(self) -> u32;
    pub fn checked_add(self, by: Duration) -> Option<Timestamp>;
    pub fn checked_sub(self, by: Duration) -> Option<Timestamp>;
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TimeError { Seconds, Nanos }
```
- `Timestamp` is a UTC instant with the range of `google.protobuf.Timestamp` (#383 R1). `new` refuses `nanos` of 1,000,000,000 or more with `Nanos` and seconds outside the range with `Seconds`. Arithmetic that would leave the range returns `None`.
- It orders and compares, so an expiry check reads `now >= expires_at`, but nothing orders events by it: the order is epoch, lane and sequence (design/03 section 10, Time).
- Its uses fit: RFC 0002's `Date::from_timestamp` reads `secs`; a lease's `expires_at` and a token's expiry are `checked_add`; #1927 R5 clamps a system clock outside the range to `MIN` or `MAX`; `ManualClock::jump_wall` (RFC 0008 section 3) is `checked_add` or `checked_sub`; RFC 0008 constraint 2h reads `Clock::now()` as UTC.
- Errors: `TimeError`, `GRDR-MODEL-0001` and `GRDR-MODEL-0002`.

### 3. Entropy (#383; answer 9)
```rust
pub trait Entropy {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), EntropyError>;
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EntropyError { Unavailable }
```
- `fill` writes `out.len()` bytes drawn from its source and returns `Ok`, or returns `Err`. After `Err` the contents of `out` are unspecified and no caller reads them, so a partial fill is an `Err`, never a success. No implementation returns bytes its source did not produce, zeroed or repeated bytes included (RFC 0008 section 6).
- The trait has one required method, no provided method and no supertrait, and stays dyn-compatible: `Engine::step` takes `&mut dyn Entropy` (design/03 section 3), and RFC 0002 Rule 2 relies on it.
- Every function in this crate that draws takes `entropy: &mut R` with `R: Entropy + ?Sized`, so a caller may pass `&mut dyn Entropy`, `&mut (dyn Entropy + Send)` or a concrete type. RFC 0008's `run` holds `&mut R` with `R: Entropy + Send + ?Sized`, from which rustc cannot form a `&mut dyn Entropy` (E0277), so the generic form is what lets it reach `RetryPolicy::next` (RFC 0008 change 1). The bench of the Review section shows both.
- `grdr-model` implements `Entropy` for no type. Outside test code the implementations are those ARCH-003's list names: `grdr-crypto`'s `random` module and `grdr-ports-testkit` (RFC 0008 R3).
- `EntropyError` holds no data: a failed generator gives nothing structured, and a source's own message is not ours to carry. An implementation returns `EntropyError::Unavailable`.
- Errors: `EntropyError`, `GRDR-MODEL-0003`. Its Connect code is `failed_precondition`, so RFC 0008's `faults_peer` is false for it: a failure of our own source never counts against a peer, opens no breaker and adds nothing to a failure share, as `ID_TIME_OUT_OF_RANGE`, the other fault of our own host, does not.

**Answer 9: `fill` is fallible.** lead-core offered three options:
1. `fill` returns a `Result`, and minting and `RetryPolicy::next` carry the failure. **Chosen.**
2. `fill` stays infallible over a source that latches its failure. After a failure the source must still write bytes into `out`, and it has none to give. Zeroed bytes make every full-jitter delay 0 and every key or nonce drawn from them all zeros (eval-security on #1924, https://github.com/416rehman/Guardrails/issues/1850#issuecomment-7076106123); repeated bytes are predictable. Rejected.
3. `fill` stays infallible behind a constructor that probes the source once. A failure after the probe leaves the same gap as option 2. Rejected.

What option 1 costs:
- Minting returns `IdError::Entropy` (section 4).
- `RetryPolicy::next` returns `GiveUp { reason: GiveUp::EntropyUnavailable, .. }` with the counter's ceiling as its backoff and `open_for` (section 6). That is RFC 0008's preferred form (its question 2), so `RetryError` does not change.
- `Engine::step` keeps its signature, `-> Output` (design/03 section 3). A failed draw on an `ActionRequest` ends the step with a typed failure in `Output`, which carries `GRDR-MODEL-0003`, never with a decision whose id was not drawn and never with an empty decision a host could read as "no decision needed". The host routes that failure through the rule class's `on_failure` (D-15), and an outcome that lets the action through raises Degraded with the code (P9; #1537 and design/03 section 3 in section 14). The C ABI takes its seed as bytes and is unchanged.
- The daemon's decision ids (#1536) state the outcome of a failed draw (section 14).

In the programs the source is `grdr_crypto::OsRandom` over aws-lc-rs (#334 R7, #1927 R11). AWS-LC documents that `RAND_bytes` calls `abort` when it cannot get enough random data (https://github.com/aws/aws-lc/blob/main/include/openssl/rand.h, read 2026-11-22), and aws-lc-rs's `fill` returns an error only when `RAND_bytes` does not return 1 (https://github.com/aws/aws-lc-rs/blob/main/aws-lc-rs/src/rand.rs, read 2026-11-22). So on the programs' path a generator failure ends the process inside the library before `fill` returns, and `OsRandom`'s `Err` branch maps the library's result type. The trait still carries the failure, because another source, such as a host's generator behind `grdr-ffi` or `grdr-wasm`, can fail and return. Section 14 lists what #334 states about the abort.

### 4. Ids (#383; answers 1 and 2)
```rust
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IdKind {
    Event, Session, ToolCall, Action, Decision, Incident, OperatorAccount, Grant, DelegationSnapshot,
    Org, RetryToken, Provider, Delegation, Holder,
    Device, HumanPrincipal, ServicePrincipal, AgentIdentity, AgentInstance, McpServer, McpTool,
    Skill, Plugin, ModelEndpoint, CredentialRef, Process, Flow, Finding,
}
impl IdKind {
    pub const VARIANTS: &'static [IdKind];
    pub const fn prefix(self) -> &'static str; // "evt"
    pub const fn route(self) -> MintRoute;
    pub const fn loggable(self) -> bool;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MintRoute { Uuid7, Random128, Derived128 }

// Every typed id but PrincipalId has this shape. EventId stands for each.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventId { /* private: its text */ }
impl EventId {
    pub const KIND: IdKind = IdKind::Event;
    pub fn from_wire(text: &str) -> Result<EventId, IdError>;
    pub fn as_str(&self) -> &str;
    // One constructor, by the kind's route:
    pub fn mint<R: Entropy + ?Sized>(now: Timestamp, entropy: &mut R) -> Result<EventId, IdError>; // Uuid7
}
// Random128:  pub fn mint<R: Entropy + ?Sized>(entropy: &mut R) -> Result<OrgId, IdError>;
// Derived128: pub fn derive(digest: [u8; 16]) -> DeviceId;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrincipalId { /* private: its text */ }
impl PrincipalId {
    pub fn human(digest: [u8; 16]) -> PrincipalId;          // prn_
    pub fn service(digest: [u8; 16]) -> PrincipalId;        // svc_
    pub fn agent_identity(digest: [u8; 16]) -> PrincipalId; // aid_
    pub fn from_wire(text: &str) -> Result<PrincipalId, IdError>;
    pub fn kind(&self) -> IdKind;
    pub fn as_str(&self) -> &str;
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IdError { Form, TimeOutOfRange, Entropy(EntropyError) }
```

| `IdKind` | Prefix | Route | Type | Defined by | Loggable |
|---|---|---|---|---|---|
| `Event` | `evt` | `Uuid7` | `EventId` | design/04 section 2 | no |
| `Session` | `ses` | `Uuid7` | `SessionId` | design/04 section 3 | no |
| `ToolCall` | `tc` | `Uuid7` | `ToolCallId` | design/04 section 3 | no |
| `Action` | `act` | `Uuid7` | `ActionId` | design/04 section 3 | no |
| `Decision` | `dec` | `Uuid7` | `DecisionId` | design/04 section 3 | no |
| `Incident` | `inc` | `Uuid7` | `IncidentId` | design/04 section 3 | no |
| `OperatorAccount` | `opa` | `Uuid7` | `OperatorAccountId` | design/04 section 3 | no |
| `Grant` | `grt` | `Uuid7` | `GrantId` | design/12 section 6 | no |
| `DelegationSnapshot` | `dls` | `Uuid7` | `DelegationSnapshotId` | design/21 section 5 (answer 1) | yes |
| `Org` | `org` | `Random128` | `OrgId` | design/04 section 3 | yes |
| `RetryToken` | `rty` | `Random128` | `RetryTokenId` | design/12 section 6 | no |
| `Provider` | `prv` | `Random128` | `ProviderId` | design/21 section 1 | no |
| `Delegation` | `dlg` | `Random128` | `DelegationId` | design/21 section 5 | no |
| `Holder` | `hld` | `Random128` | `HolderId` | RFC 0002 section 7 (answer 2) | no |
| `Device` | `dev` | `Derived128` | `DeviceId` | design/04 section 3 | no |
| `HumanPrincipal`, `ServicePrincipal`, `AgentIdentity` | `prn`, `svc`, `aid` | `Derived128` | `PrincipalId` | design/04 section 3 | no |
| `AgentInstance` | `agi` | `Derived128` | `AgentInstanceId` | design/04 section 3 | no |
| `McpServer`, `McpTool` | `mcp`, `mct` | `Derived128` | `McpServerId`, `McpToolId` | design/04 section 3 | no |
| `Skill`, `Plugin` | `skl`, `plg` | `Derived128` | `SkillId`, `PluginId` | design/04 section 3 | no |
| `ModelEndpoint` | `mdl` | `Derived128` | `ModelEndpointId` | design/04 section 3 | no |
| `CredentialRef` | `crd` | `Derived128` | `CredentialRefId` | design/04 section 3 | no |
| `Process`, `Flow`, `Finding` | `prc`, `flw`, `fnd` | `Derived128` | `ProcessId`, `FlowId`, `FindingId` | design/04 section 3 | no |

Form and minting, as #383 R5 to R10 state them, with these changes:
- The text is `<prefix>_` and 26 lower-case Crockford base32 characters, two zero bits in front of the 128 bits, so the first character is `0` to `7` and the order of two ids of one kind is the order of their bytes (#383 R8). The alphabet has no `/`, `=` or `.`, so `org=<id>/` keeps listings apart (RFC 0002 section 15).
- `from_wire` accepts exactly that form for its kind and refuses anything else with `Form`; it checks form and decodes nothing (#383 R9). `PrincipalId::from_wire` accepts any of its three prefixes, and `kind` reads the prefix. design/04 section 1's "identifiers are never parsed" binds the code that consumes ids; this crate's own form check is the one place that reads an id's text, and nothing outside it reads a prefix or a bit (section 14 proposes the sentence).
- `Uuid7` minting draws 10 bytes in one `fill` and builds RFC 9562 section 5.7's layout from `now`'s Unix milliseconds (#383 R5). A `now` before 1970 is `TimeOutOfRange`; `Timestamp::MAX` is below 2^48 milliseconds, so no later `now` can be. `Random128` draws 16 bytes in one `fill` and uses them as they are. A failed draw returns `IdError::Entropy` and builds no id.
- `Derived128` takes the 16 bytes of the digest design/04 section 3 names for the kind, computed in `grdr-crypto` (ARCH-006) and truncated to 128 bits, and draws nothing. For `prn_` that is HMAC-SHA-256 under the device pseudonym key over the kind and the stable local identity (D-51), and for the other HMAC rows of design/04 section 3 HMAC-SHA-256 under the organisation's entity key, both carried by #335's `KeyedId128`; for `dev_`, `prc_`, `flw_` and `fnd_` it is the hash that row names. A plain hash where design/04 names an HMAC is a defect, which a dictionary over uids would reverse. #335 tests the keyed derivations, and each item that derives a kind tests that it passes the digest its row names.
- No method returns an id's bits, its time or its random part. No id implements `Display` (R4). Ids are `Clone`, not `Copy`, because each holds its text so `as_str` is total: an inline ASCII buffer would need a fallible conversion to `&str`, and `core::ascii::Char` is unstable on the pinned 1.99.1 (the bench).
- Errors: `IdError`, `GRDR-MODEL-0004` and `GRDR-MODEL-0005`; `Entropy` returns `GRDR-MODEL-0003`.

The id table is one macro list in `grdr-model`, with two entry forms: one kind with its own newtype, or several kinds that share one newtype, which is how `PrincipalId` is written, three kinds with one constructor named per kind and `kind()`. From the list are generated `IdKind`, `VARIANTS`, `prefix`, `route`, `loggable` and each newtype with exactly the shape of its entry form, so no newtype is written by hand. A new row is content of this mechanism, as a code is content of RFC 0007's registry: the item that defines the id adds one entry and its pull request names RFC 0009 for `rfc-required`. A new prefix fits `[a-z]{2,3}`, is unique, and is not `agt`, which agent type ids hold (design/04 section 3). A new row is not loggable: making a kind loggable widens what logs carry (P8), so it is an amendment. `IdKind` is `#[non_exhaustive]`, so a new row breaks no match outside the crate.

The `loggable` column is the one home of that decision. design/04 section 11 names the two loggable kinds (section 14 proposes the sentence), and #383's test checks `loggable()` against that list, transcribed. The field registry (#17) classes fields, not id kinds, so it holds no copy; every field holding an id stays `identifier`.

**Answer 1: `DelegationSnapshotId` is `dls_`, minted as UUIDv7.** The token exchange writes a delegation snapshot at every workbench exchange (design/21 section 5), and a time-ordered key keeps that table's index append-mostly. `DelegationId` (`dlg_`) and `ProviderId` (`prv_`, which design/21 section 1 already names) are `Random128`, like `OrgId`: long-lived tenancy objects whose ids need no time. All three are minted by the server's tenancy code from its clock and entropy (ARCH-020).

**Answer 2: the id moves; the capability stays.** `HolderId` becomes a `grdr-model` id, `hld_`, `Random128`: it names one process start, needs no time and needs 128 random bits so two processes never share one. RFC 0002's capability stays in `grdr-ports` under the name `Holder`, holding a `HolderId`, and only `Setup` and the kit's handle build one; `Holder` has no constructor from a `HolderId`, so holding an id builds nothing (RFC 0002 section 7). Leases take `&Holder`, and an adapter stores the holder's `id().as_str()`. Minting through grdr-model's constructor keeps ARCH-020; keeping the capability in `grdr-ports` keeps RFC 0002's rule that only the composition root makes one. The rename keeps one name per type: two crates each stating a `HolderId` would be the clash #1710 AC-3 refuses.

### 5. Lanes, epochs and sequence numbers (#18; answers 3 and 4)
```rust
wire_enum! {
    pub enum UploadedLane { Decision => "decision", Spine => "spine", Bulk => "bulk", Evidence => "evidence" }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Lane { Uploaded(UploadedLane), Local }
impl Lane {
    pub const VARIANTS: &'static [Lane]; // the four uploaded lanes in order, then Local
    pub const fn as_str(self) -> &'static str; // "decision", "spine", "bulk", "evidence", "local"
    pub const fn wire_name(self) -> WireName;
    pub const fn number(self) -> i32; // 1 to 5, the protobuf enum's numbers
    pub const fn from_number(number: i32) -> Result<Lane, OrderError>;
    pub const fn uploaded(self) -> Result<UploadedLane, OrderError>;
}
impl From<UploadedLane> for Lane;
// Lane implements LogSafe as its word.

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Epoch { /* private: a non-zero u32 */ }
impl Epoch {
    pub const FIRST: Epoch; // 1
    pub const fn new(value: u32) -> Result<Epoch, OrderError>;
    pub const fn get(self) -> u32;
    pub const fn next(self) -> Option<Epoch>;
}
// Seq has the same shape over a non-zero u64. Both implement LogSafe as their own LogValue variant.

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OrderError { LaneUnspecified, LaneUnknown { number: i32 }, LaneNotUploaded, EpochZero, SeqZero }
```

**Answer 3: one `Lane` type of five lanes, with the four that leave the device as a type of their own.** design/04 section 2 has five lanes and the envelope's `lane` is a protobuf enum of five values (#394 R3). The daemon stamps `local` records with their own sequence and hash chain, so it needs all five. `local` never leaves the device (design/22 section 2), so nothing that sends or stores an uploaded record names one:
- on the server, RFC 0002's `OrgWork::Ingest`, `StorageClass::Archive`, `ArchiveBatch` and `RowPosition` take `UploadedLane`, and ingest refuses a `local` record once, where it decodes the lane (`Lane::from_number(n)?.uploaded()?`);
- on the device, the spool's read for upload (#428), the uplink's offer and batch (#1539) and the lane scheduler (#1238) take `UploadedLane`, so a loop over `Lane::VARIANTS` cannot hand a flight-recorder record to the uplink, and passing `Lane::Local` there fails to compile (section 14).

Each lane and its word is declared once: the four in `UploadedLane`'s list and `local` in `Lane`. RFC 0002's "there is no second lane enum" holds in that sense, and its four uses change (section 14).

The protobuf enum and `Lane` stay one definition through a test, `crates/grdr-model/tests/lane_wire.rs`, with `grdr-proto` as a dev-dependency (R1):
- it walks every value of the `Lane` enum in the descriptor set #17 generates, not the generated Rust type: each value other than `LANE_UNSPECIFIED` maps through `Lane::from_number` to a lane whose `number()` is that value and whose `as_str()` is that value's `wire_name` option, `LANE_UNSPECIFIED` is `LaneUnspecified`, and the descriptor's value count is `Lane::VARIANTS.len() + 1`. So a value added to the `.proto` file alone fails the test whatever shape the codec gives the generated type;
- where the codec generates a closed Rust enum, two functions also match exhaustively, with no wildcard arm, from `Lane` to the generated enum and back, so a value added on either side fails to compile. In the bench, adding a sixth value to a generated enum of prost's shape fails the test's build with E0004. Where the codec generates an open type, only the descriptor walk runs, and it holds alone;
- a number no value has is `LaneUnknown { number }`, and `Lane::Local.uploaded()` is `LaneNotUploaded`.

Generation was the other mechanism AC-4 allows. It would need a `.proto` reader in a test or `grdr-model` depending on `grdr-proto` in its normal closure, which ties this crate's API to the codec SP-1 has not chosen yet (Alternatives). The numbers are wire format, which `buf breaking` already keeps from changing, so holding them in a test costs little.

**Answer 4: `Epoch` is a non-zero `u32`, `Seq` a non-zero `u64`, `DeviceId` a `Derived128` id.** The envelope carries `uint32 epoch` and `uint64 seq` (design/04 section 1). In proto3 a zero scalar is indistinguishable from an absent field, so 0 is refused: `seq` starts at 1 per epoch and lane (design/04 section 2), and the epoch counter starts at 1 too (section 14). `next` returns `None` at the type's maximum, and its caller maps that to its own code: the daemon cannot start a new epoch, and a lane cannot take another record in this epoch. `DeviceId` is `dev_` over the 16-byte digest of the device's public key (design/04 section 3). RFC 0002's `RowPosition { observed_time: Timestamp, device_id: DeviceId, epoch: Epoch, monotonic_ns: u64, lane: UploadedLane, seq: Seq }` fits these types. `monotonic_ns` stays a `u64`: it is the device's reading in another process, and RFC 0008 section 3 never compares instants of two processes.

Errors: `OrderError`, `GRDR-MODEL-0007` to `GRDR-MODEL-0011`.

### 6. The retry state types (#282; answers 5, 6, 10 and 11)
```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetryPolicy { /* private: the RetrySpec of one RetryLimits */ }
impl RetryPolicy {
    pub fn from_limits(limits: &RetryLimits, access: PeerAccess) -> Result<RetryPolicy, RetryPolicyError>;
    pub fn next<R: Entropy + ?Sized>(
        &self, counter: AttemptCounter, retries: u32, elapsed: Duration, hint: Option<Duration>, entropy: &mut R,
    ) -> RetryStep;
    pub fn at_cap(&self, counter: AttemptCounter) -> bool;
    pub fn peer(&self) -> RetryPeer;
    pub fn timeout(&self) -> Duration;
    pub fn cap(&self) -> Duration;
    pub fn budget(&self) -> BudgetLimits;
    pub fn breaker_failures(&self) -> u32;
}
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetryPolicyError { PeerMismatch { table: RetryPeer, call: RetryPeer } }

wire_enum! { pub enum PeerAccess { InProcess => "in_process", OwnFile => "own_file", Connection => "connection" } }
impl PeerAccess {
    pub const fn retry_peer(self) -> RetryPeer; // Local for InProcess and OwnFile, Remote for Connection
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AttemptCounter { /* private: u32 */ }
impl AttemptCounter {
    pub const fn new(value: u32) -> AttemptCounter;
    pub const fn get(self) -> u32;
    pub const fn next(self) -> AttemptCounter; // saturating
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetryStep {
    Delay { delay: Duration, open_for: Duration },
    GiveUp { reason: GiveUp, backoff: Duration, open_for: Duration },
}
wire_enum! {
    pub enum GiveUp { MaxAttempts => "max_attempts", MaxElapsed => "max_elapsed", EntropyUnavailable => "entropy_unavailable" }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetryBudget { /* private: the slot counters and the recent outcomes */ }
impl RetryBudget {
    pub fn new(policy: &RetryPolicy) -> RetryBudget;
    pub fn record_request(&mut self, now: Monotonic);
    pub fn try_spend(&mut self, now: Monotonic) -> bool;
    pub fn record_attempt(&mut self, outcome: AttemptOutcome);
    pub fn failure_share(&self) -> Permille;
}
wire_enum! { pub enum AttemptOutcome { Succeeded => "succeeded", Failed => "failed" } }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Breaker {
    Closed(ClosedBreaker),
    Checking(CheckingBreaker),
    Open(OpenBreaker),
    HalfOpen(HalfOpenBreaker),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClosedBreaker { /* private: consecutive failures, the end of the quiet period */ }
impl ClosedBreaker {
    pub const fn consecutive_failures(&self) -> u32;
    pub const fn quiet_until(&self) -> Option<Monotonic>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckingBreaker { /* private: check_until */ }
impl CheckingBreaker { pub const fn check_until(&self) -> Monotonic; }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenBreaker { /* private: until, the next probe's phase */ }
impl OpenBreaker {
    pub const fn until(&self) -> Monotonic;
    pub const fn phase(&self) -> OpenPhase;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HalfOpenBreaker { /* private: probe_until, the phase of the probe in flight */ }
impl HalfOpenBreaker {
    pub const fn probe_until(&self) -> Monotonic;
    pub const fn phase(&self) -> HalfOpenPhase;
    pub const fn probe(&self) -> ProbeKind; // the one probe accessor
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenPhase { Health { unhealthy: u32 }, CallDue, CallTurn { until: Monotonic } }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HalfOpenPhase { Health { unhealthy: u32 }, CallTurn { until: Monotonic } }
impl Breaker {
    pub const CLOSED: Breaker; // Closed, no consecutive failures, no quiet period
    pub fn peek(&self, now: Monotonic, policy: &RetryPolicy) -> Permit;
    pub fn permit(self, now: Monotonic, policy: &RetryPolicy) -> (Breaker, Permit);
    pub fn unanswered(self, now: Monotonic, open_for: Duration, policy: &RetryPolicy) -> Breaker;
    pub fn record_success(self, now: Monotonic, policy: &RetryPolicy) -> Breaker;
    pub fn record_failure(self, now: Monotonic, policy: &RetryPolicy) -> (Breaker, Option<Monotonic>);
    pub fn record_check(self, started: Breaker, outcome: CheckOutcome, now: Monotonic, open_for: Duration, policy: &RetryPolicy) -> Breaker;
    pub fn release(self, started: Breaker, now: Monotonic, policy: &RetryPolicy) -> Breaker;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Permit { Call, Probe(ProbeKind), Refuse { until: Monotonic }, Unanswered }
wire_enum! { pub enum ProbeKind { Health => "health", Call => "call" } }
wire_enum! { pub enum CheckOutcome { Healthy => "healthy", Unhealthy => "unhealthy", Inconclusive => "inconclusive" } }
```
`RetryLimits`, `RetryPeer`, `BudgetLimits`, `Permille` and `RETRY_BOUNDS` are RFC 0007's (`grdr_schema::limits`), with `BudgetLimits::share_attempts` from section 16. `Monotonic` is RFC 0008's.

**`RetryPolicy`.**
- `from_limits` copies one checked table and is the only constructor; the fields are private, so a struct expression outside the crate fails (E0451). There is no `#[cfg(test)]` constructor. Product code reads a registered table, or a table RFC 0007's `narrow` built from one, and tests build tables with `RetryLimits::new`, which ARCH-019 keeps to test code (RFC 0007 sections 5 and 8). **Answer 6.**
- **Answer 10, the peer kind.** The caller passes `access`, how it reaches the back end the call goes to, and `from_limits` refuses a table whose `peer` differs, either way, from `access.retry_peer()`, with `PeerMismatch { table, call }`.
  - `PeerAccess::retry_peer` is the one function that classifies a back end. Only `InProcess`, a back end in the calling process such as the reference adapters, and `OwnFile`, a file on a local disk that the process opens itself, such as a SQLite database or a bundle reloaded from the state directory, are `Local`. `Connection`, every socket, pipe or network address, loopback and Unix-domain sockets included, is `Remote`: a connection can be forwarded off the machine, so nothing shows it is on this one. A file on a network mount, a UNC path and a named pipe on another machine (`\\server\pipe\name`) are not `OwnFile`: the adapter that opens a configured path classifies such a path as `Connection` or refuses it, and tests that rule (#301 for SQLite, #1542 for the SQLite bus log, and #30 if its local store builds a set-up policy; section 14). A variant added later is `Remote` unless the amendment that adds it says otherwise.
  - The comparison is a consistency check between two inputs: the table's `peer`, from `limits.toml`, and the access the caller states, from its code. It refuses an inconsistent pair. It cannot refuse a caller that is wrong about its back end in a way that makes both agree, such as a remote back end described as `InProcess` with a `local` table. A caller cannot pass a bare `RetryPeer` (E0308). What holds the access itself is each adapter item's test of the access it passes and `eval-architecture`'s reading of it on every pull request that calls `from_limits` (section 15). `grdr-uplink`'s classes pass `Connection`; an adapter's set-up passes the access of the back end it opens, and reads the registered table of that peer kind (a PostgreSQL adapter's set-up table is `peer = "remote"`, section 14).
  - A compile-time check cannot hold this, because RFC 0007's generated tables are one type whatever their peer. The error is class `internal`, because the code that picked the table or the access is wrong, and the caller's rule class decides the outcome (D-15): at set-up the construction fails with the code (RFC 0008 section 6). #282's tests cover `retry_peer` for each variant and include a remote call given a `local` table and a local call given a `remote` table.
- `next` is #282 R2 to R7 with these changes:
  - It takes two counts (RFC 0008 change 2): `counter`, the class's attempt counter before this failure is counted, sets the delay ceiling (#282 R3 and R4, with `counter.get()` in place of `attempt`), and `retries`, the run's own retries so far, is what the `MaxAttempts` check reads (`retries + 2 > max_attempts`).
  - A schedule's delay `d` is a draw in `[d - d * jitter / 1000, d]` (RFC 0007 section 5).
  - A hint `h` is first raised to `RETRY_BOUNDS.hint_floor`, and the delay is the larger of the backoff draw and `h + U(0, h)` (RFC 0007 section 5; #282 R5 as #282's first comment asks).
  - A uniform draw in `[0, m]` reads one `u64` as `u64::from_le_bytes` of 8 bytes from one `fill`, and returns `(r * (m + 1)) >> 64` in `u128` (#282 R6), so a seed gives the same delays on every target.
  - Each step carries `open_for`, the smaller of its delay, or a give-up's `backoff`, and the counter's ceiling (RFC 0008 change 3). With no hint `open_for` equals the delay, so #282's vectors hold.
  - A failed draw returns `GiveUp { reason: EntropyUnavailable, backoff: c, open_for: c }`, where `c` is the counter's ceiling, whatever else applies, so a failed source always shows as its own reason (answer 9).
  - Every sum saturates, so a counter of `u32::MAX` or a hint of `u64::MAX` milliseconds gives a ceiling at the cap and never panics.
- `at_cap(counter)` says the counter's ceiling has reached the cap. `timeout`, `cap` (the exponential cap or a schedule's last delay), `budget` and `breaker_failures` are what the executor, `for_class` and `set_policy` read (RFC 0008 change 4).
- Errors: `RetryPolicyError`, `GRDR-MODEL-0006`.

**Answer 5: the give-up reason is `GiveUp`.** RFC 0008, decided, writes `RetryError::GaveUp { reason: GiveUp, .. }`, and `GiveUpReason` would amend it for a name. `RetryStep::GiveUp { reason: GiveUp }` names the variant and the type alike, as RFC 0008 already reads. It derives what `wire_enum!` gives, `Clone`, `Copy`, `Debug`, `PartialEq`, `Eq` and `Hash`, and is `LogSafe` (RFC 0008 change 7).

**`RetryBudget`.** One budget serves one class (RFC 0008 R9).
- `new` takes every field from `policy.budget()`, which RFC 0007's rules have checked, so no caller can build a budget from unchecked fields. `record_request` and `try_spend` are #282 R8.
- `record_attempt` records the outcome of each attempt of the class, first or retry, in order, and keeps the last `budget.share_attempts` of them. `failure_share` is the failed share of those as a `Permille`, and 0 until that many are recorded. This is constraint 1d (`Permille`) and constraint 1f of RFC 0008's decision, which has this RFC follow #1966 R2: the share over recent attempts, not over the budget's time window. It differs from RFC 0008 change 4's text, which names `record_failure(now)` and a share that is 0 "while fewer than a given count have failed"; section 16 states that difference as part of the amendment of RFC 0008, so #283 builds to this form.
- The window's length is a registered bound (P14): the retry-table key `budget_share_attempts`, bounded above by the `retry-bounds.share-attempts-ceiling` row and below by `check`'s rule `BudgetShareBelowBreaker`, which refuses a window shorter than the `retry-bounds.share-multiple-floor` row's multiple of the table's `breaker_failures`, 2 at the seed (section 16). So a registered table cannot write a window of one attempt, whose share would swing between 0 and 1,000 permille, the flicker constraint 1f exists to stop. `narrow` keeps it as registered, as it keeps `budget_window_ms` and `budget_slots`, so a table built at run time cannot shorten the window, and a policy built from a narrowed table carries the registered length; `narrow` only lowers `breaker_failures`, so a narrowed table still passes `BudgetShareBelowBreaker`. That is why `new` takes the policy alone. Of the two ways the session's ruling R3 offered, neither is needed: there is no second table to validate, and a `new` that only `for_class` could reach cannot be built, because `for_class` is in `grdr-ports` and a function another crate calls is public. A change of `budget_share_attempts` is a change of the policy's budget fields, so RFC 0008's `set_policy` starts the budget again under the new fields.
- Errors: none. `try_spend` returning `false` is the refusal, which the executor reports as `BudgetExhausted` (RFC 0008 section 4).

**`Breaker`.** One class's breaker, with the four states of RFC 0008 change 5 and RFC 0008's timing exactly. Each variant holds a struct whose fields are private, read through its accessors, so outside this crate a breaker is only `Breaker::CLOSED` or what a transition returned (E0451 on a struct expression). The call-probe sub-lifecycle is a phase of its own in each of the two states that carry it:
- `OpenPhase`, what the next probe is: `Health { unhealthy }`, the class's health call after `unhealthy` unhealthy health probes in a row; `CallDue`, `breaker_failures` health probes in a row were unhealthy and the next probe starts a call-probe turn; `CallTurn { until }`, a turn is in progress and ends at `until`.
- `HalfOpenPhase`, what the probe in flight is: `Health { unhealthy }`, a health probe; `CallTurn { until }`, a call probe of the turn that ends at `until`. There is no `CallDue` here, because the permit that takes a `CallDue` probe starts the turn and fixes its end at that instant plus the cap, as RFC 0008 has it.

**Why two phase types.** Session ruling R7 offered two forms. One shared phase with the end fixed at `probe_until + cap`, as eval-adversarial's round 2 fix showed, holds every value reachable, but its end is one call timeout later than RFC 0008's, because `probe_until` is the permit plus the call timeout; it would keep an amendment of the timing. Two phase types hold every value reachable and fix the end at the permit, which is RFC 0008's decided bound exactly. So this RFC takes two phase types, and the amendment of section 16 changes the shape of the states only. A dropped call probe keeps its turn's end (`release`), a late or repeated `Inconclusive` keeps it (`record_check`), and the first permit at or after it is a health probe with the count at 0.

`HalfOpenBreaker::probe` is the one accessor for the probe's kind, derived from the phase, so a probe's kind and its turn cannot disagree. Every value the type can hold is one a transition produces under some registered table: all eight shapes, `Closed` with and without a quiet period, `Checking`, `Open` in each of its three phases and `HalfOpen` in each of its two, with `Health { unhealthy }` for every count below `breaker_failures`. The bench runs the transition table as code over every state it reaches and shows each, and runs eval-adversarial's drop and late-report sequences against RFC 0008's bound (Review section). `quiet_until` is `None` before the first quiet period, so no instant stands for "none". Every instant `now + d` that would pass the largest `Monotonic` is the largest (RFC 0008 section 4). The methods consume the state and return the next one (design/03 section 10, State machines):

| Method | Transition | RFC 0008 change 5 row |
|---|---|---|
| `peek` | What `permit` would return at `now`, with no transition | change 6 |
| `permit` | `Closed` and `Checking`: unchanged, `Call`. `Open` before `until`: `Refuse { until }`. `Open` at or after `until`: `HalfOpen` with `probe_until` at `now` plus the call timeout and `Probe(kind)`. Its phase: `Health { unhealthy }` stays a health probe while `unhealthy` is below `breaker_failures`; `CallDue`, or `Health` at or above `breaker_failures` after `set_policy` lowered it, is the turn's first call probe, `CallTurn { until: now + cap }`; `CallTurn { until }` before `until` is a call probe of that turn, and at or after it is a health probe, `Health { unhealthy: 0 }`. `HalfOpen` before `probe_until`: `Refuse { until: probe_until }`. `HalfOpen` at or after `probe_until`: unchanged, `Unanswered`, and the caller draws a step and calls `unanswered` | `Open` at `until` and a permit |
| `unanswered` | `HalfOpen` in `Health { unhealthy }` becomes `Open` until `now + open_for` with one more unhealthy probe, `CallDue` once that reaches `breaker_failures`; `HalfOpen` in `CallTurn` becomes `Open` until `now + open_for` in `Health { unhealthy: 0 }`, the turn ended; any other state is unchanged. The permit is refused | `HalfOpen` at or after `probe_until` and a permit |
| `record_success` | `Closed`: count to 0. `Checking` and `HalfOpen`: `Closed` with the count at 0 and `quiet_until` at `now` plus the call timeout. `Open`: `until` at the earlier of `until` and `now`, the phase kept | `Checking` and a success; `Open` and a late success; `HalfOpen` and a late success |
| `record_failure` | `Closed`: count one more, saturating, and at `breaker_failures` outside the quiet period move to `Checking` with `check_until` at `now` plus the call timeout. `Checking` before `check_until`: unchanged; at or after it, a new `Checking`. `Open`, `HalfOpen`: unchanged. The second value is the new `check_until` when a check starts, so the run that recorded the failure makes the health call | `Closed` and a recorded failure; `Checking` and a recorded failure; `Open` and a late failure; `HalfOpen` and a recorded failure |
| `record_check` | Applies only if the breaker still equals `started`, the state the check or probe began from; otherwise unchanged. `Checking`: `Healthy` closes with the count at 0 and a quiet period, `Unhealthy` opens until `now + open_for` in `Health { unhealthy: 0 }`. `HalfOpen` in `Health { unhealthy }`: `Healthy` closes the same way, `Unhealthy` opens until `now + open_for` with one more unhealthy probe, `CallDue` once that reaches `breaker_failures`. `HalfOpen` in `CallTurn { until }`: `Healthy`, a `Done`, closes; `Unhealthy`, a peer failure or the cutoff, opens until `now + open_for` in `Health { unhealthy: 0 }`, the turn ended; `Inconclusive`, an error the peer did not cause, is `Open { until: now }` in `CallTurn { until }`, the same end, however late the report comes. `Inconclusive` leaves every other state unchanged; a health call is never inconclusive, because only `Ok` is healthy (RFC 0008 R13) | `Checking` and a verdict; `HalfOpen` and a verdict, of either kind; `HalfOpen { probe: Call }` and no verdict |
| `release` | Applies only if the breaker still equals `started`. `HalfOpen`: `Open` until `now` plus the call timeout, in the same phase, so a dropped call probe keeps its turn's end. `Checking`: `Closed` with the count one below `breaker_failures` and `quiet_until` at `now` plus the call timeout | `release` of an abandoned probe or check |

`Open` is left only through `HalfOpen` (#282 AC-4). A turn begins at its first call probe's permit and ends one cap later, as RFC 0008 section 4 states, so no bound RFC 0008 and #283 build on the turn changes with this RFC: `breaker_failures + 1` open periods, a turn that ends within one cap, and RFC 0008's section 7 figures and cases R1 and F3 stand as decided. `CheckOutcome` names the result of a check or a probe; the spine's *Verdict* is a decision's (spine section 3), so the type does not borrow the word. Errors: none.

**Answer 11: what RFC 0008 section 8 needs.**
| RFC 0008 change | Where it is met |
|---|---|
| 1. `next` takes `&mut R` for any `R: Entropy + ?Sized` | `RetryPolicy::next` |
| 2. Two counts; `AttemptCounter` with `new`, `get`, saturating `next`, its derives and `LogSafe` | `next`'s `counter` and `retries`; `AttemptCounter`, `LogSafe` as a `Count` in section 7 |
| 3. `open_for` on each step | `RetryStep` |
| 4. The policy's timeout, cap, budget fields, `breaker_failures` and `at_cap`; the budget's failure count and share | `RetryPolicy`; `RetryBudget::record_attempt` and `failure_share`, as `Permille` (constraint 1d), per attempt over `budget_share_attempts` (constraint 1f). `record_failure(now)` and its count read `record_attempt(outcome)` and that window, by the amendment of section 16 |
| 5. Four states with the probe's state in them, every row | `Breaker`, its state structs, `OpenPhase` and `HalfOpenPhase`, with RFC 0008's timing; the state shapes change by the amendment of section 16 |
| 6. A permit's answer without a transition | `Breaker::peek` |
| 7. `Send + Sync`; `Clone` and `Debug`; the derives of `Breaker`, `ProbeKind` and the give-up reason | R10; the blocks above |
| 8. `RetryState::new(policy, clock, entropy, health)` with the policy by value | `RetryPolicy` is `Copy` |
| 9. A failed draw | Answer 9: `GiveUp::EntropyUnavailable`; `RetryError` unchanged |

### 7. Logging (#284; answer 7)
```rust
pub trait LogSafe { fn log_value(&self) -> LogValue<'_>; }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogValue<'a> {
    Bool(bool),
    Count(Count),       // grdr_schema::limits::Count
    Bytes(Bytes),       // grdr_schema::limits::Bytes
    Permille(Permille), // grdr_schema::limits::Permille
    Duration(Duration),
    Timestamp(Timestamp),
    Monotonic(Monotonic),
    Epoch(Epoch),
    Seq(Seq),
    Enum(WireName),
    Code(Code),         // grdr_schema::codes::Code
    Id(IdRef<'a>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdRef<'a> { /* private: the kind and the id's text */ }
impl<'a> IdRef<'a> {
    pub const fn kind(&self) -> IdKind;
    pub const fn as_str(&self) -> &'a str;
}

pub trait LiteralText { const TEXT: &'static str; }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct WireName { /* private: &'static str */ }
impl WireName {
    pub const fn of<L: LiteralText>() -> WireName; // [a-z][a-z0-9_.-]*, at most 64 bytes
    pub const fn as_str(self) -> &'static str;
}
// EventName and FieldName have the same shape, with the grammar [a-z][a-z0-9_.]*, at most 64 bytes.

wire_enum! { #[derive(PartialOrd, Ord)] pub enum LogLevel { Debug => "debug", Info => "info", Warn => "warn", Error => "error" } }

#[derive(Clone, Copy, Debug)]
pub struct LogRecord<'a> { /* private: the level, the event and the fields */ }
impl<'a> LogRecord<'a> {
    pub const fn new(level: LogLevel, event: EventName, fields: &'a [(FieldName, LogValue<'a>)]) -> LogRecord<'a>;
    pub const fn level(&self) -> LogLevel;
    pub const fn event(&self) -> EventName;
    pub const fn fields(&self) -> &'a [(FieldName, LogValue<'a>)];
}

// The macros, at the crate root:
//   wire_enum! { $(#[$meta])* $vis enum Name { Variant => "word", ... } }
//   wire_name!("word"), event_name!("session.start"), field_name!("retry.attempts")
//   log_record!(level, EVENT, "field.name" => value, ...)
```

The gate. A value reaches a log only as a `LogValue`, and no variant carries free text, raw bytes or a bare integer: a flag, a count, an amount in a unit, a duration, an instant, a record's epoch or sequence number, a `WireName`, a `Code` or an `IdRef`.
- **Names are fixed at build time.** `WireName`, `EventName` and `FieldName` have one constructor each, `of::<L>()`, which reads `L::TEXT` from a `LiteralText` impl. An associated constant is a constant expression, so its text is fixed when the program is built and cannot come from a run-time value: `String::leak` in it fails (E0015), and a function parameter in it fails (E0435). There is no `new` (E0599). `of` checks the grammar in an inline `const` block. The macros define the `LiteralText` type and call `of` in a `const` item, so `cargo check` already refuses a name outside the grammar (E0080). A direct call of `of` in a function body is checked when the function is built, so a build refuses it (E0080) where `cargo check` alone does not; the bench shows both. `LogRecord::new` takes only these names and `LogValue`s, so it adds no other way in. Fixed at build time is not the same as written in the source: a hand-written `LiteralText` impl may set `TEXT` from `env!`, `option_env!`, `include_str!` or a file a build script wrote, and each is a constant the source does not show. The log-gate scan of section 15 refuses `env!`, `option_env!`, `include_str!` and `include_bytes!` in a `LiteralText` impl.
- **What the grammar refuses.** `WireName`'s grammar refuses an empty word, a word over 64 bytes, upper case, whitespace, a first character other than a lower-case letter, and every other character but digits, `_`, `.` and `-`. So it refuses a path, a URL, a command line, an IPv4 or IPv6 address and an email address. It admits every dotted lower-case name, a host name such as `build-01.corp.example.com` included, because wire words such as `file.read` and `action.agent.spawn` have that form. A host therefore reaches a log only as text fixed at build time: as a literal, which ARCH-021 refuses outside `brand/`, configuration defaults and tests, or through one of the macros the log-gate scan refuses in a `LiteralText` impl; review reads what neither sees.
- **No bare integers, and the residual.** `LogSafe` is implemented for no integer type, so a raw uid, pid or port written as an integer fails at the call site (E0277). A count is logged as RFC 0007's `Count`, an amount as `Bytes` or `Permille`, a duration as `Duration`, and a record position as its `Epoch` and `Seq`. The types cannot stop the other form: every unit and counter constructor is public (RFC 0007 section 5), so a call site can wrap a raw identifier in one, `"peer.uid" => Count::new(u64::from(uid))`, `AttemptCounter::new(pid)`, `Epoch::new(uid)`, `Seq::new(port)`, `Bytes::new(..)`, `Millis::new(..)`, `Permille::new(..)`, `Timestamp::new(..)`, `Monotonic::from_nanos(..)` or `Duration::from_*(..)`, and `LogRecord::new` takes `LogValue` variants built the same way. No `impl LogSafe` is needed for it, so reading impls does not find it. That is the residual: a raw number wrapped in a unit type at a call site reaches a log. The log-gate scan of section 15 lists every such constructor, and every `LogValue` variant expression, written in a `log_record!` argument or a `LogRecord::new` field outside `grdr-model`, and `eval-security` reads each listed site and refuses one whose operand is an identifier rather than a count, length or duration the code owns.
- **Ids.** `IdRef` has no public constructor. It is built only by the `LogSafe` impls of the ids whose kind is loggable, so a struct expression of it fails (E0451) and no other id reaches a log.
- `LogValue` is exhaustive, so a variant added by amendment fails every sink's build until the sink formats it.

`LogSafe` is implemented for:
- `bool`, `Duration`, `Timestamp`, `Monotonic`, `Epoch` and `Seq`, each as its own variant, and `AttemptCounter` as a `Count`;
- every `wire_enum!` type, and `Lane`, as `Enum` of the word;
- `OrgId` and `DelegationSnapshotId`, as `Id`;
- every error enum of this crate, as `Code` (R6);
- RFC 0007's `Code` as `Code`, `Bytes` as `Bytes`, `Count` as `Count`, `Millis` as `Duration` and `Permille` as `Permille`;
- `&T` where `T: LogSafe + ?Sized`.

It is implemented for no integer type, no text type (`str`, `String`, `char`), no byte type (`[u8]`, `[u8; N]`, `Vec<u8>`), no path or OS string, no generic container (`Option`, `Result`, `Vec`), no id of a kind that is not loggable, and nothing that holds entropy output (#284 R2 and R8). A program that needs to correlate a raw identifier or a content value logs its keyed digest once that type exists, never the value or a bare hash of it.

**Answer 7, which ids are `LogSafe` and how a `Code` logs.**
- Two kinds are loggable: `Org` and `DelegationSnapshot`. design/21 section 2 lets server logs carry the organisation id and the request id only, and RFC 0002's contexts log only their organisation id or snapshot id. A snapshot id is a set context's counterpart of the organisation id: it names one workbench exchange of a technician account, which design/21 section 5 already records in both organisations' audit logs, and no monitored principal. Every other kind names a person, a device, or something one person did, and a log line that carried one would be a per-person record outside the event stream's data classes and retention (P8). A diagnostic that needs to point at a record points at its `(epoch, lane, seq)`, which is structural. The request id joins when its id row is added, by amendment, as any loggable kind does.
- `LogValue::Id(IdRef)` carries the kind and the text, so a sink can label the field; the data class stays `identifier`.
- A `Code` logs as `LogValue::Code(code)`, and a sink writes its `as_str()`, never a token id or a message (RFC 0007 section 3).

The macros:
- `wire_enum!` declares a fieldless enum from one list of variants and words, deriving `Clone`, `Copy`, `Debug`, `PartialEq`, `Eq` and `Hash`, with any further derives the caller writes, and gives `VARIANTS`, `as_str`, `wire_name` and the `LogSafe` impl. A variant with a field does not match the macro's grammar and fails to compile, and a word outside `WireName`'s grammar fails (E0080). It replaces #284's `log_enum!`, whose separate list of words would be a second home for them (R5). Every type it declares is loggable, which is right because its values are a fixed set of wire words of class `structural`; an enum whose values must not reach a log is not a wire enum.
- `wire_name!`, `event_name!` and `field_name!` each define a `LiteralText` type for their literal and evaluate `of` in a `const` item. Clippy with the workspace deny list passes over the expansions (the bench).
- `log_record!(level, EVENT, "name" => value, ...)` builds the field array, calls `log_value()` on each value and returns a `LogRecord`. A field name is a string literal, because a name may hold dots. A value whose type is not `LogSafe` fails at the call site (E0277). The record borrows an array of temporaries, so it lives for the statement that writes it: `sink.write(&log_record!(..))`. Keeping it in a `let` fails (E0716).
- Formatting a record and writing it to the operating-system log or a file are the programs' (#284 R7).

`LogValue::Digest([u8; 32])` (#284 R1) is not in slice 0. No type yields it yet (#284 R2), and a public variant holding 32 bytes would let any impl log a bare hash. Design/04 work item 04-16 adds the keyed digest type, and the variant with it, by amendment. `Level` is named `LogLevel`, because R3 puts every item at the crate root and `grdr_model::Level` would not say which level.

Errors: none. Every check here is at compile time, or in the log-gate scan and the review it feeds.

### 8. InstallProfile and Tamper (answer 8)
```rust
wire_enum! { pub enum InstallProfile { Protected => "protected", User => "user" } }
wire_enum! { #[derive(PartialOrd, Ord)] pub enum Tamper { User => "user", Admin => "admin", Platform => "platform" } }
```
**Answer 8: the paths are `grdr_model::InstallProfile` and `grdr_model::Tamper`** (R3).
- `InstallProfile` is D-48's choice at install, read from install state and never from configuration (RFC 0003 section 6).
- `Tamper` is the assurance record's tamper grade (spine section 3). It is ordered by grade, `User < Admin < Platform`, so a rule that asks for at least `admin` reads `>=`.
- RFC 0003's uses fit: `peer_auth::resolve(spec, profile: InstallProfile, user)` gives `Tamper::Admin` for `Protected` and `Tamper::User` for `User`, and `EndpointIdentity::tamper() -> Tamper`.
- A protobuf or Cedar twin, when the assurance package or the configuration schema declares one, is held to the Rust type by a test of section 5's form, which the item that declares the twin adds.
- Errors: none. Both are `structural`.

### 9. Error codes
The area `MODEL` is `grdr-model`'s: subsystem "the domain types of grdr-model", owner `design/03`. This RFC assigns the codes (RFC 0007 section 4), and each item registers the codes it first constructs in `schema/codes/model.toml` and writes their source-locale tokens. Numbers may land out of order; the registry refuses a repeated number, not a gap.

| Code | Reason | Class | Connect | Bound by | Registered by | Next step (`code.<code>.fix`) |
|---|---|---|---|---|---|---|
| `GRDR-MODEL-0001` | `TIMESTAMP_SECONDS_OUT_OF_RANGE` | input | `invalid_argument` | `TimeError::Seconds` | #383 | A time falls outside 0001-01-01 to 9999-12-31 UTC. Check the clock or the record that gave it |
| `GRDR-MODEL-0002` | `TIMESTAMP_NANOS_OUT_OF_RANGE` | input | `invalid_argument` | `TimeError::Nanos` | #383 | A time's nanoseconds are a whole second or more. Check the record that gave it |
| `GRDR-MODEL-0003` | `ENTROPY_UNAVAILABLE` | fatal | `failed_precondition` | `EntropyError::Unavailable`; `IdError::Entropy` | #383 | The random source failed, so nothing that needs randomness ran. Check the host's random source, then collect a support bundle |
| `GRDR-MODEL-0004` | `ID_FORM` | input | `invalid_argument` | `IdError::Form` | #383 | An id is not a known prefix, `_` and 26 base32 characters. Check the record or request that carried it |
| `GRDR-MODEL-0005` | `ID_TIME_OUT_OF_RANGE` | fatal | `failed_precondition` | `IdError::TimeOutOfRange` | #383 | The clock reads a time before 1970, so no time-ordered id can be made. Set the system clock |
| `GRDR-MODEL-0006` | `RETRY_PEER_MISMATCH` | internal | `internal` | `RetryPolicyError::PeerMismatch` | #282 | A retry table was read for a call to the other kind of peer. This is a defect; collect a support bundle |
| `GRDR-MODEL-0007` | `LANE_UNSPECIFIED` | input | `invalid_argument` | `OrderError::LaneUnspecified` | the order item | A record names no lane. Check the version of the component that sent it |
| `GRDR-MODEL-0008` | `LANE_UNKNOWN` | input | `invalid_argument` | `OrderError::LaneUnknown` | the order item | A record names a lane this version does not know. Update this component, or check the sender |
| `GRDR-MODEL-0009` | `LANE_NOT_UPLOADED` | input | `invalid_argument` | `OrderError::LaneNotUploaded` | the order item | A record of the local lane arrived, and local records never leave the device. Check the version of the component that sent it |
| `GRDR-MODEL-0010` | `EPOCH_ZERO` | input | `invalid_argument` | `OrderError::EpochZero` | the order item | A record has epoch 0, which no device writes. Check the component that sent it |
| `GRDR-MODEL-0011` | `SEQ_ZERO` | input | `invalid_argument` | `OrderError::SeqZero` | the order item | A record has sequence number 0, which no device writes. Check the component that sent it |

Each fits RFC 0007 section 4's grammar. `ENTROPY_UNAVAILABLE` and `ID_TIME_OUT_OF_RANGE` are faults of our own host. Both are `fatal` with `failed_precondition`: repeating the call unchanged does not help, no policy retries them, and `faults_peer` (RFC 0008 R12) is false for both, so neither counts against a peer, even when an operation that wraps one fails a retried call. `RETRY_PEER_MISMATCH` is `internal`, a defect in the code that chose the table or the access, and its `fix` names the support-bundle command through the CLI registry (RFC 0007 section 3). Token arguments are `structural` `LogSafe` values.

### 10. Answers to the questions of #1850
| # | Question | Answer |
|---|---|---|
| 1 | `DelegationSnapshotId`'s prefix and route | `dls_`, `Uuid7`; `DelegationId` `dlg_` and `ProviderId` `prv_`, both `Random128` (section 4) |
| 2 | `HolderId`'s route, and whether the type moves | `hld_`, `Random128`, in `grdr-model`; RFC 0002's capability stays in `grdr-ports` as `Holder` (section 4) |
| 3 | One `Lane` type, its variants, one definition with the protobuf enum | `Lane { Uploaded(UploadedLane), Local }`, with `UploadedLane`'s four lanes; the `lane_wire` test walks the descriptor's values and, where the codec allows, matches exhaustively both ways (section 5) |
| 4 | The shapes of `Epoch`, `Seq` and `DeviceId` | Non-zero `u32`, non-zero `u64`, a `Derived128` id (section 5) |
| 5 | The give-up reason's name | `GiveUp` (section 6) |
| 6 | #282's `#[cfg(test)]` constructor | None; tests use `RetryLimits::new` and `from_limits` (section 6) |
| 7 | Which ids are `LogSafe`, through `IdRef`, and a `Code`'s form | `OrgId` and `DelegationSnapshotId`; `LogValue::Code` (section 7) |
| 8 | The paths of `InstallProfile` and `Tamper` | `grdr_model::InstallProfile`, `grdr_model::Tamper` (section 8) |
| 9 | `Entropy::fill` and a failing source (lead-core's comment) | `fill` returns `Result<(), EntropyError>` (section 3) |
| 10 | How the call's peer kind reaches `from_limits` (RFC 0007 round 4) | A `PeerAccess` from the port, classified by `PeerAccess::retry_peer`, with a consistency check at construction (section 6) |
| 11 | RFC 0008 section 8's changes 1 to 9 and constraints 1d and 1f | The table in section 6, with section 16's amendment |

### 11. Failure modes
| Failure | Declared outcome | Visible as |
|---|---|---|
| A time's seconds or nanoseconds are out of range | `TimeError::Seconds` or `Nanos` | The caller's error, `GRDR-MODEL-0001` or `0002` |
| `Timestamp` arithmetic would leave the range | `None` | The returned value |
| The random source fails | `EntropyError::Unavailable`; minting returns `IdError::Entropy` and builds no id; `next` returns `GiveUp::EntropyUnavailable` with the ceiling as backoff and `open_for`; `Engine::step` returns a typed failure, which the host routes through the rule class's `on_failure` (D-15); no bytes the source did not produce are ever used; no peer is blamed | The caller's error, `GRDR-MODEL-0003`; RFC 0008's `GaveUp` with its reason; Degraded with the code when `on_failure` lets an action through (P9) |
| A source fills part of the buffer | `Err`, never `Ok` | As above |
| AWS-LC cannot get random data in a program | The library aborts the process before `fill` returns | The process ends; #334's row says what the daemon shows |
| An id is minted with a `now` before 1970 | `IdError::TimeOutOfRange` | The caller's error, `GRDR-MODEL-0005` |
| A wire id is malformed or of another kind | `IdError::Form`; nothing is decoded | The decoder's error, `GRDR-MODEL-0004` |
| A wire lane is 0, unknown, or `local` where an uploaded lane is required | `OrderError::LaneUnspecified`, `LaneUnknown { number }` or `LaneNotUploaded` | The decoder's error, `GRDR-MODEL-0007` to `0009` |
| Device code passes `Lane::Local` to the upload path | Compile error | rustc's E0308 |
| A wire epoch or sequence number is 0 | `OrderError::EpochZero` or `SeqZero` | The decoder's error, `GRDR-MODEL-0010` or `0011` |
| An epoch or a sequence number is at its maximum | `next` returns `None`; the caller maps it to its own code | The caller's error |
| A table's peer kind differs from the call's access | `RetryPolicyError::PeerMismatch`; the caller's rule class decides (D-15) | The caller's error, `GRDR-MODEL-0006` |
| A configured file path is on a network mount, a UNC path or a remote pipe | The adapter classifies it as `Connection` or refuses it | The adapter's construction error, or its remote table |
| A registered table writes a share window below the multiple of its `breaker_failures` | `check` refuses it: `BudgetShareBelowBreaker` | The generator's refusal line; `LimitsError::RetryTable` for a table built at run time |
| A counter or a hint is huge | The ceiling stays at the cap; sums saturate | #282's cases at `u32::MAX` and a hint of `u64::MAX` ms |
| `set_policy` lowers `breaker_failures` below a phase's unhealthy count | The next permit is a call probe | The breaker's state |
| Call probes are dropped, or report late, during a turn | The turn's end stays at the first call probe's permit plus the cap; the first permit at or after it is a health probe | The breaker's state; the bench's drop and late-report sequences |
| A probe never reports | `HalfOpen` ends at `probe_until`: the next permit is `Unanswered` | The breaker's state |
| A check never reports | `Checking` ends at `check_until`: the next recorded failure starts a new check | The breaker's state |
| A check or probe reports after the breaker moved on | `record_check` and `release` leave the breaker unchanged | The breaker's state |
| A caller logs a type that is not `LogSafe`, a bare integer, or an id of a kind that is not loggable | Compile error at the call site | rustc's E0277 |
| A name or word is outside its grammar | Compile error: in `cargo check` through the macros, in a build for a direct `of` | rustc's E0080 |
| A name is built from a run-time value | Compile error | rustc's E0015 or E0435 |
| A `LiteralText` impl reads `env!`, `option_env!`, `include_str!` or `include_bytes!` | The log-gate scan refuses it | The scan's line |
| A call site wraps a raw identifier in a unit type in a log call | The log-gate scan lists the site; `eval-security` refuses it | The scan's list on the pull request |
| A record is kept past its statement | Compile error | rustc's E0716 |
| The protobuf lane enum gains a value, or `Lane` a variant | `lane_wire` fails: the descriptor walk always, the exhaustive match where the codec generates a closed enum | The test's failure; rustc's E0004 |

Nothing here fails open, with one stated exception: no error reads as success, a failed draw never yields bytes, and a refused permit is never a call. The exception is `Engine::step` on a failed draw, whose answer is the rule class's `on_failure` under D-15, open for a class that is not fail-closed; it is never read as "no decision needed", and an open answer raises Degraded with `GRDR-MODEL-0003` (P9).

### 12. Mechanisms
| Decision | Mechanism | Built by |
|---|---|---|
| One path per item (R3) | The source modules are private; a compile-fail doctest that `grdr_model::log::LogSafe` does not resolve (E0603); `cargo public-api` lists exactly sections 2 to 8 at the root | #383 and #284; #1741 |
| Layer 1 (R2) | `cargo check --locked --target wasm32-unknown-unknown -p grdr-model`; the workspace lints; ARCH-003 | Each item; #1582 |
| The edges (R1) | The protected change of section 15; ARCH-001's graph | Section 15; #1580 |
| A failed source is an error, never bytes, never a peer's fault | A fixture source that writes a marker into `out` and returns `Err`: every minting route returns `IdError::Entropy` and no id holds the marker; `next` returns `GiveUp::EntropyUnavailable` with backoff and `open_for` at the ceiling; `faults_peer` of `GRDR-MODEL-0003`'s class and Connect code is false | #383; #282; #283's table test over every pairing |
| `Entropy` stays dyn-compatible and reaches RFC 0008's `run` | Compile tests: `&mut dyn Entropy` passed to each minting route; a function generic over `R: Entropy + Send + ?Sized` that calls `mint` and `next`, whose future is `Send` when given `&mut (dyn Entropy + Send)` | #383; #282 |
| The id form and minting | #383 AC-1 to AC-7, with AC-5 gaining an id holding `/`, `=`, `.` and `..`, each refused (RFC 0002 section 15) | #383 |
| One id table, both entry forms | One macro list generates `IdKind`, `VARIANTS`, `prefix`, `route`, `loggable` and the newtypes, `PrincipalId` included; a test checks that every prefix fits `[a-z]{2,3}`, is unique and is not `agt`, and that each kind's `from_wire` refuses every other kind's text | #383 |
| The keyed derivations | `PrincipalId::human` and the other HMAC rows take the digest design/04 section 3 names; #335's tests, and each deriving item's test against its row | #335; the deriving items |
| Only two kinds log | `loggable()` checked against design/04 section 11's list, transcribed; one compile-fail doctest per kind whose `loggable()` is false, logging it (E0277), and one that builds an `IdRef` (E0451) | #383; #284 |
| The `LogSafe` gate | #284 AC-1's compile-fail doctests with a `String`, a `&str`, a `Vec<u8>`, a `[u8; 32]`, a `PathBuf`, a `char`, an `Option`, and every integer type, a `u32` named `uid` and an `i32` named `pid` among them (E0277), and `wire_enum!` given a variant with a field | #284 |
| Names are fixed at build time | Compile-fail doctests: `WireName::new`, `EventName::new`, `FieldName::new` (E0599); a `LiteralText` whose text is `String::leak` (E0015) or a parameter (E0435); words and names outside the grammar through the macros (E0080 in `cargo check`); a direct `of` with a bad literal, refused by a build (E0080). The log-gate scan refuses `env!`, `option_env!`, `include_str!` and `include_bytes!` in a `LiteralText` impl, with a fixture of each | #284; the log-gate scan item of section 15 |
| A record lives for its statement | A compile-fail doctest that keeps one in a `let` (E0716) | #284 |
| A raw identifier wrapped in a unit type is seen | The log-gate scan lists every unit or counter constructor (`Count::new`, `Bytes::new`, `Millis::new`, `Permille::new`, `AttemptCounter::new`, `Epoch::new`, `Seq::new`, `Timestamp::new`, `Monotonic::from_nanos`, `Duration::from_*`) and every `LogValue` variant expression written in a `log_record!` argument or a `LogRecord::new` field outside `grdr-model`, with fixtures that wrap a uid, a pid and a port and are listed; `eval-security` reads every listed site and every new `impl LogSafe`, a duty in its agent file | The log-gate scan item and the agent-kit item of section 15 |
| One word list per enum (R5) | `wire_enum!`; a test that each enum's words are unique | #284 |
| `Lane` is one definition with the protobuf enum | `crates/grdr-model/tests/lane_wire.rs` (section 5) | The order item (section 15), after #394 and #17 |
| Nothing uploads `local` | The upload read, the offer and the batch take `UploadedLane`; a compile-fail case passing `Lane::Local` to each (E0308) | #428, #1539, #1238 |
| Epoch and sequence numbers start at 1 | Tests at 0, 1 and the maximum, where `next` is `None` | The order item |
| One `RetryPolicy` constructor | Private fields (a compile-fail doctest, E0451); ARCH-019 refuses `RetryLimits::new` outside test code (RFC 0007 section 8) | #282; #1582 |
| The peer kind is classified once and checked for consistency | #282's tests: `retry_peer` for each `PeerAccess`, a bare `RetryPeer` refused (E0308), a remote call given a `local` table and a local call given a `remote` table, each `PeerMismatch`; each adapter item tests its access, and an adapter that opens a configured path tests that a network mount, a UNC path and a remote pipe are `Connection` or refused; `eval-architecture` reads the access on every `from_limits` call | #282; the adapter items, #301 and #1542 among them; the agent-kit item of section 15 |
| `next`'s arithmetic | #282 AC-1 to AC-3, with the counter and the run's retries drawn independently (RFC 0008 change 2), the hint floor, schedule jitter, a failed draw, and a hint of `u64::MAX` ms whose `open_for` is the ceiling | #282 |
| Every breaker value is reachable, and only transitions build one | The state structs' private fields (compile-fail doctests of a struct expression of each, E0451); #282 AC-4 as a test that runs the transition table of section 6 against a reference written from the table, over every state it reaches and every event, and checks that each of the eight shapes is reached, every `Health` count below `breaker_failures` is reached, nothing leaves `Open` except through `HalfOpen`, and every state reaches another variant; compile-fail doctests that `HalfOpenPhase` has no `CallDue` (E0599) | #282 |
| A turn ends at RFC 0008's bound | #282's turn test: from a first call probe's permit `p0`, 1, 2, 5, 20 and 1,000 dropped call probes, and an `Inconclusive` 1, 100 and 10,000 ms after `probe_until` with no permit between, each leaves the turn's end at `p0` plus the cap, permits no call probe at or after it, and gives a health probe at the first permit after it | #282 |
| The budget and the share | #282 AC-3, and share cases: 0 until `budget_share_attempts` outcomes are recorded, the failed share once the window is full, and the window of a narrowed table equal to its registered table's | #282 |
| The share window is a registered bound, at least a multiple of the breaker threshold | RFC 0007's rules and fixtures for `budget_share_attempts`: 0, the ceiling and one past it, and `BudgetShareBelowBreaker` at the multiple and one below it, a narrowed table still passing; the generator's refusal of rows where the floor multiple times the breaker-failures ceiling exceeds the share ceiling (section 16) | #279 |
| Every error variant has one code | `Coded` with an exhaustive match; RFC 0007's registry and ARCH-017 | Each item; #1582 |
| `Tamper` is ordered by grade | A test of `User < Admin < Platform` | The install profile item (section 15) |
| Stability (section 13) | The `[[crate]]` row of `surfaces.toml`, `rfc-required`, `cargo public-api`, `cargo semver-checks` | Section 15; #1741 |

### 13. Stability
- `grdr-model` enters `surfaces.toml` as `experimental` (D-60; ADR-0020; design/03 section 7), in one row of the `[[crate]]` kind RFC 0007 section 11 uses: `name = "grdr-model"`, `class = "experimental"`, `rfc = "0009"`. The class is the crate's, so `Monotonic` (RFC 0008) takes it too, and no item needs a key of its own.
- `experimental` allows a break in any release, and every change still goes by RFC: a change to a signature, a semantic, a variant, a grammar, a code's class, the loggable kinds, the access classification or the lane mapping is an amendment, a new RFC that names RFC 0009, because an accepted RFC never returns to `Review` (RFC 0001, "RFC states").
- A new row of the id table (section 4) and a new code in the `MODEL` area are content under this RFC and RFC 0007; their pull requests name RFC 0009 or RFC 0007 for `rfc-required`.
- The codes' area, numbers, reasons, classes and Connect codes are stable wire identifiers from the first release, whatever the crate's class (RFC 0007 section 11). An id's text form and a lane's word and number are wire format and change only with the protobuf package's own rules (D-06).
- `Lane`, `UploadedLane`, `Breaker`, `OpenPhase`, `HalfOpenPhase`, `Permit`, `RetryStep`, `GiveUp`, `PeerAccess`, `LogValue`, `LogLevel`, `Tamper` and `InstallProfile` are exhaustive while the crate is `experimental`, so a new variant fails every match until it is handled. Beta and stable are additive only (ADR-0020), so the RFC that promotes `grdr-model` out of `experimental` decides, for each of these enums, whether it becomes `#[non_exhaustive]` and what the wildcard arm of each caller does, as RFC 0008 constraint 2e asks of `RetryError`.
- The release notes list every change to this surface (design/34 section 10).

### 14. What each item and document changes
Under #1850 R4 and R5, each lead or author writes these into its item or document; the chief architect's documents change through the design item of section 15.
- **#383**: its route is RFC 0009, not RFC 0001.
  - Surfaces added: the items of sections 2 to 4. `Id` is not a type: "`grdr_model::{Timestamp, Entropy, IdKind, Id}`" becomes the list of section 4.
  - R2: `fill` returns `Result<(), EntropyError>` (section 3).
  - R3: the table of section 4, with `DelegationSnapshot`, `Provider`, `Delegation` and `Holder`; `prv_` leaves the non-goals.
  - R4: no `Display`; ids are `Clone` and not `Copy`; `PrincipalId` has its three constructors and `kind`, written by the list's shared-newtype entry form.
  - R5 and R6: `mint` takes `&mut R` with `R: Entropy + ?Sized`, draws once, and returns `IdError::Entropy` on a failed draw; `Random128` minting returns a `Result`.
  - R7: a `Derived128` input is the digest design/04 section 3 names for the kind, `prn_`'s under the device pseudonym key.
  - R11: the codes `GRDR-MODEL-0001` to `0005` of section 9, with the area row; its write set already names `schema/codes/model.toml`, and gains `schema/codes/areas.toml`, `crates/grdr-schema/src/codes/generated.rs` and `interface/strings/src/code.mf2.toml` (RFC 0007 section 4).
  - The id table is one macro list, and `loggable()` is tested against design/04 section 11 (section 12). Its acceptance gains the cases of section 12. It is blocked by the edges item of section 15.
- **#18**: `Lane`, `UploadedLane`, `Epoch`, `Seq` and `OrderError` are built by a new sub-issue (section 15), not by #383.
- **#394**: number the `Lane` values 1 to 5 in the order `decision`, `spine`, `bulk`, `evidence`, `local`, which `Lane::number` follows.
- **#282**: its route is RFC 0009.
  - R1: `from_limits(limits, access: PeerAccess) -> Result<RetryPolicy, RetryPolicyError>`, the only constructor, with `PeerAccess::retry_peer`; its tests build tables with `RetryLimits::new`, and the `#[cfg(test)]` constructor goes.
  - R2: `next(counter, retries, elapsed, hint, entropy: &mut R)`, `RetryStep` with `open_for`, and `GiveUp` with `EntropyUnavailable`.
  - R4: a schedule's jitter. R5: the hint floor and the larger of the two delays. R6: the little-endian `u64` read.
  - R8: `RetryBudget::new(policy)`, `record_attempt` and `failure_share` as `Permille` over `budget_share_attempts`.
  - R9: `Breaker` with its state structs, `OpenPhase`, `HalfOpenPhase` and the methods of section 6, `Permit`, `ProbeKind` and `CheckOutcome`, in place of the three-state breaker, with RFC 0008's turn timing; AC-4 gains the turn test of section 12.
  - `AttemptCounter`; the code `GRDR-MODEL-0006`, so its write set gains `schema/codes/model.toml`, `crates/grdr-schema/src/codes/generated.rs` and the token file.
  - The non-goal "Sharing one budget or breaker across threads" stays true (RFC 0008 section 8). Its acceptance gains section 12's cases. It is blocked by the edges item, by #383 for `Entropy`, by #281 for `Monotonic`, as its Requires already says, and by #279 for `budget_share_attempts`. The item grows past size M, so its lead should split it, for example into the policy, the budget and the breaker.
- **#279**: it builds section 16's amendment of RFC 0007: the `budget_share_attempts` key and field, `RetryField::BudgetShareAttempts`, the three rules, `RetryBounds::share_attempts_ceiling` and `share_multiple_floor`, the rows `retry-bounds.share-attempts-ceiling` and `retry-bounds.share-multiple-floor`, the generator's refusal of rows that cannot fit a table at the breaker-failures ceiling, `narrow` keeping the key, their fixtures and a row in the rate oracle's inputs; "Add a limit" says a table writes the key at least the floor multiple of its `breaker_failures`, twice at the seed.
- **#283**: it reads the breaker through `Breaker`'s state structs and accessors, builds each class's budget with `RetryBudget::new(&policy)`, and builds policies with a `PeerAccess`. Its cases R1 and F3 and RFC 0008's turn figures stand as decided, because the turn's timing is RFC 0008's; it builds change 4's failure count as `record_attempt(outcome)` over `budget_share_attempts` (section 16).
- **#1966**: the failure share's window is configuration, the registered key `budget_share_attempts` (section 16), and no longer the literal `2 * breaker_failures`; R2's figure is the value a table writes, `check` refuses a window below the `retry-bounds.share-multiple-floor` multiple of `breaker_failures`, and the registered-table rule holds because `narrow` keeps the key. A constraint note is posted there.
- **#301 and #1542**, and **#30** if its local store builds a set-up policy: an adapter that opens a configured path passes `OwnFile` only for a path on a local disk; it classifies a network mount, a UNC path or a remote named pipe as `Connection` and reads a remote table, or refuses the path with its own coded error, and tests that rule with a path of each kind.
- **#284**: its route is RFC 0009.
  - R1: `LogValue<'a>` has the variants of section 7, with no `Digest` and no bare integer; `LogSafe::log_value(&self) -> LogValue<'_>`.
  - R2: `LogSafe` for the list of section 7: no integer type, ids only for `OrgId` and `DelegationSnapshotId`, through `IdRef`, and RFC 0007's `Code` and unit types.
  - R3: `wire_enum!` replaces `log_enum!`, and `WireName`, `LiteralText` and `wire_name!` join.
  - R4: `EventName` and `FieldName` are built only by `of::<L>()` from a `LiteralText`, with no `new`; the macros evaluate `of` in a `const` item.
  - R5: `LogLevel` with four levels in place of `Level`; every item at the crate root.
  - R6: `log_record!` takes `"name" => value`.
  - Its write set gains the `LogSafe` impls for the ids and the units, which live in its `log` module. It is blocked by #383 and the edges item.
- **#428**: the read the uplink uses takes `UploadedLane`; `grdr audit verify`'s read may take `Lane`. A compile-fail case passes `Lane::Local` to the upload read.
- **#1539**: `UplinkBatch`, the offer loop and the per-lane cursors take `UploadedLane`, with a compile-fail case for `Lane::Local`.
- **#1238**: the lane scheduler schedules `UploadedLane`s only.
- **#334**: `OsRandom::fill` returns `EntropyError::Unavailable` when aws-lc-rs returns an error, and `CryptoError` carries a failed draw as a variant that wraps `EntropyError` and returns its code, so `RandomUnavailable` goes and one failure has one code (P17). Its failure table says that AWS-LC aborts the process when it cannot get random data, and what the daemon's supervisor then shows (section 3).
- **#335**: its `KeyedId128` is what `PrincipalId::human` and the other HMAC rows take; its tests are the oracle for the keyed derivations (section 4).
- **#1536**: R4 states what the daemon does when minting the `decision_id` fails: the request is answered as R8 answers a request it cannot take, and the failure shows with `GRDR-MODEL-0003`. The `decision_id` is `identifier`, not `structural`, and is not `LogSafe`; a diagnostic points at the record's `(epoch, lane, seq)`, and the `DecideAck` field's `data_class` is `identifier`.
- **#1537**: R2 states what `Engine::step` does when a draw fails. Its signature stays `-> Output`. For an `ActionRequest` it returns a typed failure in `Output` that carries `GRDR-MODEL-0003`, never a decision whose id was not drawn and never an empty decision. The daemon routes that failure through the rule class's `on_failure` (D-15) and never reads it as "no decision needed", and an outcome that lets the action through raises Degraded with the code (P9). A test drives a failing source through `Engine::step` for a fail-closed class and an open one, and checks the deny, the open answer and the Degraded.
- **#1927**: its open question on `Entropy::fill` is answered by section 3. `OsRandom` passed as `&mut dyn Entropy` fits.
- **RFC 0002, for its author in its next revision**. RFC 0002 is not decided before it carries these changes:
  - `Lane` becomes `UploadedLane` in `OrgWork::Ingest`, `StorageClass::Archive`, `ArchiveBatch` and `RowPosition`, and section 2's "`Lane` is `Decision`, `Spine`, `Bulk` or `Evidence`; there is no second lane enum" becomes "the server takes `UploadedLane`, the lanes that leave the device; each lane is declared once (RFC 0009 section 5)".
  - Section 7's `HolderId` becomes the capability `Holder`, holding RFC 0009's `HolderId`, with no constructor from a `HolderId`; `Setup::holder_id` and the kit's `holder_id` become `holder(&mut self, entropy: &mut dyn Entropy) -> Result<Holder, IdError>`; `Leases::acquire`, `Lease::holder` and `Claim::holder` take or return `&Holder`; the compile-fail doctests name `Holder`.
  - Section 2's contexts log their id as `LogValue::Id`, of data class `identifier`, not `structural`.
  - A storage adapter's `connect` builds its set-up policy with the `PeerAccess` of its back end: the reference adapters `InProcess`, SQLite `OwnFile` for a path on a local disk, and PostgreSQL, the object store and the bus over any socket `Connection`, so their set-up tables are `peer = "remote"`.
  - Rule 8 says each port error's `LogSafe` form "logs the port name beside the code". `LogSafe::log_value` returns one `LogValue`, and an error's is its `Code` (R6 of this RFC), so the port name and any byte index are fields of their own that the log site writes: `log_record!(.., "port" => port, "error" => error, "index" => Count::new(..))`, with the port as a `wire_enum!` word. RFC 0002's author words Rule 8 so, or names the one `LogValue` it intends.
  - Section 15's request for `OrgId`, `DelegationId` and `DelegationSnapshotId` is met by section 4, with `ProviderId`.
  - The `grdr-model` types are RFC 0009's, not "#1850" or "#18, settled by #1850".
- **RFC 0003, for its author in its next revision**. RFC 0003 is not decided before it carries these changes: `InstallProfile` and `Tamper` are `grdr_model::InstallProfile` and `grdr_model::Tamper`, stated by RFC 0009; `Monotonic`, `Timestamp` and `Clock` are RFC 0008's, not RFC 0002 section 3's; `LogSafe` is RFC 0009's and `Coded` RFC 0007's (#278), not #284 and #280.
- **RFC 0007**: section 16's amendment changes its sections 5 and 6: `BudgetLimits` gains `share_attempts`; `RetryField` gains `BudgetShareAttempts`; `RetryRule` gains `BudgetShareZero`, `BudgetShareAboveCeiling` and `BudgetShareBelowBreaker`; `RetryBounds` gains `share_attempts_ceiling` and `share_multiple_floor`; the retry bounds become fifteen rows with `retry-bounds.share-attempts-ceiling` and `retry-bounds.share-multiple-floor`; `[retry.<name>]` gains the required key `budget_share_attempts`; and `narrow` keeps it as registered. The decided RFC 0007 file is not edited; this RFC is the amendment.
- **RFC 0008**: section 16's amendment changes section 8's changes 4 and 5. Change 5's field lists of `Open` and `HalfOpen` become `OpenBreaker { until, phase: OpenPhase }` and `HalfOpenBreaker { probe_until, phase: HalfOpenPhase }`, and every state's fields are private behind accessors; the transitions and the turn's timing stay as RFC 0008 states them. Change 4's `RetryBudget::record_failure(now)` and its share, 0 "while fewer than a given count have failed", read `record_attempt(outcome)` and the failed share of the last `budget_share_attempts` attempts, 0 until that many are recorded, constraint 1f's form. Its changes 1 to 3 and 6 to 9 are met as RFC 0008 states them. The decided RFC 0008 file is not edited; this RFC is the amendment, alongside #1963 and #1966.
- **design/02 section 3.8**, proposed:
  - SR-new-0009-A, what a log line can carry, each part with the test that holds it: no `str`, byte, path, container or integer type compiles as a log argument, and no id of a kind design/04 section 11 does not name (one compile-fail doctest per type and per kind); no name is built from a value fixed after the build (compile-fail doctests for `new`, `String::leak` and a parameter), and no `LiteralText` impl reads `env!`, `option_env!`, `include_str!` or `include_bytes!` (the log-gate scan's refusal fixtures); and every unit or counter constructor, and every `LogValue` variant expression, written in a log call outside `grdr-model` is listed for review (the scan's listing fixtures, which list a wrapped uid, pid and port). The residual it states: a listed site whose operand is an identifier is refused by review, not by the build.
  - SR-new-0009-B, the device's upload path cannot name `local`, with the compile-fail cases of #428 and #1539.
- **design/03 section 3**, proposed: `Output` carries a typed failure for an `ActionRequest` whose step could not complete, such as a failed draw, which the host routes through the rule class's `on_failure` and never reads as "no decision needed".
- **design/03 section 10**, proposed:
  - Randomness: "a failed draw is an error with its code, never bytes the source did not produce, and never counts against a peer";
  - Logging: "names are fixed at build time, no bare integer is loggable, an id is `LogSafe` only for the kinds design/04 section 11 names, a unit constructor written in a log call is listed for review, and a record lives for the statement that writes it";
  - Retries: "`RetryPolicy` (pure: the attempt counter, the run's retries, injected entropy and the server's hint in, the next delay or a give-up out)", in place of "attempt number", and "the failure share counts over the table's `budget_share_attempts`".
- **design/04**, proposed: section 1's rule 3 adds "the minting crate's form check is the one reader of an id's text"; section 2's `epoch` row adds "starting at 1"; section 3's sentence "Ids defined elsewhere follow the same form" adds providers (`prv_`), delegations (`dlg_`) and delegation snapshots (`dls_`) in 21 and lease holders (`hld_`) in 20; section 11 adds "of our ids, only the organisation and delegation snapshot ids may be logged".
- **design/21 sections 2 and 5 and design/20 section 6**, proposed: the logs row of design/21 section 2 adds the delegation snapshot id beside the organisation id. The `delegation_snapshot` key that design/21 section 5 writes holds the snapshot id's text form, and the row-level security policy of design/21 section 2 and design/20 section 6 compares `current_setting('grdr.orgset', true)` as text, with no `::uuid` cast, because no `grdr-model` id gives out its bits (#383 R4) and RFC 0002 binds `as_str`.

### 15. Filed on acceptance
Each cites RFC 0009 and is blocked by the decision record's issue:
- the protected change that adds `grdr-schema` as a dependency and `grdr-proto` as a dev-dependency of `grdr-model`, in `crates/grdr-model/Cargo.toml` and `Cargo.lock`, for lead-agent-kit, trust core; it blocks #383, #282, #284 and the order item;
- the `surfaces.toml` row of section 13, titled with `surfaces.toml` and `grdr-model`, for lead-agent-kit, trust core, blocked by #1817 and #1915 as #1942 is (#1850 AC-6);
- the #18 sub-issue for `Lane`, `UploadedLane`, `Epoch`, `Seq`, `OrderError`, `lane_wire` and codes `0007` to `0011`, for lead-core, blocked by #394, #17, #284 and the edges item;
- the item for `InstallProfile` and `Tamper`, for lead-core, blocked by #284, blocking the `grdr-wire` items that call `resolve` (#377, #516);
- the log-gate scan item, a rule of the architecture lint for lead-core, blocked by #1582 and #284, with fixtures that fail and fixtures that are listed:
  - it lists every unit or counter constructor (`Count::new`, `Bytes::new`, `Millis::new`, `Permille::new`, `AttemptCounter::new`, `Epoch::new`, `Seq::new`, `Timestamp::new`, `Monotonic::from_nanos`, `Duration::from_*`) and every `LogValue` variant expression written in a `log_record!` argument or a `LogRecord::new` field outside `grdr-model`, on the pull request that adds it, for review; fixtures that wrap a uid, a pid and a port are listed;
  - it refuses `env!`, `option_env!`, `include_str!` and `include_bytes!` in a `LiteralText` impl, with a failing fixture of each;
- the agent-kit item, for lead-agent-kit: `eval-security` reads every site the log-gate scan lists and every new `impl LogSafe` outside `grdr-model` and generated code, and refuses one whose operand is an identifier rather than a count, length or duration the code owns; `eval-architecture` reads the `PeerAccess` of every `from_limits` call; each duty written into its agent file;
- the design item for the design/02, design/03, design/04, design/20 and design/21 sentences of section 14, for the chief architect;
- constraint comments on #1688 and #1757 carrying section 14's changes to RFC 0002 and RFC 0003, and on #30, #279, #282, #283, #284, #301, #334, #335, #383, #394, #428, #1238, #1536, #1537, #1539, #1542 and #1927 carrying theirs.

### 16. Amendments of RFC 0007 and RFC 0008
This RFC names RFC 0007 and RFC 0008 and amends each in the parts below, under RFC 0001's amendment route and #1850 AC-3. Everything else in them stands as decided.

**RFC 0007, sections 5 and 6: the failure share's window is a registered bound (P14).**
- `BudgetLimits` gains `pub share_attempts: u32`, the number of most recent attempts the failure share counts over. `[retry.<name>]` gains the required key `budget_share_attempts`, a count, mapped onto it, and `RetryField` gains `BudgetShareAttempts` (word `budget_share_attempts`).
- `RetryBounds` gains `pub share_attempts_ceiling: Count`, from a fourteenth required retry-bounds row, `retry-bounds.share-attempts-ceiling`, unit `count`, value 200, `min` 1, `max` 200, `scope = "fixed"`, `effect = "none"`, owned by design/22. Under RFC 0007's constraint 1d, a ceiling with no design/22 figure has its `max` at its seed value, and its `max` fits `u32`.
- `RetryBounds` gains `pub share_multiple_floor: Count`, from a fifteenth required row, `retry-bounds.share-multiple-floor`, unit `count`, value 2, `min` 2, `max` 2, `scope = "fixed"`, `effect = "none"`, owned by design/22: the least multiple of a table's `breaker_failures` its share window may be. 2 is #1966 R2's figure. A floor with no design/22 figure has `min` and `max` at its seed value (constraint 1d), so loosening it moves the range with the value, and RFC 0007's refusal of a floor row whose `min` is 0 applies to it.
- `RetryRule` gains, in `check`'s order after `BudgetFreeAboveCeiling`: `BudgetShareZero`, a value of 0, which would never count; `BudgetShareAboveCeiling`; and `BudgetShareBelowBreaker`, a value below `share_multiple_floor * breaker_failures`, with the product saturating. The third is what keeps the share from swinging between 0 and 1,000 permille on a window of a few attempts. `narrow` only lowers `breaker_failures`, so a table that passed it still passes after `narrow`.
- The generator also refuses rows where `share-multiple-floor * breaker-failures-ceiling` exceeds `share-attempts-ceiling`, because a table at the breaker ceiling could then write no window. At the seed rows that is 2 times 100 against 200, which fits; the rows' `note`s name the coupling, so a release that raises the breaker ceiling raises the share ceiling in the same change.
- `narrow` keeps `budget_share_attempts` as registered, beside `kind`, `peer`, `budget_window_ms` and `budget_slots`; any other value is `NotNarrower { field: BudgetShareAttempts }`.
- The window no longer depends on `breaker_failures` at run time; a table writes it, at least twice its `breaker_failures` at the seed rows.

**RFC 0008, section 8 changes 4 and 5: the form of the failure count and the shape of the breaker's states.** RFC 0008's transitions and turn timing are unchanged.
- Change 5: `Open { until, unhealthy_probes, turn_until }` and `HalfOpen { probe_until, probe, unhealthy_probes, turn_until }` become `Open(OpenBreaker)` and `HalfOpen(HalfOpenBreaker)`. `OpenBreaker` holds `until` and an `OpenPhase`, `HalfOpenBreaker` holds `probe_until` and a `HalfOpenPhase` (section 6). `Closed` and `Checking` keep their fields, inside `ClosedBreaker` and `CheckingBreaker`. Every state's fields are private behind accessors. The fields of RFC 0008 let values exist that no transition produces, such as a call probe in flight with no turn (eval-architecture F1, round 1); the two phase types leave none. Each row of change 5 maps to one method of section 6's table, and a turn begins at its first call probe's permit and ends one cap later, as RFC 0008 section 4 states.
- Change 4: `RetryBudget::record_failure(now)` and a failed share that is 0 "while fewer than a given count have failed" become `record_attempt(outcome)`, which records every attempt's outcome, and `failure_share()`, the failed share of the last `budget_share_attempts` attempts as a `Permille`, 0 until that many are recorded. That is constraint 1f's form, which RFC 0008's decision has this RFC follow, with the window a registered key (above).

Revision 2 also moved the end of a call-probe turn to the first call probe's end with no verdict. A dropped or late call probe could then push a turn past RFC 0008's bound (eval-adversarial round 2, major), so revision 3 drops that change.

## Surfaces changed
- `grdr-model` (layer 1, public): the items of sections 2 to 8, every one at the crate root. Class `experimental`.
- The error registry: the area `MODEL` and its eleven codes (section 9).
- As amendments (section 16): RFC 0007's `BudgetLimits`, `RetryField`, `RetryRule`, `RetryBounds`, the `[retry.<name>]` key `budget_share_attempts`, the rows `retry-bounds.share-attempts-ceiling` and `retry-bounds.share-multiple-floor` and `narrow`; RFC 0008's changes 4 and 5 in form, with its timing unchanged.
- As proposals: the `[[crate]]` row of `surfaces.toml`; the `grdr-model` edges in `Cargo.toml` and `Cargo.lock`; sentences of design/02 section 3.8, design/03 sections 3 and 10, design/04 sections 1, 2, 3 and 11, design/20 section 6 and design/21 sections 2 and 5 (section 14).
- No spine text, protobuf package, Cedar schema, third-party dependency or same-layer edge changes. The new edges go to layer 0.

## Alternatives
- **`Lane` with RFC 0002's four variants.** The daemon could not stamp `local` records, which design/04 section 2 gives their own sequence and chain. Rejected.
- **One flat `Lane` of five variants.** Every server type that takes a lane, and the device's upload path, could hold `local`, so each would need a refusal for a value that must never arrive. Rejected for `UploadedLane` inside `Lane`.
- **A flat `Lane` beside a four-variant `UploadedLane`.** Each word would be declared twice. Rejected for the nested form.
- **`Lane` generated from the `.proto` file, or `grdr-model` depending on `grdr-proto` for a `TryFrom` of the generated enum.** The first needs a `.proto` reader in the tests. The second puts the codec's runtime in the normal closure of every crate that links `grdr-model` and ties this crate's API to the generated type before SP-1 has chosen the codec. Rejected for the wire numbers and a parity test.
- **A parity test that rests on exhaustive matches alone.** A codec that generates an open enum would force a wildcard arm and drop the guarantee (eval-api 1, round 1). Rejected for the descriptor walk, with the matches where the codec allows them.
- **An infallible `fill` with a latched failure, or with a probing constructor.** Neither has bytes to give after a failure (section 3). Rejected.
- **`ENTROPY_UNAVAILABLE` with Connect `internal`.** `faults_peer` would count a failure of our own source against whichever peer the operation called (eval-api 4, round 1). Rejected for `failed_precondition`.
- **`GiveUpReason`.** A new name that would amend RFC 0008. Rejected.
- **A `#[cfg(test)]` or public second constructor of `RetryPolicy`.** The first does not reach integration tests and the second lets any crate build an unchecked policy. Rejected for `RetryLimits::new` in tests and `from_limits`.
- **`from_limits` taking a bare `RetryPeer`, as revision 1 had it.** The caller chose the value with no rule saying how, so one wrong argument skipped the remote floors (eval-api 2, round 1). Rejected for `PeerAccess` and its one classifier.
- **Loopback and Unix-domain sockets as local.** Either can be forwarded to another machine, so nothing in the process shows the peer is on this one. Rejected: every connection is remote.
- **The peer kind as a type parameter.** RFC 0007's tables are one type whatever their peer, so the type would only restate an argument. Rejected for an argument checked at construction.
- **The peer kind on RFC 0008's `Health` trait.** It would amend RFC 0008 and still need this check. Rejected.
- **Refusing only a remote call given a local table.** A one-way check leaves the other mismatch silent, and equality is simpler to state and test. Rejected.
- **The breaker's sub-lifecycle in three fields, as revision 1 had it.** Values such as a call probe in flight with no turn, or a health probe inside a turn, were representable and produced by no transition (eval-architecture F1, round 1). Rejected for a phase type per state and private fields.
- **One shared phase with the turn's end fixed when the first call probe ends with no verdict, as revision 2 had it.** A dropped first call probe fixed no end, and a late `Inconclusive` pushed the end out by its lateness, 10,060 ms past `p0` for a report 10,000 ms late; after 1,000 drops the class never returned to its health call (eval-adversarial round 2, major). Rejected.
- **One shared phase with the end fixed at `probe_until + cap` in the release and `Inconclusive` rows, as eval-adversarial's round 2 fix showed.** Every value stays reachable and drops and late reports no longer move the end, but the end is one call timeout later than RFC 0008's, so it would keep an amendment of the timing. Rejected for two phase types, which fix the end at the permit, RFC 0008's bound exactly (section 6).
- **The failure share over `2 * breaker_failures`, as revision 1 had it.** A threshold written as a literal, with no row and no setting (eval-architecture F2, round 1). Rejected for the registered key.
- **The share window with no lower rule, as revision 2 had it.** A table could write a window of one attempt, whose share is 0 or 1,000 permille after every attempt (eval-api m2, eval-adversarial m5, round 2). Rejected for `BudgetShareBelowBreaker`. **The rule's multiple, 2, written in `check`.** The multiple sets how noisy the share may be, a threshold like the others of the retry bounds (P14). Rejected for the `share-multiple-floor` row.
- **`RetryBudget::new(policy, registered)`, checked or not.** The second table was a second source of one value (eval-architecture F3, eval-api 3, round 1). Validating it would compare fields `narrow` may change, and a constructor only `for_class` reaches cannot be built across crates. Rejected for a window the policy carries.
- **`HolderId` as the capability in `grdr-model`.** Any crate could mint one, which RFC 0002's lease rules forbid. **`HolderId` minted by `grdr-ports`' own code.** ARCH-020 forbids it. Both rejected for an id in `grdr-model` and the capability `Holder` in `grdr-ports`.
- **Every minted id `LogSafe`, as #284 R2 had it.** A log would carry session, device and principal ids, per-person records outside the event stream's classes and retention, against design/21's logs row (P8). Rejected for two kinds.
- **Bare integers `LogSafe`, as revision 1 had it.** A raw uid or pid would reach a log with no impl at all (eval-security m2, round 1). Rejected for named units and counts.
- **Public `const fn new` constructors for names, as revision 1 had them.** They run at run time on a leaked string, so a host name could reach a log (eval-security m1, round 1). Rejected for `of::<L>()` over a constant. **An architecture rule refusing the constructors outside the macros.** A scan would hold what the type now holds. Rejected; the log-gate scan refuses only the macros that read build inputs in a `LiteralText` impl, which the type cannot see.
- **A grammar that refuses dotted names.** Wire words such as `file.read` and `action.agent.spawn` are dotted lower-case names, the same form as a host. Rejected for names fixed at build time, ARCH-021 and the log-gate scan.
- **Refusing every unit constructor in a log call.** A count, length or duration the code owns is the ordinary argument of a log line, so the refusal would fail most of them. Rejected for a scan that lists the sites and a review that refuses the ones whose operand is an identifier.
- **`OwnFile` for any file the process opens.** A path on a network mount, a UNC path or a remote pipe is opened as a file and served by another machine (eval-security n3, eval-api m4, eval-adversarial m4, round 2). Rejected for a file on a local disk, with the adapter classifying or refusing the rest.
- **`Display` on ids.** It invites building person-facing text by concatenation (UX6) in a crate that renders nothing. Rejected, as RFC 0007 rejects it for codes.
- **`Copy` ids with inline text.** `as_str` would need a fallible conversion, since `core::ascii::Char` is unstable on the pinned toolchain. Rejected for ids that hold their text.
- **`log_enum!` with its own list of words.** A second home for the words `as_str` returns. Rejected for `wire_enum!`.
- **`LogValue::Digest` now.** No type yields it, and a public variant of raw bytes would let any impl log a bare hash. Rejected until the keyed digest exists.
- **Public modules, such as `grdr_model::log::LogSafe`, beside or instead of root paths.** RFC 0002, 0003 and 0008 name root paths, and two paths per item are two ways to name it. Rejected for one root path.
- **Bare `u32` and `u64` for the epoch and sequence number.** A proto3 zero is an absent field, and a bare integer would accept it as a position. Rejected for non-zero types.
- **The failure share over the budget's time window, as RFC 0008 has it.** Under a steady failure rate it flickers (eval-adversarial m1, RFC 0008's constraint 1f). Rejected for #1966 R2's form.
- **`Verdict` or `Health` for the breaker's check result.** The first is the spine's word for a decision, and the second is RFC 0008's trait. Rejected for `CheckOutcome`.
- **`Level` at the crate root.** It does not say which level. Rejected for `LogLevel`.

## Drawbacks
- Every function that draws can fail, so minting, `Engine::step`, the daemon's decision ids and `Setup::holder` each carry a failure that, with AWS-LC, the programs never see returned.
- Readers meet two lane types, and the daemon writes `Lane::Uploaded(UploadedLane::Decision)` where a flat enum would be shorter.
- Each id allocates its text once.
- Only two kinds of id can be logged, so a diagnostic points at a record by `(epoch, lane, seq)`.
- Every number a log carries needs its unit or count type. A raw identifier wrapped in a unit type at a call site, `Count::new(uid)` or `Duration::from_secs(pid)`, still compiles and reaches a log; the log-gate scan lists every such site and review refuses it, so the build alone does not.
- A name built by a direct call of `of` with a bad literal passes `cargo check` and fails the build; through the macros both refuse it.
- A name is fixed at build time, not necessarily written in the source: a hand-written `LiteralText` impl can take a build input, which the log-gate scan refuses for the macros that read one.
- The lane numbers are written in Rust and in the `.proto` file, held equal by a test rather than generated.
- `WireName`'s grammar admits any dotted lower-case name, so a host literal is held by ARCH-021, the log-gate scan and review, not by the grammar.
- The breaker is four state structs, two phase enums and seven methods, and the executor keeps the state each check or probe started from.
- The peer check catches an inconsistent pair, not an adapter wrong about its back end in a way that makes both agree; the adapter's own test and review hold that.
- Every retry table writes one more key, `budget_share_attempts`, and the retry bounds have two more rows.
- #282 grows past size M and needs splitting.
- The surface lands across four items and two more filed on acceptance, so a reader follows section 1's table.

## Unresolved questions
None for this RFC's own decision. Open elsewhere:
1. **The failure share (#1966).** This RFC states the share over recent attempts with a registered window, as RFC 0008's constraint 1f asks, and fixes the window's key (section 16). #1966 decides the rest of its R2 and its other parts; if it decides another form of the share, it amends this RFC too and names both.
2. **Server-authored records.** design/04 section 2 puts an emitter id (`srv_`) in the envelope's `device_id`, which `DeviceId` refuses. The item that adds the `srv_` row decides the emitter type, and RFC 0002's `RowPosition` follows by amendment. No slice-0 path writes a server-authored record to the lake.
3. **The keyed digest.** Design/04 work item 04-16 adds its type and `LogValue::Digest` by amendment.
4. **Twins of `InstallProfile` and `Tamper`.** The item that declares either in protobuf or Cedar adds its parity test (section 8).

## Review
How review binds the decision (RFC 0001, "Review binds the decision"; ADR-0036):
- RFC 0009 decides no pinned path, so its decision adds no decision line and no file under `rfcs/evidence/`, and `rfcs/pins.toml` does not change.
- The review set: the nine persona council seats, once, on #1850; `eval-architecture`, the `[kinds] rfc` row of `.claude/risk-tiers.toml`; `eval-api`, the `public_api_change` row, because this RFC states a public crate's API; `eval-security`, because the RFC fixes what a failed random source yields and what may reach a log; and, from revision 2, `eval-adversarial`, because the RFC amends RFC 0008, whose lanes table in ADR-0040 calls for it, and RFC 0007's retry rules. At least one evaluator runs on the other model from the one in the metadata block.
- Each verdict and each seat comment gives the three role lines of RFC 0001 (#1798), as full 40-character ids:
  - `RFC file:` the blob of this file it read (`git rev-parse <commit>:rfcs/0009-grdr-model-slice-0-surface.md`), with the commit;
  - `Proposed text: none`, because no pinned path changes;
  - `Base:` the spine pin in force in `rfcs/pins.toml`, `a80859235e7a2a4444648d6fa8d389d78dde6be9`, SHA-256 `8f6ea876777c0121ecec068c0bc4cef45932be45c1c2aff4140712db1e06628d`.
- RFC 0009 is decided only while RFC 0007 reads `Accepted` on `main` (#1850 R5 and AC-9); it does at `91e1cec`. RFC 0008 is accepted too, and this RFC meets its section 8 list with section 16's amendment.
- The decision rests on an `eval-architecture` pass on the blob it decides, with no fail by an evaluator of the set on that blob, and the chief architect checks that the seats commented on that blob. The file the decision commits differs from that blob only in `State:`, `Decision record:`, link lines under this section and the `Decision` section. It reaches `main` in `Review` before the commit that decides it (RFC 0001, "RFC states").

The bench behind sections 2 to 8 is a set of sketches of the signatures, compiled with rustc 1.99.1, the pinned toolchain, outside the repository: the sketch, clippy over it with the workspace deny list, the sketch for `wasm32-unknown-unknown`, the uses that RFC 0002, RFC 0003 and RFC 0008 make of these types, a check of every code and the loggable kinds against sections 4 and 9, the breaker's transition table run against a reference over every state it reaches and every event, eval-adversarial's drop and late-report sequences against RFC 0008's turn bound, the share window's rules at their boundaries with the budget's share, a changed row turning both the table and the bound red, the lane parity test and its failure against a widened generated enum (E0004), and 69 compile-fail cases, each failing with the error section 12 names, plus a direct `of` that `cargo check` passes and a build refuses. The revision comments on #1850 give its commands and exit codes.

Round 1, on blob `18b99761788f831f30cdc01c2b1b092f2353db6a`:
- eval-architecture (Sonnet), fail: https://github.com/416rehman/Guardrails/issues/1850#issuecomment-7084311210
- eval-api (Sonnet), pass: https://github.com/416rehman/Guardrails/issues/1850#issuecomment-7084306344
- eval-security (Opus), pass: https://github.com/416rehman/Guardrails/issues/1850#issuecomment-7084459132

Round 2, on blob `3af43ca6f499127f1155e1fc59d9ae2885f17a0a`:
- eval-architecture (Sonnet), pass: https://github.com/416rehman/Guardrails/issues/1850#issuecomment-7085028882
- eval-api (Sonnet), pass: https://github.com/416rehman/Guardrails/issues/1850#issuecomment-7085055343
- eval-security (Sonnet), pass: https://github.com/416rehman/Guardrails/issues/1850#issuecomment-7085162645
- eval-adversarial (Opus), fail: https://github.com/416rehman/Guardrails/issues/1850#issuecomment-7085144267

Verdicts and seat comments on revision 3 are linked below, one per line.

## Decision
Pending.
