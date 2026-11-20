RFC: 0002
Title: The slice-0 public surface of grdr-ports and grdr-ports-testkit
Author: chief-architect
Harness: Claude Code
Model: claude-opus-5-5
State: Review
Design issue: #1688
Spine: D-05, D-33, D-34, D-35, D-51, D-57, D-61, D-69, P1, P5, P6, P8, P9, P10, P14, P15, P17 (no spine text changes)
Surfaces: public crates `grdr-ports` and `grdr-ports-testkit`, the `grdr-model` type `Monotonic`, and the storage format of lake and blob objects (key layout and `grdr-aad-v1`)
Decision record: none yet

To comment, write on issue #1688 of this repository; you need no account on any service other than the code host. A security fix under embargo (D-62) may change a public surface without an RFC; open a retroactive RFC when the fix is disclosed.

This is revision 3. It answers the round 1 and round 2 reviews; the comments headed "RFC 0002 round 2: dispositions" and "RFC 0002 round 3: dispositions" on #1688 list every finding and where it went. The text below is normative on its own. Where it differs from the nine items it adopts, this RFC wins, and section 15 tells each lead what to write back.

## Summary
Slice 0 adds the first public types and traits to `grdr-ports` and `grdr-ports-testkit`: the `Clock` and `Entropy` ports, the retry executor, identifiers, the tenant contexts and object paths, the Blobs, Jobs (leases), Bus, Relational and Events ports, and the conformance kit with a reference adapter and a suite per port. This RFC states every signature and its semantics in full, sets eleven rules every port follows, assigns the error codes, says how an adapter from outside the workspace is tested, verified and selected, and enters both crates as `experimental`. It changes no spine text and proposes amendments to design/03, design/20 and design/21 (section 14).

## Motivation
`grdr-ports` is the seam P6 and P14 rest on. The release-gating adapters of each profile and every contrib or embedder adapter meet the product only through these traits, and they are admitted only by passing the test kit (design/03 extension points; design/20 extension point 1). Every server target in slice 0 calls them, and `grdr-daemon` links the crate for `Clock`, `Entropy` and `retry::run`. A public crate changes only by RFC (D-61, design/30 R7), and `experimental` sets the break rules, not the route (ruling on #1535).

The nine items (#281, #283, #297, #298, #299, #300, #1535, #312, #313) were specified one at a time. Read together they disagree in places a later adapter would turn into a defect: two fence rules, an unfenced lake write path, a retry future that is not `Send`, one error variant with two classes, a `Set` context that reaches a per-organisation lake read, methods with no semantics, and no rule for how Events rows cross the port. Review found more: the archive segment and the detect checkpoint had no slot on the write path; fence checks that READ COMMITTED and SERIALIZABLE do not protect; a relational `guard` method that left a transaction usable after it failed; a lease token shared by every task of one process; no reference relational adapter; no read witness for provider hunts; a minting boundary that a contrib crate could step around; no resume position and no way to report a missed tail beside a hit limit; no local disk faults; and no character set for the identifiers inside paths and additional data. If nothing changes, nine implementers build against these signatures and the first adapter items (#1546, #1547, #1554) inherit the conflicts.

## Design

### 1. Rules for every port
Terms used below:
- A **tenant witness** is a value only a tenant context can produce (Rule 3).
- A **deployment-scoped** method works on a resource that belongs to no organisation: leases, bus partitions and offsets, bucket maps, migrations, a partition's flush. `architecture.toml` lists each one (section 14).
- A **fence** is a lease name and the fencing token one `Leases::acquire` call issued (section 7).
- **ARCH-nnn** is a rule of the architecture lint: registered in design/03 section 2, configured in `architecture.toml`, run by `cargo run --locked -p grdr-archlint -- check` (#1580, #1582).
- A **protected change** is a change to a gate file (`architecture.toml`, `surfaces.toml`, `.github/`), made only in an issue whose write set names it (AGENTS.md).
- **`rfc-required`** is the check of design/30 section 3: a pull request that changes a public surface names its RFC or amendment.

Rule 1. **Dependencies.** `grdr-ports` depends on `grdr-model` and `grdr-schema` and on no other crate, third-party crates included. The privileged daemon links it and layer 2 has no Cargo features (design/03 section 8), so whatever it links is in the daemon's closure. `grdr-ports-testkit` may also depend on the Arrow crates #1532 admits, at the same pins, for `MemEvents`. It is never in the normal-dependency closure of a layer 4 program under any feature set a release or distribution build enables. An adapter crate may expose a `testkit` feature for its own tests; no program and no `dist.toml` enables it.

Rule 2. **Async shape.** Every port trait has `Send + Sync` as supertraits. A method that reaches a back end is declared `fn name(&self, ...) -> impl Future<Output = Result<T, E>> + Send`, which an implementation may write as an `async fn`. A stream is a pull method of the same shape, not a `Stream` trait. No `async-trait`, no boxed futures and no `futures` crate in `grdr-ports`. The storage traits are therefore not dyn-compatible; section 12 says how a build selects an adapter. `Entropy` is synchronous and stays dyn-compatible, because `Engine::step` takes `&mut dyn Entropy` (design/03 section 3). There is no second, non-`Send` shape: the storage ports serve server targets only, and a WebAssembly host passes `now` and `Entropy` to the engine as values (layers 0 and 1 take them as arguments), so it implements none of these traits.

Rule 3. **Tenant witnesses.** A tenant witness is `&SingleCtx`, `&TenantCtx`, `&SetCtx`, an `OrgRead`, a `TenantPath`, a `ReadPath`, a `ListPrefix`, an Events plan, a relational transaction or a bus `OrgBatch`. Every port method that takes tenant data in takes a witness derived from a `SingleCtx`. Every method that returns tenant data to module code takes a witness or returns the data inside one. A read takes the widest context its store can bind: `&TenantCtx` for the relational port, whose row-level security binds a `Set` through `delegation_snapshot`, and an `OrgRead` for Events and Blobs, whose keys are per organisation. An `OrgRead` comes from a `SingleCtx` or from a `MemberCtx`, the read-only context for one organisation of a delegation snapshot (section 2), so a provider's cross-organisation lake read is one plan per member and never holds a write witness. A deployment-scoped method takes no context. Two of them handle tenant data, `Subscription::fetch` and `Events::flush`; neither hands it to module code outside a witness (section 14 gives the reading of D-35 this rests on).

Rule 4. **No organisation in inputs.** No input type of a port method has an organisation field. The organisation comes from the context and the adapter writes it: the bus `org` header (section 8), the lake's `organisation_id` column (section 10), the `org=` segment of every path (section 2). The one exemption is `MemberCursor`, a page cursor over a snapshot's organisations, which names no organisation the caller acts for; `architecture.toml` lists it.

Rule 5. **Fences.** A fence is current while its token equals the newest token issued for its lease. Tokens only grow, and every `acquire` that returns `Held` issues a new one (section 7), so a fence names one acquisition, not one holder or one process. A fenced commit takes one of two forms, and every fenced commit on the surface names its form:
- *Lease-checked*, where the commit runs in the store that holds the lease table: the commit of a transaction opened with `Relational::write_fenced`, each migration's transaction inside `Migrator::apply`, and the catalogue transaction of `Events::flush`. Inside that transaction the adapter takes a lock on the lease row that `acquire` and `renew` conflict with, holds it until the commit ends, and commits only if the fence is current. The admitted locks are `SELECT ... FOR SHARE` on the lease row in PostgreSQL, the single writer (`BEGIN IMMEDIATE`) in SQLite, and the shared hold in `MemLeases`. An isolation level is not a substitute for the lock: under SERIALIZABLE, a read of the lease row followed by another holder's `acquire` is one read-write dependency, which PostgreSQL does not abort, so the stale commit would land. A fence with a made-up larger token fails this check.
- *Row-stamped*, for the bus, whose tables may live in another database (design/20 section 7, `bus.database`). `Bus::subscribe` stamps each claimed partition's consumer row with the claim's fence in one compare-and-set that never lowers the stored fence, and returns the committed position from the same statement. `Bus::commit` succeeds only while the row holds the caller's fence, in one conditional row update (section 8). This form trusts that a claim's fence came from `Leases::acquire`. A made-up larger token would stamp the row and turn every real holder away, which is a denial of service by in-process code, but it cannot make a stale commit land. Only server targets build claims; tenants never reach the bus (design/21 section 2).

`Leases::check` is a point-in-time read. It protects no commit by itself; it lets a holder stop early. A superseded fence has one code wherever it is found (section 11).

Rule 6. **Nothing without a reference and a case.** Every method and every enum variant on the surface has a reference implementation in the test kit and at least one named conformance case. Where the variants of a data enum behave the same at the port, the port section says so and one case covers them. A method or query node whose semantics are not yet specified is not declared; it enters with its item by amendment (section 12). Each port section names the caller of each method and says when that caller is not in slice 0.

Rule 7. **Bounds are parameters.** Page and fetch limits, lease terms, query limits, stream byte bounds, flush thresholds, deadlines, cleanup grace, identifier lengths and bucket maps are values the caller passes or the adapter is built with, read from `limits.toml` (#279). No port type or reference adapter holds a tunable bound (ARCH-019). The storage format has two fixed ceilings, which are part of the format and not tunables: an identifier is at most 255 bytes, and each additional-data field at most 65,535 bytes (section 2).

Rule 8. **Errors.** Each port module has one error enum, and `Coded` (#280) binds each variant to one registered code (section 11). Faults of the back end itself are one shared type, `StoreFault`, which every port error carries as `Store(StoreFault)`, so a full disk or a serialisation failure has one code whichever port met it. Callers act on the code's class, never on the variant, so error enums are `#[non_exhaustive]`. Errors carry structural values only (keys, offsets, ids, byte indexes) and implement `LogSafe` (#284); an error about a rejected identifier carries the fault and the byte index, never the rejected text. No port type holds a person-facing string. Each code's sentence is the `code.<code>.message` and `code.<code>.fix` language tokens of design/03 section 10, and a key or name inside it reaches the reader as a typed argument rendered in a left-to-right isolate (UX6), never by `Display` concatenation. `RetryError<E>` has no code: its caller maps it to the code of the subsystem that failed. Test kit types carry no code. Both are listed in the ARCH-017 exemption list of `architecture.toml` (section 14), so the lint reads data and special-cases no name.

Rule 9. **Exhaustive data enums.** `TenantCtx`, `Scope`, `OrgRead`, `SetPurpose`, `StorageClass`, `Partition`, `LeaseState`, `Stream`, `LakeTable`, `QueryIr`, `Direction`, `Comparison`, `Literal`, `Step`, `StepKind`, `ExpandKind`, `Completion`, `LimitReason`, `Coverage`, `StopPoint` and `Fault` are exhaustive, so a new variant fails every adapter's build until it handles it. Adding one is an amendment with its suite cases.

Rule 10. **Identifiers are ASCII.** `ObjectName`, `LeaseName`, `ConsumerGroup`, `ViewName`, `ColumnName` and `CheckpointRef` hold 1 to `max` bytes, each a lower-case ASCII letter, an ASCII digit, `-`, `_` or `.`, and are neither `.` nor `..`. `max` comes from `limits.toml` and may not exceed 255. Anything else fails `parse` with `IdentError` (code `GRDR-TENANT-0001`): no normalisation, no case folding, no width folding. Ids from grdr-model (`OrgId`, `DelegationSnapshotId`, `DeviceId`, `SessionId`) render as ASCII by their own format (#1710). A name a person chooses (an organisation, a device, a group named in Arabic or Japanese) lives in a relational column and never in a path, a key or additional data. This keeps the bytes the additional data authenticates identical across adapters, file systems and locales.

Rule 11. **Order is numeric or byte-wise.** Every order on the surface compares integers and times numerically and strings, identifiers and object keys by their bytes, never by a locale's collation. That covers `Blobs::list`, `Relational::snapshot_members`, the Events orders and positions, and `Lt`, `Le`, `Gt` and `Ge` on text literals. A PostgreSQL adapter sets `COLLATE "C"` on these comparisons; its fixture runs the ordering cases on a database whose default collation is `ja-JP` (section 5).

Data classes (P8): every type on the surface is `structural`, except payload bytes (blob objects, bus payloads, `ArchiveBatch.bytes`, `ArrowIpc`), which carry the classes of what they hold and are never logged, and positions and predicate literals, which carry their columns' classes. The port records no per-object data class. `StorageClass`, with the lane for archive objects, is enough for slice 0: retention is by class and lane, erasure of content is by destroying the root session's content key, and reduction rewrites by lane (design/04 section 10), so none needs a class inside an object. A per-object class that must be authenticated would be a new additional-data tag (section 2), which is the costly kind of change and needs its own RFC.

Assurance effect (P1): none. No action class changes `visibility`, `control`, `on_failure` or `tamper`.

### 2. Identifiers, tenancy and object paths (#312, #313)
The `tenant` module is trust core.

```rust
// grdr_ports::ident
pub struct IdentMax { /* private: 1..=255 */ }
impl IdentMax { pub fn new(bytes: u16) -> Option<IdentMax>; pub fn get(&self) -> u16; }
pub struct ObjectName { /* private */ }
pub struct LeaseName { /* private */ }
pub struct ConsumerGroup { /* private */ }
pub struct ViewName { /* private */ }
pub struct ColumnName { /* private */ }
pub struct CheckpointRef { /* private */ }
// Each of the six identifier types is Clone, Eq, Ord and Hash and has these two methods:
impl ObjectName {
    pub fn parse(text: &str, max: IdentMax) -> Result<ObjectName, IdentError>;
    pub fn as_str(&self) -> &str;
}
pub struct IdentError { pub kind: IdentKind, pub fault: NameFault }
pub enum IdentKind { Object, Lease, ConsumerGroup, View, Column, Checkpoint }
pub enum NameFault { Empty, TooLong { len: usize, max: u16 }, Byte { index: usize }, DotSegment }

// grdr_ports::tenant::ctx
pub use grdr_model::{DelegationSnapshotId, OrgId};
pub enum TenantCtx { Single(SingleCtx), Set(SetCtx) }
pub struct SingleCtx { /* private: OrgId */ }
pub struct SetCtx { /* private: DelegationSnapshotId, SetPurpose */ }
pub struct MemberCtx { /* private: OrgId, DelegationSnapshotId */ }
pub enum SetPurpose { Workbench }
pub enum Scope<'a> { Single(&'a OrgId), Set(&'a DelegationSnapshotId) }
pub enum OrgRead<'a> { Single(&'a SingleCtx), Member(&'a MemberCtx) }

impl SingleCtx { pub fn org(&self) -> &OrgId; }
impl SetCtx { pub fn snapshot(&self) -> &DelegationSnapshotId; pub fn purpose(&self) -> SetPurpose; }
impl MemberCtx { pub fn org(&self) -> &OrgId; pub fn snapshot(&self) -> &DelegationSnapshotId; }
impl TenantCtx { pub fn scope(&self) -> Scope<'_>; }
impl<'a> OrgRead<'a> { pub fn org(&self) -> &'a OrgId; }
impl From<SingleCtx> for TenantCtx;
impl<'a> From<&'a SingleCtx> for OrgRead<'a>;
impl<'a> From<&'a MemberCtx> for OrgRead<'a>;

pub struct TenantMinter;
impl TenantMinter {
    pub fn single_from_token(token: &VerifiedAudience) -> SingleCtx;
    pub fn set_from_exchange(token: &VerifiedWorkbenchToken) -> SetCtx;
    pub fn single_from_record(org: &RecordedOrg) -> SingleCtx;
}
pub struct VerifiedAudience { /* private: OrgId */ }
pub struct VerifiedWorkbenchToken { /* private: DelegationSnapshotId, SetPurpose */ }
pub struct RecordedOrg { /* private: OrgId; built only inside grdr-ports */ }
impl VerifiedAudience { #[doc(hidden)] pub fn from_verified_entry_point(org: OrgId) -> VerifiedAudience; }
impl VerifiedWorkbenchToken { #[doc(hidden)] pub fn from_verified_entry_point(snapshot: DelegationSnapshotId, purpose: SetPurpose) -> VerifiedWorkbenchToken; }
impl RecordedOrg { pub fn org(&self) -> &OrgId; }

pub struct MemberCursor { /* private: OrgId */ }
impl MemberCursor { pub fn after(org: OrgId) -> MemberCursor; pub fn org(&self) -> &OrgId; }
pub struct SnapshotPage { pub orgs: Vec<OrgId>, pub next: Option<MemberCursor> }
pub struct MemberPage { pub members: Vec<MemberCtx>, pub next: Option<MemberCursor> }
pub async fn members<R: Relational>(rel: &R, set: &SetCtx, after: Option<&MemberCursor>, limit: PageLimit) -> Result<MemberPage, RelError>;

pub struct TenantKey<K> { /* private: OrgId, K */ }
impl<K> TenantKey<K> { pub fn new(ctx: OrgRead<'_>, key: K) -> TenantKey<K>; }

// grdr_ports::tenant::path
pub struct TenantPath { /* private: ReadPath */ }
pub struct ReadPath { /* private: ObjectKey and its parts */ }
pub struct ListPrefix { /* private */ }
pub struct ObjectKey { /* private: ASCII */ }
pub enum StorageClass { Decision, Activity, Content, Observable, AggDaily, Archive { lane: Lane } }
pub enum Partition { Day(Date), Month(YearMonth) }
pub enum PartitionKind { Day, Month }
pub struct Date { /* private */ }
pub struct YearMonth { /* private */ }
impl TenantPath {
    pub fn new(ctx: &SingleCtx, class: StorageClass, partition: Partition, name: ObjectName) -> Result<TenantPath, PathError>;
    pub fn read(&self) -> &ReadPath;
}
impl ReadPath {
    pub fn new(ctx: OrgRead<'_>, class: StorageClass, partition: Partition, name: ObjectName) -> Result<ReadPath, PathError>;
    pub fn key(&self) -> &ObjectKey;
}
impl ListPrefix {
    pub fn partition(ctx: OrgRead<'_>, class: StorageClass, partition: Partition) -> Result<ListPrefix, PathError>;
    pub fn as_str(&self) -> &str;
}
impl ObjectKey {
    pub fn under(prefix: &ListPrefix, key: &str) -> Option<ObjectKey>;
    pub fn as_str(&self) -> &str;
}
impl Date { pub fn parse(text: &str) -> Result<Date, PathError>; pub fn from_timestamp(at: Timestamp) -> Date; pub fn as_str(&self) -> &str; }
impl YearMonth { pub fn parse(text: &str) -> Result<YearMonth, PathError>; pub fn of(date: Date) -> YearMonth; pub fn as_str(&self) -> &str; }
#[non_exhaustive]
pub enum PathError {
    PartitionForClass { class: StorageClass, partition: PartitionKind },
    Date(DateFault),
    KeyId(KeyIdFault),
}
pub enum DateFault { Format { index: usize }, Range }
pub enum KeyIdFault { Empty, TooLong { len: usize }, Byte { index: usize } }

// grdr_ports::tenant::aad
pub struct KeyId { /* private: printable ASCII */ }
pub struct Aad { /* private */ }
impl KeyId { pub fn parse(text: &str) -> Result<KeyId, PathError>; pub fn as_str(&self) -> &str; }
impl Aad { pub fn for_object(path: &ReadPath, key_id: &KeyId) -> Aad; pub fn as_bytes(&self) -> &[u8]; }
```

`OrgId`, `DelegationSnapshotId`, `Timestamp` and `Lane` are grdr-model types (#18, settled by the RFC of #1710). The two ids are `Clone`, `Eq`, `Ord` and `Hash`, parse from and render to ASCII (`as_str`), and carry no authority: holding an id builds no context. `Lane` is `Decision`, `Spine`, `Bulk` or `Evidence`; there is no second lane enum (P17). `PageLimit` is `grdr_ports::storage::PageLimit` (section 6).

Contexts:
- No code outside `grdr-ports` constructs `SingleCtx`, `SetCtx`, `MemberCtx` or `RecordedOrg`. Fields are private, and none implements `Default`, `Deserialize` or a `From` from a string or an id. The three `TenantMinter` methods, `tenant::members` and `bus::fetch_batches` (section 8) are the only places that build them.
- There is no conversion from `SetCtx`, `MemberCtx` or `TenantCtx` to `SingleCtx`. A write takes `&SingleCtx` or a value built from one, so a `Set` or member context calling a write does not compile.
- `TenantCtx::scope` returns the organisation or the snapshot id; adapters bind storage with its `as_str` form (`SET LOCAL grdr.orgs` or `grdr.orgset`, row-level security; object prefixes). A `SetCtx` exposes no organisation list. Its members come only from `tenant::members`, which calls `Relational::snapshot_members` (section 9) for the organisation ids the snapshot holds, read under the set's binding, and mints one `MemberCtx` per id with the set's snapshot id. Adapters return plain ids and never mint.
- `TenantKey<K>` compares and hashes on `(OrgId, K)`, so a cache keyed by it cannot return one organisation's entry for another.
- The contexts are `Send + Sync + Clone + Debug + LogSafe`. They print and log only the organisation id or the snapshot id (data class `structural`) and implement neither `Serialize` nor `Deserialize`, so a context cannot be stored and replayed.
- The contexts will also carry the acting principal, the delegation and the purpose from the token (D-35), behind private fields filled from the verified input types. Adding them changes no port signature. The accessors the audit and usage-ledger adapters read arrive with the audit item by amendment (section 12).

Minting boundary. Contexts are minted in two kinds of place.
- **Entry points.** The authentication middleware of `api` and `ingest` builds `VerifiedAudience` and `VerifiedWorkbenchToken` with their `#[doc(hidden)]` constructors, after it has verified the token, and calls `single_from_token` and `set_from_exchange`. `#[doc(hidden)]` is not access control, so ARCH-027 `context-mint` fails a call to either constructor outside the middleware modules `architecture.toml` lists and `grdr-ports-testkit`. It runs over the workspace and, in the distribution build (#1593), over the source of every crate in the build's resolved dependency closure, so a contrib crate is checked too.
- **Inside `grdr-ports`.** `RecordedOrg` and `MemberCtx` have no public constructor. `grdr-ports` builds them from ids an adapter returned: the `org` header of stored bus messages (`bus::fetch_batches`), a snapshot's member ids (`tenant::members`), and, with J-1, a claimed job's organisation by the same pattern. No adapter is a minting site, so adding an adapter needs no change to a gate file.

Holding an `OrgBatch` (or, with J-1, a claimed job) is the authority to act for its organisation, so `single_from_record` needs no call-site rule. What remains is code that implements a storage port trait with invented ids and hands it to these functions. The distribution build's closure scan fails an implementation of a storage port trait in any crate that `dist.toml` does not list as an adapter of that port, and the workspace scan fails one outside the adapter crates.

The middleware and the job runner check the organisation's lifecycle state (design/21) before they mint a `SingleCtx`, and refuse a suspended or crypto-shredded organisation, so a stale job or token cannot write after detach. Each carries that case (section 13). Work that writes into several organisations, such as a pack rollout ring by ring (D-11), enqueues one job per organisation and mints its `SingleCtx` through `single_from_record`; no cross-organisation write context exists. When `erase` arrives (section 12) it takes `&SingleCtx` only.

Who looked (P8, D-35). Reads through the port record nothing. The read audit entry is written above the port by `api` and `query`. A read under a `MemberCtx` records the snapshot id the context carries, which is the cross-organisation case a person most needs to see.

Paths:
- `TenantPath::new` is the only way to a writable path, and the organisation segment comes from `ctx`. `ReadPath::new` builds the same key from an `OrgRead`; `TenantPath::read` returns the `ReadPath` of a writable path.
- `AggDaily` takes only `Partition::Month`; every other class takes only `Partition::Day`; a mismatch is `PathError::PartitionForClass`.
- The rendered key is `org=<id>/class=<class>/day=<yyyy-mm-dd>/<name>`, `org=<id>/class=agg_daily/month=<yyyy-mm>/<name>`, or `org=<id>/class=archive/lane=<lane>/day=<yyyy-mm-dd>/<name>`. Class names render as `decision`, `activity`, `content`, `observable`, `agg_daily` and `archive`; lanes as `decision`, `spine`, `bulk` and `evidence`. The path vectors of #313 pin one key per class and lane, which is the case Rule 6 needs for each `StorageClass` variant.
- `ListPrefix::partition` renders the partition directory with its trailing `/`, so retention, cleanup and restore list one partition, never a whole organisation. A `Set` context cannot reach a prefix. `ObjectKey::under` turns a key an adapter listed into an `ObjectKey`, and returns `None` for a key outside the prefix or one that breaks Rule 10, so a listing cannot return a key from another organisation's prefix.
- `Date::parse` accepts exactly `YYYY-MM-DD` and `YearMonth::parse` exactly `YYYY-MM`, in ASCII digits `0` to `9` on the proleptic Gregorian calendar; Arabic-Indic or full-width digits fail with `DateFault::Format`. `Date::from_timestamp` takes the UTC date. A partition date is UTC, and retention arithmetic runs on UTC dates. It is never shown to a person as the event's local date; a view converts the event's time to the viewer's zone (D-69).
- `KeyId::parse` accepts 1 to 65,535 bytes of printable ASCII (`0x21` to `0x7E`), so a KMS key id or ARN fits and `for_object` is total.

Additional data. `Aad::for_object` produces `org_id ‖ class ‖ partition ‖ key_id` of design/21 section 2: the 11 ASCII bytes `grdr-aad-v1`, one `0x00` byte, then the organisation id, the class field, the partition value and the key id, each as a 2-byte big-endian length followed by its bytes. The class field is the class name, and for `Archive { lane }` it is `archive.<lane>`, for example `archive.decision`, so a segment does not authenticate under another lane's path. Lane decides retention (13 months for `decision`, 184 days for the others; values from configuration, read by R-3) and reduction. The partition value is `yyyy-mm-dd`, or `yyyy-mm` for `AggDaily`. Test vectors shared with `grdr-tenancy-ref` pin the bytes (#311, #313).

The object key layout, the identifier rule of Rule 10 and this encoding are a storage format. Changing any of them needs an RFC, a new tag (`grdr-aad-v2`), readers that accept the old tag for the longest retention (13 months), and a rewrite job that ships in the same release. These strings are format constants of the code namespace `grdr`, not brand strings, and do not change under a rebrand.

Callers in slice 0: the authentication middleware and the job runner mint; `store` (#1547) writes paths; the lake read path (#1554) builds read paths and prefixes. The provider workbench read path (D-35), which is not in slice 0, calls `tenant::members`; the minting boundary is declared whole now so the trust-core review sees every minting site once.

### 3. Clock and Entropy (#281)
```rust
// grdr_model
pub struct Monotonic { /* private: nanoseconds */ }
impl Monotonic {
    pub fn checked_add(self, by: Duration) -> Option<Monotonic>;
    pub fn saturating_duration_since(self, earlier: Monotonic) -> Duration;
}

// grdr_ports::clock
pub trait Clock: Send + Sync {
    fn now(&self) -> Timestamp;
    fn monotonic(&self) -> Monotonic;
    fn sleep_until(&self, deadline: Monotonic) -> impl Future<Output = ()> + Send;
}
// grdr_ports::entropy
pub use grdr_model::Entropy;

// grdr_ports_testkit::clock
pub struct ManualClock { /* private; Sync */ }
impl ManualClock {
    pub fn new(now: Timestamp, monotonic: Monotonic) -> ManualClock;
    pub fn advance(&self, by: Duration) -> Result<(), ClockError>;
    pub fn jump_wall(&self, by_ms: i64) -> Result<(), ClockError>;
    pub fn sleeps(&self) -> Vec<Monotonic>;
}
pub enum ClockError { Overflow }
pub struct SeededEntropy { /* private */ }
impl SeededEntropy { pub fn from_seed(seed: u64) -> SeededEntropy; }
pub fn block_on<F: Future>(future: F, max_polls: u32) -> Result<F::Output, Stalled>;
pub struct Stalled { pub polls: u32 }
```

- `Monotonic` orders instants within one process; its arithmetic never wraps or panics.
- `now` is wall time and may jump. `monotonic` never decreases within a process and counts time the host spent suspended, so a lease holder that wakes after a sleep sees its deadlines as passed and renews or reacquires at once. The OS adapters in the programs meet this (`CLOCK_BOOTTIME` on Linux, `mach_continuous_time` on macOS, `QueryInterruptTime` on Windows); nothing in `grdr-ports` reads a system clock or the operating system's randomness.
- `sleep_until` completes once `monotonic()` is at or past `deadline`; a past deadline completes on the first poll.
- `ManualClock::advance` moves both clocks; `jump_wall` moves only `now`. `sleep_until(d)` completes on its first poll and, if `d` is later than the current monotonic value, advances both clocks to `d`. A sleep records its deadline when first polled; `sleeps` returns the recorded deadlines in order. Overflow returns `ClockError::Overflow`.
- `SeededEntropy` is SplitMix64, so one seed gives the same bytes on every target; its output for seed 0 equals the reference `splitmix64.c`.
- `block_on` drives a future with a no-op waker and returns `Stalled` once `max_polls` polls have returned `Pending`.

Suite `clock::suite()`, for any `A: Clock`: monotonic never decreases over 1,000 reads; after `sleep_until(d)` completes, `monotonic() >= d`; a past deadline completes on the first poll. Callers: every target, the daemon, `retry::run`.

### 4. Retry executor (#283)
```rust
// grdr_ports::retry
pub async fn run<T, E, C, R, F, Fut>(
    policy: &RetryPolicy, state: &mut RetryState, clock: &C, entropy: &mut R, op: F,
) -> Result<T, RetryError<E>>
where
    C: Clock, R: Entropy + Send + ?Sized,
    F: FnMut() -> Fut + Send, Fut: Future<Output = Attempt<T, E>> + Send,
    T: Send, E: Send;

pub struct RetryState { /* private: RetryBudget, Breaker */ }
impl RetryState { pub fn new(policy: &RetryPolicy) -> RetryState; }
pub enum Attempt<T, E> { Done(T), Retry { error: E, hint: Option<Duration> }, Fail(E) }
pub enum RetryError<E> {
    BreakerOpen { until: Monotonic, last: Option<E> },
    BudgetExhausted { attempts: u32, last: Option<E> },
    Timeout { attempts: u32, last: Option<E> },
    GaveUp { reason: GiveUp, attempts: u32, last: Option<E> },
    Failed(E),
}
```

`RetryPolicy`, `RetryBudget`, `Breaker` and `GiveUp` are grdr-model types (#282), settled by the RFC of #1710. Semantics:
- The operation says whether a failure may be retried; `run` never inspects `E`.
- Before each call `run` asks the breaker for a permit at `clock.monotonic()`; a refusal ends the run with `BreakerOpen` and makes no call.
- The first call records a request in the budget; each later call spends from it first, and a refusal ends the run with `BudgetExhausted`.
- Each call races the operation against `clock.sleep_until(start + timeout)`. Each poll polls the operation first, so an operation ready on the same poll wins. If the sleep wins, the operation is dropped and the attempt counts as retryable with no hint; with no retry after it the run returns `Timeout`.
- On `Done(t)` the breaker records a success and `run` returns `Ok(t)`.
- On `Retry` or `Fail`, `run` asks the policy once for the next step (with no hint for `Fail`), and the breaker records a failure with that step's delay, so an opened breaker's `until` is the time of the next attempt. `Fail(e)` returns `Failed(e)`. `Retry` either sleeps until `now + delay` and calls again, or returns `GaveUp`. Elapsed time is measured on `clock.monotonic()` from the first call.
- The race is written over `core::future::poll_fn`, with no dependency and no runtime. Every variant keeps the attempt count and the last error.
- The future of `run` is `Send` under these bounds; a compile-time test shows it.

Callers: every port call site in the targets and the daemon (ARCH-018 forbids any other retry loop).

### 5. Conformance kit (#281, with every port item)
```rust
// grdr_ports_testkit::conformance
pub trait Fixture: Send + Sync {
    type Adapter: Send + Sync + 'static;
    type Leases: Leases + 'static;
    fn open(&self) -> impl Future<Output = Result<Arc<Self::Adapter>, FixtureError>> + Send;
    fn leases(&self) -> Arc<Self::Leases>;
    fn block_on<T: Send>(&self, future: impl Future<Output = T> + Send) -> Result<T, Stalled>;
    fn spawn(&self, task: Pin<Box<dyn Future<Output = ()> + Send + 'static>>);
    fn settle(&self) -> Result<(), Stalled>;
    fn stop_at(&self, point: StopPoint, mode: StopMode) -> Result<Stop, FixtureError>;
    fn induce(&self, fault: Fault) -> Result<(), FixtureError>;
}
pub trait RelationalFixture: Fixture {
    fn snapshot(&self, members: &[&SingleCtx]) -> impl Future<Output = Result<SetCtx, FixtureError>> + Send;
}
pub enum StopPoint {
    FlushAfterSegments, FlushAfterLakeFiles, CommitAfterFenceCheck,
    AppendBeforeVisible, BusSubscribeAfterRead, BusCommitBeforeUpdate,
}
pub enum StopMode { Crash, Pause }
pub struct Stop { /* private */ }
impl Stop { pub fn reached(&self) -> bool; pub fn resume(self); }
pub enum Fault { Store(StoreFault), TailUnavailable }
pub enum FixtureError { CannotStop(StopPoint), CannotInduce(Fault), Open { reason: String } }

pub enum CaseKind { Contract, Crash, Differential }
pub struct Case<F> { pub name: &'static str, pub kind: CaseKind, pub run: fn(&F, &mut SeededEntropy) -> Result<(), Failure> }
pub struct Failure { pub reason: String }
pub struct Suite<F> { /* private: ordered cases */ }
impl<F: Fixture> Suite<F> { pub fn run(&self, fixture: &F, adapter: &str, seed: u64) -> Report; }
pub enum Outcome { Pass, Fail(Failure), NotApplicable(Fault) }
pub struct CaseResult { pub name: &'static str, pub kind: CaseKind, pub outcome: Outcome }
pub struct Report { pub kit_version: String, pub adapter: String, pub seed: u64, pub results: Vec<CaseResult> }
impl Report { pub fn passed(&self) -> bool; pub fn to_toml(&self) -> String; }
```

Rules of the kit:
- A suite is generic over a `Fixture` whose `Adapter` implements its port. Cases share the fixture's store. Each case isolates itself with organisation ids, names and lease names drawn fresh from `SeededEntropy` seeded by `seed`, and none assumes an empty store, so a suite runs against a shared PostgreSQL database or bucket. The report records the seed, so a failure replays.
- `open` returns a handle over the fixture's durable state; a second call models a process restart. `leases` returns the lease store the adapter's fenced commits check: for Events and Relational it is the lease table in the same store (Rule 5).
- `block_on`, `spawn` and `settle` run futures on the adapter's own executor. The in-memory fixtures use the kit's `block_on` with their own poll bound; a network adapter uses its runtime. `Stalled` means the future did not finish within the fixture's own wait bound.
- `stop_at` arms one point in the adapter's next operation that reaches it. `Crash` makes that operation return at the point and leaves durable state as a process kill there would, with no clean-up; the case then calls `open` again. `Pause` holds the operation at the point until `resume`. The bus points sit just before the stamping statement of `subscribe`, after any read the adapter makes, and just before the conditional update of `commit`, so a case can place a second operation inside the first. A Crash case uses only `Crash`; a Contract case may use `Pause`.
- `induce` creates a fault the adapter must map: the in-memory references inject it; a filesystem or SQLite fixture creates the real condition (a small full volume, a read-only directory, a file held by another process). A fixture that cannot create a fault returns `CannotInduce`, and the case reports `NotApplicable` with the fault named. A release-gating adapter's item names the faults its fixture must induce.
- A Differential case drives one operation sequence generated from the seed through the adapter and through the port's reference adapter (built by the suite over its own `ManualClock` and `MemLeases`) and compares every observable result. Opaque values such as offsets are compared by the pattern of equality and order they show, not by value.
- `passed()` is true when no case failed. The report's kit version is the `grdr-ports-testkit` crate version; a change to any case is a new version.

Running the kit against an adapter outside this workspace:
1. Depend on `grdr-ports` and, as a dev-dependency, `grdr-ports-testkit`, at the version of the server release you target. Until the crates are published to a registry, use a git dependency pinned to that release's tag.
2. Implement `Fixture` in your adapter's tests. `open` connects to the store your own test environment names (your environment variable or configuration file; the kit reads no environment). `leases` returns a `Leases` adapter on the same store where Rule 5 requires it. `block_on`, `spawn` and `settle` use your runtime. `stop_at` and `induce` use test hooks your adapter keeps behind its `testkit` feature.
3. Add one test per suite, for example `let report = grdr_ports_testkit::storage::blobs::conformance::suite().run(&fixture, "example-blobs", seed); assert!(report.passed(), "{}", report.to_toml());`, and run it with `cargo test --locked -p <your crate> --features testkit`.
4. The kit runs the same test on itself with `MemBlobsFixture` and the other reference fixtures; read them as the worked example.
5. List the adapter in your `dist.toml` with the fixture environment its conformance test needs (section 12). The distribution build runs that test itself and admits the adapter only on its own passing report. Nothing is submitted to Loonaro or to any service.
6. A PostgreSQL fixture also runs the ordering cases on a database whose default collation is `ja-JP` (Rule 11).

A how-to page, "Write a storage adapter", under `docs/product/how-to/` (design/34) summarises on one page the witness each method takes, the fence form each commit uses, the code each fault returns, and these steps. #281 writes it with the runner.

### 6. Blobs (#297)
```rust
// grdr_ports::storage
pub struct PageLimit { /* private: non-zero */ }
impl PageLimit { pub fn new(entries: u32) -> Option<PageLimit>; pub fn get(&self) -> u32; }

// grdr_ports::storage::blobs
pub trait Blobs: Send + Sync {
    fn put(&self, path: &TenantPath, bytes: Vec<u8>) -> impl Future<Output = Result<ObjectMeta, BlobError>> + Send;
    fn get(&self, path: &ReadPath) -> impl Future<Output = Result<Vec<u8>, BlobError>> + Send;
    fn get_range(&self, path: &ReadPath, range: ByteRange) -> impl Future<Output = Result<Vec<u8>, BlobError>> + Send;
    fn list(&self, prefix: &ListPrefix, after: Option<&ObjectKey>, limit: PageLimit) -> impl Future<Output = Result<Page, BlobError>> + Send;
    fn delete(&self, path: &TenantPath) -> impl Future<Output = Result<(), BlobError>> + Send;
}
pub struct ObjectMeta { pub key: ObjectKey, pub len: u64 }
pub struct ByteRange { /* private: start < end */ }
impl ByteRange { pub fn new(start: u64, end: u64) -> Option<ByteRange>; pub fn start(&self) -> u64; pub fn end(&self) -> u64; }
pub struct Page { pub keys: Vec<ObjectKey>, pub next: Option<ObjectKey> }
#[non_exhaustive]
pub enum BlobError { NotFound { key: ObjectKey }, Range { key: ObjectKey, len: u64 }, Store(StoreFault) }
```

- `put` writes an object; a `get` of that path afterwards returns exactly those bytes. The port promises nothing about a second `put` to the same path. Conditional put is used where a store has it and never required (design/20 section 3); callers name every immutable object uniquely.
- `get` returns the bytes last written; a path never written, or deleted, fails `NotFound`.
- `get_range` returns exactly the bytes `[start, end)`; an `end` beyond the object's length fails `Range` and returns no bytes.
- `list` returns at most `limit` keys under the prefix, in ascending byte order of the rendered key, strictly after `after`, with `next` set when more remain. The adapter builds each key with `ObjectKey::under`, so it never returns another organisation's key.
- `delete` removes the object: afterwards `get` and `get_range` fail `NotFound` and `list` omits the key. Deleting a path that does not exist succeeds, so a restarted job repeats no visible side effect. Noncurrent versions a versioned bucket keeps for backup expire by the bucket's lifecycle within the backup window (design/20 section 9) and are not reachable through the port. Erasure of content is by key destruction, never by `delete` alone.
- Object bytes are opaque and never logged. Errors carry the rendered key only.
- Whole objects pass as `Vec<u8>`, which fits slice 0's flush outputs (32 MB); a streaming put is an amendment with L-4.
- Deployment-scoped objects (`state-log/`, `ephemeral/detect/`, the content repository) are not on this trait (question 1).

Callers in slice 0: `store` writes lake files and archive segments (#1547, `put`); the lake read path reads Parquet footers and pages (#1554, `get`, `get_range`); `store` removes objects an interrupted flush left unreferenced (#1547, `list`, `delete`).

Cleanup of unreferenced objects. Holders of different bus partitions write into the same `org=/class=/day=` prefix, so a lister sees objects another holder has written and not yet committed. `store` therefore removes an object only when no catalogue row references it and the time in its uuidv7 name is older than a grace from `limits.toml`, which must exceed the largest flush deadline plus the lease term. Lake files and segments are always named `<uuidv7>.parquet` and `<uuidv7>.seg` (design/20 section 5.2), so the age needs no metadata call.

Suite `storage::blobs::conformance`, reference adapter `MemBlobs`: one case per bullet above; a cross-organisation case (objects under organisation A are never returned by a read or list under B); every `StoreFault` the fixture can induce maps to `Store` with that fault; listing order with keys that differ only in byte order. A property test in #297 compares `MemBlobs` with a `BTreeMap` model over generated sequences.

### 7. Jobs: leases (#298)
```rust
// grdr_ports::storage::jobs
pub trait Leases: Send + Sync {
    fn acquire(&self, name: &LeaseName, holder: &HolderId, term: LeaseTerm) -> impl Future<Output = Result<Acquire, JobsError>> + Send;
    fn renew(&self, lease: &Lease, term: LeaseTerm) -> impl Future<Output = Result<Renew, JobsError>> + Send;
    fn release(&self, lease: &Lease) -> impl Future<Output = Result<(), JobsError>> + Send;
    fn check(&self, fence: &Fence) -> impl Future<Output = Result<(), JobsError>> + Send;
}
pub struct HolderId { /* private: ASCII */ }
impl HolderId {
    pub fn mint(clock: &impl Clock, entropy: &mut dyn Entropy) -> HolderId;
    pub fn parse(text: &str) -> Option<HolderId>;
    pub fn as_str(&self) -> &str;
}
pub struct FencingToken(pub u64);
pub struct Fence { pub name: LeaseName, pub token: FencingToken }
pub struct LeaseTerm { pub ttl: Duration }
pub struct Lease { pub name: LeaseName, pub holder: HolderId, pub token: FencingToken, pub expires_at: Timestamp }
impl Lease { pub fn fence(&self) -> Fence; }
pub enum Acquire { Held(Lease), Busy { holder: HolderId, expires_at: Timestamp } }
pub enum Renew { Renewed(Lease), Lost }
pub enum LeaseState { Free { last: FencingToken }, Held { holder: HolderId, token: FencingToken, expires_at: Timestamp } }
#[non_exhaustive]
pub enum JobsError { StaleFence { current: FencingToken }, Store(StoreFault) }
```

- Each lease name is in one `LeaseState`, the type every adapter and `MemLeases` store per name. A name never acquired is `Free { last: FencingToken(0) }`. `release` and expiry move to `Free` with `last` set to the newest token issued, so the high-water mark survives every transition; an adapter never deletes a lease row. No boolean "held" flag exists.
- `acquire` returns `Held` with a new token, strictly greater than `last` or the held token, when the name is free, expired, or already held by the same holder. `Busy` is returned when another holder holds it unexpired. Re-acquiring by the same holder therefore supersedes that holder's earlier `Lease`: a task restarted inside one process, which shares the process's `HolderId`, gets a fence its stalled predecessor does not have.
- `renew` returns `Renewed` with a later `expires_at` and the same token while the caller's token is the newest and unexpired, and `Lost` once a newer token was issued or the lease expired.
- `release` frees the name only if the caller's token is the newest; releasing a lost lease does nothing.
- `expires_at` comes from the store's own clock and `LeaseTerm::ttl`; no method takes the caller's wall time. The 5 s renewal and 15 s expiry are `limits.toml` values the caller passes.
- `check` fails `StaleFence { current }` unless the fence's token equals the newest token issued for the name (Rule 5). `acquire` and `renew` wait while a lease-checked commit holds the row.
- A holder whose fence is superseded moves to `Lost` and re-enters `acquire`. That is normal after a sleep or a failover; the job runner (J-1) raises health only when it repeats past a `limits.toml` bound, so a laptop that slept shows no false alert.
- Leases belong to no organisation (a bus partition and a singleton serve every organisation on them), so the methods take no context and are deployment-scoped. The tenant-scoped Jobs methods (`enqueue`, `claim`, `step`, `complete`) are J-1's amendment.
- `HolderId` is minted once per process start through grdr-model's id constructor (ARCH-020). It names the process for `Busy` and for the bus consumer row; it is not authority, so `parse` may rebuild it from a stored row.

Callers in slice 0: the partition consumer runner (`store` on each `events` partition) and the `migrate` lease of `Migrator::apply`.

Suite `storage::jobs::conformance`, reference adapter `MemLeases` over an injected `Clock`. `MemLeases` clones cheaply and shares its state, so the other references check fences against it. Cases: one per bullet above; many tasks racing to acquire one name, after which exactly one is `Held`; a holder that pauses past expiry while a second acquires, after which the first's `check` and `renew` fail and the second's succeed; two tasks with one `HolderId`, the second acquiring while the first holds, after which the first's `check` fails and its lease-checked commit does not land; release then acquire, and expiry then acquire, each giving a token strictly greater than any before.

### 8. Bus (#299)
```rust
// grdr_ports::storage::bus
pub trait Bus: Send + Sync {
    type Subscription: Subscription;
    fn append(&self, ctx: &SingleCtx, stream: Stream, bucket: VirtualBucket, messages: Vec<Outgoing>) -> impl Future<Output = Result<Appended, BusError>> + Send;
    fn subscribe(&self, group: &ConsumerGroup, stream: Stream, claims: Vec<Claim>) -> impl Future<Output = Result<Subscribed<Self::Subscription>, BusError>> + Send;
    fn commit(&self, group: &ConsumerGroup, stream: Stream, partition: PartitionId, position: Position, fence: &Fence) -> impl Future<Output = Result<(), BusError>> + Send;
    fn lag(&self, group: &ConsumerGroup, stream: Stream) -> impl Future<Output = Result<Vec<PartitionLag>, BusError>> + Send;
    fn set_bucket_map(&self, stream: Stream, map: BucketMap) -> impl Future<Output = Result<(), BusError>> + Send;
}
pub trait Subscription: Send {
    fn fetch(&mut self, max: FetchLimit) -> impl Future<Output = Result<Vec<StoredMessage>, BusError>> + Send;
}
pub async fn fetch_batches<S: Subscription>(subscription: &mut S, max: FetchLimit) -> Result<Vec<OrgBatch>, BusError>;

pub enum Stream { Events, DetectKeyed, Findings, Control, Usage }
pub struct VirtualBucket(pub u32);
pub struct PartitionId(pub u32);
pub struct Offset(pub u64);
pub struct MapVersion(pub u64);
pub struct BucketMap { pub version: MapVersion, pub partitions: Vec<PartitionId> }
pub struct Outgoing { pub headers: Headers, pub payload: Vec<u8> }
pub struct Appended { pub partition: PartitionId, pub first: Offset, pub last: Offset }
pub struct Claim { pub partition: PartitionId, pub fence: Fence }
pub struct Position { pub offset: Offset, pub checkpoint: Option<CheckpointRef> }
pub struct PartitionPosition { pub partition: PartitionId, pub committed: Option<Position> }
pub struct Subscribed<S> { pub subscription: S, pub positions: Vec<PartitionPosition> }
pub struct StoredMessage { pub partition: PartitionId, pub offset: Offset, pub org: Option<OrgId>, pub headers: Headers, pub payload: Vec<u8> }
pub struct Message { pub offset: Offset, pub headers: Headers, pub payload: Vec<u8> }
pub struct OrgBatch { /* private: partition, RecordedOrg, messages; built only by fetch_batches */ }
impl OrgBatch { pub fn partition(&self) -> PartitionId; pub fn org(&self) -> &RecordedOrg; pub fn messages(&self) -> &[Message]; }
pub struct PartitionLag { pub partition: PartitionId, pub oldest_unprocessed: Option<Timestamp> }
pub struct FetchLimit { /* private: non-zero */ }
impl FetchLimit { pub fn new(messages: u32) -> Option<FetchLimit>; pub fn get(&self) -> u32; }
#[non_exhaustive]
pub enum BusError {
    Full { stream: Stream, partition: PartitionId },
    Regress { partition: PartitionId, committed: Offset },
    Bucket { bucket: VirtualBucket, count: u32 },
    MapVersion { current: MapVersion },
    StaleFence { partition: PartitionId, current: FencingToken },
    NoOrganisation { partition: PartitionId, offset: Offset },
    Store(StoreFault),
}
```

`Headers` holds the headers of design/20 section 4 step 4 other than `org`, `received_at` among them. The bus writes `org` itself and returns it only as `StoredMessage::org`.

- `append` writes every message to the one partition the current `BucketMap` gives the bucket, and returns that partition and the first and last offsets, contiguous and ascending in input order. A bucket at or above the map's length fails `Bucket`. Each stored message carries the context's organisation as its `org` header. When the stream's byte bound (a value the adapter is built with) would be exceeded, `append` fails `Full`, stores nothing, and names the stream and partition so `ingest` can answer with a spread `retry_after_ms`.
- Offsets within a partition are strictly increasing in the order appends become visible: a consumer never sees offset n+1 before n.
- `subscribe` handles each claim as one compare-and-set on the partition's consumer row `(group, stream, partition)`: create the row with fence 0 if absent, then set `fence` and `holder` to the claim's where the stored fence is at or below the claim's, returning the committed position from the same statement. In PostgreSQL that is `UPDATE bus_consumer SET fence = :f, holder = :h WHERE ... AND fence <= :f RETURNING committed_offset, checkpoint`. Zero rows updated means a greater fence is stored, and `subscribe` fails `StaleFence`; claims stamped earlier in the same call stay stamped, which is harmless because each names its own acquisition. A read followed by a separate update is not this rule: at READ COMMITTED a lower fence would overwrite a higher one. `positions` returns the positions read, and the subscription starts each partition after its committed offset.
- `fetch` returns at most `max` stored messages in offset order per partition, each with the organisation from its `org` header or `None` if it has none. Module code calls `fetch_batches`, which calls `fetch` and groups consecutive messages of one partition and one organisation into `OrgBatch` values, built inside `grdr-ports`, so a batch never mixes organisations whatever the adapter returns. A message with no organisation fails `NoOrganisation` with its partition and offset; nothing past it is returned, and the consumer stops on that partition and reports the code, because committing past a message nobody attributed would lose it (design/21 section 2).
- `commit` records the offset and the optional checkpoint in one conditional update of the consumer row: `SET committed_offset = :o, checkpoint = :c WHERE ... AND fence = :f AND committed_offset <= :o`. When no row is updated the adapter reads the row once to say which condition failed: another fence is `StaleFence`, a higher committed offset is `Regress`; neither changes the row. `detect` puts its snapshot's object name in `checkpoint`, so the offset and the snapshot key move together (design/20 section 7); `store` passes `None`.
- Why the row-stamped form is safe. Between a new holder's `acquire` and its `subscribe`, the old holder's commits still land. Each one records progress the old holder made under its own fenced writes, since its lake flush is lease-checked (section 10). The new holder reads the position in the statement that stamps it, so it never starts below a commit that landed, and the old holder's later commits fail. Two `subscribe` calls with different fences end with the greater one stored, in either order. The rule other consumer groups follow is the same: commit only progress a lease-checked write or an idempotent effect has confirmed. The bus checks no lease, so `bus.database` may stay a separate instance.
- A serialisation failure, where an adapter runs these statements at a stricter isolation level, is `Store(StoreFault::Conflict)` and retryable.
- `lag` gives, per partition, the `received_at` of the oldest message after the committed offset, or `None` when the group is caught up.
- `set_bucket_map` accepts only a version greater than the current one, else `MapVersion`; earlier versions are kept and readable.
- Every `Stream` behaves the same at the port; partition counts and byte bounds come from configuration. Payloads are opaque bytes at the capture level the device applied; headers are `structural`. Errors carry stream, partition, offset and token only.
- `subscribe`, `commit`, `lag`, `set_bucket_map` and `Subscription::fetch` are deployment-scoped.
- Every shipped Bus adapter is durable on disk: the log on SQLite in WAL mode for `embedded`, the log on PostgreSQL for `ha`, NATS JetStream with file storage for `distributed` (design/20 section 7). `MemBus` is a reference only.

Callers in slice 0: `ingest` appends; `store` subscribes, calls `fetch_batches`, commits and reads lag; server bootstrap writes the first bucket map version. `detect` uses `checkpoint` once D-1 is built; until then every commit passes `None`, and the reference and cases still cover it.

Suite `storage::bus::conformance`, reference adapter `MemBus` over an injected `Clock`. Cases: one per bullet above; an append and a fetch on every `Stream`; two `subscribe` calls with fences 6 and 7 on one row, the first paused at `BusSubscribeAfterRead` while the second runs, in both orders, after which the row holds 7 and only the holder of 7 can commit; the old holder commits after the new holder's `acquire` and before its `subscribe`, the commit lands, and the new holder's `positions` start at that offset; the old holder paused at `BusCommitBeforeUpdate` while the new holder subscribes, after which the old commit fails `StaleFence`; a commit with a checkpoint returned by the next `subscribe`; appends from four organisations to one partition fetched in small steps, after which every batch holds one organisation and the concatenation equals the append order; a stored message with no organisation fails `NoOrganisation`; a crash at `AppendBeforeVisible`, after which no offset of that append is visible and later offsets stay contiguous.

### 9. Relational (#300)
```rust
// grdr_ports::storage::relational
pub trait Relational: Send + Sync {
    type ReadTx: ReadTx;
    type WriteTx: WriteTx;
    fn read(&self, ctx: &TenantCtx) -> impl Future<Output = Result<Self::ReadTx, RelError>> + Send;
    fn write(&self, ctx: &SingleCtx) -> impl Future<Output = Result<Self::WriteTx, RelError>> + Send;
    fn write_fenced(&self, ctx: &SingleCtx, fence: Fence) -> impl Future<Output = Result<Self::WriteTx, RelError>> + Send;
    fn snapshot_members(&self, set: &SetCtx, after: Option<&MemberCursor>, limit: PageLimit) -> impl Future<Output = Result<SnapshotPage, RelError>> + Send;
}
pub trait ReadTx: Send {}
pub trait WriteTx: Send {
    fn commit(self) -> impl Future<Output = Result<(), RelError>> + Send;
}
pub trait Migrator: Send + Sync {
    fn apply(&self, plan: &MigrationPlan, fence: &Fence) -> impl Future<Output = Result<Applied, MigrationError>> + Send;
    fn check_compatible(&self, plan: &MigrationPlan, binary_release: Release) -> impl Future<Output = Result<(), MigrationError>> + Send;
}
pub struct Release(pub u32);
pub struct MigrationId { pub release: Release, pub seq: u32 }
pub struct Migration { pub id: MigrationId, pub step: Step }
pub enum Step { Expand(ExpandKind), Contract { of: MigrationId } }
pub enum StepKind { Expand, Contract }
pub enum ExpandKind { AddTable, AddColumnNullable, AddColumnWithDefault, AddIndex, AddPolicy }
pub struct RecordedMigration { pub id: MigrationId, pub step: StepKind }
pub struct MigrationPlan { /* private: ordered migrations */ }
impl MigrationPlan {
    pub fn new(migrations: Vec<Migration>) -> Result<MigrationPlan, PlanError>;
    pub fn migrations(&self) -> &[Migration];
    pub fn check_compatible(&self, recorded: &[RecordedMigration], binary_release: Release) -> Result<(), MigrationError>;
}
pub struct Applied { pub applied: Vec<MigrationId> }
#[non_exhaustive]
pub enum RelError { StaleFence { current: FencingToken }, Constraint, SingleOrganisation, Store(StoreFault) }
#[non_exhaustive]
pub enum PlanError { Duplicate { id: MigrationId }, Order { id: MigrationId }, ContractWithoutExpand { id: MigrationId }, ContractTooEarly { id: MigrationId } }
#[non_exhaustive]
pub enum MigrationError { SchemaTooNew { id: MigrationId }, Rel(RelError) }
```

- `read`, `write` and `write_fenced` are the only ways to open a transaction. The adapter binds the context at the start of each transaction (`SET LOCAL grdr.orgs` or `grdr.orgset` from the scope's `as_str`, design/21 section 2). `ReadTx` has no write method.
- Repositories are traits implemented on an adapter's transaction types, so the transaction is the witness. Where module repository traits live is question 2.
- `commit` makes the writes visible. A transaction opened with `write_fenced` holds its fence from the start and its `commit` is lease-checked by Rule 5, so code that holds the transaction cannot skip the check. On `StaleFence` the transaction rolls back and is consumed, so no stale write can be committed afterwards. Request handlers use `write`. The J-1 step API hands each step a handle whose only way to open a write is `write_fenced` with the step's fence, so a job step cannot skip it either (design/20 section 8, "every write checks").
- A dropped `WriteTx` makes none of its writes visible. The adapter may finish the rollback when the connection is next used, because `Drop` cannot await.
- `Constraint` is a constraint violation and carries no row data. A serialisation failure is `Store(StoreFault::Conflict)` and retryable.
- `snapshot_members` returns the organisation ids of the set's delegation snapshot, read under the set's binding, in ascending byte order of `OrgId`, strictly after `after`, at most `limit`. Module code calls `tenant::members`, which wraps each id in a `MemberCtx` (section 2).
- A store that binds one organisation only (SQLite in `embedded`, D-34) fails `SingleOrganisation` for `snapshot_members`, for `read` with a `Set` context, and for a `SingleCtx` of a second organisation, rather than serving any of them unisolated.
- `MigrationPlan::new` refuses duplicate ids, ids out of ascending order, a `Contract` whose `of` is not an `Expand` in the plan, and a `Contract` whose release is below its `Expand`'s release plus 2 (release N adds, N+1 reads the new form, N+2 drops the old). The SQL of each migration lives in the adapter crate, keyed by `MigrationId` (ARCH-015). `ExpandKind`'s variants behave the same at the port: the plan rules do not depend on the kind, so one case covers them.
- `MigrationPlan::check_compatible` is pure. It accepts recorded ids that are all in the plan, or whose ids outside the plan all belong to `binary_release + 1` and are all `Expand` steps (the previous binary runs on the new schema). Any other id outside the plan fails `SchemaTooNew { id }`.
- `Migrator::apply` applies, in order, each migration not yet recorded. Migrations belong to no organisation, so the adapter runs each in its own deployment-scoped transaction inside its crate, never a `WriteTx`. That transaction records the migration's id and commits by the lease-checked form of Rule 5 under the `migrate` fence.
- `Migrator::check_compatible` reads the recorded migrations once and calls the pure function. The server runs it once at start, before it serves anything; when it passes it costs one read and blocks nothing after. When it fails the server does not start, so a binary rolled back onto a newer schema is refused with `GRDR-REL-0007`, never run silently.
- `Migrator` is deployment-scoped. Tables without an organisation (runtime settings and the operator realm, D-70) need a deployment-scoped transaction for module code, which this trait does not offer (question 3).

Callers in slice 0: every module's repositories (`read`, `write`); `store`'s catalogue writes inside the Events adapter and every job step (`write_fenced`); server start (`check_compatible`) and `grdr server migrate` (`apply`). The provider workbench read path calls `snapshot_members` through `tenant::members`; it is not in slice 0 and is declared with the minting boundary of section 2.

Test kit:
```rust
// grdr_ports_testkit::storage::relational
pub struct ProbeKey { /* private: identifier */ }
pub trait ProbeRepo: Relational {
    fn probe_put(tx: &mut Self::WriteTx, key: &ProbeKey, value: Vec<u8>) -> impl Future<Output = Result<(), RelError>> + Send;
    fn probe_get(tx: &mut Self::ReadTx, key: &ProbeKey) -> impl Future<Output = Result<Option<Vec<u8>>, RelError>> + Send;
}
pub struct MemRelational { /* per-organisation maps, snapshot table, MemLeases handle, recorded migrations */ }
```
`ProbeRepo` is a `(key, value)` repository per organisation that each adapter implements behind its `testkit` feature with its own SQL. `MemRelational` is the reference: it implements `Relational`, `ReadTx`, `WriteTx`, `Migrator` and `ProbeRepo` over per-organisation maps, holds a `MemLeases` handle for fenced commits, keeps a snapshot table for `snapshot_members`, and drops uncommitted writes. Suite `storage::relational::conformance`, generic over a `RelationalFixture` whose adapter is `Relational + Migrator + ProbeRepo`. Cases: a write in organisation A is never returned by a read in B; a dropped `WriteTx` leaves nothing visible; a crash at `CommitAfterFenceCheck` leaves nothing visible; a fenced commit under a superseded fence fails and leaves nothing visible; a fenced commit paused at `CommitAfterFenceCheck` while another holder acquires, after which `acquire` was still waiting when the commit ended; `apply` applies in order, records ids, and is a no-op on a second run; `check_compatible` accepts and refuses per the rule above; `tenant::members` returns exactly the snapshot's organisations and pages without gap or repeat; a member context and a `Set` context cannot reach `write` (compile-fail doctests); `SingleOrganisation` for each of its three cases on a single-organisation fixture; and a Differential case against `MemRelational`. These cases run on `MemRelational` in #300, and on SQLite and PostgreSQL in their adapter items.

### 10. Events and QueryIr (#1535)
```rust
// grdr_ports::storage::events
pub trait Events: Send + Sync {
    type Plan: Send;
    type Results: ResultStream;
    fn append(&self, ctx: &SingleCtx, fence: &Fence, batch: LakeBatch) -> impl Future<Output = Result<Buffered, EventsError>> + Send;
    fn flush(&self, fence: &Fence, due: FlushDue, deadline: Monotonic) -> impl Future<Output = Result<Flushed, EventsError>> + Send;
    fn plan(&self, ctx: OrgRead<'_>, query: QueryIr, limits: QueryLimits) -> impl Future<Output = Result<Self::Plan, EventsError>> + Send;
    fn execute(&self, plan: Self::Plan) -> impl Future<Output = Result<Self::Results, EventsError>> + Send;
}
pub trait ResultStream: Send {
    fn next(&mut self) -> impl Future<Output = Result<Next, EventsError>> + Send;
}

pub struct ArrowIpc { /* private: bytes */ }
impl ArrowIpc { pub fn new(bytes: Vec<u8>) -> ArrowIpc; pub fn as_bytes(&self) -> &[u8]; pub fn into_bytes(self) -> Vec<u8>; }
pub struct LakeBatch { pub source: Offset, pub archive: ArchiveBatch, pub rows: Vec<TableRows> }
pub struct ArchiveBatch { pub lane: Lane, pub day: Date, pub bytes: Vec<u8> }
pub struct TableRows { pub table: LakeTable, pub rows: ArrowIpc }
pub enum LakeTable { Decision, Activity }
pub struct Buffered { pub added: u64, pub duplicate: u64 }
pub enum FlushDue { Thresholds, All }
pub struct Flushed { pub committed_through: Option<Offset> }

pub enum QueryIr {
    Timeline { root_session_id: SessionId, time: TimeBounds, order: Direction, after: Option<Resume> },
    Scan {
        view: ViewName, time: TimeBounds, predicates: Vec<Predicate>,
        projection: Vec<ColumnName>, order: Direction, after: Option<Resume>,
    },
}
pub enum Direction { Ascending, Descending }
pub struct TimeBounds { /* private: from < to */ }
impl TimeBounds { pub fn new(from: Timestamp, to: Timestamp) -> Result<TimeBounds, EventsError>; pub fn from(&self) -> Timestamp; pub fn to(&self) -> Timestamp; }
pub struct RowPosition { pub observed_time: Timestamp, pub device_id: DeviceId, pub epoch: Epoch, pub monotonic_ns: u64, pub lane: Lane, pub seq: Seq }
pub struct Resume { pub position: RowPosition, pub coverage: Coverage }
pub struct Predicate { pub column: ColumnName, pub op: Comparison, pub values: Vec<Literal> }
pub enum Comparison { Eq, Ne, Lt, Le, Gt, Ge, In }
pub enum Literal { Bool(bool), Int(i64), UInt(u64), Text(String), Bytes(Vec<u8>), Time(Timestamp) }
pub struct QueryLimits { pub rows: u64, pub bytes: u64, pub wall_time: Duration, pub in_values: u32 }

pub enum Next { Batch(ArrowIpc), End(Ending) }
pub struct Ending { pub completion: Completion, pub coverage: Coverage }
pub enum Completion { Complete, Limited { reason: LimitReason, resume: Option<Resume> } }
pub enum LimitReason { Rows, Bytes, WallTime }
pub enum Coverage { Full, WithoutTail }

#[non_exhaustive]
pub enum EventsError {
    View { view: ViewName },
    Column { column: ColumnName },
    Predicate { column: ColumnName },
    TimeBounds,
    BatchSchema { table: LakeTable },
    BatchUnreadable,
    StaleFence { current: FencingToken },
    Store(StoreFault),
}
```

`SessionId`, `DeviceId`, `Epoch` and `Seq` are grdr-model types (#1710). The adapter takes the lake column manifest (#510's type, in `grdr-schema`) and a `Clock` when it is built.

Rows cross the port as Arrow IPC. `ArrowIpc` holds one Arrow IPC stream: Arrow columnar format 1.x, a schema message and then record batches, with no dictionary deltas and no body compression. Its schema is the column manifest of the batch's table, or of the plan's projection. The contract is the Arrow format, a published standard (P10), not an arrow-rs release, and `grdr-ports` links no Arrow (Rule 1). The cost is one encode and one decode per batch.

Write path:
- `LakeBatch` is one bus message of the `events` stream. `source` is its offset. `archive` holds the received batch bytes unchanged, with the batch's lane and the UTC date of its `received_at`; they keep the device-side pseudonyms the batch was signed with (D-39). `rows` holds the decoded rows of each table, already flattened by the column manifest and with server pseudonyms in place of device-side ones (D-51), and with no `organisation_id` column (Rule 4). The adapter adds `organisation_id` from `ctx`, and refuses with `BatchSchema` a batch whose columns differ from the manifest, `organisation_id` included. Bytes that are not a valid Arrow IPC stream of that profile fail `BatchUnreadable`.
- `append` takes the fence of the `store` lease on the bus partition the batch came from. It fails `StaleFence` if that fence is already superseded when called (a point-in-time check), and otherwise buffers the rows and the archive batch. A row whose key `(device, epoch, lane, seq)` is already appended or committed adds nothing; `Buffered` counts added and duplicate rows. Once `append` returns, an `execute` that starts afterwards returns the added rows.
- `flush` commits the buffers that are due, one organisation at a time. `Thresholds` takes each organisation with a table buffer past the size or age the adapter was built with; `All` takes every organisation, and runs at the partition's bus retention bound and on lease release. For each organisation it writes the archive segments of the due batches first (`org=<id>/class=archive/lane=<lane>/day=<date>/<uuidv7>.seg`), then one Parquet object per table, then one catalogue transaction, lease-checked by Rule 5, that records the lake files, their statistics and data key ids, and the segments in `lake_archive_segment`. Only after that commit is visible does it drop the committed rows from the buffer.
- A crash anywhere before that commit leaves no catalogue row; the objects written before it are unreferenced and uniquely named, and `store` removes them after the grace of section 6. A crash after it leaves rows, files and segments all visible. No batch is ever committed without its archive segment.
- `flush` stops starting new organisation commits once `deadline` passes on the adapter's clock, and returns what committed. What it did not commit stays buffered or, on release, is dropped; the bus delivers it again because the bus offset never passes `committed_through`. Closing a laptop lid therefore never hangs the daemon on a flush.
- `committed_through` is the greatest offset `o` such that every batch appended under this fence with `source <= o` has its rows and segment committed, or `None`. `store` commits the bus offset to that value (design/20 section 5.2). It is not the sensor-facing `durable_through` of design/20 section 9, which is later and also needs backup health.
- A flush under a superseded fence fails `StaleFence` and drops that fence's buffers; the bus delivers the rows again to the new holder. A crash or forced power-off loses only buffered rows, which the bus still holds.
- `LakeTable` has no `Content` variant until content sealing (L-3) exists, so no path can write content unsealed (D-51; #1546 R5).
- Pseudonyms. `ArrowIpc` columns carry the pseudonym class, and the port cannot tell a device-side value from a server one. The guarantee that the lake holds server pseudonyms only is #1690's test (no stored `decision` or `activity` value equals its device-side source). The Events conformance suite does not claim it.

Read path:
- `plan` validates the query against the manifest and prepares it; it reads no catalogue snapshot and no buffer. An unregistered view fails `View`, an unregistered column `Column`; a predicate fails `Predicate` when a literal's kind differs from its column's manifest type, when `Eq` to `Ge` do not have exactly one value, or when `In` has none or more than `in_values`. `TimeBounds::new` fails `TimeBounds` unless `from < to`; bounds are half-open `[from, to)` on `observed_time`.
- `Scan` orders on `(observed_time, device_id, epoch, lane, seq)` and `Timeline` on `(epoch, monotonic_ns, lane, seq)` within its root session, ascending or descending per `order`, compared by Rule 11. `after` returns only rows strictly after `after.position` in that order.
- `execute` returns the plan's organisation's rows from committed lake files and from rows appended but not yet flushed, de-duplicated on `(device, epoch, lane, seq)`, merged in the query's order. The union is inside the port, so no caller can forget it. Buffered rows come from the adapter's own buffers and, where the buffer lives in another process, from the tail source the adapter was built with (`grdr.internal.v1alpha1.StoreTail` in `distributed`, design/20 section 5.2).
- `execute` reads the buffered rows first, then fixes the catalogue snapshot and selects the files to read. A flush drops rows from its buffer only after its catalogue commit is visible. A row appended before `execute` starts is therefore in the buffer read or in the snapshot, never missing from both, whenever `plan` ran.
- Coverage. An ending's `coverage` is `Full` when the buffered rows were read, and `WithoutTail` when the tail source failed or passed its own budget, in which case the stream still returns the lake rows. Coverage travels in `Resume`: a read resumed from a `Resume` whose coverage is `WithoutTail` also ends `WithoutTail`, because buffered rows before the resume position were never returned. A paging that missed the tail on any page therefore ends `WithoutTail` on its last page and never reports `Full` for rows it skipped. The caller shows "could not look" for unflushed events (P9), and a run from the start fills them in once the tail is back.
- Limits. Reaching `rows`, `bytes` or `wall_time` ends the stream `Limited { reason, resume }`, where `resume` holds the position of the last row returned and this read's coverage (`None` if no row was returned). The caller continues with `after: resume`, and the projection does not need the key columns. A limit and a missed tail are reported together: the reason in `completion`, the tail in `coverage`.
- A read with `after: Some(r)` returns every row strictly after `r.position` that is present when it executes. A row that arrives later with a position before it is not returned; re-run from the start to see it.
- After `End`, `next` returns the same `End` again and does no work.
- `Timeline` and `Scan` are the only query nodes until the amendments of section 12 are accepted. `retain`, `erase`, `hold` and `manifest` are not declared: a `NotSupported` default would let an adapter pass the kit without erasure (D-57).

Callers in slice 0: `store` appends and flushes (#1546, #1547); `query` plans and executes `Scan` and `Timeline` (#1554) for the CLI and console reads (#1555), including resume.

Suite `storage::events::conformance`, reference adapter `MemEvents`. `MemEvents` keeps a buffer and a committed store, checks the fence at `append` and at `flush`, writes in-memory segments with each flush, and supports the stop points and the tail fault. Cases: an appended key is idempotent; a batch with an `organisation_id` column or another schema fails `BatchSchema`; an unregistered view or column fails; one `Scan` per `Comparison` and per `Literal` kind, and a literal whose kind differs from its column fails `Predicate`; `Limited` at each limit; `Timeline` and `Scan` paged to the end through `resume`, with no gap and no repeat, in both orders; a row appended and not flushed is returned by `execute`; row R appended, then `plan`, then a flush that commits R, then `execute`, returns R exactly once; R appended, `execute` started, a flush, the stream finished, returns R exactly once; a failed tail source ends with `coverage: WithoutTail`, never `Full`; a limit reached while the tail is down ends `Limited` with `WithoutTail`, and the read resumed from it ends `WithoutTail` even once the tail is back; a flush after another holder acquired fails `StaleFence`; an `append` under a superseded fence fails `StaleFence`; `committed_through` never covers an unflushed batch; crashes at `FlushAfterSegments` and `FlushAfterLakeFiles` leave no catalogue row and no change to `committed_through`, and a later flush commits the batch with its segment; every committed batch has its segment; a `flush(All)` past its deadline returns what committed; `next` after `End`; rows of organisation A never returned under a context for B; a `Set` context cannot reach `plan` (compile-fail doctest); a Differential case against `MemEvents`. A property test in #1535 compares `MemEvents` with a `Vec` model.

### 11. Error codes
Areas for `schema/codes/areas.toml` (#278 R1):

| Area | Subsystem | Owner |
|---|---|---|
| `TENANT` | Identifiers, tenant context and object paths | design/21 |
| `STORE` | Faults of a storage back end, shared by every storage port | design/20 |
| `BLOBS` | Blob store (Blobs port) | design/20 |
| `JOBS` | Jobs and leases (Jobs port) | design/20 |
| `BUS` | Event bus (Bus port) | design/20 |
| `REL` | Relational store and schema migrations | design/20 |
| `EVENTS` | Event store (Events port) | design/20 |

```rust
// grdr_ports::storage
#[non_exhaustive]
pub enum StoreFault { Unavailable, Busy, Conflict, Full, ReadOnly, PermissionDenied, Missing, Integrity }
```

Each cause maps to one variant: a lost connection or a timeout is `Unavailable`; a file held or locked by another process, such as a scanner, is `Busy`; a serialisation failure is `Conflict`; no space or quota on the volume or bucket is `Full`; a read-only file system or volume is `ReadOnly`; refused credentials or file permissions are `PermissionDenied`; a bucket, database or data directory that does not exist is `Missing`; stored bytes that fail the store's checksum or authentication are `Integrity`. The port error's type tells which port met it, and its `LogSafe` form logs the port name beside the code.

| Code | Reason | Class | Connect | Bound by | Next step (`code.<code>.fix`) |
|---|---|---|---|---|---|
| `GRDR-TENANT-0001` | `IDENTIFIER_INVALID` | input | `invalid_argument` | `IdentError` | Use lower-case ASCII letters, digits, `-`, `_` and `.` |
| `GRDR-TENANT-0002` | `PARTITION_FOR_CLASS` | input | `invalid_argument` | `PathError::PartitionForClass` | |
| `GRDR-TENANT-0003` | `DATE_INVALID` | input | `invalid_argument` | `PathError::Date` | |
| `GRDR-TENANT-0004` | `KEY_ID_INVALID` | input | `invalid_argument` | `PathError::KeyId` | |
| `GRDR-STORE-0001` | `STORE_UNAVAILABLE` | retryable | `unavailable` | `StoreFault::Unavailable` | Check that this host reaches the store; the call is retried under its policy |
| `GRDR-STORE-0002` | `STORE_BUSY` | retryable | `unavailable` | `StoreFault::Busy` | Exclude the data directory from scanning and backup locks |
| `GRDR-STORE-0003` | `SERIALISATION_CONFLICT` | retryable | `aborted` | `StoreFault::Conflict` | Retried under its policy |
| `GRDR-STORE-0004` | `STORE_FULL` | fatal | `resource_exhausted` | `StoreFault::Full` | Free space on the volume or raise the quota, or move the data directory |
| `GRDR-STORE-0005` | `STORE_READ_ONLY` | fatal | `failed_precondition` | `StoreFault::ReadOnly` | Mount the volume read-write, or move the data directory |
| `GRDR-STORE-0006` | `STORE_PERMISSION_DENIED` | fatal | `permission_denied` | `StoreFault::PermissionDenied` | Give the service account read and write access to the store |
| `GRDR-STORE-0007` | `STORE_MISSING` | fatal | `failed_precondition` | `StoreFault::Missing` | Create the bucket, database or directory, or correct its configuration key |
| `GRDR-STORE-0008` | `OBJECT_INTEGRITY` | fatal | `data_loss` | `StoreFault::Integrity` | Restore the object from backup; this is an alarm, not a retry |
| `GRDR-BLOBS-0001` | `OBJECT_NOT_FOUND` | input | `not_found` | `BlobError::NotFound` | |
| `GRDR-BLOBS-0002` | `RANGE_OUT_OF_BOUNDS` | input | `out_of_range` | `BlobError::Range` | |
| `GRDR-JOBS-0001` | `FENCE_SUPERSEDED` | fatal | `aborted` | `StaleFence` of `JobsError`, `BusError`, `RelError`, `EventsError` | None while it is rare: the holder reacquires; repeats raise health (section 7) |
| `GRDR-BUS-0001` | `STREAM_FULL` | retryable | `resource_exhausted` | `BusError::Full` | Sensors back off and retry; check the stream's consumers if it persists |
| `GRDR-BUS-0002` | `OFFSET_REGRESSION` | internal | `internal` | `BusError::Regress` | |
| `GRDR-BUS-0003` | `BUCKET_OUT_OF_RANGE` | input | `invalid_argument` | `BusError::Bucket` | |
| `GRDR-BUS-0004` | `BUCKET_MAP_NOT_NEWER` | input | `failed_precondition` | `BusError::MapVersion` | |
| `GRDR-BUS-0005` | `MESSAGE_WITHOUT_ORGANISATION` | fatal | `data_loss` | `BusError::NoOrganisation` | Report it; a stored message lost its organisation header |
| `GRDR-REL-0001` | `CONSTRAINT_VIOLATION` | input | `failed_precondition` | `RelError::Constraint` | |
| `GRDR-REL-0002` | `SINGLE_ORGANISATION_STORE` | input | `failed_precondition` | `RelError::SingleOrganisation` | Use the `ha` profile for more than one organisation (D-34) |
| `GRDR-REL-0003` | `MIGRATION_ID_DUPLICATE` | internal | `internal` | `PlanError::Duplicate` | |
| `GRDR-REL-0004` | `MIGRATION_OUT_OF_ORDER` | internal | `internal` | `PlanError::Order` | |
| `GRDR-REL-0005` | `CONTRACT_WITHOUT_EXPAND` | internal | `internal` | `PlanError::ContractWithoutExpand` | |
| `GRDR-REL-0006` | `CONTRACT_TOO_EARLY` | internal | `internal` | `PlanError::ContractTooEarly` | |
| `GRDR-REL-0007` | `SCHEMA_TOO_NEW` | fatal | `failed_precondition` | `MigrationError::SchemaTooNew` | Install the release that wrote this schema, or a later one |
| `GRDR-EVENTS-0001` | `VIEW_NOT_REGISTERED` | input | `invalid_argument` | `EventsError::View` | |
| `GRDR-EVENTS-0002` | `COLUMN_NOT_REGISTERED` | input | `invalid_argument` | `EventsError::Column` | |
| `GRDR-EVENTS-0003` | `PREDICATE_INVALID` | input | `invalid_argument` | `EventsError::Predicate` | |
| `GRDR-EVENTS-0004` | `TIME_BOUNDS_INVALID` | input | `invalid_argument` | `EventsError::TimeBounds` | |
| `GRDR-EVENTS-0005` | `BATCH_SCHEMA_MISMATCH` | internal | `internal` | `EventsError::BatchSchema` | |
| `GRDR-EVENTS-0006` | `BATCH_UNREADABLE` | internal | `internal` | `EventsError::BatchUnreadable` | |

`MigrationError::Rel` carries a `RelError` and takes its code. The next-step column is the English source of each code's `fix` token for the codes an operator acts on; the item that registers a code writes the rest. A target that reports a fatal `STORE` code in its health shows Degraded, re-attempts at its next scheduled run and never in a retry loop, and that health code gets a runbook in `docs/runbooks/` (design/34).

A superseded fence and each store fault have one cause wherever they are found, so each has one code and one docs page (P17). Each code's page lists every variant bound to it, from the registry, and each area's index links the shared codes its enums use, so a Bus author finds `FENCE_SUPERSEDED` and `STORE_FULL` from the Bus page. Until the generator of #1636 publishes `/codes/<code>`, an adapter author reads this table and `schema/codes/<area>.toml`. Each item registers the entries its area constructs, because ARCH-017 requires every registered code to be constructed somewhere; the `STORE` entries are registered by #297, the first port item to land. The `GRDR-` prefix is the code namespace and does not change under a rebrand, so an embedder's support pages can quote codes.

### 12. Stability, adapter selection and later change
Stability:
- Both crates and `grdr_model::Monotonic` enter `surfaces.toml` as `experimental` (ADR-0020; design/03 section 7: every surface starts there), through the protected-change item #1688 R3 files after acceptance.
- `experimental` allows a break in any release, and every change still goes by RFC: a signature, a semantic, a variant, a suite case, the key layout, the identifier rule or the additional-data encoding is an amendment that names RFC 0002, and its pull requests name the amendment for `rfc-required` (design/30 section 3). One amendment may carry every change that is ready at the same time. `cargo public-api` and `cargo semver-checks` run against the class once the entry exists.
- What an adapter author can rely on: two versions describe the surface, the crates' semver and the kit version, and each server release names both. Every amendment is listed in the release notes, as `breaking` when it breaks. There is no compatibility window while the class is `experimental`. An adapter pins a kit version and moves when it moves to a new server release.
- The storage ports become `beta` when the server's packages freeze (design/03 section 7), by an RFC that changes `surfaces.toml` and sets the notice the beta class gives (ADR-0020). Its prerequisites are the deployment-scoped amendment of question 1, the Keys port RFC (design/21 K2) and the answer to question 2. The first embedding guide for storage has the same prerequisites.

Adapter selection and admission (P6, P14, design/03 E2):
- Adapters enter a build through `dist.toml`. The distribution build (#1593) generates, for each storage port, a dispatch type over the adapter types the distribution lists, which implements the port trait by delegation, and `server.profile` or the storage configuration keys pick the variant at start. The three named profiles are the default `dist.toml`. No adapter is named in `grdr-server` source, so adding one is data plus a build, never a code change in the server.
- An embedder or contrib author lists its own adapter crate in its own `dist.toml`, with the fixture environment its conformance test needs (a store the builder supplies, for example a container image or a connection setting). The distribution build runs that crate's conformance tests against the release's own `grdr-ports-testkit`, and admits the adapter only on a passing report it produced itself. A report the author wrote elsewhere is not evidence. Nothing is patched, nothing is forked, and nothing is sent to Loonaro. A contrib adapter is Tier 2 and never part of a named profile (design/03 section 6).
- The same build runs ARCH-027 and the port-implementation scan of section 2 over the resolved closure.

Amendments already expected, each with its item:
- Blobs: `put_versioned` and deployment-scoped objects (question 1); a streaming put (L-4); `ListPrefix::org` and `ListPrefix::class` with organisation removal and retention (R-3).
- Events: `retain`, `erase` (taking `&SingleCtx` only), `hold` and `manifest` (L-5, R-3); `QueryIr` nodes `Aggregate`, `Lookup`, `Hunt` and `Export` (L-6, L-7). `Export`'s projection names stable manifest columns only and it resumes through `Resume`, so there is no second cursor type. `LakeTable::Content` (L-3).
- Jobs: the methods of J-1, with a claimed job's organisation returned as a plain id and wrapped into `RecordedOrg` inside `grdr-ports`, and the step handle whose only write opener is `write_fenced`.
- Tenancy: the actor, delegation and purpose accessors, with the audit item.
- Deployment-scoped transactions (question 3) and the Keys port (design/21 K2).
- The endpoint ports (`SensorBackend` and `Actuator` #589, `SandboxBackend` #458, `JudgeBackend` #765, `DetectorPort` #1019, `DeclaredSource` #811, `Meter`) follow Rules 1, 2, 6, 7 and 8 and get their own RFCs.

### 13. Mechanisms
| Decision | Mechanism | Built by |
|---|---|---|
| Rule 1 | A third-party allow-list per crate in `architecture.toml`, read by the archlint graph rules, and a check that `grdr-ports-testkit` is in no layer 4 program's normal closure under any feature set a release or distribution build enables | #1580 reads the data; the entries are a protected change filed on acceptance |
| Rule 2 | The `+ Send` bound in every signature, checked by the compiler; a compile-time `Send` test for `retry::run` | Each item; #283 |
| Rules 3 and 4 | ARCH-015 restated: every method of a port trait takes or returns a tenant witness unless `architecture.toml` lists it as deployment-scoped, and no input type of a port method has an `OrgId` field except `MemberCursor` | A slice-0 lint item split from #1582, filed on acceptance |
| Minting boundary | No public constructor for `RecordedOrg` or `MemberCtx`; ARCH-027 `context-mint` over the two entry-point constructors; the port-implementation scan; both run on the workspace and on the distribution build's resolved closure | The same lint item; #1593 for the closure run |
| Lifecycle at minting | A case in each minting site: a suspended or shredded organisation is refused before minting | J-1 and the authentication middleware item, filed on acceptance |
| Rule 5 | Fence cases in the Jobs, Bus, Relational and Events suites: the paused fenced commit, the two-task holder, the concurrent and paused `subscribe` and `commit` cases | #298, #299, #300, #1535 |
| Rule 6 | `eval-architecture` checks, on every pull request that names RFC 0002 or an amendment, that each new public item has a reference implementation, a named case and a caller | Review, on each such pull request |
| Rule 7 | ARCH-019 | #1582 |
| Rule 8 | `Coded` (#280) with an exhaustive match, the registry (#278), ARCH-017 with its exemption list in `architecture.toml` | #280, #278, #1582; the list is a protected change |
| Rules 10 and 11 | `parse` of each identifier type; suite cases with an Arabic name, a Japanese name, an NFC and NFD pair, bidi controls (U+202E, U+2066 to U+2069), full-width Latin and Arabic-Indic digits in a date, all refused; ordering cases on byte-wise keys; the PostgreSQL fixture's `ja-JP` run | #313 (identifiers and dates), #297, #1535, the PostgreSQL adapter items |
| Archive with the lake commit | The crash cases at `FlushAfterSegments` and `FlushAfterLakeFiles`, and "every committed batch has its segment" | #1535 (cases), #1547 (adapter) |
| Union and coverage inside `execute` | The buffered-row, plan-flush-execute, flush-window, `WithoutTail` and limit-with-tail-down cases | #1535 |
| Cleanup grace | A `limits.toml` bound and a case in #1547 that a lister leaves another holder's uncommitted object alone | #1547 |
| Conformance kit | The `Fixture` runner with Crash and Differential cases, the bus stop points, `MemRelational`, and the how-to page | #281, #300 |
| Adapter selection and admission | Dispatch generated from `dist.toml`; the distribution build runs each listed adapter's conformance tests and admits only on its own passing report; a sample contrib adapter that builds and passes the kit | #1593 |
| Stability | The `surfaces.toml` entries, `rfc-required`, `cargo public-api`, `cargo semver-checks` | The protected-change item of #1688 R3 |
| Additional-data encoding | Vectors shared by #311 and #313 | #311, #313 |

### 14. Proposed changes to design documents and `architecture.toml`
Each lands through an issue whose write set names its file, after acceptance. design/21 is trust core, so its change takes the trust-core evaluators.

How D-35 and design/21 principle 2 are read. "No code path reads without a tenant context" is read as "no tenant data reaches module code without a tenant witness". Two deployment-scoped methods handle tenant data inside an adapter and `grdr-ports`: `Subscription::fetch`, whose messages module code receives only inside an `OrgBatch` (built by `fetch_batches`), and `Events::flush`, which hands no tenant data out. This is a reading of the spine, not a change to its text. If the council or an evaluator reads D-35 more strictly, the spine changes by its own RFC and this one waits for it.

- **design/20 section 3.** `Set(Vec<OrgId>, ReadOnly)` becomes `Set(DelegationSnapshotId, ReadOnly)`, as design/21 section 2 has it. "Every method takes 21's `TenantCtx`" becomes Rule 3. The Events row lists `append(ctx, fence, LakeBatch)`, `flush(fence, due, deadline)`, `plan(OrgRead, ...)` and `execute`, and names the methods that come later.
- **design/20 section 5.2** (refines). The archive segment travels in `LakeBatch` and is committed in the same lease-checked catalogue transaction. The commit unit is the organisation, all its due tables and segments together, which refines "a flush is per organisation and table". "Tail reads": the Events adapter unions buffered rows inside `execute`, through `StoreTail` in `distributed`; `query` no longer unions, and a missed tail is reported as `Coverage::WithoutTail`. The bus watermark the flush returns is named `committed_through`, apart from the sensor-facing `durable_through` of section 9. Unreferenced objects are removed after a grace read from their uuidv7 names.
- **design/20 section 7** (refines). `bus_consumer`'s `holder, fence` columns are stamped by `subscribe` in one compare-and-set that never lowers the fence, and checked by `commit` in one conditional update: the row-stamped form of Rule 5. That is what lets `bus.database` stay a separate instance. `commit` carries the detect snapshot key in the same row update, as the section already says.
- **design/20 section 8** (refines). "A claim takes a lease with a fencing token that every write checks": a job step's writes go through `write_fenced`, and every `acquire` issues a new token, also for the same holder.
- **design/21 section 2** (contradicted today). Principle 2: "a `TenantCtx` value required by every repository and store call" becomes "a tenant witness (RFC 0002 Rule 3) required by every repository and store call that touches tenant data; the deployment-scoped methods `architecture.toml` lists take none, and tenant data they handle reaches module code only inside a witness". Service framework row: the minting sites are the authentication middleware (from a verified token) and `grdr-ports` itself (a `RecordedOrg` from a stored message or claimed job, a `MemberCtx` from a delegation snapshot's ids); "Every method of the relational, lake, bus, blob and cache ports takes it" becomes Rule 3; a `Set` has no write methods, and its lake and blob reads go through `MemberCtx`. Lake and blobs row: "N per-organisation plans", each under a `MemberCtx` from `tenant::members`. Bus row: the consumer read of `bus_message` across organisations runs under a deployment binding that only the bus consumer path sets, and its rows reach module code only inside an `OrgBatch`; the binding's form is question 3, and this row is a placeholder until that RFC settles it.
- **design/03 section 2.** The ARCH-015 rule becomes the restatement in section 13. A new row adds ARCH-027 `context-mint` with the port-implementation scan, run on the workspace and on the distribution build's resolved closure.
- **design/03 section 6.** The adapter guide path `docs/extending/storage-adapter.md` becomes the how-to page of section 5. Contrib dispatch is generated from `dist.toml`, and the distribution build runs each listed adapter's conformance tests (section 12).
- **design/03 section 10, Errors.** "One enum per crate" becomes "one enum per crate, and one per port module in `grdr-ports`, which share `StoreFault`".
- **`architecture.toml`.** An empty third-party allow-list for `grdr-ports`; the Arrow crates of #1532 for `grdr-ports-testkit`, with the program-closure rule over every release and distribution feature set; the deployment-scoped list (`Leases`, `Migrator`, `Bus::subscribe`, `Bus::commit`, `Bus::lag`, `Bus::set_bucket_map`, `Subscription::fetch`, `Events::flush`); the Rule 4 exemption `MemberCursor`; the `context-mint` list of section 2 (the middleware modules of `api` and `ingest`, and `grdr-ports-testkit`); the ARCH-017 exemption list (`grdr_ports::retry::RetryError` and every error type of `grdr-ports-testkit`, each with its reason).

### 15. What each item changes
This RFC's text is normative. Under #1688 R4 each lead writes these changes back into its item before readying it. Every item's `cargo xtask` criterion becomes the `grdr-verify` gates or `cargo run --locked -p grdr-archlint -- check`, since ADR-0029 removed `xtask`.

- **#281**: `Clock: Send + Sync`, `monotonic` counts suspend time, and `ManualClock` is `Sync`. R8 becomes the `Fixture` runner of section 5, with the stop points, Crash and Differential cases and the report. It writes the how-to page.
- **#283**: R1 takes the bounds of section 4, with a compile-time `Send` test. AC-4 cites ARCH-018, a scan rule of #1582, not #1580.
- **#297**: `get` and `get_range` take `ReadPath`, `list` takes `ListPrefix` and builds keys with `ObjectKey::under`, `put_versioned` and `VersionId` go, `delete` gains the semantics and case of section 6, `ByteRange` and `PageLimit` gain accessors, and `BlobError` is `NotFound`, `Range`, `Store`. It registers the `STORE` codes. AC-3 waits on the slice-0 lint item.
- **#298**: R3 changes: every `acquire` that returns `Held` issues a new token, also for the same holder. R2's `LeaseState::Free` carries `last`, and a lease row is never deleted. `HolderId` gains `parse` and `as_str`. `JobsError` is `StaleFence` and `Store`; `LeaseName` parse errors are `IdentError`. `MemLeases` shares state and supports the shared hold of Rule 5. The cases of section 7 are added. The lead-core comment on ARCH-015 is replaced by the deployment-scoped entry.
- **#299**: `subscribe` takes claims and stamps the consumer row by compare-and-set, returning positions; `commit` takes the stream and a `Position` and is one conditional update; `poll` becomes `fetch(FetchLimit)` returning `StoredMessage`s, and `fetch_batches` builds `OrgBatch`; `BusError` follows section 8. The cases are those of section 8, including the concurrent `subscribe` and the commit inside the acquire-to-subscribe window.
- **#300**: `guard` goes, `write_fenced` arrives and `commit` of a fenced transaction is lease-checked by `FOR SHARE`; `RelError::Conflict` moves to `StoreFault::Conflict`; `snapshot_members` and `SingleOrganisation` are added; `Migrator::apply` uses the adapter's own transaction; codes `REL-0001` to `0007`. `MemRelational` and the suite run in this item.
- **#1535**: the largest change, so the lead should split it into the trait and types, and `MemEvents` with its suite. Reads take `OrgRead`; `append` takes a fence and a `LakeBatch` with its archive; `flush` is new with a deadline; rows are `ArrowIpc`; `LakeTable` loses `Content`; `QueryIr` keeps `Timeline` and `Scan` with order and `Resume`; `tail` goes and `execute` unions, reading the buffer before it fixes the snapshot; the ending carries `Completion` and `Coverage`; R6 goes. It now also requires #298, #299, #510 (the manifest type) and #1532 (Arrow for the test kit).
- **#312**: `RecordedJobOrg` becomes `RecordedOrg`, with no public constructor; `single_for_job` becomes `single_from_record`. `DelegationSnapshotId` is grdr-model's id, constructible like `OrgId`, which replaces R2's non-constructible snapshot id; the contexts stay non-constructible. `MemberCtx`, `OrgRead`, `MemberCursor` and `tenant::members` are added. The call-site list of section 2 replaces "a separate archlint item". R4 follows Rule 3. `From<SingleCtx> for TenantCtx` is added. It is blocked by the slice-0 lint item, and AC-5 needs a criterion that does not use `cargo xtask matrix-run`.
- **#313**: the `ident` module and Rule 10 are added; `TenantPath::prefix` becomes `ListPrefix::partition`; `ReadPath` and `ObjectKey::under` are added; `PathError::SetContext` and `PathError::Name` go; the AAD uses `archive.<lane>`; `Date` and `YearMonth` follow section 2; codes `TENANT-0001` to `0004`. AC-4 adds compile-fail cases for a `Set` prefix and a member write. AC-5 needs the same fix as #312.

Downstream: #311 follows section 2. #1546 moves flattening to the `store` target and builds `LakeBatch` with its archive. #1547 commits through `Events::flush` and removes unreferenced objects after the grace. #1554 takes `OrgRead`, so a `Set` context is a compile-time refusal. #1555 pages through `Resume` and shows "could not look" on `WithoutTail`. #1690 keeps its pseudonym test. #1593 builds the dispatch, runs each listed adapter's conformance tests and runs the closure scans. #1636's pages list every variant bound to a code.

## Surfaces changed
- `grdr-ports` (layer 2, public): modules `clock`, `entropy` (a re-export), `retry`, `ident`, `tenant` (`ctx`, `path`, `aad`) and `storage` (`blobs`, `jobs`, `bus`, `relational`, `events`, `PageLimit` and `StoreFault`). Class `experimental`.
- `grdr-ports-testkit` (layer 2, public): `ManualClock`, `SeededEntropy`, `block_on`, the conformance runner and fixtures, `MemBlobs`, `MemLeases`, `MemBus`, `MemRelational`, `MemEvents`, `ProbeRepo` and one suite per port. Class `experimental`.
- `grdr-model` (layer 1, public): `Monotonic`. Class `experimental`.
- The storage format of lake and blob objects: the key layout of section 2, the identifier rule of Rule 10 and the additional-data encoding `grdr-aad-v1`.
- Data and gate files, as proposals: seven code areas in `schema/codes`, entries in `surfaces.toml` and `architecture.toml`.
- No spine text and no protobuf package changes.

## Alternatives
- **Ship the surface `experimental` without an RFC, or one RFC per port.** Both rejected in the ruling on #1535: the class sets break rules, not the route, and the parts share the context, the error shape and the runner.
- **Re-export arrow-rs types from `grdr-ports`.** Zero-copy, but the daemon would link Arrow, and every arrow-rs major (up to one a quarter, https://github.com/apache/arrow-rs/blob/main/README.md, read 2026-11-20) would break the port and every partner adapter. Rejected for Arrow IPC, whose format has stayed backward compatible within version 1 since 1.0 (https://github.com/apache/arrow/blob/main/docs/source/format/Versioning.rst, read 2026-11-20). Brief 11 already recommends Arrow and Parquet as the event format.
- **A row and value model of our own in `grdr-ports`.** It invents a second columnar format beside Arrow (P10, P17) and adds a conversion to every adapter. Rejected.
- **`async-trait` or boxed `dyn` ports, for runtime selection.** A new dependency and an allocation per call. Selection by generated dispatch from `dist.toml` gives the same reach with neither. Rejected.
- **A generic server builder that an embedder calls from its own `main`.** It works, but every embedder writes and maintains composition code, and the release build would select by a second route. Rejected for the one `dist.toml` route design/03 already names.
- **One fence form everywhere, lease-checked.** The bus tables may live in a separate database from the lease table (design/20 section 7), so the bus cannot check the lease inside its own transaction. Rejected for two named forms.
- **SERIALIZABLE as a lease-checked form.** A read of the lease row followed by another holder's `acquire` is a single read-write dependency, which serialisable snapshot isolation does not abort, so the stale commit lands (round 2 evidence on PostgreSQL 17). Rejected; only a lock on the lease row counts.
- **Storage-side fencing on the bus with the token stored at first commit, as #299 had it.** It leaves a window in which the old holder commits after the new one starts from an older position, and the new holder's correct offset then reads as `Regress`. Rejected for the compare-and-set stamp at `subscribe`.
- **The same token for a re-acquiring holder, as #298 R3 had it.** Every task of one process shares the token, so a stalled task and its replacement both hold a current fence. Rejected for a new token on every acquisition.
- **`guard(&mut self, &Fence)` or `commit_fenced` chosen at commit time.** A failed guard leaves the transaction usable, and a commit-time choice lets code holding a transaction skip the check. Rejected for `write_fenced`, which binds the fence when the transaction opens.
- **`tail` as a port method that callers union.** A caller that forgets the union, or drops a failed tail, shows "nothing happened" when the product could not look (P9). Rejected for the union inside `execute`.
- **One `Partial` reason for both a hit limit and a missed tail.** One of the two is lost: either paging ends `Complete` with tail rows missing, or a long read against a down tail cannot be paged. Rejected for `Completion` and `Coverage` side by side, with coverage carried in `Resume`.
- **Per-organisation token exchange for provider hunts.** It gives every hunt a write-capable `SingleCtx` per customer. Rejected for `MemberCtx`.
- **Adapters mint `RecordedOrg` and `MemberCtx` through public hidden constructors.** Every adapter, contrib included, becomes a minting site that a workspace lint cannot see. Rejected: adapters return plain ids and `grdr-ports` mints.
- **An unpublished minting crate restricted by a dependency-graph rule.** It works for any closure, but adds a crate and a same-layer edge to protect two constructors that only the middleware calls. Rejected for the closure-wide scan, kept as the fallback if that scan cannot be built.
- **Non-ASCII identifiers with NFC, a bidi-control refusal and a byte bound.** It works but puts Unicode normalisation into the storage format, and every adapter and file system must agree on it byte for byte. Rejected: names people choose go in columns.
- **A per-port copy of the store fault codes.** Twelve codes for one set of causes, each with a page. Rejected for `StoreFault` and the `STORE` area.
- **Declare `retain`, `erase`, `hold`, `manifest`, `put_versioned` and the other query nodes now, returning `NotSupported`.** An adapter could pass the kit without erasure. Rejected under Rule 6.
- **One error enum for the whole crate,** as design/03 section 10 reads today. An adapter crate implements one port and would return variants that cannot happen. Rejected.

## Drawbacks
- Every append and every result batch is encoded and decoded once as Arrow IPC.
- `MemEvents` needs the Arrow crates, so the test kit builds more slowly and #1535 waits on #1532 and splits.
- The storage traits are not dyn-compatible, so the distribution build must generate a dispatch type per port before a contrib adapter can be selected.
- Two fence forms are more to learn than one, and the row-stamped form trusts its callers' tokens, so a fabricated token can turn real holders away.
- A new token on every acquisition means a process that re-acquires by mistake invalidates its own earlier fence and loses that work to a retry.
- The Events adapter carries the union, its tail source and the coverage rule, so it is larger than a plain lake reader.
- The distribution build needs each listed adapter's store to run its conformance tests, which makes a contrib build heavier than a plain compile.
- The `Fixture` trait asks an adapter author for stop and fault hooks, which a small adapter may find heavy; `NotApplicable` keeps the bar honest without hiding what was not run.
- Each deferred method and node costs an amendment RFC when its item arrives.

## Unresolved questions
1. **Deployment-scoped objects.** `state-log/`, `ephemeral/detect/` and the content repository have no organisation, so they cannot be `TenantPath` values. Lean: a separate deployment-scoped trait over a closed `DeploymentPath`, with `put_versioned`, listing and removal, never an org-less `TenantPath`. Settled by an amendment drafted when R-1 or D-1 is specified. It is a prerequisite of the filesystem Blobs adapter item and of the `embedded` profile's first-run slice, so neither assumes it.
2. **Where module repository traits live.** In `grdr-ports`, every repository change is an RFC. In an unpublished layer 2 crate such as `grdr-repos`, as `grdr-messages` does, it costs one RFC for the crate and its same-layer edge. Lean: the second, with class `internal`: no stability promise to an outside relational adapter until an RFC gives one. An embedder can implement the port and `ProbeRepo` today, but not the module repositories with any promise. Settled before S-2's first module repository.
3. **The deployment-scoped transaction.** Runtime settings and the operator realm (D-70, design/20 O-3 and O-4) need one, with a witness from the operator realm (design/21 O1). So does the bus log's consumer read: `fetch` reads `bus_message` across organisations, and the application role has no `BYPASSRLS`, so the bus tables need a deployment binding that only the bus adapter's consumer path can set. The bus adapter writes its own tables inside its crate (ARCH-015 allows SQL there), so it does not need this through the Relational port, but design/21 section 2 must state the binding (the placeholder in section 14). Lean: a separate database role for the bus consumer path with a policy on the bus tables only. Settled by its own RFC with O-3, which is a prerequisite of the log Bus adapter item.
4. **The slice-0 surfaces of `grdr-model` and `grdr-schema`** (#18, #278, #279, #282, #284). These signatures name their types (`OrgId`, `DelegationSnapshotId`, `Timestamp`, `Lane`, `SessionId`, `DeviceId`, `Epoch`, `Seq`, `RetryPolicy`, the column manifest). Settled by the RFC of #1710.

## Review
Round 1, on `eb9770d`:
- `eval-architecture`: fail, one blocker and seven majors. https://github.com/416rehman/Guardrails/issues/1688#issuecomment-7049670935
- Seat 1 (solo developer), one blocking finding. https://github.com/416rehman/Guardrails/issues/1688#issuecomment-7049606175
- Seat 2 (IT admin), none blocking. https://github.com/416rehman/Guardrails/issues/1688#issuecomment-7049569186
- Seat 3 (SOC analyst), two blocking. https://github.com/416rehman/Guardrails/issues/1688#issuecomment-7049587836
- Seat 4 (MSP operator), one blocking. https://github.com/416rehman/Guardrails/issues/1688#issuecomment-7049551342
- Seat 5 (OEM partner), one blocking. https://github.com/416rehman/Guardrails/issues/1688#issuecomment-7049529023
- Seat 6 (privacy), none blocking. https://github.com/416rehman/Guardrails/issues/1688#issuecomment-7049492463
- Seat 7 (contributor), two blocking. https://github.com/416rehman/Guardrails/issues/1688#issuecomment-7049511922
- Seat 8 (simplicity), none blocking. https://github.com/416rehman/Guardrails/issues/1688#issuecomment-7049473301
- Seat 9 (international), one blocking. https://github.com/416rehman/Guardrails/issues/1688#issuecomment-7049626710
- Round 2 dispositions: https://github.com/416rehman/Guardrails/issues/1688#issuecomment-7050072771

Round 2, on `6aae3b7`:
- `eval-architecture`: fail, no blocker, eight majors and nine minors. https://github.com/416rehman/Guardrails/issues/1688#issuecomment-7050348217

Round 3: pending, on this revision. The dispositions are on #1688.

## Decision
Pending.
