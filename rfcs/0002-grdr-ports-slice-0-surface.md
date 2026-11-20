RFC: 0002
Title: The slice-0 public surface of grdr-ports and grdr-ports-testkit
Author: chief-architect
Harness: Claude Code
Model: claude-opus-5-5
State: Draft
Design issue: #1688
Spine: D-05, D-33, D-34, D-35, D-57, D-61, P5, P6, P8, P9, P10, P14, P15, P17 (no spine text changes)
Surfaces: public crates `grdr-ports` and `grdr-ports-testkit`, and the `grdr-model` type `Monotonic`
Decision record: none yet

Comments go on the design issue, so commenting needs no account on any service other than the code host. A security fix under embargo (D-62) may change a public surface without an RFC; open a retroactive RFC when the fix is disclosed.

## Summary
Slice 0 adds the first public types and traits to `grdr-ports` and `grdr-ports-testkit`: the `Clock` and `Entropy` ports, the retry executor, the tenant context and object paths, the Blobs, Jobs (leases), Bus, Relational and Events ports, and the conformance runner with a reference adapter and a suite per port. This RFC adopts the signatures the nine items specify (#281, #283, #297, #298, #299, #300, #1535, #312, #313), sets nine rules every port follows, changes signatures where the items conflict with design/20, design/21 or each other, assigns the error codes, and enters both crates as `experimental`. It changes no spine text.

## Motivation
`grdr-ports` is the seam P6 and P14 rest on. The release-gating adapters of each profile and every contrib adapter meet the product only through these traits, and they are admitted only by passing the test kit (design/03 extension points; design/20 extension point 1). Every server target in slice 0 calls them, and `grdr-daemon` links the crate for `Clock`, `Entropy` and `retry::run`. A public crate changes only by RFC (D-61, design/30 R7), and `experimental` sets the break rules, not the route (ruling on #1535).

The nine items were specified one at a time. Read together they disagree in places a later adapter would turn into a defect:

- #299 R6 refuses a bus commit only once a greater fence has committed; #298 R8 and #300 R3 refuse a fence once a greater token has been issued. Under #299's rule a holder that paused past expiry can still commit.
- #1535 puts no fence on the lake write path, although design/20 sections 2 and 5.2 require every catalogue commit to carry the partition's fence, and it gives `store` no way to learn which bus offset is durable.
- `retry::run` takes `&mut dyn Entropy`, so its future is not `Send` and cannot run on a tier's multi-threaded runtime, which #297 R12 and its siblings require of every port call.
- `Unavailable { retryable: bool }` (#297, #299, #300, #1535) gives one variant two classes, while design/03 section 10 binds each variant to one registered code with one class.
- #1535 R1 lets a `Set` context reach a lake read that design/21 section 2 always plans per organisation, and #313 R4 reports at run time a misuse the compiler can refuse.
- #1535 declares methods (`retain`, `erase`, `hold`, `manifest`) and query nodes with no semantics and no reference implementation, so an adapter could pass the kit without implementing erasure.
- No item fixes how Events rows cross the port, and that decides whether `grdr-ports`, and with it the daemon, links Arrow.

If nothing changes, nine implementers build against these signatures and the first adapter items (#1546, #1547, #1554) inherit the conflicts.

## Design

### 1. Rules for every port
Rule 1. **Dependencies.** `grdr-ports` depends on `grdr-model` and `grdr-schema` and nothing else, no third-party crate included. The privileged daemon links it and layer 2 has no Cargo features (design/03 section 8), so whatever it links is in the daemon's closure. `grdr-ports-testkit` may also depend on the Arrow crates #1532 admits, at the same pins, for `MemEvents`. It is a test dependency: it never appears in the normal-dependency closure of a layer 4 program built with its default features, though an adapter may enable it behind its own `testkit` feature (#300 R9).

Rule 2. **Async shape.** Every port trait has `Send + Sync` as supertraits. A method that reaches a back end is declared `fn name(&self, ...) -> impl Future<Output = Result<T, E>> + Send`, which an implementation may write as an `async fn`. A stream is a pull method of the same shape, not a `Stream` trait. No `async-trait`, no boxed futures, no `futures` crate. The storage traits are therefore not dyn-compatible, and `grdr-server` dispatches statically per profile (design/03 E2), which suits a fixed set of three profiles. `Entropy` is synchronous and stays dyn-compatible, because `Engine::step` takes `&mut dyn Entropy` (design/03 section 3).

Rule 3. **Tenant witnesses.** A tenant witness is a value only a tenant context can produce: `&SingleCtx`, `&TenantCtx`, a `TenantPath`, a `ListPrefix`, an Events plan, a relational transaction, a bus `OrgBatch`. Every port method that takes tenant data in takes a witness, derived from a `SingleCtx` when it writes. Every method that returns tenant data takes a witness or returns the data inside one. A read takes the widest context its store can bind: `&TenantCtx` for the relational port, whose row-level security binds a `Set` through `delegation_snapshot`; `&SingleCtx` for Events and Blobs, whose prefixes and keys are per organisation and whose cross-organisation reads are one plan per organisation (design/21 section 2). A method that does neither works on a deployment-scoped resource, one that belongs to no organisation (leases, bus partitions and offsets, bucket maps, migrations, a partition's flush). It takes no context, and `architecture.toml` lists it as deployment-scoped. This is how ARCH-015 reads design/21's "every method takes `TenantCtx`".

Rule 4. **No organisation in inputs.** No input type of a port method has an organisation field. The organisation comes from the context and the adapter writes it: the bus `org` header (#299 R3), the lake's `organisation_id` column (section 10), the `org=` segment of every path (#313 R1).

Rule 5. **Fences.** A fence is current while the lease it names has issued no greater token (#298 R8). Every fenced commit checks this inside its own transaction: `Leases::check`, `WriteTx::guard`, `Bus::commit` and `Events::flush`. A superseded fence has one code wherever it is found (section 11).

Rule 6. **Nothing without a reference and a case.** Every method and every enum variant on the surface has a reference implementation in the test kit and at least one named conformance case. A method or query node whose semantics are not yet specified is not declared; it enters with its item by amendment (section 12).

Rule 7. **Bounds are parameters.** Page and fetch limits, lease terms, query limits, stream byte bounds, flush thresholds and bucket maps are values the caller passes or the adapter is built with, read from `limits.toml` (#279). No port type or reference adapter holds a bound (ARCH-019).

Rule 8. **Errors.** Each port module has one error enum, and `Coded` (#280) binds each variant to one registered code in the port's area (section 11). `Unavailable` is always retryable; a permanent refusal by the back end (permission, missing bucket or database) is `Refused`. Callers act on the code's class, never on the variant, so error enums are `#[non_exhaustive]`. Errors carry structural values only (names, keys, offsets, ids) and implement `LogSafe` (#284). `RetryError<E>` has no code: its caller maps it to the code of the subsystem that failed. Test kit types carry no code either.

Rule 9. **Exhaustive data enums.** `TenantCtx`, `Scope`, `StorageClass`, `Partition`, `Stream`, `LakeTable`, `QueryIr`, `Step`, `ExpandKind` and `PartialReason` are exhaustive, so a new variant fails every adapter's build until it handles it. Adding one is an amendment with its suite cases.

Data classes (P8): every type on the surface is `structural`, except payload bytes (blob objects, bus payloads, `ArrowIpc`), which carry the classes of what they hold and are never logged, and scan positions and predicate literals, which carry their columns' classes. Assurance effect (P1): none.

### 2. Tenancy (#312, #313)
Adopted as #312 R1 to R8 and #313 R1 to R7, with the changes below. The module stays trust core.

```rust
pub enum TenantCtx { Single(SingleCtx), Set(SetCtx) }
pub enum Scope<'a> { Single(&'a OrgId), Set(&'a DelegationSnapshotId) }
impl TenantCtx { pub fn scope(&self) -> Scope<'_>; }
impl From<SingleCtx> for TenantCtx;

impl TenantMinter {
    pub fn single_from_token(token: &VerifiedAudience) -> SingleCtx;
    pub fn set_from_exchange(token: &VerifiedWorkbenchToken) -> SetCtx;
    pub fn single_for_job(org: &RecordedOrg) -> SingleCtx;
}

impl TenantPath {
    pub fn new(ctx: &SingleCtx, class: StorageClass, partition: Partition, name: ObjectName) -> Result<TenantPath, PathError>;
}
impl ListPrefix {
    pub fn org(ctx: &SingleCtx) -> ListPrefix;
    pub fn class(ctx: &SingleCtx, class: StorageClass) -> ListPrefix;
    pub fn partition(ctx: &SingleCtx, class: StorageClass, partition: Partition) -> Result<ListPrefix, PathError>;
}
impl Aad { pub fn for_object(path: &TenantPath, key_id: &KeyId) -> Aad; }
```

- `RecordedJobOrg` becomes `RecordedOrg`: the organisation recorded on a job row or on a bus message's `org` header, both written earlier under a `SingleCtx`. Partition consumers run under the job runner's leases (design/20 section 2), so the job runner stays the one entry point besides the authentication middleware that design/21 names. `OrgBatch` exposes `&RecordedOrg`, never a bare `OrgId`.
- The `..._from_verified_entry_point` constructors of the three input types are the boundary, and `#[doc(hidden)]` is not access control. ARCH-027 `context-mint` fails a call outside the modules `architecture.toml` lists: the authentication middleware of `api` and `ingest`, the job runner, the jobs and bus adapter crates, and `grdr-ports-testkit`, which is safe under Rule 1 because no program links it.
- `ListPrefix` replaces `TenantPath::prefix(&TenantCtx)`. It renders `org=<id>/`, `org=<id>/class=<class>/` (`class=archive/lane=<lane>/` for archive) or the partition directory, so retention, compaction cleanup and restore list one partition instead of a whole organisation. `PathError::SetContext` goes away: a `Set` context cannot reach a prefix.
- The additional data is #313 R5 and #311 R8 (`grdr-aad-v1`, one `0x00`, four length-prefixed fields) with one change: the class field of `Archive { lane }` is `archive.<lane>`, for example `archive.decision`. The lane decides retention (13 months for `decision`, 184 days for the others) and reduction, so a segment must not authenticate under another lane's path.
- `Lane` is grdr-model's lane type (#18), not a second enum (P17). `Date` and `YearMonth` are validated UTC calendar values in `grdr_ports::tenant::path`.
- The contexts are `Send + Sync`; they hold ids only.
- The object key layout and this encoding are a storage format. Changing either needs an RFC, a new tag (`grdr-aad-v2`), readers that accept the old tag for the longest retention (13 months) and a rewrite job.

### 3. Clock and Entropy (#281)
Adopted as #281 R1 to R10. `grdr_model::Monotonic` (R1) is part of this surface.

```rust
pub trait Clock: Send + Sync {
    fn now(&self) -> Timestamp;
    fn monotonic(&self) -> Monotonic;
    fn sleep_until(&self, deadline: Monotonic) -> impl Future<Output = ()> + Send;
}
pub use grdr_model::Entropy;
```

`ManualClock` must be `Sync` to meet the supertraits. `Clock` has no error type; the overflow errors of `ManualClock` belong to the test kit.

### 4. Retry executor (#283)
Adopted as #283 R1 to R9, with bounds that make the future `Send`:

```rust
pub async fn run<T, E, C, R, F, Fut>(
    policy: &RetryPolicy, state: &mut RetryState, clock: &C, entropy: &mut R, op: F,
) -> Result<T, RetryError<E>>
where
    C: Clock, R: Entropy + Send + ?Sized,
    F: FnMut() -> Fut + Send, Fut: Future<Output = Attempt<T, E>> + Send,
    T: Send, E: Send;
```

`RetryState`, `Attempt` and `RetryError` live in `grdr_ports::retry`. `RetryPolicy`, `RetryBudget` and `Breaker` are grdr-model types (#282) that this RFC names but does not adopt (question 4).

### 5. Conformance runner (#281 R8)
Adopted, with three rules:

- The cases of a suite share one adapter instance. Each case isolates itself with organisation ids, object names and lease names drawn fresh from `SeededEntropy`, and none assumes an empty store, so a suite runs against a shared PostgreSQL database or bucket.
- A suite whose port checks fences (Bus, Events, the relational guard) takes the lease store in its fixture, and the reference adapters hold a handle to the same `MemLeases`.
- A report's kit version is the test kit crate's version. A change to any case is a new version, and an adapter states the version it passed.

### 6. Blobs (#297)
```rust
pub trait Blobs: Send + Sync {
    fn put(&self, path: &TenantPath, bytes: Vec<u8>) -> impl Future<Output = Result<ObjectMeta, BlobError>> + Send;
    fn put_versioned(&self, path: &TenantPath, bytes: Vec<u8>) -> impl Future<Output = Result<VersionId, BlobError>> + Send;
    fn get(&self, path: &TenantPath) -> impl Future<Output = Result<Vec<u8>, BlobError>> + Send;
    fn get_range(&self, path: &TenantPath, range: ByteRange) -> impl Future<Output = Result<Vec<u8>, BlobError>> + Send;
    fn list(&self, prefix: &ListPrefix, after: Option<&ObjectKey>, limit: PageLimit) -> impl Future<Output = Result<Page, BlobError>> + Send;
    fn delete(&self, path: &TenantPath) -> impl Future<Output = Result<(), BlobError>> + Send;
}
```

Semantics are #297 R2 to R12. Changes: `list` takes a `ListPrefix`, and `BlobError` is `NotFound`, `Range`, `Unavailable`, `Refused`, `Integrity`. Whole objects pass as `Vec<u8>`, which fits slice 0's flushes (32 MB); a streaming put is an amendment with L-4, whose outputs reach 1 GiB. Deployment-scoped objects (`state-log/`, `ephemeral/detect/`, the content repository) are not on this trait (question 1). Suite `storage::blobs::conformance`, reference adapter `MemBlobs`.

### 7. Jobs: leases (#298)
```rust
pub trait Leases: Send + Sync {
    fn acquire(&self, name: &LeaseName, holder: &HolderId, term: LeaseTerm) -> impl Future<Output = Result<Acquire, JobsError>> + Send;
    fn renew(&self, lease: &Lease, term: LeaseTerm) -> impl Future<Output = Result<Renew, JobsError>> + Send;
    fn release(&self, lease: &Lease) -> impl Future<Output = Result<(), JobsError>> + Send;
    fn check(&self, fence: &Fence) -> impl Future<Output = Result<(), JobsError>> + Send;
}
```

Semantics are #298 R1 to R12. `Leases` is deployment-scoped (#298 R11, Rule 3), which settles the ARCH-015 question #298 put to lead-core. `JobsError` is `Name`, `StaleFence`, `Unavailable`, `Refused`. `MemLeases` clones cheaply and shares its state, so the other reference adapters can check fences against it. The tenant-scoped methods (`enqueue`, `claim`, `step`, `complete`) are J-1's amendment.

### 8. Bus (#299)
```rust
pub trait Bus: Send + Sync {
    type Subscription: Subscription;
    fn append(&self, ctx: &SingleCtx, stream: Stream, bucket: VirtualBucket, messages: Vec<Outgoing>) -> impl Future<Output = Result<Appended, BusError>> + Send;
    fn subscribe(&self, group: &ConsumerGroup, stream: Stream, partitions: &[PartitionId]) -> impl Future<Output = Result<Self::Subscription, BusError>> + Send;
    fn commit(&self, group: &ConsumerGroup, partition: PartitionId, offset: Offset, fence: &Fence) -> impl Future<Output = Result<(), BusError>> + Send;
    fn lag(&self, group: &ConsumerGroup, stream: Stream) -> impl Future<Output = Result<Vec<PartitionLag>, BusError>> + Send;
    fn set_bucket_map(&self, stream: Stream, map: BucketMap) -> impl Future<Output = Result<(), BusError>> + Send;
}
pub trait Subscription: Send {
    fn fetch(&mut self, max: FetchLimit) -> impl Future<Output = Result<Vec<OrgBatch>, BusError>> + Send;
}
```

Semantics are #299 R1 to R13, with these changes:

- `commit` refuses a superseded fence by Rule 5, checked in the commit's transaction. With #299's rule a holder that paused past expiry commits before the new holder's first commit, and the new holder's correct, lower offset then reads as `Regress`. Scenario (a) of R12 becomes: once the second holder acquires, the first holder's commit fails `StaleFence` whether or not the second has committed.
- `Subscription::poll` becomes `fetch`, so it is not mistaken for `Future::poll`, and its bound is a `FetchLimit` (Rule 7).
- `OrgBatch::org` returns `&RecordedOrg` (section 2).
- `BusError` is `Full`, `Regress`, `Bucket`, `MapVersion`, `StaleFence`, `NoOrganisation` (a stored message without an `org` header, which design/21 section 2 rejects), `Unavailable`, `Refused`.
- `subscribe`, `commit`, `lag` and `set_bucket_map` are deployment-scoped.

Suite `storage::bus::conformance`, reference adapter `MemBus` holding a `MemLeases` handle.

### 9. Relational (#300)
```rust
pub trait Relational: Send + Sync {
    type ReadTx: ReadTx;
    type WriteTx: WriteTx;
    fn read(&self, ctx: &TenantCtx) -> impl Future<Output = Result<Self::ReadTx, RelError>> + Send;
    fn write(&self, ctx: &SingleCtx) -> impl Future<Output = Result<Self::WriteTx, RelError>> + Send;
}
pub trait ReadTx: Send {}
pub trait WriteTx: Send {
    fn guard(&mut self, fence: &Fence) -> impl Future<Output = Result<(), RelError>> + Send;
    fn commit(self) -> impl Future<Output = Result<(), RelError>> + Send;
}
pub trait Migrator: Send + Sync {
    fn apply(&self, plan: &MigrationPlan, fence: &Fence) -> impl Future<Output = Result<Applied, MigrationError>> + Send;
    fn check_compatible(&self, plan: &MigrationPlan, binary_release: Release) -> impl Future<Output = Result<(), MigrationError>> + Send;
}
```

Semantics are #300 R1 to R11, with these changes:

- Repositories are traits implemented on an adapter's transaction types, so the transaction is the witness. Where module repository traits live is question 2; `ProbeRepo` stays in the test kit.
- A dropped `WriteTx` makes none of its writes visible. The adapter may finish the rollback when the connection is next used, because `Drop` cannot await.
- `RelError` is `StaleFence`, `Conflict` (always retryable), `Constraint`, `Unavailable`, `Refused`. `PlanError` and `MigrationError` take codes (section 11); `MigrationError::Rel` carries a `RelError` and its code. `Release` is the release number of `MigrationId`.
- `Migrator` is deployment-scoped. Tables without an organisation (runtime settings and the operator realm, D-70) need a deployment-scoped transaction, which this trait does not offer (question 3).

### 10. Events and QueryIr (#1535)
```rust
pub trait Events: Send + Sync {
    type Plan: Send;
    type Results: ResultStream;
    fn append(&self, ctx: &SingleCtx, fence: &Fence, batch: LakeBatch) -> impl Future<Output = Result<Appended, EventsError>> + Send;
    fn flush(&self, fence: &Fence, due: FlushDue) -> impl Future<Output = Result<Flushed, EventsError>> + Send;
    fn plan(&self, ctx: &SingleCtx, query: QueryIr, limits: QueryLimits) -> impl Future<Output = Result<Self::Plan, EventsError>> + Send;
    fn execute(&self, plan: Self::Plan) -> impl Future<Output = Result<Self::Results, EventsError>> + Send;
    fn tail(&self, ctx: &SingleCtx, query: QueryIr, limits: QueryLimits) -> impl Future<Output = Result<Self::Results, EventsError>> + Send;
}
pub trait ResultStream: Send {
    fn next(&mut self) -> impl Future<Output = Result<Next, EventsError>> + Send;
}

pub enum Next { Batch(ArrowIpc), End(Completion) }
pub enum Completion { Complete, Partial { reason: PartialReason } }
pub enum PartialReason { Rows, Bytes, WallTime }

pub struct LakeBatch { pub table: LakeTable, pub source: Offset, pub rows: ArrowIpc }
pub enum LakeTable { Decision, Activity }
pub enum FlushDue { Thresholds, All }
pub struct Flushed { pub durable_through: Option<Offset> }

pub enum QueryIr {
    Timeline { root_session_id: SessionId, time: TimeBounds },
    Scan {
        view: ViewName, time: TimeBounds, predicates: Vec<Predicate>,
        projection: Vec<ColumnName>, order: ScanOrder, after: Option<RowPosition>,
    },
}
```

Semantics are #1535 R1 to R9, with these changes:

- **Rows cross the port as Arrow IPC.** `ArrowIpc` is an opaque byte newtype holding one Arrow IPC stream: Arrow columnar format 1.x, a schema message and then record batches, with no dictionary deltas and no body compression. Its schema is the lake column manifest (#510) of the batch's table, or of the plan's projection. The contract is therefore the Arrow format, a published standard (P10), and not an arrow-rs release. Within format version 1 the Arrow project guarantees that newer libraries read what older ones wrote, while arrow-rs ships a breaking major "at most once a quarter" (sources under Alternatives). Re-exporting arrow-rs types would make each of those majors a `grdr-ports` break and put Arrow in the daemon's closure (Rule 1). The cost is one encode and one decode per batch, bounded by `QueryLimits` on reads and small beside Parquet encoding and zstd on writes.
- **Callers flatten.** `LakeBatch.rows` arrive already flattened by the column manifest and with no `organisation_id` column (Rule 4); the adapter adds that column from `ctx` and refuses a batch that carries one. Every Events adapter receives the same columns, so the flattening of #1546 R2 is code in the `store` target, not part of `grdr-lake` (P17).
- **The write path is fenced.** `append` takes the fence of the `store` lease on the bus partition the rows came from and buffers them. A row whose key `(device, epoch, lane, seq)` is already appended or committed adds nothing (#1535 R2); `Appended` counts added and duplicate rows. `flush` commits the buffers that are due, in one fenced commit per organisation and table: `Thresholds` takes those past the size or age the adapter was built with, and `All` takes every buffer, at the bus retention bound and on lease release. It returns `durable_through`: every batch appended under this fence whose `source` is at or below it is committed, so `store` can commit the bus offset to that value (design/20 section 5.2). A flush under a superseded fence fails `StaleFence` and drops that fence's buffers (#1547 R5); the bus delivers the rows again to the new holder. `MemEvents` commits at `append` and keeps no buffer.
- **No content table yet.** `LakeTable` has no `Content` variant until content sealing (L-3) exists, so no path can write content unsealed (D-51; #1546 R5).
- **Two query nodes.** `QueryIr` has `Timeline` and `Scan`. `Scan` gains the time bounds, order and position #1555 needs to page newest first: `ScanOrder` is ascending or descending on `(observed_time, device_id, epoch, lane, seq)`, and `after` is the position of the last row returned. A `Predicate` is a registered column, a comparison (`Eq`, `Ne`, `Lt`, `Le`, `Gt`, `Ge`, `In`) and literal values. A view or column the adapter's manifest does not register is a plan error (#1535 R3). `Aggregate`, `Lookup`, `Hunt` and `Export` enter by amendment with L-6 and L-7, each with its reference implementation and cases (Rule 6).
- **Tail answers the same query.** `tail` takes the same `QueryIr` and limits as `plan` and answers over rows appended but not yet flushed. The caller unions and de-duplicates on `(device, epoch, lane, seq)` (#1535 R5). In `distributed` the adapter answers it through `grdr.internal.v1alpha1.StoreTail` (design/20 section 5.2).
- **Retention methods wait for their semantics.** `retain`, `erase`, `hold` and `manifest` are not declared, and #1535 R6 goes. They arrive with L-5 and R-3 as required methods with their semantics and cases. A `NotSupported` default would let an adapter pass the kit without erasure (D-57).
- `EventsError` is `View`, `Column`, `BatchSchema`, `BatchUnreadable`, `StaleFence`, `Unavailable`, `Refused`, `Integrity`.
- The adapter takes the column manifest when it is built. The manifest type is #510's, in `grdr-schema`, so the suite builds a fixture manifest of the same type.

Suite additions to #1535 R8: a flush after another holder acquired fails `StaleFence`; `durable_through` never covers an unflushed batch; a batch with an `organisation_id` column is refused; `Scan` order and `after` paging; a `Set` context cannot reach `plan` or `tail` (compile-fail doctest).

### 11. Error codes
Areas for `schema/codes/areas.toml` (#278 R1):

| Area | Subsystem | Owner |
|---|---|---|
| `TENANT` | Tenant context and object paths | design/21 |
| `BLOBS` | Blob store (Blobs port) | design/20 |
| `JOBS` | Jobs and leases (Jobs port) | design/20 |
| `BUS` | Event bus (Bus port) | design/20 |
| `REL` | Relational store and schema migrations | design/20 |
| `EVENTS` | Event store (Events port) | design/20 |

| Code | Reason | Class | Connect | Bound by |
|---|---|---|---|---|
| `GRDR-TENANT-0001` | `OBJECT_NAME_INVALID` | input | `invalid_argument` | `PathError::Name` |
| `GRDR-TENANT-0002` | `PARTITION_FOR_CLASS` | input | `invalid_argument` | `PathError::PartitionForClass` |
| `GRDR-TENANT-0003` | `DATE_INVALID` | input | `invalid_argument` | `PathError::Date` |
| `GRDR-TENANT-0004` | `KEY_ID_INVALID` | input | `invalid_argument` | `PathError::KeyId` |
| `GRDR-BLOBS-0001` | `OBJECT_NOT_FOUND` | input | `not_found` | `BlobError::NotFound` |
| `GRDR-BLOBS-0002` | `RANGE_OUT_OF_BOUNDS` | input | `out_of_range` | `BlobError::Range` |
| `GRDR-BLOBS-0003` | `STORE_UNAVAILABLE` | retryable | `unavailable` | `BlobError::Unavailable` |
| `GRDR-BLOBS-0004` | `STORE_REFUSED` | fatal | `failed_precondition` | `BlobError::Refused` |
| `GRDR-BLOBS-0005` | `OBJECT_INTEGRITY` | fatal | `data_loss` | `BlobError::Integrity` |
| `GRDR-JOBS-0001` | `LEASE_NAME_INVALID` | input | `invalid_argument` | `JobsError::Name` |
| `GRDR-JOBS-0002` | `FENCE_SUPERSEDED` | fatal | `aborted` | `StaleFence` of `JobsError`, `BusError`, `RelError`, `EventsError` |
| `GRDR-JOBS-0003` | `STORE_UNAVAILABLE` | retryable | `unavailable` | `JobsError::Unavailable` |
| `GRDR-JOBS-0004` | `STORE_REFUSED` | fatal | `failed_precondition` | `JobsError::Refused` |
| `GRDR-BUS-0001` | `STREAM_FULL` | retryable | `resource_exhausted` | `BusError::Full` |
| `GRDR-BUS-0002` | `OFFSET_REGRESSION` | internal | `internal` | `BusError::Regress` |
| `GRDR-BUS-0003` | `BUCKET_OUT_OF_RANGE` | input | `invalid_argument` | `BusError::Bucket` |
| `GRDR-BUS-0004` | `BUCKET_MAP_NOT_NEWER` | input | `failed_precondition` | `BusError::MapVersion` |
| `GRDR-BUS-0005` | `MESSAGE_WITHOUT_ORGANISATION` | fatal | `data_loss` | `BusError::NoOrganisation` |
| `GRDR-BUS-0006` | `STORE_UNAVAILABLE` | retryable | `unavailable` | `BusError::Unavailable` |
| `GRDR-BUS-0007` | `STORE_REFUSED` | fatal | `failed_precondition` | `BusError::Refused` |
| `GRDR-REL-0001` | `SERIALISATION_CONFLICT` | retryable | `aborted` | `RelError::Conflict` |
| `GRDR-REL-0002` | `CONSTRAINT_VIOLATION` | input | `failed_precondition` | `RelError::Constraint` |
| `GRDR-REL-0003` | `STORE_UNAVAILABLE` | retryable | `unavailable` | `RelError::Unavailable` |
| `GRDR-REL-0004` | `STORE_REFUSED` | fatal | `failed_precondition` | `RelError::Refused` |
| `GRDR-REL-0005` | `MIGRATION_ID_DUPLICATE` | internal | `internal` | `PlanError::Duplicate` |
| `GRDR-REL-0006` | `MIGRATION_OUT_OF_ORDER` | internal | `internal` | `PlanError::Order` |
| `GRDR-REL-0007` | `CONTRACT_WITHOUT_EXPAND` | internal | `internal` | `PlanError::ContractWithoutExpand` |
| `GRDR-REL-0008` | `CONTRACT_TOO_EARLY` | internal | `internal` | `PlanError::ContractTooEarly` |
| `GRDR-REL-0009` | `SCHEMA_TOO_NEW` | fatal | `failed_precondition` | `MigrationError::SchemaTooNew` |
| `GRDR-EVENTS-0001` | `VIEW_NOT_REGISTERED` | input | `invalid_argument` | `EventsError::View` |
| `GRDR-EVENTS-0002` | `COLUMN_NOT_REGISTERED` | input | `invalid_argument` | `EventsError::Column` |
| `GRDR-EVENTS-0003` | `BATCH_SCHEMA_MISMATCH` | internal | `internal` | `EventsError::BatchSchema` |
| `GRDR-EVENTS-0004` | `BATCH_UNREADABLE` | internal | `internal` | `EventsError::BatchUnreadable` |
| `GRDR-EVENTS-0005` | `STORE_UNAVAILABLE` | retryable | `unavailable` | `EventsError::Unavailable` |
| `GRDR-EVENTS-0006` | `STORE_REFUSED` | fatal | `failed_precondition` | `EventsError::Refused` |
| `GRDR-EVENTS-0007` | `OBJECT_INTEGRITY` | fatal | `data_loss` | `EventsError::Integrity` |

A superseded fence has one cause wherever it is found, so it has one code and one docs page (P17). Each item registers its own area's entries, because ARCH-017 requires every registered code to be constructed somewhere, and its `/codes/<code>` pages come from the generator of #1636.

### 12. Stability and later change
- Both crates enter `surfaces.toml` as `experimental` (ADR-0020; design/03 section 7: every surface starts there) through the protected-change item #1688 R3 files after acceptance.
- `experimental` allows a break in any release. Every change to this surface still goes by RFC: a signature, a semantic, a variant, a suite case, the key layout or the additional-data encoding is an amendment RFC that names RFC 0002, and its pull requests name the amendment for `rfc-required` (design/30 section 3). `cargo public-api` and `cargo semver-checks` run against the class once the entry exists.
- Amendments already expected, each with its item: Events `retain`, `erase`, `hold` and `manifest` (L-5, R-3); `QueryIr` `Aggregate`, `Lookup`, `Hunt` and `Export` (L-6, L-7); `LakeTable::Content` (L-3); the Jobs methods of J-1; a streaming put on Blobs (L-4); deployment-scoped blobs and transactions (questions 1 and 3); the Keys port (design/21 K2). The endpoint ports (`SensorBackend` and `Actuator` #589, `SandboxBackend` #458, `JudgeBackend` #765, `DetectorPort` #1019, `DeclaredSource` #811, `Meter`) follow Rules 1, 2, 6, 7 and 8 and get their own RFCs.
- A suite change is a new test kit version, and an adapter states the version it passed.
- The storage ports become `beta` when the server's packages freeze (design/03 section 7 and extension points), by an RFC that changes `surfaces.toml`.

### 13. Mechanisms
| Decision | Mechanism | Built by |
|---|---|---|
| Rule 1 | A third-party allow-list per crate in `architecture.toml`, read by the archlint graph rules, and a check that `grdr-ports-testkit` is in no layer 4 program's default closure | #1580 reads the data; the entries are a protected change filed on acceptance |
| Rule 2 | The `+ Send` bound in every signature, checked by the compiler | Each item |
| Rules 3 and 4 | ARCH-015 restated: every method of a port trait takes or returns a tenant witness unless `architecture.toml` lists it as deployment-scoped, and no input type of a port method has an `OrgId` field | A slice-0 lint item split from #1582, filed on acceptance |
| Minting boundary | ARCH-027 `context-mint`, the call-site rule of section 2 | The same lint item |
| Rule 5 | Fence cases in the Jobs, Bus, Relational and Events suites | #298, #299, #300, #1535 |
| Rule 6 | `eval-architecture` checks, on every pull request that names RFC 0002 or an amendment, that each new public item has a reference implementation and a named case | Review, on each such pull request |
| Rule 7 | ARCH-019 | #1582 |
| Rule 8 | `Coded` (#280) with an exhaustive match, the registry (#278) and ARCH-017 | #280, #278, #1582 |
| Stability | The `surfaces.toml` entry, `rfc-required`, `cargo public-api`, `cargo semver-checks` | The protected-change item of #1688 R3 |
| Additional-data encoding | Vectors shared by #311 R9 and #313 R6 | #311, #313 |

### 14. Proposed changes to design documents and `architecture.toml`
Each lands through an issue whose write set names its file, after acceptance.

- design/20 section 3: `Set(Vec<OrgId>, ReadOnly)` becomes `Set(DelegationSnapshotId, ReadOnly)`, as design/21 section 2 has it (the fix #312 asks for). "Every method takes 21's `TenantCtx`" becomes Rule 3. The Events row lists `append(ctx, fence, LakeBatch)`, `flush(fence, due)`, `plan`, `execute` and `tail`, and names the methods that come later.
- design/03 section 2: the ARCH-015 rule becomes the restatement in section 13, and a new row adds ARCH-027 `context-mint`.
- design/03 section 10, Errors: "One enum per crate" becomes "one enum per crate, and one per port module in `grdr-ports`".
- `architecture.toml`: an empty third-party allow-list for `grdr-ports`; the Arrow crates of #1532 for `grdr-ports-testkit`, with the program-closure rule; the deployment-scoped list (`Leases`, `Migrator`, `Bus::subscribe`, `Bus::commit`, `Bus::lag`, `Bus::set_bucket_map`, `Events::flush`); the `context-mint` allow-list of section 2.

### 15. What each item changes
Under #1688 R4 each lead writes these back into its item before readying it. Every item's `cargo xtask` criterion also becomes the `grdr-verify` gates or `cargo run --locked -p grdr-archlint -- check`, since ADR-0029 removed `xtask`.

- **#281**: `Clock: Send + Sync`, and `ManualClock` meets it. R8 gains the three runner rules of section 5. Rule 1 holds for both crates.
- **#283**: R1 takes the bounds of section 4, and a compile-time test shows the future of `run` is `Send`. AC-4 cites ARCH-018, a scan rule of #1582, not #1580.
- **#297**: `list` takes `ListPrefix`. `BlobError` drops `retryable` and gains `Refused`, with codes `BLOBS-0001` to `0005`. AC-3 waits on the slice-0 lint item.
- **#298**: `JobsError` drops `retryable` and gains `Refused`, with codes `JOBS-0001` to `0004`; `MemLeases` shares state. The lead-core comment on ARCH-015 is replaced by the deployment-scoped entry.
- **#299**: R5 returns `OrgBatch` with `&RecordedOrg`, and `poll` becomes `fetch(FetchLimit)`. R6 and scenario (a) follow Rule 5. R11's `MemBus` holds a `MemLeases` handle. `BusError` drops `retryable` and gains `NoOrganisation` and `Refused`, with codes `BUS-0001` to `0007`.
- **#300**: `RelError::Conflict` and `Unavailable` drop their fields and `Refused` is added; `PlanError` and `MigrationError` take codes `REL-0001` to `0009`. R2 gains the rollback wording of section 9.
- **#1535**: the largest change, likely past size M, so the lead should split it into the trait and types, and `MemEvents` with its suite. Reads take `&SingleCtx`. `append` takes a fence and `flush` is new. Rows are `ArrowIpc`. `LakeTable` loses `Content`. `QueryIr` keeps `Timeline` and `Scan` with order and position. `tail` takes `QueryIr`. R6 goes. The suite gains the cases of section 10. It now also requires #298, #299, #510 (the manifest type) and #1532 (Arrow for the test kit).
- **#312**: R3 renames `RecordedJobOrg` to `RecordedOrg`, and the call-site allow-list of section 2 replaces "a separate archlint item". R4 follows Rule 3. `From<SingleCtx> for TenantCtx` is added. It is blocked by the slice-0 lint item, and AC-5 needs a criterion that does not use `cargo xtask matrix-run`.
- **#313**: R4 becomes `ListPrefix`, `PathError::SetContext` goes, and AC-4 adds a compile-fail case for a `Set` prefix. R5 uses `archive.<lane>`. `Lane` comes from grdr-model. `PathError` gains `Date`, with codes `TENANT-0001` to `0004`. AC-5 needs the same fix as #312.

Downstream: #311 R7 and R8 follow section 2. #1546 moves flattening to the `store` target and builds `LakeBatch`. #1547 commits through `Events::flush`. #1554 R5 becomes a compile-time refusal.

## Surfaces changed
- `grdr-ports` (layer 2, public): modules `clock`, `entropy` (a re-export), `retry`, `tenant` (`ctx`, `path`, `aad`) and `storage` (`blobs`, `jobs`, `bus`, `relational`, `events`). Class `experimental`.
- `grdr-ports-testkit` (layer 2, public): `ManualClock`, `SeededEntropy`, `block_on`, the conformance runner, `MemBlobs`, `MemLeases`, `MemBus`, `MemEvents`, `ProbeRepo` and one suite per port. Class `experimental`.
- `grdr-model` (layer 1, public): `Monotonic` (#281 R1). Class `experimental`.
- The storage format of lake and blob objects: the key layout of design/20 section 5 as #313 renders it, and the additional-data encoding `grdr-aad-v1`.
- Data and gate files, as proposals: six code areas in `schema/codes`, entries in `surfaces.toml` and `architecture.toml`.
- No spine text and no protobuf package changes.

## Alternatives
- **Ship the surface `experimental` without an RFC, or one RFC per port.** Both rejected in the ruling on #1535: the class sets break rules, not the route, and the nine parts share the context, the error shape and the runner.
- **Re-export arrow-rs types from `grdr-ports`.** Zero-copy, but the daemon would link Arrow, and every arrow-rs major (up to one a quarter, https://github.com/apache/arrow-rs/blob/main/README.md, read 2026-11-20) would break the port and every partner adapter built for L4. Rejected for Arrow IPC, whose format has stayed backward compatible within version 1 since 1.0 (https://github.com/apache/arrow/blob/main/docs/source/format/Versioning.rst, read 2026-11-20). Brief 11 already recommends Arrow and Parquet as the event format.
- **A row and value model of our own in `grdr-ports`.** Keeps the test kit small, but invents a second columnar format beside Arrow (P10, P17) and adds a conversion to every adapter. Rejected.
- **A separate crate for the storage ports, free to link Arrow.** A new layer 2 crate and same-layer edge, and it still ties the port to arrow-rs releases. Rejected.
- **`async-trait` or boxed `dyn` ports.** A new dependency and an allocation per call, to buy runtime selection the three fixed profiles do not need. Rejected.
- **Fence checks against the highest committed token,** the storage-side form of fencing. It works for one store, but #298 and #300 already check issued tokens, and mixing the two leaves the window and false `Regress` described in section 8. Rejected for one rule everywhere.
- **Declare `retain`, `erase`, `hold`, `manifest` and the other four query nodes now, returning `NotSupported`.** Lets feature code compile against them early, at the price of an adapter passing the kit without erasure. Rejected under Rule 6.
- **`&TenantCtx` on lake and blob reads with a run-time `SetContext` error.** Rejected: the compiler can refuse it, which is how #312 treats writes.
- **One error enum for the whole crate,** as design/03 section 10 reads today. An adapter crate implements one port and would return variants that cannot happen. Rejected for one enum per port module.

## Drawbacks
- Every append and every result batch is encoded and decoded once as Arrow IPC.
- `MemEvents` needs the Arrow crates, so the test kit builds more slowly and #1535 has to wait on #1532 and split.
- The storage traits are not dyn-compatible, so `grdr-server` carries one dispatch enum or generic per port.
- Each deferred method and node costs an amendment RFC when its item arrives.
- Module repository traits in a public crate would cost an RFC per repository change (question 2).

## Unresolved questions
1. **Deployment-scoped objects.** `state-log/`, `ephemeral/detect/` and the content repository have no organisation, so they cannot be `TenantPath` values. Lean: a separate deployment-scoped trait over a closed `DeploymentPath`, never an org-less `TenantPath`, which would break Rule 3. Settled by an amendment drafted when R-1 or D-1 is specified, and before the filesystem Blobs adapter is planned (#297 non-goals).
2. **Where module repository traits live.** In `grdr-ports`, every repository change is an RFC. In an unpublished layer 2 crate such as `grdr-repos`, the pattern `grdr-messages` sets, it costs one RFC for the crate and its same-layer edge. Lean: the second. Settled before S-2's first module repository.
3. **The deployment-scoped transaction** for runtime settings and the operator realm (D-70, design/20 O-3 and O-4), whose witness comes from the operator realm (design/21 O1). Settled by its own RFC with O-3.
4. **The slice-0 surfaces of `grdr-model` and `grdr-schema`** (#18, #278, #279, #282, #284) have no RFC either, though these signatures name their types. Settled by the RFC of #1710.
5. **Tail inside the port.** `tail` keeps the union with the caller, as design/20 and #1535 have it. The alternative is for `execute` to union buffered rows itself, so no caller can forget. Lean: keep `tail` while design/20 places the union in `query`. The council's view is asked.

## Review
Pending. Each persona council seat and `eval-architecture` comment on #1688.

## Decision
Pending.
