# ADR-0033: The slice-0 public surface of grdr-ports and grdr-ports-testkit, adopted by RFC 0002

- Status: accepted
- Date: 2026-11-23
- Decided by: chief architect
- Spine: D-05, D-11, D-33, D-34, D-35, D-51, D-57, D-61, D-63, D-69, P1, P4, P5, P6, P8, P9, P10, P14, P15, P17 (baseline [ADR-0036](ADR-0036-the-amended-spine-is-the-baseline-adopted-by-rfc-0001.md))
- Requires: review complete on RFC 0002 revision 17 (`e2ffd3c1d79645fb1dce3c153d4f4c95b7b2f0ad`, merged on `main` at `78401aca706b79c7cbb0152db7addcfa9f82591c`, RFC file blob `9f8430afa9c17178d402d3cf43c37f247a01370c`); [ADR-0038](ADR-0038-the-grdr-model-and-grdr-schema-slice-0-surface-adopted-by-rfc-0007.md) (RFC 0007, blob `0dac0a359f4c60d270866b71d824ceb8e849c3f9`); [ADR-0040](ADR-0040-clock-entropy-and-the-retry-executor-adopted-by-rfc-0008.md) (RFC 0008, reviewed blob `b338780823870d0f81c92e1a6f9cd2a5ec472eb8`, accepted blob `b4af2b007041e3abdf6f7439824662ea6f08c52d`); [ADR-0041](ADR-0041-the-grdr-model-slice-0-surface-adopted-by-rfc-0009.md) (RFC 0009, reviewed blob `e1f4f50307ec78e6610008cbe53343e7951ce837`, accepted blob `4f36df6f0b2ce122d3b09d8109e83fb4720b1c68`); [ADR-0043](ADR-0043-lean-token-optimised-agent-team.md)
- RFC: 0002 ([`rfcs/0002-grdr-ports-slice-0-surface.md`](../../rfcs/0002-grdr-ports-slice-0-surface.md)), accepted on #1688
- Work items: #1688; #297, #298, #299, #300, #1535, #312, #313 (#281 and #283 moved to RFC 0008 / ADR-0040); #2002 (#302, #314, #315), #2003; #1969, #1967, #1698, #1859, #1860, #1892, #1911; #2020, #2021, #2022, #2023, #2024, #2025, #2026, #2027

## Context
D-61 puts every public crate's API through the RFC route ([ADR-0001](ADR-0001-decisions-are-adrs-and-public-surfaces-change-by-rfc.md), [ADR-0020](ADR-0020-stability-classes-live-in-surfaces-toml.md), [ADR-0036](ADR-0036-the-amended-spine-is-the-baseline-adopted-by-rfc-0001.md)). Work item P-1 (`docs/design/20` section 3) and T1/T2 (`docs/design/21`) introduce the slice-0 storage port traits (`Blobs`, `Leases`, `Bus`, `Relational`, `Migrator`, `Events`, `QueryIr`), the tenant minting and admission boundary (`tenant::authority`, `tenant::ctx`, `tenant::mint`, `tenant::admit`, `tenant::path`, `tenant::aad`, `ident`), the storage extension to `grdr-ports-testkit` (amending RFC 0008's conformance runner), and the internal kit key crate `grdr-ports-kitkey`.

RFC 0002 ran through seventeen revisions on #1688:
- Round 1 (`eb9770d73eb3da8c181e6d2ef930798f3241aebc`, blob `d27824da875b4b9fba77c4abcf4bacfe5e71c65c`): all nine persona council seats reviewed the RFC (`support with changes` / `accept with changes`), alongside `eval-architecture`.
- Rounds 2 to 16 refined the sealed port architecture, `MintAuthority` and purpose-bound handles, `ARCH-029` to `ARCH-032`, `PortsCall<Self>`, one-commit revocation markers, `schema/tenancy/lifecycle.toml`, Arrow IPC, the `Events` union with per-fence partition floor reads, and the Rule 1 `grdr-ports-kitkey` boundary.
- After round 8 (`5227384`), sections 3 and 4 (`Clock`, `Entropy`, `Monotonic`, `retry::run`, `#281`, `#283`) split to RFC 0008 ([ADR-0040](ADR-0040-clock-entropy-and-the-retry-executor-adopted-by-rfc-0008.md)).
- After round 16 (`3545594`, commit `7ab377a`), the chief architect's scope ruling (`issuecomment-7087459883`) separated back-end PostgreSQL internals (moved to `#2002` and verified against PostgreSQL 18 in CI) from the adapter-independent port surface and store Properties 1 to 15, and directed evaluator rules for port RFCs to `#2003`.
- Revision 17 (`e2ffd3c1d79645fb1dce3c153d4f4c95b7b2f0ad`, merged to `main` at `78401aca706b79c7cbb0152db7addcfa9f82591c`, blob `9f8430afa9c17178d402d3cf43c37f247a01370c`) applied the round-16 scope ruling and RFC 0009's constraints (`issuecomment-7086187361`), keeping `ARCH-029` for `context-mint` (`7056005677`).
- Following `#2005` ([ADR-0043](ADR-0043-lean-token-optimised-agent-team.md)), `.claude/risk-tiers.toml` sets `[kinds] rfc` to `eval-review` and `eval-security` on two models with no persona council fan-out. In round 17 on blob `9f8430a` (against spine base `a80859235e7a2a4444648d6fa8d389d78dde6be9`), `eval-review` (`Google`, `Gemini 4 Carbon`, `7097649086`) and `eval-security` (`Google`, `Gemini 4 Neon`, `7097649756`) both passed with zero findings, and CI checks passed on `e2ffd3c`.

## Decision
Accept [RFC 0002](../../rfcs/0002-grdr-ports-slice-0-surface.md) at revision 17 (commit `e2ffd3c1d79645fb1dce3c153d4f4c95b7b2f0ad`, merged at `78401aca706b79c7cbb0152db7addcfa9f82591c`, blob `9f8430afa9c17178d402d3cf43c37f247a01370c`) and bind its surface, twelve rules, fifteen store and tenancy properties, `GRDR-<AREA>-<NNNN>` codes, four `limits.toml` rows, `experimental` stability rules and conformance kit additions for slice 0.

1. **Public crates and internal key crate.**
   - `grdr-ports` (`layer = 2`, `experimental`, `surfaces.toml` row tracked in `#1969`): exports `ident`, `tenant` (`authority`, `ctx`, `mint`, `path`, `aad`), `adapter` (adapter traits and grants), `storage` (`blobs`, `jobs`, `bus`, `relational`, `events`, `PageLimit`, `StoreFault`, re-exports of `Admitted`, `PortsCall`, `Refusal`), beside RFC 0008's `clock`, `entropy` and `retry`. Zero third-party dependencies. Only optional `kit` feature enables `KitAuthority` and `Setup::for_kit`, guarded by `grdr-ports-kitkey`.
   - `grdr-ports-testkit` (`layer = 2`, `experimental`, `surfaces.toml` row tracked in `#1969`): extends RFC 0008's conformance runner (`#281`) via `#2020` with `CaseKind`, `NotApplicable`, `Fixture`, `StorageFixture`, `RelationalFixture` (`snapshot` moved out of `#281` into `#2020`), `kit()`, `tenancy()`, `clock()`, `arm`, `reach`, `StopPoint`, `Reached`, `unarmed_reach_is_inert`, `MemTenancy`, `MemBlobs`, `MemLeases`, `MemBus`, `MemRelational`, `MemEvents`, `PROBE` (`probe_link`, `probe_walk`), `REFUSALS` and `data/optional-faults.toml`.
   - `grdr-ports-kitkey` (`layer = 2`, `surface = "internal"`): holds `KitKey`, not re-exported by `grdr-ports`, permitted only as an optional (`kit`) dependency of `grdr-ports` and a dependency of `grdr-ports-testkit`. Excluded alongside `grdr-ports-testkit` from `[workspace] default-members`, banned from all release/program closures by `#1580`'s closure + manifest rules, `deny.toml` (`#2023`), and per-program release builds (`cargo build -p <program>`).
   - Storage formats pinned by RFC 0002: tenant object key layout (`org=<id>/...`), Rule 10 ASCII identifiers (`ident`, including `RuleName`) and AEAD additional-data encoding `grdr-aad-v1` (`archive.<lane>`).

2. **Seal, minting boundary and tenant witnesses (Rules 3, 4 and 12).**
   - Port traits are sealed (`seal::Sealed`); external/module crates cannot implement `Blobs`, `Leases`, `Bus`, `Subscription`, `Relational`, `ReadTx`, `WriteTx`, `Migrator`, `Events`, `ResultStream`, or `StatementRunner`. `Admitted<A>`, `AdmittedTx<T>` and `AdmittedStream<R>` wrap admitted adapters inside `tenant::admit`, running lifecycle (`schema/tenancy/lifecycle.toml`), delegation (`DelegationRead` + `merge` floor) and transaction-bound checks on every operation.
   - `tenant::start` issues `MintAuthority` once per process. Runners receive purpose-bound handles (`TokenMinter`, `Consumer`, `ConsumerSubscription`, `MemberReadAuthority`, `JobSteps`, `KitAuthority`), restricted statically by `ARCH-029` to `architecture.toml` handle modules that match `security/trust-core.paths`. `Setup::holder` and `KitAuthority::holder` mint capability `Holder` values wrapping RFC 0009's `HolderId`.
   - Deployment-scoped methods returning tenant data (`Subscription::fetch`) take `PortsCall<Self>` so only `tenant::mint::fetch_batches` invokes them, handing module code `OrgBatch` values grouped per partition, organisation and delegation.
   - `serde` / `unsafe` barrier: `#![forbid(unsafe_code)]` (`ARCH-032`) with interim registry/proc-macro guard on port-dependent crates until `#1475`'s macro-expanded `unsafe` register check lands on both the workspace and `#1593` distribution closures.

3. **Relational properties, Events tail/floor and Error codes.**
   - Store Properties 1 to 12 and Tenancy Properties 13 to 15 hold across every relational adapter; PostgreSQL's concrete mechanisms reside in `#2002`, and SQLite's single-organisation constraints (`SingleOrganisation`, local handle FS classification) reside in `#301`.
   - `Events::execute` unions buffered/tail rows (`StoreTail` in `distributed`) under per-fence `lake_org_head` floors and `lake_org_partition`, refusing caches older than the max floor, with single-source `Coverage` on `Ending` derived by `resume()`.
   - `GRDR-STORE-0001`..`0009`, `BLOBS-0001`..`0002`, `JOBS-0001`, `BUS-0001`..`0006`, `REL-0001`..`0016`, `EVENTS-0001`..`0007`, and `TENANT-0001`..`0014`, `0016` (`GRDR-TENANT-0015` removed in rev 17) are assigned to their registering issues (`#297`, `#298`, `#299`, `#300`, `#1535`, `#312`, `#313`, and the server tenancy-table item).

4. **AC-3, AC-5 and AC-6 status on acceptance.**
   - **AC-3 (evaluator rounds & findings)**: `N2` (`PortsCall<Self>`) closed in round 4 (`7072656886`); `N1` / `N3` (floor/cache rule) closed in round 5 (`7072861568`); `EA16-1`, `EA16-2`, `EA16-6`, `S65`, `AD16-2` and RFC 0009 constraints closed in revision 17; PG-specific findings tracked in `#2002`; port-RFC evaluator scope tracked in `#2003`; round 17 passes (`eval-review` `7097649086` and `eval-security` `7097649756`) satisfy `[kinds] rfc` on `main` under [ADR-0043](ADR-0043-lean-token-optimised-agent-team.md).
   - **AC-5 (`surfaces.toml`)**: `#1969` already exists for `grdr-ports` and `grdr-ports-testkit`; commented on `#1969` to cite RFC 0002 (`9f8430a`, ADR-0033) and section 12 promotion prerequisites beside RFC 0008 rather than creating a duplicate `surfaces.toml` issue.
   - **AC-6 (spec write-backs)**: RFC 0002 write-back notes and revision-17 deltas (including `#299` CAS `subscribe` superseding `NULL` first-commit + `PortsCall`, `#1535` N1 floor rule + single `Coverage`, `#312` `PortsCall` restriction beside minting boundary, `#297`/`#298`/`#300`/`#313` updates, and `#281`/`#283` confirmation that both moved to RFC 0008 and `RelationalFixture::snapshot` moved to `#2020`) are posted on `#281`, `#283`, `#297` to `#300`, `#1535`, `#312` and `#313`. Owning leads (`lead-core`, `lead-server`) write these deltas into the issue specs before readying them (`#1688` R4) and reconcile pre-split `#281`/`#283` AC-6 wording before closing `#1688`.

5. **No pin and no evidence.** RFC 0002 changes no pinned path. `rfcs/pins.toml` stays unchanged on `a80859235e7a2a4444648d6fa8d389d78dde6be9` (`docs/design/00-decisions.md`), and no file enters `rfcs/evidence/`.

6. **What this acceptance binds.**
   - Every addition, removal or signature/semantic/variant change on `grdr-ports` (`ident`, `tenant`, `adapter`, `storage`), `grdr-ports-testkit` (`kit`, `Fixture`, `StorageFixture`, `RelationalFixture`, `StopPoint`), `grdr-ports-kitkey`, `grdr-aad-v1`, Rule 1 to Rule 12 invariants, `StoreProperty`, `RefusedReason`, `schema/tenancy/lifecycle.toml` rules, or the four `limits.toml` contracts is a new RFC amending RFC 0002 (section 12). Expected later amendments listed in section 12 (`put_versioned`/deployment objects Q1, module repos Q2, deployment-scoped transactions Q3, `retain`/`erase`/`hold`/`manifest`, `Aggregate`/`Lookup`/`Hunt`/`Export`, `Jobs` claim & step handles, actor/purpose accessors, partition removal) wait on their named items.
   - `RFC 0002` text in `rfcs/0002-grdr-ports-slice-0-surface.md` never returns to `Review` except through a new amending RFC or decision record.

## Lanes for later changes
| Path or surface | Governance lane | Evaluators required | Source rule |
|---|---|---|---|
| `crates/grdr-ports/**` (`ident`, `adapter`, `storage`) | Amendment RFC; `tier:high` on PR (`surfaces.toml` / core seam) | `eval-review`, `eval-security` (D-63 / ADR-0043) | RFC 0002 section 12 |
| `crates/grdr-ports/src/tenant.rs`, `tenant/**` | Amendment RFC + trust-core lane | Two distinct models/providers (`eval-review`, `eval-security`) | `security/trust-core.paths`, D-63 |
| `crates/grdr-ports-kitkey/**` | Amendment RFC + trust-core lane (`#2024`) | Two distinct models/providers | `security/trust-core.paths`, Rule 1 |
| `crates/grdr-ports-testkit/**` | Amendment RFC for traits/hooks; adapter fixture bugs follow `#2020` / `#2003` | `eval-review` (+ `eval-security` when changing `kit()` / `MemTenancy`) | RFC 0002 sections 5, 12 |
| `schema/tenancy/lifecycle.toml` | Amendment RFC for cell semantics; trust-core lane (`#2024`, `#2025`) | Two distinct models/providers | RFC 0002 sections 2, 14 |
| `limits.toml`, `deny.toml`, `security/trust-core.paths`, `surfaces.toml` | Protected change on `security/trust-core.paths` (`#2023`, `#2024`, `#2026`, `#1969`) | Two distinct models/providers (`lead-agent-kit`) | D-63, `AGENTS.md` |
| `architecture.toml`, `Cargo.toml` (`default-members`), `dist.toml` | Gate configuration (`#2022`, `#1593`); two models for gate data | `eval-review`, `eval-security` (`lead-agent-kit` / release) | `team/06` section 2.1, D-63 |
| `crates/grdr-archlint/**` | Trust-core gate tooling (`#1892`, `#2021`) | Two distinct models/providers | `#1892`, `security/trust-core.paths` |
| `crates/grdr-rel-postgres/**` (store checks, binding, runner, watchdog) | Layer 3 `trust-core` (`#2002` + rule-named files in `trust-core.paths`) | Two distinct models/providers + PG 18 CI (`#2002`) | Scope ruling `7087459883` |
| `docs/design/03`, `20`, `21` | Protected design change (`#2027`) | `eval-security`, `eval-adversarial` / `eval-review`, two models (`design/21`) | RFC 0002 section 14 |

## Where each item is built
| Item | Responsibility | Squad / Agent |
|---|---|---|
| `#297` | `Blobs`, `BlobsAdapter`, `ObjectKey::under`, `ReadPath`/`ListPrefix` reads, `GRDR-STORE-0001..0009` & `BLOBS-0001..0002` | `server` / `lead-server` -> `impl-rust` |
| `#298` | `Leases`, `LeasesAdapter`, `Grant`/`Renewal`, fresh token per `acquire`, `Holder` capability use, `GRDR-JOBS-0001` | `server` / `lead-server` -> `impl-rust` |
| `#299` | `Bus`, `Subscription`, CAS `subscribe`, bounded conditional `commit` (`BeyondLog`), `fetch(FetchLimit, PortsCall<Self>)`, stored delegation, `GRDR-BUS-0001..0006` | `server` / `lead-server` -> `impl-rust` |
| `#300` | `Relational`, `ReadTx`, `WriteTx`, `Migrator`, `StatementRunner`, `write_fenced`, `StoreProperty`, `MemRelational`, `PROBE`/`REFUSALS`, `GRDR-REL-0001..0016` | `server` / `lead-server` -> `impl-rust` |
| `#1535` | `Events`, `EventsAdapter`, `ResultStream`, `QueryIr`, `OrgRead`, `LakeBatch`, union inside `execute`, `Coverage` in `Ending`, `MemEvents` (`#1532`, `#1475`), `GRDR-EVENTS-0001..0007` | `server` / `lead-server` -> `impl-rust` |
| `#312` | `tenant::authority` (`start`, `Setup`, handles), `tenant::ctx`, `tenant::admit` (`Admitted*`), `tenant::mint` (`fetch_batches`, `Dispatch`), `grdr-ports-kitkey`, `GRDR-TENANT-0005..0009, 0011..0014`, `#311` differential tests | `server` / `lead-server` -> `impl-rust` |
| `#313` | `ident` (`RuleName`, Rule 10), `ReadPath`, `ListPrefix`, `ObjectKey::under`, `PathError::ClassForMember`, `grdr-aad-v1` (`archive.<lane>`), `Date`/`YearMonth`, `GRDR-TENANT-0001..0004, 0010` | `server` / `lead-server` -> `impl-rust` |
| `#311` | `grdr-tenancy-ref` four models (`batches`, `members`, `lifecycle`, `delegation`), additional-data & R13 vectors | `server` / `impl-rust` |
| `#383` | `grdr-model` ids (`OrgId`, `DelegationId`, `DelegationSnapshotId`, `ProviderId`) without `/`, `=`, `.` | `core` / `lead-core` |
| `#281`, `#283` | Moved to RFC 0008 ([ADR-0040](ADR-0040-clock-entropy-and-the-retry-executor-adopted-by-rfc-0008.md)); `RelationalFixture::snapshot` moved to `#2020` | `core` / `impl-rust` |
| `#2020` | Storage kit extension in `grdr-ports-testkit` (runner `CaseKind`, `Fixture*`, `StopPoint`, `arm`/`reach`, `kit()`, `MemRelational` kit driver, `optional-faults.toml`, how-to page) | `core` / `lead-core` |
| `#2021` | `grdr-archlint`: `ARCH-015` restated, `ARCH-029` to `ARCH-032` checks + interim `unsafe` rule | `core` / `lead-core` |
| `#1580` | `grdr-archlint`: graph rules plus Rule 1 full-resolve release-env closure check, manifest rule, `deny.toml` drift check, K1..K13 / S46 / k6 fixtures | `core` / `impl-rust` |
| `#1475` | Macro-expanded `unsafe` register barrier across workspace and `#1593` closure | `security` / `impl-rust` |
| `#1593` | `dist.toml` adapter dispatch, `not_applicable` check, per-program release builds & closure runs | `server` & `release` |
| `#2002` | PostgreSQL 18 in-database mechanisms for Properties 1 to 15 (`#302`, `#314`, `#315`, held cases) | `server` / `lead-server` |
| `#2003` | Port-RFC evaluator scope rules + Rule 6 PR review duty in agent files | `agent-kit` / `lead-agent-kit` |
| `#1969` | `surfaces.toml` `experimental` `[[crate]]` rows for `grdr-ports` and `grdr-ports-testkit` | `core` / `lead-agent-kit` |
| `#2022`, `#2023`, `#2024`, `#2025`, `#2026` | Protected updates to `architecture.toml`, `Cargo.toml` `default-members`, `deny.toml`, `security/trust-core.paths`, `schema/tenancy/lifecycle.toml` + `grdr-schema`, `limits.toml` (coordinating `#1967`, `#1698`, `#1892`) | `core` / `release` / `security` -> `lead-agent-kit` & `lead-core` |
| `#1859`, `#2027`, `#1860` | Design docs: `design/02` SR-56..64 (`#1859` + SR-58 update), `design/03, 20, 21` (`#2027`), `design/20` §8 (`#1860`) | `chief-architect` |
| Downstream server items | `#301` (SQLite), `#1546`, `#1547`, `#1554`, `#1555`, `#1636`, `#1690`, `#305` (authn middleware), `#1579` (`J-1`), `#1534` / `lead-server` compose root & tenancy table (`GRDR-TENANT-0016` + runbooks) | `server` / `lead-server` |

## Enforced by
- Type system: sealed port traits (`seal::Sealed`), `Admitted` / `AdmittedTx` / `AdmittedStream`, `PortsCall<Self>`, private `MintAuthority` in `tenant`, purpose-bound handles, capability `Holder`, non-constructible contexts and `Ok`-free error codes (`Coded`, RFC 0007).
- `grdr-archlint` & `cargo deny`: Rule 1 graph + release closure + manifest + `deny.toml` drift checks (`#1580`), `ARCH-015`, `ARCH-029` to `ARCH-032` (`#2021`).
- Expanded-code safety gate: `#1475` register check on workspace and `#1593` distribution closures (interim dependency guard in `ARCH-032` until `#1475` lands).
- Differential & conformance testing: `#311` four `grdr-tenancy-ref` models vs `#312` and `J-1`; conformance suites on `MemRelational`, `MemEvents`, `#301` SQLite, and PostgreSQL 18 CI tests in `#2002`; Rule 6 review duty (`#2003`).

## Consequences
- Storage port implementation (`#297` to `#300`, `#1535`, `#312`, `#313`) and downstream server integration (`#301`, `#1546`, `#1547`, `#1554`, `#1555`, `#305`, `#1534`, `#1690`) are unblocked at design level while respecting `#2020` to `#2027` gate dependencies and `#1475` / `#1580` / `#1532` prerequisites.
- PostgreSQL-specific catalogue, SQL-runner and role checks no longer force public-surface RFC churn on `grdr-ports` when tested or fixed against PostgreSQL 18 under `#2002`.
- Contrib adapters face a clear `Fixture` + `NotApplicable` + `PeerAccess` admission contract via `dist.toml` (`#1593`), without leaking `grdr-ports-testkit` or `grdr-ports-kitkey` into shipped binaries.
- Future amendments (deployment-scoped objects Q1, module repository crate Q2, deployment-scoped transactions Q3, `Events` retention/export nodes, `Jobs` claim & step handles) follow the RFC route explicitly without rewriting RFC 0002.

## Alternatives rejected
Recorded in detail in [RFC 0002, Alternatives](../../rfcs/0002-grdr-ports-slice-0-surface.md#alternatives):
- Shipping storage ports without an RFC or per-port RFCs (shared tenancy, error and runner contract).
- Exposing `arrow-rs` types directly on `grdr-ports` (breaks stability and daemon closure boundaries).
- `async-trait` / boxed `dyn` ports or embedder-written `main` composition (replaced by `dist.toml` dispatch).
- Source scans or `unsafe_code` lint alone instead of sealed traits, `MintAuthority`, `grdr-ports-kitkey`, `ARCH-029` and the `#1475` register check.
- Embedding PostgreSQL catalogue mechanisms, `NonSpillingHash`, or storage-side `NULL` bus fencing in the public `grdr-ports` contract.

## Revisit when
- A later slice or work item reaches Q1 (deployment-scoped objects), Q2 (module repository trait crate), Q3 (deployment-scoped transactions), `Events` erasure/retention/export queries (`retain`, `erase`, `hold`, `manifest`, `Aggregate`, `Lookup`, `Hunt`, `Export`), or `Jobs` worker methods (`J-1`).
- Storage ports become ready to graduate from `experimental` to `beta` (requiring Q1, Q2, Keys port RFC `design/21` K2, and server package freeze per section 12).
- `grdr-ports` or any tenant path introduces a new handle kind, work kind or `StoreProperty`.
