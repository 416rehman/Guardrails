RFC: 0013
Title: Cedar schema Grdr v1alpha1, policy engine request, derivation and degradation surface, and Cedar dependencies
Author: chief-architect
Harness: Antigravity
Model: Gemini 4 Neon
State: Review
Design issue: #431
Spine: D-05, D-07, D-08, D-09, D-10, D-11, D-13, D-15, D-25, D-28, D-44, D-51, D-53, D-60, D-61, D-63, D-69, P1, P2, P7, P8, P9, P14, P17 (no spine text changes)
Surfaces: Cedar schema `Grdr` v1alpha1 (`schema/cedar/v1alpha1.cedarschema`); public crate `grdr-schema` (layer 0: `cedar` module, `POLICY` error-code area `GRDR-POLICY-0001`..`0012`, `MODEL` extension `GRDR-MODEL-0012`, `policy.*` limits rows); public crate `grdr-model` (layer 1: shared policy contract value types at crate root); public crate `grdr-core` (layer 1: `policy` module `schema`, `request`, `derive`, `degrade`, exposing `cedar_policy::{Schema, Request, Entities}` while `experimental`); tool crate `grdr-policy-ref` (`layer = "tool"`, reference `derive` and `degrade` over `grdr-model` types); third-party dependencies `cedar-policy = "=4.14.1"` (`default-features = false`, normal on `grdr-core` only) and `proptest` (`dev-dependency` on `grdr-core` and `grdr-policy-ref`). As amendments: RFC 0007 (`ADR-0038`) sections 2 R10, 8, and 11 (`grdr-schema` `src/` file inventory, `layout` `dep-info`/token allow-list for `cedar.rs`, and `security/trust-core.paths`); RFC 0009 (`ADR-0041`) sections 8, 9, and 13 (adding shared policy types at `grdr-model` crate root, registering `GRDR-MODEL-0012`, and reusing `grdr_model::Tamper`). As proposals: `surfaces.toml`, `architecture.toml`, `security/trust-core.paths`, `schema/codes/areas.toml`, `schema/codes/policy.toml`, `schema/codes/model.toml`, `limits.toml`, `Cargo.toml`, `Cargo.lock`, `docs/design/03`, and `docs/design/12`
Decision record: none yet

## Summary

This RFC decides the six open design items of `#431` for WI-0018 (`#21`) and its slice-0 dependants (`#432`, `#434`, `#435`, `#436`, `#1600`, `#1602`, `#1595`, `#1597`), and states explicit amendments to [RFC 0007](./0007-grdr-model-and-grdr-schema-slice-0-surface.md) (`ADR-0038`) and [RFC 0009](./0009-grdr-model-slice-0-surface.md) (`ADR-0041`):

1. **R1 (Cedar schema `Grdr` v1alpha1):** Fixes the complete `.cedarschema` text for Cedar 4.14.x (language 4.6), covering the 6 principal-side-only entities plus 12 resource entities (`Agent` serving both roles, 18 entities total), 4 action groups (`any`, `file`, `net`, `mcp`), 15 concrete actions matching the spine action classes verbatim, per-action and common context records, the reserved empty `schedule` seam, and strict admission of all 22 worked policies of `docs/design/12` sections 3 and 5.
2. **R2 (Schema location):** Places the canonical text at `schema/cedar/v1alpha1.cedarschema`, embedded into layer-0 `grdr-schema::cedar` (`V1ALPHA1` and `SCHEMA_VERSION`), and amends RFC 0007 section 2 R10 and section 8 so `tests/construction.rs` `layout` accepts `crates/grdr-schema/src/cedar.rs` and its `include_str!` dependency edge on `schema/cedar/v1alpha1.cedarschema`.
3. **R3 (Neutral values and `absent`/`pending`):** Keeps all Cedar context records and fields required with typed neutral values (`[]`, `false`, `0`, `""`, `{}`) when absent or pending, and keeps `absent` and `pending` as engine-side `BTreeSet<ContextField>` sets on `CedarRequest`. This validates all 22 worked rules strictly with zero rule edits and prevents policy rules from branching on `absent` or `pending` directly.
4. **R4 (Rust surface of `grdr_core::policy` and `grdr-model` boundary):** Specifies `policy::{schema, request, derive, degrade}`, typed closed enums for inputs and outcomes, `PolicyRuleId` parsing and accessors, leak-free `PolicyError` (`LogSafe` via `Code`), and pure derivation and degradation data types hosted at `grdr-model`'s crate root (amending RFC 0009 and reusing `grdr_model::Tamper`) and re-exported into `grdr_core::policy` so `grdr-policy-ref` links only `grdr-model`. Keeps `surfaces.toml` at `(name, class, rfc)` with `grdr-core` `experimental` and tracks `cedar-policy` exposure under `ARCH-007`.
5. **R5 (Dependencies):** Pins `cedar-policy = "=4.14.1"` with `default-features = false` as a normal dependency of `grdr-core` only (`ARCH-004`), and admits `proptest` (`MIT OR Apache-2.0`) as a dev-dependency of `grdr-core` and `grdr-policy-ref`.
6. **R6 (`POLICY` error codes and limits):** Registers subsystem area `POLICY` (`GRDR-POLICY-0001` to `0012`) plus `GRDR-MODEL-0012` via `#278` and twelve `[bound.policy.*]` entries (including `policy.parser-input-max`, `policy.rule-id-max`, and `policy.class-tag-max`) in `limits.toml` via `#279` under RFC 0007 rules.

## Motivation

WI-0018 (`#21`) introduces the `Grdr` v1alpha1 Cedar schema, strict request builders, and the verdict derivation and degradation semantics across `grdr-schema`, `grdr-model`, `grdr-core`, and `grdr-policy-ref`. Under D-61, [docs/design/03](../docs/design/03-system-architecture-and-modularity.md) section 7, and [docs/design/30](../docs/design/30-open-source-governance-and-community.md) section 3, neither the frozen Cedar schema, nor a new public crate surface, nor new third-party dependencies (`cedar-policy`, `proptest`) may land without an accepted RFC.

Planning the slice-0 sub-issues of `#21` surfaced three specific conflicts that cannot be resolved downstream without an RFC ruling:

- `docs/design/12` section 2 states *"Context records are always present"* with neutral values, yet also says an unresolved command *"marks `context.command.classes` absent"*. Meanwhile worked policy 5 (`destructive.infra-teardown`) and ten sibling worked rules in section 5 read `context.*` attributes without `has` guards. Marking those attributes optional (`?`) in the `.cedarschema` would break strict validation in `#435`.
- `docs/design/12` section 2 writes `grdr-schema/policy/v1alpha1.cedarschema`, whereas WI-0018 and `#435` use `schema/cedar/`.
- `#434` requires `grdr-policy-ref` to declare no normal dependency on `grdr-core` or `cedar-policy` (`cargo tree -p grdr-policy-ref -e normal` clean), while `#1595` places `derive` and `degrade` inside `grdr_core::policy` and `#1597` requires `grdr_policy_ref::{derive, degrade}` to run over the exact same Rust input and output types without shared evaluator logic (D-63).

This RFC resolves each ambiguity before implementation begins.

## Design

### 1. Scope and layer placement

This RFC fixes the slice-0 surface needed by `#432`, `#434`, `#435`, `#436`, `#1600`, `#1602`, `#1595`, and `#1597`. The mode transform (`#217`, `#218`), grant index (`#219`, `#220`), per-rule read sets (`#216`), pack compiler (`#71`), AuthZEN mapping (`docs/design/12` section 15), `cedar-policy-symcc`/cvc5 (`docs/design/12` section 7), and `grdr.policy.v1alpha1` protobuf messages remain outside this RFC.

**Layering and `ARCH-013`:** `grdr_core::policy` sits in layer 1 (`crates/grdr-core`). Its non-test code does no I/O, reads no system clock, draws no entropy, uses no `unsafe`, contains no panic paths, obeys `#![deny(clippy::arithmetic_side_effects)]`, and builds for `wasm32-unknown-unknown` (ADR-0006). Within `grdr-core`, `policy` imports only layer-0 `grdr-schema`, layer-1 `grdr-model`, `cedar-policy`, and modules inside `policy::*`; it never imports `crate::analyze`, `crate::session`, `crate::detect`, `crate::discover`, or `crate::compile`.

### 2. R1: The `Grdr` v1alpha1 Cedar schema

The normative schema for Cedar 4.14.1 (language 4.6) is the verbatim `.cedarschema` text below.

#### Design rules encoded in the schema

1. **Entity inventory (6 principal-side-only + 12 resources = 18 entity types).**
   - Six principal-side-only entities: `Organisation`, `Group`, `Device`, `AgentInstance`, `Session`, `Process`.
   - Twelve resource entities, every one carrying `classes: Set<String>`: `Agent` (shared with `AgentInstance`'s parent chain and `agent.spawn`'s resource), `Executable`, `Path`, `Endpoint`, `ModelEndpoint`, `McpServer`, `McpTool`, `Credential`, `ConfigTarget`, `ElevationRoute`, `UiTarget`, `Sink`.
   - **Privacy boundary (P8, D-51):** No entity attribute holds a human pseudonym, user name, email address, or OS user identifier.
2. **Principal applicability per action.**
   - Thirteen operational actions (`exec`, `file.read`, `file.write`, `file.delete`, `net.connect`, `net.request`, `llm.request`, `mcp.connect`, `mcp.call`, `cred.use`, `config.change`, `elevate`, `ui.act`) admit `[Session, Process]`. This supports `principal is Grdr::Session` (policies 1, 2a, 3, 4, 5, 6, 13, 15), `principal is Grdr::Process` on `file.write`/`file.delete` (policy 16b), and unscoped `principal` rules on `cred.use`, `mcp.connect`, `mcp.call`, and `llm.request` (policies 2b, 7, 8, 12, 16a, 17) so unattributed host processes and sessions both match.
   - `agent.spawn` and `data.flow` admit `[Session]` only: only an existing `Session` spawns a child agent with `context.child` containment tracking (policy 14), and `data.flow` operates on session-carried taint labels (`context.session.labels`, which `#436` keeps empty for `Process`). This excludes `Process` on `agent.spawn` and `data.flow`, and excludes non-principal entities (`Organisation`, `Group`, `Device`, `AgentInstance`, resource types) on every action.
3. **Action groups (`file`, `net`, `mcp`, `any`).**
   - Action groups `"any"`, `"file"` (`in [Action::"any"]`), `"net"` (`in [Action::"any"]`), and `"mcp"` (`in [Action::"any"]`) omit `appliesTo`, so no authorisation request can invoke a group directly.
   - Leaf actions join their group via `in [Action::"<group>"]` (or `in [Action::"any"]`), making `"any"` contain all 15 actions transitively under Cedar's `in` semantics.
4. **Reserved `schedule` field.**
   - `ScheduleContext` is `{}` (an empty required record) in v1alpha1. Every request passes `"schedule": {}` so context records stay uniformly present without smuggling raw wall-clock values into cached evaluation keys (`docs/design/12` section 2). Concrete schedule predicates (such as window tags) are reserved for a later schema revision.
5. **String representations for closed vocabularies.**
   - Attributes whose values are closed enumerations in Rust (`os`, `profile`, `tier`, `containment`, `actor_kind`, `control_point`, `transport`, `mode`, `cloud.provider`, `attribution.actor_kind`) use Cedar `String` attributes so rules can write equality comparisons such as `principal.actor_kind == "undetermined"` (policy 16b) and `context.mode == "release"` (policy 16a). Input builders validate and emit these strings from closed Rust enums only.

#### Verbatim `v1alpha1.cedarschema`

```cedar
namespace Grdr {
  type SessionContext = {
    labels: Set<String>,
    label_epoch: Long,
  };

  type AttributionContext = {
    grade: Long,
    actor_kind: String,
    evidence: Set<String>,
  };

  type AssuranceContext = {
    visibility: Long,
    control: Long,
    tamper: Long,
    fail_closed: Bool,
  };

  type ScheduleContext = {};

  type CommonContext = {
    session: SessionContext,
    grants: Set<String>,
    attribution: AttributionContext,
    assurance: AssuranceContext,
    facts: Set<String>,
    control_point: String,
    schedule: ScheduleContext,
  };

  entity Organisation;

  entity Group in [Group, Organisation];

  entity Device in [Group] {
    os: String,
    profile: String,
  };

  entity Agent {
    tier: String,
    classes: Set<String>,
  };

  entity AgentInstance in [Agent, Device, Group];

  entity Session in [Session, AgentInstance] {
    depth: Long,
    contained: Bool,
    containment: String,
    classes: Set<String>,
  };

  entity Process in [Device] {
    actor_kind: String,
    agent_capable_host: Bool,
    classes: Set<String>,
  };

  entity Executable {
    classes: Set<String>,
  };

  entity Path {
    classes: Set<String>,
    in_workspace: Bool,
  };

  entity Endpoint {
    classes: Set<String>,
    port: Long,
  };

  entity ModelEndpoint {
    classes: Set<String>,
    provider: String,
  };

  entity McpServer {
    classes: Set<String>,
    transport: String,
    identity_pinned: Bool,
  };

  entity McpTool in [McpServer] {
    classes: Set<String>,
    manifest_pinned: Bool,
    write_capable: Bool,
  };

  entity Credential {
    classes: Set<String>,
  };

  entity ConfigTarget {
    classes: Set<String>,
  };

  entity ElevationRoute {
    classes: Set<String>,
  };

  entity UiTarget {
    classes: Set<String>,
  };

  entity Sink {
    classes: Set<String>,
  };

  action "any";
  action "file" in [Action::"any"];
  action "net" in [Action::"any"];
  action "mcp" in [Action::"any"];

  action "exec" in [Action::"any"] appliesTo {
    principal: [Session, Process],
    resource: [Executable],
    context: {
      session: SessionContext,
      grants: Set<String>,
      attribution: AttributionContext,
      assurance: AssuranceContext,
      facts: Set<String>,
      control_point: String,
      schedule: ScheduleContext,
      command: {
        classes: Set<String>,
      },
    },
  };

  action "file.read" in [Action::"file"] appliesTo {
    principal: [Session, Process],
    resource: [Path],
    context: {
      session: SessionContext,
      grants: Set<String>,
      attribution: AttributionContext,
      assurance: AssuranceContext,
      facts: Set<String>,
      control_point: String,
      schedule: ScheduleContext,
      recursive: Bool,
    },
  };

  action "file.write" in [Action::"file"] appliesTo {
    principal: [Session, Process],
    resource: [Path],
    context: {
      session: SessionContext,
      grants: Set<String>,
      attribution: AttributionContext,
      assurance: AssuranceContext,
      facts: Set<String>,
      control_point: String,
      schedule: ScheduleContext,
      recursive: Bool,
    },
  };

  action "file.delete" in [Action::"file"] appliesTo {
    principal: [Session, Process],
    resource: [Path],
    context: {
      session: SessionContext,
      grants: Set<String>,
      attribution: AttributionContext,
      assurance: AssuranceContext,
      facts: Set<String>,
      control_point: String,
      schedule: ScheduleContext,
      recursive: Bool,
    },
  };

  action "net.connect" in [Action::"net"] appliesTo {
    principal: [Session, Process],
    resource: [Endpoint],
    context: CommonContext,
  };

  action "net.request" in [Action::"net"] appliesTo {
    principal: [Session, Process],
    resource: [Endpoint],
    context: {
      session: SessionContext,
      grants: Set<String>,
      attribution: AttributionContext,
      assurance: AssuranceContext,
      facts: Set<String>,
      control_point: String,
      schedule: ScheduleContext,
      http: {
        classes: Set<String>,
      },
      cloud: {
        provider: String,
        account_classes: Set<String>,
        tenant_classes: Set<String>,
        verified: Bool,
      },
    },
  };

  action "llm.request" in [Action::"any"] appliesTo {
    principal: [Session, Process],
    resource: [ModelEndpoint],
    context: {
      session: SessionContext,
      grants: Set<String>,
      attribution: AttributionContext,
      assurance: AssuranceContext,
      facts: Set<String>,
      control_point: String,
      schedule: ScheduleContext,
      tenant: {
        classes: Set<String>,
        verified: Bool,
      },
    },
  };

  action "mcp.connect" in [Action::"mcp"] appliesTo {
    principal: [Session, Process],
    resource: [McpServer],
    context: CommonContext,
  };

  action "mcp.call" in [Action::"mcp"] appliesTo {
    principal: [Session, Process],
    resource: [McpTool],
    context: {
      session: SessionContext,
      grants: Set<String>,
      attribution: AttributionContext,
      assurance: AssuranceContext,
      facts: Set<String>,
      control_point: String,
      schedule: ScheduleContext,
      args: {
        classes: Set<String>,
        extracted: Bool,
      },
    },
  };

  action "cred.use" in [Action::"any"] appliesTo {
    principal: [Session, Process],
    resource: [Credential],
    context: {
      session: SessionContext,
      grants: Set<String>,
      attribution: AttributionContext,
      assurance: AssuranceContext,
      facts: Set<String>,
      control_point: String,
      schedule: ScheduleContext,
      mode: String,
    },
  };

  action "agent.spawn" in [Action::"any"] appliesTo {
    principal: [Session],
    resource: [Agent],
    context: {
      session: SessionContext,
      grants: Set<String>,
      attribution: AttributionContext,
      assurance: AssuranceContext,
      facts: Set<String>,
      control_point: String,
      schedule: ScheduleContext,
      child: {
        depth: Long,
        contained: Bool,
        classes: Set<String>,
      },
    },
  };

  action "config.change" in [Action::"any"] appliesTo {
    principal: [Session, Process],
    resource: [ConfigTarget],
    context: {
      session: SessionContext,
      grants: Set<String>,
      attribution: AttributionContext,
      assurance: AssuranceContext,
      facts: Set<String>,
      control_point: String,
      schedule: ScheduleContext,
      change_classes: Set<String>,
    },
  };

  action "elevate" in [Action::"any"] appliesTo {
    principal: [Session, Process],
    resource: [ElevationRoute],
    context: CommonContext,
  };

  action "ui.act" in [Action::"any"] appliesTo {
    principal: [Session, Process],
    resource: [UiTarget],
    context: CommonContext,
  };

  action "data.flow" in [Action::"any"] appliesTo {
    principal: [Session],
    resource: [Sink],
    context: {
      session: SessionContext,
      grants: Set<String>,
      attribution: AttributionContext,
      assurance: AssuranceContext,
      facts: Set<String>,
      control_point: String,
      schedule: ScheduleContext,
      source_labels: Set<String>,
    },
  };
}
```

#### Strict-validation proof over all 22 worked policies

Every worked policy printed in [docs/design/12](../docs/design/12-policy-engine.md) sections 3 and 5 type-checks under Cedar strict mode against the schema above without modification:

| Policy (`design/12`) | `@id` | Principal scope | Action(s) | Resource narrowed to | Reads checked strictly |
|---|---|---|---|---|---|
| 1 (section 5) | `essentials.control-files.write` | `Session` | `file.write`, `file.delete`, `config.change` | `[Path, ConfigTarget]` (unscoped) | `resource.classes: Set<String>` on both |
| 2a (section 5) | `essentials.bypass-flags` | `Session` | `exec`, `agent.spawn`, `config.change` | `[Executable, Agent, ConfigTarget]` | `context.facts: Set<String>` on all three |
| 2b (section 5) | `essentials.honeytoken` | unscoped (`[Session, Process]`) | `cred.use` | `Credential` | `resource.classes: Set<String>` |
| 3 (section 5) | `essentials.delete-outside-workspace` | `Session` | `file.delete` | `[Path]` (narrows from `file.delete`) | `context.recursive: Bool`, `resource.in_workspace: Bool`, `resource.classes` |
| 4 src (section 3) | `essentials.cred-store.read` | `Session` | `file.read` | `[Path]` (narrows from `file.read`) | `resource.classes: Set<String>` |
| 4 cmp (section 3) | `local/.../essentials.cred-store.read` | `Session` | `file.read` | `[Path]` (narrows from `file.read`) | `resource.classes`, `context.grants: Set<String>` |
| 5 (section 5) | `destructive.infra-teardown` | `Session` | `exec` | `[Executable]` | `context.command.classes: Set<String>` |
| 6 (section 5) | `destructive.opaque-command` | `Session` | `exec` | `[Executable]` | `context.facts`, `context.assurance.control: Long` |
| 7 (section 5) | `mcp.server-allow-list` | unscoped (`[Session, Process]`) | `mcp.connect` | `McpServer` | `resource.identity_pinned: Bool`, `resource.classes` |
| 8 (section 5) | `mcp.tool-pin` | unscoped (`[Session, Process]`) | `mcp.call` | `McpTool` | `resource.manifest_pinned: Bool` |
| 9 (section 5) | `supply.publish` | `Session` | `data.flow` | `Sink` | `resource.classes` |
| 10 (section 5) | `dataflow.trifecta` | `Session` | `data.flow` | `Sink` | `context.session.labels: Set<String>` |
| 11 (section 5) | `dataflow.secret-to-sink` | `Session` | `data.flow` | `Sink` | `context.session.labels: Set<String>` |
| 12a (section 5) | `egress.model-provider` | unscoped (`[Session, Process]`) | `llm.request` | `ModelEndpoint` | `resource.classes` |
| 12b (section 5) | `egress.model-tenant` | unscoped (`[Session, Process]`) | `llm.request` | `ModelEndpoint` | `context.tenant.verified: Bool`, `context.tenant.classes` |
| 13a (section 5) | `cloud.aws-account-pin` | `Session` | `net.request` | `Endpoint` | `context.cloud.provider`, `verified`, `account_classes` |
| 13b (section 5) | `cloud.prod-mutation` | `Session` | `net.request` | `Endpoint` | `context.cloud.account_classes`, `context.http.classes` |
| 14 (section 5) | `agents.subagent-ceiling` | `Session` | `agent.spawn` | `Agent` | `context.child.{depth, classes, contained}`, `principal.contained` |
| 15 (section 5) | `agents.min-assurance.prod-cred` | `Session` | `cred.use` | `Credential` | `resource.classes`, `principal.contained`, `context.assurance.{control, fail_closed}` |
| 16a (section 5) | `agents.min-attribution.cred-release` | unscoped (`[Session, Process]`) | `cred.use` | `Credential` | `context.mode: String`, `context.attribution.grade: Long` |
| 16b (section 5) | `agents.undetermined.control-files` | `Process` | `file.write`, `file.delete` | `[Path]` (narrows from `file.*`) | `principal.agent_capable_host`, `principal.actor_kind`, `resource.classes` |
| 17 (section 5) | `secrets.prompt-redact` | unscoped (`[Session, Process]`) | `llm.request` | `ModelEndpoint` | `context.facts` |

### 3. R2: Schema file location, `grdr-schema` embedding, and RFC 0007 amendment

The canonical schema file lives at `schema/cedar/v1alpha1.cedarschema`.

- This keeps all language-neutral schema sources under `schema/` (`schema/codes/`, `schema/cedar/`, `schema/fixtures/`), matching `docs/design/03` section 11, `#435`'s write set, and `#392`'s drift checks, without adding a redundant top-level `grdr-schema/` directory beside `crates/grdr-schema/`.
- Layer-0 crate `grdr-schema` exposes `crates/grdr-schema/src/cedar.rs`:
  - `pub const SCHEMA_VERSION: &str = "v1alpha1";`
  - `pub const V1ALPHA1: &str = include_str!("../../../schema/cedar/v1alpha1.cedarschema");`
- `grdr-schema` takes zero new dependencies (`#![forbid(unsafe_code)]`, `#![deny(clippy::arithmetic_side_effects)]`, constants only).
- `docs/design/12` section 2 updates `grdr-schema/policy/v1alpha1.cedarschema` to `schema/cedar/v1alpha1.cedarschema` in a design-doc follow-up.

#### Amendments to [RFC 0007](./0007-grdr-model-and-grdr-schema-slice-0-surface.md) (`ADR-0038`)

RFC 0007 section 2 R10 fixed `crates/grdr-schema/src/` at seven files and forbade `include_str!` and non-`src/` files in `rustc --emit=dep-info` under `tests/construction.rs` (`layout`), while section 11 requires any module-tree change to name RFC 0007 explicitly as amended. This RFC amends RFC 0007 sections 2 R10, 8, and 11:

1. **Module tree (`crates/grdr-schema/src/`):** Adds `crates/grdr-schema/src/cedar.rs` as an eighth source file alongside RFC 0007's seven (`lib.rs`, `codes.rs`, `codes/registry.rs`, `codes/generated.rs`, `limits.rs`, `limits/registry.rs`, `limits/generated.rs`). Following the incremental `layout` design also proposed by RFC 0016 (`health`), `#435` writes `layout` in `tests/construction.rs` to assert the exact file set for whichever modules among `{codes, limits, health, cedar}` are declared in `src/lib.rs`, so `#278`, `#279`, `#435`, and RFC 0016's items can land in any order without breaking `layout` in between (yielding 11 files when both `health` and `cedar` are present).
2. **`dep-info` and token allow-list for `cedar.rs` only:** `layout`'s `rustc --emit=dep-info` check admits `schema/cedar/v1alpha1.cedarschema` solely as the source embedded by `crates/grdr-schema/src/cedar.rs`, and its token scan permits `include_str!` solely in `crates/grdr-schema/src/cedar.rs`. Every other hand-written file under `crates/grdr-schema/src/` (`lib.rs`, `codes*`, `limits*`, `health*`) keeps RFC 0007's strict ban on `include!`, `include_str!`, `include_bytes!`, `path`, `cfg_attr`, inline `mod` bodies, and `macro_rules!` outside `lib.rs`.
3. **Trust-core list (`security/trust-core.paths`):** Proposes adding `crates/grdr-schema/src/cedar.rs` alongside RFC 0007's trust-core paths (`schema/cedar/**` is already high-tier under `schema/**`).

### 4. R3: Neutral values and `absent`/`pending` sets

**Ruling:** All Cedar context records and fields remain **required** in `v1alpha1.cedarschema`. When a control point or analyser cannot supply a field (for example an `Unresolved` command classifier or missing telemetry), the request builder writes the field's typed neutral value into the Cedar `Context` and records its `ContextField` path in the engine-side `absent` or `pending` set carried on `CedarRequest`. Neither `absent` nor `pending` is a Cedar context attribute.

**Neutral values:**

| Cedar type | Neutral value |
|---|---|
| `Set<String>` | `[]` (empty set) |
| `Bool` | `false` |
| `Long` | `0` |
| `String` | `""` (empty string) |
| `ScheduleContext` | `{}` |

**Rationale:**

1. Every one of the 22 worked policies in `docs/design/12` sections 3 and 5 reads context attributes (`context.command.classes`, `context.recursive`, `context.tenant.*`, `context.cloud.*`, `context.http.classes`, `context.child.*`, `context.mode`, `context.assurance.*`, `context.attribution.grade`, `context.facts`, `context.session.labels`) without `has` guards. Keeping context attributes required lets `#435` validate all 22 worked rules verbatim without introducing `has` boilerplate or modifying existing rule prose.
2. Under `docs/design/12` section 4, `absent` and `pending` govern rows 6 and 7 (`DEFER` and not-evaluable fallback) using each rule's computed read set (`#216`) intersected with the request's missing inputs. Exposing `absent` and `pending` inside Cedar policy `Context` would allow pack authors to bypass the engine's row-6 and row-7 fail-closed/fallback semantics with ad-hoc `when`/`unless` clauses. Keeping them engine-side enforces `P14` and `ARCH` invariants.
3. For `context.attribution` when absent, `grade` takes neutral `0`, matching `#436` AC-3 (`attribution.grade is 0 and absent names attribution`). For `context.cloud` and `context.tenant` when unverified or absent, `verified` is `false` (`docs/design/12` section 2; `D-16`), making rules guarded by `context.tenant.verified` or `context.cloud.verified` inert while `not_evaluable` detection still triggers via the rule's read set meeting `absent`.
4. `docs/design/12` section 2 line 80 ("marks `context.command.classes` absent") is clarified to state that `context.command.classes` takes `[]` in Cedar `Context` while `"context.command.classes"` is listed in `CedarRequest::absent`.

### 5. R4: Public Rust surface of `grdr_core::policy` and shared `grdr-model` types

#### Stability class and `ARCH-007` exposure

`grdr-core` stays `class = "experimental"` in [`surfaces.toml`](../surfaces.toml) (`D-60`). Because `surfaces.toml`'s `[[crate]]` schema accepts only the three keys `name`, `class`, and `rfc` (`rfc = "0005"` at creation, updated or kept under `experimental`), this RFC introduces no extra keys into `surfaces.toml`. Because `#435` R3 returns `cedar_policy::Schema` directly from `grdr_core::policy::schema::load()`, and request builders expose `cedar_policy::{Request, Entities}`, `ARCH-007` authorises `cedar-policy` public exposure on `grdr-core` only while `grdr-core` remains `experimental` (tracked via `ARCH-007` configuration in `architecture.toml` and this RFC). Moving `grdr-core` to `beta` or `stable` in a later RFC requires wrapping `cedar_policy::{Schema, Request, Entities}` behind opaque Guardrails types first so Cedar upgrades cannot leak breaking type changes into `beta` or `stable` APIs.

#### Shared value types in `grdr-model` and amendment to [RFC 0009](./0009-grdr-model-slice-0-surface.md) (`ADR-0041`)

`#434` forbids `grdr-policy-ref` from taking any normal dependency on `grdr-core` or `cedar-policy`, whereas `#1595` implements `derive` and `degrade` in `grdr_core::policy` and `#1597` tests `grdr_policy_ref::{derive, degrade}` over the exact same Rust input and output types. Hosting the pure policy-verdict contract types in `grdr-model` (layer 1, zero `cedar-policy` dependency) and re-exporting them publicly from `grdr_core::policy::{self, derive, degrade}` resolves this cleanly:

- `grdr-policy-ref` depends normally on `grdr-model` only (`#434` AC-2 passes).
- `grdr_core::policy` exposes the complete R4 surface directly (`grdr_core::policy::derive`, `grdr_core::policy::degrade`, `grdr_core::policy::{ControlPointCaps, Derived, Executed, ...}`).
- Differential tests in `grdr-core` (`tests/policy_derive_differential.rs`) pass identical values to both implementations with zero translation and zero shared evaluator code (`D-63`).

Under RFC 0009 section 13 and section 16, adding public types to `grdr-model` amends RFC 0009 (`ADR-0041`). This RFC amends RFC 0009 sections 8, 9, and 13 and obeys every RFC 0009 convention:

1. **One path per item (RFC 0009 R3):** All public policy contract types, enums, and `PolicyRuleIdError` sit at `grdr_model`'s crate root (implemented in private submodules) and are re-exported into `grdr_core::policy`.
2. **Closed wire enums (RFC 0009 R5 and section 13):** Every fieldless closed enum added to `grdr-model` (`ActionClass`, `ControlPoint`, `Verdict`, `ExecutedVerb`, `DerivationRow`, `ModifyBudget`, `EnforcedMode`, `ApprovalGrade`, `Obligation`, `Transform`, `NormaliserOutcome`, `ControlPointCoverage`, `DecisionReason`) is declared through RFC 0009's `wire_enum!` macro with lowercase `WireName`-grammar words, providing `pub const VARIANTS: &'static [Self]`, `pub const fn as_str(self) -> &'static str`, `pub const fn wire_name(self) -> WireName`, and `impl LogSafe` (`LogValue::Enum`). Consistent with RFC 0009 section 13, these enums are exhaustive while `grdr-model` is `experimental` (no `#[non_exhaustive]`).
3. **Existing RFC 0009 types reused:** Reuses `grdr_model::Tamper` (`User < Admin < Platform`, RFC 0009 section 8) directly in `AssuranceInput` instead of adding a duplicate rank enum, alongside `OrgId`, `DeviceId`, `SessionId`, `AgentInstanceId`, `GrantId`, `InstallProfile`, `LogSafe`, `LogValue`, and `WireName`.
4. **Error registration (RFC 0009 section 9):** Registers `GRDR-MODEL-0012` (`RULE_ID_FORM`, `class = "input"`, `connect = "invalid_argument"`) in `schema/codes/model.toml` for `PolicyRuleIdError`.
5. **Deterministic containers and `P8`:** Uses `BTreeSet` rather than hash sets across all contract types so iteration order is identical on Linux, macOS, Windows, C ABI, and `wasm32-unknown-unknown`, and leaks no runtime identifiers in `Debug` or logs.

#### Exact shared contract signatures (owned by `grdr-model`, re-exported by `grdr_core::policy`)

```rust
// Every fieldless enum below is declared with RFC 0009's `wire_enum!`, giving
// VARIANTS, as_str(), wire_name(), and LogSafe (LogValue::Enum).

wire_enum! {
    pub enum ActionClass {
        Exec => "exec",
        FileRead => "file.read",
        FileWrite => "file.write",
        FileDelete => "file.delete",
        NetConnect => "net.connect",
        NetRequest => "net.request",
        LlmRequest => "llm.request",
        McpConnect => "mcp.connect",
        McpCall => "mcp.call",
        CredUse => "cred.use",
        AgentSpawn => "agent.spawn",
        ConfigChange => "config.change",
        Elevate => "elevate",
        UiAct => "ui.act",
        DataFlow => "data.flow",
    }
}

wire_enum! {
    pub enum ControlPoint {
        Hook => "hook",
        McpBroker => "mcp-broker",
        Proxy => "proxy",
        Sandbox => "sandbox",
        Sensor => "sensor",
        Gateway => "gateway",
        Browser => "browser",
        Connector => "connector",
    }
}

wire_enum! {
    pub enum Verdict {
        Allow => "allow",
        Deny => "deny",
        Modify => "modify",
        StepUp => "step_up",
        Defer => "defer",
    }
}

wire_enum! {
    pub enum ExecutedVerb {
        Allow => "allow",
        Deny => "deny",
        DenyWithRetryToken => "deny-with-retry-token",
        Hold => "hold",
        Modify => "modify",
        ObserveOnly => "observe-only",
    }
}

wire_enum! {
    pub enum DerivationRow {
        MalformedInput => "row-1-malformed-input",
        PolicyError => "row-2-policy-error",
        ModifyRemedy => "row-3-modify-remedy",
        BlockOrUnmetAsk => "row-4-block-or-unmet-ask",
        AskStepUp => "row-5-ask-step-up",
        PendingDefer => "row-6-pending-defer",
        NotEvaluableFallback => "row-7-not-evaluable",
        BasePermitAllow => "row-8-base-permit",
        DefaultDeny => "row-9-default-deny",
    }
}

wire_enum! {
    #[derive(Default)]
    pub enum ModifyBudget {
        #[default]
        Fresh => "fresh",
        Once => "once",
        Twice => "twice",
    }
}

wire_enum! {
    pub enum EnforcedMode {
        Ask => "ask",
        Block => "block",
    }
}

wire_enum! {
    #[derive(PartialOrd, Ord)]
    pub enum ApprovalGrade {
        G0 => "g0",
        G1 => "g1",
        G2 => "g2",
        G3 => "g3",
    }
}

wire_enum! {
    pub enum Obligation {
        Receipt => "receipt",
        Expect => "expect",
        Snapshot => "snapshot",
        PinRecorder => "pin-recorder",
        NotifyUser => "notify-user",
        NotifySponsor => "notify-sponsor",
    }
}

wire_enum! {
    pub enum Transform {
        RedactSecrets => "redact-secrets",
        WrapLauncher => "wrap-launcher",
        SwapCredential => "swap-credential",
    }
}

wire_enum! {
    pub enum NormaliserOutcome {
        Valid => "valid",
        Unresolved => "unresolved",
        Malformed => "malformed",
    }
}

wire_enum! {
    #[derive(PartialOrd, Ord)]
    pub enum ControlPointCoverage {
        None => "none",
        Request => "request",
        ScopedBoundary => "scoped-boundary",
        MandatoryBoundary => "mandatory-boundary",
    }
}

wire_enum! {
    pub enum DecisionReason {
        MalformedNormaliser => "malformed-normaliser",
        PolicyError => "policy-error",
        RemedyModify => "remedy-modify",
        BlockedByRule => "blocked-by-rule",
        AskGradeUnavailable => "ask-grade-unavailable",
        AskStepUp => "ask-step-up",
        PendingDefer => "pending-defer",
        PendingDeadlineExpired => "pending-deadline-expired",
        NotEvaluableStepUp => "not-evaluable-step-up",
        NotEvaluableExpect => "not-evaluable-expect",
        NotEvaluableCoverageGap => "not-evaluable-coverage-gap",
        BasePermit => "base-permit",
        DefaultDeny => "default-deny",
        ObligationUnmet => "obligation-unmet",
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PendingWindow {
    WithinDeadline { retry_after_ms: u64 },
    DeadlineExpired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PolicyRuleIdError {
    Empty,
    TooLong,
    InvalidCharacter,
}
// Implements Coded (GRDR-MODEL-0012) and LogSafe (LogValue::Code); no Display or Error (RFC 0009 R4, R6).

/// Validated non-empty identifier for a rule (`<rule-id>` or `<layer>/<pack>@<ver>/<rule-id>`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyRuleId(String);

impl PolicyRuleId {
    /// Parses printable non-whitespace ASCII up to `POLICY_RULE_ID_MAX` bytes, rejecting `..` segments.
    pub fn parse(text: &str) -> Result<Self, PolicyRuleIdError>;
    pub fn as_str(&self) -> &str;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForbidMatch {
    pub rule_id: PolicyRuleId,
    pub mode: EnforcedMode,
    pub min_grade: ApprovalGrade,
    pub remedy: Option<Transform>,
    pub obligations: BTreeSet<Obligation>,
    /// True only for a rule authored in the `user` layer under `InstallProfile::User`
    /// where D-31's disclosed time lock stands in for `ApprovalGrade::G1`.
    pub user_local_time_lock: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct NotEvaluableRule {
    pub rule_id: PolicyRuleId,
    pub fail_closed: bool,
    pub min_grade: ApprovalGrade,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlPointCaps {
    pub verbs: BTreeSet<ExecutedVerb>,
    pub transforms: BTreeSet<Transform>,
    pub can_hold: bool,
    pub hold_deadline_ms: Option<u64>,
    pub fails_closed: bool,
    pub obligations: BTreeSet<Obligation>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeriveInput {
    pub action_class: ActionClass,
    pub normaliser: NormaliserOutcome,
    pub errored_policies: BTreeSet<PolicyRuleId>,
    pub satisfied_forbids: Vec<ForbidMatch>,
    pub base_permit_matched: bool,
    pub permit_obligations: BTreeSet<Obligation>,
    pub lifted_grant_obligations: BTreeSet<Obligation>,
    pub pending_rules: BTreeSet<PolicyRuleId>,
    pub not_evaluable_rules: Vec<NotEvaluableRule>,
    pub lifted_grants: BTreeSet<PolicyRuleId>,
    pub control_coverage: ControlPointCoverage,
    pub os_control_point_attached: bool,
    pub offered_grades: BTreeSet<ApprovalGrade>,
    pub pending_window: PendingWindow,
    pub modify_budget: ModifyBudget,
    pub caps: ControlPointCaps,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Derived {
    pub row: DerivationRow,
    pub verdict: Verdict,
    pub reason: DecisionReason,
    pub determining_rules: BTreeSet<PolicyRuleId>,
    pub obligations: BTreeSet<Obligation>,
    pub not_evaluable: BTreeSet<PolicyRuleId>,
    pub errored_rules: BTreeSet<PolicyRuleId>,
    pub coverage_gap: bool,
    pub retry_after_ms: Option<u64>,
    pub min_grade: Option<ApprovalGrade>,
    pub transform: Option<Transform>,
    pub next_modify_budget: ModifyBudget,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Executed {
    pub decided: Verdict,
    pub executed_as: ExecutedVerb,
    pub hold_ms: Option<u64>,
    pub retry_after_ms: Option<u64>,
    pub would_be: Option<Verdict>,
    pub coverage_gap: bool,
}
```

#### Module layout and signatures in `grdr_core::policy`

```rust
pub mod schema {
    pub const VERSION: &str = grdr_schema::cedar::SCHEMA_VERSION;
    pub fn load() -> Result<cedar_policy::Schema, PolicyError>;
}

pub mod request {
    pub mod inputs;
    pub mod common;
    pub mod principal;
    pub mod exec;
    // Per-action modules for the remaining 14 actions (#1602) follow exec's pattern.

    pub struct CommonParts { /* private: validated principal/ancestor entities, common context, absent, pending */ }
    pub struct CedarRequest { /* private: request, entities, absent, pending */ }

    impl CedarRequest {
        pub fn request(&self) -> &cedar_policy::Request;
        pub fn entities(&self) -> &cedar_policy::Entities;
        pub fn absent(&self) -> &BTreeSet<inputs::ContextField>;
        pub fn pending(&self) -> &BTreeSet<inputs::ContextField>;
        pub fn into_parts(self) -> (
            cedar_policy::Request,
            cedar_policy::Entities,
            BTreeSet<inputs::ContextField>,
            BTreeSet<inputs::ContextField>,
        );
    }

    pub fn build_common(
        principal: &inputs::PrincipalInput,
        common: &inputs::CommonInput,
        schema: &cedar_policy::Schema,
    ) -> Result<CommonParts, PolicyError>;

    pub fn build_exec(
        common: &CommonParts,
        exec: &inputs::ExecInput,
        schema: &cedar_policy::Schema,
    ) -> Result<CedarRequest, PolicyError>;

    pub fn build_request(
        principal: &inputs::PrincipalInput,
        common: &inputs::CommonInput,
        action: &inputs::ActionInput,
        schema: &cedar_policy::Schema,
    ) -> Result<CedarRequest, PolicyError>;

    pub fn build_derived_data_flow(
        common: &CommonParts,
        flow: &inputs::DataFlowInput,
        schema: &cedar_policy::Schema,
    ) -> Result<CedarRequest, PolicyError>;
}

pub mod derive {
    pub use grdr_model::{
        ActionClass, ApprovalGrade, ControlPointCaps, ControlPointCoverage, DecisionReason,
        DerivationRow, DeriveInput, Derived, EnforcedMode, ForbidMatch, ModifyBudget,
        NormaliserOutcome, NotEvaluableRule, Obligation, PendingWindow, PolicyRuleId,
        PolicyRuleIdError, Transform, Verdict,
    };

    pub fn derive(input: &DeriveInput) -> Derived;
}

pub mod degrade {
    pub use grdr_model::{ControlPointCaps, Derived, Executed, ExecutedVerb};

    pub fn degrade(derived: &Derived, caps: &ControlPointCaps) -> Executed;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SchemaLoadFailure {
    ParseError,
    UnexpectedWarning,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SchemaValidationFailure {
    RequestRejected,
    EntityHierarchyRejected,
    ContextRejected,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyError {
    SchemaLoadFailed { kind: SchemaLoadFailure },
    EnforcingLabelsOverLimit { limit: u64, actual: usize },
    ClassesOverLimit { field: request::inputs::ContextField, limit: u64, actual: usize },
    FactsOverLimit { limit: u64, actual: usize },
    GrantsOverLimit { limit: u64, actual: usize },
    EvidenceOverLimit { limit: u64, actual: usize },
    SessionChainOverLimit { limit: u64, actual: usize },
    MalformedInput { field: &'static str },
    SchemaRejected { kind: SchemaValidationFailure },
    EvaluationFailed { errored_rules: BTreeSet<PolicyRuleId> },
    ObligationUnmet { obligation: Obligation },
    ParserInputOverLimit { limit: u64, actual: usize },
}
// Implements `std::fmt::Display`, `std::error::Error`, `grdr_schema::codes::Coded` (ARCH-017),
// and `grdr_model::LogSafe` (`fn log_value(&self) -> LogValue<'_> { LogValue::Code(self.code()) }`).
```

#### Typed request inputs (`policy::request::inputs`)

To align directly with `#436` R1-R6 and `#1600` R1-R3 while preventing raw paths, raw commands, or human names from entering Cedar (`P8`):

- `OpaqueId`: validated non-empty identifier (`1..=limits::POLICY_OPAQUE_ID_MAX` bytes, printable non-control characters, NFC-clean). Carries `.as_str()` and converts from `grdr-model` typed ids (`OrgId`, `DeviceId`, `SessionId`, `AgentInstanceId`, `McpServerId`, `McpToolId`, `ModelEndpointId`). Never contains a raw path, URL query, argv, or user identifier. `Debug` renders a fixed redacted placeholder (`OpaqueId(<len> bytes)`), never leaking runtime identifiers (`ses_*`, `dev_*`, `prc_*`).
- `ClassTag`: validated non-empty class/fact/label tag string (`1..=limits::POLICY_CLASS_TAG_MAX` bytes, printable ASCII/token grammar, never agent/tool content).
- `ContextField`: closed `#[non_exhaustive]` enum naming each context or sub-record field path verbatim so `absent`, `pending`, and `#216`'s `ReadSet` share one vocabulary:
  `SessionLabels` (`"context.session.labels"`), `SessionLabelEpoch` (`"context.session.label_epoch"`), `Grants` (`"context.grants"`), `Attribution` (`"context.attribution"`), `Assurance` (`"context.assurance"`), `Facts` (`"context.facts"`), `ControlPoint` (`"context.control_point"`), `CommandClasses` (`"context.command.classes"`), `Recursive` (`"context.recursive"`), `HttpClasses` (`"context.http.classes"`), `Cloud` (`"context.cloud"`), `Tenant` (`"context.tenant"`), `Args` (`"context.args"`), `Mode` (`"context.mode"`), `Child` (`"context.child"`), `ChangeClasses` (`"context.change_classes"`), `SourceLabels` (`"context.source_labels"`), plus entity-side fields where telemetry is absent (`ResourceInWorkspace`, `ResourceIdentityPinned`, `ResourceManifestPinned`).
- `LabelKind { Enforcing, Advisory }` and `Label { name: ClassTag, kind: LabelKind }`. `build_common` includes only `Enforcing` labels in `context.session.labels`; `Advisory` labels are dropped silently before any Cedar value is built (`D-09`, ADR-0011). For `PrincipalInput::Process`, `context.session.labels` is always empty (`[]`).
- `PrincipalInput` closed enum:
  - `Session { session: OpaqueId, parent: Option<Box<SessionRef>>, instance: OpaqueId, agent: AgentInput, device: DeviceInput, groups: Vec<GroupInput>, depth: u32, contained: bool, containment: ContainmentMode, classes: Vec<ClassTag> }`
  - `Process { process: OpaqueId, device: DeviceInput, actor_kind: ProcessActorKind, agent_capable_host: bool, classes: Vec<ClassTag> }`
  - Supporting `OrgInput { id: OpaqueId }`, `GroupInput { id: OpaqueId, parent_groups: Vec<OpaqueId>, orgs: Vec<OrgInput> }`, `DeviceInput { id: OpaqueId, os: DeviceOs, profile: InstallProfile, groups: Vec<GroupInput> }`, `AgentInput { id: OpaqueId, tier: AgentTier, classes: Vec<ClassTag> }`, and `SessionRef` (parent `Session` descriptor carrying its own `session`, `parent`, `instance`, `depth`, `contained`, `containment`, `classes`).
- `CommonInput`: `{ labels: Vec<Label>, label_epoch: u64, grants: Vec<PolicyRuleId>, attribution: Option<AttributionInput>, assurance: Option<AssuranceInput>, facts: Option<Vec<ClassTag>>, control_point: ControlPoint, absent: BTreeSet<ContextField>, pending: BTreeSet<ContextField> }`. `AssuranceInput` takes closed enums `VisibilityRank` (`0..=3`), `ControlRank` (`0..=3`), `grdr_model::Tamper` (`User => 0`, `Admin => 1`, `Platform => 2`), and `OnFailure { Open, Closed }` -> `fail_closed: bool`; the AL label is never an input (`#436` R5).
- Per-action inputs: `ExecInput` (with `normaliser: NormaliserOutcome`, `executable: OpaqueId`, `executable_classes: Vec<ClassTag>`, `command_classes: Option<Vec<ClassTag>>`; `Malformed` returns `Err(PolicyError::MalformedInput)` and `Unresolved` writes neutral `[]` and adds `ContextField::CommandClasses` to `absent`), plus typed inputs for the other 14 actions (`FileActionInput` for `file.read`/`file.write`/`file.delete`, `NetConnectInput`, `NetRequestInput`, `LlmRequestInput`, `McpConnectInput`, `McpCallInput`, `CredUseInput`, `AgentSpawnInput`, `ConfigChangeInput`, `ElevateInput`, `UiActInput`, `DataFlowInput`) combined under `ActionInput`.

#### Semantics invariants of `derive` and `degrade`

- **`derive(input)`:**
  1. Applies rows 1 to 9 of `docs/design/12` section 4 in strict order; records the winning `DerivationRow` in `Derived::row`.
  2. Row 3 (`ModifyRemedy`) is evaluated only while `modify_budget` is `Fresh` or `Once` (stepping to `Once` or `Twice`); at `ModifyBudget::Twice`, row 3 is skipped so at most two re-evaluations occur (`#1595` R3).
  3. At Row 4 (`BlockOrUnmetAsk`), each `ForbidMatch` `r` running at `EnforcedMode::Ask` is checked individually: it is grade-satisfiable only when `input.offered_grades.contains(&r.min_grade) || (r.user_local_time_lock && r.min_grade == ApprovalGrade::G1)`. A rule-local `user_local_time_lock` flag never lowers a co-occurring non-user-local rule (such as an `essentials` or `organisation` `Ask` rule) from `DENY` (`AskGradeUnavailable`) to `STEP_UP`.
  4. At Row 7 (`NotEvaluableFallback`), rules whose `rule_id` sits in `input.lifted_grants` are excluded. If any non-lifted rule remains, `Derived::not_evaluable` is populated with **all** non-lifted `not_evaluable` rule ids across every Row 7 outcome, and routing branches strictly as follows:
     - When `input.control_coverage >= ControlPointCoverage::ScopedBoundary && input.os_control_point_attached`: verdict is `Verdict::Allow`, `reason` is `DecisionReason::NotEvaluableExpect`, `Obligation::Expect` is merged into obligations, `coverage_gap = false`, and `determining_rules` holds the non-lifted rule ids.
     - Otherwise (`!(input.control_coverage >= ControlPointCoverage::ScopedBoundary && input.os_control_point_attached)`, including boundary callers with `os_control_point_attached == false` such as launch containment or forced proxy): if any non-lifted rule has `fail_closed == true`, verdict is `Verdict::StepUp` (`DecisionReason::NotEvaluableStepUp`), `determining_rules` holds the fail-closed non-lifted rule ids, `min_grade` holds the highest `min_grade` among them, and `coverage_gap = false`; else verdict is `Verdict::Allow` (`DecisionReason::NotEvaluableCoverageGap`), `determining_rules` is empty, and `coverage_gap = true`.
  5. Obligation merging and must-obligation enforcement across Rows 3 to 8: collect candidate obligations from `Obligation::Receipt`, `input.permit_obligations`, `input.lifted_grant_obligations`, plus obligations of determining `satisfied_forbids` (Rows 3, 4, 5) and `Obligation::Expect` (Row 7 boundary branch when `os_control_point_attached == true`; `Obligation::Expect` is never emitted when `os_control_point_attached == false`, `#1595` R5). Whenever the candidate verdict is non-`DENY` and candidate obligations contain `Obligation::Snapshot` while `!caps.obligations.contains(&Obligation::Snapshot)`, promote the verdict to `Verdict::Deny` with `reason = DecisionReason::ObligationUnmet`, preserving the winning `DerivationRow` and `Obligation::Receipt` while dropping action-execution obligations (`Snapshot`, `Expect`).
- **`degrade(derived, caps)`:**
  1. If `!caps.verbs.contains(&ExecutedVerb::Deny)` (observe-only control point), executes `ExecutedVerb::ObserveOnly` with `would_be = Some(derived.verdict)` and `coverage_gap = true`.
  2. Otherwise, never executes a less restrictive verb than `derived.verdict`:
     - `Deny` -> `ExecutedVerb::Deny`.
     - `Modify` -> `ExecutedVerb::Modify` if `caps.verbs.contains(&ExecutedVerb::Modify)`, else `ExecutedVerb::Deny`.
     - `StepUp` -> `ExecutedVerb::Hold` if `caps.can_hold && caps.fails_closed` and `caps.hold_deadline_ms` is `Some(deadline_ms)` with non-zero clamped hold, else `ExecutedVerb::DenyWithRetryToken`. The hold duration uses widened `u128` arithmetic over `Permille::ONE` so any `deadline_ms` up to `u64::MAX` is infallible (`#1595` AC-2): `scaled = u128::from(deadline_ms) * u128::from(POLICY_HOLD_DEADLINE_SHARE.get()) / u128::from(Permille::ONE.get())`, then clamped to `u128::from(POLICY_FILE_HOLD_CAP.as_millis())` and converted cleanly to `u64`.
     - `Defer` -> `ExecutedVerb::Hold` under the same `can_hold`/`fails_closed`/`Some(deadline_ms)` guard and widened `u128` clamp, else `ExecutedVerb::DenyWithRetryToken` carrying `derived.retry_after_ms`.
     - `Allow` -> `ExecutedVerb::Allow`.

### 6. R5: Dependencies (`cedar-policy` and `proptest`)

1. **`cedar-policy` (`=4.14.1`, `default-features = false`):**
   - Root `Cargo.toml` `[workspace.dependencies]` adds:
     `cedar-policy = { version = "=4.14.1", default-features = false }`
   - Normal dependency of `crates/grdr-core/Cargo.toml` ONLY (`cedar-policy = { workspace = true }`).
   - Rationale for `default-features = false`: Cedar's three default features (`datetime`, `decimal`, `ipaddr`) enable extension types that `Grdr` v1alpha1 does not use. Leaving all default features disabled keeps `chrono` and timezone/locale crates out of layer-1 and `wasm32-unknown-unknown` dependency graphs while retaining `Schema::from_cedarschema_str`, `Validator`, `Policy`, `PolicySet`, `Request`, `Entities`, and `Authorizer`.
   - **`ARCH-004` isolation:** `cedar-policy` is listed under `[arch004] content_parsers` in [`architecture.toml`](../architecture.toml). It never enters `grdr-schema`, `grdr-model`, `grdr-fastpath`, `grdr-hook`, `grdr-daemon`, or any `privilege = "privileged"` binary closure. `grdr-archlint` verifies this in `#432` AC-4.
   - **Deferred items:** `cedar-policy-symcc` and `cvc5` (`docs/design/12` section 7) are NOT admitted here; they arrive with server `control` target items later.
2. **`proptest` (`MIT OR Apache-2.0`):**
   - Root `Cargo.toml` `[workspace.dependencies]` adds `proptest` at the newest stable `1.x` release (`1.12.0` at authoring) passing `cargo deny` and `cargo vet`.
   - Admitted solely under `[dev-dependencies]` of `grdr-core` (in `#432`) and `grdr-policy-ref` (in `#434`). It enters zero shipped build targets (`normal` and `build` dependency graphs are unaffected).
3. **Licence and supply-chain verification (`supply-chain/licences.toml`, `docs/design/35` section 2.6):**
   - `cedar-policy` and its internal crates (`cedar-policy-core`, `cedar-policy-formatter`) are `Apache-2.0`.
   - `proptest` is `MIT OR Apache-2.0`.
   - Every direct and transitive licence expected in both graphs (`Apache-2.0`, `MIT`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `Unicode-3.0`) falls within `[class] name = "permissive"` of [`supply-chain/licences.toml`](../supply-chain/licences.toml).
   - `#432` runs `cargo deny check`, RustSec/OSV advisory checks, and `cargo vet` / `supply-chain/admissions.toml` verification against exact `Cargo.lock` checksums. The parser-input size cap mitigation for the 2026 Cedar parser memory advisory noted in `docs/design/03` section 13 (`policy.parser-input-max`) lands in `limits.toml` through `#279` (since `#432` modifies only `Cargo.toml`, `Cargo.lock`, `supply-chain/**`, and `crates/grdr-core/Cargo.toml`).

### 7. R6: `POLICY` error codes and `limits.toml` policy bounds

#### Area and error codes (`schema/codes/areas.toml`, `schema/codes/policy.toml`, `schema/codes/model.toml` via `#278`)

```toml
[area.POLICY]
subsystem = "policy engine"
owner = "design/12"
```

| Code | Reason (`UPPER_SNAKE`) | Class | Connect code | When raised |
|---|---|---|---|---|
| `GRDR-POLICY-0001` | `SCHEMA_LOAD_FAILED` | `internal` | `internal` | `V1ALPHA1` failed to parse or emitted warnings |
| `GRDR-POLICY-0002` | `ENFORCING_LABELS_OVER_LIMIT` | `input` | `invalid_argument` | Enforcing label count exceeds `POLICY_ENFORCING_LABELS_MAX` |
| `GRDR-POLICY-0003` | `CLASSES_OVER_LIMIT` | `input` | `invalid_argument` | A class set exceeds `POLICY_CLASSES_SET_MAX` |
| `GRDR-POLICY-0004` | `FACTS_OVER_LIMIT` | `input` | `invalid_argument` | `facts` exceeds `POLICY_FACTS_SET_MAX` |
| `GRDR-POLICY-0005` | `GRANTS_OVER_LIMIT` | `input` | `invalid_argument` | `grants` exceeds `POLICY_GRANTS_SET_MAX` |
| `GRDR-POLICY-0006` | `EVIDENCE_OVER_LIMIT` | `input` | `invalid_argument` | `attribution.evidence` exceeds `POLICY_EVIDENCE_SET_MAX` |
| `GRDR-POLICY-0007` | `SESSION_CHAIN_OVER_LIMIT` | `input` | `invalid_argument` | Ancestor session chain or group DAG exceeds `POLICY_SESSION_CHAIN_MAX` |
| `GRDR-POLICY-0008` | `REQUEST_MALFORMED_INPUT` | `input` | `invalid_argument` | Empty/overlong opaque id, malformed normaliser state, or invalid input |
| `GRDR-POLICY-0009` | `REQUEST_SCHEMA_REJECTED` | `internal` | `internal` | `cedar_policy::Request::new` or `Entities::from_entities` rejected the built request |
| `GRDR-POLICY-0010` | `POLICY_EVALUATION_FAILED` | `policy` | `permission_denied` | An enforced Cedar policy errored during evaluation |
| `GRDR-POLICY-0011` | `OBLIGATION_UNMET` | `policy` | `failed_precondition` | Control point lacks a must-obligation such as `snapshot` |
| `GRDR-POLICY-0012` | `PARSER_INPUT_OVER_LIMIT` | `input` | `invalid_argument` | Cedar schema or policy source bytes exceed `POLICY_PARSER_INPUT_MAX` |

In addition, amending RFC 0009 registers `GRDR-MODEL-0012` (`RULE_ID_FORM`, `class = "input"`, `connect = "invalid_argument"`, bound by `PolicyRuleIdError`) in `schema/codes/model.toml` under area `MODEL`.

Each entry conforms to RFC 0007 section 4 (`status = "active"`, language tokens `code.<area>_<nnnn>.message` and `code.<area>_<nnnn>.fix`, registered via `#278`'s registry and `#1853` token rules per RFC 0010).

#### Policy bounds in `limits.toml` (via `#279` / RFC 0007 section 6)

| Bound name | Unit = value | `min`..=`max` | Scope / Effect | Owner | Generated constant |
|---|---|---|---|---|---|
| `policy.enforcing-labels-max` | `count = 64` | `1..=64` | `fixed` / `none` | `design/12` | `POLICY_ENFORCING_LABELS_MAX` |
| `policy.classes-set-max` | `count = 256` | `1..=1024` | `fixed` / `none` | `design/12` | `POLICY_CLASSES_SET_MAX` |
| `policy.facts-set-max` | `count = 256` | `1..=1024` | `fixed` / `none` | `design/12` | `POLICY_FACTS_SET_MAX` |
| `policy.grants-set-max` | `count = 1024` | `1..=4096` | `fixed` / `none` | `design/12` | `POLICY_GRANTS_SET_MAX` |
| `policy.evidence-set-max` | `count = 32` | `1..=64` | `fixed` / `none` | `design/04` | `POLICY_EVIDENCE_SET_MAX` |
| `policy.session-chain-max` | `count = 16` | `1..=64` | `fixed` / `none` | `design/12` | `POLICY_SESSION_CHAIN_MAX` |
| `policy.opaque-id-max` | `bytes = 256` | `16..=1024` | `fixed` / `none` | `design/04` | `POLICY_OPAQUE_ID_MAX` |
| `policy.rule-id-max` | `bytes = 256` | `32..=512` | `fixed` / `none` | `design/12` | `POLICY_RULE_ID_MAX` |
| `policy.class-tag-max` | `bytes = 128` | `32..=256` | `fixed` / `none` | `design/12` | `POLICY_CLASS_TAG_MAX` |
| `policy.parser-input-max` | `bytes = 262144` | `4096..=1048576` | `fixed` / `none` | `design/03` | `POLICY_PARSER_INPUT_MAX` |
| `policy.hold-deadline-share` | `permille = 800` | `1..=800` | `fixed` / `none` | `design/12` | `POLICY_HOLD_DEADLINE_SHARE` |
| `policy.file-hold-cap` | `ms = 30000` | `1..=30000` | `fixed` / `none` | `design/12` | `POLICY_FILE_HOLD_CAP` |

All names follow RFC 0007 section 6 naming rules: no hyphen-separated word of any segment is a unit word (`b`, `byte`, `bytes`, `kb`, `kib`, `mb`, `mib`, `gb`, `gib`, `count`, `ns`, `us`, `ms`, `millis`, `s`, `sec`, `secs`, `second`, `seconds`, `minute`, `minutes`, `h`, `hour`, `hours`, `day`, `days`, `permille`, `percent`, `pct`), and no segment equals a reserved key word (`bytes`, `count`, `ms`, `permille`, `min`, `max`, `scope`, `effect`, `key`, `ceiling`, `owner`, `note`, `peer`).

### 8. Mechanisms (`P14`), Data classes (`P8`), Assurance (`P1`), Failure modes

- **Mechanism (`P14`):** All behaviour rules, class lists, labels, mode floors, bounds, and error messages live in packs, `schema/cedar/v1alpha1.cedarschema`, `schema/codes/policy.toml`, `schema/codes/model.toml`, and `limits.toml`. Rust code in `grdr_core::policy` implements only the schema loader, deterministic request construction, derivation table, and degradation function.
- **Data classes (`P8`):** `v1alpha1.cedarschema`, classes, facts, labels, grades, ranks, `PolicyRuleId`, `PolicyError` (`LogValue::Code`), and `ContextField` paths are `structural`. Entity ids are opaque `identifier` values; `Request` builders never accept raw paths, argv strings, request bodies, or human identifiers (`D-51`), and `OpaqueId`/`PolicyError` never expose inner identifiers in `Debug` or `LogSafe`.
- **Assurance effect (`P1`):** `derive` and `degrade` map decisions to enforced or observe-only verbs and mark `coverage_gap = true` when a control point cannot deny or a non-lifted non-fail-closed rule is not evaluable outside a boundary OS control point (`control: none` on observe-only control points). Schema loading and request construction carry existing assurance ranks without modifying them.
- **Failure modes (`P9`, `D-15`):** Schema parse failure or warning prevents bundle activation (`GRDR-POLICY-0001`). Parser input exceeding `POLICY_PARSER_INPUT_MAX` is rejected (`GRDR-POLICY-0012`). Any input bound overflow rejects the build with its `GRDR-POLICY-*` code and never truncates (`GRDR-POLICY-0002` to `0007`). `NormaliserOutcome::Malformed` resolves upstream (`GRDR-POLICY-0008`) and in `derive` Row 1 to `DENY`. Evaluation errors resolve in `derive` Row 2 to fail-closed `DENY` (`policy-error`). Missing must-obligation `Snapshot` across Rows 3 to 8 resolves to `DENY` (`obligation-unmet`). Over `ModifyBudget::Twice`, Row 3 is skipped so no transform loop can starve a request.

## Surfaces changed

This RFC authors design specification only (`rfcs/0013-cedar-schema-grdr-policy-surface.md`). Accepting it authorises the following changes across follow-up issues:

| Surface | Proposed change | Implementing item(s) |
|---|---|---|
| `schema/cedar/v1alpha1.cedarschema` | Create canonical `Grdr` v1alpha1 schema verbatim | `#435` |
| `grdr-schema` (layer 0, amending RFC 0007) | Add `cedar::{V1ALPHA1, SCHEMA_VERSION}`, update `tests/construction.rs` `layout` incrementally for `cedar.rs` + `schema/cedar/v1alpha1.cedarschema`, register area `POLICY` (`GRDR-POLICY-0001`..`0012`), `GRDR-MODEL-0012`, and 12 `policy.*` limits | `#435`, `#278`, `#279` |
| `grdr-model` (layer 1, amending RFC 0009) | Host shared policy contract enums (`wire_enum!`) and structs (`PolicyRuleId`, `PolicyRuleIdError`, `ForbidMatch`, `ControlPointCaps`, `DeriveInput`, `Derived`, `Executed`, etc.) at crate root; reuse `Tamper` | `#1595` (re-plan / `#739` alignment) |
| `grdr-core` (layer 1) | Add `policy::{schema, request, derive, degrade}`, `PolicyError` (`LogSafe` via `Code`), re-export shared `grdr-model` types; depend on `grdr-schema` and `cedar-policy` | `#432`, `#435`, `#436`, `#1600`, `#1602`, `#1595` |
| `grdr-policy-ref` (`tool`) | Add `derive` and `degrade` reference functions over `grdr-model` types only (`proptest` dev-dep) | `#434`, `#1597` |
| `Cargo.toml`, `Cargo.lock`, `supply-chain/` | Pin `cedar-policy = "=4.14.1"` (`default-features = false`) and `proptest` | `#432` |
| `surfaces.toml`, `architecture.toml`, `security/trust-core.paths` | Keep `grdr-core` `class = "experimental"` (`[[crate]]` schema `(name, class, rfc)` unchanged) while tracking `ARCH-007` `cedar-policy` exposure in `architecture.toml`/RFC record; register `grdr-policy-ref`, `grdr-core` -> `grdr-schema`, and `crates/grdr-schema/src/cedar.rs` trust-core path | `#434`, lead-agent-kit protected-change items |
| `docs/design/03`, `docs/design/12` | Update schema file path (`schema/cedar/v1alpha1.cedarschema`), `absent` phrasing for `context.command.classes`, and `ARCH-013` note (`grdr-schema` + `cedar-policy` in `policy`) | Design follow-up after acceptance |

## Alternatives

1. **Make missing context fields optional (`?`) in `v1alpha1.cedarschema` instead of required with neutral values (`R3`).**
   - *Rejected:* Breaks strict validation of policy 5 and ten sibling worked rules in `docs/design/12` section 5 unless every worked rule is rewritten with repetitive `has` guards, and creates drift between policy read sets and Cedar evaluation semantics.
2. **Expose `absent` and `pending` as Cedar context attributes (`R3`).**
   - *Rejected:* Allows user/pack rules to branch directly on `absent` or `pending`, bypassing rows 6 and 7 (`DEFER`, `STEP_UP`, `expect`, coverage gap) in `derive`. Keeping them engine-side enforces `P14`.
3. **Wrap `cedar_policy::{Schema, Request, Entities}` in opaque `grdr-core` newtypes now instead of tracking `ARCH-007` exposure while `experimental` (`R4`).**
   - *Rejected for slice 0:* `#435` R3 explicitly specifies `load() -> Result<cedar_policy::Schema, ...>`, and `#436`/`#1600` validate directly with `cedar-policy` types. Keeping `grdr-core` at `class = "experimental"` in `surfaces.toml` with `ARCH-007` tracking avoids replanning `#435`, `#436`, and `#1600`; wrapping stays mandatory before `beta`/`stable` graduation (`D-60`).
4. **Have `grdr-policy-ref` depend directly on `grdr-core` for `Derived`/`DeriveInput`/`ControlPointCaps` (`R4`).**
   - *Rejected:* Directly violates `#434` R2/AC-2 (`cargo tree -p grdr-policy-ref -e normal` must show neither `grdr-core` nor `cedar-policy`). Placing shared value types in `grdr-model` satisfies `#434`, `#1595`, and `#1597` simultaneously with zero shared evaluator code (`D-63`).
5. **Enable `cedar-policy` default features (`datetime`, `decimal`, `ipaddr`) (`R5`).**
   - *Rejected:* Adds unused transitive crates (including `chrono`) to layer 1 and `wasm32-unknown-unknown` builds (`#432` R1 specifies default features off unless the RFC names features).

## Drawbacks

- **Two-crate coordination for `derive`/`degrade` types:** Putting `ControlPointCaps`, `DeriveInput`, `Derived`, and `Executed` in `grdr-model` instead of only inside `crates/grdr-core/src/policy/` amends RFC 0009 and requires a write-set adjustment across `#1595` and `#1597` (and alignment with `#739`).
- **Amending RFC 0007's `layout` gate for `cedar.rs`:** Expanding `grdr-schema`'s module tree and permitting `include_str!` solely in `crates/grdr-schema/src/cedar.rs` relaxes RFC 0007's seven-file list; keeping `layout` incremental over `{codes, limits, health, cedar}` prevents merge conflicts with RFC 0016 (`#668`).
- **Schema bump required when `schedule` gains attributes:** Because `ScheduleContext` is `{}` (required), adding future time-of-day attributes requires a coordinated schema version bump (`v1alpha2`) rather than populating optional fields in-place. This is already how `docs/design/12` section 10 handles schema evolution (`schema_version` compatibility resolver).
- **Repeated common context block in `.cedarschema`:** Cedar's schema grammar lacks record spread syntax, so 11 of the 15 actions list the 7 common context keys explicitly alongside their per-action fields (using shared `SessionContext`, `AttributionContext`, `AssuranceContext`, `ScheduleContext` common types to prevent field drift). `#435`'s shape test and `#392`'s drift check enforce uniformity mechanically.

## Unresolved questions

1. **Exact alignment with `#739` (`RFC-1`):** `#739` will settle additional policy engine public types (`RuleMeta`, `CanonicalAction`, grants and retry metadata) in `grdr-model` and `grdr-core`. If `#739` changes naming conventions for `ActionClass`, `ApprovalGrade`, or `PolicyRuleId`, it may supersede those type names explicitly in `grdr-model` while keeping `v1alpha1.cedarschema` and `grdr_core::policy` semantics intact.
2. **Exact `proptest` patch version (`1.12.x`) and `cargo vet` audit entries:** `#432` resolves and freezes the exact `Cargo.lock` versions, checksums, and `supply-chain/` exemptions/audits when admitting `cedar-policy = "=4.14.1"` and `proptest`.
3. **Sub-issue re-plan scope upon acceptance:** Lead-core updates `#1595` (to place or depend on the shared `grdr-model` types), `#1597` (R1/AC-3 to import shared contract types from `grdr-model` rather than `grdr-core`), `#278` (`POLICY` area codes `0001`..`0012` plus `GRDR-MODEL-0012`), `#279` (add the twelve `policy.*` bounds including `policy.parser-input-max`), `#435` (`layout` test update for `cedar.rs` + `include_str!` allow-list), and opens the `architecture.toml` / `security/trust-core.paths` protected-change updates for `lead-agent-kit`.

## Review

Pending review on `#431` against spine blob `a80859235e7a2a4444648d6fa8d389d78dde6be9` (`SHA-256` `8f6ea876777c0121ecec068c0bc4cef45932be45c1c2aff4140712db1e06628d`).

Prior planning input on `#431`:

- `lead-core` planning note on `#431` (identifying the 22-policy count across `docs/design/12` sections 3 and 5, `Grdr::Process` on `file.write`/`file.delete`, unscoped `principal` on `cred.use`/`mcp.connect`/`mcp.call`/`llm.request`, and the required-vs-optional ruling needed for policy 5 `context.command.classes`).

Per `.claude/risk-tiers.toml` (`ADR-0043`), review runs with `eval-review` and `eval-security` on two distinct models or providers (maximum two rounds), posting verdicts with RFC file blob, proposed text/base pins, provider, and model on `#431`.

## Decision

Pending review on `#431`.
