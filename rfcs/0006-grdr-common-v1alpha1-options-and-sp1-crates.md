RFC: 0006
Title: `grdr.common.v1alpha1`: the option registry, the data-class enums, how `buf` gates them, and the crates SP-1 and descriptor decoding admit
Author: chief-architect
Harness: Claude Code
Model: claude-opus-5-5
State: Review
Design issue: #1848
Spine: D-06, D-31, D-51, D-60, D-61, D-63, D-66, P8, P9, P14, P16, P17 (no spine text changes)
Surfaces: the new protobuf package `grdr.common.v1alpha1` (experimental): `proto/grdr/common/v1alpha1/options.proto` with the enums `DataClass` and `ContentKind` and five descriptor-option extensions; `buf.yaml`; the committed descriptor set `crates/grdr-proto/descriptors/proto.binpb` of the public crate `grdr-proto`; optional dependencies of `grdr-proto` behind the mutually exclusive features `sp1-buffa` and `sp1-prost`; the generated modules `capture` and `registry` of the public crate `grdr-schema`. As proposals: two data files of `grdr-schema` (`capture.toml`, `reclassifications.toml`), design/04 sections 1, 10, 11, 13 and 14, design/26 section 9, design/36 section 2, one `[[proto_package]]` row of `surfaces.toml`, a `depends_on` key on the `grdr-schema-lint` row of `architecture.toml`, and eighteen lines of `security/trust-core.paths` (plus a `<dir>/**` rule for workspace `proc-macro` packages)
Decision record: none yet

To comment, write on issue #1848 of this repository; you need no account on any service other than the code host. A security fix under embargo (D-62) may change a public surface without an RFC; open a retroactive RFC when the fix is disclosed.

## Summary
The first `proto/` change is one file, `proto/grdr/common/v1alpha1/options.proto`. It holds two closed enums, `DataClass` and `ContentKind`, and the five options #353 needs: `data_class` on every field, `content_kind`, `policy_readable`, `sealable`, and `wire_name` on every enum value. Tools find the options package from each file's import and read options by full name, so neither the version nor the option numbers are literals. The capture matrix, the rank of each class and the default level are one trust-core data file, `capture.toml`. Any change to a field's class or `sealable` option, a field's removal, a level that opens a class, and a changed wire name each need a new entry in a second trust-core file, `reclassifications.toml`, citing the accepted RFC the pull request names and a council seat's review. One job, built from the base with a pinned toolchain, reads the head from git objects by id only as data: after a pre-cargo tree check refuses case-fold collisions, non-ASCII bytes, symbolic links and submodules, it runs the field rules, compares the head with the base (SL12), regenerates the field registry and the modules `grdr_schema::capture` and `grdr_schema::registry` from the head's data (failing on any byte difference), and runs `manifests` from outside the head tree over every workspace package, failing on exit 2 as well as exit 1. It fails any workspace package that sets `package.build`, puts a `custom-build` outside `<pkg>/build.rs`, puts a target outside its directory, uses a non-workspace `path` dependency, or declares a `proc-macro` outside `security/trust-core.paths`, and fails a head that moves `grdr-schema` or `grdr-model` or gives either a build script. An entry reaches a deployed device only once the organisation confirms that entry. The package is experimental, and `surfaces.toml` is the only source of that class. `buf` gates it under WI-0014's rules W1 to W5. For SP-1 (#360), `grdr-proto` gains `buffa`, `buffa-types` and `buffa-build` 0.9.2 behind `sp1-buffa`, and `prost`, `prost-types` and `prost-build` 0.14.6 behind `sp1-prost`, never both at once. `grdr-schema-lint` decodes descriptors with `buffa-descriptor` 0.9.2.

## Motivation
- #353 cannot open its pull request without an RFC line: the package is a wire format (D-61; the #17-E1 decision on #17).
- #353 as written cannot build. Its `options.proto` needs `DataClass` as the type of `data_class`, and its `data_class.proto` needs `wire_name` on every value, so each file imports the other. Protobuf refuses import cycles.
- #360 may not admit a crate until a ruling names it (#17-E2), and #386 has no descriptor decoder until #360 lands one.
- Every later package imports this file. Its options are the mechanism P8 rests on: the capture filter, redaction, the field registry, the lake columns and every export mapping are generated from them (ADR-0007).

## Design

### 1. Package and file
- R1. One file, `proto/grdr/common/v1alpha1/options.proto`, package `grdr.common.v1alpha1`, `syntax = "proto3"`. It imports only `google/protobuf/descriptor.proto`, which `buf` carries locally, so there is no registry dependency (P16; #1697 condition 3). It is the options file: the one file of the namespace that declares a descriptor-option extension.
- R2. It holds the enums of section 3 and every extension of a `google.protobuf.*Options` message the namespace declares. It declares no message.
- R3. The package's first segment is `[identity] namespace` in `brand/brand.toml`, `grdr` today (D-66). That key is the wire namespace, class A of design/36 section 2. A rebuilt white-label manifest keeps the upstream value, and the brand manifest loader (LBC-3, #1856) refuses any other value until 04-4 (#396) moves the namespace for every distribution at once. Reading the namespace from the manifest keeps a literal `grdr` out of every tool; it does not make the wire rebrandable, which design/26 section 9 already lists as unchanged in a rebuild.
- R4. The other shared types design/04 section 1 lists for this package (`ActionClass`, `Mode`, `Redaction`, `Sealed` and the rest) go in their own files, one family per file (design/04 section 1 rule 6), each through its own RFC. Every file of the namespace except the options file imports `options.proto`.

One file is what removes the cycle. `buf` 1.67.0 builds and lints it, the `wire_name` used in the file that declares it included. #353 AC-1 confirms that with the pinned `buf` (#1697); if the pinned `buf` refuses it, #353 stops `blocked` and this RFC is amended.

### 2. The option registry
| Number | Extends | Option | Type | Required on |
|---|---|---|---|---|
| 50001 | `FieldOptions` | `data_class` | `DataClass` | every field of every message in the namespace, never `DATA_CLASS_UNSPECIFIED` |
| 50002 | `FieldOptions` | `content_kind` | `ContentKind` | exactly the fields whose class is `DATA_CLASS_CONTENT` |
| 50003 | `FieldOptions` | `policy_readable` | `bool` | optional; never on a `float` or `double` field |
| 50004 | `FieldOptions` | `sealable` | `bool` | optional; marks a field with a `Sealed` twin (D-35), whose number 04-19 assigns |
| 50011 | `EnumValueOptions` | `wire_name` | `string` | every enum value except the zero value, unique within its enum |

- R5. A number is allocated here only and never reused. A retired option stays declared with `[deprecated = true]`, so its number stays taken. `buf breaking` passes a deleted or renumbered extension and flags only a rename or retype at an existing number, so SL12 is the check: it fails a change that drops an option or gives its number to another name. The numbers stay in the in-house range 50000 to 99999 until #398 moves all five in one change to the range the protobuf global extension registry grants (external precondition, #17-E3; SL09 checks the range). Option numbers appear in descriptor sets, never in event bytes, so that move changes no event on the wire, no golden vector and no class digest.
- R6. Every tool and generator that reads an option (the lint, the registry writer, the filter and mapping generators) takes the options package of a file from that file's import: the package of the options file it imports, or the file's own package for the options file. It then resolves `<options package>.<option>` by full name, from a committed descriptor set, never by number and never through generated code. No reader holds a version literal. This is also the supported way for a third party to read our sets (Surfaces changed). When the freeze (04-29) adds a `v1` options file beside `v1alpha1`, its RFC amends SL10's one-options-file rule and no reader changes.
- R7. `options.proto` changes only by RFC. Its enums are closed (design/04 section 13 rule 3), and its options are what every filter and mapping is generated from.
- R8. The extensions describe the schema, not data, so they carry no `data_class`.

### 3. The classes and their source of truth
```proto
enum DataClass {
  DATA_CLASS_UNSPECIFIED = 0;
  DATA_CLASS_IDENTIFIER = 1 [(wire_name) = "identifier"];
  DATA_CLASS_STRUCTURAL = 2 [(wire_name) = "structural"];
  DATA_CLASS_DERIVED = 3 [(wire_name) = "derived"];
  DATA_CLASS_CONTENT = 4 [(wire_name) = "content"];
}
enum ContentKind {
  CONTENT_KIND_UNSPECIFIED = 0;
  CONTENT_KIND_ARGUMENT = 1 [(wire_name) = "argument"];
  CONTENT_KIND_BODY = 2 [(wire_name) = "body"];
}
```
- R9. Both enums are closed: no `_OTHER` value, and each is listed in `crates/grdr-schema/enums.toml` (#386 R5).
- R10. `options.proto` is the one source of the class names. Every tool under `crates/` that reads classes reads the committed descriptor set, `capture.toml` through its loader (R13), or a file generated from them (R13a). The one other list is the `DataClass` enum of RFC 0004's `grdr-cabi-testkit`, which R11 holds to `grdr_schema::capture`.
- R11. The five commitment classes of design/04 section 10 are named from the wire names: `identifier`, `structural`, `derived`, `content.argument` and `content.body`. That spelling is the one `envelope.withheld`, the registry and every export use. SL13 also requires each wire name of `DataClass` and `ContentKind` to be its value's name without the enum's prefix, in lower case (`DATA_CLASS_IDENTIFIER` is `identifier`), so names cannot be permuted across values. RFC 0004's testkit describes C fields with five classes of its own (`Identifier`, `Structural`, `Derived`, `ContentArgument`, `ContentBody`). A test in the testkit, filed on acceptance, reads `grdr_schema::capture` and fails unless the testkit renders its five classes as exactly the five names there. That fixes a spelling RFC 0004 left open; no header exists yet, so no header text changes. This RFC does not change what RFC 0004 section 10 leaves to review: whether a C field's class is the right one.
- R12. A zero value carries no `wire_name` and is never rendered. A zero or undeclared value of a closed enum, read where a value is required, is a finding or an error, never a default. A `data_class` number the enum does not declare is SL01; `buf` refuses to build one (exit 100), so its fixture is a buf-built set that the test changes in memory, as #386 R7's drift test does. An export that meets an enum value it has no wire name for keeps the record, omits that field and marks the record in a field the mapping format of 04-21 defines, which #495 names in its criteria. `envelope.withheld` lists only the classes the capture filter removed and never carries that mark.
- R13. `crates/grdr-schema/capture.toml` is design/04 section 11's matrix as data, with the rank of each class and the default level. It decides what leaves the device, so it is trust core (R19). One loader reads it, in `grdr-schema-lint`. The loader refuses, with exit 2 and its code: an unknown key; a repeated `[[class]]` or `[[level]]` name; a name in `passes` or `redacted` that no `[[class]]` declares; a class in both lists of one level; and a `default` that is missing or names no level.

```toml
# design/04 section 11 as data. Read only through grdr-schema-lint's loader (RFC 0006 R13).
# Rank is the order of [[class]] tables: later is more sensitive.
# At a level, a class in `passes` passes the filter whole, a class in `redacted` passes without
# the `original` of its redactions, and any other class is withheld.
default = "metadata"

[[class]]
name = "structural"
[[class]]
name = "derived"
[[class]]
name = "identifier"
[[class]]
name = "content.argument"
[[class]]
name = "content.body"

[[level]]
name = "metadata"
passes = ["structural", "derived", "identifier"]
[[level]]
name = "redacted arguments"
passes = ["structural", "derived", "identifier"]
redacted = ["content.argument"]
[[level]]
name = "redacted content"
passes = ["structural", "derived", "identifier"]
redacted = ["content.argument", "content.body"]
[[level]]
name = "full content"
passes = ["structural", "derived", "identifier", "content.argument", "content.body"]
```

  `identifier` ranks above `derived` because an identifier joins records across events and back to a principal, device or artefact (D-51), while a derived value describes one event. `structural` ranks lowest because it describes shape only. SL13 reads the rank; SL12 does not, because any change of a field's class needs an entry (R17).

  `default` is the level every sink that leaves the device starts at. P8 and D-51 fix it at `metadata`, so SL13 requires it to pass and redact no content class, and SL12 fails any change of it. The flight recorder's own level stays on the device and remains a configuration default (design/04 section 11). Retention by class (D-51) is a configuration default design/20 applies, and the rule that a `secret` redaction keeps no `original` belongs to the capture step (design/16 section 11, 04-17). Neither is in the file.

  A level says what passes the filter for a sink at that level. The routes by which redacted arguments leave at the default level, an `EvidenceSpan` on a finding or a content grant (D-51), are not levels and are not in the file. Until the RFC that adds `EvidenceSpan` names them (R14), the matrix is incomplete for findings: at `metadata` the filter withholds every content leaf, `EvidenceSpan.text` included, and no generator infers a route from a leaf class.

  A rule that reads a class the organisation's level withholds reports "could not look" in the rule linter and in replay, never "no match" (P9). A mapping never assigns a class: a mapped value takes the class of the field it lands in, and a host value with no field goes to `native` as content (design/04 section 1 rule 4). Levels are ours alone: a partner or an organisation cannot define one (P8, D-51). The disclosure view labels each class "declared by the schema" and never states a property, such as pseudonymisation, that no check holds.
- R13a. Generated files. Each is written whole by `grdr-schema-lint` and has no hand-written part.
  - `capture --out crates/grdr-schema/src/capture.rs` writes the module `grdr_schema::capture` from `capture.toml` and `reclassifications.toml`: the levels, the ranks, the default, and each entry's key and `from` (R17).
  - `registry --out crates/grdr-schema/registry/fields.json` writes the field registry and, from the same walk, the module `grdr_schema::registry` (`crates/grdr-schema/src/registry.rs`). That module is the one load site of the registry: Rust code reads the registry only through it, and no shipped program parses JSON (ARCH-004). Tools outside Rust read `fields.json`.
  - `crates/grdr-schema/src/lib.rs` declares both modules.
  - Every other reader uses the two modules and never parses `capture.toml` or `fields.json` (P17): the 04-16 filter (#117), the pack validator's class ceiling (#511), R11's testkit test, the rule linter and replay of design/13, the export mapper (04-21), the disclosure view and the tray (D-51), and the configuration schema's default upload level (design/29 section 8).
  - The `schema-gate` job of section 7 checks the head's tree from git objects by id before running Cargo, regenerates all three files from the head's data with the base's build, and fails on any byte difference or exit 2. It runs Cargo from outside the head tree with the base's pinned toolchain and runs `manifests` over every workspace package, failing when `grdr-schema` or `grdr-model` has a manifest or library root other than `crates/<name>/Cargo.toml` and `crates/<name>/src/lib.rs` or any build script, or when any workspace package sets `package.build`, puts a `custom-build` target outside `<pkg>/build.rs`, puts a target outside its directory, resolves a `path` dependency outside the workspace, or declares a `proc-macro` target whose directory is not covered by `security/trust-core.paths` ignoring ASCII case (`manifests`, section 7).
  - The lane holds what no byte check sees. For a change to either crate's `lib.rs`, the evaluators check that `grdr-schema`'s declares `capture` and `registry`, and `grdr-model`'s declares `capture`, only as plain `pub mod` lines, with no attribute, macro or `include!` (#1880).
  - The generated files, both crates' `lib.rs` and manifests, `**/build.rs`, and any workspace `proc-macro` package are trust core (R19).
- R14. Left to the RFC of the first item that adds a message field (#18, 04-5):
  - an `encoding` option for bytes fields with its values (`Receipt.decision`, `native` and `Redaction.original` among the cases it is checked against);
  - the data file that names each digest's `<alg>` label;
  - the class of a field whose type is a namespace message, and how SL12 compares a retype or successor that involves one (R17);
  - a marker for fields that carry a human principal, an option or a data file, with a lint that it sits only on `identifier` fields;
  - the routes of an `EvidenceSpan` and a content grant, each as data in a trust-core file, with an entry kind added to R17 that seat 6 reviews for each route;
  - packages of a partner with classes of their own.

  The capture filter and the class-digest walk read leaf classes only (design/04 sections 10 and 11), so nothing in this RFC reads a namespace message-typed field's own class.
- R14a. Imported types. A file of the set outside the namespace is allowed only if `crates/grdr-schema-lint/foreign_files.toml` lists its name with the SHA-256 of its `FileDescriptorProto` as the pinned `buf` bundles it. The list holds `google/protobuf/descriptor.proto`, which only the options file may import, and `google/protobuf/timestamp.proto` and `google/protobuf/duration.proto` (#368 R1), whose leaves are numbers. SL10 compares each such file's descriptor in the committed set with its listed digest, so it judges the content and never the path: a look-alike under `google/protobuf/`, a local copy that shadows a well-known file and a file of our own under that prefix all fail. Adding a file to the list is a trust-core change whose review checks that its leaves are numbers and `bool`s only. In the field registry each leaf of such a type takes the class of the namespace field that holds it, so a `Timestamp` on a content field is content. The 04-16 filter refuses a leaf the registry gives no class (`UnregisteredField`, #117 R8), so a classless leaf never ships. A partner's own package is outside the namespace: no lint reads it and the filter refuses its fields, so it reaches no sink except through a mapping into our fields.

### 4. Stability and releases
- R15. `grdr.common.v1alpha1` is experimental: nothing is stable before one external embed pilot completes (D-60). Its class lives in one `[[proto_package]]` row of `surfaces.toml` with the keys `package` and `class`, each a double-quoted value on its own line, the rule RFC 0004 section 2 sets for `[[c_header]]` rows (ADR-0020). `package` is the name below the namespace (`common.v1alpha1`).
- R16. `surfaces.toml` is the only source of a package's class. No option carries stability, per field or per file. The version suffix follows design/04's own naming: `v1alpha1` until the freeze, `v1` after it (04-29). A `v1` package may stay experimental, as D-60 and ADR-0020 allow. SL11 keeps the one rule that needs no second statement: a row whose class is `stable` names no package with an unstable suffix.
- R17. During `v1alpha1`, `buf breaking` uses `WIRE_JSON`, and the freeze switches it to `FILE` (design/04 section 13). Every change to `proto/**` names an accepted RFC (D-61; `rfc-required`, #1741 R1). Neither reads a field's options, and naming an accepted RFC says nothing about a class. So SL12 holds three kinds of change, each to an entry in `crates/grdr-schema/reclassifications.toml`:
  - a **field change**: a field of the base whose treatment changes, or that disappears. A field's treatment is its class, written `<class> sealable` when the field carries `sealable = true` (`content.argument sealable`). Every change counts: a lower class, a higher one, and losing or gaining `sealable`;
  - a **level release**: a level passes or redacts a class that the base's form of that level withheld, or passes one the base only redacted; a level the base lacks releases each class it passes or redacts. Levels come from the base's `capture.toml`;
  - a **wire-name change**: an enum value of the namespace whose `wire_name` changes or that disappears, or a value the base lacks whose `wire_name` the base holds on another value of that enum or a base entry of that enum has as its `from`. Every saved hunt, rule and parser keyed on a name breaks or changes meaning with it.

  The forms:

```toml
[[field]]
message = "grdr.event.v1alpha1.Exec"
number = 3
from = "content.argument"
to = "structural"          # a treatment, or "removed"
rfc = "0099"
review = 7000000001

[[field]]
message = "grdr.event.v1alpha1.Exec"
number = 4
from = "content.body sealable"
to = "removed"
successor = { message = "grdr.event.v1alpha1.ExecDetail", number = 1 }   # or "none"
rfc = "0099"
review = 7000000001

[[level]]
level = "redacted arguments"
class = "content.body"
from = "withheld"          # "withheld", "redacted", or "absent" for a level the base lacks
to = "redacted"            # "redacted" or "passes"
rfc = "0099"
review = 7000000001

[[wire_name]]
enum = "grdr.event.v1alpha1.ActionClass"
number = 2
from = "file.read"         # a wire name, or "absent" for a value the base lacks
to = "file.open"           # a wire name, or "removed"
rfc = "0099"
review = 7000000002
```

  `rfc` is four digits and `review` the id of a comment. `successor` appears exactly on the entries whose `to` is `"removed"`. The loader of this file is in `grdr-schema-lint` too, and it refuses an unknown key, a missing key, a misplaced `successor` and any value outside its form, with exit 2. An entry's key is its kind, its identity, `from`, `to` and `rfc`.

  1. The head's file is the base's file with new entries after the base's entries of their kind. No two entries are equal, and a new entry whose key equals a base entry's fails, so one RFC cannot excuse the same change twice. Only new entries count. Entries never leave the file.
  2. Each change of the three kinds needs exactly one new entry with its kind, identity, `from` and `to`, and each new entry must match exactly one change. A removal entry names its successor: the field of the head that carries the removed field's value, or `"none"`. With a successor, SL12 compares the successor's treatment in the head with the removed field's in the base, and a difference is one more field change, of the successor's identity, from the removed field's treatment. A successor the head lacks fails, and a change that removes a field may add no field other than a successor its removal entries name.
  3. A pull request that adds entries names one RFC in its `RFC:` line (design/30 section 3, #1741 R2), and every new entry's `rfc` must equal it. #1741's checker must report that RFC's state in force on the base as `Accepted`; SL12 reads that state and nothing else of the RFC. `review` is the comment, on that RFC's design issue, of the seat the kind names: seat 6 (`persona-privacy-officer`) for a field change or a level release, seat 3 (`persona-soc-analyst`) for a wire-name change. The comment opens with the role lines of the RFC route (#1798), names the entry's kind, identity, `from` and `to`, and returns accept or accept with changes. Where the seat blocks, `review` is the product lead's written disposition of that block (team/01 section 10). An RFC that proposes an entry is a design change that convenes that seat. The seat's comment is a design review, not consent: the organisation consents through its confirmation (R17b), which under the works-council profile includes the co-approver.
  4. The file is trust core (R19), so a pull request that adds an entry takes the full lane. Its evaluators make four checks per new entry (#1880): the cited RFC is the pull request's `RFC:` line and #1741's checker reported it `Accepted`; its accepted text decides the entry's kind, identity, `from`, `to` and successor; `review` meets rule 3; and no base entry cites that RFC for an equivalent change. SL12 makes the first check and rule 1's key check mechanically. The others read text, so the lane makes them.

  These fail SL12 outright, entries or not: a change to the set or order of the classes; a removed or reordered level; a change of `default`; a dropped option or an option number given to another name; a field in a new version of a base package (R17a); a field that a base removal entry names, absent from the base and present in the head; and a retype or a successor where either field's type, or a map's value type, is a message, until #18's RFC says how its leaves compare (R14). Only an RFC that amends this rule changes them, and its lint change lands before the data change it allows (section 7).
- R17a. Field identity. SL12 knows a field by its message's full name and its number, and an enum value by its enum's full name and its number. A field's type is its scalar type, or the full name of its message or enum type, and for a map field its key type and its value type. A field whose type changes is removed and added at the same identity, so its removal entry names the field itself as its successor, and `"none"` fails. Renaming the field alone keeps its identity. Renaming its message or package, or moving it to another message, removes it and adds a new field, which its removal entry names as the successor. A new field's class is judged by review, by R17c's notice and by the privacy canary (04-18, #493), which runs as a required check on every pull request that adds a field once it exists. A field in a package that differs from a base package only in its last segment, a new version, fails until the RFC of the freeze (04-29) says how each such field names its predecessor and amends this rule.
- R17b. Deployed devices. An entry takes effect on an organisation's devices only once that organisation confirms that entry, not its RFC, with a record it signs through the D-31 widening step-up as #1878 defines it. Until then the 04-16 filter holds what the entry released. Over the entries the organisation has not confirmed:
  - a class at a level is held at the least open of its state at that level in the head and the `from` of each level entry for that level and class, reading `absent` as `withheld`;
  - a field at a level takes the least open of the held states, at that level, of its head class and of the class in the `from` of each entry for that field, so a field entry and a level entry never release each other;
  - for one class, sealed is less open than unsealed, so the field keeps `sealable` while its head treatment or any of those `from`s has it. In the endpoint-sealed key mode (D-35), whatever emits a `Sealed` twin reads this held treatment, and withholds a field held at `sealable` that has no twin in the head.
- R17c. Notice. The release note of a pull request that adds an entry has `category = "security"` and an `action_required` naming the confirmation; one that changes a wire name has `category = "breaking"` and names the shipped packs and Sigma taxonomy lines the regenerated taxonomy changes. The release note, and design/29's pending diff (#1878), list every new entry with its treatments or level states, every removed enum value and changed wire name with the old and new name, and every field the change adds with its class and whether that class passes at the default level. Whether an old wire name stays as an alias for a while is for the RFC that proposes the change. `eval-docs` and the full lane check the release note; #1878 shows each pending entry with its effective date in the monitoring catalogue, the Privacy screen and the tray status line until the organisation confirms it.

### 5. How `buf` gates it
- R18. `buf.yaml` at the repository root is `version: v2`, with lint `use: [STANDARD]`, `disallow_comment_ignores: true` and breaking `use: [WIRE_JSON]`, all at the top level. Its one module entry has `path: proto` and nothing else: `buf` replaces the top-level `lint` or `breaking` block in its entirety with a module's own block (buf.yaml v2 reference, https://buf.build/docs/configuration/v2/buf-yaml/, read 2026-11-21). It has no `except`, `ignore`, `ignore_only`, `ignore_unstable_packages` or `disable_builtin` key. `ignore_unstable_packages` alone would skip every `v1alpha1` package, and without `disallow_comment_ignores` a `// buf:lint:ignore` comment in any `.proto` file switches a rule off. R23's cases catch a module-level block, `ignore_unstable_packages` and comment ignores. An `except` of some other rule, or a module-level `use` that keeps the tested rules, leaves the cases at exit 100; only the trust-core lane on `buf.yaml` and the key list above hold those.
- R19. The gate item, worked by `lead-agent-kit` with the trust-core lane (AGENTS.md, gate configuration; D-63), lands the first `buf.yaml` and the fixtures under `schema/fixtures/buf/**`, `crates/grdr-schema/capture.toml` as R13 gives it, a `crates/grdr-schema/reclassifications.toml` that holds only a comment, and eighteen `security/trust-core.paths` lines (plus a `<dir>/**` line for every workspace package with a `proc-macro` target):
  - `**/buf.yaml` and `schema/fixtures/buf/**`;
  - the data files, `crates/grdr-schema/capture.toml` and `crates/grdr-schema/reclassifications.toml`;
  - the generated files and their declaration: `crates/grdr-schema/src/capture.rs`, `crates/grdr-schema/src/registry.rs`, `crates/grdr-schema/registry/**` and `crates/grdr-schema/src/lib.rs`;
  - the lint with its tests, fixtures and data, `crates/grdr-schema-lint/**`;
  - #117's write set: `crates/grdr-model/src/lib.rs`, `crates/grdr-model/src/capture.rs`, `crates/grdr-model/src/capture/**`, `crates/grdr-model/tests/capture_filter.rs`, `crates/grdr-model/tests/vectors/capture/**` and `schema/codes/model.toml`;
  - the manifests and build scripts: `crates/grdr-schema/Cargo.toml`, `crates/grdr-model/Cargo.toml` and `**/build.rs` (covering `crates/grdr-schema/build.rs`, `crates/grdr-model/build.rs` and every other `build.rs`; already landed if #1955 precedes the gate item), plus `<dir>/**` for every workspace package with a `proc-macro` target added in the same change (today zero exist).

  A line may name a path that does not exist yet. Every line in `security/trust-core.paths` matches paths ignoring ASCII case (`:(glob,icase)`, #1923/#1955; #1975 has landed the pinned-toolchain action `.github/actions/tree-paths/` on `main`). Under ADR-0043 (`5df7b36`) and #1955 Option A, `Cargo.lock`, root `Cargo.toml` and `supply-chain/admissions.toml` remain outside `security/trust-core.paths`, while #1955 adds `**/.cargo/**`, `**/.gitattributes`, `**/.gitmodules`, `**/build.rs` and the `<dir>/**` `proc-macro` rule. The `buf.yaml` glob follows the deny configuration's lines, so a nested `buf.yaml` is trust core too. The lint links no workspace crate: the item sets `depends_on = []` on `[crates.grdr-schema-lint]` in `architecture.toml`, which the architecture lint holds (#1580). A change that gives the lint a workspace edge, to #1856's brand manifest loader for example, adds that crate to `depends_on` and its paths to these lines in the same pull request. The lint's third-party crates are rows of `supply-chain/admissions.toml`, which the `rust` job holds equal to `Cargo.lock` (section 8) alongside `cargo-deny` and `osv-scanner`.

  No `proto/` exists on `main`, so the item's own criteria are R23's fresh-copy runs and a byte comparison of `capture.toml` with R13, never a root `buf lint`. It lands before #353, #386 and the lint item, so the data files, the lint and the filter are trust core from their first commit, and every base the lint ever reads holds both data files.
- R20. `buf` runs only as a plain command, in a session or in the `proto` job of `verify.yml` (#1842), at the version `[tool.buf]` of `supply-chain/build-tools.toml` pins (#1697). It runs offline: no registry dependency, no remote plugin and no login (#1697 condition 3). `cargo test --workspace --locked` never runs `buf` or `protoc` (W1).
- R21. Rust reads committed descriptor sets only (W2). `crates/grdr-proto/descriptors/proto.binpb` is the output of `buf build proto --as-file-descriptor-set --exclude-source-info -o crates/grdr-proto/descriptors/proto.binpb`. It keeps its imports, because a descriptor pool needs `google/protobuf/descriptor.proto` to read options by name, so the command never takes `--exclude-imports`. Every change to `proto/` regenerates it in the same pull request.
- R22. CI rebuilds every committed set and golden vector and fails on any byte difference (W3; #1842 R5 to R7).
- R23. The negative controls run against the configuration the `proto` module actually gets (W4). For each case under `schema/fixtures/buf/<case>/`, the job works in a fresh copy of the checkout, with the root `buf.yaml`, and always names `proto` as the input.
  - A breaking case (`before/`, `after/`): place `before/` under `proto/`, run `buf build proto -o <tmp>/before.binpb`, replace it with `after/`, then `buf breaking proto --against <tmp>/before.binpb` must exit 100 and name what `expect.txt` holds. The cases are `renumbered_field` and `reused_enum_value`.
  - A lint case (`lint/`): place it under `proto/`, then `buf lint proto` must exit 100 and name the rule in `expect.txt`. The case is `comment_ignore`: an enum whose zero value lacks `_UNSPECIFIED`, under a `// buf:lint:ignore ENUM_ZERO_VALUE_SUFFIX` comment.
  - Every case's package is `<namespace>.fixture.v1alpha1` and imports nothing, so `ignore_unstable_packages`, a module-level block or allowed comment ignores turns a case to exit 0 and fails the job.
  - `stale_descriptor` (#353 R7) stays as #1842 R7 runs it.

### 6. Crates for SP-1 and for descriptor decoding
- R24. #360 adds exactly these as optional dependencies of `grdr-proto`, each at an `=` version. `sp1-buffa` and `sp1-prost` each enable only their own rows, and neither is a default feature. They are mutually exclusive: `grdr-proto` fails to compile, through `compile_error!`, when both are on, so feature unification in an embedder's workspace cannot link two codecs. #368 therefore compares each codec with the golden vectors in a build of its own. `cargo deny check` still resolves both closures, because `deny.toml` sets `all-features = true` and resolving compiles nothing. Both features are experimental, the generated types behind them are outside any stable part of `grdr-proto`, and the losing feature leaves with the item that adopts SP-1's winner.

| Crate | Version | Edge, feature | Features | Licence | crates.io owners | Published | crates.io checksum |
|---|---|---|---|---|---|---|---|
| `buffa` | 0.9.2 | normal, `sp1-buffa` | `default-features = false`, `std` | Apache-2.0 | `iainmcgin` | 2026-09-03 | `a92f2f5df67a9d5ccfc65237bfc954c56328aee40a04a9b92381ecba370be246` |
| `buffa-types` | 0.9.2 | normal, `sp1-buffa` | default | Apache-2.0 | `iainmcgin` | 2026-09-03 | `b15b05c8418f1e200e406e5b19df97400dffa833e2450e4392c506896cbc97ac` |
| `buffa-build` | 0.9.2 | build, `sp1-buffa` | default | Apache-2.0 | `iainmcgin` | 2026-09-03 | `eee6b6b4a8d23f1f98a043f188f4d9d2ef8bee43191f42e93ac577f3c3b0f334` |
| `prost` | 0.14.6 | normal, `sp1-prost` | default (`derive`, `std`) | Apache-2.0 | `danburkert`, `github:tokio-rs:prost-core` | 2026-11-12 | `3ef0b569d1d907ab3a28596aee62cf1f61dacb0529a4bedcd8e7460e2d5228b4` |
| `prost-types` | 0.14.6 | normal, `sp1-prost` | default | Apache-2.0 | as `prost` | 2026-11-12 | `f29a7c4c7a84cef41a53d338a2d10d4f1b043ea5c3dde26db22ee2c9c1b1c75b` |
| `prost-build` | 0.14.6 | build, `sp1-prost` | `default-features = false` | Apache-2.0 | as `prost` | 2026-11-12 | `b6e4d69d0fa3e7f6f9cf6b53a0e83e4fc99ba3586f65ce166cff30bd13bb4ad2` |

`buffa-types` and `prost-types` carry `google.protobuf.Timestamp`, which the SP-1 schema uses (#368 R1).

- R25. Build scripts generate only from committed sets and never run `protoc` or `buf` (W2). buffa uses `buffa_build::Config::descriptor_set`, never `use_buf`. prost uses `prost_build::Config::skip_protoc_run` with `file_descriptor_set_path`, or `compile_fds` over the set decoded with `prost-types`; the `prost` and `prost-types` build-dependencies that `compile_fds` needs are already in the closure.
- R26. `grdr-schema-lint` (#386) decodes with `buffa-descriptor` 0.9.2 (checksum `2b7dd79a6898e70dac8adae959c8ad2cae51ed96397935c91c996280cedcb55e`) and its feature `reflect`, whatever SP-1 decides. The lint builds a pool with `DescriptorPool::decode` over the committed set and reads each option through `DynamicMessage::from_options` and `DescriptorPool::extension_by_name` (R6). The crate enters `Cargo.lock` in #360 as a dependency of `buffa-codegen`, and `reflect` adds no package, so #386 adds its own entry and no third-party package (#360 R2). Moving the lint to another decoder, `prost-reflect` included, amends this RFC (R31). #386 therefore no longer needs #368.
- R27. Closure, resolved with cargo 1.99.1 and resolver 3 for every target, at `7d2de57`; `main` at `84187e7` changed only `supply-chain/admissions.toml`, so its lockfile still holds no third-party package. `sp1-buffa` builds 32 packages, 13 of them on normal edges, the part a release would link if buffa wins. `sp1-prost` builds 35, 11 on normal edges. The lint's decoder closure is 13 packages, all inside `sp1-buffa`'s. `Cargo.lock` gains 63 packages: the 50 either feature builds, and 13 that Cargo locks as optional dependencies no enabled feature reaches. 16 of the 63 are also rows of #1575's admission on `main`; if one of its consumers locks them first, #360 adds 47.
- R28. ARCH-004 (`architecture.toml` `[arch004]`). `grdr-proto` is admitted as a decoder with `admits = []`. Neither feature's normal-edge closure holds a `content_parsers` entry:
  - `sp1-buffa` links `buffa`, `buffa-types`, `bytes`, `foldhash`, `hashbrown` 0.15.5 and `once_cell`, with the proc macros `rustversion` and `thiserror-impl` and their `proc-macro2`, `quote`, `syn` 3 and `unicode-ident`, and `thiserror`;
  - `sp1-prost` links `prost`, `prost-types` and `bytes`, with the proc macro `prost-derive` and its `anyhow`, `either`, `itertools`, `proc-macro2`, `quote`, `syn` 2 and `unicode-ident`.

  `regex` is reached only through `prost-build`'s build edge. `serde_json` is only an optional dependency of `buffa-types` behind its `json` feature, which no edge enables. A change to `crates/grdr-proto/Cargo.toml` that enabled it in a closure ARCH-004 checks would fail that check; it would not change `Cargo.lock`, because the package is already locked. #360 lists both normal-edge closures in its hand-off.
- R29. Licences. Every expression in the closure is satisfied by the permissive class of `supply-chain/licences.toml`; `r-efi`'s `MIT OR Apache-2.0 OR LGPL-2.1-or-later` is taken under MIT. No crate is in `supply-chain/do-not-read.toml` or `deny.toml`'s bans. The licence-closure report of the `embedded` profile (design/26 section 12) lists each feature's normal-edge closure on its own and repeats the `r-efi` election.
- R30. `hashbrown` stays at 0.17.1, #1575's row. A fresh resolve picks 0.17.2, published 2026-11-22T01:08:02Z, inside the three-day cooldown of design/35 section 2.6.
- R31. #360 records the admission in `supply-chain/admissions.toml` in #1575's format: the 63 closure rows with name, version, licence and checksum, the build scripts and proc macros, and one justification per direct crate. `buffa-descriptor`'s justification names its single owner, its pre-1.0 state, that it reaches no shipped program, and the `unsafe` search below. Each consumer entry of a feature-gated edge carries a `feature` key, which this row adds to the format. A resolve at implementation time that differs from R27 goes in #360's hand-off for `eval-licence` and `eval-security`. Only a different direct crate or version amends this RFC. The head of the row:

```toml
[[admission]]
issue = 360
crates = ["buffa", "buffa-types", "buffa-build", "prost", "prost-types", "prost-build", "buffa-descriptor"]
consumers = [
  { crate = "grdr-proto", kind = "normal", feature = "sp1-buffa", only = ["buffa", "buffa-types"], issue = 360 },
  { crate = "grdr-proto", kind = "build", feature = "sp1-buffa", only = ["buffa-build"], issue = 360 },
  { crate = "grdr-proto", kind = "normal", feature = "sp1-prost", only = ["prost", "prost-types"], issue = 360 },
  { crate = "grdr-proto", kind = "build", feature = "sp1-prost", only = ["prost-build"], issue = 360 },
  { crate = "grdr-schema-lint", kind = "normal", only = ["buffa-descriptor"], issue = 386 },
]
resolver = "cargo 1.99.1, resolver 3, the features of RFC 0006 R24 and R26"
```

Maintainers and what they bring:
- **buffa.** All five buffa crates and `smoothutf8`, which the build graph pulls in, have one crates.io owner, `iainmcgin`; the repository is `anthropics/buffa`, pre-1.0. Unknown fields are kept by default, and `buffa-build`'s `preserve_unknown_fields` is on unless turned off. A text search of `src/` for `unsafe {`, `unsafe fn` and `unsafe impl` finds 28 lines in `buffa` and none in `buffa-types` or `buffa-descriptor`. The search misses `unsafe{` and macro output, and no crate of the three sets `forbid(unsafe_code)`.
- **prost.** Owned by `danburkert` and the team `github:tokio-rs:prost-core`. Its README marks it passively maintained: no new features, security fixes released promptly. It drops unknown fields (tokio-rs/prost#2, open since 2017-06-26), which is why design/04 section 1 pairs it with "never re-encode". The same search finds 12 lines in `prost` and none in `prost-types`.
- **Build-time code.** The two features build these build scripts: `anyhow`, `getrandom`, `libc`, `prettyplease`, `proc-macro2`, `quote`, `rustix`, `rustversion` and `thiserror`. They build these proc macros: `prost-derive`, `rustversion` and `thiserror-impl`.

What was run, on a probe manifest with R24's dependencies and the repository's `deny.toml`:
- `cargo deny ... check licenses advisories bans sources` (cargo-deny 0.21.0; the pinned 0.22.0 is not installed here): exit 0. It printed two duplicate-version warnings, `hashbrown` 0.15 and 0.17 and `syn` 2 and 3. RustSec advisory-db was at commit `55e1c3dfbd834237a05bbbf7b50ba3b5be27b662`.
- OSV `querybatch` for all 63 packages: no id.
- The crates.io sparse index for all 63: every checksum matches, and none is yanked. Only `hashbrown` 0.17.2 falls inside the cooldown (R30).

### 7. New lint rules and how they run
Filed on acceptance as one `grdr-schema-lint` item.
| Id | Fails when |
|---|---|
| SL10 | Two files of the set declare a descriptor-option extension, at the top level or inside a message, or none does, or the one that does is outside a `<namespace>.common.<version>` package. The options file declares a message, or imports anything but `google/protobuf/descriptor.proto`. A namespace file other than the options file lacks a direct import of it in `FileDescriptorProto.dependency`, imports it as public or weak, or imports `google/protobuf/descriptor.proto`. A file of the set outside the namespace is not in `foreign_files.toml`, or its descriptor does not have the digest listed there (R14a). An option from any other package does not count, so the field or value then fails SL01 or SL04 |
| SL11 | A package of the namespace has no `[[proto_package]]` row or more than one, or a `stable` row names a package whose last segment is unstable as buf's `PACKAGE_VERSION_SUFFIX` rule reads it (`alpha`, `beta`, `test`) |
| SL12 | `compare` finds a change R17 lists without the new entry that matches it, an entry R17's rules refuse, a new entry whose `rfc` is not the pull request's `RFC:` line or whose RFC is not `Accepted`, a head field with no valid class (as SL01), or one of R17's outright failures (exit 1). Any input that is missing, unreadable or over its bound, base or head, the RFC states included, exits 2 with its code and never passes (P9) |
| SL13 | `capture.toml`'s classes are not exactly the five names R11 derives. A `DataClass` or `ContentKind` enum is defined anywhere but the options file, or a wire name of either is not its value's name without the enum's prefix, in lower case. At some level a class is more open than a class of lower rank (withheld, then redacted, then passes), or less open than at the level before it. The default level passes or redacts a content class (P8, D-51) |

The commands:
- `compare --base <dir> --head <dir> --rfc-line <file> --rfc-states <file>` is SL12 and SL13. Each directory holds the descriptor set, `capture.toml` and `reclassifications.toml` at their paths. `--rfc-line` holds the pull request's `RFC:` value, empty when the body names none, and `--rfc-states` the state in force of every RFC on the base, both as #1741's checker writes them. `compare` loads both sides through the loaders, so every loader refusal applies to the head's files.
- `check --descriptors <file> --surfaces <file>` is SL01 to SL07, SL10 and SL11. The namespace comes from the base's brand manifest.
- `capture --check` and `registry --check` regenerate R13a's files from the head's inputs and compare them byte for byte with the head's committed copies.
- `manifests --metadata <file> --tree <dir> --trust-core <file> --crate <name>...` reads the JSON that `cargo metadata --no-deps --format-version 1` printed for the head's tree, the head's `security/trust-core.paths` (`--trust-core`), the root `Cargo.toml`, and every workspace package's manifest in `--tree` through the lint's TOML loader. It exits 2 when any input file (`--metadata`, `--trust-core`, root `Cargo.toml`, or any workspace package's metadata `manifest_path` file in `--tree`) is missing, unreadable, malformed or over its `limits.toml` bound, when a workspace package's `manifest_path` lies outside `--tree`, or when a `--crate` name (`grdr-schema`, `grdr-model`) is absent from the metadata. Over every workspace package, it exits 1 when: the manifest holds a `package.build` key; any `custom-build` target has a `src_path` other than `<tree>/<pkg>/build.rs`; any target has a `src_path` outside `<tree>/<pkg>/`; any `path` dependency in the root or workspace manifests resolves outside the metadata's workspace packages; or any `proc-macro` target sits in a package whose directory `<pkg>/**` is not covered by `--trust-core` matching ignoring ASCII case. For each named `--crate` (`grdr-schema`, `grdr-model`) present in the metadata, it also exits 1 when its metadata `manifest_path` is not `<tree>/crates/<name>/Cargo.toml`, when a `custom-build` target exists, or when the package does not have exactly one `lib` target with `src_path` equal to `<tree>/crates/<name>/src/lib.rs`, as RFC 0004's `c-headers` step 1 and `HDR-5` refuse for its crates.
- Each input has a size bound, and the record file an entry bound, as keys the gate item adds (`G-1`) and `grdr-schema-lint` reads from `limits.toml`. The base's values apply, and an input over its bound is unreadable.

How they run, as `rfc-required` runs under RFC 0001 and #1741:
- **On a pull request.** The `schema-gate` job runs on `pull_request_target`, so its workflow file is the base's. It checks out the base, immediately pins the Rust toolchain through `.github/actions/tree-paths` (reading the base's `rust-toolchain.toml` from git objects by id with object replacement off and setting `RUSTUP_TOOLCHAIN` in `GITHUB_ENV`, #1923/#1975), and builds `grdr-schema-lint` there. Every git read runs with `--no-replace-objects` (`GIT_NO_REPLACE_OBJECTS=1`) and exits 2 (`GRDR-GATE-0007`) if any ref under `refs/replace/` exists; it resolves the base and head commits once each to full object ids (`git rev-parse --verify --end-of-options <ref>^{commit}`). Before writing any head file or calling Cargo, it runs the pre-cargo tree check on the head object id (`.github/actions/tree-paths/check_tree.py --rev <head_id>` from the base, reading `git ls-tree -r -t -z`), failing on any byte outside printable ASCII (`0x20` to `0x7E`), any two paths or directory prefixes equal under ASCII case folding that differ in bytes, any entry of mode `120000` (symbolic link) or `160000` (submodule), or the remaining tree-check rules, and exiting 2 if `<head_id>` cannot be read or `refs/replace/` is present. It then reads the head's descriptor set, data files, `surfaces.toml`, `security/trust-core.paths`, `fields.json`, `capture.rs` and `registry.rs` into a temporary directory, and writes the head's verified regular-file blobs (`100644`/`100755`) into a second temporary directory, directly from git blob objects by object id (`git ls-tree` and `git cat-file blob`, never through `git archive`), so `.gitattributes` has no effect. From outside the head tree (the base's checkout as working directory), with `RUSTUP_TOOLCHAIN` set to the base's pinned toolchain and without reading any head `.cargo/config.toml` or toolchain file, it runs `cargo metadata --no-deps --offline --format-version 1 --manifest-path <head_tree>/Cargo.toml`, which reads the manifests as data and runs no build script. It runs `check`, `compare`, `capture --check`, `registry --check` and `manifests` over them, with the `RFC:` line from #1741's reading of the pull request body, passed through a file and never interpolated into a command. It never builds or runs the head's code or scripts. It has read-only permissions, no secrets and `persist-credentials: false`, uses no cache action, and records the zizmor exception its trigger needs, as #1741 does; zizmor's cache-poisoning audit stays clean. Every step fails on any non-zero exit, exit 2, a panic or a signal included. The lint is `#![forbid(unsafe_code)]`, and #1881's fuzz target covers the decoder and both loaders.
- **On every push to `main`.** The same job runs with the parent as the base, built from the parent, and takes the `RFC:` line from the commit's merged pull request. A commit that adds an entry and has no merged pull request fails. A failure opens an issue for the chief architect naming the commit and the finding; the revert is its own issue, as RFC 0001's detector does. Ruleset 27805089 on `main` already refuses direct pushes (#1719): it requires a pull request, blocks deletion and force pushes, and has no bypass actor.
- **Required.** `schema-gate` and the `proto` job become required checks of that ruleset (#1879).
- **The head's build.** The `proto` job keeps `buf`'s steps (#1842) and runs the head's own `check`, so a pull request that adds a rule meets it. No property in this RFC rests on that run.
- **Two-step changes.** A change to the lint's code or data takes effect from the next pull request's base. A change to a generator or a check, or an RFC that amends an outright failure, therefore lands as two pull requests: the lint change, then the data or generated-file change it allows. Moving a file the job reads also takes two: the first teaches the lint to read the base at the old path and the head at the new one, and the second moves the file and teaches the lint to read both at the new path.

### 8. Mechanisms
| Decision | Mechanism | Built by |
|---|---|---|
| Every field has a class; `content_kind` exactly on content; no float marked `policy_readable`; closed enums; no `Any` or `Struct`; no field in 900 to 999 | SL01 to SL07 over the committed set, walking nested messages and oneof members, from the base's build | #386; #1843 runs it |
| Zero values have no `wire_name`; every other value has a unique one | SL04, amended to exempt zero values | #386 |
| One options file; the options package comes from the import; foreign files judged by content | SL10 and `foreign_files.toml` | Lint item |
| `surfaces.toml` is the only source of the class | SL11, and the `[[proto_package]]` row | Filed on acceptance (two items) |
| A field change, level release or wire-name change needs one new entry citing the pull request's accepted RFC, never one already used; the classes, levels, default, option numbers and retired fields do not move | SL12 (`compare`) from the base's build, on pull requests and on push | Lint item; #1843 runs it |
| An entry's RFC decides it, and its review is the seat's | Four checks per new entry in the evaluators' rubric | #1880 |
| `capture.toml` has one loader and one shape; class names follow the wire names; openness never rises with rank or falls between levels; the default passes no content | The loader and SL13 | Lint item |
| Generated files are what the base's code makes from the head's data | `capture --check` and `registry --check` from the base's build | Lint item and #386; #1843 runs them |
| `grdr-schema` and `grdr-model` compile from their committed `crates/<name>/src/lib.rs` with no build script; every workspace package keeps any `build.rs` at `<pkg>/build.rs`, sets no `package.build`, keeps targets inside its directory, resolves `path` dependencies inside the workspace, and puts any `proc-macro` package on `security/trust-core.paths` (matched ignoring case) | `manifests` over `cargo metadata --no-deps` of the head's tree (checked for case-fold, non-ASCII and links before Cargo, written from git objects by id, and read from outside the head tree with the pinned toolchain), from the base's build | Lint item; #1843 runs it; #1923/#1955/#1975 |
| Each crate's `lib.rs` declares the generated modules and the filter as plain `pub mod` lines | The `lib.rs` check in the evaluators' rubric, on every change to either `lib.rs` | #1880 |
| A gate never passes when it could not look | Exit 2 on a missing, unreadable or over-bound input, missing `--crate` in metadata, missing metadata `manifest_path` in `--tree`, or `refs/replace/`; the job fails on any non-zero exit, exit 2 included | Lint item; #1843 |
| The gates hold before a merge | `schema-gate` and `proto` as required checks of ruleset 27805089 | #1879 |
| Hostile head bytes do not subvert the job | A fuzz target over the decoder and both loaders | #1881 |
| The lint does what R17 says | A table model of `compare`, independent of the lint, with a differential test over generated base and head pairs and its case count and seed recorded (D-63) | Lint item |
| An entry reaches a deployed device only after its organisation confirms it | The 04-16 filter's hold (R17b) and the signed confirmation record | #117; #1878 |
| People are told of entries and new fields | The release note of R17c and design/29's pending diff | `eval-docs`; #1878 |
| A classless leaf never ships; imported leaves take their holder's class | R14a in the registry writer and SL10; `UnregisteredField` in the filter | #386, lint item, #117 |
| The data files, generated files, lint, filter, both crates' manifests, every `build.rs`, any `proc-macro` package, Cargo configs, git attributes and submodules change only with the full lane | Eighteen `security/trust-core.paths` lines (`**/build.rs` included) plus `<dir>/**` per workspace `proc-macro` package and #1955 Option A's `**/.cargo/**`, `**/.gitattributes` and `**/.gitmodules` lines, matched ignoring case (`:(glob,icase)`); `depends_on = []` for the lint | The gate item; #1923/#1955; #1580 holds the edge |
| A new field's class | The privacy canary, a required check on every pull request that adds a field | #493 |
| Option numbers leave the in-house range together | SL09 | #398 |
| A renumbered field, a reused enum value or a comment ignore fails under the real module's configuration | R23's fixtures, run in a fresh copy | The gate item; #1842 R4 |
| Committed sets and vectors are fresh | Rebuild and byte compare, with a stale-set negative control | #1842 R5 to R7 |
| The lint's decoder agrees with `buf`'s | The registry built from `buf`'s JSON rendering of the set equals the committed one | Lint item; #1843 runs it |
| Every `proto/**` and `crates/grdr-schema/**` change names an accepted RFC | `rfc-required` (`grdr-schema` is a layer 0 public crate) | #1741 |
| `grdr-proto` has exactly R24's crates, licences in the class, no `protoc`, one codec at a time | #360's criteria (section 10), `cargo deny check`, the admission row | #360 |
| No build reaches a schema compiler; third-party `Cargo.lock` build-time code matches admitted crates (outside `security/trust-core.paths` under ADR-0043) | The `rust` job runs with `PROTOC` unset and no `protoc` or `buf` on `PATH`; `cargo-deny`, `osv-scanner` and a step comparing `Cargo.lock` with `supply-chain/admissions.toml` hold third-party crates and build-time code (required protection before release-build reliance; interim residual until landed) | Filed on acceptance (lead-agent-kit); `verify.yml`, `scan.yml` |
| Workspace builds do not rewrite tracked sources on disk (release builds included) | Every CI cargo job, release builds included, fails when `git status --porcelain` is non-empty afterwards (required protection before release-build reliance; interim residual until landed) | #1910 (lead-agent-kit) |
| The losing codec's crates leave `Cargo.lock` | The item that makes SP-1's winner the crate's codec | #368's decision record files it |

#### Seeded fixtures
The lint item adds these cases, each wrong by construction, and its tests run them. Names follow #1854 where it has one. "Passes" means exit 0.

| Fixture | Expect |
|---|---|
| `sl12::downgrade_without_entry`; `sl12::raise_without_entry` | exit 1 |
| `sl12::downgrade_with_new_entry` | passes |
| `sl12::sealable_lost`, `sl12::sealable_gained` | exit 1 without an entry, passes with one |
| `sl12::record_reuse`: the base holds the entry, the field is back at its old treatment, the head lowers it again with only the old entry | exit 1 |
| `sl12::rfc_reused`: a new entry with a base entry's key and a new `review` | exit 1 |
| `sl12::duplicate_entry`, `sl12::entry_edited`, `sl12::entry_removed`, `sl12::entry_moved` | exit 1 |
| `sl12::unmatched_entry` | exit 1 |
| `sl12::rfc_line_mismatch`: a new entry whose `rfc` is not the `RFC:` line | exit 1 |
| `sl12::rfc_not_accepted`: the cited RFC is `Draft`, `Implemented`, the template, or absent from the base | exit 1 |
| `sl12::rfc_states_missing`: no states file | exit 2 |
| `sl12::removed_field`: with a removal entry whose successor is `"none"`; with no entry | passes; exit 1 |
| `sl12::removal_without_successor`: a removal entry with no `successor` key | exit 2 |
| `sl12::unnamed_new_field`: a change with a removal entry adds a field that no removal entry names, with `"none"` and with a decoy successor | exit 1 |
| `sl12::move_to_successor`: `Exec.argv` moved to `Exec2.argv` at a lower class, with only the removal entry; then with the successor's entry too | exit 1; passes |
| `sl12::rename_is_removal`: `argv` removed and `argv_v2` added in its message, and a renamed message | exit 1 without a removal entry naming the successor |
| `sl12::retype_is_removal`: a string field retyped to bytes, with a removal entry naming the field itself; naming `"none"` | passes; exit 1 |
| `sl12::message_retype`: a field retyped from `Detail` to `Detail2`, and a map's value from `string` to a message | exit 1, entries or not |
| `sl12::retired_field_returns`: a field a base removal entry names comes back | exit 1, entries or not |
| `sl12::version_without_predecessor`: `v1` beside `v1alpha1` | exit 1 |
| `sl12::level_release`: `redacted arguments` gains `content.body` | exit 1 without an entry, passes with one |
| `sl12::new_level`: a level the base lacks passes every class | exit 1 without five entries, passes with them |
| `sl12::level_removed`, `sl12::level_reordered`, `sl12::default_changed`, `sl12::class_order_changed` | exit 1, entries or not |
| `sl12::wire_name_changed` | exit 1 without an entry, passes with one |
| `sl12::wire_name_moved`: a value removed and its name given to a new value, in one change and in two | exit 1 without an entry for the new value |
| `sl12::option_dropped`, `sl12::option_renumbered` | exit 1 |
| `sl12::missing_base`, `sl12::missing_head`: each input in turn | exit 2 |
| `sl12::over_bound`: each input over its `limits.toml` bound | exit 2 |
| `generated::capture_hand_edit`: the head's `capture.rs` differs from what the base's code writes, a wrapper constant included | exit 1 |
| `generated::registry_hand_edit`: the same for `fields.json` and for `registry.rs` | exit 1 |
| `generated::writer_changed`: the head's files were written by a changed writer | exit 1 |
| `generated::lib_target_moved`, `generated::build_script_added`, `generated::build_key_set`: each for `grdr-schema` and for `grdr-model` | exit 1 |
| `manifests::decoy_crate_path`: `crates/grdr-schema` renamed and another package named `grdr-schema` present in `cargo metadata` at `crates/other/Cargo.toml` | exit 1 |
| `manifests::other_crate_build_key`: another workspace package sets `package.build` (a path or `false`) | exit 1 |
| `manifests::other_crate_custom_build_path`: another workspace package declares a `custom-build` target outside `<pkg>/build.rs` | exit 1 |
| `manifests::other_crate_build_rs_allowed`: another workspace package (`crates/grdr-proto`) has `crates/grdr-proto/build.rs` and no `package.build` key | passes (`**/build.rs` keeps it on the trust-core lane) |
| `manifests::proc_macro_unlisted`: a workspace package with a `proc-macro` target whose `<dir>/**` is absent from `security/trust-core.paths` | exit 1 |
| `manifests::proc_macro_icase_match`: a workspace `proc-macro` package `crates/Sample-Macro` covered by `crates/sample-macro/**` in `security/trust-core.paths` | passes |
| `manifests::target_outside_crate`: a workspace package target whose `src_path` lies outside `<pkg>/` | exit 1 |
| `manifests::external_path_dep`: a workspace manifest `path` dependency pointing outside the metadata's workspace packages | exit 1 |
| `manifests::missing_or_unreadable`: a named `--crate` absent from `cargo metadata`, a metadata `manifest_path` missing or unreadable in `--tree`, or a missing, unreadable or over-bound manifest, metadata or `--trust-core` input | exit 2 |
| `capture_toml::repeated_name`, `capture_toml::undeclared_class`, `capture_toml::unknown_key` (a `pseudonymous` key included), `capture_toml::class_in_both_lists`, `capture_toml::default_level` | exit 2 |
| `sl13::default_passes_content`, `sl13::permuted_wire_names`, `sl13::second_data_class` | exit 1 |
| `sl13::openness_rises_with_rank`: a level that redacts `content.argument` and passes `content.body` | exit 1 |
| `sl10::second_options_package`, `sl10::import_public`, `sl10::nested_extension` | exit 1 |
| `sl10::foreign_message_with_text`; `sl10::look_alike` (`google/protobuf/blob.proto`); `sl10::shadow` (a local `timestamp.proto` with an extra field); `sl10::own_google_protobuf_file` (`google/protobuf/v1/codes.proto`) | exit 1 |
| `registry::imported_type_classes`: a `Timestamp` on a structural and on a content field | the leaves take each holder's class |
| `filter::classless_leaf` (#117) | `UnregisteredField`, no copy |
| `filter::field_and_level_held` (#117): a field entry from `content.body` to `content.argument`, and a level entry from `withheld` to `redacted` for `content.body` at `redacted arguments` | withheld at `redacted arguments` while both are unconfirmed; redacted once either is confirmed |
| `filter::sealable_loss_held` (#117): an unconfirmed entry from `content.argument sealable` to `content.argument` | the field keeps `sealable`, and in the endpoint-sealed key mode it is withheld, since the head has no twin |
| SL01 oneof, nested message and map cases, and an undeclared number set in memory (#386) | exit 1 each |

#1843's own criteria hold the job-level routes that no unit fixture of the lint can show on its own:
- `schema_gate::head_code_ignored`: on a local branch that edits `crates/grdr-schema-lint/src/` to skip SL12 and the generated-file checks, and lowers a field, the job's commands, run as written from the base, exit 1.
- `schema_gate::gitattributes_export_ignored`: a head commit whose root `.gitattributes` sets `export-ignore` on `crates/grdr-schema/build.rs` and `export-subst` on `crates/grdr-schema/Cargo.toml` still materialises both from git blob objects by object id and exits 1 in `manifests`.
- `schema_gate::case_fold_collision`: a head tree with two paths (and one with two directory prefixes) equal under ASCII case folding exits 1 in the pre-cargo tree check before any file is written or Cargo runs.
- `schema_gate::non_ascii_path`: a head tree with a non-printable-ASCII path byte exits 1 in the pre-cargo tree check before any file is written or Cargo runs.
- `schema_gate::member_manifest_link`: a head tree with a mode `120000` symbolic link (for example `crates/zz/Cargo.toml`) or a mode `160000` submodule exits 1 in the pre-cargo tree check before any file is written or Cargo runs.
- `schema_gate::replace_ref_present`: a repository holding a ref under `refs/replace/` exits 2 (`GRDR-GATE-0007`) and fails the step.
- `schema_gate::head_cargo_and_toolchain_ignored`: a head tree with `.cargo/config.toml` (`build.rustc` set to a missing program) and `rust-toolchain.toml` naming a missing channel, run from outside the head tree with the base's pinned `RUSTUP_TOOLCHAIN`, leaves `cargo metadata` at exit 0 without reading either head file.
- `schema_gate::exit_two_fails`: exit 2 from `check_tree.py`, `manifests`, `compare` or `check` fails the `schema-gate` step.

### 9. Proposed changes to design documents and gate files
Each lands through an item whose write set names its file, filed on acceptance.
- **design/04 section 1.** The code block becomes `options.proto` as sections 2 and 3 give it. The naming rules gain: `proto3` for every `v1alpha1` file; descriptor-option extensions only in the options file; the options package taken from the import (R6); zero values without a `wire_name`; foreign files only as R14a allows.
- **design/04 section 10.** The commitment classes are spelt `content.argument` and `content.body`, as `withheld` already does.
- **design/04 section 11.** The matrix points to `crates/grdr-schema/capture.toml` as its data and states R13's rank and default level, that levels do not carry the evidence-span and content-grant routes, and R17b's rule for deployed devices.
- **design/04 section 13.** The check table gains SL10 to SL13 and R13a's generated-file checks, all from the base's build, and its wire-compatibility row names R17's entries.
- **design/04 section 14.** A mapping never assigns a class (R13).
- **design/26 section 9 and design/36 section 2.** `[identity] namespace` is the wire namespace, class A, which a rebuilt manifest keeps (R3).
- **design/29 sections 6, 8 and 9.** The confirmation record and the pending entries, through #1878.
- **`surfaces.toml`.** `[[proto_package]]` with `package = "common.v1alpha1"` and `class = "experimental"`, created by whichever of this item and #1817 lands first.
- **`security/trust-core.paths`.** The eighteen lines of R19 (with `**/build.rs`, case-insensitive matching and the `<dir>/**` `proc-macro` rule if not already merged by #1955 Option A; ADR-0043's exclusion of `Cargo.lock`, root `Cargo.toml` and `supply-chain/admissions.toml` stays intact), in the gate item.
- **`architecture.toml`.** `depends_on = []` on `[crates.grdr-schema-lint]`, in the gate item.

### 10. What each item changes
This RFC is normative. Each lead writes these changes back into its item before readying it.
- **#353.** The write set loses `buf.yaml` and `schema/fixtures/buf/**` to the gate item (R19), and the item is blocked by it. R2 and R3 become sections 1 to 3: one `options.proto` with two enums and five extensions, values named in full (`DATA_CLASS_IDENTIFIER = 1`), `syntax = "proto3"`, and no fallback file. R5's command keeps imports (R21). AC-1 stays `buf lint` at the root. AC-2, AC-3 and AC-5 move to the gate item. The pull request names `RFC: 0006`.
- **#360.** R1's list is R24's table, and R2's decoder is `buffa-descriptor` 0.9.2 (R26). It holds `hashbrown` at 0.17.1 (R30) and writes the admission row of R31. Its write set gains `supply-chain/admissions.toml`, which #1575 has created on `main`. AC-4 builds each feature on its own (`--features sp1-buffa`, then `--features sp1-prost`) with no `protoc` and no `buf` on `PATH`. New criteria: `cargo check --locked -p grdr-proto --features sp1-buffa,sp1-prost` fails with the `compile_error!` message; `cargo check --locked --target wasm32-unknown-unknown -p grdr-proto --features <feature>` exits 0 for each feature on its own; and every package `Cargo.lock` gains is a row of the admission with the same version and checksum. The wasm32 criterion shows that each feature builds for that target; that a built module imports nothing (design/26) is checked on `grdr-wasm`'s module. The pull request names `RFC: 0006`.
- **#386.** R0's decoder is R26's, and the crate depends on no workspace crate. R1 takes the options package from the import (R6). SL01 walks every message, nested ones included, and every field, oneof members included; a map field's entry message is skipped, its key and value take the map field's class, and its type includes the key and value types (R17a). Fixtures for oneof, nested and map cases, and the undeclared-number case set in memory (R12). The registry gives each leaf of an imported type its holder's class (R14a) and records each field's message full name, number and treatment. `registry --out` also writes `crates/grdr-schema/src/registry.rs` (R13a), and the write set gains it and `crates/grdr-schema/src/lib.rs`. A new failure mode: a file whose options package is missing from the set exits 2 with a code lead-core registers, never `Clean`. SL04 exempts zero values. The blocked-by link to #368 is removed. "Trust core: no" becomes yes.
- **#368.** It compares each codec with the golden vectors in a build of its own (R24). If prost wins, its decision record may propose an amendment of this RFC to move the lint to `prost-reflect` (R26).
- **#398.** Moves 50001 to 50004 and 50011 together (R5).
- **#1842.** R4 runs R23's cases in a fresh copy of the checkout with `proto` as the input, breaking and lint cases both, and AC-2 and AC-3 follow. It waits on the gate item.
- **#1843.** It adds the `schema-gate` job of section 7, on `pull_request_target` and on every push to `main`, pinning the toolchain through `.github/actions/tree-paths` (#1923/#1975), refusing `refs/replace/` with exit 2 (`GRDR-GATE-0007`), running the pre-cargo tree check (`.github/actions/tree-paths/check_tree.py`, #1955) before writing any head file, extracting the head's inputs and tree directly from git blob objects by object id (never `git archive`), running `cargo metadata` from outside the head tree with `RUSTUP_TOOLCHAIN` set, running `check`, `compare`, `capture --check`, `registry --check` and `manifests --trust-core` from the base's build, and failing on any non-zero exit (exit 2 included). R1's `check` and `registry --check` move from the `proto` job to it; the `proto` job keeps the head's own `check` and gains the step that renders the set with `buf build proto --as-file-descriptor-set --exclude-source-info -o "$RUNNER_TEMP/proto.json"` and checks that the registry built from that JSON equals the committed one. The lint item adds that reading of `buf`'s JSON, through `serde_json`, which #1575's closure already locks, with its own consumer entry. Its job names are the contexts #1879 requires. It is blocked by the lint item, #1741 and #1955, and it blocks #18 and every later change to `proto/**`, so no class changes before SL12 runs. Its criteria include section 8's `schema_gate::*` cases.
- **#117.** The filter reads `grdr_schema::capture` and `grdr_schema::registry`, refuses a classless leaf, imported leaves included (R14a), and holds as R17b says. Its one new criterion: for one field with entries E1 (A to B) and E2 (B to C), the filter applies the less open of A and C while E1 is unconfirmed, whether or not E2 is; an entry stays held when the organisation has confirmed another entry that cites the same RFC; a successor stays at the removed field's treatment until its entry is confirmed; a level entry holds its level and class at `from`; a field entry whose `from` class has an unconfirmed level entry at that level stays at that level entry's `from` (`filter::field_and_level_held`); an unconfirmed loss of `sealable` keeps the field `sealable` (`filter::sealable_loss_held`); and `absent` reads as `withheld`. Its reference model is AC-1's transcribed matrix with leaf classes read by draft 03's walker, with a differential test over generated events and matrix evidence (D-63). Its paths become trust core, and it is blocked by #1878.
- **#1741.** Its checker writes, for the `schema-gate` job, the state in force of every RFC on a tree and the pull request's `RFC:` value, each to a file.
- **#1580.** The architecture lint honours a crate's own `depends_on`, which replaces its layer's for workspace crates.
- **#1856.** The loader refuses a manifest whose `[identity] namespace` differs from the upstream value (R3). If the lint comes to link it, R19's rule for a new edge applies.
- **#1854.** Its rows follow the accepted text. SR-51 covers `check`, the generated-file checks, reading git objects by id without `git archive`, running the pre-cargo tree check, running Cargo from outside the head tree with the pinned toolchain, and `manifests` over every workspace package as well as SL12. SR-52's transitions are R17's three kinds, with any change of a field's treatment, a removal's successor, the `RFC:` line and `Accepted` state, and the key rule. SR-53 has no bootstrap exception, and its base inputs are the descriptor set, `capture.toml`, `reclassifications.toml`, `security/trust-core.paths`, the workspace manifests and the RFC states; an over-bound or unreadable input exits 2 and fails the step. SR-54's loader is in `grdr-schema-lint`, with the generated module in `grdr-schema`; it has no `pseudonymous` key, and it refuses a default level that passes or redacts a content class rather than one named other than `metadata`. `sl13::duplicate_level` is `capture_toml::repeated_name`.
- **#493.** The privacy canary runs on every pull request that adds a field and is a required check once it exists (R17a).
- **#495.** Its criteria name the field that marks a record with an omitted unknown value (R12).
- **#18.** Its RFC decides R14's list, including the entry kind for the evidence-span and content-grant routes and how SL12 compares a message-typed field.

Filed on acceptance, each citing this RFC and its decision record:
- the gate item of R19: the first `buf.yaml`, the four fixture cases, `capture.toml`, the empty `reclassifications.toml`, the eighteen `security/trust-core.paths` lines (or those not already landed by #1955, matching ignoring ASCII case with the `proc-macro` rule) and the `architecture.toml` key (lead-agent-kit, trust core, blocked by #1697, blocking #353, #386, #1842 and the lint item). Its criteria are R23's fresh-copy runs and the byte comparison of `capture.toml` with R13;
- the `[[proto_package]]` row of `surfaces.toml`, a protected trust-core change (chief-architect);
- `grdr-schema-lint` SL10 to SL13, both loaders, `capture --out` and `--check`, `compare`, `manifests` (over every workspace package, `--trust-core` matching ignoring ASCII case, `<tree>/crates/<name>/` pinning with exit 1 when present in metadata at another path, and exit 2 when a `--crate` is absent from metadata or an input or metadata `manifest_path` file is missing or unreadable), `foreign_files.toml`, the `limits.toml` bounds, the JSON reading, section 8's fixtures and the table model of `compare` (squad core, trust core, blocked by #386, the gate item, the row item and #1741, blocking #1843 and #18);
- R11's test in `grdr-cabi-testkit` (squad core, blocked by #1778 and the lint item);
- the `rust` job and lockfile checks of section 8 (`PROTOC` unset, no `protoc` or `buf` on `PATH`, and `Cargo.lock == supply-chain/admissions.toml`, required alongside `cargo-deny`, `osv-scanner` and #1910's post-cargo clean-tree check before release-build reliance) (lead-agent-kit, trust core because `.github/workflows/verify.yml` is on `security/trust-core.paths`);
- the "could not look" rule of R13 for design/13's rule linter and replay (its squad's lead);
- the design document amendments of section 9 (chief-architect).

Filed with this revision, each waiting on this RFC's acceptance:
- #1878, design/29's confirmation record and pending entries (chief-architect; blocks #117);
- #1879, `schema-gate` and `proto` as required checks of ruleset 27805089 (lead-agent-kit; blocked by #1843 and #1842);
- #1880, the evaluators' four checks per new entry and R13a's `lib.rs` check (lead-agent-kit);
- #1881, the fuzz target over the job's head inputs (squad core; blocked by the lint item and #415).

### 11. Failure modes
| Failure | Outcome | Visible as |
|---|---|---|
| The pinned `buf` refuses an option used in its own file | #353 stops `blocked`; this RFC is amended | #353's hand-off |
| A file's options package is missing from the set | The lint exits 2 with its code; it never reports `Clean` | stderr and the CI step |
| A manifest's `[identity] namespace` differs from the upstream value | The brand manifest loader refuses it (#1856); the job reads the base's manifest | The loader's error |
| A head field with no class, a zero one or an undeclared one | SL01 and SL12 exit 1 at that field | The `schema-gate` check |
| A field change, level release or wire-name change without a new matching entry | SL12 exits 1, naming the identity, both values and the entry it needs | The `schema-gate` check |
| An entry already on the base, edited, removed, repeated, reusing a key, matching no change, or citing an RFC that is not the `RFC:` line or not `Accepted` | SL12 exits 1, naming the entry | The `schema-gate` check |
| An entry whose RFC does not decide it, or whose review does not meet R17 rule 3 | A major finding of the lane's four checks | The verdicts (#1880) |
| A removal whose successor has another treatment, or a new field beside a removal that no removal entry names | SL12 exits 1; with the successor's entry, the filter holds the successor | The `schema-gate` check; #117's tests |
| A base or head input, a metadata `manifest_path` file in `--tree`, or a named `--crate` in metadata is missing, unreadable or over its bound, or `refs/replace/` exists | Exit 2 with its code (`GRDR-GATE-0007` on `refs/replace/`); fails the step and never passes | The `schema-gate` check |
| A decoder or loader fault on hostile head bytes | The job fails on any non-zero exit; #1881 looks for such inputs | The `schema-gate` check; fuzz findings |
| A generated file differs from what the base's code makes from the head's data | `capture --check` or `registry --check` exits 1 | The `schema-gate` check |
| `grdr-schema` or `grdr-model` moves its manifest or library root or gains a build script; or any workspace package sets `package.build`, puts `custom-build` outside `<pkg>/build.rs`, puts a target outside its directory, resolves a `path` dependency outside the workspace, or declares an unlisted `proc-macro` target | `manifests` exits 1; both crates' manifests, `**/build.rs` and each `proc-macro` directory are trust core (ignoring ASCII case) | The `schema-gate` check |
| Head `.gitattributes` sets `export-ignore` or `export-subst` | Ignored: `schema-gate` reads verified regular-file blobs from git objects by object id, never through `git archive` | `schema-gate` (`schema_gate::gitattributes_export_ignored`) |
| Head tree has a non-printable-ASCII path, a case-fold collision, a symbolic link (`120000`) or a submodule (`160000`) | Pre-cargo tree check (`check_tree.py`) exits 1 before any file is written or Cargo runs | The `schema-gate` check |
| Another workspace crate's `build.rs` or `proc-macro`, or third-party `Cargo.lock` build-time code, writes a generated module or filter file on disk during a build | Workspace `**/build.rs`, proc-macro `<dir>/**`, `**/.cargo/**`, `**/.gitattributes` and `**/.gitmodules` are held by the trust-core lane (#1955); third-party `Cargo.lock` build-time code stays outside `security/trust-core.paths` (ADR-0043) and is held by `cargo-deny`, `osv-scanner`, section 8's `Cargo.lock == supply-chain/admissions.toml` check and `#1910`'s post-cargo clean-tree check (both required before release-build reliance, with an interim residual until they land) | The trust-core lane, `verify.yml` / `scan.yml`, and `#1910` once landed |
| Either crate's `lib.rs` declares a generated module or the filter through an attribute, a macro or `include!` | A major finding of the lane's `lib.rs` check | The verdicts (#1880) |
| A pull request changes the lint's code or fixtures | No effect on its own checks, which run from the base's build; the change takes the full lane | The `schema-gate` check and the evaluators |
| `capture.toml` has an unknown key, a repeated name, an undeclared class or a class in both lists | The loader exits 2 with its code, for every reader | The `schema-gate` check |
| A leaf has no class, imported leaves included | The filter produces no copy (`UnregisteredField`), and the caller counts it in `health.coverage` | #117's error and the coverage count |
| A change merges onto a newer base than its checks read | The push run fails and opens an issue for the chief architect; the revert is its own issue | The push run and the issue |
| A commit on `main` adds an entry and has no merged pull request | The push run fails; the ruleset refuses direct pushes in the first place | The push run and the issue |
| A required check fails or does not report | The ruleset blocks the merge (#1879) | The pull request's checks |
| An entry reaches a device before its organisation confirms it | The filter applies the least open treatment until the organisation's record for that entry | #117's tests; the pending diff |
| Both codec features are enabled | `grdr-proto` does not compile | The build error |
| A configuration change makes a fixture case pass | R23's step fails, naming the case | Job log |
| A committed descriptor set or vector is stale | #1842 R5 or R6 fails, naming the file and the rebuild command | Job log |
| A codec's build script needs `protoc` or `buf` | #360 or #368 stops `blocked` (W2); the `rust` job's check fails | The hand-off and the job log |
| A resolve differs from R27 at implementation time | Listed for `eval-licence` and `eval-security` (R31) | #360's hand-off |

## Surfaces changed
| Surface | Class | At the freeze (04-29) |
|---|---|---|
| Package `grdr.common.v1alpha1`: `options.proto`, the enums, the option names | experimental (`surfaces.toml`) | renamed `v1`; option and value names kept |
| The wire names of `DataClass` and `ContentKind`, and the class names of R11 | experimental | kept; a change needs an entry (R17) |
| The capture level names in `capture.toml` | experimental | kept; the level set changes only as R17 allows |
| Option numbers 50001 to 50004 and 50011 | experimental | not kept: #398 moves them. Read options by full name (R6). An embedder with its own options on the same extendees keeps clear of these five numbers |
| `crates/grdr-proto/descriptors/proto.binpb` | experimental | regenerated with every change |
| The features `sp1-buffa` and `sp1-prost` of `grdr-proto` | experimental | not kept: the loser leaves with SP-1's adopting item, and the winner stops being a feature |
| The generated modules `grdr_schema::capture` and `grdr_schema::registry` | experimental | follow their sources |
| `buf.yaml`, `capture.toml`, `reclassifications.toml`, `foreign_files.toml` | gate data, trust core | not a product surface |

- `options.proto` defines no message, so no event changes. The default build of `grdr-proto` and its closure are unchanged.
- As proposals: design/04 sections 1, 10, 11, 13 and 14, design/26 section 9, design/36 section 2, a `surfaces.toml` row, eighteen `security/trust-core.paths` lines (plus `<dir>/**` per workspace `proc-macro` package, matched ignoring case) and one `architecture.toml` key that narrows the lint's edges. No spine text, pinned path, Cedar schema, licence policy or same-layer edge changes.
- This RFC changes no field, level or wire name, so it adds no entry to `reclassifications.toml`.

Data classes (P8): this RFC adds the class mechanism and no data field. The lint and the build scripts read schema descriptors and data files only, which are `structural`, and log no event data. Assurance effect (P1): none. No action class changes `visibility`, `control`, `on_failure` or `tamper`.

## Alternatives
- **The options package as a literal in each reader.** It breaks at the freeze and cannot serve N and N-1 at once. Rejected for R6.
- **The options package as a key of the `[[proto_package]]` row.** It works, but it is a second statement of what the import already says. Rejected for the import.
- **The stability class stated by the suffix and the row, held equal by a lint.** Two sources, and it forbids an experimental `v1`, which D-60 and ADR-0020 allow. Rejected for SL11's one-way rule.
- **A per-field or per-file `stability` option.** A second source beside `surfaces.toml` (ADR-0020, P17). Rejected.
- **`encoding` now.** #353 and #360 have no bytes field, and a closed set fixed now would have to fit `Receipt.decision`, `native` and `Redaction.original` unseen. Deferred to #18's RFC (R14).
- **Reclassification held by the registry diff and `rfc-required` alone.** Any accepted RFC satisfies `rfc-required`, so a downgrade passes every check. Rejected for SL12 and entries.
- **Decision lines read from an accepted RFC's text.** The lint has to parse Markdown, whose open cases (HTML comments, nested headings, quotes) each let a line count or not by accident; an accepted RFC can gain a line later; and a line, once accepted, excuses the same change again. Rejected for a once-only entry in a trust-core file.
- **A rank test for field changes, with a `pseudonymous` flag for `identifier` to content.** Two rules and a flag nothing reads, to say what "any change needs an entry" says once. Rejected; a raise now costs an entry.
- **SL12 and the generated-file checks built from the head, with their code trust core.** They would still pass mechanically on the pull request that changes them, and the head's build links code no trust-core line covers. Rejected for the base's build.
- **A hand-written module over generated constants.** A wrapper hands every reader a value the data never held, and no drift check reads it. Rejected for whole generated modules.
- **A bootstrap flag for a base with no data files.** It is honoured on one base and stays in the gate afterwards. Rejected: the gate item lands both files before the lint exists.
- **Confirmation by RFC.** One confirmation would cover every later entry citing that RFC, where D-31 makes a grant exact and single-use. Rejected for one record per entry.
- **SL12 reading the `review` comment through the API.** Under one login (ADR-0035) only a comment's form can be checked, and a comment parser would join the gate. Rejected for the lane's four checks.
- **Field identity by path.** A field at a new path had no floor. Rejected for the message's full name and number, with a retype or move as a removal that names its successor.
- **Foreign imports allowed by path prefix and leaf type.** A look-alike or a shadow under `google/protobuf/` passes. Rejected for SL10's digest list.
- **Each reader parsing `capture.toml` or `fields.json`.** Several parsers that can disagree, and a JSON parser in shipped programs (SD-04, ARCH-004). Rejected for one loader and generated modules.
- **Codec features that may be on together.** Feature unification in an embedder's workspace would link two codecs. Rejected for `compile_error!`.
- **Editions instead of `proto3`.** Both SP-1 candidates would have to generate them, and design/04's rules are written in `proto3` terms. Deferred to an RFC.
- **`prost-reflect` 0.16.5 as the lint's decoder** (MIT OR Apache-2.0, owner `andrewhickman`; `DescriptorPool::decode` keeps extension options; read 2026-11-21 on docs.rs). It works and adds one package. If buffa wins, design/04's first choice, it would keep the prost crates in the lockfile for a tool crate alone, while `buffa-descriptor` costs nothing. It is the decoder an amendment would name (R26).
- **`prost-types` alone.** It drops custom options with every other unknown field, so it cannot read `data_class`. Rejected.
- **Reading option numbers from raw `FieldOptions` bytes in the lint.** A protobuf decoder of our own in a gate, beside the codec (P17). Rejected.
- **Reading options through `grdr-proto`'s generated extension constants.** This ties the lint to the SP-1 outcome and to the numbers #398 moves. Rejected for R6.
- **A third SP-1 candidate.** `protobuf` 3.7.2 (MIT) has had no release since 2025-03-10, and the crate name now carries the official 4.x line, published as semver pre-releases such as `4.36.2-release` over `google-protobuf`; D-63 admits no pre-release. Design/04 names two candidates. Rejected.
- **`prost-build` with default features.** `format` adds `prettyplease` 0.3 and `syn` 3 to a build script whose output nobody reads. Rejected.
- **Breaking fixtures checked with `--config buf.yaml` from their own directories.** A module-level block in `buf.yaml` would apply to `proto` only, so those runs would not see it. Rejected for R23's fresh copy.
- **Head tree materialised with `git archive` (even with `info/attributes` overrides).** Requires repository attribute overrides and does not verify the tree before extraction. Rejected for running the pre-cargo tree check first and reading regular-file git blob objects by object id.

Sources, all read 2026-11-21: the crates.io API and sparse index for every crate named here; https://docs.rs/buffa-build/0.9.2/buffa_build/struct.Config.html; https://docs.rs/prost-build/0.14.6/prost_build/struct.Config.html; https://docs.rs/buffa/0.9.2/buffa/; https://docs.rs/prost-reflect/0.16.5/prost_reflect/struct.DescriptorPool.html; https://raw.githubusercontent.com/anthropics/buffa/main/README.md; https://raw.githubusercontent.com/tokio-rs/prost/master/README.md; https://api.github.com/repos/tokio-rs/prost/issues/2; https://buf.build/docs/configuration/v2/buf-yaml/; the published source of `buffa-descriptor` 0.9.2 (`src/pool.rs`, `src/reflect/dynamic.rs`).

## Drawbacks
- A spike locks 63 packages, which stay until the adopting item removes the losing codec's crates.
- buffa is pre-1.0, and one crates.io account owns six of the crates. The lint depends on it even if prost wins, unless an amendment moves it. If buffa wins, the gate's decoder and the codec generator share one crate, so a decoding defect is common to both; the comparison with `buf`'s JSON rendering (section 8) is the independent reading.
- The option numbers stay in the in-house range until a third party grants a registered one (#398).
- An entry needs an RFC, a seat's review, the full lane and, before devices apply it, each organisation's confirmation. A raise needs one too. A retired option keeps its declaration, and a removed field's number never returns.
- SL12 checks an entry's RFC line, its RFC's state and its key, not that the RFC decided the change or that the review supports it. The lane's four checks hold those, and every comment and verdict is made under one login (ADR-0035).
- A genuinely new field gets its class from review, the release note and the pending diff, and from the privacy canary once #493 exists. Whether a device should hold one until confirmed is open (Unresolved question 4).
- Eighteen trust-core lines (plus `<dir>/**` for each workspace `proc-macro` package, matched ignoring case). The `lib.rs` and manifest of `grdr-schema` and of `grdr-model`, `**/build.rs`, and `schema/codes/model.toml` are among them, so a change that only adds a module, a dependency or a code to either crate takes the full lane. A moved manifest or library root or a build script fails `manifests`. A `#[path]` or `cfg_attr` attribute, a macro or another module declared in either crate's `lib.rs` could still stand in for a generated module or the filter, and could do so in release builds only. No byte check sees that, so the lane's `lib.rs` check (#1880) holds it.
- Putting `**/build.rs`, every workspace `proc-macro` `<dir>/**`, `**/.cargo/**`, `**/.gitattributes` and `**/.gitmodules` on `security/trust-core.paths` (#1955 Option A) sends every workspace build-script, proc-macro, Cargo-config and gitattribute/submodule change through the full lane, and `manifests` reads every workspace manifest; even so, a `build.rs` or proc macro in another workspace crate that writes a generated module or filter file on disk during a build (including in release builds only) is held by that trust-core lane rather than `manifests` or committed-file byte checks alone, while third-party `Cargo.lock` build-time code stays outside `security/trust-core.paths` under ADR-0043 (`5df7b36`) and is held by `cargo-deny`, `osv-scanner`, section 8's `Cargo.lock == supply-chain/admissions.toml` check and `#1910`'s post-cargo clean-tree check, both explicit required protections before release-build reliance, leaving an interim residual until those two checks land on `main`.
- A change to a generator, a check, a path the job reads or an outright failure takes two pull requests. Between a generator change and the regeneration, every other pull request fails the `schema-gate` job.
- The negative controls need a fresh copy of the checkout per case.

## Unresolved questions
1. **The registered extension range.** It waits on the protobuf global extension registry (#398, #17-E3). Until then a pool that merges an embedder's set with ours can meet one of our five numbers twice if the embedder used it; Surfaces changed tells embedders to keep clear of them, and a later option takes a new in-house number by RFC.
2. **If prost wins SP-1.** An amendment of this RFC may move the lint to `prost-reflect` (R26).
3. **Map order.** `buffa`'s default map type is a hash map, so two encodings of one map need not match byte for byte. The schema allows one map, `native` (design/04 section 1 rule 4), and SP-1's schema has none. Integrity hashes the bytes as first encoded and nothing re-encodes before verifying (rule 8). #368's lead decides whether SP-1 adds a `native`-shaped case.
4. **For `product-lead`: new fields on deployed devices.** Should the 04-16 filter hold a field added after an organisation's last confirmation until that organisation confirms it? The release note and the pending diff list such a field either way (R17c), and #1878 records the answer in design/29.
5. **Left to #18's RFC** (R14): `encoding`, the digest labels, the class of a namespace message-typed field and how SL12 compares one, the principal marker, the evidence-span and content-grant routes with their entry kind, and partner packages with classes of their own.
6. **Left to the freeze RFC** (04-29): how a field in `v1` names its predecessor, a second options file, and whether `reclassifications.toml` is compacted.
7. **Not checked here.**
   - The pinned `buf`: no pin exists yet (#1697). `buf` 1.67.0 built section 1's layout, ran R23's cases and rendered extension options by full name in its JSON output; #353 AC-1, the gate item's criteria and the lint item's first run are the first runs at the pin.
   - The pinned cargo-deny 0.22.0; 0.21.0 ran.
   - Either codec's behaviour, which is SP-1's job.
   - `buffa-descriptor`'s reading of custom options was read in its published source, not run.
   - `schema-gate`'s git object extraction, pre-cargo tree check (`check_tree.py`, #1955), outside-tree `cargo metadata`, `manifests` over every workspace package, section 8's `Cargo.lock == supply-chain/admissions.toml` check and `#1910`'s post-cargo clean-tree check: `#1923`/`#1975` has landed `.github/actions/tree-paths/` on `main`, while `#1955`, the lint item, `#1843`, the lockfile-admissions check and `#1910` remain to land (the lockfile-admissions check and `#1910` are required before release-build reliance, leaving an interim residual on third-party `Cargo.lock` build-time code and post-build writes until they land, and RFC publication waits on `#1955`).

## Review
Round 8 is a delta review of this revision's changes only (the `manifests` exit-1 vs exit-2 rule for `--crate` and `manifests::decoy_crate_path`, and reconciling `security/trust-core.paths` and third-party `Cargo.lock` build-time protections with ADR-0043 `5df7b36`, `#1955` Option A, section 8's `Cargo.lock == supply-chain/admissions.toml` check and `#1910`) by `eval-review` and `eval-security` on two distinct models (ADR-0043); if both pass, the RFC is still held from publication until `#1955` (the remaining gate work of `#1923` after `#1975` merged) lands on `main`. Each puts one comment on #1848 that opens with three role lines, then the other blobs it read:
- `RFC file: <blob of rfcs/0006-grdr-common-v1alpha1-options-and-sp1-crates.md at the commit reviewed>`;
- `Proposed text: none`;
- `Base: a80859235e7a2a4444648d6fa8d389d78dde6be9`, the spine pin;
- `read=<path>@<blob>` for every other file it relied on.

A comment without these lines does not count. This RFC changes no pinned path, so its decision has no RFC 0001 decision line (ADR-0036). The decided file may differ from the reviewed blob only where RFC 0001's "Review binds the decision" allows. Earlier rounds' verdicts and seat comments, and where each finding went, are on #1848; the deciding round's are linked here when the RFC is decided.

This text was written against these blobs, on `main` unless named:
- `docs/design/00-decisions.md`: `a80859235e7a2a4444648d6fa8d389d78dde6be9`;
- `docs/design/04-event-model-and-schemas.md`: `e77880a12d2f42e715836a6da9598b86f33b20b0`;
- `docs/design/16-data-protection.md`: `2a1b57f0a0979d5ff0d5df9760db50d24b336bc3`;
- `docs/design/26-embedding-oem-and-white-label.md`: `8d9327dce0ca530e065f06a8ed287dec664e1f5b`;
- `docs/design/29-compliance-and-privacy.md`: `dc26184909208f3d50ac670158cc505efad3e003`;
- `docs/design/36-legal-brand-and-commercial.md`: `dfcb5df2a9be6f5d58719919f17e32057301da47`;
- `rfcs/0001-adopt-the-spine.md`: `353436cd2f9cff08037783ca66678c52cd7d6be4`;
- `rfcs/0004-c-header-generation-and-drift-check.md`: `1f998f42db6c6ea6640c55df0a655e450759340f`;
- `security/trust-core.paths`: `1577f6c967b91ce762681f61eca5bd9afbcd5538` (post-ADR-0043 `origin/main` `5df7b36`, plus `#1955` Option A);
- `architecture.toml`: `9bbac9570131a6dddeed5f3c749eb1aac599c554`;
- `brand/brand.toml`: `a32c7cfbf0c9197a8464581483546e74f08c545b`;
- `supply-chain/licences.toml`: `65338a382a81c1ac500c533e22fa6ee22397928d`;
- `supply-chain/admissions.toml`: `1b25c164ade9d313e80bd6286444e289062d7f1f`;
- `deny.toml`: `2d0457ff71ea5c9bba91de0a580cd80f650d1479`;
- ADR-0007: `5b6cdffc1648817f3e48a821ef2b34383b24b8f1`;
- ADR-0020: `e0a2998b7baed6c2aa21629ce25d61f2fa12ad20`.

## Decision
Not decided.
