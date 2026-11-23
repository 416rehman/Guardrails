RFC: 0017
Title: grdr-strings public surface, the grdr-messages contract and the ICU4X 2.4 dependency
Author: chief-architect
Harness: antigravity
Model: Gemini 4 Neon
State: Review
Design issue: #448
Spine: D-38, D-42, D-44, D-51, D-60, D-61, D-63, D-66, D-69, P7, P8, P14, P16, P17 (no spine text changes)
Surfaces: the public crate `grdr-strings` (layer 2, experimental); the generated crate `grdr-messages` (layer 2, unpublished); the tool crate `grdr-interface-gen` (tool); the features `grdr-strings/pack-text` and `grdr-strings/export` and `ARCH-024` `strings-closure`; the error-code areas `STR`, `MSG` and `IFG` (experimental); eight `strings.*` rows in `limits.toml`; the admitted ICU4X 2.4.0, `icu_experimental` 0.7.0, `zoneinfo64` 0.3.0 and companion crates; the `grdr:class` MF2 attribute and `notify.*` / `email.*` data-class gate. As proposals: `architecture.toml`, `surfaces.toml`, `schema/codes/areas.toml`, `limits.toml`, `supply-chain/admissions.toml`, `security/trust-core.paths`, design/03 section 2 and ARCH-024, design/28 section 13, design/34 section 15a, the three crate `AGENTS.md` files, and constraint write-backs on #449, #1612, #1613, #1614, #1615, #1616, #1618, #1384 and #1853
Decision record: none yet

To comment, write on issue #448 of this repository; you need no account on any service other than the code host. A security fix under embargo (D-62) may change a public surface without an RFC; open a retroactive RFC when the fix is disclosed.

This is revision 2. It resolves round 1 findings from `eval-review` and `eval-security` on PR #2050 (commit `3f37c59`): runtime `MessageDomain` and `.local` taint enforcement in `MessageTemplate` and `CompiledPackMessage`, refusal of `DataClass` downgrades, embedded bidi/C0/ANSI control rejection and universal `FSI`/`PDI` isolation, terminal `Strip` fallback to English (`en`), redacting `Debug` implementations, `limits.toml` resource bounds (`ARCH-019`), `export` / `from_boxed_blobs` gating, 3-day/7-day dependency cooldown rules, `MessageError` code delegation, lowercase `code.<area>_<nnnn>.*` parity IDs and unique `IFG` error reasons.

## Summary
This RFC defines the language-token runtime contract across `grdr-strings`, `grdr-messages` and `grdr-interface-gen` under D-69 and [WI-0041](../docs/design/03-system-architecture-and-modularity.md#L518), and admits the ICU4X 2.4 dependency closure that backs it:
1. **`grdr-strings` public surface (R1).** A pure, no-I/O, no-clock, `#![forbid(unsafe_code)]`, `wasm32-unknown-unknown`-compatible layer 2 crate exposing: Unicode MessageFormat 2 (LDML Part 9, CLDR 49) parsing and compilation bounded by `limits.toml` (`ARCH-019`); the closed function registry (`:number`, `:integer`, `:datetime`, `:unit`, `:grdr:relative`, `:grdr:duration`, `:grdr:list`, `:grdr:brand`, `:grdr:term`); typed `MessageRef` and argument values with redacting `Debug` bound to `DataClass`; RFC 4647 locale negotiation; CLDR-derived direction and script tables; control-character rejection (`GRDR-STR-0010`), universal bidi placeholder isolation (`FSI`/`PDI`) across every locale and identifier isolation (`LRI`/`PDI` with ASCII digits); terminal `Strip` fallback to `en`; grapheme counting (`grapheme_count`); and deterministic pseudo-locale transforms (`en-XA`, `ar-XB`, `ja-XC`).
2. **`grdr-messages` contract and static bundle layout (R2).** A layer 2 unpublished crate generated deterministically by `grdr-interface-gen` under `crates/grdr-messages/src/generated/`, holding one typed Rust accessor and `_ref` builder per token, typed `Present` / `Presentation` accessors over `interface/presentation.toml`, `RouteId` and `NotificationKindId` constants, `MessageError` delegating wrapped `StringError` codes verbatim, and a statically embedded Postcard CLDR-49 data blob (`include_bytes!`) plus aligned `[u32; N]` TZDB table for the `shipped` locales of `locales.toml`. Using `BlobDataProvider::try_new_from_static_blob` inside `grdr-strings` instead of `icu_provider_baked` code generation avoids `unsafe` (`VarZeroSlice::from_bytes_unchecked`) under `[workspace.lints.rust] unsafe_code = "forbid"` and avoids any `icu*` import inside `grdr-messages`. Missing tokens, missing arguments or mistyped arguments fail `cargo check`.
3. **Features `pack-text` and `export` and `ARCH-024` `strings-closure` (R3).** Only `grdr-strings` declares `icu*` dependencies. `pack-text` gates compiled pack message evaluation (`CompiledPackMessage`), is never a default feature, and is enabled only in `grdr-engine`, `grdr-server` and `grdr`. Privileged programs (`grdr-daemon`, `grdr-updater`, `grdr-approve`) never enable `pack-text` or call dynamic blob loaders, and `grdr-hook` links neither `grdr-strings` nor `grdr-messages`. Feature `export` (`icu_provider_export`) is permitted only in tool crate `grdr-interface-gen` and `grdr-strings` tests.
4. **Admitted ICU4X 2.4 crates (R4).** Exact pinned crates at the `2.4.0` line (with `icu_experimental = "=0.7.0"`, `zoneinfo64 = "=0.3.0"`, `fixed_decimal = "=0.7.3"`, `writeable = "=0.6.4"`, and `postcard = "=1.1.3"`), every crate under `Unicode-3.0` or `MIT OR Apache-2.0` (`supply-chain/licences.toml` permissive class), with `compiled_data` excluded from runtime binaries and full `wasm32-unknown-unknown` support.
5. **`grdr:class` enforcement (R5).** Both `MessageTemplate` and `CompiledPackMessage` carry `MessageId` and `MessageDomain`, re-validate AST/data-class invariants at parse and `from_compiled_bytes` deserialisation, propagate `DataClass` taint upward through `.local` chains, refuse sensitivity downgrades (`NamedArg::class() < ArgDecl.class` or inline `grdr:class < decl.class`), and default unclassified standalone dynamic arguments fail-closed to `content`. Any `notify.*`, `email.*`, or pack notification template carrying a `content`-class argument fails `grdr-interface-gen check`, fails `from_compiled_bytes` (`GRDR-STR-0007`), and fails at format time (`StringError::DisallowedDataClass`).

## Motivation
- `#449` cannot add `grdr-strings`, `grdr-messages` and `grdr-interface-gen` to `Cargo.toml`, `architecture.toml` and `Cargo.lock` until an accepted RFC fixes the public surface of `grdr-strings`, the contract of `grdr-messages`, and the exact ICU4X 2.4 dependency list (`D-61`, `D-63`).
- `#1612` (`grdr-strings`), `#1613` (`grdr-interface-gen`), `#1614` (the token tree), `#1615` (`grdr-messages`), `#1616` (`@grdr/i18n`), `#1618` (presentation registry), `#1384` (`agent.*` block tokens) and `#1853` (`code.*` parity checks) are blocked on this contract.
- A straightforward reading of [design/28](../docs/design/28-desktop-and-developer-experience.md) ("ICU4X 2.4 with baked data") risks generating Rust code via `icu_provider_baked`, which emits `unsafe` constructors that violate `[workspace.lints.rust] unsafe_code = "forbid"` and introduces `icu_provider` imports outside `grdr-strings` in violation of `ARCH-024`. Resolving the static Postcard blob layout up front prevents a rework across `#449`, `#1613` and `#1615`.
- `design/34` section 15a requires UTC timestamps (`grdr_model::Timestamp`, `0001-01-01..=9999-12-31`) to render in any viewer's time zone while `grdr-strings` does no I/O and reads no clock. Explicit TZDB resolution and boundary handling across `Timestamp::MIN..=Timestamp::MAX` must be settled before implementation.

## Design

### 1. Crate placement, dependencies and layer rules
The three crates of [design/03](../docs/design/03-system-architecture-and-modularity.md) section 2 fit the workspace layer rules as follows:

| Crate | Layer | Surface | Privilege | Renders | Normal workspace dependencies |
|---|---|---|---|---|---|
| `grdr-strings` | `2` | `public` | `none` | `none` | `grdr-schema`, `grdr-model` |
| `grdr-messages` | `2` | `unpublished` (generated) | `none` | `generated` | `grdr-strings` |
| `grdr-interface-gen` | `tool` | `internal` | `none` | `none` | `grdr-strings` (`export` feature), `grdr-schema`, `grdr-model` |

Each crate's `[package.metadata.grdr]` keys (`layer`, `privilege`, `surface`, `renders`) match [design/03](../docs/design/03-system-architecture-and-modularity.md) section 2 verbatim when `#449` adds the three manifests.

- **R1.1 Dependencies.** `grdr-strings` depends on `grdr-schema` (layer 0: `Code`, `Coded`, `Bytes`, `Millis`, `Count`, `Permille`), `grdr-model` (layer 1: `Timestamp`, `LogSafe`, `LogValue`, `WireName`) and the admitted third-party crates listed in Section 5. `grdr-messages` depends only on `grdr-strings` via the listed same-layer edge in `architecture.toml`, plus `grdr-interface-gen` (a `tool` crate, permitted as a dev-dependency under `ARCH-001`) and `#1615`'s compile-fail test harness as dev-dependencies only. `grdr-interface-gen` depends on `grdr-strings`, `grdr-schema`, `grdr-model`, the workspace TOML and JSON readers already queued in `supply-chain/admissions.toml` (`toml`, `serde`, `serde_json` from `#1575`), and the JSON Schema validator tracked by `#1886` when admitted.
- **R1.2 Layer 2 purity.** `grdr-strings` performs no filesystem, network, process, environment-variable, system-clock or entropy I/O (`ARCH-003`). Callers pass explicit `Timestamp`, `ViewerTimeZone`, `LocaleBundle`, `BrandContext`, `TermTable` and locale candidate slices.
- **R1.3 Build and safety invariants.** Both `grdr-strings` and `grdr-messages` inherit `[lints] workspace = true` (`unsafe_code = "forbid"` and all workspace Clippy panic-path lints) and declare `#![deny(clippy::arithmetic_side_effects)]` at the crate root. No non-test code may panic (`unwrap`, `expect`, `panic!`, `todo!`, `unimplemented!`, `unreachable!`, slice indexing, string slicing). All arithmetic uses checked or saturating operations.
- **R1.4 `wasm32` target.** `grdr-strings` and `grdr-messages` compile cleanly for `wasm32-unknown-unknown` with default features. Tool feature `grdr-strings/export` is never enabled on `wasm32` or in runtime binaries.
- **R1.5 Single path per public item.** All normative public types, enums, traits and free functions of `grdr-strings` are exported at the crate root (`grdr_strings::*`), keeping internal module splits private (following RFC 0009 R3).
- **R1.6 Resource bounds (`ARCH-019`, `design/03` §10).** Every parser, AST, expansion, pack-blob and output bound comes from `limits.toml` through `grdr_schema::limits` generated constants rather than literal numbers in product code. Any input or pack payload exceeding a bound returns `StringError::ResourceBoundExceeded` (`GRDR-STR-0012`) or `PackBlobInvalid` (`GRDR-STR-0008`).

| `limits.toml` bound key | Unit | Value | Range (`min..=max`) | Scope | Effect | Owner |
|---|---|---|---|---|---|---|
| `strings.template-max` | `bytes` | `16384` | `1024..=65536` | `fixed` | `none` | `design/34` |
| `strings.ast-nodes-max` | `count` | `512` | `32..=4096` | `fixed` | `none` | `design/34` |
| `strings.local-depth-max` | `count` | `8` | `1..=32` | `fixed` | `none` | `design/34` |
| `strings.match-branches-max` | `count` | `64` | `8..=256` | `fixed` | `none` | `design/34` |
| `strings.pack-blob-max` | `bytes` | `65536` | `1024..=262144` | `fixed` | `none` | `design/12` |
| `strings.list-items-max` | `count` | `64` | `4..=256` | `fixed` | `none` | `design/34` |
| `strings.pseudo-expansion-added` | `permille` | `400` | `200..=1000` | `fixed` | `none` | `design/34` |
| `strings.agent-block-chars-max` | `count` | `600` | `200..=1200` | `fixed` | `none` | `design/28` |

### 2. `grdr-strings` public Rust surface (R1)
Every error enum is `#[non_exhaustive]` and implements `grdr_schema::codes::Coded` and `grdr_model::LogSafe`. Error fields hold structural metadata only (`MessageId`, slot name, `DataClass`, line/column, bound key), never untrusted source or argument string bytes. Neither `MessageRef`, `ArgValue`, `NamedArg`, `MessageArgs`, nor any formatted output implements `grdr_model::LogSafe` (P8). Types that can hold `Content` or `Identifier` values implement a manual redacting `Debug` printing variant names, field counts and byte lengths only, never inner text bytes (RFC 0005 R1.7). Formatted human text is returned only from explicit formatting functions, never through `Display` on tokens or arguments (`renders = "none"` discipline matching RFC 0007 and RFC 0009).

#### 2.1 Data classes, `MessageRef` and typed arguments
```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DataClass {
    Identifier,
    Structural,
    Derived,
    Content,
}
impl DataClass {
    pub const VARIANTS: &'static [DataClass];
    pub const fn as_str(self) -> &'static str; // "identifier", "structural", "derived", "content"
    pub fn from_attr(value: &str) -> Result<DataClass, StringError>;
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MessageDomain {
    General,
    Notification,
    Email,
    Code,
    Agent,
    PackNotification,
    PackRule,
}
impl MessageDomain {
    pub fn from_id(id: &MessageId) -> Self; // notify.* -> Notification, email.* -> Email, code.* -> Code, agent.* -> Agent, else General
    pub const fn allows_data_class(self, class: DataClass) -> bool;
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ArgType {
    String,
    Integer,
    Decimal,
    Timestamp,
    RelativeSeconds,
    Duration,
    Bytes,
    Millis,
    Count,
    Permille,
    Code,
    StringList,
    Brand,
    Term,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArgDecl {
    pub name: String,
    pub ty: ArgType,
    pub class: DataClass,
    pub explicit_class: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MessageId(/* validated dotted lower-case identifier e.g. "common.loading" */);
impl MessageId {
    pub const fn of<L: grdr_model::LiteralText>() -> Self; // compile-time checked via inline const
    pub fn parse(raw: &str) -> Result<Self, StringError>;
    pub fn as_str(&self) -> &str;
    pub fn domain(&self) -> MessageDomain;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecimalInput {
    Integer(i128),
    Scaled { mantissa: i128, magnitude_shift: i16 }, // exact base-10 decimal, never binary float formatting drift
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BrandSlot {
    ProductName,
    ShortName,
    VendorName,
    CoBrandDisplayName,
    SupportDomain,
}

#[non_exhaustive]
#[derive(Clone, PartialEq, Eq)] // manual redacting Debug: prints variant and byte/item length only
pub enum ArgValue {
    String(String),
    Integer(i64),
    Decimal(DecimalInput),
    Timestamp(grdr_model::Timestamp),
    RelativeSeconds(i64),
    Duration(core::time::Duration),
    Bytes(grdr_schema::limits::Bytes),
    Millis(grdr_schema::limits::Millis),
    Count(grdr_schema::limits::Count),
    Permille(grdr_schema::limits::Permille),
    Code(grdr_schema::codes::Code),
    StringList(Vec<String>),
    Brand(BrandSlot),
    Term(String),
}
impl ArgValue {
    pub const fn arg_type(&self) -> ArgType;
}

#[derive(Clone, PartialEq, Eq)] // manual redacting Debug: prints slot name, ArgType and DataClass only
pub struct NamedArg { /* private fields: name, value, class */ }
impl NamedArg {
    pub fn name(&self) -> &str;
    pub fn value(&self) -> &ArgValue;
    pub const fn class(&self) -> DataClass;
}

#[derive(Clone, PartialEq, Eq, Default)] // manual redacting Debug: prints arg count, names and DataClass only
pub struct MessageArgs(/* ordered unique map Vec<NamedArg> by name */);
impl MessageArgs {
    pub fn new() -> Self;
    pub fn insert(&mut self, name: impl Into<String>, value: ArgValue, class: DataClass) -> Result<(), StringError>;
    pub fn get(&self, name: &str) -> Option<&NamedArg>;
    pub fn iter(&self) -> core::slice::Iter<'_, NamedArg>;
}

#[derive(Clone, PartialEq, Eq)] // manual redacting Debug: prints id, source_hash, and redacted args summary only
pub struct MessageRef {
    pub id: MessageId,
    pub args: MessageArgs,
    pub source_hash: [u8; 32],
}
impl MessageRef {
    pub fn new(id: MessageId, args: MessageArgs, source_hash: [u8; 32]) -> Self;
    pub fn max_data_class(&self) -> DataClass;
}

#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StringError {
    Syntax { line: usize, column: usize },
    UnknownFunction,
    MissingOrWrongArg { name: String, expected: Option<ArgType> },
    LocaleUnknown,
    MissingReferenceTime,
    InvalidDataClassAttr,
    DisallowedDataClass { id: MessageId, arg: String, class: DataClass },
    PackBlobInvalid,
    BundleData,
    UnsafeControlChar { arg: Option<String> },
    UnsupportedBidiStrip,
    ResourceBoundExceeded { bound: &'static str },
}
// StringError implements std::fmt::Display, std::error::Error,
// grdr_schema::codes::Coded (GRDR-STR-0001..0012), and grdr_model::LogSafe (as LogValue::Code).
```
Notes:
- `DataClass` mirrors `docs/design/04` section 1 and `grdr.common.v1alpha1.DataClass` (`Identifier < Structural < Derived < Content`). Once RFC 0006 lands, `grdr-schema` or `grdr-proto` maps cleanly onto these four variants.
- `DecimalInput` avoids IEEE-754 floating-point precision drift across `grdr-strings` (ICU4X `FixedDecimal`) and `@grdr/i18n` (`Intl.NumberFormat`), allowing parity vectors to compare byte-for-byte.
- `MessageRef` stores the source token's SHA-256 digest (`source_hash`) as fixed `[u8; 32]` so audit/receipt readers detect when a stored `MessageRef` predates a source template revision without storing raw rendered text ([design/04](../docs/design/04-event-model-and-schemas.md)).

#### 2.2 MF2 parsing, template representation and function registry
```rust
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Mf2Function {
    Number,
    Integer,
    DateTime,
    Unit,
    GrdrRelative,
    GrdrDuration,
    GrdrList,
    GrdrBrand,
    GrdrTerm,
}
impl Mf2Function {
    pub const REGISTRY: &'static [Mf2Function];
    pub fn from_name(name: &str) -> Result<Self, StringError>;
    pub const fn as_str(self) -> &'static str;
    pub const fn supports_selection(self) -> bool;
    pub const fn supports_formatting(self) -> bool;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageTemplate { /* private: MessageId, MessageDomain, parsed LDML Part 9 AST, declared ArgDecl table, source hash */ }
impl MessageTemplate {
    pub fn parse(id: MessageId, domain: MessageDomain, source: &str, declared: &[ArgDecl]) -> Result<Self, StringError>;
    pub fn parse_infer(id: MessageId, source: &str) -> Result<Self, StringError>;
    pub fn id(&self) -> &MessageId;
    pub fn domain(&self) -> MessageDomain;
    pub fn declared_args(&self) -> &[ArgDecl];
    pub fn required_functions(&self) -> &[Mf2Function];
    pub fn source_hash(&self) -> [u8; 32];
}

pub fn format_template(
    template: &MessageTemplate,
    args: &MessageArgs,
    locale: &LocaleTag,
    ctx: &FormatContext<'_>,
) -> Result<String, StringError>;

pub fn format_utc_iso8601(ts: grdr_model::Timestamp) -> String; // UTC tooltip / technical detail (design/27 section 11)

#[cfg(feature = "pack-text")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledPackMessage { /* private: MessageId, MessageDomain (PackNotification | PackRule), declared args, validated AST */ }
#[cfg(feature = "pack-text")]
impl CompiledPackMessage {
    pub fn from_compiled_bytes(bytes: &[u8]) -> Result<Self, StringError>;
    pub fn id(&self) -> &MessageId;
    pub fn domain(&self) -> MessageDomain;
    pub fn declared_args(&self) -> &[ArgDecl];
    pub fn format(&self, args: &MessageArgs, locale: &LocaleTag, ctx: &FormatContext<'_>) -> Result<String, StringError>;
}
```
Supported Unicode MessageFormat 2 (LDML Part 9, CLDR 49) syntax, closed registry and validation rules:
- **Syntax scope and DoS bounds:** Quoted and unquoted pattern text, placeholders `{...}`, `.input` and `.local` variable declarations (`name = expression`), `.match $sel1 [$sel2 ...]` selector statements with literal keys (`|...|` or bare name token), CLDR plural category keys (`zero`, `one`, `two`, `few`, `many`, `other`) and wildcard fallback `*`, variable attributes `grdr:class=<class>`, and standard MF2 escapes (`\\`, `\{`, `\}`, `\|`). Nested `.match` is rejected (`GRDR-STR-0001`). Exhaustiveness requires a `*` fallback branch on every `.match` (`GRDR-STR-0001`). Every parse and deserialisation rejects inputs exceeding `limits.toml` bounds (`strings.template-max`, `strings.ast-nodes-max`, `strings.local-depth-max`, `strings.match-branches-max`, `strings.pack-blob-max`, `strings.list-items-max`) with `StringError::ResourceBoundExceeded` (`GRDR-STR-0012`) or `PackBlobInvalid` (`GRDR-STR-0008`).
- **Unknown function rejection:** Any `:fn` name outside `Mf2Function::REGISTRY` plus bare variable / `:string` exact-match selector syntax fails `MessageTemplate::parse` and `CompiledPackMessage::from_compiled_bytes` with `StringError::UnknownFunction` (`GRDR-STR-0002`, `#1612` R2).
- **`.local` taint propagation and `DataClass` enforcement (`P8`, `ADV-8`):**
  1. `MessageTemplate::parse` rejects any inline `grdr:class` annotation strictly lower than `declared` (`attr < decl.class`) with `DisallowedDataClass` (`GRDR-STR-0007`), preserving `max(attr, decl.class)`.
  2. Each `.local` binding computes its effective `DataClass` as the maximum `DataClass` across all variables and nested expressions on its right-hand side (`:grdr:brand` and `:grdr:term` fixed at `Structural`). Any inline `grdr:class` annotation on a `.local` lower than the inferred expression class is rejected (`GRDR-STR-0007`); taint propagates across `.local` chains up to `strings.local-depth-max`.
  3. `CompiledPackMessage::from_compiled_bytes` never trusts pre-compiled pack assertions blindly: it re-validates size and AST bounds, closed functions, non-nested `*`-terminated `.match` nodes, `.local` taint, `domain.allows_data_class(...)` over all `ArgDecl`s, and checks literal runs for URLs (`http://`, `https://`, scheme `://`), Markdown/markup syntax and embedded bidi/control characters (`GRDR-STR-0007`, `0008`, `0010`, `0012`).
  4. At format time (`format_template`, `CompiledPackMessage::format`, `render_ref`), each `NamedArg` is checked against its `ArgDecl`: if `arg.class() < decl.class`, formatting refuses the downgrade (`GRDR-STR-0007`), and `effective_class = decl.class.max(arg.class())` is checked against `template.domain().allows_data_class(effective_class)`, returning `Err(StringError::DisallowedDataClass { id, arg, class })` on violation.
- **Exact function contracts (`#448` R1):**

| Function | Accepted `ArgValue` kinds | Role | Options supported | ICU4X 2.4 / companion backing |
|---|---|---|---|---|
| `:number` | `Integer`, `Decimal`, `Count`, `Bytes`, `Millis`, `Permille` | Format & Select | `minimumFractionDigits`, `maximumFractionDigits`, `useGrouping` (`true\|false\|auto`), `notation` (`standard\|compact`), `compactDisplay` (`short\|long`), `numberingSystem` (`latn` etc.) | `icu_decimal::DecimalFormatter`, `icu_plurals::PluralRules` |
| `:integer` | `Integer`, `Count`, `Bytes`, `Millis`, `Permille` | Format & Select | `useGrouping`, `numberingSystem` | `icu_decimal::DecimalFormatter`, `icu_plurals::PluralRules` |
| `:datetime` | `Timestamp` | Format | `dateStyle` (`short\|medium\|long\|full`), `timeStyle` (`short\|medium\|long\|full`), `hourCycle` (`h12\|h23`), `timeZone` (`viewer\|utc`), `displaySeconds` (`true\|false`) | `icu_calendar`, `icu_time`, `icu_datetime::DateTimeFormatter`, `zoneinfo64` |
| `:unit` | `Bytes`, `Millis`, `Count`, `Permille`, `Integer`, `Decimal` | Format & Select | `unit` (`byte\|kibibyte\|mibibyte\|gibibyte\|millisecond\|second\|minute\|hour\|percent\|permille`), `unitDisplay` (`long\|short\|narrow`) | `icu_experimental::units::CategorizedUnitsFormatter` (`0.7.0`), `icu_plurals::PluralRules` |
| `:grdr:relative` | `RelativeSeconds`, `Timestamp` (vs `ctx.reference_now`) | Format | `unit` (`auto\|second\|minute\|hour\|day\|week\|month\|year`), `numeric` (`auto\|always`), `style` (`long\|short\|narrow`) | `icu_experimental::relativetime::RelativeTimeFormatter` (`0.7.0`) |
| `:grdr:duration` | `Duration`, `Millis` | Format | `style` (`long\|short\|narrow\|digital`) | `icu_experimental::duration::DurationFormatter` (`0.7.0`) |
| `:grdr:list` | `StringList` | Format | `type` (`conjunction\|disjunction\|unit`), `style` (`long\|short\|narrow`) | `icu_list::ListFormatter` |
| `:grdr:brand` | `Brand` | Format | `slot` (defaults to argument `BrandSlot`) | Resolved directly from `FormatContext.brand` (`brand/brand.toml`, D-66) |
| `:grdr:term` | `Term` | Format | `form` (`singular\|plural`, defaults `singular`) | Resolved from `FormatContext.terms` (`schema/vocabulary.toml`, P17) |

Unit semantics and RFC 0007 alignment:
- `:number` and `:integer` format `Bytes` (underlying `u64` byte count), `Millis` (underlying `u64` ms), `Count` (underlying `u64`), and `Permille` (scaled as whole permille or `percent` when `unit=percent` converts `n / 10.0` cleanly using `DecimalInput`). `:unit` maps `unit=byte` with automatic IEC binary scaling option `scale=binary` (`B`, `KiB`, `MiB`, `GiB`) or exact `unit` selection cleanly via `CategorizedUnitsFormatter`.
- `:datetime` receives `grdr_model::Timestamp` (`MIN` = `0001-01-01T00:00:00Z`, `MAX` = `9999-12-31T23:59:59.999999999Z`). To satisfy RFC 0009's boundary invariant (`Timestamp::MIN` and `Timestamp::MAX` passing through `:datetime` in `en`, `ar`, `ja`):
  1. When `ViewerTimeZone::Iana` shifts `Timestamp` into local civil coordinates, `zoneinfo64` computes the exact historical or proleptic rule offset in memory from the aligned `[u32; N]` TZDB table (with `ViewerTimeZone::Utc` using zero offset and `ViewerTimeZone::Fixed` using the caller's offset in seconds).
  2. Shifted civil years at boundaries (such as `Timestamp::MAX` shifted `+09:00` in `Asia/Tokyo` to ISO year `10000`, or `Timestamp::MIN` shifted `-05:00` to year `0`) exceed `icu_calendar::Date::try_new_iso`'s `-9999..=9999` check; `grdr-strings` constructs those dates with `icu_calendar::Date::try_from_fields` (`-999_999..=999_999` range) and formats with Gregorian fallback if a non-Gregorian era table (e.g. `ja-u-ca-japanese`) cannot represent an extreme epoch boundary, so `:datetime` never fails or panics on `Timestamp::MIN..=Timestamp::MAX`.
- `:grdr:relative` accepts `RelativeSeconds(i64)` directly or computes `(ts - reference_now)` only when the caller explicitly passes `reference_now: Some(Timestamp)` in `FormatContext` (`ARCH-003`: `grdr-strings` never reads a clock). Calling `:grdr:relative` on a `Timestamp` with `reference_now: None` returns `StringError::MissingReferenceTime` (`GRDR-STR-0005`).

#### 2.3 Locale bundle, negotiation, direction and script tables
```rust
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LocaleTag(/* canonicalised BCP-47 string, e.g. "en", "de", "ja", "ar", "en-XA", "ar-XB", "ja-XC" */);
impl LocaleTag {
    pub fn parse(raw: &str) -> Result<Self, StringError>;
    pub fn as_str(&self) -> &str;
    pub fn is_pseudo(&self) -> bool;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LocaleTier {
    Source,
    Shipped,
    Preview,
    Pseudo,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Direction {
    Ltr,
    Rtl,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocaleEntry {
    pub tag: LocaleTag,
    pub tier: LocaleTier,
    pub direction: Direction,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ScriptTag {
    Latn, Cyrl, Grek, Arab, Hebr, Hans, Hant, Jpan, Kore, Thai, Deva,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum BidiIsolation {
    #[default]
    Isolate, // Unicode FSI/PDI and LRI/PDI isolates for GUI, web, notifications and bidi-capable terminals
    Strip,   // Plain terminal fallback when GRDR_TERMINAL_BIDI is disabled (LTR locales only; RTL falls back to en)
}

#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ViewerTimeZone {
    Utc,
    Fixed { offset_seconds: i32, iana_id: Option<String> },
    Iana(String),
}

pub struct LocaleBundle { /* Arc-backed BlobDataProvider + LocaleFallbackProvider + ZoneInfo64 */ }
impl LocaleBundle {
    pub fn from_static_blobs(cldr_postcard: &'static [u8], zoneinfo_u32: &'static [u32]) -> Result<Self, StringError>;
    #[cfg(any(feature = "pack-text", feature = "export", test))]
    pub fn from_boxed_blobs(cldr_postcard: Box<[u8]>, zoneinfo_u32: Box<[u32]>) -> Result<Self, StringError>;
    pub fn direction(&self, locale: &LocaleTag) -> Direction;
    pub fn script(&self, locale: &LocaleTag) -> Result<ScriptTag, StringError>;
    pub fn grapheme_count(&self, text: &str) -> usize;
    pub fn wrap_lines(&self, text: &str, max_columns: usize) -> Vec<String>;
}

pub fn negotiate_locale(candidates: &[&str], catalogue: &[LocaleEntry]) -> LocaleTag;
pub fn resolve_output_locale(requested: &LocaleTag, bundle: &LocaleBundle, bidi: BidiIsolation) -> LocaleTag;
pub fn normalise_nfc(text: &str, bundle: &LocaleBundle) -> Result<String, StringError>;

pub struct BrandContext {
    pub product_name: String,
    pub short_name: String,
    pub vendor_name: String,
    pub co_brand_display_name: Option<String>,
    pub support_domain: String,
}

pub struct TermTable { /* locale -> term key -> singular/plural string loaded from term.* catalogue */ }

pub struct FormatContext<'a> {
    pub bundle: &'a LocaleBundle,
    pub brand: &'a BrandContext,
    pub terms: &'a TermTable,
    pub time_zone: ViewerTimeZone,
    pub reference_now: Option<grdr_model::Timestamp>,
    pub bidi: BidiIsolation,
}
```
Negotiation and direction rules:
- `negotiate_locale(candidates: &[&str], catalogue: &[LocaleEntry]) -> LocaleTag` implements RFC 4647 Lookup with CLDR likely-subtag expansion (`icu_locale::LocaleCanonicalizer`, `icu_locale_fallback::LocaleFallbacker`), accepting pre-read candidate slices in precedence order `[--lang, GRDR_LANG, ui.locale, LC_ALL, LC_MESSAGES, LANG]` ([design/28](../docs/design/28-desktop-and-developer-experience.md) section 10), mapping POSIX `"C"` / `"POSIX"` (with optional `.UTF-8`) to `"en"`, stripping encoding suffixes (`en_US.UTF-8` -> `en-US`), matching pseudo-locales explicitly (`en-XA`, `ar-XB`, `ja-XC`) without stripping private-use/variant subtags, and falling back to `"en"`.
- `LocaleBundle::direction` reads CLDR 49 character/layout directionality via `icu_locale::LocaleDirectionality::try_new_with_buffer_provider` (`ar`, `he`, `fa`, `ur` -> `Direction::Rtl`; `"ar-XB"` -> `Direction::Rtl`; `"en-XA"` and `"ja-XC"` -> `Direction::Ltr`).
- `LocaleBundle::script` maps locales onto the eleven typography script token families of [design/27](../docs/design/27-web-console-ux.md) section 10 (`latn`, `cyrl`, `grek`, `arab`, `hebr`, `hans`, `hant`, `jpan`, `kore`, `thai`, `deva`) via `icu_locale::LocaleExpander`.
- `LocaleBundle::grapheme_count` counts UAX #29 extended grapheme clusters using `icu_segmenter::GraphemeClusterSegmenter::try_new_with_buffer_provider` (no LSTM weights needed), providing one shared definition for token `max` enforcement (`#1612` R4).

#### 2.4 Placeholder isolation, control rejection, identifiers and Unicode normalisation
- **Control and bidi-override rejection (`GRDR-STR-0010`):** Every literal string and dynamic string input (`ArgValue::String`, every element of `ArgValue::StringList`, `ArgValue::Term`, and every `BrandContext` field) is scanned before formatting and inside `MessageTemplate::parse` / `CompiledPackMessage::from_compiled_bytes` for Unicode bidirectional controls (`U+061C`, `U+200E..=U+200F`, `U+202A..=U+202E`, `U+2066..=U+2069`) and C0/C1/ANSI escape controls (`U+0000..=U+001F` excluding `\n` when the slot explicitly permits multi-line prose, plus `U+007F` and `U+0080..=U+009F`). Any match is rejected immediately with `StringError::UnsafeControlChar` (`GRDR-STR-0010`), preventing embedded `PDI` (`U+2069`) from closing an outer isolate early (UAX #9) and preventing ANSI terminal escape injection. `ArgValue::StringList` entries exceeding `strings.list-items-max` fail with `StringError::ResourceBoundExceeded` (`GRDR-STR-0012`).
- **Universal placeholder isolation (`D-69`, `design/34` §15a):** Under `BidiIsolation::Isolate`:
  - Any `DataClass::Identifier` argument (`Code`, ids, paths, hosts, CLI calls, hashes) is formatted left-to-right with ASCII digits (`latn` numbering system regardless of active locale, never through `:number`) and wrapped in Unicode LRI (`U+2066`) .. PDI (`U+2069`) when interpolated into prose (matching [RFC 0007](./0007-grdr-model-and-grdr-schema-slice-0-surface.md#L622)).
  - Every other formatted dynamic placeholder is wrapped unconditionally in Unicode FSI (`U+2068`) .. PDI (`U+2069`) in **every** locale (LTR and RTL alike, implementing D-69's "every placeholder isolated").
  - Under `BidiIsolation::Strip` (for terminals where `GRDR_TERMINAL_BIDI` is disabled per [design/28](../docs/design/28-desktop-and-developer-experience.md) section 10), `resolve_output_locale` falls back to `"en"` whenever the requested locale has `Direction::Rtl`, and `format_template` / `CompiledPackMessage::format` refuse `Direction::Rtl` paired with `BidiIsolation::Strip` (`StringError::UnsupportedBidiStrip`, `GRDR-STR-0011`), ensuring unisolated RTL prose is never emitted; for LTR locales, isolates are omitted cleanly.
- **NFC & safety (`design/34` §15a):** `normalise_nfc(text: &str, bundle: &LocaleBundle) -> Result<String, StringError>` normalises strings via `icu_normalizer::ComposingNormalizer::try_new_with_buffer_provider` and exposes control/bidi/URL character scanners used by `grdr-interface-gen check`.

#### 2.5 Pseudo-locale transforms (`en-XA`, `ar-XB`, `ja-XC`)
```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PseudoLocale {
    EnXa,
    ArXb,
    JaXc,
}
impl PseudoLocale {
    pub fn from_locale(tag: &LocaleTag) -> Option<Self>;
    pub const fn as_str(self) -> &'static str; // "en-XA", "ar-XB", "ja-XC"
}

pub fn format_pseudo_template(
    template: &MessageTemplate,
    args: &MessageArgs,
    pseudo: PseudoLocale,
    ctx: &FormatContext<'_>,
) -> Result<String, StringError>;
```
Deterministic transform rules (`#1612` R3 & AC-2, [design/28](../docs/design/28-desktop-and-developer-experience.md) DX-16, [design/34](../docs/design/34-documentation-support-and-lifecycle.md) §15a):
- Transforms run strictly on literal text segments of the AST **after** variable/function slot boundaries are identified (and skip any code spans `` `...` ``, `:grdr:brand`, `:grdr:term`, `Identifier` values, or tokens marked `translate = false` such as `agent.*`):
  - **`en-XA` (accented expansion):** Replaces ASCII letters in translatable literal spans with deterministic accented Latin equivalents (preserving case), appends deterministic filler padding so transformed literal content expands by at least `strings.pseudo-expansion-added` from `limits.toml` (`400` permille at seed: `graphemes(out_literal) * 1000 >= graphemes(src_literal) * (1000 + added)`), and encloses the complete rendered message in `[` and `]` (for truncation detection).
  - **`ar-XB` (RTL + placeholder isolation):** Marks direction as `Direction::Rtl`, wraps every non-identifier placeholder unconditionally in FSI (`\u{2068}`) .. PDI (`\u{2069}`) and every `Identifier` slot in LRI (`\u{2066}`) .. PDI (`\u{2069}`), prefixes RLM (`\u{200F}`) on RTL literal runs, and applies deterministic Arabic-script / bidi-reordering stress framing without mutating placeholders or code identifiers. Under `BidiIsolation::Strip`, `ar-XB` falls back to `"en"` like any RTL locale.
  - **`ja-XC` (CJK width/script substitution):** Maps every ASCII letter (`A-Z`, `a-z`) inside translatable literal spans to deterministic Japanese Katakana/Kanji substitution characters so **zero ASCII `[A-Za-z]` letters remain** outside placeholders, code spans, `:grdr:brand` and `:grdr:term` spans (`#1612` AC-2).
- `format_template` automatically dispatches to `format_pseudo_template` when `PseudoLocale::from_locale(locale)` is `Some(pseudo)` unless the message is marked non-translatable (`translate = false`), in which case the unmodified English template formats directly (`#1615` AC-3).

### 3. `grdr-messages` contract and static ICU4X bundle layout (R2)
`crates/grdr-messages` is generated deterministically by `grdr-interface-gen generate` from `interface/strings/`, `interface/presentation.toml`, `interface/routes.toml` and `interface/notifications.toml`. Every generated artefact is committed under `crates/grdr-messages/src/generated/` and verified by `cargo test -p grdr-messages drift` (`#1615` R3, AC-2). Hand edits are forbidden, and builds never invoke the generator (`#1615` R1).

#### 3.1 Generated module layout
```text
crates/grdr-messages/
  Cargo.toml              # normal dep: grdr-strings only; dev-deps: grdr-interface-gen, trybuild
  src/
    lib.rs                # thin checked wrapper exposing bundle handle + `pub use generated::*`
    generated/
      mod.rs
      cldr_shipped.postcard   # deterministic Postcard blob of `shipped` locales + `und`
      zoneinfo64_u32.rs       # aligned `pub const ZONEINFO64: &[u32]` from pinned TZDB 2026e
      tokens.rs               # one typed function + `_ref` builder per token, grouped by namespace
      present.rs              # `Present` impls & typed accessors from interface/presentation.toml
      ids.rs                  # `RouteId` and `NotificationKindId` constants
      catalogue.rs            # embedded LocaleEntry list + source English/locale templates
```
Core wrapper types exposed at `grdr_messages` root:
```rust
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MessageError {
    BundleInit { source: grdr_strings::StringError },
    Format { id: grdr_strings::MessageId, source: grdr_strings::StringError },
    UnknownMessageId { id: String },
    DriftDetected { path: String },
}
// Implements std::fmt::Display, std::error::Error, grdr_schema::codes::Coded,
// and grdr_model::LogSafe (as LogValue::Code): BundleInit and Format delegate verbatim
// to `source.code()`; UnknownMessageId maps to GRDR-MSG-0001; DriftDetected maps to GRDR-MSG-0002.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Presentation {
    pub label: String,
    pub why_title: Option<String>,
    pub agent_word: Option<&'static str>,
}

pub trait Present {
    fn present(&self, locale: &grdr_strings::LocaleTag, ctx: &grdr_strings::FormatContext<'_>) -> Result<Presentation, MessageError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RouteId(pub &'static str);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NotificationKindId(pub &'static str);
```
Contract guarantees (`#1615` R2, AC-1, DX-16):
- **Static typing per token:** Every token `<ns>.<key>` becomes a Rust function `grdr_messages::<ns>::<key>(locale: &LocaleTag, ctx: &FormatContext<'_>, <typed_params>) -> Result<String, MessageError>` alongside `grdr_messages::<ns>::<key>_ref(<typed_params>) -> MessageRef` and `grdr_messages::render_ref(&MessageRef, &LocaleTag, &FormatContext<'_>) -> Result<String, MessageError>`. Parameters take concrete Rust types derived from each token's declared `ArgDecl` (`&str`, `i64`, `DecimalInput`, `Timestamp`, `Duration`, `Bytes`, `Millis`, `Count`, `Permille`, `Code`, `&[&str]`, etc.). Calling a missing token, omitting an argument or passing an argument of the wrong type fails `cargo check` (`E0425`, `E0061`, `E0308`), proven by `trybuild` compile-fail UI tests (`#1615` AC-1). Each generated function and `render_ref` calls `resolve_output_locale` first so `BidiIsolation::Strip` on an RTL locale transparently routes to the compiled `"en"` template rather than failing or emitting unisolated RTL text.
- **Presentation enum accessors (`#1618`):** Each enum registered in `interface/presentation.toml` (`Verdict`, `Mode`, `Approver`, `BlockComponent`, `PersonRoute`, etc.) generates a `present` accessor returning its typed `Presentation` struct whose display fields call the registered language-token accessors rather than embedding literal strings. Exhaustive `match` arms enforce that every registered variant has a row.
- **Route and notification constants (`design/03`):** `ids.rs` exports typed `RouteId` and `NotificationKindId` constants generated from `interface/routes.toml` and `interface/notifications.toml`.
- **Bundle loading:** `grdr_messages::shipped_bundle() -> Result<&'static LocaleBundle, MessageError>` lazily wraps `LocaleBundle::from_static_blobs(include_bytes!("generated/cldr_shipped.postcard"), generated::zoneinfo64_u32::ZONEINFO64)` via `std::sync::OnceLock`. Runtime binaries perform zero disk I/O and zero network calls.
- **`MessageError` delegation and generated `catalogue` (`ARCH-017`):** `MessageError` delegates `BundleInit { source }` and `Format { id, source }` verbatim to `source.code()`, preserving `StringError` codes and classes such as `GRDR-STR-0007` (`policy` / `permission_denied`). `UnknownMessageId` maps to `GRDR-MSG-0001` and `DriftDetected` maps to `GRDR-MSG-0002`. `render_ref` looks up `MessageRef.id` and its `MessageDomain` in the generated `catalogue` module and invokes `grdr_strings::format_template`.

#### 3.2 Why static Postcard blob + `[u32; N]` replaces `icu_provider_baked` codegen
[design/28](../docs/design/28-desktop-and-developer-experience.md#L303) specifies "ICU4X 2.4 with baked data for the shipped locales". In ICU4X 2.4, `icu_provider_baked` (`BakedExporter`) generates Rust files containing `unsafe { zerovec::VarZeroSlice::from_bytes_unchecked(...) }` and direct imports of `icu_provider` / `zerovec`. Compiling generated `icu_provider_baked` modules inside `grdr-messages` would fail `[workspace.lints.rust] unsafe_code = "forbid"` (`Cargo.toml`) and break `ARCH-024` (requiring `grdr-messages` to depend directly on `icu*` crates).

Embedding `cldr_shipped.postcard` in `grdr-messages` and reading it inside `grdr-strings` via `icu_provider_blob::BlobDataProvider::try_new_from_static_blob` achieves identical zero-I/O, zero-allocation static-memory delivery ("baked into the binary") while keeping `#[forbid(unsafe_code)]` and `ARCH-024` intact. Similarly, emitting `zoneinfo64_u32.rs` as aligned `u32` words lets `ZoneInfo64::try_from_u32s` load without an unsafe transmuting macro crate (`resb`).

#### 3.3 Offline deterministic regeneration in CI (`#1615` AC-2)
CI runs with no external network fetches during `cargo test --workspace --locked` (`verify.yml`). To make `grdr-interface-gen generate` offline and byte-reproducible across Linux, macOS and Windows:
- A pinned master data snapshot `interface/strings/cldr/cldr49-data.postcard` (generated once offline via `icu4x-datagen` pinned to CLDR `49.0.0`, Unicode `18.0.0`, TZDB `2026e` covering the supported locale set) and `interface/strings/cldr/zoneinfo64.res`, together with their SHA-256 checksums in `interface/strings/cldr/manifest.toml`, are committed in the repository.
- When `grdr-interface-gen generate` runs (enabled via `grdr-strings`'s non-default tool feature `export`), it verifies `manifest.toml` digests, subsets `cldr49-data.postcard` deterministically down to `shipped` locales of `interface/strings/locales.toml` plus `und` root fallback (sorted canonically by marker and locale), converts `zoneinfo64.res` big-endian/little-endian words deterministically into `zoneinfo64_u32.rs`, and emits all generated Rust and TypeScript files sorted stably with LF line endings.
- `preview` locales and pseudo-locales (`en-XA`, `ar-XB`, `ja-XC`) run against `cldr49-data.postcard` in tests without inflating shipped runtime binaries (`cldr_shipped.postcard`). Promoting a locale from `preview` to `shipped` is a data change in `interface/strings/locales.toml` followed by `grdr-interface-gen generate` (`D-69`).

### 4. Feature `pack-text` and `ARCH-024` `strings-closure` (R3)
`ARCH-024` in [design/03](../docs/design/03-system-architecture-and-modularity.md#L138) governs the exact crate and feature closure for internationalisation and policy pack text:

1. **Exclusive `icu*` ownership.** In `cargo metadata`, only `grdr-strings` (normal and optional dependencies) may declare any dependency matching `icu*` or `zoneinfo64`. Neither `grdr-messages`, `grdr-interface-gen`, `grdr-core`, any layer 3 adapter nor any layer 4 program may depend directly on any `icu*` crate.
2. **Restricted `pack-text` and `export` features.** `grdr-strings` defines non-default Cargo features:
   ```toml
   [features]
   default = []
   pack-text = []
   export = ["dep:icu_provider_export", "icu_provider_blob/export"]
   ```
   `pack-text` enables `CompiledPackMessage`, Postcard deserialisation of pack `messages/<locale>.mf2.toml` compiled payloads (`from_compiled_bytes(&[u8])`), and dynamic bundle loading (`LocaleBundle::from_boxed_blobs`). Feature `export` (`icu_provider_export`) is permitted **only** in the `tool` crate `grdr-interface-gen` and `grdr-strings` dev/unit tests; `grdr-archlint` fails `ARCH-024` if any layer 3 adapter, layer 4 binary, `privileged` binary or `wasm32` build enables `export` or calls `LocaleBundle::from_boxed_blobs`.
3. **Allowed programs for `pack-text`.** In the resolved Cargo feature graph per package, `grdr-strings/pack-text` may be enabled **only** in the closure of:
   - `grdr-engine`
   - `grdr-server`
   - `grdr` (CLI)
   It is **forbidden** (`ARCH-024` exit 1) in `privileged` programs (`grdr-daemon`, `grdr-updater`, `grdr-approve`) and in `grdr-wasm` / `grdr-ffi` unless explicitly added by an RFC amendment. Note that because Cargo unifies features across workspace builds when running `cargo build --workspace`, `grdr-archlint` checks `cargo metadata` feature resolution **per program manifest (`--manifest-path` / isolated package feature resolution `--no-default-features` / explicit feature tree)** for every `privileged` binary (`#1580`), verifying none enables `pack-text` or `export` directly or transitively.
4. **`grdr-hook` exclusion.** `grdr-hook` links neither `grdr-strings` nor `grdr-messages`. It surfaces verbatim pre-rendered `BlockNotice` strings or raw identifiers (`D-69`, `ARCH-024`).
5. **Pack message safety (`ARCH-004`, `design/12` s10).** Pack build compiles `messages/<locale>.mf2.toml` into signed `CompiledPackMessage` binary records (`@message` and English `@steer`), verifies URL-free and Markdown-free invariants, and caps grapheme lengths via `limits.toml`. Because `grdr-daemon` and `grdr-updater` never link `pack-text` (and emit structured `MessageRef`s or static codes rather than parsing pack text), no content or template parser enters a privileged binary (`ARCH-004`). `grdr-approve` (`privilege = "privileged"` or desktop approval helper) formats only static compiled UI tokens via `grdr-messages` (`LocaleBundle::from_static_blobs`) without `pack-text`, `export`, `from_boxed_blobs`, `serde_json` or `toml`.

### 5. Admitted ICU4X 2.4 crates, licences, provenance and `wasm32` (R4)
All upstream crates below are pinned to exact versions (`=x.y.z`) in `grdr-strings/Cargo.toml` and `Cargo.lock`, carry permissive licences already admitted in `supply-chain/licences.toml` (`Unicode-3.0`, `MIT OR Apache-2.0`), use `default-features = false` with `serde` (never `compiled_data`, `fs`, `net` or `std::time`), and build cleanly for `wasm32-unknown-unknown`.

| Crate | Exact version | SPDX licence | Upstream provenance | Enabled features | Purpose in `grdr-strings` |
|---|---|---|---|---|---|
| `icu_provider` | `=2.4.0` | `Unicode-3.0` | `https://github.com/unicode-org/icu4x` | `serde`, `sync` | Core `DataProvider`, `BufferProvider`, `DataError` |
| `icu_provider_adapters` | `=2.4.0` | `Unicode-3.0` | `https://github.com/unicode-org/icu4x` | `none` | `LocaleFallbackProvider` over buffer providers |
| `icu_provider_blob` | `=2.4.0` | `Unicode-3.0` | `https://github.com/unicode-org/icu4x` | `alloc` (`export` under tool-only `export`) | `BlobDataProvider::try_new_from_static_blob` (safe static blobs) |
| `icu_locale_core` | `=2.4.0` | `Unicode-3.0` | `https://github.com/unicode-org/icu4x` | `serde`, `alloc` | BCP-47 `Locale` parsing and subtags |
| `icu_locale` | `=2.4.0` | `Unicode-3.0` | `https://github.com/unicode-org/icu4x` | `serde` | `LocaleCanonicalizer`, `LocaleExpander`, `LocaleDirectionality` |
| `icu_locale_fallback` | `=2.4.0` | `Unicode-3.0` | `https://github.com/unicode-org/icu4x` | `serde` | CLDR locale fallback chains (`LocaleFallbacker`) |
| `icu_collections` | `=2.4.0` | `Unicode-3.0` | `https://github.com/unicode-org/icu4x` | `serde` | `CodePointTrie` / `CodePointInversionList` backing properties |
| `icu_properties` | `=2.4.0` | `Unicode-3.0` | `https://github.com/unicode-org/icu4x` | `serde`, `alloc` | Unicode properties (`BidiClass`, script, control scanners) |
| `icu_normalizer` | `=2.4.0` | `Unicode-3.0` | `https://github.com/unicode-org/icu4x` | `serde` | `ComposingNormalizer` (NFC validation and canonicalisation) |
| `icu_decimal` | `=2.4.0` | `Unicode-3.0` | `https://github.com/unicode-org/icu4x` | `serde` | `DecimalFormatter` for `:number` and `:integer` |
| `icu_plurals` | `=2.4.0` | `Unicode-3.0` | `https://github.com/unicode-org/icu4x` | `serde` | `PluralRules` for CLDR plural categories in `.match` |
| `icu_list` | `=2.4.0` | `Unicode-3.0` | `https://github.com/unicode-org/icu4x` | `serde` | `ListFormatter` for `:grdr:list` |
| `icu_calendar` | `=2.4.0` | `Unicode-3.0` | `https://github.com/unicode-org/icu4x` | `serde` | Calendar dates (`Date::try_from_fields` across `-9999..=10000`) |
| `icu_time` | `=2.4.0` | `Unicode-3.0` | `https://github.com/unicode-org/icu4x` | `serde` | `Time`, `ZonedDateTime`, `IanaParser`, `UtcOffset`, `TimeZoneInfo` |
| `icu_datetime` | `=2.4.0` | `Unicode-3.0` | `https://github.com/unicode-org/icu4x` | `serde` | `DateTimeFormatter` semantic skeletons for `:datetime` |
| `icu_segmenter` | `=2.4.0` | `Unicode-3.0` | `https://github.com/unicode-org/icu4x` | `serde` (no `lstm`) | `GraphemeClusterSegmenter` and UAX #14 `LineSegmenter` |
| `icu_experimental` | `=0.7.0` | `Unicode-3.0` | `https://github.com/unicode-org/icu4x` | `serde` | `duration::DurationFormatter`, `units::CategorizedUnitsFormatter`, `relativetime::RelativeTimeFormatter` |
| `fixed_decimal` | `=0.7.3` | `Unicode-3.0` | `https://github.com/unicode-org/icu4x` | `none` | Exact base-10 decimals with no float rounding |
| `writeable` | `=0.6.4` | `Unicode-3.0` | `https://github.com/unicode-org/icu4x` | `none` | Zero-copy ICU4X `Writeable` formatting trait |
| `zoneinfo64` | `=0.3.0` | `Unicode-3.0` | `https://github.com/unicode-org/icu4x` | `none` | Pure in-memory IANA TZDB offset resolution over `[u32]` |
| `postcard` | `=1.1.3` | `MIT OR Apache-2.0` | `https://github.com/jamesmunns/postcard` | `alloc` | Already pulled by `icu_provider_blob`; decodes `CompiledPackMessage` under `pack-text` |
| `icu_provider_export` (optional, tool-only `export`) | `=2.4.0` | `Unicode-3.0` | `https://github.com/unicode-org/icu4x` | `default-features = false` | Used solely by `grdr-interface-gen` offline bundle generation (`export`) |

Transitive closure rules (`#449`):
- Before `#449` adds these dependencies to `Cargo.lock`, `lead-agent-kit` records every crate in the resolved `Cargo.lock` closure (including ICU4X foundations `zerovec`, `zerotrie`, `tinystr`, `litemap`, `yoke`, `zerofrom`, `potential_utf`, `icu_pattern`, `calendrical_calculations`, `displaydoc`, `serde`, `num-bigint`, `num-rational`, `num-traits`) with exact version, SPDX expression (`supply-chain/licences.toml` permissive class), crates.io SHA-256 checksum, build script / proc-macro audit, and dependency publish-cooldown check (`design/35` section 2.6: 3 days / 72 hours for patch and minor releases and 7 days for major releases) in `supply-chain/admissions.toml`.
- If `icu_experimental = "0.7.0"` pulls any unapproved or `compiled_data`-locked transitive crate (such as unconditionally pulling `icu_experimental_data` if not optional in `0.7.0`), `#449` inspects the exact `Cargo.lock` entry during admission; if `icu_experimental_data` is non-optional and adds unsafe baked blobs or excessive binary weight, an amendment to RFC 0017 selects direct subsetting or isolates `:grdr:duration` / `:unit` until ICU4X separates the data crate.
- `cargo build -p grdr-strings --target wasm32-unknown-unknown` and `cargo deny check` are mandatory gates on `#449`.

### 6. `grdr:class=<data class>` and data-class enforcement (R5)
Under P8, personal or sensitive content never leaves the device or leaks into notifications, emails or logs ([design/18](../docs/design/18-response-approvals-and-soc-operations.md#L276), [design/25](../docs/design/25-integrations-imports-exports.md#L222), [design/28](../docs/design/28-desktop-and-developer-experience.md), [design/34](../docs/design/34-documentation-support-and-lifecycle.md) §17). Language tokens encode this boundary directly in the MF2 contract:

1. **Syntax and metadata binding:**
   - Every token argument in `interface/strings/src/*.mf2.toml` declares `args.<name>.class = "identifier" | "structural" | "derived" | "content"`.
   - Inside MF2 message text, `.input {$name ... grdr:class=<class>}` or placeholder expression `{$name ... grdr:class=<class>}` uses the standard LDML Part 9 private-use attribute `grdr:class`.
   - Validation rules in `grdr-strings` and `grdr-interface-gen check`:
     - An unrecognised `grdr:class` value fails parsing (`GRDR-STR-0006`).
     - If `grdr:class` is written in MF2 text and differs from `args.<name>.class` in TOML metadata, `grdr-interface-gen check` fails (`GRDR-IFG-0007`).
     - If `grdr:class` is omitted in MF2 text, `grdr-interface-gen` binds `args.<name>.class` from TOML metadata (which is required on every argument of every token in `interface/strings/src/`). For standalone `MessageTemplate::parse_infer` calls without external metadata, `:grdr:brand` and `:grdr:term` default to `DataClass::Structural`; every other dynamic variable defaults fail-closed to `DataClass::Content` (`P8`).
2. **`notify.*` and `email.*` hard failure (`#448` R5):**
   - Any token whose id starts with `notify.` or `email.`, and any pack `NotificationTemplate`, fails `grdr-interface-gen check` (exit 1, `GRDR-IFG-0008`, nothing generated) if any declared or inferred argument has `class == DataClass::Content`.
   - At deserialisation (`CompiledPackMessage::from_compiled_bytes`) and at format time (`format_template`, `CompiledPackMessage::format`, `render_ref`), both `MessageTemplate` and `CompiledPackMessage` carry `MessageId` and `MessageDomain`, propagate `DataClass` taint across `.local` chains, refuse any sensitivity downgrade (`NamedArg.class() < ArgDecl.class` or inline `grdr:class < decl.class`), and return `Err(StringError::DisallowedDataClass { id, arg, class })` (`GRDR-STR-0007`) whenever an `ArgDecl` or effective argument on `Notification`, `Email` or `PackNotification` carries `DataClass::Content`.
   - Generated Rust accessors in `grdr-messages` never provide a `Content`-accepting parameter on `notify.*` or `email.*` functions (`cargo check` enforces structural/identifier/derived typing cleanly).
3. **`code.*` and `agent.*` rules (`RFC 0007`, `#1853`, `#1384`):**
   - `code.<area>_<nnnn>.message` and `code.<area>_<nnnn>.fix` tokens permit `Structural` arguments plus an `Identifier` `code` argument; `Derived` or `Content` arguments fail `grdr-interface-gen check` (`GRDR-IFG-0007`) and runtime formatting (`GRDR-STR-0007`). Every entry in `grdr_schema::codes::ALL` must have both tokens (`#1853` R2).
   - `agent.*` tokens (`#1384`) carry `Identifier` (`rule_id`, `code`, `reference`) and `Structural` (`action_class`, `product`, inert URL-free `@steer`), mark `translate = false`, contain zero Markdown or links, and fit within `strings.agent-block-chars-max` from `limits.toml` (`600` characters at seed, `design/28` §11). `Content` arguments fail validation.
4. **Non-logging (`P8`):** Output strings and `Content`/`Derived` argument values never implement `grdr_model::LogSafe`, and `ArgValue`, `NamedArg`, `MessageArgs` and `MessageRef` implement redacting `Debug` (Section 2.1). Error structs carry only `Code`, `MessageId`, argument slot names, bound keys and `DataClass` labels.

### 7. Proposed error codes (`STR`, `MSG`, `IFG`)
Under RFC 0007, three experimental areas are registered in `schema/codes/areas.toml`: `STR` (`grdr-strings`), `MSG` (`grdr-messages`) and `IFG` (`grdr-interface-gen`). Parity language tokens follow RFC 0007 section 3's lowercase snake-case grammar with no brand prefix: `code.<area>_<nnnn>.message` and `code.<area>_<nnnn>.fix` (for example `code.str_0001.message` and `code.msg_0001.fix`, landed under `#1853`).

| Code | Reason | Class | Connect code | Summary |
|---|---|---|---|---|
| `GRDR-STR-0001` | `MF2_SYNTAX_INVALID` | `input` | `invalid_argument` | Malformed MF2 pattern, nested `.match`, or missing `*` fallback branch |
| `GRDR-STR-0002` | `MF2_UNKNOWN_FUNCTION` | `input` | `invalid_argument` | Function name outside the closed `Mf2Function::REGISTRY` |
| `GRDR-STR-0003` | `MF2_MISSING_OR_WRONG_ARG` | `input` | `invalid_argument` | Required argument absent or `ArgValue` type mismatches declaration |
| `GRDR-STR-0004` | `LOCALE_UNKNOWN` | `input` | `invalid_argument` | Unrecognised or invalid BCP-47 locale tag or missing bundle data |
| `GRDR-STR-0005` | `RELATIVE_TIME_NEEDS_NOW` | `internal` | `internal` | `:grdr:relative` called with `Timestamp` and `reference_now = None` |
| `GRDR-STR-0006` | `INVALID_DATA_CLASS_ATTR` | `input` | `invalid_argument` | Invalid `grdr:class` attribute value in MF2 message |
| `GRDR-STR-0007` | `DISALLOWED_DATA_CLASS` | `policy` | `permission_denied` | `Content` argument or class downgrade on `notify.*`, `email.*`, `code.*`, `agent.*` or `.local` |
| `GRDR-STR-0008` | `PACK_BLOB_INVALID` | `input` | `invalid_argument` | Corrupted or malformed `CompiledPackMessage` binary payload (`pack-text`) |
| `GRDR-STR-0009` | `BUNDLE_DATA_INVALID` | `internal` | `internal` | Unreadable or inconsistent CLDR Postcard blob or `zoneinfo64` table |
| `GRDR-STR-0010` | `UNSAFE_CONTROL_CHAR` | `input` | `invalid_argument` | Forbidden Unicode bidi control or C0/C1/ANSI escape control in template or argument |
| `GRDR-STR-0011` | `UNSUPPORTED_BIDI_STRIP` | `input` | `invalid_argument` | RTL locale passed to formatter with `BidiIsolation::Strip` without `en` fallback |
| `GRDR-STR-0012` | `RESOURCE_BOUND_EXCEEDED` | `input` | `resource_exhausted` | Template bytes, AST nodes, `.local` depth, `.match` branches, pack blob or list items exceed `limits.toml` |
| `GRDR-MSG-0001` | `UNKNOWN_MESSAGE_ID` | `input` | `not_found` | `MessageRef` id not present in generated catalogue |
| `GRDR-MSG-0002` | `GENERATED_DRIFT` | `internal` | `internal` | Committed `crates/grdr-messages/src/generated/` differs from `interface/` |
| `GRDR-IFG-0001` | `TOKEN_SCHEMA_INVALID` | `input` | `invalid_argument` | Token entry violates `strings.schema.json` or misses `desc`, `max` or `risk` |
| `GRDR-IFG-0002` | `MF2_PARSE_FAILED` | `input` | `invalid_argument` | English or locale MF2 text failed `grdr-strings` syntax or closed-registry validation |
| `GRDR-IFG-0003` | `UNDECLARED_OR_MISMATCHED_ARG` | `input` | `invalid_argument` | Placeholder missing from token `args` declaration or typed incompatibly |
| `GRDR-IFG-0004` | `LITERAL_BRAND_NAME` | `input` | `invalid_argument` | Token text hard-codes product name instead of `:grdr:brand` (`D-66`) |
| `GRDR-IFG-0005` | `TOKEN_EXCEEDS_MAX` | `input` | `invalid_argument` | Token text or pseudo-locale rendering exceeds declared `max` graphemes |
| `GRDR-IFG-0006` | `MISSING_CODE_TOKEN` | `input` | `invalid_argument` | Active or retired code in `grdr_schema::codes::ALL` lacks `code.<area>_<nnnn>.message` or `.fix` |
| `GRDR-IFG-0007` | `DATA_CLASS_MISMATCH` | `input` | `invalid_argument` | Inline `grdr:class` disagrees with `args.<name>.class` or `code.*` uses non-structural class |
| `GRDR-IFG-0008` | `CONTENT_CLASS_IN_NOTIFY` | `policy` | `permission_denied` | `notify.*`, `email.*`, or pack notification template declares or infers `content`-class argument |
| `GRDR-IFG-0009` | `DISALLOWED_CHAR_OR_MARKUP` | `input` | `invalid_argument` | Token contains URL, Markdown syntax, emoji, non-NFC text or forbidden bidi/control character |

`MessageError::BundleInit` and `MessageError::Format` delegate directly to `source.code()` (`impl Coded for MessageError`), leaving no unused or masking `MSG` codes (`ARCH-017`). Additional generator-internal fault codes (such as registry JSON Schema validation, dangling cross-references and CLI output I/O failures) are registered additively by `#1613` under RFC 0007 section 4 with unique `UPPER_SNAKE` reasons in `schema/codes/ifg.toml`.

### 8. Proposed registry, doc and downstream issue write-backs
On acceptance (`ADR-*` issued on `#448`):
- **`architecture.toml`:** `#449` updates `grdr-strings`, `grdr-messages` and `grdr-interface-gen` (`created = true`, `ARCH-024` rule metadata banning `icu*` outside `grdr-strings`, restricting `pack-text` to `grdr-engine`, `grdr-server`, `grdr`, banning `export` outside `grdr-interface-gen` and `grdr-strings` tests, and excluding `grdr-hook` from `grdr-strings`/`grdr-messages`).
- **`surfaces.toml`:** One protected-change item adds `[[crate]]` `grdr-strings` (`stability = "experimental"`, citing this RFC and its ADR per ADR-0020).
- **`supply-chain/admissions.toml`:** `#449` (for `lead-agent-kit`) adds the complete Section 5 `Cargo.lock` closure, SHA-256 checksums, build-script / proc-macro audit, and 3-day / 7-day cooldown verification (`design/35` section 2.6) before `#449` merges.
- **`schema/codes/areas.toml` and `limits.toml`:** Registers `STR`, `MSG`, `IFG` (Section 7) and the eight `[bound.*]` rows of Section 1 (`R1.6`) through their respective schema/limits protected items under RFC 0007.
- **Design docs updates:** Clarify in `docs/design/28` section 13 that ICU4X 2.4 baked data is embedded as a verified static Postcard `BlobDataProvider` blob + `[u32]` `zoneinfo64` table rather than `unsafe` `icu_provider_baked` modules; clarify in `docs/design/34` section 15a the closed 9-function MF2 registry, `grdr:class` fail-closed defaults, `limits.toml` bounds, universal `FSI`/`PDI` isolation, control-character rejection and `Timestamp::MIN..=MAX` extended-date boundary rule.
- **Constraint comments written back to blocked issues:**
  - `#449`: exact dependency list (`grdr-schema`, `grdr-model`, Section 5 ICU4X 2.4 crates), `default = []`, `pack-text` & `export` features, `trybuild` dev-dependency admission check if needed by `#1615`, 3-day/7-day cooldown and `admissions.toml` update.
  - `#1612`: exact root-exported Rust items of Section 2 (including `MessageDomain`, redacting `Debug`, `UnsafeControlChar`, `UnsupportedBidiStrip`, `ResourceBoundExceeded`, `resolve_output_locale`), `.local` taint propagation, `limits.toml` bounds (`ARCH-019`), `DecimalInput` + `BrandContext` + `TermTable`, extended-date `Timestamp::MIN..=MAX` handling, control rejection, universal `FSI`/`PDI`, terminal `Strip` -> `en` fallback, and pseudo-locale rules.
  - `#1613`: `grdr:class` enforcement (`GRDR-IFG-0007`, `GRDR-IFG-0008`), additive registration of generator-only `GRDR-IFG-*` codes under RFC 0007 section 4 with unique reasons, deterministic `cldr49-data.postcard` subsetting via `grdr-strings/export`, deterministic `[u32; N]` emission for `zoneinfo64`.
  - `#1614`: `locales.toml` `shipped`/`preview`/`pseudo` tiers, `args.<name>.class` required on every argument, `cldr49-data.postcard` + `zoneinfo64.res` + `manifest.toml` placement.
  - `#1615`: generated file tree `crates/grdr-messages/src/generated/`, `_ref` builders + `render_ref` + `present` accessors, `MessageError` code delegation (`ARCH-017`), `Strip` + RTL -> `en` wrapper routing, `shipped_bundle()` lazy static blob, `drift` & `compile_fail` tests.
  - `#1616`, `#1618`, `#1384`, `#1853`: parity rules on `DecimalInput`, `Identifier` LRI/PDI + ASCII digits, `Presentation` struct accessor contract, `agent.*` non-translation + `strings.agent-block-chars-max` bound, and RFC 0007 lowercase `code.<area>_<nnnn>.message` / `.fix` parity.

## Surfaces changed
- **Proposed public crate:** `grdr-strings` (layer 2, public, experimental, no I/O, no clock, `#![forbid(unsafe_code)]`, `wasm32-unknown-unknown`): Section 2 items (`DataClass`, `MessageDomain`, `ArgType`, `ArgDecl`, `MessageId`, `DecimalInput`, `BrandSlot`, `ArgValue`, `NamedArg`, `MessageArgs`, `MessageRef`, `StringError`, `Mf2Function`, `MessageTemplate`, `CompiledPackMessage`, `LocaleTag`, `LocaleTier`, `Direction`, `LocaleEntry`, `ScriptTag`, `BidiIsolation`, `ViewerTimeZone`, `LocaleBundle`, `BrandContext`, `TermTable`, `FormatContext`, `PseudoLocale`, and free functions `format_template`, `format_utc_iso8601`, `negotiate_locale`, `resolve_output_locale`, `normalise_nfc`, `format_pseudo_template`).
- **Proposed generated crate contract:** `grdr-messages` (layer 2, unpublished, generated): Section 3 module structure (`tokens`, `present`, `ids`, `catalogue`, `cldr_shipped.postcard`, `zoneinfo64_u32.rs`, `shipped_bundle()`, `render_ref()`, `MessageError` delegating wrapped `StringError` codes, `Presentation`, `Present`, `RouteId`, `NotificationKindId`, typed per-token functions and `_ref` builders).
- **Proposed features & lint gate:** `grdr-strings/pack-text` (`CompiledPackMessage`, `LocaleBundle::from_boxed_blobs`), `grdr-strings/export` (tool-only) and `ARCH-024` `strings-closure`.
- **Proposed resource bounds:** eight `strings.*` `[bound.*]` rows in `limits.toml` (`R1.6`, `ARCH-019`).
- **Proposed third-party dependencies:** 18 ICU4X `2.4.0` / companion crates, `icu_experimental` `0.7.0`, `zoneinfo64` `0.3.0`, `postcard` `1.1.3` (Section 5).
- **Proposed error areas:** `STR` (`GRDR-STR-0001..0012`), `MSG` (`GRDR-MSG-0001..0002`), `IFG` (`GRDR-IFG-0001..0009`) (Section 7).
- **Proposed `grdr:class` enforcement:** compile-time and runtime block on `content`-class arguments in `notify.*`, `email.*`, and pack notifications, anti-downgrade `.local` taint, and redacting `Debug` (Sections 2 and 6).
- **No spine text changes.**

## Alternatives
- **Generate `icu_provider_baked` Rust modules into `grdr-messages`.** Rejected because ICU4X `2.4` baked code generation emits `unsafe { VarZeroSlice::from_bytes_unchecked(...) }` and direct `icu_provider` imports inside the generated crate, violating `[workspace.lints.rust] unsafe_code = "forbid"` (`Cargo.toml`) and `ARCH-024`. Embedding a deterministic Postcard blob in `grdr-messages` read by safe `BlobDataProvider::try_new_from_static_blob` inside `grdr-strings` satisfies both invariants with zero runtime allocation and zero I/O.
- **Require callers to pre-resolve UTC timestamps to local `UtcOffset` before calling `grdr-strings` (or admit `jiff`).** Rejected. Requiring every Rust caller (`grdr`, `grdr-server`, desktop) to carry its own TZDB library duplicates mechanism (P17). Admitting `jiff` would add a separate date-time ecosystem outside ICU4X (`#29-E1` was ICU4X), whereas ICU4X's own `Unicode-3.0` crate `zoneinfo64` evaluates historical and proleptic TZDB transitions in memory with `no_std`, zero I/O and `wasm32` support.
- **Keep `grdr-strings` independent of `grdr-schema` and `grdr-model` using raw `i64`/`u64` primitives.** Rejected. `grdr-strings` sits at layer 2; reusing `grdr_schema::codes::{Code, Coded}`, `grdr_schema::limits::{Bytes, Millis, Count, Permille}` and `grdr_model::{Timestamp, LogSafe}` preserves single definitions (P17) and prevents unvalidated integer confusion in public APIs (`RFC 0007`, `RFC 0009`).
- **Admit `unicode-segmentation` and `unicode-bidi` alongside ICU4X.** Rejected. `icu_segmenter` `2.4.0` already implements UAX #29 extended grapheme cluster counting pinned to the exact same Unicode 18 tables (`P17`), and `icu_locale` + `icu_properties` + explicit FSI/PDI/LRI isolation cover Guardrails' bidi rules without dragging in extra parsers.
- **Default omitted `grdr:class` attributes in standalone MF2 strings to `Structural`.** Rejected under P8. Any omitted class outside validated TOML metadata defaults fail-closed to `Content` (except `:grdr:brand` and `:grdr:term`), ensuring accidental dynamic placeholders are blocked by `notify.*` / `email.*` checks rather than leaked silently.
- **Enable `compiled_data` in runtime builds of `grdr-strings`.** Rejected. `compiled_data` compiles full CLDR tables for every world locale into desktop and `wasm32` binaries and emits `unsafe` baked slices. Only the `shipped` locales of `locales.toml` (plus `und`) belong in runtime binaries (`design/28` §13).

## Drawbacks
- **Dependency footprint:** Admitting ICU4X `2.4.0` introduces roughly 20 ICU4X crates and their `zerovec`/`yoke`/`tinystr` transitive closure into `Cargo.lock` (audited once in `supply-chain/admissions.toml` under `#449`).
- **Pre-1.0 experimental ICU4X components:** `icu_experimental` is `0.7.0` and `zoneinfo64` is `0.3.0`; both are exact-pinned (`=0.7.0`, `=0.3.0`) so minor updates happen only through intentional `Cargo.lock` review.
- **Committed data snapshots in git:** `cldr49-data.postcard`, `zoneinfo64.res`, `cldr_shipped.postcard` and `zoneinfo64_u32.rs` add binary/numeric artefacts to version control so CI builds and `drift` tests run completely offline without downloading CLDR or TZDB archives.
- **Extended boundary fallback on `Timestamp::MIN..=MAX`:** Non-Gregorian era calendars may fall back to proleptic Gregorian formatting when a viewer time zone shifts `0001-01-01` or `9999-12-31` across year `0` or year `10000`.

## Unresolved questions
1. **Exact transitive closure of `icu_experimental = "=0.7.0"`:** When `#449` runs `cargo update` / `cargo deny check` against the live crates.io index to populate `supply-chain/admissions.toml`, confirm whether `icu_experimental_data` is pulled unconditionally by `icu_experimental 0.7.0` or gated behind `compiled_data`, and confirm every crate satisfies the `design/35` section 2.6 publish cooldown.
2. **`grdr.common.v1alpha1.MessageRef` proto binding:** The protobuf wire message `MessageRef` in `docs/design/04` sits in its own `grdr.common.v1alpha1` proto RFC (after RFC 0006). That RFC must bind proto `MessageRef` arguments cleanly onto `grdr_strings::MessageRef` (`DecimalInput` encoding, `DataClass` enum parity).
3. **`present()` return fields (`#1618` & `#1891`):** `#1618` splits presentation status and icons to `#1891`. When `#1618` is readied, confirm whether `Presentation` exposes an `Option<IconToken>` / optional status field so adding `#1891` columns requires no signature change.
4. **Master `cldr49-data.postcard` locale pool:** Before `#1614` commits `interface/strings/cldr/cldr49-data.postcard`, confirm the exact set of `preview` locales included in the committed master blob (matching `locales.toml`) to bound repository size.

## Review
Review on `#448` runs on this blob under `D-61`, `D-63`, `.claude/risk-tiers.toml` (`[kinds] rfc` plus `new_dependency` / `public_api_change`), and `ADR-0043` (`eval-review` and `eval-security` on two distinct models, plus persona council seats as requested on `#448`). Every reviewing comment on `#448` opens with the three role lines required by [RFC 0001](./0001-adopt-the-spine.md):
- `RFC file: <blob of rfcs/0017-grdr-strings-language-token-runtime.md at the commit reviewed>`
- `Proposed text: none`
- `Base: a80859235e7a2a4444648d6fa8d389d78dde6be9`
- `read=<path>@<blob>` for every other file it relied on

This text was written against these git blobs at commit `f83ea0f` on `main`:
- `docs/design/00-decisions.md`: `a80859235e7a2a4444648d6fa8d389d78dde6be9`
- `docs/design/03-system-architecture-and-modularity.md`: `2f9e920f0ace798592876d5009909eb096e7e952`
- `docs/design/04-event-model-and-schemas.md`: `e77880a12d2f42e715836a6da9598b86f33b20b0`
- `docs/design/12-policy-engine.md`: `b432904799251eca1d931378a6094ca6ea8b08db`
- `docs/design/27-web-console-ux.md`: `73d4368ff62807c771ab51b3a330c0ec1a862a3e`
- `docs/design/28-desktop-and-developer-experience.md`: `428385fc76372e0ee0b1bcc1e3b8aa2a76bd0b21`
- `docs/design/30-open-source-governance-and-community.md`: `91f909de5f9ed9aaf6db0bbeb4641db16976adda`
- `docs/design/34-documentation-support-and-lifecycle.md`: `0d8c37fbc63020a407a05912364eb2aced878f3f`
- `docs/design/35-product-security-programme.md`: `dbc3874d96f51415db2e91c340747dac77043c2d`
- `rfcs/0001-adopt-the-spine.md`: `353436cd2f9cff08037783ca66678c52cd7d6be4`
- `rfcs/0005-fastpath-rust-surface.md`: `4ad52380450ff611f274b4813a19a7f8e412eb7f`
- `rfcs/0007-grdr-model-and-grdr-schema-slice-0-surface.md`: `0c0a6745f04888bec8ef2e718352549f47181201`
- `rfcs/0009-grdr-model-slice-0-surface.md`: `4f36df6f0b2ce122d3b09d8109e83fb4720b1c68`
- `architecture.toml`: `60743ee6b3f532190237a499b236784bf3587e04`
- `surfaces.toml`: `2fa94d4fecd4cdb355bfdcaf8ebce42f5bacb57a`
- `brand/brand.toml`: `a32c7cfbf0c9197a8464581483546e74f08c545b`
- `deny.toml`: `2d0457ff71ea5c9bba91de0a580cd80f650d1479`
- `supply-chain/licences.toml`: `65338a382a81c1ac500c533e22fa6ee22397928d`
- `supply-chain/admissions.toml`: `1b25c164ade9d313e80bd6286444e289062d7f1f`

## Decision
Not decided. Awaits review on `#448` under `D-61` and [RFC 0001](./0001-adopt-the-spine.md).
