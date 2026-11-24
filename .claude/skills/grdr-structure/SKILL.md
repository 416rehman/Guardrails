---
name: grdr-structure
description: "Write or change code the way this repository wants it built: the mechanism before the feature, structures before implementations, small files, explicit state types, no panic paths, no hard-coded values, few comments. Use before writing or editing any Rust, TypeScript, JavaScript or CSS source, and whenever a review reports a structure check S1 to S7."
license: Apache-2.0
metadata:
  version: "2"
  owner: agent-kit
  closes-by: [type, lint]
---

# Structure rules for code

These are the owner's rules (owner instructions 4, 9, 15 and 26, recorded in `docs/design/_review/04-owner-kit-instructions.md`). Seven of them are the structure checks S1 to S7, which the owner calls V-structure. No tool runs them now: you check your own diff against them before you report, and `eval-diff` checks it again. They are not the security power prompts of `docs/team/04`. Audit A01 and the evaluators check what a pattern cannot. The interface checks UX1 to UX8 belong to `grdr-interface`, loaded after `ui-architect`. Code written to these rules from the first line never meets a finding, so read the rules before you write, not after a review complains.

## Core engineering principles (Beta / Pre-release)

Enforced by `.claude/hooks/docs-check.mjs` and `.agents/hooks/agy-pre-tool-use.mjs`:

1. **(Pre-release / Beta dev lifecycle only; drop at GA release):** Do not maintain backward compatibility with previous unreleased dev versions of this platform. Delete outdated code outright with no compatibility layers, migration scripts, or backup fallback shims (still model data schemas and versioned contracts cleanly for future post-GA evolution).
2. Choose the simplest implementation that meets current needs. No speculative abstractions or configuration layers added "just in case".
3. Let the system grow in layers: get a minimal end-to-end slice working first, then add capabilities once it runs. Never tear down working code over hypothetical future complexity.
4. Keep components modular with clear separation of concerns.
5. Prefer mature, maintained third-party libraries; do not rewrite them yourself without a compelling reason.
6. Check what existing project dependencies already provide before adding a new package or writing custom code.
7. Make architectural decisions for the long term. No "we will make it work for now and deal with it later" stopgaps or `HACK`/`FIXME` workarounds.
8. Study how mature products in our space solve the problem and reuse proven patterns instead of inventing from scratch.
9. Push back on harmful changes: if a requested task or change would hurt the end product more than it helps (for example, forcing compile-time static typing where data-driven extensibility or clean modularity is required), push back directly, explain the trade-off, and propose a better alternative instead of blindly implementing it.

## The seven rules

1. **Structures before implementations.** Every Rust file runs in this order: module declarations and imports, then constants and statics, then types (structs, enums, type aliases, traits), then impls, then free functions, then the test module last. TypeScript: imports, constants, types and interfaces, then functions and classes. A reader learns what exists before reading what it does.
2. **Files stay small.** A source file over 500 lines of code (blank lines, comments and the test module excluded) is split by responsibility. A file already over the limit must not grow, and the next change that touches it splits it.
3. **No implicit state machines, ever.** Mutually exclusive booleans, a status or phase held as a string or integer, `Option` fields valid only in some phases, and checks like `started && !finished` are one lifecycle smeared across fields. Redesign it as an explicit state type: an enum whose variants carry the data each state owns, and transitions as functions that consume one state and return the next (typestate where it is cheap), so an invalid combination cannot be represented. Every non-terminal state has an exit: success, failure, cancel, timeout or restart. `references/state-types.md` shows the conversion.
4. **Comments only when nothing else can say it.** Keep a comment only for a reason the code cannot show: an invariant, an external constraint, a link to a spec, decision record or RFC, and the `// SAFETY:` comment every `unsafe` block needs. No narration, change-log or step comments, no commented-out code, no TODO without a work-item id (`TODO(#123)`, or `TODO(WI-0012)` for a reserved item). Rename or extract instead of commenting. Rustdoc on public items stays where the crate's lints require it, and stays short.
5. **Fix the core problem.** When a check or a review finds a problem, change the design so the problem cannot recur. Never silence the check, add a guard around the symptom, rename to dodge the pattern, or split a file mechanically to get under 500 lines. If the right fix is outside the item's write set, report the finding and a proposed issue instead of a local workaround.
6. **Readable code.** One job per function and module. Names that say what a thing is. Early returns over nesting, four levels at most. Enums over boolean parameters. Every bound in `limits.toml`, never a magic number or a named constant holding one. Errors carry their `GRDR-<AREA>-<NNNN>` code. Modules split by feature, not by kind. The public surface as small as it can be.
7. **Find the mechanism first** (P14, framework over features). Before writing a feature, find the mechanism it belongs to: a port with adapters, a signed pack, a manifest, a configuration schema or a plugin seam. Extend that mechanism, or add one, and express the feature as content or configuration on top of it, with the product's own behaviour as the default content. A vendor, agent, rule, threshold, workflow, UI flow, integration or policy written into code where a mechanism would carry it is a design defect, and `eval-architecture` fails it. Name the extension point you used or added in your report.

## Writing code that needs no escape hatch

A type escape tells the compiler to stop checking something it could check. No pattern catches all of them; `eval-diff` treats each as a failed criterion.

- **Narrowing casts.** `as` between integer types can drop bits or flip a sign. Convert with `try_from` and handle the error; keep `as` for a widening the types already prove safe.
- **Lint switches.** `#[allow]` or `#[expect]` written to quiet a lint hides what the lint found. Fix the code; a lint that is wrong for this line takes `reason = "..."` saying why.
- **Discarded results.** `let _ =` on a `Result` drops the failure. Handle it or return it.
- **Clones to please the borrow checker.** Restructure ownership instead: borrow, move, or split the struct. Clone only data that needs two owners.
- **Untyped values.** `serde_json::Value`, `Box<dyn Any>` or a map of strings in place of a type moves the type check to run time. Define the type; untyped data lives only at the parse boundary.
- **Skipped error paths.** `unwrap` and `expect` are S6.
- **TypeScript.** `as` casts, `!` non-null assertions, `any` and `@ts-ignore` do the same. Narrow with a type guard, and take `unknown` at the boundary.

Two habits keep a change small. Touch only the lines the item needs: no reformatting, renaming or refactoring beside it; file a new issue for what you noticed. And write no compatibility code (shims, deprecated aliases, readers for old formats) for a release nobody runs yet.

## The checks and how to fix each

| Check | Finds | Severity in review | The fix |
|---|---|---|---|
| S1 | A file over 500 code lines, or a file already over it that grew | Blocks | Find the separate jobs the file does and move each, with the types and functions that serve it, into a module named for what it is |
| S2 | A top-level type, constant or static declared after the first top-level `impl` or function, outside the test module | Blocks | Move the declaration up into its section. If it sits low because only one function far below uses it, the file holds two responsibilities: apply S1's fix |
| S3 | New comment lines that are narration, change-log, step comments, commented-out code, or a TODO without a work-item id; diff only | Blocks | Delete the comment. Carry its meaning in a name or an extracted function. For a TODO, file the issue first and cite it |
| S4 | Implicit state machines: three or more `bool` fields in one type; a `state`, `status`, `phase`, `stage` or `mode` field typed as a string, integer or `bool`; `Option` fields whose presence is checked together | Blocks | An explicit state type (rule 3). For a true false positive, the reason in your report's decisions, showing every combination of the fields is a meaningful value |
| S5 | Nesting deeper than four levels | Warns | Early returns, an extracted function, a `match` on a tuple or on a state type |
| S6 | A panic path on a new line outside test code: `unwrap`, `expect`, `panic!`, `todo!`, `unimplemented!`, `unreachable!`, indexing or slicing that panics on short input, `process::exit`; in scripts `process.exit`; diff only | Blocks | A typed error with its code that the caller handles; `get`, `split_first` or a slice pattern for input of unknown length; a type that cannot hold the impossible case |
| S7 | A hard-coded value in non-test code: a URL, host, domain, email or IP literal; a brand or vendor name; a number used as a bound, timeout, retry count, size, capacity or threshold; a colour or spacing literal; text a person reads written into markup | Blocks | The value in its data source, read through its loader (below) |

S7 takes the brand names from `brand/brand.toml` and the vendor names from the adapter, pack and integration manifests, so it finds exactly the names the data defines. Names reserved for documentation (`example.com`, `*.example`, `*.test`, `*.invalid`) and the documentation address ranges pass; loopback does not, outside tests. Zero, one and index arithmetic are never bounds. On the interface paths (`web/`, `site/`, the browser extension) UX1 and UX3 of `grdr-interface` report the colours, spacing, text and product name instead, so each literal is reported once.

Every value has a home outside the code, and code only reads it (owner instruction 26):

| The literal | Its home |
|---|---|
| URL, host, port, email, IP | A configuration key in the `grdr.config` schema, its default in the brand manifest. A self-hosted site sets its own and never depends on Loonaro's domain |
| Product or company name | `brand/brand.toml`, read through configuration, or `:grdr:brand` inside a message |
| Vendor name | The adapter, pack or manifest entry that integrates the vendor (rule 7) |
| Bound, timeout, retry budget, size, threshold | `limits.toml`, read through its typed loader; an operator-tunable setting goes in the configuration schema |
| Colour, spacing, font, motion | The design token by name |
| Text a person reads | A language token in `interface/strings/` (D-69), called through its generated accessor |

`references/checks.md` gives what each check counts and worked fixes.

Check each file against S1 to S7 as you finish it, not at the end: findings left for later pile up, and a blocking finding on your diff fails the review.

## Exemptions

There is no exemption file. A true false positive of S4, S6 or S7 is argued in your report's decisions with the reason (for S4, that every combination of the fields is a meaningful value and none records progress through a lifecycle; for S6 or S7, that no data source or typed error can hold it), and `eval-architecture` decides. "It would take long to redesign" is not a false positive. A new bound is a new `limits.toml` entry, which agents may not edit: file it as its own issue with the key, the value, the area and the code that reads it, and report `blocked` until it lands.

## Audit A01

A01 (implicit-state-machines, `docs/team/04` section 1) is the model-driven check behind S4. It finds lifecycles spread across flags, options, timestamps, counters and tasks that no field pattern catches.

- `eval-diff` runs it on every change whose diff adds or changes a type's fields, a status-like field, or a `match` on one. An A01 finding that survives the refuting pass is a blocking review finding, severity `major`, closed only by a type change (`closes-by = "type"`): never by a comment, a guard or a test alone.
- `garden-architecture` runs A01 over the whole tree when the owner asks. Each surviving finding becomes a repair issue that closes only by a type change.
- When you receive one, the fix is rule 3. Name the states, the events and the transition table first, then write the enum.

## Fix the core problem

The evaluator rubric (`eval-diff`) fails a criterion when it sees a symptom fix, a new guard around an implicit state, or a mechanical file split. These are the common traps:

| Finding | Papering over (fails review) | Fixing the core problem |
|---|---|---|
| S1, file too long | Moving the second half into `foo_part2.rs`, `helpers.rs` or `types.rs` | Splitting along responsibilities, so each module has one job and its own name |
| S4, three booleans | A fourth flag, an assertion that two are never both true, a comment listing the legal combinations | One enum whose variants are the legal combinations |
| S4, `status: String` | Validating the string, or a `const` per value | An enum; data valid in one status moves into that variant |
| S3, narration comment | Rewording it until the pattern stops matching | Deleting it and naming the thing it described |
| S5, deep nesting | Joining conditions with `&&` until the depth passes | Early returns, or a function per case |
| S6, `unwrap` | `unwrap_or_default()` or a made-up fallback that hides a real failure | A typed error the caller handles, or a type in which the case cannot arise |
| S7, literal bound or host | Moving the literal into a `const`, building the URL from literal pieces with `format!`, spelling the name differently | The value in its data source, read through its loader |
| A failing gate | An `#[allow]`, an exemption argued for a real finding, a skipped test | The design change the gate is asking for |

If the design change reaches outside your write set (another crate owns the type, or the fix belongs in a shared module), do not build a local workaround. Report the finding, file a new issue that proposes the change (skill `grdr-handoff`), and name it in your report.
