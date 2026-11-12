# ADR-0022: Errors carry registered codes, logs take only `LogSafe` values, and every bound is a named limit

- Status: proposed
- Date: 2026-11-11
- Decided by: chief architect
- Spine: P8, P9, P14, section 5
- Requires: nothing
- RFC: not required: restates P8, P9 and section 5 as repository mechanism
- Work items: [WI-0001], [WI-0003], [WI-0014]

## Context
A panic in a sensor is an outage on someone else's machine, an unbounded buffer is a denial of service, and a log line with content in it is a privacy breach (owner instructions 15 and 26; review l07).

## Decision
No crate has a panic path in non-test code: every fallible path returns a typed error with a `GRDR-<AREA>-<NNNN>` code from the registry in `schema/`. Log macros accept only values that implement `LogSafe`, so content-class data cannot be logged. Every bound, timeout and threshold is a named key in `limits.toml` (`.agents/kit/limits.toml` for the kit) and no numeric bound is a literal in code. Layers 0 to 2 and privileged crates use checked or saturating arithmetic.

## Enforced by
The workspace lints in the root `Cargo.toml` (deny `unwrap`, `expect`, `panic!`, `todo!`, `unimplemented!`, `unreachable!`, unchecked indexing, `process::exit`) and Clippy's disallowed-methods list; structure checks S6 and S7 in `post-edit`, `stop-gate` and gate V20; the `limits.toml` check, which fails a missing or unknown key; `grdr-schema-lint` for the error-code registry ([WI-0014]).

## Consequences
Every failure has a code a person can search for and a declared outcome. Adding a bound means adding a key first.

## Alternatives rejected
- Panics caught at a supervisor boundary: state is lost and the cause is not typed.
- Redaction at the log sink: it runs after the data has left the type system.

## Revisit when
Never as a rule; an exemption is an entry in `quality/hardcoded-exemptions.toml` through a protected change that `eval-architecture` agrees to.
