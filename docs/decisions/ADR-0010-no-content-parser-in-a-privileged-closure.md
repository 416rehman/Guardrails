# ADR-0010: No content parser in the dependency closure of a privileged program

- Status: proposed
- Date: 2026-11-11
- Decided by: chief architect
- Spine: D-20, D-63
- Requires: nothing
- RFC: not required: restates D-20 as repository mechanism
- Work items: [WI-0003]

## Context
The privileged core holds the floor policy and the actuators. A parser of untrusted content in that process turns any parser bug into a privileged one (brief 37; reviews c3, l01, l10).

## Decision
The privileged core handles fixed-layout events and precompiled tables only. All untrusted content is parsed in the sandboxed engine process. No crate that parses content (JSON, YAML, TOML, protobuf text, shell, HTTP, MCP, model protocols) is in the dependency closure of a program whose metadata says `privilege = "privileged"`.

## Enforced by
ARCH-004, which reads the privileged programs and the parser list from `architecture.toml` and fails on any such edge, direct or transitive; its fixture is `serde_json` under `grdr-daemon`. `verify` also fails a privileged crate that `security/trust-core.paths` does not cover.

## Consequences
The daemon and the engine talk in fixed-layout messages. Configuration the daemon needs is compiled to tables by an unprivileged step.

## Alternatives rejected
- Memory-safe parsers in the privileged process: memory safety does not stop logic bugs or resource exhaustion.
- Review instead of a lint: a transitive dependency adds a parser without any line of ours changing.

## Revisit when
A privileged function cannot be met with fixed-layout input; that case goes to an RFC.
