# ADR-0046: Trust-core coverage follows D-63's categories, and ADR-0010's coverage check reads privileged programs

- Status: proposed
- Date: 2026-11-23
- Decided by: chief architect
- Spine: D-20, D-63, P2
- Requires: #1580 (`grdr-archlint`), #1751 (`ARCH-004` privileged-program coverage check), #1749 (`grdr-os-service` and `grdr-peer-os` in `security/trust-core.paths`)
- RFC: not required: it reads D-63 as written and adds no category
- Work items: #1752, #1580, #1751, #1749

Partly supersedes [ADR-0010](ADR-0010-no-content-parser-in-a-privileged-closure.md) (one sentence under `Enforced by`: "`verify` also fails a privileged crate that `security/trust-core.paths` does not cover").

## Context
[ADR-0010](ADR-0010-no-content-parser-in-a-privileged-closure.md) turns D-20 into a repository check: no content parser sits in the dependency closure of a program whose metadata says `privilege = "privileged"`. Its `Enforced by` section also wrote: "`verify` also fails a privileged crate that `security/trust-core.paths` does not cover."

In `#2` (`[WI-0001]`), `[package.metadata.grdr]` assigned `privilege = "privileged"` to `grdr-daemon`, `grdr-sandbox-engine` and `grdr-sensor-linux-bpf` (each covered by [`security/trust-core.paths`](../../security/trust-core.paths)), and also to the layer 3 libraries `grdr-sensor-linux` and `grdr-store-local` because `grdr-daemon` links them, while layer 0 to 2 libraries carry `privilege = "none"`. Neither `grdr-sensor-linux` nor `grdr-store-local` is named in `D-63` ([`docs/design/00-decisions.md`](../design/00-decisions.md)) or in [`docs/design/02-threat-model.md`](../design/02-threat-model.md) Interfaces.

Reading ADR-0010's coverage sentence over every crate with `privilege = "privileged"` would either fail CI on `#2` or force libraries into `security/trust-core.paths` whenever a privileged program links them, expanding `D-63`'s closed category list without an RFC (`D-61`). Meanwhile, the ruling on `#1743` and `#1671` (`ADR-0045`) placed endpoint OS calls in `grdr-os-service` and IPC peer-authentication OS adapters in `grdr-peer-os` (`#1749`), inside existing `D-63` categories that `docs/design/02` Interfaces needed to name alongside `grdr-sandbox-engine`. Raised on `#2` and ruled by the chief architect on `#1580`.

## Decision
1. **Trust core follows D-63's categories, never `privilege` (R1).** A crate or path is trust core (`security/trust-core.paths`) because it holds code of a `D-63` category, as [`docs/design/02-threat-model.md`](../design/02-threat-model.md) Interfaces lists them, never because of its `[package.metadata.grdr]` `privilege` value.
2. **Role of `privilege` (R1).** On a layer 4 program (and the out-of-workspace `bpf/grdr-sensor-linux-bpf`), `privilege` records the privilege of the process (`privileged`, `sandboxed`, `untrusted`, `none`). On a library, `privilege` is derived from the programs that link it (layer 0 to 2 libraries carry `none`); `privileged` selects `#![deny(clippy::arithmetic_side_effects)]` ([`docs/design/03-system-architecture-and-modularity.md`](../design/03-system-architecture-and-modularity.md) section 10) and `ARCH-004`'s content-parser closure rule, and it does not move a crate into the trust-core review lane (`D-63`, `P2`, [ADR-0043](ADR-0043-lean-token-optimised-agent-team.md)).
3. **ADR-0010's coverage sentence superseded (R2).** This record supersedes one sentence of [ADR-0010](ADR-0010-no-content-parser-in-a-privileged-closure.md) under `Enforced by`, "`verify` also fails a privileged crate that `security/trust-core.paths` does not cover", with: **CI fails a layer 4 program whose metadata says `privilege = "privileged"` and that no glob of [`security/trust-core.paths`](../../security/trust-core.paths) covers.** A library carrying `privilege = "privileged"` outside `security/trust-core.paths` passes that coverage check, while `ARCH-004`'s closure rule and section 10 checked arithmetic still bind it.
4. **`docs/design/02` Interfaces list (R3).** The `security/trust-core.paths` sentence in [`docs/design/02-threat-model.md`](../design/02-threat-model.md) Interfaces names the crates added by `#1743` and `#1671`: `grdr-sandbox-engine` and `grdr-os-service` with `grdr-daemon` as the privileged core, and `grdr-peer-os` as the OS adapters of IPC peer authentication (`grdr-wire` holding the platform-neutral peer-authentication code). `grdr-sensor-linux` and `grdr-store-local` are not added. Kernel enforcement in `grdr-sensor-linux` still receives `D-63` trust-core review through `D-19`'s precondition (`S-12` and trust-core review) when enforcement lands, and its kernel programs under `bpf/**` remain in `security/trust-core.paths`.

## Enforced by
- `ARCH-004`'s coverage half in `grdr-archlint` (`#1751`, blocked by `#1580`), recorded in the mechanism column of the `ARCH-004` row in [`docs/design/03-system-architecture-and-modularity.md`](../design/03-system-architecture-and-modularity.md) section 2: fails a layer 4 crate with `privilege = "privileged"` covered by no glob in [`security/trust-core.paths`](../../security/trust-core.paths), and lets a privileged library outside the list pass (with must-fail and must-pass fixtures in `#1751`).
- `ARCH-004`'s content-parser closure rule (`#1580`) and section 10's `#![deny(clippy::arithmetic_side_effects)]`, which continue to bind `grdr-sensor-linux`, `grdr-store-local` and every `privileged` crate.
- [`security/trust-core.paths`](../../security/trust-core.paths) (`#1749` adds `crates/grdr-os-service/**` and `crates/grdr-peer-os/**`; `crates/grdr-sandbox-engine/**`, `programs/grdr-daemon/**`, `crates/grdr-wire/src/peer_auth/**` and `bpf/**` are already listed), read by [`.claude/risk-tiers.toml`](../../.claude/risk-tiers.toml) (`eval-tier`).
- Until `#1580` and `#1751` land in CI, evaluator review (`eval-review`, `eval-security`, `eval-tier`) checks privileged programs against `security/trust-core.paths` and `docs/design/03` section 2.

## Consequences
- `grdr-sensor-linux` and `grdr-store-local` retain `privilege = "privileged"` (checked arithmetic and `ARCH-004` closure checks) without entering `security/trust-core.paths` or taking the two-model trust-core lane on unrelated sensor or local-store changes.
- Linking a library from a privileged program selects its `privilege` role without expanding `D-63`'s category list through the dependency graph or turning CI red.
- Every layer 4 program marked `privilege = "privileged"` (such as `grdr-daemon`, `grdr-updater`, `grdr-approve`) must be covered by `security/trust-core.paths` before CI passes.
- `docs/design/02` Interfaces and `security/trust-core.paths` remain aligned on the `D-63` categories after `#1743`, `#1671` and `#1749`.

## Alternatives rejected
- **Apply ADR-0010's coverage check to every crate with `privilege = "privileged"`:** adds `grdr-sensor-linux` and `grdr-store-local` to `security/trust-core.paths` without an RFC (`D-61`) and makes `D-63` coverage follow dependency edges automatically.
- **Set `privilege = "none"` on `grdr-sensor-linux` and `grdr-store-local`:** drops section 10 checked arithmetic and weakens `ARCH-004` visibility on layer 3 libraries linked directly into `grdr-daemon`.

## Revisit when
- A privileged library holds code no `D-63` category names, but whose failure breaks a `D-63` property; that case is an RFC amending `D-63` in [`docs/design/00-decisions.md`](../design/00-decisions.md) (`D-61`).
- `#1751` is closed without landing, leaving `ARCH-004`'s privileged-program coverage check held by review alone.
