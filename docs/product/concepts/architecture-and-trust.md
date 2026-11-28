---
id: architecture-and-trust
type: explanation
personas:
  - operator
  - auditor
  - extender
shapes:
  - solo
  - team
  - self-hosted
  - hosted
covers:
  - ipc
  - split-plane
  - assurance
owner_squad: architecture
stability: beta
title: Architecture and Trust Boundaries
---

# Architecture and Trust Boundaries

Guardrails ADR separates untrusted endpoint telemetry, customer tenant administration, and multi-tenant infrastructure operations across strict crate layers (`contracts/architecture.toml`) and network/IPC boundaries.

## Split Console and Operator Planes

`grdr-server` refuses to start if `--bind` and `--operator-bind` resolve to the same socket address:

- **Tenant Console Plane (`--bind`):** Hosts customer Web UI (`--web-dir`) and Connect/Protobuf RPC services (`grdr.api.overview.v1alpha1.OverviewService`, `InventoryService`, `VerdictService`, `PolicyService`, `SessionService`, `UserService`, `ResponseService`, and `SurfaceService`).
- **Operator Plane (`--operator-bind`):** Hosts isolated Operator UI (`--operator-web-dir`), `grdr.api.operator.v1alpha1.OperatorService` with explicit impersonation and break-glass receipts, plus scoped read-only `OverviewService` and `ResponseService` audit endpoints under separate bearer credentials (`--operator-token`).

## OS Peer-Authenticated Endpoint IPC

`grdr-daemon` exposes zero HTTP or TCP listeners. Local callers connect over OS peer-authenticated IPC (`Unix domain sockets` on Linux/macOS or named pipes on Windows) with process identity validation enforced before handling decisions or configuration reads.

## Dynamic Manifest-Driven Catalogue

Agent harnesses, detection fingerprints, compliance controls, and integrations are declared in signed packs and TOML/JSON/YAML manifests rather than static compiled enumerations. Supporting new agents or integrations requires no core engine recompilation.

## Assurance Levels (`AL0` to `AL4`)

Endpoints report an explicit **Assurance level** (`AL0` discovery-only through `AL4` signed OS/kernel enforcement with verified binary floor) derived from observed sensor, hook, and hardware key attestation evidence.
