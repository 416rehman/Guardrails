# Guardrails ADR

Guardrails ADR is an open-source agent detection and response (ADR) platform (`grdr`). It discovers AI coding agents and MCP servers on endpoints via declarative manifests, evaluates tool and action requests locally against Cedar policies and Essentials packs, records cryptographic decision receipts, and serves separate Console and Operator control planes over Connect/Protobuf RPCs.

## Components

- **API Server & Split Web Hosts (`programs/grdr-server`):** Serves typed Connect/Protobuf services (`grdr.api.overview.v1alpha1.OverviewService`, `grdr.api.inventory.v1alpha1.InventoryService`, `grdr.api.verdict.v1alpha1.VerdictService`, `grdr.api.policy.v1alpha1.PolicyService`, `grdr.api.activity.v1alpha1.SessionService`, `grdr.api.tenancy.v1alpha1.UserService`, `grdr.api.response.v1alpha1.ResponseService`, and `grdr.api.surfaces.v1alpha1.SurfaceService`) on `--bind`, alongside an isolated Operator plane (`grdr.api.operator.v1alpha1.OperatorService` plus scoped audit/overview reads) on a distinct `--operator-bind` socket. Supports `embedded` (SQLite + local blob + `grdr-bus-log` / `sqlite-log`), `ha` (PostgreSQL 18 + object store + `grdr-bus-log` / `postgresql-log`), and `distributed` (PostgreSQL 18 + NATS JetStream + object store) storage profiles.
- **Endpoint Agent Daemon (`programs/grdr-daemon`):** Cross-platform privileged supervisor exposing OS peer-authenticated IPC (`Unix domain sockets` on Linux/macOS, named pipes on Windows) via `--decide-endpoint` and `--local-endpoint` with zero HTTP/TCP listeners, supervising `grdr-engine`, `grdr-uplink`, and `grdr-updater`, backed by an Ed25519-verified local floor cache.
- **Endpoint CLI, Hook Shim & MCP Proxy (`programs/grdr`, `programs/grdr-hook`):** Fail-closed `PreToolUse` hook enforcement, stdio JSON-RPC MCP wrapper (`grdr mcp-proxy`), diagnostics (`grdr doctor`), compliance evidence export (`grdr comply`), air-gap packaging/verification (`grdr airgap`), enrollment (`grdr join` / `grdr leave`), and server preflight/migration (`grdr server preflight`, `grdr server migrate`).
- **Multi-Cell SaaS Router & Billing Core (`crates/grdr-saas`):** Region-pinned 4096-bucket shard router, signed route/redirect tickets, lossless organisation migration bundles (`lake/` + `audit/` + revocation watermarks), idempotent usage ledger (35-day acceptance window), invoice adapters (`StatementFile`, `StripeMeter`, `KillBill`), and launch/economics gates.
- **Web Console & Operator UI (`web/`):** React 19 + TypeScript + Vite workspace (`pnpm`) building the customer Console (`web/dist/`) and isolated Operator UI (`web/dist-operator/`) from shared tokens and UI primitives (`web/packages/`).
- **Documentation Portal (`website/`, `docs/`):** Standalone offline-searchable Docusaurus 3 + Pagefind documentation site backed by Diataxis product guides (`docs/product/`), operational runbooks (`docs/runbooks/`), extending guides (`docs/extending/`), and machine-readable lifecycle contracts (`lifecycle.toml`, `contracts/upgrade-path.json`).

## Prerequisites

- Stable Rust toolchain matching workspace `Cargo.toml` (`cargo`, `rustfmt`, `clippy`, `cargo-deny`)
- Node.js 22+ and `pnpm` (`packageManager` pinned in `web/package.json` and `website/package.json`)

## Quickstart

### 1. Build the Console and Operator Web Frontends

```powershell
pnpm --dir web install --frozen-lockfile
pnpm --dir web run build
```

This builds the customer Console bundle into `web/dist/` and the isolated Operator bundle into `web/dist-operator/`.

### 2. Start `grdr-server` (Connect RPC + Split Console/Operator Hosts)

```powershell
cargo run -p grdr-server -- `
  --bind 127.0.0.1:8787 `
  --operator-bind 127.0.0.1:8788 `
  --web-dir web/dist `
  --operator-web-dir web/dist-operator `
  --demo-seed `
  --data-dir ./grdr-data
```

Open `http://127.0.0.1:8787/` for the customer Console and `http://127.0.0.1:8788/` for the isolated Operator UI.
During frontend development, run `pnpm --dir web run dev` (port `5173`, proxies `/grdr.*` to `127.0.0.1:8787`) or `pnpm --dir web run dev:operator` (port `5174`, proxies `/grdr.*` to `127.0.0.1:8788`).

### 3. Self-Test or Run the Endpoint Daemon (`grdr-daemon`)

Verify the OS peer-authenticated IPC stack without changing local host configuration:

```powershell
cargo run -p grdr-daemon -- --self-test
```

Run the endpoint daemon connected to a local server:

```powershell
cargo run -p grdr-daemon -- --profile user --data-dir ./grdr-daemon-data --server http://127.0.0.1:8787
```

### 4. CLI Discovery, Hook Check, and Diagnostics

```powershell
cargo run -p grdr -- scan
cargo run -p grdr -- doctor
cargo run -p grdr -- check --action file.write --target .claude/settings.json
cargo run -p grdr -- hook status --agent claude-code
```

Evaluate a `PreToolUse` JSON event directly via stdin using `grdr-hook`:

```powershell
'{"session_id":"s1","tool_name":"Write","tool_input":{"file_path":".claude/settings.json"}}' | cargo run -p grdr-hook
```

### 5. Build and Search the Offline Documentation Portal (`website/`)

```powershell
pnpm --dir website install --frozen-lockfile
pnpm --dir website run build
```

## Verification

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --locked --all-targets -- -D warnings
cargo test --workspace --locked
cargo deny --config security/deny.toml check
node scripts/check-architecture.mjs
node scripts/licence-lint.mjs
node scripts/check-docs-gen.mjs --check
node scripts/check-docs.mjs
pnpm --dir web run typecheck
pnpm --dir web run test
pnpm --dir web run build
pnpm --dir website run build
```

## Frequently Asked Questions

### What is Loonaro Guardrails?

Guardrails ADR (`grdr`) is an open-source, local-first agent detection and response platform. It protects developer workstations, CI runners, and fleet endpoints where AI coding agents and MCP servers invoke tools, files, shell commands, and network destinations.

### What problem does Guardrails solve?

Teams often rely on markdown rules or advisory prompts that agents and scripts can bypass under context drift or prompt injection. Guardrails enforces typed Cedar policies and signed Essentials packs synchronously at hook, MCP proxy, and OS sensor boundaries with tamper-evident decision receipts.

### How does Guardrails integrate with local agents, endpoints, and CI?

The CLI (`grdr`), hook shim (`grdr-hook`), and privileged daemon (`grdr-daemon`) enforce policies locally over OS peer-authenticated IPC and sync receipts over Connect/Protobuf RPCs with `grdr-server`. Repository checks run the same contracts in CI via `cargo test --workspace`, `pnpm`, `scripts/check-architecture.mjs`, and `scripts/licence-lint.mjs`.

### Is Guardrails ADR open source?

Yes. Code and content ship under `Apache-2.0` (`BPF` kernel programs under `GPL-2.0-only OR BSD-2-Clause`, documentation under `Apache-2.0 OR CC-BY-4.0`), validated continuously by `scripts/licence-lint.mjs` against `security/supply-chain/licences.toml`. Commercial tiers add hosted multi-cell operations and SLA support without withholding security, SSO, RBAC, or audit capabilities.

## Documentation & Governance Map

- Product Guides: [docs/product/tutorials/quickstart.md](docs/product/tutorials/quickstart.md)
- Operational Runbooks: [docs/runbooks/RB-INDEX.md](docs/runbooks/RB-INDEX.md)
- Extending & Port Adapters: [docs/extending/README.md](docs/extending/README.md)
- Release Lifecycle & Upgrade Paths: [lifecycle.toml](lifecycle.toml), [upgrade-path.json](upgrade-path.json), and [contracts/upgrade-path.json](contracts/upgrade-path.json)
- Governance, Contributing, CoC, Security & RFCs: [GOVERNANCE.md](GOVERNANCE.md), [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), [SECURITY.md](SECURITY.md), [rfcs/README.md](rfcs/README.md)
- Architecture Spine (Contributors): [docs/design/00-decisions.md](docs/design/00-decisions.md)
- Machine-Readable LLM Index: [llms.txt](llms.txt)
