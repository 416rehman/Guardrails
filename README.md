# Guardrails ADR

Guardrails ADR is an open-source agent detection and response (ADR) platform (`grdr`). It discovers AI coding agents and MCP servers on endpoints, evaluates tool and action requests locally against Essentials and custom policies, mints cryptographic decision receipts, and provides an operator Web Console for live sessions, graded approvals, findings triage, and scoped kill switches.

## Components implemented

- **API Server & Console Host (`programs/grdr-server`):** Axum REST JSON API (`/api/v1/*`), SSE real-time stream (`/api/v1/live`), in-memory or atomic disk storage (`--data-dir`), and static asset hosting for the built Web Console.
- **Endpoint Agent Daemon (`programs/grdr-daemon`):** Cross-platform local AI harness and MCP server scanner (`grdr-agents`), offline local decision evaluator (`/local/v1/decide`), and background uplink sync (`/api/v1/devices/checkin`, `/api/v1/events/batch`).
- **Hook Shim (`programs/grdr-hook`) & CLI (`programs/grdr`):** Low-latency Claude Code `PreToolUse` hook shim with offline Essentials fail-safe fallback, plus `grdr scan`, `grdr status`, `grdr check`, and `grdr install-hook`.
- **Policy Engine & Model (`crates/grdr-model`, `crates/grdr-core`, `crates/grdr-agents`):** Essentials ruleset (`Block` control-file edits and hook bypass flags, `Ask` credential reads / destructive deletes / privilege elevation, `Watch` egress and MCP writes), historical rule replay simulation, grant-scoped approvals, and assurance grading (`AL0` to `AL4`).
- **Web Console (`web/`):** React 19 + TypeScript + Vite operator interface across six views (`Home`, `Inventory`, `Sessions`, `Protect`, `Respond`, `Live Tester`) with inert quoting for untrusted strings, deliberate approval arming friction, and SSE live updates.

## Prerequisites

- Rust toolchain pinned in `rust-toolchain.toml` (`cargo`, `rustfmt`, `clippy`)
- Node.js 22+ and `pnpm` (`corepack enable` or `pnpm`)

## Quickstart

### 1. Build the Web Console

```powershell
pnpm --dir web install --frozen-lockfile
pnpm --dir web run build
```

### 2. Start the API Server (serves Web Console + REST/SSE API)

```powershell
cargo run -p grdr-server -- --bind 127.0.0.1:8787 --web-dir web/dist --demo-seed --data-dir ./grdr-data
```

Open `http://127.0.0.1:8787/` in your browser.
During frontend development, you can also run `pnpm --dir web dev` (proxies `/api` to `http://127.0.0.1:8787`).

### 3. Run the Endpoint Agent Daemon

```powershell
cargo run -p grdr-daemon -- --bind 127.0.0.1:8788 --server http://127.0.0.1:8787
```

This discovers local AI agents and MCP servers, checks in with the API server, caches active rules locally for offline decisions, and exposes the loopback decision API on `127.0.0.1:8788`.

### 4. CLI & Hook Shim

```powershell
cargo run -p grdr -- scan
cargo run -p grdr -- status
cargo run -p grdr -- check --action file.write --target .claude/settings.json
cargo run -p grdr -- install-hook --agent claude-code
```

Test the Claude Code hook shim directly:

```powershell
'{"session_id":"s1","tool_name":"Write","tool_input":{"file_path":".claude/settings.json"}}' | cargo run -p grdr-hook
```

## Verification

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --locked --all-targets -- -D warnings
cargo test --workspace --locked
cargo deny check
pnpm --dir web run typecheck
pnpm --dir web run test
pnpm --dir web run build
```

For architecture notes, see [`docs/design/00-decisions.md`](docs/design/00-decisions.md).
