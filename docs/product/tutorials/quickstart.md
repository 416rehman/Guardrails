---
id: quickstart
type: tutorial
personas:
  - developer
  - operator
shapes:
  - solo
  - team
  - self-hosted
covers:
  - cli
  - grdr-server
  - grdr-daemon
  - grdr-hook
owner_squad: platform
stability: beta
title: Quickstart
---

# Quickstart

Run Guardrails ADR locally on Windows, macOS, or Linux in under five minutes.

## 1. Build the Console and Operator Frontends

```powershell
pnpm --dir web install --frozen-lockfile
pnpm --dir web run build
```

This builds the customer Console in `web/dist/` and the isolated Operator interface in `web/dist-operator/`.

## 2. Start `grdr-server`

Launch the split control-plane host with distinct Console (`--bind`) and Operator (`--operator-bind`) socket bindings:

```powershell
cargo run -p grdr-server -- --bind 127.0.0.1:8787 --operator-bind 127.0.0.1:8788 --web-dir web/dist --operator-web-dir web/dist-operator --demo-seed --data-dir ./grdr-data
```

- Customer Console and Connect RPC API (`grdr.api.*`): `http://127.0.0.1:8787/`
- Isolated Operator UI and Operator Connect RPC (`grdr.api.operator.v1alpha1.OperatorService`): `http://127.0.0.1:8788/`

## 3. Run Endpoint Discovery and Daemon Self-Test

Verify the OS peer-authenticated IPC supervisor (`grdr-daemon`) without modifying host configuration:

```powershell
cargo run -p grdr-daemon -- --self-test
```

Discover installed AI coding harnesses and MCP servers from local declarative manifests:

```powershell
cargo run -p grdr -- scan
cargo run -p grdr -- doctor
```

## 4. Evaluate Actions and Hook Payloads

Check how active Essentials rules evaluate a sensitive configuration write:

```powershell
cargo run -p grdr -- check --action file.write --target .claude/settings.json
```

Test `grdr-hook` directly via stdin JSON:

```powershell
'{"session_id":"s1","tool_name":"Write","tool_input":{"file_path":".claude/settings.json"}}' | cargo run -p grdr-hook
```

## Next Steps

- [Configure Hooks and MCP Proxy](../how-to/configure-hooks-and-mcp.md)
- [Server Storage Profiles and Preflight](../operate/server-profiles.md)
