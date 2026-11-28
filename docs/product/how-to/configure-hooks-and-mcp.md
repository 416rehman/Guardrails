---
id: configure-hooks-and-mcp
type: how-to
personas:
  - developer
  - operator
shapes:
  - solo
  - team
covers:
  - hook
  - mcp-proxy
  - cli
owner_squad: agent-adapters
stability: beta
title: Configure Agent Hooks and MCP Proxy
---

# Configure Agent Hooks and MCP Proxy

Guardrails ADR enforces policies synchronously at tool boundaries using `grdr-hook` and `grdr mcp-proxy`. Both components fail closed whenever local policy evaluation cannot complete within the latency watchdog budget.

## Preview and Install Harness Hooks

Inspect current hook status without touching local settings files:

```powershell
cargo run -p grdr -- hook status --agent claude-code
cargo run -p grdr -- hook install --agent claude-code
```

Without `--apply`, `grdr hook install` previews the exact configuration diff and backup path. Pass `--apply` only when you want to write the backup journal and install the hook.

To revert cleanly from the backup journal:

```powershell
cargo run -p grdr -- hook uninstall --agent claude-code
```

## Wrap Stdio MCP Servers with `grdr mcp-proxy`

Wrap any stdio JSON-RPC MCP server so every `tools/call` invocation passes local policy checks and tool-pinning verification:

```powershell
cargo run -p grdr -- mcp-proxy --server-name filesystem --agent claude-code -- your-mcp-server-binary
```

Replace the trailing command with your MCP server executable and arguments. If tool schemas drift from pinned manifests, `grdr mcp-proxy` blocks execution and writes a signed receipt.

## Verify Hash-Chained Local Receipts

Verify local JSONL receipt integrity after running hook or MCP evaluations:

```powershell
cargo run -p grdr -- audit verify --json
```
