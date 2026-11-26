// SPDX-License-Identifier: Apache-2.0
// Guardrails ADR default MCP Server and Tool Security pack (D-53).

@id("mcp.unpinned-server")
@class("mcp")
@max_mode("Ask")
@min_grade("G1")
@on_loss("step-up")
@message("Connecting to an MCP server without a pinned identity requires approval.")
@steer("Pin the MCP server digest or request explicit approval to connect.")
forbid (
  principal,
  action == Grdr::Action::"mcp.connect",
  resource is Grdr::McpServer
) when {
  !resource.identity_pinned
};

@id("mcp.unpinned-write-tool")
@class("mcp")
@max_mode("Ask")
@min_grade("G1")
@on_loss("step-up")
@message("Invoking an unpinned write-capable MCP tool requires approval.")
@steer("Pin tool schema manifest or request approval before mutating external state.")
forbid (
  principal,
  action == Grdr::Action::"mcp.call",
  resource is Grdr::McpTool
) when {
  !resource.manifest_pinned && resource.write_capable
};

@id("mcp.unextracted-args")
@class("mcp")
@max_mode("Ask")
@min_grade("G1")
@on_loss("step-up")
@message("State-mutating MCP call with unextracted arguments requires confirmation.")
@steer("Inspect tool payload arguments before approving execution.")
forbid (
  principal,
  action == Grdr::Action::"mcp.call",
  resource is Grdr::McpTool
) when {
  resource.write_capable && !context.args.extracted
};
