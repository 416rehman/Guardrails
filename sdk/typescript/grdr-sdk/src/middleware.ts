// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import type { GuardrailsClient } from "./client.ts";
import type { AgentDeclaration, DecisionReceipt } from "./types.ts";

export interface ToolCallRequest {
  name: string;
  args?: Record<string, unknown>;
  actionClass?: string;
}

export function declareFrameworkAgent(
  client: GuardrailsClient,
  opts: {
    agentName: string;
    framework: string;
    frameworkVersion?: string;
    tools?: AgentDeclaration["tools"];
    mcpServers?: AgentDeclaration["mcp_servers"];
    egressHosts?: string[];
    uncoveredHostedTools?: string[];
  },
): AgentDeclaration {
  const decl: AgentDeclaration = {
    schema: "grdr.agent-declaration.v1alpha1",
    agent_name: opts.agentName,
    framework: opts.framework,
    framework_version: opts.frameworkVersion ?? "0.1.0",
    control_point: "gateway",
    tools: opts.tools ?? [],
    mcp_servers: opts.mcpServers ?? [],
    egress_hosts: opts.egressHosts ?? [],
    control_paths: [`sdk:ts:${opts.framework}`, "gateway:/v1/guard"],
    covered_by: ["grdr-sdk"],
    uncovered_hosted_tools: opts.uncoveredHostedTools ?? [],
  };
  client.declare(decl);
  return decl;
}

export function langGraphToolMiddleware(
  client: GuardrailsClient,
  opts: {
    agentName: string;
    actionClassMap?: Record<string, string>;
    sessionId?: string;
  },
): <T>(req: ToolCallRequest, nextFn: (req: ToolCallRequest) => Promise<T> | T) => Promise<T> {
  return async <T>(
    req: ToolCallRequest,
    nextFn: (req: ToolCallRequest) => Promise<T> | T,
  ): Promise<T> => {
    const args = req.args ?? {};
    const target = stringField(args, ["target", "path", "command", "url"]) ?? req.name;
    const actionClass = req.actionClass ?? opts.actionClassMap?.[req.name] ?? "mcp.call";
    await client.decide(
      {
        agent_name: opts.agentName,
        action_class: actionClass,
        target,
        control_point: "gateway",
        session_id: opts.sessionId,
        summary: req.name,
      },
      { raiseOnDeny: true },
    );
    return await nextFn(req);
  };
}

export function openAiAgentsGuardrail(
  client: GuardrailsClient,
  opts: { agentName: string; hostedTools?: string[]; sessionId?: string },
): (call: {
  toolName: string;
  actionClass?: string;
  target: string;
}) => Promise<{ tripwireTriggered: boolean; receipt: DecisionReceipt }> {
  if (opts.hostedTools && opts.hostedTools.length > 0) {
    declareFrameworkAgent(client, {
      agentName: opts.agentName,
      framework: "openai-agents-sdk",
      uncoveredHostedTools: opts.hostedTools,
    });
  }
  return async (call) => {
    const receipt = await client.decide({
      agent_name: opts.agentName,
      action_class: call.actionClass ?? "mcp.call",
      target: call.target,
      control_point: "gateway",
      session_id: opts.sessionId,
      summary: call.toolName,
    });
    return {
      tripwireTriggered: receipt.verdict !== "allow",
      receipt,
    };
  };
}

export function claudeAgentSdkHook(
  client: GuardrailsClient,
  opts?: { agentName?: string; sessionId?: string },
): (event: {
  tool_name: string;
  tool_input?: Record<string, unknown>;
  action_class?: string;
  session_id?: string;
}) => Promise<{ permissionDecision: "allow" | "ask" | "deny"; permissionDecisionReason: string }> {
  const agentName = opts?.agentName ?? "claude-agent-sdk";
  return async (event) => {
    const input = event.tool_input ?? {};
    const target =
      stringField(input, ["file_path", "command", "url", "target"]) ?? event.tool_name;
    const receipt = await client.decide({
      agent_name: agentName,
      action_class: event.action_class ?? inferActionClass(event.tool_name),
      target,
      control_point: "hook",
      session_id: opts?.sessionId ?? event.session_id,
      summary: event.tool_name,
    });
    const decision =
      receipt.verdict === "allow" ? "allow" : receipt.verdict === "ask" ? "ask" : "deny";
    return {
      permissionDecision: decision,
      permissionDecisionReason: receipt.reason,
    };
  };
}

function stringField(obj: Record<string, unknown>, keys: string[]): string | undefined {
  for (const key of keys) {
    const val = obj[key];
    if (typeof val === "string" && val.length > 0) {
      return val;
    }
  }
  return undefined;
}

function inferActionClass(toolName: string): string {
  const lower = toolName.toLowerCase();
  if (lower === "bash" || lower === "shell" || lower === "exec") {
    return "exec";
  }
  if (lower === "read" || lower === "read_file") {
    return "file.read";
  }
  if (lower === "write" || lower === "edit" || lower === "write_file") {
    return "file.write";
  }
  if (lower === "delete" || lower === "rm") {
    return "file.delete";
  }
  if (lower === "webfetch" || lower === "fetch") {
    return "net.request";
  }
  return "mcp.call";
}
