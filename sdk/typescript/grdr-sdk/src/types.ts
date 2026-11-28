// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

export type Verdict = "allow" | "modify" | "ask" | "block";

export type FailurePolicy = "fail_closed" | "fail_open" | "local_floor";

export interface ToolDeclaration {
  name: string;
  action_class: string;
  description: string;
}

export interface McpServerDeclaration {
  name: string;
  transport: string;
  endpoint: string;
}

export interface AgentDeclaration {
  schema: string;
  agent_name: string;
  framework: string;
  framework_version: string;
  control_point: string;
  tools: ToolDeclaration[];
  mcp_servers: McpServerDeclaration[];
  egress_hosts: string[];
  control_paths: string[];
  covered_by: string[];
  uncovered_hosted_tools: string[];
}

export interface DecideInput {
  agent_name: string;
  action_class: string;
  target: string;
  control_point?: string;
  session_id?: string;
  device_id?: string;
  summary?: string;
  metadata?: Record<string, string | number | boolean>;
}

export interface DecisionReceipt {
  id: string;
  verdict: Verdict;
  rule_id: string;
  reason: string;
  session_id: string;
  mode: string;
  degraded: boolean;
}

export class GuardrailsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GuardrailsError";
  }
}

export class ApprovalRequired extends GuardrailsError {
  readonly receipt: DecisionReceipt;

  constructor(receipt: DecisionReceipt) {
    super(`Approval required (${receipt.rule_id || "policy"}): ${receipt.reason}`);
    this.name = "ApprovalRequired";
    this.receipt = receipt;
  }
}

export class ActionBlocked extends GuardrailsError {
  readonly receipt: DecisionReceipt;

  constructor(receipt: DecisionReceipt) {
    super(`Action blocked (${receipt.rule_id || "policy"}): ${receipt.reason}`);
    this.name = "ActionBlocked";
    this.receipt = receipt;
  }
}

export function parseVerdict(raw: string): Verdict {
  const normalized = raw.trim().toLowerCase().replace(/^verdict_/, "");
  if (
    normalized === "allow" ||
    normalized === "modify" ||
    normalized === "ask" ||
    normalized === "block"
  ) {
    return normalized;
  }
  throw new GuardrailsError(`unsupported verdict value: ${raw}`);
}

export function parseFailurePolicy(raw: string | undefined): FailurePolicy {
  if (!raw) {
    return "fail_closed";
  }
  const normalized = raw.trim().toLowerCase().replace(/-/g, "_");
  if (normalized === "fail_closed" || normalized === "fail_open" || normalized === "local_floor") {
    return normalized;
  }
  throw new GuardrailsError(`invalid GRDR_ON_UNREACHABLE value: ${raw}`);
}

function canonicalSort(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(canonicalSort);
  }
  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) =>
      a < b ? -1 : a > b ? 1 : 0,
    );
    const out: Record<string, unknown> = {};
    for (const [k, v] of entries) {
      out[k] = canonicalSort(v);
    }
    return out;
  }
  return value;
}

export function canonicalDeclarationJson(decl: AgentDeclaration): string {
  return JSON.stringify(canonicalSort(decl));
}
