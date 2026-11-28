// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import {
  ActionBlocked,
  ApprovalRequired,
  GuardrailsError,
  canonicalDeclarationJson,
  parseFailurePolicy,
  parseVerdict,
} from "./types.ts";
import type {
  AgentDeclaration,
  DecideInput,
  DecisionReceipt,
  FailurePolicy,
  Verdict,
} from "./types.ts";

export interface ClientConfig {
  endpoint: string;
  token?: string;
  timeoutMs?: number;
  onUnreachable?: FailurePolicy;
  declarationDir?: string;
  userAgent?: string;
}

export type LocalFloorEvaluator = (attempt: DecideInput) => DecisionReceipt | Promise<DecisionReceipt>;

export class SessionHandle {
  private readonly client: GuardrailsClient;
  readonly agentName: string;
  readonly sessionId: string;

  constructor(client: GuardrailsClient, agentName: string, sessionId: string) {
    this.client = client;
    this.agentName = agentName;
    this.sessionId = sessionId;
  }

  async decide(
    actionClass: string,
    target: string,
    options?: { controlPoint?: string; summary?: string; raiseOnDeny?: boolean },
  ): Promise<DecisionReceipt> {
    return this.client.decide(
      {
        agent_name: this.agentName,
        action_class: actionClass,
        target,
        control_point: options?.controlPoint ?? "gateway",
        session_id: this.sessionId,
        summary: options?.summary,
      },
      { raiseOnDeny: options?.raiseOnDeny ?? false },
    );
  }
}

export class GuardrailsClient {
  private readonly config: Required<ClientConfig>;
  private readonly localFloor?: LocalFloorEvaluator;
  private readonly declarations: AgentDeclaration[] = [];

  constructor(config?: Partial<ClientConfig>, localFloor?: LocalFloorEvaluator) {
    const envPolicy = parseFailurePolicy(process.env.GRDR_ON_UNREACHABLE);
    this.config = {
      endpoint: (config?.endpoint ?? process.env.GRDR_ENDPOINT ?? "http://127.0.0.1:8787").replace(
        /\/+$/,
        "",
      ),
      token: config?.token ?? process.env.GRDR_TOKEN ?? "",
      timeoutMs: config?.timeoutMs ?? 5000,
      onUnreachable: config?.onUnreachable ?? envPolicy,
      declarationDir: config?.declarationDir ?? process.env.GRDR_DECLARATION_DIR ?? "",
      userAgent: config?.userAgent ?? "grdr-sdk-ts/0.1.0",
    };
    this.localFloor = localFloor;
  }

  declare(declaration: AgentDeclaration): string {
    this.declarations.push(declaration);
    const canonical = canonicalDeclarationJson(declaration);
    if (this.config.declarationDir) {
      fs.mkdirSync(this.config.declarationDir, { recursive: true });
      const safeName = declaration.agent_name.replace(/[^a-zA-Z0-9_-]/g, "_");
      const outPath = path.join(this.config.declarationDir, `${safeName}.declaration.json`);
      fs.writeFileSync(outPath, `${canonical}\n`, "utf8");
    }
    return canonical;
  }

  session(agentName: string, sessionId?: string): SessionHandle {
    const sid = sessionId ?? `sess_${crypto.randomUUID().replace(/-/g, "").slice(0, 16)}`;
    return new SessionHandle(this, agentName, sid);
  }

  recordedDeclarations(): readonly AgentDeclaration[] {
    return this.declarations;
  }

  async decide(
    attempt: DecideInput,
    options?: { raiseOnDeny?: boolean },
  ): Promise<DecisionReceipt> {
    const receipt = await this.postGuard(attempt);
    if (options?.raiseOnDeny) {
      if (receipt.verdict === "ask") {
        throw new ApprovalRequired(receipt);
      }
      if (receipt.verdict === "block") {
        throw new ActionBlocked(receipt);
      }
    }
    return receipt;
  }

  async report(
    agentName: string,
    actionClass: string,
    target: string,
    verdict: Verdict,
    options?: { sessionId?: string; summary?: string },
  ): Promise<{ accepted: number }> {
    const body = {
      device_id: process.env.GRDR_DEVICE_ID ?? "sdk-local",
      attempts: [
        {
          id: `att_${crypto.randomUUID().replace(/-/g, "").slice(0, 16)}`,
          session_id: options?.sessionId ?? "",
          agent_name: agentName,
          action_class: actionClass,
          target,
          summary: options?.summary ?? "",
        },
      ],
      receipts: [
        {
          id: `rcpt_${crypto.randomUUID().replace(/-/g, "").slice(0, 16)}`,
          verdict,
          rule_id: "sdk.post-report",
          reason: options?.summary ?? "post-action telemetry",
        },
      ],
    };
    const res = await this.postJson("/v1/ingest", body);
    const acceptedRaw = res.accepted;
    return { accepted: typeof acceptedRaw === "number" ? acceptedRaw : 0 };
  }

  guardFn<TArgs extends unknown[], TResult>(
    spec: {
      agentName: string;
      actionClass: string;
      target: string | ((...args: TArgs) => string);
      controlPoint?: string;
      sessionId?: string;
    },
    fn: (...args: TArgs) => Promise<TResult> | TResult,
  ): (...args: TArgs) => Promise<TResult> {
    return async (...args: TArgs): Promise<TResult> => {
      const target = typeof spec.target === "function" ? spec.target(...args) : spec.target;
      await this.decide(
        {
          agent_name: spec.agentName,
          action_class: spec.actionClass,
          target,
          control_point: spec.controlPoint ?? "gateway",
          session_id: spec.sessionId,
          summary: fn.name || "guarded_action",
        },
        { raiseOnDeny: true },
      );
      return await fn(...args);
    };
  }

  private async postGuard(attempt: DecideInput): Promise<DecisionReceipt> {
    try {
      const res = await this.postJson("/v1/guard", {
        agent_name: attempt.agent_name,
        action_class: attempt.action_class,
        control_point: attempt.control_point ?? "gateway",
        target: attempt.target,
        session_id: attempt.session_id,
        device_id: attempt.device_id,
        summary: attempt.summary,
        metadata: attempt.metadata,
      });
      const candidate =
        res.receipt !== null && typeof res.receipt === "object"
          ? (res.receipt as Record<string, unknown>)
          : res;
      return {
        id: typeof candidate.id === "string" ? candidate.id : "",
        verdict: parseVerdict(typeof candidate.verdict === "string" ? candidate.verdict : "block"),
        rule_id:
          typeof candidate.ruleId === "string"
            ? candidate.ruleId
            : typeof candidate.rule_id === "string"
              ? candidate.rule_id
              : "",
        reason: typeof candidate.reason === "string" ? candidate.reason : "",
        session_id:
          typeof candidate.sessionId === "string"
            ? candidate.sessionId
            : typeof candidate.session_id === "string"
              ? candidate.session_id
              : "",
        mode: typeof candidate.mode === "string" ? candidate.mode : "",
        degraded: candidate.degraded === true,
      };
    } catch (err) {
      if (err instanceof GuardrailsError && err.message.startsWith("gateway rejected")) {
        throw err;
      }
      return this.handleUnreachable(attempt, err);
    }
  }

  private async postJson(
    reqPath: string,
    payload: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.config.timeoutMs);
    try {
      const headers: Record<string, string> = {
        "Content-Type": "application/json",
        Accept: "application/json",
        "User-Agent": this.config.userAgent,
      };
      if (this.config.token) {
        headers.Authorization = `Bearer ${this.config.token}`;
      }
      const resp = await fetch(`${this.config.endpoint}${reqPath}`, {
        method: "POST",
        headers,
        body: JSON.stringify(payload),
        redirect: "manual",
        signal: controller.signal,
      });
      const text = await resp.text();
      if ((resp.status >= 300 && resp.status < 500) || resp.type === "opaqueredirect") {
        throw new GuardrailsError(`gateway rejected request (${resp.status || 302}): ${text}`);
      }
      if (!resp.ok) {
        throw new Error(`HTTP ${resp.status}: ${text}`);
      }
      const parsed: unknown = text ? JSON.parse(text) : {};
      if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new GuardrailsError("expected JSON object from gateway");
      }
      return parsed as Record<string, unknown>;
    } finally {
      clearTimeout(timer);
    }
  }

  private async handleUnreachable(attempt: DecideInput, err: unknown): Promise<DecisionReceipt> {
    const detail = err instanceof Error ? err.message : String(err);
    if (this.config.onUnreachable === "fail_open") {
      return {
        id: `degraded_${crypto.randomUUID().replace(/-/g, "").slice(0, 12)}`,
        verdict: "allow",
        rule_id: "sdk.fail_open",
        reason: `endpoint unreachable (${detail}); allowed under GRDR_ON_UNREACHABLE=fail_open`,
        session_id: attempt.session_id ?? "",
        mode: "Off",
        degraded: true,
      };
    }
    if (this.config.onUnreachable === "local_floor" && this.localFloor) {
      return await this.localFloor(attempt);
    }
    return {
      id: `closed_${crypto.randomUUID().replace(/-/g, "").slice(0, 12)}`,
      verdict: "block",
      rule_id:
        this.config.onUnreachable === "local_floor"
          ? "sdk.local_floor.no_table"
          : "sdk.fail_closed",
      reason: `endpoint unreachable (${detail}); blocked`,
      session_id: attempt.session_id ?? "",
      mode: "Block",
      degraded: true,
    };
  }
}
