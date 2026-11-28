// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import * as crypto from "node:crypto";

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly reason: string;
  readonly details: Record<string, unknown>;

  constructor(
    status: number,
    code: string,
    reason: string,
    message: string,
    details: Record<string, unknown>,
  ) {
    super(`HTTP ${status} [${code}/${reason}]: ${message}`);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.reason = reason;
    this.details = details;
  }
}

export interface PageInfo {
  nextPageToken?: string;
  prevPageToken?: string;
  totalSizeEstimate?: number;
  hasMore?: boolean;
}

export class GrdrApiClient {
  private readonly baseUrl: string;
  private readonly token: string;
  private readonly userAgent: string;
  private readonly timeoutMs: number;
  private readonly etags = new Map<string, string>();

  constructor(opts: {
    baseUrl: string;
    token?: string;
    timeoutMs?: number;
    userAgent?: string;
  }) {
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.token = opts.token ?? "";
    this.timeoutMs = opts.timeoutMs ?? 10_000;
    this.userAgent = opts.userAgent ?? "grdr-api-ts/0.1.0";
  }

  async openApiSpec(): Promise<Record<string, unknown>> {
    return (await this.request("GET", "/v1/openapi.json")).body;
  }

  async health(): Promise<Record<string, unknown>> {
    return (await this.request("GET", "/v1/health")).body;
  }

  async overview(): Promise<Record<string, unknown>> {
    return (await this.request("GET", "/v1/overview")).body;
  }

  async guard(payload: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.mutate("POST", "/v1/guard", payload);
  }

  async getConditional(
    reqPath: string,
  ): Promise<{ modified: boolean; body: Record<string, unknown> | null }> {
    const etag = this.etags.get(reqPath);
    const res = await this.request(
      "GET",
      reqPath,
      undefined,
      etag ? { "If-None-Match": etag } : undefined,
    );
    if (res.status === 304) {
      return { modified: false, body: null };
    }
    const nextEtag = res.headers.get("etag");
    if (nextEtag) {
      this.etags.set(reqPath, nextEtag);
    }
    return { modified: true, body: res.body };
  }

  async *iterCollection<T = Record<string, unknown>>(
    reqPath: string,
    itemsField: string,
    opts?: { pageSize?: number; filter?: string; orderBy?: string },
  ): AsyncGenerator<T> {
    let pageToken = "";
    while (true) {
      const qs = new URLSearchParams();
      qs.set("page_size", String(opts?.pageSize ?? 50));
      if (pageToken) {
        qs.set("page_token", pageToken);
      }
      if (opts?.filter) {
        qs.set("filter", opts.filter);
      }
      if (opts?.orderBy) {
        qs.set("order_by", opts.orderBy);
      }
      const { body } = await this.request("GET", `${reqPath}?${qs.toString()}`);
      const items = body[itemsField];
      if (Array.isArray(items)) {
        for (const item of items) {
          yield item as T;
        }
      }
      const pageInfo = (body.pageInfo ?? body.page_info ?? {}) as PageInfo;
      const next = pageInfo.nextPageToken ?? "";
      if (!next) {
        break;
      }
      pageToken = next;
    }
  }

  async listDevices(opts?: {
    pageSize?: number;
    filter?: string;
  }): Promise<Array<Record<string, unknown>>> {
    const out: Array<Record<string, unknown>> = [];
    for await (const item of this.iterCollection<Record<string, unknown>>(
      "/v1/devices",
      "devices",
      opts,
    )) {
      out.push(item);
    }
    return out;
  }

  async createRule(
    payload: Record<string, unknown>,
    idempotencyKey?: string,
  ): Promise<Record<string, unknown>> {
    return this.mutate("POST", "/v1/rules", payload, idempotencyKey);
  }

  async createPolicyChange(
    payload: Record<string, unknown>,
    idempotencyKey?: string,
  ): Promise<Record<string, unknown>> {
    return this.mutate("POST", "/v1/policy-changes", payload, idempotencyKey);
  }

  async checkPolicyChange(changeId: string): Promise<Record<string, unknown>> {
    return this.mutate("POST", `/v1/policy-changes/${encodeURIComponent(changeId)}:check`, {});
  }

  async simulatePolicyChange(changeId: string): Promise<Record<string, unknown>> {
    return this.mutate("POST", `/v1/policy-changes/${encodeURIComponent(changeId)}:simulate`, {});
  }

  async applyPolicyChange(
    changeId: string,
    idempotencyKey?: string,
  ): Promise<Record<string, unknown>> {
    return this.mutate(
      "POST",
      `/v1/policy-changes/${encodeURIComponent(changeId)}:apply`,
      {},
      idempotencyKey,
    );
  }

  async approvePolicyChange(
    changeId: string,
    payload: Record<string, unknown> = {},
  ): Promise<Record<string, unknown>> {
    return this.mutate(
      "POST",
      `/v1/policy-changes/${encodeURIComponent(changeId)}:approve`,
      payload,
    );
  }

  async getGitopsBinding(): Promise<Record<string, unknown>> {
    return (await this.request("GET", "/v1/gitops-binding")).body;
  }

  async upsertGitopsBinding(payload: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.mutate("PUT", "/v1/gitops-binding", payload);
  }

  async createWebhookEndpoint(
    payload: Record<string, unknown>,
    idempotencyKey?: string,
  ): Promise<Record<string, unknown>> {
    return this.mutate("POST", "/v1/webhook-endpoints", payload, idempotencyKey);
  }

  async mutate(
    method: "POST" | "PUT" | "PATCH" | "DELETE",
    reqPath: string,
    payload: Record<string, unknown>,
    idempotencyKey?: string,
  ): Promise<Record<string, unknown>> {
    return (
      await this.request(method, reqPath, payload, {
        "Idempotency-Key": idempotencyKey ?? crypto.randomUUID(),
      })
    ).body;
  }

  async request(
    method: string,
    reqPath: string,
    payload?: Record<string, unknown>,
    extraHeaders?: Record<string, string>,
  ): Promise<{ status: number; body: Record<string, unknown>; headers: Headers }> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const headers: Record<string, string> = {
        Accept: "application/json",
        "User-Agent": this.userAgent,
        ...extraHeaders,
      };
      if (this.token) {
        headers.Authorization = `Bearer ${this.token}`;
      }
      let serialized: string | undefined;
      if (payload !== undefined) {
        serialized = JSON.stringify(payload);
        headers["Content-Type"] = "application/json";
      }
      const resp = await fetch(`${this.baseUrl}${reqPath}`, {
        method,
        headers,
        body: serialized,
        redirect: "manual",
        signal: controller.signal,
      });
      if (resp.status === 304) {
        return { status: 304, body: {}, headers: resp.headers };
      }
      if ((resp.status >= 300 && resp.status < 400) || resp.type === "opaqueredirect") {
        throw new ApiError(
          resp.status || 302,
          "redirect_blocked",
          "REDIRECT_BLOCKED",
          "HTTP redirect blocked to protect Authorization header",
          { location: resp.headers.get("location") ?? "" },
        );
      }
      const text = await resp.text();
      const parsed: unknown = text ? JSON.parse(text) : {};
      const obj =
        parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)
          ? (parsed as Record<string, unknown>)
          : { value: parsed };
      if (!resp.ok) {
        throw new ApiError(
          resp.status,
          typeof obj.code === "string" ? obj.code : "",
          typeof obj.reason === "string" ? obj.reason : "",
          typeof obj.message === "string" ? obj.message : text,
          obj,
        );
      }
      return { status: resp.status, body: obj, headers: resp.headers };
    } finally {
      clearTimeout(timer);
    }
  }
}
