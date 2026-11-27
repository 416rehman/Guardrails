// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import type {
  ActionClass,
  BrowserInspectRequest,
  BrowserTarget,
  BrowserVerdict,
  ManagedExtensionConfig,
  NativeHostStatus,
} from "./types.js";

export const NATIVE_HOST_NAME = "grdr.browser";
export const NATIVE_PROTOCOL_VERSION = 1;
export const MAX_NATIVE_MESSAGE_BYTES = 1_048_576;
export const DEFAULT_DECIDE_BUDGET_MS = 300;
export const DEFAULT_HELLO_TIMEOUT_MS = 1_500;
const MAX_ANNOTATION_BYTES = 4_096;

export interface NativeHelloMessage {
  type: "hello";
  protocol_version: number;
  extension_version: string;
  browser: BrowserTarget;
  organization_id: string;
  server_origin: string;
}

export interface NativeEventMessage {
  type: "event";
  kind: "upload" | "prompt" | "mcp.call" | "toolactivated" | "toolcancel" | "dnr.applied";
  hostname: string;
  transport: string;
  tool_name?: string;
  server_id?: string;
  secret_rule_ids: string[];
  file_extensions: string[];
}

export interface NativeDecideMessage {
  type: "decide";
  request_id: string;
  budget_ms: number;
  action_class: ActionClass;
  hostname: string;
  url_path: string;
  transport: string;
  has_file_upload: boolean;
  file_extensions: string[];
  secret_rule_ids: string[];
  tool_name?: string;
  server_id?: string;
  annotations?: Record<string, unknown>;
}

export type NativeOutboundMessage =
  | NativeHelloMessage
  | NativeEventMessage
  | NativeDecideMessage;

export interface NativeHelloAckMessage {
  type: "hello";
  protocol_version?: number;
  host_version?: string;
  ui_locale?: string;
}

export interface NativeVerdictMessage {
  type: "verdict";
  request_id: string;
  verdict: BrowserVerdict;
  rule_id: string;
  reason: string;
  ttl_ms?: number;
  ui_locale?: string;
  host_version?: string;
}

const textEncoder = new TextEncoder();
const textDecoderFatal = new TextDecoder("utf-8", { fatal: true });

export function encodeNativeFrame(message: NativeOutboundMessage | NativeVerdictMessage): Uint8Array {
  const payload = textEncoder.encode(JSON.stringify(message));
  if (payload.byteLength > MAX_NATIVE_MESSAGE_BYTES) {
    throw new Error(
      `GRDR-EXT-0101 Native messaging frame exceeds 1 MiB limit (${payload.byteLength} bytes)`,
    );
  }
  const frame = new Uint8Array(4 + payload.byteLength);
  const view = new DataView(frame.buffer);
  view.setUint32(0, payload.byteLength, true);
  frame.set(payload, 4);
  return frame;
}

export class NativeFrameDecoder {
  private buffer = new Uint8Array(0);

  push(chunk: Uint8Array): Array<Record<string, unknown>> {
    const maxBuffered = MAX_NATIVE_MESSAGE_BYTES + 4;
    if (chunk.length > maxBuffered || this.buffer.length + chunk.length > maxBuffered * 2) {
      this.buffer = new Uint8Array(0);
      throw new Error("GRDR-EXT-0102 Native frame buffer exceeded 1 MiB framing ceiling");
    }

    const merged = new Uint8Array(this.buffer.length + chunk.length);
    merged.set(this.buffer, 0);
    merged.set(chunk, this.buffer.length);
    this.buffer = merged;

    const messages: Array<Record<string, unknown>> = [];
    while (this.buffer.length >= 4) {
      const view = new DataView(this.buffer.buffer, this.buffer.byteOffset, this.buffer.byteLength);
      const length = view.getUint32(0, true);
      if (length === 0 || length > MAX_NATIVE_MESSAGE_BYTES) {
        this.buffer = new Uint8Array(0);
        throw new Error(`GRDR-EXT-0102 Invalid native frame length ${length}`);
      }
      if (this.buffer.length < 4 + length) {
        break;
      }
      const slice = this.buffer.subarray(4, 4 + length);
      const remaining = this.buffer.subarray(4 + length);
      this.buffer = merged.byteLength > 4096 ? remaining.slice() : remaining;

      let parsed: unknown;
      try {
        const jsonText = textDecoderFatal.decode(slice);
        parsed = JSON.parse(jsonText) as unknown;
      } catch (err) {
        this.buffer = new Uint8Array(0);
        const detail = err instanceof Error ? err.message : "malformed frame";
        throw new Error(`GRDR-EXT-0103 Invalid native frame payload: ${detail}`);
      }

      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        this.buffer = new Uint8Array(0);
        throw new Error("GRDR-EXT-0103 Native host message must be a JSON object");
      }
      messages.push(parsed as Record<string, unknown>);
    }
    return messages;
  }
}

export function validateNativeVerdictMessage(raw: unknown): NativeVerdictMessage | null {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return null;
  }
  const obj = raw as Record<string, unknown>;
  if (obj.type !== "verdict") {
    return null;
  }
  if (typeof obj.request_id !== "string" || obj.request_id.length === 0) {
    return null;
  }
  if (obj.verdict !== "allow" && obj.verdict !== "step_up" && obj.verdict !== "deny") {
    return null;
  }
  if (typeof obj.rule_id !== "string" || typeof obj.reason !== "string") {
    return null;
  }
  return {
    type: "verdict",
    request_id: obj.request_id,
    verdict: obj.verdict,
    rule_id: obj.rule_id,
    reason: obj.reason,
    ttl_ms: typeof obj.ttl_ms === "number" ? obj.ttl_ms : undefined,
    ui_locale: typeof obj.ui_locale === "string" ? obj.ui_locale : undefined,
    host_version: typeof obj.host_version === "string" ? obj.host_version : undefined,
  };
}

function validateNativeHelloAck(raw: unknown): NativeHelloAckMessage | null {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return null;
  }
  const obj = raw as Record<string, unknown>;
  if (obj.type !== "hello") {
    return null;
  }
  return {
    type: "hello",
    protocol_version: typeof obj.protocol_version === "number" ? obj.protocol_version : undefined,
    host_version: typeof obj.host_version === "string" ? obj.host_version : undefined,
    ui_locale: typeof obj.ui_locale === "string" ? obj.ui_locale : undefined,
  };
}

export function boundAnnotations(raw: Record<string, unknown> | undefined): Record<string, unknown> | undefined {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return undefined;
  const bounded: Record<string, unknown> = {};
  let count = 0;
  for (const [k, v] of Object.entries(raw)) {
    if (count >= 16) break;
    if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") {
      bounded[k.slice(0, 64)] = typeof v === "string" ? v.slice(0, 256) : v;
      count += 1;
    } else if (v && typeof v === "object" && !Array.isArray(v)) {
      const nested: Record<string, string | number | boolean> = {};
      let nCount = 0;
      for (const [nk, nv] of Object.entries(v as Record<string, unknown>)) {
        if (nCount >= 8) break;
        if (typeof nv === "string" || typeof nv === "number" || typeof nv === "boolean") {
          nested[nk.slice(0, 64)] = typeof nv === "string" ? nv.slice(0, 128) : nv;
          nCount += 1;
        }
      }
      bounded[k.slice(0, 64)] = nested;
      count += 1;
    }
  }
  const serialized = JSON.stringify(bounded);
  return serialized.length <= MAX_ANNOTATION_BYTES ? bounded : undefined;
}

export function buildRedactedDecidePayload(
  req: BrowserInspectRequest,
  secretRuleIds: string[],
  budgetMs = DEFAULT_DECIDE_BUDGET_MS,
): NativeDecideMessage {
  let urlPath = "/";
  try {
    urlPath = new URL(req.url).pathname;
  } catch {
    urlPath = "/";
  }
  return {
    type: "decide",
    request_id: req.requestId,
    budget_ms: budgetMs,
    action_class: req.actionClass,
    hostname: req.hostname,
    url_path: urlPath,
    transport: req.transport,
    has_file_upload: req.hasFileUpload,
    file_extensions: req.fileExtensions,
    secret_rule_ids: secretRuleIds,
    tool_name: req.toolName,
    server_id: req.toolName ? `webmcp:${req.hostname}` : undefined,
    annotations: boundAnnotations(req.toolAnnotations),
  };
}

export interface NativePortLike {
  postMessage: (message: unknown) => void;
  onMessage: { addListener: (fn: (msg: unknown) => void) => void };
  onDisconnect: { addListener: (fn: () => void) => void };
  disconnect?: () => void;
}

export class NativeHostBridge {
  private port: NativePortLike | null = null;
  private helloTimer: ReturnType<typeof setTimeout> | null = null;
  private status: NativeHostStatus = {
    kind: "degraded",
    reason: "host_missing",
    errorCode: "GRDR-EXT-0104",
    message: "Native host grdr.browser not connected; local Wasm floor active.",
  };
  private pending = new Map<
    string,
    { resolve: (verdict: NativeVerdictMessage | null) => void; timer: ReturnType<typeof setTimeout> }
  >();

  getStatus(): NativeHostStatus {
    return this.status;
  }

  connect(
    connector: (name: string) => NativePortLike | null,
    extensionVersion: string,
    browserTarget: BrowserTarget,
    managedConfig: ManagedExtensionConfig,
    lastErrorMessage?: () => string | undefined,
    helloTimeoutMs = DEFAULT_HELLO_TIMEOUT_MS,
  ): NativeHostStatus {
    this.disconnect();
    this.status = { kind: "connecting", startedAtMs: Date.now() };
    let nextPort: NativePortLike | null = null;
    try {
      nextPort = connector(NATIVE_HOST_NAME);
    } catch (err) {
      this.status = {
        kind: "degraded",
        reason: "host_missing",
        errorCode: "GRDR-EXT-0104",
        message: err instanceof Error ? err.message : "Failed connecting to grdr.browser host.",
      };
      return this.status;
    }

    if (!nextPort) {
      this.status = {
        kind: "degraded",
        reason: "host_missing",
        errorCode: "GRDR-EXT-0104",
        message: "Native messaging host API unavailable; running in local Wasm floor mode.",
      };
      return this.status;
    }

    this.port = nextPort;
    nextPort.onMessage.addListener((msg) => {
      this.handleInbound(msg);
    });
    nextPort.onDisconnect.addListener(() => {
      this.clearHelloTimer();
      const reasonMsg = lastErrorMessage?.() || "Native messaging host disconnected.";
      this.port = null;
      this.status = {
        kind: "degraded",
        reason: "host_disconnected",
        errorCode: "GRDR-EXT-0105",
        message: reasonMsg,
      };
      this.flushPending(null);
    });

    const hello: NativeHelloMessage = {
      type: "hello",
      protocol_version: NATIVE_PROTOCOL_VERSION,
      extension_version: extensionVersion,
      browser: browserTarget,
      organization_id: managedConfig.organizationId,
      server_origin: managedConfig.serverOrigin,
    };

    try {
      nextPort.postMessage(hello);
      this.helloTimer = setTimeout(() => {
        if (this.status.kind === "connecting") {
          this.status = {
            kind: "degraded",
            reason: "timeout",
            errorCode: "GRDR-EXT-0108",
            message: "Native host grdr.browser hello handshake timed out; local Wasm floor active.",
          };
        }
      }, helloTimeoutMs);
    } catch (err) {
      this.clearHelloTimer();
      this.port = null;
      this.status = {
        kind: "degraded",
        reason: "protocol_error",
        errorCode: "GRDR-EXT-0106",
        message: err instanceof Error ? err.message : "Failed sending native hello.",
      };
    }
    return this.status;
  }

  disconnect(): void {
    this.clearHelloTimer();
    if (this.port?.disconnect) {
      try {
        this.port.disconnect();
      } catch {
        // Ignore teardown disconnect failure on closed port.
      }
    }
    this.port = null;
    this.flushPending(null);
  }

  sendEvent(event: NativeEventMessage): boolean {
    if (!this.port || this.status.kind !== "connected") {
      return false;
    }
    try {
      this.port.postMessage(event);
      return true;
    } catch {
      return false;
    }
  }

  requestDecision(
    message: NativeDecideMessage,
    budgetMs = DEFAULT_DECIDE_BUDGET_MS,
  ): Promise<NativeVerdictMessage | null> {
    if (!this.port || this.status.kind === "degraded") {
      return Promise.resolve(null);
    }
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.pending.delete(message.request_id);
        this.status = {
          kind: "degraded",
          reason: "timeout",
          errorCode: "GRDR-EXT-0107",
          message: `Native host decide exceeded ${budgetMs}ms budget; fallback to local Wasm floor.`,
        };
        resolve(null);
      }, budgetMs);
      this.pending.set(message.request_id, { resolve, timer });
      try {
        this.port?.postMessage(message);
      } catch {
        clearTimeout(timer);
        this.pending.delete(message.request_id);
        this.status = {
          kind: "degraded",
          reason: "host_disconnected",
          errorCode: "GRDR-EXT-0105",
          message: "Native host port threw during decide dispatch.",
        };
        resolve(null);
      }
    });
  }

  private clearHelloTimer(): void {
    if (this.helloTimer) {
      clearTimeout(this.helloTimer);
      this.helloTimer = null;
    }
  }

  private handleInbound(raw: unknown): void {
    const helloAck = validateNativeHelloAck(raw);
    if (helloAck) {
      this.clearHelloTimer();
      this.status = {
        kind: "connected",
        hostVersion: helloAck.host_version ?? "0.1.0",
        protocolVersion: helloAck.protocol_version ?? NATIVE_PROTOCOL_VERSION,
        uiLocale: helloAck.ui_locale ?? "en",
        connectedAtMs: Date.now(),
      };
      return;
    }

    const verdict = validateNativeVerdictMessage(raw);
    if (!verdict) {
      return;
    }
    this.clearHelloTimer();
    if (this.status.kind === "connecting") {
      this.status = {
        kind: "connected",
        hostVersion: verdict.host_version ?? "0.1.0",
        protocolVersion: NATIVE_PROTOCOL_VERSION,
        uiLocale: verdict.ui_locale ?? "en",
        connectedAtMs: Date.now(),
      };
    } else if (this.status.kind === "connected") {
      this.status = {
        ...this.status,
        uiLocale: verdict.ui_locale ?? this.status.uiLocale,
        hostVersion: verdict.host_version ?? this.status.hostVersion,
      };
    }
    const waiter = this.pending.get(verdict.request_id);
    if (waiter) {
      clearTimeout(waiter.timer);
      this.pending.delete(verdict.request_id);
      waiter.resolve(verdict);
    }
  }

  private flushPending(value: NativeVerdictMessage | null): void {
    for (const [id, waiter] of this.pending.entries()) {
      clearTimeout(waiter.timer);
      waiter.resolve(value);
      this.pending.delete(id);
    }
  }
}
