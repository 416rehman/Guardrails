// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import {
  authorizeOrNotice,
  extractBodyMetadata,
  extractFileExtensions,
  type NoticeLocaleStrings,
  type PageHookDecisionBridge,
  type PageOutboundInspectPayload,
  type PageTelemetryEvent,
} from "./content-notice.js";
import { createWrappedEventSource, wrapModelContextObject } from "./content-webmcp.js";
import type { BrowserInspectDecision } from "./types.js";

export {
  extractBodyMetadata,
  extractFileExtensions,
  showClosedShadowNotice,
} from "./content-notice.js";
export type { PageHookDecisionBridge, PageOutboundInspectPayload, PageTelemetryEvent };

const BRIDGE_POST_MSG_TYPE = "__grdr_ext_bridge_init";
const BRIDGE_WAIT_BUDGET_MS = 500;

function nextRequestId(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return `grdr-${Date.now()}-${Math.floor(Math.random() * 1_000_000)}`;
}

function resolveAbsoluteUrl(rawUrl: string, baseHref: string): URL | null {
  try {
    return new URL(rawUrl, baseHref);
  } catch {
    return null;
  }
}

function failClosedTimeoutDecision(
  payload: PageOutboundInspectPayload,
  ruleId: string,
  reason: string,
): BrowserInspectDecision {
  const highRisk =
    payload.hasFileUpload ||
    payload.fileExtensions.length > 0 ||
    payload.actionClass === "mcp.call";
  return {
    requestId: payload.requestId,
    verdict: highRisk ? "deny" : "step_up",
    ruleId,
    reason,
    modeApplied: highRisk ? "block" : "ask",
    appId: null,
    appName: payload.hostname,
    source: "wasm_floor",
    hostDegraded: true,
    secretHits: [],
    sensitiveExtensions: payload.fileExtensions,
    flags: 0,
  };
}

function lockDescriptor(obj: object, prop: PropertyKey, value: unknown): void {
  try {
    Object.defineProperty(obj, prop, {
      value,
      writable: false,
      configurable: false,
    });
  } catch {
    try {
      (obj as Record<PropertyKey, unknown>)[prop] = value;
    } catch {
      // Ignore if environment freezes prototypes completely.
    }
  }
}

function isRequestLike(input: unknown): input is Request {
  if (typeof Request !== "undefined" && input instanceof Request) {
    return true;
  }
  return Boolean(
    input &&
      typeof input === "object" &&
      typeof (input as { url?: unknown }).url === "string" &&
      typeof (input as { method?: unknown }).method === "string" &&
      typeof (input as { clone?: unknown }).clone === "function",
  );
}

async function extractFetchMetadata(
  input: RequestInfo | URL,
  init?: RequestInit,
): Promise<ReturnType<typeof extractBodyMetadata>> {
  if (init && init.body !== undefined) {
    return extractBodyMetadata(init.body);
  }
  if (isRequestLike(input) && input.body !== null) {
    try {
      const contentType =
        typeof input.headers?.get === "function"
          ? (input.headers.get("content-type") || "").toLowerCase()
          : "";
      if (contentType.includes("multipart/form-data") && typeof input.clone === "function") {
        const clonedForm = input.clone() as Request & { formData?: () => Promise<FormData> };
        if (typeof clonedForm.formData === "function") {
          const fd = await clonedForm.formData();
          return extractBodyMetadata(fd);
        }
      }
      const cloned = input.clone();
      const buf = await cloned.arrayBuffer();
      return extractBodyMetadata(buf);
    } catch {
      return {
        hasFileUpload: false,
        fileNames: [],
        fileExtensions: [],
        fileMimeTypes: [],
        bodyPreview: "[Unreadable Request body]",
      };
    }
  }
  return extractBodyMetadata(undefined);
}

export function installPageHooks(
  win: Window,
  doc: Document,
  bridge: PageHookDecisionBridge,
): void {
  const baseHref = () => win.location?.href || "https://localhost/";

  if (typeof win.fetch === "function") {
    const origFetch = win.fetch.bind(win);
    const wrappedFetch: typeof win.fetch = async (input, init) => {
      const rawUrl =
        typeof input === "string"
          ? input
          : isRequestLike(input)
            ? input.url
            : String(input);
      const parsed = resolveAbsoluteUrl(rawUrl, baseHref());
      const method = (
        init?.method ||
        (isRequestLike(input) ? input.method : "GET")
      ).toUpperCase();
      if (parsed && (method === "POST" || method === "PUT" || method === "PATCH")) {
        const meta = await extractFetchMetadata(input, init);
        const { allowed, decision } = await authorizeOrNotice(doc, bridge, {
          requestId: nextRequestId(),
          url: parsed.href,
          hostname: parsed.hostname,
          method,
          transport: "fetch",
          actionClass: meta.hasFileUpload ? "data_flow" : "llm_request",
          ...meta,
        });
        if (!allowed) {
          throw new Error(`Guardrails blocked request (${decision.ruleId})`);
        }
      }
      return origFetch(input, init);
    };
    lockDescriptor(win, "fetch", wrappedFetch);
  }

  const xhrProto = (win as unknown as { XMLHttpRequest?: typeof XMLHttpRequest }).XMLHttpRequest?.prototype;
  if (xhrProto) {
    const xhrState = new WeakMap<XMLHttpRequest, { method: string; url: string }>();
    const origOpen = xhrProto.open;
    const origSend = xhrProto.send;

    const wrappedOpen = function (
      this: XMLHttpRequest,
      method: string,
      url: string | URL,
      asyncFlag = true,
      user?: string | null,
      pass?: string | null,
    ) {
      xhrState.set(this, { method: method.toUpperCase(), url: String(url) });
      return origOpen.call(this, method, url, Boolean(asyncFlag), user ?? null, pass ?? null);
    };

    const wrappedSend = function (
      this: XMLHttpRequest,
      body?: Document | XMLHttpRequestBodyInit | null,
    ) {
      const tracked = xhrState.get(this);
      const parsed = tracked ? resolveAbsoluteUrl(tracked.url, baseHref()) : null;
      if (
        tracked &&
        parsed &&
        (tracked.method === "POST" || tracked.method === "PUT" || tracked.method === "PATCH")
      ) {
        const meta = extractBodyMetadata(body);
        void authorizeOrNotice(doc, bridge, {
          requestId: nextRequestId(),
          url: parsed.href,
          hostname: parsed.hostname,
          method: tracked.method,
          transport: "xhr",
          actionClass: meta.hasFileUpload ? "data_flow" : "net_request",
          ...meta,
        }).then(({ allowed }) => {
          if (allowed) {
            origSend.call(this, body as Parameters<XMLHttpRequest["send"]>[0]);
          } else {
            try {
              this.abort();
            } catch {
              // Ignore abort error if XHR state already closed.
            }
          }
        });
        return;
      }
      return origSend.call(this, body as Parameters<XMLHttpRequest["send"]>[0]);
    };

    lockDescriptor(xhrProto, "open", wrappedOpen);
    lockDescriptor(xhrProto, "send", wrappedSend);
  }

  const wsProto = (win as unknown as { WebSocket?: typeof WebSocket }).WebSocket?.prototype;
  if (wsProto) {
    const origWsSend = wsProto.send;
    const wrappedWsSend = function (
      this: WebSocket,
      data: string | ArrayBufferLike | Blob | ArrayBufferView,
    ) {
      const parsed = resolveAbsoluteUrl(this.url || "", baseHref());
      const meta = extractBodyMetadata(data);
      if (parsed) {
        void authorizeOrNotice(doc, bridge, {
          requestId: nextRequestId(),
          url: parsed.href,
          hostname: parsed.hostname,
          method: "WEBSOCKET",
          transport: "websocket",
          actionClass: "net_request",
          ...meta,
        }).then(({ allowed }) => {
          if (allowed) {
            origWsSend.call(this, data as Parameters<WebSocket["send"]>[0]);
          }
        });
        return;
      }
      return origWsSend.call(this, data as Parameters<WebSocket["send"]>[0]);
    };
    lockDescriptor(wsProto, "send", wrappedWsSend);
  }

  const OrigEventSource = (win as unknown as { EventSource?: typeof EventSource }).EventSource;
  if (typeof OrigEventSource === "function") {
    const wrapped = createWrappedEventSource(OrigEventSource, doc, bridge, (raw) =>
      resolveAbsoluteUrl(raw, baseHref()),
    );
    lockDescriptor(win, "EventSource", wrapped);
  }

  const NavCtor = (win as unknown as { Navigator?: { prototype?: Record<string, unknown> } }).Navigator;
  const navProto = NavCtor?.prototype;
  const navObj = win.navigator as Navigator & {
    sendBeacon?: (url: string | URL, data?: BodyInit | null) => boolean;
  };
  const wrapBeacon = (origBeacon: (url: string | URL, data?: BodyInit | null) => boolean) => {
    return function (this: unknown, url: string | URL, data?: BodyInit | null): boolean {
      const parsed = resolveAbsoluteUrl(String(url), baseHref());
      const meta = extractBodyMetadata(data);
      if (parsed && (meta.hasFileUpload || meta.bodyPreview.length > 0)) {
        void authorizeOrNotice(doc, bridge, {
          requestId: nextRequestId(),
          url: parsed.href,
          hostname: parsed.hostname,
          method: "BEACON",
          transport: "beacon",
          actionClass: "data_flow",
          ...meta,
        }).then(({ allowed }) => {
          if (allowed) {
            origBeacon.call(this ?? navObj, url, data);
          }
        });
        return true;
      }
      return origBeacon.call(this ?? navObj, url, data);
    };
  };
  const rawProtoBeacon =
    navProto && typeof navProto.sendBeacon === "function"
      ? (navProto.sendBeacon as (this: unknown, url: string | URL, data?: BodyInit | null) => boolean)
      : null;
  if (navProto && rawProtoBeacon) {
    lockDescriptor(navProto, "sendBeacon", wrapBeacon(rawProtoBeacon));
  }
  if (navObj && typeof navObj.sendBeacon === "function") {
    const rawOwnBeacon = Object.prototype.hasOwnProperty.call(navObj, "sendBeacon")
      ? navObj.sendBeacon
      : rawProtoBeacon ?? navObj.sendBeacon;
    lockDescriptor(navObj, "sendBeacon", wrapBeacon(rawOwnBeacon.bind(navObj)));
  }

  const docWithCtx = doc as Document & { modelContext?: Record<string, unknown> };
  if (docWithCtx.modelContext && typeof docWithCtx.modelContext === "object") {
    wrapModelContextObject(docWithCtx.modelContext, doc, win, bridge);
  } else {
    let storedModelContext: Record<string, unknown> | undefined;
    try {
      Object.defineProperty(docWithCtx, "modelContext", {
        configurable: true,
        enumerable: true,
        get() {
          return storedModelContext;
        },
        set(nextCtx: Record<string, unknown> | undefined) {
          storedModelContext = nextCtx;
          if (nextCtx && typeof nextCtx === "object") {
            wrapModelContextObject(nextCtx, doc, win, bridge);
          }
        },
      });
    } catch {
      // Ignore non-configurable document.modelContext override.
    }
  }

  win.addEventListener("toolactivated", (evt) => {
    const detail = (evt as CustomEvent<{ name?: string }>).detail;
    bridge.emitTelemetry({
      kind: "toolactivated",
      hostname: win.location?.hostname || "localhost",
      toolName: detail?.name || "unknown",
    });
  });

  win.addEventListener("toolcancel", (evt) => {
    const detail = (evt as CustomEvent<{ name?: string }>).detail;
    bridge.emitTelemetry({
      kind: "toolcancel",
      hostname: win.location?.hostname || "localhost",
      toolName: detail?.name || "unknown",
    });
  });
}

export function createWindowBridgeTransport(win: Window, doc: Document): PageHookDecisionBridge {
  let boundPort: MessagePort | null = null;
  let noticeLabels: NoticeLocaleStrings | undefined;
  const pending = new Map<string, (decision: BrowserInspectDecision) => void>();
  const queuedRequests: Array<{ cancelled: boolean; run: () => void }> = [];

  const expectedToken = doc.documentElement?.dataset.grdrBoot || "";
  if (doc.documentElement?.dataset && "grdrBoot" in doc.documentElement.dataset) {
    delete doc.documentElement.dataset.grdrBoot;
  }

  const onBridgeInit = (evt: MessageEvent) => {
    if (boundPort) return;
    if (!evt.isTrusted || evt.source !== win) return;
    const data = evt.data as
      | { type?: string; token?: string; labels?: NoticeLocaleStrings }
      | undefined;
    if (!data || data.type !== BRIDGE_POST_MSG_TYPE) return;
    if (!expectedToken || data.token !== expectedToken) return;
    const port = evt.ports?.[0];
    if (!port) return;

    if (typeof evt.stopImmediatePropagation === "function") {
      evt.stopImmediatePropagation();
    }
    if (typeof win.removeEventListener === "function") {
      win.removeEventListener("message", onBridgeInit, true);
    }

    boundPort = port;
    if (data.labels) {
      noticeLabels = data.labels;
    }
    port.onmessage = (msgEvt: MessageEvent) => {
      const res = msgEvt.data as BrowserInspectDecision | undefined;
      if (!res || typeof res.requestId !== "string") return;
      const resolve = pending.get(res.requestId);
      if (resolve) {
        pending.delete(res.requestId);
        resolve(res);
      }
    };
    port.start();

    while (queuedRequests.length > 0) {
      const entry = queuedRequests.shift();
      if (entry && !entry.cancelled) {
        entry.run();
      }
    }
  };

  win.addEventListener("message", onBridgeInit, true);

  return {
    getLocaleStrings: () => noticeLabels,
    requestDecision(payload: PageOutboundInspectPayload): Promise<BrowserInspectDecision> {
      return new Promise((resolve) => {
        const dispatch = () => {
          const timer = setTimeout(() => {
            pending.delete(payload.requestId);
            resolve(
              failClosedTimeoutDecision(
                payload,
                "browser.bridge.timeout-fail-closed",
                "Extension bridge exceeded 500ms budget; enforced fail-closed protection.",
              ),
            );
          }, BRIDGE_WAIT_BUDGET_MS);

          pending.set(payload.requestId, (decision) => {
            clearTimeout(timer);
            resolve(decision);
          });

          if (boundPort) {
            boundPort.postMessage({ kind: "inspect", payload });
          } else {
            pending.delete(payload.requestId);
            clearTimeout(timer);
            resolve(
              failClosedTimeoutDecision(
                payload,
                "browser.bridge.uninitialized-fail-closed",
                "Extension bridge unavailable; enforced fail-closed protection.",
              ),
            );
          }
        };

        if (boundPort) {
          dispatch();
          return;
        }

        const queueEntry = {
          cancelled: false,
          run: () => {
            clearTimeout(initTimer);
            dispatch();
          },
        };
        const initTimer = setTimeout(() => {
          queueEntry.cancelled = true;
          resolve(
            failClosedTimeoutDecision(
              payload,
              "browser.bridge.uninitialized-fail-closed",
              "Extension bridge port was not bound before transfer; enforced fail-closed verdict.",
            ),
          );
        }, BRIDGE_WAIT_BUDGET_MS);

        queuedRequests.push(queueEntry);
      });
    },
    emitTelemetry(event: PageTelemetryEvent): void {
      if (boundPort) {
        boundPort.postMessage({ kind: "telemetry", event });
      }
    },
  };
}

if (typeof window !== "undefined" && typeof document !== "undefined") {
  installPageHooks(window, document, createWindowBridgeTransport(window, document));
}
