// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import {
  MAX_BODY_INSPECT_BYTES,
  authorizeOrNotice,
  type PageHookDecisionBridge,
} from "./content-notice.js";

function nextRequestId(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return `grdr-${Date.now()}-${Math.floor(Math.random() * 1_000_000)}`;
}

function safeStringifyArgs(args: unknown[]): string {
  const seen = new WeakSet<object>();
  try {
    return JSON.stringify(args, (_key, value) => {
      if (typeof value === "bigint") return value.toString();
      if (value && typeof value === "object") {
        if (seen.has(value)) return "[Circular]";
        seen.add(value);
      }
      return value;
    }).slice(0, MAX_BODY_INSPECT_BYTES);
  } catch {
    return args.map((item) => String(item)).join(" ").slice(0, MAX_BODY_INSPECT_BYTES);
  }
}

export function wrapModelContextObject(
  modelContext: Record<string, unknown>,
  doc: Document,
  win: Window,
  bridge: PageHookDecisionBridge,
): void {
  const rawRegister = modelContext.registerTool;
  if (typeof rawRegister !== "function") {
    return;
  }
  const origRegister = rawRegister as (def: Record<string, unknown>) => unknown;
  const wrappedRegister = function (this: unknown, def: Record<string, unknown>): unknown {
    const toolName = typeof def?.name === "string" ? def.name : "unnamed_tool";
    const toolDesc = typeof def?.description === "string" ? def.description.slice(0, 500) : "";
    const annotations =
      def?.annotations && typeof def.annotations === "object"
        ? (def.annotations as Record<string, unknown>)
        : {};
    const hostname = win.location?.hostname || "localhost";

    bridge.emitTelemetry({
      kind: "webmcp.register",
      hostname,
      toolName,
      description: toolDesc,
      annotations,
    });

    const rawExecute = def?.execute;
    if (typeof rawExecute === "function") {
      const origExecute = rawExecute as (...args: unknown[]) => Promise<unknown>;
      const wrappedDef: Record<string, unknown> = {
        ...def,
        execute: async function (this: unknown, ...args: unknown[]) {
          const preview = safeStringifyArgs(args);
          const { allowed, decision } = await authorizeOrNotice(doc, bridge, {
            requestId: nextRequestId(),
            url: win.location?.href || `https://${hostname}/`,
            hostname,
            method: "WEBMCP",
            transport: "webmcp",
            actionClass: "mcp.call",
            hasFileUpload: false,
            fileNames: [],
            fileExtensions: [],
            toolName,
            toolDescription: toolDesc,
            toolAnnotations: annotations,
            bodyPreview: preview,
          });
          if (!allowed) {
            bridge.emitTelemetry({ kind: "toolcancel", hostname, toolName });
            throw new Error(`Guardrails WebMCP policy blocked ${toolName} (${decision.ruleId})`);
          }
          return origExecute.apply(this, args);
        },
      };
      return origRegister.call(this, wrappedDef);
    }
    return origRegister.call(this, def);
  };

  Object.defineProperty(modelContext, "registerTool", {
    value: wrappedRegister,
    writable: false,
    configurable: false,
    enumerable: true,
  });
}

export function createWrappedEventSource(
  OrigEventSource: typeof EventSource,
  doc: Document,
  bridge: PageHookDecisionBridge,
  resolveUrl: (raw: string) => URL | null,
): typeof EventSource {
  const WrappedEventSource = function (url: string | URL, init?: EventSourceInit) {
    const parsed = resolveUrl(String(url));
    let realInstance: EventSource | null = null;
    let closedEarly = false;
    let readyState = 0;
    const queuedListeners: Array<{
      type: string;
      listener: EventListenerOrEventListenerObject;
      options?: boolean | AddEventListenerOptions;
    }> = [];
    let onMessageHandler: ((this: EventSource, ev: MessageEvent) => unknown) | null = null;
    let onOpenHandler: ((this: EventSource, ev: Event) => unknown) | null = null;
    let onErrorHandler: ((this: EventSource, ev: Event) => unknown) | null = null;

    const controller = {
      get url() {
        return realInstance ? realInstance.url : String(url);
      },
      get withCredentials() {
        return realInstance ? realInstance.withCredentials : Boolean(init?.withCredentials);
      },
      get readyState() {
        return realInstance ? realInstance.readyState : readyState;
      },
      set onmessage(fn: ((this: EventSource, ev: MessageEvent) => unknown) | null) {
        onMessageHandler = fn;
        if (realInstance) realInstance.onmessage = fn;
      },
      get onmessage() {
        return onMessageHandler;
      },
      set onopen(fn: ((this: EventSource, ev: Event) => unknown) | null) {
        onOpenHandler = fn;
        if (realInstance) realInstance.onopen = fn;
      },
      get onopen() {
        return onOpenHandler;
      },
      set onerror(fn: ((this: EventSource, ev: Event) => unknown) | null) {
        onErrorHandler = fn;
        if (realInstance) realInstance.onerror = fn;
      },
      get onerror() {
        return onErrorHandler;
      },
      addEventListener(
        type: string,
        listener: EventListenerOrEventListenerObject,
        options?: boolean | AddEventListenerOptions,
      ) {
        if (realInstance) {
          realInstance.addEventListener(type, listener, options);
        } else {
          queuedListeners.push({ type, listener, options });
        }
      },
      removeEventListener(
        type: string,
        listener: EventListenerOrEventListenerObject,
        options?: boolean | EventListenerOptions,
      ) {
        realInstance?.removeEventListener(type, listener, options);
      },
      dispatchEvent(evt: Event) {
        return realInstance ? realInstance.dispatchEvent(evt) : false;
      },
      close() {
        closedEarly = true;
        readyState = 2;
        realInstance?.close();
      },
    };

    if (!parsed) {
      readyState = 2;
      return controller as unknown as EventSource;
    }

    void authorizeOrNotice(doc, bridge, {
      requestId: nextRequestId(),
      url: parsed.href,
      hostname: parsed.hostname,
      method: "GET",
      transport: "eventsource",
      actionClass: "net_request",
      hasFileUpload: false,
      fileNames: [],
      fileExtensions: [],
      bodyPreview: parsed.search.slice(0, MAX_BODY_INSPECT_BYTES),
    }).then(({ allowed }) => {
      if (!allowed || closedEarly) {
        readyState = 2;
        if (onErrorHandler && typeof Event === "function") {
          onErrorHandler.call(controller as unknown as EventSource, new Event("error"));
        }
        return;
      }
      const es = new OrigEventSource(url, init);
      realInstance = es;
      es.onmessage = onMessageHandler;
      es.onopen = onOpenHandler;
      es.onerror = onErrorHandler;
      for (const item of queuedListeners) {
        es.addEventListener(item.type, item.listener, item.options);
      }
    });

    return controller as unknown as EventSource;
  } as unknown as typeof EventSource;
  WrappedEventSource.prototype = OrigEventSource.prototype;
  return WrappedEventSource;
}
