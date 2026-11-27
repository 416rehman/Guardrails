// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import type { NoticeLocaleStrings, PageOutboundInspectPayload, PageTelemetryEvent } from "./content-notice.js";
import type { BrowserInspectDecision } from "./types.js";

const BRIDGE_POST_MSG_TYPE = "__grdr_ext_bridge_init";

declare const chrome: {
  runtime?: {
    sendMessage: (message: unknown) => Promise<unknown>;
  };
  i18n?: {
    getMessage: (key: string) => string;
  };
};

declare const browser: {
  runtime?: {
    sendMessage: (message: unknown) => Promise<unknown>;
  };
  i18n?: {
    getMessage: (key: string) => string;
  };
};

function getRuntimeApi() {
  if (typeof chrome !== "undefined" && chrome.runtime) {
    return chrome;
  }
  if (typeof browser !== "undefined" && browser.runtime) {
    return browser;
  }
  return null;
}

function generateBootNonce(): string {
  if (typeof crypto !== "undefined" && typeof crypto.getRandomValues === "function") {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  }
  return `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function failClosedBridgeDecision(payload: PageOutboundInspectPayload, reason: string): BrowserInspectDecision {
  const highRisk =
    payload.hasFileUpload ||
    payload.fileExtensions.length > 0 ||
    payload.actionClass === "mcp.call";
  return {
    requestId: payload.requestId,
    verdict: highRisk ? "deny" : "step_up",
    ruleId: "browser.bridge.fail-closed",
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

export interface BridgeExtApi {
  runtime?: {
    sendMessage: (message: unknown) => Promise<unknown>;
  };
  i18n?: {
    getMessage: (key: string) => string;
  };
}

export function bootstrapContentBridge(
  win: Window,
  doc: Document,
  runtimeOverride?: BridgeExtApi | null,
): void {
  const ext = runtimeOverride ?? getRuntimeApi();
  if (!ext?.runtime) {
    return;
  }
  const msg = (key: string, fallback: string) => ext.i18n?.getMessage(key) || fallback;
  const dir: "ltr" | "rtl" = ext.i18n?.getMessage("@@bidi_dir") === "rtl" ? "rtl" : "ltr";

  const labels: NoticeLocaleStrings = {
    dir,
    blockedPrefix: msg("noticeBlockedPrefix", "Blocked by Guardrails"),
    confirmPrefix: msg("noticeConfirmPrefix", "Confirm action on"),
    dismiss: msg("noticeDismiss", "Dismiss"),
    cancelTransfer: msg("noticeCancelTransfer", "Cancel transfer"),
    confirmContinue: msg("noticeConfirmContinue", "Confirm and continue"),
  };

  if (doc.documentElement) {
    doc.documentElement.dataset.grdrDir = dir;
  }

  const bootNonce = generateBootNonce();
  if (doc.documentElement) {
    doc.documentElement.dataset.grdrBoot = bootNonce;
  }

  const channel = new MessageChannel();
  channel.port1.onmessage = async (evt: MessageEvent) => {
    const inbound = evt.data as
      | { kind: "inspect"; payload: PageOutboundInspectPayload }
      | { kind: "telemetry"; event: PageTelemetryEvent }
      | undefined;
    if (!inbound) return;

    if (inbound.kind === "telemetry") {
      try {
        await ext.runtime?.sendMessage({
          type: "ext:telemetry",
          event: inbound.event,
        });
      } catch {
        // Ignore passive telemetry errors during SW restart.
      }
      return;
    }

    if (inbound.kind === "inspect") {
      try {
        const decision = (await ext.runtime?.sendMessage({
          type: "ext:inspect",
          payload: inbound.payload,
        })) as BrowserInspectDecision | undefined;
        channel.port1.postMessage(
          decision ??
            failClosedBridgeDecision(
              inbound.payload,
              "Background worker returned empty decision; applied fail-closed protection.",
            ),
        );
      } catch {
        channel.port1.postMessage(
          failClosedBridgeDecision(
            inbound.payload,
            "Background service worker unavailable; applied fail-closed protection.",
          ),
        );
      }
    }
  };
  channel.port1.start();

  const targetOrigin =
    win.location?.origin && win.location.origin !== "null" ? win.location.origin : "*";
  win.postMessage(
    {
      type: BRIDGE_POST_MSG_TYPE,
      token: bootNonce,
      labels,
    },
    targetOrigin,
    [channel.port2],
  );
}

if (typeof window !== "undefined" && typeof document !== "undefined") {
  bootstrapContentBridge(window, document);
}
