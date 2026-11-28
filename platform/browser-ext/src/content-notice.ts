// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import brandTokens from "virtual:grdr-tokens";
import type { ActionClass, BrowserInspectDecision } from "./types.js";

export const MAX_BODY_INSPECT_BYTES = 65_536;

export interface PageOutboundInspectPayload {
  requestId: string;
  url: string;
  hostname: string;
  method: string;
  transport: "fetch" | "xhr" | "websocket" | "beacon" | "eventsource" | "webmcp";
  actionClass: ActionClass;
  hasFileUpload: boolean;
  fileNames: string[];
  fileExtensions: string[];
  fileMimeTypes?: string[];
  toolName?: string;
  toolDescription?: string;
  toolAnnotations?: Record<string, unknown>;
  bodyPreview: string;
}

export interface PageTelemetryEvent {
  kind: "toolactivated" | "toolcancel" | "webmcp.register";
  hostname: string;
  toolName: string;
  description?: string;
  annotations?: Record<string, unknown>;
}

export interface PageHookDecisionBridge {
  requestDecision: (payload: PageOutboundInspectPayload) => Promise<BrowserInspectDecision>;
  emitTelemetry: (event: PageTelemetryEvent) => void;
  getLocaleStrings?: () => NoticeLocaleStrings | undefined;
}

export interface NoticeLocaleStrings {
  dir: "ltr" | "rtl";
  blockedPrefix: string;
  confirmPrefix: string;
  dismiss: string;
  cancelTransfer: string;
  confirmContinue: string;
}

interface NoticeOptions {
  mode: "deny" | "step_up";
  title: string;
  summary: string;
  ruleId: string;
  labels: NoticeLocaleStrings;
}

const DEFAULT_NOTICE_LABELS: NoticeLocaleStrings = {
  dir: "ltr",
  blockedPrefix: "Blocked by Guardrails",
  confirmPrefix: "Confirm action on",
  dismiss: "Dismiss",
  cancelTransfer: "Cancel transfer",
  confirmContinue: "Confirm and continue",
};

export function stripBidiControls(value: string): string {
  return value.replace(/[\u200E\u200F\u202A-\u202E\u2066-\u2069]/g, "");
}

export function extractFileExtensions(fileName: string): string[] {
  const base = fileName.trim().split(/[\\/]/).pop() ?? "";
  if (!base) return [];
  const lower = base.toLowerCase();
  const out: string[] = [];

  if (lower.startsWith(".")) {
    const secondDot = lower.indexOf(".", 1);
    if (secondDot > 1) {
      out.push(lower.slice(0, secondDot));
      out.push(lower.slice(secondDot));
      out.push(lower);
    } else {
      out.push(lower);
    }
    return [...new Set(out)];
  }

  const lastDot = lower.lastIndexOf(".");
  if (lastDot > 0 && lastDot < lower.length - 1) {
    out.push(lower.slice(lastDot));
  }
  return out;
}

export function extractBodyMetadata(body: unknown): {
  hasFileUpload: boolean;
  fileNames: string[];
  fileExtensions: string[];
  fileMimeTypes: string[];
  bodyPreview: string;
} {
  if (!body) {
    return {
      hasFileUpload: false,
      fileNames: [],
      fileExtensions: [],
      fileMimeTypes: [],
      bodyPreview: "",
    };
  }
  if (typeof body === "string") {
    return {
      hasFileUpload: false,
      fileNames: [],
      fileExtensions: [],
      fileMimeTypes: [],
      bodyPreview: body.slice(0, MAX_BODY_INSPECT_BYTES),
    };
  }
  if (typeof FormData !== "undefined" && body instanceof FormData) {
    const fileNames: string[] = [];
    const fileExtensions: string[] = [];
    const fileMimeTypes: string[] = [];
    const previewParts: string[] = [];
    let hasFileUpload = false;
    body.forEach((value, key) => {
      if (typeof File !== "undefined" && value instanceof File) {
        hasFileUpload = true;
        fileNames.push(value.name);
        if (value.type && !fileMimeTypes.includes(value.type)) {
          fileMimeTypes.push(value.type);
        }
        for (const ext of extractFileExtensions(value.name)) {
          if (!fileExtensions.includes(ext)) fileExtensions.push(ext);
        }
        previewParts.push(`${key}=[File:${value.name}:${value.type || "unknown"}:${value.size}]`);
      } else if (typeof Blob !== "undefined" && value instanceof Blob) {
        hasFileUpload = true;
        if (value.type && !fileMimeTypes.includes(value.type)) {
          fileMimeTypes.push(value.type);
        }
        previewParts.push(`${key}=[Blob:${value.type || "unknown"}:${value.size}]`);
      } else {
        previewParts.push(`${key}=${String(value).slice(0, 1024)}`);
      }
    });
    return {
      hasFileUpload,
      fileNames,
      fileExtensions,
      fileMimeTypes,
      bodyPreview: previewParts.join("\n").slice(0, MAX_BODY_INSPECT_BYTES),
    };
  }
  if (typeof File !== "undefined" && body instanceof File) {
    return {
      hasFileUpload: true,
      fileNames: [body.name],
      fileExtensions: extractFileExtensions(body.name),
      fileMimeTypes: body.type ? [body.type] : [],
      bodyPreview: `[File:${body.name}:${body.type || "unknown"}:${body.size}]`,
    };
  }
  if (typeof Blob !== "undefined" && body instanceof Blob) {
    return {
      hasFileUpload: true,
      fileNames: [],
      fileExtensions: [],
      fileMimeTypes: body.type ? [body.type] : [],
      bodyPreview: `[Blob:${body.type || "unknown"}:${body.size}]`,
    };
  }
  if (body instanceof ArrayBuffer || ArrayBuffer.isView(body)) {
    const view =
      body instanceof ArrayBuffer
        ? new Uint8Array(body, 0, Math.min(body.byteLength, MAX_BODY_INSPECT_BYTES))
        : new Uint8Array(
            body.buffer,
            body.byteOffset,
            Math.min(body.byteLength, MAX_BODY_INSPECT_BYTES),
          );
    const decoded = new TextDecoder("utf-8", { fatal: false }).decode(view);
    return {
      hasFileUpload: false,
      fileNames: [],
      fileExtensions: [],
      fileMimeTypes: [],
      bodyPreview: decoded.slice(0, MAX_BODY_INSPECT_BYTES),
    };
  }
  if (typeof URLSearchParams !== "undefined" && body instanceof URLSearchParams) {
    return {
      hasFileUpload: false,
      fileNames: [],
      fileExtensions: [],
      fileMimeTypes: [],
      bodyPreview: body.toString().slice(0, MAX_BODY_INSPECT_BYTES),
    };
  }
  return {
    hasFileUpload: false,
    fileNames: [],
    fileExtensions: [],
    fileMimeTypes: [],
    bodyPreview: String(body).slice(0, MAX_BODY_INSPECT_BYTES),
  };
}

function isDarkColorScheme(): boolean {
  if (typeof document !== "undefined" && document.documentElement?.getAttribute("data-theme") === "dark") {
    return true;
  }
  if (typeof window !== "undefined" && typeof window.matchMedia === "function") {
    return window.matchMedia("(prefers-color-scheme: dark)").matches;
  }
  return false;
}

function createBdi(doc: Document, text: string): HTMLElement {
  const el = doc.createElement("bdi");
  el.textContent = stripBidiControls(text);
  return el;
}

export function showClosedShadowNotice(
  doc: Document,
  opts: NoticeOptions,
): Promise<"continue" | "cancel"> {
  if (!doc.documentElement) {
    return Promise.resolve("cancel");
  }
  const existingCount = doc.documentElement.querySelectorAll
    ? doc.documentElement.querySelectorAll('[data-grdr-notice="true"]').length
    : 0;
  const bottomOffsetPx = 20 + Math.min(existingCount, 4) * 124;

  const container = doc.createElement("div");
  container.setAttribute("data-grdr-notice", "true");
  const shadow = container.attachShadow({ mode: "closed" });

  const dark = isDarkColorScheme();
  const scheme = dark ? brandTokens.dark : brandTokens.light;
  const bg = scheme.bgCanvas;
  const ink = scheme.inkPrimary;
  const muted = scheme.inkSecondary;
  const border = scheme.borderSubtle;
  const recessed = scheme.bgRecessed;
  const accent = scheme.accentSignal;
  const toneBorder = opts.mode === "deny" ? scheme.block : scheme.ask;
  const actionBg = scheme.actionPrimaryBg;
  const actionInk = scheme.actionPrimaryInk;

  const style = doc.createElement("style");
  style.textContent = [
    `:host { all: initial; position: fixed; inset-block-end: ${bottomOffsetPx}px; inset-inline-end: 20px; z-index: 2147483647; max-inline-size: 380px; font-family: "DM Sans", system-ui, -apple-system, sans-serif; }`,
    `.card { background: ${bg}; color: ${ink}; border: 1px solid ${toneBorder}; border-radius: 12px; box-shadow: 0 16px 40px rgba(15, 23, 42, 0.22); padding-block: 14px; padding-inline: 16px; display: flex; flex-direction: column; gap: 8px; }`,
    `.title { font-size: 14px; font-weight: 600; margin: 0; color: ${ink}; }`,
    `.summary { font-size: 13px; line-height: 1.45; margin: 0; color: ${muted}; }`,
    `.rule { font-family: "IBM Plex Mono", ui-monospace, monospace; font-size: 11px; background: ${recessed}; color: ${accent}; border: 1px solid ${border}; padding-block: 3px; padding-inline: 7px; border-radius: 4px; align-self: flex-start; }`,
    ".actions { display: flex; gap: 8px; justify-content: flex-end; margin-block-start: 4px; flex-wrap: wrap; }",
    `button { font: inherit; font-size: 12px; font-weight: 600; padding-block: 6px; padding-inline: 12px; border-radius: 8px; cursor: pointer; border: 1px solid ${border}; background: ${recessed}; color: ${ink}; }`,
    `button.primary { background: ${actionBg}; color: ${actionInk}; border-color: ${actionBg}; }`,
    `button:focus-visible { outline: 2px solid ${accent}; outline-offset: 2px; }`,
  ].join("\n");

  const card = doc.createElement("div");
  card.className = "card";
  card.setAttribute("dir", opts.labels.dir);
  card.setAttribute("role", "alert");
  card.setAttribute("aria-live", "assertive");

  const heading = doc.createElement("p");
  heading.className = "title";
  heading.appendChild(createBdi(doc, opts.title));

  const summary = doc.createElement("p");
  summary.className = "summary";
  summary.appendChild(createBdi(doc, opts.summary));

  const ruleBadge = doc.createElement("span");
  ruleBadge.className = "rule";
  ruleBadge.appendChild(createBdi(doc, opts.ruleId));

  const actions = doc.createElement("div");
  actions.className = "actions";

  card.appendChild(heading);
  card.appendChild(summary);
  card.appendChild(ruleBadge);
  card.appendChild(actions);
  shadow.appendChild(style);
  shadow.appendChild(card);

  return new Promise((resolve) => {
    const cleanup = (choice: "continue" | "cancel") => {
      container.remove();
      resolve(choice);
    };

    if (opts.mode === "step_up") {
      const continueBtn = doc.createElement("button");
      continueBtn.type = "button";
      continueBtn.textContent = opts.labels.confirmContinue;
      continueBtn.addEventListener("click", () => cleanup("continue"));
      actions.appendChild(continueBtn);

      const cancelBtn = doc.createElement("button");
      cancelBtn.type = "button";
      cancelBtn.className = "primary";
      cancelBtn.textContent = opts.labels.cancelTransfer;
      cancelBtn.addEventListener("click", () => cleanup("cancel"));
      actions.appendChild(cancelBtn);

      doc.documentElement.appendChild(container);
      if (typeof cancelBtn.focus === "function") {
        cancelBtn.focus();
      }
      return;
    }

    const dismissBtn = doc.createElement("button");
    dismissBtn.type = "button";
    dismissBtn.className = "primary";
    dismissBtn.textContent = opts.labels.dismiss;
    dismissBtn.addEventListener("click", () => cleanup("cancel"));
    actions.appendChild(dismissBtn);
    setTimeout(() => cleanup("cancel"), 7_000);
    doc.documentElement.appendChild(container);
  });
}

export async function authorizeOrNotice(
  doc: Document,
  bridge: PageHookDecisionBridge,
  payload: PageOutboundInspectPayload,
): Promise<{ allowed: boolean; decision: BrowserInspectDecision }> {
  const decision = await bridge.requestDecision(payload);
  const customLabels = bridge.getLocaleStrings?.();
  const dir: "ltr" | "rtl" =
    customLabels?.dir === "rtl" ||
    doc.documentElement?.dataset.grdrDir === "rtl" ||
    doc.documentElement?.getAttribute("dir") === "rtl"
      ? "rtl"
      : "ltr";
  const labels: NoticeLocaleStrings = {
    ...DEFAULT_NOTICE_LABELS,
    ...customLabels,
    dir,
  };

  if (decision.verdict === "allow") {
    return { allowed: true, decision };
  }
  if (decision.verdict === "deny") {
    void showClosedShadowNotice(doc, {
      mode: "deny",
      title: `${labels.blockedPrefix} (${stripBidiControls(decision.appName)})`,
      summary: decision.reason,
      ruleId: decision.ruleId,
      labels,
    });
    return { allowed: false, decision };
  }

  const choice = await showClosedShadowNotice(doc, {
    mode: "step_up",
    title: `${labels.confirmPrefix} ${stripBidiControls(decision.appName)}`,
    summary: decision.reason,
    ruleId: decision.ruleId,
    labels,
  });
  return { allowed: choice === "continue", decision };
}
