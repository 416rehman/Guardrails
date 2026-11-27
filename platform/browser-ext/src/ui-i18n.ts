// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import modeIconNodes from "virtual:grdr-lucide-modes";
import aiDestinationsData from "../data/ai-destinations.json" with { type: "json" };
import tenantProvidersData from "../data/tenant-providers.json" with { type: "json" };
import { compileTenantDnrRules } from "./dnr-compiler.js";
import type {
  AiDestinationSpec,
  AiDestinationsCatalog,
  BrowserMode,
  BrowserVerdict,
  ExtensionStateSnapshot,
  ManagedExtensionConfig,
  TenantProvidersCatalog,
} from "./types.js";

const SVG_NS = "http://www.w3.org/2000/svg";

interface RuntimeApi {
  runtime?: {
    sendMessage: (msg: unknown) => Promise<ExtensionStateSnapshot | { ok: boolean; snapshot: ExtensionStateSnapshot }>;
    openOptionsPage?: () => Promise<void>;
    getURL?: (path: string) => string;
  };
  tabs?: {
    query: (q: { active: boolean; currentWindow: boolean }) => Promise<Array<{ url?: string }>>;
  };
  i18n?: {
    getMessage: (key: string) => string;
  };
}

export function getExtRuntime(): RuntimeApi | null {
  const g = globalThis as unknown as { chrome?: RuntimeApi; browser?: RuntimeApi };
  return g.chrome ?? g.browser ?? null;
}

export function t(key: string, fallback: string): string {
  const msg = getExtRuntime()?.i18n?.getMessage(key);
  return msg && msg.length > 0 ? msg : fallback;
}

export function stripBidiControls(value: string): string {
  return value.replace(/[\u200E\u200F\u202A-\u202E\u2066-\u2069]/g, "");
}

export function createBidiEl<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className: string,
  untrustedText: string,
): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  if (className) el.className = className;
  const bdi = document.createElement("bdi");
  bdi.textContent = stripBidiControls(untrustedText);
  el.appendChild(bdi);
  return el;
}

export function applyBidiRoot(): void {
  const rawDir = t("@@bidi_dir", "ltr");
  const params =
    typeof window !== "undefined" ? new URLSearchParams(window.location.search) : null;
  const urlDir = params?.get("dir");
  const resolvedDir = urlDir === "rtl" ? "rtl" : rawDir === "rtl" ? "rtl" : "ltr";
  document.documentElement.setAttribute("dir", resolvedDir);

  const urlTheme = params?.get("theme");
  const prefersDark =
    typeof window.matchMedia === "function" &&
    window.matchMedia("(prefers-color-scheme: dark)").matches;
  const dark = urlTheme === "dark" || (urlTheme !== "light" && prefersDark);
  document.documentElement.setAttribute("data-theme", dark ? "dark" : "light");
}

export function modeLabel(mode: BrowserMode): string {
  switch (mode) {
    case "off":
      return t("modeOff", "Off");
    case "watch":
      return t("modeWatch", "Watch");
    case "ask":
      return t("modeAsk", "Ask");
    case "block":
      return t("modeBlock", "Block");
  }
}

export function modeBadgeToneClass(mode: BrowserMode): string {
  switch (mode) {
    case "off":
      return "tone-neutral";
    case "watch":
      return "tone-watch";
    case "ask":
      return "tone-warn";
    case "block":
      return "tone-danger";
  }
}

export function verdictLabel(verdict: BrowserVerdict): string {
  switch (verdict) {
    case "allow":
      return t("verdictAllow", "Allow");
    case "step_up":
      return t("verdictStepUp", "Ask");
    case "deny":
      return t("verdictDeny", "Deny");
  }
}

export function verdictBadgeToneClass(verdict: BrowserVerdict): string {
  switch (verdict) {
    case "allow":
      return "tone-ok";
    case "step_up":
      return "tone-warn";
    case "deny":
      return "tone-danger";
  }
}

export function matchesDestinationHost(hostname: string, dest: AiDestinationSpec): boolean {
  const norm = hostname.toLowerCase();
  if (dest.hosts.some((h) => norm === h || norm.endsWith(`.${h}`))) {
    return true;
  }
  return Boolean(
    dest.wildcardHosts?.some((pattern) => {
      const suffix = pattern.startsWith("*.") ? pattern.slice(2) : pattern;
      return norm === suffix || norm.endsWith(`.${suffix}`);
    }),
  );
}

export function createModeIcon(mode: BrowserMode): SVGSVGElement {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("width", "12");
  svg.setAttribute("height", "12");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "2");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");

  const nodes = modeIconNodes[mode] ?? [];
  for (const [tag, attrs] of nodes) {
    const child = document.createElementNS(SVG_NS, tag);
    for (const [attr, value] of Object.entries(attrs)) {
      if (attr === "key") continue;
      child.setAttribute(attr, String(value));
    }
    svg.appendChild(child);
  }
  return svg;
}

export function renderModeRadiogroup(
  groupLabel: string,
  currentMode: BrowserMode,
  locked: boolean,
  onSelect: (mode: BrowserMode) => void,
): HTMLDivElement {
  const modes: BrowserMode[] = ["off", "watch", "ask", "block"];
  const group = document.createElement("div");
  group.className = "ext-segmented";
  group.setAttribute("role", "radiogroup");
  group.setAttribute("aria-label", groupLabel);

  for (const mode of modes) {
    const active = currentMode === mode;
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = `ext-seg-btn${active ? ` is-active ${modeBadgeToneClass(mode)}` : ""}`;
    btn.setAttribute("role", "radio");
    btn.setAttribute("aria-checked", active ? "true" : "false");
    btn.disabled = locked;
    btn.appendChild(createModeIcon(mode));
    const span = document.createElement("span");
    span.textContent = modeLabel(mode);
    btn.appendChild(span);
    btn.addEventListener("click", () => onSelect(mode));
    group.appendChild(btn);
  }
  return group;
}

export function unwrapSnapshotResponse(
  res: ExtensionStateSnapshot | { ok: boolean; snapshot: ExtensionStateSnapshot },
): ExtensionStateSnapshot {
  if ("snapshot" in res && res.snapshot) {
    return res.snapshot;
  }
  return res as ExtensionStateSnapshot;
}

export function createPreviewSnapshot(previewMode: string | null): ExtensionStateSnapshot {
  const destinations = (aiDestinationsData as AiDestinationsCatalog).destinations;
  const tenantCatalog = tenantProvidersData as TenantProvidersCatalog;
  const degraded = previewMode === "degraded";
  const now = Date.now();
  const managedConfig: ManagedExtensionConfig = {
    organizationId: "org-corp-prod",
    serverOrigin: "https://guardrails.internal:8443",
    failClosedOnDegraded: degraded,
    blockAnonymousSessions: true,
    tenantRestrictions: {
      anthropic: ["org-corp-prod"],
      openai_chatgpt: ["ws-corp-enterprise"],
      google_workspace: ["corp.example"],
      entra_id: ["tenant-corp-entra"],
      github_enterprise: ["corp-enterprise"],
    },
    appModes: {},
  };
  const compiledDnr = compileTenantDnrRules(tenantCatalog, managedConfig);

  return {
    extensionVersion: "0.1.0",
    browserTarget: "chrome",
    nativeStatus: degraded
      ? {
          kind: "degraded",
          reason: "host_missing",
          errorCode: "GRDR-EXT-0104",
          message: "Native host grdr.browser unreachable; enforcing local policy floor.",
        }
      : {
          kind: "connected",
          hostVersion: "0.1.0",
          protocolVersion: 1,
          uiLocale: "en",
          connectedAtMs: now - 45_000,
        },
    wasmInfo: {
      ready: true,
      abiVersion: 1,
      importCount: 0,
      floorRulesLoaded: 4,
    },
    managedConfig,
    dnrSummary: {
      ruleCount: compiledDnr.rules.length,
      maxRules: tenantCatalog.maxDnrRules,
      activeHeaders: compiledDnr.activeHeaders,
      blockedAnonymousFilters: compiledDnr.blockedAnonymousFilters,
    },
    destinations,
    webMcpTools: [
      {
        tabId: 1,
        origin: "https://chatgpt.com",
        serverId: "webmcp:chatgpt.com",
        name: "export_workspace_summary",
        description: "Exports workspace thread summary through WebMCP context.",
        annotations: { readOnlyHint: true },
        registeredAtMs: now - 12_000,
        lastDecision: "allow",
      },
      {
        tabId: 1,
        origin: "https://claude.ai",
        serverId: "webmcp:claude.ai",
        name: "sync_local_env",
        description: "Reads project configuration state via registered tool.",
        annotations: { destructiveHint: true },
        registeredAtMs: now - 6_000,
        lastDecision: "deny",
      },
    ],
    recentDecisions: [
      {
        id: "dec-1",
        timestampMs: now - 4_000,
        hostname: "chatgpt.com",
        appName: "ChatGPT",
        transport: "fetch",
        actionClass: "data_flow",
        verdict: "deny",
        ruleId: "dlp.secret.anthropic-key",
        reason: "Blocked outbound credential match in FormData transfer.",
        source: degraded ? "wasm_floor" : "native_host",
        targetLabel: ".env.production",
      },
      {
        id: "dec-2",
        timestampMs: now - 9_500,
        hostname: "claude.ai",
        appName: "Claude Web",
        transport: "webmcp",
        actionClass: "mcp.call",
        verdict: "step_up",
        ruleId: "browser.webmcp.ask",
        reason: "WebMCP tool invocation requires user confirmation under Ask mode.",
        source: "wasm_floor",
        targetLabel: "webmcp:sync_local_env",
      },
    ],
    counters: {
      inspectedSession: 18,
      blockedSession: 2,
      stepUpSession: 1,
    },
  };
}
