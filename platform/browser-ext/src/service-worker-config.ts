// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import { boundAnnotations } from "./native-protocol.js";
import type {
  ActionClass,
  AiDestinationSpec,
  BrowserInspectDecision,
  BrowserInspectRequest,
  BrowserMode,
  BrowserTarget,
  DecisionLedgerEntry,
  ManagedExtensionConfig,
  WebMcpToolEntry,
} from "./types.js";

export const MAX_LEDGER_ENTRIES = 100;
export const EXT_VERSION = "0.1.0";
export const VALID_MODES = new Set<BrowserMode>(["off", "watch", "ask", "block"]);
const VALID_TRANSPORTS = new Set(["fetch", "xhr", "websocket", "beacon", "eventsource", "webmcp"]);
const VALID_ACTIONS = new Set<ActionClass>([
  "net_request",
  "llm_request",
  "mcp.call",
  "cred_use",
  "data_flow",
]);
const ALLOWED_URL_PROTOCOLS = new Set(["http:", "https:", "ws:", "wss:"]);

export const DEFAULT_MANAGED_CONFIG: ManagedExtensionConfig = {
  organizationId: "org-corp-prod",
  serverOrigin: "https://guardrails.internal:8443",
  failClosedOnDegraded: false,
  blockAnonymousSessions: true,
  tenantRestrictions: {},
  appModes: {},
};

export interface ExtensionApiSurface {
  runtime?: {
    id?: string;
    getURL: (path: string) => string;
    getManifest: () => { version?: string; browser_specific_settings?: unknown };
    connectNative?: (name: string) => unknown;
    lastError?: { message?: string };
    onMessage: {
      addListener: (
        fn: (
          message: unknown,
          sender: { id?: string; origin?: string; url?: string; tab?: { id?: number; url?: string } },
          sendResponse: (resp: unknown) => void,
        ) => boolean | void,
      ) => void;
    };
  };
  storage?: {
    managed?: { get: (keys?: unknown) => Promise<Record<string, unknown>> };
    session?: {
      get: (keys?: unknown) => Promise<Record<string, unknown>>;
      set: (values: Record<string, unknown>) => Promise<void>;
    };
    local?: {
      get: (keys?: unknown) => Promise<Record<string, unknown>>;
      set: (values: Record<string, unknown>) => Promise<void>;
    };
  };
  declarativeNetRequest?: {
    getDynamicRules: () => Promise<Array<{ id: number }>>;
    updateDynamicRules: (opts: {
      removeRuleIds?: number[];
      addRules?: unknown[];
    }) => Promise<void>;
  };
  action?: {
    setBadgeText: (opts: { text: string; tabId?: number }) => Promise<void>;
  };
}

export function getExtApi(): ExtensionApiSurface | null {
  const g = globalThis as unknown as {
    chrome?: ExtensionApiSurface;
    browser?: ExtensionApiSurface;
  };
  return g.chrome ?? g.browser ?? null;
}

export function detectBrowserTarget(api: ExtensionApiSurface | null): BrowserTarget {
  const manifest = api?.runtime?.getManifest?.();
  if (manifest?.browser_specific_settings) {
    return "firefox";
  }
  const ua = typeof navigator !== "undefined" ? navigator.userAgent : "";
  if (ua.includes("Edg/")) return "edge";
  return "chrome";
}

export function sanitizeModesRecord(raw: unknown): Record<string, BrowserMode> {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return {};
  }
  const clean: Record<string, BrowserMode> = {};
  for (const [key, value] of Object.entries(raw as Record<string, unknown>)) {
    if (typeof value === "string" && VALID_MODES.has(value as BrowserMode)) {
      clean[key] = value as BrowserMode;
    }
  }
  return clean;
}

export function sanitizeTenantRestrictions(raw: unknown): Record<string, string[]> {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return {};
  }
  const clean: Record<string, string[]> = {};
  for (const [provider, entries] of Object.entries(raw as Record<string, unknown>)) {
    if (Array.isArray(entries)) {
      clean[provider] = entries.filter((v): v is string => typeof v === "string");
    }
  }
  return clean;
}

export function parseManagedConfig(raw: Record<string, unknown>): ManagedExtensionConfig {
  return {
    organizationId:
      typeof raw.organizationId === "string" && raw.organizationId.trim()
        ? raw.organizationId.trim()
        : DEFAULT_MANAGED_CONFIG.organizationId,
    serverOrigin:
      typeof raw.serverOrigin === "string" && raw.serverOrigin.trim()
        ? raw.serverOrigin.trim()
        : DEFAULT_MANAGED_CONFIG.serverOrigin,
    failClosedOnDegraded: raw.failClosedOnDegraded === true,
    blockAnonymousSessions: raw.blockAnonymousSessions !== false,
    tenantRestrictions: sanitizeTenantRestrictions(raw.tenantRestrictions),
    appModes: sanitizeModesRecord(raw.appModes),
  };
}

export function matchDestinationHost(
  hostname: string,
  destinations: AiDestinationSpec[],
): AiDestinationSpec | null {
  const norm = hostname.toLowerCase();
  for (const dest of destinations) {
    if (dest.hosts.some((h) => norm === h || norm.endsWith(`.${h}`))) {
      return dest;
    }
    if (
      dest.wildcardHosts?.some((pattern) => {
        const suffix = pattern.startsWith("*.") ? pattern.slice(2) : pattern;
        return norm === suffix || norm.endsWith(`.${suffix}`);
      })
    ) {
      return dest;
    }
  }
  return null;
}

export function canonicalHostnameFromUrl(rawUrl: string): string | null {
  try {
    const parsed = new URL(rawUrl);
    if (!ALLOWED_URL_PROTOCOLS.has(parsed.protocol) || !parsed.hostname) {
      return null;
    }
    return parsed.hostname.toLowerCase();
  } catch {
    return null;
  }
}

export function checkTabOriginParity(
  tabUrl: string | undefined,
  targetHostname: string,
  destinations: AiDestinationSpec[],
  exactHostOnly: boolean,
): boolean {
  if (!tabUrl) return true;
  let tabHost: string | null = null;
  try {
    const tabParsed = new URL(tabUrl);
    if (tabParsed.protocol === "about:" || tabParsed.protocol === "blob:") {
      return true;
    }
    if (tabParsed.protocol !== "http:" && tabParsed.protocol !== "https:") {
      return false;
    }
    tabHost = tabParsed.hostname.toLowerCase();
  } catch {
    return false;
  }
  if (!tabHost) return false;
  if (tabHost === targetHostname || targetHostname.endsWith(`.${tabHost}`)) {
    return true;
  }
  if (exactHostOnly) {
    return false;
  }
  const tabDest = matchDestinationHost(tabHost, destinations);
  const targetDest = matchDestinationHost(targetHostname, destinations);
  return tabDest !== null && targetDest !== null && tabDest.id === targetDest.id;
}

export function validateInspectRequest(
  raw: unknown,
  tabId: number,
  tabUrl?: string,
  destinations: AiDestinationSpec[] = [],
): BrowserInspectRequest | null {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const obj = raw as Record<string, unknown>;
  if (
    typeof obj.requestId !== "string" ||
    !obj.requestId ||
    typeof obj.url !== "string" ||
    typeof obj.transport !== "string" ||
    !VALID_TRANSPORTS.has(obj.transport) ||
    typeof obj.actionClass !== "string" ||
    !VALID_ACTIONS.has(obj.actionClass as ActionClass)
  ) {
    return null;
  }
  const canonicalHost = canonicalHostnameFromUrl(obj.url);
  if (!canonicalHost) {
    return null;
  }
  if (
    destinations.length > 0 &&
    !checkTabOriginParity(tabUrl, canonicalHost, destinations, obj.transport === "webmcp")
  ) {
    return null;
  }

  return {
    requestId: obj.requestId.slice(0, 128),
    tabId,
    url: obj.url.slice(0, 2048),
    hostname: canonicalHost.slice(0, 256),
    method: typeof obj.method === "string" ? obj.method.slice(0, 16) : "POST",
    transport: obj.transport as BrowserInspectRequest["transport"],
    actionClass: obj.actionClass as ActionClass,
    hasFileUpload: obj.hasFileUpload === true,
    fileNames: Array.isArray(obj.fileNames)
      ? obj.fileNames.filter((s): s is string => typeof s === "string").slice(0, 32)
      : [],
    fileExtensions: Array.isArray(obj.fileExtensions)
      ? obj.fileExtensions.filter((s): s is string => typeof s === "string").slice(0, 32)
      : [],
    toolName: typeof obj.toolName === "string" ? obj.toolName.slice(0, 128) : undefined,
    toolDescription:
      typeof obj.toolDescription === "string" ? obj.toolDescription.slice(0, 500) : undefined,
    toolAnnotations: boundAnnotations(
      obj.toolAnnotations && typeof obj.toolAnnotations === "object"
        ? (obj.toolAnnotations as Record<string, unknown>)
        : undefined,
    ),
    bodyPreview: typeof obj.bodyPreview === "string" ? obj.bodyPreview.slice(0, 65_536) : "",
  };
}

export function makeUnloadedDecision(
  req: BrowserInspectRequest,
  effectiveMode: BrowserMode,
  failClosedOnDegraded: boolean,
  dest: AiDestinationSpec | null,
): BrowserInspectDecision {
  return {
    requestId: req.requestId,
    verdict: failClosedOnDegraded || effectiveMode === "block" ? "deny" : "step_up",
    ruleId: "browser.wasm.unloaded",
    reason: "Wasm policy engine unavailable; enforcing fail-closed protection.",
    modeApplied: effectiveMode,
    appId: dest?.id ?? null,
    appName: dest?.name ?? req.hostname,
    source: "wasm_floor",
    hostDegraded: true,
    secretHits: [],
    sensitiveExtensions: [],
    flags: 0,
  };
}

export function makeFailClosedErrorDecision(
  requestId: string,
  ruleId: string,
  reason: string,
): BrowserInspectDecision {
  return {
    requestId,
    verdict: "deny",
    ruleId,
    reason,
    modeApplied: "block",
    appId: null,
    appName: "browser",
    source: "wasm_floor",
    hostDegraded: true,
    secretHits: [],
    sensitiveExtensions: [],
    flags: 0,
  };
}

export interface SessionSnapshotData {
  counters: { inspectedSession: number; blockedSession: number; stepUpSession: number };
  recentDecisions: DecisionLedgerEntry[];
  webMcpTools: WebMcpToolEntry[];
}

export async function loadSessionStorage(api: ExtensionApiSurface | null): Promise<SessionSnapshotData | null> {
  try {
    const stored = await api?.storage?.session?.get(["counters", "recentDecisions", "webMcpTools"]);
    if (!stored) return null;
    const c = stored.counters && typeof stored.counters === "object" ? (stored.counters as Record<string, unknown>) : {};
    return {
      counters: {
        inspectedSession: typeof c.inspectedSession === "number" ? c.inspectedSession : 0,
        blockedSession: typeof c.blockedSession === "number" ? c.blockedSession : 0,
        stepUpSession: typeof c.stepUpSession === "number" ? c.stepUpSession : 0,
      },
      recentDecisions: Array.isArray(stored.recentDecisions)
        ? (stored.recentDecisions.slice(0, MAX_LEDGER_ENTRIES) as DecisionLedgerEntry[])
        : [],
      webMcpTools: Array.isArray(stored.webMcpTools)
        ? (stored.webMcpTools.slice(0, MAX_LEDGER_ENTRIES) as WebMcpToolEntry[])
        : [],
    };
  } catch {
    return null;
  }
}

export async function saveSessionStorage(api: ExtensionApiSurface | null, data: SessionSnapshotData): Promise<void> {
  try {
    await api?.storage?.session?.set({
      counters: data.counters,
      recentDecisions: data.recentDecisions.slice(0, MAX_LEDGER_ENTRIES),
      webMcpTools: data.webMcpTools.slice(0, MAX_LEDGER_ENTRIES),
    });
  } catch {
    // Ignore transient storage.session write errors.
  }
}
