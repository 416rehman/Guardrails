// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import aiDestinationsData from "../data/ai-destinations.json" with { type: "json" };
import dlpDetectorsData from "../data/dlp-detectors.json" with { type: "json" };
import tenantProvidersData from "../data/tenant-providers.json" with { type: "json" };
import { compileTenantDnrRules } from "./dnr-compiler.js";
import {
  DEFAULT_DECIDE_BUDGET_MS,
  NativeHostBridge,
  boundAnnotations,
  buildRedactedDecidePayload,
} from "./native-protocol.js";
import type {
  AiDestinationsCatalog,
  BrowserInspectDecision,
  BrowserInspectRequest,
  BrowserMode,
  BrowserTarget,
  DecisionLedgerEntry,
  DlpDetectorsCatalog,
  ExtensionStateSnapshot,
  ManagedExtensionConfig,
  TenantProvidersCatalog,
  WebMcpToolEntry,
} from "./types.js";
import {
  DEFAULT_MANAGED_CONFIG,
  EXT_VERSION,
  MAX_LEDGER_ENTRIES,
  VALID_MODES,
  checkTabOriginParity,
  detectBrowserTarget,
  getExtApi,
  loadSessionStorage,
  makeFailClosedErrorDecision,
  makeUnloadedDecision,
  parseManagedConfig,
  sanitizeModesRecord,
  saveSessionStorage,
  validateInspectRequest,
  type ExtensionApiSurface,
} from "./service-worker-config.js";
import { WasmPolicyEngine } from "./wasm-host.js";

export class ExtensionRuntimeController {
  readonly destinations = aiDestinationsData as AiDestinationsCatalog;
  readonly dlpCatalog = dlpDetectorsData as DlpDetectorsCatalog;
  readonly tenantCatalog = tenantProvidersData as TenantProvidersCatalog;
  readonly nativeBridge = new NativeHostBridge();

  private engine: WasmPolicyEngine | null = null;
  private managedConfig: ManagedExtensionConfig = { ...DEFAULT_MANAGED_CONFIG };
  private localAppModes: Record<string, BrowserMode> = {};
  private webMcpTools: WebMcpToolEntry[] = [];
  private recentDecisions: DecisionLedgerEntry[] = [];
  private counters = { inspectedSession: 0, blockedSession: 0, stepUpSession: 0 };
  private dnrSummary: ExtensionStateSnapshot["dnrSummary"] = {
    ruleCount: 0,
    maxRules: (tenantProvidersData as TenantProvidersCatalog).maxDnrRules,
    activeHeaders: [],
    blockedAnonymousFilters: [],
  };
  private readonly browserTarget: BrowserTarget;
  private readonly api: ExtensionApiSurface | null;

  constructor(api = getExtApi()) {
    this.api = api;
    this.browserTarget = detectBrowserTarget(api);
  }

  async initialize(wasmBytesOverride?: Uint8Array): Promise<void> {
    let wasmBytes = wasmBytesOverride;
    if (!wasmBytes && this.api?.runtime?.getURL) {
      const url = this.api.runtime.getURL("wasm/grdr_browser_wasm.wasm");
      const resp = await fetch(url);
      wasmBytes = new Uint8Array(await resp.arrayBuffer());
    }
    if (wasmBytes) {
      this.engine = await WasmPolicyEngine.create(
        wasmBytes,
        this.destinations,
        this.dlpCatalog,
      );
      this.engine.loadDefaultBrowserFloor();
    }
    await this.loadSessionState();
    await this.reloadConfiguration();
    this.reconnectNativeHost();
  }

  async reloadConfiguration(): Promise<void> {
    let managedRaw: Record<string, unknown> = {};
    let localRaw: Record<string, unknown> = {};
    try {
      if (this.api?.storage?.managed) {
        managedRaw = await this.api.storage.managed.get(null);
      }
    } catch {
      managedRaw = {};
    }
    try {
      if (this.api?.storage?.local) {
        localRaw = await this.api.storage.local.get(["appModes"]);
      }
    } catch {
      localRaw = {};
    }

    this.managedConfig = parseManagedConfig(managedRaw);
    this.localAppModes = sanitizeModesRecord(localRaw.appModes);
    await this.applyDnrRules();
  }

  async setAppModeOverride(appId: string, mode: BrowserMode): Promise<boolean> {
    if (!VALID_MODES.has(mode)) {
      return false;
    }
    if (!this.destinations.destinations.some((d) => d.id === appId)) {
      return false;
    }
    if (this.managedConfig.appModes[appId]) {
      return false;
    }
    this.localAppModes = { ...this.localAppModes, [appId]: mode };
    if (this.api?.storage?.local) {
      await this.api.storage.local.set({ appModes: this.localAppModes });
    }
    return true;
  }

  reconnectNativeHost(): void {
    const connector = this.api?.runtime?.connectNative;
    if (!connector || !this.api?.runtime) {
      this.nativeBridge.connect(
        () => null,
        EXT_VERSION,
        this.browserTarget,
        this.managedConfig,
      );
      return;
    }
    this.nativeBridge.connect(
      (name) => connector.call(this.api?.runtime, name) as never,
      EXT_VERSION,
      this.browserTarget,
      this.managedConfig,
      () => this.api?.runtime?.lastError?.message,
    );
  }

  async applyDnrRules(): Promise<void> {
    const compiled = compileTenantDnrRules(this.tenantCatalog, this.managedConfig);
    this.dnrSummary = {
      ruleCount: compiled.rules.length,
      maxRules: this.tenantCatalog.maxDnrRules,
      activeHeaders: compiled.activeHeaders,
      blockedAnonymousFilters: compiled.blockedAnonymousFilters,
    };

    if (this.api?.declarativeNetRequest) {
      const existing = await this.api.declarativeNetRequest.getDynamicRules();
      const removeRuleIds = existing.map((rule) => rule.id);
      await this.api.declarativeNetRequest.updateDynamicRules({
        removeRuleIds,
        addRules: compiled.rules,
      });
    }

    this.nativeBridge.sendEvent({
      type: "event",
      kind: "dnr.applied",
      hostname: "browser-dnr",
      transport: "dnr",
      secret_rule_ids: [],
      file_extensions: [],
    });
  }

  async inspectAction(req: BrowserInspectRequest): Promise<BrowserInspectDecision> {
    const combinedModes = {
      ...this.localAppModes,
      ...this.managedConfig.appModes,
    };
    const dest = this.engine?.matchDestination(req.hostname) ?? null;
    const effectiveMode: BrowserMode = dest
      ? (combinedModes[dest.id] ?? dest.defaultMode)
      : "watch";

    if (!this.engine) {
      const unloadedDecision = makeUnloadedDecision(
        req,
        effectiveMode,
        this.managedConfig.failClosedOnDegraded,
        dest,
      );
      this.recordDecision(req, unloadedDecision);
      await this.updateBadge(req.tabId, unloadedDecision);
      return unloadedDecision;
    }

    const hostStatusBefore = this.nativeBridge.getStatus();
    const hostDegradedBefore = hostStatusBefore.kind === "degraded";
    let finalDecision = this.engine.evaluateLocally(
      req,
      combinedModes,
      this.managedConfig.failClosedOnDegraded,
      hostDegradedBefore,
    );

    if (!hostDegradedBefore) {
      const decideMsg = buildRedactedDecidePayload(
        req,
        finalDecision.secretHits,
        DEFAULT_DECIDE_BUDGET_MS,
      );
      const nativeVerdict = await this.nativeBridge.requestDecision(
        decideMsg,
        DEFAULT_DECIDE_BUDGET_MS,
      );
      if (nativeVerdict) {
        finalDecision = {
          ...finalDecision,
          verdict: finalDecision.verdict === "deny" ? "deny" : nativeVerdict.verdict,
          ruleId: finalDecision.verdict === "deny" ? finalDecision.ruleId : nativeVerdict.rule_id,
          reason: finalDecision.verdict === "deny" ? finalDecision.reason : nativeVerdict.reason,
          source: "native_host",
          hostDegraded: false,
        };
      } else {
        const hostDegradedAfter = this.nativeBridge.getStatus().kind !== "connected";
        finalDecision = this.engine.evaluateLocally(
          req,
          combinedModes,
          this.managedConfig.failClosedOnDegraded,
          hostDegradedAfter,
        );
      }
    }

    this.recordDecision(req, finalDecision);
    await this.updateBadge(req.tabId, finalDecision);
    return finalDecision;
  }

  recordWebMcpRegistration(
    tabId: number,
    hostname: string,
    toolName: string,
    description: string,
    annotations: Record<string, unknown>,
  ): void {
    const cleanHostname = hostname.trim().toLowerCase().slice(0, 256);
    const cleanAnnotations = boundAnnotations(annotations) ?? {};
    const serverId = `webmcp:${cleanHostname}`;
    const existingIdx = this.webMcpTools.findIndex(
      (entry) => entry.tabId === tabId && entry.serverId === serverId && entry.name === toolName,
    );
    const nextEntry: WebMcpToolEntry = {
      tabId,
      origin: `https://${cleanHostname}`,
      serverId,
      name: toolName,
      description: description.slice(0, 500),
      annotations: cleanAnnotations,
      registeredAtMs: Date.now(),
    };
    if (existingIdx >= 0) {
      this.webMcpTools[existingIdx] = nextEntry;
    } else {
      this.webMcpTools = [nextEntry, ...this.webMcpTools].slice(0, MAX_LEDGER_ENTRIES);
    }
    void this.saveSessionState();
    this.nativeBridge.sendEvent({
      type: "event",
      kind: "mcp.call",
      hostname,
      transport: "webmcp",
      tool_name: toolName,
      server_id: serverId,
      secret_rule_ids: [],
      file_extensions: [],
    });
  }

  getSnapshot(): ExtensionStateSnapshot {
    const combinedModes = {
      ...this.localAppModes,
      ...this.managedConfig.appModes,
    };
    return {
      extensionVersion: EXT_VERSION,
      browserTarget: this.browserTarget,
      nativeStatus: this.nativeBridge.getStatus(),
      wasmInfo: {
        ready: this.engine !== null,
        abiVersion: this.engine?.abiVersion ?? 0,
        importCount: this.engine?.importCount ?? 0,
        floorRulesLoaded: this.engine?.loadedFloorRules ?? 0,
      },
      managedConfig: this.managedConfig,
      dnrSummary: this.dnrSummary,
      destinations: this.destinations.destinations.map((d) => ({
        ...d,
        defaultMode: combinedModes[d.id] ?? d.defaultMode,
      })),
      webMcpTools: this.webMcpTools,
      recentDecisions: this.recentDecisions,
      counters: { ...this.counters },
    };
  }

  private async loadSessionState(): Promise<void> {
    const loaded = await loadSessionStorage(this.api);
    if (!loaded) return;
    this.counters = loaded.counters;
    this.recentDecisions = loaded.recentDecisions;
    this.webMcpTools = loaded.webMcpTools;
  }

  private async saveSessionState(): Promise<void> {
    await saveSessionStorage(this.api, {
      counters: this.counters,
      recentDecisions: this.recentDecisions,
      webMcpTools: this.webMcpTools,
    });
  }

  private recordDecision(req: BrowserInspectRequest, decision: BrowserInspectDecision): void {
    this.counters.inspectedSession += 1;
    if (decision.verdict === "deny") this.counters.blockedSession += 1;
    if (decision.verdict === "step_up") this.counters.stepUpSession += 1;

    if (req.actionClass === "mcp.call" && req.toolName) {
      this.webMcpTools = this.webMcpTools.map((tool) =>
        tool.tabId === req.tabId && tool.name === req.toolName
          ? { ...tool, lastDecision: decision.verdict }
          : tool,
      );
    }

    const entry: DecisionLedgerEntry = {
      id: decision.requestId,
      timestampMs: Date.now(),
      hostname: req.hostname,
      appName: decision.appName,
      transport: req.transport,
      actionClass: req.actionClass,
      verdict: decision.verdict,
      ruleId: decision.ruleId,
      reason: decision.reason,
      source: decision.source,
      targetLabel: req.toolName
        ? `webmcp:${req.toolName}`
        : (req.fileNames[0] ?? req.hostname),
    };
    this.recentDecisions = [entry, ...this.recentDecisions].slice(0, MAX_LEDGER_ENTRIES);
    void this.saveSessionState();
  }

  private async updateBadge(tabId: number, decision: BrowserInspectDecision): Promise<void> {
    if (!this.api?.action) return;
    const text =
      decision.verdict === "deny"
        ? "BLK"
        : decision.verdict === "step_up"
          ? "ASK"
          : decision.hostDegraded
            ? "DEG"
            : "OK";
    try {
      await this.api.action.setBadgeText({ text, tabId: tabId > 0 ? tabId : undefined });
    } catch {
      // Ignore closed tab badge update races.
    }
  }
}

export function registerRuntimeMessageListener(
  runtimeApi: ExtensionApiSurface,
  controller: ExtensionRuntimeController,
  readyPromise: Promise<void>,
): void {
  if (!runtimeApi.runtime?.onMessage) return;
  const selfExtId = runtimeApi.runtime.id;

  runtimeApi.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (selfExtId && sender.id !== selfExtId) {
      sendResponse({ ok: false, error: "GRDR-EXT-0302 Foreign extension sender rejected" });
      return false;
    }

    const msg = message as Record<string, unknown> | undefined;
    if (!msg || typeof msg.type !== "string") {
      return false;
    }
    const tabId = sender.tab?.id ?? 0;
    const tabUrl = sender.tab?.url;
    const isFromTab = Boolean(sender.tab);

    readyPromise
      .then(async () => {
        if (msg.type === "ext:inspect") {
          const validReq = validateInspectRequest(
            msg.payload,
            tabId,
            tabUrl,
            controller.destinations.destinations,
          );
          if (!validReq) {
            sendResponse(
              makeFailClosedErrorDecision(
                "invalid",
                "browser.inspect.invalid-payload",
                "Malformed inspection request rejected fail-closed.",
              ),
            );
            return;
          }
          const decision = await controller.inspectAction(validReq);
          sendResponse(decision);
          return;
        }
        if (msg.type === "ext:telemetry" && msg.event && typeof msg.event === "object") {
          const evt = msg.event as {
            kind?: unknown;
            hostname?: unknown;
            toolName?: unknown;
            description?: unknown;
            annotations?: unknown;
          };
          if (typeof evt.hostname !== "string" || typeof evt.toolName !== "string") {
            sendResponse({ ok: false });
            return;
          }
          const cleanHost = evt.hostname.trim().toLowerCase().slice(0, 256);
          if (
            !cleanHost ||
            !checkTabOriginParity(tabUrl, cleanHost, controller.destinations.destinations, true)
          ) {
            sendResponse({ ok: false, error: "GRDR-EXT-0303 Tab telemetry origin mismatch" });
            return;
          }
          if (evt.kind === "webmcp.register") {
            const boundedAnn = boundAnnotations(
              evt.annotations && typeof evt.annotations === "object"
                ? (evt.annotations as Record<string, unknown>)
                : undefined,
            );
            controller.recordWebMcpRegistration(
              tabId,
              cleanHost,
              evt.toolName.slice(0, 128),
              typeof evt.description === "string" ? evt.description.slice(0, 500) : "",
              boundedAnn ?? {},
            );
          } else if (evt.kind === "toolactivated" || evt.kind === "toolcancel") {
            controller.nativeBridge.sendEvent({
              type: "event",
              kind: evt.kind,
              hostname: cleanHost,
              transport: "webmcp",
              tool_name: evt.toolName.slice(0, 128),
              server_id: `webmcp:${cleanHost}`,
              secret_rule_ids: [],
              file_extensions: [],
            });
          }
          sendResponse({ ok: true });
          return;
        }

        if (isFromTab) {
          sendResponse({ ok: false, error: "GRDR-EXT-0301 Tab context denied" });
          return;
        }

        if (msg.type === "ext:get_snapshot") {
          sendResponse(controller.getSnapshot());
          return;
        }
        if (msg.type === "ext:reconnect_host") {
          controller.reconnectNativeHost();
          sendResponse(controller.getSnapshot());
          return;
        }
        if (
          msg.type === "ext:set_app_mode" &&
          typeof msg.appId === "string" &&
          typeof msg.mode === "string"
        ) {
          const updated = await controller.setAppModeOverride(msg.appId, msg.mode as BrowserMode);
          sendResponse({ ok: updated, snapshot: controller.getSnapshot() });
          return;
        }
        sendResponse({ ok: false });
      })
      .catch((err) => {
        sendResponse(
          makeFailClosedErrorDecision(
            "init-error",
            "browser.sw.init-failed",
            err instanceof Error ? err.message : "Extension runtime failed initialization.",
          ),
        );
      });

    return true;
  });
}

const runtimeApi = getExtApi();
if (runtimeApi?.runtime?.onMessage) {
  const controller = new ExtensionRuntimeController(runtimeApi);
  const readyPromise = controller.initialize();
  registerRuntimeMessageListener(runtimeApi, controller, readyPromise);
}
