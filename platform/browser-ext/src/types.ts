// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

export type BrowserMode = "off" | "watch" | "ask" | "block";
export type BrowserVerdict = "allow" | "step_up" | "deny";
export type BrowserTarget = "chrome" | "edge" | "firefox";
export type ActionClass =
  | "net_request"
  | "llm_request"
  | "mcp.call"
  | "cred_use"
  | "data_flow";

export type NativeHostStatus =
  | {
      kind: "connected";
      hostVersion: string;
      protocolVersion: number;
      uiLocale: string;
      connectedAtMs: number;
    }
  | { kind: "connecting"; startedAtMs: number }
  | {
      kind: "degraded";
      reason: "host_missing" | "host_disconnected" | "timeout" | "protocol_error";
      errorCode: string;
      message: string;
    };

export interface AiDestinationSpec {
  id: string;
  name: string;
  category: string;
  hosts: string[];
  wildcardHosts?: string[];
  hostPermissions: string[];
  uploadPathHints: string[];
  anonymousPathHints: string[];
  defaultMode: BrowserMode;
  blockFileUploads: boolean;
  blockSecretPayloads: boolean;
  tenantProviderId: string | null;
}

export interface AiDestinationsCatalog {
  schema: string;
  version: string;
  sensitiveFileExtensions: string[];
  destinations: AiDestinationSpec[];
}

export interface DnrProviderSpec {
  id: string;
  name: string;
  headerName: string;
  requestDomains: string[];
  hostPermissions: string[];
  multiValueSeparator: string;
  omitConsumerAccountsHeader: boolean;
  blockUrlFilters: string[];
  notes: string;
}

export interface TenantProvidersCatalog {
  schema: string;
  version: string;
  maxDnrRules: number;
  headerOperation: "set";
  providers: DnrProviderSpec[];
}

export interface DlpDetectorRule {
  id: string;
  kind: "secret" | "pii";
  severity: "deny" | "stepup";
  label: string;
  pattern: string;
  flags: string;
}

export interface DlpDetectorsCatalog {
  schema: string;
  version: string;
  maxInspectBytes: number;
  rules: DlpDetectorRule[];
}

export interface ManagedExtensionConfig {
  organizationId: string;
  serverOrigin: string;
  failClosedOnDegraded: boolean;
  blockAnonymousSessions: boolean;
  tenantRestrictions: Record<string, string[]>;
  appModes: Record<string, BrowserMode>;
}

export interface BrowserInspectRequest {
  requestId: string;
  tabId: number;
  url: string;
  hostname: string;
  method: string;
  transport: "fetch" | "xhr" | "websocket" | "beacon" | "eventsource" | "webmcp";
  actionClass: ActionClass;
  hasFileUpload: boolean;
  fileNames: string[];
  fileExtensions: string[];
  toolName?: string;
  toolDescription?: string;
  toolAnnotations?: Record<string, unknown>;
  bodyPreview: string;
}

export interface BrowserInspectDecision {
  requestId: string;
  verdict: BrowserVerdict;
  ruleId: string;
  reason: string;
  modeApplied: BrowserMode;
  appId: string | null;
  appName: string;
  source: "native_host" | "wasm_floor";
  hostDegraded: boolean;
  secretHits: string[];
  sensitiveExtensions: string[];
  flags: number;
}

export interface WebMcpToolEntry {
  tabId: number;
  origin: string;
  serverId: string;
  name: string;
  description: string;
  annotations: Record<string, unknown>;
  registeredAtMs: number;
  lastDecision?: BrowserVerdict;
}

export interface DecisionLedgerEntry {
  id: string;
  timestampMs: number;
  hostname: string;
  appName: string;
  transport: string;
  actionClass: ActionClass;
  verdict: BrowserVerdict;
  ruleId: string;
  reason: string;
  source: "native_host" | "wasm_floor";
  targetLabel: string;
}

export interface ExtensionStateSnapshot {
  extensionVersion: string;
  browserTarget: BrowserTarget;
  nativeStatus: NativeHostStatus;
  wasmInfo: {
    ready: boolean;
    abiVersion: number;
    importCount: number;
    floorRulesLoaded: number;
  };
  managedConfig: ManagedExtensionConfig;
  dnrSummary: {
    ruleCount: number;
    maxRules: number;
    activeHeaders: Array<{ providerId: string; headerName: string; value: string; domains: string[] }>;
    blockedAnonymousFilters: string[];
  };
  destinations: AiDestinationSpec[];
  webMcpTools: WebMcpToolEntry[];
  recentDecisions: DecisionLedgerEntry[];
  counters: {
    inspectedSession: number;
    blockedSession: number;
    stepUpSession: number;
  };
}
