const TOKEN_STORAGE_KEY = "grdr_api_token";

export const CONNECT_PATHS = {
  getHealth: "/grdr.api.overview.v1alpha1.OverviewService/GetHealth",
  getOverview: "/grdr.api.overview.v1alpha1.OverviewService/GetOverview",
  listKeys: "/grdr.api.overview.v1alpha1.OverviewService/ListKeys",
  exportOcsf: "/grdr.api.overview.v1alpha1.OverviewService/ExportOcsf",
  exportAuditJsonl: "/grdr.api.overview.v1alpha1.OverviewService/ExportAuditJsonl",
  liveEvents: "/grdr.api.overview.v1alpha1.OverviewService/LiveEvents",
  evaluate: "/grdr.api.verdict.v1alpha1.VerdictService/Evaluate",
  evaluateBrowser: "/grdr.api.verdict.v1alpha1.VerdictService/EvaluateBrowser",
  listPacks: "/grdr.api.policy.v1alpha1.PolicyService/ListPacks",
  createRule: "/grdr.api.policy.v1alpha1.PolicyService/CreateRule",
  updateRule: "/grdr.api.policy.v1alpha1.PolicyService/UpdateRule",
  deleteRule: "/grdr.api.policy.v1alpha1.PolicyService/DeleteRule",
  updateRuleMode: "/grdr.api.policy.v1alpha1.PolicyService/UpdateRuleMode",
  replayRule: "/grdr.api.policy.v1alpha1.PolicyService/ReplayRule",
  listBrowserPolicies: "/grdr.api.policy.v1alpha1.PolicyService/ListBrowserPolicies",
  updateBrowserPolicy: "/grdr.api.policy.v1alpha1.PolicyService/UpdateBrowserPolicy",
  listDevices: "/grdr.api.inventory.v1alpha1.InventoryService/ListDevices",
  listAgents: "/grdr.api.inventory.v1alpha1.InventoryService/ListAgents",
  listMcpServers: "/grdr.api.inventory.v1alpha1.InventoryService/ListMcpServers",
  listArtifacts: "/grdr.api.inventory.v1alpha1.InventoryService/ListArtifacts",
  getConnectConfig: "/grdr.api.inventory.v1alpha1.InventoryService/GetConnectConfig",
  createDeploymentKey: "/grdr.api.inventory.v1alpha1.InventoryService/CreateDeploymentKey",
  revokeDeploymentKey: "/grdr.api.inventory.v1alpha1.InventoryService/RevokeDeploymentKey",
  renderMdmConfig: "/grdr.api.inventory.v1alpha1.InventoryService/RenderMdmConfig",
  checkIntegrationReadiness: "/grdr.api.inventory.v1alpha1.InventoryService/CheckIntegrationReadiness",
  listSessions: "/grdr.api.activity.v1alpha1.SessionService/ListSessions",
  getSession: "/grdr.api.activity.v1alpha1.SessionService/GetSession",
  listUsers: "/grdr.api.tenancy.v1alpha1.UserService/ListUsers",
  getUser: "/grdr.api.tenancy.v1alpha1.UserService/GetUser",
  getPrivacyConfig: "/grdr.api.tenancy.v1alpha1.UserService/GetPrivacyConfig",
  updatePrivacyConfig: "/grdr.api.tenancy.v1alpha1.UserService/UpdatePrivacyConfig",
  listApprovals: "/grdr.api.response.v1alpha1.ResponseService/ListApprovals",
  decideApproval: "/grdr.api.response.v1alpha1.ResponseService/DecideApproval",
  listFindings: "/grdr.api.response.v1alpha1.ResponseService/ListFindings",
  updateFinding: "/grdr.api.response.v1alpha1.ResponseService/UpdateFinding",
  listIncidents: "/grdr.api.response.v1alpha1.ResponseService/ListIncidents",
  getKillSwitch: "/grdr.api.response.v1alpha1.ResponseService/GetKillSwitch",
  setKillSwitch: "/grdr.api.response.v1alpha1.ResponseService/SetKillSwitch",
  listAuditEvents: "/grdr.api.response.v1alpha1.ResponseService/ListAuditEvents",
} as const;

export interface ConnectErrorDetailEnvelope {
  type?: string;
  value?: string;
  debug?: {
    reason?: string;
    domain?: string;
    code?: string;
    metadata?: Record<string, string>;
  };
}

export class ConnectApiError extends Error {
  readonly code: string;
  readonly reason: string;
  readonly grdrCode: string;
  readonly requestId: string;

  constructor(opts: {
    code: string;
    reason: string;
    grdrCode: string;
    message: string;
    requestId: string;
  }) {
    const prefix = opts.grdrCode || opts.code;
    super(prefix ? `${prefix}: ${opts.message}` : opts.message);
    this.name = "ConnectApiError";
    this.code = opts.code;
    this.reason = opts.reason;
    this.grdrCode = opts.grdrCode;
    this.requestId = opts.requestId;
  }
}

export function getApiToken(): string {
  try {
    return window.sessionStorage.getItem(TOKEN_STORAGE_KEY) ?? "";
  } catch {
    return "";
  }
}

export function setApiToken(token: string): void {
  try {
    const trimmed = token.trim();
    if (trimmed) {
      window.sessionStorage.setItem(TOKEN_STORAGE_KEY, trimmed);
    } else {
      window.sessionStorage.removeItem(TOKEN_STORAGE_KEY);
    }
  } catch {
    // ignore storage errors in non-browser tests
  }
}

export function connectLiveUrl(): string {
  const token = getApiToken();
  return token
    ? `${CONNECT_PATHS.liveEvents}?access_token=${encodeURIComponent(token)}`
    : CONNECT_PATHS.liveEvents;
}

function authHeaders(): Record<string, string> {
  const token = getApiToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function parseError(resp: Response): Promise<ConnectApiError> {
  const reqId = resp.headers?.get("grdr-request-id") ?? "";
  let code = `http_${resp.status}`;
  let message = `Request failed (${resp.status})`;
  let reason = "";
  let grdrCode = "";

  try {
    const parsed = (await resp.json()) as {
      code?: string;
      message?: string;
      details?: ConnectErrorDetailEnvelope[];
    };
    if (parsed.code) code = parsed.code;
    if (parsed.message) message = parsed.message;
    for (const d of parsed.details ?? []) {
      if (d.debug?.reason && !reason) reason = d.debug.reason;
      const metaCode = d.debug?.metadata?.code ?? d.debug?.code;
      if (metaCode && !grdrCode) grdrCode = metaCode;
    }
  } catch {
    // keep status fallback message
  }

  return new ConnectApiError({ code, reason, grdrCode, message, requestId: reqId });
}

export async function connectPost<T>(path: string, body: unknown = {}): Promise<T> {
  const resp = await fetch(path, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Connect-Protocol-Version": "1",
      ...authHeaders(),
    },
    body: JSON.stringify(body),
  });
  if (!resp.ok) {
    throw await parseError(resp);
  }
  return (await resp.json()) as T;
}

export async function connectGet<T>(path: string, message?: unknown): Promise<T> {
  const query =
    message !== undefined
      ? `?encoding=json&message=${encodeURIComponent(JSON.stringify(message))}`
      : "?encoding=json";
  const resp = await fetch(`${path}${query}`, {
    method: "GET",
    headers: {
      ...authHeaders(),
    },
  });
  if (!resp.ok) {
    throw await parseError(resp);
  }
  return (await resp.json()) as T;
}
