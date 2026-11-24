import type {
  ActionClass,
  ApprovalRequest,
  DecisionReceipt,
  Device,
  DiscoveredAgent,
  Finding,
  FindingLifecycle,
  GrantScope,
  Incident,
  KillAction,
  KillScope,
  KillSwitchState,
  McpServerEntry,
  Mode,
  OverviewResponse,
  PolicyPack,
  PolicyRule,
  ReplaySummary,
  SessionDetailResponse,
  SessionSummary,
} from "./types";

const TOKEN_STORAGE_KEY = "grdr_api_token";

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

function authHeaders(): Record<string, string> {
  const token = getApiToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function requestJson<T>(url: string, init?: RequestInit): Promise<T> {
  const resp = await fetch(url, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...authHeaders(),
      ...(init?.headers ?? {}),
    },
  });
  if (!resp.ok) {
    let detail = `Request failed (${resp.status})`;
    try {
      const parsed = (await resp.json()) as { code?: string; message?: string };
      if (parsed.message) {
        detail = parsed.code ? `${parsed.code}: ${parsed.message}` : parsed.message;
      }
    } catch {
      // keep default HTTP status message
    }
    throw new Error(detail);
  }
  return (await resp.json()) as T;
}

async function downloadExport(url: string, filename: string): Promise<void> {
  const resp = await fetch(url, { headers: authHeaders() });
  if (!resp.ok) {
    throw new Error(`Export failed (${resp.status})`);
  }
  const blob = await resp.blob();
  const objectUrl = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = objectUrl;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(objectUrl);
}

export const api = {
  getOverview: () => requestJson<OverviewResponse>("/api/v1/overview"),
  getDevices: () => requestJson<Device[]>("/api/v1/devices"),
  getAgents: () => requestJson<DiscoveredAgent[]>("/api/v1/inventory/agents"),
  getMcpServers: () => requestJson<McpServerEntry[]>("/api/v1/inventory/mcp-servers"),
  getSessions: () => requestJson<SessionSummary[]>("/api/v1/sessions"),
  getSessionDetail: (id: string) =>
    requestJson<SessionDetailResponse>(`/api/v1/sessions/${encodeURIComponent(id)}`),
  getPacks: () => requestJson<PolicyPack[]>("/api/v1/policies/packs"),
  createRule: (body: {
    title: string;
    description: string;
    mode: Mode;
    matcher: {
      action_classes: ActionClass[];
      target_prefixes: string[];
      target_contains: string[];
      agents: string[];
    };
    reason_template: string;
  }) =>
    requestJson<PolicyRule>("/api/v1/policies/rules", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  updateRule: (
    id: string,
    body: {
      title?: string;
      description?: string;
      mode?: Mode;
      matcher?: {
        action_classes: ActionClass[];
        target_prefixes: string[];
        target_contains: string[];
        agents: string[];
      };
      reason_template?: string;
    },
  ) =>
    requestJson<PolicyRule>(`/api/v1/policies/rules/${encodeURIComponent(id)}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
  deleteRule: (id: string) =>
    requestJson<PolicyRule>(`/api/v1/policies/rules/${encodeURIComponent(id)}`, {
      method: "DELETE",
    }),
  updateRuleMode: (id: string, mode: Mode, replayConfirmed = false) =>
    requestJson<PolicyRule>(`/api/v1/policies/rules/${encodeURIComponent(id)}/mode`, {
      method: "PATCH",
      body: JSON.stringify({ mode, replay_confirmed: replayConfirmed }),
    }),
  replayRule: (id: string, candidateMode: Mode) =>
    requestJson<ReplaySummary>(`/api/v1/policies/rules/${encodeURIComponent(id)}/replay`, {
      method: "POST",
      body: JSON.stringify({ candidate_mode: candidateMode }),
    }),
  getApprovals: () => requestJson<ApprovalRequest[]>("/api/v1/approvals"),
  decideApproval: (id: string, approve: boolean, scope: GrantScope, note: string) =>
    requestJson<ApprovalRequest>(`/api/v1/approvals/${encodeURIComponent(id)}/decide`, {
      method: "POST",
      body: JSON.stringify({ approve, scope, note }),
    }),
  getFindings: () => requestJson<Finding[]>("/api/v1/findings"),
  getIncidents: () => requestJson<Incident[]>("/api/v1/incidents"),
  updateFinding: (id: string, lifecycle: FindingLifecycle) =>
    requestJson<Finding>(`/api/v1/findings/${encodeURIComponent(id)}`, {
      method: "PATCH",
      body: JSON.stringify({ lifecycle }),
    }),
  getKillSwitch: () => requestJson<KillSwitchState>("/api/v1/kill-switch"),
  setKillSwitch: (body: {
    action: KillAction;
    scope: KillScope;
    target_id: string;
    reason: string;
    duration_minutes?: number;
  }) =>
    requestJson<KillSwitchState>("/api/v1/kill-switch", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  decideAction: (body: {
    session_id: string;
    device_id: string;
    device_name: string;
    agent_name: string;
    action_class: ActionClass;
    target: string;
    summary: string;
  }) =>
    requestJson<DecisionReceipt>("/api/v1/decide", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  exportOcsf: () => downloadExport("/api/v1/exports/ocsf", "guardrails-ocsf-1.9.json"),
  exportAuditJsonl: () =>
    downloadExport("/api/v1/exports/audit.jsonl", "guardrails-audit.jsonl"),
};
