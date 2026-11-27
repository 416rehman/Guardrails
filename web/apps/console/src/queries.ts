// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
import { useMemo } from "react";
import { QueryClient, QueryClientProvider, useQueries, useQueryClient } from "@tanstack/react-query";
export { QueryClient, QueryClientProvider };
import {
  api,
  type ApprovalRequest,
  type Device,
  type Finding,
  type Incident,
  type KillSwitchState,
  type OrgPrivacyConfig,
  type OverviewResponse,
  type PolicyPack,
  type SessionDetailResponse,
  type SessionSummary,
  type UserProfile,
} from "@grdr/api";
import {
  computeWeeklyDecisionVelocity,
  EMPTY_CONSOLE_SNAPSHOT,
  type ConsoleSnapshot,
  type WeeklyVelocitySummary,
} from "./consoleState";

export const CONSOLE_SCOPE = "console" as const;

export const consoleQueryKeys = {
  all: [CONSOLE_SCOPE] as const,
  overview: () => [CONSOLE_SCOPE, "overview", {}] as const,
  users: (params: Record<string, unknown> = {}) => [CONSOLE_SCOPE, "users", params] as const,
  usersPage: (params: Record<string, unknown>) => [CONSOLE_SCOPE, "usersPage", params] as const,
  userDetail: (id: string, identityMode?: string) =>
    [CONSOLE_SCOPE, "userDetail", { id, identityMode }] as const,
  privacyConfig: () => [CONSOLE_SCOPE, "privacyConfig", {}] as const,
  devices: (params: Record<string, unknown> = {}) => [CONSOLE_SCOPE, "devices", params] as const,
  devicesPage: (params: Record<string, unknown>) => [CONSOLE_SCOPE, "devicesPage", params] as const,
  agentsPage: (params: Record<string, unknown>) => [CONSOLE_SCOPE, "agentsPage", params] as const,
  mcpServersPage: (params: Record<string, unknown>) =>
    [CONSOLE_SCOPE, "mcpServersPage", params] as const,
  artifactsPage: (params: Record<string, unknown>) =>
    [CONSOLE_SCOPE, "artifactsPage", params] as const,
  sessions: (params: Record<string, unknown> = {}) => [CONSOLE_SCOPE, "sessions", params] as const,
  sessionsPage: (params: Record<string, unknown>) =>
    [CONSOLE_SCOPE, "sessionsPage", params] as const,
  sessionDetail: (id: string) => [CONSOLE_SCOPE, "sessionDetail", { id }] as const,
  packs: () => [CONSOLE_SCOPE, "packs", {}] as const,
  approvals: (params: Record<string, unknown> = {}) =>
    [CONSOLE_SCOPE, "approvals", params] as const,
  approvalsPage: (params: Record<string, unknown>) =>
    [CONSOLE_SCOPE, "approvalsPage", params] as const,
  findings: (params: Record<string, unknown> = {}) => [CONSOLE_SCOPE, "findings", params] as const,
  findingsPage: (params: Record<string, unknown>) =>
    [CONSOLE_SCOPE, "findingsPage", params] as const,
  incidents: (params: Record<string, unknown> = {}) =>
    [CONSOLE_SCOPE, "incidents", params] as const,
  incidentsPage: (params: Record<string, unknown>) =>
    [CONSOLE_SCOPE, "incidentsPage", params] as const,
  killSwitch: () => [CONSOLE_SCOPE, "killSwitch", {}] as const,
  connectConfig: () => [CONSOLE_SCOPE, "connectConfig", {}] as const,
  browserPolicies: () => [CONSOLE_SCOPE, "browserPolicies", {}] as const,
  reviewQueue: (params: Record<string, unknown> = {}) =>
    [CONSOLE_SCOPE, "reviewQueue", params] as const,
  complianceWorkspace: () => [CONSOLE_SCOPE, "complianceWorkspace", {}] as const,
  providerWorkspace: (orgSet?: string) =>
    [CONSOLE_SCOPE, "providerWorkspace", { orgSet }] as const,
  whyExplanation: (reference: string) =>
    [CONSOLE_SCOPE, "whyExplanation", { reference }] as const,
};

export type ConsoleStreamEventName =
  | "session.verdict"
  | "approval.decided"
  | "policy.changed"
  | "inventory.device"
  | "uplink.batch"
  | "finding.updated"
  | "kill_switch.updated"
  | "privacy.updated";

export interface ConsoleSnapshotResult {
  snapshot: ConsoleSnapshot;
  isLoading: boolean;
  errorMessage: string | null;
  invalidateAll: () => Promise<void>;
}

export function createConsoleQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
        refetchOnWindowFocus: false,
        staleTime: 5_000,
      },
    },
  });
}

export function invalidateConsoleStreamEvent(
  queryClient: QueryClient,
  eventName: ConsoleStreamEventName,
  sessionId?: string,
): Promise<void[]> {
  switch (eventName) {
    case "session.verdict":
      return Promise.all([
        queryClient.invalidateQueries({ queryKey: [CONSOLE_SCOPE, "sessions"] }),
        queryClient.invalidateQueries({ queryKey: [CONSOLE_SCOPE, "sessionsPage"] }),
        queryClient.invalidateQueries({
          queryKey: sessionId
            ? consoleQueryKeys.sessionDetail(sessionId)
            : [CONSOLE_SCOPE, "sessionDetail"],
          refetchType: "active",
        }),
        queryClient.invalidateQueries({ queryKey: [CONSOLE_SCOPE, "overview"] }),
      ]);
    case "approval.decided":
      return Promise.all([
        queryClient.invalidateQueries({ queryKey: [CONSOLE_SCOPE, "approvals"] }),
        queryClient.invalidateQueries({ queryKey: [CONSOLE_SCOPE, "approvalsPage"] }),
        queryClient.invalidateQueries({ queryKey: [CONSOLE_SCOPE, "overview"] }),
      ]);
    case "policy.changed":
      return Promise.all([
        queryClient.invalidateQueries({ queryKey: [CONSOLE_SCOPE, "packs"] }),
        queryClient.invalidateQueries({ queryKey: [CONSOLE_SCOPE, "browserPolicies"] }),
        queryClient.invalidateQueries({ queryKey: [CONSOLE_SCOPE, "overview"] }),
      ]);
    case "inventory.device":
      return Promise.all([
        queryClient.invalidateQueries({ queryKey: [CONSOLE_SCOPE, "devices"] }),
        queryClient.invalidateQueries({ queryKey: [CONSOLE_SCOPE, "devicesPage"] }),
        queryClient.invalidateQueries({ queryKey: [CONSOLE_SCOPE, "agentsPage"] }),
        queryClient.invalidateQueries({ queryKey: [CONSOLE_SCOPE, "mcpServersPage"] }),
        queryClient.invalidateQueries({ queryKey: [CONSOLE_SCOPE, "artifactsPage"] }),
        queryClient.invalidateQueries({ queryKey: [CONSOLE_SCOPE, "overview"] }),
      ]);
    case "finding.updated":
      return Promise.all([
        queryClient.invalidateQueries({ queryKey: [CONSOLE_SCOPE, "findings"] }),
        queryClient.invalidateQueries({ queryKey: [CONSOLE_SCOPE, "findingsPage"] }),
        queryClient.invalidateQueries({ queryKey: [CONSOLE_SCOPE, "incidents"] }),
        queryClient.invalidateQueries({ queryKey: [CONSOLE_SCOPE, "incidentsPage"] }),
        queryClient.invalidateQueries({ queryKey: [CONSOLE_SCOPE, "overview"] }),
      ]);
    case "kill_switch.updated":
      return Promise.all([
        queryClient.invalidateQueries({ queryKey: [CONSOLE_SCOPE, "killSwitch"] }),
        queryClient.invalidateQueries({ queryKey: [CONSOLE_SCOPE, "overview"] }),
      ]);
    case "privacy.updated":
      return Promise.all([
        queryClient.invalidateQueries({ queryKey: [CONSOLE_SCOPE, "privacyConfig"] }),
        queryClient.invalidateQueries({ queryKey: [CONSOLE_SCOPE, "users"] }),
        queryClient.invalidateQueries({ queryKey: [CONSOLE_SCOPE, "usersPage"] }),
        queryClient.invalidateQueries({ queryKey: [CONSOLE_SCOPE, "userDetail"] }),
      ]);
    case "uplink.batch":
      return Promise.all([
        queryClient.invalidateQueries({ queryKey: consoleQueryKeys.all }),
      ]);
  }
}

export function useConsoleSnapshotQueries(streamVersion: number): ConsoleSnapshotResult {
  const queryClient = useQueryClient();
  const listParams = { pageSize: 200, streamVersion };

  const results = useQueries({
    queries: [
      {
        queryKey: [CONSOLE_SCOPE, "overview", { streamVersion }],
        queryFn: (): Promise<OverviewResponse> => api.getOverview(),
      },
      {
        queryKey: consoleQueryKeys.users(listParams),
        queryFn: (): Promise<UserProfile[]> => api.getUsers(),
      },
      {
        queryKey: [CONSOLE_SCOPE, "privacyConfig", { streamVersion }],
        queryFn: (): Promise<OrgPrivacyConfig> => api.getPrivacyConfig(),
      },
      {
        queryKey: consoleQueryKeys.devices(listParams),
        queryFn: (): Promise<Device[]> => api.getDevices(),
      },
      {
        queryKey: consoleQueryKeys.sessions(listParams),
        queryFn: (): Promise<SessionSummary[]> => api.getSessions(),
      },
      {
        queryKey: [CONSOLE_SCOPE, "packs", { streamVersion }],
        queryFn: (): Promise<PolicyPack[]> => api.getPacks(),
      },
      {
        queryKey: consoleQueryKeys.approvals(listParams),
        queryFn: (): Promise<ApprovalRequest[]> => api.getApprovals(),
      },
      {
        queryKey: consoleQueryKeys.findings(listParams),
        queryFn: (): Promise<Finding[]> => api.getFindings(),
      },
      {
        queryKey: consoleQueryKeys.incidents(listParams),
        queryFn: (): Promise<Incident[]> => api.getIncidents(),
      },
      {
        queryKey: [CONSOLE_SCOPE, "killSwitch", { streamVersion }],
        queryFn: (): Promise<KillSwitchState> => api.getKillSwitch(),
      },
    ],
  });

  const firstErr = results.find((r) => r.error != null)?.error;
  const errorMessage =
    firstErr instanceof Error
      ? firstErr.message
      : firstErr
        ? "Failed loading console state"
        : null;

  const snapshot: ConsoleSnapshot = {
    overview: results[0].data ?? EMPTY_CONSOLE_SNAPSHOT.overview,
    users: results[1].data ?? EMPTY_CONSOLE_SNAPSHOT.users,
    privacyConfig: results[2].data ?? EMPTY_CONSOLE_SNAPSHOT.privacyConfig,
    devices: results[3].data ?? EMPTY_CONSOLE_SNAPSHOT.devices,
    sessions: results[4].data ?? EMPTY_CONSOLE_SNAPSHOT.sessions,
    packs: results[5].data ?? EMPTY_CONSOLE_SNAPSHOT.packs,
    approvals: results[6].data ?? EMPTY_CONSOLE_SNAPSHOT.approvals,
    findings: results[7].data ?? EMPTY_CONSOLE_SNAPSHOT.findings,
    incidents: results[8].data ?? EMPTY_CONSOLE_SNAPSHOT.incidents,
    killSwitch: results[9].data ?? EMPTY_CONSOLE_SNAPSHOT.killSwitch,
  };

  return {
    snapshot,
    isLoading: results.some((r) => r.isLoading),
    errorMessage,
    invalidateAll: () => queryClient.invalidateQueries({ queryKey: consoleQueryKeys.all }),
  };
}

const VELOCITY_DETAIL_SESSION_LIMIT = 8;

function sessionActivityMs(session: SessionSummary): number {
  const parsed = Date.parse(session.last_activity || session.started_at);
  return Number.isFinite(parsed) ? parsed : 0;
}

export function useWeeklyDecisionVelocity(
  sessions: SessionSummary[],
  enabled: boolean,
): WeeklyVelocitySummary {
  const sampled = useMemo(() => {
    if (!enabled || sessions.length === 0) return [];
    const sorted = [...sessions].sort(
      (a, b) => sessionActivityMs(b) - sessionActivityMs(a),
    );
    return sorted.slice(0, VELOCITY_DETAIL_SESSION_LIMIT);
  }, [enabled, sessions]);
  const detailQueries = useQueries({
    queries: sampled.map((session) => ({
      queryKey: consoleQueryKeys.sessionDetail(session.id),
      queryFn: () => api.getSessionDetail(session.id),
      staleTime: 30_000,
    })),
  });
  const detailsSnapshotKey = detailQueries.map((q) => q.dataUpdatedAt).join(",");

  return useMemo(() => {
    const detailsMap = new Map<string, SessionDetailResponse>();
    detailQueries.forEach((query, idx) => {
      const session = sampled[idx];
      if (session && query.data) {
        detailsMap.set(session.id, query.data);
      }
    });
    return computeWeeklyDecisionVelocity(sessions, detailsMap);
  }, [sessions, sampled, detailsSnapshotKey]);
}
