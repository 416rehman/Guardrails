// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
import {
  api,
  type ActionAttempt,
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
  type Verdict,
  type WhyExplanation,
} from "@grdr/api";
import type { EntityTarget } from "@grdr/kit";
import { pluralize, presentAgentName } from "@grdr/i18n";

export type WhyDrawerState =
  | { kind: "closed" }
  | { kind: "loading"; reference: string }
  | { kind: "ready"; explanation: WhyExplanation }
  | { kind: "error"; message: string };

export type SidebarDisplay = "expanded" | "collapsed";
export type PaletteState = "closed" | "open";
export type StreamState = { kind: "connected" } | { kind: "reconnecting" };
export type TokenBarState = { kind: "hidden" } | { kind: "editing"; input: string };
export type DevicePick = { kind: "none" } | { kind: "selected"; deviceId: string };
export type SessionPick = { kind: "auto" } | { kind: "selected"; sessionId: string };
export type PrefillDraft = { kind: "none" } | { kind: "fromAttempt"; attempt: ActionAttempt };
export type FocusTarget =
  | { kind: "none" }
  | { kind: "entity"; target: EntityTarget }
  | { kind: "sessionTurn"; target: EntityTarget; turnIndex: number };

export interface ConsoleSnapshot {
  overview: OverviewResponse | null;
  users: UserProfile[];
  privacyConfig: OrgPrivacyConfig;
  devices: Device[];
  sessions: SessionSummary[];
  packs: PolicyPack[];
  approvals: ApprovalRequest[];
  findings: Finding[];
  incidents: Incident[];
  killSwitch: KillSwitchState;
}

export type LoadState<T> =
  | { kind: "loading" }
  | { kind: "ready"; data: T }
  | { kind: "error"; message: string; staleData?: T };

export const EMPTY_CONSOLE_SNAPSHOT: ConsoleSnapshot = {
  overview: null,
  users: [],
  privacyConfig: { identity_mode: "named", user_risk_scoring: true },
  devices: [],
  sessions: [],
  packs: [],
  approvals: [],
  findings: [],
  incidents: [],
  killSwitch: { state: "inactive" },
};

export interface VelocityDayPoint {
  day: string;
  allowed: number;
  ask: number;
  block: number;
}

export type VelocityWindowKind = "current" | "historical";

export interface WeeklyVelocitySummary {
  days: VelocityDayPoint[];
  totalEvaluated: number;
  totalAllowed: number;
  totalAsk: number;
  totalBlocked: number;
  windowKind: VelocityWindowKind;
  windowLabel: string;
  isPartialSummary: boolean;
}

const VELOCITY_WINDOW_DAYS = 7;

const WEEKDAY_FORMATTER = new Intl.DateTimeFormat("en-US", { weekday: "short" });
const WINDOW_DATE_FORMATTER = new Intl.DateTimeFormat("en-US", {
  month: "short",
  day: "numeric",
});

function localDayStartMs(rawTimestamp: string | number): number | null {
  const ms = typeof rawTimestamp === "number" ? rawTimestamp : Date.parse(rawTimestamp);
  if (!Number.isFinite(ms)) return null;
  const d = new Date(ms);
  return new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
}

function addLocalDaysMs(dayStartMs: number, deltaDays: number): number {
  const d = new Date(dayStartMs);
  return new Date(d.getFullYear(), d.getMonth(), d.getDate() + deltaDays).getTime();
}

function formatWindowRange(startMs: number, endMs: number): string {
  return `${WINDOW_DATE_FORMATTER.format(new Date(startMs))} to ${WINDOW_DATE_FORMATTER.format(new Date(endMs))}`;
}

function classifyVerdictBucket(verdict: Verdict): "allowed" | "ask" | "block" {
  if (verdict === "deny") return "block";
  if (verdict === "step_up" || verdict === "defer") return "ask";
  return "allowed";
}

export function computeWeeklyDecisionVelocity(
  sessions: SessionSummary[],
  detailsBySessionId: ReadonlyMap<string, SessionDetailResponse>,
  nowMs: number = Date.now(),
): WeeklyVelocitySummary {
  interface DayCounts {
    allowed: number;
    ask: number;
    block: number;
  }

  const perDay = new Map<number, DayCounts>();
  const seenReceiptIds = new Set<string>();
  const summaryFallbackSessions: Array<{ day: number; allowed: number; ask: number; block: number }> = [];

  const addCount = (dayStart: number, kind: keyof DayCounts, delta: number) => {
    if (delta <= 0) return;
    const prev = perDay.get(dayStart) ?? { allowed: 0, ask: 0, block: 0 };
    prev[kind] += delta;
    perDay.set(dayStart, prev);
  };

  for (const session of sessions) {
    const detail = detailsBySessionId.get(session.id);
    if (detail && detail.receipts.length > 0) {
      for (const receipt of detail.receipts) {
        const dedupKey = receipt.receipt_id || `${session.id}:${receipt.attempt_id}`;
        if (seenReceiptIds.has(dedupKey)) continue;
        seenReceiptIds.add(dedupKey);
        const day = localDayStartMs(receipt.decided_at) ?? localDayStartMs(session.last_activity);
        if (day !== null) {
          addCount(day, classifyVerdictBucket(receipt.verdict), 1);
        }
      }
      continue;
    }

    const day = localDayStartMs(session.last_activity) ?? localDayStartMs(session.started_at);
    if (day !== null && session.total_actions > 0) {
      const block = Math.max(0, session.blocked_count);
      const ask = Math.max(0, session.step_up_count);
      const allowed = Math.max(0, session.total_actions - block - ask);
      addCount(day, "allowed", allowed);
      addCount(day, "ask", ask);
      addCount(day, "block", block);
      summaryFallbackSessions.push({ day, allowed, ask, block });
    }
  }

  const todayStart = localDayStartMs(nowMs) ?? localDayStartMs(Date.now()) ?? 0;
  const recentWindowStart = addLocalDaysMs(todayStart, -(VELOCITY_WINDOW_DAYS - 1));
  const observedDays = Array.from(perDay.keys());
  const hasRecentData = observedDays.some(
    (day) => day >= recentWindowStart && day <= todayStart,
  );
  const latestObserved =
    observedDays.length > 0 ? Math.max(...observedDays) : todayStart;
  const windowKind: VelocityWindowKind =
    hasRecentData || observedDays.length === 0 ? "current" : "historical";
  const endDayStart = windowKind === "current" ? todayStart : latestObserved;
  const startDayStart = addLocalDaysMs(endDayStart, -(VELOCITY_WINDOW_DAYS - 1));

  const isPartialSummary = summaryFallbackSessions.some(
    (entry) => entry.day >= startDayStart && entry.day <= endDayStart,
  );

  const days: VelocityDayPoint[] = [];
  let totalAllowed = 0;
  let totalAsk = 0;
  let totalBlocked = 0;

  for (let offset = VELOCITY_WINDOW_DAYS - 1; offset >= 0; offset -= 1) {
    const dayStart = addLocalDaysMs(endDayStart, -offset);
    const counts = perDay.get(dayStart) ?? { allowed: 0, ask: 0, block: 0 };
    const weekday = WEEKDAY_FORMATTER.format(new Date(dayStart));
    days.push({
      day: weekday,
      allowed: counts.allowed,
      ask: counts.ask,
      block: counts.block,
    });
    totalAllowed += counts.allowed;
    totalAsk += counts.ask;
    totalBlocked += counts.block;
  }

  return {
    days,
    totalEvaluated: totalAllowed + totalAsk + totalBlocked,
    totalAllowed,
    totalAsk,
    totalBlocked,
    windowKind,
    windowLabel: formatWindowRange(startDayStart, endDayStart),
    isPartialSummary,
  };
}

export interface KillSwitchSelection {
  blockedAgents: string[];
  blockedModels: string[];
  blockedGateways: string[];
}

export const EMPTY_KILL_SELECTION: KillSwitchSelection = {
  blockedAgents: [],
  blockedModels: [],
  blockedGateways: [],
};

export interface KillSwitchCatalog {
  agents: string[];
  models: string[];
  gateways: string[];
}

export type KillSwitchBlastRadius =
  | {
      kind: "device";
      scope: "device";
      targetId: string;
      deviceHostname: string;
      summaryText: string;
    }
  | {
      kind: "organisation";
      scope: "organisation";
      targetId: "*";
      endpointCount: number;
      summaryText: string;
    };

export function canonicalAgentSlugKey(value: string): string {
  return value.trim().toLowerCase().replace(/[-_]+/g, " ").replace(/\s+/g, " ");
}

function uniqueSortedTargets(values: Iterable<string>): string[] {
  const seen = new Map<string, string>();
  for (const raw of values) {
    const trimmed = raw.trim();
    const key = trimmed.toLowerCase();
    if (trimmed && trimmed !== "*" && !seen.has(key)) {
      seen.set(key, trimmed);
    }
  }
  return Array.from(seen.values()).sort((a, b) => a.localeCompare(b));
}

function uniqueAgentDisplayNames(values: Iterable<string>): string[] {
  const seen = new Map<string, string>();
  for (const raw of values) {
    const display = presentAgentName(raw);
    const key = canonicalAgentSlugKey(display);
    if (display && display !== "*" && !seen.has(key)) {
      seen.set(key, display);
    }
  }
  return Array.from(seen.values()).sort((a, b) => a.localeCompare(b));
}

export function deriveKillSwitchCatalog(
  devices: Device[],
  sessions: SessionSummary[],
): KillSwitchCatalog {
  const agents = uniqueAgentDisplayNames([
    ...devices.flatMap((d) => d.agents.map((a) => a.name)),
    ...sessions.map((s) => s.agent_name),
  ]);
  const gateways = uniqueSortedTargets(
    devices.flatMap((d) => d.mcp_servers.map((m) => m.name)),
  );
  return {
    agents,
    models: [],
    gateways,
  };
}

export function resolveKillSwitchBlastRadius(
  devices: Device[],
  selection: KillSwitchSelection,
): KillSwitchBlastRadius {
  const selectedAgentKeys = new Set(
    selection.blockedAgents.map((a) => canonicalAgentSlugKey(presentAgentName(a))),
  );
  const selectedGatewayKeys = new Set(
    selection.blockedGateways.map((g) => g.trim().toLowerCase()),
  );

  const matchedDevices = devices.filter((device) => {
    const agentMatch = device.agents.some((agent) =>
      selectedAgentKeys.has(canonicalAgentSlugKey(presentAgentName(agent.name))),
    );
    const gatewayMatch = device.mcp_servers.some((mcp) =>
      selectedGatewayKeys.has(mcp.name.trim().toLowerCase()),
    );
    return agentMatch || gatewayMatch;
  });

  if (matchedDevices.length === 1 && selection.blockedModels.length === 0) {
    const targetDevice = matchedDevices[0];
    return {
      kind: "device",
      scope: "device",
      targetId: targetDevice.id,
      deviceHostname: targetDevice.hostname,
      summaryText: `Targets endpoint ${targetDevice.hostname} (${targetDevice.id}) using device scope containment.`,
    };
  }

  return {
    kind: "organisation",
    scope: "organisation",
    targetId: "*",
    endpointCount: devices.length,
    summaryText: `Fleet-wide organisation containment applies across all ${pluralize(devices.length, "enrolled endpoint")}.`,
  };
}

export async function fetchConsoleSnapshot(): Promise<ConsoleSnapshot> {
  const [overview, users, privacyConfig, devices, sessions, packs, approvals, findings, incidents, killSwitch] =
    await Promise.all([
      api.getOverview(),
      api.getUsers(),
      api.getPrivacyConfig(),
      api.getDevices(),
      api.getSessions(),
      api.getPacks(),
      api.getApprovals(),
      api.getFindings(),
      api.getIncidents(),
      api.getKillSwitch(),
    ]);
  return {
    overview,
    users,
    privacyConfig,
    devices,
    sessions,
    packs,
    approvals,
    findings,
    incidents,
    killSwitch,
  };
}
