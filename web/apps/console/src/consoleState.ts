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
  type SessionSummary,
  type UserProfile,
} from "@grdr/api";
import type { EntityTarget } from "@grdr/kit";

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
