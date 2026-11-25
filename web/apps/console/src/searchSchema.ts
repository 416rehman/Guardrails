import type {
  ConsoleRouteId,
  InventorySectionId,
  ProtectSectionId,
} from "@grdr/i18n";
import type { SessionViewMode } from "./pages/SessionsPage";

export interface ConsoleSearchParams {
  q?: string;
  device?: string;
  sessionId?: string;
  turn?: number;
  attemptId?: string;
  userId?: string;
  ruleId?: string;
  view?: "hexmap" | "table";
  editor?: "simple" | "advanced" | "code";
  os?: string;
  agent?: string;
  outliers?: boolean;
  assurance?: string;
  hook?: string;
  transport?: string;
  pin?: string;
  kind?: string;
  scope?: string;
  signal?: string;
  dept?: string;
  tier?: string;
  incidentSeverity?: string;
  findingSeverity?: string;
  findingLifecycle?: string;
  pageToken?: string;
  page?: number;
  pageSize?: number;
  approvalsPageToken?: string;
  approvalsPage?: number;
  incidentsPageToken?: string;
  incidentsPage?: number;
  findingsPageToken?: string;
  findingsPage?: number;
}

const INVENTORY_SECTIONS: ReadonlyArray<InventorySectionId> = [
  "endpoints",
  "agents",
  "mcps",
  "skills",
  "connect",
];

const SESSION_VIEWS: ReadonlyArray<SessionViewMode> = [
  "graph",
  "trace",
  "timeline",
  "stream",
];

const PROTECT_SECTIONS: ReadonlyArray<ProtectSectionId> = ["rules", "browser"];

function optStr(raw: unknown): string | undefined {
  if (typeof raw !== "string") return undefined;
  const trimmed = raw.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function optInt(raw: unknown): number | undefined {
  if (typeof raw === "number" && Number.isFinite(raw)) return Math.trunc(raw);
  if (typeof raw === "string" && raw.trim() !== "") {
    const parsed = Number(raw);
    if (Number.isFinite(parsed)) return Math.trunc(parsed);
  }
  return undefined;
}

function optBool(raw: unknown): boolean | undefined {
  if (raw === true || raw === "true" || raw === "1") return true;
  if (raw === false || raw === "false" || raw === "0") return false;
  return undefined;
}

export function validateConsoleSearch(
  raw: Record<string, unknown>,
): ConsoleSearchParams {
  const viewRaw = optStr(raw.view);
  const view =
    viewRaw === "hexmap" || viewRaw === "table" ? viewRaw : undefined;

  const editorRaw = optStr(raw.editor);
  const editor =
    editorRaw === "simple" || editorRaw === "advanced" || editorRaw === "code"
      ? editorRaw
      : undefined;

  const pageSizeRaw = optInt(raw.pageSize);
  const pageSize =
    pageSizeRaw && pageSizeRaw > 0 ? pageSizeRaw : undefined;

  const pageRaw = optInt(raw.page);
  const page = pageRaw !== undefined && pageRaw >= 0 ? pageRaw : undefined;

  const turnRaw = optInt(raw.turn);
  const turn = turnRaw !== undefined && turnRaw > 0 ? turnRaw : undefined;

  return {
    q: optStr(raw.q),
    device: optStr(raw.device),
    sessionId: optStr(raw.sessionId),
    turn,
    attemptId: optStr(raw.attemptId),
    userId: optStr(raw.userId),
    ruleId: optStr(raw.ruleId),
    view,
    editor,
    os: optStr(raw.os),
    agent: optStr(raw.agent),
    outliers: optBool(raw.outliers),
    assurance: optStr(raw.assurance),
    hook: optStr(raw.hook),
    transport: optStr(raw.transport),
    pin: optStr(raw.pin),
    kind: optStr(raw.kind),
    scope: optStr(raw.scope),
    signal: optStr(raw.signal),
    dept: optStr(raw.dept),
    tier: optStr(raw.tier),
    incidentSeverity: optStr(raw.incidentSeverity),
    findingSeverity: optStr(raw.findingSeverity),
    findingLifecycle: optStr(raw.findingLifecycle),
    pageToken: optStr(raw.pageToken),
    page,
    pageSize,
    approvalsPageToken: optStr(raw.approvalsPageToken),
    approvalsPage: optInt(raw.approvalsPage),
    incidentsPageToken: optStr(raw.incidentsPageToken),
    incidentsPage: optInt(raw.incidentsPage),
    findingsPageToken: optStr(raw.findingsPageToken),
    findingsPage: optInt(raw.findingsPage),
  };
}

export function normalizeInventorySection(raw?: string): InventorySectionId {
  return INVENTORY_SECTIONS.find((s) => s === raw) ?? "endpoints";
}

export function normalizeSessionView(raw?: string): SessionViewMode {
  return SESSION_VIEWS.find((v) => v === raw) ?? "graph";
}

export function normalizeProtectSection(raw?: string): ProtectSectionId {
  return PROTECT_SECTIONS.find((s) => s === raw) ?? "rules";
}

export function deriveConsoleLocation(pathname: string): {
  route: ConsoleRouteId;
  inventorySection: InventorySectionId;
  sessionsView: SessionViewMode;
  protectSection: ProtectSectionId;
} {
  const parts = pathname.split("/").filter(Boolean);
  const head = parts[0] ?? "home";
  const sub = parts[1];

  switch (head) {
    case "users":
      return {
        route: "users",
        inventorySection: "endpoints",
        sessionsView: "graph",
        protectSection: "rules",
      };
    case "inventory":
      return {
        route: "inventory",
        inventorySection: normalizeInventorySection(sub),
        sessionsView: "graph",
        protectSection: "rules",
      };
    case "sessions":
      return {
        route: "sessions",
        inventorySection: "endpoints",
        sessionsView: normalizeSessionView(sub),
        protectSection: "rules",
      };
    case "protect":
      return {
        route: "protect",
        inventorySection: "endpoints",
        sessionsView: "graph",
        protectSection: normalizeProtectSection(sub),
      };
    case "respond":
      return {
        route: "respond",
        inventorySection: "endpoints",
        sessionsView: "graph",
        protectSection: "rules",
      };
    case "first-run":
      return {
        route: "first-run",
        inventorySection: "endpoints",
        sessionsView: "graph",
        protectSection: "rules",
      };
    case "review":
      return {
        route: "review",
        inventorySection: "endpoints",
        sessionsView: "graph",
        protectSection: "rules",
      };
    case "compliance":
      return {
        route: "compliance",
        inventorySection: "endpoints",
        sessionsView: "graph",
        protectSection: "rules",
      };
    case "settings":
      return {
        route: "settings",
        inventorySection: "endpoints",
        sessionsView: "graph",
        protectSection: "rules",
      };
    case "provider":
      return {
        route: "provider",
        inventorySection: "endpoints",
        sessionsView: "graph",
        protectSection: "rules",
      };
    case "coverage":
      return {
        route: "coverage",
        inventorySection: "endpoints",
        sessionsView: "graph",
        protectSection: "rules",
      };
    case "tester":
      return {
        route: "tester",
        inventorySection: "endpoints",
        sessionsView: "graph",
        protectSection: "rules",
      };
    default:
      return {
        route: "home",
        inventorySection: "endpoints",
        sessionsView: "graph",
        protectSection: "rules",
      };
  }
}

export function pathForConsoleRoute(
  route: ConsoleRouteId,
  childId?: string,
): string {
  switch (route) {
    case "home":
      return "/";
    case "first-run":
      return "/first-run";
    case "users":
      return "/users";
    case "inventory":
      return `/inventory/${normalizeInventorySection(childId)}`;
    case "sessions":
      return `/sessions/${normalizeSessionView(childId)}`;
    case "protect":
      return `/protect/${normalizeProtectSection(childId)}`;
    case "review":
      return "/review";
    case "respond":
      return "/respond";
    case "compliance":
      return "/compliance";
    case "settings":
      return "/settings";
    case "provider":
      return "/provider";
    case "coverage":
      return "/coverage";
    case "tester":
      return "/tester";
  }
}
