import {
  BRAND_NAME,
  BRAND_SHORT_NAME,
  ICON_REGISTRY,
  INTERFACE_ROUTES,
  MESSAGES,
  PRESENTATION_REGISTRY,
  SUPPORTED_LOCALES,
  VOCABULARY_TERMS,
  lookupMessage,
  t,
  type LocaleCode,
  type MessageKey,
} from "./generated";

export {
  BRAND_NAME,
  BRAND_SHORT_NAME,
  ICON_REGISTRY,
  INTERFACE_ROUTES,
  MESSAGES,
  PRESENTATION_REGISTRY,
  SUPPORTED_LOCALES,
  VOCABULARY_TERMS,
  lookupMessage,
  t,
  type LocaleCode,
  type MessageKey,
};

export type ConsoleRouteId =
  | "home"
  | "first-run"
  | "users"
  | "inventory"
  | "sessions"
  | "protect"
  | "review"
  | "respond"
  | "compliance"
  | "settings"
  | "provider"
  | "coverage"
  | "tester";

export type OperatorRouteId =
  | "op-overview"
  | "op-health"
  | "op-settings"
  | "op-upgrades"
  | "op-backups"
  | "op-audit";

export type InventorySectionId =
  | "endpoints"
  | "agents"
  | "mcps"
  | "skills"
  | "connect";

export type SessionsSectionId = "graph" | "trace" | "timeline";

export type ProtectSectionId = "rules" | "browser";

export interface ConsoleNavChild {
  id: string;
  labelKey: MessageKey | string;
  iconKey: string;
}

export interface ConsoleNavItem {
  id: ConsoleRouteId;
  labelKey: MessageKey | string;
  iconKey: string;
  children?: ReadonlyArray<ConsoleNavChild>;
}

export interface ConsoleNavGroup {
  id: "overview" | "fleet" | "protection";
  labelKey: MessageKey;
  items: ReadonlyArray<ConsoleNavItem>;
}

const EXTRA_ROUTE_LABELS: Record<string, string> = {
  "console.nav.first_run": "First run",
  "console.nav.review": "Review queue",
  "console.nav.compliance": "Compliance",
  "console.nav.settings": "Settings & privacy",
  "console.nav.provider": "Provider",
  "operator.nav.upgrades": "Upgrades",
  "operator.nav.backups": "Backups",
};

export function routeLabel(key: MessageKey | string): string {
  if (key in MESSAGES) {
    return t(key as MessageKey);
  }
  return EXTRA_ROUTE_LABELS[key] ?? key;
}

export const CONSOLE_ROUTES: ReadonlyArray<{
  id: ConsoleRouteId;
  labelKey: MessageKey | string;
  iconKey: string;
}> = [
  ...INTERFACE_ROUTES.filter((r) => r.area === "console").map((r) => ({
    id: r.id as ConsoleRouteId,
    labelKey: r.titleKey,
    iconKey: r.iconKey,
  })),
  { id: "first-run", labelKey: "console.nav.first_run", iconKey: "nav.first_run" },
  { id: "review", labelKey: "console.nav.review", iconKey: "nav.review" },
  { id: "compliance", labelKey: "console.nav.compliance", iconKey: "nav.compliance" },
  { id: "settings", labelKey: "console.nav.settings", iconKey: "nav.settings" },
  { id: "provider", labelKey: "console.nav.provider", iconKey: "nav.provider" },
];

export const CONSOLE_NAV_GROUPS: ReadonlyArray<ConsoleNavGroup> = [
  {
    id: "overview",
    labelKey: "console.nav.group.overview",
    items: [
      { id: "home", labelKey: "console.nav.home", iconKey: "nav.home" },
      { id: "first-run", labelKey: "console.nav.first_run", iconKey: "nav.first_run" },
      { id: "coverage", labelKey: "console.nav.coverage", iconKey: "nav.coverage" },
    ],
  },
  {
    id: "fleet",
    labelKey: "console.nav.group.fleet",
    items: [
      { id: "users", labelKey: "console.nav.users", iconKey: "nav.users" },
      {
        id: "inventory",
        labelKey: "console.nav.inventory",
        iconKey: "nav.inventory",
        children: [
          { id: "endpoints", labelKey: "console.nav.inventory.endpoints", iconKey: "hard-drive" },
          { id: "agents", labelKey: "console.nav.inventory.agents", iconKey: "cpu" },
          { id: "mcps", labelKey: "console.nav.inventory.mcps", iconKey: "plug" },
          { id: "skills", labelKey: "console.nav.inventory.skills", iconKey: "file-code" },
          { id: "connect", labelKey: "console.nav.inventory.connect", iconKey: "key-round" },
        ],
      },
      {
        id: "sessions",
        labelKey: "console.nav.sessions",
        iconKey: "nav.sessions",
        children: [
          { id: "graph", labelKey: "console.nav.sessions.graph", iconKey: "git-branch" },
          { id: "trace", labelKey: "console.nav.sessions.trace", iconKey: "route" },
          { id: "timeline", labelKey: "console.nav.sessions.timeline", iconKey: "list" },
        ],
      },
      { id: "provider", labelKey: "console.nav.provider", iconKey: "nav.provider" },
    ],
  },
  {
    id: "protection",
    labelKey: "console.nav.group.protection",
    items: [
      {
        id: "protect",
        labelKey: "console.nav.protect",
        iconKey: "nav.protect",
        children: [
          { id: "rules", labelKey: "console.nav.protect.rules", iconKey: "shield" },
          { id: "browser", labelKey: "console.nav.protect.browser", iconKey: "globe" },
        ],
      },
      { id: "review", labelKey: "console.nav.review", iconKey: "nav.review" },
      { id: "respond", labelKey: "console.nav.respond", iconKey: "nav.respond" },
      { id: "compliance", labelKey: "console.nav.compliance", iconKey: "nav.compliance" },
      { id: "settings", labelKey: "console.nav.settings", iconKey: "nav.settings" },
      { id: "tester", labelKey: "console.nav.tester", iconKey: "nav.tester" },
    ],
  },
];

export const OPERATOR_ROUTES: ReadonlyArray<{
  id: OperatorRouteId;
  labelKey: MessageKey | string;
  iconKey: string;
}> = [
  ...INTERFACE_ROUTES.filter((r) => r.area === "operator")
    .filter((r) => r.id !== "op-audit")
    .map((r) => ({
      id: r.id as OperatorRouteId,
      labelKey: r.titleKey,
      iconKey: r.iconKey,
    })),
  { id: "op-upgrades", labelKey: "operator.nav.upgrades", iconKey: "nav.operator_upgrades" },
  { id: "op-backups", labelKey: "operator.nav.backups", iconKey: "nav.operator_backups" },
  ...INTERFACE_ROUTES.filter((r) => r.id === "op-audit").map((r) => ({
    id: r.id as OperatorRouteId,
    labelKey: r.titleKey,
    iconKey: r.iconKey,
  })),
];

export function pluralize(count: number, singular: string, plural?: string): string {
  const form = count === 1 ? singular : (plural ?? `${singular}s`);
  return `${count} ${form}`;
}

export function formatOsName(os: string): string {
  const norm = os.trim().toLowerCase();
  if (norm === "macos" || norm === "darwin") return "macOS";
  if (norm === "linux") return "Linux";
  if (norm === "windows") return "Windows";
  return os;
}

export * from "./present";
import { capitalizeLabel } from "./present";

export function presentMode(mode: "off" | "watch" | "ask" | "block"): {
  label: string;
  iconKey: string;
  tone: "neutral" | "info" | "warning" | "danger";
} {
  switch (mode) {
    case "off":
      return { label: MESSAGES["mode.off.label"], iconKey: "mode.off", tone: "neutral" };
    case "watch":
      return { label: MESSAGES["mode.watch.label"], iconKey: "mode.watch", tone: "info" };
    case "ask":
      return { label: MESSAGES["mode.ask.label"], iconKey: "mode.ask", tone: "warning" };
    case "block":
      return { label: MESSAGES["mode.block.label"], iconKey: "mode.block", tone: "danger" };
  }
}

export function presentVerdict(verdict: "allow" | "modify" | "step_up" | "defer" | "deny"): {
  label: string;
  iconKey: string;
  tone: "success" | "info" | "warning" | "neutral" | "danger";
} {
  switch (verdict) {
    case "allow":
      return { label: MESSAGES["console.verdict.allow"], iconKey: "verdict.allow", tone: "success" };
    case "modify":
      return { label: MESSAGES["console.verdict.modify"], iconKey: "verdict.modify", tone: "info" };
    case "step_up":
      return { label: MESSAGES["console.verdict.step_up"], iconKey: "verdict.step_up", tone: "warning" };
    case "defer":
      return { label: MESSAGES["console.verdict.defer"], iconKey: "verdict.defer", tone: "neutral" };
    case "deny":
      return { label: MESSAGES["console.verdict.deny"], iconKey: "verdict.deny", tone: "danger" };
  }
}

export function presentAssurance(level: "AL0" | "AL1" | "AL2" | "AL3" | "AL4", control: string): {
  level: string;
  label: string;
  description: string;
  controlLabel: string;
  iconKey: string;
  tone: "success" | "warning" | "neutral";
} {
  const isBoundary = control.includes("boundary");
  const isRequest = control === "request";
  const mapped: Record<typeof level, { label: string; description: string }> = {
    AL0: { label: "Observed", description: "Discovered on device. No hook is active yet." },
    AL1: { label: "App hook", description: "Checked by the agent's hook before execution" },
    AL2: { label: "Tool proxy", description: "Routed through the local tool broker" },
    AL3: { label: "Sandboxed", description: "Isolated inside an operating-system boundary" },
    AL4: { label: "Enforced", description: "Tamper-resistant boundary enforcement verified" },
  };
  const info = mapped[level];
  return {
    level,
    label: info.label,
    description: info.description,
    controlLabel: isBoundary ? "Boundary" : isRequest ? "Request" : "Observe",
    iconKey: `assurance.${level.toLowerCase()}`,
    tone: isBoundary ? "success" : isRequest ? "warning" : "neutral",
  };
}

export function presentMdmFormat(format: string): string {
  switch (format) {
    case "intune_win32":
      return "Intune Win32 (.intunewin / PS1)";
    case "jamf_mobileconfig":
      return "Jamf Pro (.mobileconfig)";
    case "hexnode":
      return "Hexnode MDM";
    case "tanium":
      return "Tanium Deploy";
    case "chrome_enterprise":
      return "Chrome / Edge Enterprise";
    case "firefox_gpo":
      return "Firefox AD GPO / policies.json";
    case "linux_repo":
      return "Linux apt / dnf config";
    default:
      return capitalizeLabel(format);
  }
}

export function presentIntegrationCategory(category: string): string {
  switch (category) {
    case "directory_sync":
      return "Directory sync";
    case "saas_connector":
      return "SaaS activity";
    case "export_sink":
      return "Export sink";
    default:
      return capitalizeLabel(category);
  }
}

export function presentIntegrationHealth(state: string): {
  label: string;
  tone: "allow" | "ask" | "block" | "neutral";
} {
  switch (state) {
    case "connected":
      return { label: "Connected", tone: "allow" };
    case "at_risk":
      return { label: "At risk", tone: "ask" };
    case "degraded":
      return { label: "Degraded", tone: "block" };
    case "not_configured":
    default:
      return { label: "Not configured", tone: "neutral" };
  }
}

export function presentDeploymentKeyStatus(status: string): {
  label: string;
  tone: "allow" | "ask" | "block" | "neutral";
} {
  switch (status) {
    case "active":
      return { label: "Active", tone: "allow" };
    case "exhausted":
      return { label: "Quota reached", tone: "ask" };
    case "expired":
      return { label: "Expired", tone: "neutral" };
    case "revoked":
    default:
      return { label: "Revoked", tone: "block" };
  }
}

export function presentInstallProfile(profile: string): string {
  switch (profile) {
    case "standard":
      return "Standard";
    case "enforced":
      return "Enforced boundary";
    case "watch":
      return "Watch baseline";
    default:
      return capitalizeLabel(profile);
  }
}

export function presentBrowserDlpClass(cls: string): string {
  switch (cls) {
    case "file_upload":
      return "File upload";
    case "paste_secret":
      return "Secret paste";
    case "source_code":
      return "Source code";
    case "customer_pii":
      return "Customer PII";
    default:
      return capitalizeLabel(cls);
  }
}

export function presentSessionLabel(
  label: "credential_accessed" | "untrusted_web_fetched" | "repeated_denials" | "tainted_exfil_risk",
): { text: string; tone: "warning" | "info" | "danger" } {
  switch (label) {
    case "credential_accessed":
      return { text: MESSAGES["console.session_label.credential_accessed"], tone: "warning" };
    case "untrusted_web_fetched":
      return { text: MESSAGES["console.session_label.untrusted_web_fetched"], tone: "info" };
    case "repeated_denials":
      return { text: MESSAGES["console.session_label.repeated_denials"], tone: "danger" };
    case "tainted_exfil_risk":
      return { text: MESSAGES["console.session_label.tainted_exfil_risk"], tone: "danger" };
  }
}

export function formatTimestamp(iso: string | null | undefined): string {
  if (!iso) return "";
  const parsed = new Date(iso);
  if (!Number.isFinite(parsed.getTime())) return iso;
  return parsed.toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
}
