export type ConsoleRouteId =
  | "home"
  | "users"
  | "inventory"
  | "sessions"
  | "protect"
  | "respond"
  | "coverage"
  | "tester";

export type OperatorRouteId =
  | "op-overview"
  | "op-health"
  | "op-settings"
  | "op-audit";

export const CONSOLE_ROUTES: ReadonlyArray<{
  id: ConsoleRouteId;
  labelKey: keyof typeof MESSAGES;
  iconKey: string;
}> = [
  { id: "home", labelKey: "console.nav.home", iconKey: "nav.home" },
  { id: "users", labelKey: "console.nav.users", iconKey: "nav.users" },
  { id: "inventory", labelKey: "console.nav.inventory", iconKey: "nav.inventory" },
  { id: "sessions", labelKey: "console.nav.sessions", iconKey: "nav.sessions" },
  { id: "protect", labelKey: "console.nav.protect", iconKey: "nav.protect" },
  { id: "respond", labelKey: "console.nav.respond", iconKey: "nav.respond" },
  { id: "coverage", labelKey: "console.nav.coverage", iconKey: "nav.coverage" },
  { id: "tester", labelKey: "console.nav.tester", iconKey: "nav.tester" },
];

export const OPERATOR_ROUTES: ReadonlyArray<{
  id: OperatorRouteId;
  labelKey: keyof typeof MESSAGES;
  iconKey: string;
}> = [
  { id: "op-overview", labelKey: "operator.nav.overview", iconKey: "nav.operator_overview" },
  { id: "op-health", labelKey: "operator.nav.health", iconKey: "nav.operator_health" },
  { id: "op-settings", labelKey: "operator.nav.settings", iconKey: "nav.operator_settings" },
  { id: "op-audit", labelKey: "operator.nav.audit", iconKey: "nav.operator_audit" },
];

export const MESSAGES = {
  "grdr.brand.name": "Guardrails ADR",
  "grdr.brand.subtitle": "Agent protection",
  "grdr.brand.operator_subtitle": "Operator plane",
  "console.nav.home": "Home",
  "console.nav.users": "Users",
  "console.nav.inventory": "Inventory",
  "console.nav.sessions": "Sessions",
  "console.nav.protect": "Protect",
  "console.nav.respond": "Respond",
  "console.nav.coverage": "Coverage",
  "console.nav.tester": "Live Tester",
  "operator.nav.overview": "Overview",
  "operator.nav.health": "Health",
  "operator.nav.settings": "Settings",
  "operator.nav.audit": "Audit log",
  "operator.context.banner": "Operator context: Deployment administration realm only. No route to tenant prompts or agent content.",
  "mode.off.label": "Off",
  "mode.watch.label": "Watch",
  "mode.ask.label": "Ask",
  "mode.block.label": "Block",
  "console.verdict.allow": "Allow",
  "console.verdict.modify": "Modified",
  "console.verdict.step_up": "Ask",
  "console.verdict.defer": "Deferred",
  "console.verdict.deny": "Deny",
  "console.session_label.credential_accessed": "Credential accessed",
  "console.session_label.untrusted_web_fetched": "Untrusted web fetched",
  "console.session_label.repeated_denials": "Repeated denials",
  "console.session_label.tainted_exfil_risk": "Tainted exfil risk",
  "console.stream.connected": "Live stream connected",
  "console.stream.reconnecting": "Live updates paused, reconnecting",
  "console.coverage.title": "Coverage",
  "console.coverage.subtitle": "Protection strength across agents and operating systems.",
} as const;

export type MessageKey = keyof typeof MESSAGES;

export function t(key: MessageKey): string {
  return MESSAGES[key];
}

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

export function formatActionLabel(actionClass: string): string {
  switch (actionClass) {
    case "exec":
      return "Command run";
    case "file.read":
      return "File read";
    case "file.write":
      return "File write";
    case "file.delete":
      return "File delete";
    case "net.connect":
      return "Network connect";
    case "net.request":
      return "Network request";
    case "mcp.call":
      return "Tool call";
    case "cred.use":
      return "Credential access";
    case "elevate":
      return "Privilege elevation";
    case "config.change":
      return "Config change";
    case "data.flow":
      return "Data transfer";
    default:
      return actionClass;
  }
}

export function presentFindingTitle(rawTitle: string, agentName?: string): string {
  let clean = rawTitle.replace(
    /\b(?:exec|file\.read|file\.write|file\.delete|net\.connect|net\.request|mcp\.call|cred\.use|elevate|config\.change|data\.flow)\b/g,
    (token) => formatActionLabel(token),
  );
  if (agentName) {
    const target = agentName.trim().toLowerCase();
    const trimmed = clean.trim();
    const lower = trimmed.toLowerCase();
    const onSuffix = ` on ${target}`;
    const parenSuffix = `(${target})`;
    if (target && lower.endsWith(onSuffix)) {
      clean = trimmed.slice(0, trimmed.length - onSuffix.length);
    } else if (target && lower.endsWith(parenSuffix)) {
      clean = trimmed.slice(0, trimmed.length - parenSuffix.length);
    }
  }
  return clean.trim();
}

export function capitalizeLabel(value: string): string {
  if (!value) return value;
  return value.charAt(0).toUpperCase() + value.slice(1);
}

export function presentArtifactKind(kind: string): string {
  switch (kind) {
    case "skill":
      return "Skill";
    case "rule":
      return "Rule";
    case "plugin":
      return "Plugin";
    case "command":
      return "Command";
    case "subagent":
      return "Subagent";
    default:
      return capitalizeLabel(kind);
  }
}

export function presentArtifactScope(scope: string): string {
  switch (scope) {
    case "user":
      return "User";
    case "workspace":
      return "Workspace";
    case "managed":
      return "Managed";
    default:
      return capitalizeLabel(scope);
  }
}

export function presentArtifactRiskFlag(flag: string): string {
  switch (flag) {
    case "has-scripts":
      return "Has scripts";
    case "requests-broad-tools":
      return "Broad tools";
    case "bidi-obfuscation":
      return "Bidi obfuscation";
    case "unpinned-digest":
      return "Unpinned digest";
    default:
      return capitalizeLabel(flag.replace(/-/g, " "));
  }
}

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
