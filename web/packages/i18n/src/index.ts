export type ConsoleRouteId =
  | "home"
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
  "grdr.brand.subtitle": "Agent detection & response",
  "grdr.brand.operator_subtitle": "Operator deployment plane",
  "console.nav.home": "Home",
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
  "console.verdict.allow": "ALLOW",
  "console.verdict.modify": "MODIFY",
  "console.verdict.step_up": "STEP_UP",
  "console.verdict.defer": "DEFER",
  "console.verdict.deny": "DENY",
  "console.session_label.credential_accessed": "Credential accessed",
  "console.session_label.untrusted_web_fetched": "Untrusted web fetched",
  "console.session_label.repeated_denials": "Repeated denials",
  "console.session_label.tainted_exfil_risk": "Tainted exfil risk",
  "console.stream.connected": "Live stream connected",
  "console.stream.reconnecting": "Live updates paused, reconnecting",
  "console.coverage.title": "Coverage",
  "console.coverage.subtitle": "Assurance levels across endpoints, hook effectiveness, and observable blind spots.",
} as const;

export type MessageKey = keyof typeof MESSAGES;

export function t(key: MessageKey): string {
  return MESSAGES[key];
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
  controlLabel: string;
  iconKey: string;
  tone: "success" | "warning" | "neutral";
} {
  const isBoundary = control.includes("boundary");
  const isRequest = control === "request";
  return {
    level,
    controlLabel: isBoundary ? "Boundary" : isRequest ? "Request" : "Observe",
    iconKey: `assurance.${level.toLowerCase()}`,
    tone: isBoundary ? "success" : isRequest ? "warning" : "neutral",
  };
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
