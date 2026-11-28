// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import {
  BRAND_NAME,
  BRAND_SHORT_NAME,
  HARNESS_CATALOG_ICONS,
  ICON_REGISTRY,
  INTERFACE_ROUTES,
  MESSAGES,
  OS_CATALOG_ICONS,
  PRESENTATION_REGISTRY,
  SUPPORTED_LOCALES,
  TRANSLATIONS,
  VOCABULARY_TERMS,
  getLocale,
  getLocaleMeta,
  initLocale,
  lookupMessage,
  resolveLocaleTag,
  setLocale,
  subscribeLocale,
  syncDocumentLocale,
  t,
  type AllConsoleRouteId,
  type AllOperatorRouteId,
  type ConsoleRouteId,
  type InterfaceRouteId,
  type LocaleCode,
  type LocaleDirection,
  type LocaleScript,
  type MessageArgs,
  type MessageKey,
  type OperatorRouteId,
} from "./generated";
import { capitalizeLabel, resolveOsCatalogEntry } from "./present";

export {
  BRAND_NAME,
  BRAND_SHORT_NAME,
  HARNESS_CATALOG_ICONS,
  ICON_REGISTRY,
  INTERFACE_ROUTES,
  MESSAGES,
  OS_CATALOG_ICONS,
  PRESENTATION_REGISTRY,
  SUPPORTED_LOCALES,
  TRANSLATIONS,
  VOCABULARY_TERMS,
  getLocale,
  getLocaleMeta,
  initLocale,
  lookupMessage,
  resolveLocaleTag,
  setLocale,
  subscribeLocale,
  syncDocumentLocale,
  t,
  type AllConsoleRouteId,
  type AllOperatorRouteId,
  type ConsoleRouteId,
  type InterfaceRouteId,
  type LocaleCode,
  type LocaleDirection,
  type LocaleScript,
  type MessageArgs,
  type MessageKey,
  type OperatorRouteId,
};

export * from "./present";

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
  labelKey: MessageKey;
  iconKey: string;
}

export interface ConsoleNavItem {
  id: ConsoleRouteId;
  labelKey: MessageKey;
  iconKey: string;
  children?: ReadonlyArray<ConsoleNavChild>;
}

export interface ConsoleNavGroup {
  id: "overview" | "fleet" | "protection";
  labelKey: MessageKey;
  items: ReadonlyArray<ConsoleNavItem>;
}

export function routeLabel(key: MessageKey | string, locale?: LocaleCode): string {
  if (key in MESSAGES) {
    return t(key as MessageKey, undefined, locale ?? getLocale());
  }
  return key;
}

export const ALL_CONSOLE_ROUTES = INTERFACE_ROUTES.filter((r) => r.area === "console");
export const ALL_OPERATOR_ROUTES = INTERFACE_ROUTES.filter((r) => r.area === "operator");

export const CONSOLE_ROUTES: ReadonlyArray<{
  id: ConsoleRouteId;
  labelKey: MessageKey;
  iconKey: string;
  path: string;
}> = INTERFACE_ROUTES.filter((r) => r.area === "console" && r.shellNav).map((r) => ({
  id: r.id as ConsoleRouteId,
  labelKey: r.titleKey as MessageKey,
  iconKey: r.iconKey,
  path: r.path,
}));

export const OPERATOR_ROUTES: ReadonlyArray<{
  id: OperatorRouteId;
  labelKey: MessageKey;
  iconKey: string;
  path: string;
}> = INTERFACE_ROUTES.filter((r) => r.area === "operator" && r.shellNav).map((r) => ({
  id: r.id as OperatorRouteId,
  labelKey: r.titleKey as MessageKey,
  iconKey: r.iconKey,
  path: r.path,
}));

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

function toIntlLocaleTag(locale: LocaleCode): string {
  switch (locale) {
    case "en-XA":
      return "en-US";
    case "ar-XB":
      return "ar";
    case "ja-XC":
      return "ja-JP";
    default:
      return locale;
  }
}

export function pluralize(
  count: number,
  singular: string,
  plural?: string,
  locale?: LocaleCode,
): string {
  const active = locale ?? getLocale();
  const intlTag = toIntlLocaleTag(active);
  let form: string;
  try {
    const category = new Intl.PluralRules(intlTag).select(count);
    form = category === "one" ? singular : (plural ?? `${singular}s`);
  } catch {
    form = count === 1 ? singular : (plural ?? `${singular}s`);
  }
  const numText = new Intl.NumberFormat(intlTag).format(count);
  return `${numText} ${form}`;
}

export function formatOsName(os: string, locale?: LocaleCode): string {
  const entry = resolveOsCatalogEntry(os);
  if (!entry) return os;
  const active = locale ?? getLocale();
  if (entry.id === "macos") return t("os.macos", undefined, active);
  if (entry.id === "windows") return t("os.windows", undefined, active);
  if (entry.id === "linux") return t("os.linux", undefined, active);
  return entry.displayName;
}

function findPresentationEntry(enumName: string, value: string) {
  return PRESENTATION_REGISTRY.find(
    (item) => item.enumName === enumName && item.value === value,
  );
}

export function presentMode(
  mode: "off" | "watch" | "ask" | "block",
  locale?: LocaleCode,
): {
  label: string;
  iconKey: string;
  tone: "neutral" | "info" | "warning" | "danger";
} {
  const entry = findPresentationEntry("Mode", mode);
  const active = locale ?? getLocale();
  if (entry) {
    return {
      label: t(entry.labelKey as MessageKey, undefined, active),
      iconKey: entry.iconKey,
      tone: entry.tone as "neutral" | "info" | "warning" | "danger",
    };
  }
  return { label: capitalizeLabel(mode), iconKey: "mode.off", tone: "neutral" };
}

export function presentVerdict(
  verdict: "allow" | "modify" | "step_up" | "defer" | "deny",
  locale?: LocaleCode,
): {
  label: string;
  iconKey: string;
  tone: "success" | "info" | "warning" | "neutral" | "danger";
} {
  const entry = findPresentationEntry("Verdict", verdict);
  const active = locale ?? getLocale();
  if (entry) {
    return {
      label: t(entry.labelKey as MessageKey, undefined, active),
      iconKey: entry.iconKey,
      tone: entry.tone as "success" | "info" | "warning" | "neutral" | "danger",
    };
  }
  return { label: capitalizeLabel(verdict), iconKey: "verdict.allow", tone: "neutral" };
}

export function presentAssurance(
  level: "AL0" | "AL1" | "AL2" | "AL3" | "AL4",
  control: string,
  locale?: LocaleCode,
): {
  level: string;
  label: string;
  description: string;
  controlLabel: string;
  iconKey: string;
  tone: "success" | "warning" | "neutral";
} {
  const active = locale ?? getLocale();
  const normLevel = level.trim().toUpperCase();
  const entry = findPresentationEntry("AssuranceLevel", normLevel);
  const labelKey = (entry?.labelKey ?? `assurance.${normLevel.toLowerCase()}`) as MessageKey;
  const descKey = (entry?.descriptionKey ?? `assurance.${normLevel.toLowerCase()}.desc`) as MessageKey;
  const normCtrl = control.trim().toLowerCase();
  const isBoundary = normCtrl.includes("boundary");
  const isRequest =
    !isBoundary &&
    (normCtrl === "request" ||
      /\brequest\b/.test(normCtrl) ||
      normCtrl.includes("proxy") ||
      normCtrl.includes("broker"));
  const controlKey: MessageKey = isBoundary
    ? "assurance.control.boundary"
    : isRequest
      ? "assurance.control.request"
      : "assurance.control.observe";
  const registryTone = entry?.tone;
  const tone: "success" | "warning" | "neutral" =
    registryTone === "success" || registryTone === "warning" ? registryTone : "neutral";
  return {
    level: normLevel,
    label: t(labelKey, undefined, active),
    description: descKey in MESSAGES ? t(descKey, undefined, active) : "",
    controlLabel: t(controlKey, undefined, active),
    iconKey: entry?.iconKey ?? `assurance.${normLevel.toLowerCase()}`,
    tone,
  };
}

export function presentMdmFormat(format: string, locale?: LocaleCode): string {
  const entry = findPresentationEntry("MdmFormat", format);
  return entry
    ? t(entry.labelKey as MessageKey, undefined, locale ?? getLocale())
    : capitalizeLabel(format);
}

export function presentIntegrationCategory(category: string, locale?: LocaleCode): string {
  const entry = findPresentationEntry("IntegrationCategory", category);
  return entry
    ? t(entry.labelKey as MessageKey, undefined, locale ?? getLocale())
    : capitalizeLabel(category);
}

export function presentIntegrationHealth(
  state: string,
  locale?: LocaleCode,
): {
  label: string;
  tone: "allow" | "ask" | "block" | "neutral";
} {
  const entry =
    findPresentationEntry("IntegrationHealth", state) ??
    findPresentationEntry("IntegrationHealth", "not_configured");
  const label = entry
    ? t(entry.labelKey as MessageKey, undefined, locale ?? getLocale())
    : capitalizeLabel(state);
  const tone = (entry?.tone ?? "neutral") as "allow" | "ask" | "block" | "neutral";
  return { label, tone };
}

export function presentDeploymentKeyStatus(
  status: string,
  locale?: LocaleCode,
): {
  label: string;
  tone: "allow" | "ask" | "block" | "neutral";
} {
  const entry =
    findPresentationEntry("DeploymentKeyStatus", status) ??
    findPresentationEntry("DeploymentKeyStatus", "revoked");
  const label = entry
    ? t(entry.labelKey as MessageKey, undefined, locale ?? getLocale())
    : capitalizeLabel(status);
  const tone = (entry?.tone ?? "block") as "allow" | "ask" | "block" | "neutral";
  return { label, tone };
}

export function presentInstallProfile(profile: string, locale?: LocaleCode): string {
  const entry = findPresentationEntry("InstallProfile", profile);
  return entry
    ? t(entry.labelKey as MessageKey, undefined, locale ?? getLocale())
    : capitalizeLabel(profile);
}

export function presentBrowserDlpClass(cls: string, locale?: LocaleCode): string {
  const entry = findPresentationEntry("BrowserDlpClass", cls);
  return entry
    ? t(entry.labelKey as MessageKey, undefined, locale ?? getLocale())
    : capitalizeLabel(cls);
}

export function presentSessionLabel(
  label: "credential_accessed" | "untrusted_web_fetched" | "repeated_denials" | "tainted_exfil_risk",
  locale?: LocaleCode,
): {
  text: string;
  iconKey: string;
  tone: "warning" | "info" | "danger" | "neutral" | "success";
} {
  const entry = findPresentationEntry("SessionLabel", label);
  const key = (entry?.labelKey ?? `session_label.${label}`) as MessageKey;
  const tone = (entry?.tone ?? "warning") as "warning" | "info" | "danger" | "neutral" | "success";
  return {
    text: t(key, undefined, locale ?? getLocale()),
    iconKey: entry?.iconKey ?? "security.alert",
    tone,
  };
}

export function formatTimestamp(
  iso: string | null | undefined,
  locale?: LocaleCode,
  timeZone?: string,
): string {
  if (!iso) return "";
  const parsed = new Date(iso);
  if (!Number.isFinite(parsed.getTime())) return iso;
  const active = locale ?? getLocale();
  const intlTag = toIntlLocaleTag(active);
  return parsed.toLocaleString(intlTag, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
    ...(timeZone ? { timeZone } : {}),
  });
}
