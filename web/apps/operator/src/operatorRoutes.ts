// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
import { OPERATOR_ROUTES, routeLabel, type OperatorRouteId } from "@grdr/i18n";
import { iconKeyToName, type GrdrIconName } from "@grdr/ui";

export type ExtendedOperatorRouteId = OperatorRouteId | "op-orgs" | "op-keys";

export interface OperatorNavItem {
  id: ExtendedOperatorRouteId;
  path: string;
  label: string;
  subtitle: string;
  icon: GrdrIconName;
}

const CORE_ROUTE_PATHS: Record<OperatorRouteId, string> = {
  "op-overview": "/",
  "op-health": "/health",
  "op-settings": "/settings",
  "op-upgrades": "/upgrades",
  "op-backups": "/backups",
  "op-audit": "/audit",
};

const CORE_ROUTE_SUBTITLES: Record<OperatorRouteId, string> = {
  "op-overview": "Deployment isolation status, Ed25519 trust keys, and control audit overview.",
  "op-health": "Daemon liveness, persistence mode, and delivery target health.",
  "op-settings": "Identity federation, SCIM provisioning, outbound mailer, and verification keys.",
  "op-upgrades": "Staged runtime configuration revisions, diffs, rollback, and compatibility preflight.",
  "op-backups": "Delivery target circuit breakers and signed SQLite WAL backup or restore drills.",
  "op-audit": "Tamper-evident operator audit ledger with OCSF 1.9 and JSONL exports.",
};

function coreNavItem(id: OperatorRouteId): OperatorNavItem {
  const meta = OPERATOR_ROUTES.find((item) => item.id === id);
  return {
    id,
    path: CORE_ROUTE_PATHS[id],
    label: meta ? routeLabel(meta.labelKey) : id,
    subtitle: CORE_ROUTE_SUBTITLES[id],
    icon: meta ? iconKeyToName(meta.iconKey) : "server",
  };
}

export const OPERATOR_NAV_ITEMS: readonly OperatorNavItem[] = [
  coreNavItem("op-overview"),
  coreNavItem("op-health"),
  {
    id: "op-orgs",
    path: "/orgs",
    label: "Organizations",
    subtitle: "Deployment tenant isolation, policy ceilings, and new-organization bootstrap manifests.",
    icon: "globe",
  },
  {
    id: "op-keys",
    path: "/keys",
    label: "Trust keys",
    subtitle: "Deployment Ed25519 signing keys, key custody readiness, and rotation planning.",
    icon: "key-round",
  },
  coreNavItem("op-settings"),
  coreNavItem("op-upgrades"),
  coreNavItem("op-backups"),
  coreNavItem("op-audit"),
];

export function deriveOperatorRoute(pathname: string): ExtendedOperatorRouteId {
  const seg = pathname.split("/").filter(Boolean)[0] ?? "overview";
  switch (seg) {
    case "health":
      return "op-health";
    case "orgs":
      return "op-orgs";
    case "keys":
      return "op-keys";
    case "settings":
      return "op-settings";
    case "upgrades":
      return "op-upgrades";
    case "backups":
      return "op-backups";
    case "audit":
      return "op-audit";
    default:
      return "op-overview";
  }
}

export function findOperatorNavItem(id: ExtendedOperatorRouteId): OperatorNavItem {
  return OPERATOR_NAV_ITEMS.find((item) => item.id === id) ?? OPERATOR_NAV_ITEMS[0];
}
