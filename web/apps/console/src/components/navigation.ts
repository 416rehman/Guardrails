import type { Device, UserProfile } from "@grdr/api";
import {
  CONSOLE_NAV_GROUPS,
  CONSOLE_ROUTES,
  t,
  type ConsoleRouteId,
  type InventorySectionId,
  type ProtectSectionId,
} from "@grdr/i18n";
import type { BreadcrumbItem } from "./Breadcrumbs";
import type { SessionViewMode } from "../pages/SessionsPage";

export interface PaletteCommand {
  id: string;
  label: string;
  hint: string;
  run: () => void;
}

export function buildBreadcrumbs(params: {
  route: ConsoleRouteId;
  inventorySection: InventorySectionId;
  selectedDevice: Device | null;
  selectedUser?: UserProfile | null;
  sessionsView: SessionViewMode;
  activeSessionId: string | null;
  protectSection: ProtectSectionId;
  focusedRuleId?: string | null;
  onGoHome: () => void;
  onSelectUsersRoot?: () => void;
  onSelectInventorySection: (section: InventorySectionId) => void;
  onClearDevice: () => void;
  onSelectSessionsView: (view: SessionViewMode) => void;
  onSelectProtectSection: (section: ProtectSectionId) => void;
}): BreadcrumbItem[] {
  const {
    route,
    inventorySection,
    selectedDevice,
    selectedUser,
    sessionsView,
    activeSessionId,
    protectSection,
    focusedRuleId,
    onGoHome,
    onSelectUsersRoot,
    onSelectInventorySection,
    onClearDevice,
    onSelectSessionsView,
    onSelectProtectSection,
  } = params;

  if (route === "home") {
    return [{ id: "home", label: t("console.nav.home") }];
  }

  const items: BreadcrumbItem[] = [
    { id: "home", label: t("console.nav.home"), onClick: onGoHome },
  ];

  if (route === "users") {
    items.push({
      id: "users",
      label: t("console.nav.users"),
      onClick: selectedUser ? onSelectUsersRoot : undefined,
    });
    if (selectedUser) {
      items.push({ id: `user-${selectedUser.id}`, label: selectedUser.display_name });
    }
    return items;
  }

  if (route === "inventory") {
    const invItem = CONSOLE_NAV_GROUPS.flatMap((g) => g.items).find((i) => i.id === "inventory");
    const childMeta = invItem?.children?.find((c) => c.id === inventorySection);
    const childLabel = childMeta ? t(childMeta.labelKey) : t("console.nav.inventory.endpoints");

    items.push({
      id: "inventory",
      label: t("console.nav.inventory"),
      onClick: () => {
        onClearDevice();
        onSelectInventorySection("endpoints");
      },
    });
    items.push({
      id: `inventory-${inventorySection}`,
      label: childLabel,
      onClick: selectedDevice ? onClearDevice : undefined,
    });
    if (inventorySection === "endpoints" && selectedDevice) {
      items.push({ id: `device-${selectedDevice.id}`, label: selectedDevice.hostname });
    }
    return items;
  }

  if (route === "sessions") {
    const sessItem = CONSOLE_NAV_GROUPS.flatMap((g) => g.items).find((i) => i.id === "sessions");
    const childMeta = sessItem?.children?.find((c) => c.id === sessionsView);
    const viewLabel =
      sessionsView === "stream"
        ? "Stream"
        : childMeta
          ? t(childMeta.labelKey)
          : t("console.nav.sessions.graph");

    const sessionsLabel = t("console.nav.sessions");
    items.push({
      id: "sessions",
      label: sessionsLabel,
      onClick: () => onSelectSessionsView("graph"),
    });
    if (viewLabel !== sessionsLabel) {
      items.push({
        id: `sessions-${sessionsView}`,
        label: viewLabel,
        onClick: activeSessionId ? () => onSelectSessionsView(sessionsView) : undefined,
      });
    }
    if (activeSessionId) {
      items.push({ id: `session-${activeSessionId}`, label: activeSessionId });
    }
    return items;
  }

  if (route === "protect") {
    const protectItem = CONSOLE_NAV_GROUPS.flatMap((g) => g.items).find((i) => i.id === "protect");
    const childMeta = protectItem?.children?.find((c) => c.id === protectSection);
    const childLabel = childMeta ? t(childMeta.labelKey) : t("console.nav.protect.rules");

    items.push({
      id: "protect",
      label: t("console.nav.protect"),
      onClick: () => onSelectProtectSection("rules"),
    });
    items.push({
      id: `protect-${protectSection}`,
      label: childLabel,
      onClick: focusedRuleId ? () => onSelectProtectSection(protectSection) : undefined,
    });
    if (focusedRuleId) {
      items.push({ id: `rule-${focusedRuleId}`, label: focusedRuleId });
    }
    return items;
  }

  const routeMeta = CONSOLE_ROUTES.find((r) => r.id === route);
  items.push({ id: route, label: routeMeta ? t(routeMeta.labelKey) : route });
  return items;
}

export function buildCommandActions(params: {
  devices: Device[];
  theme: "light" | "dark";
  hasToken: boolean;
  query: string;
  onSelectRoute: (route: ConsoleRouteId) => void;
  onSelectChild: (route: ConsoleRouteId, childId: string) => void;
  onToggleTheme: () => void;
  onShowTokenBar: () => void;
  onInspectDevice: (device: Device) => void;
}): PaletteCommand[] {
  const {
    devices,
    theme,
    hasToken,
    query,
    onSelectRoute,
    onSelectChild,
    onToggleTheme,
    onShowTokenBar,
    onInspectDevice,
  } = params;
  const queryNorm = query.trim().toLowerCase();

  return [
    ...CONSOLE_ROUTES.map((item) => ({
      id: `route-${item.id}`,
      label: `Go to ${t(item.labelKey)}`,
      hint: "Route",
      run: () => onSelectRoute(item.id),
    })),
    ...CONSOLE_NAV_GROUPS.flatMap((g) => g.items)
      .filter((item) => item.children && item.children.length > 0)
      .flatMap((item) =>
        (item.children ?? []).map((child) => ({
          id: `sub-${item.id}-${child.id}`,
          label: `${t(item.labelKey)}: ${t(child.labelKey)}`,
          hint: "Section",
          run: () => onSelectChild(item.id, child.id),
        })),
      ),
    {
      id: "toggle-theme",
      label: theme === "light" ? "Switch to Nocturne Dark theme" : "Switch to Paper Light theme",
      hint: "Appearance",
      run: onToggleTheme,
    },
    {
      id: "connect-api-token",
      label: hasToken ? "Update local API bearer token" : "Connect local API bearer token",
      hint: "Connection",
      run: onShowTokenBar,
    },
    ...devices.map((dev) => ({
      id: `dev-${dev.id}`,
      label: `Inspect device ${dev.hostname}`,
      hint: `${dev.os}/${dev.arch}`,
      run: () => onInspectDevice(dev),
    })),
  ].filter((cmd) => !queryNorm || cmd.label.toLowerCase().includes(queryNorm));
}
