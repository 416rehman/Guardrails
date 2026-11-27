// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
import { createContext, useContext, useEffect, useMemo, useState } from "react";
import {
  Outlet,
  createBrowserHistory,
  createRootRoute,
  createRoute,
  createRouter,
  useNavigate,
  useRouterState,
  type RouterHistory,
} from "@tanstack/react-router";
import { api, getApiToken, setApiToken } from "@grdr/api";
import { t } from "@grdr/i18n";
import { ViewStateFrame } from "@grdr/kit";
import {
  Badge,
  Banner,
  Button,
  Card,
  GrdrIcon,
  GrdrThemeProvider,
  GuardrailsMark,
  HStack,
  IconButton,
  Text,
  TextInput,
  Tooltip,
  VStack,
  type GrdrThemeMode,
} from "@grdr/ui";
import { Breadcrumbs } from "../../console/src/components/Breadcrumbs";
import { OperatorAuditView } from "./OperatorAuditView";
import { OperatorBackupsView } from "./OperatorBackupsView";
import { OperatorKeysView } from "./OperatorKeysView";
import { OperatorOrgsView } from "./OperatorOrgsView";
import { OperatorSettingsView } from "./OperatorSettingsView";
import { OperatorUpgradesView } from "./OperatorUpgradesView";
import { OperatorHealthView, OperatorOverviewView } from "./OperatorViews";
import {
  OPERATOR_NAV_ITEMS,
  deriveOperatorRoute,
  findOperatorNavItem,
  type ExtendedOperatorRouteId,
} from "./operatorRoutes";
import { useOperatorSnapshotQueries, type OperatorSnapshot } from "./queries";

type SidebarDisplay = "expanded" | "collapsed";

type ExportState =
  | { kind: "idle" }
  | { kind: "exported"; message: string }
  | { kind: "failed"; message: string };

interface OperatorContextValue {
  snapshot: OperatorSnapshot;
  navigateRoute: (route: ExtendedOperatorRouteId) => void;
  invalidateAll: () => Promise<void>;
}

const OperatorContext = createContext<OperatorContextValue | null>(null);

function useOperatorSnapshot(): OperatorContextValue {
  const ctx = useContext(OperatorContext);
  if (!ctx) {
    throw new Error("GRDR-WEB-0002: OperatorContext missing");
  }
  return ctx;
}

function isAuthBlockedMessage(message: string): boolean {
  const lower = message.toLowerCase();
  return lower.includes("401") || lower.includes("token") || lower.includes("unauthorized");
}

function OperatorShell() {
  const navigate = useNavigate();
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const route = deriveOperatorRoute(pathname);

  const [themeMode, setThemeMode] = useState<GrdrThemeMode>("light");
  const [sidebarDisplay, setSidebarDisplay] = useState<SidebarDisplay>("expanded");
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [exportState, setExportState] = useState<ExportState>({ kind: "idle" });
  const [tokenInput, setTokenInput] = useState(() => getApiToken());

  const { phase, invalidateAll } = useOperatorSnapshotQueries();
  const activeNav = findOperatorNavItem(route);

  useEffect(() => {
    if (!mobileNavOpen) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setMobileNavOpen(false);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [mobileNavOpen]);

  const navigateRoute = (next: ExtendedOperatorRouteId) => {
    setMobileNavOpen(false);
    void navigate({ to: findOperatorNavItem(next).path });
  };

  const handleExportOcsf = async () => {
    try {
      setExportState({ kind: "idle" });
      await api.exportOcsf();
      setExportState({ kind: "exported", message: "Exported OCSF 1.9 event bundle" });
    } catch (err) {
      setExportState({
        kind: "failed",
        message: err instanceof Error ? err.message : "OCSF export failed",
      });
    }
  };

  const handleExportAuditJsonl = async () => {
    try {
      setExportState({ kind: "idle" });
      await api.exportAuditJsonl();
      setExportState({ kind: "exported", message: "Exported tamper-evident audit JSONL stream" });
    } catch (err) {
      setExportState({
        kind: "failed",
        message: err instanceof Error ? err.message : "Audit JSONL export failed",
      });
    }
  };

  const snapshot =
    phase.kind === "ready"
      ? phase.data
      : phase.kind === "error"
        ? (phase.staleData ?? null)
        : null;
  const viewState = phase.kind === "error" ? "error" : phase.kind === "loading" ? "empty" : "ready";
  const sidebarCollapsed = sidebarDisplay === "collapsed";
  const isAuthLocked = phase.kind === "error" && !snapshot && isAuthBlockedMessage(phase.message);

  const breadcrumbs = useMemo(() => {
    if (route === "op-overview") return [];
    const overviewNav = findOperatorNavItem("op-overview");
    return [
      { id: "op-overview", label: overviewNav.label, onClick: () => navigateRoute("op-overview") },
      { id: route, label: activeNav.label },
    ];
  }, [route, activeNav.label]);

  const railClassName = [
    "rail",
    sidebarCollapsed ? "collapsed" : "",
    mobileNavOpen ? "mobile-open" : "",
  ]
    .filter(Boolean)
    .join(" ");

  const footerText =
    phase.kind === "error"
      ? isAuthBlockedMessage(phase.message)
        ? "Authentication required"
        : "Endpoint unreachable"
      : "Local audit plane";

  return (
    <GrdrThemeProvider mode={themeMode}>
      <div className={sidebarCollapsed ? "shell collapsed" : "shell"}>
        <aside className={railClassName} aria-label="Operator navigation">
          <div className="brand-header">
            <div className="brand-mark">
              <div className="brand-glyph">
                <GuardrailsMark size={18} />
              </div>
              {!sidebarCollapsed && (
                <div className="brand-title">
                  <strong>{t("grdr.brand.name")}</strong>
                  <span>{t("grdr.brand.operator_subtitle")}</span>
                </div>
              )}
            </div>
            <button
              type="button"
              className="rail-mobile-toggle"
              aria-label="Toggle navigation menu"
              aria-expanded={mobileNavOpen}
              aria-controls="operator-rail-nav"
              onClick={() => setMobileNavOpen((prev) => !prev)}
            >
              <GrdrIcon name={mobileNavOpen ? "x" : "list"} size={14} />
              <span>{mobileNavOpen ? "Close" : activeNav.label}</span>
            </button>
            <span className="rail-collapse-btn">
              <IconButton
                label={sidebarCollapsed ? "Expand navigation" : "Collapse navigation"}
                icon={<GrdrIcon name={sidebarCollapsed ? "panel-left-open" : "panel-left-close"} size={15} />}
                variant="ghost"
                size="sm"
                onClick={() => setSidebarDisplay((prev) => (prev === "collapsed" ? "expanded" : "collapsed"))}
              />
            </span>
          </div>

          <nav id="operator-rail-nav" className="rail-nav" aria-label="Operator sections" data-mobile-collapsible="true">
            {OPERATOR_NAV_ITEMS.map((item) => {
              const lockedOut = isAuthLocked && item.id !== "op-overview";
              const btn = (
                <button
                  key={item.id}
                  type="button"
                  title={item.label}
                  aria-label={item.label}
                  aria-current={item.id === route ? "page" : undefined}
                  disabled={lockedOut}
                  className={item.id === route ? "nav-item active" : "nav-item"}
                  onClick={() => navigateRoute(item.id)}
                >
                  <span className="nav-item-label">
                    <GrdrIcon name={item.icon} size={16} />
                    {!sidebarCollapsed && <span>{item.label}</span>}
                  </span>
                </button>
              );

              if (sidebarCollapsed) {
                return (
                  <Tooltip key={item.id} content={item.label} placement="end">
                    {btn}
                  </Tooltip>
                );
              }
              return btn;
            })}
          </nav>

          {!sidebarCollapsed && (
            <div className="rail-footer">
              <span>{footerText}</span>
            </div>
          )}
        </aside>

        <div className="workspace">
          <header className="topbar operator-context">
            <HStack gap={2} align="center" style={{ flexWrap: "wrap", rowGap: 6 }}>
              <span style={{ flexShrink: 0, display: "inline-flex" }}>
                <Badge variant="warning" label="Operator realm" icon={<GrdrIcon name="lock" size={12} />} />
              </span>
              <span style={{ fontSize: 13 }}>{t("operator.context.banner")}</span>
            </HStack>
            <HStack gap={2} align="center">
              <Button
                label="Refresh"
                variant="secondary"
                size="sm"
                icon={<GrdrIcon name="refresh" size={14} />}
                onClick={() => void invalidateAll()}
              />
              <Button
                label={themeMode === "dark" ? "Light" : "Dark"}
                variant="secondary"
                size="sm"
                icon={<GrdrIcon name={themeMode === "dark" ? "sun" : "moon"} size={14} />}
                aria-label="Toggle color theme"
                onClick={() => setThemeMode((prev: GrdrThemeMode) => (prev === "dark" ? "light" : "dark"))}
              />
            </HStack>
          </header>

          <main className="content-area">
            <VStack gap={4}>
              {breadcrumbs.length > 0 && <Breadcrumbs items={breadcrumbs} />}
              <div className="page-header" style={{ flexWrap: "wrap", gap: 12 }}>
                <div>
                  <h1 className="hero-headline" style={{ fontSize: 30 }}>{activeNav.label}</h1>
                  <Text color="secondary">{activeNav.subtitle}</Text>
                </div>
                {route === "op-audit" && snapshot && (
                  <div className="op-actions-row">
                    <Button
                      label="Export OCSF 1.9"
                      variant="secondary"
                      size="sm"
                      icon={<GrdrIcon name="file-json" size={14} />}
                      onClick={() => void handleExportOcsf()}
                    />
                    <Button
                      label="Export audit JSONL"
                      variant="secondary"
                      size="sm"
                      icon={<GrdrIcon name="download" size={14} />}
                      onClick={() => void handleExportAuditJsonl()}
                    />
                  </div>
                )}
              </div>

              {exportState.kind === "exported" ? (
                <Banner status="info" title={exportState.message} collapsible={false} />
              ) : exportState.kind === "failed" ? (
                <Banner status="error" title={exportState.message} collapsible={false} />
              ) : null}

              <ViewStateFrame
                state={viewState}
                title={phase.kind === "error" ? "Operator authentication or endpoint error" : "Loading operator plane"}
                description={
                  phase.kind === "error"
                    ? phase.message
                    : "Connecting to Guardrails control-plane health and audit APIs."
                }
              >
                {snapshot ? (
                  <OperatorContext.Provider value={{ snapshot, navigateRoute, invalidateAll }}>
                    <VStack gap={4}>
                      <Outlet />
                    </VStack>
                  </OperatorContext.Provider>
                ) : null}
              </ViewStateFrame>

              {phase.kind === "error" && (
                <Card padding={3}>
                  <form
                    onSubmit={(e) => {
                      e.preventDefault();
                      setApiToken(tokenInput);
                      void invalidateAll();
                    }}
                  >
                    <VStack gap={2}>
                      <Text size="sm" weight="semibold">Authenticate operator realm</Text>
                      <Text size="sm" color="secondary">
                        Enter the dedicated operator bearer token to load isolation, trust keys, upgrades, backups, and audit logs.
                      </Text>
                      <div className="op-token-row">
                        <div className="op-token-input">
                          <TextInput
                            label="Operator token"
                            type="password"
                            placeholder="Paste dedicated operator token"
                            value={tokenInput}
                            onChange={setTokenInput}
                            data-agent-secret="true"
                            autoComplete="off"
                            width="100%"
                          />
                        </div>
                        <Button label="Apply token" type="submit" variant="primary" size="sm" />
                        <Button label="Retry" variant="secondary" size="sm" onClick={() => void invalidateAll()} />
                      </div>
                    </VStack>
                  </form>
                </Card>
              )}
            </VStack>
          </main>
        </div>
      </div>
    </GrdrThemeProvider>
  );
}

function OverviewRoute() {
  const { snapshot, navigateRoute } = useOperatorSnapshot();
  return <OperatorOverviewView snapshot={snapshot} onNavigate={navigateRoute} />;
}

function HealthRoute() {
  const { snapshot, navigateRoute } = useOperatorSnapshot();
  return <OperatorHealthView snapshot={snapshot} onNavigate={navigateRoute} />;
}

function OrgsRoute() {
  const { snapshot, navigateRoute } = useOperatorSnapshot();
  return <OperatorOrgsView snapshot={snapshot} onNavigate={navigateRoute} />;
}

function KeysRoute() {
  const { snapshot, navigateRoute } = useOperatorSnapshot();
  return <OperatorKeysView snapshot={snapshot} onNavigate={navigateRoute} />;
}

function SettingsRoute() {
  const { snapshot, navigateRoute } = useOperatorSnapshot();
  return <OperatorSettingsView snapshot={snapshot} onNavigate={navigateRoute} />;
}

function AuditRoute() {
  const { snapshot } = useOperatorSnapshot();
  return <OperatorAuditView snapshot={snapshot} />;
}

function UpgradesRoute() {
  const { snapshot, invalidateAll } = useOperatorSnapshot();
  return <OperatorUpgradesView snapshot={snapshot} onMutated={invalidateAll} />;
}

function BackupsRoute() {
  const { snapshot, invalidateAll } = useOperatorSnapshot();
  return <OperatorBackupsView snapshot={snapshot} onMutated={invalidateAll} />;
}

const rootRoute = createRootRoute({ component: OperatorShell, notFoundComponent: OverviewRoute });
const indexRoute = createRoute({ getParentRoute: () => rootRoute, path: "/", component: OverviewRoute });
const overviewRoute = createRoute({ getParentRoute: () => rootRoute, path: "/overview", component: OverviewRoute });
const healthRoute = createRoute({ getParentRoute: () => rootRoute, path: "/health", component: HealthRoute });
const orgsRoute = createRoute({ getParentRoute: () => rootRoute, path: "/orgs", component: OrgsRoute });
const keysRoute = createRoute({ getParentRoute: () => rootRoute, path: "/keys", component: KeysRoute });
const settingsRoute = createRoute({ getParentRoute: () => rootRoute, path: "/settings", component: SettingsRoute });
const upgradesRoute = createRoute({ getParentRoute: () => rootRoute, path: "/upgrades", component: UpgradesRoute });
const backupsRoute = createRoute({ getParentRoute: () => rootRoute, path: "/backups", component: BackupsRoute });
const auditRoute = createRoute({ getParentRoute: () => rootRoute, path: "/audit", component: AuditRoute });

const operatorTree = rootRoute.addChildren([
  indexRoute,
  overviewRoute,
  healthRoute,
  orgsRoute,
  keysRoute,
  settingsRoute,
  upgradesRoute,
  backupsRoute,
  auditRoute,
]);

export function createOperatorRouter(history?: RouterHistory) {
  return createRouter({
    routeTree: operatorTree,
    history: history ?? createBrowserHistory(),
    defaultNotFoundComponent: OverviewRoute,
  });
}
