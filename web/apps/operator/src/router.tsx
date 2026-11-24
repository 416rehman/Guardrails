import { createContext, useContext, useMemo, useState } from "react";
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
import { api } from "@grdr/api";
import { OPERATOR_ROUTES, type OperatorRouteId, t } from "@grdr/i18n";
import { ViewStateFrame } from "@grdr/kit";
import {
  Badge,
  Banner,
  Button,
  GrdrIcon,
  GrdrThemeProvider,
  GuardrailsMark,
  HStack,
  IconButton,
  Text,
  VStack,
  iconKeyToName,
  type GrdrThemeMode,
} from "@grdr/ui";
import { Breadcrumbs } from "../../console/src/components/Breadcrumbs";
import {
  OperatorAuditView,
  OperatorHealthView,
  OperatorOverviewView,
  OperatorSettingsView,
} from "./OperatorViews";
import {
  useOperatorSnapshotQueries,
  type OperatorSnapshot,
} from "./queries";

type SidebarDisplay = "expanded" | "collapsed";

type ExportState =
  | { kind: "idle" }
  | { kind: "exported"; message: string }
  | { kind: "failed"; message: string };

interface OperatorContextValue {
  snapshot: OperatorSnapshot;
  navigateRoute: (route: OperatorRouteId) => void;
}

const OperatorContext = createContext<OperatorContextValue | null>(null);

function useOperatorSnapshot(): OperatorContextValue {
  const ctx = useContext(OperatorContext);
  if (!ctx) {
    throw new Error("GRDR-WEB-0002: OperatorContext missing");
  }
  return ctx;
}

function deriveOperatorRoute(pathname: string): OperatorRouteId {
  const seg = pathname.split("/").filter(Boolean)[0] ?? "overview";
  switch (seg) {
    case "health":
      return "op-health";
    case "settings":
      return "op-settings";
    case "audit":
      return "op-audit";
    default:
      return "op-overview";
  }
}

function pathForOperatorRoute(route: OperatorRouteId): string {
  switch (route) {
    case "op-overview":
      return "/";
    case "op-health":
      return "/health";
    case "op-settings":
      return "/settings";
    case "op-audit":
      return "/audit";
  }
}

function OperatorShell() {
  const navigate = useNavigate();
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const route = deriveOperatorRoute(pathname);

  const [themeMode, setThemeMode] = useState<GrdrThemeMode>("light");
  const [sidebarDisplay, setSidebarDisplay] = useState<SidebarDisplay>("expanded");
  const [exportState, setExportState] = useState<ExportState>({ kind: "idle" });

  const { phase, invalidateAll } = useOperatorSnapshotQueries();

  const navigateRoute = (next: OperatorRouteId) => {
    void navigate({ to: pathForOperatorRoute(next) });
  };

  const activeRoute =
    OPERATOR_ROUTES.find((item) => item.id === route) ?? OPERATOR_ROUTES[0];

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
      setExportState({
        kind: "exported",
        message: "Exported tamper-evident audit JSONL stream",
      });
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
  const viewState =
    phase.kind === "error" ? "error" : phase.kind === "loading" ? "empty" : "ready";
  const sidebarCollapsed = sidebarDisplay === "collapsed";

  const breadcrumbs = useMemo(() => {
    if (route === "op-overview") {
      return [{ id: "op-overview", label: t("operator.nav.overview") }];
    }
    return [
      {
        id: "op-overview",
        label: t("operator.nav.overview"),
        onClick: () => navigateRoute("op-overview"),
      },
      { id: route, label: t(activeRoute.labelKey) },
    ];
  }, [route, activeRoute]);

  return (
    <GrdrThemeProvider mode={themeMode}>
      <div className={sidebarCollapsed ? "shell collapsed" : "shell"}>
        <aside className={sidebarCollapsed ? "rail collapsed" : "rail"} aria-label="Operator navigation">
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
            <span className="rail-collapse-btn">
              <IconButton
                label={sidebarCollapsed ? "Expand navigation" : "Collapse navigation"}
                icon={<GrdrIcon name={sidebarCollapsed ? "panel-left-open" : "panel-left-close"} size={15} />}
                variant="ghost"
                size="sm"
                onClick={() =>
                  setSidebarDisplay((prev) => (prev === "collapsed" ? "expanded" : "collapsed"))
                }
              />
            </span>
          </div>

          <nav className="rail-nav">
            {OPERATOR_ROUTES.map((item) => (
              <button
                key={item.id}
                type="button"
                title={t(item.labelKey)}
                aria-label={t(item.labelKey)}
                className={item.id === route ? "nav-item active" : "nav-item"}
                onClick={() => navigateRoute(item.id)}
              >
                <span className="nav-item-label">
                  <GrdrIcon name={iconKeyToName(item.iconKey)} size={16} />
                  {!sidebarCollapsed && <span>{t(item.labelKey)}</span>}
                </span>
              </button>
            ))}
          </nav>

          {!sidebarCollapsed && (
            <div className="rail-footer">
              <span>{phase.kind === "error" ? "Reconnecting..." : "Local audit plane"}</span>
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
              <Breadcrumbs items={breadcrumbs} />
              <div className="page-header">
                <div>
                  <h1 className="hero-headline" style={{ fontSize: 30 }}>
                    {t(activeRoute.labelKey)}
                  </h1>
                  <Text color="secondary">
                    Deployment telemetry, Ed25519 trust keys, and compliance audit ledger.
                  </Text>
                </div>
                <HStack gap={2}>
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
                </HStack>
              </div>

              {exportState.kind === "exported" ? (
                <Banner status="info" title={exportState.message} collapsible={false} />
              ) : exportState.kind === "failed" ? (
                <Banner status="error" title={exportState.message} collapsible={false} />
              ) : null}

              <ViewStateFrame
                state={viewState}
                title={phase.kind === "error" ? "Operator endpoint unavailable" : "Loading operator plane"}
                description={
                  phase.kind === "error"
                    ? phase.message
                    : "Connecting to Guardrails control-plane health and audit APIs."
                }
                actions={
                  <Button
                    label="Retry"
                    variant="secondary"
                    size="sm"
                    onClick={() => void invalidateAll()}
                  />
                }
              >
                {snapshot ? (
                  <OperatorContext.Provider value={{ snapshot, navigateRoute }}>
                    <VStack gap={4}>
                      <Outlet />
                    </VStack>
                  </OperatorContext.Provider>
                ) : null}
              </ViewStateFrame>
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
  const { snapshot } = useOperatorSnapshot();
  return <OperatorHealthView snapshot={snapshot} />;
}

function SettingsRoute() {
  const { snapshot } = useOperatorSnapshot();
  return <OperatorSettingsView snapshot={snapshot} />;
}

function AuditRoute() {
  const { snapshot } = useOperatorSnapshot();
  return <OperatorAuditView snapshot={snapshot} />;
}

const rootRoute = createRootRoute({
  component: OperatorShell,
  notFoundComponent: OverviewRoute,
});

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  component: OverviewRoute,
});

const overviewRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/overview",
  component: OverviewRoute,
});

const healthRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/health",
  component: HealthRoute,
});

const settingsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/settings",
  component: SettingsRoute,
});

const auditRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/audit",
  component: AuditRoute,
});

const operatorTree = rootRoute.addChildren([
  indexRoute,
  overviewRoute,
  healthRoute,
  settingsRoute,
  auditRoute,
]);

export function createOperatorRouter(history?: RouterHistory) {
  return createRouter({
    routeTree: operatorTree,
    history: history ?? createBrowserHistory(),
    defaultNotFoundComponent: OverviewRoute,
  });
}
