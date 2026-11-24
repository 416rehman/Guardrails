import { useCallback, useEffect, useMemo, useState } from "react";
import { Outlet, useNavigate, useRouterState } from "@tanstack/react-router";
import {
  api,
  getApiToken,
  setApiToken,
  type ActionAttempt,
  type GrantScope,
} from "@grdr/api";
import type {
  ConsoleRouteId,
  InventorySectionId,
  ProtectSectionId,
} from "@grdr/i18n";
import type { EntityTarget } from "@grdr/kit";
import {
  Badge,
  Banner,
  Button,
  Dialog,
  GrdrIcon,
  GrdrThemeProvider,
  HeroWaveBackdrop,
  HStack,
  Kbd,
  TextInput,
  UiSdkInlineBar,
  useUiSdkReadOnlyAgentBridge,
  type GrdrThemeMode,
} from "@grdr/ui";
import { Breadcrumbs } from "./components/Breadcrumbs";
import { buildBreadcrumbs, buildCommandActions } from "./components/navigation";
import { SidebarNav } from "./components/SidebarNav";
import { useConsoleStream } from "./components/useConsoleStream";
import {
  type PaletteState,
  type PrefillDraft,
  type SidebarDisplay,
  type StreamState,
  type TokenBarState,
} from "./consoleState";
import { ConsoleWorkspaceContext } from "./ConsoleContext";
import type { SessionViewMode } from "./pages/SessionsPage";
import { useConsoleSnapshotQueries } from "./queries";
import {
  deriveConsoleLocation,
  pathForConsoleRoute,
  validateConsoleSearch,
  type ConsoleSearchParams,
} from "./searchSchema";

export function ConsoleShell() {
  useUiSdkReadOnlyAgentBridge();

  const navigate = useNavigate();
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const rawSearch = useRouterState({
    select: (s) => s.location.search as Record<string, unknown>,
  });
  const urlSearch = useMemo(
    () => validateConsoleSearch(rawSearch ?? {}),
    [rawSearch],
  );
  const { route, inventorySection, sessionsView, protectSection } = useMemo(
    () => deriveConsoleLocation(pathname),
    [pathname],
  );

  const [theme, setTheme] = useState<GrdrThemeMode>("light");
  const [sidebarDisplay, setSidebarDisplay] = useState<SidebarDisplay>("expanded");
  const [searchQuery, setSearchQuery] = useState("");
  const [palette, setPalette] = useState<PaletteState>("closed");
  const [streamState, setStreamState] = useState<StreamState>({ kind: "connected" });
  const [tokenBar, setTokenBar] = useState<TokenBarState>({ kind: "hidden" });
  const [streamVersion, setStreamVersion] = useState(0);
  const [prefill, setPrefill] = useState<PrefillDraft>({ kind: "none" });

  const { snapshot, isLoading, errorMessage, invalidateAll } =
    useConsoleSnapshotQueries(streamVersion);
  const { devices, sessions, approvals, users } = snapshot;

  const handleDisconnectedChange = useCallback((disconnected: boolean) => {
    setStreamState(disconnected ? { kind: "reconnecting" } : { kind: "connected" });
  }, []);

  useConsoleStream(streamVersion, handleDisconnectedChange);

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPalette((prev) => (prev === "open" ? "closed" : "open"));
      } else if (e.key === "Escape") {
        setPalette("closed");
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  const navigateRoute = useCallback(
    (next: ConsoleRouteId, childId?: string) => {
      const to = pathForConsoleRoute(next, childId);
      void navigate({ to, search: {} });
    },
    [navigate],
  );

  const updateSearch = useCallback(
    (patch: Partial<ConsoleSearchParams>) => {
      const merged: Record<string, unknown> = {
        ...urlSearch,
        ...patch,
      };
      for (const key of Object.keys(merged)) {
        if (merged[key] === undefined) {
          delete merged[key];
        }
      }
      void navigate({
        to: ".",
        search: merged,
      });
    },
    [navigate, urlSearch],
  );

  const handleOpenEntity = useCallback(
    (target: EntityTarget) => {
      switch (target.kind) {
        case "user":
          void navigate({ to: "/users", search: { userId: target.id } });
          break;
        case "device":
          void navigate({
            to: "/inventory/$section",
            params: { section: "endpoints" },
            search: { device: target.id },
          });
          break;
        case "agent":
          void navigate({
            to: "/inventory/$section",
            params: { section: "agents" },
            search: { agent: target.label.toLowerCase() },
          });
          break;
        case "mcp":
          void navigate({
            to: "/inventory/$section",
            params: { section: "mcps" },
            search: { q: target.label },
          });
          break;
        case "artifact":
          void navigate({
            to: "/inventory/$section",
            params: { section: "skills" },
            search: { q: target.label },
          });
          break;
        case "session":
          void navigate({
            to: "/sessions/$view",
            params: { view: "graph" },
            search: { sessionId: target.id },
          });
          break;
        case "rule":
          void navigate({
            to: "/protect/$section",
            params: { section: "rules" },
            search: { ruleId: target.id },
          });
          break;
      }
    },
    [navigate],
  );

  const handleOpenSessionTurn = useCallback(
    (sessionId: string, turnIndex: number) => {
      void navigate({
        to: "/sessions/$view",
        params: { view: "trace" },
        search: { sessionId, turn: turnIndex },
      });
    },
    [navigate],
  );

  const handleDecideApproval = useCallback(
    async (id: string, approve: boolean, scope: GrantScope) => {
      await api.decideApproval(
        id,
        approve,
        scope,
        approve ? `Approved (${scope}) from Console Home` : "Denied from Console Home",
      );
      await invalidateAll();
    },
    [invalidateAll],
  );

  const handleCreateRuleFromAttempt = useCallback(
    (attempt: ActionAttempt) => {
      setPrefill({ kind: "fromAttempt", attempt });
      void navigate({
        to: "/protect/$section",
        params: { section: "rules" },
        search: {},
      });
    },
    [navigate],
  );

  const selectedDevice = useMemo(
    () => devices.find((d) => d.id === urlSearch.device) ?? null,
    [devices, urlSearch.device],
  );
  const selectedUser = useMemo(
    () =>
      urlSearch.userId
        ? (users.find((u) => u.id === urlSearch.userId) ?? null)
        : null,
    [users, urlSearch.userId],
  );
  const activeSessionId = urlSearch.sessionId ?? sessions[0]?.id ?? null;
  const pendingApprovals = approvals.filter((a) => a.state.status === "pending").length;

  const activeChildId =
    route === "inventory"
      ? inventorySection
      : route === "sessions"
        ? sessionsView === "stream"
          ? "graph"
          : sessionsView
        : route === "protect"
          ? protectSection
          : null;

  const breadcrumbs = useMemo(
    () =>
      buildBreadcrumbs({
        route,
        inventorySection,
        selectedDevice,
        selectedUser,
        sessionsView,
        activeSessionId,
        protectSection,
        focusedRuleId: urlSearch.ruleId ?? null,
        onGoHome: () => navigateRoute("home"),
        onSelectUsersRoot: () => navigateRoute("users"),
        onSelectInventorySection: (sec: InventorySectionId) =>
          navigateRoute("inventory", sec),
        onClearDevice: () => updateSearch({ device: undefined }),
        onSelectSessionsView: (view: SessionViewMode) =>
          void navigate({
            to: "/sessions/$view",
            params: { view },
            search: urlSearch.sessionId ? { sessionId: urlSearch.sessionId } : {},
          }),
        onSelectProtectSection: (sec: ProtectSectionId) =>
          navigateRoute("protect", sec),
      }),
    [
      route,
      inventorySection,
      selectedDevice,
      selectedUser,
      sessionsView,
      activeSessionId,
      protectSection,
      urlSearch.ruleId,
      urlSearch.sessionId,
      navigateRoute,
      updateSearch,
      navigate,
    ],
  );

  const commandActions = buildCommandActions({
    devices,
    theme,
    hasToken: Boolean(getApiToken()),
    query: searchQuery,
    onSelectRoute: (next) => {
      navigateRoute(next);
      setPalette("closed");
    },
    onSelectChild: (parent, childId) => {
      navigateRoute(parent, childId);
      setPalette("closed");
    },
    onToggleTheme: () => {
      setTheme((prev) => (prev === "dark" ? "light" : "dark"));
      setPalette("closed");
    },
    onShowTokenBar: () => {
      setTokenBar({ kind: "editing", input: getApiToken() });
      setPalette("closed");
    },
    onInspectDevice: (dev) => {
      setSearchQuery(dev.hostname);
      void navigate({
        to: "/inventory/$section",
        params: { section: "endpoints" },
        search: { device: dev.id },
      });
      setPalette("closed");
    },
  });

  const loadPhase = errorMessage
    ? ({ kind: "error", message: errorMessage } as const)
    : isLoading
      ? ({ kind: "loading" } as const)
      : ({ kind: "ready" } as const);

  return (
    <ConsoleWorkspaceContext.Provider
      value={{
        snapshot,
        loadPhase,
        streamState,
        invalidateAll,
        theme,
        onToggleTheme: () =>
          setTheme((prev) => (prev === "dark" ? "light" : "dark")),
        searchQuery,
        onSearchQueryChange: setSearchQuery,
        prefill,
        onClearPrefill: () => setPrefill({ kind: "none" }),
        onCreateRuleFromAttempt: handleCreateRuleFromAttempt,
        onOpenEntity: handleOpenEntity,
        onOpenSessionTurn: handleOpenSessionTurn,
        onNavigateRoute: navigateRoute,
        onUpdateSearch: updateSearch,
        onDecideApproval: handleDecideApproval,
        onStreamVersionBump: () => setStreamVersion((v) => v + 1),
      }}
    >
      <GrdrThemeProvider mode={theme}>
        <div className={sidebarDisplay === "collapsed" ? "shell collapsed" : "shell"}>
          <SidebarNav
            route={route}
            activeChildId={activeChildId}
            collapsed={sidebarDisplay === "collapsed"}
            onToggleCollapse={() =>
              setSidebarDisplay((prev) =>
                prev === "collapsed" ? "expanded" : "collapsed",
              )
            }
            onSelectRoute={(next) => navigateRoute(next)}
            onSelectChild={(parent, childId) => navigateRoute(parent, childId)}
            pendingApprovals={pendingApprovals}
            streamDisconnected={streamState.kind === "reconnecting"}
            deviceCount={devices.length}
            sessionCount={sessions.length}
          />

          <div className={route === "home" ? "workspace workspace-home" : "workspace"}>
            {route === "home" && <HeroWaveBackdrop theme={theme} />}
            <header className="topbar">
              <button
                type="button"
                className="search-trigger"
                onClick={() => setPalette("open")}
                aria-label="Open command search"
              >
                <span className="nav-item-label">
                  <GrdrIcon name="search" size={14} color="var(--ink-muted)" />
                  <span>{searchQuery || "Jump to device, rule, or route..."}</span>
                </span>
                <span className="search-kbd">
                  <Kbd keys="mod+k" />
                </span>
              </button>

              <div className="topbar-actions">
                <Button
                  label="Sync"
                  variant="secondary"
                  size="sm"
                  icon={<GrdrIcon name="refresh" size={14} />}
                  onClick={() => void invalidateAll()}
                />
                <Button
                  label={theme === "dark" ? "Light" : "Dark"}
                  variant="secondary"
                  size="sm"
                  icon={<GrdrIcon name={theme === "dark" ? "sun" : "moon"} size={14} />}
                  aria-label="Toggle color theme"
                  onClick={() =>
                    setTheme((prev) => (prev === "dark" ? "light" : "dark"))
                  }
                />
              </div>
            </header>

            {tokenBar.kind === "editing" && (
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  setApiToken(tokenBar.input);
                  setTokenBar({ kind: "hidden" });
                  setStreamVersion((v) => v + 1);
                }}
              >
                <UiSdkInlineBar>
                  <div style={{ flex: 1, maxWidth: 380 }} data-agent-secret="true">
                    <TextInput
                      label="Operator bearer token"
                      isLabelHidden
                      type="password"
                      placeholder="Paste --api-token value"
                      value={tokenBar.input}
                      onChange={(val) =>
                        setTokenBar({ kind: "editing", input: val })
                      }
                      width="100%"
                    />
                  </div>
                  <Button type="submit" variant="primary" size="sm" label="Save token" />
                  <Button
                    size="sm"
                    label="Clear"
                    onClick={() => {
                      setApiToken("");
                      setTokenBar({ kind: "hidden" });
                      setStreamVersion((v) => v + 1);
                    }}
                  />
                </UiSdkInlineBar>
              </form>
            )}

            <main className="main-scroll">
              <Breadcrumbs items={breadcrumbs} />
              {loadPhase.kind === "error" && (
                <Banner
                  status="error"
                  title={`API unreachable: ${loadPhase.message}`}
                  collapsible={false}
                  role="alert"
                  endContent={
                    <Button
                      size="sm"
                      label="Retry"
                      onClick={() => void invalidateAll()}
                    />
                  }
                />
              )}

              <Outlet />
            </main>
          </div>
        </div>

        <Dialog
          isOpen={palette === "open"}
          onOpenChange={(open) => setPalette(open ? "open" : "closed")}
          purpose="info"
          width={560}
          padding={2}
          aria-label="Command palette"
        >
          <div style={{ padding: "var(--space-1)" }}>
            <TextInput
              label="Filter commands"
              isLabelHidden
              placeholder="Type a screen, device hostname, or action..."
              startIcon={<GrdrIcon name="search" size={14} color="var(--ink-muted)" />}
              value={searchQuery}
              onChange={(val) => setSearchQuery(val)}
              width="100%"
            />
          </div>
          <div className="command-list">
            {commandActions.map((cmd) => (
              <button key={cmd.id} type="button" className="command-item" onClick={cmd.run}>
                <span>{cmd.label}</span>
                <HStack gap={1} align="center">
                  <Badge variant="neutral" label={cmd.hint} />
                </HStack>
              </button>
            ))}
          </div>
        </Dialog>
      </GrdrThemeProvider>
    </ConsoleWorkspaceContext.Provider>
  );
}
