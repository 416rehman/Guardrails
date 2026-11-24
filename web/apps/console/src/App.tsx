import "./styles.css";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  api,
  getApiToken,
  setApiToken,
  type GrantScope,
  type NavRoute,
} from "@grdr/api";
import type { InventorySectionId, ProtectSectionId } from "@grdr/i18n";
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
  EMPTY_CONSOLE_SNAPSHOT,
  fetchConsoleSnapshot,
  type ConsoleSnapshot,
  type DevicePick,
  type FocusTarget,
  type LoadState,
  type PaletteState,
  type PrefillDraft,
  type SessionPick,
  type SidebarDisplay,
  type StreamState,
  type TokenBarState,
} from "./consoleState";
import { CoveragePage } from "./pages/CoveragePage";
import { HomePage } from "./pages/HomePage";
import { InventoryPage } from "./pages/InventoryPage";
import { ProtectPage } from "./pages/ProtectPage";
import { RespondPage } from "./pages/RespondPage";
import { SessionsPage, type SessionViewMode } from "./pages/SessionsPage";
import { TesterPage } from "./pages/TesterPage";
import { UsersPage } from "./pages/UsersPage";

export function App() {
  useUiSdkReadOnlyAgentBridge();

  const [route, setRoute] = useState<NavRoute>("home");
  const [inventorySection, setInventorySection] = useState<InventorySectionId>("endpoints");
  const [devicePick, setDevicePick] = useState<DevicePick>({ kind: "none" });
  const [sessionsView, setSessionsView] = useState<SessionViewMode>("graph");
  const [sessionPick, setSessionPick] = useState<SessionPick>({ kind: "auto" });
  const [protectSection, setProtectSection] = useState<ProtectSectionId>("rules");
  const [theme, setTheme] = useState<GrdrThemeMode>("light");
  const [sidebarDisplay, setSidebarDisplay] = useState<SidebarDisplay>("expanded");
  const [searchQuery, setSearchQuery] = useState("");
  const [palette, setPalette] = useState<PaletteState>("closed");
  const [streamState, setStreamState] = useState<StreamState>({ kind: "connected" });
  const [loadState, setLoadState] = useState<LoadState<ConsoleSnapshot>>({ kind: "loading" });
  const [tokenBar, setTokenBar] = useState<TokenBarState>({ kind: "hidden" });
  const [streamVersion, setStreamVersion] = useState(0);
  const [prefill, setPrefill] = useState<PrefillDraft>({ kind: "none" });
  const [focus, setFocus] = useState<FocusTarget>({ kind: "none" });

  const snapshot =
    loadState.kind === "ready"
      ? loadState.data
      : loadState.kind === "error" && loadState.staleData
        ? loadState.staleData
        : EMPTY_CONSOLE_SNAPSHOT;
  const {
    overview,
    users,
    privacyConfig,
    devices,
    sessions,
    packs,
    approvals,
    findings,
    incidents,
    killSwitch,
  } = snapshot;
  const selectedDeviceId = devicePick.kind === "selected" ? devicePick.deviceId : null;
  const selectedSessionId = sessionPick.kind === "selected" ? sessionPick.sessionId : null;
  const focusedEntity = focus.kind === "none" ? null : focus.target;
  const focusedTurn = focus.kind === "sessionTurn" ? focus.turnIndex : null;
  const prefillAttempt = prefill.kind === "fromAttempt" ? prefill.attempt : null;

  const handleOpenEntity = useCallback((target: EntityTarget) => {
    setFocus({ kind: "entity", target });
    switch (target.kind) {
      case "user":
        setRoute("users");
        break;
      case "device":
        setInventorySection("endpoints");
        setRoute("inventory");
        break;
      case "agent":
        setDevicePick({ kind: "none" });
        setInventorySection("agents");
        setRoute("inventory");
        break;
      case "mcp":
        setDevicePick({ kind: "none" });
        setInventorySection("mcps");
        setRoute("inventory");
        break;
      case "artifact":
        setDevicePick({ kind: "none" });
        setInventorySection("skills");
        setRoute("inventory");
        break;
      case "session":
        setSessionPick({ kind: "selected", sessionId: target.id });
        setRoute("sessions");
        break;
      case "rule":
        setProtectSection("rules");
        setRoute("protect");
        break;
    }
  }, []);

  const handleOpenSessionTurn = useCallback((sessionId: string, turnIndex: number) => {
    setFocus({
      kind: "sessionTurn",
      target: { kind: "session", id: sessionId, label: sessionId },
      turnIndex,
    });
    setSessionPick({ kind: "selected", sessionId });
    setSessionsView("trace");
    setRoute("sessions");
  }, []);

  const loadAll = useCallback(async () => {
    try {
      const data = await fetchConsoleSnapshot();
      setLoadState({ kind: "ready", data });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed loading console state";
      setLoadState((prev) => ({
        kind: "error",
        message,
        staleData: prev.kind === "ready" ? prev.data : prev.kind === "error" ? prev.staleData : undefined,
      }));
    }
  }, []);

  const handleDisconnectedChange = useCallback((disconnected: boolean) => {
    setStreamState(disconnected ? { kind: "reconnecting" } : { kind: "connected" });
  }, []);

  useConsoleStream(streamVersion, loadAll, handleDisconnectedChange);

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

  async function handleDecideApproval(id: string, approve: boolean, scope: GrantScope) {
    await api.decideApproval(
      id,
      approve,
      scope,
      approve ? `Approved (${scope}) from Console Home` : "Denied from Console Home",
    );
    await loadAll();
  }

  function handleSelectChild(parent: NavRoute, childId: string) {
    if (parent === "inventory") {
      setDevicePick({ kind: "none" });
      setInventorySection(childId as InventorySectionId);
    } else if (parent === "sessions") {
      setSessionsView(childId as SessionViewMode);
    } else if (parent === "protect") {
      setProtectSection(childId as ProtectSectionId);
    }
    setRoute(parent);
  }

  const pendingApprovals = approvals.filter((a) => a.state.status === "pending").length;
  const selectedDevice = useMemo(
    () => devices.find((d) => d.id === selectedDeviceId) ?? null,
    [devices, selectedDeviceId],
  );
  const activeSessionId = selectedSessionId ?? sessions[0]?.id ?? null;

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
        sessionsView,
        activeSessionId,
        protectSection,
        onGoHome: () => {
          setDevicePick({ kind: "none" });
          setFocus({ kind: "none" });
          setRoute("home");
        },
        onSelectInventorySection: (sec) => {
          setInventorySection(sec);
          setRoute("inventory");
        },
        onClearDevice: () => setDevicePick({ kind: "none" }),
        onSelectSessionsView: (view) => {
          setSessionsView(view);
          setRoute("sessions");
        },
        onSelectProtectSection: (sec) => {
          setProtectSection(sec);
          setRoute("protect");
        },
      }),
    [route, inventorySection, selectedDevice, sessionsView, activeSessionId, protectSection],
  );

  const commandActions = buildCommandActions({
    devices,
    theme,
    hasToken: Boolean(getApiToken()),
    query: searchQuery,
    onSelectRoute: (next) => {
      setRoute(next);
      setPalette("closed");
    },
    onSelectChild: (parent, childId) => {
      handleSelectChild(parent, childId);
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
      setInventorySection("endpoints");
      setDevicePick({ kind: "selected", deviceId: dev.id });
      setRoute("inventory");
      setPalette("closed");
    },
  });

  return (
    <GrdrThemeProvider mode={theme}>
      <div className={sidebarDisplay === "collapsed" ? "shell collapsed" : "shell"}>
        <SidebarNav
          route={route}
          activeChildId={activeChildId}
          collapsed={sidebarDisplay === "collapsed"}
          onToggleCollapse={() =>
            setSidebarDisplay((prev) => (prev === "collapsed" ? "expanded" : "collapsed"))
          }
          onSelectRoute={(next) => {
            if (next === "inventory") setDevicePick({ kind: "none" });
            setRoute(next);
          }}
          onSelectChild={handleSelectChild}
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
              <span className="search-kbd"><Kbd keys="mod+k" /></span>
            </button>

            <div className="topbar-actions">
              <Button label="Sync" variant="secondary" size="sm" icon={<GrdrIcon name="refresh" size={14} />} onClick={() => void loadAll()} />
              <Button
                label={theme === "dark" ? "Light" : "Dark"}
                variant="secondary"
                size="sm"
                icon={<GrdrIcon name={theme === "dark" ? "sun" : "moon"} size={14} />}
                aria-label="Toggle color theme"
                onClick={() => setTheme((prev) => (prev === "dark" ? "light" : "dark"))}
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
                    onChange={(val) => setTokenBar({ kind: "editing", input: val })}
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
            {loadState.kind === "error" && (
              <Banner
                status="error"
                title={`API unreachable: ${loadState.message}`}
                collapsible={false}
                role="alert"
                endContent={<Button size="sm" label="Retry" onClick={() => void loadAll()} />}
              />
            )}

            {route === "home" && (
              <HomePage
                overview={overview}
                devices={devices}
                packs={packs}
                approvals={approvals}
                findings={findings}
                onNavigate={setRoute}
                onOpenEntity={handleOpenEntity}
                onDecideApproval={handleDecideApproval}
              />
            )}
            {route === "users" && (
              <UsersPage
                users={users}
                privacyConfig={privacyConfig}
                searchQuery={searchQuery}
                focusedEntity={focusedEntity}
                onClearFocus={() => setFocus({ kind: "none" })}
                onOpenEntity={handleOpenEntity}
                onOpenSessionTurn={handleOpenSessionTurn}
                onPrivacyUpdated={() => void loadAll()}
              />
            )}
            {route === "inventory" && (
              <InventoryPage
                devices={devices}
                searchQuery={searchQuery}
                section={inventorySection}
                onSectionChange={setInventorySection}
                selectedDeviceId={selectedDeviceId}
                onSelectDevice={(id) => setDevicePick(id ? { kind: "selected", deviceId: id } : { kind: "none" })}
                focusedEntity={focusedEntity}
                onClearFocus={() => setFocus({ kind: "none" })}
                onOpenEntity={handleOpenEntity}
                onRefresh={() => void loadAll()}
              />
            )}
            {route === "sessions" && (
              <SessionsPage
                sessions={sessions}
                devices={devices}
                searchQuery={searchQuery}
                section={sessionsView}
                onSectionChange={setSessionsView}
                selectedSessionId={selectedSessionId}
                onSelectSessionId={(id) =>
                  setSessionPick(id ? { kind: "selected", sessionId: id } : { kind: "auto" })
                }
                focusedEntity={focusedEntity}
                focusedTurn={focusedTurn}
                onClearFocus={() => setFocus({ kind: "none" })}
                onClearFocusedTurn={() =>
                  setFocus((prev) =>
                    prev.kind === "sessionTurn" ? { kind: "entity", target: prev.target } : prev,
                  )
                }
                onOpenEntity={handleOpenEntity}
                onCreateRuleFromAttempt={(attempt) => {
                  setPrefill({ kind: "fromAttempt", attempt });
                  setProtectSection("rules");
                  setRoute("protect");
                }}
              />
            )}
            {route === "protect" && (
              <ProtectPage
                packs={packs}
                devices={devices}
                section={protectSection}
                onSectionChange={setProtectSection}
                prefillAttempt={prefillAttempt}
                focusedEntity={focusedEntity}
                onClearPrefill={() => setPrefill({ kind: "none" })}
                onOpenEntity={handleOpenEntity}
                onUpdated={() => void loadAll()}
              />
            )}
            {route === "respond" && (
              <RespondPage
                approvals={approvals}
                findings={findings}
                incidents={incidents}
                devices={devices}
                killSwitch={killSwitch}
                defaultSessionId={sessions[0]?.id ?? "sess-demo-refactor"}
                onOpenEntity={handleOpenEntity}
                onOpenSessionTurn={handleOpenSessionTurn}
                onUpdated={() => void loadAll()}
              />
            )}
            {route === "coverage" && <CoveragePage devices={devices} onOpenEntity={handleOpenEntity} />}
            {route === "tester" && <TesterPage onEvaluated={() => void loadAll()} onOpenEntity={handleOpenEntity} />}
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
              <HStack gap={1} align="center"><Badge variant="neutral" label={cmd.hint} /></HStack>
            </button>
          ))}
        </div>
      </Dialog>
    </GrdrThemeProvider>
  );
}

export default App;
