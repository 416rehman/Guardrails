import "./styles.css";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  api,
  getApiToken,
  setApiToken,
  type ActionAttempt,
  type ApprovalRequest,
  type Device,
  type Finding,
  type GrantScope,
  type Incident,
  type KillSwitchState,
  type NavRoute,
  type OverviewResponse,
  type OrgPrivacyConfig,
  type PolicyPack,
  type SessionSummary,
  type UserProfile,
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
  const [selectedDeviceId, setSelectedDeviceId] = useState<string | null>(null);
  const [sessionsView, setSessionsView] = useState<SessionViewMode>("graph");
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null);
  const [protectSection, setProtectSection] = useState<ProtectSectionId>("rules");
  const [theme, setTheme] = useState<GrdrThemeMode>("light");
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [streamDisconnected, setStreamDisconnected] = useState(false);
  const [loadingError, setLoadingError] = useState<string | null>(null);
  const [showTokenBar, setShowTokenBar] = useState(false);
  const [apiTokenInput, setApiTokenInput] = useState(() => getApiToken());
  const [streamVersion, setStreamVersion] = useState(0);
  const [overview, setOverview] = useState<OverviewResponse | null>(null);
  const [users, setUsers] = useState<UserProfile[]>([]);
  const [privacyConfig, setPrivacyConfig] = useState<OrgPrivacyConfig>({
    identity_mode: "named",
    user_risk_scoring: true,
  });
  const [devices, setDevices] = useState<Device[]>([]);
  const [sessions, setSessions] = useState<SessionSummary[]>([]);
  const [packs, setPacks] = useState<PolicyPack[]>([]);
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [killSwitch, setKillSwitch] = useState<KillSwitchState>({ state: "inactive" });
  const [prefillAttempt, setPrefillAttempt] = useState<ActionAttempt | null>(null);
  const [focusedEntity, setFocusedEntity] = useState<EntityTarget | null>(null);
  const [focusedTurn, setFocusedTurn] = useState<number | null>(null);

  const handleOpenEntity = useCallback((target: EntityTarget) => {
    setFocusedEntity(target);
    switch (target.kind) {
      case "user":
        setRoute("users");
        break;
      case "device":
        setInventorySection("endpoints");
        setRoute("inventory");
        break;
      case "agent":
        setSelectedDeviceId(null);
        setInventorySection("agents");
        setRoute("inventory");
        break;
      case "mcp":
        setSelectedDeviceId(null);
        setInventorySection("mcps");
        setRoute("inventory");
        break;
      case "artifact":
        setSelectedDeviceId(null);
        setInventorySection("skills");
        setRoute("inventory");
        break;
      case "session":
        setSelectedSessionId(target.id);
        setRoute("sessions");
        break;
      case "rule":
        setProtectSection("rules");
        setRoute("protect");
        break;
    }
  }, []);

  const handleOpenSessionTurn = useCallback((sessionId: string, turnIndex: number) => {
    setFocusedEntity({ kind: "session", id: sessionId, label: sessionId });
    setSelectedSessionId(sessionId);
    setSessionsView("trace");
    setFocusedTurn(turnIndex);
    setRoute("sessions");
  }, []);

  const loadAll = useCallback(async () => {
    try {
      const [ov, usr, prv, dev, sess, pk, apr, fnd, inc, ks] = await Promise.all([
        api.getOverview(),
        api.getUsers(),
        api.getPrivacyConfig(),
        api.getDevices(),
        api.getSessions(),
        api.getPacks(),
        api.getApprovals(),
        api.getFindings(),
        api.getIncidents(),
        api.getKillSwitch(),
      ]);
      setOverview(ov);
      setUsers(usr);
      setPrivacyConfig(prv);
      setDevices(dev);
      setSessions(sess);
      setPacks(pk);
      setApprovals(apr);
      setFindings(fnd);
      setIncidents(inc);
      setKillSwitch(ks);
      setLoadingError(null);
    } catch (err) {
      setLoadingError((err as Error).message);
    }
  }, []);

  useConsoleStream(streamVersion, loadAll, setStreamDisconnected);

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((prev) => !prev);
      } else if (e.key === "Escape") {
        setPaletteOpen(false);
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
      setSelectedDeviceId(null);
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
          setSelectedDeviceId(null);
          setFocusedEntity(null);
          setRoute("home");
        },
        onSelectInventorySection: (sec) => {
          setInventorySection(sec);
          setRoute("inventory");
        },
        onClearDevice: () => setSelectedDeviceId(null),
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
      setPaletteOpen(false);
    },
    onSelectChild: (parent, childId) => {
      handleSelectChild(parent, childId);
      setPaletteOpen(false);
    },
    onToggleTheme: () => {
      setTheme((prev) => (prev === "dark" ? "light" : "dark"));
      setPaletteOpen(false);
    },
    onShowTokenBar: () => {
      setShowTokenBar(true);
      setPaletteOpen(false);
    },
    onInspectDevice: (dev) => {
      setSearchQuery(dev.hostname);
      setInventorySection("endpoints");
      setSelectedDeviceId(dev.id);
      setRoute("inventory");
      setPaletteOpen(false);
    },
  });

  return (
    <GrdrThemeProvider mode={theme}>
      <div className={sidebarCollapsed ? "shell collapsed" : "shell"}>
        <SidebarNav
          route={route}
          activeChildId={activeChildId}
          collapsed={sidebarCollapsed}
          onToggleCollapse={() => setSidebarCollapsed((c) => !c)}
          onSelectRoute={(next) => {
            if (next === "inventory") setSelectedDeviceId(null);
            setRoute(next);
          }}
          onSelectChild={handleSelectChild}
          pendingApprovals={pendingApprovals}
          streamDisconnected={streamDisconnected}
          deviceCount={devices.length}
          sessionCount={sessions.length}
        />

        <div className={route === "home" ? "workspace workspace-home" : "workspace"}>
          {route === "home" && <HeroWaveBackdrop theme={theme} />}
          <header className="topbar">
            <button
              type="button"
              className="search-trigger"
              onClick={() => setPaletteOpen(true)}
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

          {showTokenBar && (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                setApiToken(apiTokenInput);
                setShowTokenBar(false);
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
                    value={apiTokenInput}
                    onChange={(val) => setApiTokenInput(val)}
                    width="100%"
                  />
                </div>
                <Button type="submit" variant="primary" size="sm" label="Save token" />
                <Button
                  size="sm"
                  label="Clear"
                  onClick={() => {
                    setApiTokenInput("");
                    setApiToken("");
                    setShowTokenBar(false);
                    setStreamVersion((v) => v + 1);
                  }}
                />
              </UiSdkInlineBar>
            </form>
          )}

          <main className="main-scroll">
            <Breadcrumbs items={breadcrumbs} />
            {loadingError && (
              <Banner
                status="error"
                title={`API unreachable: ${loadingError}`}
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
                onClearFocus={() => setFocusedEntity(null)}
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
                onSelectDevice={setSelectedDeviceId}
                focusedEntity={focusedEntity}
                onClearFocus={() => setFocusedEntity(null)}
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
                onSelectSessionId={setSelectedSessionId}
                focusedEntity={focusedEntity}
                focusedTurn={focusedTurn}
                onClearFocus={() => setFocusedEntity(null)}
                onClearFocusedTurn={() => setFocusedTurn(null)}
                onOpenEntity={handleOpenEntity}
                onCreateRuleFromAttempt={(attempt) => {
                  setPrefillAttempt(attempt);
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
                onClearPrefill={() => setPrefillAttempt(null)}
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

      <Dialog isOpen={paletteOpen} onOpenChange={setPaletteOpen} purpose="info" width={560} padding={2} aria-label="Command palette">
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
