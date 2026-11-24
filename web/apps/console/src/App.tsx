import "./styles.css";

import { useCallback, useEffect, useState } from "react";
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
  type PolicyPack,
  type SessionSummary,
} from "@grdr/api";
import { CONSOLE_ROUTES, pluralize, t } from "@grdr/i18n";
import { type EntityTarget } from "@grdr/kit";
import {
  Badge,
  Banner,
  Button,
  Dialog,
  GrdrIcon,
  GrdrThemeProvider,
  GuardrailsMark,
  HStack,
  IconButton,
  Kbd,
  TextInput,
  UiSdkInlineBar,
  iconKeyToName,
  useUiSdkReadOnlyAgentBridge,
  type GrdrThemeMode,
} from "@grdr/ui";
import { CoveragePage } from "./pages/CoveragePage";
import { HomePage } from "./pages/HomePage";
import { InventoryPage } from "./pages/InventoryPage";
import { ProtectPage } from "./pages/ProtectPage";
import { RespondPage } from "./pages/RespondPage";
import { SessionsPage } from "./pages/SessionsPage";
import { TesterPage } from "./pages/TesterPage";

export function App() {
  useUiSdkReadOnlyAgentBridge();

  const [route, setRoute] = useState<NavRoute>("home");
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
  const [devices, setDevices] = useState<Device[]>([]);
  const [sessions, setSessions] = useState<SessionSummary[]>([]);
  const [packs, setPacks] = useState<PolicyPack[]>([]);
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [killSwitch, setKillSwitch] = useState<KillSwitchState>({ state: "inactive" });
  const [prefillAttempt, setPrefillAttempt] = useState<ActionAttempt | null>(null);
  const [focusedEntity, setFocusedEntity] = useState<EntityTarget | null>(null);
  const [returnRoute, setReturnRoute] = useState<{ route: NavRoute; label: string } | null>(null);

  function handleOpenEntity(target: EntityTarget) {
    let dest: NavRoute = route;
    switch (target.kind) {
      case "device":
      case "agent":
      case "mcp":
        dest = "inventory";
        break;
      case "session":
        dest = "sessions";
        break;
      case "rule":
        dest = "protect";
        break;
    }
    if (dest !== route) {
      const originMeta = CONSOLE_ROUTES.find((r) => r.id === route);
      setReturnRoute({
        route,
        label: originMeta ? t(originMeta.labelKey) : route,
      });
    }
    setFocusedEntity(target);
    setRoute(dest);
  }

  const loadAll = useCallback(async () => {
    try {
      const [ov, dev, sess, pk, apr, fnd, inc, ks] = await Promise.all([
        api.getOverview(),
        api.getDevices(),
        api.getSessions(),
        api.getPacks(),
        api.getApprovals(),
        api.getFindings(),
        api.getIncidents(),
        api.getKillSwitch(),
      ]);
      setOverview(ov);
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

  useEffect(() => {
    void loadAll();
    const token = getApiToken();
    const liveUrl = token
      ? `/api/v1/live?access_token=${encodeURIComponent(token)}`
      : "/api/v1/live";
    const events = new EventSource(liveUrl);
    const refreshHandler = () => {
      void loadAll();
    };
    events.onopen = () => setStreamDisconnected(false);
    events.onerror = () => setStreamDisconnected(true);
    events.addEventListener("session.verdict", refreshHandler);
    events.addEventListener("approval.decided", refreshHandler);
    events.addEventListener("policy.changed", refreshHandler);
    events.addEventListener("inventory.device", refreshHandler);
    events.addEventListener("uplink.batch", refreshHandler);
    events.addEventListener("finding.updated", refreshHandler);
    events.addEventListener("kill_switch.updated", refreshHandler);

    return () => {
      events.close();
    };
  }, [loadAll, streamVersion]);

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

  const pendingApprovals = approvals.filter((a) => a.state.status === "pending").length;
  const queryNorm = searchQuery.trim().toLowerCase();

  const commandActions = [
    ...CONSOLE_ROUTES.map((item) => ({
      id: `route-${item.id}`,
      label: `Go to ${t(item.labelKey)}`,
      hint: "Route",
      run: () => {
        setRoute(item.id);
        setPaletteOpen(false);
      },
    })),
    {
      id: "toggle-theme",
      label: theme === "light" ? "Switch to Nocturne Dark theme" : "Switch to Paper Light theme",
      hint: "Appearance",
      run: () => {
        setTheme((prev) => (prev === "dark" ? "light" : "dark"));
        setPaletteOpen(false);
      },
    },
    {
      id: "connect-api-token",
      label: getApiToken() ? "Update local API bearer token" : "Connect local API bearer token",
      hint: "Connection",
      run: () => {
        setShowTokenBar(true);
        setPaletteOpen(false);
      },
    },
    ...devices.map((dev) => ({
      id: `dev-${dev.id}`,
      label: `Inspect device ${dev.hostname}`,
      hint: `${dev.os}/${dev.arch}`,
      run: () => {
        setSearchQuery(dev.hostname);
        setRoute("inventory");
        setPaletteOpen(false);
      },
    })),
  ].filter((cmd) => !queryNorm || cmd.label.toLowerCase().includes(queryNorm));

  return (
    <GrdrThemeProvider mode={theme}>
      <div className={sidebarCollapsed ? "shell collapsed" : "shell"}>
        <aside className={sidebarCollapsed ? "rail collapsed" : "rail"} aria-label="Primary navigation">
          <div className="brand-header">
            <div className="brand-mark">
              <div className="brand-glyph">
                <GuardrailsMark size={18} />
              </div>
              {!sidebarCollapsed && (
                <div className="brand-title">
                  <strong>{t("grdr.brand.name")}</strong>
                  <span>{t("grdr.brand.subtitle")}</span>
                </div>
              )}
            </div>
            <span className="rail-collapse-btn">
              <IconButton
                label={sidebarCollapsed ? "Expand navigation" : "Collapse navigation"}
                icon={<GrdrIcon name={sidebarCollapsed ? "panel-left-open" : "panel-left-close"} size={15} />}
                variant="ghost"
                size="sm"
                onClick={() => setSidebarCollapsed((c) => !c)}
              />
            </span>
          </div>

          <nav className="rail-nav">
            {CONSOLE_ROUTES.map((item) => (
              <button
                key={item.id}
                type="button"
                title={t(item.labelKey)}
                aria-label={t(item.labelKey)}
                className={`nav-item ${route === item.id ? "active" : ""}`}
                onClick={() => {
                  setReturnRoute(null);
                  setRoute(item.id);
                }}
              >
                <span className="nav-item-label">
                  <GrdrIcon name={iconKeyToName(item.iconKey)} size={16} />
                  {!sidebarCollapsed && <span>{t(item.labelKey)}</span>}
                </span>
                {!sidebarCollapsed && item.id === "respond" && pendingApprovals > 0 && (
                  <Badge variant="warning" label={pendingApprovals} />
                )}
              </button>
            ))}
          </nav>

          {!sidebarCollapsed && (
            <div className="rail-footer">
              {streamDisconnected && (
                <div style={{ color: "var(--tone-ask)" }}>{t("console.stream.reconnecting")}</div>
              )}
              <div className="tabular">
                {`${pluralize(devices.length, "endpoint")}, ${pluralize(sessions.length, "session")}`}
              </div>
            </div>
          )}
        </aside>

        <div className="workspace">
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
                onClick={() => void loadAll()}
              />
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
            {returnRoute && (
              <div style={{ marginBottom: 12 }}>
                <Button
                  size="sm"
                  variant="ghost"
                  icon={<GrdrIcon name="arrow-left" size={13} />}
                  label={`Back to ${returnRoute.label}`}
                  onClick={() => {
                    const prev = returnRoute.route;
                    setReturnRoute(null);
                    setFocusedEntity(null);
                    setRoute(prev);
                  }}
                />
              </div>
            )}
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
            {route === "inventory" && (
              <InventoryPage
                devices={devices}
                searchQuery={searchQuery}
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
                focusedEntity={focusedEntity}
                onClearFocus={() => setFocusedEntity(null)}
                onOpenEntity={handleOpenEntity}
                onCreateRuleFromAttempt={(attempt) => {
                  setPrefillAttempt(attempt);
                  setRoute("protect");
                }}
              />
            )}
            {route === "protect" && (
              <ProtectPage
                packs={packs}
                devices={devices}
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
                onUpdated={() => void loadAll()}
              />
            )}
            {route === "coverage" && (
              <CoveragePage devices={devices} onOpenEntity={handleOpenEntity} />
            )}
            {route === "tester" && (
              <TesterPage
                onEvaluated={() => void loadAll()}
                onOpenEntity={handleOpenEntity}
              />
            )}
          </main>
        </div>
      </div>

      <Dialog
        isOpen={paletteOpen}
        onOpenChange={setPaletteOpen}
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
            <button
              key={cmd.id}
              type="button"
              className="command-item"
              onClick={cmd.run}
            >
              <span>{cmd.label}</span>
              <HStack gap={1} align="center">
                <Badge variant="neutral" label={cmd.hint} />
              </HStack>
            </button>
          ))}
        </div>
      </Dialog>
    </GrdrThemeProvider>
  );
}

export default App;
