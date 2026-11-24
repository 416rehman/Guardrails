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
  type Incident,
  type KillSwitchState,
  type NavRoute,
  type OverviewResponse,
  type PolicyPack,
  type SessionSummary,
} from "@grdr/api";
import { CONSOLE_ROUTES, t } from "@grdr/i18n";
import {
  Badge,
  Banner,
  Button,
  GrdrIcon,
  GrdrThemeProvider,
  HStack,
  TextInput,
  UiSdkInlineBar,
  iconKeyToName,
  useUiSdkReadOnlyAgentBridge,
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
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const [searchQuery, setSearchQuery] = useState("");
  const [liveConnected, setLiveConnected] = useState(false);
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
    events.onopen = () => setLiveConnected(true);
    events.onerror = () => setLiveConnected(false);
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

  const pendingApprovals = approvals.filter((a) => a.state.status === "pending").length;

  return (
    <GrdrThemeProvider mode={theme}>
      <div className="shell">
        <aside className="rail" aria-label="Primary navigation">
          <div className="brand-mark">
            <div className="brand-glyph">
              <GrdrIcon name="shield" size={18} />
            </div>
            <div className="brand-title">
              <strong>{t("grdr.brand.name")}</strong>
              <span>{t("grdr.brand.subtitle")}</span>
            </div>
          </div>

          <nav className="rail-nav">
            {CONSOLE_ROUTES.map((item) => (
              <button
                key={item.id}
                type="button"
                className={`nav-item ${route === item.id ? "active" : ""}`}
                onClick={() => setRoute(item.id)}
              >
                <span className="nav-item-label">
                  <GrdrIcon name={iconKeyToName(item.iconKey)} size={16} />
                  <span>{t(item.labelKey)}</span>
                </span>
                {item.id === "respond" && pendingApprovals > 0 && (
                  <Badge variant="warning" label={pendingApprovals} />
                )}
              </button>
            ))}
          </nav>

          <div className="rail-footer">
            <HStack gap={1} align="center">
              <GrdrIcon
                name="radio"
                size={13}
                color={liveConnected ? "var(--tone-allow)" : "var(--ink-muted)"}
              />
              <span>{liveConnected ? t("console.stream.connected") : t("console.stream.reconnecting")}</span>
            </HStack>
            <div className="tabular">
              {devices.length} endpoint(s) · {sessions.length} session(s)
            </div>
          </div>
        </aside>

        <div className="workspace">
          <header className="topbar">
            <div style={{ flex: 1, maxWidth: 420 }}>
              <TextInput
                label="Filter devices, agents, sessions"
                isLabelHidden
                type="search"
                placeholder="Filter devices, agents, sessions..."
                startIcon={<GrdrIcon name="search" size={14} color="var(--ink-muted)" />}
                value={searchQuery}
                onChange={(val) => setSearchQuery(val)}
                width="100%"
              />
            </div>

            <div className="topbar-actions">
              <Button
                label={getApiToken() ? "Token active" : "API token"}
                icon={<GrdrIcon name="key-round" size={14} />}
                onClick={() => setShowTokenBar((prev) => !prev)}
              />
              <Button
                label="Sync"
                icon={<GrdrIcon name="refresh" size={14} />}
                onClick={() => void loadAll()}
              />
              <Button
                label={theme === "dark" ? "Light" : "Dark"}
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
                approvals={approvals}
                findings={findings}
                onNavigate={setRoute}
              />
            )}
            {route === "inventory" && (
              <InventoryPage
                devices={devices}
                searchQuery={searchQuery}
                onRefresh={() => void loadAll()}
              />
            )}
            {route === "sessions" && (
              <SessionsPage
                sessions={sessions}
                searchQuery={searchQuery}
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
                onClearPrefill={() => setPrefillAttempt(null)}
                onUpdated={() => void loadAll()}
              />
            )}
            {route === "respond" && (
              <RespondPage
                approvals={approvals}
                findings={findings}
                incidents={incidents}
                killSwitch={killSwitch}
                defaultSessionId={sessions[0]?.id ?? "sess-demo-refactor"}
                onUpdated={() => void loadAll()}
              />
            )}
            {route === "coverage" && <CoveragePage devices={devices} />}
            {route === "tester" && <TesterPage onEvaluated={() => void loadAll()} />}
          </main>
        </div>
      </div>
    </GrdrThemeProvider>
  );
}

export default App;
