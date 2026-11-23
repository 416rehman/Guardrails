import { useCallback, useEffect, useState } from "react";
import {
  Activity,
  Cpu,
  Home,
  Moon,
  Radio,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  Sun,
  Terminal,
} from "lucide-react";
import { api } from "./api";
import { HomePage } from "./pages/HomePage";
import { InventoryPage } from "./pages/InventoryPage";
import { ProtectPage } from "./pages/ProtectPage";
import { RespondPage } from "./pages/RespondPage";
import { SessionsPage } from "./pages/SessionsPage";
import { TesterPage } from "./pages/TesterPage";
import type {
  ActionAttempt,
  ApprovalRequest,
  Device,
  Finding,
  Incident,
  KillSwitchState,
  NavRoute,
  OverviewResponse,
  PolicyPack,
  SessionSummary,
} from "./types";

const NAV_ITEMS: Array<{ route: NavRoute; label: string }> = [
  { route: "home", label: "Home" },
  { route: "inventory", label: "Inventory" },
  { route: "sessions", label: "Sessions" },
  { route: "protect", label: "Protect" },
  { route: "respond", label: "Respond" },
  { route: "tester", label: "Live Tester" },
];

export function App() {
  const [route, setRoute] = useState<NavRoute>("home");
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const [searchQuery, setSearchQuery] = useState("");
  const [liveConnected, setLiveConnected] = useState(false);
  const [loadingError, setLoadingError] = useState<string | null>(null);

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
    document.documentElement.setAttribute("data-theme", theme);
  }, [theme]);

  useEffect(() => {
    void loadAll();
    const events = new EventSource("/api/v1/live");
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
  }, [loadAll]);

  const pendingApprovals = approvals.filter((a) => a.state.status === "pending").length;

  function navIcon(r: NavRoute) {
    switch (r) {
      case "home":
        return <Home size={16} />;
      case "inventory":
        return <Cpu size={16} />;
      case "sessions":
        return <Activity size={16} />;
      case "protect":
        return <Shield size={16} />;
      case "respond":
        return <ShieldAlert size={16} />;
      case "tester":
        return <Terminal size={16} />;
    }
  }

  return (
    <div className="shell">
      <aside className="rail" aria-label="Primary navigation">
        <div className="brand-mark">
          <div className="brand-glyph">
            <Shield size={18} />
          </div>
          <div className="brand-title">
            <strong>Guardrails ADR</strong>
            <span>Agent detection & response</span>
          </div>
        </div>

        <nav className="rail-nav">
          {NAV_ITEMS.map((item) => (
            <button
              key={item.route}
              type="button"
              className={`nav-item ${route === item.route ? "active" : ""}`}
              onClick={() => setRoute(item.route)}
            >
              <span className="nav-item-label">
                {navIcon(item.route)}
                <span>{item.label}</span>
              </span>
              {item.route === "respond" && pendingApprovals > 0 && (
                <span className="badge ask tabular">{pendingApprovals}</span>
              )}
            </button>
          ))}
        </nav>

        <div className="rail-footer">
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <Radio size={13} color={liveConnected ? "var(--tone-allow)" : "var(--ink-muted)"} />
            <span>{liveConnected ? "Live stream connected" : "Stream reconnecting"}</span>
          </div>
          <div className="tabular">
            {devices.length} endpoint(s) · {sessions.length} session(s)
          </div>
        </div>
      </aside>

      <div className="workspace">
        <header className="topbar">
          <label className="search-box" aria-label="Filter agents or sessions">
            <Search size={14} color="var(--ink-muted)" />
            <input
              type="search"
              placeholder="Filter devices, agents, sessions..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </label>

          <div className="topbar-actions">
            <button type="button" className="btn" onClick={() => void loadAll()}>
              <RefreshCw size={14} />
              <span>Sync</span>
            </button>
            <button
              type="button"
              className="btn"
              onClick={() => setTheme((prev) => (prev === "dark" ? "light" : "dark"))}
              aria-label="Toggle color theme"
            >
              {theme === "dark" ? <Sun size={14} /> : <Moon size={14} />}
              <span>{theme === "dark" ? "Light" : "Dark"}</span>
            </button>
          </div>
        </header>

        <main className="main-scroll">
          {loadingError && (
            <div className="banner danger" role="alert">
              <span>API unreachable: {loadingError}</span>
              <button type="button" className="btn" onClick={() => void loadAll()}>
                Retry
              </button>
            </div>
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
          {route === "tester" && <TesterPage onEvaluated={() => void loadAll()} />}
        </main>
      </div>
    </div>
  );
}

export default App;
