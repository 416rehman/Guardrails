import { useCallback, useEffect, useState } from "react";
import "@grdr/tokens/tokens.css";
import "./styles.css";
import {
  api,
  formatStorageMode,
  type AuditEntry,
  type HealthResponse,
  type OverviewResponse,
  type TrustedKeyInfo,
} from "@grdr/api";
import { OPERATOR_ROUTES, type OperatorRouteId, pluralize, t } from "@grdr/i18n";

function formatAuditKind(kind: string): string {
  switch (kind) {
    case "policy.pack.loaded":
      return "Policy pack loaded";
    case "policy.update":
      return "Policy updated";
    case "kill_switch.updated":
      return "Kill switch changed";
    default:
      return kind.replace(/\./g, " ");
  }
}
import { ViewStateFrame } from "@grdr/kit";
import {
  Badge,
  Banner,
  Button,
  EmptyState,
  GrdrFlowGraph,
  GrdrIcon,
  GrdrThemeProvider,
  GuardrailsMark,
  Heading,
  HStack,
  IconButton,
  Text,
  VStack,
  iconKeyToName,
  type GrdrThemeMode,
} from "@grdr/ui";

interface OperatorSnapshot {
  health: HealthResponse;
  overview: OverviewResponse;
  keys: TrustedKeyInfo[];
  audit: AuditEntry[];
}

type SidebarDisplay = "expanded" | "collapsed";

type LoadState<T> =
  | { kind: "loading" }
  | { kind: "ready"; data: T }
  | { kind: "error"; message: string; staleData?: T };

type StreamState =
  | { kind: "connected" }
  | { kind: "reconnecting" };

type ExportState =
  | { kind: "idle" }
  | { kind: "exported"; message: string }
  | { kind: "failed"; message: string };

export function OperatorApp() {
  const [route, setRoute] = useState<OperatorRouteId>("op-overview");
  const [themeMode, setThemeMode] = useState<GrdrThemeMode>("light");
  const [sidebarDisplay, setSidebarDisplay] = useState<SidebarDisplay>("expanded");
  const [loadState, setLoadState] = useState<LoadState<OperatorSnapshot>>({ kind: "loading" });
  const [streamState, setStreamState] = useState<StreamState>({ kind: "connected" });
  const [exportState, setExportState] = useState<ExportState>({ kind: "idle" });

  const load = useCallback(async () => {
    try {
      const [health, overview, keys, audit] = await Promise.all([
        api.getHealth(),
        api.getOverview(),
        api.getKeys(),
        api.getAudit(),
      ]);
      setLoadState({ kind: "ready", data: { health, overview, keys, audit } });
      setStreamState({ kind: "connected" });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to load operator state";
      setLoadState((prev) => ({
        kind: "error",
        message,
        staleData: prev.kind === "ready" ? prev.data : prev.kind === "error" ? prev.staleData : undefined,
      }));
      setStreamState({ kind: "reconnecting" });
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const activeRoute = OPERATOR_ROUTES.find((item) => item.id === route) ?? OPERATOR_ROUTES[0];

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

  const snapshot = loadState.kind === "ready" ? loadState.data : loadState.kind === "error" ? (loadState.staleData ?? null) : null;
  const viewState = loadState.kind === "error" ? "error" : loadState.kind === "loading" ? "empty" : "ready";
  const sidebarCollapsed = sidebarDisplay === "collapsed";

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
                onClick={() => setRoute(item.id)}
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
              <span>{streamState.kind === "reconnecting" ? "Reconnecting..." : "Local audit plane"}</span>
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
                onClick={() => void load()}
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
                title={loadState.kind === "error" ? "Operator endpoint unavailable" : "Loading operator plane"}
                description={
                  loadState.kind === "error"
                    ? loadState.message
                    : "Connecting to Guardrails control-plane health and audit APIs."
                }
                actions={
                  <Button
                    label="Retry"
                    variant="secondary"
                    size="sm"
                    onClick={() => void load()}
                  />
                }
              >
                {snapshot ? (
                  <VStack gap={4}>
                    {route === "op-overview" ? (
                      <>
                        <div className="metric-strip" style={{ borderBlockEnd: "1px solid var(--border-subtle)", paddingBlockEnd: 24, marginBlockStart: 0 }}>
                          <div className="metric-cell">
                            <div className="metric-value tabular">
                              {snapshot.health.status === "ok" || snapshot.health.status === "healthy"
                                ? "Healthy"
                                : snapshot.health.status}
                            </div>
                            <div className="metric-label">Service health</div>
                            <div className="metric-note">{`Version ${snapshot.health.version} (${formatStorageMode(snapshot.health.storage_mode)})`}</div>
                          </div>
                          <div className="metric-cell">
                            <div className="metric-value tabular">{snapshot.overview.online_devices}</div>
                            <div className="metric-label">Devices online</div>
                            <div className="metric-note">{`${snapshot.overview.total_agents} discovered agents`}</div>
                          </div>
                          <div className="metric-cell">
                            <div className="metric-value tabular">{snapshot.keys.length}</div>
                            <div className="metric-label">Trusted signers</div>
                            <div className="metric-note">Ed25519 receipt keys</div>
                          </div>
                          <div className="metric-cell">
                            <div className="metric-value tabular">{snapshot.audit.length}</div>
                            <div className="metric-label">Audit entries</div>
                            <div className="metric-note">Hash-chained control ledger</div>
                          </div>
                        </div>

                        <div className="quiet-split">
                          <section className="ledger-section">
                            <div className="ledger-header">
                              <HStack gap={2} align="center">
                                <GrdrIcon name="shield-check" size={16} color="var(--tone-allow)" />
                                <h2 className="ledger-title">Deployment boundary</h2>
                              </HStack>
                              <Badge variant="success" icon={<GrdrIcon name="lock" size={11} />} label="Tenant isolated" />
                            </div>
                            <GrdrFlowGraph
                              direction="LR"
                              height={220}
                              ariaLabel="P8 Deployment isolation boundary diagram"
                              nodes={[
                                {
                                  id: "op-realm",
                                  label: "Operator plane",
                                  subtitle: `${pluralize(snapshot.keys.length, "key")} · ${pluralize(snapshot.audit.length, "audit")}`,
                                  badge: "Isolated",
                                  tone: "accent",
                                  icon: "server",
                                },
                                {
                                  id: "tenant-plane",
                                  label: "Tenant payloads",
                                  subtitle: "Unmounted on operator origin",
                                  badge: "Blocked",
                                  tone: "block",
                                  icon: "lock",
                                },
                              ]}
                              edges={[
                                {
                                  id: "p8-wall",
                                  source: "op-realm",
                                  target: "tenant-plane",
                                  label: "No route",
                                  dashed: true,
                                  tone: "block",
                                },
                              ]}
                            />
                            <div className="kv-row">
                              <Text color="secondary">Storage engine</Text>
                              <Text className="mono">{formatStorageMode(snapshot.health.storage_mode)}</Text>
                            </div>
                            <div className="kv-row">
                              <Text color="secondary">Kill switch state</Text>
                              <Badge
                                variant={snapshot.overview.kill_switch.state === "inactive" ? "success" : "error"}
                                label={snapshot.overview.kill_switch.state === "inactive" ? "Inactive" : snapshot.overview.kill_switch.state}
                              />
                            </div>
                            <div className="kv-row">
                              <Text color="secondary">Pending operator approvals</Text>
                              <HStack gap={2} align="center">
                                <Badge variant="neutral" label={snapshot.overview.pending_approvals} />
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  label="Inspect audit"
                                  endContent={<GrdrIcon name="arrow-right" size={12} />}
                                  onClick={() => setRoute("op-audit")}
                                />
                              </HStack>
                            </div>
                          </section>

                          <section className="ledger-section">
                            <div className="ledger-header">
                              <h2 className="ledger-title">Recent control audit</h2>
                              <Button
                                variant="ghost"
                                size="sm"
                                label="Full ledger"
                                endContent={<GrdrIcon name="arrow-right" size={13} />}
                                onClick={() => setRoute("op-audit")}
                              />
                            </div>
                            {snapshot.audit.length === 0 ? (
                              <EmptyState
                                title="No audit events yet"
                                description="Control-plane changes appear here automatically."
                                icon={<GrdrIcon name="file-text" size={20} />}
                              />
                            ) : (
                              <table className="table">
                                <thead>
                                  <tr>
                                    <th>Event</th>
                                    <th>Actor</th>
                                    <th>Summary</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {snapshot.audit.slice(0, 5).map((entry) => (
                                    <tr key={entry.id}>
                                      <td>{formatAuditKind(entry.kind)}</td>
                                      <td>{entry.actor}</td>
                                      <td>{entry.summary}</td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            )}
                          </section>
                        </div>
                      </>
                    ) : null}

                    {route === "op-health" ? (
                      <section className="ledger-section">
                        <div className="ledger-header">
                          <Heading level={3}>Control-plane liveness</Heading>
                          <Badge
                            label={snapshot.health.status}
                            variant={snapshot.health.status === "ok" ? "success" : "warning"}
                          />
                        </div>
                        <div className="kv-row">
                          <Text color="secondary">Daemon version</Text>
                          <Text className="mono">{snapshot.health.version}</Text>
                        </div>
                        <div className="kv-row">
                          <Text color="secondary">Storage mode</Text>
                          <Text className="mono">{formatStorageMode(snapshot.health.storage_mode)}</Text>
                        </div>
                        <div className="kv-row">
                          <Text color="secondary">Active kill switch</Text>
                          <Text>{snapshot.overview.kill_switch.state}</Text>
                        </div>
                        <div className="kv-row">
                          <Text color="secondary">Open findings</Text>
                          <Text hasTabularNumbers>{snapshot.overview.open_findings}</Text>
                        </div>
                      </section>
                    ) : null}

                    {route === "op-settings" ? (
                      <section className="ledger-section">
                        <div className="ledger-header">
                          <Heading level={3}>Receipt signing keys</Heading>
                        </div>
                        {snapshot.keys.length === 0 ? (
                          <EmptyState
                            title="No signing keys registered"
                            description="Configure receipt signing keys via grdr keygen."
                            icon={<GrdrIcon name="key-round" size={24} />}
                          />
                        ) : (
                          <table className="table">
                            <thead>
                              <tr>
                                <th>Key ID</th>
                                <th>Public key (Base64)</th>
                              </tr>
                            </thead>
                            <tbody>
                              {snapshot.keys.map((key) => (
                                <tr key={key.key_id}>
                                  <td className="mono">{key.key_id}</td>
                                  <td className="mono">{key.public_key_b64.slice(0, 32)}...</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        )}
                      </section>
                    ) : null}

                    {route === "op-audit" ? (
                      <section className="ledger-section">
                        <div className="ledger-header">
                          <Heading level={3}>Operator audit stream</Heading>
                        </div>
                        {snapshot.audit.length === 0 ? (
                          <EmptyState
                            title="No audit entries yet"
                            description="Control-plane changes appear here cleanly."
                            icon={<GrdrIcon name="file-text" size={24} />}
                          />
                        ) : (
                          <table className="table">
                            <thead>
                              <tr>
                                <th>Timestamp</th>
                                <th>Kind</th>
                                <th>Actor</th>
                                <th>Target</th>
                                <th>Summary</th>
                              </tr>
                            </thead>
                            <tbody>
                              {snapshot.audit.map((entry) => (
                                <tr key={entry.id}>
                                  <td className="mono">{entry.timestamp}</td>
                                  <td className="mono">{entry.kind}</td>
                                  <td>{entry.actor}</td>
                                  <td className="mono">{entry.target}</td>
                                  <td>{entry.summary}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        )}
                      </section>
                    ) : null}
                  </VStack>
                ) : null}
              </ViewStateFrame>
            </VStack>
          </main>
        </div>
      </div>
    </GrdrThemeProvider>
  );
}
