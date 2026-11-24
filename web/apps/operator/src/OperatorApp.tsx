import { useCallback, useEffect, useState } from "react";
import "@grdr/tokens/tokens.css";
import "./styles.css";
import {
  api,
  type AuditEntry,
  type HealthResponse,
  type OverviewResponse,
  type TrustedKeyInfo,
} from "@grdr/api";
import { OPERATOR_ROUTES, type OperatorRouteId, t } from "@grdr/i18n";
import { ViewStateFrame } from "@grdr/kit";
import {
  Badge,
  Banner,
  Button,
  EmptyState,
  GrdrIcon,
  GrdrThemeProvider,
  GuardrailsMark,
  Heading,
  HStack,
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

export function OperatorApp() {
  const [route, setRoute] = useState<OperatorRouteId>("op-overview");
  const [themeMode, setThemeMode] = useState<GrdrThemeMode>("light");
  const [snapshot, setSnapshot] = useState<OperatorSnapshot | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [exportNote, setExportNote] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setError(null);
      const [health, overview, keys, audit] = await Promise.all([
        api.getHealth(),
        api.getOverview(),
        api.getKeys(),
        api.getAudit(),
      ]);
      setSnapshot({ health, overview, keys, audit });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load operator state");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const activeRoute = OPERATOR_ROUTES.find((item) => item.id === route) ?? OPERATOR_ROUTES[0];

  const handleExportOcsf = async () => {
    try {
      setExportNote(null);
      await api.exportOcsf();
      setExportNote("Exported OCSF 1.9 event bundle");
    } catch (err) {
      setExportNote(err instanceof Error ? err.message : "OCSF export failed");
    }
  };

  const handleExportAuditJsonl = async () => {
    try {
      setExportNote(null);
      await api.exportAuditJsonl();
      setExportNote("Exported tamper-evident audit JSONL stream");
    } catch (err) {
      setExportNote(err instanceof Error ? err.message : "Audit JSONL export failed");
    }
  };

  const viewState = error ? "error" : loading || !snapshot ? "empty" : "ready";

  return (
    <GrdrThemeProvider mode={themeMode}>
      <div className="shell">
        <aside className="rail" aria-label="Operator navigation">
          <div className="brand-mark">
            <div className="brand-glyph">
              <GuardrailsMark size={18} />
            </div>
            <div className="brand-title">
              <strong>{t("grdr.brand.name")}</strong>
              <span>{t("grdr.brand.operator_subtitle")}</span>
            </div>
          </div>

          <nav className="rail-nav">
            {OPERATOR_ROUTES.map((item) => (
              <button
                key={item.id}
                type="button"
                className={item.id === route ? "nav-item active" : "nav-item"}
                onClick={() => setRoute(item.id)}
              >
                <span className="nav-item-label">
                  <GrdrIcon name={iconKeyToName(item.iconKey)} size={16} />
                  <span>{t(item.labelKey)}</span>
                </span>
              </button>
            ))}
          </nav>

          <div className="rail-footer">
            <Button
              label={themeMode === "dark" ? "Light theme" : "Dark theme"}
              variant="ghost"
              size="sm"
              icon={<GrdrIcon name={themeMode === "dark" ? "sun" : "moon"} size={14} />}
              onClick={() => setThemeMode((prev: GrdrThemeMode) => (prev === "dark" ? "light" : "dark"))}
            />
          </div>
        </aside>

        <div className="workspace">
          <header className="topbar operator-context">
            <HStack gap={2} align="center">
              <Badge variant="warning" label="Operator realm" icon={<GrdrIcon name="lock" size={12} />} />
              <span style={{ fontSize: 13 }}>{t("operator.context.banner")}</span>
            </HStack>
            <Button
              label="Refresh"
              variant="secondary"
              size="sm"
              icon={<GrdrIcon name="refresh" size={14} />}
              onClick={() => void load()}
            />
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

              {exportNote ? (
                <Banner status="info" title={exportNote} collapsible={false} />
              ) : null}

              <ViewStateFrame
                state={viewState}
                title={error ? "Operator endpoint unavailable" : "Loading operator plane"}
                description={error ?? "Connecting to Guardrails control-plane health and audit APIs."}
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
                            <div className="metric-value tabular">{snapshot.health.status}</div>
                            <div className="metric-label">Service health</div>
                            <div className="metric-note">{`Version ${snapshot.health.version} (${snapshot.health.storage_mode})`}</div>
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
                              <Badge variant="success" icon={<GrdrIcon name="lock" size={11} />} label="P8 isolated" />
                            </div>
                            <svg
                              width="100%"
                              height="118"
                              viewBox="0 0 540 118"
                              role="img"
                              aria-label="P8 Deployment isolation boundary diagram"
                            >
                              <rect
                                x="6"
                                y="10"
                                width="224"
                                height="96"
                                rx="8"
                                fill="var(--bg-recessed)"
                                stroke="var(--accent-primary)"
                                strokeWidth="1.5"
                              />
                              <text x="20" y="34" fontSize="12" fontWeight="700" fill="var(--ink-primary)">
                                Operator control realm
                              </text>
                              <text x="20" y="54" fontSize="11" fill="var(--ink-secondary)">
                                Health, Ed25519 keys, OCSF exports
                              </text>
                              <text x="20" y="74" fontSize="11" fill="var(--tone-allow)">
                                {`${snapshot.keys.length} trusted key(s), ${snapshot.audit.length} audit entry`}
                              </text>

                              <line
                                x1="258"
                                y1="12"
                                x2="258"
                                y2="106"
                                stroke="var(--tone-block)"
                                strokeWidth="2"
                                strokeDasharray="5 4"
                              />
                              <text x="270" y="64" fontSize="11" fontWeight="700" fill="var(--tone-block)">
                                0 routes
                              </text>

                              <rect
                                x="330"
                                y="10"
                                width="204"
                                height="96"
                                rx="8"
                                fill="var(--bg-recessed)"
                                stroke="var(--border-strong)"
                                strokeWidth="1.2"
                                strokeDasharray="4 3"
                              />
                              <text x="344" y="34" fontSize="12" fontWeight="700" fill="var(--ink-muted)">
                                Tenant prompts &amp; payloads
                              </text>
                              <text x="344" y="54" fontSize="11" fill="var(--ink-muted)">
                                Unmounted (0) on operator origin
                              </text>
                              <text x="344" y="74" fontSize="11" fill="var(--ink-muted)">
                                Enforced by P8 isolation rule
                              </text>
                            </svg>
                            <div className="kv-row">
                              <Text color="secondary">Tenant prompt & payload routes</Text>
                              <Text className="mono">Unmounted (0)</Text>
                            </div>
                            <div className="kv-row">
                              <Text color="secondary">Storage engine</Text>
                              <Text className="mono">{snapshot.health.storage_mode}</Text>
                            </div>
                            <div className="kv-row">
                              <Text color="secondary">Kill switch state</Text>
                              <Badge
                                variant={snapshot.overview.kill_switch.state === "inactive" ? "success" : "error"}
                                label={snapshot.overview.kill_switch.state}
                              />
                            </div>
                            <div className="kv-row">
                              <Text color="secondary">Pending operator approvals</Text>
                              <Text hasTabularNumbers>{snapshot.overview.pending_approvals}</Text>
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
                                    <th>Kind</th>
                                    <th>Actor</th>
                                    <th>Summary</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {snapshot.audit.slice(0, 5).map((entry) => (
                                    <tr key={entry.id}>
                                      <td className="mono">{entry.kind}</td>
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
                          <Text className="mono">{snapshot.health.storage_mode}</Text>
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
