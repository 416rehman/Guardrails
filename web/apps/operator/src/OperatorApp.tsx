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
import { InsightTile, ViewStateFrame } from "@grdr/kit";
import {
  Badge,
  Banner,
  Button,
  Card,
  EmptyState,
  GrdrIcon,
  GrdrThemeProvider,
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
  const [themeMode, setThemeMode] = useState<GrdrThemeMode>("dark");
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
              <GrdrIcon name="lock" size={18} />
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
              <Text size="sm">{t("operator.context.banner")}</Text>
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
                  <Heading level={1}>{t(activeRoute.labelKey)}</Heading>
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
                        <div className="grid-4">
                          <InsightTile
                            headline="Service health"
                            metric={snapshot.health.status}
                            comparison={`Version ${snapshot.health.version} (${snapshot.health.storage_mode})`}
                            actionLabel="Inspect health"
                            onAction={() => setRoute("op-health")}
                          />
                          <InsightTile
                            headline="Devices online"
                            metric={String(snapshot.overview.online_devices)}
                            comparison={`${snapshot.overview.total_agents} discovered agents`}
                            actionLabel="Review audit"
                            onAction={() => setRoute("op-audit")}
                          />
                          <InsightTile
                            headline="Trusted keys"
                            metric={String(snapshot.keys.length)}
                            comparison="Ed25519 receipt signers"
                            actionLabel="Manage keys & exports"
                            onAction={() => setRoute("op-settings")}
                          />
                          <InsightTile
                            headline="Audit entries"
                            metric={String(snapshot.audit.length)}
                            comparison="Tamper-evident control ledger"
                            actionLabel="Open audit log"
                            onAction={() => setRoute("op-audit")}
                          />
                        </div>

                        <div className="grid-2">
                          <Card padding={4}>
                            <VStack gap={3}>
                              <HStack justify="between" align="center">
                                <Heading level={3}>Deployment boundary</Heading>
                                <Badge variant="success" label="P8 isolated" />
                              </HStack>
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
                            </VStack>
                          </Card>

                          <Card padding={4}>
                            <VStack gap={3}>
                              <HStack justify="between" align="center">
                                <Heading level={3}>Recent control audit</Heading>
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  label="Full ledger"
                                  endContent={<GrdrIcon name="arrow-right" size={13} />}
                                  onClick={() => setRoute("op-audit")}
                                />
                              </HStack>
                              {snapshot.audit.length === 0 ? (
                                <EmptyState
                                  title="No audit events yet"
                                  description="Control-plane changes are appended here automatically."
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
                            </VStack>
                          </Card>
                        </div>
                      </>
                    ) : null}

                    {route === "op-health" ? (
                      <Card padding={4}>
                        <VStack gap={3}>
                          <HStack justify="between" align="center">
                            <Heading level={3}>Control-plane liveness</Heading>
                            <Badge
                              label={snapshot.health.status}
                              variant={snapshot.health.status === "ok" ? "success" : "warning"}
                            />
                          </HStack>
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
                        </VStack>
                      </Card>
                    ) : null}

                    {route === "op-settings" ? (
                      <Card padding={4}>
                        <VStack gap={3}>
                          <Heading level={3}>Receipt signing keys</Heading>
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
                        </VStack>
                      </Card>
                    ) : null}

                    {route === "op-audit" ? (
                      <Card padding={4}>
                        <VStack gap={3}>
                          <Heading level={3}>Operator audit stream</Heading>
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
                        </VStack>
                      </Card>
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
