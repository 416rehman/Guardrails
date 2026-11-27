// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
import { formatStorageMode } from "@grdr/api";
import { capitalizeLabel, formatTimestamp, pluralize } from "@grdr/i18n";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  GrdrFlowGraph,
  GrdrIcon,
  Heading,
  HStack,
  ProgressBar,
  StatusInline,
  Text,
  VStack,
} from "@grdr/ui";
import { formatAuditKind } from "./OperatorAuditView";
import type { ExtendedOperatorRouteId } from "./operatorRoutes";
import type { OperatorSnapshot } from "./queries";

interface ChecklistItem {
  id: string;
  label: string;
  done: boolean;
  actionLabel?: string;
  route?: ExtendedOperatorRouteId;
}

export function OperatorOverviewView({
  snapshot,
  onNavigate,
}: {
  snapshot: OperatorSnapshot;
  onNavigate: (route: ExtendedOperatorRouteId) => void;
}) {
  const checklist: ChecklistItem[] = [
    {
      id: "daemon-health",
      label: "Control-plane service healthy and isolated",
      done: snapshot.health.status === "ok" || snapshot.health.status === "healthy",
      actionLabel: "View health",
      route: "op-health",
    },
    {
      id: "receipt-keys",
      label: "Ed25519 receipt signing keys registered",
      done: snapshot.keys.length > 0,
      actionLabel: "Trust keys",
      route: "op-keys",
    },
    {
      id: "persistent-db",
      label: "Persistent SQLite WAL storage enabled",
      done: snapshot.health.storage_mode.kind === "sqlite",
      actionLabel: "View health",
      route: "op-health",
    },
    {
      id: "backup-drill",
      label: "Backup or restore verification drill completed",
      done: snapshot.operatorState.drills.some((d) => d.status === "passed"),
      actionLabel: "Run drill",
      route: "op-backups",
    },
  ];

  const completedSteps = checklist.filter((step) => step.done).length;
  const readinessPct = Math.max(20, Math.round((completedSteps / checklist.length) * 100));

  return (
    <VStack gap={4}>
      <div
        className="metric-strip"
        style={{
          borderBlockEnd: "1px solid var(--border-subtle)",
          paddingBlockEnd: 24,
          marginBlockStart: 0,
        }}
      >
        <div className="metric-cell">
          <div className="metric-value tabular">
            {snapshot.health.status === "ok" || snapshot.health.status === "healthy"
              ? "Healthy"
              : capitalizeLabel(snapshot.health.status)}
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

      <Card padding={3}>
        <VStack gap={2}>
          <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
            <VStack gap={0}>
              <Heading level={2}>Deployment readiness checklist</Heading>
              <Text size="sm" color="secondary">
                Core isolation, trust-key, and backup controls verified for this operator realm.
              </Text>
            </VStack>
            <Badge
              variant={completedSteps === checklist.length ? "success" : "info"}
              label={`${completedSteps}/${checklist.length} ready`}
            />
          </HStack>
          <ProgressBar
            label="Operator readiness"
            isLabelHidden
            value={readinessPct}
            max={100}
            variant={completedSteps === checklist.length ? "success" : "accent"}
          />
          <div>
            {checklist.map((item) => {
              const targetRoute = item.route;
              return (
                <div key={item.id} className="op-check-item">
                  <HStack gap={2} align="center">
                    <StatusInline tone={item.done ? "allow" : "ask"} dot label={item.label} />
                  </HStack>
                  {targetRoute && item.actionLabel && (
                    <Button
                      size="sm"
                      variant="ghost"
                      label={item.actionLabel}
                      endContent={<GrdrIcon name="arrow-right" size={12} />}
                      onClick={() => onNavigate(targetRoute)}
                    />
                  )}
                </div>
              );
            })}
          </div>
        </VStack>
      </Card>

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
            ariaLabel="Deployment isolation boundary diagram"
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
                subtitle: "Restricted on operator origin",
                badge: "Blocked",
                tone: "block",
                icon: "lock",
              },
            ]}
            edges={[
              {
                id: "realm-wall",
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
              label={
                snapshot.overview.kill_switch.state === "inactive"
                  ? "Inactive"
                  : capitalizeLabel(snapshot.overview.kill_switch.state.replace(/_/g, " "))
              }
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
                onClick={() => onNavigate("op-audit")}
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
              onClick={() => onNavigate("op-audit")}
            />
          </div>
          {snapshot.audit.length === 0 ? (
            <EmptyState
              title="No audit events yet"
              description="Control-plane changes appear here automatically."
              icon={<GrdrIcon name="file-text" size={20} />}
            />
          ) : (
            <div className="table-wrap">
              <table className="table responsive-table">
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
                      <td data-label="Event">{formatAuditKind(entry.kind)}</td>
                      <td data-label="Actor">{entry.actor}</td>
                      <td data-label="Summary">{entry.summary}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>
    </VStack>
  );
}

export function OperatorHealthView({
  snapshot,
  onNavigate,
}: {
  snapshot: OperatorSnapshot;
  onNavigate?: (route: ExtendedOperatorRouteId) => void;
}) {
  return (
    <VStack gap={4}>
      <section className="ledger-section">
        <div className="ledger-header">
          <Heading level={2}>Daemon health</Heading>
          <Badge
            variant={snapshot.health.status === "ok" || snapshot.health.status === "healthy" ? "success" : "warning"}
            label={
              snapshot.health.status === "ok" || snapshot.health.status === "healthy"
                ? "Healthy"
                : capitalizeLabel(snapshot.health.status)
            }
          />
        </div>
        <div className="kv-row">
          <Text color="secondary">Status</Text>
          <Text>{capitalizeLabel(snapshot.health.status)}</Text>
        </div>
        <div className="kv-row">
          <Text color="secondary">Version</Text>
          <Text className="mono">{snapshot.health.version}</Text>
        </div>
        <div className="kv-row">
          <Text color="secondary">Storage engine</Text>
          <Text className="mono">{formatStorageMode(snapshot.health.storage_mode)}</Text>
        </div>
        <div className="kv-row">
          <Text color="secondary">Timestamp</Text>
          <Text className="mono">{formatTimestamp(snapshot.health.timestamp)}</Text>
        </div>
        <div className="kv-row">
          <Text color="secondary">Kill switch</Text>
          <Text>{capitalizeLabel(snapshot.overview.kill_switch.state.replace(/_/g, " "))}</Text>
        </div>
      </section>

      <section className="ledger-section">
        <div className="ledger-header" style={{ flexWrap: "wrap", gap: 8 }}>
          <VStack gap={0}>
            <Heading level={2}>Delivery target probes</Heading>
            <Text size="sm" color="secondary">
              Circuit-breaker state and round-trip latency across audit and export sinks.
            </Text>
          </VStack>
          {onNavigate && (
            <Button
              size="sm"
              variant="secondary"
              label="Open Backups & breakers"
              endContent={<GrdrIcon name="arrow-right" size={13} />}
              onClick={() => onNavigate("op-backups")}
            />
          )}
        </div>

        {snapshot.operatorState.targets.length === 0 ? (
          <EmptyState
            title="No delivery targets configured"
            description="Configure an OTLP collector or GRC export sink to monitor delivery latency."
            icon={<GrdrIcon name="activity" size={20} />}
          />
        ) : (
          <div className="table-wrap">
            <table className="table responsive-table">
              <thead>
                <tr>
                  <th>Target</th>
                  <th>State</th>
                  <th>Circuit</th>
                  <th>Latency</th>
                </tr>
              </thead>
              <tbody>
                {snapshot.operatorState.targets.map((tgt) => (
                  <tr key={tgt.id}>
                    <td data-label="Target">{tgt.name}</td>
                    <td data-label="State">
                      <StatusInline
                        tone={
                          tgt.status === "healthy"
                            ? "allow"
                            : tgt.status === "degraded"
                              ? "ask"
                              : "block"
                        }
                        dot
                        label={capitalizeLabel(tgt.status.replace(/_/g, " "))}
                      />
                    </td>
                    <td data-label="Circuit" className="mono">
                      {tgt.circuit_state}
                    </td>
                    <td data-label="Latency" className="mono tabular">
                      {`${tgt.latency_ms}ms`}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </VStack>
  );
}
