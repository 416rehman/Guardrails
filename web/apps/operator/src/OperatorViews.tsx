import { formatStorageMode } from "@grdr/api";
import { pluralize, type OperatorRouteId } from "@grdr/i18n";
import {
  Badge,
  Button,
  EmptyState,
  GrdrFlowGraph,
  GrdrIcon,
  Heading,
  HStack,
  Text,
} from "@grdr/ui";
import type { OperatorSnapshot } from "./queries";

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

export function OperatorOverviewView({
  snapshot,
  onNavigate,
}: {
  snapshot: OperatorSnapshot;
  onNavigate: (route: OperatorRouteId) => void;
}) {
  return (
    <>
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
  );
}

export function OperatorHealthView({ snapshot }: { snapshot: OperatorSnapshot }) {
  return (
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
  );
}

export function OperatorSettingsView({ snapshot }: { snapshot: OperatorSnapshot }) {
  return (
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
  );
}

export function OperatorAuditView({ snapshot }: { snapshot: OperatorSnapshot }) {
  return (
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
  );
}
