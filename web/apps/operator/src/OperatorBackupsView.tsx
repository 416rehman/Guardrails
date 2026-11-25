import { useState } from "react";
import { api } from "@grdr/api";
import { formatTimestamp } from "@grdr/i18n";
import {
  Banner,
  Button,
  GrdrIcon,
  Heading,
  HStack,
  StatusInline,
  Text,
  TextInput,
  VStack,
} from "@grdr/ui";
import type { OperatorSnapshot } from "./queries";

type BackupPhase =
  | { kind: "idle" }
  | { kind: "busy"; op: string }
  | { kind: "ok"; message: string }
  | { kind: "error"; message: string };

export function OperatorBackupsView({
  snapshot,
  onMutated,
}: {
  snapshot: OperatorSnapshot;
  onMutated: () => Promise<void>;
}) {
  const opState = snapshot.operatorState;
  const [drillNote, setDrillNote] = useState("Scheduled SQLite WAL snapshot check");
  const [phase, setPhase] = useState<BackupPhase>({ kind: "idle" });

  async function resetBreaker(targetId: string) {
    setPhase({ kind: "busy", op: targetId });
    try {
      const updated = await api.resetTargetBreaker({
        target_id: targetId,
      });
      setPhase({
        kind: "ok",
        message: `Probed ${updated.name} (${updated.circuit_state})`,
      });
      await onMutated();
    } catch (e) {
      setPhase({
        kind: "error",
        message: e instanceof Error ? e.message : "Failed resetting target breaker",
      });
    }
  }

  async function triggerDrill(kind: "backup" | "restore") {
    setPhase({ kind: "busy", op: kind });
    try {
      const drill = await api.runBackupDrill({
        kind,
        note: drillNote,
      });
      setPhase({
        kind: "ok",
        message: `Completed ${drill.kind} drill ${drill.drill_id} (${drill.record_count} records verified in ${drill.duration_ms}ms)`,
      });
      await onMutated();
    } catch (e) {
      setPhase({
        kind: "error",
        message: e instanceof Error ? e.message : "Backup or restore drill failed",
      });
    }
  }

  return (
    <VStack gap={4}>
      {phase.kind === "ok" && <Banner status="info" title={phase.message} collapsible={false} />}
      {phase.kind === "error" && <Banner status="error" title={phase.message} collapsible={false} />}

      <section className="ledger-section">
        <div className="ledger-header" style={{ flexWrap: "wrap", gap: 10 }}>
          <VStack gap={0}>
            <Heading level={2}>Delivery targets and circuit breakers</Heading>
            <Text size="sm" color="secondary">
              Tiered resilience health for audit ledgers, OTLP collectors, and GRC outbox workers.
            </Text>
          </VStack>
        </div>

        <div className="table-wrap">
          <table className="table responsive-table">
            <thead>
              <tr>
                <th>Target</th>
                <th>Tier</th>
                <th>State</th>
                <th>Circuit</th>
                <th>Latency</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {opState.targets.map((tgt) => (
                <tr key={tgt.id}>
                  <td data-label="Target">
                    <VStack gap={0}>
                      <strong>{tgt.name}</strong>
                      <Text size="sm" color="secondary">{tgt.detail}</Text>
                    </VStack>
                  </td>
                  <td data-label="Tier" className="mono">{`Tier ${tgt.tier}`}</td>
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
                      label={tgt.status.replace(/_/g, " ")}
                    />
                  </td>
                  <td data-label="Circuit" className="mono">{`${tgt.circuit_state} (${tgt.failure_count} err)`}</td>
                  <td data-label="Latency" className="mono tabular">{`${tgt.latency_ms}ms`}</td>
                  <td data-label="Actions">
                    {tgt.circuit_state !== "closed" || tgt.status !== "healthy" ? (
                      <Button
                        size="sm"
                        variant="secondary"
                        label="Reset breaker"
                        isDisabled={phase.kind === "busy"}
                        onClick={() => void resetBreaker(tgt.id)}
                      />
                    ) : (
                      <Text size="sm" color="secondary">Nominal</Text>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="ledger-section">
        <div className="ledger-header" style={{ flexWrap: "wrap", gap: 10 }}>
          <VStack gap={0}>
            <Heading level={2}>Signed backup and restore drills</Heading>
            <Text size="sm" color="secondary">
              Verify SQLite WAL integrity, signed receipt digests, and point-in-time recovery.
            </Text>
          </VStack>
          <HStack gap={2} align="end" style={{ flexWrap: "wrap" }}>
            <TextInput
              label="Drill note"
              value={drillNote}
              onChange={setDrillNote}
              width={240}
            />
            <Button
              size="sm"
              variant="secondary"
              icon={<GrdrIcon name="download" size={14} />}
              label="Run backup drill"
              isDisabled={phase.kind === "busy"}
              onClick={() => void triggerDrill("backup")}
            />
            <Button
              size="sm"
              variant="primary"
              icon={<GrdrIcon name="refresh" size={14} />}
              label="Run restore check"
              isDisabled={phase.kind === "busy"}
              onClick={() => void triggerDrill("restore")}
            />
          </HStack>
        </div>

        <div className="table-wrap">
          <table className="table responsive-table">
            <thead>
              <tr>
                <th>Drill</th>
                <th>Kind</th>
                <th>Status</th>
                <th>Verification</th>
                <th>Digest</th>
              </tr>
            </thead>
            <tbody>
              {opState.drills.map((drill) => (
                <tr key={drill.drill_id}>
                  <td data-label="Drill">
                    <VStack gap={0}>
                      <span className="mono">{drill.drill_id}</span>
                      <Text size="sm" color="secondary">{`${drill.actor} · ${formatTimestamp(drill.executed_at)}`}</Text>
                    </VStack>
                  </td>
                  <td data-label="Kind">{drill.kind}</td>
                  <td data-label="Status">
                    <StatusInline
                      tone={drill.status === "passed" ? "allow" : "ask"}
                      dot
                      label={drill.status}
                    />
                  </td>
                  <td data-label="Verification">
                    <VStack gap={0}>
                      <Text size="sm">{`${drill.record_count} records · ${drill.verified_tables} tables (${drill.duration_ms}ms)`}</Text>
                      <Text size="sm" color="secondary">{drill.note}</Text>
                    </VStack>
                  </td>
                  <td data-label="Digest" className="mono">{drill.snapshot_digest.slice(0, 16)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </VStack>
  );
}
