import { useEffect, useState } from "react";
import { api } from "@grdr/api";
import { formatTimestamp } from "@grdr/i18n";
import {
  Badge,
  Banner,
  Button,
  Card,
  CheckboxInput,
  GrdrIcon,
  GrdrSelect,
  Heading,
  HStack,
  StatusInline,
  Text,
  TextInput,
  VStack,
} from "@grdr/ui";
import type { OperatorSnapshot } from "./queries";

type UpgradePhase =
  | { kind: "idle" }
  | { kind: "busy"; op: string }
  | { kind: "ok"; message: string }
  | { kind: "error"; message: string };

const CAPABILITY_LABELS: Record<string, string> = {
  SignedReceipts: "Signed receipts",
  SessionLabels: "Session labels",
  FastpathFloor: "Fast-path floor",
  McpToolPinning: "MCP tool pinning",
  StepUpApproval: "Step-up approval",
};

function formatCapabilityList(caps: string[]): string {
  return caps
    .map((c) => CAPABILITY_LABELS[c] ?? c.replace(/([a-z0-9])([A-Z])/g, "$1 $2").toLowerCase())
    .join(", ");
}

export function OperatorUpgradesView({
  snapshot,
  onMutated,
}: {
  snapshot: OperatorSnapshot;
  onMutated: () => Promise<void>;
}) {
  const opState = snapshot.operatorState;
  const cfg = opState.runtime_config;

  const [captureLevel, setCaptureLevel] = useState(cfg.capture_level);
  const [privacyProfile, setPrivacyProfile] = useState(cfg.privacy_profile);
  const [retentionPreset, setRetentionPreset] = useState(cfg.retention_preset);
  const [releaseChannel, setReleaseChannel] = useState(cfg.release_channel);
  const [otlpEnabled, setOtlpEnabled] = useState(cfg.otlp_enabled);
  const [summary, setSummary] = useState("Promote balanced audit retention with works-council safeguards");
  const [rollbackReason, setRollbackReason] = useState("Revert unverified telemetry tuning");
  const [targetVersion, setTargetVersion] = useState(opState.target_version || "1.3.0");
  const [stepUpToken, setStepUpToken] = useState("");
  const [phase, setPhase] = useState<UpgradePhase>({ kind: "idle" });

  useEffect(() => {
    setCaptureLevel(cfg.capture_level);
    setPrivacyProfile(cfg.privacy_profile);
    setRetentionPreset(cfg.retention_preset);
    setReleaseChannel(cfg.release_channel);
    setOtlpEnabled(cfg.otlp_enabled);
  }, [cfg]);

  async function stageRevision() {
    setPhase({ kind: "busy", op: "stage" });
    try {
      const staged = await api.stageConfigRevision({
        capture_level: captureLevel,
        privacy_profile: privacyProfile,
        retention_preset: retentionPreset,
        otlp_enabled: otlpEnabled,
        release_channel: releaseChannel,
        summary,
      });
      setPhase({
        kind: "ok",
        message: `Staged config revision v${staged.version} (${staged.revision_id})`,
      });
      await onMutated();
    } catch (e) {
      setPhase({
        kind: "error",
        message: e instanceof Error ? e.message : "Failed staging runtime revision",
      });
    }
  }

  async function applyRevision(revisionId: string) {
    setPhase({ kind: "busy", op: revisionId });
    try {
      const res = await api.applyConfigRevision({
        revision_id: revisionId,
        step_up: stepUpToken.trim().length > 0,
        step_up_token: stepUpToken.trim() || undefined,
      });
      setStepUpToken("");
      setPhase({
        kind: "ok",
        message: `Applied runtime revision v${res.applied_revision.version} (${res.applied_revision.revision_id})`,
      });
      await onMutated();
    } catch (e) {
      setPhase({
        kind: "error",
        message: e instanceof Error ? e.message : "Failed applying revision",
      });
    }
  }

  async function rollbackRevision(targetRevisionId?: string) {
    setPhase({ kind: "busy", op: "rollback" });
    try {
      const res = await api.rollbackConfigRevision({
        target_revision_id: targetRevisionId,
        reason: rollbackReason,
        step_up: stepUpToken.trim().length > 0,
        step_up_token: stepUpToken.trim() || undefined,
      });
      setStepUpToken("");
      setPhase({
        kind: "ok",
        message: `Rolled back active configuration to v${res.rolled_back_revision.version}`,
      });
      await onMutated();
    } catch (e) {
      setPhase({
        kind: "error",
        message: e instanceof Error ? e.message : "Rollback failed",
      });
    }
  }

  async function runPreflight() {
    setPhase({ kind: "busy", op: "preflight" });
    try {
      const res = await api.runUpgradePreflight({
        target_version: targetVersion,
      });
      setPhase({
        kind: "ok",
        message: res.overall_compatible
          ? `Preflight for v${res.target_version} passed compatibility gates.`
          : `Preflight for v${res.target_version} reported warnings requiring operator review.`,
      });
      await onMutated();
    } catch (e) {
      setPhase({
        kind: "error",
        message: e instanceof Error ? e.message : "Preflight check failed",
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
            <Heading level={2}>Runtime configuration revisions</Heading>
            <Text size="sm" color="secondary">
              Stage candidate runtime changes, inspect diffs before activation, or roll back safely.
            </Text>
          </VStack>
          <HStack gap={2} align="center">
            <Badge variant="success" label={`Active v${cfg.version}`} />
            <Button
              size="sm"
              variant="secondary"
              label="Rollback to previous"
              isDisabled={phase.kind === "busy" || opState.revisions.length < 2}
              onClick={() => void rollbackRevision()}
            />
          </HStack>
        </div>

        <Card padding={3}>
          <VStack gap={3}>
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
                gap: "var(--space-2)",
              }}
            >
              <GrdrSelect
                label="Capture ceiling"
                value={captureLevel}
                options={[
                  { value: "metadata-only", label: "Metadata only" },
                  { value: "metrics-only", label: "Metrics only" },
                  { value: "redacted-excerpt", label: "Redacted excerpt" },
                ]}
                onChange={setCaptureLevel}
              />
              <GrdrSelect
                label="Privacy regime"
                value={privacyProfile}
                options={[
                  { value: "standard", label: "Standard" },
                  { value: "works-council", label: "Works council" },
                ]}
                onChange={setPrivacyProfile}
              />
              <GrdrSelect
                label="Retention preset"
                value={retentionPreset}
                options={[
                  { value: "default", label: "Default" },
                  { value: "eu-works-council", label: "EU Works Council" },
                  { value: "regulated", label: "Regulated archive" },
                ]}
                onChange={setRetentionPreset}
              />
              <GrdrSelect
                label="Release channel"
                value={releaseChannel}
                options={[
                  { value: "stable", label: "Stable" },
                  { value: "canary", label: "Canary" },
                ]}
                onChange={setReleaseChannel}
              />
            </div>

            <HStack gap={3} align="end" style={{ flexWrap: "wrap" }}>
              <div style={{ flex: 1, minWidth: 220 }}>
                <TextInput
                  label="Change summary"
                  value={summary}
                  onChange={setSummary}
                  width="100%"
                />
              </div>
              <div style={{ flex: 1, minWidth: 220 }}>
                <TextInput
                  label="Rollback reason (when reverting)"
                  value={rollbackReason}
                  onChange={setRollbackReason}
                  width="100%"
                />
              </div>
              <CheckboxInput
                label="Enable OTLP exporter"
                value={otlpEnabled}
                onChange={setOtlpEnabled}
              />
              {cfg.privacy_profile === "works-council" && (
                <TextInput
                  label="Step-up verification token (to leave works-council)"
                  type="password"
                  placeholder="Enter GRDR_STEP_UP_TOKEN"
                  value={stepUpToken}
                  onChange={setStepUpToken}
                />
              )}
              <Button
                variant="primary"
                size="sm"
                label="Stage revision"
                isDisabled={phase.kind === "busy"}
                onClick={() => void stageRevision()}
              />
            </HStack>
          </VStack>
        </Card>

        <div className="table-wrap">
          <table className="table responsive-table">
            <thead>
              <tr>
                <th>Revision</th>
                <th>State</th>
                <th>Summary and diff</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {opState.revisions.map((rev) => (
                <tr key={rev.revision_id}>
                  <td data-label="Revision">
                    <VStack gap={0}>
                      <span className="mono">{`v${rev.version} (${rev.revision_id})`}</span>
                      <Text size="sm" color="secondary">{`${rev.author} · ${formatTimestamp(rev.created_at)}`}</Text>
                    </VStack>
                  </td>
                  <td data-label="State">
                    <StatusInline
                      tone={
                        rev.state === "applied"
                          ? "allow"
                          : rev.state === "draft" || rev.state === "validated"
                            ? "ask"
                            : "neutral"
                      }
                      dot
                      label={rev.state}
                    />
                  </td>
                  <td data-label="Summary and diff">
                    <VStack gap={1}>
                      <Text size="sm">{rev.summary}</Text>
                      {rev.diff_lines.length > 0 && (
                        <Text size="sm" color="secondary" className="mono">
                          {rev.diff_lines
                            .map((d) => `${d.field}: ${d.previous} -> ${d.next}`)
                            .join(" | ")}
                        </Text>
                      )}
                    </VStack>
                  </td>
                  <td data-label="Actions">
                    <HStack gap={1}>
                      {(rev.state === "draft" || rev.state === "validated") && (
                        <Button
                          size="sm"
                          variant="primary"
                          label="Apply"
                          isDisabled={phase.kind === "busy"}
                          onClick={() => void applyRevision(rev.revision_id)}
                        />
                      )}
                      {rev.revision_id !== cfg.revision_id && rev.state !== "draft" && (
                        <Button
                          size="sm"
                          variant="secondary"
                          label="Restore"
                          isDisabled={phase.kind === "busy"}
                          onClick={() => void rollbackRevision(rev.revision_id)}
                        />
                      )}
                    </HStack>
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
            <Heading level={2}>Upgrade compatibility preflight</Heading>
            <Text size="sm" color="secondary">
              Validate daemon, schema, and protocol handshake ranges before promoting fleet rollouts.
            </Text>
          </VStack>
          <HStack gap={2} align="end" style={{ flexWrap: "wrap" }}>
            <TextInput
              label="Target version"
              value={targetVersion}
              onChange={setTargetVersion}
              width={130}
            />
            <Button
              variant="secondary"
              size="sm"
              icon={<GrdrIcon name="shield-check" size={14} />}
              label="Run preflight"
              isDisabled={phase.kind === "busy"}
              onClick={() => void runPreflight()}
            />
          </HStack>
        </div>

        <StatusInline
          tone={opState.overall_compatible ? "allow" : "ask"}
          dot
          label={
            opState.overall_compatible
              ? `Ready for v${opState.target_version}`
              : `Warnings on v${opState.target_version}`
          }
        />

        <div className="table-wrap">
          <table className="table responsive-table">
            <thead>
              <tr>
                <th>Component</th>
                <th>Versions</th>
                <th>Status</th>
                <th>Capabilities and remediation</th>
              </tr>
            </thead>
            <tbody>
              {opState.preflight_matrix.map((chk) => (
                <tr key={chk.component}>
                  <td data-label="Component" className="mono">{chk.component}</td>
                  <td data-label="Versions" className="mono">{`${chk.current_version} -> ${chk.target_version} (${chk.supported_range})`}</td>
                  <td data-label="Status">
                    <StatusInline
                      tone={
                        chk.status === "compatible"
                          ? "allow"
                          : chk.status === "compatible_with_warnings"
                            ? "ask"
                            : "block"
                      }
                      dot
                      label={chk.status.replace(/_/g, " ")}
                    />
                  </td>
                  <td data-label="Capabilities and remediation">
                    <VStack gap={0}>
                      <Text size="sm" color="secondary">
                        {formatCapabilityList(chk.agreed_capabilities)}
                      </Text>
                      {chk.remediation && <Text size="sm">{chk.remediation}</Text>}
                    </VStack>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </VStack>
  );
}
