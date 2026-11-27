// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
import { useEffect, useState } from "react";
import { api, type ConfigRevisionEntry, type OperatorRuntimeConfig } from "@grdr/api";
import { capitalizeLabel, formatTimestamp } from "@grdr/i18n";
import {
  Badge,
  Banner,
  Button,
  Card,
  CheckboxInput,
  Dialog,
  EmptyState,
  GrdrIcon,
  GrdrSelect,
  Heading,
  HStack,
  IconButton,
  StatusInline,
  Text,
  TextInput,
  VStack,
} from "@grdr/ui";
import { OperatorUpgradePreflight } from "./OperatorUpgradePreflight";
import type { OperatorSnapshot } from "./queries";

type UpgradePhase =
  | { kind: "idle" }
  | { kind: "busy"; op: string }
  | { kind: "ok"; message: string }
  | { kind: "error"; message: string };

type UpgradeDialogState =
  | { kind: "closed" }
  | {
      kind: "confirming";
      action: "apply" | "rollback";
      revisionId?: string;
      summary: string;
      requiresStepUp: boolean;
      stepUpToken: string;
    };

const CAPTURE_RANK: Record<string, number> = {
  "metadata-only": 0,
  "metrics-only": 1,
  "redacted-excerpt": 2,
};

function isProtectionWeakened(
  current: OperatorRuntimeConfig,
  candidate: OperatorRuntimeConfig | undefined,
): boolean {
  if (!candidate) {
    return current.privacy_profile === "works-council" || current.capture_level === "metadata-only";
  }
  const lowersPrivacy = current.privacy_profile === "works-council" && candidate.privacy_profile !== "works-council";
  const currentRank = CAPTURE_RANK[current.capture_level] ?? 0;
  const candidateRank = CAPTURE_RANK[candidate.capture_level] ?? 0;
  return lowersPrivacy || candidateRank > currentRank;
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
  const [targetVersion, setTargetVersion] = useState(() => opState.target_version || snapshot.health.version);
  const [dialog, setDialog] = useState<UpgradeDialogState>({ kind: "closed" });
  const [phase, setPhase] = useState<UpgradePhase>({ kind: "idle" });

  useEffect(() => {
    setCaptureLevel(cfg.capture_level);
    setPrivacyProfile(cfg.privacy_profile);
    setRetentionPreset(cfg.retention_preset);
    setReleaseChannel(cfg.release_channel);
    setOtlpEnabled(cfg.otlp_enabled);
  }, [cfg]);

  useEffect(() => {
    setTargetVersion(opState.target_version || snapshot.health.version);
  }, [opState.target_version, snapshot.health.version]);

  const draftWeakensProtection =
    (cfg.privacy_profile === "works-council" && privacyProfile === "standard") ||
    (CAPTURE_RANK[captureLevel] ?? 0) > (CAPTURE_RANK[cfg.capture_level] ?? 0);

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
      setPhase({ kind: "ok", message: `Staged config revision v${staged.version} (${staged.revision_id})` });
      await onMutated();
    } catch (e) {
      setPhase({ kind: "error", message: e instanceof Error ? e.message : "Failed staging runtime revision" });
    }
  }

  function openApplyDialog(rev: ConfigRevisionEntry) {
    setDialog({
      kind: "confirming",
      action: "apply",
      revisionId: rev.revision_id,
      summary: `Activate v${rev.version} (${rev.revision_id}): ${rev.summary}`,
      requiresStepUp: isProtectionWeakened(cfg, rev.config),
      stepUpToken: "",
    });
  }

  function openRollbackDialog(targetRevisionId?: string) {
    const candidateRev = targetRevisionId
      ? opState.revisions.find((r) => r.revision_id === targetRevisionId)
      : opState.revisions.find((r) => r.revision_id !== cfg.revision_id);
    setDialog({
      kind: "confirming",
      action: "rollback",
      revisionId: targetRevisionId,
      summary: candidateRev
        ? `Restore configuration v${candidateRev.version} (${candidateRev.revision_id}) with reason "${rollbackReason.trim()}"`
        : `Rollback active v${cfg.version} with reason "${rollbackReason.trim()}"`,
      requiresStepUp: isProtectionWeakened(cfg, candidateRev?.config),
      stepUpToken: "",
    });
  }

  async function executeConfirmedDialog() {
    if (dialog.kind !== "confirming") return;
    const { action, revisionId, stepUpToken } = dialog;
    const token = stepUpToken.trim();
    setDialog({ kind: "closed" });
    setPhase({ kind: "busy", op: revisionId ?? action });
    try {
      if (action === "apply" && revisionId) {
        const res = await api.applyConfigRevision({
          revision_id: revisionId,
          step_up: token.length > 0,
          step_up_token: token || undefined,
        });
        setPhase({
          kind: "ok",
          message: `Applied runtime revision v${res.applied_revision.version} (${res.applied_revision.revision_id})`,
        });
      } else {
        const res = await api.rollbackConfigRevision({
          target_revision_id: revisionId,
          reason: rollbackReason,
          step_up: token.length > 0,
          step_up_token: token || undefined,
        });
        setPhase({
          kind: "ok",
          message: `Rolled back active configuration to v${res.rolled_back_revision.version}`,
        });
      }
      await onMutated();
    } catch (e) {
      setPhase({ kind: "error", message: e instanceof Error ? e.message : "Configuration transition failed" });
    }
  }

  async function runPreflight() {
    setPhase({ kind: "busy", op: "preflight" });
    try {
      const res = await api.runUpgradePreflight({ target_version: targetVersion });
      setPhase({
        kind: "ok",
        message: res.overall_compatible
          ? `Preflight for v${res.target_version} passed compatibility gates.`
          : `Preflight for v${res.target_version} reported warnings requiring operator review.`,
      });
      await onMutated();
    } catch (e) {
      setPhase({ kind: "error", message: e instanceof Error ? e.message : "Preflight check failed" });
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
              onClick={() => openRollbackDialog()}
            />
          </HStack>
        </div>

        <Card padding={3}>
          <VStack gap={3}>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: "var(--space-2)" }}>
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

            <div className="op-actions-row">
              <div style={{ flex: "1 1 220px", minWidth: 0 }}>
                <TextInput label="Change summary" value={summary} onChange={setSummary} width="100%" />
              </div>
              <div style={{ flex: "1 1 220px", minWidth: 0 }}>
                <TextInput label="Rollback reason (when reverting)" value={rollbackReason} onChange={setRollbackReason} width="100%" />
              </div>
              <CheckboxInput label="Enable OTLP exporter" value={otlpEnabled} onChange={setOtlpEnabled} />
              <Button
                variant="primary"
                size="sm"
                label="Stage revision"
                isDisabled={phase.kind === "busy" || summary.trim() === ""}
                onClick={() => void stageRevision()}
              />
            </div>

            {draftWeakensProtection && (
              <Banner
                status="warning"
                title="Candidate revision widens capture or lowers works-council privacy"
                description="Activating this staged revision will require explicit confirmation and a fresh step-up verification token."
                collapsible={false}
              />
            )}
          </VStack>
        </Card>

        {opState.revisions.length === 0 ? (
          <EmptyState
            title="No runtime configuration revisions staged"
            description="Stage a candidate configuration revision above to inspect diffs before activation."
            icon={<GrdrIcon name="layers" size={20} />}
          />
        ) : (
          <div className="table-wrap">
            <table className="table responsive-table">
              <thead>
                <tr><th>Revision</th><th>State</th><th>Summary and diff</th><th>Actions</th></tr>
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
                        tone={rev.state === "applied" ? "allow" : rev.state === "draft" || rev.state === "validated" ? "ask" : "neutral"}
                        dot
                        label={capitalizeLabel(rev.state.replace(/_/g, " "))}
                      />
                    </td>
                    <td data-label="Summary and diff">
                      <VStack gap={1}>
                        <Text size="sm">{rev.summary}</Text>
                        {rev.diff_lines.length > 0 && (
                          <Text size="sm" color="secondary" className="mono">
                            {rev.diff_lines.map((d) => `${d.field}: ${d.previous} -> ${d.next}`).join(" | ")}
                          </Text>
                        )}
                      </VStack>
                    </td>
                    <td data-label="Actions">
                      <HStack gap={1}>
                        {(rev.state === "draft" || rev.state === "validated") && (
                          <Button size="sm" variant="primary" label="Apply" isDisabled={phase.kind === "busy"} onClick={() => openApplyDialog(rev)} />
                        )}
                        {rev.revision_id !== cfg.revision_id && rev.state !== "draft" && (
                          <Button size="sm" variant="secondary" label="Restore" isDisabled={phase.kind === "busy"} onClick={() => openRollbackDialog(rev.revision_id)} />
                        )}
                      </HStack>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <OperatorUpgradePreflight
        targetVersion={targetVersion}
        onChangeTargetVersion={setTargetVersion}
        overallCompatible={opState.overall_compatible}
        opTargetVersion={opState.target_version}
        preflightMatrix={opState.preflight_matrix}
        busy={phase.kind === "busy"}
        onRunPreflight={() => void runPreflight()}
      />

      <Dialog
        isOpen={dialog.kind === "confirming"}
        onOpenChange={(open) => {
          if (!open) setDialog({ kind: "closed" });
        }}
        purpose="required"
        width={520}
        padding={4}
        aria-label="Confirm runtime configuration transition"
      >
        {dialog.kind === "confirming" && (
          <VStack gap={3}>
            <HStack justify="between" align="start">
              <HStack gap={2} align="center">
                <GrdrIcon name="shield-alert" size={18} color="var(--tone-ask)" />
                <Heading level={2}>{dialog.action === "apply" ? "Confirm apply revision" : "Confirm configuration restore"}</Heading>
              </HStack>
              <IconButton label="Close" icon={<GrdrIcon name="x" size={14} />} variant="ghost" size="sm" onClick={() => setDialog({ kind: "closed" })} />
            </HStack>
            <Text size="sm" color="secondary">{dialog.summary}</Text>
            {dialog.requiresStepUp && (
              <Banner
                status="warning"
                title="Fresh step-up credential required"
                description="This transition relaxes privacy or capture safeguards and requires explicit step-up verification."
                collapsible={false}
              />
            )}
            <TextInput
              label={dialog.requiresStepUp ? "Step-up verification token (required)" : "Step-up verification token (optional)"}
              type="password"
              placeholder="Enter step-up verification token"
              value={dialog.stepUpToken}
              onChange={(val) => setDialog({ ...dialog, stepUpToken: val })}
              data-agent-secret="true"
              autoComplete="off"
              width="100%"
            />
            <HStack justify="end" gap={2}>
              <Button variant="secondary" size="sm" label="Cancel" onClick={() => setDialog({ kind: "closed" })} />
              <Button
                variant="primary"
                size="sm"
                label={dialog.action === "apply" ? "Confirm apply" : "Confirm restore"}
                isDisabled={dialog.requiresStepUp && dialog.stepUpToken.trim() === ""}
                onClick={() => void executeConfirmedDialog()}
              />
            </HStack>
          </VStack>
        )}
      </Dialog>
    </VStack>
  );
}
