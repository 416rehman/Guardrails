// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, type ComplianceWorkspaceResponse, type RetentionStateSummary } from "@grdr/api";
import { capitalizeLabel } from "@grdr/i18n";
import { Quoted } from "@grdr/kit";
import {
  Badge,
  Banner,
  Button,
  Card,
  Dialog,
  EmptyState,
  GrdrIcon,
  GrdrSelect,
  Heading,
  HStack,
  IconButton,
  ProgressBar,
  StatusInline,
  Text,
  TextInput,
  UiSdkSegmentedControl,
  VStack,
} from "@grdr/ui";
import { consoleQueryKeys } from "../queries";

type SettingsPhase =
  | { kind: "idle" }
  | { kind: "busy" }
  | { kind: "ok"; message: string }
  | { kind: "error"; message: string; bootstrapHint?: boolean };

interface PolicyDraft {
  privacyProfile?: "standard" | "works-council";
  preset?: string;
  captureLevel?: string;
  overrideBasis: string;
}

type PolicyDialogState = { kind: "closed" } | { kind: "confirming"; stepUpToken: string };

interface ReidFormState {
  pseudonymId?: string;
  legalBasis?: string;
  reason: string;
  copiedRequestId?: string;
}

function readServerCaptureLevel(retention: RetentionStateSummary | undefined): string | null {
  if (!retention) return null;
  if ("capture_level" in retention && typeof retention.capture_level === "string") {
    return retention.capture_level;
  }
  return retention.privacy_profile === "works-council" || retention.content_days === 0
    ? "metadata-only"
    : "metadata-and-signals";
}

export function SettingsPrivacyPage({ onChanged }: { onChanged?: () => Promise<void> }) {
  const wsQuery = useQuery<ComplianceWorkspaceResponse>({
    queryKey: consoleQueryKeys.complianceWorkspace(),
    queryFn: () => api.getComplianceWorkspace(),
  });

  const ws = wsQuery.data;
  const retention = ws?.retention;
  const metrics = ws?.disclosure_metrics;

  const [policyDraft, setPolicyDraft] = useState<PolicyDraft>({ overrideBasis: "" });
  const [policyDialog, setPolicyDialog] = useState<PolicyDialogState>({ kind: "closed" });
  const [reidForm, setReidForm] = useState<ReidFormState>({ reason: "" });
  const [phase, setPhase] = useState<SettingsPhase>({ kind: "idle" });

  const serverCaptureLevel = readServerCaptureLevel(retention) ?? "metadata-only";
  const privacyProfile = policyDraft.privacyProfile ?? retention?.privacy_profile ?? "standard";
  const preset = policyDraft.preset ?? retention?.presets[0] ?? "default";
  const captureLevel = policyDraft.captureLevel ?? serverCaptureLevel;

  const reidPseudo =
    reidForm.pseudonymId ??
    ws?.reid_requests[0]?.pseudonym_id ??
    ws?.subject_requests[0]?.subject_ref ??
    ws?.legal_holds[0]?.scope_summary ??
    "";
  const reidLegalBasis = reidForm.legalBasis ?? retention?.legal_basis[0] ?? "";

  const isDowngradingWorksCouncil = retention?.privacy_profile === "works-council" && privacyProfile === "standard";
  const isWideningCapture = Boolean(retention) && serverCaptureLevel === "metadata-only" && captureLevel !== "metadata-only";
  const requiresEthicalStepUp = isDowngradingWorksCouncil || isWideningCapture;

  async function writeClipboardRequestRef(requestId: string) {
    if (typeof navigator === "undefined" || typeof navigator.clipboard?.writeText !== "function") {
      setPhase({ kind: "error", message: `Clipboard access unavailable. Copy request ID manually: ${requestId}` });
      return;
    }
    try {
      await navigator.clipboard.writeText(requestId);
      setReidForm((prev) => ({ ...prev, copiedRequestId: requestId }));
      setTimeout(() => {
        setReidForm((prev) => (prev.copiedRequestId === requestId ? { ...prev, copiedRequestId: undefined } : prev));
      }, 1800);
    } catch {
      setPhase({ kind: "error", message: `Clipboard write rejected. Copy request ID manually: ${requestId}` });
    }
  }

  function copyRequestRef(requestId: string) {
    void writeClipboardRequestRef(requestId);
  }

  function handleSavePolicyClick() {
    if (requiresEthicalStepUp) {
      if (policyDraft.overrideBasis.trim() === "") {
        setPhase({
          kind: "error",
          message: "Enter an explicit legal basis override before lowering works-council privacy or widening capture depth.",
        });
        return;
      }
      setPolicyDialog({ kind: "confirming", stepUpToken: "" });
      return;
    }
    void commitPolicySave("");
  }

  async function commitPolicySave(explicitStepUpToken: string) {
    setPolicyDialog({ kind: "closed" });
    setPhase({ kind: "busy" });
    try {
      const token = explicitStepUpToken.trim();
      const updated = await api.updateCompliancePolicy({
        privacy_profile: privacyProfile,
        presets: [preset],
        override_legal_basis: policyDraft.overrideBasis.trim() || undefined,
        capture_level: captureLevel,
        step_up: token.length > 0,
        step_up_token: token || undefined,
      });
      setPolicyDraft({ overrideBasis: "" });
      setPhase({
        kind: "ok",
        message: `Applied ${updated.privacy_profile} privacy regime (${updated.activity_days}d activity / ${updated.audit_days}d audit).`,
      });
      await wsQuery.refetch();
      await onChanged?.();
    } catch (e) {
      setPhase({ kind: "error", message: e instanceof Error ? e.message : "Failed updating compliance privacy settings" });
    }
  }

  async function requestReid() {
    setPhase({ kind: "busy" });
    try {
      const created = await api.requestReidentification({
        pseudonym_id: reidPseudo.trim(),
        legal_basis: reidLegalBasis.trim(),
        reason: reidForm.reason.trim(),
      });
      setReidForm((prev) => ({ ...prev, reason: "" }));
      setPhase({
        kind: "ok",
        message: `Created re-identification quorum request ${created.request_id} (${created.approvers.length}/2 approvals). Have two distinct principals co-sign.`,
      });
      await wsQuery.refetch();
      await onChanged?.();
    } catch (e) {
      setPhase({ kind: "error", message: e instanceof Error ? e.message : "Failed creating re-identification request" });
    }
  }

  async function approveReid(requestId: string) {
    setPhase({ kind: "busy" });
    try {
      const res = await api.approveReidentification({ request_id: requestId });
      setPhase({
        kind: "ok",
        message: res.resolved_identity
          ? `Quorum reached (2/2). Scoped principal: ${res.resolved_identity}`
          : `Approval recorded (${res.approvers.length}/2). One more distinct approver needed.`,
      });
      await wsQuery.refetch();
      await onChanged?.();
    } catch (e) {
      const message = e instanceof Error ? e.message : "Approval failed";
      const isSelfOrDup =
        message.toLowerCase().includes("requester cannot approve") ||
        message.toLowerCase().includes("distinct approver");
      setPhase({ kind: "error", message, bootstrapHint: isSelfOrDup });
    }
  }

  const disclosureCounts = [
    { label: "Re-identifications", value: metrics?.total_reidentifications ?? 0 },
    { label: "Legal holds", value: metrics?.total_holds ?? 0 },
    { label: "Subject erasures", value: metrics?.total_erasures ?? 0 },
    { label: "Evidence exports", value: metrics?.total_exports ?? 0 },
  ];

  return (
    <VStack gap={4}>
      {wsQuery.isError && (
        <Banner
          status="error"
          title={wsQuery.error instanceof Error ? wsQuery.error.message : "Failed loading privacy configuration."}
          collapsible={false}
          endContent={<Button variant="secondary" size="sm" label="Retry" onClick={() => void wsQuery.refetch()} />}
        />
      )}

      <Card padding={3}>
        <VStack gap={3}>
          <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
            <VStack gap={0}>
              <Heading level={1}>Settings, privacy & disclosure</Heading>
              <Text size="sm" color="secondary">
                Configure standard vs works-council privacy ceilings, capture depth, two-approver re-identification quorum, and quarterly disclosures.
              </Text>
            </VStack>
            <Badge
              variant={privacyProfile === "works-council" ? "info" : "neutral"}
              icon={<GrdrIcon name="lock" size={12} />}
              label={privacyProfile === "works-council" ? "Works-council pseudonymous" : "Standard named"}
            />
          </HStack>

          {phase.kind === "ok" && <Banner status="success" title={phase.message} collapsible={false} />}
          {phase.kind === "error" && (
            <Banner
              status="error"
              title={phase.message}
              description={
                phase.bootstrapHint
                  ? "Two distinct authenticated principals are required. Switch reviewer credentials in Command search (Ctrl+K) or ask another authorized principal to sign off."
                  : undefined
              }
              collapsible={false}
            />
          )}

          <div className="grid-2">
            <VStack gap={2}>
              <Text size="sm" weight="semibold">Privacy profile</Text>
              <UiSdkSegmentedControl
                ariaLabel="Privacy regime profile"
                value={privacyProfile}
                onChange={(next) => setPolicyDraft((prev) => ({ ...prev, privacyProfile: next }))}
                options={[
                  { value: "standard", label: "Standard (named)" },
                  { value: "works-council", label: "Works council (pseudonymous)" },
                ]}
              />
              <GrdrSelect
                label="Retention preset"
                value={preset}
                onChange={(next) => setPolicyDraft((prev) => ({ ...prev, preset: next }))}
                options={[
                  { value: "default", label: "Default baseline (396d decision)" },
                  { value: "eu-ai-act-deployer", label: "EU AI Act Art. 26(6) (184d activity)" },
                  { value: "pci-dss-4", label: "PCI DSS 4.0 (365d audit)" },
                  { value: "hipaa", label: "HIPAA Security Rule" },
                  { value: "sox-itgc", label: "SOX ITGC" },
                ]}
              />
            </VStack>

            <VStack gap={2}>
              <GrdrSelect
                label="Endpoint capture ceiling"
                value={captureLevel}
                onChange={(next) => setPolicyDraft((prev) => ({ ...prev, captureLevel: next }))}
                options={[
                  { value: "metadata-only", label: "Metadata only (strict)" },
                  { value: "metadata-and-signals", label: "Metadata + anomaly signals" },
                ]}
              />
              <TextInput
                label={requiresEthicalStepUp ? "Explicit legal basis override (required)" : "Explicit legal basis override (optional)"}
                placeholder="Required when leaving works-council or widening capture"
                value={policyDraft.overrideBasis}
                onChange={(val) => setPolicyDraft((prev) => ({ ...prev, overrideBasis: val }))}
              />
              {requiresEthicalStepUp && (
                <Banner
                  status="warning"
                  title="Step-up confirmation and legal basis required"
                  description="Weakening works-council privacy or widening capture depth requires explicit legal basis justification and a fresh step-up credential confirmation."
                  collapsible={false}
                />
              )}
            </VStack>
          </div>

          {retention ? (
            <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
              <HStack gap={2} style={{ flexWrap: "wrap" }}>
                <Badge variant="neutral" label={`Content ${retention.content_days}d`} />
                <Badge variant="neutral" label={`Activity ${retention.activity_days}d`} />
                <Badge variant="neutral" label={`Decision ${retention.decision_days}d`} />
                <Badge variant="neutral" label={`Audit ${retention.audit_days}d`} />
              </HStack>
              <Button
                variant="primary"
                size="sm"
                label="Save privacy & retention regime"
                isDisabled={phase.kind === "busy" || (requiresEthicalStepUp && policyDraft.overrideBasis.trim() === "")}
                onClick={handleSavePolicyClick}
              />
            </HStack>
          ) : (
            <Text size="sm" color="secondary">{wsQuery.isLoading ? "Loading retention policy..." : "Retention summary unavailable."}</Text>
          )}
        </VStack>
      </Card>

      <div className="grid-2">
        <Card padding={3}>
          <VStack gap={3}>
            <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
              <Heading level={2}>Two-approver re-identification quorum</Heading>
              <Badge variant="warning" label="2 distinct approvers" />
            </HStack>
            <Banner
              status="info"
              title="Two distinct principals required to unmask a pseudonym"
              description="The requester cannot approve their own request. Copy the request reference below so two separate reviewers can co-sign from independent sessions."
              collapsible={false}
            />
            <div className="grid-2">
              <TextInput label="Pseudonym reference" placeholder="Enter vault pseudonym ID" value={reidPseudo} onChange={(val) => setReidForm((prev) => ({ ...prev, pseudonymId: val }))} />
              <TextInput label="Legal basis" placeholder="e.g. Incident investigation Art. 6(1)(f)" value={reidLegalBasis} onChange={(val) => setReidForm((prev) => ({ ...prev, legalBasis: val }))} />
            </div>
            <TextInput label="Justification" placeholder="Document specific security or legal justification" value={reidForm.reason} onChange={(val) => setReidForm((prev) => ({ ...prev, reason: val }))} />
            <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
              <Text size="sm" color="secondary">Requester and approver identities bind to authenticated principal sessions.</Text>
              <Button
                variant="secondary"
                size="sm"
                label="Submit quorum request"
                isDisabled={phase.kind === "busy" || reidPseudo.trim() === "" || reidLegalBasis.trim() === "" || reidForm.reason.trim() === ""}
                onClick={() => void requestReid()}
              />
            </HStack>
            {(ws?.reid_requests.length ?? 0) === 0 ? (
              <EmptyState title="No re-identification requests" description="All monitored sessions remain pseudonymous until two authorized approvers sign a scoped request." icon={<GrdrIcon name="lock" size={20} />} />
            ) : (
              <div className="checklist">
                {(ws?.reid_requests ?? []).map((rq) => {
                  const quorumPct = Math.min(100, Math.max(20, Math.round((rq.approvers.length / Math.max(1, rq.required_approvals)) * 100)));
                  return (
                    <div key={rq.request_id} className="check-row" style={{ flexWrap: "wrap", gap: 8 }}>
                      <VStack gap={1} style={{ flex: "1 1 220px", minWidth: 0 }}>
                        <HStack gap={2} align="center" style={{ flexWrap: "wrap" }}>
                          <Quoted text={rq.pseudonym_id} />
                          <StatusInline tone={rq.status === "approved" ? "allow" : "ask"} dot label={`${rq.approvers.length}/${rq.required_approvals} approved`} />
                        </HStack>
                        <ProgressBar label={`Quorum progress for ${rq.request_id}`} isLabelHidden value={quorumPct} max={100} variant={rq.status === "approved" ? "success" : "accent"} />
                        <Text size="sm" color="secondary">{`Requester: ${rq.requester} · ${rq.legal_basis}`}</Text>
                        {rq.approvers.length > 0 && <Text size="sm" color="secondary">{`Signed by: ${rq.approvers.join(", ")}`}</Text>}
                        {rq.resolved_identity && <StatusInline tone="allow" label={`Unmasked: ${rq.resolved_identity}`} />}
                      </VStack>
                      <HStack gap={2} align="center" style={{ flexWrap: "wrap" }}>
                        <Button variant="ghost" size="sm" label={reidForm.copiedRequestId === rq.request_id ? "Copied ID" : "Copy ID"} onClick={() => copyRequestRef(rq.request_id)} />
                        {rq.status === "pending_quorum" && (
                          <Button variant="primary" size="sm" label="Sign off (quorum)" isDisabled={phase.kind === "busy"} onClick={() => void approveReid(rq.request_id)} />
                        )}
                      </HStack>
                    </div>
                  );
                })}
              </div>
            )}
          </VStack>
        </Card>

        <Card padding={3}>
          <VStack gap={3}>
            <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
              <Heading level={2}>Quarterly disclosure ledger</Heading>
              <Badge variant="info" label={metrics?.quarter ?? "Current quarter"} />
            </HStack>
            <div className="metric-strip" style={{ marginBlockStart: 0, paddingBlockStart: 0, borderBlockStart: "none" }}>
              {disclosureCounts.map((item) => (
                <div key={item.label} className="metric-cell">
                  <div className="metric-value tabular">{item.value}</div>
                  <div className="metric-label">{item.label}</div>
                </div>
              ))}
            </div>
            {(ws?.disclosures.length ?? 0) === 0 ? (
              <EmptyState title="No quarterly disclosures recorded yet" description="Re-identifications, legal holds, erasures, and evidence exports automatically log here." icon={<GrdrIcon name="file-text" size={20} />} />
            ) : (
              <div className="table-wrap">
                <table className="table responsive-table">
                  <thead>
                    <tr><th>Kind</th><th>Actor</th><th>Target</th><th>Basis</th></tr>
                  </thead>
                  <tbody>
                    {(ws?.disclosures ?? []).map((entry) => (
                      <tr key={entry.id}>
                        <td data-label="Kind">
                          <StatusInline tone={entry.kind === "legal_hold" ? "ask" : "neutral"} dot label={capitalizeLabel(entry.kind.replace(/_/g, " "))} />
                        </td>
                        <td data-label="Actor">{entry.actor}</td>
                        <td data-label="Target" className="mono">{entry.target_ref}</td>
                        <td data-label="Basis">{entry.legal_basis}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </VStack>
        </Card>
      </div>

      <Dialog
        isOpen={policyDialog.kind === "confirming"}
        onOpenChange={(open) => {
          if (!open) setPolicyDialog({ kind: "closed" });
        }}
        purpose="required"
        width={520}
        padding={4}
        aria-label="Confirm privacy regime change"
      >
        {policyDialog.kind === "confirming" && (
          <VStack gap={3}>
            <HStack justify="between" align="start">
              <HStack gap={2} align="center">
                <GrdrIcon name="shield-alert" size={18} color="var(--tone-ask)" />
                <Heading level={2}>Confirm privacy ceiling change</Heading>
              </HStack>
              <IconButton label="Close" icon={<GrdrIcon name="x" size={14} />} variant="ghost" size="sm" onClick={() => setPolicyDialog({ kind: "closed" })} />
            </HStack>
            <Text size="sm" color="secondary">
              {`Applying profile "${privacyProfile}" with capture ceiling "${captureLevel}" under legal basis "${policyDraft.overrideBasis.trim()}" increases data visibility and logs a 14-day endpoint notice.`}
            </Text>
            <TextInput
              label="Fresh step-up verification credential"
              type="password"
              placeholder="Enter step-up verification token"
              value={policyDialog.stepUpToken}
              onChange={(val) => setPolicyDialog({ kind: "confirming", stepUpToken: val })}
              data-agent-secret="true"
              autoComplete="off"
              width="100%"
            />
            <HStack justify="end" gap={2}>
              <Button variant="secondary" size="sm" label="Cancel" onClick={() => setPolicyDialog({ kind: "closed" })} />
              <Button
                variant="primary"
                size="sm"
                label="Confirm and apply"
                isDisabled={policyDialog.stepUpToken.trim() === ""}
                onClick={() => void commitPolicySave(policyDialog.stepUpToken)}
              />
            </HStack>
          </VStack>
        )}
      </Dialog>
    </VStack>
  );
}
