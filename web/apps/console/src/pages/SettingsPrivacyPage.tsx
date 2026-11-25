import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, type ComplianceWorkspaceResponse } from "@grdr/api";
import { capitalizeLabel } from "@grdr/i18n";
import {
  Badge,
  Banner,
  Button,
  Card,
  GrdrIcon,
  GrdrSelect,
  Heading,
  HStack,
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
  | { kind: "error"; message: string };

export function SettingsPrivacyPage({
  onChanged,
}: {
  onChanged?: () => Promise<void>;
}) {
  const wsQuery = useQuery<ComplianceWorkspaceResponse>({
    queryKey: consoleQueryKeys.complianceWorkspace(),
    queryFn: () => api.getComplianceWorkspace(),
  });

  const ws = wsQuery.data;
  const retention = ws?.retention;
  const metrics = ws?.disclosure_metrics;

  const [privacyProfile, setPrivacyProfile] = useState<"standard" | "works-council">("standard");
  const [preset, setPreset] = useState("default");
  const [captureLevel, setCaptureLevel] = useState("metadata-only");
  const [overrideBasis, setOverrideBasis] = useState("");
  const [stepUpToken, setStepUpToken] = useState("");
  const [reidPseudo, setReidPseudo] = useState("prn_8f4c21a9e041");
  const [reidLegalBasis, setReidLegalBasis] = useState("Incident investigation Art. 6(1)(f)");
  const [reidReason, setReidReason] = useState("Verify device owner after repeated SSH key blocks");
  const [phase, setPhase] = useState<SettingsPhase>({ kind: "idle" });

  useEffect(() => {
    if (retention) {
      setPrivacyProfile(retention.privacy_profile);
      if (retention.presets[0]) {
        setPreset(retention.presets[0]);
      }
    }
  }, [retention]);

  const isDowngradingWorksCouncil =
    retention?.privacy_profile === "works-council" && privacyProfile === "standard";

  async function savePolicy() {
    setPhase({ kind: "busy" });
    try {
      const updated = await api.updateCompliancePolicy({
        privacy_profile: privacyProfile,
        presets: [preset],
        override_legal_basis: overrideBasis || undefined,
        capture_level: captureLevel,
        step_up: stepUpToken.trim().length > 0,
        step_up_token: stepUpToken.trim() || undefined,
      });
      setStepUpToken("");
      setPhase({
        kind: "ok",
        message: `Applied ${updated.privacy_profile} privacy regime (${updated.activity_days}d activity / ${updated.audit_days}d audit).`,
      });
      await wsQuery.refetch();
      await onChanged?.();
    } catch (e) {
      setPhase({
        kind: "error",
        message: e instanceof Error ? e.message : "Failed updating compliance privacy settings",
      });
    }
  }

  async function requestReid() {
    setPhase({ kind: "busy" });
    try {
      const created = await api.requestReidentification({
        pseudonym_id: reidPseudo,
        legal_basis: reidLegalBasis,
        reason: reidReason,
      });
      setPhase({
        kind: "ok",
        message: `Created re-identification quorum request ${created.request_id} (${created.approvers.length}/2 approvals).`,
      });
      await wsQuery.refetch();
      await onChanged?.();
    } catch (e) {
      setPhase({
        kind: "error",
        message: e instanceof Error ? e.message : "Failed creating re-identification request",
      });
    }
  }

  async function approveReid(requestId: string) {
    setPhase({ kind: "busy" });
    try {
      const res = await api.approveReidentification({
        request_id: requestId,
      });
      setPhase({
        kind: "ok",
        message: res.resolved_identity
          ? `Quorum reached (2/2). Scoped principal: ${res.resolved_identity}`
          : `Approval recorded (${res.approvers.length}/2). One more distinct approver needed.`,
      });
      await wsQuery.refetch();
      await onChanged?.();
    } catch (e) {
      setPhase({
        kind: "error",
        message: e instanceof Error ? e.message : "Approval failed",
      });
    }
  }

  return (
    <VStack gap={4}>
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

          {phase.kind === "ok" && (
            <Banner status="success" title={phase.message} collapsible={false} />
          )}
          {phase.kind === "error" && (
            <Banner status="error" title={phase.message} collapsible={false} />
          )}

          <div className="grid-2">
            <VStack gap={2}>
              <Text size="sm" weight="semibold">
                Privacy profile
              </Text>
              <UiSdkSegmentedControl
                ariaLabel="Privacy regime profile"
                value={privacyProfile}
                onChange={(next) => setPrivacyProfile(next)}
                options={[
                  { value: "standard", label: "Standard (named)" },
                  { value: "works-council", label: "Works council (pseudonymous)" },
                ]}
              />
              <GrdrSelect
                label="Retention preset"
                value={preset}
                onChange={setPreset}
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
                onChange={setCaptureLevel}
                options={[
                  { value: "metadata-only", label: "Metadata only (strict P8)" },
                  { value: "metadata-and-signals", label: "Metadata + anomaly signals" },
                ]}
              />
              <TextInput
                label="Explicit legal basis override (optional)"
                placeholder="Required when leaving works-council or exceeding ceiling"
                value={overrideBasis}
                onChange={setOverrideBasis}
              />
              {isDowngradingWorksCouncil && (
                <TextInput
                  label="Step-up verification token"
                  type="password"
                  placeholder="Enter GRDR_STEP_UP_TOKEN"
                  value={stepUpToken}
                  onChange={setStepUpToken}
                />
              )}
            </VStack>
          </div>

          {retention && (
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
                isDisabled={phase.kind === "busy" || (isDowngradingWorksCouncil && stepUpToken.trim() === "")}
                onClick={() => void savePolicy()}
              />
            </HStack>
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
            <div className="grid-2">
              <TextInput label="Pseudonym reference" value={reidPseudo} onChange={setReidPseudo} />
              <TextInput label="Legal basis" value={reidLegalBasis} onChange={setReidLegalBasis} />
            </div>
            <TextInput label="Justification" value={reidReason} onChange={setReidReason} />
            <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
              <Text size="sm" color="secondary">
                Requester and approver identities bind to authenticated session tokens.
              </Text>
              <Button
                variant="secondary"
                size="sm"
                label="Submit quorum request"
                isDisabled={phase.kind === "busy"}
                onClick={() => void requestReid()}
              />
            </HStack>

            {(ws?.reid_requests ?? []).map((rq) => (
              <div key={rq.request_id} className="kv-row" style={{ flexWrap: "wrap", gap: 8 }}>
                <VStack gap={0}>
                  <HStack gap={2} align="center" style={{ flexWrap: "wrap" }}>
                    <Text size="sm" weight="semibold" className="mono">
                      {rq.pseudonym_id}
                    </Text>
                    <StatusInline
                      tone={rq.status === "approved" ? "allow" : "ask"}
                      dot
                      label={`${rq.approvers.length}/${rq.required_approvals} approved`}
                    />
                  </HStack>
                  <Text size="sm" color="secondary">
                    {`Requester: ${rq.requester} · ${rq.legal_basis}`}
                  </Text>
                  {rq.resolved_identity && (
                    <StatusInline tone="allow" label={`Unmasked: ${rq.resolved_identity}`} />
                  )}
                </VStack>
                {rq.status === "pending_quorum" && (
                  <Button
                    variant="primary"
                    size="sm"
                    label="Sign off (quorum)"
                    isDisabled={phase.kind === "busy"}
                    onClick={() => void approveReid(rq.request_id)}
                  />
                )}
              </div>
            ))}
          </VStack>
        </Card>

        <Card padding={3}>
          <VStack gap={3}>
            <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
              <Heading level={2}>Quarterly disclosure ledger</Heading>
              <Badge variant="info" label={metrics?.quarter ?? "2026-Q4"} />
            </HStack>
            <div className="metric-strip" style={{ marginBlockStart: 0, paddingBlockStart: 0, borderBlockStart: "none" }}>
              <div className="metric-cell">
                <div className="metric-value tabular">{metrics?.total_reidentifications ?? 0}</div>
                <div className="metric-label">Re-identifications</div>
              </div>
              <div className="metric-cell">
                <div className="metric-value tabular">{metrics?.total_holds ?? 0}</div>
                <div className="metric-label">Legal holds</div>
              </div>
              <div className="metric-cell">
                <div className="metric-value tabular">{metrics?.total_erasures ?? 0}</div>
                <div className="metric-label">Subject erasures</div>
              </div>
              <div className="metric-cell">
                <div className="metric-value tabular">{metrics?.total_exports ?? 0}</div>
                <div className="metric-label">Evidence exports</div>
              </div>
            </div>
            <div className="table-wrap">
              <table className="table responsive-table">
                <thead>
                  <tr>
                    <th>Kind</th>
                    <th>Actor</th>
                    <th>Target</th>
                    <th>Basis</th>
                  </tr>
                </thead>
                <tbody>
                  {(ws?.disclosures ?? []).map((entry) => (
                    <tr key={entry.id}>
                      <td data-label="Kind">
                        <StatusInline
                          tone={entry.kind === "legal_hold" ? "ask" : "neutral"}
                          dot
                          label={capitalizeLabel(entry.kind.replace(/_/g, " "))}
                        />
                      </td>
                      <td data-label="Actor">{entry.actor}</td>
                      <td data-label="Target" className="mono">{entry.target_ref}</td>
                      <td data-label="Basis">{entry.legal_basis}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </VStack>
        </Card>
      </div>
    </VStack>
  );
}
