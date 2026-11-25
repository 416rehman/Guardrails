import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, type ComplianceWorkspaceResponse } from "@grdr/api";
import { capitalizeLabel } from "@grdr/i18n";
import { Quoted } from "@grdr/kit";
import {
  Badge,
  Banner,
  Button,
  Card,
  GrdrIcon,
  Heading,
  HStack,
  ProgressBar,
  StatusInline,
  Text,
  TextInput,
  VStack,
} from "@grdr/ui";
import { consoleQueryKeys } from "../queries";

type ComplyPhase =
  | { kind: "idle" }
  | { kind: "busy"; op: string }
  | { kind: "ok"; message: string }
  | { kind: "error"; message: string };

export function CompliancePage({
  onChanged,
}: {
  onChanged?: () => Promise<void>;
}) {
  const wsQuery = useQuery<ComplianceWorkspaceResponse>({
    queryKey: consoleQueryKeys.complianceWorkspace(),
    queryFn: () => api.getComplianceWorkspace(),
  });

  const [matterRef, setMatterRef] = useState("MATTER-2026-042");
  const [holdTarget, setHoldTarget] = useState("prn_92e04ab11f88");
  const [holdReason, setHoldReason] = useState("Preserve endpoint decision logs for quarterly audit");
  const [phase, setPhase] = useState<ComplyPhase>({ kind: "idle" });

  const ws = wsQuery.data;

  async function runExport(format: "oscal-component" | "oscal-assessment" | "csv" | "markdown") {
    setPhase({ kind: "busy", op: format });
    try {
      const artifact = await api.exportComplianceArtifact({
        format,
      });
      const blob = new Blob([artifact.payload], { type: artifact.content_type });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = artifact.filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      setPhase({
        kind: "ok",
        message: `Generated ${artifact.filename} (OSCAL ${artifact.oscal_version}, sha256:${artifact.digest.slice(0, 12)})`,
      });
      await wsQuery.refetch();
      await onChanged?.();
    } catch (e) {
      setPhase({
        kind: "error",
        message: e instanceof Error ? e.message : "Export failed",
      });
    }
  }

  async function pushGrc(target: "ciso-assistant" | "probo") {
    setPhase({ kind: "busy", op: target });
    try {
      const res = await api.pushGrcEvidence({
        target,
      });
      setPhase({ kind: "ok", message: `${res.summary} (${res.envelope_id})` });
      await wsQuery.refetch();
      await onChanged?.();
    } catch (e) {
      setPhase({
        kind: "error",
        message: e instanceof Error ? e.message : "GRC evidence push failed",
      });
    }
  }

  async function submitHold() {
    setPhase({ kind: "busy", op: "hold" });
    try {
      const hold = await api.createLegalHold({
        matter_ref: matterRef,
        reason: holdReason,
        pseudonym_or_session: holdTarget,
      });
      setPhase({
        kind: "ok",
        message: `Staged legal hold ${hold.hold_id} on ${hold.scope_summary} (${hold.approvers.length}/2 quorum)`,
      });
      await wsQuery.refetch();
      await onChanged?.();
    } catch (e) {
      setPhase({
        kind: "error",
        message: e instanceof Error ? e.message : "Failed placing legal hold",
      });
    }
  }

  async function cosignHold(holdId: string) {
    setPhase({ kind: "busy", op: holdId });
    try {
      const hold = await api.approveLegalHold({
        hold_id: holdId,
        note: "Co-signed in Compliance workspace",
      });
      setPhase({
        kind: "ok",
        message: `Legal hold ${hold.hold_id} updated (${hold.lifecycle})`,
      });
      await wsQuery.refetch();
      await onChanged?.();
    } catch (e) {
      setPhase({
        kind: "error",
        message: e instanceof Error ? e.message : "Failed co-signing legal hold",
      });
    }
  }

  return (
    <VStack gap={4}>
      <Card padding={3}>
        <VStack gap={3}>
          <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
            <VStack gap={0}>
              <Heading level={1}>Compliance & integrations</Heading>
              <Text size="sm" color="secondary">
                Live capability evidence, OSCAL 1.2.3 exports, dual-approver legal holds, and SaaS / GRC connectors.
              </Text>
            </VStack>
            <HStack gap={2} style={{ flexWrap: "wrap" }}>
              <Button
                variant="secondary"
                size="sm"
                icon={<GrdrIcon name="file-json" size={14} />}
                label="Export OSCAL 1.2.3 Component"
                isDisabled={phase.kind === "busy"}
                onClick={() => void runExport("oscal-component")}
              />
              <Button
                variant="secondary"
                size="sm"
                icon={<GrdrIcon name="download" size={14} />}
                label="Export Assessment JSON"
                isDisabled={phase.kind === "busy"}
                onClick={() => void runExport("oscal-assessment")}
              />
              <Button
                variant="secondary"
                size="sm"
                icon={<GrdrIcon name="download" size={14} />}
                label="Export CSV"
                isDisabled={phase.kind === "busy"}
                onClick={() => void runExport("csv")}
              />
            </HStack>
          </HStack>

          {phase.kind === "ok" && (
            <Banner status="success" title={phase.message} collapsible={false} />
          )}
          {phase.kind === "error" && (
            <Banner status="error" title={phase.message} collapsible={false} />
          )}
        </VStack>
      </Card>

      <Card padding={3}>
        <VStack gap={3}>
          <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
            <Heading level={2}>Framework crosswalk readiness</Heading>
            <Badge
              variant="info"
              label={
                ws?.retention
                  ? `${ws.retention.privacy_profile} ceiling · ${ws.retention.activity_days}d activity`
                  : "Loading..."
              }
            />
          </HStack>
          <div className="grid-2">
            {(ws?.frameworks ?? []).map((fw) => (
              <Card key={fw.framework_id} padding={2}>
                <VStack gap={1}>
                  <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 6 }}>
                    <Text size="sm" weight="semibold">
                      {fw.display_title}
                    </Text>
                    <Text
                      size="sm"
                      color="secondary"
                      hasTabularNumbers
                      style={{ whiteSpace: "nowrap", flexShrink: 0 }}
                    >
                      {`${fw.addressed_controls}/${fw.total_controls} controls · ${fw.coverage_percent}%`}
                    </Text>
                  </HStack>
                  <ProgressBar
                    label={fw.display_title}
                    isLabelHidden
                    value={fw.coverage_percent}
                    max={100}
                    variant={fw.coverage_percent >= 75 ? "success" : "accent"}
                  />
                </VStack>
              </Card>
            ))}
          </div>
        </VStack>
      </Card>

      <div className="grid-2">
        <Card padding={3}>
          <VStack gap={2}>
            <Heading level={2}>Signed capability evidence</Heading>
            <div className="table-wrap">
              <table className="table responsive-table">
                <thead>
                  <tr>
                    <th>Capability</th>
                    <th>Result</th>
                    <th>Controls</th>
                    <th>Signature</th>
                  </tr>
                </thead>
                <tbody>
                  {(ws?.evidence_items ?? []).map((item) => (
                    <tr key={item.id}>
                      <td data-label="Capability">
                        <VStack gap={0}>
                          <Text size="sm" weight="semibold" className="mono">
                            {item.capability}
                          </Text>
                          <Text size="sm" color="secondary">
                            {item.statement}
                          </Text>
                        </VStack>
                      </td>
                      <td data-label="Result">
                        <StatusInline
                          tone={
                            item.result === "met"
                              ? "allow"
                              : item.result === "partial"
                                ? "ask"
                                : "neutral"
                          }
                          dot
                          label={capitalizeLabel(item.result)}
                        />
                      </td>
                      <td data-label="Controls">
                        <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                          {item.control_refs.slice(0, 3).map((ref) => (
                            <span
                              key={ref}
                              className="mono"
                              style={{ fontSize: 12, whiteSpace: "nowrap" }}
                            >
                              {ref}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td data-label="Signature">
                        <StatusInline
                          tone={item.signature_status === "verified" ? "allow" : "neutral"}
                          label={item.signature_status}
                        />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </VStack>
        </Card>

        <Card padding={3}>
          <VStack gap={3}>
            <HStack justify="between" align="center">
              <Heading level={2}>SaaS & GRC connectors</Heading>
              <Badge variant="neutral" label={`${ws?.connectors.length ?? 0} integrations`} />
            </HStack>
            {(ws?.connectors ?? []).map((conn) => (
              <div key={conn.id} className="kv-row" style={{ flexWrap: "wrap", gap: 8 }}>
                <VStack gap={0}>
                  <HStack gap={2} align="center" style={{ flexWrap: "wrap" }}>
                    <Text size="sm" weight="semibold">
                      {conn.name}
                    </Text>
                    <Badge variant="neutral" label={conn.capture_ceiling} />
                    <StatusInline
                      tone={conn.circuit_state === "closed" ? "allow" : "ask"}
                      label={conn.circuit_state}
                    />
                  </HStack>
                  <Text size="sm" color="secondary">
                    {`${conn.summary} · ${conn.queued_items} queued · ${conn.delivered_items} delivered`}
                  </Text>
                </VStack>
                {(conn.id === "ciso-assistant" || conn.id === "probo") && (
                  <Button
                    variant="secondary"
                    size="sm"
                    label="Push evidence"
                    isDisabled={phase.kind === "busy"}
                    onClick={() => void pushGrc(conn.id as "ciso-assistant" | "probo")}
                  />
                )}
              </div>
            ))}
          </VStack>
        </Card>
      </div>

      <div className="grid-2">
        <Card padding={3}>
          <VStack gap={3}>
            <HStack justify="between" align="center">
              <Heading level={2}>Legal holds ledger</Heading>
              <Badge variant="warning" label="Two-approver quorum" />
            </HStack>
            <div className="grid-2">
              <TextInput label="Matter reference" value={matterRef} onChange={setMatterRef} />
              <TextInput label="Pseudonym or session" value={holdTarget} onChange={setHoldTarget} />
            </div>
            <TextInput label="Preservation rationale" value={holdReason} onChange={setHoldReason} />
            <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
              <Text size="sm" color="secondary">
                Submitting starts 1/2 quorum under your signed-in session. A second principal co-signs to activate.
              </Text>
              <Button
                variant="primary"
                size="sm"
                label="Place legal hold (1/2)"
                isDisabled={phase.kind === "busy"}
                onClick={() => void submitHold()}
              />
            </HStack>
            {(ws?.legal_holds ?? []).map((h) => (
              <div key={h.hold_id} className="kv-row" style={{ flexWrap: "wrap", gap: 8 }}>
                <VStack gap={0}>
                  <Text size="sm" weight="semibold">
                    {h.matter_ref}
                  </Text>
                  <Quoted text={h.scope_summary} />
                  <Text size="sm" color="secondary">
                    {`Approvers (${h.approvers.length}/2): ${h.approvers.join(", ")}`}
                  </Text>
                </VStack>
                <HStack gap={2} align="center">
                  <StatusInline
                    tone={h.lifecycle === "active" ? "allow" : "ask"}
                    dot
                    label={h.lifecycle.replace(/_/g, " ")}
                  />
                  {h.lifecycle === "pending_quorum" && (
                    <Button
                      variant="secondary"
                      size="sm"
                      label="Co-sign hold (quorum)"
                      isDisabled={phase.kind === "busy"}
                      onClick={() => void cosignHold(h.hold_id)}
                    />
                  )}
                </HStack>
              </div>
            ))}
          </VStack>
        </Card>

        <Card padding={3}>
          <VStack gap={2}>
            <Heading level={2}>Subject access & erasure requests</Heading>
            <div className="table-wrap">
              <table className="table responsive-table">
                <thead>
                  <tr>
                    <th>Request</th>
                    <th>Kind</th>
                    <th>Subject ref</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {(ws?.subject_requests ?? []).map((sr) => (
                    <tr key={sr.request_id}>
                      <td data-label="Request" className="mono">{sr.request_id}</td>
                      <td data-label="Kind">{sr.kind}</td>
                      <td data-label="Subject ref" className="mono">{sr.subject_ref}</td>
                      <td data-label="Status">
                        <StatusInline
                          tone={sr.status === "pending_held" ? "ask" : "allow"}
                          dot
                          label={sr.status === "pending_held" ? "Held by legal hold" : "Executed"}
                        />
                      </td>
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
