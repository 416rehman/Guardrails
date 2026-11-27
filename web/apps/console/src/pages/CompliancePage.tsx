// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, type ComplianceWorkspaceResponse } from "@grdr/api";
import { capitalizeLabel } from "@grdr/i18n";
import {
  Badge,
  Banner,
  Button,
  Card,
  EmptyState,
  GrdrIcon,
  GrdrSelect,
  Heading,
  HStack,
  ProgressBar,
  StatusInline,
  Text,
  VStack,
} from "@grdr/ui";
import { consoleQueryKeys } from "../queries";
import { ComplianceGovernanceSection } from "./ComplianceGovernanceSection";

type ExportFormat = "oscal-component" | "oscal-assessment" | "csv" | "markdown";
type GrcTarget = "ciso-assistant" | "probo";

type ComplyPhase =
  | { kind: "idle" }
  | { kind: "busy"; op: string }
  | { kind: "ok"; message: string }
  | { kind: "error"; message: string };

const ALLOWED_DOWNLOAD_MIME = new Set([
  "text/plain",
  "application/json",
  "text/csv",
  "text/markdown",
  "application/xml",
]);

function isExportFormat(value: string): value is ExportFormat {
  return (
    value === "oscal-component" ||
    value === "oscal-assessment" ||
    value === "csv" ||
    value === "markdown"
  );
}

function isGrcTarget(value: string): value is GrcTarget {
  return value === "ciso-assistant" || value === "probo";
}

function sanitizeDownloadFilename(raw: string, fallback: string): string {
  const leaf = raw.replace(/[\u0000-\u001f\u007f]/g, "").split(/[\\/]/).pop() ?? "";
  const clean = leaf.replace(/\.\.+/g, ".").replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^[.-]+/, "");
  return clean.length > 0 ? clean : fallback;
}

function downloadTextBlob(filename: string, contentType: string, payload: string) {
  const safeName = sanitizeDownloadFilename(filename, "guardrails-compliance-export.txt");
  const normalized = contentType.split(";")[0]?.trim().toLowerCase() ?? "";
  const safeMime = ALLOWED_DOWNLOAD_MIME.has(normalized) ? normalized : "text/plain";
  const blob = new Blob([payload], { type: safeMime });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = safeName;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function parseJsonUnknown(raw: string): unknown {
  return JSON.parse(raw);
}

export function CompliancePage({ onChanged }: { onChanged?: () => Promise<void> }) {
  const wsQuery = useQuery<ComplianceWorkspaceResponse>({
    queryKey: consoleQueryKeys.complianceWorkspace(),
    queryFn: () => api.getComplianceWorkspace(),
  });

  const [matterRef, setMatterRef] = useState(`MATTER-${new Date().getFullYear()}-001`);
  const [customHoldTarget, setCustomHoldTarget] = useState<string | undefined>(undefined);
  const [holdReason, setHoldReason] = useState("Preserve endpoint decision logs for quarterly audit");
  const [selectedFramework, setSelectedFramework] = useState("all");
  const [exportFormat, setExportFormat] = useState<ExportFormat>("oscal-component");
  const [phase, setPhase] = useState<ComplyPhase>({ kind: "idle" });

  const ws = wsQuery.data;
  const holdTarget =
    customHoldTarget ??
    ws?.subject_requests[0]?.subject_ref ??
    ws?.legal_holds[0]?.scope_summary ??
    "";

  async function runExport(format: ExportFormat) {
    setPhase({ kind: "busy", op: format });
    try {
      const artifact = await api.exportComplianceArtifact({
        format,
        framework_id: selectedFramework === "all" ? undefined : selectedFramework,
      });
      downloadTextBlob(artifact.filename, artifact.content_type, artifact.payload);
      setPhase({
        kind: "ok",
        message: `Generated ${artifact.filename} (OSCAL ${artifact.oscal_version}, sha256:${artifact.digest.slice(0, 12)})`,
      });
      await wsQuery.refetch();
      await onChanged?.();
    } catch (e) {
      setPhase({ kind: "error", message: e instanceof Error ? e.message : "Export failed" });
    }
  }

  async function downloadExitBundle() {
    setPhase({ kind: "busy", op: "exit-bundle" });
    try {
      const oscal = await api.exportComplianceArtifact({
        format: "oscal-assessment",
        framework_id: selectedFramework === "all" ? undefined : selectedFramework,
      });
      const bundle = {
        bundle_version: "1.0",
        generated_at: new Date().toISOString(),
        retention_policy: ws?.retention ?? null,
        frameworks: ws?.frameworks ?? [],
        legal_holds: ws?.legal_holds ?? [],
        subject_requests: ws?.subject_requests ?? [],
        disclosure_metrics: ws?.disclosure_metrics ?? null,
        disclosures: ws?.disclosures ?? [],
        oscal_assessment_digest: oscal.digest,
        oscal_assessment: parseJsonUnknown(oscal.payload),
      };
      downloadTextBlob("guardrails-compliance-exit-bundle.json", "application/json", JSON.stringify(bundle, null, 2));
      setPhase({
        kind: "ok",
        message: `Downloaded portable exit bundle with OSCAL assessment digest sha256:${oscal.digest.slice(0, 12)}.`,
      });
      await wsQuery.refetch();
      await onChanged?.();
    } catch (e) {
      setPhase({ kind: "error", message: e instanceof Error ? e.message : "Failed assembling exit bundle" });
    }
  }

  async function pushGrc(target: GrcTarget) {
    setPhase({ kind: "busy", op: target });
    try {
      const res = await api.pushGrcEvidence({ target });
      setPhase({ kind: "ok", message: `${res.summary} (${res.envelope_id})` });
      await wsQuery.refetch();
      await onChanged?.();
    } catch (e) {
      setPhase({ kind: "error", message: e instanceof Error ? e.message : "GRC evidence push failed" });
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
      setPhase({ kind: "error", message: e instanceof Error ? e.message : "Failed placing legal hold" });
    }
  }

  async function cosignHold(holdId: string) {
    setPhase({ kind: "busy", op: holdId });
    try {
      const hold = await api.approveLegalHold({
        hold_id: holdId,
        note: "Co-signed in Compliance workspace",
      });
      setPhase({ kind: "ok", message: `Legal hold ${hold.hold_id} updated (${hold.lifecycle})` });
      await wsQuery.refetch();
      await onChanged?.();
    } catch (e) {
      setPhase({ kind: "error", message: e instanceof Error ? e.message : "Failed co-signing legal hold" });
    }
  }

  const metrics = ws?.disclosure_metrics;
  const frameworkOptions = [
    { value: "all", label: "All frameworks" },
    ...(ws?.frameworks ?? []).map((f) => ({ value: f.framework_id, label: f.display_title })),
  ];

  return (
    <VStack gap={4}>
      {wsQuery.isError && (
        <Banner
          status="error"
          title={wsQuery.error instanceof Error ? wsQuery.error.message : "Failed loading compliance workspace."}
          collapsible={false}
          endContent={<Button variant="secondary" size="sm" label="Retry" onClick={() => void wsQuery.refetch()} />}
        />
      )}

      <Card padding={3}>
        <VStack gap={3}>
          <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
            <VStack gap={0}>
              <Heading level={1}>Compliance & integrations</Heading>
              <Text size="sm" color="secondary">
                Live capability evidence, OSCAL 1.2.3 exports, dual-approver legal holds, and SaaS or GRC connectors.
              </Text>
            </VStack>
            <HStack gap={2} align="center" style={{ flexWrap: "wrap" }}>
              <GrdrSelect
                label="Framework export scope"
                isLabelHidden
                size="sm"
                variant="secondary"
                value={selectedFramework}
                options={frameworkOptions}
                onChange={setSelectedFramework}
              />
              <GrdrSelect
                label="Export format"
                isLabelHidden
                size="sm"
                variant="secondary"
                value={exportFormat}
                options={[
                  { value: "oscal-component", label: "OSCAL 1.2.3 Component" },
                  { value: "oscal-assessment", label: "Assessment JSON" },
                  { value: "csv", label: "Controls CSV" },
                  { value: "markdown", label: "Summary Markdown" },
                ]}
                onChange={(val) => {
                  if (isExportFormat(val)) setExportFormat(val);
                }}
              />
              <Button
                variant="secondary"
                size="sm"
                icon={<GrdrIcon name="file-text" size={14} />}
                label="Export"
                isDisabled={phase.kind === "busy"}
                onClick={() => void runExport(exportFormat)}
              />
              <Button
                variant="primary"
                size="sm"
                icon={<GrdrIcon name="download" size={14} />}
                label="Download Exit Bundle"
                isDisabled={phase.kind === "busy" || wsQuery.isLoading}
                onClick={() => void downloadExitBundle()}
              />
            </HStack>
          </HStack>

          <div
            className="metric-strip"
            style={{ marginBlockStart: 0, paddingBlockStart: 8, borderBlockStart: "1px solid var(--border-subtle)" }}
          >
            <div className="metric-cell">
              <div className="metric-value tabular">{ws?.frameworks.length ?? 0}</div>
              <div className="metric-label">Mapped frameworks</div>
              <div className="metric-note">{metrics?.quarter ?? "Current quarter"}</div>
            </div>
            <div className="metric-cell">
              <div className="metric-value tabular">{metrics?.total_holds ?? 0}</div>
              <div className="metric-label">Legal holds</div>
              <div className="metric-note">Two-approver quorum</div>
            </div>
            <div className="metric-cell">
              <div className="metric-value tabular">{metrics?.total_erasures ?? 0}</div>
              <div className="metric-label">Subject erasures</div>
              <div className="metric-note">{`${ws?.subject_requests.length ?? 0} total DSARs`}</div>
            </div>
            <div className="metric-cell">
              <div className="metric-value tabular">{metrics?.total_exports ?? 0}</div>
              <div className="metric-label">Evidence exports</div>
              <div className="metric-note">Signed audit digests</div>
            </div>
          </div>

          {phase.kind === "ok" && <Banner status="success" title={phase.message} collapsible={false} />}
          {phase.kind === "error" && <Banner status="error" title={phase.message} collapsible={false} />}
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
                  : wsQuery.isLoading
                    ? "Loading..."
                    : "Unavailable"
              }
            />
          </HStack>
          {wsQuery.isLoading ? (
            <Text size="sm" color="secondary">Loading framework crosswalks...</Text>
          ) : (ws?.frameworks.length ?? 0) === 0 ? (
            <EmptyState
              title="No compliance frameworks loaded"
              description="Install a compliance crosswalk pack to evaluate product capability coverage."
              icon={<GrdrIcon name="shield-check" size={20} />}
            />
          ) : (
            <div className="grid-2">
              {(ws?.frameworks ?? []).map((fw) => (
                <Card key={fw.framework_id} padding={2}>
                  <VStack gap={1}>
                    <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 6 }}>
                      <Text size="sm" weight="semibold">{fw.display_title}</Text>
                      <Text size="sm" color="secondary" hasTabularNumbers style={{ whiteSpace: "nowrap", flexShrink: 0 }}>
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
          )}
        </VStack>
      </Card>

      <div className="grid-2">
        <Card padding={3}>
          <VStack gap={2}>
            <Heading level={2}>Signed capability evidence</Heading>
            {(ws?.evidence_items.length ?? 0) === 0 ? (
              <EmptyState
                title="No capability evidence recorded yet"
                description="Live evidence items populate once endpoints report receipts and policy evaluations."
                icon={<GrdrIcon name="file-text" size={20} />}
              />
            ) : (
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
                            <Text size="sm" weight="semibold" className="mono">{item.capability}</Text>
                            <Text size="sm" color="secondary">{item.statement}</Text>
                          </VStack>
                        </td>
                        <td data-label="Result">
                          <StatusInline
                            tone={item.result === "met" ? "allow" : item.result === "partial" ? "ask" : "neutral"}
                            dot
                            label={capitalizeLabel(item.result)}
                          />
                        </td>
                        <td data-label="Controls">
                          <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                            {item.control_refs.slice(0, 3).map((ref) => (
                              <span key={ref} className="mono" style={{ fontSize: 12, whiteSpace: "nowrap" }}>{ref}</span>
                            ))}
                          </div>
                        </td>
                        <td data-label="Signature">
                          <StatusInline
                            tone={item.signature_status === "verified" ? "allow" : "neutral"}
                            label={capitalizeLabel(item.signature_status)}
                          />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </VStack>
        </Card>

        <Card padding={3}>
          <VStack gap={3}>
            <HStack justify="between" align="center">
              <Heading level={2}>SaaS & GRC connectors</Heading>
              <Badge variant="neutral" label={`${ws?.connectors.length ?? 0} integrations`} />
            </HStack>
            {(ws?.connectors.length ?? 0) === 0 ? (
              <EmptyState
                title="No GRC or SaaS compliance connectors configured"
                description="Configure CISO Assistant, Probo, or SaaS compliance pulls in deployment configuration."
                icon={<GrdrIcon name="plug" size={20} />}
              />
            ) : (
              <div className="checklist">
                {(ws?.connectors ?? []).map((conn) => {
                  const grcTarget = isGrcTarget(conn.id) ? conn.id : null;
                  return (
                    <div key={conn.id} className="check-row" style={{ flexWrap: "wrap", gap: 8 }}>
                      <VStack gap={0}>
                        <HStack gap={2} align="center" style={{ flexWrap: "wrap" }}>
                          <Text size="sm" weight="semibold">{conn.name}</Text>
                          <Badge variant="neutral" label={conn.capture_ceiling} />
                          <StatusInline
                            tone={conn.circuit_state === "closed" ? "allow" : "ask"}
                            label={capitalizeLabel(conn.circuit_state.replace(/_/g, " "))}
                          />
                        </HStack>
                        <Text size="sm" color="secondary">
                          {`${conn.summary} · ${conn.queued_items} queued · ${conn.delivered_items} delivered`}
                        </Text>
                      </VStack>
                      {grcTarget && (
                        <Button
                          variant="secondary"
                          size="sm"
                          label="Push evidence"
                          isDisabled={phase.kind === "busy"}
                          onClick={() => void pushGrc(grcTarget)}
                        />
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </VStack>
        </Card>
      </div>

      <ComplianceGovernanceSection
        matterRef={matterRef}
        onChangeMatterRef={setMatterRef}
        holdTarget={holdTarget}
        onChangeHoldTarget={setCustomHoldTarget}
        holdReason={holdReason}
        onChangeHoldReason={setHoldReason}
        busy={phase.kind === "busy"}
        legalHolds={ws?.legal_holds ?? []}
        subjectRequests={ws?.subject_requests ?? []}
        onSubmitHold={() => void submitHold()}
        onCosignHold={(id) => void cosignHold(id)}
      />
    </VStack>
  );
}
