import { useState } from "react";
import {
  api,
  type ApprovalRequest,
  type Finding,
  type FindingLifecycle,
  type GrantScope,
  type Incident,
  type KillScope,
  type KillSwitchState,
} from "@grdr/api";
import { ApprovalCard, Quoted, SessionLabelBadge } from "@grdr/kit";
import {
  Badge,
  Banner,
  Button,
  Card,
  GrdrIcon,
  HarnessIcon,
  Heading,
  HStack,
  Text,
  TextInput,
  VStack,
} from "@grdr/ui";

const MATRIX_ENDPOINTS = ["Claude", "Claude Code", "Cursor", "Codex", "Gemini", "GitHub Copilot", "OpenCode", "Windsurf"];
const MATRIX_MODELS = ["Anthropic", "OpenAI", "Google", "AWS Bedrock", "Meta Llama", "Mistral"];
const MATRIX_GATEWAYS = ["MCP Broker", "Guardrails Proxy", "LiteLLM", "Kong", "Azure AI Foundry", "Portkey"];

export function RespondPage({
  approvals,
  findings,
  incidents,
  killSwitch,
  defaultSessionId,
  onUpdated,
}: {
  approvals: ApprovalRequest[];
  findings: Finding[];
  incidents: Incident[];
  killSwitch: KillSwitchState;
  defaultSessionId: string;
  onUpdated: () => void;
}) {
  const [error, setError] = useState<string | null>(null);
  const [exportStatus, setExportStatus] = useState<string | null>(null);

  const [scope, setScope] = useState<KillScope>("session");
  const [targetId, setTargetId] = useState(defaultSessionId || "sess-demo-refactor");
  const [killReason, setKillReason] = useState("Containment triggered by operator during triage");
  const [confirmKill, setConfirmKill] = useState(false);
  const [killModalOpen, setKillModalOpen] = useState(false);
  const [matrixQuery, setMatrixQuery] = useState("");
  const [matrixConfirmPhrase, setMatrixConfirmPhrase] = useState("");
  const [blockedAgents, setBlockedAgents] = useState<string[]>(MATRIX_ENDPOINTS);
  const [blockedModels, setBlockedModels] = useState<string[]>(MATRIX_MODELS);
  const [blockedGateways, setBlockedGateways] = useState<string[]>(MATRIX_GATEWAYS);

  const pending = approvals.filter((a) => a.state.status === "pending");

  async function handleAllow(reqId: string, grantScope: GrantScope) {
    try {
      await api.decideApproval(reqId, true, grantScope, "Approved via Respond console");
      onUpdated();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function handleDeny(reqId: string) {
    try {
      await api.decideApproval(reqId, false, "once", "Denied in Respond console");
      onUpdated();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function handleFindingStatus(id: string, lifecycle: FindingLifecycle) {
    try {
      await api.updateFinding(id, lifecycle);
      onUpdated();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function handleKillSwitch(action: "freeze" | "kill" | "release") {
    setError(null);
    try {
      await api.setKillSwitch({
        action,
        scope,
        target_id: scope === "organisation" ? "*" : targetId,
        reason: killReason,
        duration_minutes: action === "freeze" ? 60 : undefined,
      });
      setConfirmKill(false);
      onUpdated();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  return (
    <VStack gap={4}>
      <div className="page-header">
        <div>
          <Heading level={1}>Respond</Heading>
          <Text color="secondary">
            Approve or deny pending step-up requests (1-second armed delay prevents misclicks), review findings, export telemetry, and engage containment.
          </Text>
        </div>
        <Button
          variant="destructive"
          label="Open kill switch matrix"
          icon={<GrdrIcon name="alert-octagon" size={14} />}
          onClick={() => setKillModalOpen(true)}
        />
      </div>

      <div className="metric-strip" style={{ marginBlockStart: 0, paddingBlockStart: 0, borderBlockStart: "none" }}>
        <div className="metric-cell">
          <div className="metric-value tabular">{pending.length}</div>
          <div className="metric-label">Waiting approvals</div>
          <div className="kpi-bar">
            <div style={{ width: `${Math.min(100, pending.length * 25 + 15)}%`, background: "var(--tone-ask)" }} />
          </div>
        </div>
        <div className="metric-cell">
          <div className="metric-value tabular">{findings.length}</div>
          <div className="metric-label">Open findings</div>
          <div className="kpi-bar">
            <div style={{ width: "30%", background: "var(--tone-block)" }} />
            <div style={{ width: "45%", background: "var(--tone-ask)" }} />
            <div style={{ width: "25%", background: "var(--tone-watch)" }} />
          </div>
        </div>
        <div className="metric-cell">
          <div className="metric-value tabular">{incidents.length}</div>
          <div className="metric-label">Correlated incidents</div>
          <div className="kpi-bar">
            <div style={{ width: "65%", background: "var(--tone-block)" }} />
          </div>
        </div>
        <div className="metric-cell">
          <div className="metric-value tabular">{killSwitch.state}</div>
          <div className="metric-label">Kill switch status</div>
          <div className="kpi-bar">
            <div
              style={{
                width: "100%",
                background: killSwitch.state === "inactive" ? "var(--tone-allow)" : "var(--tone-block)",
              }}
            />
          </div>
        </div>
      </div>

      {error && <Banner status="error" title={error} collapsible={false} />}

      <Card padding={3}>
        <VStack gap={3}>
          <HStack justify="between" align="center">
            <HStack gap={2} align="center">
              <GrdrIcon name="hand" size={16} />
              <Heading level={2}>{`Pending approval queue (${pending.length})`}</Heading>
            </HStack>
            <Badge variant="warning" label="Ethical friction active" />
          </HStack>

          {pending.length === 0 ? (
            <Text color="secondary">No pending approval requests right now.</Text>
          ) : (
            <VStack gap={2}>
              {pending.map((req) => (
                <ApprovalCard
                  key={req.id}
                  id={req.id}
                  ruleTitle={req.rule_title}
                  requiredGrade={req.required_grade}
                  agentName={req.agent_name}
                  actionClass={req.action_class}
                  deviceName={req.device_name}
                  target={req.target}
                  reason={req.reason}
                  onAllow={handleAllow}
                  onDeny={handleDeny}
                />
              ))}
            </VStack>
          )}
        </VStack>
      </Card>

      <Card padding={3}>
        <VStack gap={3}>
          <HStack justify="between" align="center">
            <VStack gap={1}>
              <HStack gap={2} align="center">
                <GrdrIcon name="layers" size={16} />
                <Heading level={2}>{`Correlated incidents (${incidents.length})`}</Heading>
              </HStack>
              <Text color="secondary">
                Findings merged by session lineage, device, and enforcing labels. Export structured telemetry for SIEM ingestion.
              </Text>
            </VStack>
            <HStack gap={2}>
              <Button
                label="Export OCSF 1.9"
                icon={<GrdrIcon name="file-json" size={14} />}
                onClick={async () => {
                  setError(null);
                  setExportStatus(null);
                  try {
                    await api.exportOcsf();
                    setExportStatus("Downloaded guardrails-ocsf-1.9.json");
                  } catch (err) {
                    setError((err as Error).message);
                  }
                }}
              />
              <Button
                label="Export Audit JSONL"
                icon={<GrdrIcon name="download" size={14} />}
                onClick={async () => {
                  setError(null);
                  setExportStatus(null);
                  try {
                    await api.exportAuditJsonl();
                    setExportStatus("Downloaded guardrails-audit.jsonl");
                  } catch (err) {
                    setError((err as Error).message);
                  }
                }}
              />
            </HStack>
          </HStack>

          {exportStatus && <Banner status="info" title={exportStatus} collapsible={false} />}

          {incidents.length === 0 ? (
            <Text color="secondary">No correlated incidents recorded.</Text>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Incident</th>
                    <th>Session & device</th>
                    <th>Labels</th>
                    <th>Severity</th>
                    <th>Lifecycle</th>
                  </tr>
                </thead>
                <tbody>
                  {incidents.map((inc) => (
                    <tr key={inc.id}>
                      <td>
                        <strong>{inc.title}</strong>
                        <Text type="supporting" color="secondary" size="sm">
                          {inc.summary}
                        </Text>
                      </td>
                      <td>
                        <div className="mono">{inc.session_id}</div>
                        <Text color="secondary" size="sm">
                          {inc.device_name}
                        </Text>
                      </td>
                      <td>
                        {inc.labels.length === 0 ? (
                          <Text color="secondary" size="sm">
                            None
                          </Text>
                        ) : (
                          <HStack gap={1}>
                            {inc.labels.map((lbl) => (
                              <SessionLabelBadge key={lbl} label={lbl} />
                            ))}
                          </HStack>
                        )}
                      </td>
                      <td>
                        <Badge
                          variant={
                            inc.severity === "critical" || inc.severity === "high"
                              ? "error"
                              : "warning"
                          }
                          label={inc.severity}
                        />
                      </td>
                      <td>
                        <Badge
                          variant={inc.lifecycle === "resolved" ? "success" : "info"}
                          label={inc.lifecycle}
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

      <div className="grid-2">
        <Card padding={3}>
          <VStack gap={3}>
            <Heading level={2}>{`Findings (${findings.length})`}</Heading>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Finding</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Transition</th>
                  </tr>
                </thead>
                <tbody>
                  {findings.map((f) => (
                    <tr key={f.id}>
                      <td>
                        <strong>{f.title}</strong>
                        <div style={{ marginTop: 4 }}>
                          <Quoted text={f.target} />
                        </div>
                      </td>
                      <td>
                        <Badge
                          variant={
                            f.severity === "critical" || f.severity === "high"
                              ? "error"
                              : "warning"
                          }
                          label={f.severity}
                        />
                      </td>
                      <td>
                        <Badge
                          variant={f.lifecycle === "resolved" ? "success" : "info"}
                          label={f.lifecycle}
                        />
                      </td>
                      <td>
                        <HStack gap={1}>
                          {f.lifecycle === "open" && (
                            <Button
                              size="sm"
                              label="Acknowledge"
                              onClick={() => void handleFindingStatus(f.id, "acknowledged")}
                            />
                          )}
                          {f.lifecycle !== "resolved" && (
                            <Button
                              size="sm"
                              label="Resolve"
                              icon={<GrdrIcon name="check" size={12} />}
                              onClick={() => void handleFindingStatus(f.id, "resolved")}
                            />
                          )}
                        </HStack>
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
              <HStack gap={2} align="center">
                <GrdrIcon name="shield-off" size={16} />
                <Heading level={2}>Scoped kill switch</Heading>
              </HStack>
              <Badge
                variant={killSwitch.state === "inactive" ? "success" : "error"}
                label={killSwitch.state}
              />
            </HStack>

            <div className="form-grid">
              <div className="field">
                <label htmlFor="ks-scope">Scope</label>
                <select
                  id="ks-scope"
                  value={scope}
                  onChange={(e) => setScope(e.target.value as KillScope)}
                >
                  <option value="session">Session</option>
                  <option value="device">Device</option>
                  <option value="organisation">Organisation</option>
                </select>
              </div>
              <TextInput
                label="Target ID"
                value={scope === "organisation" ? "*" : targetId}
                isDisabled={scope === "organisation"}
                onChange={(val) => setTargetId(val)}
              />
              <div className="field full">
                <TextInput
                  label="Audit reason"
                  value={killReason}
                  onChange={(val) => setKillReason(val)}
                  width="100%"
                />
              </div>
              <div className="field full" style={{ flexDirection: "row", alignItems: "center", gap: 8 }}>
                <input
                  id="ks-confirm"
                  type="checkbox"
                  checked={confirmKill}
                  onChange={(e) => setConfirmKill(e.target.checked)}
                />
                <label htmlFor="ks-confirm" style={{ margin: 0 }}>
                  Confirm containment action stops all matching agent actions immediately
                </label>
              </div>
              <div className="field full" style={{ flexDirection: "row", flexWrap: "wrap", gap: 8 }}>
                <Button
                  label="Freeze (60 min)"
                  isDisabled={!confirmKill}
                  onClick={() => void handleKillSwitch("freeze")}
                />
                <Button
                  variant="destructive"
                  label="Engage kill switch"
                  icon={<GrdrIcon name="alert-octagon" size={14} />}
                  isDisabled={!confirmKill}
                  data-agent-confirm="Confirm stopping all matching agent sessions immediately"
                  onClick={() => void handleKillSwitch("kill")}
                />
                <Button
                  variant="secondary"
                  label="3-column matrix"
                  onClick={() => setKillModalOpen(true)}
                />
                {killSwitch.state !== "inactive" && (
                  <Button
                    variant="primary"
                    label="Release"
                    onClick={() => void handleKillSwitch("release")}
                  />
                )}
              </div>
            </div>
          </VStack>
        </Card>
      </div>

      {killModalOpen && (
        <div className="killswitch-backdrop" role="dialog" aria-modal="true" aria-label="Scoped Kill Switch Matrix">
          <div className="killswitch-dialog">
            <HStack justify="between" align="center">
              <HStack gap={2} align="center">
                <GrdrIcon name="shield-off" size={18} color="var(--tone-block)" />
                <Heading level={2}>Scoped Kill Switch</Heading>
              </HStack>
              <Button size="sm" label="Close" icon={<GrdrIcon name="x" size={14} />} onClick={() => setKillModalOpen(false)} />
            </HStack>

            <Banner
              status="error"
              title="Terminate and block AI on the endpoint and at the gateway"
              collapsible={false}
            />

            <TextInput
              label="Filter endpoints, model providers, or gateways"
              value={matrixQuery}
              onChange={setMatrixQuery}
              width="100%"
            />

            <div className="killswitch-cols">
              <div className="killswitch-col">
                <strong>{`Endpoint (${blockedAgents.length}/${MATRIX_ENDPOINTS.length})`}</strong>
                {MATRIX_ENDPOINTS.filter((a) => a.toLowerCase().includes(matrixQuery.toLowerCase())).map((ag) => (
                  <label key={ag} className="killswitch-check">
                    <input
                      type="checkbox"
                      checked={blockedAgents.includes(ag)}
                      onChange={(e) =>
                        setBlockedAgents((prev) =>
                          e.target.checked ? [...prev, ag] : prev.filter((x) => x !== ag),
                        )
                      }
                    />
                    <HarnessIcon name={ag} size={14} />
                    <span>{ag}</span>
                  </label>
                ))}
              </div>

              <div className="killswitch-col">
                <strong>{`Model providers (${blockedModels.length}/${MATRIX_MODELS.length})`}</strong>
                {MATRIX_MODELS.filter((m) => m.toLowerCase().includes(matrixQuery.toLowerCase())).map((m) => (
                  <label key={m} className="killswitch-check">
                    <input
                      type="checkbox"
                      checked={blockedModels.includes(m)}
                      onChange={(e) =>
                        setBlockedModels((prev) =>
                          e.target.checked ? [...prev, m] : prev.filter((x) => x !== m),
                        )
                      }
                    />
                    <HarnessIcon name={m} size={14} />
                    <span>{m}</span>
                  </label>
                ))}
              </div>

              <div className="killswitch-col">
                <strong>{`Gateways (${blockedGateways.length}/${MATRIX_GATEWAYS.length})`}</strong>
                {MATRIX_GATEWAYS.filter((g) => g.toLowerCase().includes(matrixQuery.toLowerCase())).map((g) => (
                  <label key={g} className="killswitch-check">
                    <input
                      type="checkbox"
                      checked={blockedGateways.includes(g)}
                      onChange={(e) =>
                        setBlockedGateways((prev) =>
                          e.target.checked ? [...prev, g] : prev.filter((x) => x !== g),
                        )
                      }
                    />
                    <GrdrIcon name="server" size={14} />
                    <span>{g}</span>
                  </label>
                ))}
              </div>
            </div>

            <HStack justify="between" align="end" style={{ gap: 12, flexWrap: "wrap" }}>
              <div style={{ flex: 1, minWidth: 260 }}>
                <TextInput
                  label="Enter target scope confirmation (type: fleet-kill)"
                  value={matrixConfirmPhrase}
                  onChange={setMatrixConfirmPhrase}
                  width="100%"
                />
              </div>
              <HStack gap={2}>
                <Button label="Cancel" onClick={() => setKillModalOpen(false)} />
                <Button
                  variant="destructive"
                  icon={<GrdrIcon name="alert-octagon" size={14} />}
                  label={`Activate kill switch (${blockedAgents.length + blockedModels.length + blockedGateways.length})`}
                  isDisabled={matrixConfirmPhrase.trim().toLowerCase() !== "fleet-kill"}
                  data-agent-confirm="Confirm fleet-wide kill switch"
                  onClick={async () => {
                    await handleKillSwitch("kill");
                    setKillModalOpen(false);
                  }}
                />
              </HStack>
            </HStack>
          </div>
        </div>
      )}
    </VStack>
  );
}
