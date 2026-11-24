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
  Heading,
  HStack,
  Text,
  TextInput,
  VStack,
} from "@grdr/ui";

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
    </VStack>
  );
}
