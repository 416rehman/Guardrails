import { useState } from "react";
import {
  api,
  type ApprovalRequest,
  type Device,
  type Finding,
  type FindingLifecycle,
  type GrantScope,
  type Incident,
  type KillScope,
  type KillSwitchState,
} from "@grdr/api";
import { capitalizeLabel, presentFindingTitle, presentIncidentSummary } from "@grdr/i18n";
import { ApprovalCard, EntityLink, type EntityTarget, Quoted, SessionLabelBadge } from "@grdr/kit";
import {
  Badge,
  Banner,
  Button,
  Card,
  GrdrIcon,
  Heading,
  HStack,
  Text,
  VStack,
} from "@grdr/ui";
import { KillSwitchSection, type KillSwitchFlow } from "./KillSwitchControls";

type RespondFeedback =
  | { kind: "idle" }
  | { kind: "error"; message: string }
  | { kind: "exported"; message: string };

export function RespondPage({
  approvals,
  findings,
  incidents,
  devices = [],
  killSwitch,
  defaultSessionId,
  onOpenEntity,
  onOpenSessionTurn,
  onUpdated,
}: {
  approvals: ApprovalRequest[];
  findings: Finding[];
  incidents: Incident[];
  devices?: Device[];
  killSwitch: KillSwitchState;
  defaultSessionId: string;
  onOpenEntity?: (target: EntityTarget) => void;
  onOpenSessionTurn?: (sessionId: string, turnIndex: number) => void;
  onUpdated: () => void;
}) {
  const [feedback, setFeedback] = useState<RespondFeedback>({ kind: "idle" });
  const [scope, setScope] = useState<KillScope>("session");
  const [targetId, setTargetId] = useState(defaultSessionId || "sess-demo-refactor");
  const [killReason, setKillReason] = useState("Containment triggered by operator during triage");
  const [killFlow, setKillFlow] = useState<KillSwitchFlow>({ kind: "closed", inlineArmed: false });

  const pending = approvals.filter((a) => a.state.status === "pending");

  async function handleAllow(reqId: string, grantScope: GrantScope) {
    try {
      await api.decideApproval(reqId, true, grantScope, "Approved via Respond console");
      onUpdated();
    } catch (err) {
      setFeedback({ kind: "error", message: (err as Error).message });
    }
  }

  async function handleDeny(reqId: string) {
    try {
      await api.decideApproval(reqId, false, "once", "Denied in Respond console");
      onUpdated();
    } catch (err) {
      setFeedback({ kind: "error", message: (err as Error).message });
    }
  }

  async function handleFindingStatus(id: string, lifecycle: FindingLifecycle) {
    try {
      await api.updateFinding(id, lifecycle);
      onUpdated();
    } catch (err) {
      setFeedback({ kind: "error", message: (err as Error).message });
    }
  }

  async function handleKillSwitch(action: "freeze" | "kill" | "release") {
    setFeedback({ kind: "idle" });
    try {
      await api.setKillSwitch({
        action,
        scope,
        target_id: scope === "organisation" ? "*" : targetId,
        reason: killReason,
        duration_minutes: action === "freeze" ? 60 : undefined,
      });
      setKillFlow({ kind: "closed", inlineArmed: false });
      onUpdated();
    } catch (err) {
      setFeedback({ kind: "error", message: (err as Error).message });
    }
  }

  return (
    <VStack gap={4}>
      <div className="page-header">
        <div>
          <Heading level={1}>Respond</Heading>
          <Text color="secondary">
            Review pending approvals, investigate findings, and stop compromised sessions.
          </Text>
        </div>
        <Button
          variant="destructive"
          label="Open kill switch matrix"
          icon={<GrdrIcon name="alert-octagon" size={14} />}
          onClick={() =>
            setKillFlow({
              kind: "modalOpen",
              blockedAgents: [],
              blockedModels: [],
              blockedGateways: [],
              query: "",
            })
          }
        />
      </div>

      <div className="metric-strip" style={{ marginBlockStart: 0, paddingBlockStart: 0, borderBlockStart: "none" }}>
        <div className="metric-cell">
          <div className="metric-value tabular">{pending.length}</div>
          <div className="metric-label">Waiting approvals</div>
          <div className="kpi-bar" style={{ height: 6 }}>
            <div style={{ width: `${Math.min(100, pending.length * 25 + 15)}%`, background: "var(--viz-ask-start)" }} />
          </div>
        </div>
        <div className="metric-cell">
          <div className="metric-value tabular">{findings.length}</div>
          <div className="metric-label">Open findings</div>
          <div className="kpi-bar" style={{ height: 6 }}>
            <div style={{ width: "30%", background: "var(--viz-block-start)" }} />
            <div style={{ width: "45%", background: "var(--viz-ask-start)" }} />
            <div style={{ width: "25%", background: "var(--viz-watch-start)" }} />
          </div>
        </div>
        <div className="metric-cell">
          <div className="metric-value tabular">{incidents.length}</div>
          <div className="metric-label">Correlated incidents</div>
          <div className="kpi-bar" style={{ height: 6 }}>
            <div style={{ width: "65%", background: "var(--viz-block-start)" }} />
          </div>
        </div>
        <div className="metric-cell">
          <div className="metric-value tabular">{capitalizeLabel(killSwitch.state)}</div>
          <div className="metric-label">Kill switch status</div>
          <div className="kpi-bar" style={{ height: 6 }}>
            <div
              style={{
                width: "100%",
                background: killSwitch.state === "inactive" ? "var(--tone-allow)" : "var(--viz-block-start)",
              }}
            />
          </div>
        </div>
      </div>

      {feedback.kind === "error" && (
        <Banner status="error" title={feedback.message} collapsible={false} />
      )}

      <Card padding={3}>
        <VStack gap={3}>
          <HStack justify="between" align="center">
            <HStack gap={2} align="center">
              <GrdrIcon name="hand" size={16} />
              <Heading level={2}>{`Pending approval queue (${pending.length})`}</Heading>
            </HStack>
            <Badge variant="warning" label="1s hold to confirm" />
          </HStack>

          {pending.length === 0 ? (
            <Text color="secondary">No pending approval requests right now.</Text>
          ) : (
            <VStack gap={2}>
              {pending.map((req) => (
                <ApprovalCard
                  key={req.id}
                  id={req.id}
                  ruleId={req.rule_id}
                  ruleTitle={req.rule_title}
                  requiredGrade={req.required_grade}
                  agentName={req.agent_name}
                  actionClass={req.action_class}
                  deviceId={req.device_id}
                  deviceName={req.device_name}
                  deviceOs={devices.find((d) => d.id === req.device_id || d.hostname === req.device_name)?.os}
                  target={req.target}
                  reason={req.reason}
                  onAllow={handleAllow}
                  onDeny={handleDeny}
                  onOpenEntity={onOpenEntity}
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
                  setFeedback({ kind: "idle" });
                  try {
                    await api.exportOcsf();
                    setFeedback({ kind: "exported", message: "Downloaded guardrails-ocsf-1.9.json" });
                  } catch (err) {
                    setFeedback({ kind: "error", message: (err as Error).message });
                  }
                }}
              />
              <Button
                label="Export Audit JSONL"
                icon={<GrdrIcon name="download" size={14} />}
                onClick={async () => {
                  setFeedback({ kind: "idle" });
                  try {
                    await api.exportAuditJsonl();
                    setFeedback({ kind: "exported", message: "Downloaded guardrails-audit.jsonl" });
                  } catch (err) {
                    setFeedback({ kind: "error", message: (err as Error).message });
                  }
                }}
              />
            </HStack>
          </HStack>

          {feedback.kind === "exported" && (
            <Banner status="info" title={feedback.message} collapsible={false} />
          )}

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
                        <VStack gap={1}>
                          <strong>{inc.title}</strong>
                          <Text type="supporting" color="secondary" size="sm">
                            {presentIncidentSummary(inc.summary)}
                          </Text>
                        </VStack>
                      </td>
                      <td>
                        <VStack gap={1}>
                          <EntityLink
                            kind="session"
                            id={inc.session_id}
                            label={inc.session_id}
                            compact
                            onSelect={onOpenEntity}
                          />
                          <HStack gap={1} align="center" style={{ flexWrap: "wrap", columnGap: 6, rowGap: 2 }}>
                            <EntityLink
                              kind="agent"
                              label={inc.agent_name}
                              compact
                              onSelect={onOpenEntity}
                            />
                            <span style={{ color: "var(--ink-muted)" }}>on</span>
                            <EntityLink
                              kind="device"
                              id={inc.device_id}
                              label={inc.device_name}
                              os={devices.find((d) => d.id === inc.device_id || d.hostname === inc.device_name)?.os}
                              compact
                              onSelect={onOpenEntity}
                            />
                          </HStack>
                        </VStack>
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
                          icon={
                            <GrdrIcon
                              name={
                                inc.severity === "critical"
                                  ? "alert-octagon"
                                  : inc.severity === "high"
                                    ? "alert-triangle"
                                    : "alert-circle"
                              }
                              size={11}
                            />
                          }
                          label={capitalizeLabel(inc.severity)}
                        />
                      </td>
                      <td>
                        <Badge
                          variant={inc.lifecycle === "resolved" ? "success" : "info"}
                          icon={
                            <GrdrIcon
                              name={inc.lifecycle === "resolved" ? "check-circle" : "circle"}
                              size={11}
                            />
                          }
                          label={capitalizeLabel(inc.lifecycle)}
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
                {findings.map((f) => {
                  const titleText = presentFindingTitle(f.title, f.agent_name);
                  return (
                    <tr key={f.id}>
                      <td>
                        <strong>{titleText}</strong>
                        <HStack gap={1} align="center" style={{ flexWrap: "wrap", columnGap: 6, rowGap: 2, marginTop: 4 }}>
                          <EntityLink
                            kind="agent"
                            label={f.agent_name}
                            compact
                            onSelect={onOpenEntity}
                          />
                          <span style={{ color: "var(--ink-muted)" }}>on</span>
                          <EntityLink
                            kind="device"
                            id={f.device_id}
                            label={f.device_name}
                            os={devices.find((d) => d.id === f.device_id || d.hostname === f.device_name)?.os}
                            compact
                            onSelect={onOpenEntity}
                          />
                          {f.rule_id && (
                            <>
                              <span style={{ color: "var(--ink-muted)" }} aria-hidden="true">·</span>
                              <EntityLink
                                kind="rule"
                                id={f.rule_id}
                                label={f.rule_id}
                                compact
                                onSelect={onOpenEntity}
                              />
                            </>
                          )}
                        </HStack>
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
                          icon={
                            <GrdrIcon
                              name={
                                f.severity === "critical"
                                  ? "alert-octagon"
                                  : f.severity === "high"
                                    ? "alert-triangle"
                                    : "alert-circle"
                              }
                              size={11}
                            />
                          }
                          label={capitalizeLabel(f.severity)}
                        />
                      </td>
                      <td>
                        <Badge
                          variant={f.lifecycle === "resolved" ? "success" : "info"}
                          icon={
                            <GrdrIcon
                              name={f.lifecycle === "resolved" ? "check-circle" : "circle"}
                              size={11}
                            />
                          }
                          label={capitalizeLabel(f.lifecycle)}
                        />
                      </td>
                      <td>
                        <HStack gap={1} style={{ flexWrap: "wrap" }}>
                          {onOpenSessionTurn && (
                            <Button
                              size="sm"
                              variant="ghost"
                              icon={<GrdrIcon name="route" size={12} />}
                              label="Inspect trace"
                              onClick={() => onOpenSessionTurn(f.session_id, 1)}
                            />
                          )}
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
                  );
                })}
              </tbody>
            </table>
          </div>
        </VStack>
      </Card>

      <KillSwitchSection
        killSwitch={killSwitch}
        scope={scope}
        targetId={targetId}
        killReason={killReason}
        flow={killFlow}
        onScopeChange={setScope}
        onTargetIdChange={setTargetId}
        onKillReasonChange={setKillReason}
        onFlowChange={setKillFlow}
        onTrigger={handleKillSwitch}
      />
    </VStack>
  );
}
