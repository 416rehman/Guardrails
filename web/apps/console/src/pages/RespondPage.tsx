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
import { capitalizeLabel, pluralize, presentFindingTitle } from "@grdr/i18n";
import { ApprovalCard, EntityLink, type EntityTarget, Quoted, SessionLabelBadge } from "@grdr/kit";
import {
  Badge,
  Banner,
  Button,
  Card,
  Dialog,
  GrdrIcon,
  GrdrSelect,
  HarnessIcon,
  Heading,
  HStack,
  IconButton,
  SelectableTile,
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
  devices = [],
  killSwitch,
  defaultSessionId,
  onOpenEntity,
  onUpdated,
}: {
  approvals: ApprovalRequest[];
  findings: Finding[];
  incidents: Incident[];
  devices?: Device[];
  killSwitch: KillSwitchState;
  defaultSessionId: string;
  onOpenEntity?: (target: EntityTarget) => void;
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
  const [blockedAgents, setBlockedAgents] = useState<string[]>([]);
  const [blockedModels, setBlockedModels] = useState<string[]>([]);
  const [blockedGateways, setBlockedGateways] = useState<string[]>([]);

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
            Review pending approvals, investigate findings, and stop compromised sessions.
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

      {error && <Banner status="error" title={error} collapsible={false} />}

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
                  );
                })}
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
              label={capitalizeLabel(killSwitch.state)}
            />
          </HStack>

            <div className="form-grid">
              <GrdrSelect
                label="Scope"
                value={scope}
                options={[
                  { value: "session", label: "Session" },
                  { value: "device", label: "Device" },
                  { value: "organisation", label: "Organisation" },
                ]}
                onChange={(val) => setScope(val as KillScope)}
                width="100%"
              />
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
              <div className="field full">
                <SelectableTile
                  label="Stop all matching agent actions immediately"
                  checked={confirmKill}
                  onChange={setConfirmKill}
                  icon={<GrdrIcon name="shield-alert" size={15} color="var(--tone-block)" />}
                />
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

      <Dialog
        isOpen={killModalOpen}
        onOpenChange={setKillModalOpen}
        purpose="form"
        width={900}
        padding={4}
        aria-label="Scoped Kill Switch Matrix"
      >
        <VStack gap={3}>
          <HStack justify="between" align="start">
            <HStack gap={2} align="start">
              <div style={{ paddingTop: 2 }}>
                <GrdrIcon name="shield-off" size={20} color="var(--tone-block)" />
              </div>
              <VStack gap={0}>
                <Heading level={2}>Scoped Kill Switch</Heading>
                <Text size="sm" color="secondary">
                  Select which agents, model providers, or gateways to contain.
                </Text>
              </VStack>
            </HStack>
            <IconButton
              label="Close"
              icon={<GrdrIcon name="x" size={15} />}
              variant="secondary"
              size="sm"
              onClick={() => setKillModalOpen(false)}
            />
          </HStack>

          <Banner
            status="error"
            title={
              blockedAgents.length + blockedModels.length + blockedGateways.length === 0
                ? "Select target agent types, model providers, or gateways to contain."
                : `Preview: will isolate ${pluralize(blockedAgents.length, "agent type")}, ${pluralize(blockedModels.length, "provider")}, and ${pluralize(blockedGateways.length, "gateway")}.`
            }
            collapsible={false}
          />

          <div className="killswitch-search-bar">
            <div style={{ flex: 1, minWidth: 220 }}>
              <TextInput
                label="Search agents, providers, or gateways"
                isLabelHidden
                placeholder="Search agents, providers, or gateways..."
                startIcon={<GrdrIcon name="search" size={14} color="var(--ink-muted)" />}
                value={matrixQuery}
                onChange={setMatrixQuery}
                width="100%"
              />
            </div>
            <HStack gap={2} align="center">
              <Text size="sm" color="secondary" className="tabular">
                {`${blockedAgents.length + blockedModels.length + blockedGateways.length} selected`}
              </Text>
              {blockedAgents.length + blockedModels.length + blockedGateways.length > 0 && (
                <Button
                  size="sm"
                  variant="secondary"
                  label="Clear"
                  onClick={() => {
                    setBlockedAgents([]);
                    setBlockedModels([]);
                    setBlockedGateways([]);
                  }}
                />
              )}
            </HStack>
          </div>

          <div className="killswitch-cols">
            {(
              [
                {
                  key: "agents",
                  title: "Agent types",
                  icon: "layers" as const,
                  items: MATRIX_ENDPOINTS,
                  selected: blockedAgents,
                  setSelected: setBlockedAgents,
                },
                {
                  key: "models",
                  title: "Model providers",
                  icon: "cpu" as const,
                  items: MATRIX_MODELS,
                  selected: blockedModels,
                  setSelected: setBlockedModels,
                },
                {
                  key: "gateways",
                  title: "Gateways",
                  icon: "plug" as const,
                  items: MATRIX_GATEWAYS,
                  selected: blockedGateways,
                  setSelected: setBlockedGateways,
                },
              ] as const
            ).map((col) => {
              const queryLower = matrixQuery.toLowerCase();
              return (
                <div key={col.key} className="killswitch-col">
                  <div className="killswitch-col-head">
                    <HStack gap={2} align="center">
                      <GrdrIcon name={col.icon} size={14} color="var(--ink-secondary)" />
                      <span>{col.title}</span>
                    </HStack>
                    <span className="killswitch-col-count tabular">
                      {`${col.selected.length}/${col.items.length}`}
                    </span>
                  </div>
                  {col.items
                    .filter((entry) => entry.toLowerCase().includes(queryLower))
                    .map((entry) => {
                      const isSelected = col.selected.includes(entry);
                      return (
                        <SelectableTile
                          key={entry}
                          label={entry}
                          checked={isSelected}
                          icon={<HarnessIcon name={entry} size={15} />}
                          onChange={(checked) =>
                            col.setSelected((prev) =>
                              checked ? [...prev, entry] : prev.filter((x) => x !== entry),
                            )
                          }
                        />
                      );
                    })}
                </div>
              );
            })}
          </div>

          <HStack justify="between" align="end" style={{ gap: 20, marginTop: 8, flexWrap: "wrap" }}>
            <div style={{ flex: 1, minWidth: 240 }}>
              <TextInput
                label="Type fleet-kill to confirm"
                placeholder="fleet-kill"
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
                isDisabled={
                  blockedAgents.length + blockedModels.length + blockedGateways.length === 0 ||
                  matrixConfirmPhrase.trim().toLowerCase() !== "fleet-kill"
                }
                data-agent-confirm="Confirm fleet-wide kill switch"
                onClick={async () => {
                  await handleKillSwitch("kill");
                  setKillModalOpen(false);
                }}
              />
            </HStack>
          </HStack>
        </VStack>
      </Dialog>
    </VStack>
  );
}
