// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
import { useContext, useEffect, useState } from "react";
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
import { capitalizeLabel } from "@grdr/i18n";
import { type EntityTarget } from "@grdr/kit";
import { Banner, Button, GrdrIcon, Heading, Text, VStack } from "@grdr/ui";
import { ConsoleWorkspaceContext } from "../ConsoleContext";
import {
  EMPTY_KILL_SELECTION,
  resolveKillSwitchBlastRadius,
  type KillSwitchSelection,
} from "../consoleState";
import type { ConsoleSearchParams } from "../searchSchema";
import { KillSwitchSection, type KillSwitchFlow } from "./KillSwitchControls";
import { FindingsSection } from "./FindingsSection";
import {
  CorrelatedIncidentsSection,
  PendingApprovalsSection,
} from "./RespondSections";

type RespondFeedback =
  | { kind: "idle" }
  | { kind: "error"; message: string }
  | { kind: "exported"; message: string };

export function buildKillSwitchPayload(
  action: "freeze" | "kill" | "release",
  scope: KillScope,
  targetId: string,
  reason: string,
  devices: Device[],
  selection?: KillSwitchSelection,
): {
  action: "freeze" | "kill" | "release";
  scope: KillScope;
  target_id: string;
  reason: string;
  duration_minutes?: number;
} {
  const blockedAgents = selection?.blockedAgents ?? [];
  const blockedModels = selection?.blockedModels ?? [];
  const blockedGateways = selection?.blockedGateways ?? [];
  const combinedTargets = [...blockedAgents, ...blockedModels, ...blockedGateways];

  if (action !== "release" && combinedTargets.length > 0) {
    const blastRadius = resolveKillSwitchBlastRadius(devices, {
      blockedAgents,
      blockedModels,
      blockedGateways,
    });
    const summaryParts: string[] = [];
    if (blockedAgents.length > 0) {
      summaryParts.push(`agents=${blockedAgents.join("|")}`);
    }
    if (blockedModels.length > 0) {
      summaryParts.push(`models=${blockedModels.join("|")}`);
    }
    if (blockedGateways.length > 0) {
      summaryParts.push(`gateways=${blockedGateways.join("|")}`);
    }
    const baseReason = reason.trim() || "Scoped containment activated by operator";
    return {
      action,
      scope: blastRadius.scope,
      target_id: blastRadius.targetId,
      reason: `${baseReason} [${summaryParts.join(", ")}]`,
      duration_minutes: action === "freeze" ? 60 : undefined,
    };
  }

  return {
    action,
    scope,
    target_id: scope === "organisation" ? "*" : targetId,
    reason,
    duration_minutes: action === "freeze" ? 60 : undefined,
  };
}

export function RespondPage({
  approvals,
  findings,
  incidents,
  devices = [],
  killSwitch,
  defaultSessionId,
  urlSearch,
  onUpdateSearch,
  onOpenEntity,
  onOpenSessionTurn,
  onExplainReceipt,
  onUpdated,
}: {
  approvals: ApprovalRequest[];
  findings: Finding[];
  incidents: Incident[];
  devices?: Device[];
  killSwitch: KillSwitchState;
  defaultSessionId: string;
  urlSearch?: ConsoleSearchParams;
  onUpdateSearch?: (patch: Partial<ConsoleSearchParams>) => void;
  onOpenEntity?: (target: EntityTarget) => void;
  onOpenSessionTurn?: (sessionId: string, turnIndex: number) => void;
  onExplainReceipt?: (reference: string) => void;
  onUpdated: () => void;
}) {
  const workspace = useContext(ConsoleWorkspaceContext);
  const sessions = workspace?.snapshot.sessions ?? [];
  const [feedback, setFeedback] = useState<RespondFeedback>({ kind: "idle" });
  const [refreshKey, setRefreshKey] = useState(0);
  const [scope, setScope] = useState<KillScope>("session");
  const [targetId, setTargetId] = useState(defaultSessionId || "sess-demo-refactor");
  const [killReason, setKillReason] = useState("Containment triggered by operator during triage");
  const [savedSelection, setSavedSelection] = useState<KillSwitchSelection>(EMPTY_KILL_SELECTION);
  const [killFlow, setKillFlow] = useState<KillSwitchFlow>({ kind: "closed", inlineArmed: false });

  const killScope = killSwitch.state === "inactive" ? null : killSwitch.scope;
  const killTargetId = killSwitch.state === "inactive" ? null : killSwitch.target_id;

  useEffect(() => {
    if (killSwitch.state !== "inactive" && killScope && killTargetId !== null) {
      setScope(killScope);
      setTargetId(killScope === "organisation" ? "*" : killTargetId);
    }
  }, [killSwitch.state, killScope, killTargetId]);

  function handleScopeChange(nextScope: KillScope) {
    setScope(nextScope);
    if (nextScope === "organisation") {
      setTargetId("*");
    } else if (nextScope === "device") {
      setTargetId(devices[0]?.id ?? "");
    } else {
      setTargetId(sessions[0]?.id ?? defaultSessionId ?? "");
    }
  }

  function updateKillFlow(next: KillSwitchFlow) {
    setKillFlow(next);
  }

  function openScopedModal() {
    setFeedback({ kind: "idle" });
    const count =
      savedSelection.blockedAgents.length +
      savedSelection.blockedModels.length +
      savedSelection.blockedGateways.length;
    if (count > 0) {
      setKillFlow({
        kind: "armedConfirming",
        blockedAgents: savedSelection.blockedAgents,
        blockedModels: savedSelection.blockedModels,
        blockedGateways: savedSelection.blockedGateways,
        query: "",
        confirmPhrase: "",
      });
    } else {
      setKillFlow({
        kind: "modalOpen",
        blockedAgents: [],
        blockedModels: [],
        blockedGateways: [],
        query: "",
      });
    }
  }

  const pendingCount = approvals.filter((a) => a.state.status === "pending").length;

  function bumpRefresh() {
    setRefreshKey((k) => k + 1);
    onUpdated();
  }

  async function handleAllow(reqId: string, grantScope: GrantScope) {
    try {
      await api.decideApproval(reqId, true, grantScope, "Approved via Respond console");
      bumpRefresh();
    } catch (err) {
      setFeedback({ kind: "error", message: (err as Error).message });
    }
  }

  async function handleDeny(reqId: string) {
    try {
      await api.decideApproval(reqId, false, "once", "Denied in Respond console");
      bumpRefresh();
    } catch (err) {
      setFeedback({ kind: "error", message: (err as Error).message });
    }
  }

  async function handleFindingStatus(id: string, lifecycle: FindingLifecycle) {
    try {
      await api.updateFinding(id, lifecycle);
      bumpRefresh();
    } catch (err) {
      setFeedback({ kind: "error", message: (err as Error).message });
    }
  }

  async function handleExportOcsf() {
    setFeedback({ kind: "idle" });
    try {
      await api.exportOcsf();
      setFeedback({ kind: "exported", message: "Downloaded guardrails-ocsf-1.9.json" });
    } catch (err) {
      setFeedback({ kind: "error", message: (err as Error).message });
    }
  }

  async function handleExportAuditJsonl() {
    setFeedback({ kind: "idle" });
    try {
      await api.exportAuditJsonl();
      setFeedback({ kind: "exported", message: "Downloaded guardrails-audit.jsonl" });
    } catch (err) {
      setFeedback({ kind: "error", message: (err as Error).message });
    }
  }

  async function handleKillSwitch(
    action: "freeze" | "kill" | "release",
    selection?: KillSwitchSelection,
  ): Promise<boolean> {
    setFeedback({ kind: "idle" });
    try {
      const payload = buildKillSwitchPayload(
        action,
        scope,
        targetId,
        killReason,
        devices,
        selection,
      );
      await api.setKillSwitch(payload);
      if (action === "release") {
        setSavedSelection(EMPTY_KILL_SELECTION);
      } else if (selection) {
        setSavedSelection(selection);
      }
      setKillFlow({ kind: "closed", inlineArmed: false });
      bumpRefresh();
      return true;
    } catch (err) {
      setFeedback({ kind: "error", message: (err as Error).message });
      return false;
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
          label="Emergency controls"
          icon={<GrdrIcon name="alert-octagon" size={14} />}
          onClick={openScopedModal}
        />
      </div>

      <div className="metric-strip" style={{ marginBlockStart: 0, paddingBlockStart: 0, borderBlockStart: "none" }}>
        <div className="metric-cell">
          <div className="metric-value tabular">{pendingCount}</div>
          <div className="metric-label">Waiting approvals</div>
          <div className="kpi-bar" style={{ height: 6 }}>
            <div style={{ width: `${Math.min(100, pendingCount * 25 + 15)}%`, background: "var(--viz-ask-start)" }} />
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

      <PendingApprovalsSection
        devices={devices}
        refreshKey={refreshKey}
        urlSearch={urlSearch}
        onUpdateSearch={onUpdateSearch}
        onAllow={handleAllow}
        onDeny={handleDeny}
        onOpenEntity={onOpenEntity}
        onExplainReceipt={onExplainReceipt}
      />

      <CorrelatedIncidentsSection
        devices={devices}
        refreshKey={refreshKey}
        urlSearch={urlSearch}
        onUpdateSearch={onUpdateSearch}
        exportedMessage={feedback.kind === "exported" ? feedback.message : undefined}
        onExportOcsf={handleExportOcsf}
        onExportAuditJsonl={handleExportAuditJsonl}
        onOpenEntity={onOpenEntity}
      />

      <FindingsSection
        devices={devices}
        refreshKey={refreshKey}
        urlSearch={urlSearch}
        onUpdateSearch={onUpdateSearch}
        onUpdateLifecycle={handleFindingStatus}
        onOpenEntity={onOpenEntity}
        onOpenSessionTurn={onOpenSessionTurn}
        onExplainReceipt={onExplainReceipt}
      />

      <KillSwitchSection
        killSwitch={killSwitch}
        devices={devices}
        sessions={sessions}
        savedSelection={savedSelection}
        errorMessage={feedback.kind === "error" ? feedback.message : undefined}
        scope={scope}
        targetId={targetId}
        killReason={killReason}
        flow={killFlow}
        onScopeChange={handleScopeChange}
        onTargetIdChange={setTargetId}
        onKillReasonChange={setKillReason}
        onFlowChange={updateKillFlow}
        onTrigger={handleKillSwitch}
      />
    </VStack>
  );
}
