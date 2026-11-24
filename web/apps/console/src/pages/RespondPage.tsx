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
import { capitalizeLabel } from "@grdr/i18n";
import { type EntityTarget } from "@grdr/kit";
import { Banner, Button, GrdrIcon, Heading, Text, VStack } from "@grdr/ui";
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
  onUpdated: () => void;
}) {
  const [feedback, setFeedback] = useState<RespondFeedback>({ kind: "idle" });
  const [refreshKey, setRefreshKey] = useState(0);
  const [scope, setScope] = useState<KillScope>("session");
  const [targetId, setTargetId] = useState(defaultSessionId || "sess-demo-refactor");
  const [killReason, setKillReason] = useState("Containment triggered by operator during triage");
  const [killFlow, setKillFlow] = useState<KillSwitchFlow>({ kind: "closed", inlineArmed: false });

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
      bumpRefresh();
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
      />

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
