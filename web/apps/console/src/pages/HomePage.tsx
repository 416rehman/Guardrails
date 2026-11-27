// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
import { useContext, useState } from "react";
import type {
  ApprovalRequest,
  Device,
  Finding,
  GrantScope,
  NavRoute,
  OverviewResponse,
  PolicyPack,
} from "@grdr/api";
import { pluralize, presentFindingTitle } from "@grdr/i18n";
import { EntityLink, type EntityTarget, Quoted, VerdictBadge } from "@grdr/kit";
import {
  Banner,
  Button,
  GrdrCoverageRing,
  GrdrIcon,
  GrdrVelocityChart,
  HStack,
  StatusInline,
  Text,
  VStack,
} from "@grdr/ui";
import { ConsoleWorkspaceContext } from "../ConsoleContext";
import { useWeeklyDecisionVelocity } from "../queries";
import { EnrolledEndpointsCard, SetupReadinessCard } from "./HomeSections";

export function HomePage({
  overview,
  devices,
  packs,
  approvals,
  findings,
  onNavigate,
  onOpenEntity,
  onDecideApproval,
  onExplainReceipt,
}: {
  overview: OverviewResponse | null;
  devices: Device[];
  packs: PolicyPack[];
  approvals: ApprovalRequest[];
  findings: Finding[];
  onNavigate: (route: NavRoute) => void;
  onOpenEntity: (target: EntityTarget) => void;
  onDecideApproval: (id: string, approve: boolean, scope: GrantScope) => Promise<void>;
  onExplainReceipt?: (reference: string) => void;
}) {
  const [expandedApprovalId, setExpandedApprovalId] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const workspace = useContext(ConsoleWorkspaceContext);
  const velocity = useWeeklyDecisionVelocity(
    workspace?.snapshot.sessions ?? [],
    Boolean(workspace),
  );

  const pending = approvals.filter((a) => a.state.status === "pending");
  const openFindings = findings.filter((f) => {
    if (f.lifecycle === "resolved") return false;
    const isAskDuplicate = pending.some(
      (p) =>
        p.agent_name === f.agent_name &&
        p.target === f.target &&
        p.session_id === f.session_id &&
        (f.severity === "medium" ||
          f.title.toLowerCase().includes("approval") ||
          f.title === p.rule_title),
    );
    return !isAskDuplicate;
  });
  const completedSteps = overview?.setup_steps.filter((s) => s.done).length ?? 0;
  const totalSteps = overview?.setup_steps.length ?? 0;
  const readinessPct = totalSteps === 0 ? 0 : Math.round((completedSteps / totalSteps) * 100);

  const allAgents = devices.flatMap((d) => d.agents);
  const boundaryAgents = allAgents.filter((a) => a.assurance.control.includes("boundary")).length;
  const coveragePct =
    allAgents.length === 0 ? 0 : Math.round((boundaryAgents / allAgents.length) * 100);
  const totalRules = packs.reduce((sum, pack) => sum + pack.rules.length, 0);

  const headline =
    pending.length > 0
      ? `${pluralize(pending.length, "action")} waiting for your decision`
      : openFindings.length > 0
        ? `${pluralize(openFindings.length, "finding")} to inspect`
        : `${boundaryAgents} of ${allAgents.length} agents guarded at boundary`;

  async function decide(id: string, approve: boolean, scope: GrantScope) {
    setBusyId(id);
    try {
      await onDecideApproval(id, approve, scope);
      setExpandedApprovalId(null);
    } finally {
      setBusyId(null);
    }
  }

  return (
    <VStack gap={4}>
      {overview?.kill_switch && overview.kill_switch.state !== "inactive" && (
        <Banner
          status="error"
          title={`Kill switch active (${overview.kill_switch.state}): ${overview.kill_switch.reason}`}
          collapsible={false}
          role="alert"
          endContent={
            <Button
              variant="secondary"
              size="sm"
              label="Manage in Respond"
              onClick={() => onNavigate("respond")}
            />
          }
        />
      )}

      <section className="hero-stage" aria-label="Protection overview">
        <div>
          <h1 className="hero-headline">{headline}</h1>
          <div className="hero-summary" style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 6 }}>
            <span>{`Watching ${pluralize(allAgents.length, "agent")} across`}</span>
            {devices.length === 0 ? (
              <span>your enrolled endpoints</span>
            ) : (
              devices.map((dev, idx) => (
                <span key={dev.id} style={{ display: "inline-flex", alignItems: "center" }}>
                  <EntityLink
                    kind="device"
                    id={dev.id}
                    label={dev.hostname}
                    os={dev.os}
                    onSelect={onOpenEntity}
                  />
                  {idx < devices.length - 1 && (
                    <span style={{ color: "var(--ink-muted)" }}>,</span>
                  )}
                </span>
              ))
            )}
            <span>{`with ${pluralize(packs.length, "active policy pack")}.`}</span>
          </div>

          <HStack gap={2} style={{ marginTop: 20 }}>
            <Button
              variant="primary"
              label={pending.length > 0 ? "Review waiting actions" : "Test a live call"}
              endContent={<GrdrIcon name="arrow-right" size={14} />}
              onClick={() => onNavigate(pending.length > 0 ? "respond" : "tester")}
            />
            <Button
              variant="secondary"
              label="Inspect sessions"
              onClick={() => onNavigate("sessions")}
            />
          </HStack>

          <div className="metric-strip">
            <div className="metric-cell">
              <div className="metric-value tabular">{devices.length}</div>
              <div className="metric-label">Enrolled hosts</div>
              <div className="metric-note">{`${pluralize(allAgents.length, "discovered agent")}`}</div>
            </div>
            <div className="metric-cell">
              <div className="metric-value tabular">{pending.length}</div>
              <div className="metric-label" style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
                <span>Waiting approvals</span>
                {pending.length > 0 && <span className="attention-dot" aria-hidden="true" />}
              </div>
              <div className="metric-note">One-time or session</div>
            </div>
            <div className="metric-cell">
              <div className="metric-value tabular">{openFindings.length}</div>
              <div className="metric-label">Open findings</div>
              <div className="metric-note">{pluralize(overview?.active_sessions ?? 0, "active session")}</div>
            </div>
            <div className="metric-cell">
              <div className="metric-value tabular">{totalRules}</div>
              <div className="metric-label">Active rules</div>
              <div className="metric-note">Compiled locally</div>
            </div>
          </div>
        </div>

        <div className="ring-panel">
          <GrdrCoverageRing
            valuePct={coveragePct}
            label="Boundary"
            size={136}
            tone={coveragePct >= 80 ? "allow" : "accent"}
          />

          <Button
            variant="ghost"
            size="sm"
            label="Coverage details"
            endContent={<GrdrIcon name="arrow-right" size={13} />}
            onClick={() => onNavigate("coverage")}
          />
        </div>
      </section>

      <section className="visual-panel" aria-label="Weekly decision velocity">
        <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 12 }}>
          <HStack gap={2} align="center">
            <GrdrIcon name="activity" size={16} color="var(--accent-primary)" />
            <Text style={{ fontWeight: 600 }}>
              {velocity.windowKind === "current"
                ? `Evaluated agent calls this week (${velocity.totalEvaluated})`
                : `Evaluated agent calls (${velocity.windowLabel}) (${velocity.totalEvaluated})`}
            </Text>
          </HStack>
          <HStack gap={3} align="center" style={{ flexWrap: "wrap" }}>
            <StatusInline tone="neutral" dot dotColor="var(--viz-allow-end)" label={`Allowed ${velocity.totalAllowed}`} />
            <StatusInline tone="neutral" dot dotColor="var(--viz-ask-start)" label={`Ask ${velocity.totalAsk}`} />
            <StatusInline tone="neutral" dot dotColor="var(--viz-block-start)" label={`Blocked ${velocity.totalBlocked}`} />
          </HStack>
        </HStack>
        <GrdrVelocityChart data={velocity.days} />
        {velocity.totalEvaluated === 0 ? (
          <Text size="sm" color="secondary">
            No agent decisions recorded in this 7-day window yet.
          </Text>
        ) : (
          velocity.isPartialSummary && (
            <Text size="sm" color="secondary">
              Includes session summary counts (detailed bars cover the 8 most recent sessions).
            </Text>
          )
        )}
      </section>

      <section className="ledger-section" aria-label="Needs you">
        <div className="ledger-header">
          <h2 className="ledger-title">Waiting for your decision</h2>
          <HStack gap={2} align="center">
            <Text size="sm" color="secondary" className="tabular">
              {`${pluralize(pending.length, "approval")}, ${pluralize(openFindings.length, "open finding")}`}
            </Text>
            {openFindings.length > 2 && (
              <Button
                variant="ghost"
                size="sm"
                label={`View all ${openFindings.length} findings`}
                endContent={<GrdrIcon name="arrow-right" size={13} />}
                onClick={() => onNavigate("respond")}
              />
            )}
          </HStack>
        </div>

        {pending.length === 0 && openFindings.length === 0 ? (
          <Text color="secondary">
            Every active session matches current policy with zero pending prompts.
          </Text>
        ) : (
          <div className="ledger-list">
            {pending.map((item) => {
              const isOpen = expandedApprovalId === item.id;
              return (
                <div key={item.id} className="ledger-row attention-row">
                  <div className="ledger-row-main">
                    <VStack gap={1}>
                      <HStack gap={2} align="center" style={{ flexWrap: "wrap", columnGap: 6, rowGap: 2 }}>
                        <VerdictBadge verdict="step_up" />
                        <strong>{item.rule_title}</strong>
                        <span style={{ color: "var(--ink-muted)" }} aria-hidden="true">·</span>
                        <EntityLink
                          kind="agent"
                          label={item.agent_name}
                          compact
                          onSelect={onOpenEntity}
                        />
                        <Text size="sm" color="secondary">
                          on
                        </Text>
                        <EntityLink
                          kind="device"
                          id={item.device_id}
                          label={item.device_name}
                          os={devices.find((d) => d.id === item.device_id || d.hostname === item.device_name)?.os}
                          compact
                          onSelect={onOpenEntity}
                        />
                      </HStack>
                      <Quoted text={item.target} />
                    </VStack>

                    <Button
                      size="sm"
                      variant={isOpen ? "secondary" : "primary"}
                      label={isOpen ? "Hide review" : "Review"}
                      onClick={() => setExpandedApprovalId(isOpen ? null : item.id)}
                    />
                  </div>

                  {isOpen && (
                    <div className="ledger-row-drawer">
                      <Text size="sm" color="secondary">
                        {item.reason}
                      </Text>
                      <HStack gap={2} align="center">
                        <Button
                          size="sm"
                          variant="primary"
                          isDisabled={busyId === item.id}
                          label="Approve once"
                          onClick={() => void decide(item.id, true, "once")}
                        />
                        <Button
                          size="sm"
                          variant="secondary"
                          isDisabled={busyId === item.id}
                          label="Allow for session"
                          onClick={() => void decide(item.id, true, "session")}
                        />
                        <Button
                          size="sm"
                          variant="destructive"
                          isDisabled={busyId === item.id}
                          label="Deny"
                          onClick={() => void decide(item.id, false, "once")}
                        />
                        {onExplainReceipt && (
                          <Button
                            size="sm"
                            variant="ghost"
                            icon={<GrdrIcon name="info" size={12} />}
                            label="Why?"
                            onClick={() => onExplainReceipt(item.id)}
                          />
                        )}
                      </HStack>
                    </div>
                  )}
                </div>
              );
            })}

            {openFindings.slice(0, 2).map((finding) => {
              const displayTitle = presentFindingTitle(finding.title, finding.agent_name);
              const lowerTitle = finding.title.toLowerCase();
              const isWatchFinding =
                finding.severity === "low" || lowerTitle.startsWith("watch");
              const isAskFinding =
                !isWatchFinding &&
                (finding.severity === "medium" ||
                  lowerTitle.includes("approval") ||
                  finding.class.includes("approval"));
              const findingIcon = isWatchFinding ? "eye" : isAskFinding ? "hand" : "ban";
              const findingColor = isWatchFinding
                ? "var(--tone-watch)"
                : isAskFinding
                  ? "var(--tone-ask)"
                  : "var(--tone-block)";
              return (
                <div key={finding.id} className="ledger-row">
                  <div className="ledger-row-main">
                    <VStack gap={1}>
                      <HStack gap={2} align="center" style={{ flexWrap: "wrap", columnGap: 6, rowGap: 2 }}>
                        <GrdrIcon
                          name={findingIcon}
                          size={14}
                          color={findingColor}
                        />
                        <strong>{displayTitle}</strong>
                        <span style={{ color: "var(--ink-muted)" }} aria-hidden="true">·</span>
                        <EntityLink
                          kind="agent"
                          label={finding.agent_name}
                          compact
                          onSelect={onOpenEntity}
                        />
                        <Text size="sm" color="secondary">
                          on
                        </Text>
                        <EntityLink
                          kind="device"
                          id={finding.device_id}
                          label={finding.device_name}
                          os={devices.find((d) => d.id === finding.device_id || d.hostname === finding.device_name)?.os}
                          compact
                          onSelect={onOpenEntity}
                        />
                        {finding.rule_id && (
                          <>
                            <span style={{ color: "var(--ink-secondary)", fontWeight: 600, marginInline: 2 }} aria-hidden="true">·</span>
                            <EntityLink
                              kind="rule"
                              id={finding.rule_id}
                              label={finding.rule_id}
                              compact
                              onSelect={onOpenEntity}
                            />
                          </>
                        )}
                      </HStack>
                      <Quoted text={finding.target} />
                    </VStack>

                    <HStack gap={1} align="center">
                      {onExplainReceipt && (
                        <Button
                          size="sm"
                          variant="ghost"
                          icon={<GrdrIcon name="info" size={12} />}
                          label="Why?"
                          onClick={() => onExplainReceipt(finding.id)}
                        />
                      )}
                      <Button
                        size="sm"
                        variant="secondary"
                        label="Inspect"
                        onClick={() => onNavigate("respond")}
                      />
                    </HStack>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>

      <section className="quiet-split" aria-label="Deployment checklist">
        <SetupReadinessCard
          steps={overview?.setup_steps ?? []}
          completedSteps={completedSteps}
          totalSteps={totalSteps}
          readinessPct={readinessPct}
          onNavigate={onNavigate}
        />
        <EnrolledEndpointsCard
          devices={devices}
          onNavigate={onNavigate}
          onOpenEntity={onOpenEntity}
        />
      </section>
    </VStack>
  );
}
