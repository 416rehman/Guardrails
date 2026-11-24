import { useState } from "react";
import type {
  ApprovalRequest,
  Device,
  Finding,
  GrantScope,
  NavRoute,
  OverviewResponse,
  PolicyPack,
} from "@grdr/api";
import { formatActionLabel, pluralize } from "@grdr/i18n";
import { AssuranceBadge, Quoted, VerdictBadge } from "@grdr/kit";
import {
  Badge,
  Banner,
  Button,
  GrdrCoverageRing,
  GrdrIcon,
  GrdrVelocityChart,
  HStack,
  ProgressBar,
  Text,
  VStack,
} from "@grdr/ui";

const VELOCITY_DAYS = [
  { day: "Mon", allowed: 18, ask: 1, block: 0 },
  { day: "Tue", allowed: 24, ask: 2, block: 1 },
  { day: "Wed", allowed: 21, ask: 0, block: 1 },
  { day: "Thu", allowed: 32, ask: 3, block: 2 },
  { day: "Fri", allowed: 28, ask: 1, block: 0 },
  { day: "Sat", allowed: 14, ask: 0, block: 0 },
  { day: "Sun", allowed: 19, ask: 1, block: 1 },
];

export function HomePage({
  overview,
  devices,
  packs,
  approvals,
  findings,
  onNavigate,
  onDecideApproval,
}: {
  overview: OverviewResponse | null;
  devices: Device[];
  packs: PolicyPack[];
  approvals: ApprovalRequest[];
  findings: Finding[];
  onNavigate: (route: NavRoute) => void;
  onDecideApproval: (id: string, approve: boolean, scope: GrantScope) => Promise<void>;
}) {
  const [expandedApprovalId, setExpandedApprovalId] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const pending = approvals.filter((a) => a.state.status === "pending");
  const openFindings = findings.filter((f) => f.lifecycle !== "resolved");
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
      ? `${pending.length} action waiting for your decision`
      : openFindings.length > 0
        ? `${openFindings.length} finding to inspect`
        : `${boundaryAgents} of ${allAgents.length} agents guarded at boundary`;

  const hostNames = devices.map((d) => d.hostname).join(", ") || "your enrolled endpoints";

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
          <p className="hero-summary">
            {`Watching ${pluralize(allAgents.length, "agent")} across ${hostNames} with ${pluralize(packs.length, "active policy pack")}.`}
          </p>

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
              <div className="metric-label">Waiting approvals</div>
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
              Evaluated agent calls this week (169)
            </Text>
          </HStack>
          <HStack gap={2} align="center">
            <Badge variant="neutral" label="Allowed (156)" />
            <Badge variant="warning" icon={<GrdrIcon name="hand" size={11} />} label="Ask (8)" />
            <Badge variant="error" icon={<GrdrIcon name="ban" size={11} />} label="Blocked (5)" />
          </HStack>
        </HStack>
        <GrdrVelocityChart data={VELOCITY_DAYS} />
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
                <div key={item.id} className="ledger-row">
                  <div className="ledger-row-main">
                    <VStack gap={1}>
                      <HStack gap={2} align="center">
                        <VerdictBadge verdict="step_up" />
                        <strong>{item.rule_title}</strong>
                        <Text size="sm" color="secondary">
                          {`${item.agent_name} on ${item.device_name}`}
                        </Text>
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
                      </HStack>
                    </div>
                  )}
                </div>
              );
            })}

            {openFindings.slice(0, 2).map((finding) => {
              const displayTitle = finding.title
                .replace(/\b(?:file\.write|file\.read|file\.delete|exec|mcp\.call|net\.request|cred\.use)\b/g, (m) =>
                  formatActionLabel(m),
                );
              return (
                <div key={finding.id} className="ledger-row">
                  <div className="ledger-row-main">
                    <VStack gap={1}>
                      <HStack gap={2} align="center">
                        <GrdrIcon name="alert-circle" size={14} color="var(--tone-block)" />
                        <strong>{displayTitle}</strong>
                        <Text size="sm" color="secondary">
                          {`${finding.agent_name} on ${finding.device_name}`}
                        </Text>
                      </HStack>
                      <Quoted text={finding.target} />
                    </VStack>

                    <Button
                      size="sm"
                      variant="secondary"
                      label="Inspect"
                      onClick={() => onNavigate("respond")}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>

      <section className="quiet-split" aria-label="Deployment checklist">
        <div className="ledger-section">
          <div className="ledger-header">
            <h2 className="ledger-title">Setup readiness</h2>
            <Text size="sm" color="secondary" className="tabular">
              {`${completedSteps} of ${totalSteps} ready (${readinessPct}%)`}
            </Text>
          </div>

          <ProgressBar value={readinessPct} max={100} label="Setup readiness" isLabelHidden />

          <div className="checklist">
            {overview?.setup_steps.map((step) => (
              <div key={step.id} className="check-row">
                <HStack gap={2} align="center">
                  <GrdrIcon
                    name={step.done ? "check-circle" : "circle"}
                    size={15}
                    color={step.done ? "var(--tone-allow)" : "var(--ink-muted)"}
                  />
                  <div>
                    <div style={{ fontWeight: 500 }}>{step.label}</div>
                    <Text size="sm" color="secondary">
                      {step.detail}
                    </Text>
                  </div>
                </HStack>
                {!step.done && (
                  <Button
                    size="sm"
                    variant="ghost"
                    label="Finish"
                    onClick={() => onNavigate("protect")}
                  />
                )}
              </div>
            ))}
          </div>
        </div>

        <div className="ledger-section">
          <div className="ledger-header">
            <h2 className="ledger-title">Enrolled endpoints</h2>
            <Button
              size="sm"
              variant="ghost"
              label="Inventory"
              endContent={<GrdrIcon name="arrow-right" size={13} />}
              onClick={() => onNavigate("inventory")}
            />
          </div>

          <div className="checklist">
            {devices.map((device) => (
              <div key={device.id} className="check-row" style={{ alignItems: "flex-start" }}>
                <HStack gap={2} align="start">
                  <div
                    style={{
                      width: 28,
                      height: 28,
                      borderRadius: 6,
                      background: "var(--bg-recessed)",
                      border: "1px solid var(--border-subtle)",
                      display: "grid",
                      placeItems: "center",
                      flexShrink: 0,
                      marginTop: 2,
                    }}
                  >
                    <GrdrIcon name="cpu" size={14} color="var(--ink-primary)" />
                  </div>
                  <VStack gap={1}>
                    <div style={{ fontWeight: 600 }}>{device.hostname}</div>
                    <Text size="sm" color="secondary">
                      {`${device.os} / ${device.arch} · ${pluralize(device.agents.length, "agent")} · ${pluralize(device.mcp_servers.length, "MCP server")}`}
                    </Text>
                    <HStack gap={1} style={{ flexWrap: "wrap" }}>
                      {device.agents.map((ag) => (
                        <AssuranceBadge
                          key={ag.id}
                          level={ag.assurance_level}
                          control={`${ag.name}: ${ag.assurance.control}`}
                        />
                      ))}
                    </HStack>
                  </VStack>
                </HStack>
                <Badge
                  variant={device.hook_effective ? "success" : "warning"}
                  icon={<GrdrIcon name={device.hook_effective ? "shield-check" : "shield-alert"} size={12} />}
                  label={device.hook_effective ? "Hooks active" : "Request mode"}
                />
              </div>
            ))}
          </div>
        </div>
      </section>
    </VStack>
  );
}
