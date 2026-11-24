import type { ApprovalRequest, Finding, NavRoute, OverviewResponse } from "@grdr/api";
import { InsightTile, Quoted, VerdictBadge, ViewStateFrame } from "@grdr/kit";
import { Badge, Banner, Button, Card, GrdrIcon, Heading, HStack, Text, VStack } from "@grdr/ui";

export function HomePage({
  overview,
  approvals,
  findings,
  onNavigate,
}: {
  overview: OverviewResponse | null;
  approvals: ApprovalRequest[];
  findings: Finding[];
  onNavigate: (route: NavRoute) => void;
}) {
  const pending = approvals.filter((a) => a.state.status === "pending");
  const openFindings = findings.filter((f) => f.lifecycle !== "resolved");
  const completedSteps = overview?.setup_steps.filter((s) => s.done).length ?? 0;
  const totalSteps = overview?.setup_steps.length ?? 0;

  return (
    <VStack gap={4}>
      <div className="page-header">
        <div>
          <Heading level={1}>Home</Heading>
          <Text color="secondary">
            Live visibility across enrolled endpoints, policy enforcement strength, and actions waiting on review.
          </Text>
        </div>
        <Button
          variant="primary"
          label="Test live policy"
          endContent={<GrdrIcon name="arrow-right" size={14} />}
          onClick={() => onNavigate("tester")}
        />
      </div>

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

      <div className="grid-4">
        {overview?.tiles.map((tile) => (
          <InsightTile
            key={tile.id}
            metric={tile.metric}
            headline={tile.headline}
            comparison={tile.comparison}
            actionLabel={tile.action_label}
            onAction={() => onNavigate(tile.route)}
          />
        ))}
      </div>

      <div className="grid-2">
        <Card padding={3}>
          <VStack gap={3}>
            <HStack justify="between" align="center">
              <Heading level={2}>Needs you</Heading>
              <Badge variant="warning" label={`${pending.length + openFindings.length} open`} />
            </HStack>

            {pending.length === 0 && openFindings.length === 0 ? (
              <ViewStateFrame
                state="empty"
                title="No pending step-up requests"
                description="All active sessions match current policy without open approvals or findings."
              />
            ) : (
              <div className="checklist">
                {pending.slice(0, 3).map((item) => (
                  <div key={item.id} className="check-row todo" style={{ justifyContent: "space-between" }}>
                    <VStack gap={1}>
                      <HStack gap={2} align="center">
                        <VerdictBadge verdict="step_up" />
                        <strong>{item.rule_title}</strong>
                      </HStack>
                      <Quoted text={item.target} />
                    </VStack>
                    <Button size="sm" label="Review" onClick={() => onNavigate("respond")} />
                  </div>
                ))}
                {openFindings.slice(0, 3).map((finding) => (
                  <div key={finding.id} className="check-row todo" style={{ justifyContent: "space-between" }}>
                    <VStack gap={1}>
                      <HStack gap={2} align="center">
                        <GrdrIcon name="alert-circle" size={14} color="var(--tone-block)" />
                        <strong>{finding.title}</strong>
                      </HStack>
                      <Quoted text={finding.target} />
                    </VStack>
                    <Button size="sm" label="Inspect" onClick={() => onNavigate("respond")} />
                  </div>
                ))}
              </div>
            )}
          </VStack>
        </Card>

        <Card padding={3}>
          <VStack gap={3}>
            <HStack justify="between" align="center">
              <Heading level={2}>Platform readiness</Heading>
              <Badge variant="success" label={`${completedSteps} of ${totalSteps} ready`} />
            </HStack>
            <div className="checklist">
              {overview?.setup_steps.map((step) => (
                <div key={step.id} className={`check-row ${step.done ? "done" : "todo"}`}>
                  <GrdrIcon
                    name={step.done ? "check-circle" : "circle"}
                    size={16}
                    color={step.done ? "var(--tone-allow)" : "var(--ink-muted)"}
                  />
                  <div>
                    <div style={{ fontWeight: 500 }}>{step.label}</div>
                    <Text type="supporting" color="secondary" size="sm">
                      {step.detail}
                    </Text>
                  </div>
                </div>
              ))}
            </div>
          </VStack>
        </Card>
      </div>
    </VStack>
  );
}
