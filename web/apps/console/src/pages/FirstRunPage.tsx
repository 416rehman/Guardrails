// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, type ComplianceWorkspaceResponse, type Device } from "@grdr/api";
import { pluralize } from "@grdr/i18n";
import { AssuranceBadge, EntityLink, type EntityTarget } from "@grdr/kit";
import {
  Badge,
  Banner,
  Button,
  Card,
  CheckboxInput,
  EmptyState,
  GrdrIcon,
  Heading,
  HStack,
  ProgressBar,
  StatusInline,
  Text,
  UiSdkSegmentedControl,
  VStack,
} from "@grdr/ui";
import { consoleQueryKeys } from "../queries";

type FirstRunPhase =
  | { kind: "idle" }
  | { kind: "saving" }
  | { kind: "ok"; message: string }
  | { kind: "error"; message: string };

const GOAL_GRADIENT_MIN_PCT = 20;

export function FirstRunPage({
  devices,
  onOpenEntity,
  onNavigateCompliance,
  onChanged,
}: {
  devices: Device[];
  onOpenEntity?: (target: EntityTarget) => void;
  onNavigateCompliance?: () => void;
  onChanged?: () => Promise<void>;
}) {
  const workspaceQuery = useQuery<ComplianceWorkspaceResponse>({
    queryKey: consoleQueryKeys.complianceWorkspace(),
    queryFn: () => api.getComplianceWorkspace(),
  });

  const fr = workspaceQuery.data?.first_run;
  const [profile, setProfile] = useState<"protected" | "user">("protected");
  const [stepUpEnabled, setStepUpEnabled] = useState(true);
  const [phase, setPhase] = useState<FirstRunPhase>({ kind: "idle" });

  useEffect(() => {
    if (fr) {
      setProfile(fr.selected_profile);
      setStepUpEnabled(fr.step_up_enabled);
    }
  }, [fr]);

  const steps = fr?.steps ?? [];
  const doneCount = steps.filter((s) => s.done).length;
  const totalCount = steps.length;
  const rawPct =
    totalCount === 0 ? GOAL_GRADIENT_MIN_PCT : Math.round((doneCount / totalCount) * 100);
  const progressPct = Math.max(GOAL_GRADIENT_MIN_PCT, rawPct);
  const allAgents = devices.flatMap((d) => d.agents.map((ag) => ({ dev: d, ag })));
  const readinessLabel = workspaceQuery.isLoading
    ? "Checking setup..."
    : workspaceQuery.isError
      ? "Status unavailable"
      : totalCount === 0
        ? "Console connected"
        : `${doneCount} / ${totalCount} ready`;

  async function applyFirstRun(confirmProtection: boolean) {
    setPhase({ kind: "saving" });
    try {
      const updated = await api.completeFirstRun({
        profile,
        confirm_protection: confirmProtection,
        step_up_enabled: stepUpEnabled,
      });
      setPhase({
        kind: "ok",
        message: updated.confirmed
          ? `Protection profile (${updated.selected_profile}) activated across ${pluralize(devices.length, "endpoint")}.`
          : "Saved draft setup preferences.",
      });
      await workspaceQuery.refetch();
      await onChanged?.();
    } catch (e) {
      setPhase({
        kind: "error",
        message: e instanceof Error ? e.message : "Failed saving setup profile",
      });
    }
  }

  return (
    <VStack gap={4}>
      {workspaceQuery.isError && (
        <Banner
          status="error"
          title={
            workspaceQuery.error instanceof Error
              ? workspaceQuery.error.message
              : "Could not load onboarding workspace state."
          }
          collapsible={false}
          endContent={
            <Button
              variant="secondary"
              size="sm"
              label="Retry"
              onClick={() => void workspaceQuery.refetch()}
            />
          }
        />
      )}

      <Card padding={3}>
        <VStack gap={3}>
          <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
            <VStack gap={0}>
              <Heading level={1}>First run setup</Heading>
              <Text size="sm" color="secondary">
                Read-only endpoint scan completed. Choose Protected so agents cannot bypass hooks or alter rules.
              </Text>
            </VStack>
            <Badge
              variant={
                workspaceQuery.isError
                  ? "error"
                  : totalCount > 0 && doneCount === totalCount
                    ? "success"
                    : "info"
              }
              label={readinessLabel}
            />
          </HStack>

          <ProgressBar
            label="Readiness progress"
            value={progressPct}
            max={100}
            hasValueLabel
            formatValueLabel={() =>
              totalCount === 0
                ? "Console connected (baseline active)"
                : `${doneCount} of ${totalCount} steps complete`
            }
            variant={totalCount > 0 && doneCount === totalCount ? "success" : "accent"}
          />

          <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 12 }}>
            <VStack gap={1}>
              <Text size="sm" weight="semibold">
                Protection install profile
              </Text>
              <UiSdkSegmentedControl
                ariaLabel="Protection install profile"
                value={profile}
                onChange={(next) => setProfile(next)}
                options={[
                  {
                    value: "protected",
                    label: "Protected boundary",
                    icon: <GrdrIcon name="shield-check" size={14} />,
                  },
                  {
                    value: "user",
                    label: "User mode (requests only)",
                    icon: <GrdrIcon name="shield" size={14} />,
                  },
                ]}
              />
            </VStack>

            <CheckboxInput
              label="Require OS biometric step-up for sensitive actions"
              value={stepUpEnabled}
              onChange={(checked) => setStepUpEnabled(checked)}
            />
          </HStack>

          {phase.kind === "ok" && (
            <Banner status="success" title={phase.message} collapsible={false} />
          )}
          {phase.kind === "error" && (
            <Banner status="error" title={phase.message} collapsible={false} />
          )}

          <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
            <Button
              variant="ghost"
              size="sm"
              label="Inspect privacy and compliance"
              endContent={<GrdrIcon name="arrow-right" size={13} />}
              onClick={() => onNavigateCompliance?.()}
            />
            <HStack gap={2} align="center" style={{ flexWrap: "wrap" }}>
              <Button
                variant="secondary"
                size="sm"
                isDisabled={phase.kind === "saving"}
                label="Save draft"
                onClick={() => void applyFirstRun(false)}
              />
              <Button
                variant="primary"
                size="md"
                isDisabled={phase.kind === "saving"}
                icon={<GrdrIcon name="shield-check" size={15} />}
                label={phase.kind === "saving" ? "Applying profile..." : "Confirm protection profile"}
                onClick={() => void applyFirstRun(true)}
              />
            </HStack>
          </HStack>
        </VStack>
      </Card>

      <div className="grid-2">
        <Card padding={3}>
          <VStack gap={2}>
            <Heading level={2}>Onboarding checklist</Heading>
            {workspaceQuery.isLoading ? (
              <Text size="sm" color="secondary">
                Loading onboarding checklist...
              </Text>
            ) : steps.length === 0 ? (
              <div className="checklist">
                <div className="check-row" style={{ flexWrap: "wrap", gap: 12 }}>
                  <HStack gap={2} align="center">
                    <GrdrIcon name="check-circle" size={15} color="var(--tone-allow)" />
                    <VStack gap={0}>
                      <Text size="sm" weight="semibold">
                        Console started
                      </Text>
                      <Text size="sm" color="secondary">
                        Confirm a protection profile above to record baseline enrollment state.
                      </Text>
                    </VStack>
                  </HStack>
                  <StatusInline tone="allow" label="Done" />
                </div>
              </div>
            ) : (
              <div className="checklist">
                {steps.map((step) => (
                  <div key={step.id} className="check-row" style={{ flexWrap: "wrap", gap: 12 }}>
                    <HStack gap={2} align="center">
                      <GrdrIcon
                        name={step.done ? "check-circle" : "clock"}
                        size={15}
                        color={step.done ? "var(--tone-allow)" : "var(--ink-muted)"}
                      />
                      <VStack gap={0}>
                        <Text size="sm" weight="semibold">
                          {step.label}
                        </Text>
                        <Text size="sm" color="secondary">
                          {step.detail}
                        </Text>
                      </VStack>
                    </HStack>
                    <StatusInline
                      tone={step.done ? "allow" : "neutral"}
                      label={step.done ? "Done" : "Pending"}
                    />
                  </div>
                ))}
              </div>
            )}
          </VStack>
        </Card>

        <Card padding={3}>
          <VStack gap={2}>
            <HStack justify="between" align="center">
              <Heading level={2}>Discovered local harnesses</Heading>
              <Badge variant="neutral" label={pluralize(allAgents.length, "agent")} />
            </HStack>
            {allAgents.length === 0 ? (
              <EmptyState
                title="No harnesses discovered yet"
                description="Enroll an endpoint via Connect & MDM or run local agent discovery to map installed coding agents."
                icon={<GrdrIcon name="cpu" size={20} />}
              />
            ) : (
              <div className="checklist">
                {allAgents.map(({ dev, ag }) => (
                  <div key={`${dev.id}-${ag.id}`} className="check-row" style={{ flexWrap: "wrap", gap: 8 }}>
                    <HStack gap={2} align="center" style={{ flexWrap: "wrap" }}>
                      <EntityLink
                        kind="agent"
                        id={ag.id}
                        label={ag.name}
                        compact
                        onSelect={onOpenEntity}
                      />
                      <EntityLink
                        kind="device"
                        id={dev.id}
                        label={dev.hostname}
                        os={dev.os}
                        compact
                        onSelect={onOpenEntity}
                      />
                    </HStack>
                    <AssuranceBadge level={ag.assurance_level} control={ag.assurance.control} />
                  </div>
                ))}
              </div>
            )}
          </VStack>
        </Card>
      </div>
    </VStack>
  );
}
