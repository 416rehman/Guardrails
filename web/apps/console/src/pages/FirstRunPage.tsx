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
  const [stepUpEnabled, setStepUpEnabled] = useState(false);
  const [phase, setPhase] = useState<FirstRunPhase>({ kind: "idle" });

  useEffect(() => {
    if (fr) {
      setProfile(fr.selected_profile);
      setStepUpEnabled(fr.step_up_enabled);
    }
  }, [fr]);

  const steps = fr?.steps ?? [];
  const doneCount = steps.filter((s) => s.done).length;
  const totalCount = steps.length || 6;
  const progressPct = totalCount === 0 ? 50 : Math.round((doneCount / totalCount) * 100);
  const allAgents = devices.flatMap((d) =>
    d.agents.map((ag) => ({ dev: d, ag })),
  );

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
              variant={doneCount === totalCount ? "success" : "info"}
              label={`${doneCount} / ${totalCount} ready`}
            />
          </HStack>

          <ProgressBar
            label="Readiness progress"
            value={progressPct}
            max={100}
            hasValueLabel
            formatValueLabel={() => `${doneCount} of ${totalCount} steps complete`}
            variant={doneCount === totalCount ? "success" : "accent"}
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
              label="Inspect privacy & compliance"
              endContent={<GrdrIcon name="arrow-right" size={13} />}
              onClick={() => onNavigateCompliance?.()}
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
        </VStack>
      </Card>

      <div className="grid-2">
        <Card padding={3}>
          <VStack gap={2}>
            <Heading level={2}>Onboarding checklist</Heading>
            {steps.map((step) => (
              <div key={step.id} className="kv-row" style={{ gap: 12 }}>
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
          </VStack>
        </Card>

        <Card padding={3}>
          <VStack gap={2}>
            <HStack justify="between" align="center">
              <Heading level={2}>Discovered local harnesses</Heading>
              <Badge variant="neutral" label={pluralize(allAgents.length, "agent")} />
            </HStack>
            {allAgents.map(({ dev, ag }) => (
              <div key={`${dev.id}-${ag.id}`} className="kv-row" style={{ flexWrap: "wrap", gap: 8 }}>
                <HStack gap={2} align="center" style={{ flexWrap: "wrap" }}>
                  <EntityLink kind="agent" id={ag.id} label={ag.name} compact onSelect={onOpenEntity} />
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
          </VStack>
        </Card>
      </div>
    </VStack>
  );
}
