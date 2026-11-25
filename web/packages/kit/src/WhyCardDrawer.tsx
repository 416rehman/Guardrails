import {
  Badge,
  Banner,
  Button,
  Card,
  Divider,
  GrdrIcon,
  Heading,
  HStack,
  Text,
  UiSdkDrawer,
  VStack,
} from "@grdr/ui";
import { formatActionLabel, formatTimestamp, presentFindingTitle } from "@grdr/i18n";
import { EntityLink, type EntityTarget } from "./EntityLink";
import { Quoted } from "./Quoted";
import { VerdictBadge } from "./VerdictBadge";

export interface WhyExplanationView {
  reference: string;
  receipt_id: string;
  attempt_id: string;
  heading: string;
  verdict: "allow" | "modify" | "step_up" | "defer" | "deny";
  status_code: string;
  component: string;
  action_class: string;
  rule_id: string;
  rule_title: string;
  pack_id: string;
  agent_name: string;
  device_id: string;
  device_name: string;
  session_id: string;
  target_quoted: string;
  reason: string;
  agent_told: string;
  timestamp: string;
  key_id: string | null;
  signature_status: string;
  primary_action_label: string;
  primary_action_route: string;
  approval_id: string | null;
  approver_label: string | null;
}

export function WhyCardDrawer({
  explanation,
  loading = false,
  errorMessage = null,
  onClose,
  onOpenEntity,
  onNavigateAction,
}: {
  explanation: WhyExplanationView | null;
  loading?: boolean;
  errorMessage?: string | null;
  onClose: () => void;
  onOpenEntity?: (target: EntityTarget) => void;
  onNavigateAction?: (routePath: string) => void;
}) {
  const open = Boolean(explanation || loading || errorMessage);

  return (
    <UiSdkDrawer
      open={open}
      onClose={onClose}
      title={explanation?.heading ?? "Decision explanation"}
      description={
        explanation
          ? `${explanation.status_code} · ${explanation.component}`
          : "Inspect exact policy match, quoted target, and agent notice"
      }
    >
      {loading && (
        <HStack gap={2} align="center">
          <GrdrIcon name="clock" size={15} />
          <Text size="sm" color="secondary">
            Loading signed receipt explanation...
          </Text>
        </HStack>
      )}

      {errorMessage && (
        <Banner status="error" title={errorMessage} collapsible={false} />
      )}

      {explanation && (
        <VStack gap={3}>
          <VStack gap={1}>
            <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
              <HStack gap={2} align="center" style={{ flexWrap: "wrap" }}>
                <VerdictBadge verdict={explanation.verdict} />
                <Badge
                  variant={explanation.signature_status === "verified" ? "success" : "neutral"}
                  icon={<GrdrIcon name="key-round" size={11} />}
                  label={
                    explanation.signature_status === "verified"
                      ? "Verified receipt"
                      : "Unsigned record"
                  }
                />
              </HStack>
            </HStack>
            <span
              className="mono"
              style={{
                fontSize: 12,
                color: "var(--ink-secondary)",
                overflowWrap: "anywhere",
                wordBreak: "normal",
              }}
            >
              {`Receipt ${explanation.receipt_id}${explanation.reference !== explanation.receipt_id ? ` · Ref ${explanation.reference}` : ""}`}
            </span>
          </VStack>

          <Card padding={3}>
            <VStack gap={2}>
              <Text size="sm" color="secondary" weight="semibold">
                What happened
              </Text>
              <HStack gap={1} align="center" style={{ flexWrap: "wrap", columnGap: 6, rowGap: 4 }}>
                <EntityLink
                  kind="agent"
                  label={explanation.agent_name}
                  compact
                  onSelect={onOpenEntity}
                />
                <Text size="sm" color="secondary">
                  requested
                </Text>
                <Badge variant="neutral" label={formatActionLabel(explanation.action_class)} />
                <Text size="sm" color="secondary">
                  on
                </Text>
                <EntityLink
                  kind="device"
                  id={explanation.device_id}
                  label={explanation.device_name}
                  compact
                  onSelect={onOpenEntity}
                />
              </HStack>
              <Quoted text={explanation.target_quoted} />
              <Text size="sm">{explanation.reason}</Text>
            </VStack>
          </Card>

          <Card padding={3}>
            <VStack gap={2}>
              <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
                <Text size="sm" color="secondary" weight="semibold">
                  Rule and policy pack
                </Text>
                <Text size="sm" color="secondary" className="mono">
                  {explanation.pack_id}
                </Text>
              </HStack>
              <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
                <Heading level={4}>{presentFindingTitle(explanation.rule_title)}</Heading>
                <EntityLink
                  kind="rule"
                  id={explanation.rule_id}
                  label={explanation.rule_id}
                  compact
                  onSelect={onOpenEntity}
                />
              </HStack>
              <HStack gap={2} align="center" style={{ flexWrap: "wrap" }}>
                <Text size="sm" color="secondary">
                  Session
                </Text>
                <EntityLink
                  kind="session"
                  id={explanation.session_id}
                  label={explanation.session_id}
                  compact
                  onSelect={onOpenEntity}
                />
              </HStack>
              {explanation.approver_label && (
                <Text size="sm" color="secondary">
                  {`Required approver: ${explanation.approver_label}`}
                </Text>
              )}
            </VStack>
          </Card>

          <Card padding={3}>
            <VStack gap={2}>
              <HStack gap={2} align="center">
                <GrdrIcon name="terminal" size={14} />
                <Text size="sm" color="secondary" weight="semibold">
                  What the agent was told (max 600 chars)
                </Text>
              </HStack>
              <Quoted text={explanation.agent_told} />
            </VStack>
          </Card>

          <Divider />

          <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
            <VStack gap={0}>
              <Text size="sm" color="secondary" className="mono">
                {`Key: ${explanation.key_id ?? "local-ephemeral"}`}
              </Text>
              <Text size="sm" color="secondary" hasTabularNumbers>
                {formatTimestamp(explanation.timestamp)}
              </Text>
            </VStack>
            <Button
              variant="primary"
              size="sm"
              label={explanation.primary_action_label}
              endContent={<GrdrIcon name="arrow-right" size={13} />}
              onClick={() => {
                onClose();
                onNavigateAction?.(explanation.primary_action_route);
              }}
            />
          </HStack>
        </VStack>
      )}
    </UiSdkDrawer>
  );
}
