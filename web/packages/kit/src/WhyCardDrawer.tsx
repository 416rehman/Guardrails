// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

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
  useGrdrLocale,
} from "@grdr/ui";
import { formatActionLabel, formatTimestamp, presentFindingTitle, t } from "@grdr/i18n";
import { EntityLink, type EntityTarget } from "./EntityLink";
import { Quoted, sanitizeUntrustedText } from "./Quoted";
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
  const { locale } = useGrdrLocale();
  const open = Boolean(explanation || loading || errorMessage);

  return (
    <UiSdkDrawer
      open={open}
      onClose={onClose}
      title={
        explanation
          ? sanitizeUntrustedText(explanation.heading).safeText
          : t("kit.why.default_title", undefined, locale)
      }
      description={
        explanation
          ? `${explanation.status_code} · ${explanation.component}`
          : t("kit.why.default_desc", undefined, locale)
      }
    >
      {loading && (
        <HStack gap={2} align="center">
          <GrdrIcon name="clock" size={15} />
          <Text size="sm" color="secondary">
            {t("kit.why.loading", undefined, locale)}
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
                      ? t("kit.why.verified_receipt", undefined, locale)
                      : t("kit.why.unsigned_record", undefined, locale)
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
              {t("kit.why.receipt_id", { receiptId: explanation.receipt_id }, locale)}
              {explanation.reference !== explanation.receipt_id
                ? ` · ${t("kit.why.ref_id", { reference: explanation.reference }, locale)}`
                : ""}
            </span>
          </VStack>

          <Card padding={3}>
            <VStack gap={2}>
              <Text size="sm" color="secondary" weight="semibold">
                {t("kit.why.what_happened", undefined, locale)}
              </Text>
              <HStack gap={1} align="center" style={{ flexWrap: "wrap", columnGap: 6, rowGap: 4 }}>
                <EntityLink
                  kind="agent"
                  label={explanation.agent_name}
                  compact
                  onSelect={onOpenEntity}
                />
                <Text size="sm" color="secondary">
                  {t("kit.why.requested", undefined, locale)}
                </Text>
                <Badge
                  variant="neutral"
                  label={<bdi>{formatActionLabel(explanation.action_class, locale)}</bdi>}
                />
                <Text size="sm" color="secondary">
                  {t("kit.why.on", undefined, locale)}
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
              <Text size="sm"><bdi>{sanitizeUntrustedText(explanation.reason).safeText}</bdi></Text>
            </VStack>
          </Card>

          <Card padding={3}>
            <VStack gap={2}>
              <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
                <Text size="sm" color="secondary" weight="semibold">
                  {t("kit.why.rule_and_pack", undefined, locale)}
                </Text>
                <Text size="sm" color="secondary" className="mono">
                  <bdi dir="ltr">{explanation.pack_id}</bdi>
                </Text>
              </HStack>
              <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
                {/* untrusted rule title fallback */}
                <Heading level={4}>
                  <bdi>{sanitizeUntrustedText(presentFindingTitle(explanation.rule_title, undefined, locale)).safeText}</bdi>
                </Heading>
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
                  {t("kit.why.session", undefined, locale)}
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
                  {t("kit.why.required_approver", { approver: explanation.approver_label }, locale)}
                </Text>
              )}
            </VStack>
          </Card>

          <Card padding={3}>
            <VStack gap={2}>
              <HStack gap={2} align="center">
                <GrdrIcon name="terminal" size={14} />
                <Text size="sm" color="secondary" weight="semibold">
                  {t("kit.why.agent_told", undefined, locale)}
                </Text>
              </HStack>
              <Quoted text={explanation.agent_told} />
            </VStack>
          </Card>

          <Divider />

          <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
            <VStack gap={0}>
              <Text size="sm" color="secondary" className="mono">
                {t(
                  "kit.why.key_label",
                  { keyId: explanation.key_id ?? t("kit.why.key_ephemeral", undefined, locale) },
                  locale,
                )}
              </Text>
              <Text size="sm" color="secondary" hasTabularNumbers>
                {formatTimestamp(explanation.timestamp, locale)}
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
