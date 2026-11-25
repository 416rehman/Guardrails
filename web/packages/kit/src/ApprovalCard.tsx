import { useEffect, useState } from "react";
import { Badge, Button, GrdrIcon, HStack, Text, VStack } from "@grdr/ui";
import { EntityLink, type EntityTarget } from "./EntityLink";
import { Quoted } from "./Quoted";
import { VerdictBadge } from "./VerdictBadge";

type GrantScope = "once" | "session" | "one_hour";

export function ApprovalCard({
  id,
  ruleId,
  ruleTitle,
  requiredGrade,
  agentName,
  actionClass,
  deviceId,
  deviceName,
  deviceOs,
  target,
  reason,
  onAllow,
  onDeny,
  onOpenEntity,
  onWhy,
}: {
  id: string;
  ruleId?: string;
  ruleTitle: string;
  requiredGrade: string;
  agentName: string;
  actionClass: string;
  deviceId?: string;
  deviceName: string;
  deviceOs?: string;
  target: string;
  reason: string;
  onAllow: (id: string, scope: GrantScope) => Promise<void>;
  onDeny: (id: string) => Promise<void>;
  onOpenEntity?: (target: EntityTarget) => void;
  onWhy?: (approvalId: string) => void;
}) {
  const [armingScope, setArmingScope] = useState<GrantScope | null>(null);
  const [armedScope, setArmedScope] = useState<GrantScope | null>(null);

  useEffect(() => {
    if (!armingScope) return;
    const timer = window.setTimeout(() => {
      setArmedScope(armingScope);
      setArmingScope(null);
    }, 1000);
    return () => window.clearTimeout(timer);
  }, [armingScope]);

  async function handleAllow(scope: GrantScope) {
    if (armedScope !== scope) {
      setArmedScope(null);
      setArmingScope(scope);
      return;
    }
    await onAllow(id, scope);
    setArmedScope(null);
  }

  return (
    <div className="grdr-attention-card">
      <VStack gap={2}>
        <HStack justify="between" align="center">
          <HStack gap={2} align="center">
            <VerdictBadge verdict="step_up" />
            <strong>{ruleTitle}</strong>
          </HStack>
          <Badge
            variant="warning"
            label={
              requiredGrade === "G1"
                ? "Approval required"
                : requiredGrade === "G2"
                  ? "Admin approval"
                  : requiredGrade
            }
          />
        </HStack>

        <HStack gap={1} align="center" style={{ flexWrap: "wrap", columnGap: 6, rowGap: 2 }}>
          <EntityLink kind="agent" label={agentName} compact onSelect={onOpenEntity} />
          <Text type="supporting" color="secondary" size="sm">
            {`(${actionClass}) on`}
          </Text>
          <EntityLink
            kind="device"
            id={deviceId ?? deviceName}
            label={deviceName}
            os={deviceOs}
            compact
            onSelect={onOpenEntity}
          />
          {ruleId && (
            <>
              <span style={{ color: "var(--ink-muted)" }} aria-hidden="true">·</span>
              <EntityLink kind="rule" id={ruleId} label={ruleId} compact onSelect={onOpenEntity} />
            </>
          )}
        </HStack>
        <div>
          <Quoted text={target} />
        </div>
        <Text>{reason}</Text>

        <HStack gap={2} style={{ flexWrap: "wrap" }}>
          <Button
            variant="destructive"
            size="sm"
            label="Deny"
            onClick={() => void onDeny(id)}
          />
          {onWhy && (
            <Button
              variant="ghost"
              size="sm"
              label="Why?"
              endContent={<GrdrIcon name="arrow-right" size={12} />}
              onClick={() => onWhy(id)}
            />
          )}
          {(["once", "session", "one_hour"] as const).map((scope) => {
            const armed = armedScope === scope;
            const arming = armingScope === scope;
            const scopeLabel =
              scope === "once"
                ? "Allow once"
                : scope === "session"
                  ? "Allow for this session"
                  : "Allow for one hour";
            return (
              <Button
                key={scope}
                variant={armed ? "primary" : "secondary"}
                size="sm"
                className="grdr-ui-arm-btn"
                label={armed ? `Confirm ${scopeLabel}` : arming ? "Arming (1s)..." : scopeLabel}
                onClick={() => void handleAllow(scope)}
              />
            );
          })}
        </HStack>
      </VStack>
    </div>
  );
}
