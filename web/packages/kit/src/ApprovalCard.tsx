import { useEffect, useState } from "react";
import { Badge, Button, Card, HStack, Text, VStack } from "@grdr/ui";
import { Quoted } from "./Quoted";
import { VerdictBadge } from "./VerdictBadge";

type GrantScope = "once" | "session" | "one_hour";

export function ApprovalCard({
  id,
  ruleTitle,
  requiredGrade,
  agentName,
  actionClass,
  deviceName,
  target,
  reason,
  onAllow,
  onDeny,
}: {
  id: string;
  ruleTitle: string;
  requiredGrade: string;
  agentName: string;
  actionClass: string;
  deviceName: string;
  target: string;
  reason: string;
  onAllow: (id: string, scope: GrantScope) => Promise<void>;
  onDeny: (id: string) => Promise<void>;
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
    <Card padding={3}>
      <VStack gap={2}>
        <HStack justify="between" align="center">
          <HStack gap={2} align="center">
            <VerdictBadge verdict="step_up" />
            <strong>{ruleTitle}</strong>
          </HStack>
          <Badge variant="warning" label={`Grade ${requiredGrade}`} />
        </HStack>

        <Text type="supporting" color="secondary" size="sm">
          {`${agentName} (${actionClass}) on ${deviceName}`}
        </Text>
        <div>
          <Quoted text={target} />
        </div>
        <Text>{reason}</Text>

        <HStack gap={2}>
          <Button
            variant="destructive"
            size="sm"
            label="Deny"
            onClick={() => void onDeny(id)}
          />
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
    </Card>
  );
}
