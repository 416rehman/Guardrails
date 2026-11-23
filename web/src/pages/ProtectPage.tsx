import { useEffect, useState } from "react";
import { CheckCircle2, Lock, Play, Plus } from "lucide-react";
import { api } from "../api";
import { ModeControl } from "../components/ModeControl";
import { ModeBadge, VerdictBadge } from "../components/VerdictBadge";
import { Quoted } from "../components/Quoted";
import type { ActionAttempt, ActionClass, Device, Mode, PolicyPack, ReplaySummary } from "../types";

interface ProtectPageProps {
  packs: PolicyPack[];
  devices: Device[];
  prefillAttempt: ActionAttempt | null;
  onClearPrefill: () => void;
  onUpdated: () => void;
}

const ACTION_CLASSES: ActionClass[] = [
  "exec",
  "file.read",
  "file.write",
  "file.delete",
  "net.connect",
  "net.request",
  "mcp.call",
  "cred.use",
  "elevate",
  "config.change",
  "data.flow",
];

export function ProtectPage({
  packs,
  devices,
  prefillAttempt,
  onClearPrefill,
  onUpdated,
}: ProtectPageProps) {
  const [replay, setReplay] = useState<{ ruleId: string; summary: ReplaySummary } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showNewForm, setShowNewForm] = useState<boolean>(prefillAttempt !== null);

  const [title, setTitle] = useState("Require approval for .env secret edits");
  const [actionClass, setActionClass] = useState<ActionClass>("file.write");
  const [containsPattern, setContainsPattern] = useState(".env");
  const [mode, setMode] = useState<Mode>("ask");
  const [reason, setReason] = useState("Modifying environment secret files requires operator approval.");

  useEffect(() => {
    if (prefillAttempt) {
      setShowNewForm(true);
      setTitle(`Govern ${prefillAttempt.action_class} on ${prefillAttempt.agent_name}`);
      setActionClass(prefillAttempt.action_class);
      setContainsPattern(prefillAttempt.target);
      setMode("ask");
      setReason(`Rule created from observed ${prefillAttempt.action_class} attempt.`);
    }
  }, [prefillAttempt]);

  const boundaryDevices = devices.filter((d) => d.install_profile === "protected").length;
  const requestDevices = devices.filter((d) => d.install_profile === "user").length;

  async function handleModeChange(ruleId: string, currentMode: Mode, nextMode: Mode) {
    setError(null);
    if (currentMode === "watch" && (nextMode === "ask" || nextMode === "block")) {
      try {
        const summary = await api.replayRule(ruleId, nextMode);
        setReplay({ ruleId, summary });
      } catch (err) {
        setError((err as Error).message);
      }
      return;
    }

    try {
      await api.updateRuleMode(ruleId, nextMode, false);
      onUpdated();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function confirmReplayPromotion() {
    if (!replay) return;
    try {
      await api.updateRuleMode(replay.ruleId, replay.summary.candidate_mode, true);
      setReplay(null);
      onUpdated();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function handleCreateRule(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api.createRule({
        title,
        description: reason,
        mode,
        matcher: {
          action_classes: [actionClass],
          target_prefixes: [],
          target_contains: [containsPattern],
          agents: [],
        },
        reason_template: reason,
      });
      setShowNewForm(false);
      onClearPrefill();
      onUpdated();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  return (
    <>
      <div className="page-header">
        <div>
          <h1>Protect</h1>
          <p>
            Rules execute locally in Off, Watch, Ask, or Block mode. Protected endpoints enforce via boundary; User endpoints enforce as requests ({boundaryDevices} boundary, {requestDevices} request device(s)).
          </p>
        </div>
        <button
          type="button"
          className="btn btn-primary"
          onClick={() => setShowNewForm((prev) => !prev)}
        >
          <Plus size={14} />
          <span>{showNewForm ? "Close rule builder" : "New rule"}</span>
        </button>
      </div>

      {error && <div className="banner danger">{error}</div>}

      {showNewForm && (
        <section className="surface">
          <h2 className="section-title">Create policy rule</h2>
          <form onSubmit={handleCreateRule} className="form-grid">
            <div className="field">
              <label htmlFor="rule-title">Rule title</label>
              <input
                id="rule-title"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                required
              />
            </div>
            <div className="field">
              <label htmlFor="rule-action">Action class</label>
              <select
                id="rule-action"
                value={actionClass}
                onChange={(e) => setActionClass(e.target.value as ActionClass)}
              >
                {ACTION_CLASSES.map((ac) => (
                  <option key={ac} value={ac}>{ac}</option>
                ))}
              </select>
            </div>
            <div className="field">
              <label htmlFor="rule-pattern">Target contains pattern</label>
              <input
                id="rule-pattern"
                value={containsPattern}
                onChange={(e) => setContainsPattern(e.target.value)}
                required
              />
            </div>
            <div className="field">
              <label htmlFor="rule-mode">Initial mode</label>
              <ModeControl value={mode} onChange={setMode} />
            </div>
            <div className="field full">
              <label htmlFor="rule-reason">Reason shown on block or approval</label>
              <input
                id="rule-reason"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                required
              />
            </div>
            <div className="field full" style={{ flexDirection: "row", justifyContent: "flex-end", gap: 8 }}>
              <button
                type="button"
                className="btn"
                onClick={() => {
                  setShowNewForm(false);
                  onClearPrefill();
                }}
              >
                Cancel
              </button>
              <button type="submit" className="btn btn-primary">
                Save rule
              </button>
            </div>
          </form>
        </section>
      )}

      {replay && (
        <section className="surface" style={{ borderColor: "var(--tone-watch)" }}>
          <div className="page-header">
            <div>
              <h2 className="section-title" style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <Play size={15} />
                <span>Replay impact before promoting {replay.ruleId}</span>
              </h2>
              <p style={{ margin: "4px 0 0", color: "var(--ink-secondary)" }}>
                Promoting a Watch rule requires reviewing historical matches over the selected window.
              </p>
            </div>
            <ModeBadge mode={replay.summary.candidate_mode} />
          </div>

          <div style={{ display: "flex", flexWrap: "wrap", gap: 16 }}>
            <span className="badge success">
              <CheckCircle2 size={12} />
              <span>Window chosen: {replay.summary.window_label}</span>
            </span>
            <span className="badge info tabular">Scanned: {replay.summary.total_scanned}</span>
            <span className="badge warning tabular">Matched: {replay.summary.matched}</span>
            <span className="badge ask tabular">Would ask: {replay.summary.would_ask}</span>
            <span className="badge block tabular">Would block: {replay.summary.would_block}</span>
          </div>

          {replay.summary.samples.length > 0 && (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Session</th>
                    <th>Agent</th>
                    <th>Target</th>
                    <th>Current</th>
                    <th>After promotion</th>
                  </tr>
                </thead>
                <tbody>
                  {replay.summary.samples.map((sample) => (
                    <tr key={sample.attempt_id}>
                      <td className="mono">{sample.session_id}</td>
                      <td>{sample.agent_name}</td>
                      <td><Quoted text={sample.target} /></td>
                      <td><VerdictBadge verdict={sample.current_verdict} /></td>
                      <td><VerdictBadge verdict={sample.candidate_verdict} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
            <button type="button" className="btn" onClick={() => setReplay(null)}>
              Keep in Watch
            </button>
            <button type="button" className="btn btn-primary" onClick={confirmReplayPromotion}>
              Confirm promotion to {replay.summary.candidate_mode}
            </button>
          </div>
        </section>
      )}

      {packs.map((pack) => (
        <section key={pack.id} className="surface">
          <div className="page-header">
            <div>
              <h2 className="section-title">{pack.name} ({pack.version})</h2>
              <p style={{ margin: "4px 0 0", color: "var(--ink-secondary)" }}>{pack.description}</p>
            </div>
            <span className="badge info">{pack.channel}</span>
          </div>

          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Rule</th>
                  <th>Match</th>
                  <th>Hits</th>
                  <th>Mode control</th>
                </tr>
              </thead>
              <tbody>
                {pack.rules.map((rule) => (
                  <tr key={rule.id}>
                    <td>
                      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                        <strong>{rule.title}</strong>
                        {rule.locked && (
                          <span className="badge danger" title="Locked baseline floor rule">
                            <Lock size={11} />
                            <span>Floor</span>
                          </span>
                        )}
                      </div>
                      <div style={{ fontSize: 12.5, color: "var(--ink-secondary)", marginTop: 2 }}>
                        {rule.description}
                      </div>
                    </td>
                    <td>
                      <div className="mono">{rule.matcher.action_classes.join(", ")}</div>
                      <div style={{ fontSize: 12, color: "var(--ink-muted)" }}>
                        {rule.matcher.target_contains.slice(0, 3).join(", ")}
                      </div>
                    </td>
                    <td className="tabular">{rule.hits}</td>
                    <td>
                      <ModeControl
                        value={rule.mode}
                        locked={rule.locked}
                        onChange={(next) => handleModeChange(rule.id, rule.mode, next)}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ))}
    </>
  );
}
