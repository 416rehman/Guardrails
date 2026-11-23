import { useEffect, useState } from "react";
import { AlertOctagon, Check, Hand, ShieldOff } from "lucide-react";
import { api } from "../api";
import { Quoted } from "../components/Quoted";
import type {
  ApprovalRequest,
  Finding,
  FindingLifecycle,
  GrantScope,
  KillScope,
  KillSwitchState,
} from "../types";

interface RespondPageProps {
  approvals: ApprovalRequest[];
  findings: Finding[];
  killSwitch: KillSwitchState;
  defaultSessionId: string;
  onUpdated: () => void;
}

export function RespondPage({
  approvals,
  findings,
  killSwitch,
  defaultSessionId,
  onUpdated,
}: RespondPageProps) {
  const [error, setError] = useState<string | null>(null);
  const [armingKey, setArmingKey] = useState<string | null>(null);
  const [armedKey, setArmedKey] = useState<string | null>(null);

  const [scope, setScope] = useState<KillScope>("session");
  const [targetId, setTargetId] = useState(defaultSessionId || "sess-demo-refactor");
  const [killReason, setKillReason] = useState("Containment triggered by operator during triage");
  const [confirmKill, setConfirmKill] = useState(false);

  useEffect(() => {
    if (!armingKey) return;
    const timer = window.setTimeout(() => {
      setArmedKey(armingKey);
      setArmingKey(null);
    }, 1000);
    return () => window.clearTimeout(timer);
  }, [armingKey]);

  const pending = approvals.filter((a) => a.state.status === "pending");

  async function handleAllowClick(reqId: string, grantScope: GrantScope) {
    const key = `${reqId}:${grantScope}`;
    if (armedKey !== key) {
      setArmedKey(null);
      setArmingKey(key);
      return;
    }
    try {
      await api.decideApproval(reqId, true, grantScope, "Approved via Respond console");
      setArmedKey(null);
      onUpdated();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function handleDeny(reqId: string) {
    try {
      await api.decideApproval(reqId, false, "once", "Denied in Respond console");
      onUpdated();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function handleFindingStatus(id: string, lifecycle: FindingLifecycle) {
    try {
      await api.updateFinding(id, lifecycle);
      onUpdated();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function handleKillSwitch(action: "freeze" | "kill" | "release") {
    setError(null);
    try {
      await api.setKillSwitch({
        action,
        scope,
        target_id: scope === "organisation" ? "*" : targetId,
        reason: killReason,
        duration_minutes: action === "freeze" ? 60 : undefined,
      });
      setConfirmKill(false);
      onUpdated();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  return (
    <>
      <div className="page-header">
        <div>
          <h1>Respond</h1>
          <p>
            Graded approval queue, findings triage, and scoped kill switch controls.
          </p>
        </div>
      </div>

      {error && <div className="banner danger">{error}</div>}

      <section className="surface">
        <div className="page-header">
          <h2 className="section-title" style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <Hand size={16} />
            <span>Pending approvals ({pending.length})</span>
          </h2>
          <span style={{ fontSize: 12.5, color: "var(--ink-secondary)" }}>
            Allow actions arm for 1 second before confirming
          </span>
        </div>

        {pending.length === 0 ? (
          <p style={{ margin: 0, color: "var(--ink-secondary)" }}>No approval requests waiting.</p>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            {pending.map((req) => {
              const scopes: Array<{ scope: GrantScope; label: string }> = [
                { scope: "once", label: "Allow once" },
                { scope: "session", label: "Allow session" },
                { scope: "one_hour", label: "Allow 1 hour" },
              ];
              return (
                <div
                  key={req.id}
                  style={{
                    border: "1px solid var(--border-strong)",
                    borderRadius: "var(--radius-md)",
                    padding: "var(--space-3)",
                    backgroundColor: "var(--bg-elevated)",
                    display: "flex",
                    flexDirection: "column",
                    gap: 10,
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", flexWrap: "wrap", gap: 8 }}>
                    <div>
                      <strong>{req.rule_title}</strong>
                      <div style={{ fontSize: 12.5, color: "var(--ink-secondary)" }}>
                        Agent {req.agent_name} on {req.device_name} ({req.session_id}) · {req.required_grade}
                      </div>
                    </div>
                    <span className="badge ask">{req.action_class}</span>
                  </div>

                  <div>
                    <Quoted text={req.target} />
                  </div>
                  <div style={{ fontSize: 13, color: "var(--ink-secondary)" }}>{req.reason}</div>

                  <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                    <button
                      type="button"
                      className="btn btn-danger"
                      onClick={() => handleDeny(req.id)}
                    >
                      Deny
                    </button>
                    {scopes.map((opt) => {
                      const key = `${req.id}:${opt.scope}`;
                      const isArming = armingKey === key;
                      const isArmed = armedKey === key;
                      return (
                        <button
                          key={opt.scope}
                          type="button"
                          className={`btn arm-btn ${isArmed ? "btn-primary" : ""}`}
                          disabled={isArming}
                          onClick={() => handleAllowClick(req.id, opt.scope)}
                        >
                          <span
                            className="arm-fill"
                            style={{ width: isArming || isArmed ? "100%" : "0%" }}
                          />
                          <span style={{ position: "relative" }}>
                            {isArmed ? `Confirm ${opt.label}` : isArming ? "Arming..." : opt.label}
                          </span>
                        </button>
                      );
                    })}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>

      <div className="grid-2">
        <section className="surface">
          <h2 className="section-title">Findings ({findings.length})</h2>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Finding</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Transition</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f) => (
                  <tr key={f.id}>
                    <td>
                      <strong>{f.title}</strong>
                      <div style={{ marginTop: 4 }}><Quoted text={f.target} /></div>
                    </td>
                    <td>
                      <span className={`badge ${f.severity === "critical" || f.severity === "high" ? "danger" : "warning"}`}>
                        {f.severity}
                      </span>
                    </td>
                    <td>
                      <span className={`badge ${f.lifecycle === "resolved" ? "success" : "info"}`}>
                        {f.lifecycle}
                      </span>
                    </td>
                    <td>
                      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                        {f.lifecycle === "open" && (
                          <button type="button" className="btn" onClick={() => handleFindingStatus(f.id, "acknowledged")}>
                            Acknowledge
                          </button>
                        )}
                        {f.lifecycle !== "resolved" && (
                          <button type="button" className="btn" onClick={() => handleFindingStatus(f.id, "resolved")}>
                            <Check size={12} />
                            <span>Resolve</span>
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section className="surface">
          <div className="page-header">
            <h2 className="section-title" style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <ShieldOff size={16} />
              <span>Scoped kill switch</span>
            </h2>
            <span className={`badge ${killSwitch.state === "inactive" ? "success" : "danger"}`}>
              {killSwitch.state}
            </span>
          </div>

          <div className="form-grid">
            <div className="field">
              <label htmlFor="ks-scope">Scope</label>
              <select
                id="ks-scope"
                value={scope}
                onChange={(e) => setScope(e.target.value as KillScope)}
              >
                <option value="session">Session</option>
                <option value="device">Device</option>
                <option value="organisation">Organisation</option>
              </select>
            </div>
            <div className="field">
              <label htmlFor="ks-target">Target ID</label>
              <input
                id="ks-target"
                value={scope === "organisation" ? "*" : targetId}
                disabled={scope === "organisation"}
                onChange={(e) => setTargetId(e.target.value)}
              />
            </div>
            <div className="field full">
              <label htmlFor="ks-reason">Audit reason</label>
              <input
                id="ks-reason"
                value={killReason}
                onChange={(e) => setKillReason(e.target.value)}
              />
            </div>
            <div className="field full" style={{ flexDirection: "row", alignItems: "center", gap: 8 }}>
              <input
                id="ks-confirm"
                type="checkbox"
                checked={confirmKill}
                onChange={(e) => setConfirmKill(e.target.checked)}
              />
              <label htmlFor="ks-confirm" style={{ margin: 0 }}>
                Confirm containment action stops all matching agent actions immediately
              </label>
            </div>
            <div className="field full" style={{ flexDirection: "row", flexWrap: "wrap", gap: 8 }}>
              <button
                type="button"
                className="btn"
                disabled={!confirmKill}
                onClick={() => handleKillSwitch("freeze")}
              >
                Freeze (60 min)
              </button>
              <button
                type="button"
                className="btn btn-danger"
                disabled={!confirmKill}
                onClick={() => handleKillSwitch("kill")}
              >
                <AlertOctagon size={14} />
                <span>Engage kill switch</span>
              </button>
              {killSwitch.state !== "inactive" && (
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={() => handleKillSwitch("release")}
                >
                  Release
                </button>
              )}
            </div>
          </div>
        </section>
      </div>
    </>
  );
}
