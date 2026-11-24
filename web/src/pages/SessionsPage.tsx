import { useEffect, useState } from "react";
import { PlusCircle, Shield, ShieldAlert, ShieldCheck, Tag } from "lucide-react";
import { api } from "../api";
import { Quoted } from "../components/Quoted";
import { VerdictBadge } from "../components/VerdictBadge";
import type { ActionAttempt, SessionDetailResponse, SessionLabel, SessionSummary } from "../types";

const LABEL_NAMES: Record<SessionLabel, string> = {
  credential_accessed: "Credential accessed",
  untrusted_web_fetched: "Untrusted web fetched",
  repeated_denials: "Repeated denials",
  tainted_exfil_risk: "Tainted exfil risk",
};

function labelTone(label: SessionLabel): string {
  switch (label) {
    case "tainted_exfil_risk":
    case "repeated_denials":
      return "danger";
    case "credential_accessed":
      return "warning";
    case "untrusted_web_fetched":
      return "info";
  }
}

interface SessionsPageProps {
  sessions: SessionSummary[];
  searchQuery: string;
  onCreateRuleFromAttempt: (attempt: ActionAttempt) => void;
}

export function SessionsPage({ sessions, searchQuery, onCreateRuleFromAttempt }: SessionsPageProps) {
  const [selectedId, setSelectedId] = useState<string | null>(sessions[0]?.id ?? null);
  const [detail, setDetail] = useState<SessionDetailResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const query = searchQuery.trim().toLowerCase();
  const filtered = sessions.filter(
    (s) =>
      !query ||
      s.id.toLowerCase().includes(query) ||
      s.agent_name.toLowerCase().includes(query) ||
      s.device_name.toLowerCase().includes(query),
  );

  const firstFilteredId = filtered[0]?.id ?? null;

  useEffect(() => {
    if (!selectedId && firstFilteredId) {
      setSelectedId(firstFilteredId);
    }
  }, [firstFilteredId, selectedId]);

  useEffect(() => {
    if (!selectedId) {
      setDetail(null);
      return;
    }
    let cancelled = false;
    api
      .getSessionDetail(selectedId)
      .then((res) => {
        if (!cancelled) {
          setDetail(res);
          setError(null);
        }
      })
      .catch((err: Error) => {
        if (!cancelled) setError(err.message);
      });
    return () => {
      cancelled = true;
    };
  }, [selectedId, sessions]);

  return (
    <>
      <div className="page-header">
        <div>
          <h1>Sessions</h1>
          <p>
            Ordered action timelines with cryptographic decision receipts and rule promotion handoff.
          </p>
        </div>
      </div>

      <section className="surface">
        <h2 className="section-title">Recorded sessions ({filtered.length})</h2>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Session</th>
                <th>Agent</th>
                <th>Device</th>
                <th>Enforcing labels</th>
                <th>Actions</th>
                <th>Blocked</th>
                <th>Asked</th>
                <th>Watch hits</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((sess) => {
                const labels = sess.labels ?? [];
                return (
                  <tr
                    key={sess.id}
                    className={`selectable ${selectedId === sess.id ? "selected" : ""}`}
                    onClick={() => setSelectedId(sess.id)}
                  >
                    <td className="mono">{sess.id}</td>
                    <td><strong>{sess.agent_name}</strong></td>
                    <td>{sess.device_name}</td>
                    <td>
                      {labels.length === 0 ? (
                        <span style={{ color: "var(--ink-muted)", fontSize: 12 }}>None</span>
                      ) : (
                        <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                          {labels.map((lbl) => (
                            <span key={lbl} className={`badge ${labelTone(lbl)}`}>
                              {LABEL_NAMES[lbl]}
                            </span>
                          ))}
                        </div>
                      )}
                    </td>
                    <td className="tabular">{sess.total_actions}</td>
                    <td className="tabular">{sess.blocked_count}</td>
                    <td className="tabular">{sess.step_up_count}</td>
                    <td className="tabular">{sess.watch_hits}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>

      {error && <div className="banner danger">{error}</div>}

      {detail && (
        <section className="surface">
          <div className="page-header">
            <div>
              <h2 className="section-title" style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <Shield size={16} />
                <span>Timeline for {detail.session.id}</span>
              </h2>
              <p style={{ margin: "4px 0 0", color: "var(--ink-secondary)" }}>
                Agent: {detail.session.agent_name} on {detail.session.device_name}
              </p>
              {(detail.session.labels ?? []).length > 0 && (
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 8, alignItems: "center" }}>
                  <Tag size={13} color="var(--ink-muted)" />
                  {(detail.session.labels ?? []).map((lbl) => (
                    <span key={lbl} className={`badge ${labelTone(lbl)}`}>
                      {LABEL_NAMES[lbl]}
                    </span>
                  ))}
                </div>
              )}
            </div>
            <span className="badge info tabular">{detail.attempts.length} event(s)</span>
          </div>

          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Action class</th>
                  <th>Target</th>
                  <th>Verdict</th>
                  <th>Rule & reason</th>
                  <th>Receipt</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {detail.attempts.map((attempt) => {
                  const receipt = detail.receipts.find((r) => r.attempt_id === attempt.id);
                  return (
                    <tr key={attempt.id}>
                      <td><span className="mono">{attempt.action_class}</span></td>
                      <td><Quoted text={attempt.target} /></td>
                      <td>
                        {receipt ? (
                          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                            <VerdictBadge verdict={receipt.verdict} />
                            {receipt.mode_applied === "watch" && receipt.would_be && (
                              <span style={{ fontSize: 11.5, color: "var(--tone-watch)" }}>
                                Watch would_be: {receipt.would_be}
                              </span>
                            )}
                          </div>
                        ) : (
                          "-"
                        )}
                      </td>
                      <td>
                        <div style={{ fontWeight: 500 }}>{receipt?.rule_id ?? "no-match"}</div>
                        <div style={{ fontSize: 12.5, color: "var(--ink-secondary)" }}>
                          {receipt?.reason ?? "-"}
                        </div>
                      </td>
                      <td className="mono" title={receipt?.receipt_digest}>
                        {receipt ? (
                          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                            <span>{receipt.receipt_digest.slice(0, 12)}</span>
                            {receipt.signature_verified === true && (
                              <span
                                className="badge success"
                                style={{ display: "inline-flex", alignItems: "center", gap: 4, width: "fit-content" }}
                              >
                                <ShieldCheck size={11} />
                                <span>Signed ({receipt.key_id ?? "verified"})</span>
                              </span>
                            )}
                            {receipt.signature_verified === false && (
                              <span
                                className="badge danger"
                                style={{ display: "inline-flex", alignItems: "center", gap: 4, width: "fit-content" }}
                              >
                                <ShieldAlert size={11} />
                                <span>Invalid signature</span>
                              </span>
                            )}
                          </div>
                        ) : (
                          "-"
                        )}
                      </td>
                      <td>
                        <button
                          type="button"
                          className="btn"
                          onClick={() => onCreateRuleFromAttempt(attempt)}
                        >
                          <PlusCircle size={13} />
                          <span>Create rule</span>
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </>
  );
}
