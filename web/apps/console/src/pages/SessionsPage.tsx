import { useEffect, useState } from "react";
import { api, type ActionAttempt, type SessionDetailResponse, type SessionSummary } from "@grdr/api";
import { Quoted, SessionLabelBadge, VerdictBadge } from "@grdr/kit";
import {
  Badge,
  Banner,
  Button,
  GrdrIcon,
  HarnessIcon,
  Heading,
  HStack,
  Text,
  UiSdkSegmentedControl,
  VStack,
} from "@grdr/ui";

type SessionViewMode = "graph" | "timeline" | "stream";

export function SessionsPage({
  sessions,
  searchQuery,
  onCreateRuleFromAttempt,
}: {
  sessions: SessionSummary[];
  searchQuery: string;
  onCreateRuleFromAttempt: (attempt: ActionAttempt) => void;
}) {
  const [selectedId, setSelectedId] = useState<string | null>(sessions[0]?.id ?? null);
  const [selectedAttemptId, setSelectedAttemptId] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<SessionViewMode>("graph");
  const [zoomPct, setZoomPct] = useState<number>(100);
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
          setSelectedAttemptId(res.attempts[0]?.id ?? null);
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

  const focusedAttempt =
    detail?.attempts.find((a) => a.id === selectedAttemptId) ?? detail?.attempts[0] ?? null;
  const focusedReceipt = focusedAttempt
    ? detail?.receipts.find((r) => r.attempt_id === focusedAttempt.id)
    : undefined;

  return (
    <VStack gap={4}>
      <div className="page-header">
        <div>
          <Heading level={1}>Sessions</Heading>
          <Text color="secondary">
            Action storylines, interactive execution graphs, and high-density signed receipt streams.
          </Text>
        </div>
      </div>

      {error && <Banner status="error" title={error} collapsible={false} />}

      <div className="storyline-split">
        <div className="ledger-section">
          <div className="ledger-header">
            <h2 className="ledger-title">{`Recorded sessions (${filtered.length})`}</h2>
          </div>

          <div className="ledger-list">
            {filtered.map((sess) => {
              const labels = sess.labels ?? [];
              const isSelected = selectedId === sess.id;
              return (
                <div
                  key={sess.id}
                  className={`ledger-row selectable ${isSelected ? "selected" : ""}`}
                  style={{ paddingInline: 12, cursor: "pointer" }}
                  onClick={() => setSelectedId(sess.id)}
                >
                  <div className="ledger-row-main">
                    <HStack gap={2} align="center">
                      <HarnessIcon name={sess.agent_name} size={15} />
                      <div>
                        <strong>{sess.agent_name}</strong>
                        <div className="mono" style={{ color: "var(--ink-muted)" }}>
                          {`${sess.device_name}, ${sess.total_actions} call(s)`}
                        </div>
                      </div>
                    </HStack>
                    <HStack gap={1}>
                      {sess.blocked_count > 0 && (
                        <Badge variant="error" label={`${sess.blocked_count} denied`} />
                      )}
                      {sess.step_up_count > 0 && (
                        <Badge variant="warning" label={`${sess.step_up_count} ask`} />
                      )}
                    </HStack>
                  </div>

                  {labels.length > 0 && (
                    <HStack gap={1}>
                      {labels.map((lbl) => (
                        <SessionLabelBadge key={lbl} label={lbl} />
                      ))}
                    </HStack>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        <div className="ledger-section">
          {detail ? (
            <>
              <div className="ledger-header" style={{ flexWrap: "wrap", gap: 10 }}>
                <div>
                  <h2 className="ledger-title">{`${detail.session.agent_name} on ${detail.session.device_name}`}</h2>
                  <Text size="sm" color="secondary" className="mono">
                    {detail.session.id}
                  </Text>
                </div>
                <HStack gap={2} align="center">
                  <UiSdkSegmentedControl<SessionViewMode>
                    ariaLabel="Session inspection mode"
                    value={viewMode}
                    options={[
                      {
                        value: "graph",
                        label: "Graph",
                        icon: <GrdrIcon name="git-branch" size={13} />,
                      },
                      {
                        value: "timeline",
                        label: "Timeline",
                        icon: <GrdrIcon name="list" size={13} />,
                      },
                      {
                        value: "stream",
                        label: "Stream",
                        icon: <GrdrIcon name="activity" size={13} />,
                      },
                    ]}
                    onChange={setViewMode}
                  />
                  <Badge variant="info" label={`${detail.attempts.length} step(s)`} />
                </HStack>
              </div>

              {viewMode === "graph" && (
                <div className="graph-workspace" aria-label="Session execution graph">
                  <div className="graph-toolbar" role="toolbar" aria-label="Graph viewport controls">
                    <button
                      type="button"
                      className="graph-tool-btn"
                      title="Zoom in"
                      onClick={() => setZoomPct((z) => Math.min(130, z + 15))}
                    >
                      <GrdrIcon name="zoom-in" size={14} />
                    </button>
                    <button
                      type="button"
                      className="graph-tool-btn"
                      title="Zoom out"
                      onClick={() => setZoomPct((z) => Math.max(70, z - 15))}
                    >
                      <GrdrIcon name="zoom-out" size={14} />
                    </button>
                    <button
                      type="button"
                      className="graph-tool-btn"
                      title="Reset fit"
                      onClick={() => setZoomPct(100)}
                    >
                      <GrdrIcon name="maximize" size={14} />
                    </button>
                  </div>

                  <div style={{ overflowX: "auto" }}>
                    <svg
                      width={`${zoomPct}%`}
                      height={Math.max(240, detail.attempts.length * 64 + 40)}
                      viewBox={`0 0 740 ${Math.max(240, detail.attempts.length * 64 + 40)}`}
                      role="img"
                      aria-label="Agent session execution path graph"
                    >
                      <circle cx="52" cy="118" r="18" fill="var(--bg-canvas)" stroke="var(--accent-primary)" strokeWidth="2" />
                      <text x="52" y="122" textAnchor="middle" fontSize="10" fontWeight="700" fill="var(--ink-primary)">
                        HOST
                      </text>
                      <text x="52" y="150" textAnchor="middle" fontSize="11" fill="var(--ink-secondary)">
                        {detail.session.device_name}
                      </text>

                      <path d="M 70 118 L 138 118" stroke="var(--border-strong)" strokeWidth="1.6" />

                      <circle cx="158" cy="118" r="18" fill="var(--bg-canvas)" stroke="var(--tone-allow)" strokeWidth="2" />
                      <text x="158" y="122" textAnchor="middle" fontSize="10" fontWeight="700" fill="var(--tone-allow)">
                        AGNT
                      </text>
                      <text x="158" y="150" textAnchor="middle" fontSize="11" fill="var(--ink-primary)">
                        {detail.session.agent_name}
                      </text>

                      <path d="M 176 118 L 244 118" stroke="var(--border-strong)" strokeWidth="1.6" />

                      <circle cx="264" cy="118" r="18" fill="var(--bg-canvas)" stroke="var(--accent-primary)" strokeWidth="2" />
                      <text x="264" y="122" textAnchor="middle" fontSize="10" fontWeight="700" fill="var(--accent-primary)">
                        GRDR
                      </text>
                      <text x="264" y="150" textAnchor="middle" fontSize="11" fill="var(--ink-secondary)">
                        Policy engine
                      </text>

                      {detail.attempts.map((attempt, idx) => {
                        const receipt = detail.receipts.find((r) => r.attempt_id === attempt.id);
                        const y = 34 + idx * 62;
                        const verdict = receipt?.verdict ?? "allow";
                        const nodeStroke =
                          verdict === "deny"
                            ? "var(--tone-block)"
                            : verdict === "step_up"
                              ? "var(--tone-ask)"
                              : "var(--tone-allow)";
                        const isFocused = focusedAttempt?.id === attempt.id;
                        const shortTarget =
                          attempt.target.length > 28
                            ? `${attempt.target.slice(0, 25)}...`
                            : attempt.target;

                        return (
                          <g
                            key={attempt.id}
                            style={{ cursor: "pointer" }}
                            onClick={() => setSelectedAttemptId(attempt.id)}
                          >
                            <path
                              d={`M 282 118 C 330 118, 336 ${y}, 386 ${y}`}
                              fill="none"
                              stroke="var(--border-strong)"
                              strokeWidth="1.6"
                            />
                            <circle
                              cx="404"
                              cy={y}
                              r="17"
                              fill="var(--bg-canvas)"
                              stroke={nodeStroke}
                              strokeWidth={isFocused ? "2.6" : "2"}
                            />
                            <text
                              x="404"
                              y={y + 4}
                              textAnchor="middle"
                              fontSize="9"
                              fontWeight="700"
                              fill={nodeStroke}
                            >
                              {verdict === "deny" ? "DENY" : verdict === "step_up" ? "ASK" : "OK"}
                            </text>
                            <rect
                              x="432"
                              y={y - 20}
                              width="288"
                              height="40"
                              rx="8"
                              fill="var(--bg-canvas)"
                              stroke={isFocused ? "var(--accent-primary)" : "var(--border-subtle)"}
                              strokeWidth={isFocused ? "1.8" : "1"}
                            />
                            <text x="444" y={y - 3} fontSize="12" fontWeight="600" fill="var(--ink-primary)">
                              {attempt.action_class}
                            </text>
                            <text x="444" y={y + 12} fontSize="11" fill="var(--ink-muted)">
                              {shortTarget}
                            </text>
                          </g>
                        );
                      })}
                    </svg>
                    <HStack justify="center" style={{ marginTop: 4 }}>
                      <Badge
                        variant="neutral"
                        label={`${detail.attempts.length + 3} nodes loaded`}
                      />
                    </HStack>
                  </div>
                </div>
              )}

              {viewMode === "timeline" && (
                <div className="storyline-track">
                  {detail.attempts.map((attempt) => {
                    const receipt = detail.receipts.find((r) => r.attempt_id === attempt.id);
                    const dotClass =
                      receipt?.verdict === "allow"
                        ? "allow"
                        : receipt?.verdict === "step_up"
                          ? "ask"
                          : receipt?.verdict === "deny"
                            ? "deny"
                            : "";
                    const isFocused = focusedAttempt?.id === attempt.id;

                    return (
                      <div
                        key={attempt.id}
                        className={`story-node ${isFocused ? "selected" : ""}`}
                        onClick={() => setSelectedAttemptId(attempt.id)}
                      >
                        <span className={`story-dot ${dotClass}`} aria-hidden="true" />
                        <HStack justify="between" align="center">
                          <HStack gap={2} align="center">
                            <span className="mono" style={{ fontWeight: 500 }}>
                              {attempt.action_class}
                            </span>
                            {receipt && <VerdictBadge verdict={receipt.verdict} />}
                          </HStack>
                          <Text size="sm" color="secondary" className="mono">
                            {receipt?.rule_id ?? "baseline"}
                          </Text>
                        </HStack>
                        <div style={{ marginTop: 6 }}>
                          <Quoted text={attempt.target} />
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}

              {viewMode === "stream" && (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Status</th>
                        <th>Finding / Rule</th>
                        <th>Action</th>
                        <th>Collector</th>
                        <th>Target</th>
                      </tr>
                    </thead>
                    <tbody>
                      {detail.attempts.map((attempt) => {
                        const receipt = detail.receipts.find((r) => r.attempt_id === attempt.id);
                        const isFocused = focusedAttempt?.id === attempt.id;
                        return (
                          <tr
                            key={attempt.id}
                            className={`selectable ${isFocused ? "selected" : ""}`}
                            onClick={() => setSelectedAttemptId(attempt.id)}
                          >
                            <td>{receipt ? <VerdictBadge verdict={receipt.verdict} /> : "allow"}</td>
                            <td className="mono">{receipt?.rule_id ?? "baseline"}</td>
                            <td className="mono">{attempt.action_class}</td>
                            <td>
                              <HStack gap={1} align="center">
                                <HarnessIcon name={attempt.agent_name} size={13} />
                                <span>{attempt.agent_name}</span>
                              </HStack>
                            </td>
                            <td>
                              <Quoted text={attempt.target} />
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}

              {focusedAttempt && (
                <div className="ledger-row-drawer">
                  <HStack justify="between" align="center">
                    <strong>{focusedReceipt?.rule_id ?? "Observed attempt"}</strong>
                    {focusedReceipt?.signature_verified === true && (
                      <Badge
                        variant="success"
                        icon={<GrdrIcon name="shield-check" size={11} />}
                        label={`Signed (${focusedReceipt.key_id ?? "verified"})`}
                      />
                    )}
                  </HStack>
                  <Text size="sm" color="secondary">
                    {focusedReceipt?.reason ?? focusedAttempt.summary}
                  </Text>
                  <HStack justify="between" align="center">
                    <span className="mono" style={{ color: "var(--ink-muted)" }}>
                      {focusedReceipt ? `Receipt ${focusedReceipt.receipt_digest.slice(0, 16)}` : ""}
                    </span>
                    <Button
                      size="sm"
                      variant="primary"
                      label="Create rule"
                      icon={<GrdrIcon name="plus-circle" size={13} />}
                      onClick={() => onCreateRuleFromAttempt(focusedAttempt)}
                    />
                  </HStack>
                </div>
              )}
            </>
          ) : (
            <Text color="secondary">Select a session to inspect its storyline.</Text>
          )}
        </div>
      </div>
    </VStack>
  );
}
