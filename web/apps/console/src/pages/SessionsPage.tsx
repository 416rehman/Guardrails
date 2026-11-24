import { useEffect, useMemo, useState } from "react";
import { api, type ActionAttempt, type AssuranceLevel, type SessionDetailResponse, type SessionSummary } from "@grdr/api";
import { formatActionLabel, pluralize, presentAssurance } from "@grdr/i18n";
import { Quoted, SessionLabelBadge, VerdictBadge } from "@grdr/kit";
import {
  Badge,
  Banner,
  Button,
  type GrdrFlowEdge,
  type GrdrFlowNode,
  GrdrFlowGraph,
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
          const firstFlagged = res.attempts.find((a) =>
            res.receipts.some((r) => r.attempt_id === a.id && r.verdict !== "allow"),
          );
          setSelectedAttemptId(firstFlagged?.id ?? res.attempts[0]?.id ?? null);
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

  const { flowNodes, flowEdges } = useMemo(() => {
    if (!detail) return { flowNodes: [] as GrdrFlowNode[], flowEdges: [] as GrdrFlowEdge[] };
    const assuranceLabel = presentAssurance(
      detail.session.assurance_level as AssuranceLevel,
      detail.session.assurance_level === "AL3" || detail.session.assurance_level === "AL4"
        ? "boundary"
        : "request",
    ).label;
    const nodes: GrdrFlowNode[] = [
      {
        id: "host",
        label: detail.session.device_name,
        subtitle: "Enrolled endpoint",
        badge: "HOST",
        tone: "accent",
        icon: "cpu",
      },
      {
        id: "agent",
        label: detail.session.agent_name,
        subtitle: `Protection: ${assuranceLabel}`,
        badge: assuranceLabel,
        tone: "allow",
        harnessName: detail.session.agent_name,
      },
      {
        id: "engine",
        label: "Policy engine",
        subtitle: "Cedar local eval",
        badge: "GRDR",
        tone: "accent",
        icon: "shield-check",
      },
    ];
    const edges: GrdrFlowEdge[] = [
      { id: "e-host-agent", source: "host", target: "agent" },
      { id: "e-agent-engine", source: "agent", target: "engine" },
    ];
    for (const attempt of detail.attempts) {
      const receipt = detail.receipts.find((r) => r.attempt_id === attempt.id);
      const verdict = receipt?.verdict ?? "allow";
      const isWatchHit = Boolean(verdict === "allow" && receipt?.rule_id);
      const tone =
        verdict === "deny"
          ? "block"
          : verdict === "step_up"
            ? "ask"
            : isWatchHit
              ? "watch"
              : "allow";
      const badge =
        verdict === "deny"
          ? "Deny"
          : verdict === "step_up"
            ? "Ask"
            : isWatchHit
              ? "Watch"
              : "Allow";
      const iconName =
        verdict === "deny"
          ? "ban"
          : verdict === "step_up"
            ? "hand"
            : isWatchHit
              ? "eye"
              : "check-circle";
      nodes.push({
        id: attempt.id,
        label: formatActionLabel(attempt.action_class),
        subtitle: attempt.target,
        badge,
        tone,
        icon: iconName,
        selected: focusedAttempt?.id === attempt.id,
      });
      edges.push({
        id: `e-eng-${attempt.id}`,
        source: "engine",
        target: attempt.id,
        tone:
          verdict === "deny"
            ? "block"
            : isWatchHit
              ? "watch"
              : verdict === "allow"
                ? "allow"
                : "neutral",
      });
    }
    return { flowNodes: nodes, flowEdges: edges };
  }, [detail, focusedAttempt?.id]);

  return (
    <VStack gap={4}>
      <div className="page-header">
        <div>
          <Heading level={1}>Sessions</Heading>
          <Text color="secondary">
            Inspect agent sessions as a graph, timeline, or event stream.
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
                          {`${sess.device_name} · ${pluralize(sess.total_actions, "call")}`}
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
                  <Badge variant="info" label={pluralize(detail.attempts.length, "step")} />
                </HStack>
              </div>

              {viewMode === "graph" && (
                <GrdrFlowGraph
                  nodes={flowNodes}
                  edges={flowEdges}
                  direction="LR"
                  height={336}
                  ariaLabel="Agent session execution path graph"
                  onNodeSelect={(nodeId) => {
                    if (detail.attempts.some((a) => a.id === nodeId)) {
                      setSelectedAttemptId(nodeId);
                    }
                  }}
                />
              )}

              {viewMode === "timeline" && (
                <div className="storyline-track">
                  {detail.attempts.map((attempt) => {
                    const receipt = detail.receipts.find((r) => r.attempt_id === attempt.id);
                    const isWatchHit = Boolean(receipt?.verdict === "allow" && receipt.rule_id);
                    const dotClass = isWatchHit
                      ? ""
                      : receipt?.verdict === "allow"
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
                            <span style={{ fontWeight: 600 }}>
                              {formatActionLabel(attempt.action_class)}
                            </span>
                            {isWatchHit ? (
                              <Badge variant="info" icon={<GrdrIcon name="eye" size={11} />} label="Watch" />
                            ) : (
                              receipt && <VerdictBadge verdict={receipt.verdict} />
                            )}
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
                        <th>Rule</th>
                        <th>Action</th>
                        <th>Agent</th>
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
                            <td>{receipt ? <VerdictBadge verdict={receipt.verdict} /> : "Allow"}</td>
                            <td className="mono">{receipt?.rule_id ?? "baseline"}</td>
                            <td>{formatActionLabel(attempt.action_class)}</td>
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
                  <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
                    <HStack gap={2} align="center">
                      <strong>{formatActionLabel(focusedAttempt.action_class)}</strong>
                      {focusedReceipt?.rule_id && (
                        <Badge variant="neutral" label={focusedReceipt.rule_id} />
                      )}
                    </HStack>
                    {focusedReceipt?.signature_verified === true && (
                      <span title={`Signing key ${focusedReceipt.key_id ?? "local"}`} style={{ display: "inline-flex" }}>
                        <Badge
                          variant="success"
                          icon={<GrdrIcon name="shield-check" size={11} />}
                          label="Verified receipt"
                        />
                      </span>
                    )}
                  </HStack>
                  <div>
                    <Quoted text={focusedAttempt.target} />
                  </div>
                  <Text size="sm" color="secondary">
                    {focusedReceipt?.reason ?? focusedAttempt.summary}
                  </Text>
                  <HStack justify="between" align="center">
                    <span className="mono" style={{ color: "var(--ink-muted)" }}>
                      {focusedReceipt ? `Receipt ${focusedReceipt.receipt_digest.slice(0, 12)}` : ""}
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
