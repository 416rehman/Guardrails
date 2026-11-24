import { useEffect, useState } from "react";
import { api, type ActionAttempt, type SessionDetailResponse, type SessionSummary } from "@grdr/api";
import { Quoted, SessionLabelBadge, VerdictBadge } from "@grdr/kit";
import { Badge, Banner, Button, GrdrIcon, Heading, HStack, Text, VStack } from "@grdr/ui";

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
            Action storylines with signed receipts and one-click rule creation.
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
                    <div>
                      <strong>{sess.agent_name}</strong>
                      <div className="mono" style={{ color: "var(--ink-muted)" }}>
                        {`${sess.device_name}, ${sess.total_actions} call(s)`}
                      </div>
                    </div>
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
              <div className="ledger-header">
                <div>
                  <h2 className="ledger-title">{`${detail.session.agent_name} on ${detail.session.device_name}`}</h2>
                  <Text size="sm" color="secondary" className="mono">
                    {detail.session.id}
                  </Text>
                </div>
                <Badge variant="info" label={`${detail.attempts.length} step(s)`} />
              </div>

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
