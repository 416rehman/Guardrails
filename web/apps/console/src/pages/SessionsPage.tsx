import { useEffect, useState } from "react";
import { api, type ActionAttempt, type SessionDetailResponse, type SessionSummary } from "@grdr/api";
import { Quoted, SessionLabelBadge, VerdictBadge } from "@grdr/kit";
import { Badge, Banner, Button, Card, GrdrIcon, Heading, HStack, Text, VStack } from "@grdr/ui";

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
    <VStack gap={4}>
      <div className="page-header">
        <div>
          <Heading level={1}>Sessions</Heading>
          <Text color="secondary">
            Ordered action timelines with cryptographic decision receipts and rule promotion handoff.
          </Text>
        </div>
      </div>

      <Card padding={3}>
        <VStack gap={3}>
          <Heading level={2}>{`Recorded sessions (${filtered.length})`}</Heading>
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
                      <td>
                        <strong>{sess.agent_name}</strong>
                      </td>
                      <td>{sess.device_name}</td>
                      <td>
                        {labels.length === 0 ? (
                          <Text color="secondary" size="sm">
                            None
                          </Text>
                        ) : (
                          <HStack gap={1}>
                            {labels.map((lbl) => (
                              <SessionLabelBadge key={lbl} label={lbl} />
                            ))}
                          </HStack>
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
        </VStack>
      </Card>

      {error && <Banner status="error" title={error} collapsible={false} />}

      {detail && (
        <Card padding={3}>
          <VStack gap={3}>
            <HStack justify="between" align="center">
              <VStack gap={1}>
                <HStack gap={2} align="center">
                  <GrdrIcon name="shield" size={16} />
                  <Heading level={2}>{`Timeline for ${detail.session.id}`}</Heading>
                </HStack>
                <Text color="secondary">
                  {`Agent: ${detail.session.agent_name} on ${detail.session.device_name}`}
                </Text>
                {(detail.session.labels ?? []).length > 0 && (
                  <HStack gap={1} align="center">
                    <GrdrIcon name="tag" size={13} color="var(--ink-muted)" />
                    {(detail.session.labels ?? []).map((lbl) => (
                      <SessionLabelBadge key={lbl} label={lbl} />
                    ))}
                  </HStack>
                )}
              </VStack>
              <Badge variant="info" label={`${detail.attempts.length} event(s)`} />
            </HStack>

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
                        <td>
                          <span className="mono">{attempt.action_class}</span>
                        </td>
                        <td>
                          <Quoted text={attempt.target} />
                        </td>
                        <td>
                          {receipt ? (
                            <VStack gap={1}>
                              <VerdictBadge verdict={receipt.verdict} />
                              {receipt.mode_applied === "watch" && receipt.would_be && (
                                <Text size="sm" color="secondary">
                                  {`Watch would_be: ${receipt.would_be}`}
                                </Text>
                              )}
                            </VStack>
                          ) : (
                            "-"
                          )}
                        </td>
                        <td>
                          <div style={{ fontWeight: 500 }}>{receipt?.rule_id ?? "no-match"}</div>
                          <Text type="supporting" color="secondary" size="sm">
                            {receipt?.reason ?? "-"}
                          </Text>
                        </td>
                        <td className="mono">
                          {receipt ? (
                            <VStack gap={1}>
                              <span>{receipt.receipt_digest.slice(0, 12)}</span>
                              {receipt.signature_verified === true && (
                                <Badge
                                  variant="success"
                                  icon={<GrdrIcon name="shield-check" size={11} />}
                                  label={`Signed (${receipt.key_id ?? "verified"})`}
                                />
                              )}
                              {receipt.signature_verified === false && (
                                <Badge
                                  variant="error"
                                  icon={<GrdrIcon name="shield-alert" size={11} />}
                                  label="Invalid signature"
                                />
                              )}
                            </VStack>
                          ) : (
                            "-"
                          )}
                        </td>
                        <td>
                          <Button
                            size="sm"
                            label="Create rule"
                            icon={<GrdrIcon name="plus-circle" size={13} />}
                            onClick={() => onCreateRuleFromAttempt(attempt)}
                          />
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </VStack>
        </Card>
      )}
    </VStack>
  );
}
