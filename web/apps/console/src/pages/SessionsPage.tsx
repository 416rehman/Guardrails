import { useEffect, useMemo, useState } from "react";
import {
  api,
  type ActionAttempt,
  type Device,
  type SessionDetailResponse,
  type SessionSummary,
} from "@grdr/api";
import { pluralize } from "@grdr/i18n";
import { EntityLink, type EntityTarget, SessionLabelBadge } from "@grdr/kit";
import {
  Badge,
  Banner,
  GrdrFlowGraph,
  GrdrIcon,
  Heading,
  HStack,
  Text,
  TextInput,
  UiSdkSegmentedControl,
  VStack,
} from "@grdr/ui";
import { PagerBar } from "../components/PagerBar";
import {
  buildSessionFlowGraph,
  SessionAttemptDrawer,
  SessionStreamTable,
  SessionTimelineView,
} from "./SessionInspectorViews";
import { TraceWaterfall } from "./TraceWaterfall";

export type SessionViewMode = "graph" | "trace" | "timeline" | "stream";

export function SessionsPage({
  sessions,
  devices = [],
  searchQuery,
  section,
  onSectionChange,
  selectedSessionId,
  onSelectSessionId,
  focusedEntity,
  focusedTurn,
  onClearFocus,
  onClearFocusedTurn,
  onOpenEntity,
  onCreateRuleFromAttempt,
}: {
  sessions: SessionSummary[];
  devices?: Device[];
  searchQuery: string;
  section?: SessionViewMode;
  onSectionChange?: (next: SessionViewMode) => void;
  selectedSessionId?: string | null;
  onSelectSessionId?: (id: string | null) => void;
  focusedEntity?: EntityTarget | null;
  focusedTurn?: number | null;
  onClearFocus?: () => void;
  onClearFocusedTurn?: () => void;
  onOpenEntity?: (target: EntityTarget) => void;
  onCreateRuleFromAttempt: (attempt: ActionAttempt) => void;
}) {
  const [internalSelectedId, setInternalSelectedId] = useState<string | null>(
    sessions[0]?.id ?? null,
  );
  const [internalViewMode, setInternalViewMode] = useState<SessionViewMode>("graph");
  const [selectedAttemptId, setSelectedAttemptId] = useState<string | null>(null);
  const [activeTurn, setActiveTurn] = useState<number | null>(null);
  const [detail, setDetail] = useState<SessionDetailResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [localQuery, setLocalQuery] = useState("");
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(25);

  const selectedId = selectedSessionId !== undefined ? selectedSessionId : internalSelectedId;
  const viewMode = section ?? internalViewMode;

  function selectSession(id: string | null) {
    setInternalSelectedId(id);
    onSelectSessionId?.(id);
  }

  function changeViewMode(next: SessionViewMode) {
    setInternalViewMode(next);
    onSectionChange?.(next);
  }

  useEffect(() => {
    if (focusedEntity?.kind === "session") {
      selectSession(focusedEntity.id);
      onClearFocus?.();
    }
  }, [focusedEntity, onClearFocus]);

  useEffect(() => {
    if (typeof focusedTurn === "number" && focusedTurn > 0) {
      changeViewMode("trace");
      setActiveTurn(focusedTurn);
      onClearFocusedTurn?.();
    }
  }, [focusedTurn, onClearFocusedTurn]);

  const query = `${searchQuery} ${localQuery}`.trim().toLowerCase();
  const filtered = useMemo(
    () =>
      sessions.filter(
        (s) =>
          !query ||
          s.id.toLowerCase().includes(query) ||
          s.agent_name.toLowerCase().includes(query) ||
          s.device_name.toLowerCase().includes(query) ||
          (s.user_display ?? "").toLowerCase().includes(query),
      ),
    [sessions, query],
  );

  const safePage = page * pageSize >= filtered.length && filtered.length > 0 ? 0 : page;
  const startIdx = safePage * pageSize;
  const pagedSessions = filtered.slice(startIdx, startIdx + pageSize);
  const firstFilteredId = filtered[0]?.id ?? null;

  useEffect(() => {
    if (!selectedId && firstFilteredId) {
      selectSession(firstFilteredId);
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

  const { flowNodes, flowEdges } = useMemo(
    () =>
      detail
        ? buildSessionFlowGraph(detail, focusedAttempt?.id ?? null)
        : { flowNodes: [], flowEdges: [] },
    [detail, focusedAttempt?.id],
  );

  return (
    <VStack gap={4}>
      <div className="page-header">
        <div>
          <Heading level={1}>Sessions</Heading>
          <Text color="secondary">
            Inspect agent sessions as a graph, trace waterfall, timeline, or event stream.
          </Text>
        </div>
      </div>

      {error && <Banner status="error" title={error} collapsible={false} />}

      <div className="storyline-split">
        <div className="ledger-section">
          <div className="ledger-header" style={{ flexWrap: "wrap", gap: 8 }}>
            <h2 className="ledger-title">{`Recorded sessions (${filtered.length})`}</h2>
            <Text size="sm" color="secondary" className="tabular">
              {filtered.length === 0
                ? "0 of 0"
                : `${startIdx + 1}-${Math.min(startIdx + pageSize, filtered.length)} of ${filtered.length}`}
            </Text>
          </div>

          <div style={{ marginBlock: 8 }}>
            <TextInput
              label="Search recorded sessions"
              isLabelHidden
              size="sm"
              placeholder="Filter by session, agent, host, or user..."
              startIcon={<GrdrIcon name="search" size={13} color="var(--ink-muted)" />}
              value={localQuery}
              onChange={(val) => {
                setLocalQuery(val);
                setPage(0);
              }}
              width="100%"
            />
          </div>

          <div className="ledger-list">
            {pagedSessions.map((sess) => {
              const labels = sess.labels ?? [];
              const isSelected = selectedId === sess.id;
              return (
                <div
                  key={sess.id}
                  className={`ledger-row selectable ${isSelected ? "selected" : ""}`}
                  style={{ paddingInline: 12, cursor: "pointer" }}
                  onClick={() => selectSession(sess.id)}
                >
                  <div className="ledger-row-main">
                    <VStack gap={1}>
                      <HStack
                        gap={1}
                        align="center"
                        style={{ flexWrap: "wrap", columnGap: 6, rowGap: 2 }}
                      >
                        <EntityLink
                          kind="agent"
                          label={sess.agent_name}
                          compact
                          onSelect={onOpenEntity}
                        />
                        <Text size="sm" color="secondary">
                          on
                        </Text>
                        <EntityLink
                          kind="device"
                          id={sess.device_id}
                          label={sess.device_name}
                          os={
                            devices.find(
                              (d) => d.id === sess.device_id || d.hostname === sess.device_name,
                            )?.os
                          }
                          compact
                          onSelect={onOpenEntity}
                        />
                      </HStack>
                      <HStack
                        gap={2}
                        align="center"
                        style={{ columnGap: 8, rowGap: 2, flexWrap: "wrap" }}
                      >
                        {sess.user_display && (
                          <EntityLink
                            kind="user"
                            id={sess.user_id ?? sess.user_display}
                            label={sess.user_display}
                            compact
                            onSelect={onOpenEntity}
                          />
                        )}
                        <EntityLink
                          kind="session"
                          id={sess.id}
                          label={sess.id}
                          compact
                          onSelect={() => selectSession(sess.id)}
                        />
                        <Text size="sm" color="secondary" className="tabular">
                          {`${pluralize(sess.total_actions, "call")} · ${pluralize(sess.turn_count ?? 1, "turn")}`}
                        </Text>
                      </HStack>
                    </VStack>
                    <HStack gap={1}>
                      {sess.blocked_count > 0 && (
                        <Badge
                          variant="error"
                          icon={<GrdrIcon name="ban" size={11} />}
                          label={`${sess.blocked_count} denied`}
                        />
                      )}
                      {sess.step_up_count > 0 && (
                        <Badge
                          variant="warning"
                          icon={<GrdrIcon name="hand" size={11} />}
                          label={`${sess.step_up_count} ask`}
                        />
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

          <PagerBar
            page={safePage}
            pageSize={pageSize}
            totalItems={filtered.length}
            label="Sessions pagination"
            onPageChange={setPage}
            onPageSizeChange={(sz) => {
              setPageSize(sz);
              setPage(0);
            }}
          />
        </div>

        <div className="ledger-section">
          {detail ? (
            <>
              <div className="ledger-header" style={{ flexWrap: "wrap", gap: 10 }}>
                <VStack gap={1}>
                  <HStack gap={1} align="center" style={{ flexWrap: "wrap" }}>
                    <EntityLink
                      kind="agent"
                      label={detail.session.agent_name}
                      onSelect={onOpenEntity}
                    />
                    <Text size="sm" color="secondary">
                      on
                    </Text>
                    <EntityLink
                      kind="device"
                      id={detail.session.device_id}
                      label={detail.session.device_name}
                      os={
                        devices.find(
                          (d) =>
                            d.id === detail.session.device_id ||
                            d.hostname === detail.session.device_name,
                        )?.os
                      }
                      onSelect={onOpenEntity}
                    />
                  </HStack>
                  <HStack gap={2} align="center" style={{ flexWrap: "wrap" }}>
                    <EntityLink
                      kind="session"
                      id={detail.session.id}
                      label={detail.session.id}
                      compact
                      onSelect={() => selectSession(detail.session.id)}
                    />
                    {detail.session.user_display && (
                      <EntityLink
                        kind="user"
                        id={detail.session.user_id ?? detail.session.user_display}
                        label={detail.session.user_display}
                        compact
                        onSelect={onOpenEntity}
                      />
                    )}
                  </HStack>
                </VStack>
                <HStack gap={2} align="center" style={{ flexWrap: "wrap" }}>
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
                        value: "trace",
                        label: "Trace",
                        icon: <GrdrIcon name="route" size={13} />,
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
                    onChange={changeViewMode}
                  />
                  <Badge variant="info" label={pluralize(detail.attempts.length, "step")} />
                </HStack>
              </div>

              {viewMode === "trace" && (
                <TraceWaterfall
                  attempts={detail.attempts}
                  receipts={detail.receipts}
                  turns={detail.turns ?? []}
                  activeTurn={activeTurn}
                  selectedAttemptId={focusedAttempt?.id ?? null}
                  onSelectTurn={setActiveTurn}
                  onSelectAttempt={setSelectedAttemptId}
                  onOpenEntity={onOpenEntity}
                />
              )}

              {viewMode === "graph" && (
                <GrdrFlowGraph
                  nodes={flowNodes}
                  edges={flowEdges}
                  direction="LR"
                  height={336}
                  ariaLabel="Agent session execution path graph"
                  onNodeSelect={(nodeId) => {
                    if (nodeId === "host") {
                      onOpenEntity?.({
                        kind: "device",
                        id: detail.session.device_id,
                        label: detail.session.device_name,
                      });
                    } else if (nodeId === "agent") {
                      onOpenEntity?.({
                        kind: "agent",
                        id: detail.session.agent_name,
                        label: detail.session.agent_name,
                      });
                    } else if (detail.attempts.some((a) => a.id === nodeId)) {
                      setSelectedAttemptId(nodeId);
                    }
                  }}
                />
              )}

              {viewMode === "timeline" && (
                <SessionTimelineView
                  attempts={detail.attempts}
                  receipts={detail.receipts}
                  focusedAttemptId={focusedAttempt?.id ?? null}
                  onSelectAttempt={setSelectedAttemptId}
                  onOpenEntity={onOpenEntity}
                />
              )}

              {viewMode === "stream" && (
                <SessionStreamTable
                  attempts={detail.attempts}
                  receipts={detail.receipts}
                  focusedAttemptId={focusedAttempt?.id ?? null}
                  onSelectAttempt={setSelectedAttemptId}
                  onOpenEntity={onOpenEntity}
                />
              )}

              {focusedAttempt && (
                <SessionAttemptDrawer
                  attempt={focusedAttempt}
                  receipt={focusedReceipt}
                  onOpenEntity={onOpenEntity}
                  onCreateRuleFromAttempt={onCreateRuleFromAttempt}
                />
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
