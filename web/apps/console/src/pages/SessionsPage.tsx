import { useEffect, useMemo, useState } from "react";
import {
  api,
  type ActionAttempt,
  type Device,
  type SessionDetailResponse,
  type SessionSummary,
} from "@grdr/api";
import { pluralize } from "@grdr/i18n";
import { EntityLink, type EntityTarget } from "@grdr/kit";
import {
  Badge,
  Banner,
  GrdrFlowGraph,
  GrdrIcon,
  Heading,
  HStack,
  Text,
  UiSdkSegmentedControl,
  VStack,
} from "@grdr/ui";
import {
  buildSessionFlowGraph,
  SessionAttemptDrawer,
  SessionStreamTable,
  SessionTimelineView,
} from "./SessionInspectorViews";
import { SessionListPane } from "./SessionListPane";
import { TraceWaterfall } from "./TraceWaterfall";

export type SessionViewMode = "graph" | "trace" | "timeline" | "stream";

type SessionSelection =
  | { kind: "none" }
  | { kind: "selected"; sessionId: string };

type SessionDetailState =
  | { kind: "idle" }
  | { kind: "loading"; sessionId: string }
  | { kind: "ready"; detail: SessionDetailResponse; selectedAttemptId?: string }
  | { kind: "error"; sessionId: string; message: string };

type TurnFocus =
  | { kind: "all" }
  | { kind: "turn"; turnIndex: number };

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
  const [internalSelection, setInternalSelection] = useState<SessionSelection>(() =>
    sessions[0] ? { kind: "selected", sessionId: sessions[0].id } : { kind: "none" },
  );
  const [internalViewMode, setInternalViewMode] = useState<SessionViewMode>("graph");
  const [turnFocus, setTurnFocus] = useState<TurnFocus>({ kind: "all" });
  const [detailState, setDetailState] = useState<SessionDetailState>({ kind: "idle" });

  const selectedId =
    selectedSessionId !== undefined
      ? selectedSessionId
      : internalSelection.kind === "selected"
        ? internalSelection.sessionId
        : null;
  const viewMode = section ?? internalViewMode;

  function selectSession(id: string | null) {
    setInternalSelection(id ? { kind: "selected", sessionId: id } : { kind: "none" });
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
      setTurnFocus({ kind: "turn", turnIndex: focusedTurn });
      onClearFocusedTurn?.();
    }
  }, [focusedTurn, onClearFocusedTurn]);

  useEffect(() => {
    if (!selectedId && sessions[0]?.id) {
      selectSession(sessions[0].id);
    }
  }, [sessions, selectedId]);

  useEffect(() => {
    if (!selectedId) {
      setDetailState({ kind: "idle" });
      return;
    }
    let cancelled = false;
    setDetailState({ kind: "loading", sessionId: selectedId });
    api
      .getSessionDetail(selectedId)
      .then((res) => {
        if (!cancelled) {
          const firstFlagged = res.attempts.find((a) =>
            res.receipts.some((r) => r.attempt_id === a.id && r.verdict !== "allow"),
          );
          setDetailState({
            kind: "ready",
            detail: res,
            selectedAttemptId: firstFlagged?.id ?? res.attempts[0]?.id,
          });
        }
      })
      .catch((err: Error) => {
        if (!cancelled) {
          setDetailState({ kind: "error", sessionId: selectedId, message: err.message });
        }
      });
    return () => {
      cancelled = true;
    };
  }, [selectedId, sessions]);

  const detail = detailState.kind === "ready" ? detailState.detail : null;
  const selectedAttemptId = detailState.kind === "ready" ? (detailState.selectedAttemptId ?? null) : null;
  const setSelectedAttemptId = (attemptId: string | null) => {
    setDetailState((prev) =>
      prev.kind === "ready"
        ? { ...prev, selectedAttemptId: attemptId ?? undefined }
        : prev,
    );
  };

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

      {detailState.kind === "error" && (
        <Banner status="error" title={detailState.message} collapsible={false} />
      )}

      <div className="storyline-split">
        <SessionListPane
          devices={devices}
          searchQuery={searchQuery}
          selectedId={selectedId}
          onSelectSession={selectSession}
          onOpenEntity={onOpenEntity}
        />

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
                  activeTurn={turnFocus.kind === "turn" ? turnFocus.turnIndex : null}
                  selectedAttemptId={focusedAttempt?.id ?? null}
                  onSelectTurn={(t) =>
                    setTurnFocus(t === null ? { kind: "all" } : { kind: "turn", turnIndex: t })
                  }
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
