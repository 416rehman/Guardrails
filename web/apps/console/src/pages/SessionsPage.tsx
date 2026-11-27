// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
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
  Button,
  GrdrFlowGraph,
  GrdrIcon,
  Heading,
  HStack,
  Text,
  UiSdkSegmentedControl,
  VStack,
} from "@grdr/ui";
import { consoleQueryKeys } from "../queries";
import type { ConsoleSearchParams } from "../searchSchema";
import {
  buildClusteredFlowPhases,
  buildSessionFlowGraph,
  ClusteredFlowTable,
  selectPrioritizedGraphDetail,
  SessionAttemptDrawer,
  SessionStreamTable,
  SessionTimelineView,
} from "./SessionInspectorViews";
import { SessionListPane } from "./SessionListPane";
import { TraceWaterfall } from "./TraceWaterfall";

export type SessionViewMode = "graph" | "trace" | "timeline" | "stream";

type LargeGraphMode = "clustered" | "sampled";

const LARGE_GRAPH_NODE_LIMIT = 100;
const INFRA_NODE_COUNT = 3;

export { buildClusteredFlowPhases };

type SessionSelection =
  | { kind: "none" }
  | { kind: "selected"; sessionId: string };

type TurnFocus =
  | { kind: "all" }
  | { kind: "turn"; turnIndex: number };

export function SessionsPage({
  sessions,
  devices = [],
  searchQuery,
  urlSearch,
  onUpdateSearch,
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
  onExplainReceipt,
}: {
  sessions: SessionSummary[];
  devices?: Device[];
  searchQuery: string;
  urlSearch?: ConsoleSearchParams;
  onUpdateSearch?: (patch: Partial<ConsoleSearchParams>) => void;
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
  onExplainReceipt?: (reference: string) => void;
}) {
  const [internalSelection, setInternalSelection] = useState<SessionSelection>(() =>
    sessions[0] ? { kind: "selected", sessionId: sessions[0].id } : { kind: "none" },
  );
  const [internalViewMode, setInternalViewMode] = useState<SessionViewMode>("graph");
  const [largeGraphMode, setLargeGraphMode] = useState<LargeGraphMode>("clustered");
  const [fallbackTurn, setFallbackTurn] = useState<TurnFocus>({ kind: "all" });
  const [fallbackAttemptId, setFallbackAttemptId] = useState<string | null>(null);

  const selectedId =
    selectedSessionId !== undefined
      ? selectedSessionId
      : internalSelection.kind === "selected"
        ? internalSelection.sessionId
        : null;
  const viewMode = section ?? internalViewMode;
  const activeTurn =
    urlSearch?.turn !== undefined
      ? urlSearch.turn
      : fallbackTurn.kind === "turn"
        ? fallbackTurn.turnIndex
        : null;

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
      setFallbackTurn({ kind: "turn", turnIndex: focusedTurn });
      onUpdateSearch?.({ turn: focusedTurn });
      onClearFocusedTurn?.();
    }
  }, [focusedTurn, onClearFocusedTurn, onUpdateSearch]);

  useEffect(() => {
    if (!selectedId && sessions[0]?.id) {
      selectSession(sessions[0].id);
    }
  }, [sessions, selectedId]);

  const detailQuery = useQuery<SessionDetailResponse>({
    queryKey: consoleQueryKeys.sessionDetail(selectedId ?? ""),
    queryFn: () => api.getSessionDetail(selectedId ?? ""),
    enabled: Boolean(selectedId),
  });

  const detail = detailQuery.data ?? null;
  const firstFlagged = detail?.attempts.find((a) =>
    detail.receipts.some((r) => r.attempt_id === a.id && r.verdict !== "allow"),
  );
  const selectedAttemptId =
    urlSearch?.attemptId ??
    fallbackAttemptId ??
    firstFlagged?.id ??
    detail?.attempts[0]?.id ??
    null;

  function selectAttempt(attemptId: string | null) {
    setFallbackAttemptId(attemptId);
    onUpdateSearch?.({ attemptId: attemptId ?? undefined });
  }

  function selectTurn(turn: number | null) {
    setFallbackTurn(turn === null ? { kind: "all" } : { kind: "turn", turnIndex: turn });
    onUpdateSearch?.({ turn: turn ?? undefined });
  }

  const focusedAttempt =
    detail?.attempts.find((a) => a.id === selectedAttemptId) ?? detail?.attempts[0] ?? null;
  const focusedReceipt = focusedAttempt
    ? detail?.receipts.find((r) => r.attempt_id === focusedAttempt.id)
    : undefined;

  const rawNodeCount = detail ? detail.attempts.length + INFRA_NODE_COUNT : 0;
  const isLargeGraph = rawNodeCount > LARGE_GRAPH_NODE_LIMIT;

  const { flowNodes, flowEdges } = useMemo(() => {
    if (!detail || (isLargeGraph && largeGraphMode === "clustered")) {
      return { flowNodes: [], flowEdges: [] };
    }
    const graphDetail = isLargeGraph
      ? selectPrioritizedGraphDetail(detail, LARGE_GRAPH_NODE_LIMIT - INFRA_NODE_COUNT)
      : detail;
    return buildSessionFlowGraph(graphDetail, focusedAttempt?.id ?? null);
  }, [detail, focusedAttempt?.id, isLargeGraph, largeGraphMode]);

  const clusteredPhases = useMemo(
    () =>
      detail && isLargeGraph && largeGraphMode === "clustered"
        ? buildClusteredFlowPhases(detail.attempts, detail.receipts)
        : [],
    [detail, isLargeGraph, largeGraphMode],
  );

  function handleFlowNodeSelect(nodeId: string) {
    if (!detail) return;
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
      selectAttempt(nodeId);
    }
  }

  const detailError =
    detailQuery.error instanceof Error ? detailQuery.error.message : null;

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

      {detailError && (
        <Banner status="error" title={detailError} collapsible={false} />
      )}

      <div className="storyline-split">
        <SessionListPane
          devices={devices}
          searchQuery={searchQuery}
          urlSearch={urlSearch}
          onUpdateSearch={onUpdateSearch}
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
                  activeTurn={activeTurn}
                  selectedAttemptId={focusedAttempt?.id ?? null}
                  onSelectTurn={selectTurn}
                  onSelectAttempt={selectAttempt}
                  onOpenEntity={onOpenEntity}
                />
              )}

              {viewMode === "graph" && isLargeGraph && (
                <VStack gap={3}>
                  <Banner
                    status="info"
                    title={`Large session graph (${rawNodeCount} nodes): clustered by action class to keep layout responsive.`}
                    collapsible={false}
                    endContent={
                      <Button
                        size="sm"
                        variant="secondary"
                        label={
                          largeGraphMode === "clustered"
                            ? `Preview priority ${LARGE_GRAPH_NODE_LIMIT} nodes`
                            : "Cluster by action class"
                        }
                        onClick={() =>
                          setLargeGraphMode((prev) =>
                            prev === "clustered" ? "sampled" : "clustered",
                          )
                        }
                      />
                    }
                  />
                  {largeGraphMode === "clustered" ? (
                    <ClusteredFlowTable
                      phases={clusteredPhases}
                      onSelectAttempt={selectAttempt}
                    />
                  ) : (
                    <GrdrFlowGraph
                      nodes={flowNodes}
                      edges={flowEdges}
                      direction="LR"
                      height={336}
                      ariaLabel="Sampled agent session execution path graph"
                      onNodeSelect={handleFlowNodeSelect}
                    />
                  )}
                </VStack>
              )}

              {viewMode === "graph" && !isLargeGraph && (
                <GrdrFlowGraph
                  nodes={flowNodes}
                  edges={flowEdges}
                  direction="LR"
                  height={336}
                  ariaLabel="Agent session execution path graph"
                  onNodeSelect={handleFlowNodeSelect}
                />
              )}

              {viewMode === "timeline" && (
                <SessionTimelineView
                  attempts={detail.attempts}
                  receipts={detail.receipts}
                  focusedAttemptId={focusedAttempt?.id ?? null}
                  onSelectAttempt={selectAttempt}
                  onOpenEntity={onOpenEntity}
                />
              )}

              {viewMode === "stream" && (
                <SessionStreamTable
                  attempts={detail.attempts}
                  receipts={detail.receipts}
                  focusedAttemptId={focusedAttempt?.id ?? null}
                  onSelectAttempt={selectAttempt}
                  onOpenEntity={onOpenEntity}
                />
              )}

              {focusedAttempt && (
                <SessionAttemptDrawer
                  attempt={focusedAttempt}
                  receipt={focusedReceipt}
                  onOpenEntity={onOpenEntity}
                  onCreateRuleFromAttempt={onCreateRuleFromAttempt}
                  onExplainReceipt={onExplainReceipt}
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
