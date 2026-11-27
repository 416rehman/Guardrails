// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
import { useMemo } from "react";
import type {
  ActionAttempt,
  ActionClass,
  AssuranceLevel,
  DecisionReceipt,
  SessionDetailResponse,
} from "@grdr/api";
import { formatActionLabel, presentAssurance } from "@grdr/i18n";
import { EntityLink, type EntityTarget, Quoted, VerdictBadge } from "@grdr/kit";
import {
  Badge,
  Button,
  type GrdrFlowEdge,
  type GrdrFlowNode,
  GrdrIcon,
  HStack,
  Text,
} from "@grdr/ui";

export interface ClusteredFlowPhase {
  actionClass: ActionClass;
  total: number;
  allowCount: number;
  askCount: number;
  denyCount: number;
  representativeAttemptId: string;
  latestAttemptId: string;
  sampleTarget: string;
}

export function buildClusteredFlowPhases(
  attempts: ActionAttempt[],
  receipts: DecisionReceipt[],
): ClusteredFlowPhase[] {
  const receiptsByAttempt = new Map(receipts.map((r) => [r.attempt_id, r]));
  const grouped = new Map<ActionClass, ClusteredFlowPhase>();

  for (const attempt of attempts) {
    const receipt = receiptsByAttempt.get(attempt.id);
    const verdict = receipt?.verdict ?? "allow";
    const existing = grouped.get(attempt.action_class) ?? {
      actionClass: attempt.action_class,
      total: 0,
      allowCount: 0,
      askCount: 0,
      denyCount: 0,
      representativeAttemptId: attempt.id,
      latestAttemptId: attempt.id,
      sampleTarget: attempt.target,
    };
    existing.total += 1;
    existing.latestAttemptId = attempt.id;
    if (verdict === "deny") {
      existing.denyCount += 1;
      existing.representativeAttemptId = attempt.id;
      existing.sampleTarget = attempt.target;
    } else if (verdict === "step_up" || verdict === "defer") {
      existing.askCount += 1;
      if (existing.denyCount === 0) {
        existing.representativeAttemptId = attempt.id;
        existing.sampleTarget = attempt.target;
      }
    } else {
      existing.allowCount += 1;
      if (existing.denyCount === 0 && existing.askCount === 0) {
        existing.sampleTarget = attempt.target;
      }
    }
    grouped.set(attempt.action_class, existing);
  }

  return Array.from(grouped.values()).sort(
    (a, b) => b.denyCount - a.denyCount || b.askCount - a.askCount || b.total - a.total,
  );
}

export function selectPrioritizedGraphDetail(
  detail: SessionDetailResponse,
  maxAttempts: number,
): SessionDetailResponse {
  if (detail.attempts.length <= maxAttempts) {
    return detail;
  }
  const receiptsByAttempt = new Map(detail.receipts.map((r) => [r.attempt_id, r]));
  const chosenIndices = new Set<number>();

  detail.attempts.forEach((attempt, idx) => {
    if (chosenIndices.size >= maxAttempts) return;
    const verdict = receiptsByAttempt.get(attempt.id)?.verdict;
    if (verdict === "deny" || verdict === "step_up" || verdict === "defer") {
      chosenIndices.add(idx);
    }
  });

  for (let idx = detail.attempts.length - 1; idx >= 0 && chosenIndices.size < maxAttempts; idx -= 1) {
    chosenIndices.add(idx);
  }

  const sampledAttempts = detail.attempts.filter((_, idx) => chosenIndices.has(idx));
  return {
    ...detail,
    attempts: sampledAttempts,
  };
}

export function buildSessionFlowGraph(
  detail: SessionDetailResponse,
  focusedAttemptId: string | null,
): { flowNodes: GrdrFlowNode[]; flowEdges: GrdrFlowEdge[] } {
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

  const receiptsByAttempt = new Map(detail.receipts.map((r) => [r.attempt_id, r]));

  for (const attempt of detail.attempts) {
    const receipt = receiptsByAttempt.get(attempt.id);
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
      selected: focusedAttemptId === attempt.id,
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
}

export function SessionTimelineView({
  attempts,
  receipts,
  focusedAttemptId,
  onSelectAttempt,
  onOpenEntity,
}: {
  attempts: ActionAttempt[];
  receipts: DecisionReceipt[];
  focusedAttemptId: string | null;
  onSelectAttempt: (id: string) => void;
  onOpenEntity?: (target: EntityTarget) => void;
}) {
  const receiptsByAttempt = useMemo(
    () => new Map(receipts.map((r) => [r.attempt_id, r])),
    [receipts],
  );

  return (
    <div className="storyline-track">
      {attempts.map((attempt) => {
        const receipt = receiptsByAttempt.get(attempt.id);
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
        const isFocused = focusedAttemptId === attempt.id;

        return (
          <div
            key={attempt.id}
            className={`story-node ${isFocused ? "selected" : ""}`}
            onClick={() => onSelectAttempt(attempt.id)}
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
              {receipt?.rule_id ? (
                <EntityLink
                  kind="rule"
                  id={receipt.rule_id}
                  label={receipt.rule_id}
                  compact
                  onSelect={onOpenEntity}
                />
              ) : (
                <Text size="sm" color="secondary" className="mono">
                  baseline
                </Text>
              )}
            </HStack>
            <div style={{ marginTop: 6 }}>
              <Quoted text={attempt.target} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

export function SessionStreamTable({
  attempts,
  receipts,
  focusedAttemptId,
  onSelectAttempt,
  onOpenEntity,
}: {
  attempts: ActionAttempt[];
  receipts: DecisionReceipt[];
  focusedAttemptId: string | null;
  onSelectAttempt: (id: string) => void;
  onOpenEntity?: (target: EntityTarget) => void;
}) {
  const receiptsByAttempt = useMemo(
    () => new Map(receipts.map((r) => [r.attempt_id, r])),
    [receipts],
  );

  return (
    <div className="table-wrap">
      <table className="responsive-table">
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
          {attempts.map((attempt) => {
            const receipt = receiptsByAttempt.get(attempt.id);
            const isWatchHit = Boolean(receipt?.verdict === "allow" && receipt.rule_id);
            const isFocused = focusedAttemptId === attempt.id;
            return (
              <tr
                key={attempt.id}
                className={`selectable ${isFocused ? "selected" : ""}`}
                onClick={() => onSelectAttempt(attempt.id)}
              >
                <td data-label="Status">
                  {isWatchHit ? (
                    <Badge variant="info" icon={<GrdrIcon name="eye" size={11} />} label="Watch" />
                  ) : receipt ? (
                    <VerdictBadge verdict={receipt.verdict} />
                  ) : (
                    "Allow"
                  )}
                </td>
                <td data-label="Rule">
                  {receipt?.rule_id ? (
                    <EntityLink
                      kind="rule"
                      id={receipt.rule_id}
                      label={receipt.rule_id}
                      compact
                      onSelect={onOpenEntity}
                    />
                  ) : (
                    <span className="mono" style={{ color: "var(--ink-muted)" }}>
                      baseline
                    </span>
                  )}
                </td>
                <td data-label="Action">{formatActionLabel(attempt.action_class)}</td>
                <td data-label="Agent">
                  <EntityLink
                    kind="agent"
                    label={attempt.agent_name}
                    compact
                    onSelect={onOpenEntity}
                  />
                </td>
                <td data-label="Target">
                  <Quoted text={attempt.target} />
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export function SessionAttemptDrawer({
  attempt,
  receipt,
  onOpenEntity,
  onCreateRuleFromAttempt,
  onExplainReceipt,
}: {
  attempt: ActionAttempt;
  receipt?: DecisionReceipt;
  onOpenEntity?: (target: EntityTarget) => void;
  onCreateRuleFromAttempt: (attempt: ActionAttempt) => void;
  onExplainReceipt?: (reference: string) => void;
}) {
  return (
    <div className="ledger-row-drawer">
      <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
        <HStack gap={2} align="center" style={{ columnGap: 6, rowGap: 2, flexWrap: "wrap" }}>
          <strong>{formatActionLabel(attempt.action_class)}</strong>
          {receipt?.rule_id && (
            <>
              <span style={{ color: "var(--ink-muted)" }} aria-hidden="true">·</span>
              <EntityLink
                kind="rule"
                id={receipt.rule_id}
                label={receipt.rule_id}
                compact
                onSelect={onOpenEntity}
              />
            </>
          )}
        </HStack>
        {receipt?.signature_verified === true && (
          <span title={`Signing key ${receipt.key_id ?? "local"}`} style={{ display: "inline-flex" }}>
            <Badge
              variant="success"
              icon={<GrdrIcon name="shield-check" size={11} />}
              label="Verified receipt"
            />
          </span>
        )}
      </HStack>
      <div>
        <Quoted text={attempt.target} />
      </div>
      <Text size="sm" color="secondary">
        {receipt?.reason ?? attempt.summary}
      </Text>
      <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
        <span className="mono" style={{ color: "var(--ink-muted)" }}>
          {receipt ? `Receipt ${receipt.receipt_digest.slice(0, 12)}` : ""}
        </span>
        <HStack gap={2} align="center">
          {onExplainReceipt && (
            <Button
              size="sm"
              variant="secondary"
              label="Why?"
              icon={<GrdrIcon name="info" size={13} />}
              onClick={() => onExplainReceipt(receipt?.receipt_id ?? attempt.id)}
            />
          )}
          <Button
            size="sm"
            variant="primary"
            label="Create rule"
            icon={<GrdrIcon name="plus-circle" size={13} />}
            onClick={() => onCreateRuleFromAttempt(attempt)}
          />
        </HStack>
      </HStack>
    </div>
  );
}

export function ClusteredFlowTable({
  phases,
  onSelectAttempt,
}: {
  phases: ClusteredFlowPhase[];
  onSelectAttempt: (attemptId: string) => void;
}) {
  return (
    <div className="table-wrap">
      <table className="responsive-table">
        <thead>
          <tr>
            <th>Action phase</th>
            <th>Steps</th>
            <th>Allowed</th>
            <th>Ask</th>
            <th>Blocked</th>
            <th>Sample target</th>
            <th>Inspect</th>
          </tr>
        </thead>
        <tbody>
          {phases.map((phase) => (
            <tr key={phase.actionClass}>
              <td data-label="Action phase">
                <strong>{formatActionLabel(phase.actionClass)}</strong>
              </td>
              <td data-label="Steps" className="tabular">{phase.total}</td>
              <td data-label="Allowed" className="tabular">{phase.allowCount}</td>
              <td data-label="Ask" className="tabular">{phase.askCount}</td>
              <td data-label="Blocked" className="tabular">{phase.denyCount}</td>
              <td data-label="Sample target">
                <Quoted text={phase.sampleTarget} />
              </td>
              <td data-label="Inspect">
                <HStack gap={1} style={{ flexWrap: "wrap" }}>
                  <Button
                    size="sm"
                    variant="ghost"
                    label={phase.denyCount > 0 ? "Focus denied" : phase.askCount > 0 ? "Focus ask" : "Focus step"}
                    onClick={() => onSelectAttempt(phase.representativeAttemptId)}
                  />
                  {phase.latestAttemptId !== phase.representativeAttemptId && (
                    <Button
                      size="sm"
                      variant="ghost"
                      label="Latest"
                      onClick={() => onSelectAttempt(phase.latestAttemptId)}
                    />
                  )}
                </HStack>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
