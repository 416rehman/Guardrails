import type {
  ActionAttempt,
  AssuranceLevel,
  DecisionReceipt,
  SessionDetailResponse,
} from "@grdr/api";
import { formatActionLabel } from "@grdr/i18n";
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
import { presentAssurance } from "@grdr/i18n";

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
  return (
    <div className="storyline-track">
      {attempts.map((attempt) => {
        const receipt = receipts.find((r) => r.attempt_id === attempt.id);
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
  return (
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
          {attempts.map((attempt) => {
            const receipt = receipts.find((r) => r.attempt_id === attempt.id);
            const isFocused = focusedAttemptId === attempt.id;
            return (
              <tr
                key={attempt.id}
                className={`selectable ${isFocused ? "selected" : ""}`}
                onClick={() => onSelectAttempt(attempt.id)}
              >
                <td>{receipt ? <VerdictBadge verdict={receipt.verdict} /> : "Allow"}</td>
                <td>
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
                <td>{formatActionLabel(attempt.action_class)}</td>
                <td>
                  <EntityLink
                    kind="agent"
                    label={attempt.agent_name}
                    compact
                    onSelect={onOpenEntity}
                  />
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
  );
}

export function SessionAttemptDrawer({
  attempt,
  receipt,
  onOpenEntity,
  onCreateRuleFromAttempt,
}: {
  attempt: ActionAttempt;
  receipt?: DecisionReceipt;
  onOpenEntity?: (target: EntityTarget) => void;
  onCreateRuleFromAttempt: (attempt: ActionAttempt) => void;
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
      <HStack justify="between" align="center">
        <span className="mono" style={{ color: "var(--ink-muted)" }}>
          {receipt ? `Receipt ${receipt.receipt_digest.slice(0, 12)}` : ""}
        </span>
        <Button
          size="sm"
          variant="primary"
          label="Create rule"
          icon={<GrdrIcon name="plus-circle" size={13} />}
          onClick={() => onCreateRuleFromAttempt(attempt)}
        />
      </HStack>
    </div>
  );
}
