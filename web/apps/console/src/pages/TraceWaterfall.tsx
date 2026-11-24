import { useMemo, useState } from "react";
import type {
  ActionAttempt,
  DecisionReceipt,
  ProvenanceSource,
  SpanKind,
  TurnSummary,
} from "@grdr/api";
import { formatActionLabel, pluralize } from "@grdr/i18n";
import { EntityLink, type EntityTarget, Quoted, VerdictBadge } from "@grdr/kit";
import { Badge, Button, GrdrIcon, HStack, StatusInline, Text, VStack } from "@grdr/ui";

function spanKindLabel(kind: SpanKind | undefined): string {
  switch (kind) {
    case "invoke_agent":
      return "Agent turn";
    case "chat":
      return "Model call";
    case "mcp_call":
      return "MCP call";
    case "os_effect":
      return "OS effect";
    case "subagent_spawn":
      return "Sub-agent handoff";
    case "compaction":
      return "Context compaction";
    default:
      return "Tool call";
  }
}

function provenanceMeta(source: ProvenanceSource | undefined): {
  label: string;
  tone: "allow" | "ask" | "neutral";
  icon: "shield-check" | "eye" | "circle";
} {
  switch (source) {
    case "mediated":
      return { label: "Mediated boundary", tone: "allow", icon: "shield-check" };
    case "reconciled":
      return { label: "Reconciled", tone: "allow", icon: "shield-check" };
    case "observed":
      return { label: "Observed OS", tone: "allow", icon: "eye" };
    default:
      return { label: "Claimed only", tone: "ask", icon: "circle" };
  }
}

function barToneVar(verdict: string | undefined, isWatchHit: boolean): string {
  if (verdict === "deny") return "var(--tone-block)";
  if (verdict === "step_up") return "var(--tone-ask)";
  if (isWatchHit) return "var(--tone-watch)";
  return "var(--tone-allow)";
}

export function TraceWaterfall({
  attempts,
  receipts,
  turns,
  activeTurn,
  selectedAttemptId,
  onSelectTurn,
  onSelectAttempt,
  onOpenEntity,
}: {
  attempts: ActionAttempt[];
  receipts: DecisionReceipt[];
  turns: TurnSummary[];
  activeTurn: number | null;
  selectedAttemptId: string | null;
  onSelectTurn: (turn: number | null) => void;
  onSelectAttempt: (id: string) => void;
  onOpenEntity?: (target: EntityTarget) => void;
}) {
  const [expandedSpans, setExpandedSpans] = useState<Record<string, boolean>>({});

  const visibleAttempts = useMemo(
    () =>
      attempts.filter((a) => {
        if (activeTurn === null) return true;
        return (a.turn_index ?? 1) === activeTurn;
      }),
    [attempts, activeTurn],
  );

  const maxDurationMs = useMemo(
    () => Math.max(100, ...visibleAttempts.map((a) => a.duration_ms ?? 120)),
    [visibleAttempts],
  );

  function toggleExpanded(id: string) {
    setExpandedSpans((prev) => ({ ...prev, [id]: !prev[id] }));
  }

  return (
    <VStack gap={3}>
      <div className="trace-turn-scrubber" role="region" aria-label="Turn scrubber">
        <Button
          size="sm"
          variant={activeTurn === null ? "primary" : "secondary"}
          label={`All turns (${turns.length || 1})`}
          onClick={() => onSelectTurn(null)}
        />
        {turns.map((turn) => {
          const isCurrent = activeTurn === turn.turn_index;
          return (
            <Button
              key={turn.turn_index}
              size="sm"
              variant={isCurrent ? "primary" : "secondary"}
              icon={
                turn.has_compaction ? (
                  <GrdrIcon name="layers" size={12} />
                ) : turn.has_subagent_handoff ? (
                  <GrdrIcon name="git-fork" size={12} />
                ) : undefined
              }
              label={`Turn ${turn.turn_index}`}
              onClick={() => onSelectTurn(turn.turn_index)}
            />
          );
        })}
      </div>

      <div className="trace-legend-row">
        <HStack gap={2} align="center" style={{ flexWrap: "wrap" }}>
          <StatusInline dot dotColor="var(--tone-allow)" tone="allow" label="Allow" />
          <StatusInline dot dotColor="var(--tone-watch)" tone="watch" label="Watch" />
          <StatusInline dot dotColor="var(--tone-ask)" tone="ask" label="Ask" />
          <StatusInline dot dotColor="var(--tone-block)" tone="block" label="Deny" />
        </HStack>
        <span className="mono tabular" style={{ fontSize: 11.5, color: "var(--ink-muted)" }}>
          {`Scale: 0 ms to ${maxDurationMs} ms`}
        </span>
      </div>

      <div className="trace-waterfall">
        {visibleAttempts.map((attempt, index) => {
          const receipt = receipts.find((r) => r.attempt_id === attempt.id);
          const verdict = receipt?.verdict ?? "allow";
          const isWatchHit = Boolean(verdict === "allow" && receipt?.rule_id);
          const duration = attempt.duration_ms ?? 120;
          const pct = Math.max(8, Math.min(100, Math.round((duration / maxDurationMs) * 100)));
          const offsetPct = Math.min(72, index * 9);
          const clampedWidth = Math.max(8, Math.min(100 - offsetPct, pct));
          const prov = provenanceMeta(attempt.provenance);
          const secondary = attempt.secondary_actions ?? [];
          const hasChildren = secondary.length > 0;
          const isExpanded = expandedSpans[attempt.id] ?? hasChildren;
          const isSelected = selectedAttemptId === attempt.id;
          const isChildSpan = Boolean(attempt.parent_span_id);
          const showExtraCompaction = Boolean(attempt.compaction && attempt.span_kind !== "compaction");

          return (
            <div
              key={attempt.id}
              className={`trace-span-card ${isSelected ? "selected" : ""}`}
              onClick={() => onSelectAttempt(attempt.id)}
            >
              <div className={`trace-span-main ${isChildSpan ? "child" : ""}`}>
                <VStack gap={1}>
                  <HStack gap={2} align="center" style={{ flexWrap: "wrap" }}>
                    <span className="mono" style={{ fontSize: 11.5, color: "var(--ink-muted)" }}>
                      {`T${attempt.turn_index ?? 1}`}
                    </span>
                    <Badge variant="neutral" label={spanKindLabel(attempt.span_kind)} />
                    <span style={{ fontWeight: 600 }}>{formatActionLabel(attempt.action_class)}</span>
                    {isWatchHit ? (
                      <Badge variant="info" icon={<GrdrIcon name="eye" size={11} />} label="Watch" />
                    ) : (
                      receipt && <VerdictBadge verdict={receipt.verdict} />
                    )}
                    {showExtraCompaction && (
                      <Badge variant="info" icon={<GrdrIcon name="layers" size={11} />} label="Compaction" />
                    )}
                    {attempt.skill_used && (
                      <EntityLink
                        kind="artifact"
                        id={attempt.skill_used}
                        label={attempt.skill_used}
                        compact
                        onSelect={onOpenEntity}
                      />
                    )}
                  </HStack>
                  <Quoted text={attempt.target} />
                  <Text size="sm" color="secondary">
                    {attempt.summary}
                  </Text>
                </VStack>

                <VStack gap={1} align="end">
                  <StatusInline
                    tone={prov.tone}
                    icon={<GrdrIcon name={prov.icon} size={12} />}
                    label={prov.label}
                  />
                  <span className="mono tabular" style={{ fontSize: 12, color: "var(--ink-secondary)" }}>
                    {`${duration} ms`}
                  </span>
                </VStack>
              </div>

              <div className="trace-bar-rail" aria-hidden="true">
                <div
                  className="trace-bar-fill"
                  style={{
                    marginInlineStart: `${offsetPct}%`,
                    width: `${clampedWidth}%`,
                    backgroundColor: barToneVar(receipt?.verdict, isWatchHit),
                  }}
                />
              </div>

              {hasChildren && (
                <div className="trace-secondary-wrap">
                  <button
                    type="button"
                    className="trace-expand-btn"
                    onClick={(ev) => {
                      ev.stopPropagation();
                      toggleExpanded(attempt.id);
                    }}
                  >
                    <GrdrIcon name={isExpanded ? "chevron-down" : "chevron-right"} size={12} />
                    <span>{`Decomposed shell actions (${pluralize(secondary.length, "step")})`}</span>
                  </button>
                  {isExpanded && (
                    <div className="trace-secondary-list">
                      {secondary.map((sub, idx) => (
                        <div key={`${attempt.id}-sub-${idx}`} className="trace-secondary-item">
                          <Badge variant="neutral" label={formatActionLabel(sub.action_class)} />
                          <Quoted text={sub.command} />
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {receipt?.rule_id && (
                <HStack gap={2} align="center" style={{ marginTop: 6 }}>
                  <Text size="sm" color="secondary">Rule:</Text>
                  <EntityLink
                    kind="rule"
                    id={receipt.rule_id}
                    label={receipt.rule_id}
                    compact
                    onSelect={onOpenEntity}
                  />
                </HStack>
              )}
            </div>
          );
        })}
      </div>
    </VStack>
  );
}
