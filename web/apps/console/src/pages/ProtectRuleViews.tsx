// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import type { ActionClass, Mode, PolicyPack, ReplaySummary } from "@grdr/api";
import { pluralize } from "@grdr/i18n";
import { EntityLink, type EntityTarget, ModeBadge, ModeControl, Quoted, VerdictBadge } from "@grdr/kit";
import {
  Badge,
  Button,
  Card,
  GrdrIcon,
  GrdrSelect,
  Heading,
  HStack,
  Text,
  TextInput,
  VStack,
} from "@grdr/ui";

const ACTION_CLASSES: ActionClass[] = [
  "exec",
  "file.read",
  "file.write",
  "file.delete",
  "net.connect",
  "net.request",
  "mcp.call",
  "cred.use",
  "elevate",
  "config.change",
  "data.flow",
];

export function RuleEditorCard({
  editingRuleId,
  title,
  actionClass,
  containsPattern,
  mode,
  reason,
  onTitleChange,
  onActionClassChange,
  onContainsPatternChange,
  onModeChange,
  onReasonChange,
  onSubmit,
  onCancel,
}: {
  editingRuleId: string | null;
  title: string;
  actionClass: ActionClass;
  containsPattern: string;
  mode: Mode;
  reason: string;
  onTitleChange: (val: string) => void;
  onActionClassChange: (val: ActionClass) => void;
  onContainsPatternChange: (val: string) => void;
  onModeChange: (val: Mode) => void;
  onReasonChange: (val: string) => void;
  onSubmit: (e: FormEvent) => void;
  onCancel: () => void;
}) {
  return (
    <Card padding={3}>
      <VStack gap={3}>
        <Heading level={2}>
          {editingRuleId ? `Edit rule (${editingRuleId})` : "Create policy rule"}
        </Heading>
        <form onSubmit={onSubmit} className="form-grid">
          <TextInput
            label="Rule title"
            value={title}
            onChange={onTitleChange}
            isRequired
          />
          <GrdrSelect
            label="Action class"
            value={actionClass}
            options={ACTION_CLASSES.map((ac) => ({ value: ac, label: ac }))}
            onChange={(val) => onActionClassChange(val as ActionClass)}
            width="100%"
          />
          <TextInput
            label="Target contains pattern"
            value={containsPattern}
            onChange={onContainsPatternChange}
            isRequired
          />
          <div className="field">
            <label htmlFor="rule-mode">Initial mode</label>
            <ModeControl value={mode} onChange={onModeChange} />
          </div>
          <div className="field full">
            <TextInput
              label="Reason shown on block or approval"
              value={reason}
              onChange={onReasonChange}
              isRequired
              width="100%"
            />
          </div>
          <div className="field full" style={{ flexDirection: "row", justifyContent: "flex-end", gap: 8 }}>
            <Button label="Cancel" onClick={onCancel} />
            <Button
              type="submit"
              variant="primary"
              label={editingRuleId ? "Update rule" : "Save rule"}
            />
          </div>
        </form>
      </VStack>
    </Card>
  );
}

export function ReplayImpactCard({
  replay,
  onOpenEntity,
  onDismiss,
  onConfirm,
}: {
  replay: { ruleId: string; summary: ReplaySummary };
  onOpenEntity?: (target: EntityTarget) => void;
  onDismiss: () => void;
  onConfirm: () => void;
}) {
  return (
    <Card padding={3}>
      <VStack gap={3}>
        <HStack justify="between" align="center">
          <VStack gap={1}>
            <HStack gap={2} align="center">
              <GrdrIcon name="play" size={15} />
              <Heading level={2}>{`Replay impact before promoting ${replay.ruleId}`}</Heading>
            </HStack>
            <Text color="secondary">
              Promoting a Watch rule requires reviewing historical matches over the selected window.
            </Text>
          </VStack>
          <ModeBadge mode={replay.summary.candidate_mode} />
        </HStack>

        <HStack gap={2} style={{ flexWrap: "wrap" }}>
          <Badge
            variant="success"
            icon={<GrdrIcon name="check-circle" size={12} />}
            label={`Window chosen: ${replay.summary.window_label}`}
          />
          <Badge variant="info" label={`Scanned: ${replay.summary.total_scanned}`} />
          <Badge variant="warning" label={`Matched: ${replay.summary.matched}`} />
          <Badge variant="warning" label={`Would ask: ${replay.summary.would_ask}`} />
          <Badge variant="error" label={`Would block: ${replay.summary.would_block}`} />
        </HStack>

        {replay.summary.samples.length > 0 && (
          <div className="table-wrap">
            <table className="responsive-table">
              <thead>
                <tr>
                  <th>Session</th>
                  <th>Agent</th>
                  <th>Target</th>
                  <th>Current</th>
                  <th>After promotion</th>
                </tr>
              </thead>
              <tbody>
                {replay.summary.samples.map((sample) => (
                  <tr key={sample.attempt_id}>
                    <td data-label="Session">
                      <EntityLink
                        kind="session"
                        id={sample.session_id}
                        label={sample.session_id}
                        compact
                        onSelect={onOpenEntity}
                      />
                    </td>
                    <td data-label="Agent">
                      <EntityLink
                        kind="agent"
                        label={sample.agent_name}
                        compact
                        onSelect={onOpenEntity}
                      />
                    </td>
                    <td data-label="Target">
                      <Quoted text={sample.target} />
                    </td>
                    <td data-label="Current">
                      <VerdictBadge verdict={sample.current_verdict} />
                    </td>
                    <td data-label="After promotion">
                      <VerdictBadge verdict={sample.candidate_verdict} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <HStack justify="end" gap={2}>
          <Button label="Keep in Watch" onClick={onDismiss} />
          <Button
            variant="primary"
            label={`Confirm promotion to ${replay.summary.candidate_mode}`}
            onClick={onConfirm}
          />
        </HStack>
      </VStack>
    </Card>
  );
}

type CopyState = "idle" | "copied" | "unavailable";

function escapeCedarString(raw: string): string {
  return raw
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/\n/g, "\\n")
    .replace(/\r/g, "\\r")
    .replace(/\t/g, "\\t");
}

function escapeCedarLikeSegment(raw: string): string {
  return escapeCedarString(raw).replace(/\*/g, "\\*");
}

function sanitizeCedarComment(raw: string): string {
  return raw.replace(/[\r\n\u202a-\u202e\u2066-\u2069\u200e\u200f]+/g, " ").trim();
}

export function formatCedarPolicySource(packs: PolicyPack[], query: string): {
  source: string;
  ruleCount: number;
  lockedCount: number;
} {
  const normalizedQuery = query.trim().toLowerCase();
  const blocks: string[] = [];
  let ruleCount = 0;
  let lockedCount = 0;

  for (const pack of packs) {
    for (const rule of pack.rules) {
      if (normalizedQuery) {
        const haystack = [
          rule.id,
          rule.title,
          pack.id,
          pack.name,
          ...rule.matcher.action_classes,
          ...rule.matcher.agents,
          ...rule.matcher.target_contains,
          ...rule.matcher.target_prefixes,
        ]
          .join(" ")
          .toLowerCase();
        if (!haystack.includes(normalizedQuery)) {
          continue;
        }
      }
      ruleCount += 1;
      if (rule.locked) lockedCount += 1;

      const safeRuleId = sanitizeCedarComment(rule.id);
      const safePackId = sanitizeCedarComment(pack.id);
      if (!rule.enabled || rule.mode === "off") {
        blocks.push(
          `// ${safeRuleId} (${safePackId}, mode=${rule.mode}, enabled=${rule.enabled}, inactive)\n// No active forbid statement emitted while mode is off or disabled.`,
        );
        continue;
      }

      const idEsc = escapeCedarString(rule.id);
      const reasonEsc = escapeCedarString(rule.reason_template || rule.title);
      const minGradeEsc = escapeCedarString(rule.min_grade || "G1");
      const modeEsc = escapeCedarString(rule.mode);

      const actionClause =
        rule.matcher.action_classes.length === 0
          ? 'action in Grdr::Action::"any"'
          : rule.matcher.action_classes.length === 1
            ? `action == Grdr::Action::"${escapeCedarString(rule.matcher.action_classes[0])}"`
            : `action in [${rule.matcher.action_classes
                .map((a) => `Grdr::Action::"${escapeCedarString(a)}"`)
                .join(", ")}]`;

      const conditions: string[] = [];
      if (rule.matcher.agents.length > 0) {
        const agentChecks = rule.matcher.agents.map(
          (agent) => `principal in Grdr::Agent::"${escapeCedarString(agent.trim().toLowerCase())}"`,
        );
        conditions.push(
          agentChecks.length === 1 ? agentChecks[0] : `(${agentChecks.join(" || ")})`,
        );
      }

      const targetChecks = [
        ...rule.matcher.target_prefixes.map(
          (prefix) => `resource.target like "${escapeCedarLikeSegment(prefix)}*"`,
        ),
        ...rule.matcher.target_contains.map(
          (part) => `resource.target like "*${escapeCedarLikeSegment(part)}*"`,
        ),
      ];
      if (targetChecks.length > 0) {
        conditions.push(
          targetChecks.length === 1 ? targetChecks[0] : `(${targetChecks.join(" || ")})`,
        );
      }

      const annotations = [
        `@id("${idEsc}")`,
        `@mode("${modeEsc}")`,
        `@min_grade("${minGradeEsc}")`,
        ...(rule.locked && rule.mode === "block" ? ['@final("true")'] : []),
        `@message("${reasonEsc}")`,
      ];
      const whenBlock =
        conditions.length > 0 ? `\nwhen {\n  ${conditions.join(" &&\n  ")}\n}` : "";

      blocks.push(
        `// ${safeRuleId} (${safePackId}, locked=${rule.locked})\n${annotations.join("\n")}\nforbid(\n  principal is Grdr::Session,\n  ${actionClause},\n  resource\n)${whenBlock};`,
      );
    }
  }

  return {
    source: blocks.join("\n\n"),
    ruleCount,
    lockedCount,
  };
}

export function CedarProjectionPanel({ packs }: { packs: PolicyPack[] }) {
  const [selectedPackId, setSelectedPackId] = useState<string>("all");
  const [filterQuery, setFilterQuery] = useState<string>("");
  const [copyState, setCopyState] = useState<CopyState>("idle");
  const copyTimerRef = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
      }
    };
  }, []);

  const visiblePacks = useMemo(
    () => (selectedPackId === "all" ? packs : packs.filter((p) => p.id === selectedPackId)),
    [packs, selectedPackId],
  );
  const { source, ruleCount, lockedCount } = useMemo(
    () => formatCedarPolicySource(visiblePacks, filterQuery),
    [visiblePacks, filterQuery],
  );

  function scheduleCopyReset() {
    if (copyTimerRef.current !== null) {
      window.clearTimeout(copyTimerRef.current);
    }
    copyTimerRef.current = window.setTimeout(() => {
      setCopyState("idle");
      copyTimerRef.current = null;
    }, 2000);
  }

  async function copySource() {
    if (!source) return;
    if (typeof navigator === "undefined" || !navigator.clipboard?.writeText) {
      setCopyState("unavailable");
      scheduleCopyReset();
      return;
    }
    try {
      await navigator.clipboard.writeText(source);
      setCopyState("copied");
      scheduleCopyReset();
    } catch {
      setCopyState("unavailable");
      scheduleCopyReset();
    }
  }

  return (
    <section className="visual-panel" aria-label="Compiled Cedar policy projection">
      <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 10 }}>
        <HStack gap={2} align="center">
          <GrdrIcon name="code" size={16} color="var(--accent-primary)" />
          <Heading level={2}>Read-only Cedar projection</Heading>
        </HStack>
        <HStack gap={2} align="center" style={{ flexWrap: "wrap" }}>
          <Badge
            variant="info"
            icon={<GrdrIcon name="lock" size={11} />}
            label={`${pluralize(ruleCount, "rule")} (${lockedCount} locked)`}
          />
          <Button
            size="sm"
            variant="secondary"
            icon={<GrdrIcon name={copyState === "copied" ? "check" : "file-code"} size={13} />}
            label={
              copyState === "copied"
                ? "Copied"
                : copyState === "unavailable"
                  ? "Clipboard unavailable"
                  : "Copy Cedar"
            }
            isDisabled={!source}
            onClick={() => void copySource()}
          />
        </HStack>
      </HStack>

      <HStack gap={2} align="end" style={{ flexWrap: "wrap" }}>
        <div style={{ flex: "1 1 200px", minWidth: 200 }}>
          <GrdrSelect
            label="Policy pack"
            value={selectedPackId}
            options={[
              { value: "all", label: `All packs (${packs.length})` },
              ...packs.map((pack) => ({
                value: pack.id,
                label: `${pack.name} (${pack.rules.length})`,
              })),
            ]}
            onChange={(next) => setSelectedPackId(next)}
            width="100%"
          />
        </div>
        <div style={{ flex: 1, minWidth: 200 }}>
          <TextInput
            label="Filter rules"
            isLabelHidden
            placeholder="Filter Cedar rules by id, action, or target..."
            startIcon={<GrdrIcon name="search" size={13} color="var(--ink-muted)" />}
            value={filterQuery}
            onChange={setFilterQuery}
            width="100%"
          />
        </div>
      </HStack>

      <pre className="cedar-code">
        {source || "// No Cedar rules match the current pack or filter."}
      </pre>
    </section>
  );
}
