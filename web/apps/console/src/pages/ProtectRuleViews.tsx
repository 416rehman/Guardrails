import type { FormEvent } from "react";
import type { ActionClass, Mode, ReplaySummary } from "@grdr/api";
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
            <table>
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
                    <td>
                      <EntityLink
                        kind="session"
                        id={sample.session_id}
                        label={sample.session_id}
                        compact
                        onSelect={onOpenEntity}
                      />
                    </td>
                    <td>
                      <EntityLink
                        kind="agent"
                        label={sample.agent_name}
                        compact
                        onSelect={onOpenEntity}
                      />
                    </td>
                    <td>
                      <Quoted text={sample.target} />
                    </td>
                    <td>
                      <VerdictBadge verdict={sample.current_verdict} />
                    </td>
                    <td>
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
