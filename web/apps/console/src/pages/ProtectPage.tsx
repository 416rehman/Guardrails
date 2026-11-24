import { useEffect, useState } from "react";
import {
  api,
  type ActionAttempt,
  type ActionClass,
  type Device,
  type Mode,
  type PolicyPack,
  type PolicyRule,
  type ReplaySummary,
} from "@grdr/api";
import { ModeBadge, ModeControl, Quoted, VerdictBadge } from "@grdr/kit";
import {
  Badge,
  Banner,
  Button,
  Card,
  GrdrIcon,
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

export function ProtectPage({
  packs,
  devices,
  prefillAttempt,
  onClearPrefill,
  onUpdated,
}: {
  packs: PolicyPack[];
  devices: Device[];
  prefillAttempt: ActionAttempt | null;
  onClearPrefill: () => void;
  onUpdated: () => void;
}) {
  const [replay, setReplay] = useState<{ ruleId: string; summary: ReplaySummary } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showNewForm, setShowNewForm] = useState<boolean>(prefillAttempt !== null);
  const [editingRuleId, setEditingRuleId] = useState<string | null>(null);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);

  const [title, setTitle] = useState("Require approval for .env secret edits");
  const [actionClass, setActionClass] = useState<ActionClass>("file.write");
  const [containsPattern, setContainsPattern] = useState(".env");
  const [mode, setMode] = useState<Mode>("ask");
  const [reason, setReason] = useState("Modifying environment secret files requires operator approval.");

  useEffect(() => {
    if (prefillAttempt) {
      setShowNewForm(true);
      setTitle(`Govern ${prefillAttempt.action_class} on ${prefillAttempt.agent_name}`);
      setActionClass(prefillAttempt.action_class);
      setContainsPattern(prefillAttempt.target);
      setMode("ask");
      setReason(`Rule created from observed ${prefillAttempt.action_class} attempt.`);
    }
  }, [prefillAttempt]);

  const boundaryDevices = devices.filter((d) => d.install_profile === "protected").length;
  const requestDevices = devices.filter((d) => d.install_profile === "user").length;

  async function handleModeChange(ruleId: string, currentMode: Mode, nextMode: Mode) {
    setError(null);
    if (currentMode === "watch" && (nextMode === "ask" || nextMode === "block")) {
      try {
        const summary = await api.replayRule(ruleId, nextMode);
        setReplay({ ruleId, summary });
      } catch (err) {
        setError((err as Error).message);
      }
      return;
    }

    try {
      await api.updateRuleMode(ruleId, nextMode, false);
      onUpdated();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function confirmReplayPromotion() {
    if (!replay) return;
    try {
      await api.updateRuleMode(replay.ruleId, replay.summary.candidate_mode, true);
      setReplay(null);
      onUpdated();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function handleSaveRule(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    const matcher = {
      action_classes: [actionClass],
      target_prefixes: [],
      target_contains: [containsPattern],
      agents: [],
    };
    try {
      if (editingRuleId) {
        await api.updateRule(editingRuleId, {
          title,
          description: reason,
          mode,
          matcher,
          reason_template: reason,
        });
      } else {
        await api.createRule({
          title,
          description: reason,
          mode,
          matcher,
          reason_template: reason,
        });
      }
      setEditingRuleId(null);
      setShowNewForm(false);
      onClearPrefill();
      onUpdated();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  function startEditRule(rule: PolicyRule) {
    setError(null);
    setConfirmDeleteId(null);
    setEditingRuleId(rule.id);
    setTitle(rule.title);
    setActionClass(rule.matcher.action_classes[0] ?? "file.write");
    setContainsPattern(rule.matcher.target_contains[0] ?? "");
    setMode(rule.mode);
    setReason(rule.reason_template);
    setShowNewForm(true);
  }

  async function handleDeleteRule(ruleId: string) {
    setError(null);
    try {
      await api.deleteRule(ruleId);
      setConfirmDeleteId(null);
      if (editingRuleId === ruleId) {
        setEditingRuleId(null);
        setShowNewForm(false);
      }
      onUpdated();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  return (
    <VStack gap={4}>
      <div className="page-header">
        <div>
          <Heading level={1}>Protect</Heading>
          <Text color="secondary">
            {`Rules execute locally in Off, Watch, Ask, or Block mode. Protected endpoints enforce via boundary; User endpoints enforce as requests (${boundaryDevices} boundary, ${requestDevices} request device(s)).`}
          </Text>
        </div>
        <Button
          variant="primary"
          label={showNewForm ? "Close rule builder" : "New rule"}
          icon={<GrdrIcon name="plus" size={14} />}
          onClick={() => {
            setEditingRuleId(null);
            setShowNewForm((prev) => !prev);
          }}
        />
      </div>

      {error && <Banner status="error" title={error} collapsible={false} />}

      {showNewForm && (
        <Card padding={3}>
          <VStack gap={3}>
            <Heading level={2}>
              {editingRuleId ? `Edit rule (${editingRuleId})` : "Create policy rule"}
            </Heading>
            <form onSubmit={handleSaveRule} className="form-grid">
              <TextInput
                label="Rule title"
                value={title}
                onChange={(val) => setTitle(val)}
                isRequired
              />
              <div className="field">
                <label htmlFor="rule-action">Action class</label>
                <select
                  id="rule-action"
                  value={actionClass}
                  onChange={(e) => setActionClass(e.target.value as ActionClass)}
                >
                  {ACTION_CLASSES.map((ac) => (
                    <option key={ac} value={ac}>
                      {ac}
                    </option>
                  ))}
                </select>
              </div>
              <TextInput
                label="Target contains pattern"
                value={containsPattern}
                onChange={(val) => setContainsPattern(val)}
                isRequired
              />
              <div className="field">
                <label htmlFor="rule-mode">Initial mode</label>
                <ModeControl value={mode} onChange={setMode} />
              </div>
              <div className="field full">
                <TextInput
                  label="Reason shown on block or approval"
                  value={reason}
                  onChange={(val) => setReason(val)}
                  isRequired
                  width="100%"
                />
              </div>
              <div className="field full" style={{ flexDirection: "row", justifyContent: "flex-end", gap: 8 }}>
                <Button
                  label="Cancel"
                  onClick={() => {
                    setEditingRuleId(null);
                    setShowNewForm(false);
                    onClearPrefill();
                  }}
                />
                <Button
                  type="submit"
                  variant="primary"
                  label={editingRuleId ? "Update rule" : "Save rule"}
                />
              </div>
            </form>
          </VStack>
        </Card>
      )}

      {replay && (
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

            <HStack gap={2}>
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
                        <td className="mono">{sample.session_id}</td>
                        <td>{sample.agent_name}</td>
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
              <Button label="Keep in Watch" onClick={() => setReplay(null)} />
              <Button
                variant="primary"
                label={`Confirm promotion to ${replay.summary.candidate_mode}`}
                onClick={() => void confirmReplayPromotion()}
              />
            </HStack>
          </VStack>
        </Card>
      )}

      {packs.map((pack) => (
        <Card key={pack.id} padding={3}>
          <VStack gap={3}>
            <HStack justify="between" align="center">
              <VStack gap={1}>
                <Heading level={2}>{`${pack.name} (${pack.version})`}</Heading>
                <Text color="secondary">{pack.description}</Text>
              </VStack>
              <Badge variant="info" label={pack.channel} />
            </HStack>

            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Rule</th>
                    <th>Match</th>
                    <th>Hits</th>
                    <th>Mode control</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {pack.rules.map((rule) => (
                    <tr key={rule.id}>
                      <td>
                        <HStack gap={2} align="center" style={{ flexWrap: "wrap" }}>
                          <strong>{rule.title}</strong>
                          {rule.locked && (
                            <span style={{ flexShrink: 0, display: "inline-flex" }}>
                              <Badge
                                variant="error"
                                icon={<GrdrIcon name="lock" size={11} />}
                                label="Floor"
                              />
                            </span>
                          )}
                        </HStack>
                        <Text type="supporting" color="secondary" size="sm">
                          {rule.description}
                        </Text>
                      </td>
                      <td>
                        <div className="mono">{rule.matcher.action_classes.join(", ")}</div>
                        <Text color="secondary" size="sm">
                          {rule.matcher.target_contains.slice(0, 3).join(", ")}
                        </Text>
                      </td>
                      <td className="tabular">{rule.hits}</td>
                      <td>
                        <ModeControl
                          value={rule.mode}
                          locked={rule.locked}
                          boundaryDevices={boundaryDevices}
                          requestDevices={requestDevices}
                          onChange={(next) => void handleModeChange(rule.id, rule.mode, next)}
                        />
                      </td>
                      <td>
                        {rule.locked ? (
                          <Text color="secondary" size="sm">
                            Floor locked
                          </Text>
                        ) : confirmDeleteId === rule.id ? (
                          <HStack gap={1}>
                            <Button
                              variant="destructive"
                              size="sm"
                              label="Confirm delete"
                              onClick={() => void handleDeleteRule(rule.id)}
                            />
                            <Button
                              size="sm"
                              label="Cancel"
                              onClick={() => setConfirmDeleteId(null)}
                            />
                          </HStack>
                        ) : (
                          <HStack gap={1}>
                            <Button
                              size="sm"
                              label="Edit"
                              aria-label={`Edit rule ${rule.title}`}
                              icon={<GrdrIcon name="pencil" size={13} />}
                              onClick={() => startEditRule(rule)}
                            />
                            <Button
                              size="sm"
                              label="Delete"
                              aria-label={`Delete rule ${rule.title}`}
                              icon={<GrdrIcon name="trash" size={13} />}
                              onClick={() => setConfirmDeleteId(rule.id)}
                            />
                          </HStack>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </VStack>
        </Card>
      ))}
    </VStack>
  );
}
