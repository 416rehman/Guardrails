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
import { pluralize } from "@grdr/i18n";
import { EntityLink, type EntityTarget, ModeBadge, ModeControl, Quoted, VerdictBadge } from "@grdr/kit";
import { BrowserPoliciesSection } from "./BrowserPoliciesSection";
import {
  Badge,
  Banner,
  Button,
  Card,
  GrdrIcon,
  GrdrSelect,
  Heading,
  HStack,
  Text,
  TextInput,
  UiSdkSegmentedControl,
  VStack,
} from "@grdr/ui";

type EditorViewMode = "simple" | "advanced" | "code" | "browser";

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
  focusedEntity,
  onClearPrefill,
  onOpenEntity,
  onUpdated,
}: {
  packs: PolicyPack[];
  devices: Device[];
  prefillAttempt: ActionAttempt | null;
  focusedEntity?: EntityTarget | null;
  onClearPrefill: () => void;
  onOpenEntity?: (target: EntityTarget) => void;
  onUpdated: () => void;
}) {
  const focusedRuleId = focusedEntity?.kind === "rule" ? focusedEntity.id : null;
  const [replay, setReplay] = useState<{ ruleId: string; summary: ReplaySummary } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [editorMode, setEditorMode] = useState<EditorViewMode>("simple");
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
  const appHookAgents = devices
    .flatMap((d) => d.agents)
    .filter((a) => !a.assurance.control.includes("boundary")).length;

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
            {editorMode === "browser"
              ? "Govern file uploads, pasted secrets, and extension locks across hosted browser AI apps."
              : `Control what agents can run locally in Watch, Ask, or Block mode (${pluralize(boundaryDevices, "sandboxed endpoint")}, ${pluralize(appHookAgents, "app-hook agent")}).`}
          </Text>
        </div>
        <HStack gap={2} align="center" style={{ flexWrap: "wrap" }}>
          <UiSdkSegmentedControl<EditorViewMode>
            ariaLabel="Policy representation view"
            value={editorMode}
            options={[
              {
                value: "simple",
                label: "Simple",
                icon: <GrdrIcon name="list" size={13} />,
              },
              {
                value: "advanced",
                label: "Advanced",
                icon: <GrdrIcon name="shield" size={13} />,
              },
              {
                value: "code",
                label: "Code",
                icon: <GrdrIcon name="code" size={13} />,
              },
              {
                value: "browser",
                label: "Browser AI",
                icon: <GrdrIcon name="globe" size={13} />,
              },
            ]}
            onChange={setEditorMode}
          />
          {editorMode !== "browser" && (
            <Button
              variant="primary"
              label={showNewForm ? "Close rule builder" : "New rule"}
              icon={<GrdrIcon name="plus" size={14} />}
              onClick={() => {
                setEditingRuleId(null);
                setShowNewForm((prev) => !prev);
              }}
            />
          )}
        </HStack>
      </div>

      {error && <Banner status="error" title={error} collapsible={false} />}

      {editorMode === "browser" ? (
        <BrowserPoliciesSection />
      ) : (
        <>

      {editorMode === "advanced" && (
        <section className="visual-panel" aria-label="Structured policy sentence builder">
          <HStack justify="between" align="center">
            <HStack gap={2} align="center">
              <GrdrIcon name="shield" size={16} color="var(--accent-primary)" />
              <Heading level={2}>Rule sentence builder</Heading>
            </HStack>
            <Badge variant="info" label="Compiles to Cedar & fastpath" />
          </HStack>
          <Text>
            {`When any enrolled agent executes `}
            <strong className="mono">{actionClass}</strong>
            {` matching `}
            <strong className="mono">{containsPattern || "*"}</strong>
            {`, enforce `}
            <strong>{mode.toUpperCase()}</strong>
            {` on boundary devices.`}
          </Text>
          <HStack gap={2}>
            <Button
              size="sm"
              variant="secondary"
              label="Customize & save rule"
              icon={<GrdrIcon name="pencil" size={13} />}
              onClick={() => setShowNewForm(true)}
            />
          </HStack>
        </section>
      )}

      {editorMode === "code" && (
        <section className="visual-panel" aria-label="Compiled Cedar policy projection">
          <HStack justify="between" align="center">
            <HStack gap={2} align="center">
              <GrdrIcon name="code" size={16} color="var(--accent-primary)" />
              <Heading level={2}>Read-only Cedar projection</Heading>
            </HStack>
            <Badge
              variant="info"
              icon={<GrdrIcon name="lock" size={11} />}
              label={pluralize(packs.reduce((n, p) => n + p.rules.length, 0), "rule")}
            />
          </HStack>
          <pre className="cedar-code">
            {packs
              .flatMap((pack) =>
                pack.rules.map((rule) => {
                  const actionExpr = rule.matcher.action_classes
                    .map((a) => `Action::"${a}"`)
                    .join(", ");
                  const pat = rule.matcher.target_contains[0] ?? "*";
                  return `// ${rule.id} (${pack.id}, mode=${rule.mode}, locked=${rule.locked})\nforbid(\n  principal in Agent::"*" ,\n  action in [${actionExpr}],\n  resource\n) when {\n  context.mode == "${rule.mode}" &&\n  context.target like "*${pat}*"\n};`;
                }),
              )
              .join("\n\n")}
          </pre>
        </section>
      )}

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
              <GrdrSelect
                label="Action class"
                value={actionClass}
                options={ACTION_CLASSES.map((ac) => ({ value: ac, label: ac }))}
                onChange={(val) => setActionClass(val as ActionClass)}
                width="100%"
              />
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
        <section key={pack.id} className="ledger-section">
          <div className="ledger-header">
            <div>
              <h2 className="ledger-title">{`${pack.name} (${pack.version})`}</h2>
              <Text color="secondary">{pack.description}</Text>
            </div>
            <Badge
              variant="info"
              label={pack.channel === "schema-policy" ? "Built-in pack" : pack.channel}
            />
          </div>

          <div className="ledger-list">
            {pack.rules.map((rule) => (
              <div
                key={rule.id}
                className={`ledger-row ${focusedRuleId === rule.id ? "selected" : ""} ${rule.locked ? "floor-locked" : ""}`.trim()}
              >
                <div className="ledger-row-main">
                  <VStack gap={1} style={{ flex: 1, minWidth: 260 }}>
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
                      {rule.hits > 0 && (
                        <Text size="sm" color="secondary" className="tabular">
                          {`· ${pluralize(rule.hits, "hit")}`}
                        </Text>
                      )}
                    </HStack>
                    <Text type="supporting" color="secondary" size="sm">
                      {rule.description}
                    </Text>
                    <HStack gap={2} align="center" style={{ flexWrap: "wrap", marginTop: 4 }}>
                      {editorMode !== "simple" && (
                        <span className="mono" style={{ color: "var(--ink-muted)" }}>
                          {rule.matcher.action_classes.join(", ")}
                        </span>
                      )}
                      {rule.matcher.target_contains.slice(0, 3).map((pat) => (
                        <Quoted key={pat} text={pat} />
                      ))}
                    </HStack>
                  </VStack>

                  <HStack gap={3} align="center" style={{ flexWrap: "wrap" }}>
                    <ModeControl
                      value={rule.mode}
                      locked={rule.locked}
                      boundaryDevices={boundaryDevices}
                      requestDevices={appHookAgents}
                      onChange={(next) => void handleModeChange(rule.id, rule.mode, next)}
                    />

                    {rule.locked ? (
                      <div style={{ minWidth: 164, display: "flex", justifyContent: "flex-end" }}>
                        <Text color="secondary" size="sm">
                          Floor locked
                        </Text>
                      </div>
                    ) : confirmDeleteId === rule.id ? (
                      <div style={{ minWidth: 164, display: "flex", justifyContent: "flex-end" }}>
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
                      </div>
                    ) : (
                      <div style={{ minWidth: 164, display: "flex", justifyContent: "flex-end" }}>
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
                      </div>
                    )}
                  </HStack>
                </div>
              </div>
            ))}
          </div>
        </section>
      ))}
        </>
      )}
    </VStack>
  );
}
