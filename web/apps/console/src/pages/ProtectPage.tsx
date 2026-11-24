import { useEffect, useState, type FormEvent } from "react";
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
import { pluralize, type ProtectSectionId } from "@grdr/i18n";
import { type EntityTarget, ModeControl, Quoted } from "@grdr/kit";
import {
  Badge,
  Banner,
  Button,
  GrdrIcon,
  Heading,
  HStack,
  Text,
  UiSdkSegmentedControl,
  VStack,
} from "@grdr/ui";
import { BrowserPoliciesSection } from "./BrowserPoliciesSection";
import { ReplayImpactCard, RuleEditorCard } from "./ProtectRuleViews";

type EditorViewMode = "simple" | "advanced" | "code";

export function ProtectPage({
  packs,
  devices,
  section = "rules",
  onSectionChange,
  prefillAttempt,
  focusedEntity,
  onClearPrefill,
  onOpenEntity,
  onUpdated,
}: {
  packs: PolicyPack[];
  devices: Device[];
  section?: ProtectSectionId;
  onSectionChange?: (next: ProtectSectionId) => void;
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
  const [reason, setReason] = useState(
    "Modifying environment secret files requires operator approval.",
  );

  useEffect(() => {
    if (prefillAttempt) {
      onSectionChange?.("rules");
      setShowNewForm(true);
      setTitle(`Govern ${prefillAttempt.action_class} on ${prefillAttempt.agent_name}`);
      setActionClass(prefillAttempt.action_class);
      setContainsPattern(prefillAttempt.target);
      setMode("ask");
      setReason(`Rule created from observed ${prefillAttempt.action_class} attempt.`);
    }
  }, [prefillAttempt, onSectionChange]);

  const boundaryDevices = devices.filter((d) => d.install_profile === "protected").length;
  const appHookAgents = devices
    .flatMap((d) => d.agents)
    .filter((a) => !a.assurance.control.includes("boundary")).length;
  const isBrowserSection = section === "browser";

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

  async function handleSaveRule(e: FormEvent) {
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
            {isBrowserSection
              ? "Govern file uploads, pasted secrets, and extension locks across hosted browser AI apps."
              : `Control what agents can run locally in Watch, Ask, or Block mode (${pluralize(boundaryDevices, "sandboxed endpoint")}, ${pluralize(appHookAgents, "app-hook agent")}).`}
          </Text>
        </div>
        {!isBrowserSection && (
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
              ]}
              onChange={setEditorMode}
            />
            <Button
              variant="primary"
              label={showNewForm ? "Close rule builder" : "New rule"}
              icon={<GrdrIcon name="plus" size={14} />}
              onClick={() => {
                setEditingRuleId(null);
                setShowNewForm((prev) => !prev);
              }}
            />
          </HStack>
        )}
      </div>

      {error && <Banner status="error" title={error} collapsible={false} />}

      {isBrowserSection ? (
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
            <RuleEditorCard
              editingRuleId={editingRuleId}
              title={title}
              actionClass={actionClass}
              containsPattern={containsPattern}
              mode={mode}
              reason={reason}
              onTitleChange={setTitle}
              onActionClassChange={setActionClass}
              onContainsPatternChange={setContainsPattern}
              onModeChange={setMode}
              onReasonChange={setReason}
              onSubmit={handleSaveRule}
              onCancel={() => {
                setEditingRuleId(null);
                setShowNewForm(false);
                onClearPrefill();
              }}
            />
          )}

          {replay && (
            <ReplayImpactCard
              replay={replay}
              onOpenEntity={onOpenEntity}
              onDismiss={() => setReplay(null)}
              onConfirm={() => void confirmReplayPromotion()}
            />
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
