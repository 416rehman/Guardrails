// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
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
import type { ConsoleSearchParams } from "../searchSchema";
import { BrowserPoliciesSection } from "./BrowserPoliciesSection";
import { CedarProjectionPanel, ReplayImpactCard, RuleEditorCard } from "./ProtectRuleViews";

type EditorViewMode = "simple" | "advanced" | "code";

type RuleDialogState =
  | { kind: "idle" }
  | { kind: "creating" }
  | { kind: "editing"; ruleId: string }
  | { kind: "confirmingDelete"; ruleId: string };

type ReplayState =
  | { kind: "idle" }
  | { kind: "preview"; ruleId: string; summary: ReplaySummary };

type ProtectFeedback =
  | { kind: "none" }
  | { kind: "error"; message: string };

export function ProtectPage({
  packs,
  devices,
  section = "rules",
  onSectionChange,
  urlSearch,
  onUpdateSearch,
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
  urlSearch?: ConsoleSearchParams;
  onUpdateSearch?: (patch: Partial<ConsoleSearchParams>) => void;
  prefillAttempt: ActionAttempt | null;
  focusedEntity?: EntityTarget | null;
  onClearPrefill: () => void;
  onOpenEntity?: (target: EntityTarget) => void;
  onUpdated: () => void;
}) {
  const focusedRuleId =
    urlSearch?.ruleId ?? (focusedEntity?.kind === "rule" ? focusedEntity.id : null);
  const [replay, setReplay] = useState<ReplayState>({ kind: "idle" });
  const [feedback, setFeedback] = useState<ProtectFeedback>({ kind: "none" });
  const [fallbackEditorMode, setFallbackEditorMode] = useState<EditorViewMode>("simple");
  const editorMode = urlSearch?.editor ?? fallbackEditorMode;
  const setEditorMode = (next: EditorViewMode) => {
    setFallbackEditorMode(next);
    onUpdateSearch?.({ editor: next === "simple" ? undefined : next });
  };
  const [dialog, setDialog] = useState<RuleDialogState>(() =>
    prefillAttempt ? { kind: "creating" } : { kind: "idle" },
  );

  const [title, setTitle] = useState("Require approval for .env secret edits");
  const [actionClass, setActionClass] = useState<ActionClass>("file.write");
  const [containsPattern, setContainsPattern] = useState(".env");
  const [mode, setMode] = useState<Mode>("ask");
  const [reason, setReason] = useState(
    "Modifying environment secret files requires operator approval.",
  );

  const isFormOpen = dialog.kind === "creating" || dialog.kind === "editing";
  const editingRuleId = dialog.kind === "editing" ? dialog.ruleId : null;
  const confirmDeleteId = dialog.kind === "confirmingDelete" ? dialog.ruleId : null;

  useEffect(() => {
    if (prefillAttempt) {
      onSectionChange?.("rules");
      setDialog({ kind: "creating" });
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
    setFeedback({ kind: "none" });
    if (currentMode === "watch" && (nextMode === "ask" || nextMode === "block")) {
      try {
        const summary = await api.replayRule(ruleId, nextMode);
        setReplay({ kind: "preview", ruleId, summary });
      } catch (err) {
        setFeedback({ kind: "error", message: (err as Error).message });
      }
      return;
    }

    try {
      await api.updateRuleMode(ruleId, nextMode, false);
      onUpdated();
    } catch (err) {
      setFeedback({ kind: "error", message: (err as Error).message });
    }
  }

  async function confirmReplayPromotion() {
    if (replay.kind !== "preview") return;
    try {
      await api.updateRuleMode(replay.ruleId, replay.summary.candidate_mode, true);
      setReplay({ kind: "idle" });
      onUpdated();
    } catch (err) {
      setFeedback({ kind: "error", message: (err as Error).message });
    }
  }

  async function handleSaveRule(e: FormEvent) {
    e.preventDefault();
    setFeedback({ kind: "none" });
    const matcher = {
      action_classes: [actionClass],
      target_prefixes: [],
      target_contains: [containsPattern],
      agents: [],
    };
    try {
      if (dialog.kind === "editing") {
        await api.updateRule(dialog.ruleId, {
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
      setDialog({ kind: "idle" });
      onClearPrefill();
      onUpdated();
    } catch (err) {
      setFeedback({ kind: "error", message: (err as Error).message });
    }
  }

  function startEditRule(rule: PolicyRule) {
    setFeedback({ kind: "none" });
    setTitle(rule.title);
    setActionClass(rule.matcher.action_classes[0] ?? "file.write");
    setContainsPattern(rule.matcher.target_contains[0] ?? "");
    setMode(rule.mode);
    setReason(rule.reason_template);
    setDialog({ kind: "editing", ruleId: rule.id });
  }

  async function handleDeleteRule(ruleId: string) {
    setFeedback({ kind: "none" });
    try {
      await api.deleteRule(ruleId);
      setDialog({ kind: "idle" });
      onUpdated();
    } catch (err) {
      setFeedback({ kind: "error", message: (err as Error).message });
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
              label={isFormOpen ? "Close rule builder" : "New rule"}
              icon={<GrdrIcon name="plus" size={14} />}
              onClick={() => {
                setDialog((prev) =>
                  prev.kind === "creating" || prev.kind === "editing"
                    ? { kind: "idle" }
                    : { kind: "creating" },
                );
              }}
            />
          </HStack>
        )}
      </div>

      {feedback.kind === "error" && (
        <Banner status="error" title={feedback.message} collapsible={false} />
      )}

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
                  onClick={() => setDialog({ kind: "creating" })}
                />
              </HStack>
            </section>
          )}

          {editorMode === "code" && <CedarProjectionPanel packs={packs} />}

          {isFormOpen && (
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
                setDialog({ kind: "idle" });
                onClearPrefill();
              }}
            />
          )}

          {replay.kind === "preview" && (
            <ReplayImpactCard
              replay={{ ruleId: replay.ruleId, summary: replay.summary }}
              onOpenEntity={onOpenEntity}
              onDismiss={() => setReplay({ kind: "idle" })}
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
                                onClick={() => setDialog({ kind: "idle" })}
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
                                onClick={() => setDialog({ kind: "confirmingDelete", ruleId: rule.id })}
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
