// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
import { useContext, useMemo } from "react";
import type {
  Device,
  KillScope,
  KillSwitchState,
  SessionSummary,
} from "@grdr/api";
import { capitalizeLabel, pluralize, presentAgentName } from "@grdr/i18n";
import {
  Badge,
  Banner,
  Button,
  Card,
  Dialog,
  GrdrIcon,
  GrdrSelect,
  HarnessIcon,
  Heading,
  HStack,
  IconButton,
  SelectableTile,
  Text,
  TextInput,
  VStack,
} from "@grdr/ui";
import { ConsoleWorkspaceContext } from "../ConsoleContext";
import {
  deriveKillSwitchCatalog,
  EMPTY_KILL_SELECTION,
  resolveKillSwitchBlastRadius,
  type KillSwitchSelection,
} from "../consoleState";

export type { KillSwitchSelection };

export type KillSwitchFlow =
  | { kind: "closed"; inlineArmed: boolean }
  | {
      kind: "modalOpen";
      blockedAgents: string[];
      blockedModels: string[];
      blockedGateways: string[];
      query: string;
    }
  | {
      kind: "armedConfirming";
      blockedAgents: string[];
      blockedModels: string[];
      blockedGateways: string[];
      query: string;
      confirmPhrase: string;
    };

export function KillSwitchSection({
  killSwitch,
  devices,
  sessions,
  savedSelection = EMPTY_KILL_SELECTION,
  errorMessage,
  scope,
  targetId,
  killReason,
  flow,
  onScopeChange,
  onTargetIdChange,
  onKillReasonChange,
  onFlowChange,
  onTrigger,
}: {
  killSwitch: KillSwitchState;
  devices?: Device[];
  sessions?: SessionSummary[];
  savedSelection?: KillSwitchSelection;
  errorMessage?: string;
  scope: KillScope;
  targetId: string;
  killReason: string;
  flow: KillSwitchFlow;
  onScopeChange: (scope: KillScope) => void;
  onTargetIdChange: (targetId: string) => void;
  onKillReasonChange: (reason: string) => void;
  onFlowChange: (next: KillSwitchFlow) => void;
  onTrigger: (
    action: "freeze" | "kill" | "release",
    selection?: KillSwitchSelection,
  ) => Promise<boolean>;
}) {
  const workspace = useContext(ConsoleWorkspaceContext);
  const resolvedDevices = devices ?? workspace?.snapshot.devices ?? [];
  const resolvedSessions = sessions ?? workspace?.snapshot.sessions ?? [];
  const catalog = useMemo(
    () => deriveKillSwitchCatalog(resolvedDevices, resolvedSessions),
    [resolvedDevices, resolvedSessions],
  );
  const inlineArmed = flow.kind === "closed" && flow.inlineArmed;
  const isModalOpen = flow.kind === "modalOpen" || flow.kind === "armedConfirming";
  const blockedAgents = isModalOpen ? flow.blockedAgents : [];
  const blockedModels = isModalOpen ? flow.blockedModels : [];
  const blockedGateways = isModalOpen ? flow.blockedGateways : [];
  const matrixQuery = isModalOpen ? flow.query : "";
  const confirmPhrase = flow.kind === "armedConfirming" ? flow.confirmPhrase : "";
  const totalSelected = blockedAgents.length + blockedModels.length + blockedGateways.length;
  const blastRadius = useMemo(
    () =>
      resolveKillSwitchBlastRadius(resolvedDevices, {
        blockedAgents,
        blockedModels,
        blockedGateways,
      }),
    [resolvedDevices, blockedAgents, blockedModels, blockedGateways],
  );

  const targetOptions = useMemo(() => {
    if (scope === "session") {
      const opts = resolvedSessions.map((s) => ({
        value: s.id,
        label: `${s.id} (${presentAgentName(s.agent_name)} on ${s.device_name})`,
      }));
      if (targetId && !opts.some((o) => o.value === targetId)) {
        opts.unshift({ value: targetId, label: targetId });
      }
      return opts;
    }
    if (scope === "device") {
      const opts = resolvedDevices.map((d) => ({
        value: d.id,
        label: `${d.hostname} (${d.id})`,
      }));
      if (targetId && !opts.some((o) => o.value === targetId)) {
        opts.unshift({ value: targetId, label: targetId });
      }
      return opts;
    }
    return [];
  }, [scope, resolvedSessions, resolvedDevices, targetId]);

  const activeBannerTitle =
    killSwitch.state === "inactive"
      ? ""
      : killSwitch.scope === "organisation"
        ? `Active fleet-wide organisation containment (${pluralize(resolvedDevices.length, "enrolled endpoint")}): ${killSwitch.reason}`
        : `Active ${killSwitch.scope} containment (target ${killSwitch.target_id}): ${killSwitch.reason}`;

  function openModal() {
    const savedCount =
      savedSelection.blockedAgents.length +
      savedSelection.blockedModels.length +
      savedSelection.blockedGateways.length;
    if (savedCount > 0) {
      onFlowChange({
        kind: "armedConfirming",
        blockedAgents: savedSelection.blockedAgents,
        blockedModels: savedSelection.blockedModels,
        blockedGateways: savedSelection.blockedGateways,
        query: "",
        confirmPhrase: "",
      });
    } else {
      onFlowChange({
        kind: "modalOpen",
        blockedAgents: [],
        blockedModels: [],
        blockedGateways: [],
        query: "",
      });
    }
  }

  function updateSelections(
    nextAgents: string[],
    nextModels: string[],
    nextGateways: string[],
  ) {
    const count = nextAgents.length + nextModels.length + nextGateways.length;
    if (count === 0) {
      onFlowChange({
        kind: "modalOpen",
        blockedAgents: nextAgents,
        blockedModels: nextModels,
        blockedGateways: nextGateways,
        query: matrixQuery,
      });
    } else {
      onFlowChange({
        kind: "armedConfirming",
        blockedAgents: nextAgents,
        blockedModels: nextModels,
        blockedGateways: nextGateways,
        query: matrixQuery,
        confirmPhrase,
      });
    }
  }

  return (
    <>
      <Card padding={3}>
        <VStack gap={3}>
          <HStack justify="between" align="center">
            <HStack gap={2} align="center">
              <GrdrIcon name="shield-off" size={16} />
              <Heading level={2}>Scoped kill switch</Heading>
            </HStack>
            <Badge
              variant={killSwitch.state === "inactive" ? "success" : "error"}
              label={capitalizeLabel(killSwitch.state)}
            />
          </HStack>

          {killSwitch.state !== "inactive" && (
            <Banner
              status="error"
              title={activeBannerTitle}
              collapsible={false}
            />
          )}

          <div className="form-grid">
            <GrdrSelect
              label="Scope"
              value={scope}
              options={[
                { value: "session", label: "Session" },
                { value: "device", label: "Device" },
                { value: "organisation", label: "Organisation" },
              ]}
              onChange={(val) => onScopeChange(val as KillScope)}
              width="100%"
            />
            {scope === "organisation" || targetOptions.length === 0 ? (
              <TextInput
                label="Target ID"
                value={scope === "organisation" ? "*" : targetId}
                isDisabled={scope === "organisation"}
                onChange={onTargetIdChange}
              />
            ) : (
              <GrdrSelect
                label="Target ID"
                value={targetId}
                options={targetOptions}
                onChange={onTargetIdChange}
                width="100%"
              />
            )}
            <div className="field full">
              <TextInput
                label="Audit reason"
                value={killReason}
                onChange={onKillReasonChange}
                width="100%"
              />
            </div>
            <div className="field full">
              <SelectableTile
                label="Stop all matching agent actions immediately"
                checked={inlineArmed}
                onChange={(checked) => onFlowChange({ kind: "closed", inlineArmed: checked })}
                icon={<GrdrIcon name="shield-alert" size={15} color="var(--tone-block)" />}
              />
            </div>
            <div className="field full" style={{ flexDirection: "row", flexWrap: "wrap", gap: 8 }}>
              <Button
                label="Freeze (60 min)"
                isDisabled={!inlineArmed}
                onClick={() => void onTrigger("freeze")}
              />
              <Button
                variant="destructive"
                label="Engage kill switch"
                icon={<GrdrIcon name="alert-octagon" size={14} />}
                isDisabled={!inlineArmed}
                data-agent-confirm="Confirm stopping all matching agent sessions immediately"
                onClick={() => void onTrigger("kill")}
              />
              <Button
                variant="secondary"
                label="Lock down controls"
                onClick={openModal}
              />
              {killSwitch.state !== "inactive" && (
                <Button
                  variant="primary"
                  label="Release"
                  onClick={() => void onTrigger("release")}
                />
              )}
            </div>
          </div>
        </VStack>
      </Card>

      <Dialog
        isOpen={isModalOpen}
        onOpenChange={(open) => {
          if (!open) onFlowChange({ kind: "closed", inlineArmed: false });
        }}
        purpose="form"
        width={900}
        padding={4}
        aria-label="Scoped Kill Switch Matrix"
      >
        <VStack gap={3}>
          <HStack justify="between" align="start">
            <HStack gap={2} align="start">
              <div style={{ paddingTop: 2 }}>
                <GrdrIcon name="shield-off" size={20} color="var(--tone-block)" />
              </div>
              <VStack gap={0}>
                <Heading level={2}>Scoped Kill Switch</Heading>
                <Text size="sm" color="secondary">
                  Select which agents, model providers, or gateways to contain.
                </Text>
              </VStack>
            </HStack>
            <IconButton
              label="Close"
              icon={<GrdrIcon name="x" size={15} />}
              variant="secondary"
              size="sm"
              onClick={() => onFlowChange({ kind: "closed", inlineArmed: false })}
            />
          </HStack>

          <Banner
            status="error"
            title={
              totalSelected === 0
                ? "Select target agent types, model providers, or gateways to contain."
                : `Preview: will isolate ${pluralize(blockedAgents.length, "agent type")}, ${pluralize(blockedModels.length, "provider")}, and ${pluralize(blockedGateways.length, "gateway")}. ${blastRadius.summaryText}`
            }
            collapsible={false}
          />

          {errorMessage && (
            <Banner status="error" title={errorMessage} collapsible={false} />
          )}

          <div className="killswitch-search-bar">
            <div style={{ flex: 1, minWidth: 220 }}>
              <TextInput
                label="Search agents, providers, or gateways"
                isLabelHidden
                placeholder="Search agents, providers, or gateways..."
                startIcon={<GrdrIcon name="search" size={14} color="var(--ink-muted)" />}
                value={matrixQuery}
                onChange={(nextQuery) => {
                  if (flow.kind === "modalOpen" || flow.kind === "armedConfirming") {
                    onFlowChange({ ...flow, query: nextQuery });
                  }
                }}
                width="100%"
              />
            </div>
            <HStack gap={2} align="center">
              <Text size="sm" color="secondary" className="tabular">
                {`${totalSelected} selected`}
              </Text>
              {totalSelected > 0 && (
                <Button
                  size="sm"
                  variant="secondary"
                  label="Clear"
                  onClick={() => updateSelections([], [], [])}
                />
              )}
            </HStack>
          </div>

          <div className="killswitch-cols">
            {(
              [
                {
                  key: "agents",
                  title: "Agent types",
                  icon: "layers" as const,
                  items: catalog.agents,
                  selected: blockedAgents,
                  apply: (next: string[]) => updateSelections(next, blockedModels, blockedGateways),
                },
                {
                  key: "models",
                  title: "Model providers",
                  icon: "cpu" as const,
                  items: catalog.models,
                  selected: blockedModels,
                  apply: (next: string[]) => updateSelections(blockedAgents, next, blockedGateways),
                },
                {
                  key: "gateways",
                  title: "Gateways",
                  icon: "plug" as const,
                  items: catalog.gateways,
                  selected: blockedGateways,
                  apply: (next: string[]) => updateSelections(blockedAgents, blockedModels, next),
                },
              ] as const
            ).map((col) => {
              const queryLower = matrixQuery.toLowerCase();
              const filteredItems = col.items.filter((entry) =>
                entry.toLowerCase().includes(queryLower),
              );
              return (
                <div key={col.key} className="killswitch-col">
                  <div className="killswitch-col-head">
                    <HStack gap={2} align="center">
                      <GrdrIcon name={col.icon} size={14} color="var(--ink-secondary)" />
                      <span>{col.title}</span>
                    </HStack>
                    <span className="killswitch-col-count tabular">
                      {`${col.selected.length}/${col.items.length}`}
                    </span>
                  </div>
                  {col.items.length === 0 ? (
                    <Text size="sm" color="secondary">
                      {col.key === "models"
                        ? "No model endpoints discovered in telemetry yet."
                        : "No targets discovered in fleet telemetry yet."}
                    </Text>
                  ) : filteredItems.length === 0 ? (
                    <Text size="sm" color="secondary">
                      No matches for current filter.
                    </Text>
                  ) : (
                    filteredItems.map((entry) => {
                      const isSelected = col.selected.includes(entry);
                      return (
                        <SelectableTile
                          key={entry}
                          label={entry}
                          checked={isSelected}
                          icon={<HarnessIcon name={entry} size={15} />}
                          onChange={(checked) =>
                            col.apply(
                              checked
                                ? [...col.selected, entry]
                                : col.selected.filter((x) => x !== entry),
                            )
                          }
                        />
                      );
                    })
                  )}
                </div>
              );
            })}
          </div>

          <HStack justify="between" align="end" style={{ gap: 20, marginTop: 8, flexWrap: "wrap" }}>
            <div style={{ flex: 1, minWidth: 240 }}>
              <TextInput
                label="Type fleet-kill to confirm"
                placeholder="Enter confirmation phrase"
                value={confirmPhrase}
                onChange={(phrase) => {
                  if (flow.kind === "armedConfirming") {
                    onFlowChange({ ...flow, confirmPhrase: phrase });
                  }
                }}
                width="100%"
              />
            </div>
            <HStack gap={2}>
              <Button
                label="Cancel"
                onClick={() => onFlowChange({ kind: "closed", inlineArmed: false })}
              />
              <Button
                variant="destructive"
                icon={<GrdrIcon name="alert-octagon" size={14} />}
                label={`Activate kill switch (${totalSelected})`}
                isDisabled={
                  flow.kind !== "armedConfirming" ||
                  flow.confirmPhrase.trim().toLowerCase() !== "fleet-kill"
                }
                data-agent-confirm={
                  blastRadius.scope === "device"
                    ? "Confirm device kill switch"
                    : "Confirm fleet-wide kill switch"
                }
                onClick={async () => {
                  const ok = await onTrigger("kill", {
                    blockedAgents,
                    blockedModels,
                    blockedGateways,
                  });
                  if (ok) {
                    onFlowChange({ kind: "closed", inlineArmed: false });
                  }
                }}
              />
            </HStack>
          </HStack>
        </VStack>
      </Dialog>
    </>
  );
}
