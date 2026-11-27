// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
import { useContext, useMemo } from "react";
import type { AssuranceLevel, Device } from "@grdr/api";
import { formatOsName, presentAgentName, t } from "@grdr/i18n";
import { AssuranceBadge, EntityLink, type EntityTarget, Quoted, ViewStateFrame } from "@grdr/kit";
import { Badge, Card, GrdrIcon, Heading, HStack, OsIcon, StatusInline, Text, VStack } from "@grdr/ui";
import { ConsoleWorkspaceContext } from "../ConsoleContext";
import { canonicalAgentSlugKey } from "../consoleState";

const ASSURANCE_RANK: Record<AssuranceLevel, number> = {
  AL0: 0,
  AL1: 1,
  AL2: 2,
  AL3: 3,
  AL4: 4,
};

function normalizeOsKey(os: string): string {
  const cleaned = os.trim().toLowerCase();
  if (cleaned === "darwin" || cleaned === "mac os" || cleaned === "mac") return "macos";
  if (cleaned === "win32" || cleaned === "win64") return "windows";
  return cleaned || "unknown";
}

function orderOsColumns(osKeys: string[]): string[] {
  const knownRank = (os: string): number => {
    if (os === "macos") return 0;
    if (os === "linux") return 1;
    if (os === "windows") return 2;
    return 3;
  };
  return [...osKeys].sort((a, b) => {
    const rankDiff = knownRank(a) - knownRank(b);
    return rankDiff !== 0 ? rankDiff : a.localeCompare(b);
  });
}

export function CoveragePage({
  devices,
  onOpenEntity,
}: {
  devices: Device[];
  onOpenEntity?: (target: EntityTarget) => void;
}) {
  const workspace = useContext(ConsoleWorkspaceContext);
  const allAgents = useMemo(
    () => devices.flatMap((d) => d.agents.map((a) => ({ device: d, agent: a }))),
    [devices],
  );
  const matrixOses = useMemo(
    () => orderOsColumns(Array.from(new Set(devices.map((d) => normalizeOsKey(d.os))))),
    [devices],
  );
  const matrixAgents = useMemo(() => {
    const seen = new Map<string, string>();
    for (const item of allAgents) {
      const display = presentAgentName(item.agent.name);
      const key = canonicalAgentSlugKey(display);
      if (key && !seen.has(key)) {
        seen.set(key, display);
      }
    }
    for (const session of workspace?.snapshot.sessions ?? []) {
      const display = presentAgentName(session.agent_name);
      const key = canonicalAgentSlugKey(display);
      if (key && !seen.has(key)) {
        seen.set(key, display);
      }
    }
    return Array.from(seen.values()).sort((a, b) => a.localeCompare(b));
  }, [allAgents, workspace?.snapshot.sessions]);
  const protectedCount = allAgents.filter((x) =>
    x.agent.assurance.control.includes("boundary"),
  ).length;
  const blindSpots = allAgents.filter(
    (x) => !x.agent.hook_installed || !x.device.hook_effective,
  );
  const coveragePct =
    allAgents.length === 0 ? 0 : Math.round((protectedCount / allAgents.length) * 100);

  return (
    <VStack gap={4}>
      <div className="page-header">
        <div>
          <Heading level={1}>{t("console.coverage.title")}</Heading>
          <Text color="secondary">{t("console.coverage.subtitle")}</Text>
        </div>
        <Badge
          variant={coveragePct >= 80 ? "success" : "warning"}
          icon={<GrdrIcon name="shield-check" size={13} />}
          label={`${coveragePct}% boundary enforced (${protectedCount} of ${allAgents.length})`}
        />
      </div>

      {devices.length === 0 ? (
        <ViewStateFrame
          state="empty"
          title="Coverage is computed after the first enrolled device reports"
          description="Install or start grdr-daemon on an endpoint to measure hook canary health and assurance levels."
        />
      ) : (
        <VStack gap={4}>
          <section className="visual-panel" aria-label="Agent by OS assurance matrix">
            <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
              <HStack gap={2} align="center">
                <GrdrIcon name="layers" size={16} color="var(--accent-primary)" />
                <Heading level={2}>Protection by agent & OS</Heading>
              </HStack>
              <Text size="sm" color="secondary">
                Enforcement strength observed per agent across operating systems
              </Text>
            </HStack>
            {matrixAgents.length === 0 || matrixOses.length === 0 ? (
              <Text size="sm" color="secondary">
                No agent harnesses discovered on enrolled devices yet.
              </Text>
            ) : (
              <div className="table-wrap">
                <table className="heatmap-grid responsive-table">
                  <thead>
                    <tr>
                      <th>Agent harness</th>
                      {matrixOses.map((osKey) => (
                        <th key={osKey}>
                          <HStack gap={1} align="center">
                            <OsIcon os={osKey} size={13} />
                            <span>{formatOsName(osKey)}</span>
                          </HStack>
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {matrixAgents.map((agentName) => (
                      <tr key={agentName}>
                        <td data-label="Agent harness">
                          <EntityLink
                            kind="agent"
                            label={agentName}
                            compact
                            onSelect={onOpenEntity}
                          />
                        </td>
                        {matrixOses.map((osKey) => {
                          const matches = allAgents.filter(
                            (item) =>
                              normalizeOsKey(item.device.os) === osKey &&
                              canonicalAgentSlugKey(presentAgentName(item.agent.name)) ===
                                canonicalAgentSlugKey(presentAgentName(agentName)),
                          );
                          const conservativeMatch =
                            matches.length === 0
                              ? undefined
                              : matches.reduce((weakest, candidate) =>
                                  ASSURANCE_RANK[candidate.agent.assurance_level] <
                                  ASSURANCE_RANK[weakest.agent.assurance_level]
                                    ? candidate
                                    : weakest,
                                );
                          return (
                            <td
                              key={`${agentName}-${osKey}`}
                              data-label={formatOsName(osKey)}
                              className={conservativeMatch ? undefined : "heatmap-cell-unobserved"}
                            >
                              {conservativeMatch ? (
                                <AssuranceBadge
                                  level={conservativeMatch.agent.assurance_level}
                                  control={conservativeMatch.agent.assurance.control}
                                />
                              ) : (
                                <span className="heatmap-cell-empty">Not observed</span>
                              )}
                            </td>
                          );
                        })}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          <Card padding={3}>
            <VStack gap={3}>
              <Heading level={2}>{`Assurance matrix by endpoint (${allAgents.length})`}</Heading>
              <div className="table-wrap">
                <table className="responsive-table">
                  <thead>
                    <tr>
                      <th>Endpoint</th>
                      <th>Agent</th>
                      <th>Assurance</th>
                      <th>Hook health</th>
                    </tr>
                  </thead>
                  <tbody>
                    {allAgents.map(({ device, agent }) => (
                      <tr key={`${device.id}-${agent.id}`}>
                        <td data-label="Endpoint">
                          <EntityLink
                            kind="device"
                            id={device.id}
                            label={device.hostname}
                            os={device.os}
                            compact
                            onSelect={onOpenEntity}
                          />
                        </td>
                        <td data-label="Agent">
                          <EntityLink
                            kind="agent"
                            id={agent.id}
                            label={agent.name}
                            compact
                            onSelect={onOpenEntity}
                          />
                        </td>
                        <td data-label="Assurance">
                          <AssuranceBadge
                            level={agent.assurance_level}
                            control={agent.assurance.control}
                          />
                        </td>
                        <td data-label="Hook health">
                          <StatusInline
                            tone={device.hook_effective && agent.hook_installed ? "allow" : "ask"}
                            icon={<GrdrIcon name={device.hook_effective && agent.hook_installed ? "check-circle" : "alert-triangle"} size={13} />}
                            label={
                              device.hook_effective && agent.hook_installed
                                ? "Hook active"
                                : "Could not prove hook"
                            }
                          />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </VStack>
          </Card>

          <Card padding={3}>
            <VStack gap={3}>
              <Heading level={2}>{`Blind spots (${blindSpots.length})`}</Heading>
              {blindSpots.length === 0 ? (
                <Text color="secondary">
                  Zero blind spots: every discovered agent harness reports active hook coverage.
                </Text>
              ) : (
                <div className="checklist">
                  {blindSpots.map(({ device, agent }) => (
                    <div key={`blind-${device.id}-${agent.id}`} className="check-row todo blind-spot-row" style={{ alignItems: "flex-start" }}>
                      <HStack gap={2} align="start">
                        <GrdrIcon name="shield-alert" size={16} color="var(--tone-ask)" />
                        <VStack gap={1}>
                          <HStack gap={1} align="center" style={{ flexWrap: "wrap", columnGap: 6, rowGap: 2 }}>
                            <EntityLink
                              kind="agent"
                              id={agent.id}
                              label={agent.name}
                              compact
                              onSelect={onOpenEntity}
                            />
                            <Text size="sm" color="secondary">
                              on
                            </Text>
                            <EntityLink
                              kind="device"
                              id={device.id}
                              label={device.hostname}
                              os={device.os}
                              compact
                              onSelect={onOpenEntity}
                            />
                          </HStack>
                          <Text type="supporting" color="secondary" size="sm">
                            {`Hook coverage is not active yet on this ${formatOsName(device.os)} endpoint. Install the hook with:`}
                          </Text>
                          <Quoted text="grdr install-hook --apply" />
                        </VStack>
                      </HStack>
                    </div>
                  ))}
                </div>
              )}
            </VStack>
          </Card>
        </VStack>
      )}
    </VStack>
  );
}
