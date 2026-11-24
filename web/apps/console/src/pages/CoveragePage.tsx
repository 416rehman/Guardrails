import type { Device } from "@grdr/api";
import { formatOsName, t } from "@grdr/i18n";
import { AssuranceBadge, EntityLink, type EntityTarget, Quoted, ViewStateFrame } from "@grdr/kit";
import { Badge, Card, GrdrIcon, Heading, HStack, OsIcon, Text, VStack } from "@grdr/ui";

const MATRIX_AGENTS = ["Claude Code", "Cursor", "Codex", "Gemini CLI"] as const;
const MATRIX_OS = ["macos", "linux", "windows"] as const;

export function CoveragePage({
  devices,
  onOpenEntity,
}: {
  devices: Device[];
  onOpenEntity?: (target: EntityTarget) => void;
}) {
  const allAgents = devices.flatMap((d) => d.agents.map((a) => ({ device: d, agent: a })));
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
            <HStack justify="between" align="center">
              <HStack gap={2} align="center">
                <GrdrIcon name="layers" size={16} color="var(--accent-primary)" />
                <Heading level={2}>Protection by agent & OS</Heading>
              </HStack>
              <Text size="sm" color="secondary">
                Enforcement strength observed per agent across operating systems
              </Text>
            </HStack>
            <div className="table-wrap">
              <table className="heatmap-grid">
                <thead>
                  <tr>
                    <th>Agent harness</th>
                    <th>
                      <HStack gap={1} align="center">
                        <OsIcon os="macos" size={13} />
                        <span>macOS</span>
                      </HStack>
                    </th>
                    <th>
                      <HStack gap={1} align="center">
                        <OsIcon os="linux" size={13} />
                        <span>Linux</span>
                      </HStack>
                    </th>
                    <th>
                      <HStack gap={1} align="center">
                        <OsIcon os="windows" size={13} />
                        <span>Windows</span>
                      </HStack>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {MATRIX_AGENTS.map((agentName) => (
                    <tr key={agentName}>
                      <td>
                        <EntityLink
                          kind="agent"
                          label={agentName}
                          compact
                          onSelect={onOpenEntity}
                        />
                      </td>
                      {MATRIX_OS.map((osKey) => {
                        const match = allAgents.find(
                          (item) =>
                            item.device.os.toLowerCase().includes(osKey) &&
                            item.agent.name.toLowerCase().includes(agentName.split(" ")[0].toLowerCase()),
                        );
                        return (
                          <td key={`${agentName}-${osKey}`} className={match ? undefined : "heatmap-cell-unobserved"}>
                            {match ? (
                              <AssuranceBadge
                                level={match.agent.assurance_level}
                                control={match.agent.assurance.control}
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
          </section>

          <Card padding={3}>
            <VStack gap={3}>
              <Heading level={2}>{`Assurance matrix by endpoint (${allAgents.length})`}</Heading>
              <div className="table-wrap">
                <table>
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
                        <td>
                          <EntityLink
                            kind="device"
                            id={device.id}
                            label={device.hostname}
                            os={device.os}
                            compact
                            onSelect={onOpenEntity}
                          />
                        </td>
                        <td>
                          <EntityLink
                            kind="agent"
                            id={agent.id}
                            label={agent.name}
                            compact
                            onSelect={onOpenEntity}
                          />
                        </td>
                        <td>
                          <AssuranceBadge
                            level={agent.assurance_level}
                            control={agent.assurance.control}
                          />
                        </td>
                        <td>
                          <Badge
                            variant={device.hook_effective && agent.hook_installed ? "success" : "warning"}
                            icon={<GrdrIcon name={device.hook_effective && agent.hook_installed ? "check-circle" : "alert-triangle"} size={12} />}
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
