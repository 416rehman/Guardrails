import type { Device } from "@grdr/api";
import { formatOsName, t } from "@grdr/i18n";
import { AssuranceBadge, Quoted, ViewStateFrame } from "@grdr/kit";
import { Badge, Card, GrdrIcon, HarnessIcon, Heading, HStack, Text, VStack } from "@grdr/ui";

const MATRIX_AGENTS = ["Claude Code", "Cursor", "Codex", "Gemini CLI"] as const;
const MATRIX_OS = ["macos", "linux", "windows"] as const;

export function CoveragePage({ devices }: { devices: Device[] }) {
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
                    <th>macOS</th>
                    <th>Linux</th>
                    <th>Windows</th>
                  </tr>
                </thead>
                <tbody>
                  {MATRIX_AGENTS.map((agentName) => (
                    <tr key={agentName}>
                      <td>
                        <HStack gap={2} align="center">
                          <HarnessIcon name={agentName} size={15} />
                          <strong>{agentName}</strong>
                        </HStack>
                      </td>
                      {MATRIX_OS.map((osKey) => {
                        const match = allAgents.find(
                          (item) =>
                            item.device.os.toLowerCase().includes(osKey) &&
                            item.agent.name.toLowerCase().includes(agentName.split(" ")[0].toLowerCase()),
                        );
                        return (
                          <td key={`${agentName}-${osKey}`}>
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

          <div className="grid-2">
          <Card padding={3}>
            <VStack gap={3}>
              <Heading level={2}>{`Assurance matrix by endpoint (${allAgents.length})`}</Heading>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Endpoint</th>
                      <th>OS</th>
                      <th>Agent</th>
                      <th>Assurance</th>
                      <th>Hook health</th>
                    </tr>
                  </thead>
                  <tbody>
                    {allAgents.map(({ device, agent }) => (
                      <tr key={`${device.id}-${agent.id}`}>
                        <td>
                          <strong>{device.hostname}</strong>
                        </td>
                        <td>{formatOsName(device.os)}</td>
                        <td>{agent.name}</td>
                        <td>
                          <AssuranceBadge
                            level={agent.assurance_level}
                            control={agent.assurance.control}
                          />
                        </td>
                        <td>
                          <Badge
                            variant={device.hook_effective && agent.hook_installed ? "success" : "warning"}
                            label={
                              device.hook_effective && agent.hook_installed
                                ? "Proven active"
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
                    <div key={`blind-${device.id}-${agent.id}`} className="check-row todo" style={{ alignItems: "flex-start" }}>
                      <HStack gap={2} align="start">
                        <GrdrIcon name="shield-alert" size={16} color="var(--tone-ask)" />
                        <VStack gap={1}>
                          <div style={{ fontWeight: 500 }}>
                            {`${agent.name} on ${device.hostname}`}
                          </div>
                          <Text type="supporting" color="secondary" size="sm">
                            {`${agent.name} hooks are not active yet on this ${formatOsName(device.os)} endpoint. Install the hook with:`}
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
          </div>
        </VStack>
      )}
    </VStack>
  );
}
