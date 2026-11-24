import type { Device } from "@grdr/api";
import { t } from "@grdr/i18n";
import { AssuranceBadge, ViewStateFrame } from "@grdr/kit";
import { Badge, Card, GrdrIcon, Heading, HStack, Text, VStack } from "@grdr/ui";

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
                        <td>{device.os}</td>
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
                    <div key={`blind-${device.id}-${agent.id}`} className="check-row todo">
                      <GrdrIcon name="shield-alert" size={16} color="var(--tone-ask)" />
                      <div>
                        <div style={{ fontWeight: 500 }}>
                          {`${agent.name} on ${device.hostname}`}
                        </div>
                        <Text type="supporting" color="secondary" size="sm">
                          {`Hook not proven effective (control=${agent.assurance.control}, install_profile=${device.install_profile}). Run grdr install-hook --apply.`}
                        </Text>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </VStack>
          </Card>
        </div>
      )}
    </VStack>
  );
}
