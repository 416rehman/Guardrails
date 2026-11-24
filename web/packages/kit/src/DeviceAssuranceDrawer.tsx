import { Badge, Heading, HStack, Text, UiSdkDrawer, VStack } from "@grdr/ui";
import { AssuranceBadge } from "./VerdictBadge";
import { Quoted } from "./Quoted";

export interface MatrixDevice {
  id: string;
  hostname: string;
  os: string;
  arch: string;
  install_profile: string;
  hook_effective: boolean;
  agents: ReadonlyArray<{
    id: string;
    name: string;
    kind: string;
    config_path: string;
    hook_installed: boolean;
    assurance_level: "AL0" | "AL1" | "AL2" | "AL3" | "AL4";
    assurance: { visibility: string; control: string; on_failure: string; tamper: string };
  }>;
  mcp_servers: ReadonlyArray<{
    name: string;
    transport: string;
    command: string;
    pinned: boolean;
  }>;
}

export function DeviceAssuranceDrawer({
  device,
  onClose,
}: {
  device: MatrixDevice | null;
  onClose: () => void;
}) {
  return (
    <UiSdkDrawer
      open={device !== null}
      onClose={onClose}
      title="Device assurance matrix"
      description={device ? `${device.hostname} (${device.id})` : undefined}
    >
      {device && (
        <VStack gap={3}>
          <HStack gap={2}>
            <Badge variant="info" label={device.install_profile} />
            <Badge
              variant={device.hook_effective ? "success" : "warning"}
              label={device.hook_effective ? "Hook active" : "Discovery only"}
            />
            <Badge variant="neutral" label={`${device.os} / ${device.arch}`} />
          </HStack>

          <VStack gap={2}>
            <Heading level={3}>Harness assurance ({device.agents.length})</Heading>
            {device.agents.length === 0 ? (
              <Text color="secondary">No local agent harnesses reported for this device.</Text>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Agent</th>
                      <th>Assurance</th>
                      <th>Visibility / Failure</th>
                      <th>Config</th>
                    </tr>
                  </thead>
                  <tbody>
                    {device.agents.map((agent) => (
                      <tr key={agent.id}>
                        <td>
                          <strong>{agent.name}</strong>
                          <div style={{ fontSize: 12, color: "var(--ink-muted)" }}>
                            {agent.kind} · tamper: {agent.assurance.tamper}
                          </div>
                        </td>
                        <td>
                          <AssuranceBadge
                            level={agent.assurance_level}
                            control={agent.assurance.control}
                          />
                        </td>
                        <td>
                          <div>
                            {agent.assurance.visibility} · fail-{agent.assurance.on_failure}
                          </div>
                          <div style={{ fontSize: 12, color: "var(--ink-muted)" }}>
                            Hook {agent.hook_installed ? "configured" : "absent"}
                          </div>
                        </td>
                        <td>
                          <Quoted text={agent.config_path} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </VStack>

          <VStack gap={2}>
            <Heading level={3}>MCP server inventory ({device.mcp_servers.length})</Heading>
            {device.mcp_servers.length === 0 ? (
              <Text color="secondary">No MCP servers bound to this endpoint.</Text>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Server</th>
                      <th>Transport</th>
                      <th>Digest pin</th>
                    </tr>
                  </thead>
                  <tbody>
                    {device.mcp_servers.map((mcp, idx) => (
                      <tr key={`${mcp.name}-${idx}`}>
                        <td>
                          <strong>{mcp.name}</strong>
                          <div>
                            <Quoted text={mcp.command} />
                          </div>
                        </td>
                        <td>
                          <span className="mono">{mcp.transport}</span>
                        </td>
                        <td>
                          <Badge
                            variant={mcp.pinned ? "success" : "warning"}
                            label={mcp.pinned ? "Pinned" : "Unpinned"}
                          />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </VStack>
        </VStack>
      )}
    </UiSdkDrawer>
  );
}
