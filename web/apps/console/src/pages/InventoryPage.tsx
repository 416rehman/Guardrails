import { useState } from "react";
import type { Device } from "@grdr/api";
import { AssuranceBadge, DeviceAssuranceDrawer, Quoted } from "@grdr/kit";
import { Badge, Button, Card, GrdrIcon, Heading, HStack, Text, VStack } from "@grdr/ui";

export function InventoryPage({
  devices,
  searchQuery,
  onRefresh,
}: {
  devices: Device[];
  searchQuery: string;
  onRefresh: () => void;
}) {
  const [selectedDeviceId, setSelectedDeviceId] = useState<string | null>(null);
  const query = searchQuery.trim().toLowerCase();
  const filteredDevices = devices.filter(
    (d) =>
      !query ||
      d.hostname.toLowerCase().includes(query) ||
      d.os.toLowerCase().includes(query) ||
      d.agents.some((a) => a.name.toLowerCase().includes(query)),
  );
  const selectedDevice = devices.find((d) => d.id === selectedDeviceId) ?? null;

  const agents = filteredDevices.flatMap((device) =>
    device.agents.map((agent) => ({
      deviceHostname: device.hostname,
      agent,
    })),
  );

  const mcps = filteredDevices.flatMap((device) =>
    device.mcp_servers.map((mcp) => ({ deviceHostname: device.hostname, mcp })),
  );

  return (
    <VStack gap={4}>
      <div className="page-header">
        <div>
          <Heading level={1}>Inventory</Heading>
          <Text color="secondary">
            AI coding agents, MCP tool servers, and honest enforcement capability reported per endpoint.
          </Text>
        </div>
        <Button
          label="Refresh inventory"
          icon={<GrdrIcon name="refresh" size={14} />}
          onClick={onRefresh}
        />
      </div>

      <Card padding={3}>
        <VStack gap={3}>
          <HStack gap={2} align="center">
            <GrdrIcon name="hard-drive" size={16} />
            <Heading level={2}>{`Enrolled devices (${filteredDevices.length})`}</Heading>
          </HStack>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Hostname</th>
                  <th>Platform</th>
                  <th>Profile</th>
                  <th>Hook status</th>
                  <th>Agents / MCPs</th>
                  <th>Status</th>
                  <th>Assurance matrix</th>
                </tr>
              </thead>
              <tbody>
                {filteredDevices.map((device) => (
                  <tr
                    key={device.id}
                    className={`selectable ${selectedDevice?.id === device.id ? "selected" : ""}`}
                    onClick={() => setSelectedDeviceId(device.id)}
                  >
                    <td>
                      <strong>{device.hostname}</strong>
                      <div className="mono" style={{ color: "var(--ink-muted)" }}>
                        {device.id}
                      </div>
                    </td>
                    <td>
                      {device.os} / {device.arch}
                    </td>
                    <td>
                      <Badge variant="info" label={device.install_profile} />
                    </td>
                    <td>
                      <Badge
                        variant={device.hook_effective ? "success" : "warning"}
                        label={device.hook_effective ? "Hook configured" : "Discovery only"}
                      />
                    </td>
                    <td className="tabular">
                      {device.agents.length} / {device.mcp_servers.length}
                    </td>
                    <td>
                      <Badge
                        variant={device.online ? "success" : "neutral"}
                        label={device.online ? "Online" : "Offline"}
                      />
                    </td>
                    <td>
                      <Button
                        size="sm"
                        label="Inspect matrix"
                        icon={<GrdrIcon name="shield-check" size={13} />}
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedDeviceId(device.id);
                        }}
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
          <HStack gap={2} align="center">
            <GrdrIcon name="cpu" size={16} />
            <Heading level={2}>{`Discovered AI agents (${agents.length})`}</Heading>
          </HStack>
          {agents.length === 0 ? (
            <Text color="secondary">
              No agents discovered yet. Start grdr-daemon on an endpoint to scan local harnesses.
            </Text>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Agent</th>
                    <th>Endpoint</th>
                    <th>Assurance level</th>
                    <th>Hook shim</th>
                    <th>MCPs</th>
                    <th>Config path</th>
                  </tr>
                </thead>
                <tbody>
                  {agents.map(({ deviceHostname, agent }) => (
                    <tr key={`${deviceHostname}-${agent.id}`}>
                      <td>
                        <strong>{agent.name}</strong>
                      </td>
                      <td>{deviceHostname}</td>
                      <td>
                        <AssuranceBadge
                          level={agent.assurance_level}
                          control={agent.assurance.control}
                        />
                      </td>
                      <td>
                        <Badge
                          variant={agent.hook_installed ? "success" : "warning"}
                          label={agent.hook_installed ? "Installed" : "Not configured"}
                        />
                      </td>
                      <td className="tabular">{agent.mcp_count}</td>
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
      </Card>

      <Card padding={3}>
        <VStack gap={3}>
          <HStack gap={2} align="center">
            <GrdrIcon name="plug" size={16} />
            <Heading level={2}>{`MCP servers (${mcps.length})`}</Heading>
          </HStack>
          {mcps.length === 0 ? (
            <Text color="secondary">No MCP server definitions discovered.</Text>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Source agent</th>
                    <th>Endpoint</th>
                    <th>Transport</th>
                    <th>Command / endpoint</th>
                    <th>Digest pin</th>
                  </tr>
                </thead>
                <tbody>
                  {mcps.map(({ deviceHostname, mcp }, idx) => (
                    <tr key={`${deviceHostname}-${mcp.name}-${idx}`}>
                      <td>
                        <strong>{mcp.name}</strong>
                      </td>
                      <td>{mcp.source_agent}</td>
                      <td>{deviceHostname}</td>
                      <td>
                        <span className="mono">{mcp.transport}</span>
                      </td>
                      <td>
                        <Quoted text={mcp.command} />
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
      </Card>

      <DeviceAssuranceDrawer
        device={selectedDevice}
        onClose={() => setSelectedDeviceId(null)}
      />
    </VStack>
  );
}
