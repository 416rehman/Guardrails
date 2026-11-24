import { formatOsName, presentAssurance } from "@grdr/i18n";
import {
  Badge,
  type GrdrFlowEdge,
  type GrdrFlowNode,
  GrdrFlowGraph,
  GrdrIcon,
  Heading,
  HStack,
  Text,
  UiSdkDrawer,
  VStack,
} from "@grdr/ui";
import { AssuranceBadge } from "./VerdictBadge";
import { Quoted } from "./Quoted";

function friendlyControl(control: string): string {
  if (control.includes("boundary")) return "OS boundary";
  if (control === "request") return "Hook request";
  return "Observation only";
}

function friendlyVisibility(visibility: string, failMode: string): string {
  const vis = visibility === "observed" ? "Verified" : "Unverified";
  const fail = failMode.includes("closed") ? "blocks on bypass" : "allows on bypass";
  return `${vis} · ${fail}`;
}

function friendlyTamper(tamper: string): string {
  return tamper === "admin" ? "Admin locked" : "User editable";
}

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
  const assetNodes: GrdrFlowNode[] = [];
  const assetEdges: GrdrFlowEdge[] = [];
  if (device) {
    assetNodes.push({
      id: "device-host",
      label: device.hostname,
      subtitle: `${formatOsName(device.os)} / ${device.arch}`,
      badge: "Host",
      tone: "accent",
      icon: "cpu",
    });
    for (const ag of device.agents) {
      const boundary = ag.assurance.control.includes("boundary");
      const assuranceText = presentAssurance(ag.assurance_level, ag.assurance.control).label;
      assetNodes.push({
        id: `ag-${ag.id}`,
        label: ag.name,
        subtitle: friendlyControl(ag.assurance.control),
        badge: assuranceText,
        tone: boundary ? "allow" : "ask",
        harnessName: ag.name,
      });
      assetEdges.push({
        id: `edge-host-${ag.id}`,
        source: "device-host",
        target: `ag-${ag.id}`,
        tone: boundary ? "allow" : "neutral",
      });
    }
    const primaryAgentId = device.agents[0] ? `ag-${device.agents[0].id}` : "device-host";
    device.mcp_servers.forEach((mcp, idx) => {
      const mcpId = `mcp-${idx}-${mcp.name}`;
      assetNodes.push({
        id: mcpId,
        label: mcp.name,
        subtitle: mcp.transport,
        badge: mcp.pinned ? "Pinned" : "Unpinned",
        tone: mcp.pinned ? "allow" : "ask",
        icon: "plug",
      });
      assetEdges.push({
        id: `edge-${primaryAgentId}-${mcpId}`,
        source: primaryAgentId,
        target: mcpId,
        dashed: !mcp.pinned,
        tone: mcp.pinned ? "allow" : "neutral",
      });
    });
  }

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
            <Badge
              variant="info"
              label={device.install_profile === "protected" ? "Protected" : "User mode"}
            />
            <Badge
              variant={device.hook_effective ? "success" : "warning"}
              label={device.hook_effective ? "Hook active" : "Discovery only"}
            />
            <Badge variant="neutral" label={`${formatOsName(device.os)} / ${device.arch}`} />
          </HStack>

          <VStack gap={1}>
            <HStack gap={1} align="center">
              <GrdrIcon name="route" size={14} color="var(--accent-primary)" />
              <Text size="sm" style={{ fontWeight: 600 }}>
                Endpoint asset topology
              </Text>
            </HStack>
            <GrdrFlowGraph
              nodes={assetNodes}
              edges={assetEdges}
              direction="LR"
              height={236}
              ariaLabel={`Asset graph for ${device.hostname}`}
            />
          </VStack>

          <VStack gap={2}>
            <Heading level={3}>Agent protection ({device.agents.length})</Heading>
            {device.agents.length === 0 ? (
              <Text color="secondary">No local agents reported for this device.</Text>
            ) : (
              <div className="table-wrap">
                <table style={{ tableLayout: "fixed", width: "100%" }}>
                  <colgroup>
                    <col style={{ width: "19%" }} />
                    <col style={{ width: "21%" }} />
                    <col style={{ width: "26%" }} />
                    <col style={{ width: "34%" }} />
                  </colgroup>
                  <thead>
                    <tr>
                      <th>Agent</th>
                      <th>Protection</th>
                      <th>Verification</th>
                      <th>Config</th>
                    </tr>
                  </thead>
                  <tbody>
                    {device.agents.map((agent) => (
                      <tr key={agent.id}>
                        <td>
                          <strong>{agent.name}</strong>
                          <div style={{ fontSize: 12, color: "var(--ink-muted)" }}>
                            {friendlyTamper(agent.assurance.tamper)}
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
                            {friendlyVisibility(agent.assurance.visibility, agent.assurance.on_failure)}
                          </div>
                          <div style={{ fontSize: 12, color: "var(--ink-muted)" }}>
                            {agent.hook_installed ? "Hook configured" : "Hook absent"}
                          </div>
                        </td>
                        <td title={agent.config_path}>
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
