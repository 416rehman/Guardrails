import { Badge, GrdrIcon, Heading, HStack, Text, UiSdkDrawer, VStack } from "@grdr/ui";
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

          <div
            style={{
              padding: 12,
              borderRadius: 10,
              border: "1px solid var(--border-subtle)",
              background: "var(--bg-recessed)",
            }}
          >
            <HStack gap={1} align="center" style={{ marginBottom: 8 }}>
              <GrdrIcon name="route" size={14} color="var(--accent-primary)" />
              <Text size="sm" style={{ fontWeight: 600 }}>
                Endpoint asset topology graph
              </Text>
            </HStack>
            <svg
              width="100%"
              height={Math.max(120, Math.max(device.agents.length, device.mcp_servers.length) * 44 + 28)}
              viewBox={`0 0 560 ${Math.max(120, Math.max(device.agents.length, device.mcp_servers.length) * 44 + 28)}`}
              role="img"
              aria-label={`Asset graph for ${device.hostname}`}
            >
              <circle cx="52" cy="60" r="18" fill="var(--bg-canvas)" stroke="var(--accent-primary)" strokeWidth="2" />
              <text x="52" y="64" textAnchor="middle" fontSize="10" fontWeight="700" fill="var(--ink-primary)">
                HOST
              </text>
              <text x="52" y="92" textAnchor="middle" fontSize="11" fontWeight="600" fill="var(--ink-primary)">
                {device.hostname}
              </text>

              {device.agents.map((ag, idx) => {
                const y = 38 + idx * 46;
                const stroke = ag.assurance.control.includes("boundary")
                  ? "var(--tone-allow)"
                  : "var(--tone-ask)";
                return (
                  <g key={ag.id}>
                    <path
                      d={`M 70 60 C 120 60, 140 ${y}, 190 ${y}`}
                      fill="none"
                      stroke="var(--border-strong)"
                      strokeWidth="1.5"
                    />
                    <circle cx="206" cy={y} r="15" fill="var(--bg-canvas)" stroke={stroke} strokeWidth="2" />
                    <text x="206" y={y + 4} textAnchor="middle" fontSize="9.5" fontWeight="700" fill={stroke}>
                      {ag.assurance_level}
                    </text>
                    <text x="228" y={y + 4} fontSize="11.5" fontWeight="600" fill="var(--ink-primary)">
                      {ag.name}
                    </text>
                  </g>
                );
              })}

              {device.mcp_servers.map((mcp, idx) => {
                const y = 38 + idx * 46;
                const pinStroke = mcp.pinned ? "var(--tone-allow)" : "var(--tone-ask)";
                return (
                  <g key={`${mcp.name}-${idx}`}>
                    <path
                      d={`M 330 50 C 370 50, 380 ${y}, 418 ${y}`}
                      fill="none"
                      stroke="var(--border-strong)"
                      strokeWidth="1.5"
                      strokeDasharray={mcp.pinned ? undefined : "4 3"}
                    />
                    <rect
                      x="418"
                      y={y - 14}
                      width="132"
                      height="28"
                      rx="6"
                      fill="var(--bg-canvas)"
                      stroke={pinStroke}
                      strokeWidth="1.5"
                    />
                    <text x="484" y={y + 4} textAnchor="middle" fontSize="11" fontWeight="600" fill="var(--ink-primary)">
                      {mcp.name}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>

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
