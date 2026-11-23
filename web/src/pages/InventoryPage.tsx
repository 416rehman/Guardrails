import { Cpu, HardDrive, Plug, RefreshCw } from "lucide-react";
import { AssuranceBadge } from "../components/VerdictBadge";
import { Quoted } from "../components/Quoted";
import type { Device } from "../types";

interface InventoryPageProps {
  devices: Device[];
  searchQuery: string;
  onRefresh: () => void;
}

export function InventoryPage({ devices, searchQuery, onRefresh }: InventoryPageProps) {
  const query = searchQuery.trim().toLowerCase();
  const filteredDevices = devices.filter(
    (d) =>
      !query ||
      d.hostname.toLowerCase().includes(query) ||
      d.os.toLowerCase().includes(query) ||
      d.agents.some((a) => a.name.toLowerCase().includes(query)),
  );

  const agents = filteredDevices.flatMap((device) =>
    device.agents.map((agent) => ({ deviceHostname: device.hostname, profile: device.install_profile, agent })),
  );

  const mcps = filteredDevices.flatMap((device) =>
    device.mcp_servers.map((mcp) => ({ deviceHostname: device.hostname, mcp })),
  );

  return (
    <>
      <div className="page-header">
        <div>
          <h1>Inventory</h1>
          <p>
            AI coding agents, MCP tool servers, and honest enforcement capability reported per endpoint.
          </p>
        </div>
        <button type="button" className="btn" onClick={onRefresh}>
          <RefreshCw size={14} />
          <span>Refresh inventory</span>
        </button>
      </div>

      <section className="surface">
        <div className="page-header">
          <h2 className="section-title" style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <HardDrive size={16} />
            <span>Enrolled devices ({filteredDevices.length})</span>
          </h2>
        </div>
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
              </tr>
            </thead>
            <tbody>
              {filteredDevices.map((device) => (
                <tr key={device.id}>
                  <td>
                    <strong>{device.hostname}</strong>
                    <div className="mono" style={{ color: "var(--ink-muted)" }}>{device.id}</div>
                  </td>
                  <td>{device.os} / {device.arch}</td>
                  <td>
                    <span className="badge info">{device.install_profile}</span>
                  </td>
                  <td>
                    <span className={`badge ${device.hook_effective ? "success" : "warning"}`}>
                      {device.hook_effective ? "Hook configured" : "Discovery only"}
                    </span>
                  </td>
                  <td className="tabular">{device.agents.length} / {device.mcp_servers.length}</td>
                  <td>
                    <span className={`badge ${device.online ? "success" : "neutral"}`}>
                      {device.online ? "Online" : "Offline"}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="surface">
        <div className="page-header">
          <h2 className="section-title" style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <Cpu size={16} />
            <span>Discovered AI agents ({agents.length})</span>
          </h2>
        </div>
        {agents.length === 0 ? (
          <p style={{ margin: 0, color: "var(--ink-secondary)" }}>
            No agents discovered yet. Start grdr-daemon on an endpoint to scan local harnesses.
          </p>
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
                    <td><strong>{agent.name}</strong></td>
                    <td>{deviceHostname}</td>
                    <td>
                      <AssuranceBadge level={agent.assurance_level} control={agent.assurance.control} />
                    </td>
                    <td>
                      <span className={`badge ${agent.hook_installed ? "success" : "warning"}`}>
                        {agent.hook_installed ? "Installed" : "Not configured"}
                      </span>
                    </td>
                    <td className="tabular">{agent.mcp_count}</td>
                    <td><Quoted text={agent.config_path} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="surface">
        <div className="page-header">
          <h2 className="section-title" style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <Plug size={16} />
            <span>MCP servers ({mcps.length})</span>
          </h2>
        </div>
        {mcps.length === 0 ? (
          <p style={{ margin: 0, color: "var(--ink-secondary)" }}>No MCP server definitions discovered.</p>
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
                    <td><strong>{mcp.name}</strong></td>
                    <td>{mcp.source_agent}</td>
                    <td>{deviceHostname}</td>
                    <td><span className="mono">{mcp.transport}</span></td>
                    <td><Quoted text={mcp.command} /></td>
                    <td>
                      <span className={`badge ${mcp.pinned ? "success" : "warning"}`}>
                        {mcp.pinned ? "Pinned" : "Unpinned"}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}
