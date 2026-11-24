import { useState } from "react";
import { Cpu, HardDrive, Plug, RefreshCw, ShieldCheck, X } from "lucide-react";
import { AssuranceBadge } from "../components/VerdictBadge";
import { Quoted } from "../components/Quoted";
import type { Device } from "../types";

interface InventoryPageProps {
  devices: Device[];
  searchQuery: string;
  onRefresh: () => void;
}

export function InventoryPage({ devices, searchQuery, onRefresh }: InventoryPageProps) {
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
                  <td>
                    <button
                      type="button"
                      className="btn"
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedDeviceId(device.id);
                      }}
                    >
                      <ShieldCheck size={13} />
                      <span>Inspect matrix</span>
                    </button>
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

      {selectedDevice && (
        <div
          className="drawer-backdrop"
          role="dialog"
          aria-modal="true"
          aria-label={`Device assurance matrix for ${selectedDevice.hostname}`}
          onClick={() => setSelectedDeviceId(null)}
        >
          <aside className="drawer-panel" onClick={(e) => e.stopPropagation()}>
            <div className="drawer-header">
              <div>
                <h2 className="section-title">Device assurance matrix</h2>
                <div style={{ marginTop: 4 }}>
                  <strong>{selectedDevice.hostname}</strong>{" "}
                  <span className="mono" style={{ color: "var(--ink-muted)" }}>
                    ({selectedDevice.id})
                  </span>
                </div>
                <div style={{ marginTop: 6, display: "flex", gap: 6, flexWrap: "wrap" }}>
                  <span className="badge info">{selectedDevice.install_profile}</span>
                  <span className={`badge ${selectedDevice.hook_effective ? "success" : "warning"}`}>
                    {selectedDevice.hook_effective ? "Hook active" : "Discovery only"}
                  </span>
                  <span className="badge neutral">
                    {selectedDevice.os} / {selectedDevice.arch}
                  </span>
                </div>
              </div>
              <button
                type="button"
                className="btn"
                aria-label="Close device matrix"
                onClick={() => setSelectedDeviceId(null)}
              >
                <X size={14} />
                <span>Close</span>
              </button>
            </div>

            <div>
              <h3 className="section-title" style={{ marginBottom: 8 }}>
                Harness assurance ({selectedDevice.agents.length})
              </h3>
              {selectedDevice.agents.length === 0 ? (
                <p style={{ margin: 0, color: "var(--ink-secondary)" }}>
                  No local agent harnesses reported for this device.
                </p>
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
                      {selectedDevice.agents.map((agent) => (
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
                          <td><Quoted text={agent.config_path} /></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            <div>
              <h3 className="section-title" style={{ marginBottom: 8 }}>
                MCP server inventory ({selectedDevice.mcp_servers.length})
              </h3>
              {selectedDevice.mcp_servers.length === 0 ? (
                <p style={{ margin: 0, color: "var(--ink-secondary)" }}>
                  No MCP servers bound to this endpoint.
                </p>
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
                      {selectedDevice.mcp_servers.map((mcp, idx) => (
                        <tr key={`${mcp.name}-${idx}`}>
                          <td>
                            <strong>{mcp.name}</strong>
                            <div><Quoted text={mcp.command} /></div>
                          </td>
                          <td><span className="mono">{mcp.transport}</span></td>
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
            </div>
          </aside>
        </div>
      )}
    </>
  );
}
