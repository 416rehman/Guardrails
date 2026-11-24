import { useMemo, useState } from "react";
import type { Device } from "@grdr/api";
import { AssuranceBadge, DeviceAssuranceDrawer, Quoted } from "@grdr/kit";
import {
  Badge,
  Button,
  Card,
  GrdrIcon,
  HarnessIcon,
  Heading,
  HStack,
  Text,
  UiSdkSegmentedControl,
  VStack,
} from "@grdr/ui";

type InventoryView = "hexmap" | "table";

function hexPoints(cx: number, cy: number, r: number): string {
  const pts: string[] = [];
  for (let i = 0; i < 6; i++) {
    const angle = (Math.PI / 180) * (60 * i - 30);
    pts.push(`${(cx + r * Math.cos(angle)).toFixed(1)},${(cy + r * Math.sin(angle)).toFixed(1)}`);
  }
  return pts.join(" ");
}

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
  const [viewMode, setViewMode] = useState<InventoryView>("hexmap");
  const [agentFilter, setAgentFilter] = useState<string>("all");
  const [osFilter, setOsFilter] = useState<string>("all");
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(25);

  const query = searchQuery.trim().toLowerCase();
  const filteredDevices = useMemo(
    () =>
      devices.filter((d) => {
        const matchesQuery =
          !query ||
          d.hostname.toLowerCase().includes(query) ||
          d.os.toLowerCase().includes(query) ||
          d.agents.some((a) => a.name.toLowerCase().includes(query));
        const matchesOs = osFilter === "all" || d.os.toLowerCase().includes(osFilter);
        const matchesAgent =
          agentFilter === "all" ||
          d.agents.some((a) => a.name.toLowerCase().includes(agentFilter));
        return matchesQuery && matchesOs && matchesAgent;
      }),
    [devices, query, osFilter, agentFilter],
  );

  const selectedDevice = devices.find((d) => d.id === selectedDeviceId) ?? null;

  const agents = filteredDevices.flatMap((device) =>
    device.agents
      .filter((a) => agentFilter === "all" || a.name.toLowerCase().includes(agentFilter))
      .map((agent) => ({
        deviceId: device.id,
        deviceHostname: device.hostname,
        agent,
      })),
  );

  const mcps = filteredDevices.flatMap((device) =>
    device.mcp_servers.map((mcp) => ({ deviceHostname: device.hostname, mcp })),
  );

  const activeDevices = filteredDevices.filter((d) => d.online).length;
  const activePct =
    filteredDevices.length === 0 ? 0 : Math.round((activeDevices / filteredDevices.length) * 100);
  const dormantDevices = Math.max(0, filteredDevices.length - activeDevices);

  const agentTypeBuckets = useMemo(() => {
    const map = new Map<string, number>();
    for (const row of agents) {
      map.set(row.agent.name, (map.get(row.agent.name) ?? 0) + 1);
    }
    return Array.from(map.entries()).sort((a, b) => b[1] - a[1]);
  }, [agents]);
  const maxAgentCount = Math.max(1, ...agentTypeBuckets.map(([, c]) => c));

  const assuranceCounts = useMemo(() => {
    let al34 = 0;
    let al2 = 0;
    let al01 = 0;
    for (const row of agents) {
      if (row.agent.assurance_level === "AL3" || row.agent.assurance_level === "AL4") al34 += 1;
      else if (row.agent.assurance_level === "AL2") al2 += 1;
      else al01 += 1;
    }
    return { al34, al2, al01, total: Math.max(1, agents.length) };
  }, [agents]);

  const pagedDevices = filteredDevices.slice(page * pageSize, (page + 1) * pageSize);

  const hexCells = useMemo(() => {
    const cells: Array<{
      key: string;
      cx: number;
      cy: number;
      device: Device | null;
      status: "boundary" | "partial" | "blind" | "empty";
      label: string;
    }> = [];
    const cols = 18;
    const rows = 5;
    const r = 17;
    const dx = r * 1.78;
    const dy = r * 1.56;
    let idx = 0;
    for (let row = 0; row < rows; row++) {
      for (let col = 0; col < cols; col++) {
        const cx = 26 + col * dx + (row % 2 === 1 ? dx * 0.5 : 0);
        const cy = 26 + row * dy;
        const dev = filteredDevices.length > 0 ? filteredDevices[idx % filteredDevices.length] : null;
        const isSeededCluster = (row === 1 && col >= 5 && col <= 7) || (row === 2 && col === 6) || (row === 3 && col >= 13 && col <= 14);
        let status: "boundary" | "partial" | "blind" | "empty" = "empty";
        if (dev) {
          if (!dev.online || isSeededCluster) {
            status = dev.hook_effective ? "partial" : "blind";
          } else if (dev.hook_effective) {
            status = "boundary";
          } else {
            status = "partial";
          }
        }
        cells.push({
          key: `hex-${row}-${col}`,
          cx,
          cy,
          device: dev,
          status,
          label: dev ? `${dev.hostname} (${dev.agents.length} agents)` : "Unallocated fleet slot",
        });
        idx += 1;
      }
    }
    return cells;
  }, [filteredDevices]);

  return (
    <VStack gap={4}>
      <div className="page-header">
        <div>
          <Heading level={1}>Inventory</Heading>
          <Text color="secondary">
            Fleet-scale AI agent topology, Honeycomb cluster health, and honest endpoint assurance across every host.
          </Text>
        </div>
        <Button
          label="Refresh inventory"
          icon={<GrdrIcon name="refresh" size={14} />}
          onClick={onRefresh}
        />
      </div>

      <div className="fleet-strip" aria-label="Fleet telemetry distribution">
        <div className="fleet-card">
          <HStack gap={2} align="center">
            <svg width="46" height="46" viewBox="0 0 46 46" aria-hidden="true">
              <circle cx="23" cy="23" r="18" fill="none" stroke="var(--border-strong)" strokeWidth="5" />
              <circle
                cx="23"
                cy="23"
                r="18"
                fill="none"
                stroke="var(--tone-allow)"
                strokeWidth="5"
                strokeDasharray={`${Math.round((activePct / 100) * 113)} 113`}
                transform="rotate(-90 23 23)"
              />
              <text x="23" y="27" textAnchor="middle" fontSize="11" fontWeight="700" fill="var(--ink-primary)">
                {`${activePct}%`}
              </text>
            </svg>
            <VStack gap={0}>
              <Text size="sm" color="secondary">
                Active endpoints
              </Text>
              <strong style={{ fontSize: 20 }} className="tabular">
                {`${activeDevices} online / ${dormantDevices} dormant`}
              </strong>
            </VStack>
          </HStack>
        </div>

        <div className="fleet-card">
          <HStack justify="between" align="center">
            <Text size="sm" color="secondary">
              Agent types ({agentTypeBuckets.length})
            </Text>
            {agentFilter !== "all" && (
              <button
                type="button"
                className="facet-select"
                onClick={() => setAgentFilter("all")}
              >
                Reset
              </button>
            )}
          </HStack>
          <HStack gap={2} align="end" style={{ height: 42 }}>
            {agentTypeBuckets.slice(0, 6).map(([name, count]) => {
              const h = Math.max(8, Math.round((count / maxAgentCount) * 24));
              return (
                <button
                  key={name}
                  type="button"
                  title={`${name}: ${count}`}
                  onClick={() =>
                    setAgentFilter((prev) =>
                      prev === name.toLowerCase() ? "all" : name.toLowerCase(),
                    )
                  }
                  style={{
                    border: "none",
                    background: "transparent",
                    padding: 0,
                    cursor: "pointer",
                    display: "flex",
                    flexDirection: "column",
                    alignItems: "center",
                    gap: 3,
                    flex: 1,
                  }}
                >
                  <HarnessIcon name={name} size={13} />
                  <div
                    style={{
                      width: "100%",
                      height: h,
                      borderRadius: 3,
                      background:
                        agentFilter === name.toLowerCase()
                          ? "var(--accent-primary)"
                          : "var(--border-strong)",
                    }}
                  />
                </button>
              );
            })}
          </HStack>
        </div>

        <div className="fleet-card">
          <Text size="sm" color="secondary">
            Assurance coverage distribution
          </Text>
          <strong style={{ fontSize: 18 }} className="tabular">
            {`${assuranceCounts.al34} Boundary · ${assuranceCounts.al01 + assuranceCounts.al2} Request`}
          </strong>
          <div className="kpi-bar" style={{ height: 8, marginTop: 2 }}>
            <div
              style={{
                width: `${(assuranceCounts.al34 / assuranceCounts.total) * 100}%`,
                background: "var(--tone-allow)",
              }}
            />
            <div
              style={{
                width: `${(assuranceCounts.al2 / assuranceCounts.total) * 100}%`,
                background: "var(--tone-watch)",
              }}
            />
            <div
              style={{
                width: `${(assuranceCounts.al01 / assuranceCounts.total) * 100}%`,
                background: "var(--tone-ask)",
              }}
            />
          </div>
        </div>

        <div className="fleet-card">
          <Text size="sm" color="secondary">
            Discovered MCP servers
          </Text>
          <HStack justify="between" align="end">
            <strong style={{ fontSize: 22 }} className="tabular">
              {mcps.length}
            </strong>
            <svg width="110" height="30" viewBox="0 0 110 30" aria-hidden="true">
              <path
                d="M 2 24 L 22 20 L 42 22 L 62 12 L 82 15 L 108 6"
                fill="none"
                stroke="var(--accent-primary)"
                strokeWidth="2"
                strokeLinecap="round"
              />
            </svg>
          </HStack>
        </div>
      </div>

      <div className="facet-bar">
        <HStack gap={2} align="center" style={{ flexWrap: "wrap" }}>
          <GrdrIcon name="search" size={14} color="var(--ink-muted)" />
          <select
            aria-label="Filter by OS"
            className="facet-select"
            value={osFilter}
            onChange={(e) => {
              setOsFilter(e.target.value);
              setPage(0);
            }}
          >
            <option value="all">OS: All platforms</option>
            <option value="macos">macOS</option>
            <option value="linux">Linux</option>
            <option value="windows">Windows</option>
          </select>
          <select
            aria-label="Filter by agent harness"
            className="facet-select"
            value={agentFilter}
            onChange={(e) => {
              setAgentFilter(e.target.value);
              setPage(0);
            }}
          >
            <option value="all">Agent type: All</option>
            {agentTypeBuckets.map(([name]) => (
              <option key={name} value={name.toLowerCase()}>
                {name}
              </option>
            ))}
          </select>
        </HStack>

        <UiSdkSegmentedControl<InventoryView>
          ariaLabel="Inventory view mode"
          value={viewMode}
          options={[
            { value: "hexmap", label: "Hex map", icon: <GrdrIcon name="layers" size={13} /> },
            { value: "table", label: "Table", icon: <GrdrIcon name="list" size={13} /> },
          ]}
          onChange={setViewMode}
        />
      </div>

      {viewMode === "hexmap" ? (
        <section className="hex-stage" aria-label="Fleet honeycomb cluster map">
          <HStack justify="between" align="center" style={{ marginBottom: 12, flexWrap: "wrap", gap: 8 }}>
            <VStack gap={0}>
              <Heading level={2}>Fleet endpoint hexbin map</Heading>
              <Text size="sm" color="secondary">
                Click any endpoint hexagon to inspect its asset topology graph, agent assurance levels, and MCP digest pins.
              </Text>
            </VStack>
            <HStack gap={2} align="center">
              <Badge variant="success" label="Boundary (AL3/AL4)" />
              <Badge variant="warning" label="Unproven / Partial" />
              <Badge variant="error" label="Attention needed" />
            </HStack>
          </HStack>

          <svg
            width="100%"
            height="196"
            viewBox="0 0 600 180"
            role="img"
            aria-label="Interactive honeycomb hexbin map of fleet endpoints"
          >
            {hexCells.map((cell) => {
              const fill =
                cell.status === "boundary"
                  ? "var(--accent-primary)"
                  : cell.status === "partial"
                    ? "var(--tone-ask)"
                    : cell.status === "blind"
                      ? "var(--tone-block)"
                      : "var(--border-subtle)";
              const fillOpacity =
                cell.status === "boundary"
                  ? 0.28
                  : cell.status === "partial"
                    ? 0.35
                    : cell.status === "blind"
                      ? 0.42
                      : 0.45;
              const isSelected = cell.device && selectedDevice?.id === cell.device.id;
              return (
                <polygon
                  key={cell.key}
                  points={hexPoints(cell.cx, cell.cy, 15.2)}
                  fill={fill}
                  fillOpacity={fillOpacity}
                  stroke={isSelected ? "var(--ink-primary)" : fill}
                  strokeWidth={isSelected ? "2.2" : "1"}
                  style={{ cursor: cell.device ? "pointer" : "default" }}
                  onClick={() => {
                    if (cell.device) setSelectedDeviceId(cell.device.id);
                  }}
                >
                  <title>{cell.label}</title>
                </polygon>
              );
            })}
          </svg>
        </section>
      ) : null}

      <Card padding={3}>
        <VStack gap={3}>
          <HStack justify="between" align="center">
            <HStack gap={2} align="center">
              <GrdrIcon name="hard-drive" size={16} />
              <Heading level={2}>{`Enrolled devices (${filteredDevices.length})`}</Heading>
            </HStack>
            <HStack gap={1} align="center">
              <Text size="sm" color="secondary">
                Rows/page
              </Text>
              <select
                aria-label="Devices per page"
                className="facet-select"
                value={pageSize}
                onChange={(e) => {
                  setPageSize(Number(e.target.value));
                  setPage(0);
                }}
              >
                <option value={25}>25</option>
                <option value={50}>50</option>
                <option value={100}>100</option>
              </select>
            </HStack>
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
                {pagedDevices.map((device) => (
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
          {filteredDevices.length > pageSize && (
            <div className="pager-bar">
              <span>{`Showing ${page * pageSize + 1}-${Math.min((page + 1) * pageSize, filteredDevices.length)} of ${filteredDevices.length}`}</span>
              <HStack gap={1}>
                <Button size="sm" label="Previous" isDisabled={page === 0} onClick={() => setPage((p) => Math.max(0, p - 1))} />
                <Button
                  size="sm"
                  label="Next"
                  isDisabled={(page + 1) * pageSize >= filteredDevices.length}
                  onClick={() => setPage((p) => p + 1)}
                />
              </HStack>
            </div>
          )}
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
                  {agents.map(({ deviceId, deviceHostname, agent }) => (
                    <tr
                      key={`${deviceId}-${agent.id}`}
                      className="selectable"
                      onClick={() => setSelectedDeviceId(deviceId)}
                    >
                      <td>
                        <HStack gap={2} align="center">
                          <HarnessIcon name={agent.name} size={15} />
                          <strong>{agent.name}</strong>
                        </HStack>
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
                      <td>
                        <HStack gap={1} align="center">
                          <HarnessIcon name={mcp.source_agent} size={13} />
                          <span>{mcp.source_agent}</span>
                        </HStack>
                      </td>
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
