import { useMemo, useState } from "react";
import type { Device } from "@grdr/api";
import { formatOsName, pluralize } from "@grdr/i18n";
import { AssuranceBadge, DeviceAssuranceDrawer, Quoted } from "@grdr/kit";
import {
  Badge,
  Button,
  Card,
  type FleetHexCell,
  GrdrCoverageRing,
  GrdrFleetHexMap,
  GrdrIcon,
  GrdrSelect,
  HarnessIcon,
  Heading,
  HStack,
  Pagination,
  Text,
  UiSdkSegmentedControl,
  VStack,
} from "@grdr/ui";

type InventoryView = "hexmap" | "table";

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
  const [outliersOnly, setOutliersOnly] = useState(false);
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
        const hasOutlier =
          !d.online || !d.hook_effective || d.mcp_servers.some((m) => !m.pinned);
        const matchesOutlier = !outliersOnly || hasOutlier;
        return matchesQuery && matchesOs && matchesAgent && matchesOutlier;
      }),
    [devices, query, osFilter, agentFilter, outliersOnly],
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

  const hexCells = useMemo<FleetHexCell[]>(() => {
    const cols = 12;
    return filteredDevices.map((dev, idx) => {
      const status: FleetHexCell["status"] = !dev.online
        ? "blind"
        : dev.hook_effective
          ? "boundary"
          : "partial";
      return {
        key: dev.id,
        col: idx % cols,
        row: Math.floor(idx / cols),
        deviceId: dev.id,
        status,
        label: `${dev.hostname} · ${pluralize(dev.agents.length, "agent")}`,
      };
    });
  }, [filteredDevices]);

  const pinnedMcps = mcps.filter((m) => m.mcp.pinned).length;
  const unpinnedMcps = mcps.length - pinnedMcps;

  return (
    <VStack gap={4}>
      <div className="page-header">
        <div>
          <Heading level={1}>Inventory</Heading>
          <Text color="secondary">
            Devices, coding agents, and tool servers across your fleet.
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
            <GrdrCoverageRing valuePct={activePct} size={56} tone="allow" compact />
            <VStack gap={0}>
              <Text size="sm" color="secondary">
                Active endpoints
              </Text>
              <strong style={{ fontSize: 20, whiteSpace: "nowrap" }} className="tabular">
                {`${activeDevices} online`}
              </strong>
              <Text size="sm" color="secondary" className="tabular">
                {`${dormantDevices} dormant`}
              </Text>
            </VStack>
          </HStack>
        </div>

        <div className="fleet-card">
          <HStack justify="between" align="center">
            <Text size="sm" color="secondary">
              Agent types ({agentTypeBuckets.length})
            </Text>
            {agentFilter !== "all" && (
              <Button
                size="sm"
                variant="ghost"
                label="Reset"
                onClick={() => setAgentFilter("all")}
              />
            )}
          </HStack>
          <VStack gap={1}>
            {agentTypeBuckets.slice(0, 3).map(([name, count]) => {
              const pct = Math.max(18, Math.round((count / maxAgentCount) * 100));
              const isSelected = agentFilter === name.toLowerCase();
              return (
                <button
                  key={name}
                  type="button"
                  title={`Filter by ${name} (${count})`}
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
                    display: "grid",
                    gridTemplateColumns: "18px minmax(0, 1fr) 20px",
                    alignItems: "center",
                    gap: 6,
                    width: "100%",
                    textAlign: "left",
                  }}
                >
                  <HarnessIcon name={name} size={13} />
                  <div
                    style={{
                      display: "flex",
                      flexDirection: "column",
                      gap: 2,
                      minWidth: 0,
                    }}
                  >
                    <span
                      style={{
                        fontSize: 12,
                        fontWeight: isSelected ? 700 : 500,
                        color: "var(--ink-primary)",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {name}
                    </span>
                    <div
                      style={{
                        width: "100%",
                        height: 5,
                        borderRadius: 99,
                        background: "var(--border-subtle)",
                        overflow: "hidden",
                      }}
                    >
                      <div
                        style={{
                          width: `${pct}%`,
                          height: "100%",
                          borderRadius: 99,
                          background: isSelected ? "var(--accent-primary)" : "var(--ink-secondary)",
                        }}
                      />
                    </div>
                  </div>
                  <span className="tabular" style={{ fontSize: 12, fontWeight: 600, color: "var(--ink-secondary)", textAlign: "right" }}>
                    {count}
                  </span>
                </button>
              );
            })}
          </VStack>
        </div>

        <div className="fleet-card">
          <Text size="sm" color="secondary">
            Protection breakdown
          </Text>
          <strong style={{ fontSize: 18 }} className="tabular">
            {`${assuranceCounts.al34} Sandboxed · ${assuranceCounts.al01 + assuranceCounts.al2} Hook only`}
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
          <strong style={{ fontSize: 22 }} className="tabular">
            {mcps.length}
          </strong>
          <Text size="sm" color="secondary" className="tabular">
            {`${pinnedMcps} pinned · ${unpinnedMcps} unpinned`}
          </Text>
        </div>
      </div>

      <div className="facet-bar">
        <HStack gap={2} align="center" style={{ flexWrap: "wrap" }}>
          <GrdrIcon name="sliders-horizontal" size={14} color="var(--ink-muted)" />
          <GrdrSelect
            label="Filter by OS"
            isLabelHidden
            size="sm"
            variant="secondary"
            value={osFilter}
            options={[
              { value: "all", label: "OS: All platforms" },
              { value: "macos", label: "macOS" },
              { value: "linux", label: "Linux" },
              { value: "windows", label: "Windows" },
            ]}
            onChange={(val) => {
              setOsFilter(val);
              setPage(0);
            }}
          />
          <GrdrSelect
            label="Filter by agent type"
            isLabelHidden
            size="sm"
            variant="secondary"
            value={agentFilter}
            options={[
              { value: "all", label: "Agent type: All" },
              ...agentTypeBuckets.map(([name]) => ({
                value: name.toLowerCase(),
                label: name,
              })),
            ]}
            onChange={(val) => {
              setAgentFilter(val);
              setPage(0);
            }}
          />
          <Button
            size="sm"
            variant={outliersOnly ? "primary" : "secondary"}
            icon={<GrdrIcon name="alert-triangle" size={13} />}
            label="Outliers only"
            onClick={() => {
              setOutliersOnly((prev) => !prev);
              setPage(0);
            }}
          />
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
              <Heading level={2}>
                {filteredDevices.length >= 25
                  ? "Fleet cohort cluster map"
                  : "Fleet endpoint map"}
              </Heading>
              <Text size="sm" color="secondary">
                {filteredDevices.length >= 25
                  ? "Grouped by OS, device group, and assurance tier. Click a cluster or outlier host to inspect topology."
                  : "Click an endpoint hexagon to inspect its asset topology graph, agent assurance levels, and MCP pins."}
              </Text>
            </VStack>
            <HStack gap={2} align="center">
              <Badge variant="success" label="Sandboxed / Enforced" />
              <Badge variant="warning" label="Hook only" />
              <Badge variant="error" label="Attention needed" />
            </HStack>
          </HStack>

          <GrdrFleetHexMap
            cells={hexCells}
            selectedDeviceId={selectedDevice?.id ?? null}
            onSelectDevice={setSelectedDeviceId}
            height={filteredDevices.length <= 6 ? 112 : 204}
          />
        </section>
      ) : null}

      <Card padding={3}>
        <VStack gap={3}>
          <HStack justify="between" align="center">
            <HStack gap={2} align="center">
              <GrdrIcon name="hard-drive" size={16} />
              <Heading level={2}>{`Enrolled devices (${filteredDevices.length})`}</Heading>
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
                      {formatOsName(device.os)} / {device.arch}
                    </td>
                    <td>
                      <Badge
                        variant="info"
                        label={device.install_profile === "protected" ? "Protected" : "User mode"}
                      />
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
            <Pagination
              page={page + 1}
              onChange={(p) => setPage(Math.max(0, p - 1))}
              totalItems={filteredDevices.length}
              pageSize={pageSize}
              pageSizeOptions={[25, 50, 100]}
              onPageSizeChange={(sz) => {
                setPageSize(sz);
                setPage(0);
              }}
              variant="count"
              size="sm"
              label="Enrolled devices pagination"
            />
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
