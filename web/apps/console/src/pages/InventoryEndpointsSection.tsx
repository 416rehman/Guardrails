import { useMemo, useState } from "react";
import { api, type Device } from "@grdr/api";
import { pluralize, type InventorySectionId } from "@grdr/i18n";
import { EntityLink, OsLabel } from "@grdr/kit";
import {
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
  StatusInline,
  Text,
  UiSdkSegmentedControl,
  VStack,
} from "@grdr/ui";
import { CursorPagerBar, formatRangeLabel } from "../components/PagerBar";
import { aipQuote, useServerPage } from "../components/useServerPage";
import type { ConsoleSearchParams } from "../searchSchema";

type InventoryView = "hexmap" | "table";

export function InventoryEndpointsSection({
  devices,
  searchQuery,
  urlSearch,
  onUpdateSearch,
  agentFilter,
  selectedDeviceId,
  onAgentFilterChange,
  onSelectDevice,
  onNavigateSection,
}: {
  devices: Device[];
  searchQuery: string;
  urlSearch?: ConsoleSearchParams;
  onUpdateSearch?: (patch: Partial<ConsoleSearchParams>) => void;
  agentFilter: string;
  selectedDeviceId: string | null;
  onAgentFilterChange: (next: string) => void;
  onSelectDevice: (deviceId: string | null) => void;
  onNavigateSection: (section: InventorySectionId) => void;
}) {
  const [fallbackView, setFallbackView] = useState<InventoryView>("hexmap");
  const [fallbackOs, setFallbackOs] = useState<string>("all");
  const [fallbackOutliers, setFallbackOutliers] = useState(false);

  const viewMode = urlSearch?.view ?? fallbackView;
  const osFilter = urlSearch?.os ?? fallbackOs;
  const outliersOnly = urlSearch?.outliers ?? fallbackOutliers;

  const setViewMode = (next: InventoryView) => {
    setFallbackView(next);
    onUpdateSearch?.({ view: next === "hexmap" ? undefined : next });
  };
  const setOsFilter = (next: string) => {
    setFallbackOs(next);
    onUpdateSearch?.({
      os: next === "all" ? undefined : next,
      pageToken: undefined,
      page: undefined,
    });
  };
  const toggleOutliers = () => {
    const next = !outliersOnly;
    setFallbackOutliers(next);
    onUpdateSearch?.({
      outliers: next ? true : undefined,
      pageToken: undefined,
      page: undefined,
    });
  };

  const query = searchQuery.trim().toLowerCase();
  const aipFilter = useMemo(() => {
    const clauses: string[] = [];
    if (osFilter !== "all") clauses.push(`os:${aipQuote(osFilter)}`);
    if (outliersOnly) clauses.push("(online = false OR hook_effective = false)");
    if (query) clauses.push(`(hostname:${aipQuote(query)} OR os:${aipQuote(query)})`);
    return clauses.join(" AND ");
  }, [osFilter, outliersOnly, query]);

  const devicePage = useServerPage(
    api.listDevicesPage,
    aipFilter,
    "hostname asc",
    25,
    0,
    onUpdateSearch
      ? {
          resource: "devicesPage",
          pageToken: urlSearch?.pageToken ?? "",
          pageIndex: urlSearch?.page ?? 0,
          pageSize: urlSearch?.pageSize ?? 25,
          onPageChange: ({ pageToken, pageIndex }) =>
            onUpdateSearch({
              pageToken: pageToken || undefined,
              page: pageIndex > 0 ? pageIndex : undefined,
            }),
          onPageSizeChange: (nextSize) =>
            onUpdateSearch({
              pageSize: nextSize === 25 ? undefined : nextSize,
              pageToken: undefined,
              page: undefined,
            }),
        }
      : { resource: "devicesPage" },
  );

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
          agentFilter === "all" || d.agents.some((a) => a.name.toLowerCase().includes(agentFilter));
        const hasOutlier = !d.online || !d.hook_effective || d.mcp_servers.some((m) => !m.pinned);
        return matchesQuery && matchesOs && matchesAgent && (!outliersOnly || hasOutlier);
      }),
    [devices, query, osFilter, agentFilter, outliersOnly],
  );

  const agents = filteredDevices.flatMap((device) =>
    device.agents
      .filter((a) => agentFilter === "all" || a.name.toLowerCase().includes(agentFilter))
      .map((agent) => ({ deviceId: device.id, agent })),
  );
  const mcps = filteredDevices.flatMap((device) => device.mcp_servers);
  const activeDevices = filteredDevices.filter((d) => d.online).length;
  const activePct = filteredDevices.length === 0 ? 0 : Math.round((activeDevices / filteredDevices.length) * 100);
  const dormantDevices = Math.max(0, filteredDevices.length - activeDevices);

  const agentTypeBuckets = useMemo(() => {
    const map = new Map<string, number>();
    for (const row of agents) map.set(row.agent.name, (map.get(row.agent.name) ?? 0) + 1);
    return Array.from(map.entries()).sort((a, b) => b[1] - a[1]);
  }, [agents]);

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

  const pagedDevices =
    devicePage.items.length > 0 || devicePage.pageInfo.total_size_estimate > 0
      ? devicePage.items
      : filteredDevices;
  const totalDevicesCount = Math.max(devicePage.pageInfo.total_size_estimate, pagedDevices.length);
  const startIdx = devicePage.pageIndex * devicePage.pageSize;

  const hexCells = useMemo<FleetHexCell[]>(() => {
    const cols = 12;
    return filteredDevices.map((dev, idx) => {
      const fullBoundary =
        dev.agents.length > 0 &&
        dev.agents.every(
          (a) => a.hook_installed && (a.assurance_level === "AL2" || a.assurance_level === "AL3" || a.assurance_level === "AL4"),
        );
      const status: FleetHexCell["status"] = !dev.online ? "blind" : dev.hook_effective && fullBoundary ? "boundary" : "partial";
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

  const pinnedMcps = mcps.filter((m) => m.pinned).length;
  const unpinnedMcps = mcps.length - pinnedMcps;

  return (
    <>
      <div className="fleet-strip" aria-label="Fleet telemetry distribution">
        <div className="fleet-card">
          <HStack gap={2} align="center">
            <GrdrCoverageRing valuePct={activePct} size={56} tone="allow" compact />
            <VStack gap={0}>
              <Text size="sm" color="secondary">Active endpoints</Text>
              <strong style={{ fontSize: 20, whiteSpace: "nowrap" }} className="tabular">{`${activeDevices} online`}</strong>
              <Text size="sm" color="secondary" className="tabular">{`${dormantDevices} dormant`}</Text>
            </VStack>
          </HStack>
        </div>

        <div className="fleet-card">
          <HStack justify="between" align="center">
            <Text size="sm" color="secondary">Agent types</Text>
            {agentFilter !== "all" && (
              <Button size="sm" variant="ghost" label="Reset" onClick={() => onAgentFilterChange("all")} />
            )}
          </HStack>
          <strong style={{ fontSize: 22 }} className="tabular">{agentTypeBuckets.length}</strong>
          <HStack gap={2} align="center" style={{ flexWrap: "wrap" }}>
            {agentTypeBuckets.slice(0, 3).map(([name, count]) => {
              const isSelected = agentFilter === name.toLowerCase();
              return (
                <button
                  key={name}
                  type="button"
                  title={`Filter by ${name} (${count})`}
                  onClick={() => onAgentFilterChange(isSelected ? "all" : name.toLowerCase())}
                  style={{
                    border: "none",
                    background: "transparent",
                    padding: 0,
                    cursor: "pointer",
                    display: "inline-flex",
                    alignItems: "center",
                    gap: 4,
                    fontSize: 12,
                    fontWeight: isSelected ? 600 : 500,
                    color: isSelected ? "var(--accent-primary)" : "var(--ink-secondary)",
                  }}
                >
                  <HarnessIcon name={name} size={12} />
                  <span>{`${name} (${count})`}</span>
                </button>
              );
            })}
          </HStack>
        </div>

        <div className="fleet-card">
          <Text size="sm" color="secondary">Protection breakdown</Text>
          <strong style={{ fontSize: 18 }} className="tabular">
            {`${assuranceCounts.al34} Sandboxed · ${assuranceCounts.al01 + assuranceCounts.al2} Hook only`}
          </strong>
          <div className="kpi-bar" style={{ height: 4, marginTop: 2 }}>
            <div style={{ width: `${(assuranceCounts.al34 / assuranceCounts.total) * 100}%`, background: "var(--tone-allow)" }} />
            <div style={{ width: `${((assuranceCounts.al01 + assuranceCounts.al2) / assuranceCounts.total) * 100}%`, background: "var(--tone-ask)" }} />
          </div>
          <HStack gap={3} align="center" style={{ marginTop: 2 }}>
            <StatusInline tone="allow" dot label="Sandboxed" />
            <StatusInline tone="ask" dot label="Hook only" />
          </HStack>
        </div>

        <div className="fleet-card">
          <HStack justify="between" align="center">
            <Text size="sm" color="secondary">Discovered MCP servers</Text>
            <Button size="sm" variant="ghost" label="View all" onClick={() => onNavigateSection("mcps")} />
          </HStack>
          <strong style={{ fontSize: 22 }} className="tabular">{mcps.length}</strong>
          <Text size="sm" color="secondary" className="tabular">{`${pinnedMcps} pinned · ${unpinnedMcps} unpinned`}</Text>
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
            onChange={(val) => setOsFilter(val)}
          />
          <GrdrSelect
            label="Filter by agent type"
            isLabelHidden
            size="sm"
            variant="secondary"
            value={agentFilter}
            options={[
              { value: "all", label: "Agent type: All" },
              ...agentTypeBuckets.map(([name]) => ({ value: name.toLowerCase(), label: name })),
            ]}
            onChange={(val) => onAgentFilterChange(val)}
          />
          <Button
            size="sm"
            variant={outliersOnly ? "primary" : "secondary"}
            icon={<GrdrIcon name="alert-triangle" size={13} />}
            label="Outliers only"
            onClick={toggleOutliers}
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
              <Heading level={2}>{filteredDevices.length >= 25 ? "Fleet cohort cluster map" : "Fleet endpoint map"}</Heading>
              <Text size="sm" color="secondary">
                {filteredDevices.length >= 25
                  ? "Grouped by OS, device group, and assurance tier. Click a cluster or outlier host to inspect topology."
                  : "Click an endpoint hexagon to inspect its asset topology graph, agent assurance levels, and MCP pins."}
              </Text>
            </VStack>
            <HStack gap={3} align="center">
              <StatusInline tone="allow" dot label="Sandboxed" />
              <StatusInline tone="ask" dot label="Hook only" />
              <StatusInline tone="block" dot label="Attention needed" />
            </HStack>
          </HStack>

          <GrdrFleetHexMap
            cells={hexCells}
            selectedDeviceId={selectedDeviceId}
            onSelectDevice={onSelectDevice}
            height={filteredDevices.length <= 6 ? 112 : 204}
          />
        </section>
      ) : null}

      <Card padding={3}>
        <VStack gap={3}>
          <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
            <HStack gap={2} align="center">
              <GrdrIcon name="hard-drive" size={16} />
              <Heading level={2}>{`Enrolled devices (${totalDevicesCount})`}</Heading>
            </HStack>
            <Text size="sm" color="secondary" className="tabular">
              {formatRangeLabel(startIdx, Math.max(pagedDevices.length, 1), totalDevicesCount)}
            </Text>
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
                    className={`selectable ${selectedDeviceId === device.id ? "selected" : ""}`}
                    onClick={() => onSelectDevice(device.id)}
                  >
                    <td>
                      <EntityLink kind="device" id={device.id} label={device.hostname} os={device.os} onSelect={() => onSelectDevice(device.id)} />
                      <div className="mono" style={{ color: "var(--ink-muted)", marginTop: 3 }}>{device.id}</div>
                    </td>
                    <td><OsLabel os={device.os} arch={device.arch} size={14} /></td>
                    <td>
                      <StatusInline
                        tone={device.install_profile === "protected" ? "watch" : "neutral"}
                        icon={<GrdrIcon name={device.install_profile === "protected" ? "shield-check" : "shield-half"} size={13} />}
                        label={device.install_profile === "protected" ? "Protected" : "User mode"}
                      />
                    </td>
                    <td>
                      <StatusInline
                        tone={device.hook_effective ? "allow" : "ask"}
                        icon={<GrdrIcon name={device.hook_effective ? "check-circle" : "alert-triangle"} size={13} />}
                        label={device.hook_effective ? "Hook active" : "Discovery only"}
                      />
                    </td>
                    <td className="tabular">{device.agents.length} / {device.mcp_servers.length}</td>
                    <td><StatusInline tone={device.online ? "allow" : "neutral"} dot label={device.online ? "Online" : "Offline"} /></td>
                    <td>
                      <Button
                        size="sm"
                        label="Inspect matrix"
                        icon={<GrdrIcon name="shield-check" size={13} />}
                        onClick={(e) => { e.stopPropagation(); onSelectDevice(device.id); }}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <CursorPagerBar
            pageIndex={devicePage.pageIndex}
            pageSize={devicePage.pageSize}
            itemCount={pagedDevices.length}
            pageInfo={devicePage.pageInfo}
            label="Enrolled devices pagination"
            onNext={devicePage.goNext}
            onPrev={devicePage.goPrev}
            onPageSizeChange={devicePage.setPageSize}
          />
        </VStack>
      </Card>
    </>
  );
}
