import { useEffect, useMemo, useState } from "react";
import type { Device } from "@grdr/api";
import {
  formatOsName,
  pluralize,
  presentArtifactKind,
  presentArtifactRiskFlag,
  presentArtifactScope,
} from "@grdr/i18n";
import { AssuranceBadge, DeviceAssuranceDrawer, EntityLink, type EntityTarget, OsLabel, Quoted } from "@grdr/kit";
import { ConnectSection } from "./ConnectSection";
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
  StatusInline,
  Text,
  UiSdkSegmentedControl,
  VStack,
} from "@grdr/ui";

type InventorySection = "fleet" | "connect";
type InventoryView = "hexmap" | "table";

export function InventoryPage({
  devices,
  searchQuery,
  focusedEntity,
  onClearFocus,
  onOpenEntity,
  onRefresh,
}: {
  devices: Device[];
  searchQuery: string;
  focusedEntity?: EntityTarget | null;
  onClearFocus?: () => void;
  onOpenEntity?: (target: EntityTarget) => void;
  onRefresh: () => void;
}) {
  const [section, setSection] = useState<InventorySection>("fleet");
  const [selectedDeviceId, setSelectedDeviceId] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<InventoryView>("hexmap");
  const [agentFilter, setAgentFilter] = useState<string>("all");
  const [osFilter, setOsFilter] = useState<string>("all");
  const [outliersOnly, setOutliersOnly] = useState(false);
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(25);

  useEffect(() => {
    if (!focusedEntity) return;
    if (focusedEntity.kind === "device") {
      const match = devices.find(
        (d) => d.id === focusedEntity.id || d.hostname === focusedEntity.label,
      );
      if (match) {
        setSelectedDeviceId(match.id);
        setAgentFilter("all");
      }
      onClearFocus?.();
    } else if (focusedEntity.kind === "agent") {
      setAgentFilter(focusedEntity.label.toLowerCase());
      setSelectedDeviceId(null);
      onClearFocus?.();
    } else if (focusedEntity.kind === "mcp") {
      const owner = devices.find((d) =>
        d.mcp_servers.some((m) => m.name === focusedEntity.id || m.name === focusedEntity.label),
      );
      if (owner) {
        setSelectedDeviceId(owner.id);
      }
      onClearFocus?.();
    } else if (focusedEntity.kind === "artifact") {
      const owner = devices.find((d) =>
        (d.artifacts ?? []).some(
          (a) => a.id === focusedEntity.id || a.name === focusedEntity.label,
        ),
      );
      if (owner) {
        setSelectedDeviceId(owner.id);
      }
      onClearFocus?.();
    }
  }, [focusedEntity, devices, onClearFocus]);

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
        deviceOs: device.os,
        agent,
      })),
  );

  const mcps = filteredDevices.flatMap((device) =>
    device.mcp_servers.map((mcp) => ({
      deviceId: device.id,
      deviceHostname: device.hostname,
      deviceOs: device.os,
      mcp,
    })),
  );

  const artifacts = filteredDevices.flatMap((device) =>
    (device.artifacts ?? [])
      .filter(
        (art) =>
          agentFilter === "all" || art.source_agent.toLowerCase().includes(agentFilter),
      )
      .map((artifact) => ({
        deviceId: device.id,
        deviceHostname: device.hostname,
        deviceOs: device.os,
        artifact,
      })),
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
      const fullBoundary =
        dev.agents.length > 0 &&
        dev.agents.every(
          (a) =>
            a.hook_installed &&
            (a.assurance_level === "AL2" ||
              a.assurance_level === "AL3" ||
              a.assurance_level === "AL4"),
        );
      const status: FleetHexCell["status"] = !dev.online
        ? "blind"
        : dev.hook_effective && fullBoundary
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
        <HStack gap={2} align="center" style={{ flexWrap: "wrap" }}>
          <UiSdkSegmentedControl<InventorySection>
            ariaLabel="Inventory section"
            value={section}
            options={[
              { value: "fleet", label: "Fleet & Skills" },
              { value: "connect", label: "Connect & Integrations" },
            ]}
            onChange={setSection}
          />
          <Button
            label="Refresh inventory"
            icon={<GrdrIcon name="refresh" size={14} />}
            onClick={onRefresh}
          />
        </HStack>
      </div>

      {section === "connect" ? (
        <ConnectSection />
      ) : (
        <>

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
              Agent types
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
          <strong style={{ fontSize: 22 }} className="tabular">
            {agentTypeBuckets.length}
          </strong>
          <HStack gap={2} align="center" style={{ flexWrap: "wrap" }}>
            {agentTypeBuckets.slice(0, 3).map(([name, count]) => {
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
          <Text size="sm" color="secondary">
            Protection breakdown
          </Text>
          <strong style={{ fontSize: 18 }} className="tabular">
            {`${assuranceCounts.al34} Sandboxed · ${assuranceCounts.al01 + assuranceCounts.al2} Hook only`}
          </strong>
          <div className="kpi-bar" style={{ height: 4, marginTop: 2 }}>
            <div
              style={{
                width: `${(assuranceCounts.al34 / assuranceCounts.total) * 100}%`,
                background: "var(--tone-allow)",
              }}
            />
            <div
              style={{
                width: `${((assuranceCounts.al01 + assuranceCounts.al2) / assuranceCounts.total) * 100}%`,
                background: "var(--tone-ask)",
              }}
            />
          </div>
          <HStack gap={3} align="center" style={{ marginTop: 2 }}>
            <StatusInline tone="allow" dot label="Sandboxed" />
            <StatusInline tone="ask" dot label="Hook only" />
          </HStack>
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
            <HStack gap={3} align="center">
              <StatusInline tone="allow" dot label="Sandboxed" />
              <StatusInline tone="ask" dot label="Hook only" />
              <StatusInline tone="block" dot label="Attention needed" />
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
                      <EntityLink
                        kind="device"
                        id={device.id}
                        label={device.hostname}
                        os={device.os}
                        onSelect={() => setSelectedDeviceId(device.id)}
                      />
                      <div className="mono" style={{ color: "var(--ink-muted)", marginTop: 3 }}>
                        {device.id}
                      </div>
                    </td>
                    <td>
                      <OsLabel os={device.os} arch={device.arch} size={14} />
                    </td>
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
                    <td className="tabular">
                      {device.agents.length} / {device.mcp_servers.length}
                    </td>
                    <td>
                      <StatusInline
                        tone={device.online ? "allow" : "neutral"}
                        dot
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
                  {agents.map(({ deviceId, deviceHostname, deviceOs, agent }) => (
                    <tr
                      key={`${deviceId}-${agent.id}`}
                      className="selectable"
                      onClick={() => setSelectedDeviceId(deviceId)}
                    >
                      <td>
                        <EntityLink
                          kind="agent"
                          id={agent.id}
                          label={agent.name}
                          compact
                          onSelect={onOpenEntity}
                        />
                      </td>
                      <td>
                        <EntityLink
                          kind="device"
                          id={deviceId}
                          label={deviceHostname}
                          os={deviceOs}
                          compact
                          onSelect={() => setSelectedDeviceId(deviceId)}
                        />
                      </td>
                      <td>
                        <AssuranceBadge
                          level={agent.assurance_level}
                          control={agent.assurance.control}
                        />
                      </td>
                      <td>
                        <StatusInline
                          tone={agent.hook_installed ? "allow" : "ask"}
                          icon={<GrdrIcon name={agent.hook_installed ? "check-circle" : "alert-triangle"} size={13} />}
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
                  {mcps.map(({ deviceId, deviceHostname, deviceOs, mcp }, idx) => (
                    <tr key={`${deviceHostname}-${mcp.name}-${idx}`}>
                      <td>
                        <EntityLink
                          kind="mcp"
                          id={mcp.name}
                          label={mcp.name}
                          compact
                          onSelect={onOpenEntity}
                        />
                      </td>
                      <td>
                        <EntityLink
                          kind="agent"
                          label={mcp.source_agent}
                          compact
                          onSelect={onOpenEntity}
                        />
                      </td>
                      <td>
                        <EntityLink
                          kind="device"
                          id={deviceId}
                          label={deviceHostname}
                          os={deviceOs}
                          compact
                          onSelect={onOpenEntity}
                        />
                      </td>
                      <td>
                        <HStack gap={1} align="center">
                          <GrdrIcon
                            name={mcp.transport.toLowerCase() === "stdio" ? "terminal" : "globe"}
                            size={12}
                            color="var(--ink-secondary)"
                          />
                          <span className="mono">{mcp.transport}</span>
                        </HStack>
                      </td>
                      <td>
                        <Quoted text={mcp.command} />
                      </td>
                      <td>
                        <Badge
                          variant={mcp.pinned ? "success" : "warning"}
                          icon={<GrdrIcon name={mcp.pinned ? "lock" : "alert-triangle"} size={11} />}
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

      <Card padding={3}>
        <VStack gap={3}>
          <HStack gap={2} align="center">
            <GrdrIcon name="file-code" size={16} />
            <Heading level={2}>{`Skills, rules & plugins (${artifacts.length})`}</Heading>
          </HStack>
          {artifacts.length === 0 ? (
            <Text color="secondary">
              No skills, standing rules, commands, or subagents discovered on matching devices.
            </Text>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Artifact</th>
                    <th>Kind</th>
                    <th>Scope</th>
                    <th>Agent & device</th>
                    <th>Digest</th>
                    <th>Usage</th>
                    <th>Signals</th>
                  </tr>
                </thead>
                <tbody>
                  {artifacts.map(({ deviceId, deviceHostname, deviceOs, artifact }) => (
                    <tr key={artifact.id}>
                      <td>
                        <VStack gap={1}>
                          <EntityLink
                            kind="artifact"
                            id={artifact.id}
                            label={artifact.name}
                            compact
                            onSelect={onOpenEntity}
                          />
                          <Quoted text={artifact.path} />
                        </VStack>
                      </td>
                      <td>
                        <Badge variant="neutral" label={presentArtifactKind(artifact.kind)} />
                      </td>
                      <td>
                        <Text size="sm">{presentArtifactScope(artifact.scope)}</Text>
                      </td>
                      <td>
                        <HStack gap={1} align="center" style={{ flexWrap: "nowrap", columnGap: 6 }}>
                          <EntityLink
                            kind="agent"
                            label={artifact.source_agent}
                            compact
                            onSelect={onOpenEntity}
                          />
                          <EntityLink
                            kind="device"
                            id={deviceId}
                            label={deviceHostname}
                            os={deviceOs}
                            compact
                            onSelect={onOpenEntity}
                          />
                        </HStack>
                      </td>
                      <td className="nowrap-cell">
                        <Quoted text={artifact.content_digest.slice(0, 8)} />
                      </td>
                      <td className="tabular">{artifact.usage_count}</td>
                      <td>
                        {artifact.risk_flags.length === 0 ? (
                          <StatusInline
                            tone="allow"
                            icon={<GrdrIcon name="check-circle" size={12} />}
                            label={artifact.pinned ? "Pinned" : "Clean"}
                          />
                        ) : (
                          <HStack gap={1} style={{ flexWrap: "wrap" }}>
                            {artifact.risk_flags.map((flag) => (
                              <Badge
                                key={flag}
                                variant={flag === "bidi-obfuscation" ? "error" : "warning"}
                                icon={<GrdrIcon name="alert-triangle" size={11} />}
                                label={presentArtifactRiskFlag(flag)}
                              />
                            ))}
                          </HStack>
                        )}
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
        onOpenEntity={onOpenEntity}
        onClose={() => setSelectedDeviceId(null)}
      />
        </>
      )}
    </VStack>
  );
}
