// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
import { useMemo, useState } from "react";
import { api, type Device } from "@grdr/api";
import { EntityLink, type EntityTarget, Quoted } from "@grdr/kit";
import {
  Badge,
  Button,
  Card,
  GrdrIcon,
  GrdrSelect,
  Heading,
  HStack,
  Text,
  TextInput,
  VStack,
} from "@grdr/ui";
import { CursorPagerBar, formatRangeLabel } from "../components/PagerBar";
import { aipQuote, useServerPage } from "../components/useServerPage";
import type { ConsoleSearchParams } from "../searchSchema";
import { SkillsAndRulesView } from "./InventorySkillsSection";

export function InventoryMcpAndSkills({
  mode,
  devices,
  globalQuery,
  urlSearch,
  onUpdateSearch,
  onSelectDevice,
  onOpenEntity,
}: {
  mode: "mcps" | "skills";
  devices: Device[];
  globalQuery: string;
  urlSearch?: ConsoleSearchParams;
  onUpdateSearch?: (patch: Partial<ConsoleSearchParams>) => void;
  onSelectDevice: (deviceId: string) => void;
  onOpenEntity?: (target: EntityTarget) => void;
}) {
  if (mode === "skills") {
    return (
      <SkillsAndRulesView
        devices={devices}
        globalQuery={globalQuery}
        urlSearch={urlSearch}
        onUpdateSearch={onUpdateSearch}
        onSelectDevice={onSelectDevice}
        onOpenEntity={onOpenEntity}
      />
    );
  }
  return (
    <McpServersView
      devices={devices}
      globalQuery={globalQuery}
      urlSearch={urlSearch}
      onUpdateSearch={onUpdateSearch}
      onSelectDevice={onSelectDevice}
      onOpenEntity={onOpenEntity}
    />
  );
}

function McpServersView({
  devices,
  globalQuery,
  urlSearch,
  onUpdateSearch,
  onSelectDevice,
  onOpenEntity,
}: {
  devices: Device[];
  globalQuery: string;
  urlSearch?: ConsoleSearchParams;
  onUpdateSearch?: (patch: Partial<ConsoleSearchParams>) => void;
  onSelectDevice: (deviceId: string) => void;
  onOpenEntity?: (target: EntityTarget) => void;
}) {
  const [fallbackQuery, setFallbackQuery] = useState("");
  const [fallbackTransport, setFallbackTransport] = useState("all");
  const [fallbackPin, setFallbackPin] = useState("all");

  const localQuery = urlSearch?.q ?? fallbackQuery;
  const transportFilter = urlSearch?.transport ?? fallbackTransport;
  const pinFilter = urlSearch?.pin ?? fallbackPin;

  const setLocalQuery = (q: string) => {
    setFallbackQuery(q);
    onUpdateSearch?.({
      q: q.trim() ? q : undefined,
      pageToken: undefined,
      page: undefined,
    });
  };
  const setTransportFilter = (transport: string) => {
    setFallbackTransport(transport);
    onUpdateSearch?.({
      transport: transport === "all" ? undefined : transport,
      pageToken: undefined,
      page: undefined,
    });
  };
  const setPinFilter = (pin: string) => {
    setFallbackPin(pin);
    onUpdateSearch?.({
      pin: pin === "all" ? undefined : pin,
      pageToken: undefined,
      page: undefined,
    });
  };

  const allMcps = useMemo(
    () =>
      devices.flatMap((device) =>
        device.mcp_servers.map((mcp) => ({
          deviceId: device.id,
          deviceHostname: device.hostname,
          deviceOs: device.os,
          mcp,
        })),
      ),
    [devices],
  );
  const deviceOsById = useMemo(() => new Map(devices.map((d) => [d.id, d.os])), [devices]);

  const combinedQuery = `${globalQuery} ${localQuery}`.trim().toLowerCase();
  const aipFilter = useMemo(() => {
    const clauses: string[] = [];
    if (combinedQuery) {
      clauses.push(
        `(name:${aipQuote(combinedQuery)} OR source_agent:${aipQuote(combinedQuery)} OR device_name:${aipQuote(combinedQuery)})`,
      );
    }
    if (transportFilter !== "all") clauses.push(`transport = ${aipQuote(transportFilter)}`);
    if (pinFilter === "pinned") clauses.push("pinned = true");
    if (pinFilter === "unpinned") clauses.push("pinned = false");
    return clauses.join(" AND ");
  }, [combinedQuery, transportFilter, pinFilter]);

  const mcpPage = useServerPage(
    api.listMcpServersPage,
    aipFilter,
    "name asc",
    25,
    0,
    onUpdateSearch
      ? {
          resource: "mcpServersPage",
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
      : { resource: "mcpServersPage" },
  );
  const startIdx = mcpPage.pageIndex * mcpPage.pageSize;
  const pagedMcps = mcpPage.items.map((item) => ({
    deviceId: item.device_id,
    deviceHostname: item.device_name,
    deviceOs: deviceOsById.get(item.device_id) ?? "linux",
    mcp: item.server,
  }));
  const totalMcpsCount = mcpPage.pageInfo.total_size_estimate || pagedMcps.length;
  const pinnedCount = allMcps.filter((m) => m.mcp.pinned).length;
  const stdioCount = allMcps.filter((m) => m.mcp.transport.toLowerCase() === "stdio").length;
  const hasFilters = Boolean(localQuery.trim()) || transportFilter !== "all" || pinFilter !== "all";

  return (
    <VStack gap={4}>
      <div className="fleet-strip-3" aria-label="MCP server summary">
        <div className="fleet-card">
          <Text size="sm" color="secondary">Discovered MCP servers</Text>
          <strong style={{ fontSize: 22 }} className="tabular">{allMcps.length}</strong>
          <Text size="sm" color="secondary" className="tabular">{`Across ${devices.length} endpoints`}</Text>
        </div>
        <div className="fleet-card">
          <Text size="sm" color="secondary">Digest pinning</Text>
          <strong style={{ fontSize: 22 }} className="tabular">{`${pinnedCount} pinned`}</strong>
          <Text size="sm" color="secondary" className="tabular">{`${allMcps.length - pinnedCount} unpinned`}</Text>
        </div>
        <div className="fleet-card">
          <Text size="sm" color="secondary">Transport mix</Text>
          <strong style={{ fontSize: 22 }} className="tabular">{`${stdioCount} stdio`}</strong>
          <Text size="sm" color="secondary" className="tabular">{`${allMcps.length - stdioCount} remote HTTP or SSE`}</Text>
        </div>
      </div>

      <div className="facet-bar">
        <HStack gap={2} align="center" style={{ flexWrap: "wrap", flex: 1 }}>
          <div style={{ minWidth: 220, flex: "1 1 220px", maxWidth: 320 }}>
            <TextInput
              label="Search MCP servers"
              isLabelHidden
              size="sm"
              placeholder="Filter by server name, command, or host..."
              startIcon={<GrdrIcon name="search" size={13} color="var(--ink-muted)" />}
              value={localQuery}
              onChange={(val) => setLocalQuery(val)}
              width="100%"
            />
          </div>
          <GrdrSelect
            label="Filter by transport"
            isLabelHidden
            size="sm"
            variant="secondary"
            value={transportFilter}
            options={[
              { value: "all", label: "Transport: All" },
              { value: "stdio", label: "stdio" },
              { value: "http", label: "http" },
              { value: "sse", label: "sse" },
            ]}
            onChange={(val) => setTransportFilter(val)}
          />
          <GrdrSelect
            label="Filter by pin state"
            isLabelHidden
            size="sm"
            variant="secondary"
            value={pinFilter}
            options={[
              { value: "all", label: "Pin status: All" },
              { value: "pinned", label: "Pinned" },
              { value: "unpinned", label: "Unpinned" },
            ]}
            onChange={(val) => setPinFilter(val)}
          />
          {hasFilters && (
            <Button
              size="sm"
              variant="ghost"
              label="Reset filters"
              onClick={() => {
                setFallbackQuery("");
                setFallbackTransport("all");
                setFallbackPin("all");
                onUpdateSearch?.({
                  q: undefined,
                  transport: undefined,
                  pin: undefined,
                  pageToken: undefined,
                  page: undefined,
                });
              }}
            />
          )}
        </HStack>
      </div>

      <Card padding={3}>
        <VStack gap={3}>
          <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
            <HStack gap={2} align="center">
              <GrdrIcon name="plug" size={16} />
              <Heading level={2}>{`MCP servers (${totalMcpsCount})`}</Heading>
            </HStack>
            <Text size="sm" color="secondary" className="tabular">
              {formatRangeLabel(startIdx, Math.max(pagedMcps.length, 1), totalMcpsCount)}
            </Text>
          </HStack>

          {pagedMcps.length === 0 && !mcpPage.loading ? (
            <Text color="secondary">No MCP server definitions match the active filters.</Text>
          ) : (
            <div className="table-wrap">
              <table className="responsive-table">
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
                  {pagedMcps.map(({ deviceId, deviceHostname, deviceOs, mcp }, idx) => (
                    <tr key={`${deviceHostname}-${mcp.name}-${idx}`}>
                      <td data-label="Name"><EntityLink kind="mcp" id={mcp.name} label={mcp.name} compact onSelect={onOpenEntity} /></td>
                      <td data-label="Source agent"><EntityLink kind="agent" label={mcp.source_agent} compact onSelect={onOpenEntity} /></td>
                      <td data-label="Endpoint">
                        <EntityLink
                          kind="device"
                          id={deviceId}
                          label={deviceHostname}
                          os={deviceOs}
                          compact
                          onSelect={() => onSelectDevice(deviceId)}
                        />
                      </td>
                      <td data-label="Transport">
                        <HStack gap={1} align="center">
                          <GrdrIcon
                            name={mcp.transport.toLowerCase() === "stdio" ? "terminal" : "globe"}
                            size={12}
                            color="var(--ink-secondary)"
                          />
                          <span className="mono">{mcp.transport}</span>
                        </HStack>
                      </td>
                      <td data-label="Command / endpoint"><Quoted text={mcp.command} /></td>
                      <td data-label="Digest pin">
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

          <CursorPagerBar
            pageIndex={mcpPage.pageIndex}
            pageSize={mcpPage.pageSize}
            itemCount={pagedMcps.length}
            pageInfo={mcpPage.pageInfo}
            label="MCP servers pagination"
            onNext={mcpPage.goNext}
            onPrev={mcpPage.goPrev}
            onPageSizeChange={mcpPage.setPageSize}
          />
        </VStack>
      </Card>
    </VStack>
  );
}
