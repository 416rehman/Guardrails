import { useEffect, useMemo, useState } from "react";
import { api, type Device } from "@grdr/api";
import { AssuranceBadge, EntityLink, type EntityTarget, Quoted } from "@grdr/kit";
import {
  Button,
  Card,
  GrdrIcon,
  GrdrSelect,
  Heading,
  HStack,
  StatusInline,
  Text,
  TextInput,
  VStack,
} from "@grdr/ui";
import { CursorPagerBar, formatRangeLabel } from "../components/PagerBar";
import { aipQuote, useServerPage } from "../components/useServerPage";

export function InventoryAgentsSection({
  devices,
  globalQuery,
  initialAgentFilter = "all",
  onSelectDevice,
  onOpenEntity,
}: {
  devices: Device[];
  globalQuery: string;
  initialAgentFilter?: string;
  onSelectDevice: (deviceId: string) => void;
  onOpenEntity?: (target: EntityTarget) => void;
}) {
  const [localQuery, setLocalQuery] = useState("");
  const [agentTypeFilter, setAgentTypeFilter] = useState(initialAgentFilter);
  const [assuranceFilter, setAssuranceFilter] = useState("all");
  const [hookFilter, setHookFilter] = useState("all");

  useEffect(() => {
    setAgentTypeFilter(initialAgentFilter);
  }, [initialAgentFilter]);

  const allRows = useMemo(
    () =>
      devices.flatMap((device) =>
        device.agents.map((agent) => ({
          deviceId: device.id,
          deviceHostname: device.hostname,
          deviceOs: device.os,
          agent,
        })),
      ),
    [devices],
  );

  const deviceOsById = useMemo(
    () => new Map(devices.map((d) => [d.id, d.os])),
    [devices],
  );

  const agentTypeOptions = useMemo(() => {
    const names = Array.from(new Set(allRows.map((r) => r.agent.name))).sort();
    return [
      { value: "all", label: "Harness: All agents" },
      ...names.map((name) => ({ value: name.toLowerCase(), label: name })),
    ];
  }, [allRows]);

  const combinedQuery = `${globalQuery} ${localQuery}`.trim().toLowerCase();
  const aipFilter = useMemo(() => {
    const clauses: string[] = [];
    if (combinedQuery) {
      clauses.push(`(name:${aipQuote(combinedQuery)} OR device_name:${aipQuote(combinedQuery)})`);
    }
    if (agentTypeFilter !== "all") {
      clauses.push(`name:${aipQuote(agentTypeFilter)}`);
    }
    if (assuranceFilter === "sandboxed") {
      clauses.push("(assurance_level = al3 OR assurance_level = al4)");
    } else if (assuranceFilter === "proxy") {
      clauses.push("assurance_level = al2");
    } else if (assuranceFilter === "hook") {
      clauses.push("assurance_level = al1");
    } else if (assuranceFilter === "observed") {
      clauses.push("assurance_level = al0");
    }
    if (hookFilter === "installed") clauses.push("hook_installed = true");
    if (hookFilter === "missing") clauses.push("hook_installed = false");
    return clauses.join(" AND ");
  }, [combinedQuery, agentTypeFilter, assuranceFilter, hookFilter]);

  const agentPage = useServerPage(api.listAgentsPage, aipFilter, "name asc", 25);
  const startIdx = agentPage.pageIndex * agentPage.pageSize;
  const pagedRows = agentPage.items.map((item) => ({
    deviceId: item.device_id,
    deviceHostname: item.device_name,
    deviceOs: deviceOsById.get(item.device_id) ?? "linux",
    agent: item.agent,
  }));
  const totalAgentsCount = agentPage.pageInfo.total_size_estimate || pagedRows.length;
  const sandboxedCount = allRows.filter(
    (r) => r.agent.assurance_level === "AL3" || r.agent.assurance_level === "AL4",
  ).length;
  const hookInstalledCount = allRows.filter((r) => r.agent.hook_installed).length;
  const distinctTypes = new Set(allRows.map((r) => r.agent.name)).size;
  const hasFilters =
    Boolean(localQuery.trim()) ||
    agentTypeFilter !== "all" ||
    assuranceFilter !== "all" ||
    hookFilter !== "all";

  return (
    <VStack gap={4}>
      <div className="fleet-strip" aria-label="Agent fleet summary">
        <div className="fleet-card">
          <Text size="sm" color="secondary">Discovered agents</Text>
          <strong style={{ fontSize: 22 }} className="tabular">{allRows.length}</strong>
          <Text size="sm" color="secondary" className="tabular">{`Across ${devices.length} endpoints`}</Text>
        </div>
        <div className="fleet-card">
          <Text size="sm" color="secondary">Distinct harnesses</Text>
          <strong style={{ fontSize: 22 }} className="tabular">{distinctTypes}</strong>
          <Text size="sm" color="secondary">Detected coding harnesses</Text>
        </div>
        <div className="fleet-card">
          <Text size="sm" color="secondary">Boundary protected</Text>
          <strong style={{ fontSize: 22 }} className="tabular">{sandboxedCount}</strong>
          <Text size="sm" color="secondary" className="tabular">
            {`${allRows.length - sandboxedCount} hook or observe`}
          </Text>
        </div>
        <div className="fleet-card">
          <Text size="sm" color="secondary">Hook shims active</Text>
          <strong style={{ fontSize: 22 }} className="tabular">{hookInstalledCount}</strong>
          <Text size="sm" color="secondary" className="tabular">
            {`${allRows.length - hookInstalledCount} not configured`}
          </Text>
        </div>
      </div>

      <div className="facet-bar">
        <HStack gap={2} align="center" style={{ flexWrap: "wrap", flex: 1 }}>
          <div style={{ minWidth: 220, flex: "1 1 220px", maxWidth: 320 }}>
            <TextInput
              label="Search agents"
              isLabelHidden
              size="sm"
              placeholder="Filter by agent, host, or config path..."
              startIcon={<GrdrIcon name="search" size={13} color="var(--ink-muted)" />}
              value={localQuery}
              onChange={(val) => setLocalQuery(val)}
              width="100%"
            />
          </div>
          <GrdrSelect
            label="Filter by harness"
            isLabelHidden
            size="sm"
            variant="secondary"
            value={agentTypeFilter}
            options={agentTypeOptions}
            onChange={(val) => setAgentTypeFilter(val)}
          />
          <GrdrSelect
            label="Filter by assurance tier"
            isLabelHidden
            size="sm"
            variant="secondary"
            value={assuranceFilter}
            options={[
              { value: "all", label: "Assurance: All tiers" },
              { value: "sandboxed", label: "Sandboxed / Enforced" },
              { value: "proxy", label: "Tool proxy" },
              { value: "hook", label: "App hook" },
              { value: "observed", label: "Observed only" },
            ]}
            onChange={(val) => setAssuranceFilter(val)}
          />
          <GrdrSelect
            label="Filter by hook shim"
            isLabelHidden
            size="sm"
            variant="secondary"
            value={hookFilter}
            options={[
              { value: "all", label: "Hook shim: All" },
              { value: "installed", label: "Installed" },
              { value: "missing", label: "Not configured" },
            ]}
            onChange={(val) => setHookFilter(val)}
          />
          {hasFilters && (
            <Button
              size="sm"
              variant="ghost"
              label="Reset filters"
              onClick={() => {
                setLocalQuery("");
                setAgentTypeFilter("all");
                setAssuranceFilter("all");
                setHookFilter("all");
              }}
            />
          )}
        </HStack>
      </div>

      <Card padding={3}>
        <VStack gap={3}>
          <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
            <HStack gap={2} align="center">
              <GrdrIcon name="cpu" size={16} />
              <Heading level={2}>{`Discovered AI agents (${totalAgentsCount})`}</Heading>
            </HStack>
            <Text size="sm" color="secondary" className="tabular">
              {formatRangeLabel(startIdx, Math.max(pagedRows.length, 1), totalAgentsCount)}
            </Text>
          </HStack>

          {pagedRows.length === 0 && !agentPage.loading ? (
            <Text color="secondary">
              No agents match the active filters. Adjust filters or enroll an endpoint running grdr-daemon.
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
                  {pagedRows.map(({ deviceId, deviceHostname, deviceOs, agent }) => (
                    <tr key={`${deviceId}-${agent.id}`} className="selectable" onClick={() => onSelectDevice(deviceId)}>
                      <td><EntityLink kind="agent" id={agent.id} label={agent.name} compact onSelect={onOpenEntity} /></td>
                      <td><EntityLink kind="device" id={deviceId} label={deviceHostname} os={deviceOs} compact onSelect={() => onSelectDevice(deviceId)} /></td>
                      <td><AssuranceBadge level={agent.assurance_level} control={agent.assurance.control} /></td>
                      <td>
                        <StatusInline
                          tone={agent.hook_installed ? "allow" : "ask"}
                          icon={<GrdrIcon name={agent.hook_installed ? "check-circle" : "alert-triangle"} size={13} />}
                          label={agent.hook_installed ? "Installed" : "Not configured"}
                        />
                      </td>
                      <td className="tabular">{agent.mcp_count}</td>
                      <td><Quoted text={agent.config_path} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          <CursorPagerBar
            pageIndex={agentPage.pageIndex}
            pageSize={agentPage.pageSize}
            itemCount={pagedRows.length}
            pageInfo={agentPage.pageInfo}
            label="Agents pagination"
            onNext={agentPage.goNext}
            onPrev={agentPage.goPrev}
            onPageSizeChange={agentPage.setPageSize}
          />
        </VStack>
      </Card>
    </VStack>
  );
}
