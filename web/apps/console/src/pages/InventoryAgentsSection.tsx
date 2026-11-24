import { useEffect, useMemo, useState } from "react";
import type { Device } from "@grdr/api";
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
import { formatRangeLabel, PagerBar } from "../components/PagerBar";

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
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(25);

  useEffect(() => {
    setAgentTypeFilter(initialAgentFilter);
    setPage(0);
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

  const agentTypeOptions = useMemo(() => {
    const names = Array.from(new Set(allRows.map((r) => r.agent.name))).sort();
    return [
      { value: "all", label: "Harness: All agents" },
      ...names.map((name) => ({ value: name.toLowerCase(), label: name })),
    ];
  }, [allRows]);

  const combinedQuery = `${globalQuery} ${localQuery}`.trim().toLowerCase();
  const filteredRows = useMemo(
    () =>
      allRows.filter(({ deviceHostname, agent }) => {
        if (
          combinedQuery &&
          !agent.name.toLowerCase().includes(combinedQuery) &&
          !deviceHostname.toLowerCase().includes(combinedQuery) &&
          !agent.config_path.toLowerCase().includes(combinedQuery)
        ) {
          return false;
        }
        if (
          agentTypeFilter !== "all" &&
          !agent.name.toLowerCase().includes(agentTypeFilter.toLowerCase())
        ) {
          return false;
        }
        if (assuranceFilter === "sandboxed") {
          if (agent.assurance_level !== "AL3" && agent.assurance_level !== "AL4") return false;
        } else if (assuranceFilter === "proxy" && agent.assurance_level !== "AL2") {
          return false;
        } else if (assuranceFilter === "hook" && agent.assurance_level !== "AL1") {
          return false;
        } else if (assuranceFilter === "observed" && agent.assurance_level !== "AL0") {
          return false;
        }
        if (hookFilter === "installed" && !agent.hook_installed) return false;
        if (hookFilter === "missing" && agent.hook_installed) return false;
        return true;
      }),
    [allRows, combinedQuery, agentTypeFilter, assuranceFilter, hookFilter],
  );

  const safePage = page * pageSize >= filteredRows.length && filteredRows.length > 0 ? 0 : page;
  const startIdx = safePage * pageSize;
  const pagedRows = filteredRows.slice(startIdx, startIdx + pageSize);
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
              onChange={(val) => { setLocalQuery(val); setPage(0); }}
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
            onChange={(val) => { setAgentTypeFilter(val); setPage(0); }}
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
            onChange={(val) => { setAssuranceFilter(val); setPage(0); }}
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
            onChange={(val) => { setHookFilter(val); setPage(0); }}
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
                setPage(0);
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
              <Heading level={2}>{`Discovered AI agents (${filteredRows.length})`}</Heading>
            </HStack>
            <Text size="sm" color="secondary" className="tabular">
              {formatRangeLabel(startIdx, pageSize, filteredRows.length)}
            </Text>
          </HStack>

          {filteredRows.length === 0 ? (
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

          <PagerBar
            page={safePage}
            pageSize={pageSize}
            totalItems={filteredRows.length}
            label="Agents pagination"
            onPageChange={setPage}
            onPageSizeChange={(sz) => { setPageSize(sz); setPage(0); }}
          />
        </VStack>
      </Card>
    </VStack>
  );
}
