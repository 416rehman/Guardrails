// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
import { useEffect, useMemo, useState } from "react";
import { api, type Device } from "@grdr/api";
import { presentAgentName } from "@grdr/i18n";
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
import { canonicalAgentSlugKey } from "../consoleState";
import type { ConsoleSearchParams } from "../searchSchema";

export function InventoryAgentsSection({
  devices,
  globalQuery,
  initialAgentFilter = "all",
  urlSearch,
  onUpdateSearch,
  onSelectDevice,
  onOpenEntity,
}: {
  devices: Device[];
  globalQuery: string;
  initialAgentFilter?: string;
  urlSearch?: ConsoleSearchParams;
  onUpdateSearch?: (patch: Partial<ConsoleSearchParams>) => void;
  onSelectDevice: (deviceId: string) => void;
  onOpenEntity?: (target: EntityTarget) => void;
}) {
  const [fallbackQuery, setFallbackQuery] = useState("");
  const [fallbackAgentType, setFallbackAgentType] = useState(initialAgentFilter);
  const [fallbackAssurance, setFallbackAssurance] = useState("all");
  const [fallbackHook, setFallbackHook] = useState("all");

  useEffect(() => {
    setFallbackAgentType(initialAgentFilter);
  }, [initialAgentFilter]);

  const localQuery = urlSearch?.q ?? fallbackQuery;
  const agentTypeFilter = urlSearch?.agent ?? fallbackAgentType;
  const assuranceFilter = urlSearch?.assurance ?? fallbackAssurance;
  const hookFilter = urlSearch?.hook ?? fallbackHook;

  const setLocalQuery = (q: string) => {
    setFallbackQuery(q);
    onUpdateSearch?.({
      q: q.trim() ? q : undefined,
      pageToken: undefined,
      page: undefined,
    });
  };
  const setAgentTypeFilter = (agent: string) => {
    setFallbackAgentType(agent);
    onUpdateSearch?.({
      agent: agent === "all" ? undefined : agent,
      pageToken: undefined,
      page: undefined,
    });
  };
  const setAssuranceFilter = (assurance: string) => {
    setFallbackAssurance(assurance);
    onUpdateSearch?.({
      assurance: assurance === "all" ? undefined : assurance,
      pageToken: undefined,
      page: undefined,
    });
  };
  const setHookFilter = (hook: string) => {
    setFallbackHook(hook);
    onUpdateSearch?.({
      hook: hook === "all" ? undefined : hook,
      pageToken: undefined,
      page: undefined,
    });
  };

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
    const seen = new Map<string, string>();
    for (const row of allRows) {
      const display = presentAgentName(row.agent.name);
      const key = canonicalAgentSlugKey(display);
      if (key && !seen.has(key)) {
        seen.set(key, display);
      }
    }
    const sorted = Array.from(seen.entries()).sort((a, b) => a[1].localeCompare(b[1]));
    return [
      { value: "all", label: "Harness: All agents" },
      ...sorted.map(([value, label]) => ({ value, label })),
    ];
  }, [allRows]);

  const normalizedAgentFilter =
    agentTypeFilter === "all"
      ? "all"
      : canonicalAgentSlugKey(presentAgentName(agentTypeFilter));

  const combinedQuery = `${globalQuery} ${localQuery}`.trim().toLowerCase();
  const aipFilter = useMemo(() => {
    const clauses: string[] = [];
    if (combinedQuery) {
      clauses.push(`(name:${aipQuote(combinedQuery)} OR device_name:${aipQuote(combinedQuery)})`);
    }
    if (normalizedAgentFilter !== "all") {
      const matchedSpellings = Array.from(
        new Set(
          allRows
            .filter(
              (r) => canonicalAgentSlugKey(presentAgentName(r.agent.name)) === normalizedAgentFilter,
            )
            .map((r) => r.agent.name.trim().toLowerCase())
            .filter(Boolean),
        ),
      );
      const rawAgentTerm = agentTypeFilter.trim().toLowerCase();
      const displayFallback = presentAgentName(agentTypeFilter).toLowerCase();
      const slugHyphen = normalizedAgentFilter.replace(/\s+/g, "-");
      const nameTerms = Array.from(
        new Set([...matchedSpellings.slice(0, 3), displayFallback, rawAgentTerm, normalizedAgentFilter].filter(Boolean)),
      ).slice(0, 4);
      const kindTerms = Array.from(new Set([slugHyphen, rawAgentTerm].filter(Boolean))).slice(0, 2);
      const termClauses = [
        ...nameTerms.map((term) => `name:${aipQuote(term)}`),
        ...kindTerms.map((term) => `kind:${aipQuote(term)}`),
      ];
      clauses.push(`(${termClauses.join(" OR ")})`);
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
  }, [combinedQuery, agentTypeFilter, normalizedAgentFilter, allRows, assuranceFilter, hookFilter]);

  const agentPage = useServerPage(
    api.listAgentsPage,
    aipFilter,
    "name asc",
    25,
    0,
    onUpdateSearch
      ? {
          resource: "agentsPage",
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
      : { resource: "agentsPage" },
  );
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
  const distinctTypes = new Set(
    allRows.map((r) => canonicalAgentSlugKey(presentAgentName(r.agent.name))),
  ).size;
  const hasFilters =
    Boolean(localQuery.trim()) ||
    normalizedAgentFilter !== "all" ||
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
            value={normalizedAgentFilter}
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
                setFallbackQuery("");
                setFallbackAgentType("all");
                setFallbackAssurance("all");
                setFallbackHook("all");
                onUpdateSearch?.({
                  q: undefined,
                  agent: undefined,
                  assurance: undefined,
                  hook: undefined,
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
              <table className="responsive-table">
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
                      <td data-label="Agent"><EntityLink kind="agent" id={agent.id} label={agent.name} compact onSelect={onOpenEntity} /></td>
                      <td data-label="Endpoint"><EntityLink kind="device" id={deviceId} label={deviceHostname} os={deviceOs} compact onSelect={() => onSelectDevice(deviceId)} /></td>
                      <td data-label="Assurance level"><AssuranceBadge level={agent.assurance_level} control={agent.assurance.control} /></td>
                      <td data-label="Hook shim">
                        <StatusInline
                          tone={agent.hook_installed ? "allow" : "ask"}
                          icon={<GrdrIcon name={agent.hook_installed ? "check-circle" : "alert-triangle"} size={13} />}
                          label={agent.hook_installed ? "Installed" : "Not configured"}
                        />
                      </td>
                      <td data-label="MCPs" className="tabular">{agent.mcp_count}</td>
                      <td data-label="Config path"><Quoted text={agent.config_path} /></td>
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
