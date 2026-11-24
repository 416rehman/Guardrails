import { useMemo, useState } from "react";
import type { Device } from "@grdr/api";
import {
  presentArtifactKind,
  presentArtifactRiskFlag,
  presentArtifactScope,
} from "@grdr/i18n";
import { EntityLink, type EntityTarget, Quoted } from "@grdr/kit";
import {
  Badge,
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

export function SkillsAndRulesView({
  devices,
  globalQuery,
  onSelectDevice,
  onOpenEntity,
}: {
  devices: Device[];
  globalQuery: string;
  onSelectDevice: (deviceId: string) => void;
  onOpenEntity?: (target: EntityTarget) => void;
}) {
  const [localQuery, setLocalQuery] = useState("");
  const [kindFilter, setKindFilter] = useState("all");
  const [scopeFilter, setScopeFilter] = useState("all");
  const [signalFilter, setSignalFilter] = useState("all");
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(25);

  const allArtifacts = useMemo(
    () =>
      devices.flatMap((device) =>
        (device.artifacts ?? []).map((artifact) => ({
          deviceId: device.id,
          deviceHostname: device.hostname,
          deviceOs: device.os,
          artifact,
        })),
      ),
    [devices],
  );

  const combinedQuery = `${globalQuery} ${localQuery}`.trim().toLowerCase();
  const filteredArtifacts = useMemo(
    () =>
      allArtifacts.filter(({ deviceHostname, artifact }) => {
        if (
          combinedQuery &&
          !artifact.name.toLowerCase().includes(combinedQuery) &&
          !artifact.path.toLowerCase().includes(combinedQuery) &&
          !artifact.source_agent.toLowerCase().includes(combinedQuery) &&
          !deviceHostname.toLowerCase().includes(combinedQuery)
        ) {
          return false;
        }
        if (kindFilter !== "all" && artifact.kind !== kindFilter) return false;
        if (scopeFilter !== "all" && artifact.scope !== scopeFilter) return false;
        if (signalFilter === "flagged" && artifact.risk_flags.length === 0) return false;
        if (signalFilter === "clean" && artifact.risk_flags.length > 0) return false;
        return true;
      }),
    [allArtifacts, combinedQuery, kindFilter, scopeFilter, signalFilter],
  );

  const safePage =
    page * pageSize >= filteredArtifacts.length && filteredArtifacts.length > 0 ? 0 : page;
  const startIdx = safePage * pageSize;
  const pagedArtifacts = filteredArtifacts.slice(startIdx, startIdx + pageSize);
  const flaggedCount = allArtifacts.filter((a) => a.artifact.risk_flags.length > 0).length;
  const pinnedCount = allArtifacts.filter((a) => a.artifact.pinned).length;
  const hasFilters =
    Boolean(localQuery.trim()) ||
    kindFilter !== "all" ||
    scopeFilter !== "all" ||
    signalFilter !== "all";

  return (
    <VStack gap={4}>
      <div className="fleet-strip-3" aria-label="Skills and rules summary">
        <div className="fleet-card">
          <Text size="sm" color="secondary">Discovered artifacts</Text>
          <strong style={{ fontSize: 22 }} className="tabular">{allArtifacts.length}</strong>
          <Text size="sm" color="secondary">Skills, standing rules, commands, and plugins</Text>
        </div>
        <div className="fleet-card">
          <Text size="sm" color="secondary">Risk signals</Text>
          <strong style={{ fontSize: 22 }} className="tabular">{flaggedCount}</strong>
          <Text size="sm" color="secondary" className="tabular">
            {`${allArtifacts.length - flaggedCount} clean artifacts`}
          </Text>
        </div>
        <div className="fleet-card">
          <Text size="sm" color="secondary">Digest pinned</Text>
          <strong style={{ fontSize: 22 }} className="tabular">{pinnedCount}</strong>
          <Text size="sm" color="secondary" className="tabular">
            {`${allArtifacts.length - pinnedCount} unpinned`}
          </Text>
        </div>
      </div>

      <div className="facet-bar">
        <HStack gap={2} align="center" style={{ flexWrap: "wrap", flex: 1 }}>
          <div style={{ minWidth: 220, flex: "1 1 220px", maxWidth: 320 }}>
            <TextInput
              label="Search skills and rules"
              isLabelHidden
              size="sm"
              placeholder="Filter by artifact name, path, or agent..."
              startIcon={<GrdrIcon name="search" size={13} color="var(--ink-muted)" />}
              value={localQuery}
              onChange={(val) => { setLocalQuery(val); setPage(0); }}
              width="100%"
            />
          </div>
          <GrdrSelect
            label="Filter by kind"
            isLabelHidden
            size="sm"
            variant="secondary"
            value={kindFilter}
            options={[
              { value: "all", label: "Kind: All" },
              { value: "skill", label: "Skill" },
              { value: "rule", label: "Rule" },
              { value: "plugin", label: "Plugin" },
              { value: "command", label: "Command" },
              { value: "subagent", label: "Subagent" },
            ]}
            onChange={(val) => { setKindFilter(val); setPage(0); }}
          />
          <GrdrSelect
            label="Filter by scope"
            isLabelHidden
            size="sm"
            variant="secondary"
            value={scopeFilter}
            options={[
              { value: "all", label: "Scope: All" },
              { value: "user", label: "User" },
              { value: "workspace", label: "Workspace" },
              { value: "managed", label: "Managed" },
            ]}
            onChange={(val) => { setScopeFilter(val); setPage(0); }}
          />
          <GrdrSelect
            label="Filter by risk signal"
            isLabelHidden
            size="sm"
            variant="secondary"
            value={signalFilter}
            options={[
              { value: "all", label: "Signals: All" },
              { value: "flagged", label: "Flagged only" },
              { value: "clean", label: "Clean only" },
            ]}
            onChange={(val) => { setSignalFilter(val); setPage(0); }}
          />
          {hasFilters && (
            <Button
              size="sm"
              variant="ghost"
              label="Reset filters"
              onClick={() => {
                setLocalQuery("");
                setKindFilter("all");
                setScopeFilter("all");
                setSignalFilter("all");
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
              <GrdrIcon name="file-code" size={16} />
              <Heading level={2}>{`Skills, rules & plugins (${filteredArtifacts.length})`}</Heading>
            </HStack>
            <Text size="sm" color="secondary" className="tabular">
              {formatRangeLabel(startIdx, pageSize, filteredArtifacts.length)}
            </Text>
          </HStack>

          {filteredArtifacts.length === 0 ? (
            <Text color="secondary">
              No skills, standing rules, commands, or subagents match the active filters.
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
                  {pagedArtifacts.map(({ deviceId, deviceHostname, deviceOs, artifact }) => (
                    <tr key={artifact.id}>
                      <td>
                        <VStack gap={1}>
                          <EntityLink kind="artifact" id={artifact.id} label={artifact.name} compact onSelect={onOpenEntity} />
                          <Quoted text={artifact.path} />
                        </VStack>
                      </td>
                      <td><Badge variant="neutral" label={presentArtifactKind(artifact.kind)} /></td>
                      <td><Text size="sm">{presentArtifactScope(artifact.scope)}</Text></td>
                      <td>
                        <HStack gap={1} align="center" style={{ flexWrap: "nowrap", columnGap: 6 }}>
                          <EntityLink kind="agent" label={artifact.source_agent} compact onSelect={onOpenEntity} />
                          <EntityLink
                            kind="device"
                            id={deviceId}
                            label={deviceHostname}
                            os={deviceOs}
                            compact
                            onSelect={() => onSelectDevice(deviceId)}
                          />
                        </HStack>
                      </td>
                      <td className="nowrap-cell"><Quoted text={artifact.content_digest.slice(0, 8)} /></td>
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

          <PagerBar
            page={safePage}
            pageSize={pageSize}
            totalItems={filteredArtifacts.length}
            label="Skills and rules pagination"
            onPageChange={setPage}
            onPageSizeChange={(sz) => { setPageSize(sz); setPage(0); }}
          />
        </VStack>
      </Card>
    </VStack>
  );
}
