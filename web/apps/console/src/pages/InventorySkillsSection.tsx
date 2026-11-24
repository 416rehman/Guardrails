import { useMemo, useState } from "react";
import { api, type Device } from "@grdr/api";
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
import { CursorPagerBar, formatRangeLabel } from "../components/PagerBar";
import { aipQuote, useServerPage } from "../components/useServerPage";
import type { ConsoleSearchParams } from "../searchSchema";

export function SkillsAndRulesView({
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
  const [fallbackKind, setFallbackKind] = useState("all");
  const [fallbackScope, setFallbackScope] = useState("all");
  const [fallbackSignal, setFallbackSignal] = useState("all");

  const localQuery = urlSearch?.q ?? fallbackQuery;
  const kindFilter = urlSearch?.kind ?? fallbackKind;
  const scopeFilter = urlSearch?.scope ?? fallbackScope;
  const signalFilter = urlSearch?.signal ?? fallbackSignal;

  const setLocalQuery = (q: string) => {
    setFallbackQuery(q);
    onUpdateSearch?.({
      q: q.trim() ? q : undefined,
      pageToken: undefined,
      page: undefined,
    });
  };
  const setKindFilter = (kind: string) => {
    setFallbackKind(kind);
    onUpdateSearch?.({
      kind: kind === "all" ? undefined : kind,
      pageToken: undefined,
      page: undefined,
    });
  };
  const setScopeFilter = (scope: string) => {
    setFallbackScope(scope);
    onUpdateSearch?.({
      scope: scope === "all" ? undefined : scope,
      pageToken: undefined,
      page: undefined,
    });
  };
  const setSignalFilter = (signal: string) => {
    setFallbackSignal(signal);
    onUpdateSearch?.({
      signal: signal === "all" ? undefined : signal,
      pageToken: undefined,
      page: undefined,
    });
  };

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
  const deviceOsById = useMemo(() => new Map(devices.map((d) => [d.id, d.os])), [devices]);

  const combinedQuery = `${globalQuery} ${localQuery}`.trim().toLowerCase();
  const aipFilter = useMemo(() => {
    const clauses: string[] = [];
    if (combinedQuery) {
      clauses.push(
        `(name:${aipQuote(combinedQuery)} OR source_agent:${aipQuote(combinedQuery)} OR device_name:${aipQuote(combinedQuery)})`,
      );
    }
    if (kindFilter !== "all") clauses.push(`kind = ${aipQuote(kindFilter)}`);
    if (scopeFilter !== "all") clauses.push(`scope = ${aipQuote(scopeFilter)}`);
    return clauses.join(" AND ");
  }, [combinedQuery, kindFilter, scopeFilter]);

  const artifactPage = useServerPage(
    api.listArtifactsPage,
    aipFilter,
    "detected_at desc",
    25,
    0,
    onUpdateSearch
      ? {
          resource: "artifactsPage",
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
      : { resource: "artifactsPage" },
  );
  const startIdx = artifactPage.pageIndex * artifactPage.pageSize;
  const pagedArtifacts = artifactPage.items
    .filter((artifact) => {
      if (signalFilter === "flagged") return artifact.risk_flags.length > 0;
      if (signalFilter === "clean") return artifact.risk_flags.length === 0;
      return true;
    })
    .map((artifact) => ({
      deviceId: artifact.device_id,
      deviceHostname: artifact.device_name,
      deviceOs: deviceOsById.get(artifact.device_id) ?? "linux",
      artifact,
    }));
  const totalArtifactsCount = artifactPage.pageInfo.total_size_estimate || pagedArtifacts.length;
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
              onChange={(val) => setLocalQuery(val)}
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
            onChange={(val) => setKindFilter(val)}
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
            onChange={(val) => setScopeFilter(val)}
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
            onChange={(val) => setSignalFilter(val)}
          />
          {hasFilters && (
            <Button
              size="sm"
              variant="ghost"
              label="Reset filters"
              onClick={() => {
                setFallbackQuery("");
                setFallbackKind("all");
                setFallbackScope("all");
                setFallbackSignal("all");
                onUpdateSearch?.({
                  q: undefined,
                  kind: undefined,
                  scope: undefined,
                  signal: undefined,
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
              <GrdrIcon name="file-code" size={16} />
              <Heading level={2}>{`Skills, rules & plugins (${totalArtifactsCount})`}</Heading>
            </HStack>
            <Text size="sm" color="secondary" className="tabular">
              {formatRangeLabel(startIdx, Math.max(pagedArtifacts.length, 1), totalArtifactsCount)}
            </Text>
          </HStack>

          {pagedArtifacts.length === 0 && !artifactPage.loading ? (
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

          <CursorPagerBar
            pageIndex={artifactPage.pageIndex}
            pageSize={artifactPage.pageSize}
            itemCount={pagedArtifacts.length}
            pageInfo={artifactPage.pageInfo}
            label="Skills and rules pagination"
            onNext={artifactPage.goNext}
            onPrev={artifactPage.goPrev}
            onPageSizeChange={artifactPage.setPageSize}
          />
        </VStack>
      </Card>
    </VStack>
  );
}
