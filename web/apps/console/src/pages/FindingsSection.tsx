import { useMemo, useState } from "react";
import {
  api,
  type Device,
  type Finding,
  type FindingLifecycle,
} from "@grdr/api";
import { capitalizeLabel, presentFindingTitle } from "@grdr/i18n";
import { EntityLink, type EntityTarget, Quoted } from "@grdr/kit";
import {
  Banner,
  Button,
  Card,
  GrdrIcon,
  GrdrSelect,
  Heading,
  HStack,
  StatusInline,
  Text,
  VStack,
} from "@grdr/ui";
import { CursorPagerBar } from "../components/PagerBar";
import { aipQuote, useServerPage } from "../components/useServerPage";
import type { ConsoleSearchParams } from "../searchSchema";

function deviceOsFor(devices: Device[], deviceId: string, deviceName: string): string | undefined {
  return devices.find((d) => d.id === deviceId || d.hostname === deviceName)?.os;
}

export function FindingsSection({
  devices,
  refreshKey,
  urlSearch,
  onUpdateSearch,
  onUpdateLifecycle,
  onOpenEntity,
  onOpenSessionTurn,
  onExplainReceipt,
}: {
  devices: Device[];
  refreshKey: number;
  urlSearch?: ConsoleSearchParams;
  onUpdateSearch?: (patch: Partial<ConsoleSearchParams>) => void;
  onUpdateLifecycle: (id: string, lifecycle: FindingLifecycle) => Promise<void>;
  onOpenEntity?: (target: EntityTarget) => void;
  onOpenSessionTurn?: (sessionId: string, turnIndex: number) => void;
  onExplainReceipt?: (reference: string) => void;
}) {
  const [fallbackSeverity, setFallbackSeverity] = useState("all");
  const [fallbackLifecycle, setFallbackLifecycle] = useState("all");

  const severityFilter = urlSearch?.findingSeverity ?? fallbackSeverity;
  const lifecycleFilter = urlSearch?.findingLifecycle ?? fallbackLifecycle;

  const setSeverityFilter = (next: string) => {
    setFallbackSeverity(next);
    onUpdateSearch?.({
      findingSeverity: next === "all" ? undefined : next,
      findingsPageToken: undefined,
      findingsPage: undefined,
    });
  };
  const setLifecycleFilter = (next: string) => {
    setFallbackLifecycle(next);
    onUpdateSearch?.({
      findingLifecycle: next === "all" ? undefined : next,
      findingsPageToken: undefined,
      findingsPage: undefined,
    });
  };

  const aipFilter = useMemo(() => {
    const clauses: string[] = [];
    if (severityFilter !== "all") clauses.push(`severity = ${aipQuote(severityFilter)}`);
    if (lifecycleFilter !== "all") clauses.push(`lifecycle = ${aipQuote(lifecycleFilter)}`);
    return clauses.join(" AND ");
  }, [severityFilter, lifecycleFilter]);

  const findingsPage = useServerPage<Finding>(
    api.listFindingsPage,
    aipFilter,
    "detected_at desc",
    25,
    refreshKey,
    onUpdateSearch
      ? {
          resource: "findingsPage",
          pageToken: urlSearch?.findingsPageToken ?? "",
          pageIndex: urlSearch?.findingsPage ?? 0,
          pageSize: urlSearch?.pageSize ?? 25,
          onPageChange: ({ pageToken, pageIndex }) =>
            onUpdateSearch({
              findingsPageToken: pageToken || undefined,
              findingsPage: pageIndex > 0 ? pageIndex : undefined,
            }),
          onPageSizeChange: (nextSize) =>
            onUpdateSearch({
              pageSize: nextSize === 25 ? undefined : nextSize,
              findingsPageToken: undefined,
              findingsPage: undefined,
            }),
        }
      : { resource: "findingsPage" },
  );
  const findings = findingsPage.items;
  const totalCount = findingsPage.pageInfo.total_size_estimate || findings.length;

  return (
    <Card padding={3}>
      <VStack gap={3}>
        <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 10 }}>
          <Heading level={2}>{`Findings (${totalCount})`}</Heading>
          <HStack gap={2} align="center" style={{ flexWrap: "wrap" }}>
            <GrdrSelect
              label="Finding severity"
              isLabelHidden
              size="sm"
              value={severityFilter}
              options={[
                { value: "all", label: "All severities" },
                { value: "critical", label: "Critical" },
                { value: "high", label: "High" },
                { value: "medium", label: "Medium" },
                { value: "low", label: "Low" },
              ]}
              onChange={setSeverityFilter}
              width={150}
            />
            <GrdrSelect
              label="Finding status"
              isLabelHidden
              size="sm"
              value={lifecycleFilter}
              options={[
                { value: "all", label: "All statuses" },
                { value: "open", label: "Open" },
                { value: "acknowledged", label: "Acknowledged" },
                { value: "contained", label: "Contained" },
                { value: "resolved", label: "Resolved" },
              ]}
              onChange={setLifecycleFilter}
              width={150}
            />
          </HStack>
        </HStack>

        {findingsPage.error && (
          <Banner status="error" title={findingsPage.error} collapsible={false} />
        )}

        {findings.length === 0 ? (
          <Text color="secondary">
            {findingsPage.loading ? "Loading findings..." : "No findings match the active filters."}
          </Text>
        ) : (
          <div className="table-wrap">
            <table className="responsive-table">
              <thead>
                <tr>
                  <th>Finding</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Transition</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f) => {
                  const titleText = presentFindingTitle(f.title, f.agent_name);
                  return (
                    <tr key={f.id}>
                      <td data-label="Finding">
                        <VStack gap={1}>
                          <strong>{titleText}</strong>
                          <HStack gap={1} align="center" style={{ flexWrap: "wrap", columnGap: 6, rowGap: 2 }}>
                            <EntityLink kind="agent" label={f.agent_name} compact onSelect={onOpenEntity} />
                            <span style={{ color: "var(--ink-muted)" }}>on</span>
                            <EntityLink
                              kind="device"
                              id={f.device_id}
                              label={f.device_name}
                              os={deviceOsFor(devices, f.device_id, f.device_name)}
                              compact
                              onSelect={onOpenEntity}
                            />
                            {f.rule_id && (
                              <>
                                <span style={{ color: "var(--ink-muted)" }} aria-hidden="true">·</span>
                                <EntityLink
                                  kind="rule"
                                  id={f.rule_id}
                                  label={f.rule_id}
                                  compact
                                  onSelect={onOpenEntity}
                                />
                              </>
                            )}
                          </HStack>
                          <Quoted text={f.target} />
                        </VStack>
                      </td>
                      <td data-label="Severity">
                        <StatusInline
                          tone={f.severity === "critical" || f.severity === "high" ? "block" : "ask"}
                          dot
                          label={capitalizeLabel(f.severity)}
                        />
                      </td>
                      <td data-label="Status">
                        <StatusInline
                          tone={f.lifecycle === "resolved" ? "allow" : "neutral"}
                          dot
                          label={capitalizeLabel(f.lifecycle)}
                        />
                      </td>
                      <td data-label="Transition">
                        <HStack gap={1} style={{ flexWrap: "wrap" }}>
                          {onExplainReceipt && (
                            <Button
                              size="sm"
                              variant="ghost"
                              icon={<GrdrIcon name="info" size={12} />}
                              label="Why?"
                              onClick={() => onExplainReceipt(f.id)}
                            />
                          )}
                          {onOpenSessionTurn && (
                            <Button
                              size="sm"
                              variant="ghost"
                              icon={<GrdrIcon name="route" size={12} />}
                              label="Inspect trace"
                              onClick={() => onOpenSessionTurn(f.session_id, 1)}
                            />
                          )}
                          {f.lifecycle === "open" && (
                            <Button
                              size="sm"
                              label="Acknowledge"
                              onClick={() => void onUpdateLifecycle(f.id, "acknowledged")}
                            />
                          )}
                          {f.lifecycle !== "resolved" && (
                            <Button
                              size="sm"
                              label="Resolve"
                              icon={<GrdrIcon name="check" size={12} />}
                              onClick={() => void onUpdateLifecycle(f.id, "resolved")}
                            />
                          )}
                        </HStack>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        <CursorPagerBar
          pageIndex={findingsPage.pageIndex}
          pageSize={findingsPage.pageSize}
          itemCount={findings.length}
          pageInfo={findingsPage.pageInfo}
          label="Findings pagination"
          onNext={findingsPage.goNext}
          onPrev={findingsPage.goPrev}
          onPageSizeChange={findingsPage.setPageSize}
        />
      </VStack>
    </Card>
  );
}
