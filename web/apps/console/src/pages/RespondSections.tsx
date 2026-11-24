import { useMemo, useState } from "react";
import {
  api,
  type ApprovalRequest,
  type Device,
  type GrantScope,
  type Incident,
} from "@grdr/api";
import { capitalizeLabel, presentIncidentSummary } from "@grdr/i18n";
import { ApprovalCard, EntityLink, type EntityTarget, SessionLabelBadge } from "@grdr/kit";
import {
  Badge,
  Banner,
  Button,
  Card,
  GrdrIcon,
  GrdrSelect,
  Heading,
  HStack,
  Text,
  VStack,
} from "@grdr/ui";
import { CursorPagerBar } from "../components/PagerBar";
import { aipQuote, useServerPage } from "../components/useServerPage";
import type { ConsoleSearchParams } from "../searchSchema";

function deviceOsFor(devices: Device[], deviceId: string, deviceName: string): string | undefined {
  return devices.find((d) => d.id === deviceId || d.hostname === deviceName)?.os;
}

export function PendingApprovalsSection({
  devices,
  refreshKey,
  urlSearch,
  onUpdateSearch,
  onAllow,
  onDeny,
  onOpenEntity,
}: {
  devices: Device[];
  refreshKey: number;
  urlSearch?: ConsoleSearchParams;
  onUpdateSearch?: (patch: Partial<ConsoleSearchParams>) => void;
  onAllow: (id: string, scope: GrantScope) => Promise<void>;
  onDeny: (id: string) => Promise<void>;
  onOpenEntity?: (target: EntityTarget) => void;
}) {
  const approvalsPage = useServerPage<ApprovalRequest>(
    api.listApprovalsPage,
    'status = "pending"',
    "requested_at desc",
    25,
    refreshKey,
    onUpdateSearch
      ? {
          resource: "approvalsPage",
          pageToken: urlSearch?.approvalsPageToken ?? "",
          pageIndex: urlSearch?.approvalsPage ?? 0,
          pageSize: urlSearch?.pageSize ?? 25,
          onPageChange: ({ pageToken, pageIndex }) =>
            onUpdateSearch({
              approvalsPageToken: pageToken || undefined,
              approvalsPage: pageIndex > 0 ? pageIndex : undefined,
            }),
          onPageSizeChange: (nextSize) =>
            onUpdateSearch({
              pageSize: nextSize === 25 ? undefined : nextSize,
              approvalsPageToken: undefined,
              approvalsPage: undefined,
            }),
        }
      : { resource: "approvalsPage" },
  );
  const pending = approvalsPage.items;
  const totalCount = approvalsPage.pageInfo.total_size_estimate || pending.length;

  return (
    <Card padding={3}>
      <VStack gap={3}>
        <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
          <HStack gap={2} align="center">
            <GrdrIcon name="hand" size={16} />
            <Heading level={2}>{`Pending approval queue (${totalCount})`}</Heading>
          </HStack>
          <Badge variant="warning" label="1s hold to confirm" />
        </HStack>

        {approvalsPage.error && (
          <Banner status="error" title={approvalsPage.error} collapsible={false} />
        )}

        {pending.length === 0 ? (
          <Text color="secondary">
            {approvalsPage.loading
              ? "Loading pending approval requests..."
              : "No pending approval requests right now."}
          </Text>
        ) : (
          <VStack gap={2}>
            {pending.map((req) => (
              <ApprovalCard
                key={req.id}
                id={req.id}
                ruleId={req.rule_id}
                ruleTitle={req.rule_title}
                requiredGrade={req.required_grade}
                agentName={req.agent_name}
                actionClass={req.action_class}
                deviceId={req.device_id}
                deviceName={req.device_name}
                deviceOs={deviceOsFor(devices, req.device_id, req.device_name)}
                target={req.target}
                reason={req.reason}
                onAllow={onAllow}
                onDeny={onDeny}
                onOpenEntity={onOpenEntity}
              />
            ))}
          </VStack>
        )}

        <CursorPagerBar
          pageIndex={approvalsPage.pageIndex}
          pageSize={approvalsPage.pageSize}
          itemCount={pending.length}
          pageInfo={approvalsPage.pageInfo}
          label="Approvals pagination"
          onNext={approvalsPage.goNext}
          onPrev={approvalsPage.goPrev}
          onPageSizeChange={approvalsPage.setPageSize}
        />
      </VStack>
    </Card>
  );
}

export function CorrelatedIncidentsSection({
  devices,
  refreshKey,
  urlSearch,
  onUpdateSearch,
  exportedMessage,
  onExportOcsf,
  onExportAuditJsonl,
  onOpenEntity,
}: {
  devices: Device[];
  refreshKey: number;
  urlSearch?: ConsoleSearchParams;
  onUpdateSearch?: (patch: Partial<ConsoleSearchParams>) => void;
  exportedMessage?: string;
  onExportOcsf: () => Promise<void>;
  onExportAuditJsonl: () => Promise<void>;
  onOpenEntity?: (target: EntityTarget) => void;
}) {
  const [fallbackSeverity, setFallbackSeverity] = useState("all");
  const severityFilter = urlSearch?.incidentSeverity ?? fallbackSeverity;
  const setSeverityFilter = (next: string) => {
    setFallbackSeverity(next);
    onUpdateSearch?.({
      incidentSeverity: next === "all" ? undefined : next,
      incidentsPageToken: undefined,
      incidentsPage: undefined,
    });
  };

  const aipFilter = useMemo(
    () => (severityFilter === "all" ? "" : `severity = ${aipQuote(severityFilter)}`),
    [severityFilter],
  );
  const incidentsPage = useServerPage<Incident>(
    api.listIncidentsPage,
    aipFilter,
    "last_seen desc",
    25,
    refreshKey,
    onUpdateSearch
      ? {
          resource: "incidentsPage",
          pageToken: urlSearch?.incidentsPageToken ?? "",
          pageIndex: urlSearch?.incidentsPage ?? 0,
          pageSize: urlSearch?.pageSize ?? 25,
          onPageChange: ({ pageToken, pageIndex }) =>
            onUpdateSearch({
              incidentsPageToken: pageToken || undefined,
              incidentsPage: pageIndex > 0 ? pageIndex : undefined,
            }),
          onPageSizeChange: (nextSize) =>
            onUpdateSearch({
              pageSize: nextSize === 25 ? undefined : nextSize,
              incidentsPageToken: undefined,
              incidentsPage: undefined,
            }),
        }
      : { resource: "incidentsPage" },
  );
  const incidents = incidentsPage.items;
  const totalCount = incidentsPage.pageInfo.total_size_estimate || incidents.length;

  return (
    <Card padding={3}>
      <VStack gap={3}>
        <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 10 }}>
          <VStack gap={1}>
            <HStack gap={2} align="center">
              <GrdrIcon name="layers" size={16} />
              <Heading level={2}>{`Correlated incidents (${totalCount})`}</Heading>
            </HStack>
            <Text color="secondary">
              Findings merged by session lineage, device, and enforcing labels. Export structured telemetry for SIEM ingestion.
            </Text>
          </VStack>
          <HStack gap={2} align="center" style={{ flexWrap: "wrap" }}>
            <GrdrSelect
              label="Incident severity"
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
            <Button
              label="Export OCSF 1.9"
              icon={<GrdrIcon name="file-json" size={14} />}
              onClick={() => void onExportOcsf()}
            />
            <Button
              label="Export Audit JSONL"
              icon={<GrdrIcon name="download" size={14} />}
              onClick={() => void onExportAuditJsonl()}
            />
          </HStack>
        </HStack>

        {exportedMessage && <Banner status="info" title={exportedMessage} collapsible={false} />}
        {incidentsPage.error && (
          <Banner status="error" title={incidentsPage.error} collapsible={false} />
        )}

        {incidents.length === 0 ? (
          <Text color="secondary">
            {incidentsPage.loading ? "Loading correlated incidents..." : "No correlated incidents recorded."}
          </Text>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Incident</th>
                  <th>Session & device</th>
                  <th>Labels</th>
                  <th>Severity</th>
                  <th>Lifecycle</th>
                </tr>
              </thead>
              <tbody>
                {incidents.map((inc) => (
                  <tr key={inc.id}>
                    <td>
                      <VStack gap={1}>
                        <strong>{inc.title}</strong>
                        <Text type="supporting" color="secondary" size="sm">
                          {presentIncidentSummary(inc.summary)}
                        </Text>
                      </VStack>
                    </td>
                    <td>
                      <VStack gap={1}>
                        <EntityLink
                          kind="session"
                          id={inc.session_id}
                          label={inc.session_id}
                          compact
                          onSelect={onOpenEntity}
                        />
                        <HStack gap={1} align="center" style={{ flexWrap: "wrap", columnGap: 6, rowGap: 2 }}>
                          <EntityLink kind="agent" label={inc.agent_name} compact onSelect={onOpenEntity} />
                          <span style={{ color: "var(--ink-muted)" }}>on</span>
                          <EntityLink
                            kind="device"
                            id={inc.device_id}
                            label={inc.device_name}
                            os={deviceOsFor(devices, inc.device_id, inc.device_name)}
                            compact
                            onSelect={onOpenEntity}
                          />
                        </HStack>
                      </VStack>
                    </td>
                    <td>
                      {inc.labels.length === 0 ? (
                        <Text color="secondary" size="sm">
                          None
                        </Text>
                      ) : (
                        <HStack gap={1}>
                          {inc.labels.map((lbl) => (
                            <SessionLabelBadge key={lbl} label={lbl} />
                          ))}
                        </HStack>
                      )}
                    </td>
                    <td>
                      <Badge
                        variant={inc.severity === "critical" || inc.severity === "high" ? "error" : "warning"}
                        icon={
                          <GrdrIcon
                            name={
                              inc.severity === "critical"
                                ? "alert-octagon"
                                : inc.severity === "high"
                                  ? "alert-triangle"
                                  : "alert-circle"
                            }
                            size={11}
                          />
                        }
                        label={capitalizeLabel(inc.severity)}
                      />
                    </td>
                    <td>
                      <Badge
                        variant={inc.lifecycle === "resolved" ? "success" : "info"}
                        icon={
                          <GrdrIcon
                            name={inc.lifecycle === "resolved" ? "check-circle" : "circle"}
                            size={11}
                          />
                        }
                        label={capitalizeLabel(inc.lifecycle)}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <CursorPagerBar
          pageIndex={incidentsPage.pageIndex}
          pageSize={incidentsPage.pageSize}
          itemCount={incidents.length}
          pageInfo={incidentsPage.pageInfo}
          label="Incidents pagination"
          onNext={incidentsPage.goNext}
          onPrev={incidentsPage.goPrev}
          onPageSizeChange={incidentsPage.setPageSize}
        />
      </VStack>
    </Card>
  );
}
