// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, type ProviderWorkspaceResponse } from "@grdr/api";
import { capitalizeLabel } from "@grdr/i18n";
import {
  Badge,
  Banner,
  Button,
  Card,
  EmptyState,
  GrdrIcon,
  GrdrSelect,
  Heading,
  HStack,
  StatusInline,
  Text,
  TextInput,
  VStack,
} from "@grdr/ui";
import { consoleQueryKeys } from "../queries";

type ProviderPhase =
  | { kind: "idle" }
  | { kind: "busy" }
  | { kind: "ok"; message: string }
  | { kind: "error"; message: string };

function formatOrgSetLabel(orgSet: string): string {
  return orgSet
    .split(/[-_]+/)
    .filter(Boolean)
    .map((part) => capitalizeLabel(part))
    .join(" ");
}

export function ProviderWorkbenchPage({
  onChanged,
}: {
  onChanged?: () => Promise<void>;
}) {
  const [orgSet, setOrgSet] = useState("all");
  const [knownOrgSets, setKnownOrgSets] = useState<string[]>([]);
  const [customPromoteVer, setCustomPromoteVer] = useState<string | null>(null);
  const [reason, setReason] = useState("Cross-org incident inspection");
  const [phase, setPhase] = useState<ProviderPhase>({ kind: "idle" });

  const provQuery = useQuery<ProviderWorkspaceResponse>({
    queryKey: consoleQueryKeys.providerWorkspace(orgSet),
    queryFn: () => api.getProviderWorkspace(orgSet),
  });

  const ws = provQuery.data;

  useEffect(() => {
    if (!ws?.orgs.length) return;
    const nextSets = Array.from(new Set(ws.orgs.map((o) => o.org_set).filter(Boolean))).sort();
    setKnownOrgSets((prev) => Array.from(new Set([...prev, ...nextSets])).sort());
  }, [ws]);

  const promoteVer = customPromoteVer ?? ws?.rings[0]?.target_version ?? "";
  const orgSetOptions = [
    { value: "all", label: "All org sets" },
    ...knownOrgSets.map((setName) => ({
      value: setName,
      label: formatOrgSetLabel(setName),
    })),
  ];

  async function actAs(orgId: string | null) {
    setPhase({ kind: "busy" });
    try {
      const res = await api.switchProviderOrg({
        org_id: orgId,
        reason,
      });
      setPhase({
        kind: "ok",
        message: res.acting_as_org_name
          ? `Acting as ${res.acting_as_org_name} (${res.acting_as_reason ?? "scoped"}).`
          : "Exited acting-as tenant scope.",
      });
      await provQuery.refetch();
      await onChanged?.();
    } catch (e) {
      setPhase({
        kind: "error",
        message: e instanceof Error ? e.message : "Failed switching organization scope",
      });
    }
  }

  async function advanceRing(ring: string) {
    setPhase({ kind: "busy" });
    try {
      const res = await api.advanceProviderRing({
        ring,
        target_version: promoteVer,
      });
      setPhase({
        kind: "ok",
        message: `Promoted ${res.ring} ring to safety floor v${res.target_version}.`,
      });
      await provQuery.refetch();
      await onChanged?.();
    } catch (e) {
      setPhase({
        kind: "error",
        message: e instanceof Error ? e.message : "Failed promoting rollout ring",
      });
    }
  }

  return (
    <VStack gap={4}>
      {provQuery.isError && (
        <Banner
          status="error"
          title={
            provQuery.error instanceof Error
              ? provQuery.error.message
              : "Failed loading provider workbench."
          }
          collapsible={false}
          endContent={
            <Button
              variant="secondary"
              size="sm"
              label="Retry"
              onClick={() => void provQuery.refetch()}
            />
          }
        />
      )}

      {ws?.acting_as_org_id && (
        <Banner
          status="warning"
          title={`Acting as ${ws.acting_as_org_name ?? ws.acting_as_org_id}: ${ws.acting_as_reason ?? "Audited MSP session"}`}
          collapsible={false}
          endContent={
            <Button
              variant="secondary"
              size="sm"
              label="Exit acting-as"
              onClick={() => void actAs(null)}
            />
          }
        />
      )}

      <Card padding={3}>
        <VStack gap={3}>
          <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
            <VStack gap={0}>
              <Heading level={1}>Provider workbench</Heading>
              <Text size="sm" color="secondary">
                Multi-organization queue, org set filtering, delegated rollout rings, and audited acting-as isolation.
              </Text>
            </VStack>
            <div style={{ minWidth: 200, maxWidth: "100%" }}>
              <GrdrSelect
                label="Org set"
                value={orgSet}
                onChange={setOrgSet}
                options={orgSetOptions}
              />
            </div>
          </HStack>

          <div className="grid-2">
            <TextInput label="Acting-as audit reason" value={reason} onChange={setReason} />
            <TextInput
              label="Floor pack version for ring promotion"
              value={promoteVer}
              onChange={(val) => setCustomPromoteVer(val)}
            />
          </div>

          {phase.kind === "ok" && (
            <Banner status="success" title={phase.message} collapsible={false} />
          )}
          {phase.kind === "error" && (
            <Banner status="error" title={phase.message} collapsible={false} />
          )}
        </VStack>
      </Card>

      <Card padding={3}>
        <VStack gap={2}>
          <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
            <Heading level={2}>Managed organizations</Heading>
            <Badge variant="neutral" label={`${ws?.orgs.length ?? 0} orgs`} />
          </HStack>
          {provQuery.isLoading ? (
            <Text size="sm" color="secondary">
              Loading managed organizations...
            </Text>
          ) : (ws?.orgs.length ?? 0) === 0 ? (
            <EmptyState
              title="No managed organizations registered"
              description="Provision tenant organizations in the Operator Portal to manage delegated rollout rings and acting-as sessions."
              icon={<GrdrIcon name="layers" size={20} />}
            />
          ) : (
            <div className="table-wrap">
              <table className="table responsive-table">
                <thead>
                  <tr>
                    <th>Organization</th>
                    <th>Org set</th>
                    <th>Ring</th>
                    <th>Status</th>
                    <th>Devices</th>
                    <th>Coverage</th>
                    <th>Findings</th>
                    <th>Floor</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {(ws?.orgs ?? []).map((org) => {
                    const isActive = ws?.acting_as_org_id === org.org_id;
                    return (
                      <tr key={org.org_id}>
                        <td data-label="Organization">
                          <VStack gap={0}>
                            <Text size="sm" weight="semibold">
                              {org.name}
                            </Text>
                            <Text size="sm" color="secondary" className="mono">
                              {org.org_id}
                            </Text>
                          </VStack>
                        </td>
                        <td data-label="Org set">{org.org_set}</td>
                        <td data-label="Ring">
                          <Badge variant="info" label={org.ring} />
                        </td>
                        <td data-label="Status">
                          <StatusInline
                            tone={
                              org.status === "healthy"
                                ? "allow"
                                : org.status === "attention"
                                  ? "ask"
                                  : "block"
                            }
                            dot
                            label={capitalizeLabel(org.status)}
                          />
                        </td>
                        <td data-label="Devices" className="tabular">
                          {org.devices_count}
                        </td>
                        <td data-label="Coverage" className="tabular">{`${org.coverage_pct}%`}</td>
                        <td data-label="Findings" className="tabular">
                          {`${org.open_findings} (${org.pending_approvals} ask)`}
                        </td>
                        <td data-label="Floor" className="mono">{`v${org.floor_version}`}</td>
                        <td data-label="Action">
                          <Button
                            variant={isActive ? "primary" : "secondary"}
                            size="sm"
                            isDisabled={phase.kind === "busy"}
                            label={isActive ? "Exit scope" : "Act as org"}
                            onClick={() => void actAs(isActive ? null : org.org_id)}
                          />
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </VStack>
      </Card>

      <Card padding={3}>
        <VStack gap={2}>
          <Heading level={2}>Delegated rollout rings</Heading>
          {(ws?.rings.length ?? 0) === 0 ? (
            <EmptyState
              title="No rollout rings configured"
              description="Delegated policy floor rings appear here once organizations are assigned to release rings."
              icon={<GrdrIcon name="layers" size={20} />}
            />
          ) : (
            <div className="grid-2">
              {(ws?.rings ?? []).map((ring) => (
                <Card key={ring.ring} padding={2}>
                  <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
                    <VStack gap={0}>
                      <HStack gap={2} align="center">
                        <GrdrIcon name="layers" size={14} />
                        <Heading level={3}>{ring.ring}</Heading>
                        <StatusInline
                          tone={ring.health_state === "healthy" ? "allow" : "ask"}
                          label={capitalizeLabel(ring.health_state.replace(/_/g, " "))}
                        />
                      </HStack>
                      <Text size="sm" color="secondary">
                        {`v${ring.target_version} · ${ring.org_count} orgs · ${ring.soak_hours}h soak`}
                      </Text>
                    </VStack>
                    <Button
                      variant="secondary"
                      size="sm"
                      label="Promote ring"
                      isDisabled={phase.kind === "busy" || promoteVer.trim() === ""}
                      onClick={() => void advanceRing(ring.ring)}
                    />
                  </HStack>
                </Card>
              ))}
            </div>
          )}
        </VStack>
      </Card>
    </VStack>
  );
}
