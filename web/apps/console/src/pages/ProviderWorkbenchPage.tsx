import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, type ProviderWorkspaceResponse } from "@grdr/api";
import {
  Badge,
  Banner,
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
import { consoleQueryKeys } from "../queries";

type ProviderPhase =
  | { kind: "idle" }
  | { kind: "busy" }
  | { kind: "ok"; message: string }
  | { kind: "error"; message: string };

export function ProviderWorkbenchPage({
  onChanged,
}: {
  onChanged?: () => Promise<void>;
}) {
  const [orgSet, setOrgSet] = useState("all");
  const [promoteVer, setPromoteVer] = useState("1.3.0");
  const [reason, setReason] = useState("Cross-org incident inspection");
  const [phase, setPhase] = useState<ProviderPhase>({ kind: "idle" });

  const provQuery = useQuery<ProviderWorkspaceResponse>({
    queryKey: consoleQueryKeys.providerWorkspace(orgSet),
    queryFn: () => api.getProviderWorkspace(orgSet),
  });

  const ws = provQuery.data;

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
            <div style={{ minWidth: 200 }}>
              <GrdrSelect
                label="Org set"
                value={orgSet}
                onChange={setOrgSet}
                options={[
                  { value: "all", label: "All org sets" },
                  { value: "global-enterprise", label: "Global Enterprise" },
                  { value: "eu-works-council", label: "EU Works Council" },
                  { value: "apac-partners", label: "APAC Partners" },
                ]}
              />
            </div>
          </HStack>

          <div className="grid-2">
            <TextInput
              label="Acting-as audit reason"
              value={reason}
              onChange={setReason}
            />
            <TextInput
              label="Floor pack version for ring promotion"
              value={promoteVer}
              onChange={setPromoteVer}
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
          <Heading level={2}>Managed organizations</Heading>
          <div className="table-wrap">
            <table className="table responsive-table">
              <thead>
                <tr>
                  <th>Organization</th>
                  <th>Org set</th>
                  <th>Ring</th>
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
                      <td data-label="Coverage" className="tabular">{`${org.coverage_pct}%`}</td>
                      <td data-label="Findings" className="tabular">{org.open_findings}</td>
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
        </VStack>
      </Card>

      <Card padding={3}>
        <VStack gap={2}>
          <Heading level={2}>Delegated rollout rings</Heading>
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
                        label={ring.health_state}
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
                    isDisabled={phase.kind === "busy"}
                    onClick={() => void advanceRing(ring.ring)}
                  />
                </HStack>
              </Card>
            ))}
          </div>
        </VStack>
      </Card>
    </VStack>
  );
}
