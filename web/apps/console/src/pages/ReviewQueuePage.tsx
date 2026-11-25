import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, type Device, type ReviewBucket, type ReviewCluster, type ReviewQueueResponse } from "@grdr/api";
import { formatTimestamp, pluralize, presentFindingTitle } from "@grdr/i18n";
import { EntityLink, type EntityTarget, ModeBadge, Quoted } from "@grdr/kit";
import {
  Badge,
  Banner,
  Button,
  Card,
  EmptyState,
  GrdrIcon,
  Heading,
  HStack,
  Text,
  TextInput,
  UiSdkSegmentedControl,
  VStack,
} from "@grdr/ui";
import { consoleQueryKeys } from "../queries";

type QueuePhase =
  | { kind: "idle" }
  | { kind: "busy"; clusterId: string }
  | { kind: "ok"; message: string }
  | { kind: "error"; message: string };

function bucketBadge(bucket: ReviewBucket): { label: string; variant: "warning" | "info" | "neutral" } {
  switch (bucket) {
    case "worth_a_look":
      return { label: "Worth a look", variant: "warning" };
    case "routine":
      return { label: "Routine", variant: "info" };
    case "noise":
      return { label: "Noise", variant: "neutral" };
  }
}

export function ReviewQueuePage({
  devices,
  onOpenEntity,
  onExplainReceipt,
  onChanged,
}: {
  devices: Device[];
  onOpenEntity?: (target: EntityTarget) => void;
  onExplainReceipt?: (reference: string) => void;
  onChanged?: () => Promise<void>;
}) {
  const [bucket, setBucket] = useState<"all" | ReviewBucket>("all");
  const [search, setSearch] = useState("");
  const [phase, setPhase] = useState<QueuePhase>({ kind: "idle" });

  const queueQuery = useQuery<ReviewQueueResponse>({
    queryKey: consoleQueryKeys.reviewQueue({ bucket, search }),
    queryFn: () => api.listReviewQueue(bucket, search),
  });

  const data = queueQuery.data;
  const clusters = data?.clusters ?? [];

  async function decide(
    cluster: ReviewCluster,
    decision: "promote" | "suppress" | "dismiss" | "escalate",
  ) {
    setPhase({ kind: "busy", clusterId: cluster.id });
    try {
      await api.decideReviewCluster({
        id: cluster.id,
        decision,
        target_mode: decision === "promote" ? cluster.suggested_mode : undefined,
        note: `${decision} from Review Queue`,
      });
      setPhase({
        kind: "ok",
        message: `Recorded decision (${decision}) for ${cluster.rule_title}.`,
      });
      await queueQuery.refetch();
      await onChanged?.();
    } catch (e) {
      setPhase({
        kind: "error",
        message: e instanceof Error ? e.message : "Failed applying review triage decision",
      });
    }
  }

  return (
    <VStack gap={4}>
      <Card padding={3}>
        <VStack gap={3}>
          <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
            <VStack gap={0}>
              <Heading level={1}>Review queue</Heading>
              <Text size="sm" color="secondary">
                Clustered by rule, observable digest, and agent type. Promote candidates or quiet routine noise.
              </Text>
            </VStack>
            <HStack gap={2} style={{ flexWrap: "wrap" }}>
              <Badge variant="warning" label={`${data?.worth_a_look_count ?? 0} worth a look`} />
              <Badge variant="info" label={`${data?.routine_count ?? 0} routine`} />
              <Badge variant="neutral" label={`${data?.noise_count ?? 0} noise`} />
            </HStack>
          </HStack>

          <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 10 }}>
            <UiSdkSegmentedControl
              ariaLabel="Review queue buckets"
              value={bucket}
              onChange={(next) => setBucket(next)}
              options={[
                { value: "all", label: "All" },
                { value: "worth_a_look", label: "Worth a look" },
                { value: "routine", label: "Routine" },
                { value: "noise", label: "Noise" },
              ]}
            />
            <div style={{ minWidth: 220, flex: "1 1 240px", maxWidth: 340 }}>
              <TextInput
                label="Filter clusters"
                isLabelHidden
                placeholder="Search rule, agent, target..."
                value={search}
                onChange={(val) => setSearch(val)}
              />
            </div>
            {(bucket !== "all" || search.trim() !== "") && (
              <Button
                variant="ghost"
                size="sm"
                icon={<GrdrIcon name="x" size={13} />}
                label="Reset filters"
                onClick={() => {
                  setBucket("all");
                  setSearch("");
                }}
              />
            )}
          </HStack>

          {phase.kind === "ok" && (
            <Banner status="success" title={phase.message} collapsible={false} />
          )}
          {phase.kind === "error" && (
            <Banner status="error" title={phase.message} collapsible={false} />
          )}
        </VStack>
      </Card>

      {clusters.length === 0 ? (
        <Card padding={3}>
          <EmptyState
            title="No matching review clusters"
            description="Adjust the bucket filter or search query to inspect earlier events."
            icon={<GrdrIcon name="list" size={24} />}
            actions={
              bucket !== "all" || search.trim() !== "" ? (
                <Button
                  variant="secondary"
                  size="sm"
                  label="Reset filters"
                  onClick={() => {
                    setBucket("all");
                    setSearch("");
                  }}
                />
              ) : undefined
            }
          />
        </Card>
      ) : (
        <VStack gap={3}>
          {clusters.map((cluster) => {
            const meta = bucketBadge(cluster.bucket);
            const clusterTitle = presentFindingTitle(cluster.rule_title, cluster.agent_name);
            const devOs = devices.find(
              (d) => d.id === cluster.device_id || d.hostname === cluster.device_name,
            )?.os;
            const isBusy = phase.kind === "busy" && phase.clusterId === cluster.id;

            return (
              <Card key={cluster.id} padding={3}>
                <VStack gap={2}>
                  <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
                    <HStack gap={2} align="center" style={{ flexWrap: "wrap" }}>
                      <Badge variant={meta.variant} label={meta.label} />
                      <Badge variant="neutral" label={`Score ${cluster.score}`} />
                      <Heading level={3}>{clusterTitle}</Heading>
                    </HStack>
                    <HStack gap={2} align="center">
                      <Badge
                        variant={cluster.status === "open" ? "neutral" : "success"}
                        label={cluster.status}
                      />
                      <Text size="sm" color="secondary" className="mono">
                        {`#${cluster.observable_digest}`}
                      </Text>
                    </HStack>
                  </HStack>

                  <HStack gap={2} align="center" style={{ flexWrap: "wrap" }}>
                    <EntityLink
                      kind="rule"
                      id={cluster.rule_id}
                      label={cluster.rule_id}
                      compact
                      onSelect={onOpenEntity}
                    />
                    <EntityLink
                      kind="agent"
                      label={cluster.agent_name}
                      compact
                      onSelect={onOpenEntity}
                    />
                    <EntityLink
                      kind="device"
                      id={cluster.device_id}
                      label={cluster.device_name}
                      os={devOs}
                      compact
                      onSelect={onOpenEntity}
                    />
                    <EntityLink
                      kind="session"
                      id={cluster.session_id}
                      label={cluster.session_id}
                      compact
                      onSelect={onOpenEntity}
                    />
                    <Text size="sm" color="secondary" hasTabularNumbers>
                      {pluralize(cluster.occurrence_count, "hit")}
                    </Text>
                  </HStack>

                  <HStack gap={2} align="center" style={{ flexWrap: "wrap" }}>
                    <Quoted text={cluster.target_preview} />
                    <ModeBadge mode={cluster.current_mode} />
                    {cluster.suggested_mode !== cluster.current_mode && (
                      <>
                        <GrdrIcon name="arrow-right" size={12} color="var(--ink-muted)" />
                        <ModeBadge mode={cluster.suggested_mode} />
                      </>
                    )}
                    <Text size="sm" color="secondary">
                      {cluster.risk_label}
                    </Text>
                  </HStack>

                  <Text size="sm" color="secondary">
                    {cluster.reason}
                  </Text>

                  <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
                    <Text size="sm" color="secondary" hasTabularNumbers>
                      {formatTimestamp(cluster.latest_timestamp)}
                    </Text>
                    <HStack gap={2} style={{ flexWrap: "wrap" }}>
                      {onExplainReceipt && (
                        <Button
                          variant="ghost"
                          size="sm"
                          label="Why?"
                          onClick={() => onExplainReceipt(cluster.receipt_ref)}
                        />
                      )}
                      <Button
                        variant="secondary"
                        size="sm"
                        isDisabled={isBusy}
                        label="Suppress"
                        onClick={() => void decide(cluster, "suppress")}
                      />
                      <Button
                        variant="secondary"
                        size="sm"
                        isDisabled={isBusy}
                        label="Escalate"
                        onClick={() => void decide(cluster, "escalate")}
                      />
                      <Button
                        variant="primary"
                        size="sm"
                        isDisabled={isBusy}
                        label={
                          cluster.suggested_mode !== cluster.current_mode
                            ? `Promote to ${cluster.suggested_mode}`
                            : "Accept"
                        }
                        onClick={() => void decide(cluster, "promote")}
                      />
                    </HStack>
                  </HStack>
                </VStack>
              </Card>
            );
          })}
        </VStack>
      )}
    </VStack>
  );
}
