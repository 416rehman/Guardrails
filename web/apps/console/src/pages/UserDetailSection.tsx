// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
import type { ArtifactEntry, RiskTier, UserDetailResponse } from "@grdr/api";
import { formatActionLabel, pluralize } from "@grdr/i18n";
import { EntityLink, type EntityTarget, Quoted, VerdictBadge } from "@grdr/kit";
import { Badge, Button, Card, EmptyState, GrdrIcon, Heading, HStack, Text, VStack } from "@grdr/ui";

export function riskTone(tier: RiskTier): "block" | "ask" | "watch" | "allow" {
  switch (tier) {
    case "critical":
      return "block";
    case "high":
      return "ask";
    case "elevated":
      return "watch";
    case "low":
      return "allow";
  }
}

export function riskBadgeVariant(tier: RiskTier): "error" | "warning" | "info" | "success" {
  switch (tier) {
    case "critical":
      return "error";
    case "high":
      return "warning";
    case "elevated":
      return "info";
    case "low":
      return "success";
  }
}

export function capitalizeTier(tier: string): string {
  if (!tier) return "";
  return tier.slice(0, 1).toUpperCase() + tier.slice(1);
}

interface UserDetailSectionProps {
  detail: UserDetailResponse | null;
  isPseudonymous: boolean;
  onOpenEntity?: (target: EntityTarget) => void;
  onOpenSessionTurn: (sessionId: string, turnIndex: number) => void;
}

export function UserDetailSection({
  detail,
  isPseudonymous,
  onOpenEntity,
  onOpenSessionTurn,
}: UserDetailSectionProps) {
  if (!detail) {
    return (
      <div className="ledger-section">
        <EmptyState
          title="Select a user"
          description="Choose a directory entry to inspect assigned devices, risk drivers, and activity feed."
          icon={<GrdrIcon name="user" size={20} />}
        />
      </div>
    );
  }

  return (
    <div className="ledger-section">
      <VStack gap={3}>
        <div className="ledger-header" style={{ flexWrap: "wrap", gap: 10 }}>
          <VStack gap={1}>
            <HStack gap={2} align="center" style={{ flexWrap: "wrap" }}>
              <Heading level={2}>{detail.user.display_name}</Heading>
              {!isPseudonymous && (
                <Badge
                  variant={riskBadgeVariant(detail.user.risk_tier)}
                  label={`Risk score ${detail.user.risk_score} (${capitalizeTier(detail.user.risk_tier)})`}
                />
              )}
            </HStack>
            <Text size="sm" color="secondary">
              {isPseudonymous
                ? `Pseudonymous identity · ${detail.user.department} · Synced via ${detail.user.idp_source}`
                : `${detail.user.email} · ${detail.user.department} · Synced via ${detail.user.idp_source}`}
            </Text>
          </VStack>
          <div className="mono" style={{ color: "var(--ink-muted)", fontSize: 12 }}>
            {`Pseudonym ${detail.user.pseudonym_id}`}
          </div>
        </div>

        {!isPseudonymous && detail.user.risk_factors.length > 0 && (
          <Card padding={2}>
            <VStack gap={2}>
              <Text size="sm" weight="semibold">
                Risk score drivers
              </Text>
              <div className="risk-driver-grid">
                {detail.user.risk_factors.map((factor) => (
                  <div key={factor.code} className="risk-driver-row">
                    <Text size="sm">{`${factor.label} (${factor.count})`}</Text>
                    <span className="mono" style={{ color: "var(--tone-block)", fontWeight: 600 }}>
                      {`+${factor.points} pts`}
                    </span>
                  </div>
                ))}
              </div>
            </VStack>
          </Card>
        )}

        <div className="grid-2">
          <Card padding={2}>
            <VStack gap={2}>
              <Text size="sm" weight="semibold">
                {`Devices & agents (${detail.devices.length})`}
              </Text>
              {detail.devices.length === 0 ? (
                <Text size="sm" color="secondary">
                  No endpoints currently attributed to this user.
                </Text>
              ) : (
                detail.devices.map((dev) => (
                  <HStack key={dev.id} gap={2} align="center" style={{ flexWrap: "wrap" }}>
                    <EntityLink
                      kind="device"
                      id={dev.id}
                      label={dev.hostname}
                      os={dev.os}
                      compact
                      onSelect={onOpenEntity}
                    />
                    {dev.agents.map((ag) => (
                      <EntityLink
                        key={ag.id}
                        kind="agent"
                        id={ag.id}
                        label={ag.name}
                        compact
                        onSelect={onOpenEntity}
                      />
                    ))}
                  </HStack>
                ))
              )}
            </VStack>
          </Card>

          <Card padding={2}>
            <VStack gap={2}>
              <Text size="sm" weight="semibold">
                {`Assigned skills & rules (${detail.artifacts.length})`}
              </Text>
              {detail.artifacts.length === 0 ? (
                <Text size="sm" color="secondary">
                  No skills or rules discovered on assigned endpoints.
                </Text>
              ) : (
                detail.artifacts.map((art: ArtifactEntry) => (
                  <HStack key={art.id} justify="between" align="center" style={{ gap: 8, flexWrap: "wrap" }}>
                    <EntityLink
                      kind="artifact"
                      id={art.id}
                      label={art.name}
                      compact
                      onSelect={onOpenEntity}
                    />
                    <HStack gap={1}>
                      <Badge variant="neutral" label={art.kind} />
                      {art.risk_flags.length > 0 && (
                        <Badge variant="warning" label={pluralize(art.risk_flags.length, "flag")} />
                      )}
                    </HStack>
                  </HStack>
                ))
              )}
            </VStack>
          </Card>
        </div>

        <VStack gap={2}>
          <Heading level={3}>{`Per-user activity feed (${detail.recent_attempts.length})`}</Heading>
          {detail.recent_attempts.length === 0 ? (
            <Text color="secondary">No recorded activity for this user yet.</Text>
          ) : (
            <div className="table-wrap">
              <table className="table responsive-table">
                <thead>
                  <tr>
                    <th>Verdict</th>
                    <th>Turn</th>
                    <th>Action & target</th>
                    <th>Agent</th>
                    <th>Trace</th>
                  </tr>
                </thead>
                <tbody>
                  {detail.recent_attempts.map((attempt) => {
                    const receipt = detail.receipts.find((r) => r.attempt_id === attempt.id);
                    const isWatchHit = Boolean(receipt?.verdict === "allow" && receipt.rule_id);
                    const turnNum = attempt.turn_index ?? 1;
                    return (
                      <tr key={attempt.id}>
                        <td data-label="Verdict">
                          {isWatchHit ? (
                            <Badge
                              variant="info"
                              icon={<GrdrIcon name="eye" size={11} />}
                              label="Watch"
                            />
                          ) : receipt ? (
                            <VerdictBadge verdict={receipt.verdict} />
                          ) : (
                            <VerdictBadge verdict="allow" />
                          )}
                        </td>
                        <td data-label="Turn" className="mono">{`T${turnNum}`}</td>
                        <td data-label="Action & target">
                          <VStack gap={1}>
                            <span style={{ fontWeight: 500 }}>{formatActionLabel(attempt.action_class)}</span>
                            <Quoted text={attempt.target} />
                          </VStack>
                        </td>
                        <td data-label="Agent">
                          <EntityLink
                            kind="agent"
                            label={attempt.agent_name}
                            compact
                            onSelect={onOpenEntity}
                          />
                        </td>
                        <td data-label="Trace">
                          <Button
                            size="sm"
                            variant="ghost"
                            icon={<GrdrIcon name="route" size={12} />}
                            label={`Open turn ${turnNum}`}
                            onClick={() => onOpenSessionTurn(attempt.session_id, turnNum)}
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
      </VStack>
    </div>
  );
}
