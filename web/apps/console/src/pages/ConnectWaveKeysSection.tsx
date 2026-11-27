// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
import { useState } from "react";
import type { DeploymentKey } from "@grdr/api";
import { presentDeploymentKeyStatus, presentInstallProfile } from "@grdr/i18n";
import { Quoted } from "@grdr/kit";
import {
  Badge,
  Button,
  Card,
  Dialog,
  EmptyState,
  GrdrIcon,
  GrdrSelect,
  Heading,
  HStack,
  IconButton,
  ProgressBar,
  StatusInline,
  Text,
  TextInput,
  VStack,
} from "@grdr/ui";

interface ConnectWaveKeysSectionProps {
  keys: DeploymentKey[];
  keyLabel: string;
  onChangeKeyLabel: (v: string) => void;
  keyWave: string;
  onChangeKeyWave: (v: string) => void;
  keyProfile: string;
  onChangeKeyProfile: (v: string) => void;
  keyMaxUses: string;
  onChangeKeyMaxUses: (v: string) => void;
  keyTtlDays: string;
  onChangeKeyTtlDays: (v: string) => void;
  issuingKey: boolean;
  onIssueKey: () => void;
  onRevokeKey: (id: string) => void;
}

export function ConnectWaveKeysSection({
  keys,
  keyLabel,
  onChangeKeyLabel,
  keyWave,
  onChangeKeyWave,
  keyProfile,
  onChangeKeyProfile,
  keyMaxUses,
  onChangeKeyMaxUses,
  keyTtlDays,
  onChangeKeyTtlDays,
  issuingKey,
  onIssueKey,
  onRevokeKey,
}: ConnectWaveKeysSectionProps) {
  const [revokeTarget, setRevokeTarget] = useState<DeploymentKey | null>(null);

  return (
    <Card padding={3}>
      <VStack gap={3}>
        <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
          <VStack gap={0}>
            <Heading level={2}>{`Wave deployment keys (${keys.length})`}</Heading>
            <Text size="sm" color="secondary">
              Scoped enrollment tokens with per-wave seat quotas and explicit revocation.
            </Text>
          </VStack>
        </HStack>

        <div className="connect-key-form">
          <TextInput label="Wave label" value={keyLabel} onChange={onChangeKeyLabel} />
          <TextInput label="Wave cohort" value={keyWave} onChange={onChangeKeyWave} />
          <GrdrSelect
            label="Install profile"
            size="md"
            variant="input"
            value={keyProfile}
            options={[
              { value: "standard", label: "Standard" },
              { value: "enforced", label: "Enforced boundary" },
              { value: "watch", label: "Watch baseline" },
            ]}
            onChange={onChangeKeyProfile}
          />
          <TextInput label="Max uses" value={keyMaxUses} onChange={onChangeKeyMaxUses} />
          <TextInput label="Valid days" value={keyTtlDays} onChange={onChangeKeyTtlDays} />
          <div className="connect-key-submit">
            <Button
              variant="primary"
              icon={<GrdrIcon name="key-round" size={14} />}
              label={issuingKey ? "Issuing..." : "Issue wave key"}
              isDisabled={issuingKey}
              onClick={onIssueKey}
            />
          </div>
        </div>

        {keys.length === 0 ? (
          <EmptyState
            title="No wave deployment keys issued"
            description="Issue a scoped enrollment key above to bind new endpoints to an install profile and quota."
            icon={<GrdrIcon name="key-round" size={20} />}
          />
        ) : (
          <div className="table-wrap">
            <table className="table responsive-table">
              <thead>
                <tr>
                  <th>Wave & token prefix</th>
                  <th>Profile</th>
                  <th>Quota usage</th>
                  <th>Status</th>
                  <th>Issued by</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {keys.map((key) => {
                  const st = presentDeploymentKeyStatus(key.status);
                  const pct =
                    key.max_uses > 0
                      ? Math.min(100, Math.round((key.used_count / key.max_uses) * 100))
                      : 0;
                  const isClosed = key.status === "revoked" || key.status === "expired";
                  return (
                    <tr key={key.id}>
                      <td data-label="Wave & token prefix">
                        <VStack gap={1}>
                          <Text size="sm" weight="semibold">
                            {key.label}
                          </Text>
                          <Quoted text={key.token_preview} />
                        </VStack>
                      </td>
                      <td data-label="Profile">
                        <Badge variant="neutral" label={presentInstallProfile(key.install_profile)} />
                      </td>
                      <td data-label="Quota usage" style={{ minWidth: 160 }}>
                        <VStack gap={1}>
                          <Text size="sm" className="tabular">
                            {`${key.used_count} / ${key.max_uses} seats`}
                          </Text>
                          <ProgressBar
                            label={`${key.label} quota`}
                            isLabelHidden
                            value={Math.max(4, pct)}
                            max={100}
                            variant={pct >= 85 ? "warning" : "accent"}
                            isDisabled={isClosed}
                          />
                        </VStack>
                      </td>
                      <td data-label="Status">
                        <StatusInline tone={st.tone} dot label={st.label} />
                      </td>
                      <td data-label="Issued by">
                        <Text size="sm" color="secondary">
                          {key.created_by}
                        </Text>
                      </td>
                      <td data-label="Action">
                        {key.status === "active" ? (
                          <Button
                            size="sm"
                            variant="secondary"
                            label="Revoke"
                            onClick={() => setRevokeTarget(key)}
                          />
                        ) : (
                          <Text size="sm" color="secondary">
                            Closed
                          </Text>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </VStack>

      <Dialog
        isOpen={revokeTarget !== null}
        onOpenChange={(open) => {
          if (!open) setRevokeTarget(null);
        }}
        purpose="required"
        width={480}
        padding={4}
        aria-label="Confirm wave deployment key revocation"
      >
        {revokeTarget && (
          <VStack gap={3}>
            <HStack justify="between" align="start">
              <HStack gap={2} align="center">
                <GrdrIcon name="alert-triangle" size={18} color="var(--tone-block)" />
                <Heading level={2}>Revoke deployment key</Heading>
              </HStack>
              <IconButton
                label="Close"
                icon={<GrdrIcon name="x" size={14} />}
                variant="ghost"
                size="sm"
                onClick={() => setRevokeTarget(null)}
              />
            </HStack>
            <Text size="sm" color="secondary">
              {`Revoking "${revokeTarget.label}" (${revokeTarget.token_preview}) immediately blocks new endpoint enrollments using this wave key. Existing enrolled endpoints stay connected.`}
            </Text>
            <HStack justify="end" gap={2}>
              <Button variant="secondary" size="sm" label="Cancel" onClick={() => setRevokeTarget(null)} />
              <Button
                variant="destructive"
                size="sm"
                label="Revoke deployment key"
                onClick={() => {
                  const targetId = revokeTarget.id;
                  setRevokeTarget(null);
                  onRevokeKey(targetId);
                }}
              />
            </HStack>
          </VStack>
        )}
      </Dialog>
    </Card>
  );
}
