// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
import type { CompatCheckEntry } from "@grdr/api";
import { capitalizeLabel } from "@grdr/i18n";
import {
  Button,
  EmptyState,
  GrdrIcon,
  Heading,
  StatusInline,
  Text,
  TextInput,
  VStack,
} from "@grdr/ui";

const CAPABILITY_LABELS: Record<string, string> = {
  SignedReceipts: "Signed receipts",
  SessionLabels: "Session labels",
  FastpathFloor: "Fast-path floor",
  McpToolPinning: "MCP tool pinning",
  StepUpApproval: "Step-up approval",
};

function formatCapabilityList(caps: string[]): string {
  return caps
    .map((c) => CAPABILITY_LABELS[c] ?? c.replace(/([a-z0-9])([A-Z])/g, "$1 $2").toLowerCase())
    .join(", ");
}

interface OperatorUpgradePreflightProps {
  targetVersion: string;
  onChangeTargetVersion: (val: string) => void;
  overallCompatible: boolean;
  opTargetVersion: string;
  preflightMatrix: CompatCheckEntry[];
  busy: boolean;
  onRunPreflight: () => void;
}

export function OperatorUpgradePreflight({
  targetVersion,
  onChangeTargetVersion,
  overallCompatible,
  opTargetVersion,
  preflightMatrix,
  busy,
  onRunPreflight,
}: OperatorUpgradePreflightProps) {
  return (
    <section className="ledger-section">
      <div className="ledger-header" style={{ flexWrap: "wrap", gap: 10 }}>
        <VStack gap={0}>
          <Heading level={2}>Upgrade compatibility preflight</Heading>
          <Text size="sm" color="secondary">
            Validate daemon, schema, and protocol handshake ranges before promoting fleet rollouts.
          </Text>
        </VStack>
        <div className="op-actions-row">
          <div style={{ flex: "1 1 140px", minWidth: 0, maxWidth: 200 }}>
            <TextInput
              label="Target version"
              value={targetVersion}
              onChange={onChangeTargetVersion}
              width="100%"
            />
          </div>
          <Button
            variant="secondary"
            size="sm"
            icon={<GrdrIcon name="shield-check" size={14} />}
            label="Run preflight"
            isDisabled={busy || targetVersion.trim() === ""}
            onClick={onRunPreflight}
          />
        </div>
      </div>

      <StatusInline
        tone={overallCompatible ? "allow" : "ask"}
        dot
        label={overallCompatible ? `Ready for v${opTargetVersion}` : `Warnings on v${opTargetVersion}`}
      />

      {preflightMatrix.length === 0 ? (
        <EmptyState
          title="No upgrade preflight checks run"
          description="Enter a target release version above and run preflight to inspect daemon and schema handshake compatibility."
          icon={<GrdrIcon name="shield-check" size={20} />}
        />
      ) : (
        <div className="table-wrap">
          <table className="table responsive-table">
            <thead>
              <tr>
                <th>Component</th>
                <th>Versions</th>
                <th>Status</th>
                <th>Capabilities and remediation</th>
              </tr>
            </thead>
            <tbody>
              {preflightMatrix.map((chk) => (
                <tr key={chk.component}>
                  <td data-label="Component" className="mono">{chk.component}</td>
                  <td data-label="Versions" className="mono">
                    {`${chk.current_version} -> ${chk.target_version} (${chk.supported_range})`}
                  </td>
                  <td data-label="Status">
                    <StatusInline
                      tone={
                        chk.status === "compatible"
                          ? "allow"
                          : chk.status === "compatible_with_warnings"
                            ? "ask"
                            : "block"
                      }
                      dot
                      label={capitalizeLabel(chk.status.replace(/_/g, " "))}
                    />
                  </td>
                  <td data-label="Capabilities and remediation">
                    <VStack gap={0}>
                      <Text size="sm" color="secondary">{formatCapabilityList(chk.agreed_capabilities)}</Text>
                      {chk.remediation && <Text size="sm">{chk.remediation}</Text>}
                    </VStack>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
