// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
import { useMemo, useState } from "react";
import {
  Badge,
  Banner,
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
import type { ExtendedOperatorRouteId } from "./operatorRoutes";
import type { OperatorSnapshot } from "./queries";

type CustodyMode = "ed25519-host" | "kms-envelope";
type GraceWindow = "14d" | "30d" | "90d";

interface OperatorKeysViewProps {
  snapshot: OperatorSnapshot;
  onNavigate: (route: ExtendedOperatorRouteId) => void;
}

type KeyActionState =
  | { kind: "idle" }
  | { kind: "copied"; message: string }
  | { kind: "copyError"; message: string }
  | { kind: "planned"; keyId: string; command: string };

type RotationDialogState = { kind: "closed" } | { kind: "confirming" };

function isCustodyMode(value: string): value is CustodyMode {
  return value === "ed25519-host" || value === "kms-envelope";
}

function isGraceWindow(value: string): value is GraceWindow {
  return value === "14d" || value === "30d" || value === "90d";
}

function sanitizeKeyId(raw: string): string {
  return raw
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function shellQuote(raw: string): string {
  return `'${raw.replace(/'/g, "'\\''")}'`;
}

export function OperatorKeysView({ snapshot, onNavigate }: OperatorKeysViewProps) {
  const defaultNextId = `key-rot-${snapshot.keys.length + 1}`;
  const [nextKeyId, setNextKeyId] = useState(defaultNextId);
  const [custodyMode, setCustodyMode] = useState<CustodyMode>("ed25519-host");
  const [graceWindow, setGraceWindow] = useState<GraceWindow>("30d");
  const [stepUpToken, setStepUpToken] = useState("");
  const [confirmDialog, setConfirmDialog] = useState<RotationDialogState>({ kind: "closed" });
  const [actionState, setActionState] = useState<KeyActionState>({ kind: "idle" });

  const readinessChecks = [
    {
      id: "active-signer",
      label: "Active Ed25519 receipt signing key registered",
      done: snapshot.keys.length > 0,
      detail: `${snapshot.keys.length} trusted key entries active`,
    },
    {
      id: "persistent-storage",
      label: "Persistent database engine configured for key ledger",
      done: snapshot.health.storage_mode.kind === "sqlite",
      detail:
        snapshot.health.storage_mode.kind === "sqlite"
          ? "SQLite WAL persistence active"
          : "Ephemeral memory mode active",
    },
    {
      id: "verified-drill",
      label: "Recent backup and signature integrity drill verified",
      done: snapshot.operatorState.drills.some((d) => d.status === "passed"),
      detail: `${snapshot.operatorState.drills.length} recorded drills`,
    },
  ];

  const completedCount = readinessChecks.filter((c) => c.done).length;
  const readinessPct = Math.max(20, Math.round((completedCount / Math.max(1, readinessChecks.length)) * 100));
  const normalizedKeyId = sanitizeKeyId(nextKeyId) || defaultNextId;

  const rotationCommand = useMemo(() => {
    return [
      "grdrctl operator key rotate",
      `--key-id ${shellQuote(normalizedKeyId)}`,
      `--custody ${shellQuote(custodyMode)}`,
      `--grace-window ${shellQuote(graceWindow)}`,
      "--step-up",
    ].join(" ");
  }, [custodyMode, graceWindow, normalizedKeyId]);

  async function copyText(text: string, message: string) {
    if (typeof navigator === "undefined" || typeof navigator.clipboard?.writeText !== "function") {
      setActionState({
        kind: "copyError",
        message: "Clipboard access is unavailable in this browser context. Copy the value manually.",
      });
      return;
    }
    try {
      await navigator.clipboard.writeText(text);
      setActionState({ kind: "copied", message });
    } catch {
      setActionState({
        kind: "copyError",
        message: "Clipboard write was rejected by the browser. Copy the value manually.",
      });
    }
  }

  function confirmStageRotation() {
    setConfirmDialog({ kind: "closed" });
    setStepUpToken("");
    setActionState({
      kind: "planned",
      keyId: normalizedKeyId,
      command: rotationCommand,
    });
  }

  return (
    <VStack gap={4}>
      <section className="ledger-section">
        <div className="ledger-header" style={{ flexWrap: "wrap", gap: 10 }}>
          <VStack gap={0}>
            <Heading level={2}>{`Trusted Ed25519 verification keys (${snapshot.keys.length})`}</Heading>
            <Text size="sm" color="secondary">
              Public keys distributed to endpoints and auditors to verify signed decision receipts.
            </Text>
          </VStack>
          <HStack gap={2} align="center">
            <Badge variant="success" label="Signature verification active" />
            <Button
              size="sm"
              variant="secondary"
              label="Deployment settings"
              endContent={<GrdrIcon name="arrow-right" size={13} />}
              onClick={() => onNavigate("op-settings")}
            />
          </HStack>
        </div>

        {snapshot.keys.length === 0 ? (
          <EmptyState
            title="No trusted receipt signing keys registered"
            description="Bootstrap an initial Ed25519 root key on the control-plane host before enrolling agents."
            icon={<GrdrIcon name="key-round" size={22} />}
            actions={
              <Button size="sm" variant="secondary" label="Review backup state" onClick={() => onNavigate("op-backups")} />
            }
          />
        ) : (
          <div className="table-wrap">
            <table className="table responsive-table">
              <thead>
                <tr>
                  <th>Key ID</th>
                  <th>Status</th>
                  <th>Public key (base64)</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {snapshot.keys.map((key) => (
                  <tr key={key.key_id}>
                    <td data-label="Key ID" className="mono">{key.key_id}</td>
                    <td data-label="Status">
                      <StatusInline tone="allow" dot label="Trusted Ed25519" />
                    </td>
                    <td data-label="Public key (base64)" className="mono">{key.public_key_b64}</td>
                    <td data-label="Actions">
                      <Button
                        size="sm"
                        variant="ghost"
                        label="Copy public key"
                        onClick={() => void copyText(key.public_key_b64, `Copied public key ${key.key_id}.`)}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <Card padding={3}>
        <VStack gap={3}>
          <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
            <VStack gap={0}>
              <Heading level={2}>Key custody readiness</Heading>
              <Text size="sm" color="secondary">
                Verification checks for root signing custody and recovery durability.
              </Text>
            </VStack>
            <Badge
              variant={completedCount === readinessChecks.length ? "success" : "warning"}
              label={`${completedCount}/${readinessChecks.length} verified`}
            />
          </HStack>
          <ProgressBar
            label="Key custody readiness"
            isLabelHidden
            value={readinessPct}
            max={100}
            variant={completedCount === readinessChecks.length ? "success" : "accent"}
          />
          <div>
            {readinessChecks.map((item) => (
              <div key={item.id} className="op-check-item">
                <VStack gap={0}>
                  <Text size="sm" weight="semibold">{item.label}</Text>
                  <Text size="sm" color="secondary">{item.detail}</Text>
                </VStack>
                <StatusInline
                  tone={item.done ? "allow" : "ask"}
                  dot
                  label={item.done ? "Verified" : "Action needed"}
                />
              </div>
            ))}
          </div>
        </VStack>
      </Card>

      <Card padding={3}>
        <VStack gap={3}>
          <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
            <VStack gap={0}>
              <Heading level={2}>Key rotation ceremony planner</Heading>
              <Text size="sm" color="secondary">
                Stage a successor signing key ID, dual-verification grace window, and step-up authorization before rotating via host CLI.
              </Text>
            </VStack>
            <Badge variant="warning" label="Host CLI required" />
          </HStack>

          <div className="op-form-grid">
            <TextInput label="Next key identifier" value={nextKeyId} onChange={setNextKeyId} width="100%" />
            <GrdrSelect
              label="Custody mode"
              value={custodyMode}
              onChange={(val) => {
                if (isCustodyMode(val)) setCustodyMode(val);
              }}
              options={[
                { value: "ed25519-host", label: "Local host keypair (Ed25519)" },
                { value: "kms-envelope", label: "External KMS envelope wrap" },
              ]}
            />
            <GrdrSelect
              label="Overlap grace window"
              value={graceWindow}
              onChange={(val) => {
                if (isGraceWindow(val)) setGraceWindow(val);
              }}
              options={[
                { value: "14d", label: "14 days overlap" },
                { value: "30d", label: "30 days overlap" },
                { value: "90d", label: "90 days overlap" },
              ]}
            />
            <TextInput
              label="Step-up authorization token"
              type="password"
              placeholder="Enter step-up verification token"
              value={stepUpToken}
              onChange={setStepUpToken}
              data-agent-secret="true"
              autoComplete="off"
              width="100%"
            />
          </div>

          <div className="op-actions-row">
            <Button
              variant="primary"
              size="sm"
              icon={<GrdrIcon name="key-round" size={14} />}
              label="Stage key rotation"
              isDisabled={stepUpToken.trim() === "" || normalizedKeyId === ""}
              onClick={() => setConfirmDialog({ kind: "confirming" })}
            />
            <Button
              variant="secondary"
              size="sm"
              label="Copy rotation CLI"
              onClick={() => void copyText(rotationCommand, "Copied key rotation CLI command.")}
            />
          </div>

          {actionState.kind === "copied" && <Banner status="success" title={actionState.message} collapsible={false} />}
          {actionState.kind === "copyError" && <Banner status="warning" title={actionState.message} collapsible={false} />}
          {actionState.kind === "planned" && (
            <Banner
              status="info"
              title={`Host CLI required for ${actionState.keyId}`}
              description="Apply rotation via host CLI on the control-plane host with dual-custody sign-off."
              collapsible={false}
            />
          )}

          <pre className="op-pre">{rotationCommand}</pre>
        </VStack>
      </Card>

      <Dialog
        isOpen={confirmDialog.kind === "confirming"}
        onOpenChange={(open) => {
          if (!open) setConfirmDialog({ kind: "closed" });
        }}
        purpose="required"
        width={480}
        padding={4}
        aria-label="Confirm key rotation ceremony staging"
      >
        <VStack gap={3}>
          <HStack justify="between" align="start">
            <HStack gap={2} align="center">
              <GrdrIcon name="key-round" size={18} color="var(--tone-ask)" />
              <Heading level={2}>Confirm key rotation plan</Heading>
            </HStack>
            <IconButton label="Close" icon={<GrdrIcon name="x" size={14} />} variant="ghost" size="sm" onClick={() => setConfirmDialog({ kind: "closed" })} />
          </HStack>
          <Text size="sm" color="secondary">
            {`Prepare host CLI rotation for "${normalizedKeyId}" under "${custodyMode}" custody with a ${graceWindow} overlap grace window. Existing keys stay trusted throughout the overlap window.`}
          </Text>
          <HStack justify="end" gap={2}>
            <Button variant="secondary" size="sm" label="Cancel" onClick={() => setConfirmDialog({ kind: "closed" })} />
            <Button variant="primary" size="sm" label="Stage rotation CLI" onClick={confirmStageRotation} />
          </HStack>
        </VStack>
      </Dialog>
    </VStack>
  );
}
