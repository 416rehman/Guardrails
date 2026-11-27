// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
import { useMemo, useState } from "react";
import { formatStorageMode } from "@grdr/api";
import { capitalizeLabel, formatTimestamp } from "@grdr/i18n";
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
import type { ExtendedOperatorRouteId } from "./operatorRoutes";
import type { OperatorSnapshot } from "./queries";

type PrivacyRegime = "standard" | "works-council";
type RetentionOption = "default" | "eu-works-council" | "regulated";

interface OperatorOrgsViewProps {
  snapshot: OperatorSnapshot;
  onNavigate: (route: ExtendedOperatorRouteId) => void;
}

type DraftFeedback =
  | { kind: "idle" }
  | { kind: "staged"; command: string; manifest: string }
  | { kind: "copied"; message: string };

interface OrgDraft {
  orgSlug: string;
  displayName: string;
  privacyRegime?: PrivacyRegime;
  retentionPreset?: RetentionOption;
  residencyZone: string;
  adminEmail: string;
}

function isPrivacyRegime(value: string): value is PrivacyRegime {
  return value === "standard" || value === "works-council";
}

function isRetentionOption(value: string): value is RetentionOption {
  return value === "default" || value === "eu-works-council" || value === "regulated";
}

function deriveTemplateDomain(): string {
  if (typeof window === "undefined") return "guardrails.local";
  const host = (window.location.hostname || "").trim().toLowerCase();
  const isLoopbackOrIp =
    !host ||
    host === "localhost" ||
    host === "127.0.0.1" ||
    host === "::1" ||
    host === "[::1]" ||
    /^\d{1,3}(\.\d{1,3}){3}$/.test(host) ||
    host.includes(":");
  return isLoopbackOrIp ? "guardrails.local" : host;
}

function slugifyOrgName(raw: string): string {
  return raw
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function shellQuote(raw: string): string {
  return `'${raw.replace(/'/g, "'\\''")}'`;
}

export function OperatorOrgsView({ snapshot, onNavigate }: OperatorOrgsViewProps) {
  const cfg = snapshot.operatorState.runtime_config;
  const templateDomain = useMemo(() => deriveTemplateDomain(), []);

  const [draft, setDraft] = useState<OrgDraft>(() => ({
    orgSlug: "",
    displayName: "",
    residencyZone: "eu-central",
    adminEmail: `security-admin@${templateDomain}`,
  }));
  const [feedback, setFeedback] = useState<DraftFeedback>({ kind: "idle" });

  const serverRegime: PrivacyRegime = isPrivacyRegime(cfg.privacy_profile)
    ? cfg.privacy_profile
    : "standard";
  const serverRetention: RetentionOption = isRetentionOption(cfg.retention_preset)
    ? cfg.retention_preset
    : "default";

  const privacyRegime = draft.privacyRegime ?? serverRegime;
  const retentionPreset = draft.retentionPreset ?? serverRetention;
  const normalizedSlug = slugifyOrgName(draft.orgSlug || draft.displayName);

  const generatedSpec = useMemo(() => {
    const cleanSlug = normalizedSlug || "new-org";
    const cleanName = draft.displayName.trim() || cleanSlug;
    const cleanEmail = draft.adminEmail.trim() || `security-admin@${templateDomain}`;

    const command = [
      "grdrctl operator org create",
      `--slug ${shellQuote(cleanSlug)}`,
      `--name ${shellQuote(cleanName)}`,
      `--privacy-regime ${shellQuote(privacyRegime)}`,
      `--retention-preset ${shellQuote(retentionPreset)}`,
      `--residency ${shellQuote(draft.residencyZone)}`,
      `--admin-email ${shellQuote(cleanEmail)}`,
    ].join(" ");

    const manifest = [
      "[operator.organization]",
      `slug = ${JSON.stringify(cleanSlug)}`,
      `display_name = ${JSON.stringify(cleanName)}`,
      `privacy_regime = ${JSON.stringify(privacyRegime)}`,
      `retention_preset = ${JSON.stringify(retentionPreset)}`,
      `residency_zone = ${JSON.stringify(draft.residencyZone)}`,
      `bootstrap_admin = ${JSON.stringify(cleanEmail)}`,
      `release_channel = ${JSON.stringify(cfg.release_channel)}`,
    ].join("\n");

    return { command, manifest, cleanSlug };
  }, [
    cfg.release_channel,
    draft.adminEmail,
    draft.displayName,
    draft.residencyZone,
    normalizedSlug,
    privacyRegime,
    retentionPreset,
    templateDomain,
  ]);

  function handleBuildSpec() {
    setFeedback({
      kind: "staged",
      command: generatedSpec.command,
      manifest: generatedSpec.manifest,
    });
  }

  async function handleCopyCommand() {
    if (typeof navigator === "undefined" || typeof navigator.clipboard?.writeText !== "function") {
      setFeedback({
        kind: "staged",
        command: generatedSpec.command,
        manifest: generatedSpec.manifest,
      });
      return;
    }
    try {
      await navigator.clipboard.writeText(generatedSpec.command);
      setFeedback({ kind: "copied", message: "Copied organization bootstrap CLI command." });
    } catch {
      setFeedback({
        kind: "staged",
        command: generatedSpec.command,
        manifest: generatedSpec.manifest,
      });
    }
  }

  return (
    <VStack gap={4}>
      <Banner
        status="info"
        title="Deployment tenant boundary active"
        description="Tenant secrets, user payloads, and rule matches never surface on this operator origin. Multi-organization directory provisioning uses the host CLI workflow below."
        collapsible={false}
      />

      <div className="metric-strip" style={{ marginBlockStart: 0 }}>
        <div className="metric-cell">
          <div className="metric-value tabular">{snapshot.overview.total_devices}</div>
          <div className="metric-label">Registered devices</div>
          <div className="metric-note">{`${snapshot.overview.online_devices} currently online`}</div>
        </div>
        <div className="metric-cell">
          <div className="metric-value tabular">{snapshot.overview.total_agents}</div>
          <div className="metric-label">Discovered agents</div>
          <div className="metric-note">{`${snapshot.overview.total_mcp_servers} MCP integrations`}</div>
        </div>
        <div className="metric-cell">
          <div className="metric-value tabular">{capitalizeLabel(cfg.privacy_profile.replace(/-/g, " "))}</div>
          <div className="metric-label">Active privacy regime</div>
          <div className="metric-note">{`Retention preset: ${cfg.retention_preset}`}</div>
        </div>
        <div className="metric-cell">
          <div className="metric-value tabular">{snapshot.keys.length}</div>
          <div className="metric-label">Signing trust keys</div>
          <div className="metric-note">{`Release channel: ${cfg.release_channel}`}</div>
        </div>
      </div>

      <section className="ledger-section">
        <div className="ledger-header" style={{ flexWrap: "wrap", gap: 10 }}>
          <VStack gap={0}>
            <Heading level={2}>Deployment-scoped tenant directory</Heading>
            <Text size="sm" color="secondary">
              Organization inventory synchronized from the control-plane host.
            </Text>
          </VStack>
          <HStack gap={2} align="center">
            <Badge variant="neutral" label={formatStorageMode(snapshot.health.storage_mode)} />
            <Button
              size="sm"
              variant="secondary"
              label="Manage release channel"
              endContent={<GrdrIcon name="arrow-right" size={13} />}
              onClick={() => onNavigate("op-upgrades")}
            />
          </HStack>
        </div>

        <div className="kv-row">
          <Text color="secondary">Current deployment plane</Text>
          <HStack gap={2} align="center">
            <StatusInline
              tone={snapshot.overview.kill_switch.state === "inactive" ? "allow" : "block"}
              dot
              label={
                snapshot.overview.kill_switch.state === "inactive"
                  ? "Isolated and nominal"
                  : capitalizeLabel(snapshot.overview.kill_switch.state.replace(/_/g, " "))
              }
            />
            <Text size="sm" className="mono">
              {`v${snapshot.health.version} (${formatTimestamp(snapshot.health.timestamp)})`}
            </Text>
          </HStack>
        </div>

        <EmptyState
          title="Multi-organization listing requires host CLI"
          description="Use the Console Provider Workbench for fleet organization rollout rings, or prepare a host CLI bootstrap manifest below."
          icon={<GrdrIcon name="globe" size={22} />}
        />
      </section>

      <Card padding={3}>
        <VStack gap={3}>
          <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
            <VStack gap={0}>
              <Heading level={2}>Provision organization manifest</Heading>
              <Text size="sm" color="secondary">
                Configure a new tenant slug, privacy floor, residency boundary, and break-glass owner before applying via host CLI.
              </Text>
            </VStack>
            <Badge variant="warning" label="Host CLI required" />
          </HStack>

          <div className="op-form-grid">
            <TextInput
              label="Organization slug"
              placeholder="e.g. org-acme-eu"
              value={draft.orgSlug}
              onChange={(val) => setDraft((prev) => ({ ...prev, orgSlug: val }))}
              width="100%"
            />
            <TextInput
              label="Display name"
              placeholder="Organization display name"
              value={draft.displayName}
              onChange={(val) => setDraft((prev) => ({ ...prev, displayName: val }))}
              width="100%"
            />
            <GrdrSelect
              label="Privacy regime ceiling"
              value={privacyRegime}
              onChange={(val) => {
                if (isPrivacyRegime(val)) setDraft((prev) => ({ ...prev, privacyRegime: val }));
              }}
              options={[
                { value: "standard", label: "Standard (named)" },
                { value: "works-council", label: "Works council (pseudonymous)" },
              ]}
            />
            <GrdrSelect
              label="Retention preset"
              value={retentionPreset}
              onChange={(val) => {
                if (isRetentionOption(val)) setDraft((prev) => ({ ...prev, retentionPreset: val }));
              }}
              options={[
                { value: "default", label: "Default" },
                { value: "eu-works-council", label: "EU Works Council" },
                { value: "regulated", label: "Regulated archive" },
              ]}
            />
            <GrdrSelect
              label="Data residency zone"
              value={draft.residencyZone}
              onChange={(val) => setDraft((prev) => ({ ...prev, residencyZone: val }))}
              options={[
                { value: "eu-central", label: "EU Central" },
                { value: "us-east", label: "US East" },
                { value: "uk-london", label: "UK London" },
                { value: "on-prem-airgap", label: "Self-hosted isolated" },
              ]}
            />
            <TextInput
              label="Bootstrap admin email"
              value={draft.adminEmail}
              onChange={(val) => setDraft((prev) => ({ ...prev, adminEmail: val }))}
              width="100%"
            />
          </div>

          <div className="op-actions-row">
            <Button
              variant="primary"
              size="sm"
              icon={<GrdrIcon name="plus" size={14} />}
              label="Prepare bootstrap spec"
              isDisabled={draft.displayName.trim() === "" || !draft.adminEmail.includes("@")}
              onClick={handleBuildSpec}
            />
            <Button
              variant="secondary"
              size="sm"
              label="Copy CLI command"
              isDisabled={draft.displayName.trim() === "" || !draft.adminEmail.includes("@")}
              onClick={() => void handleCopyCommand()}
            />
          </div>

          {feedback.kind === "copied" && <Banner status="success" title={feedback.message} collapsible={false} />}
          {feedback.kind === "staged" && (
            <Banner
              status="info"
              title={`Host CLI command ready for ${generatedSpec.cleanSlug}`}
              description="Apply via host CLI or copy the TOML block below onto the control-plane host."
              collapsible={false}
            />
          )}

          <VStack gap={1}>
            <Text size="sm" weight="semibold">Host CLI and TOML preview</Text>
            <pre className="op-pre">{`${generatedSpec.command}\n\n${generatedSpec.manifest}`}</pre>
          </VStack>
        </VStack>
      </Card>
    </VStack>
  );
}
