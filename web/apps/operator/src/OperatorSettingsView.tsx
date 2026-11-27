// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
import { useMemo, useState } from "react";
import { getApiToken } from "@grdr/api";
import { capitalizeLabel } from "@grdr/i18n";
import {
  Badge,
  Banner,
  Button,
  Card,
  CheckboxInput,
  EmptyState,
  GrdrIcon,
  GrdrSelect,
  Heading,
  HStack,
  StatusInline,
  Text,
  TextInput,
  UiSdkSegmentedControl,
  VStack,
} from "@grdr/ui";
import type { ExtendedOperatorRouteId } from "./operatorRoutes";
import type { OperatorSnapshot } from "./queries";

type IdpProtocol = "oidc" | "saml";
type MailerTlsMode = "starttls" | "smtps";
type ScimCadence = "30d" | "90d" | "180d";

interface OperatorSettingsViewProps {
  snapshot: OperatorSnapshot;
  onNavigate: (route: ExtendedOperatorRouteId) => void;
}

type SettingsFeedback =
  | { kind: "idle" }
  | { kind: "error"; message: string }
  | { kind: "copied"; message: string }
  | { kind: "staged"; title: string; detail: string };

function isIdpProtocol(value: string): value is IdpProtocol {
  return value === "oidc" || value === "saml";
}

function isMailerTlsMode(value: string): value is MailerTlsMode {
  return value === "starttls" || value === "smtps";
}

function isScimCadence(value: string): value is ScimCadence {
  return value === "30d" || value === "90d" || value === "180d";
}

function deriveSafeDomain(): string {
  if (typeof window === "undefined") {
    return "guardrails.local";
  }
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

function isValidHttpsOrLocalUrl(raw: string): boolean {
  try {
    const parsed = new URL(raw.trim());
    return parsed.protocol === "https:" || parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1";
  } catch {
    return false;
  }
}

function shellQuote(raw: string): string {
  return `'${raw.replace(/'/g, "'\\''")}'`;
}

export function OperatorSettingsView({ snapshot, onNavigate }: OperatorSettingsViewProps) {
  const defaultDomain = useMemo(() => deriveSafeDomain(), []);
  const cfg = snapshot.operatorState.runtime_config;
  const hasOperatorToken = Boolean(getApiToken());

  const [protocol, setProtocol] = useState<IdpProtocol>("oidc");
  const [issuerUrl, setIssuerUrl] = useState(`https://${defaultDomain}/oauth2/default`);
  const [clientId, setClientId] = useState("guardrails-operator");
  const [groupClaim, setGroupClaim] = useState("groups");
  const [scimEnabled, setScimEnabled] = useState(true);
  const [scimCadence, setScimCadence] = useState<ScimCadence>("90d");

  const [smtpHost, setSmtpHost] = useState(`smtp.${defaultDomain}`);
  const [smtpPort, setSmtpPort] = useState("587");
  const [tlsMode, setTlsMode] = useState<MailerTlsMode>("starttls");
  const [senderAddress, setSenderAddress] = useState(`guardrails@${defaultDomain}`);
  const [testRecipient, setTestRecipient] = useState(`security-ops@${defaultDomain}`);

  const [feedback, setFeedback] = useState<SettingsFeedback>({ kind: "idle" });

  const combinedToml = useMemo(() => {
    const parsedPort = Number.parseInt(smtpPort, 10);
    const validPort = Number.isFinite(parsedPort) && parsedPort > 0 && parsedPort <= 65535 ? parsedPort : 587;
    return [
      "[operator.idp]",
      `protocol = ${JSON.stringify(protocol)}`,
      `issuer_url = ${JSON.stringify(issuerUrl.trim())}`,
      `client_id = ${JSON.stringify(clientId.trim())}`,
      `group_claim = ${JSON.stringify(groupClaim.trim() || "groups")}`,
      "",
      "[operator.scim]",
      `enabled = ${scimEnabled ? "true" : "false"}`,
      `endpoint_path = "/scim/v2"`,
      `token_rotation_days = ${JSON.stringify(scimCadence)}`,
      "",
      "[operator.mailer]",
      `smtp_host = ${JSON.stringify(smtpHost.trim())}`,
      `smtp_port = ${validPort}`,
      `tls_mode = ${JSON.stringify(tlsMode)}`,
      `sender = ${JSON.stringify(senderAddress.trim())}`,
    ].join("\n");
  }, [
    clientId,
    groupClaim,
    issuerUrl,
    protocol,
    scimCadence,
    scimEnabled,
    senderAddress,
    smtpHost,
    smtpPort,
    tlsMode,
  ]);

  function validateIdp(): string | null {
    if (!isValidHttpsOrLocalUrl(issuerUrl)) {
      return "Issuer or metadata URL must use HTTPS (or localhost for local development).";
    }
    if (clientId.trim().length < 3) {
      return "Client ID or SAML entity ID must be at least 3 characters.";
    }
    return null;
  }

  function validateMailer(): string | null {
    const parsedPort = Number.parseInt(smtpPort, 10);
    if (smtpHost.trim().length === 0) {
      return "SMTP host is required before testing outbound delivery.";
    }
    if (!Number.isFinite(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
      return "SMTP port must be between 1 and 65535.";
    }
    if (!senderAddress.includes("@")) {
      return "Sender address must be a valid email address.";
    }
    return null;
  }

  function stageIdpSettings() {
    const err = validateIdp();
    if (err) {
      setFeedback({ kind: "error", message: err });
      return;
    }
    setFeedback({
      kind: "staged",
      title: `Identity federation (${protocol.toUpperCase()}) validated and staged`,
      detail:
        "Apply the generated [operator.idp] and [operator.scim] configuration block via host CLI on the control-plane server.",
    });
  }

  function stageMailerSettings() {
    const err = validateMailer();
    if (err) {
      setFeedback({ kind: "error", message: err });
      return;
    }
    const targetAddr = testRecipient.trim() || senderAddress.trim();
    setFeedback({
      kind: "staged",
      title: `Mailer probe staged for ${targetAddr}`,
      detail: `Apply via host CLI: grdrctl operator mailer test --to ${shellQuote(targetAddr)}`,
    });
  }

  async function copyToml() {
    if (typeof navigator === "undefined" || typeof navigator.clipboard?.writeText !== "function") {
      setFeedback({
        kind: "staged",
        title: "TOML preview ready below",
        detail: "Clipboard access is unavailable in this browser session. Copy from the configuration block below.",
      });
      return;
    }
    try {
      await navigator.clipboard.writeText(combinedToml);
      setFeedback({ kind: "copied", message: "Copied operator TOML configuration." });
    } catch {
      setFeedback({
        kind: "staged",
        title: "TOML preview ready below",
        detail: "Clipboard access is restricted in this browser session. Copy from the configuration block below.",
      });
    }
  }

  return (
    <VStack gap={4}>
      {feedback.kind === "error" && <Banner status="error" title={feedback.message} collapsible={false} />}
      {feedback.kind === "copied" && <Banner status="success" title={feedback.message} collapsible={false} />}
      {feedback.kind === "staged" && (
        <Banner status="info" title={feedback.title} description={feedback.detail} collapsible={false} />
      )}

      <Card padding={3}>
        <VStack gap={3}>
          <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
            <VStack gap={0}>
              <Heading level={2}>Identity provider and SCIM 2.0 provisioning</Heading>
              <Text size="sm" color="secondary">
                Bind operator realm sign-in to enterprise SSO and schedule directory synchronization.
              </Text>
            </VStack>
            <Badge variant="warning" label="Host CLI required" />
          </HStack>

          <UiSdkSegmentedControl<IdpProtocol>
            ariaLabel="Identity federation protocol"
            value={protocol}
            onChange={(next) => {
              if (isIdpProtocol(next)) setProtocol(next);
            }}
            options={[
              { value: "oidc", label: "OIDC" },
              { value: "saml", label: "SAML 2.0" },
            ]}
          />

          <div className="op-form-grid">
            <TextInput
              label={protocol === "oidc" ? "OIDC issuer URL" : "SAML metadata URL"}
              value={issuerUrl}
              onChange={setIssuerUrl}
              width="100%"
            />
            <TextInput
              label={protocol === "oidc" ? "Client ID" : "SP entity ID"}
              value={clientId}
              onChange={setClientId}
              width="100%"
            />
            <TextInput label="Role and group claim" value={groupClaim} onChange={setGroupClaim} width="100%" />
            <GrdrSelect
              label="SCIM bearer rotation"
              value={scimCadence}
              onChange={(val) => {
                if (isScimCadence(val)) setScimCadence(val);
              }}
              options={[
                { value: "30d", label: "Every 30 days" },
                { value: "90d", label: "Every 90 days" },
                { value: "180d", label: "Every 180 days" },
              ]}
            />
          </div>

          <div className="kv-row">
            <CheckboxInput
              label="Enable SCIM 2.0 group and user deprovisioning (/scim/v2)"
              value={scimEnabled}
              onChange={setScimEnabled}
            />
            <Button size="sm" variant="primary" label="Validate and stage SSO" onClick={stageIdpSettings} />
          </div>
        </VStack>
      </Card>

      <Card padding={3}>
        <VStack gap={3}>
          <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
            <VStack gap={0}>
              <Heading level={2}>Outbound mailer and alert delivery</Heading>
              <Text size="sm" color="secondary">
                Configure SMTP relay settings for approval digests, recovery notices, and lock alerts.
              </Text>
            </VStack>
            <Badge variant="warning" label="Host CLI required" />
          </HStack>

          <div className="op-form-grid">
            <TextInput label="SMTP relay host" value={smtpHost} onChange={setSmtpHost} width="100%" />
            <TextInput label="SMTP port" value={smtpPort} onChange={setSmtpPort} width="100%" />
            <GrdrSelect
              label="Transport security"
              value={tlsMode}
              onChange={(val) => {
                if (isMailerTlsMode(val)) setTlsMode(val);
              }}
              options={[
                { value: "starttls", label: "STARTTLS (587)" },
                { value: "smtps", label: "Implicit TLS (465)" },
              ]}
            />
            <TextInput label="From sender address" value={senderAddress} onChange={setSenderAddress} width="100%" />
            <TextInput label="Probe recipient" value={testRecipient} onChange={setTestRecipient} width="100%" />
          </div>

          <div className="op-actions-row">
            <Button size="sm" variant="secondary" label="Stage SMTP probe" onClick={stageMailerSettings} />
            <Button size="sm" variant="ghost" label="Copy TOML config" onClick={() => void copyToml()} />
          </div>

          <pre className="op-pre">{combinedToml}</pre>
        </VStack>
      </Card>

      <div className="quiet-split">
        <section className="ledger-section">
          <div className="ledger-header" style={{ flexWrap: "wrap", gap: 8 }}>
            <Heading level={2}>Active runtime profile summary</Heading>
            <Button
              size="sm"
              variant="secondary"
              label="Edit in Upgrades"
              endContent={<GrdrIcon name="arrow-right" size={13} />}
              onClick={() => onNavigate("op-upgrades")}
            />
          </div>
          <div className="kv-row">
            <Text color="secondary">Privacy regime</Text>
            <Text className="mono">{capitalizeLabel(cfg.privacy_profile.replace(/-/g, " "))}</Text>
          </div>
          <div className="kv-row">
            <Text color="secondary">Capture ceiling</Text>
            <Text className="mono">{cfg.capture_level}</Text>
          </div>
          <div className="kv-row">
            <Text color="secondary">Retention preset</Text>
            <Text className="mono">{cfg.retention_preset}</Text>
          </div>
          <div className="kv-row">
            <Text color="secondary">Operator realm auth</Text>
            <StatusInline
              tone={hasOperatorToken ? "allow" : "ask"}
              dot
              label={hasOperatorToken ? "Session token active" : "Host session active"}
            />
          </div>
        </section>

        <section className="ledger-section">
          <div className="ledger-header" style={{ flexWrap: "wrap", gap: 8 }}>
            <Heading level={2}>Receipt signing keys</Heading>
            <Button
              size="sm"
              variant="secondary"
              label="Open key ceremony"
              endContent={<GrdrIcon name="arrow-right" size={13} />}
              onClick={() => onNavigate("op-keys")}
            />
          </div>
          {snapshot.keys.length === 0 ? (
            <EmptyState
              title="No signing keys registered"
              description="Register an Ed25519 signing key before activating fleet telemetry."
              icon={<GrdrIcon name="key-round" size={20} />}
            />
          ) : (
            <div className="table-wrap">
              <table className="table responsive-table">
                <thead>
                  <tr>
                    <th>Key ID</th>
                    <th>Public key (base64)</th>
                  </tr>
                </thead>
                <tbody>
                  {snapshot.keys.map((key) => (
                    <tr key={key.key_id}>
                      <td data-label="Key ID" className="mono">{key.key_id}</td>
                      <td data-label="Public key (base64)" className="mono">{key.public_key_b64}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>
    </VStack>
  );
}
