// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
import { useEffect, useState } from "react";
import {
  api,
  type ConnectConfigResponse,
  type CreateDeploymentKeyResponse,
  type IntegrationEntry,
  type MdmFormat,
  type MdmRenderResponse,
} from "@grdr/api";
import { Quoted } from "@grdr/kit";
import {
  Badge,
  Banner,
  Button,
  Card,
  EmptyState,
  GrdrIcon,
  Heading,
  HStack,
  OsIcon,
  StatusInline,
  Text,
  UiSdkSegmentedControl,
  VStack,
} from "@grdr/ui";
import { ConnectMdmAndIntegrations } from "./ConnectMdmAndIntegrations";
import { ConnectWaveKeysSection } from "./ConnectWaveKeysSection";

type ConnectLoadState =
  | { kind: "loading" }
  | { kind: "ready"; config: ConnectConfigResponse; actionError?: string }
  | { kind: "error"; message: string };

type IssueKeyState =
  | { kind: "idle" }
  | { kind: "issuing" }
  | { kind: "issued"; created: CreateDeploymentKeyResponse }
  | { kind: "failed"; message: string };

type MdmRenderState =
  | { kind: "idle" }
  | { kind: "rendering"; previous?: MdmRenderResponse }
  | { kind: "ready"; payload: MdmRenderResponse }
  | { kind: "failed"; message: string; previous?: MdmRenderResponse };

type ReadinessCheckState =
  | { kind: "idle" }
  | { kind: "checking"; integrationId: string }
  | { kind: "failed"; message: string };

type CopyState =
  | { kind: "idle" }
  | { kind: "copied"; snippetId: string }
  | { kind: "failed"; message: string };

export function ConnectSection() {
  const [loadState, setLoadState] = useState<ConnectLoadState>({ kind: "loading" });
  const [platform, setPlatform] = useState<string>("macos");
  const [copyState, setCopyState] = useState<CopyState>({ kind: "idle" });

  const [keyLabel, setKeyLabel] = useState("Finance Pilot");
  const [keyWave, setKeyWave] = useState("wave-1");
  const [keyProfile, setKeyProfile] = useState("standard");
  const [keyMaxUses, setKeyMaxUses] = useState("50");
  const [keyTtlDays, setKeyTtlDays] = useState("30");
  const [issueState, setIssueState] = useState<IssueKeyState>({ kind: "idle" });

  const [mdmFormat, setMdmFormat] = useState<MdmFormat>("intune_win32");
  const [selectedKeyId, setSelectedKeyId] = useState<string>("");
  const [includeBrowser, setIncludeBrowser] = useState<"enabled" | "disabled">("enabled");
  const [updateAuthority, setUpdateAuthority] = useState<"managed" | "self">("managed");
  const [mdmState, setMdmState] = useState<MdmRenderState>({ kind: "idle" });
  const [readinessState, setReadinessState] = useState<ReadinessCheckState>({ kind: "idle" });

  const loadedConfig = loadState.kind === "ready" ? loadState.config : null;

  async function loadConfig() {
    setLoadState((prev) => (prev.kind === "error" ? { kind: "loading" } : prev));
    try {
      const next = await api.getConnectConfig();
      setLoadState({ kind: "ready", config: next });
      setKeyWave((prev) =>
        prev === "wave-1" && next.deployment_keys.length > 0
          ? `wave-${next.deployment_keys.length + 1}`
          : prev,
      );
      setSelectedKeyId((prev) => {
        if (prev && next.deployment_keys.some((k) => k.id === prev)) return prev;
        return next.deployment_keys.find((k) => k.status === "active")?.id ?? "";
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed loading Connect configuration.";
      setLoadState((prev) =>
        prev.kind === "ready"
          ? { kind: "ready", config: prev.config, actionError: message }
          : { kind: "error", message },
      );
    }
  }

  useEffect(() => {
    void loadConfig();
  }, []);

  useEffect(() => {
    if (!loadedConfig) return;
    let active = true;
    setMdmState((prev) => ({
      kind: "rendering",
      previous: prev.kind === "ready" ? prev.payload : prev.kind === "rendering" ? prev.previous : undefined,
    }));
    void api
      .renderMdmConfig({
        format: mdmFormat,
        deployment_key_id: selectedKeyId || null,
        include_browser_extension: includeBrowser === "enabled",
        update_authority: updateAuthority,
      })
      .then((res) => {
        if (active) setMdmState({ kind: "ready", payload: res });
      })
      .catch((err) => {
        if (active) {
          const message = err instanceof Error ? err.message : "Failed rendering MDM payload.";
          setMdmState((prev) => ({
            kind: "failed",
            message,
            previous: prev.kind === "rendering" ? prev.previous : undefined,
          }));
        }
      });
    return () => {
      active = false;
    };
  }, [loadedConfig, mdmFormat, selectedKeyId, includeBrowser, updateAuthority]);

  async function writeClipboardSnippet(id: string, value: string) {
    if (typeof navigator === "undefined" || typeof navigator.clipboard?.writeText !== "function") {
      setCopyState({
        kind: "failed",
        message: "Clipboard access is unavailable in this browser context. Copy the snippet manually.",
      });
      return;
    }
    try {
      await navigator.clipboard.writeText(value);
      setCopyState({ kind: "copied", snippetId: id });
      setTimeout(() => {
        setCopyState((prev) => (prev.kind === "copied" && prev.snippetId === id ? { kind: "idle" } : prev));
      }, 1800);
    } catch {
      setCopyState({
        kind: "failed",
        message: "Clipboard write was rejected by the browser. Copy the snippet manually.",
      });
    }
  }

  function copySnippet(id: string, value: string) {
    void writeClipboardSnippet(id, value);
  }

  async function handleIssueKey() {
    setIssueState({ kind: "issuing" });
    try {
      const maxUses = Math.max(1, Number.parseInt(keyMaxUses, 10) || 50);
      const ttlDays = Math.max(1, Number.parseInt(keyTtlDays, 10) || 30);
      const res = await api.createDeploymentKey({
        label: keyLabel,
        wave: keyWave,
        install_profile: keyProfile,
        max_uses: maxUses,
        ttl_days: ttlDays,
      });
      setIssueState({ kind: "issued", created: res });
      setSelectedKeyId(res.key.id);
      await loadConfig();
    } catch (err) {
      setIssueState({
        kind: "failed",
        message: err instanceof Error ? err.message : "Failed issuing deployment key.",
      });
    }
  }

  async function handleRevokeKey(id: string) {
    setLoadState((prev) =>
      prev.kind === "ready" ? { kind: "ready", config: prev.config } : prev,
    );
    try {
      await api.revokeDeploymentKey(id);
      await loadConfig();
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed revoking deployment key.";
      setLoadState((prev) =>
        prev.kind === "ready"
          ? { kind: "ready", config: prev.config, actionError: message }
          : { kind: "error", message },
      );
    }
  }

  async function handleCheckReadiness(item: IntegrationEntry) {
    setReadinessState({ kind: "checking", integrationId: item.id });
    try {
      const updated = await api.checkIntegrationReadiness(item.id);
      setLoadState((prev) =>
        prev.kind === "ready"
          ? {
              kind: "ready",
              config: {
                ...prev.config,
                integrations: prev.config.integrations.map((entry) =>
                  entry.id === updated.id ? updated : entry,
                ),
              },
            }
          : prev,
      );
      setReadinessState({ kind: "idle" });
    } catch (err) {
      setReadinessState({
        kind: "failed",
        message: err instanceof Error ? err.message : "Failed verifying integration readiness.",
      });
    }
  }

  if (loadState.kind === "loading") {
    return (
      <Card padding={3}>
        <Text color="secondary">
          Loading endpoint onboarding, MDM payloads, and identity sync state...
        </Text>
      </Card>
    );
  }

  if (loadState.kind === "error") {
    return (
      <Banner
        status="error"
        title={loadState.message}
        collapsible={false}
        endContent={
          <Button variant="secondary" size="sm" label="Retry" onClick={() => void loadConfig()} />
        }
      />
    );
  }

  const config = loadState.config;
  const errorMessage =
    loadState.actionError ??
    (issueState.kind === "failed"
      ? issueState.message
      : mdmState.kind === "failed"
        ? mdmState.message
        : readinessState.kind === "failed"
          ? readinessState.message
          : copyState.kind === "failed"
            ? copyState.message
            : undefined);
  const createdKey = issueState.kind === "issued" ? issueState.created : null;
  const issuingKey = issueState.kind === "issuing";
  const copiedId = copyState.kind === "copied" ? copyState.snippetId : null;
  const checkingId = readinessState.kind === "checking" ? readinessState.integrationId : null;
  const renderedMdm =
    mdmState.kind === "ready"
      ? mdmState.payload
      : mdmState.kind === "rendering" || mdmState.kind === "failed"
        ? (mdmState.previous ?? null)
        : null;

  const browserOrigin =
    typeof window !== "undefined" && window.location?.origin ? window.location.origin : "";
  const originMismatch =
    Boolean(browserOrigin) &&
    Boolean(config.server_origin) &&
    browserOrigin !== config.server_origin &&
    !browserOrigin.startsWith("http://localhost:");

  const activeInstaller =
    config.installers.find((item) => item.platform === platform) ?? config.installers[0];

  return (
    <VStack gap={4}>
      {errorMessage && <Banner status="error" title={errorMessage} collapsible={false} />}

      {originMismatch && (
        <Banner
          status="info"
          title={`Installer payloads target ${config.server_origin}`}
          description={`You are viewing the console at ${browserOrigin}. Update the server external origin setting before rolling out MDM scripts to remote endpoints.`}
          collapsible={false}
        />
      )}

      {createdKey && (
        <Banner
          status="success"
          title={`One-time wave key issued for ${createdKey.key.label}`}
          description={`Copy this enrollment token now. Only its short prefix (${createdKey.key.token_preview}) remains visible later: ${createdKey.plaintext_token}`}
          collapsible={false}
          endContent={
            <Button
              size="sm"
              variant="secondary"
              label={copiedId === "created-key" ? "Copied" : "Copy token"}
              onClick={() => copySnippet("created-key", createdKey.plaintext_token)}
            />
          }
        />
      )}

      <div className="grid-2">
        <Card padding={3}>
          <VStack gap={3}>
            <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
              <HStack gap={2} align="center">
                <GrdrIcon name="terminal" size={16} />
                <Heading level={2}>Endpoint installers</Heading>
              </HStack>
              <UiSdkSegmentedControl<string>
                ariaLabel="Installer operating system"
                value={platform}
                options={[
                  { value: "macos", label: "macOS", icon: <OsIcon os="macos" size={13} /> },
                  { value: "windows", label: "Windows", icon: <OsIcon os="windows" size={13} /> },
                  { value: "linux", label: "Linux", icon: <OsIcon os="linux" size={13} /> },
                ]}
                onChange={setPlatform}
              />
            </HStack>

            {config.server_origin && (
              <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
                <Text size="sm" color="secondary">
                  Enrollment server origin
                </Text>
                <Quoted text={config.server_origin} />
              </HStack>
            )}

            {activeInstaller ? (
              <VStack gap={2}>
                <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
                  <Text size="sm" weight="semibold">
                    {`${activeInstaller.label} v${activeInstaller.version}`}
                  </Text>
                  <Button
                    size="sm"
                    variant="secondary"
                    label={copiedId === "installer-cmd" ? "Copied" : "Copy install command"}
                    onClick={() => copySnippet("installer-cmd", activeInstaller.command)}
                  />
                </HStack>
                <pre
                  className="connect-payload mono"
                  style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}
                >
                  {activeInstaller.command}
                </pre>
                <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
                  <Text size="sm" color="secondary">
                    SHA-256 verification digest
                  </Text>
                  <HStack gap={2} align="center" style={{ flexWrap: "wrap" }}>
                    <Quoted text={`${activeInstaller.sha256.slice(0, 16)}...`} />
                    <Button
                      size="sm"
                      variant="ghost"
                      label={copiedId === "installer-sha" ? "Copied" : "Copy SHA-256"}
                      onClick={() => copySnippet("installer-sha", activeInstaller.sha256)}
                    />
                  </HStack>
                </HStack>
                <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
                  <Text size="sm" color="secondary">
                    Connectivity & proxy preflight
                  </Text>
                  <Quoted text={activeInstaller.doctor_command} />
                </HStack>
                <Text size="sm" color="secondary">
                  {activeInstaller.notes}
                </Text>
              </VStack>
            ) : (
              <EmptyState
                title="No installer manifests returned"
                description="Verify server binary packaging and download route availability."
                icon={<GrdrIcon name="terminal" size={20} />}
              />
            )}
          </VStack>
        </Card>

        <Card padding={3}>
          <VStack gap={3}>
            <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
              <HStack gap={2} align="center">
                <GrdrIcon name="radio" size={16} />
                <Heading level={2}>Local OTLP collector fan-out</Heading>
              </HStack>
              <StatusInline
                tone={config.otlp.enabled ? "allow" : "neutral"}
                dot
                label={config.otlp.enabled ? "Loopback active" : "Disabled"}
              />
            </HStack>

            <div className="risk-driver-grid">
              <div className="risk-driver-row">
                <Text size="sm" color="secondary">
                  OTLP gRPC endpoint
                </Text>
                <Quoted text={`${config.otlp.bind_address}:${config.otlp.grpc_port}`} />
              </div>
              <div className="risk-driver-row">
                <Text size="sm" color="secondary">
                  OTLP HTTP endpoint
                </Text>
                <Quoted text={`${config.otlp.bind_address}:${config.otlp.http_port}`} />
              </div>
              <div className="risk-driver-row">
                <Text size="sm" color="secondary">
                  Accepted spans (24h)
                </Text>
                <span className="mono tabular" style={{ fontWeight: 600 }}>
                  {config.otlp.accepted_spans_24h.toLocaleString()}
                </span>
              </div>
              <div className="risk-driver-row">
                <Text size="sm" color="secondary">
                  Listener scope
                </Text>
                <Badge
                  variant={config.otlp.loopback_only ? "success" : "warning"}
                  label={config.otlp.loopback_only ? "Loopback only" : "LAN bound"}
                />
              </div>
            </div>

            <VStack gap={1}>
              <Text size="sm" weight="semibold">
                Downstream export targets
              </Text>
              {config.otlp.downstream_targets.length === 0 ? (
                <Text size="sm" color="secondary">
                  No downstream collectors configured yet. Configure OTLP destinations in deployment settings.
                </Text>
              ) : (
                config.otlp.downstream_targets.map((target) => (
                  <Quoted key={target} text={target} />
                ))
              )}
            </VStack>
          </VStack>
        </Card>
      </div>

      <ConnectWaveKeysSection
        keys={config.deployment_keys}
        keyLabel={keyLabel}
        onChangeKeyLabel={setKeyLabel}
        keyWave={keyWave}
        onChangeKeyWave={setKeyWave}
        keyProfile={keyProfile}
        onChangeKeyProfile={setKeyProfile}
        keyMaxUses={keyMaxUses}
        onChangeKeyMaxUses={setKeyMaxUses}
        keyTtlDays={keyTtlDays}
        onChangeKeyTtlDays={setKeyTtlDays}
        issuingKey={issuingKey}
        onIssueKey={() => void handleIssueKey()}
        onRevokeKey={(id) => void handleRevokeKey(id)}
      />

      <ConnectMdmAndIntegrations
        config={config}
        mdmFormat={mdmFormat}
        onChangeMdmFormat={setMdmFormat}
        selectedKeyId={selectedKeyId}
        onChangeSelectedKeyId={setSelectedKeyId}
        includeBrowser={includeBrowser}
        onChangeIncludeBrowser={setIncludeBrowser}
        updateAuthority={updateAuthority}
        onChangeUpdateAuthority={setUpdateAuthority}
        renderedMdm={renderedMdm}
        copiedId={copiedId}
        onCopySnippet={copySnippet}
        checkingId={checkingId}
        onCheckReadiness={(item) => void handleCheckReadiness(item)}
      />
    </VStack>
  );
}
