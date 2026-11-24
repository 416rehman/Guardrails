import { useEffect, useState } from "react";
import {
  api,
  type ConnectConfigResponse,
  type CreateDeploymentKeyResponse,
  type IntegrationEntry,
  type MdmFormat,
  type MdmRenderResponse,
} from "@grdr/api";
import { presentDeploymentKeyStatus, presentInstallProfile } from "@grdr/i18n";
import { Quoted } from "@grdr/kit";
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
  UiSdkSegmentedControl,
  VStack,
} from "@grdr/ui";
import { ConnectMdmAndIntegrations } from "./ConnectMdmAndIntegrations";

export function ConnectSection() {
  const [config, setConfig] = useState<ConnectConfigResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [platform, setPlatform] = useState<string>("macos");
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const [keyLabel, setKeyLabel] = useState("Finance Pilot");
  const [keyWave, setKeyWave] = useState("wave-3");
  const [keyProfile, setKeyProfile] = useState("standard");
  const [keyMaxUses, setKeyMaxUses] = useState("50");
  const [keyTtlDays, setKeyTtlDays] = useState("30");
  const [createdKey, setCreatedKey] = useState<CreateDeploymentKeyResponse | null>(null);
  const [issuingKey, setIssuingKey] = useState(false);

  const [mdmFormat, setMdmFormat] = useState<MdmFormat>("intune_win32");
  const [selectedKeyId, setSelectedKeyId] = useState<string>("");
  const [includeBrowser, setIncludeBrowser] = useState<"enabled" | "disabled">("enabled");
  const [updateAuthority, setUpdateAuthority] = useState<"managed" | "self">("managed");
  const [renderedMdm, setRenderedMdm] = useState<MdmRenderResponse | null>(null);
  const [checkingId, setCheckingId] = useState<string | null>(null);

  async function loadConfig() {
    setError(null);
    try {
      const next = await api.getConnectConfig();
      setConfig(next);
      setSelectedKeyId((prev) => {
        if (prev && next.deployment_keys.some((k) => k.id === prev)) return prev;
        return next.deployment_keys.find((k) => k.status === "active")?.id ?? "";
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed loading Connect configuration.");
    }
  }

  useEffect(() => {
    void loadConfig();
  }, []);

  useEffect(() => {
    if (!config) return;
    let active = true;
    void api
      .renderMdmConfig({
        format: mdmFormat,
        deployment_key_id: selectedKeyId || null,
        include_browser_extension: includeBrowser === "enabled",
        update_authority: updateAuthority,
      })
      .then((res) => {
        if (active) setRenderedMdm(res);
      })
      .catch((err) => {
        if (active) setError(err instanceof Error ? err.message : "Failed rendering MDM payload.");
      });
    return () => {
      active = false;
    };
  }, [config, mdmFormat, selectedKeyId, includeBrowser, updateAuthority]);

  function copySnippet(id: string, value: string) {
    if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
      void navigator.clipboard.writeText(value);
    }
    setCopiedId(id);
    setTimeout(() => {
      setCopiedId((prev) => (prev === id ? null : prev));
    }, 1800);
  }

  async function handleIssueKey() {
    setIssuingKey(true);
    setError(null);
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
      setCreatedKey(res);
      setSelectedKeyId(res.key.id);
      await loadConfig();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed issuing deployment key.");
    } finally {
      setIssuingKey(false);
    }
  }

  async function handleRevokeKey(id: string) {
    setError(null);
    try {
      await api.revokeDeploymentKey(id);
      await loadConfig();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed revoking deployment key.");
    }
  }

  async function handleCheckReadiness(item: IntegrationEntry) {
    setCheckingId(item.id);
    setError(null);
    try {
      const updated = await api.checkIntegrationReadiness(item.id);
      setConfig((prev) =>
        prev
          ? {
              ...prev,
              integrations: prev.integrations.map((entry) =>
                entry.id === updated.id ? updated : entry,
              ),
            }
          : prev,
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed verifying integration readiness.");
    } finally {
      setCheckingId(null);
    }
  }

  if (!config && !error) {
    return (
      <Card padding={3}>
        <Text color="secondary">Loading endpoint onboarding, MDM configs, and identity sync state...</Text>
      </Card>
    );
  }

  const activeInstaller =
    config?.installers.find((item) => item.platform === platform) ?? config?.installers[0];

  return (
    <VStack gap={4}>
      {error && (
        <Banner status="error" title={error} collapsible={false} />
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

      {config && (
        <>
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
                      { value: "macos", label: "macOS" },
                      { value: "windows", label: "Windows" },
                      { value: "linux", label: "Linux" },
                    ]}
                    onChange={setPlatform}
                  />
                </HStack>

                {activeInstaller && (
                  <VStack gap={2}>
                    <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
                      <Text size="sm" style={{ fontWeight: 600 }}>
                        {`${activeInstaller.label} v${activeInstaller.version}`}
                      </Text>
                      <Button
                        size="sm"
                        variant="secondary"
                        label={copiedId === "installer-cmd" ? "Copied" : "Copy install command"}
                        onClick={() => copySnippet("installer-cmd", activeInstaller.command)}
                      />
                    </HStack>
                    <pre className="connect-payload mono">{activeInstaller.command}</pre>
                    <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
                      <Text size="sm" color="secondary">
                        SHA-256 verification digest
                      </Text>
                      <Quoted text={`${activeInstaller.sha256.slice(0, 16)}...`} />
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
                    <Text size="sm" color="secondary">OTLP gRPC endpoint</Text>
                    <Quoted text={`${config.otlp.bind_address}:${config.otlp.grpc_port}`} />
                  </div>
                  <div className="risk-driver-row">
                    <Text size="sm" color="secondary">OTLP HTTP endpoint</Text>
                    <Quoted text={`${config.otlp.bind_address}:${config.otlp.http_port}`} />
                  </div>
                  <div className="risk-driver-row">
                    <Text size="sm" color="secondary">Accepted spans (24h)</Text>
                    <span className="mono tabular" style={{ fontWeight: 600 }}>
                      {config.otlp.accepted_spans_24h.toLocaleString()}
                    </span>
                  </div>
                  <div className="risk-driver-row">
                    <Text size="sm" color="secondary">Listener scope</Text>
                    <Badge
                      variant={config.otlp.loopback_only ? "success" : "warning"}
                      label={config.otlp.loopback_only ? "Loopback only" : "LAN bound"}
                    />
                  </div>
                </div>

                <VStack gap={1}>
                  <Text size="sm" style={{ fontWeight: 600 }}>
                    Downstream export targets
                  </Text>
                  {config.otlp.downstream_targets.map((target) => (
                    <Quoted key={target} text={target} />
                  ))}
                </VStack>
              </VStack>
            </Card>
          </div>

          <Card padding={3}>
            <VStack gap={3}>
              <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
                <VStack gap={0}>
                  <Heading level={2}>{`Wave deployment keys (${config.deployment_keys.length})`}</Heading>
                  <Text size="sm" color="secondary">
                    Scoped enrollment tokens with per-wave seat quotas and explicit revocation.
                  </Text>
                </VStack>
              </HStack>

              <div className="connect-key-form">
                <TextInput label="Wave label" value={keyLabel} onChange={setKeyLabel} />
                <TextInput label="Wave cohort" value={keyWave} onChange={setKeyWave} />
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
                  onChange={setKeyProfile}
                />
                <TextInput label="Max uses" value={keyMaxUses} onChange={setKeyMaxUses} />
                <TextInput label="Valid days" value={keyTtlDays} onChange={setKeyTtlDays} />
                <div className="connect-key-submit">
                  <Button
                    variant="primary"
                    icon={<GrdrIcon name="key-round" size={14} />}
                    label={issuingKey ? "Issuing..." : "Issue wave key"}
                    isDisabled={issuingKey}
                    onClick={handleIssueKey}
                  />
                </div>
              </div>

              <div className="table-wrap">
                <table>
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
                    {config.deployment_keys.map((key) => {
                      const st = presentDeploymentKeyStatus(key.status);
                      const pct =
                        key.max_uses > 0
                          ? Math.min(100, Math.round((key.used_count / key.max_uses) * 100))
                          : 0;
                      const barColor =
                        key.status === "revoked" || key.status === "expired"
                          ? "var(--ink-muted)"
                          : pct >= 85
                            ? "var(--tone-ask)"
                            : "var(--accent-primary)";
                      return (
                        <tr key={key.id}>
                          <td>
                            <VStack gap={1}>
                              <span style={{ fontWeight: 600 }}>{key.label}</span>
                              <Quoted text={key.token_preview} />
                            </VStack>
                          </td>
                          <td>
                            <Badge variant="neutral" label={presentInstallProfile(key.install_profile)} />
                          </td>
                          <td style={{ minWidth: 160 }}>
                            <VStack gap={1}>
                              <Text size="sm" className="tabular">
                                {`${key.used_count} / ${key.max_uses} seats`}
                              </Text>
                              <div
                                className="quota-bar-rail"
                                role="progressbar"
                                aria-label={`${key.label} quota`}
                                aria-valuenow={pct}
                                aria-valuemin={0}
                                aria-valuemax={100}
                              >
                                <div
                                  className="quota-bar-fill"
                                  style={{
                                    width: `${Math.max(4, pct)}%`,
                                    backgroundColor: barColor,
                                  }}
                                />
                              </div>
                            </VStack>
                          </td>
                          <td>
                            <StatusInline tone={st.tone} dot label={st.label} />
                          </td>
                          <td>
                            <Text size="sm" color="secondary">{key.created_by}</Text>
                          </td>
                          <td>
                            {key.status === "active" ? (
                              <Button
                                size="sm"
                                variant="secondary"
                                label="Revoke"
                                onClick={() => handleRevokeKey(key.id)}
                              />
                            ) : (
                              <Text size="sm" color="secondary">Closed</Text>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </VStack>
          </Card>

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
            onCheckReadiness={handleCheckReadiness}
          />
        </>
      )}
    </VStack>
  );
}
