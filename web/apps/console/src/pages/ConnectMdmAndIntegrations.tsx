// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
import type {
  ConnectConfigResponse,
  IntegrationEntry,
  MdmFormat,
  MdmRenderResponse,
} from "@grdr/api";
import {
  capitalizeLabel,
  formatTimestamp,
  pluralize,
  presentIntegrationCategory,
  presentIntegrationHealth,
  presentMdmFormat,
} from "@grdr/i18n";
import { Quoted } from "@grdr/kit";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  GrdrIcon,
  GrdrSelect,
  Heading,
  HStack,
  StatusInline,
  Text,
  UiSdkSegmentedControl,
  VStack,
} from "@grdr/ui";

const MDM_FORMATS: MdmFormat[] = [
  "intune_win32",
  "jamf_mobileconfig",
  "hexnode",
  "tanium",
  "chrome_enterprise",
  "firefox_gpo",
  "linux_repo",
];

function isMdmFormat(value: string): value is MdmFormat {
  return MDM_FORMATS.some((fmt) => fmt === value);
}

function badgeVariantForTone(
  tone: "allow" | "ask" | "block" | "neutral",
): "success" | "warning" | "error" | "neutral" {
  switch (tone) {
    case "allow":
      return "success";
    case "ask":
      return "warning";
    case "block":
      return "error";
    case "neutral":
      return "neutral";
  }
}

const ALLOWED_DOWNLOAD_MIME = new Set([
  "text/plain",
  "application/json",
  "text/csv",
  "text/markdown",
  "application/xml",
]);

function sanitizeDownloadFilename(raw: string, fallback: string): string {
  const leaf = raw.replace(/[\u0000-\u001f\u007f]/g, "").split(/[\\/]/).pop() ?? "";
  const stripped = leaf.replace(/\.\.+/g, ".").replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^[.-]+/, "");
  return stripped.length > 0 ? stripped : fallback;
}

function resolveDownloadMime(raw: string): string {
  const normalized = raw.split(";")[0]?.trim().toLowerCase() ?? "";
  return ALLOWED_DOWNLOAD_MIME.has(normalized) ? normalized : "text/plain";
}

function downloadPayload(filename: string, contentType: string, payload: string) {
  const safeName = sanitizeDownloadFilename(filename, "guardrails-mdm-payload.txt");
  const safeMime = resolveDownloadMime(contentType);
  const blob = new Blob([payload], { type: safeMime });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = safeName;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

interface ConnectMdmAndIntegrationsProps {
  config: ConnectConfigResponse;
  mdmFormat: MdmFormat;
  onChangeMdmFormat: (fmt: MdmFormat) => void;
  selectedKeyId: string;
  onChangeSelectedKeyId: (id: string) => void;
  includeBrowser: "enabled" | "disabled";
  onChangeIncludeBrowser: (v: "enabled" | "disabled") => void;
  updateAuthority: "managed" | "self";
  onChangeUpdateAuthority: (v: "managed" | "self") => void;
  renderedMdm: MdmRenderResponse | null;
  copiedId: string | null;
  onCopySnippet: (id: string, value: string) => void;
  checkingId: string | null;
  onCheckReadiness: (entry: IntegrationEntry) => void;
}

export function ConnectMdmAndIntegrations({
  config,
  mdmFormat,
  onChangeMdmFormat,
  selectedKeyId,
  onChangeSelectedKeyId,
  includeBrowser,
  onChangeIncludeBrowser,
  updateAuthority,
  onChangeUpdateAuthority,
  renderedMdm,
  copiedId,
  onCopySnippet,
  checkingId,
  onCheckReadiness,
}: ConnectMdmAndIntegrationsProps) {
  return (
    <>
      <Card padding={3}>
        <VStack gap={3}>
          <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
            <VStack gap={0}>
              <Heading level={2}>MDM & managed browser payload generator</Heading>
              <Text size="sm" color="secondary">
                Render deployment payloads pre-bound to your active server origin and selected wave key.
              </Text>
            </VStack>
            <HStack gap={2} align="center" style={{ flexWrap: "wrap" }}>
              {config.server_origin && <Quoted text={config.server_origin} />}
              {renderedMdm && (
                <>
                  <Button
                    size="sm"
                    variant="secondary"
                    icon={<GrdrIcon name="download" size={13} />}
                    label="Download"
                    onClick={() =>
                      downloadPayload(
                        renderedMdm.filename,
                        renderedMdm.content_type,
                        renderedMdm.payload,
                      )
                    }
                  />
                  <Button
                    size="sm"
                    variant="secondary"
                    label={copiedId === "mdm-payload" ? "Copied" : `Copy ${renderedMdm.filename}`}
                    onClick={() => onCopySnippet("mdm-payload", renderedMdm.payload)}
                  />
                </>
              )}
            </HStack>
          </HStack>

          <div className="facet-bar">
            <HStack gap={2} align="center" style={{ flexWrap: "wrap" }}>
              <GrdrSelect
                label="MDM platform"
                isLabelHidden
                size="sm"
                variant="secondary"
                value={mdmFormat}
                options={MDM_FORMATS.map((fmt) => ({
                  value: fmt,
                  label: presentMdmFormat(fmt),
                }))}
                onChange={(val) => {
                  if (isMdmFormat(val)) onChangeMdmFormat(val);
                }}
              />
              <GrdrSelect
                label="Wave key"
                isLabelHidden
                size="sm"
                variant="secondary"
                value={selectedKeyId}
                options={[
                  { value: "", label: "No pre-bound wave key" },
                  ...config.deployment_keys.map((k) => ({
                    value: k.id,
                    label: k.label,
                  })),
                ]}
                onChange={onChangeSelectedKeyId}
              />
            </HStack>

            <HStack gap={2} align="center" style={{ flexWrap: "wrap" }}>
              <UiSdkSegmentedControl<"enabled" | "disabled">
                ariaLabel="Include browser extension policy"
                value={includeBrowser}
                options={[
                  { value: "enabled", label: "Browser ext on" },
                  { value: "disabled", label: "Browser ext off" },
                ]}
                onChange={onChangeIncludeBrowser}
              />
              <UiSdkSegmentedControl<"managed" | "self">
                ariaLabel="Update authority"
                value={updateAuthority}
                options={[
                  { value: "managed", label: "MDM updates" },
                  { value: "self", label: "Self updates" },
                ]}
                onChange={onChangeUpdateAuthority}
              />
            </HStack>
          </div>

          {renderedMdm && (
            <VStack gap={2}>
              <pre
                className="connect-payload mono"
                style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}
              >
                {renderedMdm.payload}
              </pre>
              <VStack gap={1}>
                {renderedMdm.deployment_notes.map((note) => (
                  <Text key={note} size="sm" color="secondary">
                    {note}
                  </Text>
                ))}
              </VStack>
            </VStack>
          )}
        </VStack>
      </Card>

      <Card padding={3}>
        <VStack gap={3}>
          <VStack gap={0}>
            <Heading level={2}>{`Directory sync & SaaS connectors (${config.integrations.length})`}</Heading>
            <Text size="sm" color="secondary">
              Pull identity sync health, 14-day credential rotation warnings, and live readiness checks.
            </Text>
          </VStack>

          {config.integrations.length === 0 ? (
            <EmptyState
              title="No directory sync or SaaS connectors configured"
              description="Configure SCIM or SaaS compliance integrations in deployment settings to verify live connectivity."
              icon={<GrdrIcon name="plug" size={20} />}
            />
          ) : (
            <div className="grid-2">
              {config.integrations.map((item) => {
                const health = presentIntegrationHealth(item.state);
                const syncLabel = item.last_sync_at
                  ? `Last sync ${formatTimestamp(item.last_sync_at)}`
                  : "Never synced";
                return (
                  <Card key={item.id} padding={2}>
                    <VStack gap={2}>
                      <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
                        <VStack gap={0}>
                          <Text weight="semibold">{item.name}</Text>
                          <Text size="sm" color="secondary">
                            {`${presentIntegrationCategory(item.category)} · ${pluralize(item.synced_users, "user")} · ${syncLabel}`}
                          </Text>
                        </VStack>
                        <Badge
                          variant={badgeVariantForTone(health.tone)}
                          label={
                            item.state === "at_risk" && item.credential_expires_in_days !== null
                              ? `${capitalizeLabel(health.label)}: ${item.credential_expires_in_days}d expiry`
                              : capitalizeLabel(health.label)
                          }
                        />
                      </HStack>

                      <Text size="sm" color="secondary">
                        {item.detail}
                      </Text>

                      <VStack gap={1}>
                        {item.readiness_checks.map((chk) => (
                          <HStack
                            key={chk.name}
                            justify="between"
                            align="center"
                            style={{ gap: 8, flexWrap: "wrap" }}
                          >
                            <StatusInline
                              tone={chk.passed ? "allow" : "block"}
                              icon={
                                <GrdrIcon
                                  name={chk.passed ? "check-circle" : "alert-circle"}
                                  size={12}
                                />
                              }
                              label={chk.name}
                            />
                            <Text size="sm" color="secondary">
                              {chk.detail}
                            </Text>
                          </HStack>
                        ))}
                      </VStack>

                      <HStack justify="end">
                        <Button
                          size="sm"
                          variant="secondary"
                          icon={<GrdrIcon name="refresh" size={12} />}
                          label={checkingId === item.id ? "Checking..." : "Check readiness"}
                          isDisabled={checkingId === item.id}
                          onClick={() => onCheckReadiness(item)}
                        />
                      </HStack>
                    </VStack>
                  </Card>
                );
              })}
            </div>
          )}
        </VStack>
      </Card>
    </>
  );
}
