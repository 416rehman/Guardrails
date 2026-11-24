import type {
  ConnectConfigResponse,
  MdmFormat,
  MdmRenderResponse,
  IntegrationEntry,
} from "@grdr/api";
import {
  pluralize,
  presentIntegrationCategory,
  presentIntegrationHealth,
  presentMdmFormat,
} from "@grdr/i18n";
import {
  Badge,
  Button,
  Card,
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
                Render deployment payloads pre-bound to your server origin and active wave key.
              </Text>
            </VStack>
            {renderedMdm && (
              <Button
                size="sm"
                variant="secondary"
                label={copiedId === "mdm-payload" ? "Copied" : `Copy ${renderedMdm.filename}`}
                onClick={() => onCopySnippet("mdm-payload", renderedMdm.payload)}
              />
            )}
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
                onChange={(val) => onChangeMdmFormat(val as MdmFormat)}
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
              <pre className="connect-payload mono">{renderedMdm.payload}</pre>
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

          <div className="grid-2">
            {config.integrations.map((item) => {
              const health = presentIntegrationHealth(item.state);
              return (
                <Card key={item.id} padding={2}>
                  <VStack gap={2}>
                    <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
                      <VStack gap={0}>
                        <Text style={{ fontWeight: 600 }}>{item.name}</Text>
                        <Text size="sm" color="secondary">
                          {`${presentIntegrationCategory(item.category)} · ${pluralize(item.synced_users, "user")}`}
                        </Text>
                      </VStack>
                      <Badge
                        variant={badgeVariantForTone(health.tone)}
                        label={
                          item.state === "at_risk" && item.credential_expires_in_days !== null
                            ? `${health.label}: ${item.credential_expires_in_days}d expiry`
                            : health.label
                        }
                      />
                    </HStack>

                    <Text size="sm" color="secondary">
                      {item.detail}
                    </Text>

                    <VStack gap={1}>
                      {item.readiness_checks.map((chk) => (
                        <HStack key={chk.name} justify="between" align="center" style={{ gap: 8 }}>
                          <StatusInline
                            tone={chk.passed ? "allow" : "block"}
                            icon={<GrdrIcon name={chk.passed ? "check-circle" : "alert-circle"} size={12} />}
                            label={chk.name}
                          />
                          <Text size="sm" color="secondary">{chk.detail}</Text>
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
        </VStack>
      </Card>
    </>
  );
}
