// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import { useEffect, useState } from "react";
import {
  api,
  type BrowserAppPolicy,
  type BrowserDlpClass,
  type BrowserEvaluateResponse,
  type MdmFormat,
  type MdmRenderResponse,
  type Mode,
} from "@grdr/api";
import { pluralize, presentBrowserDlpClass, presentMdmFormat } from "@grdr/i18n";
import { ModeControl, Quoted, VerdictBadge } from "@grdr/kit";
import {
  Badge,
  Banner,
  Button,
  EmptyState,
  GrdrIcon,
  GrdrSelect,
  Heading,
  HStack,
  Switch,
  Text,
  TextInput,
  VStack,
} from "@grdr/ui";
import aiDestinationsData from "../../../../../platform/browser-ext/data/ai-destinations.json";
import tenantProvidersData from "../../../../../platform/browser-ext/data/tenant-providers.json";

type LoadState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; policies: BrowserAppPolicy[] };

type EvalState =
  | { kind: "idle" }
  | { kind: "running" }
  | { kind: "error"; message: string }
  | { kind: "done"; result: BrowserEvaluateResponse; fastpathNotice: string };

type MdmState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; response: MdmRenderResponse };

type CopyState = "idle" | "copied" | "failed";
type PayloadView = "preview" | "expanded";
type UpdateAuthority = "managed" | "self";

interface SimDraft {
  appId: string;
  domain: string;
  dlpClass: BrowserDlpClass;
  fileExt: string;
  secretMatch: boolean;
}

interface MdmDraft {
  format: MdmFormat;
  updateAuthority: UpdateAuthority;
  forceInstallExtension: boolean;
}

const DESTINATION_TENANT_MAP = new Map<string, string>(
  aiDestinationsData.destinations
    .filter((d): d is typeof d & { tenantProviderId: string } => Boolean(d.tenantProviderId))
    .map((d) => [d.id, d.tenantProviderId]),
);

const TENANT_PROVIDER_MAP = new Map<string, { headerName: string; notes: string }>(
  tenantProvidersData.providers.map((p) => [p.id, { headerName: p.headerName, notes: p.notes }]),
);

const SENSITIVE_EXTENSIONS = new Set(
  aiDestinationsData.sensitiveFileExtensions.map((ext) => ext.trim().toLowerCase()),
);

const DLP_OPTIONS: Array<{ value: BrowserDlpClass; label: string }> = [
  { value: "file_upload", label: presentBrowserDlpClass("file_upload") },
  { value: "paste_secret", label: presentBrowserDlpClass("paste_secret") },
  { value: "source_code", label: presentBrowserDlpClass("source_code") },
  { value: "customer_pii", label: presentBrowserDlpClass("customer_pii") },
];

const BROWSER_MDM_FORMATS: MdmFormat[] = [
  "chrome_enterprise",
  "firefox_gpo",
  "jamf_mobileconfig",
  "intune_win32",
  "hexnode",
];

const UPDATE_AUTHORITY_OPTIONS: Array<{ value: UpdateAuthority; label: string }> = [
  { value: "managed", label: "Managed via MDM" },
  { value: "self", label: "Self-managed updates" },
];

function formatErrorMessage(err: unknown, fallback: string): string {
  return err instanceof Error && err.message.trim() ? err.message : fallback;
}

function resolveTenantHint(policyId: string): { headerName: string; notes: string } | null {
  const providerId =
    DESTINATION_TENANT_MAP.get(policyId) ??
    (policyId === "github-copilot" ? "github_enterprise" : undefined);
  return providerId ? (TENANT_PROVIDER_MAP.get(providerId) ?? null) : null;
}

function matchesSensitiveExtension(rawExt: string): boolean {
  const normalized = rawExt.trim().toLowerCase();
  if (!normalized) return false;
  if (SENSITIVE_EXTENSIONS.has(normalized)) return true;
  return normalized.startsWith(".env.") && SENSITIVE_EXTENSIONS.has(".env");
}

function previewLocalFastpath(fileExt: string, hasSecret: boolean): string {
  const normalized = fileExt.trim().toLowerCase();
  if (hasSecret) return "Local failsafe engine flags outbound credentials before transfer leaves browser.";
  if (normalized && matchesSensitiveExtension(normalized)) {
    return `Local failsafe engine intercepts restricted ${normalized} artifact transfer.`;
  }
  return "No local failsafe signature hit. Server policy and WebMCP rules decide.";
}

function summarizeApps(policies: BrowserAppPolicy[]) {
  let enforcedCount = 0;
  let managedLockedCount = 0;
  let totalEvents = 0;
  let totalBlocked = 0;
  for (const policy of policies) {
    if (policy.mode === "block" || policy.mode === "ask") enforcedCount += 1;
    if (policy.managed_extension_only) managedLockedCount += 1;
    totalEvents += policy.events_24h;
    totalBlocked += policy.blocked_24h;
  }
  return { enforcedCount, managedLockedCount, totalEvents, totalBlocked };
}

function BrowserPoliciesSkeleton() {
  const bar = { background: "var(--bg-recessed)", borderRadius: "var(--radius-sm)" };
  return (
    <VStack gap={3} aria-busy="true" aria-label="Loading browser enforcement policies">
      <div className="fleet-strip-3">
        {[0, 1, 2].map((i) => (
          <div key={i} className="fleet-card">
            <VStack gap={2}>
              <div style={{ ...bar, height: 12, width: "60%" }} />
              <div style={{ ...bar, height: 24, width: "36%" }} />
              <div style={{ ...bar, height: 12, width: "75%" }} />
            </VStack>
          </div>
        ))}
      </div>
      <section className="visual-panel">
        <div className="ledger-list">
          {[0, 1, 2].map((i) => (
            <div key={i} className="ledger-row">
              <VStack gap={1}>
                <div style={{ ...bar, height: 14, width: 180 }} />
                <div style={{ ...bar, height: 12, width: "70%" }} />
              </VStack>
            </div>
          ))}
        </div>
      </section>
    </VStack>
  );
}

export function BrowserPoliciesSection() {
  const [loadState, setLoadState] = useState<LoadState>({ kind: "loading" });
  const [busyPolicyId, setBusyPolicyId] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [evalState, setEvalState] = useState<EvalState>({ kind: "idle" });
  const [mdmState, setMdmState] = useState<MdmState>({ kind: "idle" });
  const [copyState, setCopyState] = useState<CopyState>("idle");
  const [payloadView, setPayloadView] = useState<PayloadView>("preview");
  const [sim, setSim] = useState<SimDraft>({
    appId: "chatgpt",
    domain: "chat.openai.com",
    dlpClass: "paste_secret",
    fileExt: ".env",
    secretMatch: true,
  });
  const [mdmDraft, setMdmDraft] = useState<MdmDraft>({
    format: "chrome_enterprise",
    updateAuthority: "managed",
    forceInstallExtension: true,
  });

  useEffect(() => {
    let active = true;
    api
      .getBrowserPolicies()
      .then((policies) => {
        if (!active) return;
        setLoadState({ kind: "ready", policies });
        if (policies.length > 0) {
          const first = policies[0];
          setSim((prev) => ({ ...prev, appId: first.id, domain: first.domains[0] ?? prev.domain }));
        }
      })
      .catch((err) => {
        if (active) {
          setLoadState({ kind: "error", message: formatErrorMessage(err, "Unable to load browser policies.") });
        }
      });
    return () => {
      active = false;
    };
  }, []);

  async function patchPolicy(
    id: string,
    patch: { mode?: Mode; block_file_uploads?: boolean; block_secret_paste?: boolean; managed_extension_only?: boolean },
  ) {
    if (loadState.kind !== "ready") return;
    setBusyPolicyId(id);
    setErrorMessage(null);
    try {
      const updated = await api.updateBrowserPolicy(id, patch);
      setLoadState((prev) =>
        prev.kind === "ready" ? { ...prev, policies: prev.policies.map((p) => (p.id === id ? updated : p)) } : prev,
      );
    } catch (err) {
      setErrorMessage(formatErrorMessage(err, "Failed saving destination policy."));
    } finally {
      setBusyPolicyId(null);
    }
  }

  async function runEvaluate() {
    setEvalState({ kind: "running" });
    try {
      const result = await api.evaluateBrowserAction({
        app_id: sim.appId,
        domain: sim.domain,
        dlp_class: sim.dlpClass,
        file_extension: sim.fileExt.trim() || null,
        has_secret_match: sim.secretMatch,
      });
      setEvalState({ kind: "done", result, fastpathNotice: previewLocalFastpath(sim.fileExt, sim.secretMatch) });
      setLoadState((prev) => {
        if (prev.kind !== "ready") return prev;
        const targetId = result.app_id ?? sim.appId;
        return {
          ...prev,
          policies: prev.policies.map((p) =>
            p.id === targetId
              ? { ...p, events_24h: p.events_24h + 1, blocked_24h: p.blocked_24h + (result.verdict === "deny" ? 1 : 0) }
              : p,
          ),
        };
      });
    } catch (err) {
      setEvalState({ kind: "error", message: formatErrorMessage(err, "Failed evaluating browser action.") });
    }
  }

  async function renderMdm() {
    setMdmState({ kind: "loading" });
    setCopyState("idle");
    setPayloadView("preview");
    try {
      const response = await api.renderMdmConfig({
        format: mdmDraft.format,
        deployment_key_id: null,
        include_browser_extension: mdmDraft.forceInstallExtension,
        update_authority: mdmDraft.updateAuthority,
      });
      setMdmState({ kind: "ready", response });
    } catch (err) {
      setMdmState({ kind: "error", message: formatErrorMessage(err, "Failed rendering MDM payload.") });
    }
  }

  async function copyMdmPayload() {
    if (mdmState.kind !== "ready") return;
    try {
      await navigator.clipboard.writeText(mdmState.response.payload);
      setCopyState("copied");
    } catch {
      setCopyState("failed");
    }
  }

  if (loadState.kind === "loading") return <BrowserPoliciesSkeleton />;
  if (loadState.kind === "error") return <Banner status="error" title={loadState.message} collapsible={false} />;

  const { policies } = loadState;
  const stats = summarizeApps(policies);
  const appOptions = policies.map((p) => ({ value: p.id, label: p.name }));
  const mdmFormatOptions = BROWSER_MDM_FORMATS.map((fmt) => ({ value: fmt, label: presentMdmFormat(fmt) }));

  return (
    <VStack gap={3}>
      {errorMessage ? <Banner status="error" title={errorMessage} collapsible={false} /> : null}

      <div className="fleet-strip-3">
        <div className="fleet-card">
          <div className="fleet-card-head">
            <Text size="sm" color="secondary" style={{ fontWeight: 500 }}>Governed AI destinations</Text>
            <GrdrIcon name="globe" size={14} />
          </div>
          <div className="fleet-card-metric tabular">{policies.length}</div>
          <Text size="sm" color="secondary">{`${stats.enforcedCount} enforcing Ask or Block mode`}</Text>
        </div>

        <div className="fleet-card">
          <div className="fleet-card-head">
            <Text size="sm" color="secondary" style={{ fontWeight: 500 }}>Blocked browser transfers (24h)</Text>
            <GrdrIcon name="shield-check" size={14} />
          </div>
          <div className="fleet-card-metric tabular">{stats.totalBlocked}</div>
          <Text size="sm" color="secondary">{`${pluralize(stats.totalEvents, "inspected transfer")} across active endpoints`}</Text>
        </div>

        <div className="fleet-card">
          <div className="fleet-card-head">
            <Text size="sm" color="secondary" style={{ fontWeight: 500 }}>Managed extension locks</Text>
            <GrdrIcon name="lock" size={14} />
          </div>
          <div className="fleet-card-metric tabular">{stats.managedLockedCount}</div>
          <Text size="sm" color="secondary">Active extension enforcement on managed endpoints</Text>
        </div>
      </div>

      <section className="visual-panel">
        <VStack gap={2}>
          <VStack gap={1}>
            <Heading level={2}>AI destination policies and tenant locks</Heading>
            <Text size="sm" color="secondary">
              Controls file uploads, secret detection, WebMCP tool calls, and tenant access headers across Chrome, Edge, and Firefox.
            </Text>
          </VStack>

          {policies.length === 0 ? (
            <EmptyState
              icon={<GrdrIcon name="globe" size={24} />}
              title="No browser destinations configured"
              description="Add an AI SaaS destination rule or refresh the default policy pack to govern browser uploads and WebMCP calls."
            />
          ) : (
            <div className="ledger-list">
              {policies.map((policy) => {
                const headerHint = resolveTenantHint(policy.id);
                const isBusy = busyPolicyId === policy.id;
                return (
                  <div key={policy.id} className="ledger-row">
                    <div className="ledger-row-main" style={{ gap: "var(--space-2)" }}>
                      <VStack gap={2} style={{ minWidth: 0, flex: "1 1 auto" }}>
                        <HStack gap={2} align="center" style={{ flexWrap: "wrap" }}>
                          <Text size="sm" style={{ fontWeight: 600 }}>{policy.name}</Text>
                          <span className="tabular" style={{ color: "var(--ink-muted)", fontSize: "12px" }}>
                            {`${policy.events_24h} events / ${policy.blocked_24h} blocked`}
                          </span>
                        </HStack>

                        <div className="facet-bar" style={{ gap: "var(--space-1)", alignItems: "center", justifyContent: "flex-start" }}>
                          {policy.domains.map((domain) => <Quoted key={domain} text={domain} />)}
                          {headerHint ? <Badge variant="neutral" label={`Header: ${headerHint.headerName}`} /> : null}
                        </div>

                        {headerHint ? <Text size="sm" color="secondary">{headerHint.notes}</Text> : null}

                        <div className="facet-bar" style={{ gap: "var(--space-3)", alignItems: "center", justifyContent: "flex-start" }}>
                          <Switch size="sm" label="File uploads" value={policy.block_file_uploads} isDisabled={isBusy} onChange={(c) => void patchPolicy(policy.id, { block_file_uploads: c })} />
                          <Switch size="sm" label="Secret payloads" value={policy.block_secret_paste} isDisabled={isBusy} onChange={(c) => void patchPolicy(policy.id, { block_secret_paste: c })} />
                          <Switch size="sm" label="Managed ext only" value={policy.managed_extension_only} isDisabled={isBusy} onChange={(c) => void patchPolicy(policy.id, { managed_extension_only: c })} />
                        </div>
                      </VStack>

                      <div style={{ flexShrink: 0 }}>
                        <ModeControl value={policy.mode} locked={isBusy} onChange={(next) => void patchPolicy(policy.id, { mode: next })} />
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </VStack>
      </section>

      <div className="grid-2">
        <section className="visual-panel" style={{ minWidth: 0 }}>
          <VStack gap={2}>
            <Heading level={3}>Browser DLP and WebMCP simulator</Heading>
            <Text size="sm" color="secondary">
              Preview browser policy verdicts for outbound uploads, secret tokens, and WebMCP calls before rollout.
            </Text>

            <div className="grid-2">
              <GrdrSelect
                label="Destination"
                value={sim.appId}
                options={appOptions}
                onChange={(val) => {
                  const found = policies.find((p) => p.id === val);
                  setSim((prev) => ({ ...prev, appId: val, domain: found?.domains[0] ?? prev.domain }));
                }}
              />
              <GrdrSelect label="Action or DLP class" value={sim.dlpClass} options={DLP_OPTIONS} onChange={(val) => setSim((prev) => ({ ...prev, dlpClass: val as BrowserDlpClass }))} />
            </div>

            <div className="grid-2">
              <TextInput label="Target hostname" value={sim.domain} onChange={(val) => setSim((prev) => ({ ...prev, domain: val }))} />
              <TextInput label="File extension" value={sim.fileExt} onChange={(val) => setSim((prev) => ({ ...prev, fileExt: val }))} />
            </div>

            <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: "var(--space-2)" }}>
              <Switch size="sm" label="Contains secret pattern" value={sim.secretMatch} onChange={(c) => setSim((prev) => ({ ...prev, secretMatch: c }))} />
              <Button
                variant="primary"
                size="sm"
                isDisabled={evalState.kind === "running" || policies.length === 0}
                icon={<GrdrIcon name="play" size={12} />}
                label={evalState.kind === "running" ? "Evaluating..." : "Run browser check"}
                onClick={() => void runEvaluate()}
              />
            </HStack>

            {evalState.kind === "error" ? <Banner status="error" title={evalState.message} collapsible={false} /> : null}
            {evalState.kind === "done" ? (
              <div className="ledger-row">
                <VStack gap={1}>
                  <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: "var(--space-2)" }}>
                    <HStack gap={2} align="center" style={{ flexWrap: "wrap" }}>
                      <VerdictBadge verdict={evalState.result.verdict} />
                      <Text size="sm" style={{ fontWeight: 600 }}>{evalState.result.app_name}</Text>
                    </HStack>
                    {evalState.result.rule_id ? <Quoted text={evalState.result.rule_id} /> : null}
                  </HStack>
                  <Text size="sm" color="secondary">{evalState.result.reason}</Text>
                  <Text size="sm" color="secondary">{evalState.fastpathNotice}</Text>
                </VStack>
              </div>
            ) : null}
          </VStack>
        </section>

        <section className="visual-panel" style={{ minWidth: 0 }}>
          <VStack gap={2}>
            <Heading level={3}>Extension rollout and MDM policies</Heading>
            <Text size="sm" color="secondary">
              Generate force-install MDM manifests for Chrome, Edge, and Firefox with native host registration.
            </Text>

            <div className="grid-2">
              <GrdrSelect label="MDM target" value={mdmDraft.format} options={mdmFormatOptions} onChange={(val) => setMdmDraft((prev) => ({ ...prev, format: val as MdmFormat }))} />
              <GrdrSelect label="Update authority" value={mdmDraft.updateAuthority} options={UPDATE_AUTHORITY_OPTIONS} onChange={(val) => setMdmDraft((prev) => ({ ...prev, updateAuthority: val === "self" ? "self" : "managed" }))} />
            </div>

            <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: "var(--space-2)" }}>
              <Switch size="sm" label="Force browser extension" value={mdmDraft.forceInstallExtension} onChange={(c) => setMdmDraft((prev) => ({ ...prev, forceInstallExtension: c }))} />
              <HStack gap={2} align="center" style={{ flexWrap: "wrap" }}>
                {mdmState.kind === "ready" ? (
                  <>
                    <Button size="sm" variant="secondary" label={payloadView === "expanded" ? "Collapse payload" : "Expand payload"} onClick={() => setPayloadView((prev) => (prev === "expanded" ? "preview" : "expanded"))} />
                    <Button size="sm" variant="secondary" label={copyState === "copied" ? "Copied" : copyState === "failed" ? "Copy unavailable" : "Copy payload"} onClick={() => void copyMdmPayload()} />
                  </>
                ) : null}
                <Button size="sm" variant="primary" isDisabled={mdmState.kind === "loading"} icon={<GrdrIcon name="download" size={12} />} label={mdmState.kind === "loading" ? "Rendering..." : "Generate MDM payload"} onClick={() => void renderMdm()} />
              </HStack>
            </HStack>

            {mdmState.kind === "error" ? <Banner status="error" title={mdmState.message} collapsible={false} /> : null}
            {mdmState.kind === "ready" ? (
              <VStack gap={1}>
                <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: "var(--space-1)" }}>
                  <Quoted text={mdmState.response.filename} />
                  {mdmState.response.deployment_notes[0] ? <Text size="sm" color="secondary">{mdmState.response.deployment_notes[0]}</Text> : null}
                </HStack>
                <pre className="connect-payload mono" style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", maxHeight: payloadView === "expanded" ? "none" : "360px", overflowY: payloadView === "expanded" ? "visible" : "auto" }}>
                  {mdmState.response.payload}
                </pre>
              </VStack>
            ) : null}
            <Banner status="info" title="Sensor boundary: inspects fetch, XHR, WebSocket, beacon, FormData uploads, and WebMCP registerTool without keystroke or clipboard listeners." collapsible={false} />
          </VStack>
        </section>
      </div>
    </VStack>
  );
}
