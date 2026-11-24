import { useEffect, useState } from "react";
import {
  api,
  type BrowserAppPolicy,
  type BrowserDlpClass,
  type BrowserEvaluateResponse,
  type Mode,
} from "@grdr/api";
import { pluralize, presentBrowserDlpClass } from "@grdr/i18n";
import { ModeControl, Quoted, VerdictBadge } from "@grdr/kit";
import {
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
  VStack,
} from "@grdr/ui";

const DLP_CLASSES: BrowserDlpClass[] = [
  "file_upload",
  "paste_secret",
  "source_code",
  "customer_pii",
];

export function BrowserPoliciesSection() {
  const [policies, setPolicies] = useState<BrowserAppPolicy[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const [testAppId, setTestAppId] = useState<string>("chatgpt");
  const [testDlpClass, setTestDlpClass] = useState<BrowserDlpClass>("file_upload");
  const [testExt, setTestExt] = useState<string>(".env");
  const [evalResult, setEvalResult] = useState<BrowserEvaluateResponse | null>(null);
  const [evaluating, setEvaluating] = useState(false);

  async function loadPolicies() {
    setError(null);
    try {
      const next = await api.getBrowserPolicies();
      setPolicies(next);
      setTestAppId((prev) => (next.some((p) => p.id === prev) ? prev : (next[0]?.id ?? "chatgpt")));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed loading browser policies.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadPolicies();
  }, []);

  async function patchPolicy(
    id: string,
    patch: {
      mode?: Mode;
      block_file_uploads?: boolean;
      block_secret_paste?: boolean;
      managed_extension_only?: boolean;
    },
  ) {
    setError(null);
    try {
      const updated = await api.updateBrowserPolicy(id, patch);
      setPolicies((prev) => prev.map((p) => (p.id === updated.id ? updated : p)));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed updating browser policy.");
    }
  }

  async function handleEvaluate() {
    const selected = policies.find((p) => p.id === testAppId);
    if (!selected) return;
    setEvaluating(true);
    setError(null);
    try {
      const res = await api.evaluateBrowserAction({
        app_id: selected.id,
        domain: selected.domains[0] ?? "chatgpt.com",
        dlp_class: testDlpClass,
        file_extension: testDlpClass === "file_upload" ? testExt.trim() || null : null,
        has_secret_match: true,
      });
      setEvalResult(res);
      await loadPolicies();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed running browser DLP check.");
    } finally {
      setEvaluating(false);
    }
  }

  if (loading && policies.length === 0) {
    return (
      <Card padding={3}>
        <Text color="secondary">Loading managed browser AI policies...</Text>
      </Card>
    );
  }

  const enforcedApps = policies.filter((p) => p.mode !== "off").length;
  const blocked24h = policies.reduce((acc, p) => acc + p.blocked_24h, 0);
  const managedOnlyCount = policies.filter((p) => p.managed_extension_only).length;

  return (
    <VStack gap={4}>
      {error && <Banner status="error" title={error} collapsible={false} />}

      <div className="fleet-strip-3" aria-label="Browser AI enforcement summary">
        <div className="fleet-card">
          <Text size="sm" color="secondary">
            Governed AI apps
          </Text>
          <strong style={{ fontSize: 22 }} className="tabular">
            {`${enforcedApps} / ${policies.length}`}
          </strong>
          <Text size="sm" color="secondary">
            Enforced by browser extension
          </Text>
        </div>

        <div className="fleet-card">
          <Text size="sm" color="secondary">
            Blocked browser transfers (24h)
          </Text>
          <strong style={{ fontSize: 22, color: "var(--tone-block)" }} className="tabular">
            {blocked24h}
          </strong>
          <Text size="sm" color="secondary">
            Prevented uploads & secret pastes
          </Text>
        </div>

        <div className="fleet-card">
          <Text size="sm" color="secondary">
            Managed extension locks
          </Text>
          <strong style={{ fontSize: 22 }} className="tabular">
            {managedOnlyCount}
          </strong>
          <Text size="sm" color="secondary">
            Apps requiring MDM extension pin
          </Text>
        </div>
      </div>

      <Card padding={3}>
        <VStack gap={3}>
          <VStack gap={0}>
            <Heading level={2}>{`Browser AI SaaS enforcement (${policies.length})`}</Heading>
            <Text size="sm" color="secondary">
              Control file uploads, pasted secrets, and extension locks per hosted AI workspace.
            </Text>
          </VStack>

          <div className="ledger-list">
            {policies.map((policy) => (
              <div key={policy.id} className="ledger-row">
                <div className="ledger-row-main">
                  <VStack gap={1} style={{ flex: 1, minWidth: 240 }}>
                    <HStack gap={2} align="center" style={{ flexWrap: "wrap" }}>
                      <strong>{policy.name}</strong>
                      <Text size="sm" color="secondary" className="tabular">
                        {`${pluralize(policy.events_24h, "event")} · ${policy.blocked_24h} blocked`}
                      </Text>
                    </HStack>
                    <HStack gap={1} align="center" style={{ flexWrap: "wrap" }}>
                      {policy.domains.map((domain) => (
                        <Quoted key={domain} text={domain} />
                      ))}
                    </HStack>
                    <HStack gap={2} align="center" style={{ flexWrap: "wrap", marginTop: 4 }}>
                      <button
                        type="button"
                        aria-pressed={policy.block_file_uploads}
                        className={`policy-toggle-chip ${policy.block_file_uploads ? "blocked" : ""}`.trim()}
                        onClick={() =>
                          patchPolicy(policy.id, { block_file_uploads: !policy.block_file_uploads })
                        }
                      >
                        <GrdrIcon name={policy.block_file_uploads ? "ban" : "check"} size={12} />
                        <span>{policy.block_file_uploads ? "File uploads blocked" : "File uploads allowed"}</span>
                      </button>
                      <button
                        type="button"
                        aria-pressed={policy.block_secret_paste}
                        className={`policy-toggle-chip ${policy.block_secret_paste ? "blocked" : ""}`.trim()}
                        onClick={() =>
                          patchPolicy(policy.id, { block_secret_paste: !policy.block_secret_paste })
                        }
                      >
                        <GrdrIcon name={policy.block_secret_paste ? "shield-alert" : "check"} size={12} />
                        <span>{policy.block_secret_paste ? "Secret paste checked" : "Secret paste off"}</span>
                      </button>
                      <button
                        type="button"
                        aria-pressed={policy.managed_extension_only}
                        className={`policy-toggle-chip ${policy.managed_extension_only ? "active" : ""}`.trim()}
                        onClick={() =>
                          patchPolicy(policy.id, {
                            managed_extension_only: !policy.managed_extension_only,
                          })
                        }
                      >
                        <GrdrIcon
                          name={policy.managed_extension_only ? "lock" : "globe"}
                          size={12}
                        />
                        <span>{policy.managed_extension_only ? "Managed extension required" : "Unrestricted browser"}</span>
                      </button>
                    </HStack>
                  </VStack>

                  <div className="ledger-row-controls">
                    <ModeControl
                      value={policy.mode}
                      onChange={(nextMode) => patchPolicy(policy.id, { mode: nextMode })}
                    />
                  </div>
                </div>
              </div>
            ))}
          </div>
        </VStack>
      </Card>

      <Card padding={3}>
        <VStack gap={3}>
          <VStack gap={0}>
            <Heading level={2}>Browser DLP simulator</Heading>
            <Text size="sm" color="secondary">
              Verify how the Chrome/Edge/Firefox extension responds before deploying a policy change.
            </Text>
          </VStack>

          <div className="facet-bar">
            <HStack gap={2} align="end" style={{ flexWrap: "wrap" }}>
              <GrdrSelect
                label="Target AI app"
                size="md"
                variant="input"
                value={testAppId}
                options={policies.map((p) => ({ value: p.id, label: p.name }))}
                onChange={setTestAppId}
              />
              <GrdrSelect
                label="Transfer type"
                size="md"
                variant="input"
                value={testDlpClass}
                options={DLP_CLASSES.map((cls) => ({
                  value: cls,
                  label: presentBrowserDlpClass(cls),
                }))}
                onChange={(v) => setTestDlpClass(v as BrowserDlpClass)}
              />
              {testDlpClass === "file_upload" && (
                <TextInput label="File extension" value={testExt} onChange={setTestExt} />
              )}
              <Button
                variant="primary"
                icon={<GrdrIcon name="play" size={13} />}
                label={evaluating ? "Checking..." : "Run browser check"}
                isDisabled={evaluating}
                onClick={handleEvaluate}
              />
            </HStack>
          </div>

          {evalResult && (
            <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
              <HStack gap={2} align="center" style={{ flexWrap: "wrap" }}>
                <VerdictBadge verdict={evalResult.verdict} />
                <Text size="sm" style={{ fontWeight: 500 }}>
                  {evalResult.reason}
                </Text>
              </HStack>
              {evalResult.rule_id ? (
                <Quoted text={evalResult.rule_id} />
              ) : (
                <StatusInline tone="allow" dot label="No block rule matched" />
              )}
            </HStack>
          )}
        </VStack>
      </Card>
    </VStack>
  );
}
