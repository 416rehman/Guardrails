import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  api,
  CONNECT_PATHS,
  ConnectApiError,
  type ApprovalRequest,
  type AuditEntry,
  type BrowserAppPolicy,
  type ConnectConfigResponse,
  type Device,
  type Finding,
  type HealthResponse,
  type Incident,
  type KillSwitchState,
  type OrgPrivacyConfig,
  type OverviewResponse,
  type PolicyPack,
  type SessionDetailResponse,
  type SessionSummary,
  type TrustedKeyInfo,
  type UserDetailResponse,
  type UserProfile,
} from "@grdr/api";
import { ModeControl, Quoted, VerdictBadge } from "@grdr/kit";
import { GrdrThemeProvider } from "@grdr/ui";
import { App } from "@grdr/console";
import { OperatorApp } from "@grdr/operator";

const overviewFixture: OverviewResponse = {
  server_status: "ok",
  total_devices: 1,
  online_devices: 1,
  total_agents: 1,
  total_mcp_servers: 1,
  active_sessions: 1,
  pending_approvals: 1,
  open_findings: 1,
  open_incidents: 1,
  kill_switch: { state: "inactive" },
  tiles: [
    {
      id: "tile-blocked",
      headline: "Blocked risky actions",
      metric: "2",
      comparison: "vs 0 yesterday",
      action_label: "Inspect sessions",
      route: "sessions",
      tone: "warning",
    },
  ],
  setup_steps: [
    { id: "step-1", label: "Install daemon", done: true, detail: "Connected" },
  ],
};

const devicesFixture: Device[] = [
  {
    id: "dev-1",
    hostname: "devbox.local",
    os: "linux",
    arch: "x86_64",
    install_profile: "user",
    daemon_version: "0.2.0",
    online: true,
    hook_effective: false,
    last_seen: "2026-11-23T12:00:00Z",
    agents: [
      {
        id: "agent-claude",
        name: "claude-code",
        kind: "ClaudeCode",
        config_path: "~/.claude/settings.json",
        hook_installed: false,
        mcp_count: 1,
        assurance: {
          visibility: "User hook",
          control: "Hook",
          on_failure: "Fail open",
          tamper: "User editable",
        },
        assurance_level: "AL1",
        sponsor: "local-dev",
        detected_at: "2026-11-23T11:00:00Z",
      },
    ],
    mcp_servers: [
      {
        name: "github",
        transport: "stdio",
        command: "npx -y @modelcontextprotocol/server-github",
        source_agent: "claude-code",
        config_path: "~/.claude/settings.json",
        pinned: false,
      },
    ],
    artifacts: [
      {
        id: "art_skl_usr_deploy",
        name: "deploy-helper",
        kind: "skill",
        scope: "user",
        source_agent: "claude-code",
        path: "~/.claude/skills/deploy-helper",
        content_digest: "9b71d224bd62f3785d96d46ad3ea3d73",
        file_count: 2,
        total_bytes: 1200,
        usage_count: 7,
        pinned: false,
        risk_flags: ["has-scripts"],
        device_id: "dev-1",
        device_name: "devbox.local",
        user_id: "usr-1",
        detected_at: "2026-11-23T11:30:00Z",
      },
    ],
    user_id: "usr-1",
    user_display: "Maya Chen",
  },
];

const usersFixture: UserProfile[] = [
  {
    id: "usr-1",
    display_name: "Maya Chen",
    email: "maya.chen@acme-eng.example",
    department: "Platform Engineering",
    idp_source: "Okta JWKS",
    pseudonym_id: "prn_test_01",
    device_ids: ["dev-1"],
    agent_names: ["claude-code"],
    artifact_count: 1,
    session_count: 1,
    blocked_count: 1,
    asked_count: 1,
    watch_count: 1,
    finding_count: 1,
    risk_score: 64,
    risk_tier: "high",
    risk_factors: [
      {
        code: "risk.blocked_actions",
        label: "Blocked actions",
        points: 18,
        count: 1,
      },
    ],
    last_active: "2026-11-23T12:00:00Z",
  },
];

const sessionsFixture: SessionSummary[] = [
  {
    id: "sess-1",
    device_id: "dev-1",
    device_name: "devbox.local",
    agent_name: "claude-code",
    user_id: "usr-1",
    user_display: "Maya Chen",
    turn_count: 2,
    started_at: "2026-11-23T11:50:00Z",
    last_activity: "2026-11-23T12:00:00Z",
    total_actions: 4,
    blocked_count: 1,
    step_up_count: 1,
    watch_hits: 1,
    assurance_level: "AL1",
    labels: ["credential_accessed"],
  },
];

const sessionDetailFixture: SessionDetailResponse = {
  session: sessionsFixture[0],
  attempts: [
    {
      id: "att-1",
      session_id: "sess-1",
      device_id: "dev-1",
      device_name: "devbox.local",
      agent_name: "claude-code",
      action_class: "exec",
      control_point: "hook",
      target: "git status && curl https://example.test",
      summary: "Compound command",
      timestamp: "2026-11-23T11:55:00Z",
      user_id: "usr-1",
      user_display: "Maya Chen",
      turn_index: 2,
      span_kind: "subagent_spawn",
      duration_ms: 450,
      provenance: "observed",
      secondary_actions: [
        { command: "git status", action_class: "exec", target: "git status" },
      ],
      skill_used: "deploy-helper",
      compaction: true,
    },
  ],
  receipts: [],
  turns: [
    {
      turn_index: 2,
      trace_id: "trc_sess-1_2",
      span_count: 1,
      duration_ms: 450,
      blocked_count: 0,
      asked_count: 0,
      has_compaction: true,
      has_subagent_handoff: true,
      started_at: "2026-11-23T11:55:00Z",
    },
  ],
  user: usersFixture[0],
};

const userDetailFixture: UserDetailResponse = {
  user: usersFixture[0],
  devices: devicesFixture,
  sessions: sessionsFixture,
  recent_attempts: sessionDetailFixture.attempts,
  receipts: [],
  findings: [],
  artifacts: devicesFixture[0].artifacts ?? [],
  identity_mode: "named",
};

const privacyConfigFixture: OrgPrivacyConfig = {
  identity_mode: "named",
  user_risk_scoring: true,
};

const packsFixture: PolicyPack[] = [
  {
    id: "pack-default",
    name: "Developer Baseline",
    description: "Safe defaults for local developer agents",
    version: "1.0.0",
    channel: "stable",
    rules: [
      {
        id: "rule-1",
        title: "Protect SSH keys",
        description: "Require approval before reading ~/.ssh",
        mode: "watch",
        min_grade: "Operator",
        enabled: true,
        locked: false,
        hits: 2,
        would_ask_hits: 1,
        would_block_hits: 0,
        matcher: {
          action_classes: ["file.read"],
          target_prefixes: ["~/.ssh"],
          target_contains: [".ssh/"],
          agents: ["*"],
        },
        reason_template: "SSH key access requires explicit approval.",
      },
      {
        id: "rule-locked",
        title: "Floor: block destructive root wipes",
        description: "Cannot be relaxed below Block",
        mode: "block",
        min_grade: "Operator",
        enabled: true,
        locked: true,
        hits: 0,
        would_ask_hits: 0,
        would_block_hits: 0,
        matcher: {
          action_classes: ["exec"],
          target_prefixes: [],
          target_contains: ["rm -rf /"],
          agents: ["*"],
        },
        reason_template: "Catastrophic disk wipe blocked by baseline floor.",
      },
    ],
  },
];

const approvalsFixture: ApprovalRequest[] = [
  {
    id: "apr-1",
    receipt_id: "rcpt-1",
    session_id: "sess-1",
    device_id: "dev-1",
    device_name: "devbox.local",
    agent_name: "claude-code",
    action_class: "file.read",
    target: "~/.ssh/id_ed25519",
    rule_id: "rule-1",
    rule_title: "Protect SSH keys",
    required_grade: "Operator",
    reason: "Sensitive key access",
    requested_at: "2026-11-23T11:55:00Z",
    state: { status: "pending", expires_at: "2026-11-23T12:15:00Z" },
  },
];

const findingsFixture: Finding[] = [
  {
    id: "fnd-1",
    session_id: "sess-1",
    device_id: "dev-1",
    device_name: "devbox.local",
    agent_name: "claude-code",
    class: "cred.use",
    severity: "high",
    lifecycle: "open",
    rule_id: "rule-1",
    title: "Credential material touched",
    summary: "Attempted read on private SSH key",
    target: "~/.ssh/id_ed25519",
    detected_at: "2026-11-23T11:55:00Z",
  },
];

const incidentsFixture: Incident[] = [
  {
    id: "inc-1",
    session_id: "sess-1",
    device_id: "dev-1",
    device_name: "devbox.local",
    agent_name: "claude-code",
    title: "SSH key access incident",
    summary: "Credential material accessed in untrusted flow",
    severity: "high",
    lifecycle: "open",
    finding_ids: ["fnd-1"],
    finding_count: 1,
    labels: ["credential_accessed"],
    first_seen: "2026-11-23T11:55:00Z",
    last_seen: "2026-11-23T11:56:00Z",
  },
];

const healthFixture: HealthResponse = {
  status: "ok",
  version: "0.2.0",
  storage_mode: { kind: "memory" },
  timestamp: "2026-11-23T12:00:00Z",
};

const keysFixture: TrustedKeyInfo[] = [
  {
    key_id: "key-local-1",
    public_key_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  },
];

const auditFixture: AuditEntry[] = [
  {
    id: "aud-1",
    timestamp: "2026-11-23T12:00:00Z",
    kind: "policy.update",
    actor: "operator@local",
    summary: "Initialized baseline rules",
    target: "rule-1",
  },
];

function mockJsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function parsePageBody(init?: RequestInit): { pageSize: number; offset: number; filter: string } {
  if (!init?.body || typeof init.body !== "string") {
    return { pageSize: 50, offset: 0, filter: "" };
  }
  const parsed = JSON.parse(init.body) as {
    pageSize?: number;
    pageToken?: string;
    filter?: string;
  };
  const pageSize = parsed.pageSize && parsed.pageSize > 0 ? parsed.pageSize : 50;
  const offset = parsed.pageToken ? Number(parsed.pageToken) || 0 : 0;
  return { pageSize, offset, filter: parsed.filter ?? "" };
}

function paginateItems<T>(items: T[], init?: RequestInit) {
  const { pageSize, offset } = parsePageBody(init);
  const slice = items.slice(offset, offset + pageSize);
  return {
    slice,
    pageInfo: {
      totalSizeEstimate: items.length,
      nextPageToken: offset + pageSize < items.length ? String(offset + pageSize) : "",
      prevPageToken: offset > 0 ? String(Math.max(0, offset - pageSize)) : "",
    },
  };
}

function installFetchMock(opts?: {
  devices?: Device[];
  onListRequest?: (path: string, filter: string) => void;
}) {
  const devicesList = opts?.devices ?? devicesFixture;
  const agentItems = devicesList.flatMap((d) =>
    d.agents.map((agent) => ({ deviceId: d.id, deviceName: d.hostname, agent })),
  );
  const mcpItems = devicesList.flatMap((d) =>
    d.mcp_servers.map((server) => ({ deviceId: d.id, deviceName: d.hostname, server })),
  );
  const artifactItems = devicesList.flatMap((d) => d.artifacts ?? []);

  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const rawUrl = typeof input === "string" ? input : input.toString();
    const path = rawUrl.split("?")[0];
    if (opts?.onListRequest && init?.body) {
      opts.onListRequest(path, parsePageBody(init).filter);
    }

    if (path === CONNECT_PATHS.getHealth) return mockJsonResponse(healthFixture);
    if (path === CONNECT_PATHS.getOverview) return mockJsonResponse(overviewFixture);
    if (path === CONNECT_PATHS.listUsers) {
      const { slice, pageInfo } = paginateItems(usersFixture, init);
      return mockJsonResponse({ users: slice, pageInfo });
    }
    if (path === CONNECT_PATHS.getUser) return mockJsonResponse(userDetailFixture);
    if (path === CONNECT_PATHS.getPrivacyConfig) {
      return mockJsonResponse({ config: privacyConfigFixture });
    }
    if (path === CONNECT_PATHS.listDevices) {
      const { slice, pageInfo } = paginateItems(devicesList, init);
      return mockJsonResponse({ devices: slice, pageInfo });
    }
    if (path === CONNECT_PATHS.listAgents) {
      const { slice, pageInfo } = paginateItems(agentItems, init);
      return mockJsonResponse({ items: slice, pageInfo });
    }
    if (path === CONNECT_PATHS.listMcpServers) {
      const { slice, pageInfo } = paginateItems(mcpItems, init);
      return mockJsonResponse({ items: slice, pageInfo });
    }
    if (path === CONNECT_PATHS.listArtifacts) {
      const { slice, pageInfo } = paginateItems(artifactItems, init);
      return mockJsonResponse({ artifacts: slice, pageInfo });
    }
    if (path === CONNECT_PATHS.listSessions) {
      const { slice, pageInfo } = paginateItems(sessionsFixture, init);
      return mockJsonResponse({ sessions: slice, pageInfo });
    }
    if (path === CONNECT_PATHS.getSession) return mockJsonResponse(sessionDetailFixture);
    if (path === CONNECT_PATHS.listPacks) return mockJsonResponse({ packs: packsFixture });
    if (path === CONNECT_PATHS.listApprovals) {
      const { slice, pageInfo } = paginateItems(approvalsFixture, init);
      return mockJsonResponse({ approvals: slice, pageInfo });
    }
    if (path === CONNECT_PATHS.listFindings) {
      const { slice, pageInfo } = paginateItems(findingsFixture, init);
      return mockJsonResponse({ findings: slice, pageInfo });
    }
    if (path === CONNECT_PATHS.listIncidents) {
      const { slice, pageInfo } = paginateItems(incidentsFixture, init);
      return mockJsonResponse({ incidents: slice, pageInfo });
    }
    if (path === CONNECT_PATHS.getKillSwitch) {
      const ks: KillSwitchState = { state: "inactive" };
      return mockJsonResponse({ killSwitch: ks });
    }
    if (path === CONNECT_PATHS.listKeys) return mockJsonResponse({ keys: keysFixture });
    if (path === CONNECT_PATHS.listAuditEvents) {
      const { slice, pageInfo } = paginateItems(auditFixture, init);
      return mockJsonResponse({ entries: slice, pageInfo });
    }
    if (path === CONNECT_PATHS.getConnectConfig) return mockJsonResponse(connectFixture);
    if (path === CONNECT_PATHS.createDeploymentKey) {
      const issued = {
        key: {
          id: "key-finance-pilot",
          label: "Finance Pilot",
          token_preview: "grdr_wk_fin12345",
          install_profile: "standard",
          wave: "wave-3",
          max_uses: 50,
          used_count: 0,
          status: "active" as const,
          created_at: "2026-11-24T10:00:00Z",
          expires_at: "2026-12-24T10:00:00Z",
          created_by: "console-operator",
        },
        plaintext_token: "grdr_wk_fin123456789abcdef",
      };
      return mockJsonResponse(issued);
    }
    if (path === CONNECT_PATHS.revokeDeploymentKey) {
      return mockJsonResponse({
        key: {
          ...connectFixture.deployment_keys[0],
          status: "revoked",
        },
      });
    }
    if (path === CONNECT_PATHS.renderMdmConfig) {
      return mockJsonResponse({
        format: "intune_win32",
        filename: "guardrails-intune-install.ps1",
        content_type: "text/plain",
        payload: "origin = \"https://guardrails.internal:8443\"\ninstall_profile = \"standard\"",
        deployment_notes: ["Package as .intunewin with MSI product-code detection rule."],
      });
    }
    if (path === CONNECT_PATHS.checkIntegrationReadiness) {
      return mockJsonResponse({ integration: connectFixture.integrations[0] });
    }
    if (path === CONNECT_PATHS.listBrowserPolicies) {
      return mockJsonResponse({ policies: browserPoliciesFixture });
    }
    if (path === CONNECT_PATHS.updateBrowserPolicy) {
      return mockJsonResponse({
        policy: {
          ...browserPoliciesFixture[0],
          mode: "ask",
        },
      });
    }
    if (path === CONNECT_PATHS.evaluateBrowser) {
      return mockJsonResponse({
        app_id: "chatgpt",
        app_name: "ChatGPT",
        verdict: "deny",
        rule_id: "browser.block.chatgpt",
        reason: "ChatGPT triggered block on file upload (.env) for domain chatgpt.com.",
        dlp_class: "file_upload",
      });
    }
    if (path === CONNECT_PATHS.exportOcsf || path === CONNECT_PATHS.exportAuditJsonl) {
      return mockJsonResponse({
        filename: "export.json",
        contentType: "application/json",
        payload: "{}",
      });
    }
    return mockJsonResponse({ code: "not_found", message: `Unmocked RPC ${path}` }, 404);
  });
}

const browserPoliciesFixture: BrowserAppPolicy[] = [
  {
    id: "chatgpt",
    name: "ChatGPT",
    domains: ["chatgpt.com"],
    mode: "block",
    block_file_uploads: true,
    block_secret_paste: true,
    managed_extension_only: true,
    events_24h: 142,
    blocked_24h: 11,
  },
];

const connectFixture: ConnectConfigResponse = {
  server_origin: "https://guardrails.internal:8443",
  installers: [
    {
      platform: "macos",
      label: "macOS pkg installer",
      version: "0.4.2",
      command: "curl -fsSL https://guardrails.internal:8443/dl/guardrails-0.4.2.pkg -o /tmp/grdr.pkg",
      sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      doctor_command: "grdr doctor net",
      notes: "Signed universal installer.",
    },
  ],
  deployment_keys: [
    {
      id: "key-pilot-1",
      label: "Pilot Wave 1",
      token_preview: "grdr_wk_pilot9f1a",
      install_profile: "standard",
      wave: "wave-1",
      max_uses: 50,
      used_count: 14,
      status: "active",
      created_at: "2026-11-01T00:00:00Z",
      expires_at: "2026-12-01T00:00:00Z",
      created_by: "maya.chen@acme.dev",
    },
  ],
  otlp: {
    enabled: true,
    grpc_port: 4317,
    http_port: 4318,
    bind_address: "127.0.0.1",
    downstream_targets: ["https://collector.soc.internal:4317"],
    loopback_only: true,
    accepted_spans_24h: 18420,
  },
  integrations: [
    {
      id: "idp-entra",
      name: "Microsoft Entra ID",
      provider: "Entra",
      category: "directory_sync",
      state: "at_risk",
      synced_users: 28,
      last_sync_at: "2026-11-24T09:00:00Z",
      credential_expires_in_days: 9,
      detail: "App registration secret expires within 14 days.",
      readiness_checks: [
        {
          name: "Credential validity",
          passed: true,
          detail: "Secret expires in 9 days",
        },
      ],
    },
  ],
};

class MockEventSource {
  onopen: (() => void) | null = null;
  onerror: (() => void) | null = null;
  addEventListener() {}
  close() {}
}

beforeEach(() => {
  vi.restoreAllMocks();
  vi.stubGlobal("EventSource", MockEventSource);
});

describe("Astryx and UI SDK components", () => {
  it("renders Quoted untrusted agent text inertly without HTML evaluation", () => {
    const payload = '<img src=x onerror="alert(1)"> && rm -rf ~/.ssh';
    const { container } = render(
      <GrdrThemeProvider>
        <Quoted text={payload} />
      </GrdrThemeProvider>,
    );
    expect(container.querySelector("img")).toBeNull();
    expect(container.textContent).toContain(payload);
  });

  it("renders ModeControl on UI SDK SegmentedControl and locks floor rules", () => {
    const onLockedSelect = vi.fn();
    const { unmount } = render(
      <GrdrThemeProvider>
        <ModeControl value="block" locked onChange={onLockedSelect} />
      </GrdrThemeProvider>,
    );
    const offButton = screen.getByRole("radio", { name: "Off" });
    expect((offButton as HTMLButtonElement).disabled || offButton.getAttribute("aria-disabled") === "true").toBe(true);
    unmount();

    const onSelect = vi.fn();
    render(
      <GrdrThemeProvider>
        <ModeControl value="watch" onChange={onSelect} />
      </GrdrThemeProvider>,
    );
    const askButton = screen.getByRole("radio", { name: "Ask" });
    fireEvent.click(askButton);
    expect(onSelect).toHaveBeenCalledWith("ask");
  });

  it("renders semantic VerdictBadge labels", () => {
    render(
      <GrdrThemeProvider>
        <VerdictBadge verdict="deny" />
      </GrdrThemeProvider>,
    );
    expect(screen.getByText("Deny")).toBeTruthy();
  });
});

describe("Console and Operator Plane workflows", () => {
  it("renders Home focal stage, opens inline approval review and command palette, and navigates", async () => {
    installFetchMock();
    render(<App />);

    await waitFor(() => {
      expect(screen.getByText("1 action waiting for your decision")).toBeTruthy();
    });

    fireEvent.click(screen.getByRole("button", { name: "Review" }));
    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Approve once" })).toBeTruthy();
    });

    fireEvent.keyDown(window, { key: "k", ctrlKey: true });
    await waitFor(() => {
      expect(screen.getByRole("dialog", { name: "Command palette" })).toBeTruthy();
    });
    fireEvent.keyDown(window, { key: "Escape" });

    fireEvent.click(screen.getAllByRole("button", { name: "Inventory" })[0]);
    await waitFor(() => {
      expect(screen.getAllByText("devbox.local").length).toBeGreaterThan(0);
    });

    fireEvent.click(screen.getAllByText("devbox.local")[0]);
    await waitFor(() => {
      expect(screen.getByText("Device assurance matrix")).toBeTruthy();
    });

    fireEvent.click(screen.getByRole("button", { name: "Protect" }));
    await waitFor(() => {
      expect(screen.getByText("Protect SSH keys")).toBeTruthy();
    });

    fireEvent.click(screen.getAllByRole("button", { name: "Users" })[0]);
    await waitFor(() => {
      expect(screen.getByText("Users & risk directory")).toBeTruthy();
      expect(screen.getAllByText("Maya Chen").length).toBeGreaterThan(0);
    });

    fireEvent.click(screen.getAllByRole("button", { name: "Sessions" })[0]);
    await waitFor(() => {
      expect(screen.getByRole("radio", { name: "Trace" })).toBeTruthy();
    });
    fireEvent.click(screen.getByRole("radio", { name: "Trace" }));
    await waitFor(() => {
      expect(screen.getByText(/Decomposed shell actions/)).toBeTruthy();
    });
  });

  it("deep-links clickable EntityLink pills across Home, Inventory drawer, and Protect", async () => {
    installFetchMock();
    render(<App />);

    await waitFor(() => {
      expect(screen.getByText("1 action waiting for your decision")).toBeTruthy();
    });

    const hostLinks = screen.getAllByRole("button", { name: "devbox.local" });
    fireEvent.click(hostLinks[0]);
    await waitFor(() => {
      expect(screen.getByText("Device assurance matrix")).toBeTruthy();
      const breadcrumbNav = screen.getByRole("navigation", { name: "Breadcrumb" });
      expect(within(breadcrumbNav).getByRole("button", { name: "Home" })).toBeTruthy();
      expect(within(breadcrumbNav).getByText("devbox.local")).toBeTruthy();
    });

    fireEvent.click(screen.getByRole("button", { name: "Close Device assurance matrix" }));
    const breadcrumbNav = screen.getByRole("navigation", { name: "Breadcrumb" });
    fireEvent.click(within(breadcrumbNav).getByRole("button", { name: "Home" }));
    await waitFor(() => {
      expect(screen.getByRole("button", { name: "rule-1" })).toBeTruthy();
    });
    fireEvent.click(screen.getByRole("button", { name: "rule-1" }));
    await waitFor(() => {
      expect(screen.getByText("Protect SSH keys")).toBeTruthy();
    });
  });

  it("renders OperatorApp with locked operator-context banner and routes", async () => {
    installFetchMock();
    render(<OperatorApp />);

    await waitFor(() => {
      expect(
        screen.getByText(/Operator context: Deployment administration realm only/i),
      ).toBeTruthy();
    });

    fireEvent.click(screen.getByRole("button", { name: "Settings" }));
    await waitFor(() => {
      expect(screen.getByText("key-local-1")).toBeTruthy();
    });

    fireEvent.click(screen.getByRole("button", { name: "Audit log" }));
    await waitFor(() => {
      expect(screen.getByText("Initialized baseline rules")).toBeTruthy();
    });
  });

  it("renders Inventory Connect & MDM, issues wave key, renders MDM payload, and checks readiness", async () => {
    installFetchMock();
    render(<App />);

    await waitFor(() => {
      expect(screen.getAllByRole("button", { name: "Inventory" }).length).toBeGreaterThan(0);
    });
    fireEvent.click(screen.getAllByRole("button", { name: "Inventory" })[0]);

    await waitFor(() => {
      expect(screen.getByRole("radio", { name: "Connect & MDM" })).toBeTruthy();
    });
    fireEvent.click(screen.getByRole("radio", { name: "Connect & MDM" }));

    await waitFor(() => {
      expect(screen.getAllByText("Pilot Wave 1").length).toBeGreaterThan(0);
      expect(screen.getByText(/At risk: 9d expiry/)).toBeTruthy();
      expect(screen.getByText(/Package as .intunewin/)).toBeTruthy();
    });

    fireEvent.click(screen.getByRole("button", { name: "Issue wave key" }));
    await waitFor(() => {
      expect(screen.getByText(/One-time wave key issued for Finance Pilot/)).toBeTruthy();
    });

    fireEvent.click(screen.getByRole("button", { name: "Check readiness" }));
    await waitFor(() => {
      expect(screen.getByText("Secret expires in 9 days")).toBeTruthy();
    });

    const sidebar = screen.getByRole("navigation", { name: "Console sections" });
    fireEvent.click(within(sidebar).getByRole("button", { name: "Protect" }));
    await waitFor(() => {
      expect(within(sidebar).getByRole("button", { name: "Browser AI" })).toBeTruthy();
    });
    fireEvent.click(within(sidebar).getByRole("button", { name: "Browser AI" }));

    await waitFor(() => {
      expect(screen.getAllByText("ChatGPT").length).toBeGreaterThan(0);
    });
    fireEvent.click(screen.getByRole("button", { name: "Run browser check" }));
    await waitFor(() => {
      expect(screen.getByText("browser.block.chatgpt")).toBeTruthy();
    });
  });

  it("supports 3-group categorized sidebar sub-nav and interactive breadcrumbs", async () => {
    installFetchMock();
    render(<App />);

    await waitFor(() => {
      expect(screen.getByText("Overview")).toBeTruthy();
      expect(screen.getByText("Fleet & Activity")).toBeTruthy();
      expect(screen.getByText("Protection & Response")).toBeTruthy();
    });

    const sidebar = screen.getByRole("navigation", { name: "Console sections" });
    fireEvent.click(within(sidebar).getByRole("button", { name: "Agents" }));
    await waitFor(() => {
      expect(screen.getByText("Discovered AI agents (1)")).toBeTruthy();
      const crumbs = screen.getByRole("navigation", { name: "Breadcrumb" });
      expect(within(crumbs).getByText("Agents")).toBeTruthy();
    });

    fireEvent.click(within(sidebar).getByRole("button", { name: "MCP servers" }));
    await waitFor(() => {
      expect(screen.getAllByText("MCP servers (1)").length).toBeGreaterThan(0);
      const crumbs = screen.getByRole("navigation", { name: "Breadcrumb" });
      expect(within(crumbs).getByText("MCP servers")).toBeTruthy();
    });

    fireEvent.click(within(sidebar).getByRole("button", { name: "Skills & rules" }));
    await waitFor(() => {
      expect(screen.getByText("Skills, rules & plugins (1)")).toBeTruthy();
      const crumbs = screen.getByRole("navigation", { name: "Breadcrumb" });
      expect(within(crumbs).getByText("Skills & rules")).toBeTruthy();
    });

    const crumbsAfterSkills = screen.getByRole("navigation", { name: "Breadcrumb" });
    fireEvent.click(within(crumbsAfterSkills).getByRole("button", { name: "Inventory" }));
    await waitFor(() => {
      expect(screen.getByText("Enrolled devices (1)")).toBeTruthy();
      expect(within(screen.getByRole("navigation", { name: "Breadcrumb" })).getByText("Endpoints")).toBeTruthy();
    });

    fireEvent.click(within(sidebar).getByRole("button", { name: "Protect" }));
    await waitFor(() => {
      expect(within(sidebar).getByRole("button", { name: "Browser AI" })).toBeTruthy();
    });
    fireEvent.click(within(sidebar).getByRole("button", { name: "Browser AI" }));
    await waitFor(() => {
      expect(within(screen.getByRole("navigation", { name: "Breadcrumb" })).getByText("Browser AI")).toBeTruthy();
    });

    fireEvent.click(
      within(screen.getByRole("navigation", { name: "Breadcrumb" })).getByRole("button", {
        name: "Protect",
      }),
    );
    await waitFor(() => {
      expect(screen.getByText("Protect SSH keys")).toBeTruthy();
    });

    fireEvent.click(within(sidebar).getByRole("button", { name: "Sessions" }));
    await waitFor(() => {
      expect(within(sidebar).getByRole("button", { name: "Trace waterfall" })).toBeTruthy();
    });
    fireEvent.click(within(sidebar).getByRole("button", { name: "Trace waterfall" }));
    await waitFor(() => {
      expect(screen.getByText(/Decomposed shell actions/)).toBeTruthy();
      expect(
        within(screen.getByRole("navigation", { name: "Breadcrumb" })).getByText("Trace waterfall"),
      ).toBeTruthy();
    });
  });

  it("paginates Inventory sub-views at scale (25/50/100 rows)", async () => {
    const manyDevices: Device[] = Array.from({ length: 60 }, (_, idx) => ({
      ...devicesFixture[0],
      id: `dev-${idx + 1}`,
      hostname: `host-${idx + 1}.acme.local`,
      agents: [
        {
          ...devicesFixture[0].agents[0],
          id: `agent-${idx + 1}`,
          name: idx % 2 === 0 ? "claude-code" : "cursor",
        },
      ],
      mcp_servers: [
        {
          ...devicesFixture[0].mcp_servers[0],
          name: `mcp-${idx + 1}`,
        },
      ],
      artifacts: [
        {
          ...(devicesFixture[0].artifacts?.[0] ?? {
            id: "art-0",
            name: "skill-0",
            kind: "skill",
            scope: "user",
            source_agent: "claude-code",
            path: "~/.claude/skills/skill-0",
            content_digest: "9b71d224",
            file_count: 1,
            total_bytes: 512,
            usage_count: 1,
            pinned: false,
            risk_flags: [],
            device_id: "dev-1",
            device_name: "host-1.acme.local",
            detected_at: "2026-11-23T11:30:00Z",
          }),
          id: `art-${idx + 1}`,
          name: `skill-${idx + 1}`,
          device_id: `dev-${idx + 1}`,
          device_name: `host-${idx + 1}.acme.local`,
        },
      ],
    }));

    installFetchMock({ devices: manyDevices });

    render(<App />);
    const sidebar = await screen.findByRole("navigation", { name: "Console sections" });
    fireEvent.click(within(sidebar).getByRole("button", { name: "Agents" }));

    await waitFor(() => {
      expect(screen.getByText("Discovered AI agents (60)")).toBeTruthy();
      expect(screen.getAllByText("Showing 1-25 of 60").length).toBeGreaterThan(0);
    });

    const pagination = screen.getByRole("navigation", { name: "Agents pagination" });
    fireEvent.click(within(pagination).getByRole("button", { name: /next/i }));

    await waitFor(() => {
      expect(screen.getAllByText("Showing 26-50 of 60").length).toBeGreaterThan(0);
    });
  });

  it("parses Connect error envelopes with grdrCode and requestId", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          code: "invalid_argument",
          message: "Unsupported filter field 'prompt_text'",
          details: [
            {
              type: "google.rpc.ErrorInfo",
              debug: {
                reason: "INVALID_FILTER",
                domain: "grdr.api",
                metadata: { code: "GRDR-API-4002" },
              },
            },
          ],
        }),
        {
          status: 400,
          headers: {
            "Content-Type": "application/json",
            "grdr-request-id": "req-test-42",
          },
        },
      ),
    );

    let caught: unknown;
    try {
      await api.listUsersPage({ filter: 'prompt_text = "secret"' });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(ConnectApiError);
    const connectErr = caught as ConnectApiError;
    expect(connectErr.code).toBe("invalid_argument");
    expect(connectErr.reason).toBe("INVALID_FILTER");
    expect(connectErr.grdrCode).toBe("GRDR-API-4002");
    expect(connectErr.requestId).toBe("req-test-42");
  });
});

function walkSourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (entry === "node_modules" || entry === "dist" || entry === "dist-operator") continue;
    const stats = statSync(full);
    if (stats.isDirectory()) {
      out.push(...walkSourceFiles(full));
    } else if (/\.(ts|tsx|css|html)$/.test(entry)) {
      out.push(full);
    }
  }
  return out;
}

describe("ARCH-101..104 interface workspace guardrails", () => {
  const webRoot = resolve(dirnameFromImport(), "..");

  it("imports @astryxdesign/* and @ui-sdk/* only inside packages/ui", () => {
    const files = [
      ...walkSourceFiles(join(webRoot, "packages")),
      ...walkSourceFiles(join(webRoot, "apps")),
    ];
    for (const file of files) {
      const normalized = file.replace(/\\/g, "/");
      if (normalized.includes("/packages/ui/")) continue;
      const content = readFileSync(file, "utf8");
      expect(content).not.toMatch(/@astryxdesign\//);
      expect(content).not.toMatch(/@ui-sdk\//);
    }
  });

  it("uses zero external CDN fonts or tracking links", () => {
    const files = [
      ...walkSourceFiles(join(webRoot, "packages")),
      ...walkSourceFiles(join(webRoot, "apps")),
    ];
    for (const file of files) {
      const content = readFileSync(file, "utf8");
      expect(content).not.toMatch(/fonts\.googleapis\.com|fonts\.gstatic\.com|cdn\.jsdelivr\.net|unpkg\.com/);
    }
  });

  it("contains zero hand-drawn inline SVG or path elements across web source files", () => {
    const files = [
      ...walkSourceFiles(join(webRoot, "packages")),
      ...walkSourceFiles(join(webRoot, "apps")),
    ];
    for (const file of files) {
      const content = readFileSync(file, "utf8");
      expect(content).not.toMatch(/<svg\b/i);
      expect(content).not.toMatch(/<path\s+[^>]*\bd=/i);
    }
  });
});

function dirnameFromImport(): string {
  return resolve(fileURLToPath(import.meta.url), "..");
}
