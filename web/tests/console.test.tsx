import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type {
  ApprovalRequest,
  AuditEntry,
  Device,
  Finding,
  HealthResponse,
  Incident,
  KillSwitchState,
  OverviewResponse,
  PolicyPack,
  SessionSummary,
  TrustedKeyInfo,
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
  },
];

const sessionsFixture: SessionSummary[] = [
  {
    id: "sess-1",
    device_id: "dev-1",
    device_name: "devbox.local",
    agent_name: "claude-code",
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
  storage_mode: "memory",
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

function installFetchMock() {
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
    const url = typeof input === "string" ? input : input.toString();
    if (url.endsWith("/api/v1/health")) return mockJsonResponse(healthFixture);
    if (url.endsWith("/api/v1/overview")) return mockJsonResponse(overviewFixture);
    if (url.endsWith("/api/v1/devices")) return mockJsonResponse(devicesFixture);
    if (url.endsWith("/api/v1/sessions")) return mockJsonResponse(sessionsFixture);
    if (url.endsWith("/api/v1/policies/packs")) return mockJsonResponse(packsFixture);
    if (url.endsWith("/api/v1/approvals")) return mockJsonResponse(approvalsFixture);
    if (url.endsWith("/api/v1/findings")) return mockJsonResponse(findingsFixture);
    if (url.endsWith("/api/v1/incidents")) return mockJsonResponse(incidentsFixture);
    if (url.endsWith("/api/v1/kill-switch")) {
      const ks: KillSwitchState = { state: "inactive" };
      return mockJsonResponse(ks);
    }
    if (url.endsWith("/api/v1/keys")) return mockJsonResponse(keysFixture);
    if (url.endsWith("/api/v1/audit")) return mockJsonResponse(auditFixture);
    if (url.endsWith("/api/v1/exports/ocsf") || url.endsWith("/api/v1/exports/audit.jsonl")) {
      return new Response("{}", { status: 200 });
    }
    return mockJsonResponse({ code: "NOT_FOUND", message: `Unmocked URL ${url}` }, 404);
  });
}

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
    expect(screen.getByText("DENY")).toBeTruthy();
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
});

function dirnameFromImport(): string {
  return resolve(fileURLToPath(import.meta.url), "..");
}
