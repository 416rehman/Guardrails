// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { api, type Device, type PolicyPack, type SessionDetailResponse, type SessionSummary } from "@grdr/api";
import { GrdrThemeProvider } from "@grdr/ui";
import { QueryClient, QueryClientProvider } from "../apps/console/src/queries";
import {
  computeWeeklyDecisionVelocity,
  deriveKillSwitchCatalog,
} from "../apps/console/src/consoleState";
import { CoveragePage } from "../apps/console/src/pages/CoveragePage";
import { InventoryAgentsSection } from "../apps/console/src/pages/InventoryAgentsSection";
import { CedarProjectionPanel, formatCedarPolicySource } from "../apps/console/src/pages/ProtectRuleViews";
import { buildKillSwitchPayload, RespondPage } from "../apps/console/src/pages/RespondPage";
import {
  buildClusteredFlowPhases,
  selectPrioritizedGraphDetail,
} from "../apps/console/src/pages/SessionInspectorViews";

function makeDevice(overrides: Partial<Device> & { id: string; hostname: string }): Device {
  return {
    os: "macos",
    arch: "aarch64",
    install_profile: "protected",
    daemon_version: "0.1.0",
    online: true,
    hook_effective: true,
    agents: [],
    mcp_servers: [],
    last_seen: "2026-11-27T10:00:00Z",
    ...overrides,
  };
}

describe("W4-2 console state, policy projection, kill-switch, and clustering helpers", () => {
  it("computes local 7-day decision velocity with receipt dedup and honest empty/historical windows", () => {
    const empty = computeWeeklyDecisionVelocity([], new Map(), Date.parse("2026-11-27T15:00:00Z"));
    expect(empty.totalEvaluated).toBe(0);
    expect(empty.windowKind).toBe("current");
    expect(empty.isPartialSummary).toBe(false);
    expect(empty.days).toHaveLength(7);

    const nowMs = new Date(2026, 10, 27, 14, 0, 0).getTime();
    const todayIso = new Date(2026, 10, 27, 11, 0, 0).toISOString();
    const yesterdayIso = new Date(2026, 10, 26, 11, 0, 0).toISOString();

    const sessions: SessionSummary[] = [
      {
        id: "sess-1",
        device_id: "dev-1",
        device_name: "mac-1",
        agent_name: "Claude Code",
        started_at: yesterdayIso,
        last_activity: todayIso,
        total_actions: 10,
        blocked_count: 1,
        step_up_count: 1,
        watch_hits: 0,
        assurance_level: "AL3",
      },
      {
        id: "sess-2",
        device_id: "dev-1",
        device_name: "mac-1",
        agent_name: "Cursor",
        started_at: todayIso,
        last_activity: todayIso,
        total_actions: 3,
        blocked_count: 1,
        step_up_count: 0,
        watch_hits: 0,
        assurance_level: "AL1",
      },
    ];

    const detail: SessionDetailResponse = {
      session: sessions[0],
      attempts: [],
      receipts: [
        {
          receipt_id: "rcp-dup",
          attempt_id: "att-1",
          session_id: "sess-1",
          device_id: "dev-1",
          agent_name: "Claude Code",
          action_class: "exec",
          control_point: "hook",
          target: "git status",
          verdict: "allow",
          would_be: null,
          rule_id: null,
          pack_id: null,
          mode_applied: null,
          grant_id: null,
          reason: "ok",
          next_step: "",
          receipt_digest: "abc",
          decided_at: yesterdayIso,
        },
        {
          receipt_id: "rcp-dup",
          attempt_id: "att-1",
          session_id: "sess-1",
          device_id: "dev-1",
          agent_name: "Claude Code",
          action_class: "exec",
          control_point: "hook",
          target: "git status",
          verdict: "allow",
          would_be: null,
          rule_id: null,
          pack_id: null,
          mode_applied: null,
          grant_id: null,
          reason: "ok",
          next_step: "",
          receipt_digest: "abc",
          decided_at: yesterdayIso,
        },
        {
          receipt_id: "rcp-ask",
          attempt_id: "att-2",
          session_id: "sess-1",
          device_id: "dev-1",
          agent_name: "Claude Code",
          action_class: "file.read",
          control_point: "hook",
          target: "~/.ssh/id_rsa",
          verdict: "step_up",
          would_be: null,
          rule_id: "r1",
          pack_id: "p1",
          mode_applied: "ask",
          grant_id: null,
          reason: "ask",
          next_step: "",
          receipt_digest: "def",
          decided_at: todayIso,
        },
      ],
    };

    const detailsMap = new Map<string, SessionDetailResponse>([["sess-1", detail]]);
    const live = computeWeeklyDecisionVelocity(sessions, detailsMap, nowMs);
    expect(live.windowKind).toBe("current");
    expect(live.isPartialSummary).toBe(true);
    expect(live.totalAllowed).toBe(3);
    expect(live.totalAsk).toBe(1);
    expect(live.totalBlocked).toBe(1);
    expect(live.totalEvaluated).toBe(5);

    const oldIso = new Date(2026, 9, 10, 12, 0, 0).toISOString();
    const historical = computeWeeklyDecisionVelocity(
      [
        {
          ...sessions[1],
          id: "sess-old",
          started_at: oldIso,
          last_activity: oldIso,
          total_actions: 2,
          blocked_count: 1,
          step_up_count: 1,
        },
      ],
      new Map(),
      nowMs,
    );
    expect(historical.windowKind).toBe("historical");
    expect(historical.totalEvaluated).toBe(2);
    expect(historical.windowLabel).toContain("Oct");
  });

  it("derives KillSwitch catalog strictly from live devices and sessions without policy verbs or fake models", () => {
    const devices: Device[] = [
      makeDevice({
        id: "dev-1",
        hostname: "macbook",
        agents: [
          {
            id: "ag-1",
            name: "claude-code",
            kind: "claude-code",
            config_path: "~/.claude/settings.json",
            hook_installed: true,
            mcp_count: 1,
            assurance_level: "AL3",
            assurance: {
              visibility: "observed",
              control: "scoped-boundary",
              on_failure: "closed",
              tamper: "admin",
            },
            sponsor: null,
            detected_at: "2026-11-27T09:00:00Z",
          },
          {
            id: "ag-2",
            name: "github-copilot",
            kind: "github-copilot",
            config_path: "~/.copilot",
            hook_installed: true,
            mcp_count: 0,
            assurance_level: "AL2",
            assurance: {
              visibility: "observed",
              control: "tool-proxy",
              on_failure: "closed",
              tamper: "admin",
            },
            sponsor: null,
            detected_at: "2026-11-27T09:00:00Z",
          },
        ],
        mcp_servers: [
          {
            name: "filesystem",
            transport: "stdio",
            command: "mcp-fs",
            source_agent: "Claude Code",
            config_path: "~/.claude/settings.json",
            pinned: true,
          },
        ],
      }),
    ];

    const sessions: SessionSummary[] = [
      {
        id: "sess-a",
        device_id: "dev-1",
        device_name: "macbook",
        agent_name: "Claude Code",
        started_at: "2026-11-27T09:00:00Z",
        last_activity: "2026-11-27T09:10:00Z",
        total_actions: 1,
        blocked_count: 0,
        step_up_count: 0,
        watch_hits: 0,
        assurance_level: "AL3",
      },
    ];

    const catalog = deriveKillSwitchCatalog(devices, sessions);
    expect(catalog.agents).toEqual(["Claude Code", "GitHub Copilot"]);
    expect(catalog.gateways).toEqual(["filesystem"]);
    expect(catalog.gateways).not.toContain("write");
    expect(catalog.gateways).not.toContain("delete");
    expect(catalog.models).toEqual([]);
  });

  it("maps single-device kill-switch selections to device scope and multi-device selections to organisation scope", () => {
    const devices: Device[] = [
      makeDevice({
        id: "dev-mac",
        hostname: "macbook",
        agents: [
          {
            id: "a1",
            name: "Claude Code",
            kind: "claude-code",
            config_path: "~/.claude",
            hook_installed: true,
            mcp_count: 0,
            assurance_level: "AL3",
            assurance: { visibility: "observed", control: "boundary", on_failure: "closed", tamper: "admin" },
            sponsor: null,
            detected_at: "2026-11-27T09:00:00Z",
          },
          {
            id: "a2",
            name: "Cursor",
            kind: "cursor",
            config_path: "~/.cursor",
            hook_installed: false,
            mcp_count: 0,
            assurance_level: "AL1",
            assurance: { visibility: "claimed", control: "none", on_failure: "open", tamper: "user" },
            sponsor: null,
            detected_at: "2026-11-27T09:00:00Z",
          },
        ],
      }),
      makeDevice({
        id: "dev-win",
        hostname: "win-build",
        os: "windows",
        agents: [
          {
            id: "a3",
            name: "Claude Code",
            kind: "claude-code",
            config_path: "~/.claude",
            hook_installed: true,
            mcp_count: 0,
            assurance_level: "AL3",
            assurance: { visibility: "observed", control: "boundary", on_failure: "closed", tamper: "admin" },
            sponsor: null,
            detected_at: "2026-11-27T09:00:00Z",
          },
        ],
      }),
    ];

    const singleDevicePayload = buildKillSwitchPayload(
      "kill",
      "session",
      "sess-demo",
      "Contain cursor",
      devices,
      { blockedAgents: ["Cursor"], blockedModels: [], blockedGateways: [] },
    );
    expect(singleDevicePayload.scope).toBe("device");
    expect(singleDevicePayload.target_id).toBe("dev-mac");
    expect(singleDevicePayload.reason).toContain("[agents=Cursor]");

    const fleetPayload = buildKillSwitchPayload(
      "kill",
      "session",
      "sess-demo",
      "Contain fleet claude",
      devices,
      { blockedAgents: ["Claude Code"], blockedModels: [], blockedGateways: [] },
    );
    expect(fleetPayload.scope).toBe("organisation");
    expect(fleetPayload.target_id).toBe("*");
    expect(fleetPayload.reason).toContain("[agents=Claude Code]");
  });

  it("renders multi-pattern escaped Cedar policy projection and skips disabled or off rules", () => {
    const packs: PolicyPack[] = [
      {
        id: "pack\n//injected",
        name: "Custom",
        description: "Test",
        version: "1.0.0",
        channel: "stable",
        rules: [
          {
            id: 'rule"one',
            title: "Multi pattern rule",
            description: "Guards secrets",
            mode: "block",
            min_grade: "G2",
            enabled: true,
            locked: true,
            matcher: {
              action_classes: ["file.read", "exec"],
              target_prefixes: ["/etc/ssh*prod\\"],
              target_contains: [".env", "secret*key", "src\\*secret", 'id_rsa"key'],
              agents: ["Claude Code", "Cursor"],
            },
            hits: 0,
            would_ask_hits: 0,
            would_block_hits: 0,
            reason_template: 'Blocked "bad"\nline',
          },
          {
            id: "rule.off",
            title: "Turned off",
            description: "Should not emit forbid",
            mode: "off",
            min_grade: "G1",
            enabled: true,
            locked: false,
            matcher: {
              action_classes: ["exec"],
              target_prefixes: [],
              target_contains: ["curl"],
              agents: [],
            },
            hits: 0,
            would_ask_hits: 0,
            would_block_hits: 0,
            reason_template: "Off",
          },
        ],
      },
    ];

    const rendered = formatCedarPolicySource(packs, "");
    expect(rendered.ruleCount).toBe(2);
    expect(rendered.lockedCount).toBe(1);
    expect(rendered.source).toContain('@id("rule\\"one")');
    expect(rendered.source).toContain('@final("true")');
    expect(rendered.source).toContain('@message("Blocked \\"bad\\"\\nline")');
    expect(rendered.source).toContain("principal is Grdr::Session");
    expect(rendered.source).toContain('Grdr::Action::"file.read"');
    expect(rendered.source).toContain('Grdr::Action::"exec"');
    expect(rendered.source).toContain('principal in Grdr::Agent::"claude code"');
    expect(rendered.source).toContain('principal in Grdr::Agent::"cursor"');
    expect(rendered.source).toContain('resource.target like "/etc/ssh\\*prod\\\\*"');
    expect(rendered.source).toContain('resource.target like "*secret\\*key*"');
    expect(rendered.source).toContain('resource.target like "*src\\\\\\*secret*"');
    expect(rendered.source).toContain('resource.target like "*id_rsa\\"key*"');
    expect(rendered.source).toContain("rule.off");
    expect(rendered.source).not.toContain('forbid(\n  principal is Grdr::Session,\n  action == Grdr::Action::"exec"');

    render(<CedarProjectionPanel packs={packs} />);
    fireEvent.click(screen.getByRole("button", { name: "Copy Cedar" }));
    expect(screen.getByRole("button", { name: "Clipboard unavailable" })).toBeTruthy();
  });

  it("renders CoveragePage agent harnesses via presentAgentName without duplicating slugs", () => {
    const devices: Device[] = [
      makeDevice({
        id: "dev-1",
        hostname: "dev-box",
        agents: [
          {
            id: "ag-copilot",
            name: "github-copilot",
            kind: "github-copilot",
            config_path: "~/.copilot",
            hook_installed: true,
            mcp_count: 0,
            assurance_level: "AL3",
            assurance: { visibility: "observed", control: "scoped-boundary", on_failure: "closed", tamper: "admin" },
            sponsor: null,
            detected_at: "2026-11-27T09:00:00Z",
          },
        ],
      }),
    ];
    render(<CoveragePage devices={devices} />);
    expect(screen.getAllByRole("button", { name: "GitHub Copilot" }).length).toBeGreaterThan(0);
  });

  it("clusters large session graphs by action class and keeps denied/ask/tail steps in priority slice", () => {
    const attempts: SessionDetailResponse["attempts"] = [];
    const receipts: SessionDetailResponse["receipts"] = [];
    for (let idx = 0; idx < 110; idx += 1) {
      const id = `att-${idx}`;
      attempts.push({
        id,
        session_id: "sess-large",
        device_id: "dev-1",
        device_name: "mac",
        agent_name: "Claude Code",
        action_class: idx === 108 ? "file.write" : "exec",
        control_point: "hook",
        target: `step-${idx}`,
        summary: "step",
        timestamp: "2026-11-27T10:00:00Z",
      });
      receipts.push({
        receipt_id: `rcp-${idx}`,
        attempt_id: id,
        session_id: "sess-large",
        device_id: "dev-1",
        agent_name: "Claude Code",
        action_class: idx === 108 ? "file.write" : "exec",
        control_point: "hook",
        target: `step-${idx}`,
        verdict: idx === 108 ? "deny" : "allow",
        would_be: null,
        rule_id: null,
        pack_id: null,
        mode_applied: null,
        grant_id: null,
        reason: "ok",
        next_step: "",
        receipt_digest: "dig",
        decided_at: "2026-11-27T10:00:00Z",
      });
    }

    const phases = buildClusteredFlowPhases(attempts, receipts);
    expect(phases[0].actionClass).toBe("file.write");
    expect(phases[0].denyCount).toBe(1);
    expect(phases[0].representativeAttemptId).toBe("att-108");

    const sliced = selectPrioritizedGraphDetail(
      {
        session: {
          id: "sess-large",
          device_id: "dev-1",
          device_name: "mac",
          agent_name: "Claude Code",
          started_at: "2026-11-27T10:00:00Z",
          last_activity: "2026-11-27T10:05:00Z",
          total_actions: 110,
          blocked_count: 1,
          step_up_count: 0,
          watch_hits: 0,
          assurance_level: "AL3",
        },
        attempts,
        receipts,
      },
      97,
    );
    expect(sliced.attempts).toHaveLength(97);
    expect(sliced.attempts.some((a) => a.id === "att-108")).toBe(true);
    expect(sliced.attempts[sliced.attempts.length - 1].id).toBe("att-109");
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("emits name and kind clauses on InventoryAgentsSection slug deep-links before and after devices load", async () => {
    const emptyPage = {
      items: [],
      page_info: {
        next_page_token: "",
        prev_page_token: "",
        total_size_estimate: 0,
        has_more: false,
      },
    };
    const listSpy = vi.spyOn(api, "listAgentsPage").mockResolvedValue(emptyPage);
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });

    const { rerender } = render(
      <GrdrThemeProvider>
        <QueryClientProvider client={qc}>
          <InventoryAgentsSection
            devices={[]}
            globalQuery=""
            initialAgentFilter="github-copilot"
            onSelectDevice={() => {}}
          />
        </QueryClientProvider>
      </GrdrThemeProvider>,
    );

    await waitFor(() => {
      expect(listSpy).toHaveBeenCalled();
    });
    const firstFilter = listSpy.mock.calls[0]?.[0]?.filter ?? "";
    expect(firstFilter).toContain('name:"github copilot"');
    expect(firstFilter).toContain('kind:"github-copilot"');

    const loadedDevices: Device[] = [
      makeDevice({
        id: "dev-1",
        hostname: "dev-box",
        agents: [
          {
            id: "ag-copilot",
            name: "github_copilot",
            kind: "github-copilot",
            config_path: "~/.copilot",
            hook_installed: true,
            mcp_count: 0,
            assurance_level: "AL3",
            assurance: { visibility: "observed", control: "scoped-boundary", on_failure: "closed", tamper: "admin" },
            sponsor: null,
            detected_at: "2026-11-27T09:00:00Z",
          },
        ],
      }),
    ];
    rerender(
      <GrdrThemeProvider>
        <QueryClientProvider client={qc}>
          <InventoryAgentsSection
            devices={loadedDevices}
            globalQuery=""
            initialAgentFilter="github-copilot"
            onSelectDevice={() => {}}
          />
        </QueryClientProvider>
      </GrdrThemeProvider>,
    );

    await waitFor(() => {
      const lastFilter = listSpy.mock.calls.at(-1)?.[0]?.filter ?? "";
      expect(lastFilter).toContain('name:"github_copilot"');
      expect(lastFilter).toContain('kind:"github-copilot"');
    });
  });

  it("discards cancelled kill-switch modal drafts and keeps inline scope edits across SSE killSwitch object refreshes", async () => {
    const emptyPaged = {
      items: [],
      page_info: {
        next_page_token: "",
        prev_page_token: "",
        total_size_estimate: 0,
        has_more: false,
      },
    };
    vi.spyOn(api, "listApprovalsPage").mockResolvedValue(emptyPaged);
    vi.spyOn(api, "listIncidentsPage").mockResolvedValue(emptyPaged);
    vi.spyOn(api, "listFindingsPage").mockResolvedValue(emptyPaged);
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });

    const devices: Device[] = [
      makeDevice({
        id: "dev-1",
        hostname: "dev-box",
        agents: [
          {
            id: "ag-1",
            name: "Cursor",
            kind: "cursor",
            config_path: "~/.cursor",
            hook_installed: false,
            mcp_count: 0,
            assurance_level: "AL1",
            assurance: { visibility: "claimed", control: "none", on_failure: "open", tamper: "user" },
            sponsor: null,
            detected_at: "2026-11-27T09:00:00Z",
          },
        ],
      }),
    ];

    const killV1 = {
      state: "killed" as const,
      scope: "device" as const,
      target_id: "dev-1",
      reason: "Containment",
      issued_at: "2026-11-27T10:00:00Z",
    };

    const { rerender } = render(
      <GrdrThemeProvider>
        <QueryClientProvider client={qc}>
          <RespondPage
            approvals={[]}
            incidents={[]}
            findings={[]}
            devices={devices}
            killSwitch={killV1}
            defaultSessionId="sess-1"
            onUpdated={() => {}}
          />
        </QueryClientProvider>
      </GrdrThemeProvider>,
    );

    const scopeBox = screen.getByRole("combobox", { name: "Scope" });
    fireEvent.click(scopeBox);
    fireEvent.click(screen.getByRole("option", { name: "Organisation" }));
    expect(scopeBox.textContent).toContain("Organisation");

    rerender(
      <GrdrThemeProvider>
        <QueryClientProvider client={qc}>
          <RespondPage
            approvals={[]}
            incidents={[]}
            findings={[]}
            devices={devices}
            killSwitch={{ ...killV1 }}
            defaultSessionId="sess-1"
            onUpdated={() => {}}
          />
        </QueryClientProvider>
      </GrdrThemeProvider>,
    );
    expect(screen.getByRole("combobox", { name: "Scope" }).textContent).toContain("Organisation");

    fireEvent.click(screen.getByRole("button", { name: "Emergency controls" }));
    const dialog = screen.getByRole("dialog", { name: "Scoped Kill Switch Matrix" });
    const cursorCheck = within(dialog).getByRole("checkbox", { name: "Cursor" });
    fireEvent.click(cursorCheck);
    expect(cursorCheck.getAttribute("aria-checked")).toBe("true");
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));

    fireEvent.click(screen.getByRole("button", { name: "Emergency controls" }));
    const reopened = screen.getByRole("dialog", { name: "Scoped Kill Switch Matrix" });
    const reopenedCursor = within(reopened).getByRole("checkbox", { name: "Cursor" });
    expect(reopenedCursor.getAttribute("aria-checked")).toBe("false");
  });
});
